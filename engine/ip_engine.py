"""
IP Threat Analysis Engine
Combines rule-based heuristics with optional public APIs.
"""

import ipaddress
import re
import socket
import requests
from typing import Any

SUSPICIOUS_RANGES = [
    "185.220.0.0/14",
    "45.142.0.0/16",
    "194.165.0.0/16",
    "192.42.116.0/24",
]

TOR_EXIT_NODES = {
    "185.220.101.1", "185.220.101.2", "185.220.102.1",
    "199.249.230.1",  "199.249.231.1",
}

VPN_KEYWORDS = [
    "vpn", "proxy", "tor", "anonymizer", "hosting",
    "datacenter", "cloud", "digitalocean", "linode",
    "vultr", "hetzner", "ovh",
]

SUSPICIOUS_PORTS = {
    22:    "SSH (brute-force risk)",
    23:    "Telnet (insecure)",
    3389:  "RDP (ransomware target)",
    5900:  "VNC (remote access)",
    4444:  "Metasploit default",
    1337:  "Hacker leet port",
    31337: "Back Orifice malware",
    6881:  "BitTorrent",
    8080:  "HTTP alt / proxy",
    9050:  "Tor SOCKS proxy",
    9051:  "Tor control port",
}


def _is_valid_ip_input(ip: str) -> bool:
    """
    Only accept valid IPv4 or IPv6 addresses.
    Rejects hostnames, words, names, URLs.
    """
    ip = ip.strip()
    # Must match IPv4 pattern or IPv6 pattern
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _check_ip_format(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _check_suspicious_range(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in SUSPICIOUS_RANGES:
            if addr in ipaddress.ip_network(cidr):
                return True
    except ValueError:
        pass
    return False


def _reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _geo_lookup(ip: str) -> dict:
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,proxy,hosting,mobile",
            timeout=5,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {}


def _quick_port_scan(ip: str, ports: list) -> list:
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass
    return open_ports


def analyze_ip(ip: str, do_port_scan: bool = False) -> dict[str, Any]:
    """
    Analyze an IP address. Returns error result if input is not a valid IP.
    """
    ip = ip.strip() if ip else ""

    result = {
        "ip": ip,
        "valid": False,
        "private": False,
        "country": "Unknown",
        "isp": "Unknown",
        "threat_score": 0,
        "is_tor": False,
        "is_vpn": False,
        "is_proxy": False,
        "open_ports": "[]",
        "reverse_dns": "",
        "severity": "Low",
        "indicators": [],
        "indicators_list": [],
        "details": "",
    }

    # ── Input validation ───────────────────────────────────────────────────────
    if not ip:
        result["indicators_list"] = ["❌ Please enter an IP address."]
        result["indicators"] = "❌ Please enter an IP address."
        result["severity"] = "Invalid"
        return result

    if not _is_valid_ip_input(ip):
        result["indicators_list"] = [
            f"❌ '{ip}' is not a valid IP address.",
            "ℹ️ IP Analyzer only accepts IPv4 (e.g. 8.8.8.8) or IPv6 addresses.",
            "ℹ️ To scan a website/domain, use the URL Scanner or Vulnerability Scanner tools."
        ]
        result["indicators"] = " | ".join(result["indicators_list"])
        result["severity"] = "Invalid"
        return result

    result["valid"] = True

    if _is_private(ip):
        result["private"] = True
        inds = ["ℹ️ Private/RFC1918 address — internal network IP. Not routable on public internet."]
        result["indicators_list"] = inds
        result["indicators"] = inds[0]
        result["severity"] = "Info"
        return result

    # Geo + ISP lookup
    geo = _geo_lookup(ip)
    if geo.get("status") == "success":
        result["country"] = f"{geo.get('city','')}, {geo.get('country','')}"
        result["isp"] = geo.get("isp", "Unknown")
        if geo.get("proxy"):
            result["is_proxy"] = True
            result["threat_score"] += 30
            result["indicators"].append("⚠️ Flagged as proxy by ip-api")
        if geo.get("hosting"):
            result["is_vpn"] = True
            result["threat_score"] += 20
            result["indicators"].append("⚠️ Hosted on datacenter/VPN infrastructure")

    rdns = _reverse_dns(ip)
    result["reverse_dns"] = rdns
    if rdns and any(kw in rdns.lower() for kw in VPN_KEYWORDS):
        result["is_vpn"] = True
        result["threat_score"] += 15
        result["indicators"].append(f"⚠️ Reverse DNS suggests VPN/proxy: {rdns}")

    isp_lower = result["isp"].lower()
    if any(kw in isp_lower for kw in VPN_KEYWORDS):
        result["threat_score"] += 10
        result["indicators"].append(f"⚠️ ISP name suggests datacenter/hosting: {result['isp']}")

    if ip in TOR_EXIT_NODES:
        result["is_tor"] = True
        result["threat_score"] += 50
        result["indicators"].append("🔴 Known Tor exit node")

    if _check_suspicious_range(ip):
        result["threat_score"] += 25
        result["indicators"].append("🔴 IP falls within a known suspicious range")

    if do_port_scan:
        scan_ports = list(SUSPICIOUS_PORTS.keys())
        open_p = _quick_port_scan(ip, scan_ports)
        for p in open_p:
            desc = SUSPICIOUS_PORTS.get(p, "")
            result["threat_score"] += 15
            result["indicators"].append(f"🔴 Open suspicious port {p}: {desc}")
        result["open_ports"] = str(open_p)

    score = result["threat_score"]
    if score >= 70:
        result["severity"] = "Critical"
    elif score >= 40:
        result["severity"] = "High"
    elif score >= 20:
        result["severity"] = "Medium"
    else:
        result["severity"] = "Low"

    result["indicators_list"] = result["indicators"]
    result["details"] = " | ".join(result["indicators"])
    result["indicators"] = result["details"]   # always a string for DB

    return result
