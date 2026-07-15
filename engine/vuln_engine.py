"""
Vulnerability Scanner Engine
Checks web applications and headers for common misconfigurations.
"""

import re
import socket
import requests
from typing import Any
from urllib.parse import urlparse

REQUIRED_HEADERS = {
    "Strict-Transport-Security": "Missing HSTS — site vulnerable to SSL stripping",
    "Content-Security-Policy": "Missing CSP — site vulnerable to XSS",
    "X-Frame-Options": "Missing X-Frame-Options — clickjacking risk",
    "X-Content-Type-Options": "Missing X-Content-Type-Options — MIME sniffing risk",
    "Referrer-Policy": "Missing Referrer-Policy — data leakage risk",
    "Permissions-Policy": "Missing Permissions-Policy — browser feature exposure",
}

DANGEROUS_HEADERS = {
    "Server": "Server header exposes software version",
    "X-Powered-By": "X-Powered-By exposes backend technology",
    "X-AspNet-Version": "ASP.NET version exposed",
    "X-AspNetMvc-Version": "ASP.NET MVC version exposed",
}

COMMON_PORTS = {
    21:    ("FTP",        "High",     "FTP transmits credentials in plaintext"),
    22:    ("SSH",        "Medium",   "SSH exposed — ensure key-based auth only"),
    23:    ("Telnet",     "Critical", "Telnet is completely insecure, disable immediately"),
    25:    ("SMTP",       "Medium",   "SMTP port open — check for open relay"),
    80:    ("HTTP",       "Low",      "HTTP running — ensure redirect to HTTPS"),
    443:   ("HTTPS",      "Info",     "HTTPS — good"),
    445:   ("SMB",        "Critical", "SMB exposed — EternalBlue/ransomware target"),
    1433:  ("MSSQL",      "High",     "Database port publicly exposed"),
    3306:  ("MySQL",      "High",     "Database port publicly exposed"),
    3389:  ("RDP",        "Critical", "RDP exposed — ransomware target, restrict access"),
    5432:  ("PostgreSQL", "High",     "Database port publicly exposed"),
    5900:  ("VNC",        "High",     "VNC remote desktop exposed"),
    6379:  ("Redis",      "Critical", "Redis exposed without auth — data theft risk"),
    8080:  ("HTTP-alt",   "Medium",   "Alternate HTTP port open"),
    8443:  ("HTTPS-alt",  "Low",      "Alternate HTTPS port"),
    27017: ("MongoDB",    "Critical", "MongoDB exposed — common data breach source"),
}

SENSITIVE_PATHS = [
    "/.git/HEAD", "/.env", "/wp-config.php", "/config.php",
    "/admin", "/phpmyadmin", "/robots.txt", "/.htaccess",
    "/server-status", "/actuator", "/actuator/env",
    "/.DS_Store", "/crossdomain.xml",
]


def _is_valid_target(target: str) -> tuple[bool, str]:
    """
    Only accept valid hostnames, domain names, or IP addresses.
    Rejects plain words, names, sentences.
    """
    target = target.strip()
    if not target:
        return False, "❌ Please enter a target URL or IP address."

    # Strip protocol if present
    check = target
    for prefix in ("http://", "https://"):
        if check.lower().startswith(prefix):
            check = check[len(prefix):]
    # Get hostname part only
    host = check.split("/")[0].split(":")[0].split("?")[0]

    # Must match domain or IP pattern
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'

    if re.match(ip_pattern, host):
        # Validate each octet
        octets = host.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            return True, ""
        return False, f"❌ '{target}' is not a valid IP address."

    if re.match(domain_pattern, host):
        return True, ""

    return False, (
        f"❌ '{target}' is not a valid URL, domain, or IP address. "
        "Vulnerability Scanner requires a real hostname or IP "
        "(e.g. https://example.com, google.com, or 192.168.1.1). "
        "It cannot scan plain words or names."
    )


def _port_scan(host: str, ports: list, timeout: float = 0.8) -> dict:
    results = {}
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            results[port] = (s.connect_ex((host, port)) == 0)
            s.close()
        except Exception:
            results[port] = False
    return results


def _check_headers(url: str) -> tuple[list, list]:
    missing, exposed = [], []
    try:
        resp = requests.head(url, timeout=5, allow_redirects=True, verify=False)
        hdrs = {k.title(): v for k, v in resp.headers.items()}

        for hdr, msg in REQUIRED_HEADERS.items():
            if hdr not in hdrs:
                missing.append({"header": hdr, "message": msg, "severity": "Medium"})

        for hdr, msg in DANGEROUS_HEADERS.items():
            if hdr in hdrs:
                exposed.append({"header": hdr, "value": hdrs[hdr], "message": msg, "severity": "Low"})

        hsts = hdrs.get("Strict-Transport-Security", "")
        if hsts and "max-age" in hsts:
            age = re.search(r'max-age=(\d+)', hsts)
            if age and int(age.group(1)) < 31536000:
                missing.append({"header": "HSTS max-age", "message": "HSTS max-age too short (< 1 year)", "severity": "Low"})
    except Exception:
        pass
    return missing, exposed


def _check_sensitive_files(base_url: str) -> list:
    found = []
    base = base_url.rstrip("/")
    for path in SENSITIVE_PATHS:
        try:
            r = requests.get(base + path, timeout=3, allow_redirects=False, verify=False)
            if r.status_code in (200, 301, 302):
                severity = "Critical" if path in ("/.env", "/wp-config.php", "/.git/HEAD") else "High"
                found.append({
                    "path": path,
                    "status": r.status_code,
                    "severity": severity,
                    "message": f"Sensitive file/path accessible: {path}",
                })
        except Exception:
            pass
    return found


def scan_target(target: str, scan_type: str = "headers") -> dict[str, Any]:
    """
    Run vulnerability scan. Validates target is a real URL/IP first.
    """
    target = target.strip() if target else ""

    # Validation
    valid, err_msg = _is_valid_target(target)
    if not valid:
        return {
            "target": target,
            "scan_type": scan_type,
            "vulns_found": 0,
            "severity": "Invalid",
            "findings": err_msg,
            "findings_list": [{"category": "Error", "message": err_msg, "severity": "Invalid"}],
            "error": err_msg,
        }

    if not target.startswith(("http://", "https://")):
        url = "https://" + target
    else:
        url = target

    parsed = urlparse(url)
    host = parsed.hostname or target.split("/")[0]

    findings = []

    if scan_type in ("headers", "full"):
        missing, exposed = _check_headers(url)
        for item in missing:
            item["category"] = "Security Headers"
            findings.append(item)
        for item in exposed:
            item["category"] = "Information Disclosure"
            findings.append(item)

    if scan_type in ("ports", "full"):
        port_list = list(COMMON_PORTS.keys())
        port_results = _port_scan(host, port_list)
        for port, is_open in port_results.items():
            if is_open:
                service, sev, msg = COMMON_PORTS[port]
                findings.append({
                    "category": "Open Port",
                    "header": f"Port {port} ({service})",
                    "severity": sev,
                    "message": msg,
                })

    if scan_type in ("files", "full"):
        file_hits = _check_sensitive_files(url)
        for item in file_hits:
            item["category"] = "Exposed File"
            findings.append(item)

    vulns_found = len(findings)
    severities = [f.get("severity", "Low") for f in findings]

    if "Critical" in severities:
        overall = "Critical"
    elif "High" in severities:
        overall = "High"
    elif "Medium" in severities:
        overall = "Medium"
    elif vulns_found > 0:
        overall = "Low"
    else:
        overall = "Low"

    findings_str = " | ".join(f"[{f.get('severity','?')}] {f.get('message','')}" for f in findings)

    return {
        "target": target,
        "scan_type": scan_type,
        "vulns_found": vulns_found,
        "severity": overall,
        "findings": findings_str,
        "findings_list": findings,
    }
