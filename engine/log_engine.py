"""
Log Analyzer Engine
Parses web server / syslog / auth log files for security threats.
"""

import re
from collections import Counter
from typing import Any

PATTERNS = {
    "SQL Injection": [
        r"(union\s+select|select\s+\*|drop\s+table|insert\s+into|delete\s+from)",
        r"('|%27)(\s|%20)*(or|and|union|select)",
        r"--\s*(#|$)",
        r"xp_cmdshell",
        r"benchmark\(\d+",
    ],
    "XSS Attempt": [
        r"<script[\s>]",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"alert\s*\(",
        r"%3cscript",
    ],
    "Path Traversal": [
        r"\.\./\.\./",
        r"\.\.%2f",
        r"/etc/passwd",
        r"/etc/shadow",
        r"c:\\windows\\system32",
        r"%2e%2e%2f",
    ],
    "Brute Force": [
        r"(failed password|authentication failure|invalid user)",
        r"(too many authentication failures)",
    ],
    "Web Shell": [
        r"\.(php|asp|aspx|jsp)\?(cmd|exec|shell|cat|ls|dir|id)=",
        r"(c99|r57|b374k|wso)\.php",
        r"eval\(base64_decode",
    ],
    "Scanner/Bot": [
        r"(nikto|sqlmap|nmap|masscan|dirbuster|gobuster|wfuzz)",
        r"(zgrab|python-requests|go-http-client|curl/\d)",
        r"(nuclei|acunetix|burpsuite|w3af)",
    ],
    "Unauthorized Access": [
        r"(403|401|forbidden|unauthorized)\s",
        r"(access denied|permission denied)",
    ],
    "Command Injection": [
        r"(;|&&|\|\|)\s*(ls|cat|id|whoami|uname|pwd|wget|curl|chmod|rm\s+-rf)",
        r"\$\(.*\)",
        r"`.*`",
    ],
}

ALERT_STATUS_CODES = {
    "400": "Bad Request (malformed)",
    "401": "Unauthorized",
    "403": "Forbidden",
    "404": "Not Found (scanning?)",
    "405": "Method Not Allowed",
    "429": "Too Many Requests (rate limit hit)",
    "500": "Internal Server Error",
    "502": "Bad Gateway",
}

# Patterns that suggest a line is a real log entry
LOG_LINE_PATTERNS = [
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',   # IPv4 address
    r'\[\d{2}/\w+/\d{4}',                       # Apache/Nginx date
    r'(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+/',  # HTTP method
    r'(failed password|accepted password)',      # auth.log
    r'\b(error|warning|critical|info)\b',        # syslog
    r'HTTP/\d\.\d',                              # HTTP version
]


def _is_valid_log_input(text: str) -> tuple[bool, str]:
    """
    Validate that input looks like actual log file content, not random text.
    """
    text = text.strip()
    if not text:
        return False, "❌ Please paste or upload log file content."

    lines = text.splitlines()
    if len(lines) < 1:
        return False, "❌ No log content found."

    # Check at least some lines look like log entries
    log_like = 0
    for line in lines[:20]:  # check first 20 lines
        for pattern in LOG_LINE_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                log_like += 1
                break

    total_checked = min(len(lines), 20)
    if total_checked > 0 and log_like == 0:
        return False, (
            "❌ This does not look like a log file. "
            "Log Analyzer requires actual server log content "
            "(Apache/Nginx access logs, auth.log, syslog). "
            "Please paste valid log data or use the 'Load Sample Log' button to try an example."
        )

    return True, ""


def _parse_log_line(line: str) -> dict:
    info = {"raw": line, "ip": None, "status": None, "path": None}
    m = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3})', line)
    if m:
        info["ip"] = m.group(1)
    m = re.search(r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s"]+)', line)
    if m:
        info["path"] = m.group(1)
    m = re.search(r'"\s+(\d{3})\s+', line)
    if m:
        info["status"] = m.group(1)
    return info


def analyze_logs(log_text: str, source_name: str = "pasted log") -> dict[str, Any]:
    """
    Analyze log text for security threats.
    Validates input is actual log content first.
    """
    log_text = log_text.strip() if log_text else ""

    # Validation
    valid, err_msg = _is_valid_log_input(log_text)
    if not valid:
        return {
            "log_source": source_name,
            "total_lines": 0,
            "threats_found": 0,
            "severity": "Invalid",
            "summary": err_msg,
            "findings": [],
            "attack_breakdown": {},
            "top_ips": [],
            "status_alerts": {},
            "error": err_msg,
        }

    lines = log_text.splitlines()
    total = len(lines)

    findings = []
    ip_counter: Counter = Counter()
    attack_type_counter: Counter = Counter()
    status_counter: Counter = Counter()

    for line_no, line in enumerate(lines, 1):
        line_lower = line.lower()
        parsed = _parse_log_line(line)

        if parsed["ip"]:
            ip_counter[parsed["ip"]] += 1
        if parsed["status"]:
            status_counter[parsed["status"]] += 1

        for attack_type, patterns in PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, line_lower):
                    attack_type_counter[attack_type] += 1
                    findings.append({
                        "line_no": line_no,
                        "type": attack_type,
                        "ip": parsed.get("ip", "?"),
                        "snippet": line[:120],
                    })
                    break

    top_ips = ip_counter.most_common(10)
    status_alerts = {
        code: (cnt, ALERT_STATUS_CODES[code])
        for code, cnt in status_counter.items()
        if code in ALERT_STATUS_CODES
    }
    threats_found = len(findings)

    summary_parts = [f"Analyzed {total} lines | {threats_found} threat indicators found"]
    for atype, cnt in attack_type_counter.most_common():
        summary_parts.append(f"{atype}: {cnt}")
    if top_ips:
        top_ip_str = ", ".join(f"{ip}({c})" for ip, c in top_ips[:5])
        summary_parts.append(f"Top IPs: {top_ip_str}")

    summary = " | ".join(summary_parts)

    if threats_found >= 20 or attack_type_counter.get("Web Shell", 0) > 0:
        severity = "Critical"
    elif threats_found >= 8:
        severity = "High"
    elif threats_found >= 3:
        severity = "Medium"
    else:
        severity = "Low"

    return {
        "log_source": source_name,
        "total_lines": total,
        "threats_found": threats_found,
        "severity": severity,
        "summary": summary,
        "findings": findings[:200],
        "attack_breakdown": dict(attack_type_counter),
        "top_ips": top_ips,
        "status_alerts": status_alerts,
    }
