"""
URL Scanner Engine — with strict input validation.
Fixes:
  Bug 1 — Proper URL validation (rejects names, words, sentences)
  Bug 2 — IP octet range validation (0-255 only)
  Bug 3 — Domain structure validation (rejects 'hello', 'brijesh', etc.)
  Bug 4 — Invalid scheme rejection (ftp://, file://, javascript:, etc.)
  Bug 5 — Empty hostname detection
  Bug 6 — Invalid input returns severity='Invalid', score=0, never scanned
"""

import re
import ipaddress
import urllib.parse
from typing import Any

# Allowed URL schemes
ALLOWED_SCHEMES = {"http", "https"}

# Suspicious TLDs
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
    ".click", ".download", ".loan", ".work", ".win",
    ".stream", ".gdn", ".racing", ".trade", ".review",
}

TRUSTED_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "facebook.com", "twitter.com", "instagram.com",
    "github.com", "stackoverflow.com", "wikipedia.org",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl",
    "short.ly", "rebrand.ly", "is.gd", "cutt.ly", "tiny.cc", "buff.ly",
}

DECEPTIVE_PATHS = [
    "login", "signin", "verify", "account", "secure",
    "update", "confirm", "banking", "paypal", "wallet", "password", "credential",
]

SUSPICIOUS_PARAMS = [
    "redirect", "url", "return", "next", "goto", "forward", "target", "link", "src",
]


def _validate_url(raw: str) -> tuple[bool, str, str]:
    """
    Strict URL validation.
    Returns (is_valid, error_message, normalised_url).

    Rules:
    - Must be non-empty and at least 4 chars
    - If it has a scheme, it must be http:// or https:// only
    - Must have a valid hostname (not empty)
    - Hostname must be a valid domain OR valid IP address
    - Domain must have a proper TLD (2+ chars)
    - Plain words / names / sentences without dots are rejected
    """
    raw = raw.strip()

    # 1. Empty check
    if not raw:
        return False, "❌ Please enter a URL to scan.", ""

    if len(raw) < 4:
        return False, "❌ Input too short. Enter a valid URL like https://example.com", ""

    # 2. Reject obviously bad schemes BEFORE adding https://
    lower = raw.lower()
    for bad in ("javascript:", "file://", "ftp://", "data:", "vbscript:", "mailto:"):
        if lower.startswith(bad):
            return False, (
                f"❌ Scheme '{bad.rstrip(':')}' is not allowed. "
                "Only http:// and https:// URLs can be scanned."
            ), ""

    # 3. Normalise — prepend https:// only if no scheme present
    if "://" not in raw:
        normalised = "https://" + raw
    else:
        normalised = raw

    # 4. Parse
    try:
        parsed = urllib.parse.urlparse(normalised)
    except Exception:
        return False, "❌ Could not parse URL. Please check the format.", ""

    # 5. Scheme must be http or https
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        return False, (
            f"❌ Scheme '{scheme}://' is not allowed. "
            "Only http:// and https:// URLs are supported."
        ), ""

    # 6. Hostname must not be empty
    hostname = parsed.hostname or ""
    if not hostname:
        return False, (
            "❌ No hostname found in the URL. "
            "Make sure you enter a complete URL like https://example.com"
        ), ""

    hostname = hostname.lower().lstrip("www.")

    # 7. Check if hostname is an IP address
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
        try:
            ipaddress.IPv4Address(hostname)  # validates 0-255 per octet
        except ipaddress.AddressValueError:
            return False, (
                f"❌ '{hostname}' is not a valid IP address. "
                "Each octet must be between 0 and 255."
            ), ""
        return True, "", normalised  # valid IP-based URL

    # 8. Hostname must look like a domain (contain a dot, have valid TLD)
    if "." not in hostname:
        return False, (
            f"❌ '{raw}' is not a valid URL or domain. "
            "A domain must contain a dot (e.g. example.com, paypal.com). "
            "Plain words or names cannot be scanned by the URL Scanner."
        ), ""

    parts = hostname.split(".")
    tld = parts[-1]

    # TLD must be 2+ letters only
    if len(tld) < 2 or not tld.isalpha():
        return False, (
            f"❌ '{hostname}' does not have a valid TLD. "
            "A valid TLD must be at least 2 letters (e.g. .com, .in, .org)."
        ), ""

    # Each label in the domain must be valid (letters, digits, hyphens)
    domain_label_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$')
    for label in parts:
        if not label:
            return False, f"❌ Invalid domain format: '{hostname}'.", ""
        if not domain_label_pattern.match(label):
            return False, (
                f"❌ '{hostname}' contains invalid characters. "
                "Domain labels can only contain letters, digits, and hyphens."
            ), ""

    return True, "", normalised


def _levenshtein(a: str, b: str) -> int:
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[0]
        dp[0] = i
        for j in range(1, n + 1):
            temp = dp[j]
            dp[j] = prev if a[i-1] == b[j-1] else 1 + min(prev, dp[j], dp[j-1])
            prev = temp
    return dp[n]


def _check_typosquat(domain: str) -> list:
    hits = []
    # Remove TLD for comparison
    domain_base = re.sub(r'\.[a-zA-Z]{2,}$', '', domain)
    for target in TRUSTED_DOMAINS:
        target_base = re.sub(r'\.[a-zA-Z]{2,}$', '', target)
        dist = _levenshtein(domain_base, target_base)
        if 0 < dist <= 2 and domain != target:
            hits.append(f"Possible typosquat of {target} (edit distance={dist})")
    return hits


def analyze_url(url: str) -> dict[str, Any]:
    """
    Analyze a URL for threat indicators.
    Performs strict validation first — invalid input is rejected cleanly.
    """
    url = (url or "").strip()

    # ── Bug 7 fix: validate BEFORE any analysis ───────────────────────────────
    is_valid, err_msg, normalised = _validate_url(url)

    if not is_valid:
        # Bug 6 fix: return Invalid severity, score 0 — no scan performed
        return {
            "url":           url,
            "domain":        "",
            "score":         0.0,
            "severity":      "Invalid",
            "indicators":    err_msg,
            "redirect_chain": "",
            "valid":         False,
        }

    # From here: URL is structurally valid — perform threat analysis
    try:
        parsed = urllib.parse.urlparse(normalised)
    except Exception:
        return {
            "url": url, "domain": "", "score": 0.0,
            "severity": "Invalid", "indicators": "❌ Could not parse URL.",
            "redirect_chain": "", "valid": False,
        }

    domain = (parsed.hostname or "").lower().lstrip("www.")
    indicators = []
    score = 0.0

    # No HTTPS
    if normalised.startswith("http://"):
        score += 15
        indicators.append("⚠️ No HTTPS — connection is unencrypted")

    # URL shortener
    if any(s in domain for s in URL_SHORTENERS):
        score += 20
        indicators.append("⚠️ URL shortener detected — real destination is hidden")

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 25
            indicators.append(f"🔴 Suspicious TLD: {tld}")
            break

    # Raw IP address (Bug 2 fix — already validated above via ipaddress module)
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
        score += 30
        indicators.append("🔴 IP address used instead of domain name")

    # Excessive subdomains
    parts = domain.split(".")
    if len(parts) >= 5:
        score += 20
        indicators.append(f"⚠️ Excessive subdomains ({len(parts)} levels): {domain}")

    # Deceptive path keywords
    path_lower = parsed.path.lower()
    matched_paths = [kw for kw in DECEPTIVE_PATHS if kw in path_lower]
    if matched_paths:
        score += len(matched_paths) * 8
        indicators.append(f"⚠️ Sensitive path keywords: {', '.join(matched_paths)}")

    # Open redirect parameters
    qs = urllib.parse.parse_qs(parsed.query)
    hit_params = [p for p in SUSPICIOUS_PARAMS if p in qs]
    if hit_params:
        score += 20
        indicators.append(f"🔴 Open redirect parameters: {', '.join(hit_params)}")

    # Typosquatting
    typo_hits = _check_typosquat(domain)
    for hit in typo_hits:
        score += 35
        indicators.append(f"🔴 {hit}")

    # Unusually long domain
    if len(domain) > 40:
        score += 15
        indicators.append(f"⚠️ Unusually long domain ({len(domain)} chars)")

    # Punycode / IDN homograph
    if "xn--" in domain:
        score += 30
        indicators.append("🔴 Punycode/homograph domain detected (IDN attack risk)")

    # Known trusted domain bonus
    if domain in TRUSTED_DOMAINS and not typo_hits:
        score = max(0.0, score - 20)
        indicators.append("✅ Domain matches known trusted site")

    if not indicators:
        indicators.append("✅ No suspicious URL patterns detected")

    score = min(round(score, 2), 100.0)

    if score >= 65:
        severity = "Critical"
    elif score >= 40:
        severity = "High"
    elif score >= 20:
        severity = "Medium"
    else:
        severity = "Low"

    return {
        "url":            normalised,
        "domain":         domain,
        "score":          score,
        "severity":       severity,
        "indicators":     " | ".join(indicators),
        "redirect_chain": "",
        "valid":          True,
    }
