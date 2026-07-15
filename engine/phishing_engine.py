"""
Phishing Detection Engine
Rule-based NLP + pattern matching for email/message analysis.
"""

import re
from typing import Any

URGENCY_WORDS = [
    "urgent", "immediately", "act now", "limited time", "expires",
    "last chance", "final notice", "account suspended", "verify now",
    "confirm immediately", "24 hours", "48 hours", "asap",
]

THREAT_WORDS = [
    "your account will be closed", "suspended", "terminated",
    "unauthorized access", "security breach", "illegal activity",
    "legal action", "arrest", "lawsuit", "irs", "fbi", "police",
]

LURE_WORDS = [
    "winner", "won", "prize", "lottery", "congratulations",
    "free gift", "reward", "selected", "exclusive offer",
    "claim your", "bitcoin", "crypto", "investment opportunity",
    "double your money",
]

CREDENTIAL_WORDS = [
    "enter your password", "update your payment",
    "verify your identity", "confirm your account",
    "provide your ssn", "social security", "credit card",
    "bank account", "pin number", "mother's maiden",
]

IMPERSONATION_ENTITIES = [
    "paypal", "amazon", "microsoft", "apple", "google", "facebook",
    "netflix", "bank of america", "chase", "wells fargo", "irs",
    "social security", "fedex", "ups", "dhl",
]

SUSPICIOUS_URL_PATTERNS = [
    r"bit\.ly", r"tinyurl\.com", r"t\.co", r"ow\.ly", r"goo\.gl",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"[a-z]{15,}\.(tk|ml|ga|cf|gq|xyz|top|click|download|loan|work)",
    r"login[-_]?[a-z]+\.com",
    r"secure[-_]?[a-z]+\.com",
    r"update[-_]?[a-z]+\.com",
    r"verify[-_]?[a-z]+\.com",
    r"account[-_]?[a-z]+\.com",
]

MALICIOUS_ATTACHMENTS = [
    r"\.(exe|bat|cmd|scr|pif|vbs|js|jar|ps1|sh|dmg)",
]

SPF_FAIL_PATTERNS = [
    "spf=fail", "spf=softfail", "dmarc=fail", "dkim=fail",
    "authentication-results: fail",
]

# Minimum length for phishing analysis to make sense
MIN_TEXT_LENGTH = 20


def _is_valid_input(text: str) -> tuple[bool, str]:
    """
    Validate that input looks like an actual email/SMS/message.
    Rejects: code snippets, random letters, single words, numbers only.
    """
    text = text.strip()
    if not text:
        return False, "❌ Please enter a message or email text to analyze."

    if len(text) < MIN_TEXT_LENGTH:
        return False, (
            f"❌ Input too short ({len(text)} characters). "
            "Phishing Detector analyzes email bodies or SMS messages. "
            "Please paste a full message (at least 20 characters)."
        )

    # Must have at least 3 real English words (2+ letters each)
    words = re.findall(r'[a-zA-Z]{2,}', text)
    if len(words) < 3:
        return False, (
            "❌ Input does not look like a message. "
            "Please paste an email body, SMS, or suspicious text for analysis."
        )

    # Reject if it looks like code (high density of {}, (), ;, =, <>, //)
    code_chars = text.count('{') + text.count('}') + text.count(';') + \
                 text.count('(') + text.count(')')
    if code_chars > 5 and code_chars / max(len(text), 1) > 0.05:
        return False, (
            "❌ This looks like code, not an email or message. "
            "Phishing Detector only analyzes human-readable email/SMS/message text."
        )

    # Reject Python/SQL/JS code keywords as primary content
    code_keywords = ['def ', 'class ', 'import ', 'return ', 'elif ', 'while ',
                     '__init__', 'SELECT ', 'INSERT ', 'function(', 'var ', 'const ']
    text_check = text.lower()
    code_hits = sum(1 for kw in code_keywords if kw.lower() in text_check)
    if code_hits >= 2:
        return False, (
            "❌ This looks like code or SQL, not an email or message. "
            "Please paste actual message content to analyze."
        )

    # Reject if it's mostly random characters (very low real-word ratio)
    total_chars = len(text.replace(" ", "").replace("\n", ""))
    word_chars  = sum(len(w) for w in words)
    if total_chars > 10 and word_chars / max(total_chars, 1) < 0.4:
        return False, (
            "❌ Input appears to be random characters, not a message. "
            "Please paste an actual email body or SMS text."
        )

    # Reject if it looks like a URL (no spaces, contains domain pattern)
    stripped = text.strip()
    if " " not in stripped and re.match(r'^https?://', stripped):
        return False, (
            "❌ This looks like a URL, not a message. "
            "To scan a URL, please use the URL Scanner tool."
        )

    return True, ""


def _score_text(text_lower: str) -> tuple[float, list]:
    score = 0.0
    indicators = []

    matches = [w for w in URGENCY_WORDS if w in text_lower]
    if matches:
        score += len(matches) * 8
        indicators.append(f"⚠️ Urgency language: {', '.join(matches[:3])}")

    matches = [w for w in THREAT_WORDS if w in text_lower]
    if matches:
        score += len(matches) * 12
        indicators.append(f"🔴 Threatening language: {', '.join(matches[:3])}")

    matches = [w for w in LURE_WORDS if w in text_lower]
    if matches:
        score += len(matches) * 10
        indicators.append(f"🔴 Reward/lure language: {', '.join(matches[:3])}")

    matches = [w for w in CREDENTIAL_WORDS if w in text_lower]
    if matches:
        score += len(matches) * 15
        indicators.append(f"🔴 Credential harvesting: {', '.join(matches[:3])}")

    matches = [e for e in IMPERSONATION_ENTITIES if e in text_lower]
    if matches:
        score += len(matches) * 10
        indicators.append(f"⚠️ Impersonation attempt: {', '.join(matches[:3])}")

    url_hits = []
    for pattern in SUSPICIOUS_URL_PATTERNS:
        found = re.findall(pattern, text_lower)
        url_hits.extend(found)
    if url_hits:
        score += len(url_hits) * 12
        indicators.append(f"🔴 Suspicious URL patterns detected ({len(url_hits)} matches)")

    att_hits = []
    for pattern in MALICIOUS_ATTACHMENTS:
        att_hits.extend(re.findall(pattern, text_lower))
    if att_hits:
        score += 25
        indicators.append("🔴 Potentially malicious attachment type referenced")

    for fail_pat in SPF_FAIL_PATTERNS:
        if fail_pat in text_lower:
            score += 20
            indicators.append("🔴 Email authentication failure (SPF/DKIM/DMARC)")
            break

    excl = text_lower.count("!")
    if excl >= 3:
        score += excl * 2
        indicators.append(f"⚠️ Excessive punctuation ({excl} exclamation marks)")

    return score, indicators


def analyze_phishing(text: str) -> dict[str, Any]:
    """
    Analyze email/message text for phishing indicators.
    Rejects short inputs, names, single words.
    """
    text = text.strip() if text else ""

    # Validation
    valid, err_msg = _is_valid_input(text)
    if not valid:
        return {
            "input_text": text[:500],
            "score": 0.0,
            "severity": "Invalid",
            "indicators": err_msg,
            "verdict": err_msg,
            "indicators_list": [err_msg],
        }

    text_lower = text.lower()
    score, indicators = _score_text(text_lower)
    score = min(score, 100.0)

    if score >= 70:
        severity = "Critical"
        verdict = "🔴 HIGH RISK PHISHING — Do NOT interact with this message"
    elif score >= 45:
        severity = "High"
        verdict = "🟠 LIKELY PHISHING — Treat with extreme caution"
    elif score >= 20:
        severity = "Medium"
        verdict = "🟡 SUSPICIOUS — Verify the sender before taking any action"
    else:
        severity = "Low"
        verdict = "🟢 LIKELY SAFE — No strong phishing indicators detected"

    if not indicators:
        indicators.append("✅ No significant phishing indicators found")

    return {
        "input_text": text[:500],
        "score": round(score, 2),
        "severity": severity,
        "indicators": " | ".join(indicators),
        "verdict": verdict,
        "indicators_list": indicators,
    }
