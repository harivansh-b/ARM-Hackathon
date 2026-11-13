"""Explainable baseline detectors. Replace with trained models behind the same API."""

import hashlib
import re
import time
from dataclasses import asdict

from .evidence import EvidenceRecord
from .normalize import detect_language, extract_urls, normalize_text, normalize_url, registrable_domain

URGENCY = ("urgent", "immediately", "now", "24 hours", "suspended", "blocked", "last warning", "तुरंत", "अभी", "बंद", "निलंबित", "आखिरी चेतावनी", "jaldi", "turant", "abhi", "block ho", "band ho")
SECRETS = ("otp", "pin", "cvv", "password", "passcode", "verification code", "ओटीपी", "पासवर्ड", "पिन", "गोपनीय कोड", "otp bhejo", "code bhejo")
MONEY = ("pay", "fee", "refund", "prize", "cash", "transfer", "claim", "भुगतान", "फीस", "इनाम", "रिफंड", "पैसे", "jama", "bhugtan", "inaam", "paisa")
IMPERSONATION = ("bank", "government", "courier", "delivery", "tax", "support", "account", "बैंक", "सरकार", "डिलीवरी", "खाता", "केवाईसी", "kyc", "customer care", "customer-care")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly"}
LOOKALIKE_MARKERS = ("paypa1", "micr0soft", "g00gle", "faceb00k", "amaz0n", "netfl1x")

SIGNAL_ACTIONS = {
    "Sensitive credential request": "Never share OTP, PIN, CVV, or passwords.",
    "Suspicious urgency": "Pause and verify through the organisation's official app or website.",
    "Payment or reward language": "Do not pay a fee or transfer money to claim a reward.",
    "Impersonation context": "Contact the organisation using a trusted number, not the SMS.",
    "Link present": "Do not open the link until its destination is independently verified.",
}


def _id(source: str, value: str) -> str:
    digest = hashlib.sha256(f"{source}:{value}".encode()).hexdigest()[:12].upper()
    return f"{source[0]}{digest}"


def risk_tier_for_score(score: float) -> str:
    if score >= 0.85:
        return "CRITICAL"
    if score >= 0.65:
        return "HIGH"
    if score >= 0.35:
        return "WARN"
    return "INFO"


def analyze_sms(text: str, timestamp: int | None = None, sender: str | None = None) -> dict:
    """Analyse one SMS using bounded, offline rules and return Core evidence.

    This function never opens URLs, sends data, or claims that a low score is
    proof of safety. Its output is intentionally JSON-serialisable so it can be
    passed to the Core service or shown directly in a demo UI.
    """
    clean = normalize_text(text)
    language = detect_language(text)
    reasons: list[str] = []
    matched_signals: list[dict[str, str]] = []
    score = 0.0
    for label, words, weight, public_label in (("Urgency language", URGENCY, 0.22, "Suspicious urgency"), ("Sensitive credential request", SECRETS, 0.36, "Sensitive credential request"), ("Payment or reward language", MONEY, 0.18, "Payment or reward language"), ("Impersonation context", IMPERSONATION, 0.12, "Impersonation context")):
        matched = next((word for word in words if word in clean), None)
        if matched:
            reasons.append(label)
            matched_signals.append({"signal": public_label, "matched_text": matched, "action": SIGNAL_ACTIONS[public_label]})
            score += weight
    urls = extract_urls(text)
    if urls:
        reasons.append("Link present")
        matched_signals.append({"signal": "Link present", "matched_text": urls[0], "action": SIGNAL_ACTIONS["Link present"]})
        score += 0.18
    if sender and (sender.startswith("+") or sender.isdigit()):
        reasons.append("Unverified numeric sender")
        matched_signals.append({"signal": "Unverified numeric sender", "matched_text": sender, "action": "Verify the sender independently before responding."})
        score += 0.05
    score = min(score, 0.99)
    value = sender or hashlib.sha256(clean.encode()).hexdigest()[:16]
    record = EvidenceRecord(_id("SMS", value), "SMS", "SMISHING", timestamp or int(time.time()), {"type": "SMS", "value": value}, risk_tier_for_score(score), round(score, 4), reasons)
    result = record.to_dict()
    result["extracted_urls"] = urls
    result["language"] = language
    result["language_label"] = {"en": "English", "hi": "Hindi", "hinglish": "Hinglish", "hi-en": "Hindi + English", "unknown": "Unknown"}.get(language, "Unknown")
    result["matched_signals"] = matched_signals
    result["safe_action"] = "Verify independently; do not click links or share credentials." if score >= 0.35 else "No strong scam signal detected; remain cautious with unexpected requests."
    result["explanation"] = " ".join(signal["signal"] + ": " + signal["action"] for signal in matched_signals) or "No strong rule-based scam indicators were found."
    return result


def analyze_url(url: str, timestamp: int | None = None) -> dict:
    """Analyse URL structure only; no DNS lookup or network request is made."""
    normalized = normalize_url(url)
    domain = registrable_domain(normalized)
    host = normalized.split("/", 3)[2].split(":", 1)[0]
    reasons: list[str] = []
    score = 0.0
    if host in SHORTENERS:
        reasons.append("Opaque URL shortener")
        score += 0.35
    if re.search(r"xn--|\d+\.\d+\.\d+\.\d+", host):
        reasons.append("Punycode or IP-literal host")
        score += 0.3
    if host.count(".") >= 3:
        reasons.append("Unusually deep subdomain")
        score += 0.15
    if any(marker in host for marker in LOOKALIKE_MARKERS):
        reasons.append("Look-alike brand spelling")
        score += 0.35
    if any(token in normalized.casefold() for token in ("login", "verify", "secure", "update", "wallet", "account")):
        reasons.append("Credential or account-themed path")
        score += 0.2
    if "@" in normalized:
        reasons.append("User-information delimiter in URL")
        score += 0.25
    score = min(score, 0.99)
    record = EvidenceRecord(_id("URL", normalized), "URL", "PHISHING_URL", timestamp or int(time.time()), {"type": "DOMAIN", "value": domain}, risk_tier_for_score(score), round(score, 4), reasons)
    result = record.to_dict()
    result["normalized_url"] = normalized
    return result
