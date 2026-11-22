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
# India-relevant scam lures and coercion. Matched on word boundaries (not substrings) to limit false alarms.
LURE = (r"\bkbc\b", r"lucky draw", r"\blottery\b", r"\bjackpot\b", r"you(?: have)? won", r"\bearn\b.{0,25}(?:rs\.?|₹|inr)\s?\d",
        r"(?:rs\.?|₹|inr)\s?[\d,]+\s?(?:daily|per day|a day)", r"liking .{0,20}videos")
WEAK_LURE = (r"\bcongratulations?\b|\bcongrats\b", r"part[- ]time job", r"work from home", r"\bdaily income\b")
THREAT = (r"illegal", r"\barrest", r"legal action", r"\bcustoms\b", r"narcotics", r"digital arrest", r"will be (?:cut|disconnected|deactivated|blocked|suspended)",
          r"\bdisconnection\b", r"press 1\b", r"\bpolice\b", r"court notice", r"penalty")
# A message that WARNS about sharing a code (legitimate OTP / KYC notices) is not a message that ASKS for one.
PROTECT = re.compile(r"(?:do not|don't|dont|never|won't|will not)\s+(?:\w+\s+){0,3}?(?:share|disclose|give|reveal|tell|ask for|ask)\b(?:\s+\w+){0,4}|(?:share|batayein|batana)\s+na\s+\w+|साझा\s+न\s+करें|शेयर\s+न\s+करें|किसी\s+को\s+न\s+बताएं|na\s+batayein|kisi\s+ko\s+na", re.I)
ASKS_FOR_SECRET = re.compile(r"\b(?:share|send|enter|give|tell|reply|provide|bhejo|bhejein|daalein|batao|batayein)\b[^.!?]{0,25}\b(?:otp|pin|cvv|password|passcode)\b|\b(?:otp|pin|cvv)\b[^.!?]{0,15}\b(?:bhejo|bhejein|bhej)\b|(?:otp|ओटीपी|पिन)\s+(?:भेजें|साझा करें|बताएं|दें)", re.I)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly"}
LOOKALIKE_MARKERS = ("paypa1", "micr0soft", "g00gle", "faceb00k", "amaz0n", "netfl1x")

SIGNAL_ACTIONS = {
    "Sensitive credential request": "Never share OTP, PIN, CVV, or passwords.",
    "Suspicious urgency": "Pause and verify through the organisation's official app or website.",
    "Payment or reward language": "Do not pay a fee or transfer money to claim a reward.",
    "Impersonation context": "Contact the organisation using a trusted number, not the SMS.",
    "Link present": "Do not open the link until its destination is independently verified.",
    "Prize or job lure": "Do not respond to unexpected prize, lottery or job offers; never pay a fee to receive money or work.",
    "Threat or coercion": "Authorities and utilities do not demand calls or payment by SMS; verify through their official channel.",
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
        if matched and label == "Sensitive credential request" and PROTECT.search(clean) and not ASKS_FOR_SECRET.search(PROTECT.sub(" ", clean)):
            matched = None  # warning text ("never share your OTP"), not a request
        if matched:
            reasons.append(label)
            matched_signals.append({"signal": public_label, "matched_text": matched, "action": SIGNAL_ACTIONS[public_label]})
            score += weight
    for label, patterns, weight in (("Prize or job lure", LURE, 0.45), ("Prize or job lure", WEAK_LURE, 0.15), ("Threat or coercion", THREAT, 0.30)):
        if any(m["signal"] == label for m in matched_signals):
            continue
        hit = next((m for p in patterns if (m := re.search(p, clean))), None)
        if hit:
            reasons.append(label)
            matched_signals.append({"signal": label, "matched_text": hit.group(0), "action": SIGNAL_ACTIONS[label]})
            score += weight
    names = {m["signal"] for m in matched_signals}
    if "Suspicious urgency" in names and ({"Impersonation context", "Threat or coercion"} & names):
        score += 0.10  # urgency combined with authority or coercion is a classic scam pattern
        reasons.append("Urgency combined with authority or threat")
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
