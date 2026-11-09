"""Explainable baseline detectors. Replace with trained models behind the same API."""

import hashlib
import re
import time
from dataclasses import asdict

from .evidence import EvidenceRecord
from .normalize import extract_urls, normalize_text, normalize_url, registrable_domain

URGENCY = ("urgent", "immediately", "now", "24 hours", "suspended", "blocked", "last warning")
SECRETS = ("otp", "pin", "cvv", "password", "passcode", "verification code")
MONEY = ("pay", "fee", "refund", "prize", "cash", "transfer", "claim")
IMPERSONATION = ("bank", "government", "courier", "delivery", "tax", "support", "account")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly"}
LOOKALIKE_MARKERS = ("paypa1", "micr0soft", "g00gle", "faceb00k", "amaz0n", "netfl1x")


def _id(source: str, value: str) -> str:
    digest = hashlib.sha256(f"{source}:{value}".encode()).hexdigest()[:12].upper()
    return f"{source[0]}{digest}"


def _tier(score: float) -> str:
    if score >= 0.85:
        return "CRITICAL"
    if score >= 0.65:
        return "HIGH"
    if score >= 0.35:
        return "WARN"
    return "INFO"


def analyze_sms(text: str, timestamp: int | None = None, sender: str | None = None) -> dict:
    clean = normalize_text(text)
    reasons: list[str] = []
    score = 0.0
    for label, words, weight in (("Urgency language", URGENCY, 0.22), ("Sensitive credential request", SECRETS, 0.36), ("Payment or reward language", MONEY, 0.18), ("Impersonation context", IMPERSONATION, 0.12)):
        if any(word in clean for word in words):
            reasons.append(label)
            score += weight
    urls = extract_urls(text)
    if urls:
        reasons.append("Link present")
        score += 0.18
    score = min(score, 0.99)
    value = sender or hashlib.sha256(clean.encode()).hexdigest()[:16]
    record = EvidenceRecord(_id("SMS", value), "SMS", "SMISHING", timestamp or int(time.time()), {"type": "SMS", "value": value}, _tier(score), round(score, 4), reasons)
    result = record.to_dict()
    result["extracted_urls"] = urls
    return result


def analyze_url(url: str, timestamp: int | None = None) -> dict:
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
    record = EvidenceRecord(_id("URL", normalized), "URL", "PHISHING_URL", timestamp or int(time.time()), {"type": "DOMAIN", "value": domain}, _tier(score), round(score, 4), reasons)
    result = record.to_dict()
    result["normalized_url"] = normalized
    return result
