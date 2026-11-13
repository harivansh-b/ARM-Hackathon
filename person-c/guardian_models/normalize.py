"""Deterministic normalization shared by all Person C detectors."""

import re
import unicodedata
from urllib.parse import urlsplit, urlunsplit

ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")
URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"]+")
DEVANAGARI_RE = re.compile(r"[\u0900-\u097f]")
LATIN_RE = re.compile(r"[a-z]", re.IGNORECASE)


def normalize_text(text: str) -> str:
    """Canonicalise text before matching or model inference.

    NFKC joins visually equivalent Unicode forms, zero-width characters are
    removed, and whitespace/case are made deterministic.
    """
    text = unicodedata.normalize("NFKC", text)
    text = ZERO_WIDTH.sub("", text)
    return " ".join(text.casefold().split())


def detect_language(text: str) -> str:
    """Return a lightweight, offline language label for UI and policy routing.

    This is intentionally heuristic: it does not claim linguistic certainty and
    avoids adding a large language-identification dependency to the ARM target.
    """
    clean = normalize_text(URL_RE.sub(" ", text))
    devanagari = len(DEVANAGARI_RE.findall(clean))
    latin = len(LATIN_RE.findall(clean))
    if devanagari and latin:
        return "hi" if latin <= 4 or devanagari >= latin * 2 else "hi-en"
    if devanagari:
        return "hi"
    if latin:
        hinglish_markers = ("aapka", "apka", "karo", "kripya", "khata", "band", "verify", "link", "bhejo")
        if any(marker in clean.split() for marker in hinglish_markers):
            return "hinglish"
        return "en"
    return "unknown"


def extract_urls(text: str) -> list[str]:
    """Extract unique HTTP(S) and ``www`` URLs without making network calls."""
    urls: list[str] = []
    for raw in URL_RE.findall(text):
        candidate = raw.rstrip(".,!?;:)]}")
        if candidate.lower().startswith("www."):
            candidate = "https://" + candidate
        parts = urlsplit(candidate)
        if parts.netloc:
            urls.append(normalize_url(candidate))
    return list(dict.fromkeys(urls))


def normalize_url(url: str) -> str:
    """Return a stable URL representation for comparison and evidence IDs."""
    candidate = url.strip()
    if candidate.lower().startswith("www."):
        candidate = "https://" + candidate
    parts = urlsplit(candidate)
    host = parts.hostname.casefold() if parts.hostname else ""
    try:
        port = parts.port
    except ValueError:
        port = None
    netloc = host
    if port and not ((parts.scheme.casefold() == "https" and port == 443) or (parts.scheme.casefold() == "http" and port == 80)):
        netloc = f"{host}:{port}"
    path = parts.path or "/"
    return urlunsplit((parts.scheme.casefold() or "https", netloc, path, parts.query, ""))


def registrable_domain(url: str) -> str:
    """Return a simple registrable-domain approximation without DNS access."""
    host = urlsplit(normalize_url(url)).hostname or ""
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host
