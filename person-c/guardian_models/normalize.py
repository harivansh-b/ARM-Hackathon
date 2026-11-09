"""Deterministic normalization shared by all Person C detectors."""

import re
import unicodedata
from urllib.parse import urlsplit, urlunsplit

ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")
URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"]+")


def normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = ZERO_WIDTH.sub("", text)
    return " ".join(text.casefold().split())


def extract_urls(text: str) -> list[str]:
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
    host = urlsplit(normalize_url(url)).hostname or ""
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host
