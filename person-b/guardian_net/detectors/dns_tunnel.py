"""DNS Tunnelling detector.

Inspects DNS queries and aggregate domain statistics for tunnelling indicators:
- Shannon entropy of subdomains
- Subdomain and label lengths
- Unusual query types (TXT, NULL) vs standard (A, AAAA)
- High cardinality of unique subdomains under a single apex
- Strict privacy: NEVER stores raw subdomain payloads in evidence records.
  Only metrics (entropy, label lengths, query count, SHA256 digest) are retained.
"""
from __future__ import annotations

import collections
import hashlib
import math
from typing import Any

from ..dnswire import TYPE_NULL, TYPE_TXT
from ..evidence import create_evidence


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def extract_domain_parts(qname: str) -> tuple[str, str]:
    """Split query name into (subdomain, registrable_domain)."""
    clean = qname.strip().strip(".").lower()
    labels = clean.split(".")
    if len(labels) <= 2:
        return "", clean
    reg_domain = ".".join(labels[-2:])
    subdomain = ".".join(labels[:-2])
    return subdomain, reg_domain


class DNSTunnelDetector:
    """Stateful detector tracking per-domain query volume, types, and entropy."""

    def __init__(
        self,
        entropy_threshold: float = 3.6,
        label_length_threshold: int = 40,
        subdomain_cardinality_threshold: int = 10,
        txt_null_ratio_threshold: float = 0.5,
    ) -> None:
        self.entropy_threshold = entropy_threshold
        self.label_length_threshold = label_length_threshold
        self.subdomain_cardinality_threshold = subdomain_cardinality_threshold
        self.txt_null_ratio_threshold = txt_null_ratio_threshold

        # Tracking state per registrable domain:
        # {reg_domain: {"subdomains": set(), "txt_null_count": int, "total_queries": int}}
        self._domain_stats: dict[str, dict[str, Any]] = collections.defaultdict(
            lambda: {"subdomains": set(), "txt_null_count": 0, "total_queries": 0}
        )

    def analyze_query(
        self,
        qname: str,
        qtype: int,
        timestamp: int | None = None,
    ) -> dict[str, Any] | None:
        subdomain, reg_domain = extract_domain_parts(qname)
        if not reg_domain or not subdomain:
            return None

        sub_entropy = round(shannon_entropy(subdomain), 3)
        labels = subdomain.split(".")
        max_label_len = max(len(lbl) for lbl in labels) if labels else 0
        total_qname_len = len(qname)

        stats = self._domain_stats[reg_domain]
        stats["total_queries"] += 1
        # Store only hashed subdomains to prevent memory payload leakage
        sub_hash = hashlib.sha256(subdomain.encode("utf-8")).hexdigest()[:12]
        stats["subdomains"].add(sub_hash)

        is_txt_null = qtype in (TYPE_TXT, TYPE_NULL)
        if is_txt_null:
            stats["txt_null_count"] += 1

        reasons: list[str] = []
        score = 0.0

        if sub_entropy >= self.entropy_threshold:
            reasons.append(f"High subdomain Shannon entropy: {sub_entropy:.2f} bits (threshold {self.entropy_threshold})")
            score += 0.35

        if max_label_len >= self.label_length_threshold:
            reasons.append(f"Unusually long DNS label: {max_label_len} characters")
            score += 0.30

        if total_qname_len >= 100:
            reasons.append(f"Elevated total query length: {total_qname_len} characters")
            score += 0.15

        cardinality = len(stats["subdomains"])
        if cardinality >= self.subdomain_cardinality_threshold:
            reasons.append(f"High unique subdomain cardinality ({cardinality}) under {reg_domain}")
            score += 0.25

        if stats["total_queries"] >= 5:
            ratio = stats["txt_null_count"] / stats["total_queries"]
            if ratio >= self.txt_null_ratio_threshold:
                reasons.append(f"High proportion of TXT/NULL records: {ratio * 100:.1f}%")
                score += 0.25

        score = min(score, 0.99)
        if score < 0.35:
            return None

        # Privacy assurance: entity contains the registrable domain and metadata contains stats only, NO plaintext subdomains
        return create_evidence(
            source="DNS",
            event_type="DNS_TUNNEL",
            entity_type="DOMAIN",
            entity_value=reg_domain,
            score=score,
            reasons=reasons,
            timestamp=timestamp,
            metadata={
                "registrable_domain": reg_domain,
                "subdomain_entropy": sub_entropy,
                "max_label_length": max_label_len,
                "total_query_length": total_qname_len,
                "subdomain_sample_hash": sub_hash,
                "unique_subdomain_count": cardinality,
            },
        )
