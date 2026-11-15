"""Structured evidence contract conforming to Person C's specification.

Contract fields:
    evidence_id: stable hash of source + entity value (e.g. D1A2B3C4D5E6, C7F8A9B0C1D2)
    source: "DNS" | "CONNECTION"
    event_type: "DNS_QUERY" | "DNS_TUNNEL" | "DGA" | "BEACON" | "PORT_SCAN" | "EXFILTRATION" | "DENYLIST_MATCH"
    timestamp: Unix epoch integer seconds
    entity: {"type": "DOMAIN" | "IP" | "FLOW", "value": str}
    risk_tier: "INFO" | "WARN" | "HIGH" | "CRITICAL"
    score: float 0.0 .. 1.0
    reasons: list[str]
    related_ids: list[str]

Privacy & security constraint:
    Never store packet payloads. For DNS tunnelling, store aggregate features
    (entropy, label lengths, query count/frequency, hash) rather than raw subdomains.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


def make_evidence_id(source: str, value: str) -> str:
    """Stable ID hash matching Person C's _id scheme: f'{source[0]}{digest[:12].upper()}'."""
    digest = hashlib.sha256(f"{source}:{value}".encode("utf-8")).hexdigest()[:12].upper()
    prefix = source[0] if source else "E"
    return f"{prefix}{digest}"


def risk_tier_for_score(score: float) -> str:
    """Convert a 0.0..1.0 risk score into a risk tier matching Person C."""
    if score >= 0.85:
        return "CRITICAL"
    if score >= 0.65:
        return "HIGH"
    if score >= 0.35:
        return "WARN"
    return "INFO"


@dataclass(frozen=True)
class NetworkEvidenceRecord:
    evidence_id: str
    source: str
    event_type: str
    timestamp: int
    entity: dict[str, Any]
    risk_tier: str
    score: float
    reasons: list[str] = field(default_factory=list)
    related_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.source not in {"DNS", "CONNECTION", "SMS", "URL"}:
            raise ValueError(f"Invalid source: {self.source}")
        if self.risk_tier not in {"INFO", "WARN", "HIGH", "CRITICAL"}:
            raise ValueError(f"Invalid risk tier: {self.risk_tier}")
        if not 0.0 <= self.score <= 1.0:
            raise ValueError(f"Score must be between 0.0 and 1.0: {self.score}")
        if not self.evidence_id:
            raise ValueError("evidence_id is required")
        if not isinstance(self.entity, dict) or "type" not in self.entity or "value" not in self.entity:
            raise ValueError("entity must be a dict with 'type' and 'value'")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        # Flatten metadata into top-level for convenience/contract compatibility if needed
        # while keeping the core fields exact
        return data


def create_evidence(
    source: str,
    event_type: str,
    entity_type: str,
    entity_value: str,
    score: float,
    reasons: list[str],
    related_ids: list[str] | None = None,
    timestamp: int | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Factory helper to construct, validate, and serialize an evidence dict."""
    score = max(0.0, min(1.0, float(score)))
    ts = int(time.time()) if timestamp is None else int(timestamp)
    eid = make_evidence_id(source, entity_value)
    tier = risk_tier_for_score(score)
    rec = NetworkEvidenceRecord(
        evidence_id=eid,
        source=source,
        event_type=event_type,
        timestamp=ts,
        entity={"type": entity_type, "value": entity_value},
        risk_tier=tier,
        score=round(score, 4),
        reasons=list(reasons),
        related_ids=list(related_ids or []),
        metadata=dict(metadata or {}),
    )
    return rec.to_dict()


def append_evidence_jsonl(record: dict[str, Any], filepath: Path | str) -> None:
    """Atomically append an evidence record as a JSON line."""
    p = Path(filepath)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
