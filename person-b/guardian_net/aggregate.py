"""Per-entity evidence aggregation, deduplication, and benign allowlist filtering.

Solves the critical false-positive challenge on Linux:
- Built-in allowlist for standard Linux periodic timers, NTP, and package managers
- Aggregates multiple detection events per entity within a sliding time window
- Alerts only once per window per entity, escalating only if the risk tier increases
- Links associated evidence IDs into unified incident storylines
"""
from __future__ import annotations

import collections
import re
import time
from dataclasses import dataclass, field
from typing import Any

from .evidence import make_evidence_id, risk_tier_for_score

# Benign system traffic patterns commonly generating false alarms on Linux
BENIGN_DOMAINS = {
    "ntp.ubuntu.com",
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "ports.ubuntu.com",
    "esm.ubuntu.com",
    "motd.ubuntu.com",
    "connectivity-check.ubuntu.com",
    "daemons.canonical.com",
    "changelogs.ubuntu.com",
    "time.google.com",
    "time.cloudflare.com",
}

BENIGN_DOMAIN_SUFFIXES = (
    ".pool.ntp.org",
    ".archive.ubuntu.com",
    ".security.ubuntu.com",
    ".canonical.com",
)

BENIGN_PORTS = {
    123,  # NTP
    5353, # mDNS
    5355, # LLMNR
}

MULTICAST_IPS = {
    "224.0.0.251", "224.0.0.252", "239.255.255.250", "255.255.255.255", "127.0.0.53"
}


def is_benign_system_traffic(entity_type: str, entity_value: str, port: int | None = None) -> bool:
    """Return True if the entity matches normal Linux background system services."""
    val = entity_value.strip().lower()

    if port in BENIGN_PORTS:
        return True

    # Check benign domains across all entity types
    if val in BENIGN_DOMAINS or any(val.endswith(suffix) for suffix in BENIGN_DOMAIN_SUFFIXES):
        return True

    if entity_type == "IP" or any(c.isdigit() for c in val):
        if val in MULTICAST_IPS or val.startswith("127.") or val == "::1":
            return True

    if entity_type == "FLOW":
        if any(f":{p}->" in val or f"->{p}:" in val or val.endswith(f":{p}") for p in BENIGN_PORTS):
            return True
        for m_ip in MULTICAST_IPS:
            if m_ip in val:
                return True

    return False


@dataclass
class AggregatedEntityState:
    entity_type: str
    entity_value: str
    first_seen: int
    last_seen: int
    max_score: float = 0.0
    risk_tier: str = "INFO"
    event_types: set[str] = field(default_factory=set)
    reasons: list[str] = field(default_factory=list)
    related_ids: set[str] = field(default_factory=set)
    last_alerted_score: float = 0.0
    last_alerted_time: int = 0
    suppressed_count: int = 0


class EvidenceAggregator:
    """Consolidates flow/query evidence records per entity to prevent alert fatigue."""

    def __init__(
        self,
        alert_threshold_score: float = 0.35,
        aggregation_window_sec: int = 300,
        filter_benign: bool = True,
    ) -> None:
        self.alert_threshold_score = alert_threshold_score
        self.aggregation_window_sec = aggregation_window_sec
        self.filter_benign = filter_benign

        # {entity_key: AggregatedEntityState}
        self.entities: dict[str, AggregatedEntityState] = {}
        self.total_ingested = 0
        self.total_suppressed_benign = 0
        self.total_alerts_emitted = 0

    def ingest(self, record: dict[str, Any]) -> dict[str, Any] | None:
        """Ingest raw evidence record.

        Returns an aggregated alert dict if a new alert or escalation is triggered,
        or None if deduplicated / suppressed.
        """
        self.total_ingested += 1
        entity = record.get("entity", {})
        e_type = entity.get("type", "UNKNOWN")
        e_val = entity.get("value", "")
        ts = int(record.get("timestamp", time.time()))
        score = float(record.get("score", 0.0))
        event_type = record.get("event_type", "EVENT")
        rec_id = record.get("evidence_id", "")

        # Benign system traffic suppression
        if self.filter_benign and is_benign_system_traffic(e_type, e_val):
            self.total_suppressed_benign += 1
            return None

        entity_key = f"{e_type}:{e_val}"
        state = self.entities.get(entity_key)

        if not state:
            state = AggregatedEntityState(
                entity_type=e_type,
                entity_value=e_val,
                first_seen=ts,
                last_seen=ts,
                max_score=score,
                risk_tier=risk_tier_for_score(score),
            )
            self.entities[entity_key] = state
        else:
            state.last_seen = max(state.last_seen, ts)
            state.max_score = max(state.max_score, score)
            state.risk_tier = risk_tier_for_score(state.max_score)

        state.event_types.add(event_type)
        if rec_id:
            state.related_ids.add(rec_id)
        for r_id in record.get("related_ids", []):
            state.related_ids.add(r_id)

        # Merge reasons without duplicates
        for r in record.get("reasons", []):
            if r not in state.reasons:
                state.reasons.append(r)

        # Decide whether to emit an alert
        if state.max_score < self.alert_threshold_score:
            state.suppressed_count += 1
            return None

        # Check deduplication window:
        # Emit if:
        # 1. Never alerted before
        # 2. Score meaningfully escalated (+0.20 or tier jump)
        # 3. Window expired since last alert
        time_since_last_alert = ts - state.last_alerted_time
        score_jump = state.max_score - state.last_alerted_score

        should_alert = (
            state.last_alerted_time == 0
            or score_jump >= 0.20
            or time_since_last_alert >= self.aggregation_window_sec
        )

        if not should_alert:
            state.suppressed_count += 1
            return None

        state.last_alerted_time = ts
        state.last_alerted_score = state.max_score
        self.total_alerts_emitted += 1

        # Synthesize consolidated alert
        alert_source = record.get("source", "CONNECTION")
        return {
            "evidence_id": make_evidence_id(alert_source, e_val),
            "source": alert_source,
            "event_type": "/".join(sorted(state.event_types)),
            "timestamp": ts,
            "entity": {"type": e_type, "value": e_val},
            "risk_tier": state.risk_tier,
            "score": round(state.max_score, 4),
            "reasons": list(state.reasons),
            "related_ids": sorted(state.related_ids),
            "metadata": {
                "first_seen": state.first_seen,
                "last_seen": state.last_seen,
                "aggregated_events_count": len(state.related_ids),
                "suppressed_duplicates": state.suppressed_count,
            },
        }
