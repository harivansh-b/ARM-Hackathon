"""Beaconing detector for C2 heartbeat communication.

Detects regular, periodic outbound communication by measuring:
- Inter-arrival intervals between connection events to the same destination
- Coefficient of Variation (CV = std_dev / mean)
- Jitter tolerance: handles interval noise typical of evasive C2 beacons
- Event count threshold (k >= 5) to eliminate transient connections
"""
from __future__ import annotations

import collections
import math
import time
from typing import Any

from ..evidence import create_evidence


def calculate_interval_stats(intervals: list[float]) -> tuple[float, float, float] | None:
    """Returns (mean, std_dev, cv). None if fewer than 3 intervals."""
    if len(intervals) < 3:
        return None
    valid = [iv for iv in intervals if iv > 0.05]
    if len(valid) < 3:
        return None

    mean = sum(valid) / len(valid)
    if mean <= 0.0:
        return None
    var = sum((x - mean) ** 2 for x in valid) / len(valid)
    std_dev = math.sqrt(var)
    cv = std_dev / mean
    return mean, std_dev, cv


class BeaconDetector:
    """Tracks connection timestamps per destination entity and identifies beaconing rhythms."""

    def __init__(
        self,
        min_events: int = 5,
        cv_threshold: float = 0.30,
        min_interval_sec: float = 1.0,
        max_interval_sec: float = 3600.0,
    ) -> None:
        self.min_events = min_events
        self.cv_threshold = cv_threshold
        self.min_interval_sec = min_interval_sec
        self.max_interval_sec = max_interval_sec

        # {entity_key: deque of timestamps}
        self._history: dict[str, collections.deque[float]] = collections.defaultdict(
            lambda: collections.deque(maxlen=50)
        )

    def record_event(
        self,
        entity_value: str,
        timestamp: float | None = None,
        entity_type: str = "IP",
    ) -> dict[str, Any] | None:
        """Record an outbound event to entity_value and evaluate beaconing."""
        ts = time.time() if timestamp is None else float(timestamp)
        history = self._history[entity_value]

        # Don't add duplicate timestamps within 0.1s (e.g. multi-packet burst)
        if not history or (ts - history[-1]) > 0.1:
            history.append(ts)

        if len(history) < self.min_events:
            return None

        # Calculate inter-arrival intervals
        intervals = [history[i] - history[i - 1] for i in range(1, len(history))]
        stats = calculate_interval_stats(intervals)
        if not stats:
            return None

        mean_iv, std_dev, cv = stats

        # Filter out tight bursts (< min_interval) or overly sparse (> max_interval)
        if not (self.min_interval_sec <= mean_iv <= self.max_interval_sec):
            return None

        if cv > self.cv_threshold:
            return None

        # Build score and evidence
        score = 0.0
        reasons = []

        if cv <= 0.10:
            reasons.append(f"Highly rigid periodic beaconing: mean interval {mean_iv:.1f}s (CV={cv:.3f})")
            score += 0.55
        elif cv <= 0.20:
            reasons.append(f"Regular periodic beaconing with low jitter: mean interval {mean_iv:.1f}s (CV={cv:.3f})")
            score += 0.45
        else:
            reasons.append(f"Periodic beaconing with moderate jitter: mean interval {mean_iv:.1f}s (CV={cv:.3f})")
            score += 0.35

        event_count = len(history)
        if event_count >= 15:
            reasons.append(f"Sustained persistence: observed over {event_count} connection cycles")
            score += 0.25
        elif event_count >= 8:
            reasons.append(f"Consistent cadence across {event_count} connection cycles")
            score += 0.15

        score = min(score, 0.99)
        if score < 0.35:
            return None

        return create_evidence(
            source="CONNECTION",
            event_type="BEACON",
            entity_type=entity_type,
            entity_value=entity_value,
            score=score,
            reasons=reasons,
            timestamp=int(ts),
            metadata={
                "mean_interval_sec": round(mean_iv, 2),
                "std_dev_sec": round(std_dev, 2),
                "coefficient_of_variation": round(cv, 4),
                "sample_count": event_count,
            },
        )
