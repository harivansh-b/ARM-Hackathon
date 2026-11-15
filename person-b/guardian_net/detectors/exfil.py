"""Data exfiltration detector: volumetric anomaly and off-hours transfer.

Evaluates:
- Transfer volume vs historical baseline using robust statistics (Median and Median Absolute Deviation - MAD)
- Highly asymmetric outbound transfer ratio (bytes_sent >> bytes_received)
- Off-hours data movement (e.g. 23:00 to 06:00 local/UTC)
"""
from __future__ import annotations

import collections
import datetime
import math
from typing import Any

from ..evidence import create_evidence
from ..flows import FlowRecord


def compute_median_and_mad(values: list[int | float]) -> tuple[float, float]:
    """Calculate median and Median Absolute Deviation (MAD)."""
    if not values:
        return 0.0, 0.0
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    med = float(sorted_vals[n // 2]) if n % 2 != 0 else (sorted_vals[n // 2 - 1] + sorted_vals[n // 2]) / 2.0
    deviations = sorted(abs(x - med) for x in sorted_vals)
    mad = float(deviations[n // 2]) if n % 2 != 0 else (deviations[n // 2 - 1] + deviations[n // 2]) / 2.0
    return med, mad


class ExfiltrationDetector:
    """Detects unusual outbound data transfers exceeding MAD baselines."""

    def __init__(
        self,
        min_baseline_samples: int = 5,
        mad_zscore_threshold: float = 3.5,
        off_hours_start: int = 22,  # 10 PM
        off_hours_end: int = 6,     # 6 AM
        min_volume_bytes: int = 50_000,
    ) -> None:
        self.min_baseline_samples = min_baseline_samples
        self.mad_zscore_threshold = mad_zscore_threshold
        self.off_hours_start = off_hours_start
        self.off_hours_end = off_hours_end
        self.min_volume_bytes = min_volume_bytes

        # Baseline transfer sizes: {dest_ip: deque of bytes_orig}
        self._history: dict[str, collections.deque[int]] = collections.defaultdict(
            lambda: collections.deque(maxlen=100)
        )

    def is_off_hours(self, ts: float) -> bool:
        dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        hour = dt.hour
        if self.off_hours_start > self.off_hours_end:
            # Over midnight (e.g. 22 to 6)
            return hour >= self.off_hours_start or hour < self.off_hours_end
        return self.off_hours_start <= hour < self.off_hours_end

    def inspect_flow(self, flow: FlowRecord) -> dict[str, Any] | None:
        """Inspect a completed or active flow for data exfiltration."""
        bytes_out = flow.bytes_orig
        dest = flow.dst_ip

        history = self._history[dest]
        reasons = []
        score = 0.0

        # Only evaluate flows with appreciable outbound data
        if bytes_out < self.min_volume_bytes and len(history) >= self.min_baseline_samples:
            history.append(bytes_out)
            return None

        # Check baseline z-score
        zscore = 0.0
        if len(history) >= self.min_baseline_samples:
            med, mad = compute_median_and_mad(list(history))
            # Normal consistency factor 1.4826
            scale = 1.4826 * mad
            if scale > 0:
                zscore = (bytes_out - med) / scale
                if zscore >= self.mad_zscore_threshold:
                    reasons.append(
                        f"Outbound transfer spike: {bytes_out:,} bytes (z-score {zscore:.1f} vs MAD baseline {med:,.0f} B)"
                    )
                    score += 0.50
        elif bytes_out >= 500_000:
            # Cold start but very large volume (>500KB in isolated VM)
            reasons.append(f"High-volume outbound transfer: {bytes_out:,} bytes with no prior baseline")
            score += 0.40

        history.append(bytes_out)

        # Check asymmetry (upload >> download)
        if flow.bytes_resp > 0:
            ratio = bytes_out / flow.bytes_resp
            if ratio >= 10.0 and bytes_out >= self.min_volume_bytes:
                reasons.append(f"Highly asymmetric outbound flow: upload ratio {ratio:.1f}x vs ingress")
                score += 0.20
        elif bytes_out >= self.min_volume_bytes:
            reasons.append("Unidirectional upload with zero ingress data")
            score += 0.20

        # Check off-hours
        off_hours = self.is_off_hours(flow.last_time)
        if off_hours and score > 0:
            dt = datetime.datetime.fromtimestamp(flow.last_time, tz=datetime.timezone.utc)
            reasons.append(f"Activity occurred during off-hours window ({dt.strftime('%H:%M')} UTC)")
            score += 0.25

        score = min(score, 0.99)
        if score < 0.35:
            return None

        return create_evidence(
            source="CONNECTION",
            event_type="EXFILTRATION",
            entity_type="IP",
            entity_value=dest,
            score=score,
            reasons=reasons,
            timestamp=int(flow.last_time),
            metadata={
                "bytes_out": bytes_out,
                "bytes_in": flow.bytes_resp,
                "zscore": round(zscore, 2),
                "off_hours": off_hours,
                "sni": flow.sni,
                "ja4": flow.ja4,
            },
        )
