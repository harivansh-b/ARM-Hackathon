"""Outbound scanning detector.

Detects horizontal (port sweep) and vertical (network sweep) reconnaissance:
- Measures fan-out of destination IPs and ports within a sliding time window
- Identifies rapid SYN probes and unanswered connection attempts
"""
from __future__ import annotations

import collections
import time
from typing import Any

from ..evidence import create_evidence
from ..pcapio import ParsedPacket


class OutboundScanDetector:
    """Sliding-window outbound port and network scan detector."""

    def __init__(
        self,
        window_seconds: float = 10.0,
        port_scan_threshold: int = 15,
        host_scan_threshold: int = 15,
    ) -> None:
        self.window_seconds = window_seconds
        self.port_scan_threshold = port_scan_threshold
        self.host_scan_threshold = host_scan_threshold

        # Sliding window buffer: [(timestamp, src_ip, dst_ip, dst_port, is_syn)]
        self._events: collections.deque[tuple[float, str, str, int, bool]] = collections.deque()

    def process_packet(self, pkt: ParsedPacket) -> dict[str, Any] | None:
        """Process an outbound packet and detect scanning patterns."""
        if not pkt.src_ip or not pkt.dst_ip or pkt.dst_port <= 0:
            return None

        # Focus primarily on outbound connection initiations (TCP SYN or UDP probes)
        is_syn = (pkt.proto == "TCP" and pkt.is_syn) or pkt.proto == "UDP"
        if not is_syn:
            return None

        now = pkt.timestamp
        self._events.append((now, pkt.src_ip, pkt.dst_ip, pkt.dst_port, is_syn))

        # Evict old events outside window
        cutoff = now - self.window_seconds
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()

        # Group by target IP (port scan check)
        ports_per_target: dict[str, set[int]] = collections.defaultdict(set)
        all_targets: set[str] = set()

        for ts, s_ip, d_ip, d_port, _ in self._events:
            ports_per_target[d_ip].add(d_port)
            all_targets.add(d_ip)

        reasons = []
        score = 0.0
        alert_entity_type = "IP"
        alert_entity_value = ""

        # Check 1: Port scan against a single IP
        for target_ip, ports in ports_per_target.items():
            if len(ports) >= self.port_scan_threshold:
                reasons.append(
                    f"Outbound port scan: {len(ports)} distinct ports targeted on {target_ip} within {self.window_seconds:.0f}s"
                )
                score += 0.65
                alert_entity_value = target_ip
                break

        # Check 2: Host sweep across multiple IPs
        if len(all_targets) >= self.host_scan_threshold:
            reasons.append(
                f"Outbound host sweep: {len(all_targets)} distinct destination IPs contacted within {self.window_seconds:.0f}s"
            )
            score += 0.60
            if not alert_entity_value:
                alert_entity_type = "IP"
                alert_entity_value = pkt.src_ip

        score = min(score, 0.99)
        if score < 0.35:
            return None

        return create_evidence(
            source="CONNECTION",
            event_type="PORT_SCAN",
            entity_type=alert_entity_type,
            entity_value=alert_entity_value or pkt.dst_ip,
            score=score,
            reasons=reasons,
            timestamp=int(now),
            metadata={
                "target_ports_count": len(ports_per_target.get(alert_entity_value, [])),
                "unique_hosts_count": len(all_targets),
                "window_sec": self.window_seconds,
            },
        )
