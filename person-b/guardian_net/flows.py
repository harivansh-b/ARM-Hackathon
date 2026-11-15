"""Bounded LRU Flow Table tracking 5-tuples, byte counts, intervals, and TLS metadata.

Tracks:
- Directional 5-tuple: (proto, src_ip, src_port, dst_ip, dst_port)
- Flow lifetime: start_time, last_time, duration
- Packet and byte volumes: bytes_orig, bytes_resp, pkts_orig, pkts_resp
- Inter-arrival intervals: time differences between successive packets for beaconing detection
- Protocol state: SYN_SENT, ESTABLISHED, CLOSED
- TLS ClientHello inspection: SNI, ALPN, JA4 fingerprint
- Bounded size using OrderedDict to enforce strict memory limits via LRU eviction
"""
from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from .pcapio import ParsedPacket
from .tls_hello import TLSClientHello, parse_client_hello


@dataclass
class FlowRecord:
    flow_id: str
    proto: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    start_time: float
    last_time: float
    bytes_orig: int = 0
    bytes_resp: int = 0
    pkts_orig: int = 0
    pkts_resp: int = 0
    intervals: list[float] = field(default_factory=list)
    state: str = "INIT"
    sni: str | None = None
    alpn: list[str] = field(default_factory=list)
    ja4: str = ""

    @property
    def duration(self) -> float:
        return max(0.0, self.last_time - self.start_time)

    @property
    def total_bytes(self) -> int:
        return self.bytes_orig + self.bytes_resp

    @property
    def total_pkts(self) -> int:
        return self.pkts_orig + self.pkts_resp

    @property
    def entity_key(self) -> str:
        """Entity representation matching contract format."""
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}/{self.proto}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "proto": self.proto,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "duration": round(self.duration, 3),
            "bytes_orig": self.bytes_orig,
            "bytes_resp": self.bytes_resp,
            "pkts_orig": self.pkts_orig,
            "pkts_resp": self.pkts_resp,
            "state": self.state,
            "sni": self.sni,
            "ja4": self.ja4,
            "intervals_count": len(self.intervals),
        }


def canonical_flow_key(proto: str, ip1: str, port1: int, ip2: str, port2: int) -> tuple[str, str, int, str, int]:
    """Symmetric flow key so both directions map to the same connection."""
    if (ip1, port1) <= (ip2, port2):
        return (proto, ip1, port1, ip2, port2)
    return (proto, ip2, port2, ip1, port1)


class FlowTable:
    """Bounded LRU flow table with automatic flow eviction."""

    def __init__(self, max_flows: int = 10000, flow_timeout: float = 300.0) -> None:
        self.max_flows = max_flows
        self.flow_timeout = flow_timeout
        self.flows: OrderedDict[tuple[str, str, int, str, int], FlowRecord] = OrderedDict()
        self.evicted_count = 0

    def add_packet(self, pkt: ParsedPacket) -> FlowRecord | None:
        """Ingest a packet, update flow state, and return the updated FlowRecord."""
        if not pkt.src_ip or not pkt.dst_ip or not pkt.proto:
            return None

        key = canonical_flow_key(pkt.proto, pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
        pkt_len = len(pkt.raw_packet)

        if key in self.flows:
            flow = self.flows[key]
            # Move to MRU position
            self.flows.move_to_end(key)

            # Determine direction relative to original flow initiator
            is_forward = (pkt.src_ip, pkt.src_port) == (flow.src_ip, flow.src_port)

            # Record interval
            interval = max(0.0, pkt.timestamp - flow.last_time)
            flow.intervals.append(round(interval, 4))
            # Keep intervals bounded
            if len(flow.intervals) > 100:
                flow.intervals.pop(0)

            flow.last_time = max(flow.last_time, pkt.timestamp)

            if is_forward:
                flow.pkts_orig += 1
                flow.bytes_orig += pkt_len
            else:
                flow.pkts_resp += 1
                flow.bytes_resp += pkt_len

            # State transitions
            if pkt.proto == "TCP":
                if pkt.is_fin or pkt.is_rst:
                    flow.state = "CLOSED"
                elif flow.state == "SYN_SENT" and pkt.is_syn_ack:
                    flow.state = "ESTABLISHED"
                elif flow.state == "INIT" and pkt.is_syn:
                    flow.state = "SYN_SENT"

        else:
            # Enforce capacity
            if len(self.flows) >= self.max_flows:
                self.flows.popitem(last=False)
                self.evicted_count += 1

            # Originator defines src and dst
            flow_id = f"{pkt.proto[0]}_{pkt.src_ip}_{pkt.src_port}_{pkt.dst_ip}_{pkt.dst_port}_{int(pkt.timestamp)}"
            flow = FlowRecord(
                flow_id=flow_id,
                proto=pkt.proto,
                src_ip=pkt.src_ip,
                src_port=pkt.src_port,
                dst_ip=pkt.dst_ip,
                dst_port=pkt.dst_port,
                start_time=pkt.timestamp,
                last_time=pkt.timestamp,
                bytes_orig=pkt_len,
                bytes_resp=0,
                pkts_orig=1,
                pkts_resp=0,
                state="SYN_SENT" if (pkt.proto == "TCP" and pkt.is_syn) else "INIT",
            )
            self.flows[key] = flow

        # Check for TLS ClientHello on forward packets if not already extracted
        if pkt.proto == "TCP" and flow.sni is None and not flow.ja4 and pkt.payload:
            hello = parse_client_hello(pkt.payload)
            if hello:
                flow.sni = hello.sni
                flow.alpn = hello.alpn
                flow.ja4 = hello.ja4

        return flow

    def cleanup_expired(self, current_time: float | None = None) -> list[FlowRecord]:
        """Evict flows that have been idle longer than flow_timeout."""
        now = time.time() if current_time is None else current_time
        expired: list[FlowRecord] = []
        keys_to_remove = []

        for key, flow in self.flows.items():
            if (now - flow.last_time) > self.flow_timeout:
                keys_to_remove.append(key)
                expired.append(flow)

        for k in keys_to_remove:
            del self.flows[k]

        return expired

    def __len__(self) -> int:
        return len(self.flows)
