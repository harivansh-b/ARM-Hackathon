"""Binary PCAP reader/writer and Linux AF_PACKET raw sniffer (Python stdlib).

Supports:
- PCAP format reading and writing (little-endian & big-endian magic)
- Ethernet (LINKTYPE_ETHERNET = 1) with 802.1Q VLAN handling
- Linux Cooked capture (LINKTYPE_LINUX_SLL = 113, LINKTYPE_LINUX_SLL2 = 276)
- IPv4 (RFC 791) and IPv6 (RFC 8200) parsing
- TCP (RFC 793) flags extraction and payload parsing
- UDP (RFC 768) parsing
- Linux AF_PACKET live sniffer with graceful permission handling
"""
from __future__ import annotations

import os
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Callable, Generator

# PCAP Magic constants
PCAP_MAGIC_SAME = 0xA1B2C3D4
PCAP_MAGIC_SWAP = 0xD4C3B2A1
PCAP_MAGIC_NANO_SAME = 0xA1B23C4D
PCAP_MAGIC_NANO_SWAP = 0x4D3CB2A1

# Link types
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 12
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276

# Ethertypes
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_8021Q = 0x8100

# IP Protocols
IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17

# TCP Flags
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20


@dataclass
class ParsedPacket:
    timestamp: float
    raw_packet: bytes = field(repr=False)
    src_mac: str = ""
    dst_mac: str = ""
    ethertype: int = 0
    src_ip: str = ""
    dst_ip: str = ""
    proto: str = ""  # "TCP" | "UDP" | "ICMP" | "OTHER"
    proto_num: int = 0
    src_port: int = 0
    dst_port: int = 0
    tcp_flags: int = 0
    payload: bytes = field(default=b"", repr=False)

    @property
    def is_syn(self) -> bool:
        return bool(self.tcp_flags & TCP_SYN) and not bool(self.tcp_flags & TCP_ACK)

    @property
    def is_syn_ack(self) -> bool:
        return bool(self.tcp_flags & TCP_SYN) and bool(self.tcp_flags & TCP_ACK)

    @property
    def is_fin(self) -> bool:
        return bool(self.tcp_flags & TCP_FIN)

    @property
    def is_rst(self) -> bool:
        return bool(self.tcp_flags & TCP_RST)


class PcapWriter:
    """Standard pcap file writer."""

    def __init__(self, target: str | Path | BinaryIO, linktype: int = LINKTYPE_ETHERNET) -> None:
        self.linktype = linktype
        self._owned = False
        if isinstance(target, (str, Path)):
            p = Path(target)
            p.parent.mkdir(parents=True, exist_ok=True)
            self.file = p.open("wb")
            self._owned = True
        else:
            self.file = target

        # Write global header (24 bytes)
        # magic (4), major (2), minor (2), thiszone (4), sigfigs (4), snaplen (4), network (4)
        gh = struct.pack("=IHHiIII", PCAP_MAGIC_SAME, 2, 4, 0, 0, 65535, self.linktype)
        self.file.write(gh)
        self.file.flush()

    def write_packet(self, data: bytes, ts: float | None = None) -> None:
        if ts is None:
            ts = time.time()
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        pkt_len = len(data)
        # Record header: ts_sec (4), ts_usec (4), incl_len (4), orig_len (4)
        rec_hdr = struct.pack("=IIII", sec, usec, pkt_len, pkt_len)
        self.file.write(rec_hdr)
        self.file.write(data)
        self.file.flush()

    def close(self) -> None:
        if self._owned and not self.file.closed:
            self.file.close()

    def __enter__(self) -> PcapWriter:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


class PcapReader:
    """Standard pcap file reader supporting LE and BE files."""

    def __init__(self, target: str | Path | BinaryIO) -> None:
        self._owned = False
        if isinstance(target, (str, Path)):
            self.file = open(target, "rb")
            self._owned = True
        else:
            self.file = target

        # Read global header
        gh = self.file.read(24)
        if len(gh) < 24:
            raise ValueError("Truncated PCAP global header")

        magic = struct.unpack("=I", gh[:4])[0]
        if magic in (PCAP_MAGIC_SAME, PCAP_MAGIC_NANO_SAME):
            self.endian = "="
            self.is_nano = magic == PCAP_MAGIC_NANO_SAME
        elif magic in (PCAP_MAGIC_SWAP, PCAP_MAGIC_NANO_SWAP):
            # Swapped endianness
            self.endian = ">" if struct.unpack("=I", b"\x01\x00\x00\x00")[0] == 1 else "<"
            self.is_nano = magic in (PCAP_MAGIC_NANO_SAME, PCAP_MAGIC_NANO_SWAP)
        else:
            raise ValueError(f"Invalid PCAP magic: 0x{magic:08x}")

        _, _, _, _, _, _, self.linktype = struct.unpack(f"{self.endian}IHHiIII", gh)

    def packets(self) -> Generator[tuple[float, bytes], None, None]:
        """Generator yielding (timestamp, raw_packet_bytes)."""
        hdr_fmt = f"{self.endian}IIII"
        while True:
            hdr = self.file.read(16)
            if not hdr or len(hdr) < 16:
                break
            sec, usec, incl_len, orig_len = struct.unpack(hdr_fmt, hdr)
            pkt_data = self.file.read(incl_len)
            if len(pkt_data) < incl_len:
                break
            div = 1_000_000_000.0 if self.is_nano else 1_000_000.0
            ts = float(sec) + (float(usec) / div)
            yield ts, pkt_data

    def parsed_packets(self) -> Generator[ParsedPacket, None, None]:
        """Generator yielding decoded ParsedPacket objects."""
        for ts, data in self.packets():
            pkt = decode_packet(data, ts, self.linktype)
            if pkt:
                yield pkt

    def close(self) -> None:
        if self._owned and not self.file.closed:
            self.file.close()

    def __enter__(self) -> PcapReader:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


def decode_packet(raw: bytes, timestamp: float, linktype: int = LINKTYPE_ETHERNET) -> ParsedPacket | None:
    """Decode raw layer 2 frame into a ParsedPacket."""
    offset = 0
    ethertype = 0
    src_mac = ""
    dst_mac = ""

    if linktype == LINKTYPE_ETHERNET:
        if len(raw) < 14:
            return None
        dst_mac = ":".join(f"{b:02x}" for b in raw[:6])
        src_mac = ":".join(f"{b:02x}" for b in raw[6:12])
        ethertype = struct.unpack("!H", raw[12:14])[0]
        offset = 14
        # Handle 802.1Q VLAN
        if ethertype == ETH_P_8021Q and len(raw) >= 18:
            ethertype = struct.unpack("!H", raw[16:18])[0]
            offset = 18

    elif linktype == LINKTYPE_LINUX_SLL:
        # Linux cooked capture v1 (16 bytes)
        if len(raw) < 16:
            return None
        ethertype = struct.unpack("!H", raw[14:16])[0]
        offset = 16

    elif linktype == LINKTYPE_LINUX_SLL2:
        # Linux cooked capture v2 (20 bytes)
        if len(raw) < 20:
            return None
        ethertype = struct.unpack("!H", raw[0:2])[0]
        offset = 20

    elif linktype == LINKTYPE_RAW:
        # Raw IP
        if len(raw) < 1:
            return None
        ver = raw[0] >> 4
        ethertype = ETH_P_IP if ver == 4 else ETH_P_IPV6
        offset = 0

    # Parse IP layer
    src_ip = ""
    dst_ip = ""
    proto_num = 0
    ip_payload = b""

    if ethertype == ETH_P_IP:
        if len(raw) < offset + 20:
            return None
        ihl = (raw[offset] & 0x0F) * 4
        if ihl < 20 or len(raw) < offset + ihl:
            return None
        total_len = struct.unpack("!H", raw[offset + 2 : offset + 4])[0]
        proto_num = raw[offset + 9]
        src_ip = socket.inet_ntoa(raw[offset + 12 : offset + 16])
        dst_ip = socket.inet_ntoa(raw[offset + 16 : offset + 20])
        # Bounded payload
        end = min(len(raw), offset + total_len) if total_len > 0 else len(raw)
        ip_payload = raw[offset + ihl : end]

    elif ethertype == ETH_P_IPV6:
        if len(raw) < offset + 40:
            return None
        proto_num = raw[offset + 6]
        src_ip = socket.inet_ntop(socket.AF_INET6, raw[offset + 8 : offset + 24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, raw[offset + 24 : offset + 40])
        ip_payload = raw[offset + 40 :]

    else:
        # Non-IP
        return None

    # Parse Transport layer
    proto_str = "OTHER"
    src_port = 0
    dst_port = 0
    tcp_flags = 0
    payload = ip_payload

    if proto_num == IPPROTO_TCP:
        proto_str = "TCP"
        if len(ip_payload) >= 20:
            src_port, dst_port = struct.unpack("!HH", ip_payload[:4])
            data_offset = (ip_payload[12] >> 4) * 4
            tcp_flags = ip_payload[13]
            if len(ip_payload) >= data_offset:
                payload = ip_payload[data_offset:]

    elif proto_num == IPPROTO_UDP:
        proto_str = "UDP"
        if len(ip_payload) >= 8:
            src_port, dst_port = struct.unpack("!HH", ip_payload[:4])
            payload = ip_payload[8:]

    elif proto_num == IPPROTO_ICMP:
        proto_str = "ICMP"

    return ParsedPacket(
        timestamp=timestamp,
        raw_packet=raw,
        src_mac=src_mac,
        dst_mac=dst_mac,
        ethertype=ethertype,
        src_ip=src_ip,
        dst_ip=dst_ip,
        proto=proto_str,
        proto_num=proto_num,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        payload=payload,
    )


class LiveSniffer:
    """Linux AF_PACKET live sniffer.

    Requires raw socket capability (CAP_NET_RAW / sudo).
    Fails cleanly with clear permission error if unprivileged.
    """

    def __init__(
        self,
        interface: str | None = None,
        packet_callback: Callable[[ParsedPacket], None] | None = None,
    ) -> None:
        self.interface = interface
        self.packet_callback = packet_callback
        self.running = False
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if not hasattr(socket, "AF_PACKET"):
            raise OSError("AF_PACKET is only supported on Linux")

        try:
            # ETH_P_ALL = 0x0003
            self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            if self.interface:
                self._sock.bind((self.interface, 0))
            self._sock.settimeout(0.5)
        except PermissionError as e:
            raise PermissionError(
                "Live sniffer requires root or CAP_NET_RAW permissions (e.g. run with sudo)"
            ) from e

        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name="live-sniffer")
        self._thread.start()

    def _run(self) -> None:
        sock = self._sock
        if not sock:
            return
        while self.running:
            try:
                raw_bytes, _ = sock.recvfrom(65535)
                ts = time.time()
                pkt = decode_packet(raw_bytes, ts, linktype=LINKTYPE_ETHERNET)
                if pkt and self.packet_callback:
                    self.packet_callback(pkt)
            except socket.timeout:
                continue
            except OSError:
                break

    def stop(self) -> None:
        self.running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=1.0)
