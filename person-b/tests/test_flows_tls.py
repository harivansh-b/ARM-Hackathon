"""Unit tests for pcapio, flows, and tls_hello modules."""
import io
import socket
import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from guardian_net.flows import FlowTable, canonical_flow_key
from guardian_net.pcapio import (
    LINKTYPE_ETHERNET,
    LINKTYPE_LINUX_SLL,
    ParsedPacket,
    PcapReader,
    PcapWriter,
    TCP_ACK,
    TCP_FIN,
    TCP_SYN,
    decode_packet,
)
from guardian_net.tls_hello import (
    EXT_ALPN,
    EXT_SERVER_NAME,
    EXT_SUPPORTED_VERSIONS,
    TLSClientHello,
    compute_ja4,
    parse_client_hello,
)


def build_raw_ipv4_tcp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    flags: int = TCP_SYN,
    payload: bytes = b"",
) -> bytes:
    """Helper to synthesize a raw Ethernet+IPv4+TCP packet."""
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + 20 + len(payload),
        0x1234,
        0,
        64,
        6,  # TCP
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        1000,
        0,
        (5 << 4),  # data offset 5 (20 bytes)
        flags,
        64240,
        0,
        0,
    )
    return eth + ip_hdr + tcp_hdr + payload


def build_raw_tls_client_hello(sni: str = "c2.test", alpn: list[str] = ["h2", "http/1.1"]) -> bytes:
    """Helper to synthesize a minimal TLS 1.2/1.3 ClientHello payload."""
    sni_bytes = sni.encode("ascii")
    sni_ext = (
        struct.pack("!H", EXT_SERVER_NAME)
        + struct.pack("!H", len(sni_bytes) + 5)
        + struct.pack("!H", len(sni_bytes) + 3)
        + b"\x00"  # host_name type
        + struct.pack("!H", len(sni_bytes))
        + sni_bytes
    )

    alpn_payload = bytearray()
    for proto in alpn:
        pb = proto.encode("ascii")
        alpn_payload.append(len(pb))
        alpn_payload.extend(pb)
    alpn_ext = (
        struct.pack("!H", EXT_ALPN)
        + struct.pack("!H", len(alpn_payload) + 2)
        + struct.pack("!H", len(alpn_payload))
        + bytes(alpn_payload)
    )

    supp_ver_ext = (
        struct.pack("!H", EXT_SUPPORTED_VERSIONS)
        + struct.pack("!H", 3)
        + b"\x02\x03\x04"  # TLS 1.3
    )

    exts = sni_ext + alpn_ext + supp_ver_ext
    ciphers = struct.pack("!HH", 0x1301, 0xC02F)  # TLS_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    ciphers_block = struct.pack("!H", len(ciphers)) + ciphers
    comp_block = b"\x01\x00"  # 1 compression method (null)
    sess_id_block = b"\x00"   # 0 session id len

    handshake_body = (
        struct.pack("!H", 0x0303)  # Client version 1.2
        + (b"\x01" * 32)           # Random
        + sess_id_block
        + ciphers_block
        + comp_block
        + struct.pack("!H", len(exts))
        + exts
    )

    handshake_hdr = b"\x01" + struct.pack("!I", len(handshake_body))[1:]  # type=1, len=3 bytes
    handshake_msg = handshake_hdr + handshake_body

    record_hdr = struct.pack("!BHH", 0x16, 0x0301, len(handshake_msg))
    return record_hdr + handshake_msg


class TestFlowsAndTLS(unittest.TestCase):
    def test_tls_client_hello_parser(self) -> None:
        payload = build_raw_tls_client_hello(sni="malware-c2.example.test", alpn=["h2", "http/1.1"])
        hello = parse_client_hello(payload)
        self.assertIsNotNone(hello)
        self.assertEqual(hello.sni, "malware-c2.example.test")
        self.assertEqual(hello.alpn, ["h2", "http/1.1"])
        self.assertIn(0x1301, hello.ciphers)
        self.assertTrue(hello.ja4.startswith("t13d"))

    def test_tls_non_tls_and_truncated(self) -> None:
        # Random bytes
        self.assertIsNone(parse_client_hello(b"\x00\x01\x02\x03\x04\x05"))
        # Truncated record header
        self.assertIsNone(parse_client_hello(b"\x16\x03\x01"))
        # Handshake not ClientHello
        self.assertIsNone(parse_client_hello(b"\x16\x03\x01\x00\x05\x02\x00\x00\x01\x00"))

    def test_pcap_writer_and_reader(self) -> None:
        buf = io.BytesIO()
        writer = PcapWriter(buf)
        pkt1 = build_raw_ipv4_tcp_packet("10.77.0.1", "10.77.0.2", 12345, 80, TCP_SYN)
        pkt2 = build_raw_ipv4_tcp_packet("10.77.0.2", "10.77.0.1", 80, 12345, TCP_SYN | TCP_ACK)

        writer.write_packet(pkt1, ts=1000.0)
        writer.write_packet(pkt2, ts=1000.05)

        buf.seek(0)
        reader = PcapReader(buf)
        packets = list(reader.parsed_packets())
        self.assertEqual(len(packets), 2)

        self.assertEqual(packets[0].src_ip, "10.77.0.1")
        self.assertEqual(packets[0].dst_ip, "10.77.0.2")
        self.assertEqual(packets[0].src_port, 12345)
        self.assertEqual(packets[0].dst_port, 80)
        self.assertTrue(packets[0].is_syn)

        self.assertEqual(packets[1].src_ip, "10.77.0.2")
        self.assertEqual(packets[1].dst_ip, "10.77.0.1")
        self.assertTrue(packets[1].is_syn_ack)

    def test_flow_table_bidi_tracking(self) -> None:
        table = FlowTable(max_flows=100)
        tls_payload = build_raw_tls_client_hello(sni="beacon.test")

        # Client -> Server (SYN)
        p1 = decode_packet(build_raw_ipv4_tcp_packet("192.168.1.10", "1.2.3.4", 50000, 443, TCP_SYN), timestamp=10.0)
        f1 = table.add_packet(p1)
        self.assertEqual(f1.state, "SYN_SENT")
        self.assertEqual(f1.pkts_orig, 1)
        self.assertEqual(f1.pkts_resp, 0)

        # Server -> Client (SYN+ACK)
        p2 = decode_packet(build_raw_ipv4_tcp_packet("1.2.3.4", "192.168.1.10", 443, 50000, TCP_SYN | TCP_ACK), timestamp=10.02)
        f2 = table.add_packet(p2)
        self.assertEqual(f2.flow_id, f1.flow_id)  # Same flow
        self.assertEqual(f2.state, "ESTABLISHED")
        self.assertEqual(f2.pkts_resp, 1)

        # Client -> Server (ClientHello)
        p3 = decode_packet(build_raw_ipv4_tcp_packet("192.168.1.10", "1.2.3.4", 50000, 443, TCP_ACK, tls_payload), timestamp=10.05)
        f3 = table.add_packet(p3)
        self.assertEqual(f3.sni, "beacon.test")
        self.assertTrue(f3.ja4.startswith("t13d"))
        self.assertGreaterEqual(len(f3.intervals), 1)

        # Server -> Client (FIN)
        p4 = decode_packet(build_raw_ipv4_tcp_packet("1.2.3.4", "192.168.1.10", 443, 50000, TCP_FIN | TCP_ACK), timestamp=10.10)
        f4 = table.add_packet(p4)
        self.assertEqual(f4.state, "CLOSED")

    def test_flow_table_lru_eviction(self) -> None:
        table = FlowTable(max_flows=5)
        for i in range(10):
            p = decode_packet(build_raw_ipv4_tcp_packet("10.0.0.1", f"10.0.0.{i+10}", 1000 + i, 80, TCP_SYN), timestamp=float(i))
            table.add_packet(p)

        self.assertEqual(len(table), 5)
        self.assertEqual(table.evicted_count, 5)


if __name__ == "__main__":
    unittest.main()
