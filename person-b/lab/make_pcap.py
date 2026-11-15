"""Deterministic PCAP fixture generator for test suite and scenario replays."""
from __future__ import annotations

import base64
import os
import socket
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from guardian_net.dnswire import (
    DNSMessage,
    DNSResourceRecord,
    TYPE_A,
    TYPE_TXT,
    make_query,
    make_response,
)
from guardian_net.pcapio import (
    PcapWriter,
    TCP_ACK,
    TCP_FIN,
    TCP_SYN,
)
from guardian_net.tls_hello import EXT_SERVER_NAME


def make_eth_ip_udp(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
) -> bytes:
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + 8 + len(payload), 0x1234, 0, 64, 17, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    udp = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)
    return eth + ip + udp + payload


def make_eth_ip_tcp(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    flags: int = TCP_SYN,
    payload: bytes = b"",
) -> bytes:
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + 20 + len(payload), 0x5678, 0, 64, 6, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    tcp = struct.pack("!HHIIBBHHH", src_port, dst_port, 1000, 2000, (5 << 4), flags, 64240, 0, 0)
    return eth + ip + tcp + payload


def make_tls_client_hello_payload(sni: str) -> bytes:
    sni_bytes = sni.encode("ascii")
    sni_ext = (
        struct.pack("!H", EXT_SERVER_NAME)
        + struct.pack("!H", len(sni_bytes) + 5)
        + struct.pack("!H", len(sni_bytes) + 3)
        + b"\x00"
        + struct.pack("!H", len(sni_bytes))
        + sni_bytes
    )
    ciphers = struct.pack("!HH", 0x1301, 0xC02F)
    body = (
        struct.pack("!H", 0x0303)
        + (b"\x03" * 32)
        + b"\x00"
        + struct.pack("!H", len(ciphers))
        + ciphers
        + b"\x01\x00"
        + struct.pack("!H", len(sni_ext))
        + sni_ext
    )
    msg = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return struct.pack("!BHH", 0x16, 0x0301, len(msg)) + msg


def generate_all_scenario_pcaps(output_dir: Path | str) -> dict[str, Path]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    generated = {}

    # 1. Smishing C2 Chain: DNS query for SMS link followed by C2 beaconing
    chain_pcap = out / "smishing_c2_chain.pcap"
    with PcapWriter(chain_pcap) as w:
        t = 1000.0
        # DNS query: resolve phish-bank.test
        q = make_query("phish-bank.test", TYPE_A, msg_id=0x1111)
        w.write_packet(make_eth_ip_udp("10.77.0.1", "10.77.0.2", 53535, 53, q.to_wire()), ts=t)
        t += 0.01
        ans = [DNSResourceRecord("phish-bank.test", TYPE_A, 1, 300, "10.77.0.2")]
        resp = make_response(q, answers=ans)
        w.write_packet(make_eth_ip_udp("10.77.0.2", "10.77.0.1", 53, 53535, resp.to_wire()), ts=t)

        # Periodic TLS beaconing to resolved IP (6 cycles, 5.0s interval)
        for i in range(6):
            t += 5.0
            # SYN
            w.write_packet(make_eth_ip_tcp("10.77.0.1", "10.77.0.2", 40000 + i, 443, TCP_SYN), ts=t)
            t += 0.005
            # SYN+ACK
            w.write_packet(make_eth_ip_tcp("10.77.0.2", "10.77.0.1", 443, 40000 + i, TCP_SYN | TCP_ACK), ts=t)
            t += 0.005
            # ClientHello with SNI c2.beacon-control.test
            hello = make_tls_client_hello_payload("c2.beacon-control.test")
            w.write_packet(make_eth_ip_tcp("10.77.0.1", "10.77.0.2", 40000 + i, 443, TCP_ACK, hello), ts=t)
    generated["smishing_c2_chain"] = chain_pcap

    # 2. DNS Tunneling PCAP
    tunnel_pcap = out / "dns_tunnel.pcap"
    with PcapWriter(tunnel_pcap) as w:
        t = 2000.0
        for i in range(12):
            raw = bytes([(i * 17 + j) % 256 for j in range(30)])
            b32 = base64.b32encode(raw).decode().lower().rstrip("=")
            qname = f"{b32}.tunnel.data-exfil.test"
            q = make_query(qname, TYPE_TXT, msg_id=i + 1)
            w.write_packet(make_eth_ip_udp("10.77.0.1", "10.77.0.2", 50000 + i, 53, q.to_wire()), ts=t)
            t += 0.1
            resp = make_response(q, answers=[DNSResourceRecord(qname, TYPE_TXT, 1, 10, ["ACK"])])
            w.write_packet(make_eth_ip_udp("10.77.0.2", "10.77.0.1", 53, 50000 + i, resp.to_wire()), ts=t)
            t += 0.05
    generated["dns_tunnel"] = tunnel_pcap

    # 3. Port Scan PCAP
    scan_pcap = out / "port_scan.pcap"
    with PcapWriter(scan_pcap) as w:
        t = 3000.0
        for port in range(20, 42):
            w.write_packet(make_eth_ip_tcp("10.77.0.1", "10.77.0.2", 51000 + port, port, TCP_SYN), ts=t)
            t += 0.05
    generated["port_scan"] = scan_pcap

    # 4. Exfiltration Spike PCAP
    exfil_pcap = out / "exfil_spike.pcap"
    with PcapWriter(exfil_pcap) as w:
        t = 4000.0
        # 6 normal small flows ~5KB each, with FIN closure
        for i in range(6):
            t += 1.0
            src_p = 52000 + i
            w.write_packet(make_eth_ip_tcp("10.77.0.1", "198.51.100.99", src_p, 443, TCP_SYN), ts=t)
            t += 0.01
            w.write_packet(make_eth_ip_tcp("10.77.0.1", "198.51.100.99", src_p, 443, TCP_ACK, b"X" * (5000 + i * 200)), ts=t)
            t += 0.01
            w.write_packet(make_eth_ip_tcp("10.77.0.1", "198.51.100.99", src_p, 443, TCP_FIN | TCP_ACK), ts=t)
        # Exfil spike: large 200KB chunk burst to 198.51.100.99
        t += 5.0
        spike_port = 53000
        w.write_packet(make_eth_ip_tcp("10.77.0.1", "198.51.100.99", spike_port, 443, TCP_SYN), ts=t)
        for chunk in range(50):
            t += 0.005
            w.write_packet(make_eth_ip_tcp("10.77.0.1", "198.51.100.99", spike_port, 443, TCP_ACK, b"E" * 3000), ts=t)
        t += 0.01
        w.write_packet(make_eth_ip_tcp("10.77.0.1", "198.51.100.99", spike_port, 443, TCP_FIN | TCP_ACK), ts=t)
    generated["exfil_spike"] = exfil_pcap

    # 5. Benign Linux Background PCAP
    benign_pcap = out / "benign_linux.pcap"
    with PcapWriter(benign_pcap) as w:
        t = 5000.0
        # NTP queries
        for i in range(5):
            q = make_query("ntp.ubuntu.com", TYPE_A, msg_id=0x9000 + i)
            w.write_packet(make_eth_ip_udp("10.77.0.1", "10.77.0.2", 54000 + i, 53, q.to_wire()), ts=t)
            t += 5.0
            # NTP packet to port 123
            w.write_packet(make_eth_ip_udp("10.77.0.1", "192.0.2.123", 54100 + i, 123, b"\x1b" + b"\x00" * 47), ts=t)
            t += 5.0
        # Ubuntu package update check
        q = make_query("archive.ubuntu.com", TYPE_A, msg_id=0x9100)
        w.write_packet(make_eth_ip_udp("10.77.0.1", "10.77.0.2", 54200, 53, q.to_wire()), ts=t)
    generated["benign_linux"] = benign_pcap

    return generated


if __name__ == "__main__":
    out_dir = ROOT / "eval" / "scenarios"
    res = generate_all_scenario_pcaps(out_dir)
    print(f"[✓] Generated {len(res)} scenario PCAPs in {out_dir}")
    for name, p in res.items():
        print(f"    - {name}: {p.name} ({p.stat().st_size:,} bytes)")
