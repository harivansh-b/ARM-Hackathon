"""Network sensor performance and throughput benchmark suite.

Measures:
1. DNS wire parser throughput (queries/sec, MB/s)
2. Flow table packet ingestion rate (pkts/sec)
3. DNS Sentinel latency distribution (median, p95, p99 ms)
4. Peak process memory (RSS)

Records run manifest reusing person-a/bench/manifest.py.
All measurements are honestly labelled 'ARM64 Linux VM under QEMU'.
"""
from __future__ import annotations

import io
import json
import os
import resource
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

REPO_ROOT = ROOT.parent
PERSON_A_PATH = REPO_ROOT / "person-a"
if str(PERSON_A_PATH) not in sys.path:
    sys.path.insert(0, str(PERSON_A_PATH))

try:
    from bench.manifest import manifest  # type: ignore
except ImportError:
    import platform
    def manifest(extra: dict | None = None) -> dict:
        d = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "machine": platform.machine(),
            "target_label": "ARM64 Linux VM under QEMU",
            "python": sys.version.split()[0],
        }
        d.update(extra or {})
        return d

from guardian_net.dns_sentinel import DNSSentinel
from guardian_net.dnswire import DNSMessage, TYPE_A, make_query, make_response
from guardian_net.flows import FlowTable
from guardian_net.pcapio import ParsedPacket, TCP_SYN


def bench_dnswire_throughput(iterations: int = 20000) -> dict:
    """Benchmark raw DNS packet parsing and building throughput."""
    q = make_query("api-service.production.test", TYPE_A, msg_id=0xABCD)
    q_wire = q.to_wire()
    wire_size = len(q_wire)

    # 1. Parse throughput
    t0 = time.perf_counter()
    for _ in range(iterations):
        DNSMessage.parse(q_wire)
    parse_time = time.perf_counter() - t0
    parse_qps = iterations / parse_time
    parse_mb_s = (iterations * wire_size) / (parse_time * 1024 * 1024)

    # 2. Build throughput
    t1 = time.perf_counter()
    for _ in range(iterations):
        q.to_wire()
    build_time = time.perf_counter() - t1
    build_qps = iterations / build_time

    return {
        "iterations": iterations,
        "packet_size_bytes": wire_size,
        "parse_qps": round(parse_qps, 0),
        "parse_mb_s": round(parse_mb_s, 2),
        "build_qps": round(build_qps, 0),
    }


def bench_flow_table_throughput(iterations: int = 25000) -> dict:
    """Benchmark flow table packet ingestion and 5-tuple tracking."""
    table = FlowTable(max_flows=10000)
    # Pre-generate 100 sample packets
    packets = [
        ParsedPacket(
            timestamp=1000.0 + (i * 0.01),
            raw_packet=b"X" * 64,
            src_ip="10.77.0.1",
            dst_ip=f"10.77.0.{(i % 50) + 2}",
            proto="TCP",
            src_port=40000 + (i % 1000),
            dst_port=443,
            tcp_flags=TCP_SYN,
        )
        for i in range(100)
    ]

    t0 = time.perf_counter()
    for i in range(iterations):
        pkt = packets[i % 100]
        table.add_packet(pkt)
    elapsed = time.perf_counter() - t0
    pps = iterations / elapsed

    return {
        "iterations": iterations,
        "elapsed_sec": round(elapsed, 4),
        "packets_per_second": round(pps, 0),
        "active_flows": len(table),
    }


def bench_sentinel_latency(iterations: int = 500) -> dict:
    """Benchmark end-to-end forwarder latency distribution."""
    # Create simple loopback echo upstream
    up_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    up_sock.bind(("127.0.0.1", 0))
    up_port = up_sock.getsockname()[1]

    running = True
    def mock_echo():
        up_sock.settimeout(0.5)
        while running:
            try:
                data, addr = up_sock.recvfrom(4096)
                up_sock.sendto(data, addr)
            except Exception:
                pass
    t_echo = threading.Thread(target=mock_echo, daemon=True)
    t_echo.start()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        sent_port = s.getsockname()[1]

    with tempfile.TemporaryDirectory() as tmpdir:
        ev_file = Path(tmpdir) / "bench_evidence.jsonl"
        sentinel = DNSSentinel(
            listen_host="127.0.0.1",
            listen_port=sent_port,
            upstream_host="127.0.0.1",
            upstream_port=up_port,
            evidence_file=ev_file,
            timeout=1.0,
        )
        sentinel.start()
        time.sleep(0.05)

        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(2.0)
        q = make_query("bench.test", TYPE_A, msg_id=1)
        wire = q.to_wire()

        for _ in range(iterations):
            client.sendto(wire, ("127.0.0.1", sent_port))
            try:
                client.recvfrom(4096)
            except Exception:
                pass

        client.close()
        summary = sentinel.metrics.summary()
        sentinel.stop()
        running = False
        up_sock.close()

    return summary


def get_peak_memory_kb() -> int:
    """Return max RSS memory in kilobytes."""
    usage = resource.getrusage(resource.RUSAGE_SELF)
    # On Linux ru_maxrss is in kilobytes; on macOS it is in bytes
    return usage.ru_maxrss


def run_all_benchmarks() -> dict:
    print("[*] Running Guardian Network Sensor Benchmarks...")
    print("    Target environment: ARM64 Linux VM under QEMU")

    dnswire_res = bench_dnswire_throughput(20000)
    print(f"[✓] DNS Parser throughput: {dnswire_res['parse_qps']:,} queries/sec ({dnswire_res['parse_mb_s']} MB/s)")

    flows_res = bench_flow_table_throughput(25000)
    print(f"[✓] Flow Table throughput: {flows_res['packets_per_second']:,} packets/sec")

    latency_res = bench_sentinel_latency(500)
    print(f"[✓] Sentinel latency (n={latency_res['total']}): median={latency_res['median_ms']} ms, p95={latency_res['p95_ms']} ms, p99={latency_res['p99_ms']} ms")

    peak_rss_kb = get_peak_memory_kb()
    print(f"[✓] Peak Memory (RSS): {peak_rss_kb:,} KB")

    run_manifest = manifest(
        extra={
            "environment_label": "ARM64 Linux VM under QEMU",
            "component": "Person B (Network Sensor)",
            "benchmark_results": {
                "dnswire": dnswire_res,
                "flows": flows_res,
                "sentinel_latency": latency_res,
                "peak_rss_kb": peak_rss_kb,
            },
        }
    )

    out_file = ROOT / "bench" / "results.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(run_manifest, indent=2), encoding="utf-8")
    print(f"[✓] Benchmark manifest saved to {out_file}")
    return run_manifest


if __name__ == "__main__":
    run_all_benchmarks()
