"""Unit tests and benchmarks for DNS Sentinel."""
import json
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from guardian_net.dns_sentinel import DNSSentinel
from guardian_net.dnswire import (
    DNSHeader,
    DNSMessage,
    DNSResourceRecord,
    RCODE_NOERROR,
    TYPE_A,
    TYPE_TXT,
    make_query,
    make_response,
)


class MockUpstreamDNS:
    """Mock upstream DNS server handling UDP and TCP."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.bind((host, port))
        self.port = self.udp_sock.getsockname()[1]

        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.bind((host, self.port))
        self.tcp_sock.listen(16)

        self.running = True
        self.t_udp = threading.Thread(target=self._run_udp, daemon=True)
        self.t_tcp = threading.Thread(target=self._run_tcp, daemon=True)
        self.t_udp.start()
        self.t_tcp.start()

    def _resolve(self, req_bytes: bytes) -> bytes:
        try:
            req = DNSMessage.parse(req_bytes)
            name = req.first_question_name
            if "tc-test" in name:
                resp = make_response(req)
                resp.header.tc = 1
                return resp.to_wire()
            ans = [DNSResourceRecord(name, TYPE_A, 1, 60, "10.77.0.99")]
            resp = make_response(req, answers=ans)
            return resp.to_wire()
        except Exception:
            return req_bytes

    def _run_udp(self) -> None:
        self.udp_sock.settimeout(0.5)
        while self.running:
            try:
                data, addr = self.udp_sock.recvfrom(4096)
                resp = self._resolve(data)
                self.udp_sock.sendto(resp, addr)
            except (socket.timeout, OSError):
                continue

    def _run_tcp(self) -> None:
        self.tcp_sock.settimeout(0.5)
        while self.running:
            try:
                conn, _ = self.tcp_sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._handle_tcp_conn, args=(conn,), daemon=True).start()

    def _handle_tcp_conn(self, conn: socket.socket) -> None:
        try:
            raw_len = conn.recv(2)
            if raw_len and len(raw_len) == 2:
                (msg_len,) = struct.unpack("!H", raw_len)
                req_bytes = conn.recv(msg_len)
                resp = self._resolve(req_bytes)
                conn.sendall(struct.pack("!H", len(resp)) + resp)
        finally:
            conn.close()

    def close(self) -> None:
        self.running = False
        try:
            self.udp_sock.close()
        except Exception:
            pass
        try:
            self.tcp_sock.close()
        except Exception:
            pass


class TestDNSSentinel(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.evidence_path = Path(self.temp_dir.name) / "test_evidence.jsonl"
        self.upstream = MockUpstreamDNS()

        # Find free port for sentinel
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(("127.0.0.1", 0))
            self.sentinel_port = s.getsockname()[1]

        self.sentinel = DNSSentinel(
            listen_host="127.0.0.1",
            listen_port=self.sentinel_port,
            upstream_host=self.upstream.host,
            upstream_port=self.upstream.port,
            evidence_file=self.evidence_path,
            timeout=1.0,
        )
        self.sentinel.start()
        time.sleep(0.05)  # Allow bind to settle

    def tearDown(self) -> None:
        self.sentinel.stop()
        self.upstream.close()
        self.temp_dir.cleanup()

    def test_udp_forward_and_evidence(self) -> None:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(2.0)
        query = make_query("safe.example.test", TYPE_A, msg_id=0x1122)
        client.sendto(query.to_wire(), ("127.0.0.1", self.sentinel_port))
        data, _ = client.recvfrom(4096)
        client.close()

        resp = DNSMessage.parse(data)
        self.assertEqual(resp.id, 0x1122)
        self.assertEqual(len(resp.answers), 1)
        self.assertEqual(resp.answers[0].rdata, "10.77.0.99")

        # Give sentinel brief moment to write evidence
        time.sleep(0.05)
        self.assertTrue(self.evidence_path.exists())
        lines = self.evidence_path.read_text(encoding="utf-8").strip().split("\n")
        self.assertGreaterEqual(len(lines), 1)
        rec = json.loads(lines[-1])
        self.assertEqual(rec["source"], "DNS")
        self.assertEqual(rec["entity"]["value"], "safe.example.test")
        self.assertEqual(rec["event_type"], "DNS_QUERY")
        self.assertEqual(rec["metadata"]["resolved_ips"], ["10.77.0.99"])

    def test_custom_inspector_evidence_includes_resolution_metadata(self) -> None:
        custom_record = {
            "evidence_id": "TEST123",
            "source": "DNS",
            "event_type": "DNS_TUNNEL",
            "timestamp": 123,
            "entity": {"type": "DOMAIN", "value": "inspect.example.test"},
            "risk_tier": "HIGH",
            "score": 0.8,
            "reasons": ["test detector"],
            "metadata": {"detector_feature": "kept"},
        }
        sentinel = DNSSentinel(
            evidence_file=self.evidence_path,
            inspector=lambda query, response, latency: custom_record,
        )
        query = make_query("inspect.example.test", TYPE_A)
        response = make_response(query, answers=[
            DNSResourceRecord("inspect.example.test", TYPE_A, 1, 60, "10.77.0.55")
        ])
        sentinel._emit_telemetry(query, response, 12.5, "127.0.0.8")

        rec = json.loads(self.evidence_path.read_text(encoding="utf-8").strip())
        self.assertEqual(rec["event_type"], "DNS_TUNNEL")
        self.assertEqual(rec["metadata"]["detector_feature"], "kept")
        self.assertEqual(rec["metadata"]["resolved_ips"], ["10.77.0.55"])
        self.assertEqual(rec["metadata"]["client_ip"], "127.0.0.8")
        self.assertEqual(rec["metadata"]["qtype"], "A")

    def test_tcp_forward_and_evidence(self) -> None:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(2.0)
        client.connect(("127.0.0.1", self.sentinel_port))
        query = make_query("tcp.example.test", TYPE_A, msg_id=0x3344)
        qwire = query.to_wire()
        client.sendall(struct.pack("!H", len(qwire)) + qwire)

        raw_len = client.recv(2)
        (rlen,) = struct.unpack("!H", raw_len)
        data = client.recv(rlen)
        client.close()

        resp = DNSMessage.parse(data)
        self.assertEqual(resp.id, 0x3344)
        self.assertEqual(resp.answers[0].rdata, "10.77.0.99")

    def test_tc_flag_preservation(self) -> None:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(2.0)
        query = make_query("tc-test.example.test", TYPE_A, msg_id=0x5566)
        client.sendto(query.to_wire(), ("127.0.0.1", self.sentinel_port))
        data, _ = client.recvfrom(4096)
        client.close()

        resp = DNSMessage.parse(data)
        self.assertEqual(resp.header.tc, 1)

    def test_concurrent_clients_and_metrics(self) -> None:
        num_threads = 10
        queries_per_thread = 15
        errors = []

        def worker(w_id: int) -> None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            for i in range(queries_per_thread):
                q = make_query(f"host-{w_id}-{i}.test", TYPE_A, msg_id=(w_id * 100 + i))
                try:
                    sock.sendto(q.to_wire(), ("127.0.0.1", self.sentinel_port))
                    data, _ = sock.recvfrom(4096)
                    resp = DNSMessage.parse(data)
                    if resp.id != (w_id * 100 + i):
                        errors.append(f"Mismatch ID: {resp.id}")
                except Exception as ex:
                    errors.append(str(ex))
            sock.close()

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Errors encountered: {errors}")
        summary = self.sentinel.metrics.summary()
        self.assertEqual(summary["total"], num_threads * queries_per_thread)
        self.assertEqual(summary["success_rate_pct"], 100.0)
        self.assertGreater(summary["median_ms"], 0.0)
        self.assertGreaterEqual(summary["p95_ms"], summary["median_ms"])


if __name__ == "__main__":
    unittest.main()
