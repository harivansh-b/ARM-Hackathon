"""DNS Sentinel: Local UDP + TCP DNS forwarder with structured evidence logging.

Features:
- Configurable listen port and upstream resolver
- Handles UDP queries and TCP stream connections
- Preserves EDNS0 and TC (truncation) flags
- Handles concurrent client requests using thread pools
- Fails open: parsing or inspection errors never drop or block traffic; raw packets pass through
- Emits structured DNS evidence to JSONL matching Person C contract
- Tracks latency metrics (median, p95) and success rate
"""
from __future__ import annotations

import json
import logging
import os
import socket
import struct
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Callable

from .dnswire import (
    DNSMessage,
    DNSWireError,
    RCODE_NOERROR,
    RCODE_SERVFAIL,
    TYPE_A,
    TYPE_AAAA,
    TYPE_CNAME,
    TYPE_NAMES,
    make_response,
)
from .evidence import append_evidence_jsonl, create_evidence

logger = logging.getLogger("guardian_net.dns_sentinel")

DEFAULT_REPORT_PATH = Path(__file__).resolve().parents[1] / "reports" / "net_evidence.jsonl"


class SentinelMetrics:
    """Thread-safe latency and performance metrics tracker."""

    def __init__(self, max_samples: int = 10000) -> None:
        self._lock = threading.Lock()
        self.total_queries = 0
        self.successful_queries = 0
        self.failed_queries = 0
        self.fallback_raw_forwarded = 0
        self.latencies_ms: deque[float] = deque(maxlen=max_samples)

    def record_query(self, latency_ms: float, success: bool, fallback_raw: bool = False) -> None:
        with self._lock:
            self.total_queries += 1
            if success:
                self.successful_queries += 1
            else:
                self.failed_queries += 1
            if fallback_raw:
                self.fallback_raw_forwarded += 1
            self.latencies_ms.append(latency_ms)

    def summary(self) -> dict[str, Any]:
        with self._lock:
            total = self.total_queries
            success = self.successful_queries
            rate = (success / total * 100.0) if total > 0 else 100.0
            lats = sorted(self.latencies_ms)
            n = len(lats)
            if n == 0:
                return {
                    "total": total,
                    "success": success,
                    "success_rate_pct": rate,
                    "median_ms": 0.0,
                    "p95_ms": 0.0,
                    "p99_ms": 0.0,
                }
            median_ms = lats[n // 2]
            p95_idx = int(n * 0.95)
            p95_ms = lats[min(p95_idx, n - 1)]
            p99_idx = int(n * 0.99)
            p99_ms = lats[min(p99_idx, n - 1)]
            return {
                "total": total,
                "success": success,
                "failed": self.failed_queries,
                "fallback_raw": self.fallback_raw_forwarded,
                "success_rate_pct": round(rate, 2),
                "median_ms": round(median_ms, 2),
                "p95_ms": round(p95_ms, 2),
                "p99_ms": round(p99_ms, 2),
            }


class DNSSentinel:
    """UDP and TCP DNS Sentinel forwarder with telemetry emission."""

    def __init__(
        self,
        listen_host: str = "127.0.0.1",
        listen_port: int = 5353,
        upstream_host: str = "10.77.0.2",
        upstream_port: int = 53,
        evidence_file: Path | str | None = None,
        timeout: float = 2.0,
        inspector: Callable[[DNSMessage, DNSMessage | None, float], dict[str, Any] | None] | None = None,
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.timeout = timeout
        self.evidence_file = Path(evidence_file) if evidence_file else DEFAULT_REPORT_PATH
        self.inspector = inspector

        self.metrics = SentinelMetrics()
        self._running = False
        self._udp_sock: socket.socket | None = None
        self._tcp_sock: socket.socket | None = None
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        """Start both UDP and TCP forwarder listeners."""
        if self._running:
            return
        self._running = True

        # UDP socket
        self._udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp_sock.bind((self.listen_host, self.listen_port))

        # TCP socket
        self._tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tcp_sock.bind((self.listen_host, self.listen_port))
        self._tcp_sock.listen(64)

        t_udp = threading.Thread(target=self._run_udp_server, daemon=True, name="sentinel-udp")
        t_tcp = threading.Thread(target=self._run_tcp_server, daemon=True, name="sentinel-tcp")
        self._threads = [t_udp, t_tcp]
        t_udp.start()
        t_tcp.start()
        logger.info(
            f"DNS Sentinel listening on {self.listen_host}:{self.listen_port} (forwarding to {self.upstream_host}:{self.upstream_port})"
        )

    def stop(self) -> None:
        """Stop listeners and close sockets."""
        self._running = False
        if self._udp_sock:
            try:
                self._udp_sock.close()
            except Exception:
                pass
        if self._tcp_sock:
            try:
                self._tcp_sock.close()
            except Exception:
                pass
        for t in self._threads:
            t.join(timeout=1.0)
        self._threads.clear()

    def _run_udp_server(self) -> None:
        sock = self._udp_sock
        if not sock:
            return
        sock.settimeout(0.5)
        while self._running:
            try:
                data, client_addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle_udp_query,
                args=(data, client_addr),
                daemon=True,
            ).start()

    def _handle_udp_query(self, query_bytes: bytes, client_addr: tuple[str, int]) -> None:
        start_time = time.perf_counter()
        parsed_query: DNSMessage | None = None
        fallback_raw = False

        try:
            parsed_query = DNSMessage.parse(query_bytes)
        except Exception as e:
            fallback_raw = True
            logger.debug(f"Query parse error from {client_addr}, failing open: {e}")

        # Forward query to upstream over UDP
        response_bytes: bytes | None = None
        up_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        up_sock.settimeout(self.timeout)
        success = False

        try:
            up_sock.sendto(query_bytes, (self.upstream_host, self.upstream_port))
            response_bytes, _ = up_sock.recvfrom(4096)
            success = True
        except Exception as err:
            logger.debug(f"Upstream UDP forward error: {err}")
            # If upstream failed and we parsed query, build a SERVFAIL response so client isn't hung
            if parsed_query:
                try:
                    servfail = make_response(parsed_query, rcode=RCODE_SERVFAIL)
                    response_bytes = servfail.to_wire()
                except Exception:
                    response_bytes = None
        finally:
            up_sock.close()

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        if response_bytes and self._udp_sock and self._running:
            try:
                self._udp_sock.sendto(response_bytes, client_addr)
            except OSError:
                pass

        self.metrics.record_query(elapsed_ms, success, fallback_raw)

        # Telemetry & Evidence logging
        parsed_resp: DNSMessage | None = None
        if response_bytes:
            try:
                parsed_resp = DNSMessage.parse(response_bytes)
            except Exception:
                pass

        self._emit_telemetry(parsed_query, parsed_resp, elapsed_ms, client_addr[0])

    def _run_tcp_server(self) -> None:
        sock = self._tcp_sock
        if not sock:
            return
        sock.settimeout(0.5)
        while self._running:
            try:
                client_conn, client_addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle_tcp_connection,
                args=(client_conn, client_addr),
                daemon=True,
            ).start()

    def _handle_tcp_connection(self, conn: socket.socket, client_addr: tuple[str, int]) -> None:
        conn.settimeout(self.timeout)
        try:
            while self._running:
                # DNS over TCP prefixes each message with a 2-byte length
                hdr = self._recv_exact(conn, 2)
                if not hdr:
                    break
                (msg_len,) = struct.unpack("!H", hdr)
                query_bytes = self._recv_exact(conn, msg_len)
                if not query_bytes:
                    break

                start_time = time.perf_counter()
                parsed_query: DNSMessage | None = None
                fallback_raw = False
                try:
                    parsed_query = DNSMessage.parse(query_bytes)
                except Exception:
                    fallback_raw = True

                # Forward to upstream over TCP
                response_bytes = self._forward_tcp_upstream(query_bytes)
                success = response_bytes is not None
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0

                if response_bytes:
                    out = struct.pack("!H", len(response_bytes)) + response_bytes
                    conn.sendall(out)

                self.metrics.record_query(elapsed_ms, success, fallback_raw)

                parsed_resp: DNSMessage | None = None
                if response_bytes:
                    try:
                        parsed_resp = DNSMessage.parse(response_bytes)
                    except Exception:
                        pass
                self._emit_telemetry(parsed_query, parsed_resp, elapsed_ms, client_addr[0])
        except Exception as e:
            logger.debug(f"TCP client error {client_addr}: {e}")
        finally:
            conn.close()

    def _forward_tcp_upstream(self, query_bytes: bytes) -> bytes | None:
        up = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        up.settimeout(self.timeout)
        try:
            up.connect((self.upstream_host, self.upstream_port))
            up.sendall(struct.pack("!H", len(query_bytes)) + query_bytes)
            raw_len = self._recv_exact(up, 2)
            if not raw_len:
                return None
            (resp_len,) = struct.unpack("!H", raw_len)
            return self._recv_exact(up, resp_len)
        except Exception:
            return None
        finally:
            up.close()

    @staticmethod
    def _recv_exact(sock: socket.socket, count: int) -> bytes | None:
        buf = bytearray()
        while len(buf) < count:
            try:
                chunk = sock.recv(count - len(buf))
                if not chunk:
                    return None
                buf.extend(chunk)
            except OSError:
                return None
        return bytes(buf)

    def _emit_telemetry(
        self,
        query: DNSMessage | None,
        response: DNSMessage | None,
        latency_ms: float,
        client_ip: str,
    ) -> None:
        if not query or not query.questions:
            return

        qname = query.first_question_name
        qtype = query.first_question_type_name
        rcode = response.rcode if response else RCODE_SERVFAIL

        resolved_ips: list[str] = []
        cnames: list[str] = []
        if response:
            for rr in response.answers:
                if rr.rtype in (TYPE_A, TYPE_AAAA) and isinstance(rr.rdata, str):
                    resolved_ips.append(rr.rdata)
                elif rr.rtype == TYPE_CNAME and isinstance(rr.rdata, str):
                    cnames.append(rr.rdata)

        # If a custom inspector/detector callback is registered, run it
        custom_evidence = None
        if self.inspector:
            try:
                custom_evidence = self.inspector(query, response, latency_ms)
            except Exception as e:
                logger.debug(f"Inspector hook error: {e}")

        if custom_evidence:
            # Preserve detector evidence while attaching DNS response context needed
            # for downstream DNS -> CONNECTION correlation.
            metadata = custom_evidence.setdefault("metadata", {})
            metadata.update({
                "qtype": qtype,
                "rcode": rcode,
                "resolved_ips": resolved_ips,
                "cnames": cnames,
                "latency_ms": round(latency_ms, 2),
                "client_ip": client_ip,
                "tc": response.is_tc if response else False,
            })
            append_evidence_jsonl(custom_evidence, self.evidence_file)
            return

        # Default telemetry record (INFO tier unless NXDOMAIN / error)
        score = 0.0
        reasons = [f"DNS query {qtype} for {qname}"]
        if rcode == RCODE_SERVFAIL:
            reasons.append("Upstream resolution failed (SERVFAIL)")
            score = 0.2

        rec = create_evidence(
            source="DNS",
            event_type="DNS_QUERY",
            entity_type="DOMAIN",
            entity_value=qname,
            score=score,
            reasons=reasons,
            metadata={
                "qtype": qtype,
                "rcode": rcode,
                "resolved_ips": resolved_ips,
                "cnames": cnames,
                "latency_ms": round(latency_ms, 2),
                "client_ip": client_ip,
                "tc": response.is_tc if response else False,
            },
        )
        append_evidence_jsonl(rec, self.evidence_file)
