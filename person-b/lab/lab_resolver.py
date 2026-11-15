"""Lab authoritative DNS resolver running inside the isolated 'lab' namespace.

Responds to scenario queries:
- smishing link: phish-bank.test -> 10.77.0.2
- C2 domain: c2.beacon-control.test -> 10.77.0.2
- DNS tunnel: *.tunnel.data-exfil.test -> TXT ACK
- Standard records: A, AAAA, TXT
- NXDOMAIN for unregistered or simulated DGA domains
"""
from __future__ import annotations

import argparse
import socket
import struct
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from guardian_net.dnswire import (
    DNSMessage,
    DNSResourceRecord,
    RCODE_NOERROR,
    RCODE_NXDOMAIN,
    TYPE_A,
    TYPE_AAAA,
    TYPE_TXT,
    make_response,
)

ZONE_RECORDS: dict[str, dict[int, list[str]]] = {
    "phish-bank.test": {TYPE_A: ["10.77.0.2"]},
    "c2.beacon-control.test": {TYPE_A: ["10.77.0.2"]},
    "safe-service.test": {TYPE_A: ["10.77.0.2"], TYPE_AAAA: ["fd77::2"]},
}


def resolve_message(query: DNSMessage) -> DNSMessage:
    qname = query.first_question_name
    qtype = query.questions[0].qtype if query.questions else TYPE_A

    answers: list[DNSResourceRecord] = []
    rcode = RCODE_NOERROR

    # Check for DNS tunnel pattern
    if qname.endswith("tunnel.data-exfil.test"):
        if qtype == TYPE_TXT:
            answers.append(DNSResourceRecord(qname, TYPE_TXT, 1, 10, ["ACK:RECEIVED"]))
        else:
            answers.append(DNSResourceRecord(qname, TYPE_A, 1, 10, "10.77.0.2"))
        return make_response(query, rcode=RCODE_NOERROR, answers=answers)

    # Check static zone table
    if qname in ZONE_RECORDS and qtype in ZONE_RECORDS[qname]:
        for rdata in ZONE_RECORDS[qname][qtype]:
            answers.append(DNSResourceRecord(qname, qtype, 1, 300, rdata))
    elif qname in ZONE_RECORDS:
        # Name exists but type differs (NOERROR with no answers)
        pass
    else:
        # NXDOMAIN
        rcode = RCODE_NXDOMAIN

    return make_response(query, rcode=rcode, answers=answers)


def run_udp_server(host: str, port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    print(f"[+] Lab Resolver listening on UDP {host}:{port}")
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            query = DNSMessage.parse(data)
            resp = resolve_message(query)
            sock.sendto(resp.to_wire(), addr)
        except Exception as e:
            pass


def run_tcp_server(host: str, port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(32)
    print(f"[+] Lab Resolver listening on TCP {host}:{port}")
    while True:
        try:
            conn, _ = sock.accept()
            threading.Thread(target=_handle_tcp_client, args=(conn,), daemon=True).start()
        except Exception:
            break


def _handle_tcp_client(conn: socket.socket) -> None:
    try:
        raw_len = conn.recv(2)
        if len(raw_len) == 2:
            (msg_len,) = struct.unpack("!H", raw_len)
            req = conn.recv(msg_len)
            query = DNSMessage.parse(req)
            resp = resolve_message(query)
            resp_wire = resp.to_wire()
            conn.sendall(struct.pack("!H", len(resp_wire)) + resp_wire)
    except Exception:
        pass
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Guardian Lab DNS Resolver")
    parser.add_argument("--host", default="10.77.0.2", help="Bind IP (default 10.77.0.2)")
    parser.add_argument("--port", type=int, default=53, help="Bind port (default 53)")
    args = parser.parse_args()

    t_udp = threading.Thread(target=run_udp_server, args=(args.host, args.port), daemon=True)
    t_udp.start()
    run_tcp_server(args.host, args.port)


if __name__ == "__main__":
    main()
