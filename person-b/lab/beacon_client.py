"""Beacon client simulating an infected host contacting C2 with periodic jitter."""
from __future__ import annotations

import argparse
import random
import socket
import struct
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from guardian_net.tls_hello import EXT_SERVER_NAME


def make_tls_hello(sni: str) -> bytes:
    """Build a minimal TLS ClientHello with SNI."""
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
        + (b"\x02" * 32)
        + b"\x00"  # session id len
        + struct.pack("!H", len(ciphers))
        + ciphers
        + b"\x01\x00"  # comp
        + struct.pack("!H", len(sni_ext))
        + sni_ext
    )
    msg = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return struct.pack("!BHH", 0x16, 0x0301, len(msg)) + msg


def run_beacon(
    target_host: str,
    target_port: int,
    count: int = 8,
    interval_sec: float = 3.0,
    jitter_pct: float = 0.15,
    use_tls: bool = True,
    sni: str = "c2.beacon-control.test",
) -> None:
    print(f"[*] Starting beacon client targeting {target_host}:{target_port} (interval ~{interval_sec}s, jitter ±{jitter_pct*100:.0f}%)")
    hello_payload = make_tls_hello(sni) if use_tls else b"HEARTBEAT\n"

    for i in range(1, count + 1):
        ts = time.strftime("%H:%M:%S")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((target_host, target_port))
            s.sendall(hello_payload)
            s.close()
            print(f"[{ts}] Beacon check-in #{i}/{count} sent successfully")
        except Exception as e:
            print(f"[{ts}] Beacon #{i} failed: {e}")

        if i < count:
            jitter = (random.random() * 2.0 - 1.0) * (interval_sec * jitter_pct)
            sleep_time = max(0.2, interval_sec + jitter)
            time.sleep(sleep_time)


def main() -> None:
    parser = argparse.ArgumentParser(description="Guardian Lab Beacon Client")
    parser.add_argument("--host", default="10.77.0.2")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--count", type=int, default=8)
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--jitter", type=float, default=0.15)
    parser.add_argument("--sni", default="c2.beacon-control.test")
    parser.add_argument("--no-tls", action="store_true")
    args = parser.parse_args()

    run_beacon(
        target_host=args.host,
        target_port=args.port,
        count=args.count,
        interval_sec=args.interval,
        jitter_pct=args.jitter,
        use_tls=not args.no_tls,
        sni=args.sni,
    )


if __name__ == "__main__":
    main()
