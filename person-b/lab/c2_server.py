"""Lab C2 server running inside the isolated 'lab' namespace.

Simulates an adversary command-and-control endpoint:
- Receives periodic heartbeat beacon connections
- Accepts simulated data exfiltration uploads
- Standard library TCP socket server with mock HTTP/TLS banner
"""
from __future__ import annotations

import argparse
import socket
import sys
import threading
import time


def handle_client(conn: socket.socket, addr: tuple[str, int]) -> None:
    try:
        conn.settimeout(5.0)
        data = conn.recv(65536)
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] C2 received {len(data)} bytes from {addr[0]}:{addr[1]}")

        # If HTTP request, send standard HTTP response
        if b"HTTP/" in data:
            resp = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: 17\r\n"
                b"\r\n"
                b'{"status":"pong"}\n'
            )
            conn.sendall(resp)
        else:
            conn.sendall(b"ACK\n")
    except Exception:
        pass
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Guardian Lab C2 Server")
    parser.add_argument("--host", default="10.77.0.2", help="Bind IP")
    parser.add_argument("--port", type=int, default=443, help="Bind port")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(64)
    print(f"[+] Lab C2 Server listening on {args.host}:{args.port}")

    try:
        while True:
            conn, addr = sock.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[-] C2 Server stopping.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
