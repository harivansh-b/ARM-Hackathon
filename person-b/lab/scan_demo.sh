#!/bin/bash
# Outbound port scan demo against the isolated lab target
# Uses pure Python (stdlib) to probe multiple ports rapidly, triggering scan detection.

TARGET_IP="${1:-10.77.0.2}"
START_PORT="${2:-20}"
END_PORT="${3:-45}"

echo "[*] Launching outbound port scan demo against $TARGET_IP on ports $START_PORT..$END_PORT..."

python3 -c "
import socket, sys
target = '$TARGET_IP'
for port in range($START_PORT, $END_PORT + 1):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.05)
    try:
        s.connect((target, port))
        print(f'[+] Port {port}: OPEN')
        s.close()
    except Exception:
        pass
print('[✓] Port scan sequence finished.')
"
