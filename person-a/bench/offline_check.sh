#!/usr/bin/env bash
# Run the full scan with no network at all (new network namespace). Usage: bench/offline_check.sh <input> <artifact>
set -e
cd "$(dirname "$0")/.."
if unshare -rn true 2>/dev/null; then
  echo "== inside empty network namespace: interfaces =="; unshare -rn ip -br link || true
  unshare -rn python3 -m guardian_app.scan --input "$1" --artifact "$2" --out /tmp/offline_report.json
else
  echo "unshare -rn not permitted; try: sudo unshare -n -- sudo -u $USER ..."; exit 1
fi
echo "OFFLINE RUN OK"
