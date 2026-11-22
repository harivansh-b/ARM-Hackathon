"""Build a signed offline domain bundle from PhishTank/OpenPhish snapshots."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import date, timedelta
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "person-c"))
from guardian_models.bundles import sign_bundle


def hostname(raw: str) -> str | None:
    value = raw.strip()
    if not value:
        return None
    parsed = urlparse(value if "://" in value else "http://" + value)
    host = (parsed.hostname or "").strip().lower().strip(".")
    return host or None


def read_openphish(path: Path) -> set[str]:
    return {host for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if (host := hostname(line))}


def read_phishtank(path: Path) -> set[str]:
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as handle:
        return {host for row in csv.DictReader(handle) if (host := hostname(row.get("url", "")))}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openphish", type=Path)
    parser.add_argument("--phishtank", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--key", required=True, help="HMAC key for the prototype bundle signer")
    parser.add_argument("--version", type=int, default=1)
    parser.add_argument("--expires-days", type=int, default=30)
    args = parser.parse_args()

    domains: set[str] = set()
    sources: dict[str, int] = {}
    if args.openphish and args.openphish.exists():
        values = read_openphish(args.openphish)
        domains.update(values)
        sources["openphish"] = len(values)
    if args.phishtank and args.phishtank.exists():
        values = read_phishtank(args.phishtank)
        domains.update(values)
        sources["phishtank"] = len(values)
    if not domains:
        raise SystemExit("no threat-feed domains found")

    payload = {
        "domains": sorted(domains),
        "ips": [],
        "ja4s": [],
        "sources": sources,
        "feed_role": "known_phishing_domain_lookup",
        "raw_urls_not_retained": True,
        "generated_at": date.today().isoformat(),
    }
    bundle = sign_bundle(payload, args.key.encode("utf-8"), args.version, (date.today() + timedelta(days=args.expires_days)).isoformat())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "domains": len(domains), "sources": sources}, indent=2))


if __name__ == "__main__":
    main()
