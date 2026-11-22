"""Evaluate signed feed lookup against malicious-feed and benign URL fixtures."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "person-b"))
sys.path.insert(0, str(ROOT / "person-c"))
from guardian_net.detectors.denylist import DenylistDetector
from guardian_models.bundles import verify_bundle


def host(raw: str) -> str:
    return (urlparse(raw if "://" in raw else "http://" + raw).hostname or "").lower().strip(".")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--malicious", type=Path, required=True)
    parser.add_argument("--benign", type=Path, required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    bundle = json.loads(args.bundle.read_text(encoding="utf-8"))
    verification = verify_bundle(bundle, args.key.encode("utf-8"), today=date.today().isoformat())
    if not verification["accepted"]:
        raise SystemExit(f"bundle verification failed: {verification['errors']}")
    detector = DenylistDetector()
    detector.load_bundle(bundle, args.key.encode("utf-8"))
    malicious = [host(line) for line in args.malicious.read_text(encoding="utf-8").splitlines() if host(line)]
    benign = [host(line) for line in args.benign.read_text(encoding="utf-8").splitlines() if host(line)]
    tp = sum(detector.check_domain(item) is not None for item in malicious)
    fp = sum(detector.check_domain(item) is not None for item in benign)
    report = {
        "bundle": str(args.bundle),
        "malicious_urls": len(malicious),
        "benign_urls": len(benign),
        "matched_malicious": tp,
        "matched_benign": fp,
        "lookup_recall": tp / len(malicious) if malicious else 0.0,
        "lookup_false_positive_rate": fp / len(benign) if benign else 0.0,
        "note": "Lookup integrity evaluation; this is not a population-level phishing prevalence estimate.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
