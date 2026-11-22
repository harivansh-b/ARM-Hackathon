"""Evaluate Guardian-aligned DNS heuristics on normalized DNS benchmark rows."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

import sys
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "person-c"))
from guardian_models.metrics import binary_metrics  # noqa: E402


def score(features: dict) -> float:
    """Mirror the privacy-preserving DNS signals used by DNSTunnelDetector."""
    value = 0.0
    if float(features.get("entropy", 0) or 0) >= 3.6:
        value += 0.35
    if float(features.get("labels_max", 0) or 0) >= 40:
        value += 0.30
    if float(features.get("FQDN_count", 0) or 0) >= 100:
        value += 0.15
    if float(features.get("subdomain_length", 0) or 0) >= 40:
        value += 0.30
    if float(features.get("TXT_frequency", 0) or 0) + float(features.get("NULL_frequency", 0) or 0) >= 0.5:
        value += 0.25
    return min(value, 0.99)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("normalized_jsonl", type=Path)
    parser.add_argument("--threshold", type=float, default=0.35)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    labels: list[int] = []
    scores: list[float] = []
    by_label: dict[str, list[tuple[int, float]]] = defaultdict(list)
    for line in args.normalized_jsonl.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        label = str(row["label"])
        binary_label = int(row["is_attack"])
        row_score = score(row["features"])
        labels.append(binary_label)
        scores.append(row_score)
        by_label[label].append((binary_label, row_score))

    report = {
        "dataset": str(args.normalized_jsonl),
        "threshold": args.threshold,
        "records": len(labels),
        "note": "Guardian-aligned stateless heuristic; no payloads or network lookups.",
        "overall": binary_metrics(labels, scores, args.threshold),
        "by_label": {
            label: binary_metrics([item[0] for item in values], [item[1] for item in values], args.threshold)
            for label, values in sorted(by_label.items())
        },
    }
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
