"""Evaluate Guardian's offline URL heuristic on a labelled URL CSV.

The adapter is intentionally dependency-free and accepts common ISCX-URL2016
mirrors. It never opens URLs or performs DNS/WHOIS lookups.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "person-c"))

from guardian_models.detectors import analyze_url  # noqa: E402
from guardian_models.metrics import binary_metrics  # noqa: E402


def choose_column(fieldnames: list[str], candidates: tuple[str, ...]) -> str:
    lowered = {name.casefold().strip(): name for name in fieldnames}
    for candidate in candidates:
        if candidate.casefold() in lowered:
            return lowered[candidate.casefold()]
    raise ValueError(f"none of {candidates} found in CSV columns: {fieldnames}")


def is_benign(label: str) -> bool:
    clean = label.casefold().strip()
    return clean in {"0", "benign", "legitimate", "legit", "normal", "safe"} or "benign" in clean


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_path", type=Path)
    parser.add_argument("--url-column")
    parser.add_argument("--label-column")
    parser.add_argument("--threshold", type=float, default=0.35)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    with args.csv_path.open(newline="", encoding="utf-8-sig", errors="replace") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames or []
        url_column = args.url_column or choose_column(fields, ("url", "URL", "url_string", "URL_string"))
        label_column = args.label_column or choose_column(fields, ("label", "type", "URL_Type_obf_Type", "class"))
        labels: list[int] = []
        scores: list[float] = []
        by_label: dict[str, list[tuple[int, float]]] = defaultdict(list)
        skipped = 0
        for row in reader:
            url = (row.get(url_column) or "").strip()
            label = (row.get(label_column) or "").strip()
            if not url or not label:
                skipped += 1
                continue
            score = float(analyze_url(url)["score"])
            binary_label = 0 if is_benign(label) else 1
            labels.append(binary_label)
            scores.append(score)
            by_label[label].append((binary_label, score))

    report = {
        "dataset": str(args.csv_path),
        "url_column": url_column,
        "label_column": label_column,
        "threshold": args.threshold,
        "records": len(labels),
        "skipped": skipped,
        "note": "URL structure only; no network lookups were performed.",
        "overall": binary_metrics(labels, scores, threshold=args.threshold) if labels else {},
        "by_source_label": {
            key: binary_metrics([item[0] for item in values], [item[1] for item in values], threshold=args.threshold)
            for key, values in sorted(by_label.items())
        },
    }
    rendered = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
