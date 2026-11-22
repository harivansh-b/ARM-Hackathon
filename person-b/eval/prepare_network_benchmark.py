"""Normalize CICIDS2017, UNSW-NB15 or DNS benchmark CSVs offline.

This creates a small, schema-stable JSONL view without copying raw benchmark
files into the repository. Numeric features are retained for later model
training; identifiers and free-text columns are excluded by default.
"""

from __future__ import annotations

import argparse
import csv
import math
import json
import re
from pathlib import Path


LABEL_COLUMNS = ("label", "attack_cat", "attack category", "class", "type")
ID_COLUMNS = re.compile(r"^(flow id|source ip|destination ip|timestamp|id|unnamed)", re.I)


def find_label(fields: list[str], explicit: str | None) -> str:
    if explicit:
        if explicit not in fields:
            raise ValueError(f"label column not found: {explicit}")
        return explicit
    lowered = {field.casefold().strip(): field for field in fields}
    for candidate in LABEL_COLUMNS:
        if candidate in lowered:
            return lowered[candidate]
    raise ValueError(f"could not identify label column in {fields}")


def numeric(value: str) -> int | float | None:
    clean = value.strip()
    if not clean:
        return None
    try:
        number = float(clean)
    except ValueError:
        return None
    if not math.isfinite(number):
        return None
    return int(number) if number.is_integer() else number


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_path", type=Path)
    parser.add_argument("output_jsonl", type=Path)
    parser.add_argument("--dataset", required=True, choices=("cicids2017", "unsw-nb15", "dns-exf"))
    parser.add_argument("--label-column")
    parser.add_argument("--max-records", type=int)
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()

    with args.csv_path.open(newline="", encoding="utf-8-sig", errors="replace") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames or []
        label_column = find_label(fields, args.label_column)
        feature_columns = [
            field for field in fields
            if field != label_column and not ID_COLUMNS.match(field.strip())
        ]
        args.output_jsonl.parent.mkdir(parents=True, exist_ok=True)
        counts: dict[str, int] = {}
        written = 0
        with args.output_jsonl.open("w", encoding="utf-8") as output:
            for row in reader:
                if args.max_records is not None and written >= args.max_records:
                    break
                label = (row.get(label_column) or "").strip()
                if not label:
                    continue
                features = {
                    field: numeric(row.get(field, ""))
                    for field in feature_columns
                    if numeric(row.get(field, "")) is not None
                }
                normalized = {
                    "record_id": written,
                    "dataset": args.dataset,
                    "label": label,
                    "is_attack": not (
                        label.casefold() in {"0", "benign", "normal", "safe"}
                        or "benign" in label.casefold()
                        or "normal" in label.casefold()
                    ),
                    "features": features,
                }
                output.write(json.dumps(normalized, ensure_ascii=False) + "\n")
                counts[label] = counts.get(label, 0) + 1
                written += 1

    manifest = {
        "dataset": args.dataset,
        "input": str(args.csv_path).replace("\\", "/"),
        "output": str(args.output_jsonl).replace("\\", "/"),
        "label_column": label_column,
        "input_feature_count": len(fields) - 1,
        "numeric_feature_count": len(feature_columns),
        "records": written,
        "label_counts": counts,
        "raw_data_copied": False,
        "offline_only": True,
    }
    if args.manifest:
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
