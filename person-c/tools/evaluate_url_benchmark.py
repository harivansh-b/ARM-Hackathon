"""Evaluate Guardian's offline URL heuristic on a labelled URL CSV.

The adapter is intentionally dependency-free and accepts common ISCX-URL2016
mirrors. It never opens URLs or performs DNS/WHOIS lookups.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
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


def numeric(value: str) -> float:
    try:
        value = value.strip()
        return 0.0 if not value or value.casefold() == "nan" else float(value)
    except ValueError:
        return 0.0


def numeric_baseline(rows: list[tuple[list[float], int]], epochs: int = 4) -> tuple[list[int], list[float], float, int]:
    """Train a tiny standardized logistic baseline without external packages."""
    ordered = sorted(enumerate(rows), key=lambda item: hashlib.sha256(str(item[0]).encode()).hexdigest())
    train_cut = max(1, int(len(ordered) * 0.6))
    calibration_cut = max(train_cut + 1, int(len(ordered) * 0.8))
    train = [item[1] for item in ordered[:train_cut]]
    calibration = [item[1] for item in ordered[train_cut:calibration_cut]]
    test = [item[1] for item in ordered[calibration_cut:]]
    width = len(train[0][0])
    means = [sum(row[0][j] for row in train) / len(train) for j in range(width)]
    scales = []
    for j in range(width):
        variance = sum((row[0][j] - means[j]) ** 2 for row in train) / len(train)
        scales.append(math.sqrt(variance) or 1.0)

    def vector(values: list[float]) -> list[float]:
        return [(values[j] - means[j]) / scales[j] for j in range(width)]

    weights = [0.0] * width
    bias = 0.0
    positives = sum(label for _, label in train)
    positive_weight = (len(train) - positives) / max(1, positives)
    learning_rate = 0.005
    for _ in range(epochs * 2):
        for values, label in train:
            features = vector(values)
            score = bias + sum(weight * value for weight, value in zip(weights, features))
            probability = 1.0 / (1.0 + math.exp(max(-35.0, min(35.0, -score))))
            error = (probability - label) * (positive_weight if label else 1.0)
            bias -= learning_rate * error
            for index, value in enumerate(features):
                weights[index] -= learning_rate * error * value
    def score(values: list[float]) -> float:
        features = vector(values)
        raw = bias + sum(weight * value for weight, value in zip(weights, features))
        return 1.0 / (1.0 + math.exp(max(-35.0, min(35.0, -raw))))

    calibration_labels = [label for _, label in calibration]
    calibration_scores = [score(values) for values, _ in calibration]
    thresholds = sorted(set([0.0, 1.0, *calibration_scores]))
    scored_thresholds = [
        (candidate, binary_metrics(calibration_labels, calibration_scores, candidate))
        for candidate in thresholds
    ]
    low_fpr = [item for item in scored_thresholds if item[1]["false_positive_rate"] <= 0.05]
    threshold, _ = max(
        low_fpr or scored_thresholds,
        key=lambda item: (item[1]["f1"], item[1]["recall"], -item[0]),
    )
    labels = [label for _, label in test]
    scores = [score(values) for values, _ in test]
    return labels, scores, float(threshold), len(rows)


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
        label_column = args.label_column or choose_column(fields, ("label", "type", "URL_Type_obf_Type", "class"))
        labels: list[int] = []
        scores: list[float] = []
        by_label: dict[str, list[tuple[int, float]]] = defaultdict(list)
        skipped = 0
        url_column = args.url_column
        if not url_column:
            try:
                url_column = choose_column(fields, ("url", "URL", "url_string", "URL_string"))
            except ValueError:
                url_column = ""
        if url_column:
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
            mode = "lexical_runtime_heuristic"
            overall = binary_metrics(labels, scores, threshold=args.threshold) if labels else {}
        else:
            feature_columns = [field for field in fields if field != label_column]
            feature_rows: list[tuple[list[float], int]] = []
            raw_labels: list[str] = []
            for row in reader:
                label = (row.get(label_column) or "").strip()
                if not label:
                    skipped += 1
                    continue
                feature_rows.append(([numeric(row.get(field, "")) for field in feature_columns], 0 if is_benign(label) else 1))
                raw_labels.append(label)
            labels, scores, calibrated_threshold, total_records = numeric_baseline(feature_rows)
            mode = "feature_only_benchmark_baseline"
            overall = binary_metrics(labels, scores, threshold=calibrated_threshold) if labels else {}
            args.threshold = calibrated_threshold

    report = {
        "dataset": str(args.csv_path),
        "url_column": url_column,
        "label_column": label_column,
        "mode": mode,
        "feature_only_note": "Feature-only mode is benchmark evidence and is not wired into Guardian runtime inference." if mode == "feature_only_benchmark_baseline" else None,
        "threshold": args.threshold,
        "records": total_records if mode == "feature_only_benchmark_baseline" else len(labels),
        "evaluated_test_records": len(labels),
        "total_input_records": total_records if mode == "feature_only_benchmark_baseline" else len(labels),
        "skipped": skipped,
        "note": "URL structure only; no network lookups were performed.",
        "overall": overall,
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
