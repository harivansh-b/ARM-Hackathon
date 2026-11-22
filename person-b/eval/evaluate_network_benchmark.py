"""Train and evaluate a dependency-light reference classifier on normalized flows."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


def load_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def matrix(rows: list[dict], columns: list[str]) -> np.ndarray:
    return np.asarray(
        [[float(row.get("features", {}).get(column, 0.0) or 0.0) for column in columns] for row in rows],
        dtype=float,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("train_jsonl", type=Path)
    parser.add_argument("--test-jsonl", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-features", type=int, default=80)
    args = parser.parse_args()

    source_rows = load_rows(args.train_jsonl)
    if args.test_jsonl:
        train_rows = source_rows
        test_rows = load_rows(args.test_jsonl)
    else:
        train_rows, test_rows = train_test_split(
            source_rows,
            test_size=0.25,
            random_state=42,
            stratify=[int(row["is_attack"]) for row in source_rows],
        )
    columns = sorted({key for row in train_rows for key in row.get("features", {})})[: args.max_features]
    x_train = matrix(train_rows, columns)
    x_test = matrix(test_rows, columns)
    y_train = np.asarray([int(row["is_attack"]) for row in train_rows])
    y_test = np.asarray([int(row["is_attack"]) for row in test_rows])

    scaler = StandardScaler()
    x_train = scaler.fit_transform(np.nan_to_num(x_train, nan=0.0, posinf=0.0, neginf=0.0))
    x_test = scaler.transform(np.nan_to_num(x_test, nan=0.0, posinf=0.0, neginf=0.0))
    classifier = LogisticRegression(max_iter=300, class_weight="balanced")
    classifier.fit(x_train, y_train)
    predictions = classifier.predict(x_test)

    by_label: dict[str, dict[str, int]] = {}
    for row, prediction in zip(test_rows, predictions):
        label = str(row["label"])
        stats = by_label.setdefault(label, {"count": 0, "attacks_detected": 0, "missed": 0})
        stats["count"] += 1
        if int(row["is_attack"]):
            if prediction:
                stats["attacks_detected"] += 1
            else:
                stats["missed"] += 1

    report = {
        "dataset": train_rows[0].get("dataset", "unknown") if train_rows else "unknown",
        "train_records": len(train_rows),
        "test_records": len(test_rows),
        "feature_count": len(columns),
        "feature_columns": columns,
        "label_counts": dict(Counter(str(row["label"]) for row in test_rows)),
        "by_label": by_label,
        "confusion_matrix": confusion_matrix(y_test, predictions).tolist(),
        "classification_report": classification_report(y_test, predictions, output_dict=True),
        "note": "Reference benchmark only; scores do not represent live Guardian runtime accuracy.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
