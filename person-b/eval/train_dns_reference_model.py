"""Train a reference DNS model and export weights in a runtime-neutral JSON form.

The evaluator environment may use scikit-learn; the exported artifact contains
only feature names, scaler statistics and linear weights for later Arm runtime
integration.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("normalized_jsonl", type=Path)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    rows = [json.loads(line) for line in args.normalized_jsonl.read_text(encoding="utf-8").splitlines() if line.strip()]
    columns = sorted({key for row in rows for key in row["features"]})
    x = np.asarray([[row["features"].get(key, 0.0) or 0.0 for key in columns] for row in rows], dtype=float)
    y = np.asarray([int(row["is_attack"]) for row in rows], dtype=int)
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.25, random_state=42, stratify=y)

    scaler = StandardScaler()
    classifier = LogisticRegression(max_iter=250, class_weight="balanced")
    model = make_pipeline(scaler, classifier)
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)
    report = classification_report(y_test, predictions, output_dict=True)
    result = {
        "dataset": str(args.normalized_jsonl),
        "records": len(rows),
        "feature_count": len(columns),
        "split": {"train": len(y_train), "test": len(y_test)},
        "confusion_matrix": confusion_matrix(y_test, predictions).tolist(),
        "classification_report": report,
        "note": "Reference benchmark model; not yet wired into live Guardian DNS inference.",
    }
    artifact = {
        "format": "guardian.network.dns.logistic.v1",
        "feature_columns": columns,
        "means": scaler.mean_.tolist(),
        "scales": scaler.scale_.tolist(),
        "weights": classifier.coef_[0].tolist(),
        "bias": float(classifier.intercept_[0]),
        "threshold": 0.5,
        "source_dataset": str(args.normalized_jsonl),
    }
    args.model.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.model.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
