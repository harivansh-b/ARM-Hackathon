"""Reproducible report evaluation for language, hard-negative and time splits."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from guardian_models.dataset import load_jsonl
from guardian_models.metrics import binary_metrics
from guardian_models.sms_model import LinearSMSModel


def evaluate(model: LinearSMSModel, rows, threshold: float) -> dict:
    labels = [row.label for row in rows]
    scores = [model.predict_proba(row.text) for row in rows]
    return binary_metrics(labels, scores, threshold=threshold)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    parser.add_argument("dataset", type=Path, nargs="+")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    artifact = json.loads(args.artifact.read_text(encoding="utf-8"))
    model = LinearSMSModel.from_dict(artifact["model"])
    threshold = float(artifact.get("runtime", {}).get("threshold", 0.5))
    rows = [row for path in args.dataset for row in load_jsonl(path)]
    report = {"artifact": str(args.artifact), "threshold": threshold, "records": len(rows)}
    by_language = defaultdict(list)
    by_category = defaultdict(list)
    for row in rows:
        by_language[row.language].append(row)
        by_category[row.category].append(row)
    report["per_language"] = {key: evaluate(model, value, threshold) for key, value in sorted(by_language.items())}
    report["hard_negatives"] = {key: evaluate(model, value, threshold) for key, value in sorted(by_category.items()) if key.startswith("legitimate_")}
    dated = sorted((row for row in rows if getattr(row, "collection_date", None)), key=lambda row: row.collection_date)
    report["time_ordered"] = {"status": "available only when collection_date is present", "records_with_date": len(dated), "note": "Do not call this independent or prospective until collection dates are verified."}
    rendered = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
