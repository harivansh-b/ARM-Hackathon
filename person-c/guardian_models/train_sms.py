"""Train and evaluate the compact SMS baseline from campaign-labelled JSONL."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .dataset import campaign_split, deterministic_campaign_split, load_jsonl
from .calibration import select_threshold
from .metrics import binary_metrics, pr_auc
from .sms_model import LinearSMSModel


def main() -> None:
    """Train, calibrate and evaluate a compact campaign-safe SMS model.

    The command intentionally writes evaluation metadata into the artifact so
    a reviewer can reproduce which split, threshold and record counts were
    used. It does not fetch data or contact a network service.
    """
    parser = argparse.ArgumentParser(description="Train Guardian's explainable SMS baseline")
    parser.add_argument("dataset", type=Path)
    parser.add_argument("artifact", type=Path)
    split = parser.add_mutually_exclusive_group()
    split.add_argument("--holdout-campaign", action="append")
    split.add_argument("--holdout-fraction", type=float, default=0.2)
    parser.add_argument("--epochs", type=int, default=8)
    parser.add_argument("--max-records", type=int)
    args = parser.parse_args()
    examples = load_jsonl(args.dataset)
    if args.max_records is not None:
        if args.max_records < 4:
            raise ValueError("--max-records must be at least 4")
        ordered = sorted(examples, key=lambda item: item.example_id)
        positives = [item for item in ordered if item.label == 1]
        negatives = [item for item in ordered if item.label == 0]
        positive_limit = min(len(positives), max(1, args.max_records * len(positives) // len(ordered)))
        negative_limit = min(len(negatives), args.max_records - positive_limit)
        examples = positives[:positive_limit] + negatives[:negative_limit]
    if args.holdout_campaign:
        train_pool, test = campaign_split(examples, set(args.holdout_campaign))
        test_campaigns = sorted(set(args.holdout_campaign))
    else:
        train_pool, test = deterministic_campaign_split(examples, args.holdout_fraction)
        test_campaigns = sorted({item.campaign for item in test})
    train, calibration = deterministic_campaign_split(train_pool, 0.2, salt="calibration")
    model = LinearSMSModel(epochs=args.epochs).fit([(item.text, item.label) for item in train])
    calibration_labels = [item.label for item in calibration]
    calibration_scores = [model.predict_proba(item.text) for item in calibration]
    operating_point = select_threshold(calibration_labels, calibration_scores)
    labels = [item.label for item in test]
    scores = [model.predict_proba(item.text) for item in test]
    report = binary_metrics(labels, scores, threshold=float(operating_point["threshold"]))
    report["pr_auc"] = pr_auc(labels, scores)
    report["train_count"] = len(train)
    report["calibration_count"] = len(calibration)
    report["test_campaign_count"] = len(test_campaigns)
    report["test_campaigns_preview"] = test_campaigns[:10]
    report["dataset_labels"] = {"train": {str(label): sum(item.label == label for item in train) for label in (0, 1)}, "test": {str(label): sum(item.label == label for item in test) for label in (0, 1)}}
    args.artifact.parent.mkdir(parents=True, exist_ok=True)
    args.artifact.write_text(json.dumps({"model": model.to_dict(), "runtime": {"threshold": operating_point["threshold"], "review_band": 0.02, "max_chars": 4096}, "calibration": operating_point, "evaluation": report}, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
