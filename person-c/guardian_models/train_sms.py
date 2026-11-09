"""Train and evaluate the compact SMS baseline from campaign-labelled JSONL."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .dataset import campaign_split, load_jsonl
from .metrics import binary_metrics, pr_auc
from .sms_model import LinearSMSModel


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Guardian's explainable SMS baseline")
    parser.add_argument("dataset", type=Path)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--holdout-campaign", action="append", required=True)
    args = parser.parse_args()
    examples = load_jsonl(args.dataset)
    train, test = campaign_split(examples, set(args.holdout_campaign))
    model = LinearSMSModel().fit([(item.text, item.label) for item in train])
    labels = [item.label for item in test]
    scores = [model.predict_proba(item.text) for item in test]
    report = binary_metrics(labels, scores)
    report["pr_auc"] = pr_auc(labels, scores)
    report["train_count"] = len(train)
    report["test_campaigns"] = sorted(set(args.holdout_campaign))
    args.artifact.parent.mkdir(parents=True, exist_ok=True)
    args.artifact.write_text(json.dumps({"model": model.to_dict(), "evaluation": report}, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
