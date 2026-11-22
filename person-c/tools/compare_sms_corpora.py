"""Compare the current SMS corpus with the approved multilingual augmentation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "person-c"))

from guardian_models.calibration import select_threshold  # noqa: E402
from guardian_models.dataset import SMSExample, deterministic_campaign_split, load_jsonl  # noqa: E402
from guardian_models.metrics import binary_metrics  # noqa: E402
from guardian_models.sms_model import LinearSMSModel  # noqa: E402


def train(dataset: list, epochs: int) -> tuple[LinearSMSModel, float, dict]:
    train_pool, test = deterministic_campaign_split(dataset, 0.2, salt="candidate-test")
    train_rows, calibration = deterministic_campaign_split(train_pool, 0.2, salt="candidate-calibration")
    model = LinearSMSModel(epochs=epochs).fit([(row.text, row.label) for row in train_rows])
    threshold = float(select_threshold(
        [row.label for row in calibration],
        [model.predict_proba(row.text) for row in calibration],
    )["threshold"])
    result = binary_metrics(
        [row.label for row in test],
        [model.predict_proba(row.text) for row in test],
        threshold=threshold,
    )
    result.update({"train_count": len(train_rows), "calibration_count": len(calibration), "test_count": len(test)})
    return model, threshold, result


def evaluate(model: LinearSMSModel, threshold: float, rows: list) -> dict:
    return binary_metrics(
        [row.label for row in rows],
        [model.predict_proba(row.text) for row in rows],
        threshold=threshold,
    )


def load_evaluation_rows(paths: list[Path]) -> list[SMSExample]:
    """Load legacy hard-negative rows, adding a stable campaign when absent."""
    rows: list[SMSExample] = []
    for path in paths:
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            raw = json.loads(line)
            rows.append(SMSExample(
                text=str(raw["text"]),
                label=int(raw["label"]),
                campaign=str(raw.get("campaign") or raw.get("id") or f"{path.name}:{line_number}"),
                example_id=str(raw.get("id", "")),
                language=str(raw.get("language", "unknown")),
                category=str(raw.get("category", "unspecified")),
                source=str(raw.get("source", "evaluation")),
                collection_date=str(raw.get("collection_date", "")),
            ))
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public", type=Path, default=ROOT / "person-c/data/public_sms.jsonl")
    parser.add_argument("--multilingual", type=Path, default=ROOT / "person-c/data/sms_multilingual.jsonl")
    parser.add_argument("--hard-negatives", type=Path, nargs="+", default=[
        ROOT / "person-a/eval/hard_negatives.jsonl",
        ROOT / "person-c/data/indian_hard_negatives.jsonl",
    ])
    parser.add_argument("--epochs", type=int, default=8)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    public = load_jsonl(args.public)
    multilingual = load_jsonl(args.multilingual)
    hard = load_evaluation_rows(args.hard_negatives)
    candidates = {"public_only": public, "public_plus_multilingual": public + multilingual}
    report = {"evaluation_only_datasets": [str(path) for path in args.hard_negatives], "candidates": {}}
    for name, rows in candidates.items():
        model, threshold, held_out = train(rows, args.epochs)
        report["candidates"][name] = {
            "threshold": threshold,
            "held_out": held_out,
            "hard_negatives": evaluate(model, threshold, hard),
        }
    rendered = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
