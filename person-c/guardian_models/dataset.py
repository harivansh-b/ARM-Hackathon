"""Small, explicit dataset utilities for campaign-safe evaluation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SMSExample:
    text: str
    label: int
    campaign: str
    example_id: str = ""

    def __post_init__(self) -> None:
        if self.label not in (0, 1):
            raise ValueError("label must be 0 (benign) or 1 (scam)")
        if not self.campaign:
            raise ValueError("campaign is required to prevent campaign leakage")


def load_jsonl(path: str | Path) -> list[SMSExample]:
    examples: list[SMSExample] = []
    for line_number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            examples.append(SMSExample(str(row["text"]), int(row["label"]), str(row["campaign"]), str(row.get("id", ""))))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid JSONL row {line_number}: {exc}") from exc
    if not examples:
        raise ValueError("dataset is empty")
    return examples


def campaign_split(examples: list[SMSExample], holdout_campaigns: set[str]) -> tuple[list[SMSExample], list[SMSExample]]:
    if not holdout_campaigns:
        raise ValueError("at least one holdout campaign is required")
    train = [item for item in examples if item.campaign not in holdout_campaigns]
    test = [item for item in examples if item.campaign in holdout_campaigns]
    if not train or not test:
        raise ValueError("campaign split must produce non-empty train and test sets")
    return train, test
