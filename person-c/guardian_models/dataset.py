"""Small, explicit dataset utilities for campaign-safe evaluation."""

from __future__ import annotations

import json
import hashlib
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


def deterministic_campaign_split(examples: list[SMSExample], holdout_fraction: float = 0.2, salt: str = "") -> tuple[list[SMSExample], list[SMSExample]]:
    """Split whole campaign/template groups deterministically and keep both labels in each side."""
    if not 0.0 < holdout_fraction < 1.0:
        raise ValueError("holdout_fraction must be between 0 and 1")
    campaigns = sorted({item.campaign for item in examples})
    held_out = {campaign for campaign in campaigns if int(hashlib.sha256(f"{salt}:{campaign}".encode()).hexdigest()[:8], 16) / 0xFFFFFFFF < holdout_fraction}
    if not held_out:
        held_out.add(campaigns[-1])

    def labels(groups: set[str]) -> set[int]:
        return {item.label for item in examples if item.campaign in groups}

    train = [item for item in examples if item.campaign not in held_out]
    test = [item for item in examples if item.campaign in held_out]
    for required_label in (0, 1):
        if required_label not in labels({item.campaign for item in test}):
            movable = next((campaign for campaign in campaigns if campaign not in held_out and any(row.campaign == campaign and row.label == required_label for row in examples)), None)
            if movable is not None:
                held_out.add(movable)
        if required_label not in labels({item.campaign for item in train}):
            removable = next((campaign for campaign in sorted(held_out) if any(row.campaign == campaign and row.label == required_label for row in examples)), None)
            if removable is not None:
                held_out.remove(removable)
    train = [item for item in examples if item.campaign not in held_out]
    test = [item for item in examples if item.campaign in held_out]
    if not train or not test or labels({item.campaign for item in train}) != {0, 1} or labels({item.campaign for item in test}) != {0, 1}:
        raise ValueError("deterministic campaign split could not preserve both labels")
    return train, test
