"""Dataset loading and leakage-resistant splitting for Person-C.

The JSONL format deliberately keeps campaign/template identity separate from
the message text. Splitting by campaign prevents near-duplicate messages from
appearing in both training and evaluation, which would make the metrics look
better than real-world performance.
"""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SMSExample:
    """One labelled SMS example used by training and evaluation.

    ``language`` and ``category`` are metadata for analysis and reporting;
    they are not used as labels by the baseline classifier. Keeping them in
    the row makes it possible to report English/Hindi/Hinglish performance
    without changing the model API.
    """

    text: str
    label: int
    campaign: str
    example_id: str = ""
    language: str = "unknown"
    category: str = "unspecified"
    source: str = "synthetic"

    def __post_init__(self) -> None:
        if self.label not in (0, 1):
            raise ValueError("label must be 0 (benign) or 1 (scam)")
        if not self.campaign:
            raise ValueError("campaign is required to prevent campaign leakage")
        if not self.text.strip():
            raise ValueError("text must not be empty")
        if self.language not in {"en", "hi", "hinglish", "hi-en", "unknown"}:
            raise ValueError("unsupported language metadata")


def load_jsonl(path: str | Path) -> list[SMSExample]:
    examples: list[SMSExample] = []
    for line_number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            examples.append(SMSExample(
                text=str(row["text"]),
                label=int(row["label"]),
                campaign=str(row["campaign"]),
                example_id=str(row.get("id", "")),
                language=str(row.get("language", "unknown")),
                category=str(row.get("category", "unspecified")),
                source=str(row.get("source", "synthetic")),
            ))
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
