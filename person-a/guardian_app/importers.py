"""Load SMS from local files: csv, json/jsonl, or plain text."""
from __future__ import annotations

import csv
import json
from pathlib import Path

TEXT_KEYS = ("text", "body", "message", "sms", "content")
SENDER_KEYS = ("sender", "address", "from", "number")


def _pick(row: dict, keys: tuple[str, ...]):
    lowered = {str(k).lower(): v for k, v in row.items()}
    for key in keys:
        if lowered.get(key) not in (None, ""):
            return str(lowered[key])
    return None


def _item(row: dict, index: int) -> dict | None:
    text = _pick(row, TEXT_KEYS)
    if not text or not text.strip():
        return None
    return {"id": str(row.get("id", index)), "text": text, "sender": _pick(row, SENDER_KEYS), "label": row.get("label")}


def load_messages(path: str | Path) -> list[dict]:
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix == ".csv":
        with path.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
    elif suffix in (".json", ".jsonl"):
        raw = path.read_text(encoding="utf-8")
        rows = [json.loads(line) for line in raw.splitlines() if line.strip()] if suffix == ".jsonl" else json.loads(raw)
        if isinstance(rows, dict):
            rows = rows.get("messages", [])
    else:  # .txt: messages separated by blank lines, else one per line
        raw = path.read_text(encoding="utf-8").strip()
        parts = [p.strip() for p in raw.split("\n\n")] if "\n\n" in raw else raw.splitlines()
        rows = [{"text": p} for p in parts]
    items = [item for index, row in enumerate(rows) if (item := _item(row, index))]
    if not items:
        raise ValueError(f"no messages found in {path.name}")
    return items
