"""Build a provenance-preserving SMS training JSONL from approved inputs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def load_rows(path: Path) -> list[dict]:
    rows: list[dict] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        for field in ("text", "label", "campaign"):
            if field not in row:
                raise ValueError(f"{path}:{line_number}: missing {field}")
        row = dict(row)
        row["label"] = int(row["label"])
        row["source_file"] = str(path).replace("\\", "/")
        rows.append(row)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("datasets", type=Path, nargs="+")
    args = parser.parse_args()

    rows: list[dict] = []
    seen_ids: set[str] = set()
    seen_texts: set[str] = set()
    for path in args.datasets:
        for row in load_rows(path):
            key = str(row.get("id", ""))
            text_key = " ".join(str(row["text"]).casefold().split())
            if key and key in seen_ids:
                raise ValueError(f"duplicate id across training inputs: {key}")
            if text_key in seen_texts:
                continue
            if key:
                seen_ids.add(key)
            seen_texts.add(text_key)
            rows.append(row)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )
    counts = {str(label): sum(row["label"] == label for row in rows) for label in (0, 1)}
    print(json.dumps({"output": str(args.output), "records": len(rows), "labels": counts}, indent=2))


if __name__ == "__main__":
    main()
