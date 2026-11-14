"""Record ExecuTorch package/export metadata without contacting a network."""

from __future__ import annotations

import argparse
import importlib.util
import json
import platform
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path)
    parser.add_argument("--quantisation", default="TBD")
    parser.add_argument("--backend", default="TBD")
    parser.add_argument("--output", type=Path, default=Path("evaluation/executorch_metadata.json"))
    args = parser.parse_args()
    installed = importlib.util.find_spec("executorch") is not None
    version = "unknown"
    if installed:
        import executorch
        version = getattr(executorch, "__version__", "installed-version-not-exposed")
    payload = {
        "status": "READY_TO_COMPLETE" if installed and args.model else "PENDING_TARGET_EXPORT",
        "architecture": platform.machine(),
        "executorch_installed": installed,
        "executorch_version": version,
        "model_path": str(args.model) if args.model else None,
        "model_size_bytes": args.model.stat().st_size if args.model and args.model.exists() else None,
        "quantisation": args.quantisation,
        "backend": args.backend,
        "first_token_latency_ms": None,
        "note": "Fill first_token_latency_ms from the target advisory-model runner; do not estimate it.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
