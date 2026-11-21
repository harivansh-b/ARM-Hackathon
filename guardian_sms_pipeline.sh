#!/usr/bin/env bash
# Guardian SMS -> detection -> local Llama -> verifier -> root JSON
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
INPUT="${1:-$ROOT/person-a/samples/sms.csv}"
OUT="${2:-$ROOT/guardian_sms_report.json}"
ARTIFACT="$ROOT/person-c/artifacts/sms.json"
if [[ "$INPUT" != /* ]]; then INPUT="$ROOT/$INPUT"; fi
if [[ "$OUT" != /* ]]; then OUT="$ROOT/$OUT"; fi
if [[ ! -f "$INPUT" ]]; then echo "SMS input not found: $INPUT" >&2; exit 2; fi
if [[ ! -f "$ARTIFACT" ]]; then
  echo "Training the SMS model artifact (one-time setup)..."
  (cd "$ROOT/person-c" && python3 -m guardian_models.train_sms data/public_sms.jsonl artifacts/sms.json)
fi
# Python writes the JSON report; scan.py uses the existing Phase 1-3 integrated pipeline.
mkdir -p "$(dirname "$OUT")"
ARGS=(--input "$INPUT" --artifact "$ARTIFACT" --out "$OUT")
if [[ -n "${GUARDIAN_LLAMA_CMD:-}" ]]; then ARGS+=(--llama-cmd "$GUARDIAN_LLAMA_CMD"); else ARGS+=(--no-llm); fi
(cd "$ROOT/person-a" && PYTHONPATH="$ROOT/person-a:$ROOT/person-c" python3 -m guardian_app.scan "${ARGS[@]}")
# Normalize the report to a root-relative report destination as requested; OUT defaults to root.
echo "Saved: $OUT"
