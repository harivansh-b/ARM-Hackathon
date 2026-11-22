#!/usr/bin/env bash

# Guardian SMS -> detection -> local Llama -> verifier -> root JSON

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

INPUT="${1:-$ROOT/person-a/samples/sms.csv}"
OUT="${2:-$ROOT/guardian_sms_report.json}"
ARTIFACT="$ROOT/person-c/artifacts/sms.json"
PREPARED_TRAINING=""

if [[ "$INPUT" != /* ]]; then INPUT="$ROOT/$INPUT"; fi
if [[ "$OUT" != /* ]]; then OUT="$ROOT/$OUT"; fi

if [[ ! -f "$INPUT" ]]; then
    echo "SMS input not found: $INPUT" >&2
    exit 2
fi

if [[ ! -f "$ARTIFACT" ]]; then
    echo "Training the SMS model artifact (one-time setup)..."
    if [[ -n "${GUARDIAN_SMS_TRAINING_DATA:-}" ]]; then
        TRAINING_DATA="$GUARDIAN_SMS_TRAINING_DATA"
        if [[ "$TRAINING_DATA" != /* ]]; then TRAINING_DATA="$ROOT/$TRAINING_DATA"; fi
    else
        PREPARED_TRAINING="$(mktemp)"
        trap 'rm -f "$PREPARED_TRAINING"' EXIT
        python3 "$ROOT/person-c/tools/prepare_sms_dataset.py" \
            "$PREPARED_TRAINING" \
            "$ROOT/person-c/data/public_sms.jsonl" \
            "$ROOT/person-c/data/sms_multilingual.jsonl" >/dev/null
        TRAINING_DATA="$PREPARED_TRAINING"
    fi
    (cd "$ROOT/person-c" && python3 -m guardian_models.train_sms "$TRAINING_DATA" artifacts/sms.json)
fi

DEFAULT_LLAMA_CMD="\"$ROOT/runtime/executorch/llama_main\" --model_path \"$ROOT/models/llama/llama3_2.pte\" --tokenizer_path \"$ROOT/models/llama/tokenizer.model\" --temperature 0 --seq_len 512 --max_new_tokens 128 --prompt {prompt}"

LLAMA_CMD="${GUARDIAN_LLAMA_CMD:-$DEFAULT_LLAMA_CMD}"

mkdir -p "$(dirname "$OUT")"

ARGS=(--input "$INPUT" --artifact "$ARTIFACT" --out "$OUT" --llama-cmd "$LLAMA_CMD")

(cd "$ROOT/person-a" && PYTHONPATH="$ROOT/person-a:$ROOT/person-c" python3 -m guardian_app.scan "${ARGS[@]}")

echo "Saved: $OUT"
