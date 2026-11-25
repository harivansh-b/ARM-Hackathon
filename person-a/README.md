
# Person A — Guardian Offline SMS Scanner

Person A implements Guardian's SMS scanning workflow on ARM Linux. It imports messages from local files, runs the SMS detection runtime, analyses extracted URLs, generates evidence and optionally uses a local Llama model to explain flagged messages.

**The detector makes the security decision. The Llama advisor only explains it and cannot change the verdict.**

## Responsibilities

- Import SMS messages from local files.
- Run the SMS detection pipeline.
- Identify extracted URLs and assess them locally.
- Produce structured detection results.
- Generate approved protective actions for flagged messages.
- Optionally generate an explanation using a local Llama runtime.
- Verify generated explanations and use deterministic fallback text when necessary.
- Produce scan reports.

## Architecture

```text
Local SMS Input
      |
      v
  Importer
      |
      v
 SMS Runtime (Person C)
      |
      +----> Decision + Evidence
      |
      +----> Extract URLs
                  |
                  v
            URL Analysis
                  |
                  v
         Evidence Storyline
                  |
                  v
       Optional Local Llama
                  |
                  v
        Explanation Verifier
                  |
          +-------+-------+
          |               |
       Accepted        Fallback
          |               |
          +-------+-------+
                  |
                  v
         Structured Results
```

## Main files

| File | Responsibility |
|---|---|
| `guardian_app/scan.py` | Main scanning workflow and CLI |
| `guardian_app/importers.py` | Local message import and parsing |
| `guardian_app/advisor.py` | Prompt generation, local Llama execution, explanation verification and fallback |
| `samples/sms.csv` | Sample SMS input |
| `tests/test_app.py` | Application tests |
| `eval/hard_negatives.jsonl` | Hard-negative test input |
| `eval/extra_samples.jsonl` | Additional evaluation samples |
| `eval/make_extra_samples.py` | Additional sample generation |
| `eval/eval_hard_negatives.py` | Hard-negative evaluation |
| `bench/bench_detect.py` | Detection benchmark |
| `bench/bench_llm.py` | Advisor benchmark |
| `bench/manifest.py` | Benchmark manifest support |
| `bench/offline_check.sh` | Offline verification helper |

## Input formats

The importer supports:

- CSV
- JSON
- JSONL
- Plain text

CSV and JSON inputs support message text fields including:

- `text`
- `body`
- `message`
- `sms`
- `content`

Sender information may be supplied through:

- `sender`
- `address`
- `from`
- `number`

Plain-text inputs may contain one message per line or messages separated by blank lines.

The importer skips empty messages and raises an error if no messages are found.

## Detection workflow

### 1. Import

`guardian_app/importers.py` loads messages from the provided file and normalizes the imported structure into message records.

### 2. Detection

The scanner loads the SMS runtime from the model artifact supplied through `--artifact`.

Each message is analysed by the runtime, which returns the decision state, risk tier, score, matched signals and evidence.

Decision states include:

- `ALERT`
- `REVIEW`
- `BENIGN_CANDIDATE`

### 3. URL analysis

URLs extracted from flagged messages are assessed using Person C's URL analysis logic.

The scanner can produce URL-related evidence and relationships between the SMS and URL entities.

### 4. Protective actions

Approved actions are obtained from the deterministic safety/action logic. These actions are not authored by Llama.

### 5. Explanation

For flagged messages, the scanner can invoke the local Llama advisor, subject to the configured limit.

The prompt is constructed from structured evidence such as decision state, risk tier, signals, URL hosts and language. The raw SMS text is not included in the advisor prompt.

### 6. Verification and fallback

Generated explanations are checked for safety and grounding.

If the generated output is rejected, unavailable or empty, the system uses deterministic fallback text.

## Requirements

- Python 3
- ARM64 Linux environment recommended for the intended deployment
- Person C's SMS model artifact
- Local ExecuTorch Llama runtime and compatible model/tokenizer if Llama explanations are enabled

The Person A application uses Python standard-library functionality for its own import, scan and advisor orchestration.

The detection model and runtime are provided by Person C.

## Running the scanner

Commands below are run from the repository root.

### Scan without Llama

```bash
python3 -m person_a.guardian_app.scan \
    --input person-a/samples/sms.csv \
    --artifact person-c/artifacts/sms.json \
    --no-llm
```

Depending on the repository's package layout and Python import configuration, the equivalent working directory may be `person-a`; the module is implemented under `guardian_app/`.

The canonical standalone command from the Person A directory is:

```bash
cd person-a

python3 -m guardian_app.scan \
    --input samples/sms.csv \
    --artifact ../person-c/artifacts/sms.json \
    --no-llm
```

### Scan with Llama

From the `person-a` directory:

```bash
python3 -m guardian_app.scan \
    --input samples/sms.csv \
    --artifact ../person-c/artifacts/sms.json
```

The advisor is optional. If it is not configured or available, the scanner can fall back to deterministic explanations.

### Configure the Llama runtime

The advisor accepts a command template containing `{prompt}`.

Example:

```bash
export GUARDIAN_LLAMA_CMD="./runtime/executorch/llama_main --model_path=./models/llama/llama3_2.pte --tokenizer_path=./models/llama/tokenizer.model --temperature 0 --seq_len 512 --prompt {prompt}"
```

Keep `{prompt}` literal in the environment variable. The advisor replaces it with the prompt generated from the evidence.

The actual executable, model and tokenizer must be compatible with the installed runtime.

### Save a report

```bash
cd person-a

python3 -m guardian_app.scan \
    --input samples/sms.csv \
    --artifact ../person-c/artifacts/sms.json \
    --out reports/scan.json
```

### Limit Llama invocations

The scanner supports:

```bash
--max-llm 20
```

This limits the number of flagged messages for which Llama is used.

### Run tests

From the repository root:

```bash
python3 -m unittest discover -s person-a/tests -v
```

## Report contents

The scanner output can include:

- Message ID
- Sender
- Decision state
- Risk tier
- Score
- Matched signals
- Extracted URLs
- Detection latency
- Approved protective actions
- Advisor explanation
- Explanation source
- Verifier status
- URL/storyline evidence

## Offline operation

The detector and message importer do not require a cloud service.

The local advisor is also intended to operate through the local ExecuTorch runtime.

Guardian does not need to open an extracted URL in order to assess it.

## Benchmark and verification tooling

### Detection benchmark

```bash
python3 bench/bench_detect.py
```

Check the script's arguments for the specific benchmark input and output options.

### Advisor benchmark

```bash
python3 bench/bench_llm.py
```

### Offline verification

```bash
bash bench/offline_check.sh
```

These tools should be used according to their actual argument requirements and the local runtime configuration.

## Important limitations

- A `BENIGN_CANDIDATE` result does not guarantee that a message is legitimate.
- The advisor is not a decision-making authority.
- Explanation verification is a safety component that requires further validation.
- Test fixture metrics are not equivalent to real-world performance.
- The SMS artifact and its training/evaluation metadata should be documented separately from the scanner.
- Local Llama execution requires compatible runtime assets and configuration.

