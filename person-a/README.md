# Person A — Guardian Offline SMS Scanner

An offline-first SMS scanning application for ARM64 Linux. It imports SMS messages from local files, runs Person C's detection pipeline, and uses Llama 3.2 1B through ExecuTorch to explain flagged messages.

**The detector makes the security decision. Llama only explains it and cannot change the verdict.**

## How it works

1. `guardian_app/importers.py` imports messages from CSV, JSON, Android backup XML, and text files.
2. `SMSRuntime` from `person-c/guardian_models` analyses each message and returns a decision (`ALERT`, `REVIEW`, or `BENIGN_CANDIDATE`), score, and evidence.
3. `guardian_app/advisor.py` builds a prompt using structured detection evidence. The raw SMS message is not sent to Llama.
4. Llama 3.2 1B runs locally through ExecuTorch for `ALERT` and `REVIEW` messages.
5. The generated explanation is checked using Person C's `safety.verify_explanation` and an additional action-safety check.
6. If the explanation is empty, unsafe, or rejected, Guardian uses a deterministic template explanation instead.
7. `guardian_app/scan.py` produces a report containing the detection result, approved protective actions, explanation source, verification status, and SMS-to-URL storyline.

The Llama advisor is optional. Detection works independently of it.

## Requirements

- ARM64 Linux environment
- Python 3
- Person C's trained SMS model artifact
- ExecuTorch `llama_main` executable and a compatible Llama model/tokenizer
- Python standard library for the Person A application

The application is designed to work without network access at runtime.

## Running the application

Run commands from the repository root.

### 1. Train the SMS detector

```bash
cd person-c
python3 tools/prepare_sms_dataset.py data/sms-training.jsonl \
    data/public_sms.jsonl data/sms_multilingual.jsonl
python3 -m guardian_models.train_sms \
    data/sms-training.jsonl \
    artifacts/sms.json
cd ..
```

The root `guardian_sms_pipeline.sh` prepares the same merged training input
automatically when the artifact is missing. Set `GUARDIAN_SMS_TRAINING_DATA`
to a reviewed JSONL file to override that input. Keep
`person-c/data/indian_hard_negatives.jsonl` evaluation-only.

### 2. Run Person A tests

```bash
cd person-a
python3 -m unittest discover -s tests
```

### 3. Run detection without Llama

```bash
python3 -m guardian_app.scan \
    --input samples/sms.csv \
    --artifact ../person-c/artifacts/sms.json \
    --no-llm
```

### 4. Configure the Llama advisor

Set the command for your local ExecuTorch build.

Example:

```bash
export GUARDIAN_LLAMA_CMD="/home/dev/executorch/cmake-out/examples/models/llama/llama_main --model_path=/home/dev/executorch/llama3_2.pte --tokenizer_path=/home/dev/models/llama-3.2-1b-spinquant/tokenizer.model --temperature 0 --seq_len 512 --prompt {prompt}"
```

**Important:** Keep `{prompt}` literal. The application substitutes the generated prompt at runtime.

`--seq_len 512` provides sufficient sequence capacity for the current structured Guardian prompts and leaves room for generated explanations. Ensure the model supports this sequence length.

### 5. Run the integrated scan

```bash
python3 -m guardian_app.scan \
    --input samples/sms.csv \
    --artifact ../person-c/artifacts/sms.json \
    --out reports/integration_smoke_test_seq512.json
```

The report is saved under `person-a/reports/`.

## Integration smoke-test report

**Latest report:** `reports/integration_smoke_test_seq512.json`

This report was generated after adding `--seq_len 512` to the Llama command.

It contains three test messages:

| Message | Detector decision | Explanation source | Result |
|---|---|---|---|
| 1 | BENIGN_CANDIDATE | Template | Llama not invoked |
| 2 | ALERT | Llama | Generated explanation accepted |
| 3 | ALERT | Template fallback | Llama explanation rejected |

### What the test established

- The detector processes messages and produces decisions and evidence.
- Llama is invoked for flagged messages, not benign candidates.
- Increasing the sequence length resolved the earlier empty-generation problem.
- Llama execution statistics are now captured in the scan report.
- The fallback mechanism activates when an explanation is rejected.

### Important verifier finding

The report also exposed a safety-verification issue:

- **Message 2:** Llama advised the user not to verify the organisation through its official app or website. The verifier incorrectly accepted this explanation (`ok`).
- **Message 3:** Llama generated a correct warning against sharing OTPs, PINs, CVVs, and passwords. The verifier rejected it with `unsafe_instruction:share`.

Therefore, the current verifier must not yet be considered reliable. The accepted explanation in Message 2 demonstrates that an unsafe instruction can pass validation. The verifier logic needs further investigation and testing before the Llama explanations can be trusted.

## Benchmarks and evaluation

Person A includes the following tools:

| Tool | Purpose |
|---|---|
| `bench/bench_detect.py` | Detector latency and memory measurements |
| `bench/bench_llm.py` | Llama latency, throughput, memory, and verifier measurements |
| `bench/manifest.py` | Device and software environment information |
| `eval/eval_hard_negatives.py` | False-alarm evaluation on legitimate-message test sets |
| `eval/make_extra_samples.py` | Generates additional synthetic evaluation/training examples |
| `bench/offline_check.sh` | Attempts a scan inside an empty network namespace |

### Llama runtime measurements

From the latest integrated scan:

| Metric | Message 2 | Message 3 |
|---|---:|---:|
| Llama execution time | 3.90 s | 4.12 s |
| Prompt tokens | 160 | 164 |
| Generated tokens | 74 | 95 |
| Time to first token | 483 ms | 485 ms |
| Decode throughput | 47.96 tok/s | 38.71 tok/s |

These are measurements from an ARM64 Linux VM running under QEMU on Apple silicon, not a physical ARM development board.

### Detector evaluation

The current small synthetic hard set contains 34 legitimate messages and 15 scam messages.

| Model configuration | Legitimate wrongly alerted | Scams missed |
|---|---:|---:|
| Trained on `public_sms.jsonl` only | 9 / 34 (26.5%) | 1 / 15 |
| Plus 90 template rows, repeated 20 times | 3 / 34 (8.8%) | 1 / 15 |

The held-out F1 score of approximately 0.99 on the larger test set should not be interpreted as a real-world quality claim. Scam and legitimate examples originate from different public datasets, creating a source-distribution bias. The hard-set results are also limited by their small size and partial similarity to the synthetic training examples.

More real, consented, and anonymised legitimate SMS examples are needed for a credible false-positive evaluation.

## Benchmark reproducibility

Before benchmarking, set the following environment variables:

```bash
export EXECUTORCH_COMMIT="<commit>"
export MODEL_NAME="<model-name>"
export QUANT="<quantisation>"
```

Record the device, OS, kernel, Python version, CPU count, memory, model, quantisation, and command used.

For this VM, label results:

**ARM64 Linux VM on Apple silicon (QEMU).**

Do not report VM measurements as physical-board performance.

## Known limitations and next work

- Legitimate delivery notifications and food-delivery promotions are still sometimes flagged.
- A part-time-job scam was missed in the current hard-set evaluation.
- The Llama explanation verifier has demonstrated both false acceptance and false rejection.
- Llama sometimes repeats internal prompt instructions in its generated explanation.
- The tokenizer emits a JSON parsing warning during generation; its cause still needs investigation.
- The empty-network-namespace test has not yet been successfully completed because `unshare -rn` was denied in the VM.
- CPU temperature is unavailable in the current virtualised environment.
- Real-world performance requires evaluation on larger, independently sourced datasets.
- Check the Llama model licence, attribution and naming requirements, and the licences of all datasets before publishing model weights or data.

## Current project status

| Component | Status |
|---|---|
| Local SMS import | Implemented |
| Person C detector integration | Working |
| URL evidence and storyline | Working |
| Llama 3.2 1B integration | Working |
| Sequence-length configuration | Corrected for current prompts |
| Runtime metrics collection | Working in integrated report |
| Deterministic fallback | Working |
| Explanation verifier | Needs improvement |
| Fully isolated offline test | Not yet verified |
| Physical ARM device benchmark | Pending |

**Overall:** Person A's integrated detection and local explanation pipeline is operational in the ARM64 QEMU environment. The remaining priority is improving explanation safety verification and validating offline operation and performance on physical ARM hardware.

