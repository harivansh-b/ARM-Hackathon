# Person C Results

## Verification summary

| Check | Result | Scope |
|---|---:|---|
| Python unit tests | **14 passed** | Normalization, detection, training, metrics, runtime and multilingual fixtures |
| Python compilation | **Passed** | All `guardian_models` modules |
| Scraper syntax check | **Passed** | `tools/scrape_public_sms.js` |
| Multilingual corpus validation | **Passed** | JSONL schema, label balance and language counts |
| Network dependency during inference | **None** | Detector and runtime execute locally |

Run the unit tests with:

```text
python -m unittest discover -s tests -v
```

## Dataset inventory

| Dataset | Records | Positive | Negative | Languages | Use |
|---|---:|---:|---:|---|---|
| `sms_multilingual.jsonl` | 24 | 13 | 11 | en / hi / hinglish | Development fixture |
| `public_sms.jsonl` | 34,100 | 29,273 | 4,827 | Primarily English | Existing baseline |
| `public_sms_multilingual.jsonl` | 10,271 | 1,254 | 9,017 | English / Hindi | Robustness testing |

The public multilingual corpus contains paired English/Hindi variants from the same source message. The scraper assigns a shared campaign ID so translated variants cannot cross a campaign-held-out split. Its Hindi text is machine-translated and its label distribution is highly imbalanced.

## Smoke benchmark results

| Evaluation | Split | Precision | Recall | F1 | False-positive rate | PR-AUC |
|---|---|---:|---:|---:|---:|---:|
| Existing public baseline | 12,000-record campaign subset | 0.9990 | 0.9931 | 0.9960 | 0.0056 | 0.9998 |
| Calibrated runtime | Same campaign subset with separate calibration | 1.0000 | 0.9750 | 0.9873 | 0.0000 | 0.9997 |

```text
F1 score
Baseline    99.60% |████████████████████|
Calibrated  98.73% |███████████████████▊ |

False-positive rate
Baseline     0.56% |██████              |
Calibrated   0.00% |                    |
```

These numbers are smoke benchmarks only. The source corpus is imbalanced, one phishing source is positive-only, and template-derived groups are not true campaign IDs. They must not be presented as production accuracy.

## Runtime behavior

| Condition | Output |
|---|---|
| Clear high-risk score | `ALERT` with evidence and safe action |
| Score near threshold | `REVIEW` with independent-verification guidance |
| Low score | `BENIGN_CANDIDATE`, never a safety guarantee |
| Missing/invalid advisory model | Deterministic detector explanation remains available |
| Oversized input | Truncated to configured maximum and reported |

The runtime also records inference latency and returns model-feature contributions for debugging and explainability.

## Limitations and next measurements

The current results do not yet establish target-device performance or multilingual quality. The final report should add:

- per-language precision, recall, F1 and false-positive rate;
- legitimate Indian OTP, UPI, bank, tax and delivery hard negatives;
- time-ordered or independently collected evaluation;
- ARM device latency, peak RAM, model size, temperature and sustained operation;
- ExecuTorch model version, quantisation, backend and first-token latency;
- authorised offline-lab evidence showing that core detection and guidance work with the network disconnected.
