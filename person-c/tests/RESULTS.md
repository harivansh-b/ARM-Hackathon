# Person C Results

Latest local verification run: **2026-11-22** (Asia/Calcutta).

## Requirement checklist

| Requirement | Status | Evidence or blocker |
|---|---|---|
| Complete SMS/URL vertical slice | **Done** | Detector, runtime, evidence contract and tests |
| Multilingual metrics | **Done for development fixture** | `evaluation/report.json`; not production-quality evidence |
| Legitimate Indian hard negatives | **Done as seed set** | 10 messages across five categories; expand with consented data |
| Time-ordered/independent evaluation | **Working stage** | Date field and evaluator ready; verified independent collection pending |
| Explanation safety and fallback | **Done** | Verifier rejects unsafe/injected output; deterministic playbook fallback |
| Offline model/intelligence update validation | **Working stage** | HMAC prototype; asymmetric signing still required for release |
| Evidence storyline linking | **Done as primitive** | SMS-to-URL correlation with time window |
| ARM performance measurements | **Pending target** | Harness ready; no ARM target connected |
| ExecuTorch Llama execution | **Pending target export** | Runtime metadata collector ready; package not installed locally |
| Authorised offline-lab proof | **Pending authorisation/device** | Host smoke passed, but it is not lab evidence |
| Android Core/Net integration | **Pending** | Current repository is the Person C model workstream |

## Verification summary

| Check | Result | Scope |
|---|---:|---|
| Python unit tests | **19 passed** | Normalization, detection, training, metrics, runtime safety, verifier, bundle security, evidence linking and hard negatives |
| Python compilation | **Passed** | All `guardian_models` modules |
| Scraper syntax check | **Passed** | `tools/scrape_public_sms.js` |
| Multilingual corpus validation | **Passed** | JSONL schema, label balance and language counts |
| Network dependency during inference | **None** | Detector and runtime execute locally |
| JSONL dataset validation | **4 datasets loaded** | 24 + 10 + 34,100 + 10,271 records |
| Offline host smoke | **Passed** | Socket connections denied; core detection and guidance remained available |
| Slide-driven software controls | **Passed** | Verifier/fallback, signed bundle checks and SMS-to-URL evidence linking |

## Dataset integration update

The current branch also contains reproducible reference evaluations for
UNSW-NB15, CICIDS2017 and a signed OpenPhish offline bundle. These results are
kept separate from live-runtime accuracy claims:

| Evaluation | Result |
|---|---|
| UNSW-NB15 | 84.68% attack recall, 67.19% benign recall, 76.18% macro F1 |
| CICIDS2017 DDoS | 99.92% attack recall, 99.78% benign recall, 99.86% macro F1 |
| CICIDS2017 PortScan | 99.90% attack recall, 99.41% benign recall, 98.80% macro F1 |
| OpenPhish lookup | 300/300 malicious matches, 0/20 curated benign matches |
| DNS runtime parity | Default and opt-in model paths preserved all local scenario alert counts |

The complete reports are in the repository-level `integration-tests/`
directory, and dataset provenance is recorded in
`integration-tests/external_dataset_manifest.json`.

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

## Final-evidence workstream (working stage)

The repository now contains the measurement protocol and fixtures needed for the final report. Results are intentionally marked pending until collected from the authorised target-device run.

| Requirement | Working-stage evidence | Completion state |
|---|---|---|
| Per-language precision, recall, F1, FPR | `tools/evaluate_report.py`; grouped output in `evaluation/report.json` | Ready to run; not a production claim |
| Indian hard negatives | `data/indian_hard_negatives.jsonl`: legitimate OTP, UPI, bank, tax and delivery, English/Hindi | Seed fixture; expand with consented samples |
| Time-ordered/independent evaluation | `collection_date` is supported and the evaluator reports date coverage | Pending verified pre/post collection boundary |
| ARM latency/RAM/size/temperature/sustained operation | `evaluation/device_benchmark.csv` schema and `evaluation/README.md` runbook | Pending authorised target-device run |
| ExecuTorch version/quantisation/backend/first token | Required columns in `device_benchmark.csv` | Pending export and device measurement |
| Offline-lab evidence | Disconnected-network test protocol in `evaluation/README.md` | Pending authorised lab log/screenshots |

The host smoke artifact is `evaluation/offline_smoke_evidence.json`. It records a `CRITICAL` core result and safe guidance with network connections denied. It is explicitly not authorised lab evidence.

The offline bundle implementation is a dependency-free HMAC prototype for the software contract. The target Android release should use an asymmetric signing key and keep the public key in the application; no shared signing secret should ship in the APK.

Run the host-side evaluation from `person-c` with:

```text
python tools/evaluate_report.py artifacts/sms-multilingual.json data/sms_multilingual.jsonl data/indian_hard_negatives.jsonl --output evaluation/report.json
```

The host output is a reproducibility aid. It must be labelled development/seed evaluation until the multilingual and hard-negative sets are independently collected and reviewed.

### Current seed-run output

Using `artifacts/sms-multilingual.json` at threshold `0.893337` over the 24-row development fixture plus 10 hard negatives. This report was regenerated in the latest run and is stored at `evaluation/report.json`:

| Language | n | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|
| en | 14 | 1.000 | 0.667 | 0.800 | 0.000 |
| hi | 15 | 0.857 | 1.000 | 0.923 | 0.111 |
| hinglish | 5 | 1.000 | 1.000 | 1.000 | 0.000 |

The five hard-negative categories each contain two seed messages and each measured `0/2` false positives. Because these are small, consented-lab seed fixtures, this is a test of the reporting path and not evidence of production multilingual quality. The generated JSON is `evaluation/report.json`.
