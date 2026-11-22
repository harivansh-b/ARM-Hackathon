# Final-evidence runbook

This directory separates reproducible host evaluation from evidence that must be collected on the target ARM device. Empty cells and `PENDING_*` values are intentional; they must not be replaced with estimates.

## Host evaluation

From `person-c`:

```text
python tools/evaluate_report.py artifacts/sms-multilingual.json data/sms_multilingual.jsonl data/indian_hard_negatives.jsonl --output evaluation/report.json
```

The output contains per-language precision, recall, F1 and false-positive rate, category-level results for legitimate Indian OTP/UPI/bank/tax/delivery messages, and a date-coverage warning. A true time-ordered result requires verified collection dates and a train-before-test boundary; a campaign split is acceptable when collection dates are unavailable.

## ARM / ExecuTorch run

Record the exact device SKU, SoC, OS image, governor, ambient temperature and battery state. Run 30 warm-up messages followed by at least 30 minutes of mixed benign/high-risk traffic. Capture p50/p95 core-detector latency, first-token latency for the advisory model, peak RSS, model file size, start/end temperature, throughput and any OOM, thermal-throttle or dropped-response event. Fill `device_benchmark.csv` only from the run log.

The ExecuTorch row must include the package/runtime version, exported model identifier, quantisation scheme (for example int8 or int4), selected backend/delegate, and first-token latency. Core detection and the safety decision remain valid if advisory generation is unavailable.

## Authorised offline-lab evidence

1. Obtain written authorisation and record test ID, operator, device serial alias and timestamp.
2. Disable Wi-Fi, cellular data, Ethernet and DNS; record the disconnected state in the lab log.
3. Launch the app, submit at least one legitimate hard negative and one high-risk SMS/URL, and capture the decision, evidence and safe guidance.
4. Verify no network connection attempts are required for detection or guidance; retain system/network logs and screenshots/video.
5. Reconnect only after the run is complete and record the end state.

This is an evidence protocol, not proof of completion. The report must cite the authorised run artifact once collected.

## Reproducible local evidence

Run the network-denial smoke test with:

```text
python evaluation/offline_smoke.py artifacts/sms-multilingual.json --output evaluation/offline_smoke_evidence.json
```

This confirms that core detection and guidance execute while socket connections are denied. It is host evidence only and is not a substitute for authorised lab sign-off.

## Current dataset evidence

The current branch includes separate reports for the SMS, DNS, network and
offline threat-intelligence workstreams:

| Workstream | Current result |
|---|---|
| SMS multilingual augmentation | 86.7% hard-scam recall; 26.5% Indian legitimate-message FPR |
| UNSW-NB15 | 84.68% attack recall, 67.19% benign recall, 76.18% macro F1 |
| CICIDS2017 DDoS | 99.92% attack recall, 99.78% benign recall, 99.86% macro F1 |
| CICIDS2017 PortScan | 99.90% attack recall, 99.41% benign recall, 98.80% macro F1 |
| OpenPhish lookup | 300/300 malicious matches and 0/20 curated benign matches |
| DNS live parity | Default and opt-in model paths preserved local scenario alert counts |

The network classifier numbers are reference benchmark results, not live
Guardian accuracy. The OpenPhish number is a lookup-integrity check, not a
population-level phishing prevalence estimate. PhishTank can be added through
the same signed bundle builder once an application-key feed is available.

On the ARM target, run:

```text
python evaluation/run_device_benchmark.py artifacts/sms-multilingual.json --duration-min 30 --output evaluation/device_run.json
python evaluation/collect_executorch_metadata.py --model /path/to/exported_model.pte --quantisation int8 --backend XNNPACK --output evaluation/executorch_metadata.json
```

The benchmark records architecture, sustained throughput, p50/p95 core latency, peak RSS and thermal readings. The metadata collector records ExecuTorch version, model size, quantisation and backend; first-token latency must be added by the advisory-model runner.
