# Guardian Person C

Person C contains Guardian's on-device SMS scam, phishing URL, model,
explainability and offline intelligence workstream for the Bharat AI SoC
hackathon. Inference is designed to remain local and never depends on opening
URLs or contacting a threat-intelligence service.

## Current implementation

- Campaign-aware SMS training with the public corpus and multilingual
  English/Hindi/Hinglish augmentation.
- Indian hard-negative evaluation for OTP, UPI, banking, tax and delivery
  messages.
- URL lexical analysis with no network lookup.
- Signed offline threat-intelligence bundles for verified local domain lookup.
- Reproducible dataset adapters and benchmark reports for network datasets.

## Dataset roles

| Dataset | Role | Status |
|---|---|---|
| Public SMS/phishing corpus | SMS training | Incorporated |
| Multilingual SMS corpus | Hindi/Hinglish augmentation | Incorporated |
| Indian hard negatives | False-positive evaluation | Evaluation-only |
| CIC-Bell DNS EXF 2021 | DNS benchmark/model | Opt-in runtime path |
| UNSW-NB15 | Cross-dataset network validation | Processed benchmark |
| CICIDS2017 | DDoS and PortScan validation | Processed benchmark |
| OpenPhish | Offline phishing-domain lookup | Signed bundle |
| PhishTank | Offline phishing-domain lookup | Pending application-key feed |
| ISCX-URL2016 | URL benchmark | Documented only; no raw URL column |

Raw external files remain local and gitignored. Provenance and hashes are in
`../integration-tests/external_dataset_manifest.json`.

## Measured results

### SMS augmentation

The public-plus-multilingual model improved hard-set scam recall from **60.0%**
to **86.7%**, while held-out F1 remained effectively unchanged (**99.68%** to
**99.66%**) and legitimate-message FPR remained **26.5%**.

Report: `../integration-tests/sms_corpus_comparison.json`.

### Network reference benchmarks

These are dataset-level reference results, not live Guardian accuracy, because
the public datasets expose flow features while the runtime observes packet
windows.

| Benchmark | Attack recall | Benign recall | Macro F1 |
|---|---:|---:|---:|
| UNSW-NB15 | 84.68% | 67.19% | 76.18% |
| CICIDS2017 DDoS | 99.92% | 99.78% | 99.86% |
| CICIDS2017 PortScan | 99.90% | 99.41% | 98.80% |

Reports are in `../integration-tests/*reference.report.json`.

### Offline OpenPhish bundle

The frozen OpenPhish snapshot produced a signed bundle containing **286 unique
domains**. Lookup validation matched **300/300** feed URLs and **0/20** curated
benign URLs. This validates bundle integrity and lookup behavior; it is not a
population-level phishing accuracy estimate.

Bundle: `../integration-tests/openphish.bundle.json`.

## Commands

Run Person C tests from the repository root:

```text
python -m unittest person-c/tests/test_models.py person-c/tests/test_dataset_adapters.py -v
```

Build the default SMS training input:

```text
python person-c/tools/prepare_sms_dataset.py data/sms-training.jsonl \
    person-c/data/public_sms.jsonl person-c/data/sms_multilingual.jsonl
```

Build a signed offline threat bundle from a local feed snapshot:

```text
python person-c/tools/build_threat_bundle.py \
    --openphish data/external/threat-intel/openphish-feed.txt \
    --output integration-tests/openphish.bundle.json \
    --key <signing-key>
```

The current bundle and HMAC implementation are a prototype. A production
Android release must use asymmetric signing with only the public key shipped
in the application.

## Remaining gates

- Obtain a PhishTank application-key snapshot and rebuild the bundle.
- Validate live DNS feature parity before enabling the DNS model by default.
- Run ARM target latency, memory, model-size and sustained offline tests.
- Obtain raw URL data before claiming ISCX-URL2016 improves URL inference.
