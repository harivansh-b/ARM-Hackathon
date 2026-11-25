
# Person C — Guardian Models, Training and Offline Intelligence

Person C contains Guardian's model and data workstream. It implements the compact SMS classifier, training and calibration logic, SMS and URL analysis, evidence and safety utilities, dataset preparation, evaluation tooling and offline threat-intelligence bundle handling.

Inference and model processing are designed to operate locally.

## Responsibilities

- SMS dataset preparation.
- Campaign-aware training and evaluation.
- Compact SMS classification.
- Calibration and threshold selection.
- SMS normalization.
- URL lexical analysis.
- Evidence generation and correlation.
- Safety verification and approved actions.
- Offline threat-intelligence bundle handling.
- Benchmark and evaluation tooling.

## Architecture

```text
Dataset Sources
      |
      v
Dataset Preparation
      |
      v
Campaign / Template Splitting
      |
      v
Compact SMS Model
      |
      v
Calibration
      |
      v
Model Artifact
      |
      +--------------------+
      |                    |
      v                    v
SMS Runtime           URL / Threat
                      Intelligence
      |                    |
      +---------+----------+
                |
                v
         Evidence / Safety
                |
                v
         Person A / Web UI
```

## Main files

### Model implementation

| File | Responsibility |
|---|---|
| `guardian_models/sms_model.py` | Compact hashed-feature linear SMS classifier |
| `guardian_models/train_sms.py` | SMS training, calibration and held-out evaluation |
| `guardian_models/runtime.py` | Runtime model loading and inference |
| `guardian_models/dataset.py` | JSONL dataset loading and campaign splitting |
| `guardian_models/normalize.py` | Message and URL normalization |
| `guardian_models/calibration.py` | Operating threshold selection |
| `guardian_models/metrics.py` | Metric computation |
| `guardian_models/detectors.py` | SMS and URL analysis |
| `guardian_models/evidence.py` | Evidence records |
| `guardian_models/evidence_graph.py` | Evidence relationships |
| `guardian_models/safety.py` | Safety verification and approved action logic |
| `guardian_models/bundles.py` | Threat bundle validation |
| `guardian_models/cli.py` | Local detector CLI |

### Data and artifacts

| Path | Purpose |
|---|---|
| `data/` | Training and evaluation data |
| `artifacts/` | SMS model artifacts |
| `tools/` | Dataset preparation, scraping, evaluation and bundle tooling |
| `evaluation/` | Device and offline evaluation evidence |
| `tests/` | Model and dataset adapter tests |

## SMS model

Guardian uses a compact hashed-feature linear classifier.

The model generates features from normalized message text, including:

- Word features
- Word bigrams
- Character n-gram-like features

Feature contributions can be inspected through the model explanation functionality.

The classifier uses a sigmoid score and deterministic training logic.

The model is intentionally lightweight compared with a large neural text model.

## Training workflow

### 1. Dataset preparation

Dataset preparation combines selected training sources into a normalized JSONL file.

The repository includes public SMS/phishing data and multilingual starter data.

The hard-negative dataset is kept evaluation-only and should not be silently incorporated into training when its purpose is to measure false positives.

### 2. Campaign-aware splitting

Dataset splitting groups related messages by campaign.

This reduces the risk of near-duplicate message templates being split between training and testing.

### 3. Training

The trainer fits the compact model to the prepared examples.

It supports:

- Holdout campaign selection
- Holdout fraction
- Training epochs
- Optional class balancing
- Optional record limit

### 4. Calibration

The calibration data is used to select an operating threshold.

The calibration logic supports constraints such as maximum false-positive rate and minimum recall.

Calibration is separate from the final test set.

### 5. Evaluation

The test partition is used to calculate metrics.

The artifact includes evaluation metadata to help identify the training split, threshold and record counts.

### 6. Artifact generation

The training command writes a model artifact containing the model parameters and runtime configuration.

Guardian's SMS runtime loads the artifact for inference.

## Dependencies

The compact SMS model and primary training logic use Python standard-library functionality.

The implementation does not require a hosted ML service.

Dataset tooling may have separate dependencies depending on the specific script. For example, the public SMS scraper uses Node.js and Playwright.

Review each tool before installing dependencies or running data collection.

## Training commands

Run commands from the `person-c/` directory.

### Prepare the default training input

```bash
python3 tools/prepare_sms_dataset.py \
    data/sms-training.jsonl \
    data/public_sms.jsonl \
    data/sms_multilingual.jsonl
```

### Train the SMS model

```bash
python3 -m guardian_models.train_sms \
    data/sms-training.jsonl \
    artifacts/sms.json
```

### Train with class balancing

```bash
python3 -m guardian_models.train_sms \
    data/sms-training.jsonl \
    artifacts/sms.json \
    --balance
```

### Train with a specified holdout fraction

```bash
python3 -m guardian_models.train_sms \
    data/sms-training.jsonl \
    artifacts/sms.json \
    --holdout-fraction 0.2
```

### Specify epochs

```bash
python3 -m guardian_models.train_sms \
    data/sms-training.jsonl \
    artifacts/sms.json \
    --epochs 12
```

### Limit training records

```bash
python3 -m guardian_models.train_sms \
    data/sms-training.jsonl \
    artifacts/sms.json \
    --max-records 10000
```

The `--max-records` option limits the input used for the training run. Record selection is deterministic within the script.

## Dataset preparation

The repository includes dataset preparation and evaluation scripts.

### Prepare the default corpus

```bash
python3 tools/prepare_sms_dataset.py \
    data/sms-training.jsonl \
    data/public_sms.jsonl \
    data/sms_multilingual.jsonl
```

### Compare corpora

```bash
python3 tools/compare_sms_corpora.py
```

Review the script arguments and output path before running.

### Public SMS scraper

The scraper is implemented in:

```text
tools/scrape_public_sms.js
```

It uses Node.js and Playwright to collect public SMS data.

The scraper output and source provenance should be reviewed before using the data for training or redistribution.

Dataset licensing and source limitations remain relevant even when data is publicly accessible.

## SMS inference

The CLI supports SMS and URL analysis.

### Analyze an SMS

```bash
python3 -m guardian_models.cli --kind sms --text "Your account is locked"
```

### Analyze a URL

```bash
python3 -m guardian_models.cli --kind url --url "https://example.com"
```

The analysis is local and does not require the URL to be opened.

## URL analysis

The URL detector performs local URL analysis and normalization.

It does not require a cloud lookup for its basic inference path.

URL analysis can be used alongside SMS detection to enrich the evidence associated with a message.

## Offline threat-intelligence bundles

Guardian supports offline threat-intelligence bundles.

The bundle tooling supports locally generated data and validation.

### Build a bundle

Review the tool's CLI arguments:

```bash
python3 tools/build_threat_bundle.py --help
```

### Evaluate a threat bundle

```bash
python3 tools/evaluate_threat_bundle.py --help
```

Threat bundles should be treated as frozen local data with provenance, versioning and integrity requirements.

The repository's bundle signing implementation is a demonstrator and should not be considered a production cryptographic key-management system.

## Evaluation

The repository contains SMS, URL and device evaluation tooling.

### SMS report evaluation

```bash
python3 tools/evaluate_report.py --help
```

### URL benchmark

```bash
python3 tools/evaluate_url_benchmark.py --help
```

### SMS evaluation slices

```bash
python3 tools/eval_sms_slices.py --help
```

### Corpus comparison

```bash
python3 tools/compare_sms_corpora.py --help
```

Use the relevant dataset and output options for each evaluation.

## Device evaluation

The `evaluation/` directory contains device benchmarking and offline verification tooling.

See:

- `evaluation/README.md`
- `evaluation/run_device_benchmark.py`
- `evaluation/offline_smoke.py`
- `evaluation/collect_executorch_metadata.py`

Device measurements must be collected on the target device. Host-side measurements are not a substitute for ARM deployment evidence.

## Tests

From the repository root:

```bash
python3 -m unittest discover -s person-c/tests -v
```

Or from the `person-c/` directory:

```bash
python3 -m unittest discover -s tests -v
```

## Data roles

The repository separates training data, evaluation data and synthetic fixtures.

| Dataset | Role |
|---|---|
| Public SMS/phishing corpus | SMS training |
| Multilingual SMS starter data | Training augmentation |
| Indian hard negatives | Evaluation-only |
| Synthetic SMS examples | Demonstration and controlled evaluation |
| Public URL sources | URL research/evaluation |
| Offline threat feeds | Local lookup bundles |

Data should not be silently moved between these roles.

## Evaluation limitations

- Synthetic fixtures are not evidence of real-world prevalence.
- Dataset source and licence restrictions remain relevant.
- Campaign-based splitting reduces one type of leakage but does not guarantee independent or prospective evaluation.
- The SMS test metrics depend on the exact artifact and dataset used.
- Hard-negative results must be interpreted with their sample size.
- URL lexical analysis is not a substitute for a real-world reputation service.
- Network reference benchmarks are not live network detector accuracy.
- Device performance claims require measurements on the actual target hardware.

## Integration

Person C provides model and analysis components used by Person A and the Guardian web application.

Person A handles message import and scanning orchestration.

The web application integrates Person C's runtime and detector functions into the local Guardian interface.

