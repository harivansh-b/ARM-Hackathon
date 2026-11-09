# Guardian Person C Models

This repository contains the Guardian architecture documents and the dependency-light starting point for the Person C Models and Llama workstream.

It currently provides:

- Unicode and URL normalization shared by SMS and URL detectors.
- Explainable rule-based SMS and URL baselines.
- A stable evidence-record contract for Core integration.
- A campaign-safe JSONL dataset loader and evaluation split.
- A standard-library hashed linear SMS model with explainable features.
- Unit tests for normalization, detection, model training and safety boundaries.

The rules are a baseline, not a trained production model. Real datasets, held-out splits, calibration, and ExecuTorch export must be added after the team supplies data and confirms the target phone.

## Run

From `person-c`:

```text
python -m unittest discover -s tests -v
python -m guardian_models.cli --kind sms --text "Your account is suspended. Verify now at https://example.test"
python -m guardian_models.cli --kind url --url "https://paypa1-login.example.test/verify"
python -m guardian_models.train_sms data/sms.example.jsonl artifacts/sms-baseline.json --holdout-campaign travel-2
python -m guardian_models.train_sms data/public_sms.jsonl artifacts/public-sms-baseline.json --holdout-fraction 0.2 --max-records 12000 --epochs 3
```

## Integration contract

`guardian_models.detectors.analyze_sms` and `analyze_url` return dictionaries with:

`evidence_id`, `source`, `event_type`, `timestamp`, `entity`, `risk_tier`, `score`, `reasons`, and `related_ids`.

Scores are ranked baseline scores, not calibrated probabilities.

The example dataset is only a smoke fixture. It is not a research dataset and must not be presented as a quality result. Real evaluation requires licensed, campaign-separated data and a newer held-out split.
