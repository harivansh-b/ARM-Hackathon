# Guardian Person C Models

This module is the dependency-light starting point for the Models and Llama workstream.

It currently provides:

- Unicode and URL normalization shared by SMS and URL detectors.
- Explainable rule-based SMS and URL baselines.
- A stable evidence-record contract for Core integration.
- Unit tests for normalization, detection, and safety boundaries.

The rules are a baseline, not a trained production model. Real datasets, held-out splits, calibration, and ExecuTorch export must be added after the team supplies data and confirms the target phone.

## Run

From this directory:

```text
python -m unittest discover -s tests -v
python -m guardian_models.cli --kind sms --text "Your account is suspended. Verify now at https://example.test"
python -m guardian_models.cli --kind url --url "https://paypa1-login.example.test/verify"
```

## Integration contract

`guardian_models.detectors.analyze_sms` and `analyze_url` return dictionaries with:

`evidence_id`, `source`, `event_type`, `timestamp`, `entity`, `risk_tier`, `score`, `reasons`, and `related_ids`.

Scores are ranked baseline scores, not calibrated probabilities.
