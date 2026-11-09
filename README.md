# Guardian Person C Models

This repository contains the Guardian architecture documents and the Person C implementation for offline SMS and URL threat detection.

It currently provides:

- Unicode and URL normalization shared by SMS and URL detectors.
- Explainable rule-based SMS and URL baselines.
- A stable evidence-record contract for Core integration.
- A campaign-safe JSONL dataset loader and evaluation split.
- A standard-library hashed linear SMS model with explainable features.
- A calibrated real-time SMS runtime with alert, review and benign-candidate states.
- A Playwright scraper for redacted public SMS corpora with source and license metadata.
- Unit tests for normalization, detection, model training and safety boundaries.

The runtime is designed for fast, explainable on-device inference. It does not claim that a message is safe, and its final security verdict remains Core's responsibility.

## Architecture

See [architecture.md](architecture.md) for the system design and [docs/guardian-architecture.mmd](docs/guardian-architecture.mmd) for the editable Mermaid diagram.

## Run

From `person-c`:

```text
python -m unittest discover -s tests -v
python -m guardian_models.cli --kind sms --text "Your account is suspended. Verify now at https://example.test"
python -m guardian_models.cli --kind url --url "https://paypa1-login.example.test/verify"
python -m guardian_models.train_sms data/sms.example.jsonl artifacts/sms-baseline.json --holdout-campaign travel-2
python -m guardian_models.train_sms data/public_sms.jsonl artifacts/public-sms-calibrated.json --holdout-fraction 0.2 --max-records 12000 --epochs 3
python -c "from guardian_models.runtime import SMSRuntime; print(SMSRuntime.from_artifact('artifacts/public-sms-calibrated.json').analyze('Your account is suspended. Verify now'))"
```

## Real-data workflow

The public corpus is generated with:

```text
npm install playwright --no-save
node tools/scrape_public_sms.js
```

The scraper redacts phone numbers and email addresses, deduplicates exact phishing messages, assigns template-derived campaign groups and writes `data/public_sms.sources.json`. The source terms and limitations must be reviewed before redistribution or competition submission.

## Integration contract

`guardian_models.detectors.analyze_sms` and `analyze_url` return dictionaries with:

`evidence_id`, `source`, `event_type`, `timestamp`, `entity`, `risk_tier`, `score`, `reasons`, and `related_ids`.

The trained artifact contains a calibrated operating threshold, a review band and a maximum input length. Model scores should not be displayed as probabilities unless calibration is separately validated on an appropriate shifted holdout.

For Core integration, load a trained artifact with `guardian_models.runtime.SMSRuntime.from_artifact(...)`. The runtime threshold comes from a separate campaign-group calibration split; uncertain results remain `REVIEW` rather than being called safe.

The included public-corpus numbers are smoke benchmarks, not production accuracy claims. Real evaluation requires licensed, campaign-separated or time-ordered data, genuine OTP/delivery hard negatives, newer campaigns, calibration checks and testing on the actual Android phone.
