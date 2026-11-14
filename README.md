# Guardian Person C

Guardian Person C is the offline SMS and URL detection workstream for an ARM Linux security assistant. The current vertical slice detects smishing, returns structured evidence, supports English/Hindi/Hinglish presentation, and keeps the language model outside the security decision.

## Phase 1 implementation checklist

### Done

- [x] Primary scenario selected: offline SMS/smishing detection with URL inspection.
- [x] Deterministic SMS and URL detectors with structured evidence.
- [x] English, Hindi and Hinglish routing with safe guidance.
- [x] Compact linear model, campaign-held-out training and threshold calibration.
- [x] Per-language precision, recall, F1 and false-positive-rate evaluator.
- [x] Indian legitimate OTP, UPI, bank, tax and delivery hard-negative fixture.
- [x] Runtime safety fix: core `HIGH`/`CRITICAL` evidence cannot be downgraded by the advisory model.
- [x] Explanation verifier and approved-action fallback playbook.
- [x] Offline bundle integrity, signature and rollback checks.
- [x] SMS-to-URL evidence linking and incident-storyline primitives.
- [x] Network-denial host smoke test proving local detection and guidance execution.
- [x] Reproducible tests, compilation checks and dataset validation.

### Working stage

- [ ] Expand hard negatives with consented, anonymised Indian messages.
- [ ] Replace seed multilingual data with independently collected, time-ordered evaluation data.
- [ ] Replace the HMAC bundle prototype with asymmetric Ed25519 signing in the Android packaging path.
- [ ] Connect the verifier, bundle importer and evidence graph to the Android Core UI.
- [ ] Add model card, SBOM, licence manifest and artifact SHA-256 release records.

### Pending external validation

- [ ] Export and execute a real Llama-family model through ExecuTorch.
- [ ] Record ExecuTorch version, quantisation, backend, model size and first-token latency.
- [ ] Measure ARM device latency, peak RAM, temperature, throttling and sustained operation.
- [ ] Run the authorised disconnected-network lab test on the selected ARM target.
- [ ] Complete Android SMS/URL integration and demo-video evidence.

The checklist is intentionally honest: host-side software is implemented and tested, while target-device and authorised-lab claims remain unmeasured.

## What is implemented

| Area | Implementation |
|---|---|
| SMS detection | Deterministic indicators plus a compact standard-library linear model |
| URL detection | URL canonicalisation, shortener, look-alike, IP-literal and credential-path checks |
| Languages | English, Hindi and Hinglish routing; Hindi/Hinglish indicators |
| Explainability | Matched signals, recommended safe action and model-feature contributions |
| Runtime safety | `ALERT`, `REVIEW` and `BENIGN_CANDIDATE` states; bounded input; offline operation |
| Data quality | Campaign/template grouping, campaign-held-out splitting and calibration |
| Public data | Playwright-collected baseline and multilingual English/Hindi corpus with provenance |
| Integration boundary | JSON evidence contract for Core; Llama is an advisory explanation layer |
| Safety controls | Explanation verifier, approved-action playbook, signed offline bundle checks and evidence linking |

## Repository layout

```text
person-c/
  guardian_models/       Detector, model, runtime, dataset and metric code
  data/                  Synthetic fixtures, public JSONL data and provenance
  artifacts/             Generated model artifacts and evaluation metadata
  evaluation/            Metrics, offline evidence, device and ExecuTorch runbooks
  tests/                 Unit tests and evaluation notes
  tools/                 Playwright collection script
architecture.md          System design and safety boundaries
docs/guardian-architecture.mmd  Editable architecture diagram
```

## Quick start

From `person-c`:

```text
python -m unittest discover -s tests -v
python -m guardian_models.cli --kind sms --text "Your account is suspended. Verify now at https://example.test"
python -m guardian_models.cli --kind sms --text "आपका बैंक खाता बंद हो जाएगा। OTP भेजें।"
python -m guardian_models.cli --kind url --url "https://paypa1-login.example.test/verify"
```

## Train and run an artifact

```text
python -m guardian_models.train_sms data/sms_multilingual.jsonl artifacts/sms-multilingual.json --holdout-fraction 0.25 --epochs 12
python -c "from guardian_models.runtime import SMSRuntime; print(SMSRuntime.from_artifact('artifacts/sms-multilingual.json').analyze('Aapka bank account band ho jayega. OTP bhejo abhi'))"
```

Training uses campaign-held-out splits. The same campaign or near-duplicate template must not appear in both training and evaluation data.

## Data and reproducibility

| Dataset | Purpose | Current size | Important limitation |
|---|---|---:|---|
| `data/sms_multilingual.jsonl` | Small English/Hindi/Hinglish development fixture | 24 | Synthetic; not a benchmark |
| `data/public_sms.jsonl` | Existing English SMS/phishing baseline | 34,100 | Mixed sources and template-derived campaigns |
| `data/public_sms_multilingual.jsonl` | Public English/Hindi robustness corpus | 10,271 | Hindi is machine-translated; GPL dataset card |

Regenerate public data with:

```text
node tools/scrape_public_sms.js
```

The scraper uses Playwright request extraction, redacts phone numbers and email addresses, assigns campaign IDs, and writes source metadata beside each corpus. Review source terms and licenses before redistribution or competition submission. Hinglish is not represented by a verified public field; use consented or clearly labelled synthetic Hinglish data.

## Integration contract

`guardian_models.detectors.analyze_sms` and `analyze_url` return JSON-serialisable evidence containing:

`evidence_id`, `source`, `event_type`, `timestamp`, `entity`, `risk_tier`, `score`, `reasons`, and `related_ids`.

SMS results additionally expose `language`, `language_label`, `matched_signals`, `safe_action`, and `explanation`. `SMSRuntime.from_artifact(...)` adds the calibrated model score, model evidence, decision state, truncation flag and latency.

The detector owns the risk signal. Llama/ExecuTorch may paraphrase structured evidence, but it must not create the security verdict. If the advisory path fails, the deterministic explanation remains available.

## Limitations and next validation

The public results are smoke benchmarks, not production accuracy claims. Final evaluation must use licensed or consented data, campaign/time-separated holdouts, legitimate Indian hard negatives, per-language metrics, target-device latency/RAM measurements, and an offline ARM demonstration.

The final-evidence workstream is tracked in `person-c/evaluation/`: run `person-c/tools/evaluate_report.py` for grouped language and hard-negative metrics, then populate `person-c/evaluation/device_benchmark.csv` from the authorised ARM/ExecuTorch run. The offline-lab protocol requires the network to be disconnected and produces the evidence needed to claim that detection and guidance work without connectivity.

The slide-driven software additions are implemented in `guardian_models.safety`, `guardian_models.bundles` and `guardian_models.evidence_graph`. They provide deterministic Llama-output rejection/fallback, tamper-and-rollback checks for offline packages, and SMS-to-URL evidence linking. The bundle prototype uses HMAC-SHA256 to remain dependency-free; production Android packaging should replace it with an asymmetric Ed25519 signature while retaining the same manifest checks.

See [architecture.md](architecture.md), [results](person-c/tests/RESULTS.md) and [docs/guardian-architecture.mmd](docs/guardian-architecture.mmd).
