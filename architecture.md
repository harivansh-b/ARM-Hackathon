# Guardian Architecture

## Scope

Guardian is an offline-first SMS security assistant for an ARM Linux target. Person C owns the SMS/URL models, data pipeline, evidence contract and Llama explanation interface. The primary Phase 1 scenario is smishing: a message attempts to create urgency, impersonate a trusted service, obtain credentials, request payment, or direct the user to a suspicious URL.

## End-to-end flow

```mermaid
flowchart LR
    Input[SMS input] --> Norm[Normalize text and URLs]
    Norm --> Lang[Language and script routing]
    Lang --> Detect[Fast detector\nrules plus compact linear model]
    Detect --> Evidence[Structured evidence\nscore, tier, signals, provenance]
    Evidence --> Decision[Calibrated decision\nALERT / REVIEW / BENIGN_CANDIDATE]
    Decision --> Explain[Deterministic explanation]
    Evidence -. structured evidence only .-> Llama[Llama-family model\nExecuTorch on device]
    Llama --> Verify[Output verifier]
    Verify --> Explain
    Explain --> User[Safe recommendation]
    Public[Public and consented data] --> Split[Campaign/time split]
    Split --> Train[Train and evaluate]
    Train --> Artifact[Versioned artifact]
    Artifact -. offline import .-> Detect
```

The editable diagram is [docs/guardian-architecture.mmd](docs/guardian-architecture.mmd).

## Updated implementation architecture

The current implementation has four software boundaries:

1. **Detection boundary** — normalisation, language routing, deterministic rules, URL analysis and the compact SMS model.
2. **Decision boundary** — calibrated model evidence is combined with the stronger deterministic Core signal; `HIGH` and `CRITICAL` Core findings cannot be downgraded.
3. **Explanation boundary** — advisory Llama output is checked by `safety.verify_explanation`; rejected output falls back to the deterministic playbook.
4. **Update and correlation boundary** — `bundles.verify_bundle` validates offline package integrity, signature, expiry and rollback policy; `evidence_graph.correlate` links related SMS and URL records.

This keeps security decisions deterministic and makes the language model, update package and cross-event storyline independently testable.

## Detection boundary

The detector is the security authority. It normalizes input, extracts URLs, evaluates deterministic signals, and optionally adds a compact model score. It emits evidence such as urgency, credential request, payment language, impersonation, suspicious link, or numeric sender context.

The Llama-family model is advisory. It receives structured evidence rather than raw SMS by default and may produce a concise explanation in the selected language. It must not change the detector score or downgrade a warning. A timeout, invalid output, or verifier failure falls back to the deterministic explanation.

The verifier also rejects invented URLs or phone numbers, unsafe reassurance for high-risk evidence, unsupported actions and overlong output. Approved actions come from a fixed playbook; Llama cannot create a new security action.

## Runtime states

| State | Meaning | User-facing behavior |
|---|---|---|
| `ALERT` | Score is above the calibrated threshold | Show warning and safe action |
| `REVIEW` | Score is within the review band | Ask the user to verify independently |
| `BENIGN_CANDIDATE` | No strong signal was found | Avoid claiming the message is safe |

Input is bounded to the artifact’s configured maximum length. No URL is opened, no DNS lookup is required for SMS detection, and no message is sent to a remote service.

## Multilingual path

Language routing is a lightweight offline heuristic. URLs are excluded from language selection. Hindi Devanagari text is labelled `hi`; Roman Hindi markers are labelled `hinglish`; mixed Hindi/English text is labelled `hi-en`. These labels select presentation and evidence vocabulary; they are not a claim of linguistic certainty.

The public multilingual corpus provides English and machine-translated Hindi. Hinglish remains a separate synthetic or consented data track until a suitable public source is verified.

## Evidence contract

Each detector result contains:

```text
evidence_id, source, event_type, timestamp, entity,
risk_tier, score, reasons, related_ids
```

SMS-specific fields include language metadata, matched signals, deterministic safe action, extracted URLs and a human-readable explanation. IDs are stable hashes of source and entity values; raw message text is not stored in the evidence record.

## Data and model lifecycle

1. Collect only public, licensed, consented, or synthetic data.
2. Redact phone numbers and email addresses before storage.
3. Assign campaign/template groups before splitting.
4. Keep campaign groups disjoint across train, calibration and test sets.
5. Calibrate the operating threshold on validation data, never on the test set.
6. Record dataset source, label balance, split, model format, runtime configuration and target-device measurements in the artifact/report.
7. Import the artifact offline and verify its format before activation.
8. Verify offline intelligence/model bundles for hash, signature, expiry and minimum version before activation.
9. Keep raw message text out of evidence records by default; use stable IDs and redacted derived fields.

The Playwright scraper writes `public_sms.jsonl`, `public_sms_multilingual.jsonl`, and their provenance files. The multilingual source is machine-translated and heavily imbalanced, so it is suitable for robustness checks rather than standalone production evaluation.

## Device boundary

The planned Android deployment separates responsibilities:

- **Core** receives SMS, runs local models, stores minimal evidence, fuses findings and displays alerts. It should not request `INTERNET`.
- **Net** owns `VpnService` and emits only authorised DNS/flow metadata. It must not access SMS content or run the Core models.
- **ExecuTorch runtime** executes the required Llama-family model locally on the selected ARM target.

The separation is a permission and data-flow boundary, not only a package layout. Network failure must not disable local SMS detection.

## Current implementation status

Implemented: SMS and URL baselines, multilingual routing, Hindi/Hinglish indicators, evidence output, model-feature explanations, campaign-safe training, calibration, public Playwright collection, source metadata, deterministic explanation verification/fallback, signed offline bundle checks, evidence linking and unit tests.

Pending for the final device demonstration: ExecuTorch model export and measured Llama inference, Android/Core integration, target-device RAM and thermal measurements, time-ordered or independently collected evaluation, and authorised offline lab validation.

## Implementation checklist

| Area | Status | Evidence |
|---|---|---|
| SMS/URL detection and structured evidence | Done | `guardian_models/detectors.py`, unit tests |
| Multilingual routing and seed evaluation | Done, development quality only | `data/sms_multilingual.jsonl`, `evaluation/report.json` |
| Indian hard negatives | Done as seed fixture | `data/indian_hard_negatives.jsonl` |
| Runtime safety and Core precedence | Done | `guardian_models/runtime.py` |
| Explanation verification and fallback | Done | `guardian_models/safety.py` |
| Offline bundle validation | Working-stage prototype | `guardian_models/bundles.py`; HMAC prototype, Ed25519 pending |
| SMS/URL evidence linking | Done as primitive | `guardian_models/evidence_graph.py` |
| ARM benchmark harness | Ready to run on target | `evaluation/run_device_benchmark.py` |
| ExecuTorch metadata collector | Ready; target export unavailable | `evaluation/collect_executorch_metadata.py` |
| Authorised offline-lab evidence | Pending | `evaluation/offline_smoke_evidence.json` is host-only evidence |
| Android Core/Net application integration | Pending | Requires Android target implementation |
