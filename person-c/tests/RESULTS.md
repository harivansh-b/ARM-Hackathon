# Baseline Test Results

Command:

```text
python -m unittest discover -s tests -v
```

Result: 11 tests passed in 0.008 seconds.

Coverage includes text and URL normalization, shared evidence output, SMS risk scoring, look-alike URL detection, campaign-safe splitting, model serialization, metrics, and the boundary that keeps Llama out of detector verdicts.

The example training fixture is a smoke test only. Its `travel-2` holdout contains no scam examples, so recall and PR-AUC are not meaningful for that split. Real reporting must use licensed, campaign-separated data with both classes represented in the held-out set.

## Public corpus smoke benchmark

The Playwright scraper collected 34,100 redacted records: 29,273 positive phishing/spam records and 4,827 ham records. A deterministic 12,000-record subset produced a 9,612/2,388 campaign-group split:

`precision=0.9990`, `recall=0.9931`, `F1=0.9960`, `FPR=0.0056`, `PR-AUC=0.9998`.

These numbers are not production claims. The public corpus is source-imbalanced, the phishing source is positive-only, and the legacy corpus has template-derived rather than true campaign IDs. A proper report still needs a time-ordered or independently collected evaluation set and hard-negative analysis.

## Calibrated runtime smoke benchmark

The calibrated pipeline uses a separate campaign-group calibration split and selects an operating threshold with target false-positive rate ≤ 0.1% and recall floor ≥ 80%. On the same 12,000-record smoke subset, the resulting held-out report was `precision=1.0000`, `recall=0.9750`, `F1=0.9873`, `FPR=0.0000`, `PR-AUC=0.9997`.

Runtime output is intentionally tri-state: `ALERT`, `REVIEW`, or `BENIGN_CANDIDATE`. It never claims that a message is safe, bounds input to 4,096 characters, records latency, and falls back to the rule detector if the trained artifact is unavailable.
