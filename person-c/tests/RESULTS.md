# Baseline Test Results

Command:

```text
python -m unittest discover -s tests -v
```

Result: 9 tests passed in 0.016 seconds.

Coverage includes text and URL normalization, shared evidence output, SMS risk scoring, look-alike URL detection, campaign-safe splitting, model serialization, metrics, and the boundary that keeps Llama out of detector verdicts.

The example training fixture is a smoke test only. Its `travel-2` holdout contains no scam examples, so recall and PR-AUC are not meaningful for that split. Real reporting must use licensed, campaign-separated data with both classes represented in the held-out set.
