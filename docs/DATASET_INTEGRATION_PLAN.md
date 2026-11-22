# Guardian Dataset Integration Plan

This plan keeps training data, benchmark data, threat-intelligence data, and
synthetic demo fixtures separate. A dataset is incorporated into the product
only after its provenance, label semantics, licence, leakage risk, and fit to
Guardian's on-device feature schema are recorded.

## Decision for this branch

The SMS training path is augmented with the checked-in multilingual starter
set in `person-c/data/sms_multilingual.jsonl`. The public SMS/phishing corpus
remains the main corpus. `person-c/data/indian_hard_negatives.jsonl` remains
evaluation-only so its results stay meaningful.

The network benchmark candidates are not silently mixed into the existing
rule-based detector. They now have dependency-free normalization/evaluation
entry points, while remaining reserved for an adapter-based evaluation stage:

1. CIC-Bell-DNS-EXF-2021 for DNS exfiltration and tunnelling thresholds.
2. ISCX-URL2016 for URL lexical/obfuscation scoring.
3. CICIDS2017 and UNSW-NB15 for external flow-level validation.

This prevents feature-schema mismatch and avoids presenting synthetic PCAP
scenario results as public-dataset accuracy.

## Dataset roles

| Dataset | Role | Current status | Why it matters |
|---|---|---|---|
| Public SMS/phishing corpus | SMS training | Incorporated | Existing English baseline and phishing coverage |
| Multilingual starter set | SMS training augmentation | Incorporated | Adds Hindi, Hinglish, Indian scam categories |
| Indian hard negatives | SMS evaluation | Evaluation-only | Measures false positives on legitimate Indian messages |
| UCI SMS Spam Collection derivative | SMS baseline provenance | Documented | Reproducible legacy comparison |
| ISCX-URL2016 | URL benchmark/training candidate | Planned | Labels benign, phishing, malware, spam and defacement URLs |
| CIC-Bell-DNS-EXF-2021 | DNS benchmark/training candidate | Planned | Matches entropy, label-length and windowed DNS features |
| CICIDS2017 | Network external validation | Planned | PCAP and labelled flows across common attacks |
| UNSW-NB15 | Cross-dataset validation | Planned | Independent flow schema and nine attack families |
| PhishTank/OpenPhish | Offline threat intelligence | Planned | Known-bad URL evidence, not balanced ML training data |

## Evaluation gates

Every candidate model must report:

- campaign- or time-held-out SMS results;
- English, Hindi and Hinglish results where available;
- false-positive rate on Indian hard negatives;
- performance by network attack family;
- CPU time, peak memory and model/artifact size on the target Arm runtime;
- source URL, collection date, record count, hash and licence notes.

No public benchmark score is a live-network accuracy claim. No threat feed is
used as a benign-vs-malicious training distribution without an independently
labelled benign set.

## Merge order

1. Review the comparison report produced by `tools/compare_sms_corpora.py`.
2. Keep the augmented SMS artifact only if hard-negative false positives do
   not worsen and held-out scam recall does not regress.
3. Add URL and network adapters as separate changes with their own fixtures
   and reports.
4. Add frozen threat-intelligence snapshots only with a manifest and expiry.

## Local adapter commands

URL benchmark evaluation:

```text
python person-c/tools/evaluate_url_benchmark.py \
    path/to/ISCX-URL2016.csv \
    --output integration-tests/iscx_url2016_guardian.json
```

Network benchmark normalization:

```text
python person-b/eval/prepare_network_benchmark.py \
    path/to/UNSW_NB15_training-set.csv \
    integration-tests/unsw_nb15.normalized.jsonl \
    --dataset unsw-nb15 \
    --manifest integration-tests/unsw_nb15.manifest.json
```

The commands never fetch data, open URLs, or copy raw benchmark files into the
repository. The downloaded files and their licence/provenance manifests stay
local to the evaluation environment.

## Current measured SMS result

The first candidate comparison is recorded in
`integration-tests/sms_corpus_comparison.json`. It used one training epoch as
a fast diagnostic; the split and evaluation procedure are the same for both
candidates.

| Candidate | Held-out F1 | Hard-set scam recall | Hard-set legitimate FPR |
|---|---:|---:|---:|
| Public corpus only | 0.9968 | 60.0% | 26.5% |
| Public + multilingual starter | 0.9966 | 86.7% | 26.5% |

The augmentation materially improved detection of the hard-set scam examples,
with essentially unchanged public-corpus performance. It did not improve the
legitimate-message false-positive rate, so the next data addition should be
more diverse legitimate Indian messages rather than more synthetic scam rows.
This is a diagnostic result, not a production accuracy claim; final reporting
should rerun the comparison with the deployment training configuration.

## Downloaded benchmark findings

Two local benchmark files have now been downloaded under the gitignored
`data/external/` directory. Their URLs, hashes and roles are recorded in
`integration-tests/external_dataset_manifest.json`.

| Benchmark | Current result | Decision |
|---|---|---|
| ISCX-URL2016 feature CSV | 36,707 records across five classes; the current URL runtime cannot consume it because it has no raw URL column. The dependency-free feature baseline achieved 0% recall at the selected <=5% false-positive operating point. | Do not wire into runtime yet; obtain raw URL strings or build a separately validated numeric URL model. |
| CIC-Bell-DNS-EXF-2021 | 100,000-row diagnostic sample: precision 77.7%, recall 1.25%, FPR 0.92% using current stateless thresholds. | Do not claim improvement yet; retune or train a DNS model using the benchmark's feature schema and evaluate by day/category. |

These failures are useful evidence: adding a public benchmark without adapting
the feature schema would make the submission less credible, not more.

