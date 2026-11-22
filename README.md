# Guardian — offline Arm Linux security assistant

Guardian is an offline-first security assistant for Arm Linux. It runs two independent workflows: SMS/smishing analysis and network anomaly analysis. Deterministic detectors own security verdicts; the local Llama/ExecuTorch advisor explains evidence only. Approved playbook actions are displayed verbatim outside LLM output.

## Run

- SMS: `guardian_sms_pipeline.sh` (see script configuration/help)
- Network: `guardian_network_pipeline.sh` (PCAP replay by default; live capture requires privileges)
- Person C tests: `python3 -m unittest discover -s person-c/tests -v`
- Person A tests: `python3 -m unittest discover -s person-a/tests -v`
- Person B tests: `python3 -m unittest discover -s person-b/tests -v`

Guardian is a Linux software demonstrator, not an Android Core/Net architecture. Model artifacts and reports are local; inspect data-source licences before redistribution. Results from PCAP fixtures and synthetic tests are not live-network accuracy claims.

## Dataset integration

Dataset roles, provenance requirements, evaluation gates and current network/URL
benchmark adapters are tracked in [the dataset integration plan](docs/DATASET_INTEGRATION_PLAN.md)
and [the dataset registry](docs/dataset_registry.json). The SMS pipeline trains
from the public SMS/phishing corpus plus the reviewed multilingual starter set
when the local model artifact is first created. Indian hard negatives remain
evaluation-only.

Current branch results include: SMS hard-scam recall improved from 60.0% to
86.7% with multilingual augmentation; UNSW-NB15 reached 84.68% attack recall
on its held-out partition; CICIDS2017 reference benchmarks reached 99.92% DDoS
recall and 99.90% PortScan recall; and a signed OpenPhish bundle matched
300/300 feed URLs with 0/20 curated benign matches. These are benchmark or
lookup-integrity results, not universal live-network accuracy claims.

The DNS reference model and threat bundle are opt-in. Use `--dns-model` and
`--threat-bundle` with the network CLI; existing deterministic rules remain the
default safety layer. Raw external datasets remain gitignored.
