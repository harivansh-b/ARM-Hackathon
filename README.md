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

Dataset roles, provenance requirements, evaluation gates and planned network/URL
benchmark adapters are tracked in [the dataset integration plan](docs/DATASET_INTEGRATION_PLAN.md)
and [the dataset registry](docs/dataset_registry.json). The SMS pipeline trains
from the public SMS/phishing corpus plus the reviewed multilingual starter set
when the local model artifact is first created. Indian hard negatives remain
evaluation-only.
