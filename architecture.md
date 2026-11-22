# Guardian Architecture — Arm Linux

Guardian is an offline-first software security demonstrator on Arm Linux. It
has two separate pipelines and a shared, provenance-tracked dataset/evidence
layer. Raw external datasets are used offline for training or validation and
are never required for runtime inference.

## SMS pipeline
SMS input → deterministic SMS detector and compact classifier → URL analysis and structured evidence → optional local ExecuTorch Llama explanation → verifier → exact approved playbook actions → JSON report. The SMS verdict is authoritative and cannot be changed by the LLM. Playbook actions are rendered verbatim and are not generated or paraphrased by the model.

## Network pipeline
PCAP replay or authorized live capture → Person B packet/flow processing and anomaly detectors → optional signed local threat-bundle lookup and opt-in DNS reference model → structured alert evidence → optional local Llama explanation → verifier → JSON report. Live capture requires appropriate privileges; PCAP replay is the reproducible demo mode. Existing deterministic rules remain the default safety layer.

## Dataset and intelligence layer
Public SMS plus multilingual English/Hindi/Hinglish data → campaign-aware SMS training → SMS/URL inference. Indian hard negatives remain evaluation-only. UNSW-NB15 and CICIDS2017 provide external flow-level validation; CIC-Bell DNS EXF 2021 provides the opt-in DNS reference model; OpenPhish provides a frozen signed offline domain bundle. PhishTank uses the same bundle format when an application-key snapshot is available. ISCX-URL2016 remains benchmark-only because the available mirror has no raw URL column.

## Boundaries
- Detector verdicts are independent of LLM output.
- LLM output is advisory explanation only.
- Exact safety actions are deterministic playbook content.
- Offline execution is supported when model/runtime assets are locally installed.
- Threat feeds and benchmark artifacts are never fetched during inference; bundle loading is explicit and signature-verified.
- Public benchmark metrics are reported separately from live runtime behavior and ARM-device measurements.
- Tests/PCAP results do not establish universal live accuracy or physical-device validation.
