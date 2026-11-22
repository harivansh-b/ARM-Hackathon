# Guardian Architecture — Arm Linux

Guardian is an offline-first software security demonstrator on Arm Linux. It has two separate pipelines.

## SMS pipeline
SMS input → deterministic SMS detector and compact classifier → URL analysis and structured evidence → optional local ExecuTorch Llama explanation → verifier → exact approved playbook actions → JSON report. The SMS verdict is authoritative and cannot be changed by the LLM. Playbook actions are rendered verbatim and are not generated or paraphrased by the model.

## Network pipeline
PCAP replay or authorized live capture → Person B packet/flow processing and anomaly detectors → structured alert evidence → optional local Llama explanation → verifier → JSON report. Live capture requires appropriate privileges; PCAP replay is the reproducible demo mode.

## Boundaries
- Detector verdicts are independent of LLM output.
- LLM output is advisory explanation only.
- Exact safety actions are deterministic playbook content.
- Offline execution is supported when model/runtime assets are locally installed.
- Tests/PCAP results do not establish universal live accuracy or physical-device validation.
