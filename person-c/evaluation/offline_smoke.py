"""Evidence-producing host smoke test with all socket connections denied."""

from __future__ import annotations

import argparse
import json
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from guardian_models.runtime import SMSRuntime
from guardian_models.detectors import analyze_sms


def blocked(*_args, **_kwargs):
    raise AssertionError("network access attempted during offline smoke test")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--output", type=Path, default=Path("evaluation/offline_smoke_evidence.json"))
    args = parser.parse_args()
    original_connect = socket.socket.connect
    original_create = socket.create_connection
    socket.socket.connect = blocked
    socket.create_connection = blocked
    try:
        runtime = SMSRuntime.from_artifact(args.artifact)
        high_text = "URGENT: your bank account is suspended. Verify your OTP now at https://bad.test"
        high = runtime.analyze(high_text)
        core = analyze_sms(high_text)
        benign = runtime.analyze("Your parcel has been delivered. Thank you.")
        evidence = {
            "status": "HOST_OFFLINE_SMOKE_PASSED",
            "network_policy": "socket connect and create_connection denied",
            "detection": {"core_risk_tier": core["risk_tier"], "core_reasons": core["reasons"], "runtime_decision": high["decision_state"]},
            "guidance": {"high_risk_guidance": high["safe_action"], "benign_candidate_decision": benign["decision_state"], "benign_guidance": benign["safe_action"]},
            "authorisation": "NOT_APPLICABLE_HOST_SMOKE; authorised lab sign-off still required",
        }
    finally:
        socket.socket.connect = original_connect
        socket.create_connection = original_create
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
