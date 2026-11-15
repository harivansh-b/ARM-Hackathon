"""Scan a file of SMS offline: detector first, Llama only for flagged messages."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "person-c"))

from guardian_models.detectors import analyze_url  # noqa: E402
from guardian_models.evidence_graph import correlate  # noqa: E402
from guardian_models.runtime import SMSRuntime  # noqa: E402
from guardian_models.safety import approved_actions  # noqa: E402

from .advisor import LlamaRunner, explain  # noqa: E402
from .importers import load_messages  # noqa: E402


def scan(messages: list[dict], runtime: SMSRuntime, runner: LlamaRunner | None, max_llm: int = 20) -> list[dict]:
    results, llm_used = [], 0
    for message in messages:
        evidence = runtime.analyze(message["text"], sender=message.get("sender"))
        flagged = evidence["decision_state"] in ("ALERT", "REVIEW")
        use_llm = runner if (flagged and llm_used < max_llm) else None
        if use_llm:
            llm_used += 1
        advice = explain(evidence, use_llm) if flagged else {"text": "No strong scam signal found. This is not a guarantee of safety.", "source": "template", "verifier": "n/a"}
        story = []
        if flagged and evidence["extracted_urls"]:
            url_ev = [analyze_url(u) for u in evidence["extracted_urls"][:3]]
            links = correlate([evidence] + url_ev)
            story = [{"from": l.source_id, "to": l.target_id, "relation": l.relation} for l in links] + \
                    [{"url_evidence": u["entity"]["value"], "tier": u["risk_tier"], "reasons": u["reasons"]} for u in url_ev]
        results.append({"actions": approved_actions(evidence) if flagged else [], "story": story, "id": message["id"], "sender": message.get("sender"), "state": evidence["decision_state"],
                        "risk_tier": evidence["risk_tier"], "score": evidence["score"], "signals": [s["signal"] for s in evidence["matched_signals"]],
                        "urls": evidence["extracted_urls"], "detect_ms": evidence["latency_ms"], "advice": advice})
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Guardian offline SMS scan")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--llama-cmd", help="ExecuTorch command template containing {prompt}; or set GUARDIAN_LLAMA_CMD")
    parser.add_argument("--no-llm", action="store_true")
    parser.add_argument("--max-llm", type=int, default=20)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    runtime = SMSRuntime.from_artifact(args.artifact)
    runner = None if args.no_llm else LlamaRunner(args.llama_cmd)
    results = scan(load_messages(args.input), runtime, runner, args.max_llm)
    for r in results:
        print(f"[{r['state']:16s}] {r['score']:.3f}  {r['sender'] or '-'}  ({r['advice']['source']}) {r['advice']['text'][:140]}")
    if args.out:
        args.out.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    main()
