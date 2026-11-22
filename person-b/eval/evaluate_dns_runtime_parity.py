"""Compare default DNS rules with the opt-in benchmark model on local PCAPs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from guardian_net.cli import replay_pcap


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario-dir", type=Path, default=ROOT / "eval" / "scenarios")
    parser.add_argument("--dns-model", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    results = {}
    for pcap in sorted(args.scenario_dir.glob("*.pcap")):
        baseline = replay_pcap(pcap, silent=True)
        model = replay_pcap(pcap, silent=True, dns_model_path=args.dns_model)
        results[pcap.stem] = {
            "baseline_alerts": len(baseline),
            "model_alerts": len(model),
            "baseline_event_types": sorted({item["event_type"] for item in baseline}),
            "model_event_types": sorted({item["event_type"] for item in model}),
        }

    report = {
        "model": str(args.dns_model),
        "scenarios": results,
        "default_unchanged": all(item["baseline_alerts"] == item["model_alerts"] for item in results.values()),
        "note": "Parity gate only; this does not establish public-dataset live accuracy.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
