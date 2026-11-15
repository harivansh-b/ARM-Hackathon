"""Detector latency over a message file (median and p95), with a manifest."""
import argparse, json, statistics, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "person-c")); sys.path.insert(0, str(ROOT / "person-a"))
from guardian_models.runtime import SMSRuntime  # noqa: E402
from guardian_app.importers import load_messages  # noqa: E402
from bench.manifest import manifest  # noqa: E402

p = argparse.ArgumentParser(); p.add_argument("--input", required=True); p.add_argument("--artifact", required=True)
p.add_argument("--repeat", type=int, default=20); p.add_argument("--out")
a = p.parse_args()
rt = SMSRuntime.from_artifact(a.artifact); msgs = load_messages(a.input)
ms = [rt.analyze(m["text"])["latency_ms"] for _ in range(a.repeat) for m in msgs]
ms.sort()
res = {"n": len(ms), "median_ms": round(statistics.median(ms), 3), "p95_ms": round(ms[int(0.95 * len(ms)) - 1], 3), "max_ms": ms[-1]}
res["manifest"] = manifest({"test": "detector latency", "input": a.input})
print(json.dumps(res, indent=2))
if a.out: Path(a.out).write_text(json.dumps(res, indent=2))
