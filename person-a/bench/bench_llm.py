"""Llama explanation timing via the ExecuTorch llama_main command (wall time and peak memory of the child)."""
import argparse, json, resource, statistics, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "person-c")); sys.path.insert(0, str(ROOT / "person-a"))
from guardian_models.runtime import SMSRuntime  # noqa: E402
from guardian_app.advisor import LlamaRunner, build_prompt, verify  # noqa: E402
from bench.manifest import manifest, cpu_temp_c  # noqa: E402

p = argparse.ArgumentParser(); p.add_argument("--artifact", required=True); p.add_argument("--llama-cmd")
p.add_argument("--runs", type=int, default=10); p.add_argument("--sustained-seconds", type=int, default=0); p.add_argument("--out")
a = p.parse_args()
rt = SMSRuntime.from_artifact(a.artifact); runner = LlamaRunner(a.llama_cmd)
ev = rt.analyze("Dear customer your SBI account will be blocked today. Update KYC immediately at http://sbi-kyc-update.top/login")
prompt, times, ok = build_prompt(ev), [], 0
runner.generate(prompt)  # warm-up (page cache)
for _ in range(a.runs):
    text, secs = runner.generate(prompt); times.append(secs); ok += verify(text, ev)[0]
stats = runner.last_stats
res = {"runner_stats_last_run": stats or "runner printed no PyTorchObserver stats: copy TTFT/tokens-per-second from llama_main output", "runs": a.runs, "median_s": round(statistics.median(times), 2), "p95_s": round(sorted(times)[max(0, int(0.95 * len(times)) - 1)], 2),
       "verifier_pass": f"{ok}/{a.runs}", "sample_output": text[:300],
       "peak_rss_mb_children": round(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / 1024, 1)}
if a.sustained_seconds:
    end, trace = time.time() + a.sustained_seconds, []
    while time.time() < end:
        _, secs = runner.generate(prompt); trace.append({"t": round(time.time() - (end - a.sustained_seconds)), "s": round(secs, 2), "temp_c": cpu_temp_c()})
    res["sustained"] = trace
res["manifest"] = manifest({"test": "llama explanation", "cmd": " ".join(runner.argv)[:200]})
print(json.dumps(res, indent=2))
if a.out: Path(a.out).write_text(json.dumps(res, indent=2))
