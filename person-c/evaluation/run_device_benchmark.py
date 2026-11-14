"""Collect ARM/Linux runtime measurements for the final evidence table.

Run this script on the target ARM device. It does not claim ARM results when
run elsewhere; the output records the machine architecture and platform.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from guardian_models.runtime import SMSRuntime


def temperature_c() -> float | None:
    values = []
    for path in Path("/sys/class/thermal").glob("thermal_zone*/temp"):
        try:
            value = float(path.read_text().strip())
            values.append(value / 1000 if value > 200 else value)
        except (OSError, ValueError):
            continue
    return max(values) if values else None


def rss_mb() -> float | None:
    try:
        import resource
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return value / (1024 * 1024) if platform.system() == "Linux" else value / 1024
    except (ImportError, OSError):
        return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--duration-min", type=float, default=30)
    parser.add_argument("--output", type=Path, default=Path("evaluation/device_run.json"))
    args = parser.parse_args()
    runtime = SMSRuntime.from_artifact(args.artifact)
    samples = [
        "Your OTP for login is 482913. Do not share this OTP with anyone.",
        "URGENT: your bank account is suspended. Verify now at https://bad.test",
        "Your parcel has been delivered. Thank you for using our delivery service.",
    ]
    latencies = []
    start_temp = temperature_c()
    deadline = time.monotonic() + args.duration_min * 60
    requests = 0
    while time.monotonic() < deadline:
        started = time.perf_counter()
        runtime.analyze(samples[requests % len(samples)])
        latencies.append((time.perf_counter() - started) * 1000)
        requests += 1
    result = {
        "status": "MEASURED",
        "architecture": platform.machine(),
        "platform": platform.platform(),
        "duration_min": args.duration_min,
        "requests": requests,
        "throughput_per_min": requests / args.duration_min if args.duration_min else None,
        "core_latency_p50_ms": statistics.median(latencies) if latencies else None,
        "core_latency_p95_ms": sorted(latencies)[max(0, int(len(latencies) * 0.95) - 1)] if latencies else None,
        "peak_rss_mb": rss_mb(),
        "temperature_start_c": start_temp,
        "temperature_end_c": temperature_c(),
        "note": "ExecuTorch first-token metrics require the advisory model runner and are collected separately.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
