"""Record the conditions of a benchmark run (slide 10: device, OS, versions, quantisation, method)."""
import json, os, platform, subprocess, sys, time


def cpu_temp_c():
    base = "/sys/class/thermal"
    try:
        for zone in sorted(os.listdir(base)):
            if zone.startswith("thermal_zone"):
                return int(open(f"{base}/{zone}/temp").read()) / 1000
    except Exception:
        pass
    return None  # VMs usually expose no sensor


def manifest(extra: dict | None = None) -> dict:
    def sh(cmd):
        try:
            return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()
        except Exception:
            return ""
    data = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "machine": platform.machine(), "kernel": platform.release(),
            "os": sh("grep PRETTY_NAME /etc/os-release | cut -d= -f2"), "python": sys.version.split()[0],
            "cpus": os.cpu_count(), "mem_total_kb": sh("grep MemTotal /proc/meminfo | tr -s ' ' | cut -d' ' -f2"),
            "virtualised": sh("systemd-detect-virt") or "unknown", "cpu_temp_c": cpu_temp_c(),
            "executorch_commit": os.environ.get("EXECUTORCH_COMMIT", "SET ME"), "model": os.environ.get("MODEL_NAME", "SET ME"),
            "quantisation": os.environ.get("QUANT", "SET ME")}
    data.update(extra or {})
    return data
