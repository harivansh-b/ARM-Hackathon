"""Benign false-positive evaluator and scenario verification report generator."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from guardian_net.aggregate import EvidenceAggregator
from guardian_net.cli import replay_pcap
from guardian_net.detectors.beacon import BeaconDetector
from guardian_net.detectors.dns_tunnel import DNSTunnelDetector
from guardian_net.evidence import create_evidence
from lab.make_pcap import generate_all_scenario_pcaps


def evaluate_extended_benign_trace(hours_simulated: float = 24.0) -> dict:
    """Simulate 24 hours of standard Linux background timers (NTP, apt-daily, systemd)."""
    aggregator = EvidenceAggregator()
    beacon_det = BeaconDetector()
    tunnel_det = DNSTunnelDetector()

    # NTP every 1024s (~17 min)
    ntp_interval = 1024.0
    ntp_events = int((hours_simulated * 3600) / ntp_interval)

    # apt-daily every 12 hours
    apt_events = int(hours_simulated / 12)

    alerts_triggered = []

    # Simulate NTP
    for i in range(ntp_events):
        t = 10000.0 + (i * ntp_interval)
        ev_dns = create_evidence("DNS", "DNS_QUERY", "DOMAIN", "ntp.ubuntu.com", score=0.0, reasons=["NTP sync"], timestamp=int(t))
        a1 = aggregator.ingest(ev_dns)
        if a1:
            alerts_triggered.append(a1)

        b_ev = beacon_det.record_event("ntp.ubuntu.com", timestamp=t, entity_type="DOMAIN")
        if b_ev:
            a2 = aggregator.ingest(b_ev)
            if a2:
                alerts_triggered.append(a2)

    # Simulate apt-daily
    for i in range(apt_events):
        t = 10000.0 + (i * 43200)
        ev_apt = create_evidence("DNS", "DNS_QUERY", "DOMAIN", "archive.ubuntu.com", score=0.0, reasons=["apt-daily update"], timestamp=int(t))
        a3 = aggregator.ingest(ev_apt)
        if a3:
            alerts_triggered.append(a3)

    false_alerts_count = len(alerts_triggered)
    rate_per_hour = false_alerts_count / hours_simulated

    return {
        "hours_simulated": hours_simulated,
        "ntp_cycles": ntp_events,
        "apt_cycles": apt_events,
        "total_suppressed_benign": aggregator.total_suppressed_benign,
        "false_alerts_count": false_alerts_count,
        "false_alerts_per_hour": round(rate_per_hour, 4),
    }


def evaluate_scenarios() -> dict:
    scenario_dir = ROOT / "eval" / "scenarios"
    generate_all_scenario_pcaps(scenario_dir)

    test_matrix = [
        {"name": "smishing_c2_chain", "expected": "BEACON", "should_alert": True},
        {"name": "dns_tunnel", "expected": "DNS_TUNNEL", "should_alert": True},
        {"name": "port_scan", "expected": "PORT_SCAN", "should_alert": True},
        {"name": "exfil_spike", "expected": "EXFILTRATION", "should_alert": True},
        {"name": "benign_linux", "expected": "NONE", "should_alert": False},
    ]

    results = []
    for item in test_matrix:
        pcap_path = scenario_dir / f"{item['name']}.pcap"
        alerts = replay_pcap(pcap_path, silent=True)
        if item["should_alert"]:
            passed = any(item["expected"] in a["event_type"] for a in alerts) and len(alerts) >= 1
        else:
            passed = len(alerts) == 0

        results.append({
            "scenario": item["name"],
            "expected_event": item["expected"],
            "alerts_count": len(alerts),
            "passed": passed,
        })
    return {"matrix": results, "all_passed": all(r["passed"] for r in results)}


def main() -> None:
    print("[*] Evaluating Benign Background Noise & False Alarm Rate...")
    benign_stats = evaluate_extended_benign_trace(hours_simulated=24.0)
    print(f"[✓] Simulated {benign_stats['hours_simulated']} hours of background Linux activity")
    print(f"    - Suppressed benign events: {benign_stats['total_suppressed_benign']}")
    print(f"    - False alerts triggered: {benign_stats['false_alerts_count']}")
    print(f"    - False alerts per hour: {benign_stats['false_alerts_per_hour']} / hour")

    print("\n[*] Evaluating Attack and Replay Scenarios...")
    scenario_stats = evaluate_scenarios()
    for s in scenario_stats["matrix"]:
        status = "PASS" if s["passed"] else "FAIL"
        print(f"    - {s['scenario']:<20}: {status} ({s['alerts_count']} alerts, expected {s['expected_event']})")

    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "environment": "ARM64 Linux VM under QEMU",
        "benign_trace": benign_stats,
        "scenarios": scenario_stats,
    }

    report_path = ROOT / "eval" / "eval_report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\n[✓] Evaluation report written to {report_path}")


if __name__ == "__main__":
    main()
