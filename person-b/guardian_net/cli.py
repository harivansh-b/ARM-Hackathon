"""Command-line interface for Guardian Network Sensor.

Subcommands:
- sentinel: Run DNS sentinel forwarder with real-time detection logging
- sniff: Live AF_PACKET sniffer capturing flows and detecting anomalies
- replay: Offline replay of PCAP file through flow table and all detectors
- scenarios: Run automated verification against standard attack and benign test PCAPs
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from guardian_net.aggregate import EvidenceAggregator
from guardian_net.detectors.beacon import BeaconDetector
from guardian_net.detectors.denylist import DenylistDetector
from guardian_net.detectors.dga import DGADetector
from guardian_net.detectors.dns_tunnel import DNSTunnelDetector
from guardian_net.detectors.exfil import ExfiltrationDetector
from guardian_net.detectors.scan import OutboundScanDetector
from guardian_net.dns_sentinel import DNSSentinel
from guardian_net.dnswire import DNSMessage, TYPE_A
from guardian_net.evidence import append_evidence_jsonl
from guardian_net.flows import FlowTable
from guardian_net.pcapio import LiveSniffer, ParsedPacket, PcapReader

DEFAULT_REPORT = ROOT / "reports" / "net_evidence.jsonl"


def run_sentinel_cmd(args: argparse.Namespace) -> None:
    tunnel_det = DNSTunnelDetector(model_path=args.dns_model)
    dga_det = DGADetector()
    deny_det = DenylistDetector()

    def inspector(query: DNSMessage, resp: DNSMessage | None, latency_ms: float) -> dict | None:
        if not query or not query.questions:
            return None
        qname = query.first_question_name
        qtype = query.questions[0].qtype

        # 1. Check denylist
        ev_deny = deny_det.check_domain(qname)
        if ev_deny:
            return ev_deny

        # 2. Check DNS tunnel
        ev_tunnel = tunnel_det.analyze_query(qname, qtype)
        if ev_tunnel:
            return ev_tunnel

        # 3. Check DGA
        rcode = resp.rcode if resp else None
        ev_dga = dga_det.analyze_domain(qname, rcode=rcode)
        if ev_dga:
            return ev_dga

        return None

    sentinel = DNSSentinel(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        upstream_host=args.upstream_host,
        upstream_port=args.upstream_port,
        evidence_file=args.evidence_file,
        inspector=inspector,
    )
    sentinel.start()
    print(f"[✓] DNS Sentinel running on {args.listen_host}:{args.listen_port} -> upstream {args.upstream_host}:{args.upstream_port}")
    print(f"[*] Logging evidence to {args.evidence_file} (Press Ctrl+C to stop)")

    def sig_handler(sig, frame):
        print("\n[*] Stopping DNS Sentinel...")
        sentinel.stop()
        summary = sentinel.metrics.summary()
        print(f"[*] Summary: {summary['total']} queries, {summary['success_rate_pct']}% success, median {summary['median_ms']} ms")
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    while True:
        time.sleep(1.0)


def replay_pcap(
    pcap_path: str | Path,
    evidence_file: str | Path | None = None,
    silent: bool = False,
    dns_model_path: str | Path | None = None,
) -> list[dict]:
    """Replay a PCAP file through the complete flow and detection pipeline."""
    reader = PcapReader(pcap_path)
    flow_table = FlowTable()
    tunnel_det = DNSTunnelDetector(model_path=dns_model_path)
    dga_det = DGADetector()
    beacon_det = BeaconDetector(min_events=5)
    scan_det = OutboundScanDetector()
    exfil_det = ExfiltrationDetector()
    deny_det = DenylistDetector()
    aggregator = EvidenceAggregator()

    emitted_alerts: list[dict] = []

    for pkt in reader.parsed_packets():
        # 1. DNS detection
        if pkt.proto == "UDP" and (pkt.dst_port == 53 or pkt.src_port == 53):
            try:
                dns_msg = DNSMessage.parse(pkt.payload)
                if dns_msg.questions:
                    qname = dns_msg.first_question_name
                    qtype = dns_msg.questions[0].qtype

                    # Tunnel check
                    t_ev = tunnel_det.analyze_query(qname, qtype, timestamp=int(pkt.timestamp))
                    if t_ev:
                        alert = aggregator.ingest(t_ev)
                        if alert:
                            emitted_alerts.append(alert)

                    # DGA check
                    d_ev = dga_det.analyze_domain(qname, rcode=dns_msg.rcode if dns_msg.is_response else None, timestamp=int(pkt.timestamp))
                    if d_ev:
                        alert = aggregator.ingest(d_ev)
                        if alert:
                            emitted_alerts.append(alert)
            except Exception:
                pass

        # 2. Port scan detection
        s_ev = scan_det.process_packet(pkt)
        if s_ev:
            alert = aggregator.ingest(s_ev)
            if alert:
                emitted_alerts.append(alert)

        # 3. Flow table & TCP/TLS inspection
        flow = flow_table.add_packet(pkt)
        if flow and pkt.proto == "TCP":
            # Beacon check on outbound connections
            if flow.dst_ip:
                b_ev = beacon_det.record_event(flow.dst_ip, timestamp=pkt.timestamp)
                if b_ev:
                    alert = aggregator.ingest(b_ev)
                    if alert:
                        emitted_alerts.append(alert)

            # Exfiltration check when flow completes or exceeds threshold
            if flow.state == "CLOSED" or flow.bytes_orig >= 20_000:
                ex_ev = exfil_det.inspect_flow(flow)
                if ex_ev:
                    alert = aggregator.ingest(ex_ev)
                    if alert:
                        emitted_alerts.append(alert)

    # Final sweep of any unclosed flows
    for flow in flow_table.flows.values():
        ex_ev = exfil_det.inspect_flow(flow)
        if ex_ev:
            alert = aggregator.ingest(ex_ev)
            if alert:
                emitted_alerts.append(alert)

    reader.close()

    if evidence_file:
        for alert in emitted_alerts:
            append_evidence_jsonl(alert, evidence_file)

    if not silent:
        print(f"\n=== PCAP Replay Results: {Path(pcap_path).name} ===")
        print(f"Total packets processed, alerts triggered: {len(emitted_alerts)}")
        for a in emitted_alerts:
            print(f"[{a['risk_tier']:8s}] Score {a['score']:.2f} | {a['event_type']} | {a['entity']['value']}")
            for r in a['reasons']:
                print(f"   ↳ {r}")

    return emitted_alerts


def run_scenarios_cmd(args: argparse.Namespace) -> None:
    from lab.make_pcap import generate_all_scenario_pcaps

    scenario_dir = ROOT / "eval" / "scenarios"
    generate_all_scenario_pcaps(scenario_dir)

    scenarios = [
        ("smishing_c2_chain", "BEACON", True),
        ("dns_tunnel", "DNS_TUNNEL", True),
        ("port_scan", "PORT_SCAN", True),
        ("exfil_spike", "EXFILTRATION", True),
        ("benign_linux", "ANY", False),  # Must NOT alert!
    ]

    print("\n=================================================================")
    print("      GUARDIAN NETWORK SENSOR: SCENARIO VERIFICATION SUITE       ")
    print("=================================================================")
    print(f"{'Scenario':<22} | {'Expected Event':<16} | {'Alerts':<6} | {'Result':<8}")
    print("-" * 65)

    all_passed = True
    for name, expected_event, should_alert in scenarios:
        pcap_file = scenario_dir / f"{name}.pcap"
        alerts = replay_pcap(pcap_file, silent=True)

        passed = False
        if should_alert:
            matched = any(expected_event in a["event_type"] for a in alerts)
            passed = matched and len(alerts) >= 1
        else:
            # Benign scenario: must produce zero alerts
            passed = len(alerts) == 0

        status = "PASS" if passed else "FAIL"
        if not passed:
            all_passed = False
        print(f"{name:<22} | {expected_event:<16} | {len(alerts):<6} | {status:<8}")

    print("-" * 65)
    if all_passed:
        print("[✓] ALL SCENARIOS PASSED. Zero false alerts on benign Linux background traffic.")
    else:
        print("[✗] ONE OR MORE SCENARIOS FAILED.")
        sys.exit(1)



def run_sniff_cmd(args: argparse.Namespace) -> None:
    """Capture live packets and feed the existing stateful detection pipeline."""
    flow_table = FlowTable()
    tunnel_det = DNSTunnelDetector(model_path=args.dns_model)
    dga_det = DGADetector()
    beacon_det = BeaconDetector(min_events=5)
    scan_det = OutboundScanDetector()
    exfil_det = ExfiltrationDetector()
    deny_det = DenylistDetector()
    aggregator = EvidenceAggregator()
    emitted = 0
    packet_count = 0

    def ingest(ev: dict | None) -> None:
        nonlocal emitted
        if not ev:
            return
        alert = aggregator.ingest(ev)
        if alert:
            append_evidence_jsonl(alert, args.evidence_file)
            emitted += 1
            if not args.quiet:
                entity = alert.get("entity", {}).get("value", "?")
                print(f"[{alert.get('risk_tier', '?'):8s}] {alert.get('event_type', '?')} | {entity}", flush=True)

    def on_packet(pkt: ParsedPacket) -> None:
        nonlocal packet_count
        packet_count += 1
        # DNS: only inspect queries (not responses) to avoid treating answer payloads as queries.
        if pkt.proto == "UDP" and pkt.dst_port == 53:
            try:
                msg = DNSMessage.parse(pkt.payload)
                if msg.questions:
                    qname, qtype = msg.first_question_name, msg.questions[0].qtype
                    ingest(deny_det.check_domain(qname))
                    ingest(tunnel_det.analyze_query(qname, qtype, timestamp=int(pkt.timestamp)))
                    ingest(dga_det.analyze_domain(qname, timestamp=int(pkt.timestamp)))
            except Exception:
                pass
        ingest(scan_det.process_packet(pkt))
        flow = flow_table.add_packet(pkt)
        if flow and pkt.proto == "TCP":
            if flow.dst_ip:
                ingest(beacon_det.record_event(flow.dst_ip, timestamp=pkt.timestamp))
            if flow.state == "CLOSED" or flow.bytes_orig >= 20_000:
                ingest(exfil_det.inspect_flow(flow))

    sniffer = LiveSniffer(interface=args.interface, packet_callback=on_packet)
    Path(args.evidence_file).parent.mkdir(parents=True, exist_ok=True)
    print(f"[*] Guardian live capture on {args.interface}; evidence -> {args.evidence_file} (Ctrl+C to stop)", flush=True)
    sniffer.start()
    try:
        while sniffer.running:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.stop()
    for flow in flow_table.flows.values():
        ingest(exfil_det.inspect_flow(flow))
    print(f"[*] Stopped. Packets observed: {packet_count}; alerts written: {emitted}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Guardian Network Sensor CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # sentinel
    p_sent = subparsers.add_parser("sentinel", help="Run DNS Sentinel")
    p_sent.add_argument("--listen-host", default="127.0.0.1")
    p_sent.add_argument("--listen-port", type=int, default=5353)
    p_sent.add_argument("--upstream-host", default="10.77.0.2")
    p_sent.add_argument("--upstream-port", type=int, default=53)
    p_sent.add_argument("--evidence-file", default=DEFAULT_REPORT)
    p_sent.add_argument("--dns-model", type=Path, help="Optional offline DNS model artifact")

    # live sniff
    p_sniff = subparsers.add_parser("sniff", help="Capture live packets and run detectors")
    p_sniff.add_argument("--interface", default="enp0s1", help="Capture interface (default: enp0s1)")
    p_sniff.add_argument("--evidence-file", type=Path, default=DEFAULT_REPORT)
    p_sniff.add_argument("--quiet", action="store_true", help="Suppress alert lines")
    p_sniff.add_argument("--dns-model", type=Path, help="Optional offline DNS model artifact")

    # replay
    p_rep = subparsers.add_parser("replay", help="Replay PCAP file")
    p_rep.add_argument("--pcap", required=True, type=Path, help="Path to pcap file")
    p_rep.add_argument("--evidence-file", default=DEFAULT_REPORT)
    p_rep.add_argument("--dns-model", type=Path, help="Optional offline DNS model artifact")

    # scenarios
    p_scen = subparsers.add_parser("scenarios", help="Run scenario test suite")

    args = parser.parse_args()

    if args.command == "sentinel":
        run_sentinel_cmd(args)
    elif args.command == "sniff":
        run_sniff_cmd(args)
    elif args.command == "replay":
        replay_pcap(args.pcap, args.evidence_file, dns_model_path=args.dns_model)
    elif args.command == "scenarios":
        run_scenarios_cmd(args)


if __name__ == "__main__":
    main()
