"""Unit tests for network detectors: dns_tunnel, dga, beacon, scan, exfil, denylist."""
import base64
import hashlib
import hmac
import json
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PERSON_C_PATH = ROOT.parent / "person-c"
if str(PERSON_C_PATH) not in sys.path:
    sys.path.insert(0, str(PERSON_C_PATH))

from guardian_models.bundles import sign_bundle
from guardian_net.detectors.beacon import BeaconDetector
from guardian_net.detectors.dga import DGADetector
from guardian_net.detectors.dns_tunnel import DNSTunnelDetector, shannon_entropy
from guardian_net.detectors.denylist import DenylistDetector
from guardian_net.detectors.exfil import ExfiltrationDetector
from guardian_net.detectors.scan import OutboundScanDetector
from guardian_net.dnswire import RCODE_NXDOMAIN, TYPE_A, TYPE_TXT
from guardian_net.flows import FlowRecord
from guardian_net.pcapio import ParsedPacket, TCP_SYN


class TestDetectors(unittest.TestCase):
    def test_dns_tunnel_detector(self) -> None:
        det = DNSTunnelDetector(
            entropy_threshold=3.5,
            label_length_threshold=30,
            subdomain_cardinality_threshold=4,
        )

        # Benign short query
        res1 = det.analyze_query("www.google.com", TYPE_A)
        self.assertIsNone(res1)

        # High entropy base64 encoded data tunnel
        t1 = det.analyze_query("a9f8e7d6c5b4a392817203948576a1b2c3d4e5.tunnel.example.com", TYPE_TXT)
        self.assertIsNotNone(t1)
        self.assertEqual(t1["event_type"], "DNS_TUNNEL")
        self.assertEqual(t1["entity"]["value"], "example.com")
        self.assertIn("High subdomain Shannon entropy", t1["reasons"][0])
        # Privacy check: raw subdomain must NOT be stored in metadata
        self.assertNotIn("a9f8e7d6c5b4a392817203948576a1b2c3d4e5", str(t1))
        self.assertIn("subdomain_sample_hash", t1["metadata"])

    def test_dns_tunnel_detector_optional_model(self) -> None:
        artifact = {
            "format": "guardian.network.dns.logistic.v1",
            "feature_columns": ["entropy"],
            "means": [0.0],
            "scales": [1.0],
            "weights": [1.0],
            "bias": 0.0,
            "threshold": 0.5,
        }
        model_path = ROOT / "tests" / "_dns_model_test.json"
        model_path.write_text(json.dumps(artifact), encoding="utf-8")
        try:
            det = DNSTunnelDetector(model_path=model_path)
            event = det.analyze_query("z9x8c7v6b5n4m3.example.com", TYPE_A)
            self.assertIsNotNone(event)
            self.assertGreater(event["metadata"]["model_score"], 0.5)
            self.assertEqual(event["metadata"]["model_threshold"], 0.5)
            self.assertTrue(any("Runtime DNS model score" in reason for reason in event["reasons"]))
        finally:
            model_path.unlink(missing_ok=True)

    def test_dga_detector(self) -> None:
        det = DGADetector(entropy_threshold=3.2, consonant_ratio_threshold=0.8)

        # Benign natural domain
        res_benign = det.analyze_domain("microsoft.com")
        self.assertIsNone(res_benign)

        # DGA domain with high consonants & entropy
        dga_domain = "xzkqwpftrbvj.biz"
        res_dga = det.analyze_domain(dga_domain, rcode=RCODE_NXDOMAIN)
        self.assertIsNotNone(res_dga)
        self.assertEqual(res_dga["event_type"], "DGA")
        self.assertEqual(res_dga["entity"]["value"], "xzkqwpftrbvj.biz")
        self.assertTrue(any("consonant" in r.lower() for r in res_dga["reasons"]))

    def test_beacon_detector(self) -> None:
        det = BeaconDetector(min_events=5, cv_threshold=0.25)

        base_time = 1000.0
        # Periodic heartbeat every 10s with 5% jitter
        alerts = []
        for i in range(7):
            jitter = 0.5 if (i % 2 == 0) else -0.5
            t = base_time + (i * 10.0) + jitter
            ev = det.record_event("10.77.0.99", timestamp=t)
            if ev:
                alerts.append(ev)

        self.assertGreaterEqual(len(alerts), 1)
        last = alerts[-1]
        self.assertEqual(last["event_type"], "BEACON")
        self.assertEqual(last["entity"]["value"], "10.77.0.99")
        self.assertLess(last["metadata"]["coefficient_of_variation"], 0.20)

    def test_scan_detector(self) -> None:
        det = OutboundScanDetector(window_seconds=10.0, port_scan_threshold=5, host_scan_threshold=5)

        # Port scan against single target
        alert = None
        for port in range(1, 8):
            pkt = ParsedPacket(
                timestamp=100.0 + (port * 0.1),
                raw_packet=b"",
                src_ip="10.77.0.1",
                dst_ip="10.77.0.2",
                proto="TCP",
                src_port=50000 + port,
                dst_port=port,
                tcp_flags=TCP_SYN,
            )
            ev = det.process_packet(pkt)
            if ev:
                alert = ev

        self.assertIsNotNone(alert)
        self.assertEqual(alert["event_type"], "PORT_SCAN")
        self.assertEqual(alert["entity"]["value"], "10.77.0.2")

    def test_exfil_detector(self) -> None:
        det = ExfiltrationDetector(min_baseline_samples=5, mad_zscore_threshold=3.0, min_volume_bytes=1000)

        # Build baseline of 6 small transfers ~5000 bytes
        for i in range(6):
            flow = FlowRecord(
                flow_id=f"f{i}",
                proto="TCP",
                src_ip="10.77.0.1",
                src_port=40000 + i,
                dst_ip="198.51.100.4",
                dst_port=443,
                start_time=100.0 + i,
                last_time=105.0 + i,
                bytes_orig=5000 + (i * 100),
                bytes_resp=3000,
            )
            det.inspect_flow(flow)

        # Massive outbound spike: 2,000,000 bytes
        spike_flow = FlowRecord(
            flow_id="f_spike",
            proto="TCP",
            src_ip="10.77.0.1",
            src_port=45000,
            dst_ip="198.51.100.4",
            dst_port=443,
            start_time=200.0,
            last_time=210.0,
            bytes_orig=2_000_000,
            bytes_resp=1000,
        )
        ev = det.inspect_flow(spike_flow)
        self.assertIsNotNone(ev)
        self.assertEqual(ev["event_type"], "EXFILTRATION")
        self.assertEqual(ev["entity"]["value"], "198.51.100.4")
        self.assertGreaterEqual(ev["metadata"]["zscore"], 3.0)

    def test_denylist_detector_with_bundle(self) -> None:
        det = DenylistDetector()
        key = b"guardian-secret-signing-key-1234"
        payload = {
            "domains": ["malware-c2.example.test", "phishing-bank.test"],
            "ips": ["198.51.100.99"],
            "ja4s": ["t13d1516h2_8daaf6152771_e562703ab85f"],
        }
        bundle = sign_bundle(payload, key, version=2, expires="2099-12-31")

        # Load bundle
        loaded = det.load_bundle(bundle, key, minimum_version=1)
        self.assertTrue(loaded)

        # Test domain match
        match1 = det.check_domain("sub.malware-c2.example.test")
        self.assertIsNotNone(match1)
        self.assertEqual(match1["event_type"], "DENYLIST_MATCH")
        self.assertEqual(match1["risk_tier"], "CRITICAL")
        self.assertEqual(match1["score"], 0.99)

        # Test IP and JA4 match
        match2 = det.check_connection("198.51.100.99", ja4="t13d1516h2_8daaf6152771_e562703ab85f")
        self.assertIsNotNone(match2)
        self.assertEqual(match2["risk_tier"], "CRITICAL")

        # Test tampered bundle is rejected
        tampered = dict(bundle)
        tampered["signature"] = base64.b64encode(b"invalid-signature").decode()
        with self.assertRaises(ValueError):
            det.load_bundle(tampered, key)


if __name__ == "__main__":
    unittest.main()
