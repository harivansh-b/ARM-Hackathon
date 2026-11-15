"""Unit tests for aggregate.py and bundle_hook.py."""
import json
import sys
import tempfile
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
from guardian_net.aggregate import EvidenceAggregator, is_benign_system_traffic
from guardian_net.bundle_hook import load_threat_bundle
from guardian_net.detectors.denylist import DenylistDetector
from guardian_net.evidence import create_evidence


class TestAggregateAndBundleHook(unittest.TestCase):
    def test_benign_allowlist_filtering(self) -> None:
        self.assertTrue(is_benign_system_traffic("DOMAIN", "ntp.ubuntu.com"))
        self.assertTrue(is_benign_system_traffic("DOMAIN", "2.pool.ntp.org"))
        self.assertTrue(is_benign_system_traffic("DOMAIN", "archive.ubuntu.com"))
        self.assertTrue(is_benign_system_traffic("IP", "127.0.0.53"))
        self.assertTrue(is_benign_system_traffic("FLOW", "10.77.0.1:54321->10.77.0.2:123/UDP", port=123))

        # Malicious should NOT be benign
        self.assertFalse(is_benign_system_traffic("DOMAIN", "evil-c2.test"))
        self.assertFalse(is_benign_system_traffic("IP", "198.51.100.55"))

    def test_aggregator_deduplication(self) -> None:
        agg = EvidenceAggregator(alert_threshold_score=0.40, aggregation_window_sec=300)

        # 1. Benign NTP event
        ntp_ev = create_evidence("DNS", "DNS_QUERY", "DOMAIN", "ntp.ubuntu.com", score=0.50, reasons=["NTP"])
        self.assertIsNone(agg.ingest(ntp_ev))
        self.assertEqual(agg.total_suppressed_benign, 1)

        # 2. First malicious beacon event
        ev1 = create_evidence("CONNECTION", "BEACON", "IP", "10.77.0.99", score=0.60, reasons=["Periodic beacon"])
        alert1 = agg.ingest(ev1)
        self.assertIsNotNone(alert1)
        self.assertEqual(alert1["risk_tier"], "WARN")
        self.assertEqual(agg.total_alerts_emitted, 1)

        # 3. Repeat events for same entity within window
        for i in range(5):
            ev_repeat = create_evidence("CONNECTION", "BEACON", "IP", "10.77.0.99", score=0.60, reasons=["Periodic beacon"])
            self.assertIsNone(agg.ingest(ev_repeat))
        self.assertEqual(agg.total_alerts_emitted, 1)

        # 4. Escalation: score jumps to 0.90
        ev_escalate = create_evidence("CONNECTION", "EXFILTRATION", "IP", "10.77.0.99", score=0.90, reasons=["Massive exfiltration"])
        alert_esc = agg.ingest(ev_escalate)
        self.assertIsNotNone(alert_esc)
        self.assertEqual(alert_esc["risk_tier"], "CRITICAL")
        self.assertEqual(agg.total_alerts_emitted, 2)
        # Verify reasons are merged
        self.assertIn("Periodic beacon", alert_esc["reasons"])
        self.assertIn("Massive exfiltration", alert_esc["reasons"])

    def test_bundle_hook_loading(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_file = Path(tmpdir) / "intel_bundle.json"
            key = b"test-key-32-bytes-long-12345678"
            payload = {"domains": ["c2-test.biz"], "ips": ["1.2.3.4"], "ja4s": []}
            bundle = sign_bundle(payload, key, version=3, expires="2099-01-01")
            bundle_file.write_text(json.dumps(bundle), encoding="utf-8")

            detector = DenylistDetector()
            ok = load_threat_bundle(bundle_file, key, detector, minimum_version=1)
            self.assertTrue(ok)
            self.assertEqual(detector.bundle_version, 3)
            self.assertIn("c2-test.biz", detector.blocked_domains)


if __name__ == "__main__":
    unittest.main()
