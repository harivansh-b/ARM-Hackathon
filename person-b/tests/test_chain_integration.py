"""End-to-end integration test linking Person A SMS samples, Person C detectors,
and Person B network evidence into a unified incident chain.
"""
import csv
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

REPO_ROOT = ROOT.parent
PERSON_C_PATH = REPO_ROOT / "person-c"
if str(PERSON_C_PATH) not in sys.path:
    sys.path.insert(0, str(PERSON_C_PATH))

from guardian_models.detectors import analyze_sms, analyze_url
from guardian_models.normalize import registrable_domain
from guardian_net.correlate import build_unified_storylines, correlate_records
from guardian_net.evidence import create_evidence


class TestChainIntegration(unittest.TestCase):
    def test_sms_to_url_to_dns_to_beacon_chain(self) -> None:
        # 1. Load sample SMS from person-a/samples/sms.csv
        sample_csv = REPO_ROOT / "person-a" / "samples" / "sms.csv"
        self.assertTrue(sample_csv.exists(), f"Missing {sample_csv}")

        with sample_csv.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            messages = list(reader)

        # Message #2 is smishing with URL http://sbi-kyc-update.top/login
        sbi_msg = next((m for m in messages if "sbi-kyc-update.top" in m["text"]), None)
        self.assertIsNotNone(sbi_msg)

        now = 1700000000  # Fixed deterministic timestamp

        # 2. Person C detection: SMS smishing
        sms_ev = analyze_sms(sbi_msg["text"], timestamp=now, sender=sbi_msg.get("sender"))
        self.assertIn("extracted_urls", sms_ev)
        self.assertEqual(len(sms_ev["extracted_urls"]), 1)
        extracted_url = sms_ev["extracted_urls"][0]

        # 3. Person C detection: URL phishing
        url_ev = analyze_url(extracted_url, timestamp=now + 5)
        extracted_domain = url_ev["entity"]["value"]  # "sbi-kyc-update.top"
        self.assertEqual(extracted_domain, "sbi-kyc-update.top")

        # 4. Person B sensor: DNS Sentinel logs query for the smishing domain
        dns_ev = create_evidence(
            source="DNS",
            event_type="DNS_QUERY",
            entity_type="DOMAIN",
            entity_value="sbi-kyc-update.top",
            score=0.40,
            reasons=["DNS query for newly seen smishing domain: sbi-kyc-update.top"],
            timestamp=now + 10,
            metadata={
                "qtype": "A",
                "resolved_ips": ["10.77.0.2"],
                "registrable_domain": registrable_domain("sbi-kyc-update.top"),
            },
        )

        # 5. Person B sensor: Flow table logs periodic C2 beaconing to 10.77.0.2
        c2_ev = create_evidence(
            source="CONNECTION",
            event_type="BEACON",
            entity_type="IP",
            entity_value="10.77.0.2",
            score=0.75,
            reasons=["Regular periodic beaconing: interval 5.0s (CV=0.04)"],
            timestamp=now + 30,
            metadata={"mean_interval_sec": 5.0, "sample_count": 8},
        )

        # 6. Correlate across the entire pool
        records = [sms_ev, url_ev, dns_ev, c2_ev]
        links = correlate_records(records, window_seconds=1800)

        # Verify exact links formed
        link_relations = {(l.source_id, l.target_id): l.relation for l in links}

        # Check Link 1: SMS -> URL
        self.assertIn((sms_ev["evidence_id"], url_ev["evidence_id"]), link_relations)
        self.assertEqual(
            link_relations[(sms_ev["evidence_id"], url_ev["evidence_id"])],
            "contains_url_entity",
        )

        # Check Link 2: URL -> DNS
        self.assertIn((url_ev["evidence_id"], dns_ev["evidence_id"]), link_relations)
        self.assertEqual(
            link_relations[(url_ev["evidence_id"], dns_ev["evidence_id"])],
            "queried_dns_domain",
        )

        # Check Link 3: DNS -> CONNECTION
        self.assertIn((dns_ev["evidence_id"], c2_ev["evidence_id"]), link_relations)
        self.assertEqual(
            link_relations[(dns_ev["evidence_id"], c2_ev["evidence_id"])],
            "connected_to_resolved_ip",
        )

        # 7. Verify unified incident storyline
        stories = build_unified_storylines(records, links)
        self.assertEqual(len(stories), 1)
        story = stories[0]
        self.assertEqual(story["chain_length"], 4)
        self.assertEqual(story["sources"], ["SMS", "URL", "DNS", "CONNECTION"])
        self.assertEqual(
            story["nodes"],
            [sms_ev["evidence_id"], url_ev["evidence_id"], dns_ev["evidence_id"], c2_ev["evidence_id"]],
        )
        self.assertIn("sbi-kyc-update.top", story["summary"])
        self.assertIn("10.77.0.2", story["summary"])


if __name__ == "__main__":
    unittest.main()
