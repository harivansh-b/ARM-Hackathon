"""Unit tests for CLI commands and replay functionality."""
import io
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from guardian_net.cli import replay_pcap
from lab.make_pcap import generate_all_scenario_pcaps


class TestCLI(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.scenario_dir = Path(self.temp_dir.name)
        self.pcaps = generate_all_scenario_pcaps(self.scenario_dir)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_replay_smishing_c2_chain(self) -> None:
        alerts = replay_pcap(self.pcaps["smishing_c2_chain"], silent=True)
        self.assertGreaterEqual(len(alerts), 1)
        beacon_alert = next((a for a in alerts if "BEACON" in a["event_type"]), None)
        self.assertIsNotNone(beacon_alert)
        self.assertEqual(beacon_alert["entity"]["value"], "10.77.0.2")

    def test_replay_dns_tunnel(self) -> None:
        alerts = replay_pcap(self.pcaps["dns_tunnel"], silent=True)
        self.assertGreaterEqual(len(alerts), 1)
        tunnel_alert = next((a for a in alerts if "DNS_TUNNEL" in a["event_type"]), None)
        self.assertIsNotNone(tunnel_alert)
        self.assertEqual(tunnel_alert["entity"]["value"], "data-exfil.test")

    def test_replay_benign_linux_zero_false_positives(self) -> None:
        alerts = replay_pcap(self.pcaps["benign_linux"], silent=True)
        self.assertEqual(len(alerts), 0, "Benign Linux background traffic generated unexpected alerts!")


if __name__ == "__main__":
    unittest.main()
