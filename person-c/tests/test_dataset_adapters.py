"""Smoke tests for the dependency-free external dataset adapters."""

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


URL = load_module("guardian_url_adapter", ROOT / "person-c/tools/evaluate_url_benchmark.py")
NETWORK = load_module("guardian_network_adapter", ROOT / "person-b/eval/prepare_network_benchmark.py")


class DatasetAdapterTests(unittest.TestCase):
    def test_url_labels_keep_benign_separate(self):
        self.assertTrue(URL.is_benign("BENIGN"))
        self.assertTrue(URL.is_benign("normal"))
        self.assertFalse(URL.is_benign("phishing"))

    def test_network_adapter_detects_common_label_columns(self):
        self.assertEqual(NETWORK.find_label(["Flow ID", "Label"], None), "Label")
        self.assertEqual(NETWORK.find_label(["id", "attack_cat"], None), "attack_cat")

    def test_network_numeric_conversion_is_bounded(self):
        self.assertEqual(NETWORK.numeric("12"), 12)
        self.assertEqual(NETWORK.numeric("1.5"), 1.5)
        self.assertIsNone(NETWORK.numeric("not-a-number"))


if __name__ == "__main__":
    unittest.main()
