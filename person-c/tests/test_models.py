import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from guardian_models.detectors import analyze_sms, analyze_url
from guardian_models.normalize import extract_urls, normalize_text, normalize_url


class NormalizationTests(unittest.TestCase):
    def test_removes_zero_width_and_normalizes_case(self):
        self.assertEqual(normalize_text("  V\u200berify   NOW "), "verify now")

    def test_extracts_and_deduplicates_urls(self):
        self.assertEqual(extract_urls("See https://Example.com/a. https://example.com/a"), ["https://example.com/a"])

    def test_removes_fragment_and_default_port(self):
        self.assertEqual(normalize_url("HTTPS://Example.com:443/login#x"), "https://example.com/login")


class DetectorTests(unittest.TestCase):
    def test_sms_emits_shared_evidence_shape(self):
        result = analyze_sms("URGENT: your bank account is suspended. Send your OTP now at https://bad.test")
        self.assertEqual(result["source"], "SMS")
        self.assertIn(result["risk_tier"], {"WARN", "HIGH", "CRITICAL"})
        self.assertTrue(result["reasons"])
        json.dumps(result)

    def test_url_flags_credential_path(self):
        result = analyze_url("https://paypa1-login.example.test/verify")
        self.assertEqual(result["source"], "URL")
        self.assertGreaterEqual(result["score"], 0.5)
        self.assertIn("Look-alike brand spelling", result["reasons"])
        self.assertIn("Credential or account-themed path", result["reasons"])

    def test_llama_is_not_part_of_detector_output(self):
        result = analyze_sms("Your delivery is ready")
        self.assertNotIn("llama", result)
        self.assertIn("risk_tier", result)


if __name__ == "__main__":
    unittest.main()
