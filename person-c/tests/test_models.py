import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from guardian_models.detectors import analyze_sms, analyze_url
from guardian_models.dataset import SMSExample, campaign_split, deterministic_campaign_split
from guardian_models.metrics import binary_metrics, pr_auc
from guardian_models.normalize import extract_urls, normalize_text, normalize_url
from guardian_models.sms_model import LinearSMSModel
from guardian_models.runtime import SMSRuntime


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


class TrainingTests(unittest.TestCase):
    def test_campaign_split_keeps_campaigns_disjoint(self):
        examples = [SMSExample("bad", 1, "a"), SMSExample("good", 0, "b"), SMSExample("bad two", 1, "a")]
        train, test = campaign_split(examples, {"b"})
        self.assertEqual({item.campaign for item in train}, {"a"})
        self.assertEqual({item.campaign for item in test}, {"b"})

    def test_deterministic_split_keeps_both_labels_and_groups_intact(self):
        examples = [SMSExample("bad a", 1, "a"), SMSExample("good b", 0, "b"), SMSExample("bad c", 1, "c"), SMSExample("good d", 0, "d")]
        train, test = deterministic_campaign_split(examples, 0.5, salt="test")
        self.assertEqual({item.label for item in train}, {0, 1})
        self.assertEqual({item.label for item in test}, {0, 1})
        self.assertTrue({item.campaign for item in train}.isdisjoint({item.campaign for item in test}))

    def test_linear_model_learns_and_explains_fixture(self):
        model = LinearSMSModel(epochs=30).fit([
            ("urgent verify otp", 1),
            ("claim prize pay fee", 1),
            ("delivery arrives tomorrow", 0),
            ("booking confirmed tomorrow", 0),
        ])
        self.assertGreater(model.predict_proba("urgent verify otp"), model.predict_proba("delivery arrives tomorrow"))
        self.assertTrue(model.explain("urgent verify otp"))
        self.assertEqual(LinearSMSModel.from_dict(model.to_dict()).predict_proba("urgent verify otp"), model.predict_proba("urgent verify otp"))

    def test_metrics_include_false_positive_rate_and_pr_auc(self):
        report = binary_metrics([1, 1, 0, 0], [0.9, 0.8, 0.2, 0.1])
        self.assertEqual(report["false_positive_rate"], 0.0)
        self.assertEqual(report["f1"], 1.0)
        self.assertEqual(pr_auc([1, 1, 0, 0], [0.9, 0.8, 0.2, 0.1]), 1.0)

    def test_runtime_marks_clear_alert_and_bounds_input(self):
        model = LinearSMSModel(epochs=30).fit([("urgent verify otp", 1), ("delivery arrives tomorrow", 0)])
        runtime = SMSRuntime(model, threshold=0.5, review_band=0.02, max_chars=32)
        alert = runtime.analyze("urgent verify otp")
        self.assertEqual(alert["decision_state"], "ALERT")
        bounded = runtime.analyze("delivery arrives tomorrow " + "x" * 100)
        self.assertTrue(bounded["truncated_input"])


if __name__ == "__main__":
    unittest.main()
