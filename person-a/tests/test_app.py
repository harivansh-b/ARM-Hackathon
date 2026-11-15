import sys, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "person-a")); sys.path.insert(0, str(ROOT / "person-c"))
from guardian_app.advisor import LlamaRunner, build_prompt, explain, verify  # noqa: E402
from guardian_app.importers import load_messages  # noqa: E402

EV = {"timestamp": 1, "evidence_id": "E1", "decision_state": "ALERT", "risk_tier": "HIGH", "matched_signals": [{"signal": "Link present"}], "extracted_urls": ["http://evil.top/x"], "entity": {"type": "SMS", "value": "VM-TEST"},
      "language_label": "English", "explanation": "Link present.", "safe_action": "Do not click links."}


class Tests(unittest.TestCase):
    def test_import_csv(self):
        self.assertEqual(len(load_messages(ROOT / "person-a/samples/sms.csv")), 3)

    def test_prompt_has_no_raw_text(self):
        self.assertNotIn("evil.top/x", build_prompt(EV))  # only the host is passed
        self.assertIn("evil.top", build_prompt(EV))

    def test_verifier_blocks_reassurance(self):
        self.assertFalse(verify("This message is safe and legitimate.", EV)[0])

    def test_verifier_blocks_invented_link_and_instructions(self):
        self.assertFalse(verify("Visit http://other.com now.", EV)[0])
        self.assertFalse(verify("Please click the link to verify.", EV)[0])

    def test_verifier_allows_negated_actions(self):
        self.assertTrue(verify("This looks like a scam. Do not click the link; contact your bank using its official app.", EV)[0])

    def test_pipeline_end_to_end_with_fake_llama(self):
        import os, stat, tempfile
        from guardian_models.dataset import load_jsonl
        from guardian_models.runtime import SMSRuntime
        from guardian_models.sms_model import LinearSMSModel
        from guardian_app.scan import scan
        data = load_jsonl(ROOT / "person-c/data/sms_multilingual.jsonl")
        runtime = SMSRuntime(LinearSMSModel(epochs=6).fit([(d.text, d.label) for d in data]), threshold=0.5)
        script = Path(tempfile.mkdtemp()) / "fake.sh"
        script.write_text("#!/bin/sh\nprintf 'This looks like a scam that pushes urgency. Do not click the link; verify through the official app.'\n")
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
        msgs = [{"id": "1", "text": "Your account is suspended. Verify now at http://bad-bank.top/login and send OTP", "sender": "+9190"}]
        out = scan(msgs, runtime, LlamaRunner(f"{script} {{prompt}}"))[0]
        self.assertEqual(out["state"], "ALERT")
        self.assertEqual(out["advice"]["source"], "llama")
        self.assertTrue(out["actions"])

    def test_fallback_when_llm_missing(self):
        out = explain(EV, LlamaRunner("false {prompt}"))
        self.assertEqual(out["source"], "template")
        self.assertEqual(explain(EV, None)["source"], "template")


if __name__ == "__main__":
    unittest.main()
