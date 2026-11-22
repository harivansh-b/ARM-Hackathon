"""Honest SMS evaluation slices (never part of training). Usage: PYTHONPATH=. python3 tools/eval_sms_slices.py ARTIFACT [ARTIFACT...]
A message counts as 'flagged' if the verdict is ALERT or REVIEW; 'alert' counts ALERT only."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from guardian_models.runtime import SMSRuntime  # noqa: E402


def jl(path, only=None):
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            d = json.loads(line)
            if "text" in d and "label" in d and (only is None or d.get("split") == only):
                out.append((d["text"], int(d["label"]), d.get("category", "")))
    return out


DEMO20 = [(1, "Refund of Rs 4,999 approved for your order. Click http://refund-claim-support.co to claim"), (1, "Dear customer, your UPI handle is blocked. Enter PIN on http://upi-verify-help.com"),
          (1, "URGENT: Your bank account is suspended. Verify KYC immediately at http://bit.ly"), (1, "Your Aadhaar card will be deactivated today. Update details via http://uidai-update.top"),
          (1, "Bank alert: Someone requested Rs 15,000 via UPI. If not you, cancel at http://upi-cancel.top"), (1, "Final warning: Your credit card reward points worth 12,000 will expire today. Redeem now"),
          (1, "You have a pending customs parcel with illegal items. Press 1 to speak with customs officer"), (1, "Your electricity power will be cut tonight at 9:30 PM. Call billing officer now to avoid disconnection"),
          (1, "Part-time job alert! Earn Rs 5,000 daily from home liking YouTube videos. Apply online"), (1, "Congrats! You won Rs 25,00,000 in KBC lucky draw. Call +91-98XXX-XXXXX to claim"),
          (0, "Your package out for delivery today. Expected between 2 PM and 4 PM."), (0, "Your OTP for login is 482910. Do not share it with anyone."), (0, "Thanks for helping me move the boxes yesterday!"),
          (0, "Meeting moved to Conference Room B. Starts in 15 minutes."), (0, "Grocery list: milk, bread, eggs, tomatoes, rice."), (0, "Reminder: Dentist appointment tomorrow at 10:30 AM."),
          (0, "Hey are we still meeting at 5 PM near the station?"), (0, "Can you send me the notes from today's lecture?"), (0, "Mom called, said dinner is ready whenever you reach home."), (0, "Happy birthday! Hope you have a great day ahead.")]
SETS = {"Held-out Indian templates (synthetic)": jl(ROOT / "data/indian_synthetic.jsonl", "test") if (ROOT / "data/indian_synthetic.jsonl").exists() else [],
        "Repo hard set (person-a)": jl(ROOT.parent / "person-a/eval/hard_negatives.jsonl"), "Repo extra samples (person-a)": jl(ROOT.parent / "person-a/eval/extra_samples.jsonl"),
        "Indian hard negatives (all legit)": jl(ROOT / "data/indian_hard_negatives.jsonl"), "Demo-20 (reconstructed from screenshots)": [(t, l, "") for l, t in DEMO20]}


def evaluate(rt, data):
    tp = tpa = fn = fp = fpa = tn = 0; missed = {}
    for text, label, cat in data:
        state = rt.analyze(text)["decision_state"]; flagged, alert = state in ("ALERT", "REVIEW"), state == "ALERT"
        if label:
            tp += flagged; tpa += alert; fn += not flagged
            if not flagged: missed[cat or text[:40]] = missed.get(cat or text[:40], 0) + 1
        else:
            fp += flagged; fpa += alert; tn += not flagged
    sc, hm = tp + fn, fp + tn
    return {"n": len(data), "scams": sc, "legit": hm, "recall_flagged": round(tp / sc, 3) if sc else None, "recall_alert": round(tpa / sc, 3) if sc else None,
            "false_alarm_flagged": round(fp / hm, 3) if hm else None, "false_alarm_alert": round(fpa / hm, 3) if hm else None, "missed": missed}


if __name__ == "__main__":
    for art in sys.argv[1:]:
        rt = SMSRuntime.from_artifact(art); print(f"\n== {art}")
        for name, data in SETS.items():
            if data:
                r = evaluate(rt, data); print(f"{name:44} n={r['n']:4} scams={r['scams']:3} legit={r['legit']:3} | scam recall: flagged {r['recall_flagged']} alert {r['recall_alert']} | legit false alarms: flagged {r['false_alarm_flagged']} alert {r['false_alarm_alert']}" + (f" | missed {r['missed']}" if r['missed'] and r['n'] < 400 else ""))
