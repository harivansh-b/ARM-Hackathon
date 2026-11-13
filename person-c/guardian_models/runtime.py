"""Bounded, fail-safe SMS inference for a real-time Core integration."""

from __future__ import annotations

import json
import time
from pathlib import Path

from .detectors import analyze_sms, risk_tier_for_score
from .sms_model import LinearSMSModel


class SMSRuntime:
    def __init__(self, model: LinearSMSModel, threshold: float = 0.5, review_band: float = 0.02, max_chars: int = 4096) -> None:
        self.model = model
        self.threshold = threshold
        self.review_band = review_band
        self.max_chars = max_chars

    @classmethod
    def from_artifact(cls, path: str | Path) -> "SMSRuntime":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        config = payload.get("runtime", {})
        return cls(LinearSMSModel.from_dict(payload["model"]), float(config.get("threshold", 0.5)), float(config.get("review_band", 0.02)), int(config.get("max_chars", 4096)))

    def analyze(self, text: str, timestamp: int | None = None, sender: str | None = None) -> dict:
        """Run bounded inference and map the score to a cautious decision state.

        ``REVIEW`` is deliberately preserved around the calibrated threshold.
        ``BENIGN_CANDIDATE`` means no strong signal was found, not that the SMS
        has been proven safe.
        """
        started = time.perf_counter()
        bounded = text[: self.max_chars]
        score = self.model.predict_proba(bounded)
        result = analyze_sms(bounded, timestamp=timestamp, sender=sender)
        result["model_score"] = round(score, 6)
        result["model_evidence"] = self.model.explain(bounded, limit=6)
        result["score"] = round(score, 6)
        result["risk_tier"] = risk_tier_for_score(score)
        if abs(score - self.threshold) <= self.review_band:
            result["decision_state"] = "REVIEW"
        elif score >= self.threshold:
            result["decision_state"] = "ALERT"
        else:
            result["decision_state"] = "BENIGN_CANDIDATE"
        result["truncated_input"] = len(text) > self.max_chars
        result["latency_ms"] = round((time.perf_counter() - started) * 1000, 3)
        return result
