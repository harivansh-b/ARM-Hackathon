"""Bounded, fail-safe SMS inference for a real-time Core integration."""

from __future__ import annotations

import json
import time
from pathlib import Path

from .detectors import analyze_sms, risk_tier_for_score
from .sms_model import LinearSMSModel


class SMSRuntime:
    def __init__(self, model: LinearSMSModel, threshold: float = 0.5, review_band: float = 0.02, max_chars: int = 4096, alert_threshold: float | None = None, review_floor: float | None = None) -> None:
        self.model = model
        self.threshold = threshold
        self.review_band = review_band
        # Two explicit cut-offs: >= alert_threshold is ALERT, >= review_floor is REVIEW, else BENIGN_CANDIDATE.
        # Defaults keep the legacy behaviour (alert at `threshold`, review band just below it) for direct callers.
        self.alert_threshold = alert_threshold if alert_threshold is not None else threshold
        self.review_floor = review_floor if review_floor is not None else max(0.0, threshold - review_band)
        self.max_chars = max_chars

    @classmethod
    def from_artifact(cls, path: str | Path) -> "SMSRuntime":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        config = payload.get("runtime", {})
        # Application cut-offs: ALERT >= 0.85, REVIEW 0.45-0.85. The calibrated threshold in the artifact came from a split
        # dominated by chat-style ham, so it is kept only as metadata; override via runtime.alert_threshold / review_floor.
        return cls(LinearSMSModel.from_dict(payload["model"]), float(config.get("threshold", 0.5)), float(config.get("review_band", 0.02)),
                   int(config.get("max_chars", 4096)), float(config.get("alert_threshold", 0.85)), float(config.get("review_floor", 0.45)))

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
        # Core evidence is authoritative for safety. The advisory model may
        # escalate a result, but it must never downgrade a deterministic core
        # warning or critical finding.
        combined_score = max(score, float(result["score"]))
        result["score"] = round(combined_score, 6)
        result["risk_tier"] = risk_tier_for_score(combined_score)
        if combined_score >= self.alert_threshold:
            result["decision_state"] = "ALERT"
        elif combined_score >= self.review_floor:
            result["decision_state"] = "REVIEW"
        else:
            result["decision_state"] = "BENIGN_CANDIDATE"
        result["truncated_input"] = len(text) > self.max_chars
        result["latency_ms"] = round((time.perf_counter() - started) * 1000, 3)
        return result
