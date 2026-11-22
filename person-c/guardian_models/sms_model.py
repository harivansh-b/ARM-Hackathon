"""Compact explainable hashed linear SMS classifier using only the Python standard library."""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter

from .normalize import normalize_text

TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)


def _features(text: str) -> Counter[str]:
    """Build small word, bigram and character features with no dependencies."""
    clean = normalize_text(text)
    tokens = TOKEN_RE.findall(clean)
    features: Counter[str] = Counter()
    for token in tokens:
        features[f"w:{token}"] += 1
    for left, right in zip(tokens, tokens[1:]):
        features[f"b:{left}_{right}"] += 1
    compact = re.sub(r"\s+", " ", clean)
    for index in range(max(0, len(compact) - 3)):
        features[f"c:{compact[index:index + 4]}"] += 1
    return features


def _sigmoid(value: float) -> float:
    if value < -35:
        return 0.0
    if value > 35:
        return 1.0
    return 1.0 / (1.0 + math.exp(-value))


class LinearSMSModel:
    """Hashed-feature logistic model with deterministic SGD and evidence-friendly explanations."""

    def __init__(self, learning_rate: float = 0.08, epochs: int = 18, l2: float = 0.0005) -> None:
        self.learning_rate = learning_rate
        self.epochs = epochs
        self.l2 = l2
        self.bias = 0.0
        self.weights: dict[str, float] = {}

    @staticmethod
    def _order(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def predict_proba(self, text: str) -> float:
        """Return the sigmoid score produced by the trained linear model."""
        score = self.bias
        for feature, value in _features(text).items():
            score += self.weights.get(feature, 0.0) * value
        return _sigmoid(score)

    def fit(self, examples: list[tuple[str, int]], balance: bool = False) -> "LinearSMSModel":
        """Train deterministic SGD over text/label pairs.

        ``balance`` weights each class inversely to its frequency so a corpus that is mostly scam
        (as the public smishing data is) cannot teach the model that anything transactional is a scam.
        """
        if not examples:
            raise ValueError("cannot train on an empty dataset")
        ordered = sorted(examples, key=lambda item: self._order(item[0]))
        positives = sum(1 for _, label in ordered if label == 1)
        negatives = len(ordered) - positives
        weights = {0: len(ordered) / (2 * negatives) if negatives else 1.0, 1: len(ordered) / (2 * positives) if positives else 1.0} if balance else {0: 1.0, 1: 1.0}
        for _ in range(self.epochs):
            for text, label in ordered:
                features = _features(text)
                error = (self.predict_proba(text) - label) * weights[label]
                self.bias -= self.learning_rate * error
                for feature, value in features.items():
                    old = self.weights.get(feature, 0.0)
                    self.weights[feature] = old - self.learning_rate * (error * value + self.l2 * old)
        return self

    def explain(self, text: str, limit: int = 5) -> list[dict[str, float | str]]:
        """Return the highest absolute feature contributions for this SMS."""
        values = _features(text)
        ranked = sorted(((feature, self.weights.get(feature, 0.0) * count) for feature, count in values.items()), key=lambda item: abs(item[1]), reverse=True)
        return [{"feature": feature, "contribution": round(contribution, 6)} for feature, contribution in ranked[:limit] if contribution != 0]

    def to_dict(self) -> dict:
        return {"format": "guardian.sms.linear.v1", "learning_rate": self.learning_rate, "epochs": self.epochs, "l2": self.l2, "bias": self.bias, "weights": self.weights}

    @classmethod
    def from_dict(cls, payload: dict) -> "LinearSMSModel":
        if payload.get("format") != "guardian.sms.linear.v1":
            raise ValueError("unsupported model artifact format")
        model = cls(float(payload["learning_rate"]), int(payload["epochs"]), float(payload["l2"]))
        model.bias = float(payload["bias"])
        model.weights = {str(key): float(value) for key, value in payload["weights"].items()}
        return model
