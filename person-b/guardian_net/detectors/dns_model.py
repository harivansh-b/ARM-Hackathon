"""Optional offline DNS model with runtime-derived feature parity."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any


class RuntimeDNSModel:
    def __init__(self, artifact: dict[str, Any]) -> None:
        if artifact.get("format") not in {
            "guardian.network.dns.logistic.v1",
            "guardian.network.dns.logistic.runtime.v1",
        }:
            raise ValueError("unsupported DNS model artifact format")
        self.columns = [str(item) for item in artifact["feature_columns"]]
        self.means = [float(item) for item in artifact["means"]]
        self.scales = [float(item) or 1.0 for item in artifact["scales"]]
        self.weights = [float(item) for item in artifact["weights"]]
        self.bias = float(artifact["bias"])
        self.threshold = float(artifact.get("threshold", 0.5))

    @classmethod
    def from_file(cls, path: str | Path) -> "RuntimeDNSModel":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def predict(self, features: dict[str, float]) -> tuple[float, bool]:
        values = [
            (float(features.get(column, 0.0)) - mean) / scale
            for column, mean, scale in zip(self.columns, self.means, self.scales)
        ]
        raw = self.bias + sum(weight * value for weight, value in zip(self.weights, values))
        probability = 1.0 / (1.0 + math.exp(max(-35.0, min(35.0, -raw))))
        return probability, probability >= self.threshold
