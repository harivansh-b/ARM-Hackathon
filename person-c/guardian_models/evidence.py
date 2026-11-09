"""The shared detector-to-Core evidence contract."""

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    source: str
    event_type: str
    timestamp: int
    entity: dict[str, Any]
    risk_tier: str
    score: float
    reasons: list[str] = field(default_factory=list)
    related_ids: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.source not in {"SMS", "URL"}:
            raise ValueError("Person C evidence source must be SMS or URL")
        if self.risk_tier not in {"INFO", "WARN", "HIGH", "CRITICAL"}:
            raise ValueError("invalid risk tier")
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("baseline score must be between 0 and 1")
        if not self.evidence_id:
            raise ValueError("evidence_id is required")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
