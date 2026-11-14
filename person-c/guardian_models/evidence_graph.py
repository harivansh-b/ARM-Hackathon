"""Small offline evidence graph for incident-storyline correlation."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EvidenceLink:
    source_id: str
    target_id: str
    relation: str


def correlate(records: list[dict], window_seconds: int = 1800) -> list[EvidenceLink]:
    links = []
    for left in records:
        for right in records:
            if left is right or left.get("evidence_id") == right.get("evidence_id"):
                continue
            if abs(int(left.get("timestamp", 0)) - int(right.get("timestamp", 0))) > window_seconds:
                continue
            left_urls = set(left.get("extracted_urls", []))
            right_entity = right.get("entity", {}).get("value", "")
            if right_entity and any(right_entity in url for url in left_urls):
                links.append(EvidenceLink(left["evidence_id"], right["evidence_id"], "contains_url_entity"))
    return sorted(set(links), key=lambda link: (link.source_id, link.target_id, link.relation))
