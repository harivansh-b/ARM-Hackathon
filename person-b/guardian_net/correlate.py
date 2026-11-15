"""Cross-layer incident correlation engine connecting SMS, URL, DNS, and Flow evidence."""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Import Person C normalizer if available
PERSON_C_PATH = Path(__file__).resolve().parents[2] / "person-c"
if str(PERSON_C_PATH) not in sys.path:
    sys.path.insert(0, str(PERSON_C_PATH))

try:
    from guardian_models.normalize import registrable_domain  # type: ignore
except ImportError:
    def registrable_domain(url_or_domain: str) -> str:
        host = url_or_domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        labels = host.split(".")
        return ".".join(labels[-2:]) if len(labels) >= 2 else host


@dataclass(frozen=True)
class CorrelatedLink:
    source_id: str
    target_id: str
    relation: str

    def to_dict(self) -> dict[str, str]:
        return {"from": self.source_id, "to": self.target_id, "relation": self.relation}


def correlate_records(records: list[dict[str, Any]], window_seconds: int = 1800) -> list[CorrelatedLink]:
    """Correlate SMS, URL, DNS, and CONNECTION evidence records into a unified incident graph."""
    links: list[CorrelatedLink] = []

    for left in records:
        for right in records:
            if left is right or left.get("evidence_id") == right.get("evidence_id"):
                continue

            left_ts = int(left.get("timestamp", 0))
            right_ts = int(right.get("timestamp", 0))
            if abs(left_ts - right_ts) > window_seconds:
                continue

            left_src = left.get("source")
            right_src = right.get("source")
            left_id = left.get("evidence_id", "")
            right_id = right.get("evidence_id", "")

            # 1. SMS -> URL (contains_url_entity)
            if left_src == "SMS" and right_src == "URL":
                left_urls = set(left.get("extracted_urls", []))
                right_entity = right.get("entity", {}).get("value", "")
                if right_entity and any(right_entity in url for url in left_urls):
                    links.append(CorrelatedLink(left_id, right_id, "contains_url_entity"))

            # 2. URL -> DNS (queried_dns_domain)
            elif left_src == "URL" and right_src == "DNS":
                url_domain = left.get("entity", {}).get("value", "")
                dns_domain = right.get("entity", {}).get("value", "")
                if url_domain and dns_domain:
                    norm_url_dom = registrable_domain(url_domain)
                    norm_dns_dom = registrable_domain(dns_domain)
                    if url_domain == dns_domain or norm_url_dom == norm_dns_dom:
                        links.append(CorrelatedLink(left_id, right_id, "queried_dns_domain"))

            # 3. DNS -> CONNECTION (connected_to_resolved_ip)
            elif left_src == "DNS" and right_src == "CONNECTION":
                resolved_ips = set(left.get("metadata", {}).get("resolved_ips", []))
                conn_target = right.get("entity", {}).get("value", "")
                if conn_target in resolved_ips or any(f"->{ip}:" in conn_target for ip in resolved_ips):
                    links.append(CorrelatedLink(left_id, right_id, "connected_to_resolved_ip"))

    return sorted(set(links), key=lambda link: (link.source_id, link.target_id, link.relation))


def build_unified_storylines(records: list[dict[str, Any]], links: list[CorrelatedLink]) -> list[dict[str, Any]]:
    """Assemble chronological chains: SMS -> URL -> DNS -> CONNECTION."""
    rec_by_id = {r["evidence_id"]: r for r in records if "evidence_id" in r}
    stories = []

    # Find starting SMS nodes
    sms_ids = [r["evidence_id"] for r in records if r.get("source") == "SMS"]
    for s_id in sms_ids:
        chain = [s_id]
        curr = s_id
        while True:
            next_link = next((l for l in links if l.source_id == curr), None)
            if not next_link or next_link.target_id in chain:
                break
            chain.append(next_link.target_id)
            curr = next_link.target_id

        if len(chain) > 1:
            events = [rec_by_id[eid] for eid in chain if eid in rec_by_id]
            stories.append({
                "chain_length": len(chain),
                "nodes": [e.get("evidence_id") for e in events],
                "sources": [e.get("source") for e in events],
                "summary": " ➔ ".join(f"{e.get('source')}({e.get('entity', {}).get('value')})" for e in events),
            })

    return stories
