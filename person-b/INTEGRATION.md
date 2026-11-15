# Guardian Integration Specification: Network Sensor (Person B)

This document specifies the exact, minimal integration hooks required for **Person A** (`guardian_app`) and **Person C** (`guardian_models`) to link network sensor evidence into the unified incident storyline.

---

## 1. Request for Person C (`person-c/`)

### File A: `guardian_models/evidence.py`
**Goal:** Allow `EvidenceRecord` to accept network sources.

```python
# In class EvidenceRecord.__post_init__:
# Change from:
if self.source not in {"SMS", "URL"}:
    raise ValueError("Person C evidence source must be SMS or URL")

# To:
if self.source not in {"SMS", "URL", "DNS", "CONNECTION"}:
    raise ValueError("evidence source must be SMS, URL, DNS, or CONNECTION")
```

### File B: `guardian_models/evidence_graph.py`
**Goal:** Extend `correlate()` to link `SMS` / `URL` $\to$ `DNS` $\to$ `CONNECTION` using normalized registrable domains and resolved IPs.

```python
from guardian_models.normalize import registrable_domain

def correlate(records: list[dict], window_seconds: int = 1800) -> list[EvidenceLink]:
    links = []
    for left in records:
        for right in records:
            if left is right or left.get("evidence_id") == right.get("evidence_id"):
                continue
            if abs(int(left.get("timestamp", 0)) - int(right.get("timestamp", 0))) > window_seconds:
                continue

            left_source = left.get("source")
            right_source = right.get("source")

            # 1. SMS -> URL
            left_urls = set(left.get("extracted_urls", []))
            right_entity = right.get("entity", {}).get("value", "")
            if right_entity and any(right_entity in url for url in left_urls):
                links.append(EvidenceLink(left["evidence_id"], right["evidence_id"], "contains_url_entity"))

            # 2. URL -> DNS (matching normalized domain)
            if left_source == "URL" and right_source == "DNS":
                url_domain = left.get("entity", {}).get("value", "")
                dns_domain = right.get("entity", {}).get("value", "")
                if url_domain and dns_domain:
                    # Compare full or normalized registrable domain
                    if url_domain == dns_domain or registrable_domain(url_domain) == registrable_domain(dns_domain):
                        links.append(EvidenceLink(left["evidence_id"], right["evidence_id"], "queried_dns_domain"))

            # 3. DNS -> CONNECTION (matching resolved IP or flow)
            if left_source == "DNS" and right_source == "CONNECTION":
                resolved_ips = set(left.get("metadata", {}).get("resolved_ips", []))
                conn_target = right.get("entity", {}).get("value", "")
                # Direct IP match or flow destination match
                if conn_target in resolved_ips or any(f"->{ip}:" in conn_target for ip in resolved_ips):
                    links.append(EvidenceLink(left["evidence_id"], right["evidence_id"], "connected_to_resolved_ip"))

    return sorted(set(links), key=lambda link: (link.source_id, link.target_id, link.relation))
```

---

## 2. Request for Person A (`person-a/`)

### File: `guardian_app/scan.py`
**Goal:** Add `--net-evidence` flag so network sensor events are ingested into the storyline and passed into Llama advisor facts.

```python
# Add CLI argument in main():
parser.add_argument("--net-evidence", type=Path, help="Path to network sensor evidence JSONL")

# In scan():
# Load network evidence records within scan time window:
net_records = []
if net_evidence_path and net_evidence_path.exists():
    with net_evidence_path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                net_records.append(json.loads(line))

# Include net_records in correlate call:
story_pool = [evidence] + url_ev + net_records
links = correlate(story_pool)
```

### File: `guardian_app/advisor.py`
In `build_prompt(evidence: dict)`:
If network evidence is linked (e.g. `dns_matches` or `c2_beacons`), append:
`f"; network activity: suspicious DNS/C2 beaconing detected"` to `<data>` facts.
