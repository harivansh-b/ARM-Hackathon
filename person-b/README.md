# Person B — Guardian Linux Network Sensor

Offline-first network sensor and telemetry pipeline for **Guardian** running on **ARM64 Linux (Ubuntu in a QEMU VM)**.

It provides a transparent DNS sentinel, a bounded flow table with TLS ClientHello inspection (SNI, ALPN, JA4 fingerprinting), stateful threat detectors, entity-level alert aggregation with benign Linux system traffic filtering, and network-namespace lab tooling.

**Privacy guarantee:** Guardian never stores packet payloads. For DNS tunnelling, only statistical metrics (Shannon entropy, label lengths, cardinality, digest) are retained—raw subdomains containing exfiltrated secrets are never persisted.

---

## Architecture Overview

```text
Host Network Traffic / Apps
       │
       ▼
┌──────────────────┐      ┌─────────────────────────┐
│   DNS Sentinel   │─────▶│  reports/               │
│  (127.0.0.1:5353)│      │    net_evidence.jsonl   │◀──────┐
└────────┬─────────┘      └─────────────────────────┘       │
         │ (Fail-open)                 ▲                    │
         ▼                             │ (Aggregated alerts)│
┌──────────────────┐      ┌────────────┴────────────┐       │
│  Upstream DNS    │      │    Entity Aggregator    │       │
│  (10.77.0.2:53)  │      │  (Benign Allowlist +    │       │
└──────────────────┘      │   Deduplication Window) │       │
                          └────────────▲────────────┘       │
                                       │                    │
                          ┌────────────┴────────────┐       │
                          │     Detectors (x6)      │       │
                          │ DNS Tunnel │ DGA        │       │
                          │ Beaconing  │ Scan       │       │
                          │ Exfil MAD  │ Denylist   │       │
                          └────────────▲────────────┘       │
                                       │                    │
                          ┌────────────┴────────────┐       │
                          │    Bounded Flow Table   │       │
                          │  (5-tuple, intervals,   │       │
                          │   TLS SNI, ALPN, JA4)   │       │
                          └────────────▲────────────┘       │
                                       │                    │
                          ┌────────────┴────────────┐       │
                          │   pcapio / AF_PACKET    │───────┘
                          │ (Live Sniff or Replay)  │
                          └─────────────────────────┘
```

---

## What is Implemented

| Component | Description | Status |
|---|---|---|
| `dnswire.py` | Pure stdlib RFC 1035 wire parser and serializer with pointer loop guard | Done |
| `dns_sentinel.py` | Concurrent UDP+TCP forwarder, TC/EDNS preservation, fail-open resilience, JSONL evidence logging | Done |
| `pcapio.py` | Binary PCAP reader/writer and Linux `AF_PACKET` raw sniffer | Done |
| `flows.py` | Bounded LRU 5-tuple flow table tracking inter-arrival intervals, directionality, and TLS state | Done |
| `tls_hello.py` | TLS ClientHello parser extracting SNI, ALPN, GREASE-filtered ciphers, and JA4-style fingerprints | Done |
| `detectors/dns_tunnel.py` | Shannon entropy, label length, TXT/NULL share, and subdomain cardinality (no payload leakage) | Done |
| `detectors/dga.py` | Character entropy, consonant-to-vowel ratios, consecutive consonant streaks, and NXDOMAIN ratios | Done |
| `detectors/beacon.py` | C2 heartbeat periodicity via Coefficient of Variation ($CV \le 0.30$) with jitter tolerance ($k \ge 5$) | Done |
| `detectors/scan.py` | Outbound port sweep and subnet scan detection across a sliding time window | Done |
| `detectors/exfil.py` | Data exfiltration detection using robust rolling Median + MAD $z$-scores and off-hours heuristics | Done |
| `detectors/denylist.py` | Threat intelligence bundle matching validated using Person C's `bundles.verify_bundle` | Done |
| `aggregate.py` | Per-entity deduplication and allowlist suppression for Linux periodic timers (NTP, apt, systemd) | Done |
| `bundle_hook.py` | Threat bundle verification and dynamic runtime rule loader | Done |
| `lab/` | Isolated network namespace lab (`netns_lab.sh`), resolver, mock C2, beacon/tunnel clients, PCAP fixtures | Done |
| `cli.py` | Unified CLI supporting `sentinel`, `sniff`, `replay --pcap`, and `scenarios` | Done |
| `correlate.py` | Cross-layer incident graph linking `SMS` $\to$ `URL` $\to$ `DNS` $\to$ `CONNECTION` | Done |

---

## Benchmark & Evaluation Results

All measurements recorded in `bench/results.json` and `eval/eval_report.json`.

**Environment:** ARM64 Linux VM under QEMU on Apple silicon (Ubuntu 24.04 LTS, Python 3.14).

| Metric | Measured Value | Notes |
|---|---|---|
| **DNS Parser Throughput** | 213,033 queries/sec (9.14 MB/s) | Pure Python standard library |
| **Flow Table Throughput** | 681,771 packets/sec | Bounded LRU with directionality & intervals |
| **Sentinel Added Latency (Median)** | **0.35 ms** | UDP forwarding through local sentinel |
| **Sentinel Added Latency (P95)** | **0.55 ms** | Sub-millisecond 95th percentile |
| **Sentinel Added Latency (P99)** | **0.67 ms** | Low tail latency under load |
| **Peak Memory (RSS)** | 138 MB | Bounded memory during full load |
| **Benign Trace False Alerts** | **0.0 / hour** | Tested on 24-hour simulated NTP + apt + systemd traffic |
| **Offline Verification** | **0 egress packets** | Verified inside isolated network namespace |

---

## Quickstart

Run all commands from the repository root.

### Dataset-backed validation

The network evaluation workstream now includes normalized reference reports
for UNSW-NB15 and CICIDS2017 DDoS/PortScan subsets. Results are benchmark-only
because public flow features are not identical to live packet windows:

| Benchmark | Attack recall | Benign recall | Macro F1 |
|---|---:|---:|---:|
| UNSW-NB15 | 84.68% | 67.19% | 76.18% |
| CICIDS2017 DDoS | 99.92% | 99.78% | 99.86% |
| CICIDS2017 PortScan | 99.90% | 99.41% | 98.80% |

The raw files are local and gitignored. Provenance is recorded in
`../integration-tests/external_dataset_manifest.json`.

The DNS reference model is opt-in:

```bash
python3 person-b/guardian_net/cli.py replay \
    --pcap person-b/eval/scenarios/dns_tunnel.pcap \
    --dns-model integration-tests/cic_bell_dns_exf.reference.model.json
```

The signed OpenPhish domain bundle is also opt-in:

```bash
python3 person-b/guardian_net/cli.py replay \
    --pcap person-b/eval/scenarios/dns_tunnel.pcap \
    --threat-bundle integration-tests/openphish.bundle.json \
    --bundle-key-file /path/to/bundle-key
```

The current OpenPhish lookup report matched 300/300 feed URLs and 0/20
curated benign URLs. PhishTank support is implemented by the same bundle
builder but awaits an application-key snapshot.

### 1. Run Unit Tests (22 Person B tests in the current validation set)

```bash
python3 -m unittest discover -s person-b/tests -v
```

### 2. Run Scenario Verification Suite

```bash
python3 person-b/guardian_net/cli.py scenarios
```

Output:
```text
=================================================================
      GUARDIAN NETWORK SENSOR: SCENARIO VERIFICATION SUITE       
=================================================================
Scenario               | Expected Event   | Alerts | Result  
-----------------------------------------------------------------
smishing_c2_chain      | BEACON           | 1      | PASS    
dns_tunnel             | DNS_TUNNEL       | 2      | PASS    
port_scan              | PORT_SCAN        | 1      | PASS    
exfil_spike            | EXFILTRATION     | 2      | PASS    
benign_linux           | ANY              | 0      | PASS    
-----------------------------------------------------------------
[✓] ALL SCENARIOS PASSED. Zero false alerts on benign Linux background traffic.
```

### 3. Replay a PCAP File

```bash
python3 person-b/guardian_net/cli.py replay --pcap person-b/eval/scenarios/smishing_c2_chain.pcap
```

### 4. Run Benchmarks

```bash
python3 person-b/bench/bench_net.py
```

### 5. Run Offline Proof

```bash
sudo person-b/eval/offline_proof.sh
```

---

## Isolated Lab in Network Namespaces

The lab runs on the same VM using network namespaces with **zero route out to WAN by construction**:

```bash
# 1. Bring up the isolated lab namespace and veth pair (10.77.0.1 <-> 10.77.0.2)
sudo person-b/lab/netns_lab.sh up

# 2. Start the lab resolver and C2 server inside the 'lab' namespace
sudo ip netns exec lab python3 person-b/lab/lab_resolver.py --host 10.77.0.2 --port 53 &
sudo ip netns exec lab python3 person-b/lab/c2_server.py --host 10.77.0.2 --port 443 &

# 3. Start the DNS sentinel on the host
python3 person-b/guardian_net/cli.py sentinel \
    --listen-host 127.0.0.1 \
    --listen-port 5353 \
    --upstream-host 10.77.0.2 \
    --upstream-port 53 &

# 4. Run beacon client or tunnel client against the sentinel
python3 person-b/lab/beacon_client.py --host 10.77.0.2 --port 443 --count 8 --interval 2.0
python3 person-b/lab/dns_tunnel_client.py --host 127.0.0.1 --port 5353 --chunks 10

# 5. Tear down lab
sudo person-b/lab/netns_lab.sh down
```

---

## End-to-End Chain Integration

Person B links network activity to Person A's SMS inputs and Person C's URL analysis:

1. **SMS Message** arrives: `"Dear customer your SBI account will be blocked today. Update KYC immediately at http://sbi-kyc-update.top/login"`
2. **Person C Detectors** flag SMS smishing (`S...`) and extract URL domain (`U...`, `sbi-kyc-update.top`).
3. **DNS Sentinel** logs DNS query for `sbi-kyc-update.top` (`D...`) resolving to `10.77.0.2`.
4. **Flow Table** logs periodic TLS beaconing (`C...`) to `10.77.0.2:443`.
5. **Correlator** links:
   $$\text{SMS} \xrightarrow{\text{contains\_url\_entity}} \text{URL} \xrightarrow{\text{queried\_dns\_domain}} \text{DNS} \xrightarrow{\text{connected\_to\_resolved\_ip}} \text{CONNECTION}$$

The exact changes requested for Person A and Person C are documented in [INTEGRATION.md](INTEGRATION.md).

---

## Limitations and Operational Context

- **Host-Bound Scope:** Operates as a local endpoint sensor on this Linux host (monitoring local processes and DNS queries). It does not function as an inline network gateway or promiscuous TAP for other hosts.
- **Encrypted Payloads:** Layer 7 payloads inside TLS streams are opaque by design. Detection relies strictly on transport metadata: SNI, ALPN, cipher suite selection, JA4 fingerprints, flow volume asymmetry, and timing intervals.
- **ECH & DoH:** Encrypted Client Hello (ECH) conceals the plaintext SNI, and DNS-over-HTTPS (DoH) / DoT bypasses standard UDP/TCP port 53 forwarders unless all DNS is forced through the local sentinel.
- **Hardware Attribution:** All benchmark figures are measured on an **ARM64 Linux VM under QEMU on Apple silicon**, not physical ARM production boards.
