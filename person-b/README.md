
# Person B — Guardian Linux Network Sensor

Person B implements Guardian's local Linux network sensor. It processes packet captures or live traffic, extracts network-flow and protocol metadata, evaluates behavioral signals, aggregates evidence and emits structured network reports.

The sensor is designed to operate locally and avoid storing packet payloads in its evidence workflow.

## Responsibilities

- PCAP parsing and offline replay.
- Linux live packet capture.
- Flow tracking and bounded flow-table management.
- DNS inspection and forwarding.
- TLS ClientHello metadata extraction.
- Behavioral detection.
- Entity-level evidence aggregation.
- Offline threat-intelligence matching.
- Structured JSONL evidence output.

## Architecture

```text
              Packet / PCAP
                    |
                    v
          PCAP Reader / Sniffer
                    |
                    v
             Flow Tracking
        5-tuple / bytes / intervals
                    |
           +--------+--------+
           |                 |
           v                 v
      DNS Inspection     TLS Metadata
           |            SNI / ALPN / JA4
           +--------+--------+
                    |
                    v
              Detector Layer
     DNS Tunnel / DGA / Beacon / Scan /
         Exfiltration / Denylist
                    |
                    v
             Evidence Aggregator
      Deduplication / Risk / Suppression
                    |
                    v
            JSONL Network Reports
```

## Main files

### Core modules

| File | Responsibility |
|---|---|
| `guardian_net/cli.py` | Network sensor CLI and execution modes |
| `guardian_net/pcapio.py` | PCAP reader and live sniffer |
| `guardian_net/flows.py` | Bounded flow table and flow metadata |
| `guardian_net/tls_hello.py` | TLS ClientHello metadata parsing |
| `guardian_net/dnswire.py` | DNS wire-format parsing and serialization |
| `guardian_net/dns_sentinel.py` | DNS forwarder and inspection |
| `guardian_net/evidence.py` | Structured network evidence |
| `guardian_net/aggregate.py` | Entity aggregation and alert suppression |
| `guardian_net/correlate.py` | Evidence correlation |
| `guardian_net/bundle_hook.py` | Threat bundle integration |

### Detectors

| File | Purpose |
|---|---|
| `guardian_net/detectors/dns_tunnel.py` | DNS tunnel indicators |
| `guardian_net/detectors/dga.py` | DGA-like domain indicators |
| `guardian_net/detectors/beacon.py` | Periodic beacon behavior |
| `guardian_net/detectors/scan.py` | Outbound scan behavior |
| `guardian_net/detectors/exfil.py` | Exfiltration indicators |
| `guardian_net/detectors/denylist.py` | Threat-intelligence matching |

### Additional files

| File | Purpose |
|---|---|
| `tests/` | Unit and integration tests |
| `eval/scenarios/` | PCAP verification scenarios |
| `eval/` | Evaluation and reference dataset tooling |
| `lab/` | Local demonstration and network-lab tooling |
| `reports/net_evidence.jsonl` | Structured evidence output |

## Network processing

### PCAP processing

The sensor supports offline PCAP processing.

Packets are parsed and associated with flows using flow identifiers and network metadata. The flow table tracks packet/byte counts, timestamps, protocol state and inter-arrival intervals.

### Flow tracking

The flow table tracks:

- Protocol
- Source and destination IP
- Source and destination ports
- Flow duration
- Original and response byte counts
- Packet counts
- Inter-arrival intervals
- Flow state
- TLS SNI
- ALPN
- JA4-style fingerprint

The flow table is bounded using an LRU mechanism.

### TLS metadata

TLS ClientHello inspection extracts metadata rather than decrypted application payloads.

The parser supports metadata including SNI, ALPN and JA4-style fingerprints.

### DNS Sentinel

DNS Sentinel supports UDP and TCP forwarding and inspection.

Its implementation includes:

- Configurable listen host and port
- Configurable upstream resolver
- UDP and TCP forwarding
- EDNS0 handling
- Truncation flag handling
- Concurrent processing
- Fail-open handling
- Structured DNS evidence
- Latency statistics

The forwarder is implemented in `guardian_net/dns_sentinel.py`.

### Detector layer

#### DNS tunnelling

The DNS tunnel detector evaluates characteristics such as entropy, label lengths, record types and domain/query patterns.

The evidence workflow retains statistical indicators rather than raw exfiltration payloads.

#### DGA-like domains

The DGA detector evaluates domain characteristics and DNS response context.

#### Beaconing

The beacon detector evaluates timing regularity across network events.

#### Outbound scanning

The scan detector evaluates outbound scan patterns and port/subnet activity.

#### Exfiltration

The exfiltration detector evaluates flow and traffic-volume patterns using statistical indicators.

#### Denylist

The denylist detector supports local threat-intelligence matching through an offline bundle.

## Evidence aggregation

Evidence aggregation consolidates events associated with entities.

It can:

- Aggregate related events within a time window.
- Deduplicate alerts.
- Escalate risk when appropriate.
- Suppress selected benign system traffic.
- Maintain related evidence IDs.

This helps reduce repetitive alerts.

## Dependencies

The network sensor primarily uses Python and its standard-library components.

The current source contains:

- Python socket handling
- PCAP parsing
- Linux `AF_PACKET` capture
- Threading
- Structured JSON processing
- Statistical detector logic

Live capture is Linux-specific and may require elevated privileges or suitable packet-capture permissions.

Offline replay does not require the same privileges as live capture.

The network subsystem does not depend on a cloud service for its basic offline detection workflow.

## Running the network sensor

Commands are run from the repository root unless specified otherwise.

### Replay a PCAP

Use the network CLI:

```bash
python3 -m person_b.guardian_net.cli replay
```

Because the directory is named `person-b`, use the standalone package path from within that directory when running the module:

```bash
cd person-b
python3 -m guardian_net.cli replay path/to/file.pcap
```

### Run scenario verification

```bash
cd person-b
python3 -m guardian_net.cli scenarios
```

Check the CLI help for the available options and scenario configuration.

### Run live capture

Live capture is Linux-specific and requires access to the network interface and raw packet capture permissions.

Use the `sniff` command supported by `guardian_net.cli`.

Live capture should only be performed on networks and devices for which you have authorization.

### DNS Sentinel

The network CLI exposes a `sentinel` command for DNS forwarding and inspection.

Use the CLI help to configure its listener and upstream resolver.

## Evaluation tooling

### Reference network benchmark preparation

`eval/prepare_network_benchmark.py` normalizes supported public network datasets into the evaluation format.

The tool does not fetch datasets automatically. Supply the local source file.

Example:

```bash
python3 eval/prepare_network_benchmark.py \
    path/to/UNSW_NB15_training-set.csv \
    integration-tests/unsw_nb15.normalized.jsonl \
    --dataset unsw-nb15 \
    --manifest integration-tests/unsw_nb15.manifest.json
```

The normalization and evaluation scripts are reference benchmarking tools and do not automatically retrain or replace the live network sensor.

### Network reference evaluation

The benchmark evaluation script is:

```text
eval/evaluate_network_benchmark.py
```

It can evaluate normalized records using a separate reference classifier.

The resulting metrics must not be presented as the accuracy of the live Guardian network detector.

### Offline verification

The evaluation directory includes offline verification helpers.

Review the script arguments before running:

```bash
bash eval/offline_proof.sh
```

### Run tests

From the repository root:

```bash
python3 -m unittest discover -s person-b/tests -v
```

## Lab tooling

The `lab/` directory contains controlled demonstration tooling for network scenarios.

Examples include:

- PCAP generation
- Beacon demonstration clients
- DNS tunnel demonstration clients
- DNS lab resolver
- Network namespace lab
- C2 demonstration server
- Scan demonstration scripts
- Exfiltration demonstration scripts

Use these tools only in an isolated and authorized lab environment.

## Reports

The default network evidence file is:

```text
person-b/reports/net_evidence.jsonl
```

The report is structured JSONL, allowing events to be retained and processed without storing full packet payloads.

In the Docker deployment, this report directory is mounted to a persistent volume.

## Tests

The test suite covers multiple components of the network sensor, including:

- Detectors
- DNS wire parsing
- DNS Sentinel
- CLI behavior
- Flow/TLS processing
- Aggregation
- Integration/correlation

Run:

```bash
python3 -m unittest discover -s person-b/tests -v
```

## Reference benchmark results and limitations

The repository includes public-dataset reference evaluations.

These are separate from live network detection.

The results depend on the dataset, partition, feature schema, normalization and reference evaluation pipeline.

A public-dataset benchmark does not establish the accuracy of the live packet sensor.

Live validation should use a controlled, representative network dataset or authorized traffic collection with independently verified labels.

## Privacy

The network sensor is designed to retain metadata and evidence rather than packet payloads in its evidence workflow.

DNS tunnel analysis stores statistical characteristics rather than raw tunnel subdomain content as evidence.

Live capture requires authorization and must be used with appropriate privacy and operational safeguards.

