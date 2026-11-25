
# Guardian Web — Local Security Interface

`guardian_web/` contains Guardian's local web application and CLI integration layer. It connects the browser interface to the SMS detector, URL analysis, network PCAP replay, local advisor and system benchmark functionality.

The web application is a thin integration layer. Detection logic resides in Person A, Person B and Person C.

## Responsibilities

- Serve the local web interface.
- Expose HTTP JSON endpoints.
- Integrate SMS detection and URL analysis.
- Support batch SMS analysis and local file import.
- Integrate network scenario and PCAP replay.
- Expose system information and model hashes.
- Expose benchmark and sustained-run controls.
- Connect to the local advisor when configured.

## Architecture

```text
              Browser
                |
                v
         Static Web Interface
       HTML / CSS / JavaScript
                |
                v
          HTTP JSON Server
                |
                v
             Core Glue
       +--------+--------+
       |        |        |
       v        v        v
    Person A  Person B  Person C
    SMS       Network   Model /
    Scanner   Replay    URL /
                        Safety
       |
       v
    Local Advisor
    (Optional)
```

## Files

| File | Responsibility |
|---|---|
| `server.py` | HTTP server, static file serving and API routes |
| `core.py` | Integration logic connecting Person A/B/C |
| `cli.py` | Terminal interface |
| `__init__.py` | Package initialization |
| `static/index.html` | Web interface structure |
| `static/app.css` | Interface styling |
| `static/app.js` | Client-side application behavior |

## Dependencies

The HTTP server uses Python standard-library components.

The application integrates the Guardian subsystems:

- Person A SMS scanner and advisor.
- Person B network sensor and PCAP replay.
- Person C SMS runtime, URL analysis, safety and evidence logic.

The local Llama advisor requires the compatible runtime, model and tokenizer assets if enabled.

No external web service is required for the core local analysis workflows.

## Running the web application

Run the Guardian CLI from the repository root.

### Start the web interface

```bash
./guardian serve --host 127.0.0.1 --port 8080
```

For local use, bind to localhost:

```bash
./guardian serve --host 127.0.0.1 --port 8080
```

Open:

```text
http://127.0.0.1:8080
```

### Run inside Docker

The Docker deployment uses:

```bash
guardian serve --host 0.0.0.0 --port 8080
```

The container's internal interface is bound to port 8080. The Compose configuration maps the host port to localhost by default.

## HTTP API

The server exposes JSON endpoints for analysis, system information, network scenarios, PCAP upload/replay and benchmark workflows.

### GET endpoints

| Endpoint | Purpose |
|---|---|
| `/api/system` | System information |
| `/api/system/hashes` | Model/runtime file hashes |
| `/api/system/benchmarks` | Stored benchmark information |
| `/api/sensor/scenarios` | Available network scenarios |
| `/api/sustained` | Sustained workflow status |
| `/api/status` | Basic status and Llama readiness |

### POST endpoints

| Endpoint | Purpose |
|---|---|
| `/api/check` | Analyze a single SMS |
| `/api/import` | Import and scan an uploaded file |
| `/api/check-batch` | Batch SMS analysis |
| `/api/import-sample` | Import the bundled sample SMS |
| `/api/sensor/explain` | Generate an explanation for network evidence |
| `/api/sensor/replay` | Replay a network scenario |
| `/api/sensor/upload` | Upload a PCAP |
| `/api/sustained/start` | Start the sustained workflow |
| `/api/sustained/stop` | Stop the sustained workflow |
| `/api/system/benchmark` | Run the system benchmark |
| `/api/system/llama-benchmark` | Run the Llama benchmark |

Request and response structures are implemented in `server.py` and `core.py`.

## SMS analysis

The web application integrates the Person C SMS runtime and Person A advisor.

The core analysis function evaluates the message, extracts URLs, evaluates those URLs and produces structured output.

The optional advisor can explain the evidence.

The security verdict remains determined by the local detector.

## Batch SMS analysis

The batch API accepts message records and processes them using the local detection runtime.

Batch processing is limited to 500 messages per request in the current server implementation.

The batch endpoint is:

```text
POST /api/check-batch
```

## File import

The web application supports importing messages through its import workflow.

The underlying importer is provided by Person A.

The import API endpoint is:

```text
POST /api/import
```

A sample import endpoint is also available:

```text
POST /api/import-sample
```

## Network sensor integration

The web application integrates Person B's network replay functionality.

It supports listing available scenarios, replaying scenarios, uploading PCAP files and generating explanations for network evidence.

### Scenario listing

```text
GET /api/sensor/scenarios
```

### Replay

```text
POST /api/sensor/replay
```

### PCAP upload

```text
POST /api/sensor/upload
```

The underlying network processing is implemented in Person B.

## System information

The application can expose system information and model/runtime file hashes.

These endpoints help inspect the local environment and model assets.

### System information

```text
GET /api/system
```

### Model/runtime hashes

```text
GET /api/system/hashes
```

## Benchmarks

The application exposes local system benchmark functionality.

### System benchmark

```text
POST /api/system/benchmark
```

### Llama benchmark

```text
POST /api/system/llama-benchmark
```

The benchmark results depend on the local runtime and hardware.

Benchmark outputs must not be interpreted as universal model performance.

## Sustained workflow

The application exposes controls for a sustained workflow.

### Status

```text
GET /api/sustained
```

### Start

```text
POST /api/sustained/start
```

### Stop

```text
POST /api/sustained/stop
```

The implementation and workflow state are managed in `core.py`.

## CLI

The repository's `guardian` executable provides a terminal interface.

### Start the web server

```bash
./guardian serve --host 127.0.0.1 --port 8080
```

### Check a message

```bash
./guardian check "Your account is locked"
```

### Check a message without Llama

```bash
./guardian check --no-llm "Your account is locked"
```

### JSON output

```bash
./guardian check --json "Your account is locked"
```

### Import a file

```bash
./guardian import path/to/messages.csv
```

### List network scenarios

```bash
./guardian sensor --list
```

### Replay a scenario

```bash
./guardian sensor scenario-name
```

### System information

```bash
./guardian system
```

### System benchmark

```bash
./guardian system --bench
```

CLI options are implemented in `guardian_web/cli.py`.

## Security

The web application currently has no authentication layer.

The Docker Compose configuration binds the Web UI to localhost by default. Do not expose it publicly without implementing appropriate authentication and access control.

The application is intended for a local demonstrator.

## Limitations

- The web application is integration glue, not the primary detector implementation.
- SMS and URL analysis depend on Person C.
- SMS scanning and advisor orchestration depend on Person A.
- Network replay and network detection depend on Person B.
- Llama availability depends on compatible local runtime assets.
- Benchmark outputs are hardware and configuration dependent.
- A locally accessible web interface should not be treated as a secure public service.

