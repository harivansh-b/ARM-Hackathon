# Guardian — offline Arm Linux security assistant

Guardian is an offline-first security assistant for Arm Linux. It runs two independent workflows: SMS/smishing analysis and network anomaly analysis. Deterministic detectors own security verdicts; the local Llama/ExecuTorch advisor explains evidence only. Approved playbook actions are displayed verbatim outside LLM output.

## Run

- SMS: `guardian_sms_pipeline.sh` (see script configuration/help)
- Network: `guardian_network_pipeline.sh` (PCAP replay by default; live capture requires privileges)
- Person C tests: `python3 -m unittest discover -s person-c/tests -v`
- Person A tests: `python3 -m unittest discover -s person-a/tests -v`
- Person B tests: `python3 -m unittest discover -s person-b/tests -v`

Guardian is a Linux software demonstrator, not an Android Core/Net architecture. Model artifacts and reports are local; inspect data-source licences before redistribution. Results from PCAP fixtures and synthetic tests are not live-network accuracy claims.

## Dataset integration

Dataset roles, provenance requirements, evaluation gates and current network/URL benchmark adapters are tracked in [the dataset integration plan](docs/DATASET_INTEGRATION_PLAN.md) and [the dataset registry](docs/dataset_registry.json). The SMS pipeline trains from the public SMS/phishing corpus plus the reviewed multilingual starter set when the local model artifact is first created. Indian hard negatives remain evaluation-only.

Current branch results include: SMS hard-scam recall improved from 60.0% to 86.7% with multilingual augmentation; UNSW-NB15 reached 84.68% attack recall on its held-out partition; CICIDS2017 reference benchmarks reached 99.92% DDoS recall and 99.90% PortScan recall; and a signed OpenPhish bundle matched 300/300 feed URLs with 0/20 curated benign matches. These are benchmark or lookup-integrity results, not universal live-network accuracy claims.

The DNS reference model and threat bundle are opt-in. Use `--dns-model` and `--threat-bundle` with the network CLI; existing deterministic rules remain the default safety layer. Raw external datasets remain gitignored.

---

## Docker deployment

Guardian can be deployed as a Docker container using the deployment configuration under `deploy/`. The container runs the Guardian webapp and SSH service under Supervisor.

### Requirements

- Docker with Docker Compose support
- ARM64 Linux environment or ARM64 Docker environment
- Sufficient disk space for the Guardian image and local model

The Docker image is built for ARM64.

### Installation

1. Clone the repository:

   ```bash
   git clone <repository-url>
   cd ARM-Hackathon
   ```

2. Run the setup script:

   ```bash
   ./deploy/setup.sh
   ```

3. Configure the installation when prompted:

   - **Webapp port:** Host port for the Guardian web interface (default: `8080`).
   - **SSH port:** Host port for SSH access to the container (default: `2222`).
   - **SSH password:** Set and confirm a password of at least 12 characters. Colons are not allowed.

   The setup script creates a local SSH secret, builds the Docker image and starts Guardian in the background.

### Access Guardian

#### Web interface

Open the following address in your browser, using the webapp port selected during setup:

```text
http://localhost:8080
```

If a different port was selected, replace `8080` accordingly.

#### SSH access

Connect to the Guardian container using the configured SSH port:

```bash
ssh -p 2222 guardian@localhost
```

Replace `2222` with the selected SSH port if necessary.

Enter the SSH password configured during installation.

Guardian runs under the non-root `guardian` user inside the container. To exit the SSH session:

```bash
exit
```

### Docker management

Run the following commands from the `deploy/` directory.

#### Stop Guardian

```bash
cd deploy
docker compose down
```

This stops and removes the container while retaining the persistent Docker volume.

#### Start Guardian

```bash
cd deploy
docker compose up -d
```

#### Restart Guardian

```bash
cd deploy
docker compose restart
```

#### View container logs

```bash
cd deploy
docker compose logs -f
```

#### Check container status

```bash
cd deploy
docker compose ps
```

#### Rebuild the image

```bash
cd deploy
docker compose up -d --build
```

### Persistence

Network reports are stored in a Docker volume named `guardian_reports`.

Stopping or recreating the container does not remove this volume. The volume persists independently of the container.

To remove the container and persistent data:

```bash
cd deploy
docker compose down -v
```

<ins>This permanently deletes the persistent Docker volume and its stored reports.</ins>

### Security considerations

- The webapp and SSH ports are bound to `127.0.0.1` by default and are not directly exposed on external network interfaces.
- SSH access is restricted to the `guardian` user.
- The SSH password is stored in `deploy/secrets/guardian_ssh_password`, which is excluded from Git.
- Port configuration is stored locally in `deploy/.env`, which is also excluded from Git.
- Do not expose Guardian directly to public networks without implementing and reviewing appropriate additional security controls.
- The webapp does not currently provide authentication; local port binding is an important deployment safeguard.

### Troubleshooting

#### Docker is unavailable

Ensure Docker is installed and running before launching the setup script.

#### Webapp is inaccessible

Check the container status:

```bash
cd deploy
docker compose ps
docker compose logs
```

Ensure the webapp port selected during setup is correct.

#### SSH connection fails

Check the container status and SSH logs:

```bash
cd deploy
docker compose logs
```

Ensure the SSH port selected during setup is correct and that the container is running.

#### Port is already in use

Rerun the setup script and select an available host port.

---

Guardian is an offline-first Linux security demonstrator. The Docker deployment provides a convenient local interface and SSH access while preserving the project's offline-first design.

