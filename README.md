# Autonomous eBPF-XDR Platform

A distributed XDR (Extended Detection and Response) platform. An eBPF sensor on a target host streams process-execution telemetry into Kafka, where a Python "brain" enriches it against threat-intel and ML anomaly models, stores it in ClickHouse, and issues kill orders back to a Rust responder on the target host.

## Architecture

```
[ VM1 - Target/Endpoint 192.168.1.15 ]
    ├── eBPF Host Sensor (Go)  ──> execve events  ──> Kafka (VM2)
    └── Local Responder (Rust) ──< kill_commands (Kafka) <─ kills PIDs
                                  │
[ VM2 - Brain 192.168.1.16 ]
    ├── Kafka + Zookeeper   (event queue)
    ├── ClickHouse          (telemetry storage)
    ├── Redis               (threat-intel IOC cache)
    ├── Ingestor (Python)   Kafka -> enrich -> ClickHouse; fires kill orders on known threats
    └── AI Brain (Python)   autoencoder anomaly scoring -> fires kill orders
```

Data flow: `execve` tracepoint -> ring buffer -> Kafka `xdr-telemetry` -> ingestor + AI brain -> ClickHouse (`security_logs.execve_events`) and/or `kill_commands` -> Rust responder -> `kill -9`.

## Repository layout

| Directory          | Contents                                                        |
|--------------------|-----------------------------------------------------------------|
| `ebpf-sensor/`     | Go eBPF sensor (C BPF program, agent, Kafka publisher)          |
| `local-responder/` | Rust Kafka consumer that executes kill orders                   |
| `xdr-brain/`       | Docker stack (Kafka, ClickHouse, Redis), Python ingestor + AI   |

## VM topology

| VM        | IP            | Role |
|-----------|---------------|------|
| VM1       | 192.168.1.15  | Target/Endpoint (sensor + responder) |
| VM2       | 192.168.1.16  | Brain (Kafka, ClickHouse, Redis, Python services) |

Network design: the sensor and responder are Kafka *clients* that reach VM2. VM2's address is configured via `.env` files (see Configuration). VM1's own IP is never needed in configuration.

## Prerequisites

- Ubuntu Server 22.04+ (kernel with BTF/CO-RE support) on both VMs.
- VM1 additionally needs Go (>= 1.24), clang/libbpf, and a Rust toolchain.
- VM2 additionally needs Docker + Docker Compose plugin.

## VM2 - Brain setup (192.168.1.16)

### 1. Install Docker

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER   # log out and back in for group changes
```

### 2. Configure

```bash
cd xdr-brain
cp .env.example .env            # BRAIN_IP=192.168.1.16 is pre-set; edit if the IP changes
```

### 3. Start the stack (covers a fresh start too)

`docker compose down -v` wipes all existing Kafka offsets, ClickHouse and Redis data. Run it once to discard stale data from an old setup. The first `up` automatically applies the ClickHouse schema from `initdb/` and can never touch data afterwards (initdb runs only when the data volume is empty).

```bash
docker compose down -v      # optional: one-time reset
docker compose up -d
docker compose ps           # wait until all containers are running
```

- kafka-ui: `http://192.168.1.16:8080`
- ClickHouse HTTP: port `8123` (db `security_logs`, native port `9000`)
- Redis: port `6379`

Verify the schema was applied:

```bash
docker exec -i clickhouse clickhouse-client --password admin -q "SHOW TABLES"
```

### 4. Python environment

```bash
cd xdr-brain
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install --index-url https://download.pytorch.org/whl/cpu torch
pip install scikit-learn pandas joblib kafka-python clickhouse_driver
```

### 5. Threat-intel IOC feed (live indicators)

The kill loop matches telemetry against Redis `threat_intel:iocs`. That set is populated by two new compose services:

- **`ioc-feed`**: fills `threat_intel:iocs` from the local baseline (`iocs/baseline.txt`, always), plus URLhaus, Feodo
  and ThreatFox (need internet egress on VM2; failures degrade to local-only, non-fatal). Refreshes on schedule
  (`IOC_REFRESH_HOURS`, default 1h). Manual refresh: `docker compose run --rm --no-deps ioc-feed python ioc_feed.py --once`.
- **`ioc-learner`**: listens to the responder's `kill_confirmations` acks and grows `threat_intel:learned`
  (confirmed-bad commands). Confirmation is never based on kill success alone — only on **re-infection evidence**
  (same zero-day command killed again within `REINFECT_WINDOW_S`, default 300s / `REINFECT_KILLS`, default 2) or on
  **operator triage approval**.

Operator triage (approve/reject zero-day kill learnings), run on VM2 host (`redis` is in `requirements.txt`):

```bash
source venv/bin/activate
python ioc_approve.py                     # list pending
python ioc_approve.py --approve TOKEN     # confirm + learn
python ioc_approve.py --approve-all       # confirm everything pending
python ioc_approve.py --reject TOKEN      # discard without learning
```

Survivable-manual IOCs live in `threat_intel:manual` (never wiped by the feed). Purge learning with
`docker exec -i redis redis-cli DEL threat_intel:learned`.

### 6. Run the pipeline (each in its own terminal)

```bash
source venv/bin/activate
python ingestor.py               # Kafka -> enrich -> ClickHouse (+ kill orders on known threats)
python engine/ai_interference.py # zero-day anomaly scoring (+ kill orders)
```

The trained autoencoder and encoders are committed under `engine/models/` and `engine/*.pkl`, so the AI brain runs without training. After enough fresh telemetry has accumulated, retrain with:

```bash
source venv/bin/activate
python engine/autoencoder.py
```

## VM1 - Target setup (192.168.1.15)

### 1. Install toolchain

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev build-essential cmake pkg-config libssl-dev git
go version                      # must be >= go1.24; otherwise install from https://go.dev/dl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

### 2. Configure

```bash
cd ebpf-sensor
cp .env.example .env            # KAFKA_BROKER=192.168.1.16:9092 is pre-set; edit if the IP changes
cd ../local-responder
cp .env.example .env
```

### 3. Compile the eBPF C program into bytecode

```bash
cd ebpf-sensor/cmd/agent
go generate ./...
```

This runs bpf2go and regenerates `bpf_bpfel.go`, `bpf_bpfeb.go` and their `.o` binaries from `bpf/sensor.c`.

### 4. Build and run the sensor

```bash
cd ebpf-sensor
go build -o sensor ./cmd/agent
sudo ./sensor                   # loading eBPF programs requires root
```

### 5. Build and run the Rust responder

```bash
cd local-responder
cargo build --release
sudo ./target/release/local-responder
```

## Configuration

Config lives in `.env` files (copied from `.env.example`, both ignored by git):

| File                         | Keys                                  | Used by            |
|------------------------------|---------------------------------------|--------------------|
| `ebpf-sensor/.env`           | `KAFKA_BROKER`, `KAFKA_TOPIC`         | Sensor             |
| `local-responder/.env`       | `KAFKA_BROKER`                        | Responder          |
| `xdr-brain/.env`             | `BRAIN_IP`                            | docker-compose     |

Brain-side Python services default to `localhost` for Kafka, Redis and ClickHouse, so they need no changes when the brain IP moves.

**If the brain VM IP changes:** update `BRAIN_IP` in `xdr-brain/.env` (VM2) and `KAFKA_BROKER` in the two `.env` files (VM1), then `docker compose up -d` on VM2 and restart the sensor/responder.

## End-to-end check

With the stack, ingestor, AI brain, sensor and responder all running: run any process on VM1 and confirm `sudo ./sensor` logs `[EXEC]`, then confirm `xdr-telemetry` messages appear in kafka-ui and rows land in `execve_events`. A known-threat command produces a kill order that the responder prints and terminates.

Threat-intel wiring checks (VM2):

```bash
docker exec -i redis redis-cli SCARD threat_intel:iocs          # > 0 when feeds loaded
docker exec -i redis redis-cli SMEMBERS threat_intel:iocs       # live IOCs
docker exec -i redis redis-cli GET threat_intel:last_updated
docker exec -i redis redis-cli SCARD threat_intel:learned       # grows with confirmed learnings
docker exec -i redis redis-cli LRANGE threat_intel:pending_approval 0 -1   # zero-day kills awaiting triage
```

Feedback-loop test: make a zero-day command kill itself twice (re-execute the same novel binary after the first
kill) and confirm that without any ops action the token lands in `threat_intel:learned`; a once-only novel command
instead appears in `pending_approval` for `ioc_approve.py`. Manual override survival: `SADD threat_intel:manual foo`
stays present across feed refreshes.

## Roadmap status

> Plain-language walkthrough of the finished project and the phase-by-phase plan:
> see [PLAN.md](PLAN.md).

| Area | Status |
|------|--------|
| Pipeline: Kafka + ClickHouse + Redis stack | Done |
| eBPF sensor (execve -> Kafka) | Done |
| Threat-intel enrichment + kill responder | Done (detection via IOC cross-check) |
| Dataset-driven IOC/cross-check feeds | Done (local + URLhaus/Feodo/ThreatFox; hourly) |
| Adaptive IOC feedback (learned set) | Done (triage + re-infection confirmation) |
| Autoencoder-based anomaly scoring | Partial (committed model; re-train on fresh data) |
| NIDS (network traffic models) | Planned |
| Reinforcement-learning response agent (PPO) | Planned |
| XAI explainability (SHAP) | Planned |
| Web dashboard (Next.js/D3) | Planned |