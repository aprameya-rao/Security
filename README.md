# Autonomous eBPF-XDR Platform

A distributed XDR (Extended Detection and Response) platform. An eBPF sensor on a target host streams process-execution telemetry into Kafka, where a Python "brain" enriches it against threat-intel and ML anomaly models, stores it in ClickHouse, and issues kill orders back to a Rust responder on the target host.

## Architecture

```
[ VM1 - Target/Endpoint 192.168.1.15 ]
    ├── eBPF Host Sensor (Go)  ──> execve/connect events  ──> Kafka (VM2)
    └── Local Responder (Rust) ──< kill_commands (Kafka) <─ kills PIDs
                                  │
[ VM2 - Brain 192.168.1.16 ]
    ├── Kafka + Zookeeper   (event queue)
    ├── ClickHouse          (telemetry storage)
    ├── Redis               (threat-intel IOC cache)
    ├── Ingestor (Python)   Kafka -> enrich -> ClickHouse; fires kill orders on known threats
    └── AI Brain (Python)   autoencoder anomaly scoring -> fires kill orders
```

Data flow: `execve`/`connect` tracepoints -> ring buffer -> Kafka `xdr-telemetry` -> ingestor + AI brain -> ClickHouse (`security_logs.execve_events` / `security_logs.network_events`) and/or `kill_commands` -> Rust responder -> `kill -9`.

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
  Payload that is `local,urlhaus,feodo,threatfox`; the Feodo source is winding down (returns a handful of IPs) and
  ThreatFox now requires signing up for an API key (`THREATFOX_API_KEY`) — without it the feed skips ThreatFox quietly.
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

### Retraining the process zero-day detector

The existing zero-day detector is trained from process-execution records in
`security_logs.execve_events`. Collect representative normal activity on VM1 while the
sensor, Kafka, and `ingestor.py` are running. Avoid training on deliberate attack tests or
known IOC matches. Check the available baseline before retraining:

```bash
sudo docker exec clickhouse clickhouse-client --password admin -q \
  "SELECT count() FROM security_logs.execve_events"
```

Run training from the `xdr-brain/` directory:

```bash
source venv/bin/activate
python engine/autoencoder.py
```

This updates the process-model artifacts under `engine/models/` and the feature artifacts
under `engine/*.pkl`. Restart `engine/ai_interference.py` after retraining so it loads the
new artifacts. The process detector currently has an automatic response path for events
that exceed its configured threshold, so review the baseline and threshold before using a
new model in the live lab.

### Collecting normal network traffic for NIDS training

Phase 2 network telemetry is stored separately in `security_logs.network_events`. The NIDS
feature contract is implemented in `engine/network_features.py`; the network autoencoder
training and live scorer are a later stage and are not started by the current pipeline.

First ensure the VM2 ingestor and VM1 sensor are running, then generate normal traffic that
represents the services normally used by the endpoint:

```bash
curl -4 https://example.com
curl -6 https://example.com       # only when IPv6 connectivity is available
nc -vz 192.168.1.16 9092         # optional local Kafka connectivity
```

Allow normal background services such as DNS, NTP, package updates, SSH, and Kafka to run.
Do not include attack replays or known-threat IOC events in the baseline. Check the collected
network data:

```bash
sudo docker exec clickhouse clickhouse-client --password admin -q \
  "SELECT count() FROM security_logs.network_events"

sudo docker exec clickhouse clickhouse-client --password admin -q \
  "SELECT count(), min(ts), max(ts) FROM security_logs.network_events WHERE is_known_threat = 0"

sudo docker exec clickhouse clickhouse-client --password admin -q \
  "SELECT command, destination_ip, destination_port, count() \
   FROM security_logs.network_events \
   WHERE is_known_threat = 0 \
   GROUP BY command, destination_ip, destination_port \
   ORDER BY count() DESC LIMIT 20"
```

The current feature contract can be validated and its metadata regenerated with:

```bash
source venv/bin/activate
python engine/network_features.py
```

This writes `engine/models/nids_feature_metadata.json`, which records the feature order and
count. At this point the data is only being collected and the feature contract is being
validated. Do not expect a network anomaly model or `nids_scorer.py` to run until the later
NIDS training and live-scoring stages are implemented.

### Training the initial NIDS model

Once `security_logs.network_events` contains representative benign traffic, train the
network autoencoder from the `xdr-brain/` directory:

```bash
source venv/bin/activate
python engine/train_nids.py
```

The trainer reads only valid, non-IOC network events and creates:

```text
engine/models/nids_autoencoder.pt
engine/models/nids_scaler.pkl
engine/models/nids_feature_metadata.json
```

The metadata contains the validation reconstruction-loss statistics and an initial P99
anomaly threshold. Optional controls are available for a repeatable small run:

```bash
python engine/train_nids.py --limit 500 --epochs 100 --seed 42
```

This stage trains and saves the model only. The live NIDS scorer and alert topic are not
implemented yet, and the trained NIDS model does not issue kill commands.

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

## Phase 2 telemetry

The sensor publishes both event types to `xdr-telemetry`:

- `execve`: PID, UID, executable, and bounded command arguments.
- `connect`: PID, UID, process name, IPv4 or IPv6 destination, destination port, and protocol.

Network events are stored in `security_logs.network_events`. Destination IPs are checked against
the Redis IOC sets, but a network-only IOC match is recorded and does not currently issue a kill;
the existing command IOC kill path is unchanged. IPv4 and IPv6 addresses are normalized to the
JSON `destination_ip` field.

For an existing ClickHouse volume, apply the migration from the VM2 `xdr-brain/` directory:

```bash
docker exec -i clickhouse clickhouse-client --password admin < migrations/02-network-events.sql
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

To exercise Phase 2 network telemetry, run `curl -4 https://example.com` and `curl -6 https://example.com`
when IPv6 connectivity is available. Confirm `[CONNECT]` events, `destination_ip`/port fields in Kafka,
and rows in `security_logs.network_events`. Use a controlled test destination for IOC matching rather than
an external malicious address.

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
