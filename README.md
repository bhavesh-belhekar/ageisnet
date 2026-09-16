# AegisNet

AI-powered intrusion detection for Docker container environments. AegisNet
monitors kernel-level network traffic via eBPF, combines rule-based detection
with ML anomaly detection, explains every ML alert via SHAP, and delivers
everything to a real-time React dashboard.

## Architecture

```
eBPF (kernel socket capture)
  → Redis Streams (event buffer)
    → Backend (Python/FastAPI)
        ├── Rule Engine (4 rules: bad IP, bad port, port scan, restricted protocol)
        ├── Flow Model (Isolation Forest — external traffic anomalies)
        ├── Graph Model (new-edge detection — internal lateral movement)
        ├── Risk Scorer (config-driven severity: Low / Medium / High)
        ├── SHAP Explainer (per-feature breakdown on every ML alert)
        └── MITRE Mapper (T1071, T1043, T1046, T1571, T1021.001)
    → PostgreSQL/TimescaleDB (events + alerts)
    → Neo4j (container communication graph)
    → WebSocket → React Dashboard (real-time alert feed + SHAP panel)
```

All of this runs as a single Docker Compose stack. One command starts
everything; one command stops it.

## Prerequisites

- **Docker Engine** 20.10+
- **Docker Compose** v2 (the `docker compose` plugin, not the legacy
  `docker-compose` binary)
- **Python 3.x** (only needed for `scripts/seed_demo_data.py` in Step 6,
  which runs on the host against host-mapped ports)

## Quick Start

### 1. Clone and enter the repo

```bash
git clone <repo-url> ageisnet
cd ageisnet
```

### 2. Create your environment file

```bash
cp .env.example .env
```

The defaults work out of the box for local development. No edits needed.

### 3. Start the stack

```bash
docker compose up --build
```

This builds and starts all 11 services. First startup takes 2–3 minutes
(Pull images, build containers, initialize Postgres and Neo4j).

### 4. Confirm everything is healthy

Wait until you see this in the logs, or run it from another terminal:

```bash
curl http://localhost:8000/api/health
```

Expected response:

```json
{"status":"ok","checks":{"postgres":true,"redis":true,"neo4j":true}}
```

You can also check service status:

```bash
docker compose ps
```

All services should show `Up` or `healthy`. The `neo4j-init` container
will show `Exited (0)` — that's expected; it's a one-shot helper that
applies graph constraints and then stops.

### 5. Open the dashboard

Open this URL in your browser:

```
http://localhost:5173
```

The dashboard loads with an empty alert feed and a live container
communication graph.

### 6. Generate traffic so alerts appear

The dashboard is empty until traffic flows. Open a second terminal and
run the traffic generator:

```bash
python scripts/seed_demo_data.py
```

This sends realistic normal traffic (product browsing, order placement)
between the demo containers for 2 minutes. You'll see the network graph
update in real time on the dashboard as eBPF captures new connections.

Press `Ctrl+C` to stop it early — it finishes cleanly.

### 7. Trigger an attack to see a real detection

Run the **known-bad IP** scenario — the clearest end-to-end demo:

```bash
bash scripts/run_attack_scenario.sh known_bad_ip
```

Within 2 seconds, a **HIGH severity** alert should appear on the
dashboard with:

- **MITRE technique:** T1071 (Application Layer Protocol)
- **Description:** Known-bad IP connection detected
- **Container:** The attacker-sim container (172.18.0.100)
- **Severity badge:** Red (HIGH)

Click the alert to see the full detail panel. ML-flagged alerts also
show a SHAP explanation panel with per-feature contribution breakdowns.

### Other attack scenarios

```bash
bash scripts/run_attack_scenario.sh port_scan        # RULE-003 / T1046 — HIGH
bash scripts/run_attack_scenario.sh lateral_movement  # RULE-004 / T1571 — HIGH
bash scripts/run_attack_scenario.sh beaconing         # flow_model / T1071 — ML anomaly
bash scripts/run_attack_scenario.sh exfiltration      # flow_model / T1071 — ML anomaly
```

Or run them all:

```bash
bash scripts/run_attack_scenario.sh --all
```

## Stopping the Stack

```bash
docker compose down
```

This stops all containers and removes the network. Data in Postgres and
Neo4j persists in Docker volumes across restarts.

To wipe everything (including data):

```bash
docker compose down -v
```

## Project Status

AegisNet is **complete through Phase 8** — all success metrics validated.
See the full results in [`docs/PHASE8_FINAL_REPORT.md`](docs/PHASE8_FINAL_REPORT.md).

| Phase | Status |
|---|---|
| 0 — Foundations & Contracts | Done |
| 1 — Infrastructure Skeleton | Done |
| 2 — eBPF Capture Layer | Done |
| 3 — Rule-Based Detection | Done |
| 4 — ML Anomaly Detection | Done |
| 5 — Explainability & MITRE Mapping | Done |
| 6 — Dashboard | Done |
| 7 — Demo Environment & Attack Scenarios | Done |
| 8 — Integration, Tuning & Final Testing | Done |

## Documentation

| Document | What it covers |
|---|---|
| [`docs/PRD.md`](docs/PRD.md) | Full requirements, functional specs, success metrics |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | System design, data flow, folder structure |
| [`docs/RULES.md`](docs/RULES.md) | Engineering standards, testing checklist |
| [`docs/PHASES.doc.md`](docs/PHASES.doc.md) | Build plan, phase checkpoints, decision log |
| [`docs/PHASE8_FINAL_REPORT.md`](docs/PHASE8_FINAL_REPORT.md) | Measured results against all success metrics |

## Known Limitations

Three items are tracked for future work (not blockers for the current
scope). See [`docs/PHASE8_FINAL_REPORT.md` Section 4](docs/PHASE8_FINAL_REPORT.md)
for full detail on each.

1. **Graph-model FP validation** — graph_model's false-positive rate on
   real baseline traffic has not been measured yet (code-correctness
   validated on synthetic baseline only).

2. **Neo4j reconciliation** — during a Neo4j outage, edges accumulate in
   an in-memory cache and are not written back on recovery.

3. **Internal-traffic volume anomaly detection** — neither model detects
   volume/frequency spikes on known internal edges (flow_model is
   external-only; graph_model is new-edges-only).

## License

Academic project — see repository for details.
