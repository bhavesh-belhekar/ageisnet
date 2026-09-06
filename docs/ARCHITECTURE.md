# ARCHITECTURE.md
## AegisNet — Technical Architecture & Project Structure

| | |
|---|---|
| **Status** | Draft v1.0 |
| **Companion docs** | `PRD.md` (requirements), Project Proposal `.docx` (pitch/overview) |

---

## 1. Purpose of This Document

While the PRD defines *what* we're building and *why*, this document defines *how the code is organized* and *how components talk to each other technically* — the reference the team codes against day-to-day. This describes **one complete, end-to-end pipeline** built and delivered as a single system.

---

## 2. Architectural Style

AegisNet is a **layered, event-driven pipeline**:

```
Capture → Ingest → Detect → Explain → Store → Deliver → Present
```

Each layer is a separate, independently runnable service (its own container in Docker Compose), communicating over well-defined interfaces (message queue topics, REST/WebSocket APIs, DB connections). Different team members can own different layers in parallel, as long as everyone builds against the shared event/alert schema (see `PRD.md` Section 9) from the start.

---

## 3. Component Breakdown

### 3.1 Capture Layer — `ebpf-agent`
Runs privileged on the Docker host. Attaches eBPF programs at the **socket layer**:
- **`tracepoint/sock/inet_sock_set_state`** — captures TCP connection lifecycle transitions (ESTABLISHED → open, active-close states → close) with per-socket metadata (4-tuple, family, protocol, socket pointer).
- **kprobes `tcp_sendmsg` / `tcp_cleanup_rbuf`** — accumulate per-socket bytes sent/received; sampled at close for the event's final byte counts.
- Events are emitted through a ring buffer and surfaced by the loader over a pipe in a single line format (`EVTO|...` open, `EVTC|...` close).

**Socket-owner attribution:** Container ID is derived from the socket's own network namespace, read CO-RE (`sk->__sk_common.skc_net.net->ns.inum`) per socket. This is attachment-point independent, so open/close events stay attributed even when a transition executes in another task's context (e.g., a server socket's close run from a peer's process). See loader below.

**Hook-mechanism decision (2026-09-06):** The original plan was packet-layer hooks — **TC** for internal/east-west (veth interfaces) and **XDP** for external/north-south (network card, for speed). The socket-layer approach above is what was validated end-to-end through L1–L3 (device prototypes in `PHASES.doc.md` §5). It was chosen over building TC/XDP from scratch because: it fully meets **FR-1**'s kernel-level capture requirement (every connection's open/close, byte counts, attributable per container), it avoids redoing the validation layer, and — per PRD.md's explicit non-goal of production-grade throughput/scaling — socket-layer capture is appropriate for this project. Packet-layer TC/XDP remains a possible future upgrade path for line-rate scaling, not a current requirement.

**Direction heuristic:** `direction` (internal vs external) is derived in the loader by an **IP-map heuristic** — the loader builds a `local IP → container_id` map per network namespace (from `/proc/<pid>/net/fib_trie`) and marks an event `internal` when the destination IP resolves to a *different* known container, `external` otherwise (e.g., public internet, or a service the netns does not declare locally). This is an explicit heuristic, not a packet-interface classification — acceptable because the socket-layer hooks do not see the egress interface. It is documented as a known approximation; the external `example.com` smoke runs affirm the external path.

**Responsibility:** Produce `RawEvent` messages (connection metadata, byte counts, container attribution, `event_type` open/close per the frozen schema in `PRD.md` Section 9) onto the event pipeline. Nothing else — no detection logic lives here.

**Future improvement (not built now):** Move the loader's netns/cgroup parsing and Redis publish fully into C (hiredis), removing the Python wrapper (option 1b). Kept as Python (`load_and_publish.py`) deliberately — lower risk, reuses the L2/L3-validated pipe contract, and fits the course-project scope and PRD.md Non-Goals. Revisit only if event-rate-driven.<br>
> **Note:** This is the fixed §3.1 contract the capture implementation targets; the loader is started via `ENTRYPOINT python3 loader/load_and_publish.py`, which builds `src/capture` (clang + libbpf, CO-RE) at first start and spawns it as the capture subprocess.

### 3.2 Event Pipeline — `redis-streams`
**Responsibility:** Durable buffer between the eBPF agent and the Detection Engine. Decouples producer speed (kernel events can spike) from consumer speed (ML inference takes longer than a raw event arrival), and allows event replay for retraining ML models later.

### 3.3 Detection Engine (`backend/` — FastAPI app)
The core service, split internally into sub-modules that mirror the pipeline stages:

- **`rule_engine/`** — checks each event against static/threat-intel indicator lists (known-bad IPs, ports, domains), plus the stateful port-scan rule: a sliding-window counter per `container_id` that flags many distinct destination ports contacted within a short window. Fast, synchronous, runs on every event (the port-scan rule is stateful, but windowed and bounded per container).

  > **Known tradeoff — alert dedup is time-based, not connection-correlated (2026-09-06).** Each TCP connection produces a 4-event pipeline shape (open + close on both peers), which would fire the same rule twice and double every alert. The rule engine therefore suppresses a repeat alert for the same `(container, rule, dst)` within a 15-second window (`ALERT_SUPPRESSION_SECONDS` in `rule_engine/engine.py`, hence "one alert per connection"). This is a time-based simplification, not explicit correlation by connection 4-tuple: **two genuinely separate violations of the same rule from the same container within 15s are currently reported as a single alert.** Accepted explicitly for course-project scope; a 4-tuple-correlation pass over the open/close events would be the upgrade path if per-connection fidelity is ever needed.
- **`ml_engine/`**
  - **`flow_model/`** — Isolation Forest model scoring external (north-south) traffic features (bytes, frequency, port entropy, timing) aggregated over a 5-minute rolling window.
  - **`graph_model/`** — graph anomaly detector (heuristic graph-diff, or GNN/autoencoder) scoring internal (east-west) container communication graph edges; the "new edge" baseline is learned over a 24-hour rolling window.
  - Both window sizes are config-driven defaults in `config/risk_policy.yaml` (placeholders until finalized in Phase 4, tuned during Phase 8), not hardcoded.
- **`risk_scoring/`** — merges rule-engine hits + ML anomaly scores into one Low/Medium/High severity label per event, using a config-driven scoring policy (`config/risk_policy.yaml`), not hardcoded thresholds. The thresholds, window sizes, and FP targets in the policy file are placeholders — finalized during Phase 4 and tuned during Phase 8.
- **`explainability/`** — runs SHAP against the ML engine's output for any event that crosses the anomaly threshold, producing a feature-contribution breakdown attached to the alert.
- **`mitre_mapper/`** — looks up the appropriate MITRE ATT&CK technique ID for each detection type from a static mapping table (`config/mitre_mapping.yaml`).

**Responsibility:** Consume `RawEvent`s from the pipeline, run them through the above pipeline in order (rules → ML → risk scoring → explainability → MITRE tagging), and persist the result as an `Alert`.

### 3.4 Storage Layer
- **PostgreSQL + TimescaleDB** — `events` and `alerts` tables (time-series).
- **Neo4j** — live container communication graph (`Container` nodes, `CONNECTS_TO` relationships).

**Responsibility:** Durable persistence + queryability for both the dashboard and the ML models' baseline-learning queries.

### 3.5 Real-Time Delivery
**Service:** WebSocket endpoint inside the FastAPI backend (`backend/app/ws/`).

**Responsibility:** Push newly-created `Alert` records to connected dashboard clients immediately, without polling. Only `Low`-and-above alerts are persisted, but only `Medium`+ severity alerts trigger the real-time push — `Low` alerts stay in the audit trail (see FR-7).

### 3.6 Presentation Layer (`frontend/` — React app)
- **`AlertFeed/`** — real-time + historical alert list, filterable by severity/container.
- **`NetworkGraph/`** — live container communication graph visualization, color-coded by risk.
- **`AlertDetail/`** — per-alert drill-down including the SHAP explanation panel.

**Responsibility:** Consume the REST API (historical data) and WebSocket stream (live updates); render for a human analyst.

### 3.7 Demo / Test Environment
- **`demo-web`, `demo-api`, `demo-db`** — a small "victim" multi-container application (plain Docker images) that generates realistic normal traffic between services.
- **`scripts/attack_scenarios/`** — scripted attack traffic (port scan, known-bad IP, beaconing, lateral movement, exfiltration) run against the victim app to trigger and demonstrate detections live.

**Responsibility:** Give the eBPF agent something real to observe, and provide a repeatable way to demo every detection type end-to-end.

---

## 4. Data Flow (Step-by-Step)

1. A container does something on the network (e.g., opens a connection to a new IP, or to another container on a new port).
2. **`ebpf-agent`** observes this at the kernel level (socket-layer tracepoints/kprobes) and emits a `RawEvent` JSON message.
3. **Event pipeline** (Redis Streams) buffers the message on a stream/topic.
4. **Detection Engine** consumes the message:
   a. `rule_engine` checks it against known-bad indicators — if matched, an alert is generated immediately with `detection_type=rule`.
   b. In parallel/regardless, `ml_engine` scores the event (`flow_model` for external traffic, `graph_model` for internal traffic) — if the anomaly score crosses a threshold, `detection_type=ml`.
   c. `risk_scoring` combines whatever fired (rule and/or ML) into a single severity label.
   d. If ML fired, `explainability` computes a SHAP breakdown.
   e. `mitre_mapper` attaches a technique ID based on the detection type.
5. The resulting `Alert` is written to PostgreSQL, and (if it's a graph-related event) the Neo4j graph is updated.
6. The backend pushes the new `Alert` over WebSocket to any connected dashboard (per FR-7, only `Medium`+ alerts are pushed).
7. The **React dashboard** receives the push, adds it to the live alert feed, and (if applicable) updates the network graph view and highlights the new/anomalous edge.

---

## 5. Project Folder Structure

```
aegisnet/
│
├── README.md
├── docker-compose.yml                  # spins up the entire system with one command
├── docker-compose.override.yml         # local dev overrides (hot reload, exposed ports)
├── .env.example                        # environment variable template
│
├── docs/
│   ├── PRD.md
│   ├── ARCHITECTURE.md                 # this file
│   ├── project-proposal.docx
│   └── diagrams/
│       └── architecture.svg
│
├── capture/
│   └── ebpf-agent/
│       ├── src/
│       │   ├── tc_hook.c               # internal/east-west traffic capture
│       │   ├── xdp_hook.c              # external/north-south traffic capture
│       │   └── common.h
│       ├── loader/
│       │   └── load_and_publish.py     # loads eBPF programs, reads events, publishes to pipeline
│       ├── Makefile
│       └── Dockerfile
│
├── backend/
│   ├── app/
│   │   ├── main.py                     # FastAPI app entrypoint
│   │   ├── api/
│   │   │   ├── events.py               # GET /api/events
│   │   │   ├── alerts.py               # GET /api/alerts, /api/alerts/{id}
│   │   │   ├── graph.py                # GET /api/graph
│   │   │   └── health.py               # GET /api/health
│   │   ├── ws/
│   │   │   └── alerts_ws.py            # WebSocket /ws/alerts
│   │   ├── rule_engine/
│   │   │   ├── engine.py
│   │   │   └── indicators.py           # loads known-bad IP/domain/port lists
│   │   ├── ml_engine/
│   │   │   ├── flow_model/
│   │   │   │   ├── train.py
│   │   │   │   ├── infer.py
│   │   │   │   └── features.py
│   │   │   └── graph_model/
│   │   │       ├── train.py
│   │   │       ├── infer.py
│   │   │       └── graph_diff.py       # heuristic fallback if GNN not ready
│   │   ├── risk_scoring/
│   │   │   └── scorer.py
│   │   ├── explainability/
│   │   │   └── shap_explainer.py
│   │   ├── mitre_mapper/
│   │   │   └── mapper.py
│   │   ├── models/                     # SQLAlchemy / Pydantic schemas
│   │   │   ├── event.py
│   │   │   ├── alert.py
│   │   │   └── schemas.py
│   │   ├── db/
│   │   │   ├── postgres.py
│   │   │   └── neo4j_client.py
│   │   ├── consumers/
│   │   │   └── event_consumer.py       # reads from Redis Streams, drives the pipeline
│   │   └── config/
│   │       ├── settings.py
│   │       ├── risk_policy.yaml
│   │       └── mitre_mapping.yaml
│   ├── tests/
│   │   ├── test_rule_engine.py
│   │   ├── test_ml_engine.py
│   │   ├── test_risk_scoring.py
│   │   └── test_api.py
│   ├── requirements.txt
│   └── Dockerfile
│
├── frontend/
│   ├── src/
│   │   ├── App.tsx
│   │   ├── components/
│   │   │   ├── AlertFeed/
│   │   │   ├── NetworkGraph/
│   │   │   ├── AlertDetail/
│   │   │   └── ShapExplanationPanel/
│   │   ├── hooks/
│   │   │   └── useAlertsSocket.ts
│   │   ├── api/
│   │   │   └── client.ts
│   │   └── styles/
│   ├── public/
│   ├── package.json
│   └── Dockerfile
│
├── data/
│   ├── threat_intel/
│   │   └── known_bad_indicators.csv
│   ├── training_baselines/             # captured "normal" traffic for ML training
│   └── model_artifacts/                # saved trained model files (.pkl, .pt)
│
├── infra/
│   ├── postgres/
│   │   └── init.sql                    # schema + TimescaleDB hypertable setup
│   ├── neo4j/
│   │   └── init.cypher
│   └── redis/
│       └── redis.conf
│
├── demo-app/                            # the "victim" multi-container app for realistic traffic
│   ├── web/
│   ├── api/
│   └── db/
│
└── scripts/
    ├── seed_demo_data.py                # populate baseline "normal" traffic for demo
    ├── attack_scenarios/                 # scripted attacks run against demo-app
    │   ├── port_scan.py
    │   ├── known_bad_ip.py
    │   ├── beaconing.py
    │   ├── lateral_movement.py
    │   └── exfiltration.py
    ├── run_attack_scenario.sh           # trigger a scripted attack for live demo
    └── retrain_models.py
```

---

## 6. Why This Structure

- **`capture/ebpf-agent/` is the single, real capture layer** — there is no simulator/stand-in; the eBPF agent is built from the start and is the critical-path dependency for everything downstream.
- **`backend/app/` is split by responsibility, not by data type** — `rule_engine/`, `ml_engine/`, `risk_scoring/`, `explainability/`, `mitre_mapper/` each map directly to one pipeline stage from Section 4, so any team member can own one folder without stepping on others.
- **`ml_engine/flow_model/` and `ml_engine/graph_model/` are separate** — because they are genuinely different models trained on different data shapes (tabular vs. graph), keeping them separate avoids one messy shared module.
- **`config/` is separate from code** — risk thresholds and MITRE mappings are YAML, not hardcoded, satisfying the PRD's maintainability requirement.
- **`data/` is separate from `backend/`** — datasets and trained model artifacts change independently of code and shouldn't be mixed into the application source tree (and should typically be gitignored except for small demo fixtures).
- **`demo-app/` is separate from `scripts/`** — the victim application (what gets attacked) is infrastructure, while the attack scenarios (how it gets attacked) are test tooling; keeping them apart makes it clear which one you'd swap out to demo against a different target app.
- **`scripts/attack_scenarios/` holds demo tooling** — `run_attack_scenario.sh` is what you'll actually run live during your course presentation to trigger a visible detection end-to-end.

---

## 7. Service-to-Container Mapping (docker-compose.yml services)

| Service name | Folder | Purpose |
|---|---|---|
| `ebpf-agent` | `capture/ebpf-agent/` | Real kernel-level capture (privileged container) |
| `redis` | `infra/redis/` | Event pipeline |
| `backend` | `backend/` | FastAPI detection engine + API + WebSocket |
| `postgres` | `infra/postgres/` | Event/alert storage |
| `neo4j` | `infra/neo4j/` | Container communication graph |
| `neo4j-init` | `infra/neo4j/` | One-shot helper that applies `init.cypher` (constraints) after `neo4j` is healthy, then exits — the Neo4j image does not auto-execute `.cypher` scripts on startup |
| `frontend` | `frontend/` | React dashboard |
| `demo-web`, `demo-api`, `demo-db` | `demo-app/` | The "victim" multi-container app used to generate realistic normal + attack traffic for the demo |

---

## 8. Next Step

With this structure agreed, the next concrete step is freezing the event/alert schema (`PRD.md` Section 9) and API contract (`PRD.md` Section 10), then scaffolding the repo skeleton — `docker-compose.yml`, empty service folders with Dockerfiles, and the Postgres/Neo4j init scripts — so all components can be built in parallel from day one.

---

*End of Document*
