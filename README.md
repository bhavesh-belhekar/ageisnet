# AegisNet

AI-powered eBPF intrusion detection system for containerized & network environments.
A hybrid HIDS + NIDS that captures container network traffic at the kernel level with
eBPF and detects malicious activity. The final design (see `docs/PRD.md`) also adds ML
anomaly detection with SHAP explanations and a real-time dashboard — those are **not yet
built**; see Status below for what exists today.

See `docs/PRD.md`, `docs/ARCHITECTURE.md`, `docs/RULES.md`, `docs/PHASES.doc.md`.

## Prerequisites

- **Docker + Docker Compose v2** (all-service path)
- **Python 3.12** (local backend dev) and **Node 20+** (local frontend dev) — optional, only
  for the faster local-iteration loops below
- **Never commit `.env`** — copy the template and keep it local (it is git-ignored)

---

## Option A — Everything via Docker Compose (the demo path)

```bash
cp .env.example .env
docker compose up --build
```

This brings up all 10 services (`ebpf-agent`, `redis`, `postgres`, `neo4j`, `neo4j-init`,
`backend`, `frontend`, `demo-web`, `demo-api`, `demo-db`). `neo4j-init` is a one-shot helper
that applies the graph constraints after `neo4j` is healthy and then exits;
`docker-compose.override.yml` is merged automatically and exposes the ports below
(loopback-only) plus hot-reload mounts.

| What | Where |
|---|---|
| Backend API | `http://localhost:8000` — see `/api/health` |
| Frontend dashboard | `http://localhost:5173` *(scaffold only; UI lands in Phase 6)* |
| Postgres (override) | `localhost:5432` |
| Redis (override) | `localhost:6379` |
| Neo4j (override) | `http://localhost:7474` (bolt `localhost:7687`) |
| demo-web (override) | `http://localhost:8080` |
| demo-api (override) | `http://localhost:8081` |

To run only the infrastructure dependencies (and point a locally-run backend at them):

```bash
docker compose up -d postgres redis neo4j
```

---

## Option B — Backend in a local venv (faster dev loop)

Run tests and lint without rebuilding a container image:

```bash
cp .env.example .env
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
```

Set the dependency hosts to `localhost` when running against the dockerized infra above
(leave them as the service names if you only run in Compose):

```bash
# .env
POSTGRES_HOST=localhost
REDIS_HOST=localhost
NEO4J_HOST=localhost
```

Run the test suite (from the repo root):

```bash
pytest
```

> **Data-model note (`infra/postgres/init.sql`):** `events` and `alerts` are
> TimescaleDB hypertables, which only allow UNIQUE/PK indexes on the partitioning
> column (`timestamp`). Traditional PK/FK constraints would break the hypertable, so
> there are **no PKs/FKs** on those tables — instead, unique indexes on
> `(event_id, timestamp)` and `(alert_id, timestamp)` enforce identity, and
> referential integrity is enforced in the application layer (backend writes), not
> by the database. Don't "help" by adding FK constraints back.

Run lint/format gates (CI equivalent):

```bash
ruff check backend scripts
black --check backend scripts
```

Run the API server locally with hot reload (the `app` package lives under `backend/`
— `uvicorn` must start from there; settings resolve the repo-root `.env` no matter
the working directory):

```bash
cd backend
uvicorn app.main:app --reload --port 8000
```

Confirm: `curl http://localhost:8000/api/health` returns `200` once
postgres/redis/neo4j are healthy.

### Frontend local dev (optional)

```bash
cd frontend
npm install
npm run dev      # http://localhost:5173
```

Gates: `npm run typecheck`, `npm run lint`, `npm run format:check`.

---

## Status

**Through Phase 3 — Rule-Based Detection.** Phases 0 (contracts/scaffold), 1 (infra skeleton),
2 (eBPF socket-layer capture → Redis → Postgres), and 3 (rule engine + API + WS delivery)
are complete. Phase 4 (ML anomaly detection) onward is not yet started.

| Phase | What |
|---|---|
| 0 | Frozen event/alert schemas (`PRD.md` §9), repo scaffold, `docker-compose` |
| 1 | Infrastructure skeleton (all services up, no detection logic) |
| 2 | eBPF capture layer (kernel socket tracepoints + kprobes → Redis Streams) |
| 3 | Rule engine (T1043, T1046, T1071, T1571), risk scoring, REST API, WebSocket push |
| 4–8 | ML, SHAP explainability, MITRE mapper, dashboard, demo scripts, tuning |

---

## Verifying the System

### Health check

```bash
curl http://localhost:8000/api/health
# → {"status":"ok","checks":{"postgres":true,"redis":true,"neo4j":true}}
```

### Browse alerts

```bash
curl http://localhost:8000/api/alerts          # all alerts, newest first
curl "http://localhost:8000/api/alerts?severity=high"
curl "http://localhost:8000/api/alerts?container_id=5bf7a9363c99"
```

### Trigger a demo detection

Attack-scenario scripts exist as placeholders in `scripts/attack_scenarios/` (Phase 7);
the four rule types below can be reproduced manually with `docker compose` running.

**Prerequisites:** The backend's `data/threat_intel/known_bad_indicators.csv` ships two
TEST-NET IPs (unroutable). For RULE-001 live tests only, add a real reachable IP to the
CSV and restart the backend — remove it afterward (no rebuild required; the volume is
host-mounted, see `docker-compose.yml` backend service).

**Setup (demo containers already have basic networking tools):**

```bash
# Terminal 1 — start the known-bad port listener (RULE-002 / T1043)
docker exec -d aegisnet-demo-db-1 nc -l -p 445
```

```bash
# Terminal 2 — run the attack from demo-web
# 1) T1043: connect to known-bad port 445
# 2) T1046: scan 6 distinct service ports (threshold=5, 30s window)
# 3) T1571: connect to demo-db:5432 (not in demo-web's allowed_sources)
# 4) T1071: connect to known-bad IP (after adding it to the CSV)
docker exec aegisnet-demo-web-1 sh -c '
nc -z -w2 172.18.0.4 445
for dst in 172.18.0.3:7687 172.18.0.3:7474 172.18.0.5:6379 172.18.0.4:5432 172.18.0.8:80 172.18.0.9:8000; do
  ip=${dst%%:*}; port=${dst##*:}
  nc -z -w2 "$ip" "$port" 2>/dev/null || true
done
nc -z -w2 <KNOWN_BAD_IP> 8000
'
```

```bash
# Check results
curl http://localhost:8000/api/alerts | python3 -m json.tool
```

Expected output (example; alert IDs will differ):

| alert_id | mitre | severity | container | description |
|---|---|---|---|---|
| 1 | T1043 | medium | demo-web | Connection to known-bad port 445 |
| 2 | T1046 | high | demo-web | 5 distinct destination ports in 30s window |
| 3 | T1571 | high | demo-web | Lateral movement to demo-db:5432 |
| 4 | T1071 | high | demo-web | Known-bad IP in connection (dst) |
| 5 | T1071 | high | demo-api | Known-bad IP in connection (src, mirror) |

---

## How Alert Counts Work — Read Before Interpreting Data

### 4 events per connection

Each internal TCP connection produces **4 capture events** (open + close on both
endpoints), so a single connection can generate multiple alerts — one per rule that
fires, plus a mirror alert on the peer container when RULE-001's known-bad IP is one
endpoint. This is by design: the eBPF agent attributes each socket state transition to
its owning container.

### 15-second dedup window

To suppress the open/close duplication, the rule engine suppresses a second alert for
the same `(container, rule, destination)` within **15 seconds** (`ALERT_SUPPRESSION_SECONDS`
in `backend/app/rule_engine/engine.py`). One connection therefore produces at most
**one alert per rule per container**. This is a time-based simplification (not
4-tuple correlation) — see `docs/ARCHITECTURE.md` §3.3 for the tradeoff.

### Severity aggregation (FR-6)

When one event fires multiple rules, a config-driven `RiskScorer` (`backend/app/risk_scoring/scorer.py`)
combines them into a **single severity label per event**, which is assigned to every
alert generated by that event. A lone high-severity rule hit always stays high
(`hard_height_override` in `config/risk_policy.yaml`).
