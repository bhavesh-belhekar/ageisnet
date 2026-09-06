# AegisNet

AI-powered eBPF intrusion detection system for containerized & network environments.
Hybrid HIDS + NIDS that captures container network traffic at the kernel level with eBPF,
scores it with rule-based + ML anomaly detection, explains ML alerts with SHAP, and tags
everything with MITRE ATT&CK — all surfaced in a real-time React dashboard.

See `docs/PRD.md`, `docs/ARCHITECTURE.md`, `docs/RULES.md`, and `docs/PHASES.doc.md`.

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

This brings up all 9 services (`ebpf-agent`, `redis`, `postgres`, `neo4j`, `backend`,
`frontend`, `demo-web`, `demo-api`, `demo-db`). `docker-compose.override.yml` is merged
automatically and exposes the ports below (loopback-only) plus hot-reload mounts.

| What | Where |
|---|---|
| Backend API | `http://localhost:8000` — see `/api/health` |
| Frontend dashboard | `http://localhost:5173` |
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

Phase 1 — Infrastructure Skeleton. All services run as stubs; detection, ML, eBPF
capture, and dashboard logic land in later phases (see `docs/PHASES.doc.md`).