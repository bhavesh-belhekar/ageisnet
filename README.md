# AegisNet

AI-powered eBPF intrusion detection system for containerized & network environments.
Hybrid HIDS + NIDS that captures container network traffic at the kernel level with eBPF,
scores it with rule-based + ML anomaly detection, explains ML alerts with SHAP, and tags
everything with MITRE ATT&CK — all surfaced in a real-time React dashboard.

See `docs/PRD.md`, `docs/ARCHITECTURE.md`, `docs/RULES.md`, and `docs/PHASES.doc.md`.

## Quickstart

```bash
cp .env.example .env
docker compose up --build
```

Bring up all 9 services (ebpf-agent, redis, backend, postgres, neo4j, frontend,
demo-web, demo-api, demo-db). For local-dev conveniences (exposed ports, hot reload),
`docker-compose.override.yml` is merged automatically by `docker compose`.

| What | Where |
|---|---|
| Backend API | `http://localhost:8000` — see `/api/health` |
| Frontend dashboard | `http://localhost:5173` |
| Postgres (override) | `localhost:5432` |
| Redis (override) | `localhost:6379` |
| Neo4j (override) | `http://localhost:7474` (bolt `localhost:7687`) |

## Status

Phase 1 — Infrastructure Skeleton. All services run as stubs; detection, ML, eBPF
capture, and dashboard logic land in later phases (see `docs/PHASES.doc.md`).