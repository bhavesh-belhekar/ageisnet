# RULES.md
## AegisNet — Engineering Rules & Coding Standards

| | |
|---|---|
| **Status** | Draft v1.0 |
| **Applies to** | Everyone contributing code to this repo |
| **Companion docs** | `PRD.md`, `ARCHITECTURE.md` |

This document is the team's single source of truth for **what to use, what to avoid, which libraries/versions are approved, how to handle errors, and general engineering conventions** across every part of AegisNet. If a decision here conflicts with something in `ARCHITECTURE.md`, this file wins for implementation detail; `ARCHITECTURE.md` wins for structural/folder decisions.

---

## 1. General Rules (All Components)

### Use
- **Config-driven values** — thresholds, indicator lists, MITRE mappings, and any tunable number live in `config/*.yaml` or `.env`, never hardcoded in source.
- **Structured logging** (JSON logs) in every service, including a `container_id`/`request_id` field where relevant, so logs can be correlated across services during debugging.
- **Type hints everywhere in Python** (`def foo(x: int) -> str:`), and **TypeScript strict mode** in the frontend — no `any` without a documented reason.
- **`.env.example`** kept up to date any time a new environment variable is introduced — nobody should have to guess what variables exist.
- **Docstrings on every public function/class** in Python (one-line summary minimum; full docstring for anything non-obvious).

### Avoid
- Hardcoded IPs, ports, thresholds, or credentials anywhere in source code.
- `print()` for debugging in committed code — use the logger.
- Catching bare `except:` (Python) or swallowing errors silently in `catch {}` (JS/TS) — see Section 5.
- Committing secrets, `.env` files, trained model binaries, or datasets to git (see `.gitignore` rules, Section 7).
- Adding a new library "just because" — every new dependency must be justified against the approved list (Section 2) or explicitly discussed first.

---

## 2. Libraries & Dependencies (Approved List)

Pin exact versions in each service's `requirements.txt` / `package.json` — do not use floating versions (`>=`) for anything that touches detection logic, to keep results reproducible across the team. The version strings shown in the tables below (e.g., `fastapi==0.115.x`) are placeholders; each dependency's exact patch version is locked once chosen at Phase 0 (`PHASES.doc.md` §3).

### 2.1 `capture/ebpf-agent/`
| Purpose | Use | Avoid |
|---|---|---|
| eBPF development | `libbpf` + `bpftool` + CO-RE | BCC (only acceptable for throwaway prototyping, never in the final build — BCC requires clang/LLVM on every host, which we don't want as a runtime dependency) |
| Event publishing (Python loader) | `redis` (official `redis-py`, `>=5.0`) | Any unofficial/unmaintained Redis client forks |
| C build tooling | `clang`, `llvm`, `make` | Editing generated/vendored BPF skeleton headers by hand |

### 2.2 `backend/` (Python)
| Purpose | Use | Avoid |
|---|---|---|
| Web framework | `fastapi==0.115.x` | Flask, Django (inconsistent with async requirements — see PRD NFR on latency) |
| ASGI server | `uvicorn[standard]` | `gunicorn` alone without a Uvicorn worker class |
| Data validation | Pydantic v2 (ships with FastAPI) | Manual dict validation / untyped request bodies |
| ORM | `SQLAlchemy>=2.0` (async engine) | Raw SQL string concatenation (SQL-injection risk — always use parameterized queries or the ORM) |
| Postgres driver | `asyncpg` | `psycopg2` in async code paths (blocks the event loop) |
| Neo4j driver | `neo4j` official Python driver | Writing raw HTTP calls to Neo4j's REST API |
| Redis client | `redis-py>=5.0` (has native Streams support) | `redis-py` `<4.x` |
| ML — classical | `scikit-learn>=1.4` | Reimplementing Isolation Forest from scratch |
| ML — deep learning | `torch` (CPU build unless GPU is confirmed available), `torch_geometric` for the graph model | Mixing TensorFlow and PyTorch in the same service |
| Explainability | `shap` | Building custom feature-attribution logic instead of using SHAP's tested implementation |
| Config loading | `pydantic-settings` or plain `PyYAML` | `os.environ[...]` scattered through business logic — centralize in `config/settings.py` |
| Testing | `pytest`, `pytest-asyncio`, `httpx` (for async API test client) | `unittest` (inconsistent with the rest of the Python ecosystem choices here) |

### 2.3 `frontend/` (TypeScript/React)
| Purpose | Use | Avoid |
|---|---|---|
| Framework | `react@18.x` + `typescript@5.x` | Class components (use function components + hooks only) |
| Styling | TailwindCSS | Inline styles for anything reused more than once; avoid mixing CSS-in-JS libraries in |
| Graph visualization | `react-force-graph` or `d3` | Hand-rolled SVG physics simulation |
| Charts | `recharts` | Multiple charting libraries in the same app (pick one and stay consistent) |
| Data fetching | `fetch` wrapped in a thin typed client (`src/api/client.ts`), or `@tanstack/react-query` if caching/retry logic grows complex | Untyped `axios.get(url).then(...)` calls scattered across components |
| WebSocket | Native `WebSocket` API wrapped in a custom hook (`useAlertsSocket.ts`) | A heavy socket library when native WS is sufficient for one-directional push |

### 2.4 Infra
| Purpose | Use | Avoid |
|---|---|---|
| Time-series storage | PostgreSQL 16 + TimescaleDB extension | Rolling your own time-bucketing logic in application code |
| Event pipeline | Redis 7.x (Streams) | Redis Pub/Sub (no persistence/replay — Streams is required for our replay/training use case) |
| Graph storage | Neo4j 5.x Community Edition | Modeling the graph as adjacency-list rows in Postgres once Neo4j is available (defeats the purpose) |
| Containerization | Docker + Docker Compose v2 | `docker-compose` v1 syntax (`version:` key is deprecated in Compose v2 — omit it) |

---

## 3. What to Use vs. Avoid, By Concern

### 3.1 Security of the System Itself
- **Use:** parameterized queries, input validation via Pydantic models on every API endpoint, least-privilege container capabilities (only the `ebpf-agent` container should run privileged/with `CAP_BPF`, `CAP_NET_ADMIN` — nothing else should).
- **Avoid:** running the FastAPI backend, frontend, or database containers as privileged or root; exposing Neo4j's default credentials in a running demo; leaving Redis unauthenticated on a network-reachable port if the demo isn't fully local.

### 3.2 Data Correctness
- **Use:** a single, frozen event/alert schema (`PRD.md` Section 9) validated via Pydantic on ingestion — any event that fails schema validation is logged and dropped, not silently coerced.
- **Avoid:** letting each service define its own slightly-different version of the `Event`/`Alert` shape — schema drift between the eBPF agent, backend, and frontend is the single most likely source of integration bugs.

### 3.3 ML Reproducibility
- **Use:** fixed random seeds during training (`random_state=42` or similar) for Isolation Forest / any stochastic model, and version-tag saved model artifacts (`flow_model_v1.pkl`) rather than overwriting one file.
- **Avoid:** retraining models silently as part of the normal request path — training is a separate, explicit step (`scripts/retrain_models.py`), never triggered automatically inside `ml_engine/infer.py`.

### 3.4 Performance
- **Use:** batching where possible when writing to Postgres/Neo4j (don't do a DB round-trip per single event under load); async I/O throughout the backend.
- **Use:** SHAP computation must never block the alert delivery path — the alert is persisted and pushed to the dashboard immediately with its severity/description, and the SHAP breakdown is computed asynchronously afterward and attached via a follow-up update (the <2s latency NFR covers detection visibility, not full explainability, per `PRD.md` FR-7.3/FR-11.2).
- **Avoid:** synchronous blocking calls (e.g., `requests` library, `psycopg2`) inside `async def` route handlers or consumers — this silently kills the concurrency FastAPI is chosen for.

---

## 4. Error Handling

### 4.1 General Principle
Every error must be **caught at the right layer, logged with context, and either recovered from or surfaced clearly** — never silently swallowed, and never allowed to crash a whole service over one bad event.

### 4.2 `capture/ebpf-agent/`
- If an eBPF program fails to load (e.g., unsupported kernel feature), the agent must log a clear, actionable error (which hook, which kernel requirement) and exit non-zero — don't let it start "half-working."
- If publishing an event to Redis fails (e.g., Redis temporarily unreachable), retry with exponential backoff (max ~5 retries) before dropping the event and logging a `WARNING` with the dropped event's summary (not the full payload, to avoid log bloat).

### 4.3 `backend/`
- **Per-event processing errors:** If one event fails during rule/ML processing (e.g., malformed data, model inference exception), catch it at the consumer level, log the full event + stack trace at `ERROR`, and continue processing the next event. **One bad event must never stop the consumer loop.**
- **API layer:** Use FastAPI's exception handlers to return consistent JSON error responses:
  ```json
  { "error": "not_found", "message": "Alert with id xyz not found" }
  ```
  Never leak raw stack traces or internal exception messages to API responses — log the detail server-side, return a clean message client-side.
- **Database errors:** Wrap DB calls in `try/except` at the repository layer only (not scattered through business logic); on connection failure, retry once, then raise a typed `DatabaseUnavailableError` that the API layer converts to a `503`.
- **ML model load failures:** If a model file is missing/corrupt at startup, the backend should still start (rule engine keeps working), but log a `CRITICAL` error and mark `/api/health` as degraded — don't let a missing ML model take down rule-based detection.

### 4.4 `frontend/`
- Every API call and WebSocket handler must have a visible failure state in the UI (e.g., "Connection lost, retrying…") — never fail silently and just show a blank feed.
- WebSocket disconnects must trigger an automatic reconnect with backoff, not require a page refresh.
- Use an error boundary at the top level of the React app so one component crashing doesn't blank the entire dashboard.

### 4.5 Cross-Cutting
- **Never use exceptions for expected control flow** (e.g., don't raise-and-catch to check "does this alert exist" — query first, branch on the result).
- **Always include context in logs:** which container, which event ID, which rule/model — a bare `"Error processing event"` with no identifiers is not acceptable.
- **Fail loudly in development, gracefully in the demo path:** during development/tests, prefer to raise and see the full trace; in the running demo pipeline, prefer to log-and-continue so a single bad event doesn't kill a live demo.

---

## 5. Code Style & Review Rules

- **Python:** formatted with `black`, linted with `ruff`; no PR merges with lint errors.
- **TypeScript:** formatted with `prettier`, linted with `eslint`; strict mode on.
- **Commit messages:** `type(scope): short description` (e.g., `feat(rule_engine): add restricted-port rule`), matching Conventional Commits style — makes it easy to scan history by component.
- **No direct commits to `main`** — every change goes through a branch + PR, even solo, so the team has a reviewable history for the final report.
- **Every new feature/rule/model needs a test** before merging — no exceptions for "I'll add tests later."

---

## 6. Configuration & Secrets

- All secrets (DB passwords, API keys) go in `.env`, which is git-ignored; `.env.example` documents every required variable with a placeholder value.
- No environment-specific values (like `localhost` vs a Docker service name) hardcoded — always read from config/env so the same code runs in Compose and in local dev.

---

## 7. `.gitignore` Rules (Must-Haves)

```
.env
data/model_artifacts/*.pkl
data/model_artifacts/*.pt
data/training_baselines/*.csv
node_modules/
__pycache__/
*.pyc
.venv/
dist/
build/
```

Only small, checked-in **fixture** files (e.g., a tiny sample `known_bad_indicators.csv` for tests) are exempt — real/large datasets and trained models are never committed.

---

## 8. General Rules Checklist (Before Opening a PR)

- [ ] No hardcoded values that belong in config
- [ ] No `print()` / bare `except:` / swallowed errors
- [ ] New dependency (if any) is justified and added to the approved list in this document
- [ ] Errors are logged with context, not silently dropped
- [ ] Tests added/updated for the change
- [ ] `.env.example` updated if new env vars were introduced
- [ ] Lint/format checks pass

---

*End of Document*
