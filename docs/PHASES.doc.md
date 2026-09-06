# PHASES.doc.md
## AegisNet — Phased Build & Execution Plan

| | |
|---|---|
| **Status** | Draft v1.0 |
| **Companion docs** | `PRD.md` (requirements), `ARCHITECTURE.md` (structure), `RULES.md` (engineering standards) |

**Important distinction:** `PRD.md` and `ARCHITECTURE.md` describe AegisNet as **one complete, integrated end-to-end system** — that is the final deliverable, not a staged product. This document is different: it's the **internal execution plan** for *how the team builds that single system* in a sensible, low-risk order. Nothing here changes scope — every phase below is building toward the same one final pipeline described in the PRD.

---

## 1. Why Phase the Build (But Not the Product)

Building eBPF capture, an event pipeline, a rule engine, two ML models, SHAP, and a live dashboard all at once, with no intermediate checkpoints, is high-risk — if one piece stalls, you don't know until the very end. So we build in dependency order, with each phase producing something **testable and demonstrable on its own**, even though the *user-facing product* is only "done" once every phase is integrated.

Think of it like constructing a building: you don't show tenants a "Phase 1 building" — but you absolutely pour the foundation before framing walls, and you check each stage before moving to the next.

---

## 2. Phase Overview

| Phase | Name | Primary Owner Area | Depends On |
|---|---|---|---|
| 0 | Foundations & Contracts | Whole team | — |
| 1 | Infrastructure Skeleton | DevOps/Backend | Phase 0 |
| 2 | eBPF Capture Layer | Systems/eBPF | Phase 1 |
| 3 | Rule-Based Detection | Backend | Phase 1 (can start parallel to Phase 2 using mock events) |
| 4 | ML Anomaly Detection | ML | Phase 1, 3 |
| 5 | Explainability & MITRE Mapping | ML/Backend | Phase 4 |
| 6 | Dashboard | Frontend | Phase 1 (can start parallel using mock API) |
| 7 | Demo Environment & Attack Scenarios | Whole team | Phase 1 |
| 8 | Integration, Tuning & Final Testing | Whole team | All above |

---

## 3. Phase 0 — Foundations & Contracts

**Goal:** Lock down the shared agreements so every other phase can proceed in parallel without integration surprises.

**Tasks:**
- [ ] Freeze the `Event` and `Alert` schema (`PRD.md` Section 9) — no changes without team sign-off after this point.
- [ ] Freeze the API contract skeleton (`PRD.md` Section 10).
- [ ] Confirm the risk-scoring policy shape (`config/risk_policy.yaml` fields, even if thresholds are placeholder).
- [ ] Confirm the MITRE mapping table skeleton (`config/mitre_mapping.yaml`).
- [ ] Assign phase ownership across the team (who owns eBPF, ML, backend, frontend).
- [ ] Set up the git repo, branch strategy, and CI lint/test checks per `RULES.md` Section 5.

**Deliverable:** A written, agreed-upon schema + API contract that every subsequent phase treats as ground truth.

**Exit criteria:** Everyone on the team can describe, without checking docs, what fields are on an `Event` and an `Alert`.

---

## 4. Phase 1 — Infrastructure Skeleton

**Goal:** Get every service running (even empty/stubbed) via one `docker-compose up`.

**Tasks:**
- [ ] `docker-compose.yml` with all services defined: `ebpf-agent`, `redis`, `backend`, `postgres`, `neo4j`, `frontend`, `demo-web`, `demo-api`, `demo-db`.
- [ ] Postgres schema + TimescaleDB hypertable setup (`infra/postgres/init.sql`).
- [ ] Neo4j constraints/indexes setup (`infra/neo4j/init.cypher`).
- [ ] Redis container running with Streams enabled.
- [ ] Basic FastAPI app that starts and responds on `/api/health`.
- [ ] Basic React app that starts and shows a placeholder page.
- [ ] `.env.example` covering every service's config.

**Deliverable:** `docker-compose up` brings up all 9 services with no crash loops.

**Exit criteria:** `/api/health` returns 200; Postgres/Neo4j/Redis are reachable from the backend container; frontend loads in a browser.

---

## 5. Phase 2 — eBPF Capture Layer

**Goal:** Real kernel-level events flow into Redis.

**Tasks:**
- [x] Prototype capture using a scriptable eBPF frontend (bpftrace; BCC-family tooling was the initial suggestion — bpftrace chosen for iteration speed) to validate the approach on the dev machine.
- [x] Port the validated logic to `libbpf` + CO-RE for the actual build (per `RULES.md` Section 2.1) — **L3 parity smoke passed 2026-09-06**.
- [x] Implement the capture hook for internal (container-to-container) and external (container-to-internet) traffic.
- [x] Implement `loader/load_and_publish.py` — builds and spawns the CO-RE capture binary, reads captured events, maps them to the frozen `Event` schema, publishes to Redis Streams.
- [x] Attribute each event to a container ID (socket-owner netns via CO-RE `skc_net` → cgroup lookup).
- [x] Add retry/backoff for Redis publish failures per `RULES.md` Section 4.2 (exponential backoff, max ~5 retries, drop + `WARNING` with event summary).

**Deliverable:** Running `docker-compose up`, generating traffic between two demo containers produces real events visible in the Redis stream (verify with `redis-cli XRANGE`).

**Exit criteria:** A manual `curl` or `nc` connection between two demo containers shows up as an `Event` in Redis within ~1 second, with correct container attribution.

**Risk flag:** This is the highest-risk phase (see `PRD.md` Section 13). If it stalls, Phase 3 can continue independently using a temporary mock event publisher that writes directly to Redis in the correct schema — this unblocks downstream work without changing final scope.

**Note (Phase 2 sign-off, 2026-09-06):** Per-event shape for Phase 3 —
the final libbpf + CO-RE capture emits **4 events per internal TCP
connection**: client open, server open (both 0/0), client close, server
close (each with the socket-owner byte totals). The bpftrace prototype
used for Phase 2 validation emits only **3** (the server-side OPEN is
silently dropped because its ESTABLISHED transition races `accept()` and
attribution falls back to execution context). Any Phase 3 rule-engine
test fixtures / mock event publishers **must be built against the
4-event CO-RE shape**, not the 3-event prototype shape, so consumers are
not surprised by the extra server open later. Correlation field values
and the frozen schema are unchanged (see `PRD.md` Section 9).

---

## 6. Phase 3 — Rule-Based Detection

**Goal:** Events consumed from Redis are checked against rules and produce alerts.

**Tasks:**
- [ ] Implement `backend/app/consumers/event_consumer.py` — reads from Redis Streams.
- [ ] Implement `rule_engine/indicators.py` — loads known-bad IP/domain list, known-bad ports, restricted-port config.
- [ ] Implement `rule_engine/engine.py` — evaluates all rule categories per event.
- [ ] Implement `risk_scoring/scorer.py` — combines rule hits into a severity (ML integration comes in Phase 4).
- [ ] Implement `models/event.py`, `models/alert.py`, and DB writes to Postgres.
- [ ] Implement `api/alerts.py` and `api/events.py` GET endpoints.
- [ ] Implement `ws/alerts_ws.py` WebSocket push on new alert.
- [ ] Write unit tests for each rule category per `RULES.md` Section 8 checklist.

**Deliverable:** A known-bad-IP connection (real or mocked event) produces a stored alert retrievable via `/api/alerts` and pushed via WebSocket.

**Exit criteria:** All rule-engine unit tests pass; a manual end-to-end trigger (real or scripted) produces a visible alert record.

---

## 7. Phase 4 — ML Anomaly Detection

**Goal:** Add the anomaly-detection layer alongside rules.

**Tasks:**
- [ ] Collect/generate baseline "normal" traffic data (`data/training_baselines/`) from the demo environment running quietly for a period.
- [ ] Implement `ml_engine/flow_model/features.py` — extract features (byte volume, frequency, port entropy, timing) per event.
- [ ] Implement `ml_engine/flow_model/train.py` and `infer.py` — Isolation Forest trained on baseline, scoring new events.
- [ ] Implement `ml_engine/graph_model/graph_diff.py` — heuristic "never-seen-edge" detector against the Neo4j graph (start here; upgrade to a GNN/autoencoder only if time allows, per `PRD.md` Section 13 risk mitigation).
- [ ] Wire both models into the event-processing pipeline in `event_consumer.py`, running alongside `rule_engine`.
- [ ] Update `risk_scoring/scorer.py` to combine rule + ML output (max severity logic per `RULES.md`/`PRD.md` FR-6).
- [ ] Persist trained model artifacts with version tags (`data/model_artifacts/flow_model_v1.pkl`).

**Deliverable:** A synthetic anomaly (e.g., unusual data volume spike, or a new container-to-container edge) produces an ML-flagged alert distinct from any rule hit.

**Exit criteria:** Both `flow_model` and `graph_model` produce non-trivial anomaly scores on injected test anomalies, and a reasonable false-positive rate (<10% target) on clean baseline traffic.

---

## 8. Phase 5 — Explainability & MITRE Mapping

**Goal:** Every ML-flagged alert is explainable and technique-tagged; every alert (rule or ML) has a MITRE tag.

**Tasks:**
- [ ] Implement `explainability/shap_explainer.py` — compute SHAP values for `flow_model` predictions (and `graph_model` if using a trained model rather than the heuristic).
- [ ] Attach the top contributing features + weights to the `Alert` record (`shap_explanation` JSON field).
- [ ] Implement `mitre_mapper/mapper.py` reading `config/mitre_mapping.yaml`, applied to both rule hits and ML hits.
- [ ] Extend `api/alerts.py` `/api/alerts/{id}` to return the full SHAP breakdown.

**Deliverable:** Querying any ML-flagged alert returns a human-readable feature breakdown; every alert has a MITRE technique ID.

**Exit criteria:** 100% of ML-flagged alerts in test runs have a non-null SHAP explanation (per `PRD.md` FR-11 and Success Metrics).

---

## 9. Phase 6 — Dashboard

**Goal:** A human can see and understand what the system is detecting, live.

**Tasks:**
- [ ] Implement `hooks/useAlertsSocket.ts` — WebSocket connection with auto-reconnect (per `RULES.md` Section 4.4).
- [ ] Implement `components/AlertFeed/` — real-time + historical list, filterable by severity/container.
- [ ] Implement `components/NetworkGraph/` — live container graph, color-coded by risk (can start with mock data from `/api/graph` before Phase 4/5 are fully done).
- [ ] Implement `components/AlertDetail/` and `components/ShapExplanationPanel/`.
- [ ] Wire up `api/client.ts` typed API client.
- [ ] Add loading/error/reconnect states per `RULES.md` Section 4.4.

**Deliverable:** A judge/professor can open the dashboard and understand an incoming alert within 10 seconds without explanation (per `PRD.md` Goals table).

**Exit criteria:** Dashboard correctly renders live alerts, the network graph, and SHAP panels using real backend data (not mocks) by the end of this phase.

---

## 10. Phase 7 — Demo Environment & Attack Scenarios

**Goal:** A repeatable, scriptable way to demonstrate every detection type.

**Tasks:**
- [ ] Build `demo-app/` — simple `web` + `api` + `db` containers with realistic normal traffic between them.
- [ ] Implement `scripts/seed_demo_data.py` — populate a baseline learning period of normal traffic.
- [ ] Implement `scripts/attack_scenarios/port_scan.py`, `known_bad_ip.py`, `beaconing.py`, `lateral_movement.py`, `exfiltration.py`.
- [ ] Implement `scripts/run_attack_scenario.sh` — one-command trigger for live demo.

**Deliverable:** Running one script produces a visible, correctly-classified alert on the dashboard for each attack type in `PRD.md`'s exit criteria (Section 5).

**Exit criteria:** All 5 attack types (port scan, known-bad IP, lateral movement, beaconing, exfiltration) are demonstrable via scripted trigger with correct detection, severity, and MITRE tag.

---

## 11. Phase 8 — Integration, Tuning & Final Testing

**Goal:** The whole system works together, reliably, within the success metrics.

**Tasks:**
- [ ] Run the full attack-scenario suite end-to-end and record actual detection latency (target: <2 seconds, per `PRD.md` NFR).
- [ ] Tune `risk_policy.yaml` thresholds to hit the <10% false-positive target on clean baseline traffic.
- [ ] Load-test the Redis pipeline (target: 500 events/sec for 30 seconds without drops, per `PRD.md` NFR).
- [ ] Fix any schema drift or integration bugs surfaced during full-system testing.
- [ ] Final pass on `RULES.md` checklist across the whole codebase (lint, tests, no hardcoded values, `.env.example` current).
- [ ] Prepare the final report, referencing `PRD.md`'s Success Metrics table with actual measured results.

**Deliverable:** The complete AegisNet system, meeting every metric in `PRD.md` Section 12, ready for submission/demo.

**Exit criteria:** All items in `PRD.md` Section 12 (Success Metrics) are met and recorded with actual measured numbers.

---

## 12. Parallelization Guide

To keep the team unblocked, here's what can run in parallel once Phase 0 is done:

| Can start immediately after Phase 0/1 | Depends on another phase finishing first |
|---|---|
| Phase 2 (eBPF) — independent, but highest risk, start early | Phase 4 (ML) needs Phase 3's event flow working, or at least mock events |
| Phase 3 (Rules) — can use a mock event publisher if Phase 2 is delayed | Phase 5 (Explainability) needs Phase 4's ML models producing scores |
| Phase 6 (Dashboard) — can build against a mocked/stubbed API first | Phase 8 (Integration) needs everything else done |
| Phase 7 (Demo app) — independent, build anytime after Phase 1 | |

**Golden rule:** nobody should be blocked waiting on eBPF (Phase 2) specifically — every other phase has a path to start with mocked data conforming to the Phase 0 schema.

---

## 13. Phase Checklist Summary

- [ ] Phase 0 — Foundations & Contracts
- [ ] Phase 1 — Infrastructure Skeleton
- [ ] Phase 2 — eBPF Capture Layer
- [ ] Phase 3 — Rule-Based Detection
- [ ] Phase 4 — ML Anomaly Detection
- [ ] Phase 5 — Explainability & MITRE Mapping
- [ ] Phase 6 — Dashboard
- [ ] Phase 7 — Demo Environment & Attack Scenarios
- [ ] Phase 8 — Integration, Tuning & Final Testing

---

*End of Document*
