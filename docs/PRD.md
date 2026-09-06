# Product Requirements Document (PRD)
## AegisNet — AI-Powered eBPF Intrusion Detection System for Containerized & Network Environments

| | |
|---|---|
| **Document Owner** | [Your Name / Team] |
| **Status** | Draft v1.0 |
| **Last Updated** | [Date] |
| **Course / Project** | [Course Name] |

---

## 1. Overview

AegisNet is a hybrid Host-based + Network-based Intrusion Detection System (HIDS + NIDS) for Docker container environments. It monitors network traffic at the Linux kernel level using eBPF, combines rule-based detection with machine-learning anomaly detection, and explains every ML-flagged alert using SHAP — all surfaced through a real-time React dashboard.

This PRD defines **what** we are building end-to-end, **for whom**, and **how we'll know it's working** — as a single, complete pipeline rather than incremental phases.

---

## 2. Problem Statement

Applications running in Docker containers are vulnerable to compromise (malicious shells, lateral movement between containers, data exfiltration). Traditional Network IDS tools (Snort, Suricata) only see traffic at the network perimeter and cannot see container-to-container (east-west) traffic, nor attribute suspicious behavior to a specific container. Existing eBPF-native tools (Falco, Tetragon, Tracee) are purely rule/signature-based and cannot catch novel/unknown attack patterns, nor explain their alerts.

**AegisNet's job:** close this gap by monitoring both directions of container network traffic at the kernel level, layering ML-based anomaly detection on top of rules, and explaining every ML alert — as one complete, always-on pipeline from kernel to dashboard.

---

## 3. Goals

| Goal | Metric |
|---|---|
| Detect known network-based container attacks | Rule engine catches 100% of test-suite signature-based attacks (port scan, known-bad IP, etc.) |
| Detect unknown/novel anomalies | ML models flag injected synthetic anomalies not covered by rules, at an acceptable false-positive rate (target: <10% on test dataset) |
| Detect lateral movement | System flags 100% of simulated "new/unexpected container-to-container connection" test cases |
| Real-time alerting | Alert appears on dashboard within 2 seconds of the triggering event (demo environment) |
| Explainability | Every ML-flagged alert has an attached SHAP feature breakdown |
| Usability | A judge/professor unfamiliar with the system can understand an alert (what happened, why, how severe) within 10 seconds of viewing the dashboard |

### Non-Goals (out of scope)
- Kubernetes-native deployment (Docker Compose only for this project)
- Automated response/blocking of traffic (detection only, no enforcement)
- Multi-host/distributed cluster monitoring (single Docker host only)
- Production-grade high availability, horizontal scaling, or multi-tenant support
- Coverage of non-network attack vectors (file-integrity, syscall-level exploits) — explicitly excluded per the project's network-security focus

---

## 4. Target Users / Personas

| Persona | Need |
|---|---|
| **Course evaluator / professor** | Wants to see a working, demoable system that reflects real security engineering concepts (NIDS, MITRE ATT&CK, ML, XAI) |
| **SOC analyst (simulated persona for demo)** | Wants alerts they can trust, understand, and act on quickly — not black-box scores |
| **Project team (you)** | Needs one complete, working pipeline built end-to-end and demoed as a single system |

---

## 5. Scope — Full End-to-End System

AegisNet is built as **one complete pipeline**, all components delivered together rather than staged:

- **Capture:** Real eBPF-based event capture from day one — TC hooks for internal (east-west) container-to-container traffic, XDP for external (north-south) container-to-internet traffic.
- **Pipeline:** Redis Streams buffering events between capture and the detection engine.
- **Detection Engine:** Rule-based signature matching + ML-based anomaly detection (flow model for external traffic, graph model for the internal communication graph) running together on every event.
- **Risk Scoring:** Combined rule + ML output into a single Low/Medium/High severity score.
- **Explainability:** SHAP-based feature breakdown attached to every ML-flagged alert.
- **MITRE ATT&CK Mapping:** Every detection tagged with a real-world technique ID.
- **Storage:** PostgreSQL/TimescaleDB for events and alerts, Neo4j for the live container communication graph.
- **Real-Time Delivery:** WebSocket push of new alerts to the dashboard.
- **Dashboard:** React app showing the live network graph, real-time alert feed, and SHAP explanation panel — all present in the same build.
- **Test Environment:** Docker Compose multi-container setup (web + API + DB) to generate realistic normal and attack traffic for the demo.

**Exit criteria for the project as a whole:** A simulated attack suite — port scan, known-bad-IP connection, lateral movement attempt, beaconing, and data exfiltration spike — is run against the live Docker Compose environment, and every case is correctly captured by eBPF, scored (via rule and/or ML), explained (if ML-flagged), tagged with a MITRE technique, stored, and displayed on the dashboard within 2 seconds — end to end, in one pass.

---

## 6. Functional Requirements

### FR-1: eBPF-Based Network Event Capture
- FR-1.1: System shall capture container network events (connection open/close, bytes sent/received, port, protocol, destination) at the kernel level using eBPF.
- FR-1.2: Capture shall be attributable to a specific container (via cgroup/container ID).
- FR-1.3: Capture shall cover both internal (container-to-container, via TC hooks) and external (container-to-internet, via XDP) traffic simultaneously.

### FR-2: Container Communication Graph (East-West)
- FR-2.1: System shall build and continuously update a graph of container-to-container connections observed over a rolling learning window (default: 24 hours; config-driven).
- FR-2.2: System shall flag any new edge (container pair or port never seen before) that appears after the learning window as a candidate anomaly.
- FR-2.3: Dashboard shall visualize the current graph with anomalous edges highlighted.

### FR-3: External Traffic Monitoring (North-South)
- FR-3.1: System shall track per-container outbound connections: destination IP/domain, port, frequency, volume.
- FR-3.2: System shall detect port-scanning patterns (many distinct ports contacted in a short window from one container), implemented in the rule engine as a stateful sliding-window rule (see `ARCHITECTURE.md` §3.3) — not in the ML flow model.
- FR-3.3: System shall detect beaconing patterns (regular time-interval connections to the same destination).
- FR-3.4: System shall detect volume-based exfiltration spikes (outbound data volume significantly above a container's learned baseline).

### FR-4: Signature/Rule-Based Detection
- FR-4.1: System shall maintain a list of known-malicious IPs/domains (static list for this project; live threat-intel feed integration optional/stretch).
- FR-4.2: Any traffic matching a rule shall generate an alert immediately, independent of the ML pipeline.

### FR-5: ML-Based Anomaly Detection
- FR-5.1: System shall train an Isolation Forest (or equivalent) model on baseline external traffic features per container, aggregated over a 5-minute rolling window (config-driven).
- FR-5.2: System shall train a graph-based anomaly model (heuristic graph-diff, or a GNN/autoencoder if timeline allows) on the container communication graph.
- FR-5.3: Both models shall output a continuous anomaly score (not just binary flag).

### FR-6: Risk / Severity Scoring
- FR-6.1: System shall combine rule-engine hits and ML anomaly scores into a single Low/Medium/High severity label per event.
- FR-6.2: Scoring logic shall be config-driven (e.g., a YAML policy file), not hardcoded, so thresholds can be tuned without code changes. Initial values in the policy file are placeholders — finalized during Phase 4, tuned during Phase 8.

### FR-7: Real-Time Alerts
- FR-7.1: Every rule/ML hit — including Low severity — shall create an `Alert` record for the audit trail.
- FR-7.2: Only alerts scoring at or above the Medium threshold shall be pushed to the dashboard via WebSocket in real time, within 2 seconds of the triggering event.
- FR-7.3: The real-time push shall carry the alert's severity and description immediately; the SHAP explanation (FR-11) is computed asynchronously afterward and attached via a follow-up update.

### FR-8: React Web Dashboard
- FR-8.1: Dashboard shall show a real-time alert feed (container, timestamp, activity description, severity, MITRE ATT&CK tag).
- FR-8.2: Dashboard shall show a live container communication graph, color-coded by risk.
- FR-8.3: Dashboard shall show a SHAP explanation panel per ML-flagged alert.
- FR-8.4: Dashboard shall allow filtering alerts by severity and by container.

### FR-9: Backend (Python/FastAPI)
- FR-9.1: Backend shall expose a REST API for historical alert/event queries.
- FR-9.2: Backend shall expose a WebSocket endpoint for real-time alert push.
- FR-9.3: Backend shall run detection logic (rules + ML) on each incoming event before storage.

### FR-10: Database
- FR-10.1: System shall persist all raw events and all generated alerts with timestamps.
- FR-10.2: System shall persist the container communication graph history (for graph-diffing over time).

### FR-11: Explainable AI (SHAP)
- FR-11.1: For every ML-flagged alert, system shall compute and store the top contributing features and their weighted contribution.
- FR-11.2: SHAP computation shall run asynchronously — the alert is pushed to the dashboard immediately with its severity/description, and the SHAP breakdown is attached to the alert via a follow-up update once computed. The <2s latency NFR applies to detection visibility, not full explainability.

### FR-12: MITRE ATT&CK Mapping
- FR-12.1: Each detection type shall map to a documented MITRE ATT&CK technique ID, stored alongside the alert.

---

## 7. Non-Functional Requirements

| Category | Requirement |
|---|---|
| **Performance** | eBPF capture overhead should not exceed ~5% additional CPU on the monitored host during normal load |
| **Latency** | Alert generation-to-dashboard-display latency < 2 seconds under demo-scale traffic (applies to detection visibility — the alert with severity/description; the asynchronous SHAP explanation may follow later) |
| **Reliability** | Event pipeline (Redis Streams) must not drop events during a simulated traffic burst (e.g., 500 events/sec for 30 seconds) |
| **Usability** | Dashboard must be understandable without a manual — severity, container, and reason must be visible without extra clicks |
| **Maintainability** | Detection rules and risk-scoring thresholds must be config-driven, not hardcoded, so they can be tuned without code changes |
| **Reproducibility** | The entire system (all containers + services) must be startable via a single `docker-compose up` command |

---

## 8. System Architecture (Reference)

See the accompanying `ARCHITECTURE.md` for the full end-to-end pipeline design and folder structure:

Docker Host → eBPF (TC + XDP) → Event Pipeline (Redis Streams) → FastAPI Backend (Rule Engine + ML Engine + Risk Scoring + SHAP + MITRE Mapper) → Storage (PostgreSQL/TimescaleDB + Neo4j) → WebSocket → React Dashboard.

---

## 9. Data Model (High-Level)

**Event** (raw, from eBPF)
```
event_id, container_id, timestamp, src_ip, dst_ip, src_port, dst_port,
protocol, bytes_sent, bytes_received, direction (internal/external)
```

**Alert**
```
alert_id, event_id (FK), container_id, timestamp, detection_type (rule/ml),
severity (low/medium/high), mitre_technique_id, description,
shap_explanation (nullable, JSON), acknowledged (bool)
```

**ContainerGraphEdge** (Neo4j)
```
(:Container {id, name})-[:CONNECTS_TO {port, protocol, first_seen, last_seen, is_anomalous}]->(:Container)
```

**ThreatIntelEntry**
```
indicator (ip/domain), type, source, added_date
```

---

## 10. API Contract (High-Level — to be detailed during implementation)

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/events` | GET | List/query raw events (filterable by container, time range) |
| `/api/alerts` | GET | List/query alerts (filterable by severity, container, time range) |
| `/api/alerts/{id}` | GET | Full alert detail including SHAP explanation |
| `/api/alerts/{id}/ack` | PATCH | Set the alert's `acknowledged` flag |
| `/api/graph` | GET | Current container communication graph snapshot |
| `/ws/alerts` | WebSocket | Real-time alert push stream |
| `/api/health` | GET | Service health check |

---

## 11. Technology Stack

See `ARCHITECTURE.md` and the Project Proposal document (Section 6) for the full tech stack table with alternatives and justification. Summary:

- **Capture:** eBPF (libbpf/CO-RE), TC hooks + XDP
- **Pipeline:** Redis Streams
- **Backend:** Python + FastAPI
- **Storage:** PostgreSQL + TimescaleDB, Neo4j
- **ML:** Scikit-learn (Isolation Forest), PyTorch (GNN/Autoencoder or heuristic graph-diff)
- **Explainability:** SHAP
- **Frontend:** React + TypeScript + TailwindCSS
- **Real-time delivery:** WebSockets
- **Test environment:** Docker Compose

---

## 12. Success Metrics (for Demo/Submission)

| Metric | Target |
|---|---|
| End-to-end pipeline runs without manual intervention | Yes/No |
| Known attack (rule-based) correctly detected | 100% of test cases |
| Simulated lateral movement correctly detected | 100% of test cases |
| Simulated external anomaly (beaconing/exfil) correctly detected | ≥80% of test cases |
| False-positive rate on normal baseline traffic | <10% |
| SHAP explanation present on every ML alert | 100% |
| Dashboard alert latency | <2 seconds |

---

## 13. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| eBPF development complexity/learning curve | High | Start with BCC (easier prototyping) before optimizing to libbpf+CO-RE; budget dedicated research time early since the whole pipeline depends on this working |
| GNN implementation too complex for course timeline | Medium | Fall back to a simpler heuristic graph-diff (flag any never-seen edge) if GNN training doesn't converge in time |
| Redis Streams becomes a bottleneck or single point of failure under heavy demo load | Low | Redis Streams' throughput is more than sufficient for a single-host course-project demo scale; consumer groups can be added if replay/parallel consumption is needed later |
| ML models produce too many false positives on demo data | Medium | Use a controlled, small demo dataset with clearly-separable normal vs. attack behavior; tune thresholds before the final demo |
| Team unfamiliar with eBPF/kernel programming | High | Assign dedicated time and ownership to the capture layer early; treat it as the critical path since every other component depends on its event schema |
| End-to-end integration issues (many moving parts built at once) | High | Define the event/alert schema (Section 9) first and freeze it early, so all components can be built in parallel against a stable contract |

---

## 14. Open Questions

- Will the course allow a synthetic/injected attack dataset for demo, or is fully organic traffic generation required?
- Is Kubernetes support expected/rewarded, or is Docker Compose sufficient scope?
- What is the exact submission format — working demo, report only, or both?
- Team size and role split (backend/ML/frontend/eBPF) — needs to be finalized before build kickoff, since components will be built in parallel against the shared schema.

---

## 15. Build Sequence

Since this is delivered as one complete pipeline rather than staged releases, the team should still build in a sensible dependency order — but all components are targeted for the same final delivery, not separate demoable checkpoints:

1. Freeze the event/alert schema (Section 9) and API contract (Section 10) — this unblocks parallel work.
2. Stand up infrastructure: Docker Compose skeleton, PostgreSQL/TimescaleDB, Neo4j, Redis.
3. Build the eBPF capture agent (TC + XDP) publishing to the event pipeline.
4. Build the FastAPI backend consumer: rule engine → ML engine → risk scoring → SHAP → MITRE mapping → storage.
5. Build the React dashboard: alert feed, network graph, SHAP panel — wired to the REST API and WebSocket.
6. Build the demo/test environment: multi-container victim app + scripted attack scenarios.
7. Integrate, tune thresholds, and run the full test suite end-to-end.

---

*End of Document*
