# ARIA – Adaptive Reasoning Intelligence for Attack Deception

## Overview

ARIA is an AI-driven cyber deception platform designed to detect, analyze, and redirect malicious attackers into an intelligent honeypot environment using Software-Defined Networking (SDN), Artificial Intelligence, and Large Language Models (LLMs).

The project combines SDN-based traffic control, adaptive deception techniques, AI-powered attack analysis, Retrieval-Augmented Generation (RAG), and an interactive dashboard to improve cyber defense and threat intelligence.

---

## Objectives

- Detect suspicious network activity (SSH brute-force and port scans).
- Redirect attackers dynamically into a controlled Cowrie honeypot environment via OpenFlow 1.3.
- Reconstruct complete attacker sessions and command histories.
- Extract Indicators of Compromise (IOCs) including IPs, URLs, domains, hashes, and file paths.
- Classify attack behavior against MITRE ATT&CK tactics deterministically.
- Persist structured attack telemetry in MongoDB collections.
- Expose attack intelligence in real-time via FastAPI REST endpoints.

---

## Phase 2 Pipeline Architecture

```
Raw Cowrie Log (cowrie.json)
          │
          ▼
    Cowrie Parser (honeypot/parser.py)
          │
          ▼
   Session Builder (honeypot/session_builder.py)
          │
    ┌─────┴─────────────────────────┐
    ▼                               ▼
Command Stream              File Downloads
    │                               │
    ├───────────────┬───────────────┤
    ▼               ▼               ▼
IOC Extraction   Intent Class.   Session Meta
(IPv4, URL,      (MITRE ATT&CK   (Timestamps,
 Domain, Hash,    Tactics &       Auth Status,
 File Paths)      Techniques)     Durations)
    │               │               │
    └───────────────┼───────────────┘
                    ▼
     MongoDB Repositories Layer
     (database/repositories/)
     ├── sessions
     ├── logs
     ├── iocs
     ├── intents
     └── sdn_events
                    ▲
                    │  (Network Telemetry)
             SDN Ryu Controller
             (OpenFlow 1.3 / Mininet)
                    │
                    ▼
          FastAPI Backend Service
          (backend/app/main.py)
          └── REST API & Ingestion
```

---

## Repository Structure

```
ARIA-COPY/
├── ai/
│   ├── __init__.py
│   ├── ioc_extractor.py          # Strict regex IOC extraction & deduplication
│   ├── intent_classifier.py      # Deterministic MITRE ATT&CK intent engine
│   └── models.py                 # AI models and tactic definitions
├── backend/
│   ├── app/
│   │   ├── main.py               # FastAPI application entrypoint & lifecycle
│   │   ├── api/routes/           # API endpoints (health, sessions, logs, iocs, intents, sdn)
│   │   ├── core/                 # Central configuration (pydantic-settings) & logging
│   │   ├── schemas/              # Canonical shared Pydantic data contracts
│   │   └── services/             # Pipeline coordinator & repository dependencies
│   └── requirements.txt
├── database/
│   ├── connection.py             # Motor async client with offline fallback & indexing
│   ├── models.py                 # Document serialization helpers
│   └── repositories/             # CRUD layer (sessions, logs, iocs, intents, sdn)
├── honeypot/
│   ├── parser.py                 # Robust Cowrie JSON-lines parser
│   ├── session_builder.py        # State machine aggregating events into sessions
│   └── pipeline.py               # End-to-end AttackAnalysisPipeline orchestrator
├── sdn/
│   ├── config.py                 # Controller IP, ports, MACs, thresholds
│   ├── controller.py             # Ryu OpenFlow 1.3 Controller with SSH telemetry
│   ├── flow_manager.py           # Flow rule management (OFPFlowMod)
│   ├── monitor.py                # Pure-Python Ethernet/IP/TCP parser & SSH detector
│   ├── redirector.py             # OpenFlow 1.3 bidirectional redirection engine
│   ├── topology.py               # Conceptual network topology
│   ├── mininet_topo.py           # Runnable Mininet topology (Attacker->Switch->Server/Honeypot)
│   └── sdn_reporter.py           # HTTP telemetry dispatcher to Backend
├── docker/
│   └── Dockerfile.backend        # Container build definition for ARIA backend
├── docs/
│   └── phase2_architecture.md    # Detailed Phase 2 architectural guide
├── tests/
│   ├── fixtures/sample_cowrie.json
│   ├── test_parser.py
│   ├── test_sessions.py
│   ├── test_iocs.py
│   ├── test_intents.py
│   ├── test_repositories.py
│   ├── test_api.py
│   ├── test_pipeline.py
│   └── test_sdn.py
├── .env.example
├── docker-compose.yml
├── pytest.ini
└── requirements.txt
```

---

## Technologies

- **Python 3.10+ / 3.14**
- **FastAPI & Uvicorn**
- **Pydantic v2 & Pydantic-Settings**
- **Motor & PyMongo (MongoDB 7.0)**
- **Ryu SDN Framework** (OpenFlow 1.3)
- **Open vSwitch & Mininet**
- **Cowrie SSH/Telnet Honeypot**
- **Docker & Docker Compose**
- **Pytest & HTTPX**

---

## Installation & Setup

### 1. Python Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Environment Configuration
Copy the template configuration:
```bash
cp .env.example .env
```
Default configuration values work immediately out of the box. If MongoDB is not running, the application automatically operates in offline/degraded mode using an in-memory repository store.

### 3. Start MongoDB via Docker
```bash
docker-compose up -d aria-mongodb
```

### 4. Start the FastAPI Backend
```bash
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive OpenAPI documentation will be available at:
* Swagger UI: `http://localhost:8000/docs`
* ReDoc: `http://localhost:8000/redoc`

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | System health and MongoDB connectivity status |
| `GET` | `/api/v1/sessions` | List attack sessions (pagination, IP filter) |
| `GET` | `/api/v1/sessions/{session_id}` | Detailed session view with commands, IOCs, intents |
| `DELETE` | `/api/v1/sessions/{session_id}` | Delete session record |
| `GET` | `/api/v1/logs` | Query raw and normalized Cowrie logs |
| `POST` | `/api/v1/cowrie/log` | Ingest live Cowrie log event (triggers real-time pipeline) |
| `GET` | `/api/v1/iocs` | List extracted IOCs (filter by type, session) |
| `GET` | `/api/v1/iocs/lookup` | Look up individual IOC by exact value |
| `GET` | `/api/v1/intents` | List classified attacker intents across sessions |
| `GET` | `/api/v1/intents/{session_id}` | Get classified intents for a specific session |
| `GET` | `/api/v1/sdn/events` | List SDN switch telemetry events |
| `GET` | `/api/v1/sdn/status` | Get SDN operational status & redirection counts |
| `POST` | `/api/v1/sdn/telemetry` | Ingest real-time telemetry from SDN controller |

---

## Running Tests

Execute the comprehensive automated test suite (works fully offline without live MongoDB, Ryu, or Cowrie infrastructure):

```bash
pytest -v
```

All 31 unit and integration tests pass verifying parser resilience, session aggregation, IOC extraction, MITRE intent classification, repositories, FastAPI routes, and SDN packet decoding.

---

## SDN & Mininet Execution (Linux)

Ryu and Mininet require a Linux environment with Open vSwitch:

1. **Start Open vSwitch:**
   ```bash
   sudo service openvswitch-switch start
   ```
2. **Start the Ryu Controller:**
   ```bash
   ryu-manager sdn/controller.py
   ```
3. **Launch Mininet Virtual Topology:**
   ```bash
   sudo python3 sdn/mininet_topo.py
   ```

---

## Implementation Status Summary

* **Phase 1 (Repository Skeleton):** Complete.
* **Phase 2 (Attack Analysis & Intelligence Collection):** Fully Implemented.
* **Phase 3 (Adaptive Deception Generation):** Planned for subsequent phase.
* **Phase 4 (RAG Threat Intelligence & Automated Reports):** Planned for subsequent phase.
* **Phase 5 (Dashboard Visualization & Evaluation):** Planned for subsequent phase.