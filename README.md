# ARIA – Adaptive Reasoning Intelligence for Attack Deception

## Overview

ARIA is an AI-driven cyber deception platform designed to detect, analyze, and redirect malicious attackers into an intelligent honeypot environment using Software-Defined Networking (SDN), Artificial Intelligence, and Large Language Models (LLMs).

The project combines SDN-based traffic control, adaptive deception techniques, AI-powered attack analysis, Retrieval-Augmented Generation (RAG), and an interactive dashboard to improve cyber defense and threat intelligence.

---

## Objectives

- Detect suspicious network activity.
- Redirect attackers into a controlled honeypot environment.
- Analyze attacker behavior using AI.
- Generate threat intelligence automatically.
- Provide real-time monitoring through a dashboard.

---

## Project Architecture

```
                 Internet
                      │
                OpenFlow Switch
                      │
          ┌───────────┴───────────┐
          │                       │
   Legitimate Server         Cowrie Honeypot
          │                       │
          └───────────┬───────────┘
                      │
               SDN Controller
                      │
             AI Decision Engine
                      │
      Intent Classification + RAG
                      │
              Monitoring Dashboard
```

---

## Project Modules

### SDN

Responsible for:

- OpenFlow Controller
- Traffic Monitoring
- Flow Management
- Traffic Redirection
- Network Topology

---

### Backend

Responsible for:

- REST APIs
- Authentication
- Database Communication
- Integration between all modules

---

### AI

Responsible for:

- Intent Classification
- LLM Integration
- Retrieval-Augmented Generation (RAG)
- Threat Analysis
- IOC Extraction

---

### Honeypot

Responsible for:

- Cowrie Deployment
- Decoy Environment
- Attack Logging
- Session Capture

---

### Dashboard

Responsible for:

- Real-time Monitoring
- Attack Visualization
- Network Statistics
- Alert Management

---

## Repository Structure

```
ARIA/
│
├── ai/
├── backend/
├── configs/
├── dashboard/
├── database/
├── docker/
├── docs/
├── honeypot/
├── scripts/
├── sdn/
├── tests/
│
├── README.md
├── requirements.txt
├── docker-compose.yml
└── .gitignore
```

---

## Technologies

- Python
- JavaScript
- OS-Ken
- OpenFlow 1.3
- Open vSwitch
- Mininet
- Cowrie Honeypot
- MongoDB
- Docker
- Git & GitHub

---

## Team Branches

| Branch | Responsibility |
|---------|----------------|
| `main` | Stable project integration |
| `member1-backend` | Backend Development |
| `member2-sdn` | SDN Development |
| `member3-ai` | AI Development |
| `member4-dashboard` | Dashboard Development |

---

## Development Workflow

1. Create a feature branch from `main`.
2. Implement and test changes.
3. Commit and push to your branch.
4. Open a Pull Request.
5. Merge into `main` after review.

---

## Current Status

Project Phase: Initial Development

Completed

- Repository setup
- SDN controller foundation
- Development environment configuration
- Initial project structure

In Progress

- Backend implementation
- Ubuntu SDN environment
- Open vSwitch integration
- Mininet topology
- AI module development
- Dashboard development

---

## License

This project is developed for academic and research purposes.