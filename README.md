# Orion Security Platform

> AI-driven security assessment platform that helps organizations evaluate the security of their systems through a set of specialized scanning agents, managed from a single dashboard.

![CI](https://github.com/badsectors4u-arch/orion.ai/actions/workflows/ci_checks.yml/badge.svg)
**Repo:** https://github.com/badsectors4u-arch/orion.ai

## What it is

Orion helps organizations — from small companies to banks — assess the security of their systems through a set of specialized scanning agents, all managed from one dashboard an IT employee can actually use without being a pentest expert.

| Agent | Does |
|---|---|
| **Network Scanning** | Maps the network, runs known attack checks, visualizes it for the specialist |
| **Web Scanning** | Same idea, scoped to the company's own web application |
| **Advanced Scanning** | Deeper scan profile with more features |
| **Vulnerability Searching** | Pulls CVEs/severity from trusted sources (e.g. MITRE), produces the final technical report |

An AI "brain" sits on top of all four agents: it's the in-app assistant (**Ask Orion**), it prepares scan parameters before they reach the agents, and it analyzes results before handing them to the Vulnerability Searching agent for the report.

## Tech stack

| Layer | Choice |
|---|---|
| Frontend | React 19 + Vite, built in Docker, served by Nginx, installable as a PWA |
| Backend | Python 3.11 + FastAPI + Uvicorn |
| Database | PostgreSQL 15 |
| Queue / workers | Redis 7 + Celery 5 |
| AI | Ollama (llama3) on the host machine, Groq API as cloud fallback |
| Web server | Nginx — reverse proxy, static files, WebSocket, PWA headers |
| Orchestration | Docker Compose |
| CI/CD | GitHub Actions |

## Network

```
Port 80    (Nginx)       → serves frontend + proxies /api/* to backend
Port 8000  (FastAPI)     → internal only
Port 5432  (PostgreSQL)  → internal only
Port 6379  (Redis)       → internal only
Port 11434 (Ollama)      → on the HOST machine, outside Docker (host.docker.internal)
```

## Repo structure

```
orion.ai/
├── app/                        # Frontend (React + Vite)
├── backend/
│   └── orion/                  # FastAPI app, agents, AI brain
├── tests/                      # QA tests
├── docs/                       # Documentation
├── scripts/
│   ├── run_platform.sh / .bat
│   └── setup_local_ollama.sh / .bat
├── .github/workflows/ci_checks.yml
├── docker-compose.yml
├── docker-compose.dev.yml
├── nginx.conf
├── .env.example
├── .gitignore
└── README.md
```

## Team roles

| Role | Owns |
|---|---|
| Frontend / UI-UX | `app/src/` |
| Backend core & DB | `backend/orion/` (core) |
| Security & AI tools | `backend/orion/` (agents, AI) |
| DevOps | `docker-compose*.yml`, `nginx.conf`, `.github/`, `scripts/`, `.env.example`, `.gitignore` |
| QA & tests | `tests/`, `docs/` |

## Getting started

```bash
git clone https://github.com/badsectors4u-arch/orion.ai.git
cd orion.ai
cp .env.example .env            # fill in secrets
./scripts/setup_local_ollama.sh # pulls llama3 via Ollama on the host
docker compose up --build -d
# open http://localhost
```

Dev mode (hot-reload):
```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up
```

## Branch strategy

- `main` — protected, PR + review + green CI required
- `develop` — integration branch, all feature branches merge here first
- `feature/frontend-ui-ux`, `feature/backend-core-db`, `feature/security-ai-tools`, `feature/devops-docker-pwa`, `feature/qa-tests-thesis`

Weekly integration day: merge order (least → most likely to conflict) is DevOps → Frontend → Backend → Security/AI → QA.

## CI

`.github/workflows/ci_checks.yml` runs on every push/PR to `develop`/`main`:
1. `frontend-check` — lint + build the React app
2. `backend-check` — compile + pytest the FastAPI app
3. `docker-build-check` — full `docker compose up` + `curl /api/health`

## Golden rules (zero-conflict)

1. DevOps never touches `app/src/` or `backend/orion/` core+security code.
2. QA's `tests/` and `docs/` folders aren't touched by other roles.
3. Coordinate before changing `requirements.txt` (Backend/Security) or `package.json` (Frontend).
4. Each role works only on its own feature branch.
5. Always follow the merge order above on integration day.
