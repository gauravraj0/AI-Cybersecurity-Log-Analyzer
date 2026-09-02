# 🛡️ SentinelLens — AI Cybersecurity Log Analyzer

An AI-assisted **security monitoring platform (SIEM-lite)** that ingests application/server logs,
detects suspicious patterns with rules **and** machine learning, correlates evidence into
incidents, writes **generative-AI incident summaries**, raises alerts and visualises everything
on a real-time security dashboard.

![stack](https://img.shields.io/badge/Python-3.11-blue) ![stack](https://img.shields.io/badge/React-18-blue) ![stack](https://img.shields.io/badge/FastAPI-0.11x-green) ![stack](https://img.shields.io/badge/PostgreSQL-16-blue) ![stack](https://img.shields.io/badge/scikit--learn-IsolationForest-orange)

---

## ✨ Features

| Area | What it does |
|---|---|
| **Log ingestion** | REST JSON API, raw text (auto-format detection), file upload (access logs / syslog / JSON lines / key=value), and a synthetic traffic simulator |
| **Log parsing** | Auto-detects Apache/Nginx combined, JSON, syslog, sshd, `key=value`, plain text |
| **Real-time monitoring** | WebSocket feed of live logs, alerts and incidents + start/stop traffic simulator from the UI |
| **Anomaly detection (ML)** | Isolation Forest over per-IP behavioural features (request volume, error ratio, failed-login ratio, off-hours activity, …) with persisted model + retrain endpoint |
| **Suspicious activity identification** | 13+ signature rules: SQLi, XSS, command injection, path traversal, brute force, port scan, DoS flooding, data exfiltration, privilege escalation, malware, admin probing, scanners, off-hours privileged activity |
| **Error classification** | Every event normalised into a typed taxonomy (`web.sql_injection`, `auth.login.failure`, `system.malware`, `app.exception`, …) |
| **Severity classification** | 0–100 threat score with modifiers (off-hours, non-browser clients, privileged accounts) mapped to INFO/LOW/MEDIUM/HIGH/CRITICAL |
| **AI incident summaries** | GenAI narrative + recommended actions per incident. Uses OpenAI or Anthropic when an API key is set; otherwise a built-in heuristic analyst engine (deterministic, evidence-cited, works offline) |
| **Alert generation** | One alert per rule hit, acknowledgement workflow with analyst attribution |
| **Incident correlation** | Evidence merged into incidents by `(type, source IP)` with a 30-minute event-time window; severity escalation; MITRE tactic mapping |
| **Historical incident analysis** | Trends by type/severity/day + mean-time-to-resolve |
| **IP / activity analysis** | Per-IP behavioural profiles, threat scores, timelines, top paths/users/status codes |
| **Security dashboard** | KPIs, 24-h event/threat chart, severity donut, attack-type bar chart, risky-IP table, live alert feed |
| **Search & filtering** | Server-side full-text + facet filters (level, severity, category, event type, IP, time window), pagination |
| **Exportable reports** | Logs/Incidents/Alerts CSV, incidents JSON, and a print-ready **executive HTML report** with AI-analysed incident register |
| **Auth & RBAC** | JWT (OAuth2 password flow), PBKDF2 password hashing, roles: `viewer` (read) → `analyst` (ingest/resolve/export) → `admin` (user management, purge) |

## 🧱 Architecture

```
frontend (React 18 + Vite + Recharts)           backend (FastAPI + SQLAlchemy)
 ├── Login (JWT) ──────────────── /api/auth ───▶  Auth (JWT, PBKDF2, RBAC)
 ├── Dashboard ────────────────── /api/analytics▶ Analytics (KPIs, timelines)
 ├── Live Monitor ◀══ WebSocket ══ /ws ═════════▶ Realtime broadcaster
 ├── Log Explorer ─────────────── /api/logs ────▶ Search (server-side filters)
 ├── Incidents (AI summaries) ─── /api/incidents▶ Correlation engine
 ├── Alerts ───────────────────── /api/alerts ──▶ Alert service
 ├── IP Analysis ──────────────── /api/analytics▶ IP profiling
 ├── Reports ──────────────────── /api/reports ─▶ CSV/JSON/HTML export
 └── Users (admin) ────────────── /api/auth/users

Detection pipeline (per event):
  parse → classify (taxonomy + threat score) → per-log rules
        → window rules (brute force, scan, DoS, exfil, error spike)
        → incident correlation → alert → AI summary → WS broadcast

ML pipeline:
  per-IP behavioural features ──▶ IsolationForest (trained on 72 h baseline)
        ──▶ outlier scoring ──▶ anomaly incidents/alerts
```

## 📁 Repository layout

```
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app, SPA hosting, lifespan seeding
│   │   ├── config.py            # env-driven settings
│   │   ├── database.py          # SQLite (dev) / PostgreSQL (prod) via SQLAlchemy
│   │   ├── models.py            # User, LogEntry, IpProfile, Incident, Alert
│   │   ├── schemas.py           # Pydantic request/response models
│   │   ├── security.py          # PBKDF2 hashing, JWT, role dependencies
│   │   ├── parsers.py           # multi-format log parsing
│   │   ├── detection/           # classify.py, rules.py, anomaly.py (ML)
│   │   ├── services/            # ingest, incidents, alerts, ai_summary,
│   │   │                        # reports, simulator, realtime (WS hub)
│   │   └── routers/             # auth, logs, incidents, alerts, analytics,
│   │                            # reports, system, ws
│   ├── tests/                   # pytest: parsers, detection, end-to-end API
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/                    # React 18 + Vite + Recharts (dark SOC theme)
│   ├── src/pages/               # Dashboard, LiveLogs, LogsExplorer, Incidents,
│   │                            # Alerts, IpAnalysis, Reports, Users, Login
│   ├── nginx.conf / Dockerfile  # prod container w/ API + WS proxy
│   └── package.json
├── sample_logs/                 # demo log file for upload testing
├── docker-compose.yml           # frontend + backend + PostgreSQL
└── .env.example
```

## 🚀 Quick start

### Option A — local development (SQLite, no services needed)

```bash
# 1. Backend
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
# first run auto-seeds users + ~72 h of realistic demo data and trains the ML baseline

# 2. Frontend (dev server with API proxy)
cd frontend
npm install
npm run dev            # http://localhost:5173
```

### Option B — production-style single container

```bash
cd frontend && npm install && npm run build   # builds dist/
cd ../backend && uvicorn app.main:app --port 8000
# FastAPI serves the React app + API + WebSocket on one port → http://localhost:8000
```

### Option C — Docker Compose (PostgreSQL + all services)

```bash
cp .env.example .env       # optionally set SECRET_KEY / AI keys
docker compose up --build
# UI:        http://localhost:8080
# API docs:  http://localhost:8000/docs
```

### Demo accounts (RBAC)

| Username | Password | Role | Permissions |
|---|---|---|---|
| `admin` | `admin123` | admin | everything + user management + purge |
| `analyst` | `analyst123` | analyst | ingest, resolve incidents, ack alerts, export |
| `viewer` | `viewer123` | viewer | read-only dashboards |

> Change these immediately for any real deployment (`POST /api/auth/users`, then disable the seeds).

## 🔌 API overview (interactive docs at `/docs`)

```
POST /api/auth/login                JWT login (OAuth2 form)
GET  /api/auth/me                   current user
GET|POST /api/auth/users            list / create users        (admin)
PATCH /api/auth/users/{id}/toggle   enable/disable user        (admin)

GET  /api/logs                      search + filter + paginate
GET  /api/logs/facets               filter values
POST /api/ingest                    JSON batch ingestion       (analyst+)
POST /api/ingest/raw                raw text ingestion (auto-parse)
POST /api/ingest/upload             log file upload (multipart)

GET  /api/incidents                 list/filter incidents
GET  /api/incidents/history         historical trend analysis
GET  /api/incidents/{id}            detail + evidence trail
PATCH /api/incidents/{id}/status    open→investigating→…→resolved (analyst+)
POST /api/incidents/{id}/summarize  (re)generate AI summary    (analyst+)
POST /api/incidents/anomaly/train   retrain Isolation Forest   (analyst+)
POST /api/incidents/anomaly/detect  run ML anomaly detection   (analyst+)

GET  /api/alerts                    list/filter alerts
POST /api/alerts/{id}/ack           acknowledge                (analyst+)

GET  /api/analytics/dashboard       dashboard KPIs + chart data
GET  /api/analytics/ips             IP behaviour profiles
GET  /api/analytics/ips/{ip}        per-IP deep dive

GET  /api/reports/logs.csv          filtered log export        (analyst+)
GET  /api/reports/incidents.csv|json
GET  /api/reports/alerts.csv
GET  /api/reports/executive.html    print-ready executive report

WS   /ws?token=JWT                  live stream: logs | alerts | incidents
GET  /api/health                    liveness probe
```

### Ingesting your own logs

```bash
# JSON batch
curl -X POST http://localhost:8000/api/ingest \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"logs":[{"message":"Failed password for root from 1.2.3.4 port 5000 ssh2",
                "ip_address":"1.2.3.4","category":"auth","username":"root"}]}'

# Raw text - format auto-detected (Apache, syslog, JSON lines, key=value, plain)
curl -X POST http://localhost:8000/api/ingest/raw \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"text":"192.168.1.5 - - [02/Sep/2026:10:00:00 +0000] \"GET /?q=1%27%20OR%201%3D1 HTTP/1.1\" 200 512 \"-\" \"sqlmap/1.8\""}'

# File upload (see sample_logs/mixed_attack_session.log)
curl -X POST http://localhost:8000/api/ingest/upload \
  -H "Authorization: Bearer $TOKEN" -F file=@sample_logs/mixed_attack_session.log
```

## 🤖 Generative AI summaries

SentinelLens writes an incident narrative + recommended actions automatically when an
incident is opened, and on demand via `POST /api/incidents/{id}/summarize`:

1. **OpenAI** — set `OPENAI_API_KEY` (optionally `OPENAI_MODEL`)
2. **Anthropic** — set `ANTHROPIC_API_KEY` (optionally `ANTHROPIC_MODEL`)
3. **Built-in heuristic analyst** (default, zero-config) — assembles a deterministic,
   evidence-cited SOC narrative from the incident's forensic trail (sources, targets,
   accounts, signatures, tooling, time window) plus type-specific remediation playbooks.

The active provider is shown on each incident (`AI summary via openai | anthropic | heuristic`).

## 🧪 Tests

```bash
cd backend
python -m pytest tests/ -v
# 26 tests: parsers, classification, rules, brute-force windowing,
# ML training/detection, RBAC, ingestion, incident lifecycle, reports, WebSocket
```

## ⚙️ Configuration (env vars)

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./sentinel.db` | any SQLAlchemy URL (PostgreSQL in Compose) |
| `SECRET_KEY` | dev value | JWT signing — **change in production** |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `120` | JWT lifetime |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | unset | enable LLM summaries |
| `BRUTE_FORCE_THRESHOLD` / `BRUTE_FORCE_WINDOW_MIN` | `5` / `5` | brute-force rule tuning |
| `PORTSCAN_THRESHOLD` | `12` | distinct probes/3 min |
| `DOS_RPM_THRESHOLD` | `60` | requests/min flooding |
| `EXFIL_BYTES_THRESHOLD` | `5 MB` | single-response exfil size |
| `CORS_ORIGINS` | `*` | comma-separated origins |

## 🔒 Security notes

- Passwords: PBKDF2-HMAC-SHA256, 260k iterations, per-user salt.
- JWTs: HS256, exp-checked; WebSocket requires a valid token.
- RBAC enforced server-side on every mutating endpoint.
- Designed for a demo/learning context — before production use: change secret keys,
  put TLS in front, pin network access to the DB, rotate the seeded accounts.

---

*SentinelLens* — ingestion ➜ detection ➔ correlation ➔ AI analysis ➔ action.
