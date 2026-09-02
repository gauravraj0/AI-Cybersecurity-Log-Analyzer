# AEGIS — AI Cybersecurity Log Analyzer

AI-assisted security monitoring that ingests application and server logs, detects suspicious patterns, and writes analyst-grade incident summaries.

![AEGIS](frontend/public/og-cover.jpg)

## What it does

| Capability | How it shows up |
| --- | --- |
| Log ingestion | Paste or upload nginx combined, syslog, or JSON |
| Real-time monitoring | Live tail with search, source, and severity filters |
| Anomaly detection | scikit-learn Isolation Forest on per-IP behavior |
| Suspicious activity | SQLi, XSS, brute force, traversal, scanners, exfil, ransomware precursors |
| IP / activity analysis | Reputation, geo, ASN, tags, request/failure mix |
| Error classification | Availability, app errors, network, crypto, resource pressure |
| AI incident summaries | Generative narratives mapped to MITRE ATT&CK |
| Alerts | Severity-ranked queue tied to incidents |
| Security dashboard | Volume, mix, threat map, top hostile IPs |
| Historical analysis | Seeded 7-day SOC window |
| Severity + RBAC | Critical → info · admin / analyst / viewer |
| Exportable reports | CSV and JSON incident briefs |

## Architecture

```
React (Vite)  ──/api──►  FastAPI
                           │
                           ├─ SQLAlchemy (SQLite by default, PostgreSQL via DATABASE_URL)
                           ├─ Signature engine + Isolation Forest
                           └─ Generative incident writer
```

## Demo accounts

| Role | Username | Password |
| --- | --- | --- |
| Admin | `admin` | `Aegis#2026` |
| Analyst | `analyst` | `Analyst#2026` |
| Viewer | `viewer` | `Viewer#2026` |

## Run locally

```bash
# API
cd backend
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
./venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000

# Console (second terminal)
cd frontend
npm install
npm run dev
```

Open the Vite URL. The dev server proxies `/api` to FastAPI.

## Docker

```bash
docker compose up --build
```

## PostgreSQL

```bash
export DATABASE_URL=postgresql+psycopg2://aegis:aegis@localhost:5432/aegis
```

SQLite is the default so the demo boots with zero infra.

## Sample telemetry

`data/sample_access.txt` is a mixed nginx / syslog / JSON file you can upload from **Log Ingest**. Analysts can also press **Simulate live attack**.

## Stack

Python · React · FastAPI · SQL / PostgreSQL · Machine Learning · Generative AI · REST APIs · Docker · Git/GitHub
