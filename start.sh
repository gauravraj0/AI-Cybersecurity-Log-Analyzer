#!/usr/bin/env bash
# SentinelLens one-shot dev launcher: builds the frontend if needed and serves
# the whole app (SPA + API + WebSocket) from a single FastAPI port.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d frontend/dist ]; then
  echo "==> Building frontend (first run)..."
  (cd frontend && npm install --no-audit --no-fund && npm run build)
fi

echo "==> Starting SentinelLens on http://localhost:8000 (demo login: admin / admin123)"
cd backend
exec python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000
