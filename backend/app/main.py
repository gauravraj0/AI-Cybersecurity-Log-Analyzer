"""SentinelLens - AI Cybersecurity Log Analyzer. FastAPI application entrypoint."""
import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .config import settings
from .database import Base, engine
from .routers import alerts, analytics, auth, incidents, logs, reports, system, ws
from .services.realtime import manager, set_main_loop

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    from .seed import ensure_seeded
    ensure_seeded()
    set_main_loop(asyncio.get_running_loop())  # enables WS broadcasts from worker threads
    yield
    simulator_running = False  # simulator task dies with the event loop


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="AI-assisted security monitoring: log ingestion, anomaly detection, "
                "incident response and real-time dashboards.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

for r in (auth.router, logs.router, incidents.router, alerts.router,
          analytics.router, reports.router, system.router):
    app.include_router(r, prefix=settings.API_PREFIX)
app.include_router(ws.router)


@app.get("/api/health", tags=["system"])
def health():
    return {"status": "ok", "app": settings.APP_NAME, "version": settings.VERSION,
            "ws_connections": manager.count}


# --- Serve the built React frontend (single-container production mode) -------
STATIC_DIR = Path(__file__).resolve().parent.parent / settings.STATIC_DIR
if STATIC_DIR.exists():
    app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa(full_path: str):
        candidate = STATIC_DIR / full_path
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(STATIC_DIR / "index.html")
