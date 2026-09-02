from __future__ import annotations

import csv
import io
import json
import random
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from pydantic import BaseModel, Field
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from .auth import can_admin, can_write, create_token, get_current_user, hash_password, verify_password
from .database import Base, SessionLocal, engine, get_db, utcnow
from .engine import (
    MITRE_MAP,
    anomaly_model,
    cluster_incidents,
    coords_for_ip,
    enrich_record,
    generate_ai_summary,
    geo_for_ip,
    ip_features,
    parse_log_line,
    reputation_for,
    threat_level_from_open,
)
from .models import Alert, Incident, IPProfile, LogEntry, User
from .seed import seed_if_empty, train_from_db

app = FastAPI(
    title="AEGIS — AI Cybersecurity Log Analyzer",
    description="SOC console API for log ingestion, anomaly detection, and AI incident summaries.",
    version="1.0.0",
)

class PreviewHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = "frame-ancestors *"
        if "x-frame-options" in response.headers:
            del response.headers["x-frame-options"]
        return response


app.add_middleware(PreviewHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

SIM_LOCK = threading.RLock()
SIM_RUNNING = True


class LoginBody(BaseModel):
    username: str
    password: str


class IncidentPatch(BaseModel):
    status: str | None = None
    assigned_to: str | None = None


class IngestBody(BaseModel):
    text: str = Field(..., min_length=1)
    source: str = "upload"


class UserCreate(BaseModel):
    username: str
    full_name: str
    email: str
    password: str
    role: str = "analyst"
    department: str = "SOC"


class UserPatch(BaseModel):
    role: str | None = None
    is_active: bool | None = None
    department: str | None = None


def _user_out(u: User) -> dict[str, Any]:
    return {
        "id": u.id,
        "username": u.username,
        "full_name": u.full_name,
        "email": u.email,
        "role": u.role,
        "department": u.department,
        "is_active": u.is_active,
        "last_login": _iso(u.last_login),
        "created_at": _iso(u.created_at),
    }


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _log_out(l: LogEntry) -> dict[str, Any]:
    return {
        "id": l.id,
        "timestamp": _iso(l.timestamp),
        "ingested_at": _iso(l.ingested_at),
        "source": l.source,
        "host": l.host,
        "level": l.level,
        "message": l.message,
        "ip_address": l.ip_address,
        "user_agent": l.user_agent,
        "method": l.method,
        "path": l.path,
        "status_code": l.status_code,
        "bytes_sent": l.bytes_sent,
        "country": l.country,
        "city": l.city,
        "username": l.username,
        "is_anomaly": l.is_anomaly,
        "anomaly_score": l.anomaly_score,
        "threat_type": l.threat_type,
        "severity": l.severity,
        "error_class": l.error_class,
        "incident_id": l.incident_id,
    }


def _loads(text: str | None, default: Any) -> Any:
    if not text:
        return default
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return default


def _incident_out(i: Incident) -> dict[str, Any]:
    return {
        "id": i.id,
        "title": i.title,
        "threat_type": i.threat_type,
        "severity": i.severity,
        "status": i.status,
        "confidence": i.confidence,
        "description": i.description,
        "ai_summary": i.ai_summary,
        "mitre": _loads(i.mitre, []),
        "source_ips": _loads(i.source_ips, []),
        "recommended_actions": _loads(i.recommended_actions, []),
        "indicators": _loads(i.indicators, []),
        "first_seen": _iso(i.first_seen),
        "last_seen": _iso(i.last_seen),
        "created_at": _iso(i.created_at),
        "assigned_to": i.assigned_to,
        "event_count": i.event_count,
    }


def _find_ip(db: Session, ip: str) -> IPProfile | None:
    row = db.query(IPProfile).filter(IPProfile.ip == ip).first()
    if row:
        return row
    for obj in list(db.new):
        if isinstance(obj, IPProfile) and obj.ip == ip:
            return obj
    return None


def _upsert_ip(db: Session, rec: dict[str, Any], is_anom: bool) -> None:
    ip = rec.get("ip_address")
    if not ip:
        return
    row = _find_ip(db, ip)
    country, city, asn = geo_for_ip(ip)
    failed = 1 if (rec.get("status_code") or 0) >= 400 or "fail" in (rec.get("message") or "").lower() else 0
    tags = []
    if rec.get("threat_type"):
        tags.append(rec["threat_type"])
    if ip.startswith("185.220."):
        tags.append("tor")
    if ip.startswith(("10.", "192.168.", "172.16.")):
        tags.append("internal")
    if row is None:
        score, level = reputation_for(failed, 1, int(is_anom), tags)
        db.add(
            IPProfile(
                ip=ip,
                country=country,
                city=city,
                asn=asn,
                reputation=score,
                threat_level=level,
                total_requests=1,
                failed_requests=failed,
                anomaly_count=int(is_anom),
                tags=json.dumps(sorted(set(tags))),
                notes="Learned from live ingestion.",
            )
        )
        return
    row.total_requests += 1
    row.failed_requests += failed
    row.anomaly_count += int(is_anom)
    row.last_seen = utcnow()
    existing = set(_loads(row.tags, []))
    existing.update(tags)
    row.tags = json.dumps(sorted(existing))
    score, level = reputation_for(row.failed_requests, row.total_requests, row.anomaly_count, list(existing))
    row.reputation = score
    row.threat_level = level


def persist_records(db: Session, records: list[dict[str, Any]], cluster: bool = True) -> dict[str, Any]:
    with SIM_LOCK:
        return _persist_records(db, records, cluster)


def _persist_records(db: Session, records: list[dict[str, Any]], cluster: bool = True) -> dict[str, Any]:
    if not records:
        return {"ingested": 0, "anomalies": 0, "incidents": []}

    # score vs model
    grouped: dict[str, list] = {}
    for rec in records:
        grouped.setdefault(rec.get("ip_address") or "none", []).append(rec)

    stored: list[LogEntry] = []
    anom_count = 0
    for rec in records:
        feats = ip_features(records, rec.get("ip_address") or "none")
        is_anom, score = anomaly_model.score(feats) if feats else (False, 0.0)
        if rec.get("threat_type"):
            is_anom = True
            score = max(score, 0.72)
        rec["is_anomaly"] = is_anom
        rec["anomaly_score"] = score
        country, city, _asn = geo_for_ip(rec.get("ip_address"))
        row = LogEntry(
            timestamp=rec.get("timestamp") or utcnow(),
            source=rec.get("source") or "unknown",
            host=rec.get("host") or "ingest",
            level=rec.get("level") or "info",
            message=rec.get("message") or "",
            ip_address=rec.get("ip_address"),
            user_agent=rec.get("user_agent"),
            method=rec.get("method"),
            path=rec.get("path"),
            status_code=rec.get("status_code"),
            bytes_sent=rec.get("bytes_sent") or 0,
            country=rec.get("country") or country,
            city=rec.get("city") or city,
            username=rec.get("username"),
            is_anomaly=is_anom,
            anomaly_score=score,
            threat_type=rec.get("threat_type"),
            severity=rec.get("severity") or "info",
            error_class=rec.get("error_class"),
            raw=rec.get("raw") or rec.get("message") or "",
        )
        db.add(row)
        stored.append(row)
        if is_anom:
            anom_count += 1
        _upsert_ip(db, rec, is_anom)
    db.flush()

    created_incidents = []
    if cluster:
        for cand in cluster_incidents(records):
            existing = (
                db.query(Incident)
                .filter(
                    Incident.threat_type == cand["threat_type"],
                    Incident.status != "resolved",
                    Incident.source_ips.contains(cand["source_ips"][0] if cand["source_ips"] else ""),
                )
                .order_by(Incident.id.desc())
                .first()
            )
            if existing:
                existing.event_count += cand["event_count"]
                existing.last_seen = cand["last_seen"]
                existing.ai_summary = generate_ai_summary(
                    {
                        **cand,
                        "event_count": existing.event_count,
                        "title": existing.title,
                        "confidence": existing.confidence,
                    },
                    cand.get("_logs") or [],
                )
                inc_row = existing
            else:
                inc_row = Incident(
                    title=cand["title"],
                    threat_type=cand["threat_type"],
                    severity=cand["severity"],
                    status="open",
                    confidence=cand["confidence"],
                    description=cand["description"],
                    ai_summary=cand["ai_summary"],
                    mitre=json.dumps(cand["mitre"]),
                    source_ips=json.dumps(cand["source_ips"]),
                    recommended_actions=json.dumps(cand["recommended_actions"]),
                    indicators=json.dumps(cand["indicators"]),
                    first_seen=cand["first_seen"],
                    last_seen=cand["last_seen"],
                    event_count=cand["event_count"],
                )
                db.add(inc_row)
                db.flush()
                db.add(
                    Alert(
                        incident_id=inc_row.id,
                        title=cand["title"],
                        message=f"{cand['severity'].upper()} · {cand['event_count']} events · {cand['threat_type']}",
                        severity=cand["severity"],
                        category="detection",
                    )
                )
            created_incidents.append(_incident_out(inc_row))
            ips = set(cand["source_ips"])
            for row in stored:
                if row.ip_address in ips:
                    row.incident_id = inc_row.id
    db.commit()
    return {"ingested": len(stored), "anomalies": anom_count, "incidents": created_incidents}


@app.on_event("startup")
def on_startup() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_if_empty(db)
        train_from_db(db)
    finally:
        db.close()
    thread = threading.Thread(target=_simulate_loop, daemon=True)
    thread.start()


def _simulate_loop() -> None:
    time.sleep(8)
    benign_paths = ["/", "/health", "/api/v2/orders", "/api/v2/catalog", "/login"]
    ips = ["52.12.88.10", "13.107.42.14", "10.0.0.22", "192.168.1.50"]
    while SIM_RUNNING:
        time.sleep(random.randint(7, 14))
        db = SessionLocal()
        try:
            with SIM_LOCK:
                now = utcnow()
                rec = enrich_record(
                    {
                        "timestamp": now,
                        "source": random.choice(["nginx", "application", "waf"]),
                        "host": random.choice(["edge-01", "edge-02", "app-prod-3"]),
                        "level": "info",
                        "message": "GET live heartbeat",
                        "ip_address": random.choice(ips),
                        "method": "GET",
                        "path": random.choice(benign_paths),
                        "status_code": random.choice([200, 200, 200, 304, 404]),
                        "bytes_sent": random.randint(500, 4000),
                        "user_agent": "AegisLive/1.0",
                        "raw": "live",
                    }
                )
                rec["message"] = f"{rec['method']} {rec['path']} -> {rec['status_code']}"
                persist_records(db, [rec], cluster=False)
        except Exception:
            db.rollback()
        finally:
            db.close()


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"ok": True, "service": "aegis", "time": _iso(utcnow())}


@app.post("/api/auth/login")
def login(body: LoginBody, db: Session = Depends(get_db)) -> dict[str, Any]:
    user = db.query(User).filter(func.lower(User.username) == body.username.lower()).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")
    user.last_login = utcnow()
    db.commit()
    token = create_token(user)
    return {"token": token, "user": _user_out(user)}


@app.get("/api/auth/me")
def me(user: User = Depends(get_current_user)) -> dict[str, Any]:
    return _user_out(user)


@app.get("/api/dashboard")
def dashboard(db: Session = Depends(get_db), _user: User = Depends(get_current_user)) -> dict[str, Any]:
    now = utcnow()
    day_ago = now - timedelta(hours=24)
    total_logs = db.query(func.count(LogEntry.id)).scalar() or 0
    logs_24h = db.query(func.count(LogEntry.id)).filter(LogEntry.timestamp >= day_ago).scalar() or 0
    anomalies = db.query(func.count(LogEntry.id)).filter(LogEntry.is_anomaly.is_(True)).scalar() or 0
    open_inc = db.query(Incident).filter(Incident.status != "resolved").all()
    critical_open = sum(1 for i in open_inc if i.severity == "critical")
    high_open = sum(1 for i in open_inc if i.severity == "high")
    alerts_unack = db.query(func.count(Alert.id)).filter(Alert.acknowledged.is_(False)).scalar() or 0

    # volume by hour (last 24h)
    volume = []
    for h in range(24):
        start = now - timedelta(hours=23 - h)
        bucket = start.replace(minute=0, second=0, microsecond=0)
        end = bucket + timedelta(hours=1)
        c = (
            db.query(func.count(LogEntry.id))
            .filter(LogEntry.timestamp >= bucket, LogEntry.timestamp < end)
            .scalar()
            or 0
        )
        t = (
            db.query(func.count(LogEntry.id))
            .filter(
                LogEntry.timestamp >= bucket,
                LogEntry.timestamp < end,
                or_(LogEntry.is_anomaly.is_(True), LogEntry.severity.in_(["high", "critical"])),
            )
            .scalar()
            or 0
        )
        volume.append({"hour": bucket.strftime("%H:00"), "logs": c, "threats": t})

    sev_rows = (
        db.query(Incident.severity, func.count(Incident.id)).group_by(Incident.severity).all()
    )
    severity = {k: 0 for k in ("critical", "high", "medium", "low")}
    for k, v in sev_rows:
        severity[k] = v

    type_rows = (
        db.query(LogEntry.threat_type, func.count(LogEntry.id))
        .filter(LogEntry.threat_type.isnot(None))
        .group_by(LogEntry.threat_type)
        .order_by(func.count(LogEntry.id).desc())
        .limit(8)
        .all()
    )

    top_ips = (
        db.query(IPProfile)
        .order_by(IPProfile.reputation.asc(), IPProfile.anomaly_count.desc())
        .limit(8)
        .all()
    )

    recent_alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(8).all()
    recent_incidents = db.query(Incident).order_by(Incident.last_seen.desc()).limit(6).all()

    error_rows = (
        db.query(LogEntry.error_class, func.count(LogEntry.id))
        .filter(LogEntry.error_class.isnot(None))
        .group_by(LogEntry.error_class)
        .all()
    )

    map_points = []
    for p in db.query(IPProfile).filter(IPProfile.threat_level.in_(["high", "critical", "medium"])).all():
        lon, lat = coords_for_ip(p.ip)
        map_points.append(
            {
                "ip": p.ip,
                "country": p.country,
                "city": p.city,
                "threat_level": p.threat_level,
                "lon": lon,
                "lat": lat,
                "anomalies": p.anomaly_count,
            }
        )

    sources = (
        db.query(LogEntry.source, func.count(LogEntry.id)).group_by(LogEntry.source).all()
    )

    return {
        "kpis": {
            "total_logs": total_logs,
            "logs_24h": logs_24h,
            "anomalies": anomalies,
            "open_incidents": len(open_inc),
            "critical_open": critical_open,
            "alerts_unack": alerts_unack,
            "threat_level": threat_level_from_open(critical_open, high_open),
        },
        "volume": volume,
        "severity": severity,
        "threat_types": [{"type": t or "unknown", "count": c} for t, c in type_rows],
        "top_ips": [_ip_out(p) for p in top_ips],
        "alerts": [_alert_out(a) for a in recent_alerts],
        "incidents": [_incident_out(i) for i in recent_incidents],
        "errors": [{"class": e or "other", "count": c} for e, c in error_rows],
        "sources": [{"source": s, "count": c} for s, c in sources],
        "map_points": map_points,
    }


def _ip_out(p: IPProfile) -> dict[str, Any]:
    lon, lat = coords_for_ip(p.ip)
    return {
        "id": p.id,
        "ip": p.ip,
        "country": p.country,
        "city": p.city,
        "asn": p.asn,
        "reputation": p.reputation,
        "threat_level": p.threat_level,
        "total_requests": p.total_requests,
        "failed_requests": p.failed_requests,
        "anomaly_count": p.anomaly_count,
        "tags": _loads(p.tags, []),
        "first_seen": _iso(p.first_seen),
        "last_seen": _iso(p.last_seen),
        "notes": p.notes,
        "lon": lon,
        "lat": lat,
    }


def _alert_out(a: Alert) -> dict[str, Any]:
    return {
        "id": a.id,
        "incident_id": a.incident_id,
        "title": a.title,
        "message": a.message,
        "severity": a.severity,
        "category": a.category,
        "acknowledged": a.acknowledged,
        "created_at": _iso(a.created_at),
    }


@app.get("/api/logs")
def list_logs(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
    q: str | None = None,
    source: str | None = None,
    severity: str | None = None,
    level: str | None = None,
    ip: str | None = None,
    threat_type: str | None = None,
    anomalies: bool = False,
    since_id: int | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
) -> dict[str, Any]:
    query = db.query(LogEntry)
    if since_id:
        query = query.filter(LogEntry.id > since_id)
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                LogEntry.message.ilike(like),
                LogEntry.path.ilike(like),
                LogEntry.ip_address.ilike(like),
                LogEntry.username.ilike(like),
            )
        )
    if source:
        query = query.filter(LogEntry.source == source)
    if severity:
        query = query.filter(LogEntry.severity == severity)
    if level:
        query = query.filter(LogEntry.level == level)
    if ip:
        query = query.filter(LogEntry.ip_address == ip)
    if threat_type:
        query = query.filter(LogEntry.threat_type == threat_type)
    if anomalies:
        query = query.filter(LogEntry.is_anomaly.is_(True))
    total = query.count()
    rows = query.order_by(LogEntry.timestamp.desc(), LogEntry.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
    sources = [s for (s,) in db.query(LogEntry.source).distinct().all() if s]
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [_log_out(r) for r in rows],
        "sources": sorted(sources),
    }


@app.post("/api/logs/ingest")
def ingest_text(
    body: IngestBody,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    if not can_write(user):
        raise HTTPException(status_code=403, detail="Read-only role")
    records = []
    for line in body.text.splitlines():
        parsed = parse_log_line(line, default_source=body.source)
        if parsed:
            records.append(enrich_record(parsed))
    if not records:
        raise HTTPException(status_code=400, detail="No parseable log lines")
    return persist_records(db, records)


@app.post("/api/logs/upload")
async def ingest_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    if not can_write(user):
        raise HTTPException(status_code=403, detail="Read-only role")
    raw = (await file.read()).decode("utf-8", errors="replace")
    records = []
    for line in raw.splitlines():
        parsed = parse_log_line(line, default_source=file.filename or "upload")
        if parsed:
            records.append(enrich_record(parsed))
    if not records:
        raise HTTPException(status_code=400, detail="No parseable log lines")
    return persist_records(db, records)


@app.get("/api/incidents")
def list_incidents(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
    status: str | None = None,
    severity: str | None = None,
    q: str | None = None,
) -> dict[str, Any]:
    query = db.query(Incident)
    if status:
        query = query.filter(Incident.status == status)
    if severity:
        query = query.filter(Incident.severity == severity)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Incident.title.ilike(like), Incident.threat_type.ilike(like)))
    rows = query.order_by(Incident.last_seen.desc()).all()
    return {"items": [_incident_out(i) for i in rows], "total": len(rows)}


@app.get("/api/incidents/{incident_id}")
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    logs = (
        db.query(LogEntry)
        .filter(LogEntry.incident_id == inc.id)
        .order_by(LogEntry.timestamp.desc())
        .limit(80)
        .all()
    )
    return {**_incident_out(inc), "logs": [_log_out(l) for l in logs]}


@app.patch("/api/incidents/{incident_id}")
def patch_incident(
    incident_id: int,
    body: IncidentPatch,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    if not can_write(user):
        raise HTTPException(status_code=403, detail="Read-only role")
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    if body.status:
        if body.status not in {"open", "investigating", "contained", "resolved"}:
            raise HTTPException(status_code=400, detail="Invalid status")
        inc.status = body.status
        if body.status == "resolved":
            db.query(Alert).filter(Alert.incident_id == inc.id).update({"acknowledged": True})
    if body.assigned_to is not None:
        inc.assigned_to = body.assigned_to
    db.commit()
    db.refresh(inc)
    return _incident_out(inc)


@app.get("/api/alerts")
def list_alerts(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
    unacked: bool = False,
) -> dict[str, Any]:
    query = db.query(Alert)
    if unacked:
        query = query.filter(Alert.acknowledged.is_(False))
    rows = query.order_by(Alert.created_at.desc()).limit(100).all()
    return {"items": [_alert_out(a) for a in rows]}


@app.post("/api/alerts/{alert_id}/ack")
def ack_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    if not can_write(user):
        raise HTTPException(status_code=403, detail="Read-only role")
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.acknowledged = True
    db.commit()
    return _alert_out(alert)


@app.get("/api/ips")
def list_ips(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
    q: str | None = None,
) -> dict[str, Any]:
    query = db.query(IPProfile)
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(IPProfile.ip.ilike(like), IPProfile.country.ilike(like), IPProfile.city.ilike(like))
        )
    rows = query.order_by(IPProfile.reputation.asc()).all()
    return {"items": [_ip_out(p) for p in rows]}


@app.get("/api/ips/{ip}")
def get_ip(ip: str, db: Session = Depends(get_db), _user: User = Depends(get_current_user)) -> dict[str, Any]:
    row = db.query(IPProfile).filter(IPProfile.ip == ip).first()
    if not row:
        raise HTTPException(status_code=404, detail="IP not found")
    logs = (
        db.query(LogEntry)
        .filter(LogEntry.ip_address == ip)
        .order_by(LogEntry.timestamp.desc())
        .limit(60)
        .all()
    )
    return {**_ip_out(row), "logs": [_log_out(l) for l in logs]}


@app.get("/api/anomalies")
def list_anomalies(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    rows = (
        db.query(LogEntry)
        .filter(LogEntry.is_anomaly.is_(True))
        .order_by(LogEntry.anomaly_score.desc(), LogEntry.timestamp.desc())
        .limit(200)
        .all()
    )
    return {
        "items": [_log_out(r) for r in rows],
        "model": "IsolationForest" if anomaly_model.model is not None else "z-score heuristic",
        "trained": anomaly_model.trained,
    }


@app.get("/api/reports/export")
def export_report(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
    fmt: str = Query("json", pattern="^(json|csv)$"),
) -> Any:
    incidents = db.query(Incident).order_by(Incident.last_seen.desc()).all()
    payload = [_incident_out(i) for i in incidents]
    if fmt == "json":
        body = json.dumps(
            {
                "generated_at": _iso(utcnow()),
                "product": "AEGIS AI Cybersecurity Log Analyzer",
                "incidents": payload,
            },
            indent=2,
        )
        return StreamingResponse(
            io.BytesIO(body.encode()),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=aegis-incidents.json"},
        )
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "title", "threat_type", "severity", "status", "confidence", "event_count", "ips", "first_seen", "last_seen"])
    for i in payload:
        writer.writerow(
            [
                i["id"],
                i["title"],
                i["threat_type"],
                i["severity"],
                i["status"],
                i["confidence"],
                i["event_count"],
                ";".join(i["source_ips"]),
                i["first_seen"],
                i["last_seen"],
            ]
        )
    return StreamingResponse(
        io.BytesIO(buf.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=aegis-incidents.csv"},
    )


@app.get("/api/reports/summary")
def report_summary(db: Session = Depends(get_db), _user: User = Depends(get_current_user)) -> dict[str, Any]:
    now = utcnow()
    week = now - timedelta(days=7)
    incidents = db.query(Incident).filter(Incident.created_at >= week).all()
    logs_n = db.query(func.count(LogEntry.id)).filter(LogEntry.timestamp >= week).scalar() or 0
    narrative = (
        f"Over the last 7 days AEGIS ingested {logs_n:,} events and opened {len(incidents)} incidents. "
        f"{sum(1 for i in incidents if i.severity=='critical')} critical and "
        f"{sum(1 for i in incidents if i.status!='resolved')} still require response. "
        "Dominant families: brute force, SQL injection, reconnaissance, and behavioral anomalies. "
        "Recommended focus: contain TOR-origin SSH guessing, patch the /api/v2/users parameterization, "
        "and review large CSV exports from 203.0.113.77."
    )
    return {
        "generated_at": _iso(now),
        "window_days": 7,
        "logs": logs_n,
        "incidents": len(incidents),
        "open": sum(1 for i in incidents if i.status != "resolved"),
        "narrative": narrative,
        "by_severity": {
            s: sum(1 for i in incidents if i.severity == s) for s in ("critical", "high", "medium", "low")
        },
        "by_status": {
            s: sum(1 for i in incidents if i.status == s)
            for s in ("open", "investigating", "contained", "resolved")
        },
    }


@app.post("/api/demo/simulate")
def simulate_attack(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    if not can_write(user):
        raise HTTPException(status_code=403, detail="Read-only role")
    kind, ip, paths = random.choice(
        [
            (
                "sql_injection",
                "45.155.205.201",
                [
                    "/api/v2/users?id=1' OR 1=1--",
                    "/api/v2/users?id=4 UNION SELECT password FROM users--",
                ],
            ),
            (
                "scanner",
                "103.45.88.19",
                ["/.env", "/.git/config", "/wp-admin", "/phpmyadmin"],
            ),
            (
                "brute_force",
                "185.220.101.90",
                ["ssh"],
            ),
        ]
    )
    now = utcnow()
    records = []
    if kind == "brute_force":
        for i in range(8):
            records.append(
                enrich_record(
                    {
                        "timestamp": now - timedelta(seconds=i * 4),
                        "source": "sshd",
                        "host": "auth-01",
                        "level": "warning",
                        "message": f"Failed password for root from {ip} port {4000+i} ssh2",
                        "ip_address": ip,
                        "username": "root",
                        "raw": f"Failed password for root from {ip}",
                    }
                )
            )
    else:
        for i, p in enumerate(paths * 3):
            records.append(
                enrich_record(
                    {
                        "timestamp": now - timedelta(seconds=i * 3),
                        "source": "waf",
                        "host": "edge-01",
                        "level": "warning",
                        "message": f"GET {p} -> 403",
                        "ip_address": ip,
                        "user_agent": "sqlmap/1.8.4#stable" if kind == "sql_injection" else "nuclei",
                        "method": "GET",
                        "path": p,
                        "status_code": 403,
                        "bytes_sent": 80,
                        "raw": p,
                    }
                )
            )
    result = persist_records(db, records, cluster=True)
    result["kind"] = kind
    result["ip"] = ip
    return result


@app.get("/api/users")
def list_users(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> dict[str, Any]:
    if not can_admin(user):
        raise HTTPException(status_code=403, detail="Admin only")
    rows = db.query(User).order_by(User.id).all()
    return {"items": [_user_out(u) for u in rows]}


@app.post("/api/users")
def create_user(
    body: UserCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    if not can_admin(user):
        raise HTTPException(status_code=403, detail="Admin only")
    if body.role not in {"admin", "analyst", "viewer"}:
        raise HTTPException(status_code=400, detail="Invalid role")
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(status_code=409, detail="Username exists")
    row = User(
        username=body.username,
        full_name=body.full_name,
        email=body.email,
        password_hash=hash_password(body.password),
        role=body.role,
        department=body.department,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return _user_out(row)


@app.patch("/api/users/{user_id}")
def patch_user(
    user_id: int,
    body: UserPatch,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    if not can_admin(user):
        raise HTTPException(status_code=403, detail="Admin only")
    row = db.get(User, user_id)
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    if body.role:
        if body.role not in {"admin", "analyst", "viewer"}:
            raise HTTPException(status_code=400, detail="Invalid role")
        row.role = body.role
    if body.is_active is not None:
        row.is_active = body.is_active
    if body.department is not None:
        row.department = body.department
    db.commit()
    db.refresh(row)
    return _user_out(row)


@app.get("/api/meta")
def meta(_user: User = Depends(get_current_user)) -> dict[str, Any]:
    return {
        "product": "AEGIS",
        "name": "AI Cybersecurity Log Analyzer",
        "mitre": MITRE_MAP,
        "roles": ["admin", "analyst", "viewer"],
    }


_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"


def _safe_dist_file(full_path: str) -> Path | None:
    if not _DIST.exists():
        return None
    candidate = (_DIST / full_path).resolve()
    try:
        candidate.relative_to(_DIST.resolve())
    except ValueError:
        return None
    if candidate.is_file():
        return candidate
    return None


@app.get("/{full_path:path}")
async def spa(full_path: str):
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="Not found")
    existing = _safe_dist_file(full_path) if full_path else None
    if existing:
        return FileResponse(existing)
    index = _DIST / "index.html"
    if not index.exists():
        raise HTTPException(status_code=404, detail="UI not built")
    return FileResponse(index)
