"""Log search / filtering + ingestion endpoints."""
import json

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import LogEntry
from ..schemas import IngestResult, LogBatch, LogOut, LogPage, Msg
from ..security import get_current_user, require_role
from ..models import User
from ..parsers import parse_line
from ..services.ingest import ingest_batch

router = APIRouter(tags=["logs"])


def _apply_filters(q, level: str | None, category: str | None, severity: str | None,
                   event_type: str | None, ip: str | None, search: str | None,
                   hours: int | None, since=None, until=None):
    if level:
        q = q.filter(LogEntry.level == level.upper())
    if category:
        q = q.filter(LogEntry.category == category)
    if severity:
        q = q.filter(LogEntry.severity == severity.upper())
    if event_type:
        q = q.filter(LogEntry.event_type == event_type)
    if ip:
        q = q.filter(LogEntry.ip_address == ip)
    if hours:
        from datetime import datetime, timedelta
        q = q.filter(LogEntry.timestamp >= datetime.utcnow() - timedelta(hours=hours))
    if since:
        q = q.filter(LogEntry.timestamp >= since)
    if until:
        q = q.filter(LogEntry.timestamp <= until)
    if search:
        like = f"%{search}%"
        q = q.filter(or_(LogEntry.message.ilike(like), LogEntry.path.ilike(like),
                         LogEntry.raw.ilike(like), LogEntry.ip_address.ilike(like),
                         LogEntry.username.ilike(like), LogEntry.host.ilike(like)))
    return q


@router.get("/logs", response_model=LogPage)
def search_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    level: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    event_type: str | None = None,
    ip: str | None = None,
    search: str | None = None,
    hours: int | None = Query(None, ge=1, le=24 * 30),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    q = db.query(LogEntry)
    q = _apply_filters(q, level, category, severity, event_type, ip, search, hours)
    total = q.count()
    items = (q.order_by(LogEntry.timestamp.desc(), LogEntry.id.desc())
             .offset((page - 1) * page_size).limit(page_size).all())
    return LogPage(total=total, page=page, page_size=page_size, items=items)


@router.get("/logs/facets")
def facets(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Distinct filter values for the search UI (registered before /{log_id})."""
    return {
        "levels": [r[0] for r in db.query(LogEntry.level).distinct().all() if r[0]],
        "categories": [r[0] for r in db.query(LogEntry.category).distinct().all() if r[0]],
        "severities": [r[0] for r in db.query(LogEntry.severity).distinct().all() if r[0]],
        "event_types": [r[0] for r in db.query(LogEntry.event_type).distinct().all() if r[0]],
    }


@router.get("/logs/{log_id}", response_model=LogOut)
def get_log(log_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    log = db.get(LogEntry, log_id)
    if not log:
        raise HTTPException(404, "Log not found")
    return log


# ------------------------------------------------------------------ ingestion


@router.post("/ingest", response_model=IngestResult, status_code=202)
def ingest(payload: LogBatch, db: Session = Depends(get_db), _: User = Depends(require_role("analyst", "admin"))):
    """Structured JSON log ingestion (single or batch)."""
    result = ingest_batch(db, [log.model_dump(exclude_none=True) for log in payload.logs])
    return result


@router.post("/ingest/raw", response_model=IngestResult, status_code=202)
def ingest_raw(body: dict, db: Session = Depends(get_db), _: User = Depends(require_role("analyst", "admin"))):
    """Raw line-oriented ingestion: {"text": "...", "host": "web-01"} - format auto-detected."""
    text = str(body.get("text", ""))[:2_000_000]
    host = str(body.get("host", ""))
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parsed = parse_line(line, host)
        if parsed:
            entries.append(parsed)
    result = ingest_batch(db, entries, source_default="raw")
    return result


@router.post("/ingest/upload", response_model=IngestResult, status_code=202)
async def ingest_upload(file: UploadFile = File(...), db: Session = Depends(get_db),
                        _: User = Depends(require_role("analyst", "admin"))):
    """Upload a log file (access log, syslog, JSON lines, plain text)."""
    raw = await file.read()
    if len(raw) > 8 * 1024 * 1024:
        raise HTTPException(413, "File too large (max 8 MB)")
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(400, "Could not decode file")

    entries = []
    if file.filename and file.filename.endswith(".json") and not file.filename.endswith(".jsonl"):
        try:
            data = json.loads(text)
            if isinstance(data, list):
                entries = [d if isinstance(d, dict) else {"message": str(d)} for d in data[:5000]]
            elif isinstance(data, dict):
                entries = [data]
        except json.JSONDecodeError:
            pass
    if not entries:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            parsed = parse_line(line)
            if parsed:
                entries.append(parsed)
    result = ingest_batch(db, entries[:5000], source_default="upload")
    return result


@router.delete("/logs", response_model=Msg, dependencies=[Depends(require_role("admin"))])
def purge_logs(confirm: str = Query(...), db: Session = Depends(get_db)):
    """Danger zone: purge all log data (admin only, requires confirm=yes)."""
    if confirm != "yes":
        raise HTTPException(400, "Pass confirm=yes to purge")
    n = db.query(LogEntry).delete()
    db.commit()
    return Msg(message=f"Purged {n} log entries")
