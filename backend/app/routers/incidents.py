"""Incident management endpoints."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Incident, LogEntry, User
from ..schemas import IncidentDetail, IncidentOut, IncidentStatusUpdate, LogOut, Msg
from ..security import get_current_user, require_role
from ..services.ai_summary import generate_incident_summary
from ..detection.anomaly import detect_anomalies, train_baseline
from ..services.ingest import run_anomaly_detection

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", response_model=list[IncidentOut])
def list_incidents(
    status: str | None = None,
    severity: str | None = None,
    incident_type: str | None = None,
    search: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    q = db.query(Incident)
    if status:
        q = q.filter(Incident.status == status)
    if severity:
        q = q.filter(Incident.severity == severity)
    if incident_type:
        q = q.filter(Incident.incident_type == incident_type)
    if search:
        like = f"%{search}%"
        q = q.filter(Incident.title.ilike(like) | Incident.summary.ilike(like))
    return q.order_by(Incident.last_seen.desc()).limit(limit).all()


@router.get("/history")
def historical_analysis(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Historical incident analysis: aggregated trends over stored incidents."""
    incidents = db.query(Incident).all()
    by_type: dict = {}
    by_severity: dict = {}
    by_day: dict = {}
    mttr_minutes: list = []
    for i in incidents:
        by_type[i.incident_type] = by_type.get(i.incident_type, 0) + 1
        by_severity[i.severity] = by_severity.get(i.severity, 0) + 1
        day = (i.first_seen or i.created_at).strftime("%Y-%m-%d")
        by_day[day] = by_day.get(day, 0) + 1
        if i.status in ("resolved", "contained", "false_positive") and i.first_seen and i.last_seen:
            mttr_minutes.append(max(0.0, (i.last_seen - i.first_seen).total_seconds() / 60))
    mttr = sorted(mttr_minutes)
    return {
        "total_incidents": len(incidents),
        "by_type": sorted(by_type.items(), key=lambda x: -x[1]),
        "by_severity": by_severity,
        "by_day": sorted(by_day.items()),
        "open": sum(1 for i in incidents if i.status in ("open", "investigating")),
        "mean_time_to_resolve_minutes": round(sum(mttr) / len(mttr), 1) if mttr else None,
        "most_common_type": max(by_type, key=by_type.get) if by_type else None,
    }


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(404, "Incident not found")
    logs = [ie.log for ie in inc.events]
    detail = IncidentOut.model_validate(inc).model_dump()
    detail["events"] = [LogOut.model_validate(l).model_dump() for l in logs[:100]]
    return detail


@router.patch("/{incident_id}/status", response_model=IncidentOut)
def update_status(incident_id: int, payload: IncidentStatusUpdate,
                  db: Session = Depends(get_db),
                  current: User = Depends(require_role("analyst", "admin"))):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(404, "Incident not found")
    inc.status = payload.status
    if payload.status == "resolved" and not inc.assignee_id:
        inc.assignee_id = current.id
    db.commit()
    db.refresh(inc)
    return inc


@router.post("/{incident_id}/summarize", response_model=IncidentOut)
def regenerate_summary(incident_id: int, db: Session = Depends(get_db),
                       _: User = Depends(require_role("analyst", "admin"))):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(404, "Incident not found")
    generate_incident_summary(db, inc)
    db.refresh(inc)
    return inc


# ---------------------------------------------------------------- ML anomaly


@router.post("/anomaly/train")
def train_anomaly(db: Session = Depends(get_db), _: User = Depends(require_role("analyst", "admin"))):
    """(Re)train the Isolation Forest baseline on historical traffic."""
    return train_baseline(db)


@router.post("/anomaly/detect")
def detect_anomaly(window_minutes: int = Query(5, ge=1, le=1440),
                   db: Session = Depends(get_db),
                   _: User = Depends(require_role("analyst", "admin"))):
    """Run ML anomaly detection over the recent window; raises incidents."""
    return run_anomaly_detection(db, window_minutes=window_minutes)


@router.get("/anomaly/results")
def anomaly_results(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Latest ML anomaly scoring results (no incident side effects)."""
    return {"results": detect_anomalies(db, window_minutes=5)}
