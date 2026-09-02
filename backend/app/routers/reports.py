"""Exportable reports: CSV / JSON / executive HTML."""
import json
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Alert, Incident, LogEntry, User
from ..security import get_current_user, require_role
from ..services import reports as report_svc
from .logs import _apply_filters

router = APIRouter(prefix="/reports", tags=["reports"])


def _csv_response(csv_text: str, filename: str) -> Response:
    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/logs.csv")
def export_logs(
    level: str | None = None, category: str | None = None, severity: str | None = None,
    event_type: str | None = None, ip: str | None = None, search: str | None = None,
    hours: int | None = Query(None, ge=1, le=24 * 90),
    db: Session = Depends(get_db),
    _: User = Depends(require_role("analyst", "admin")),
):
    q = db.query(LogEntry)
    q = _apply_filters(q, level, category, severity, event_type, ip, search, hours)
    logs = q.order_by(LogEntry.timestamp.desc()).limit(20_000).all()
    return _csv_response(report_svc.logs_to_csv(logs),
                         f"sentinellens_logs_{datetime.utcnow():%Y%m%d_%H%M%S}.csv")


@router.get("/incidents.csv")
def export_incidents(db: Session = Depends(get_db), _: User = Depends(require_role("analyst", "admin"))):
    incidents = db.query(Incident).order_by(Incident.last_seen.desc()).limit(5000).all()
    return _csv_response(report_svc.incidents_to_csv(incidents),
                         f"sentinellens_incidents_{datetime.utcnow():%Y%m%d_%H%M%S}.csv")


@router.get("/alerts.csv")
def export_alerts(db: Session = Depends(get_db), _: User = Depends(require_role("analyst", "admin"))):
    alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(10_000).all()
    return _csv_response(report_svc.alerts_to_csv(alerts),
                         f"sentinellens_alerts_{datetime.utcnow():%Y%m%d_%H%M%S}.csv")


@router.get("/incidents.json")
def export_incidents_json(db: Session = Depends(get_db),
                          _: User = Depends(require_role("analyst", "admin"))):
    incidents = db.query(Incident).order_by(Incident.last_seen.desc()).limit(5000).all()
    payload = [{
        "id": i.id, "title": i.title, "type": i.incident_type, "severity": i.severity,
        "status": i.status, "threat_score": i.threat_score, "event_count": i.event_count,
        "source_ips": i.source_ips, "targets": i.targets, "labels": i.labels,
        "mitre_tactic": i.mitre_tactic, "detection_method": i.detection_method,
        "summary": i.summary, "recommendation": i.recommendation, "ai_provider": i.ai_provider,
        "first_seen": i.first_seen.isoformat() + "Z" if i.first_seen else None,
        "last_seen": i.last_seen.isoformat() + "Z" if i.last_seen else None,
    } for i in incidents]
    return Response(json.dumps(payload, indent=2), media_type="application/json",
                    headers={"Content-Disposition":
                             f'attachment; filename="sentinellens_incidents_{datetime.utcnow():%Y%m%d}.json"'})


@router.get("/executive")
def executive_report_json(hours: int = Query(24, ge=1, le=24 * 90),
                          db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return report_svc.executive_report(db, hours=hours)


@router.get("/executive.html", response_class=HTMLResponse)
def executive_report_html(hours: int = Query(24, ge=1, le=24 * 90),
                          db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    report = report_svc.executive_report(db, hours=hours)
    return HTMLResponse(report_svc.executive_report_html(report))
