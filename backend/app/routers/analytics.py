"""Dashboard analytics + IP/activity analysis endpoints."""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Alert, Incident, IpProfile, LogEntry, User
from ..schemas import AlertOut, DashboardStats, IpProfileOut
from ..security import get_current_user

router = APIRouter(prefix="/analytics", tags=["analytics"])


@router.get("/dashboard", response_model=DashboardStats)
def dashboard(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    now = datetime.utcnow()
    day_ago = now - timedelta(hours=24)

    total_logs = db.query(LogEntry).count()
    logs_24h = db.query(LogEntry).filter(LogEntry.timestamp >= day_ago).count()
    critical_events = db.query(LogEntry).filter(
        LogEntry.severity.in_(("CRITICAL", "HIGH")), LogEntry.timestamp >= day_ago).count()
    open_incidents = db.query(Incident).filter(Incident.status.in_(("open", "investigating"))).count()
    unack_alerts = db.query(Alert).filter(Alert.acknowledged.is_(False)).count()
    malicious_ips = db.query(IpProfile).filter(IpProfile.is_malicious.is_(True)).count()

    total_err = db.query(LogEntry).filter(LogEntry.level.in_(("ERROR", "CRITICAL"))).count()
    error_rate = round(total_err / total_logs, 4) if total_logs else 0.0

    # logs per hour (24 buckets)
    logs_per_hour = []
    for i in range(23, -1, -1):
        start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=i)
        end = start + timedelta(hours=1)
        c = db.query(LogEntry).filter(LogEntry.timestamp >= start, LogEntry.timestamp < end).count()
        crit = db.query(LogEntry).filter(
            LogEntry.timestamp >= start, LogEntry.timestamp < end,
            LogEntry.severity.in_(("HIGH", "CRITICAL"))).count()
        logs_per_hour.append({"hour": start.strftime("%H:00"), "count": c, "threats": crit})

    severity_breakdown = [
        {"severity": s, "count": c}
        for s, c in db.query(LogEntry.severity, func.count(LogEntry.id))
        .group_by(LogEntry.severity).all()
    ]
    category_breakdown = [
        {"category": c or "n/a", "count": n}
        for c, n in db.query(LogEntry.category, func.count(LogEntry.id))
        .group_by(LogEntry.category).all()
    ]
    top_attacks = (
        db.query(LogEntry.event_type, func.count(LogEntry.id).label("n"))
        .filter(LogEntry.severity.in_(("MEDIUM", "HIGH", "CRITICAL")))
        .group_by(LogEntry.event_type).order_by(func.count(LogEntry.id).desc()).limit(8).all()
    )
    top_ips = (
        db.query(IpProfile).order_by(IpProfile.threat_score.desc(), IpProfile.last_seen.desc())
        .limit(8).all()
    )
    recent = db.query(Alert).order_by(Alert.created_at.desc()).limit(8).all()

    return DashboardStats(
        total_logs=total_logs, logs_24h=logs_24h, critical_events=critical_events,
        open_incidents=open_incidents, unacknowledged_alerts=unack_alerts,
        malicious_ips=malicious_ips, error_rate=error_rate,
        logs_per_hour=logs_per_hour,
        severity_breakdown=severity_breakdown,
        category_breakdown=category_breakdown,
        top_attack_types=[{"type": t or "n/a", "count": n} for t, n in top_attacks],
        top_risky_ips=[IpProfileOut.model_validate(p).model_dump() for p in top_ips],
        recent_alerts=[AlertOut.model_validate(a).model_dump() for a in recent],
    )


@router.get("/ips", response_model=list[IpProfileOut])
def ip_profiles(
    only_malicious: bool = False,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    q = db.query(IpProfile)
    if only_malicious:
        q = q.filter(IpProfile.is_malicious.is_(True))
    return q.order_by(IpProfile.threat_score.desc(), IpProfile.last_seen.desc()).limit(limit).all()


@router.get("/ips/{ip}")
def ip_detail(ip: str, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    prof = db.query(IpProfile).filter(IpProfile.ip == ip).first()
    logs = (db.query(LogEntry).filter(LogEntry.ip_address == ip)
            .order_by(LogEntry.timestamp.desc()).limit(300).all())

    # activity timeline (hourly buckets over available window)
    buckets: dict = {}
    types: dict = {}
    paths: dict = {}
    users: dict = {}
    statuses: dict = {}
    for l in logs:
        if l.timestamp:
            key = l.timestamp.strftime("%m-%d %H:00")
            b = buckets.setdefault(key, {"hour": key, "count": 0, "threats": 0})
            b["count"] += 1
            if l.severity in ("HIGH", "CRITICAL"):
                b["threats"] += 1
        types[l.event_type] = types.get(l.event_type, 0) + 1
        if l.path:
            paths[l.path[:80]] = paths.get(l.path[:80], 0) + 1
        if l.username:
            users[l.username] = users.get(l.username, 0) + 1
        if l.status_code:
            statuses[l.status_code] = statuses.get(l.status_code, 0) + 1

    return {
        "profile": IpProfileOut.model_validate(prof).model_dump() if prof else None,
        "event_count": len(logs),
        "timeline": sorted(buckets.values(), key=lambda x: x["hour"]),
        "event_types": sorted(types.items(), key=lambda x: -x[1])[:10],
        "top_paths": sorted(paths.items(), key=lambda x: -x[1])[:10],
        "users": sorted(users.items(), key=lambda x: -x[1])[:10],
        "status_codes": sorted(statuses.items(), key=lambda x: -x[1]),
        "recent_logs": [{"id": l.id, "timestamp": l.timestamp.isoformat() + "Z" if l.timestamp else None,
                         "message": l.message[:200], "severity": l.severity,
                         "event_type": l.event_type} for l in logs[:25]],
    }
