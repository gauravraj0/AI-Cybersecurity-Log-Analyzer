"""Incident lifecycle: correlation of alerts/logs into incidents."""
import logging
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from ..detection.rules import RuleHit
from ..detection.classify import display_name
from ..models import Alert, Incident, IncidentEvent, LogEntry
from .ai_summary import generate_incident_summary, MITRE_MAP

logger = logging.getLogger("incidents")

# A similar hit for the same (type, ip) inside this window merges into the
# open incident instead of creating a new one.
CORRELATION_WINDOW_MIN = 30

SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def correlate_hit(db: Session, hit: RuleHit, log: LogEntry) -> tuple[Incident, bool]:
    """Attach a rule hit to an existing correlated incident or open a new one.

    Correlation is keyed on ``(incident_type, source_ip)`` and merges when the
    incident is still open and its last event is within the correlation window
    of *either* the wall clock (live traffic) or the event's own timestamp
    (historical / replayed ingestion).
    Returns ``(incident, created)``.
    """
    ip = log.ip_address or "global"
    key = f"{hit.incident_type}|{ip}"[:96]
    cutoff = min(datetime.utcnow(), log.timestamp or datetime.utcnow()) - timedelta(
        minutes=CORRELATION_WINDOW_MIN
    )

    incident = (
        db.query(Incident)
        .filter(
            Incident.correlation_key == key,
            Incident.status.in_(["open", "investigating"]),
            Incident.last_seen >= cutoff,
        )
        .order_by(Incident.last_seen.desc())
        .first()
    )

    created = False
    if incident is None:
        title = f"{display_name(hit.incident_type)} from {ip}" if ip != "global" else display_name(hit.incident_type)
        if hit.rule_id == "ML-ANOMALY":
            title = f"ML-detected anomalous behaviour — {ip}"
        incident = Incident(
            title=title[:250],
            incident_type=hit.incident_type,
            correlation_key=key,
            severity=hit.severity,
            threat_score=hit.threat_score or 50,
            first_seen=log.timestamp or datetime.utcnow(),
            last_seen=log.timestamp or datetime.utcnow(),
            source_ips=[ip] if ip != "global" else [],
            targets=[t for t in {log.path, log.username, log.host} if t][:8],
            labels=list(dict.fromkeys(hit.labels + [f"rule:{hit.rule_id}"])),
            mitre_tactic=hit.mitre_tactic or MITRE_MAP.get(itype, ""),
            detection_method="ml_anomaly" if hit.rule_id == "ML-ANOMALY" else "rule",
            event_count=0,
        )
        db.add(incident)
        db.flush()
        created = True
    else:
        # merge / escalate
        if SEVERITY_RANK.get(hit.severity, 0) > SEVERITY_RANK.get(incident.severity, 0):
            incident.severity = hit.severity
        incident.threat_score = max(incident.threat_score, hit.threat_score or 0)
        if ip != "global" and ip not in incident.source_ips:
            incident.source_ips = (incident.source_ips + [ip])[:20]
        for t in {log.path, log.username, log.host}:
            if t and t not in incident.targets:
                incident.targets = (incident.targets + [t])[:16]
        for lab in hit.labels:
            if lab not in incident.labels:
                incident.labels = (incident.labels + [lab])[:24]

    incident.last_seen = log.timestamp or datetime.utcnow()
    incident.event_count += 1

    # link evidence
    link = IncidentEvent(incident_id=incident.id, log_id=log.id)
    db.add(link)
    db.flush()

    # alert
    alert = Alert(
        rule_id=hit.rule_id, rule_name=hit.rule_name, severity=hit.severity,
        message=hit.message, log_id=log.id, incident_id=incident.id,
        ip_address=log.ip_address,
    )
    db.add(alert)
    db.flush()

    db.commit()
    db.refresh(incident)

    regenerate = created
    if not created and incident.ai_provider == "heuristic":
        # keep the deterministic narrative in sync as evidence accumulates
        regenerate = True
    if regenerate:
        try:
            generate_incident_summary(db, incident)  # AI summary on creation/merge
        except Exception as exc:  # noqa: BLE001
            logger.warning("AI summary generation failed: %s", exc)

    from .realtime import broadcast_threadsafe
    broadcast_threadsafe("incident", serialize_incident(incident))
    broadcast_threadsafe("alert", {
        "id": alert.id, "rule_id": alert.rule_id, "rule_name": alert.rule_name,
        "severity": alert.severity, "message": alert.message,
        "ip_address": alert.ip_address, "incident_id": incident.id,
        "created_at": alert.created_at.isoformat() + "Z",
    })

    return incident, created


def serialize_incident(inc: Incident) -> dict:
    return {
        "id": inc.id, "title": inc.title, "incident_type": inc.incident_type,
        "severity": inc.severity, "status": inc.status,
        "threat_score": inc.threat_score, "event_count": inc.event_count,
        "source_ips": inc.source_ips, "summary": inc.summary,
        "ai_provider": inc.ai_provider,
        "first_seen": inc.first_seen.isoformat() + "Z",
        "last_seen": inc.last_seen.isoformat() + "Z",
    }


def escalate_severity(threat_score: int) -> str:
    if threat_score >= 80:
        return "CRITICAL"
    if threat_score >= 60:
        return "HIGH"
    if threat_score >= 35:
        return "MEDIUM"
    if threat_score >= 15:
        return "LOW"
    return "INFO"
