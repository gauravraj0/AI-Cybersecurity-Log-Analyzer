"""Ingestion pipeline.

parse/classify -> persist -> per-log + window rules -> incident correlation
-> IP profile update -> real-time WS broadcast.
"""
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from ..detection.anomaly import detect_anomalies
from ..detection.classify import classify
from ..detection.rules import RuleHit, ml_anomaly_hit, per_log_rules, window_rules
from ..models import IpProfile, LogEntry
from . import incidents as incident_svc
from .realtime import manager

logger = logging.getLogger("ingest")


def _coerce_log(data: dict) -> dict:
    """Normalise an incoming dict into a classify()-compatible structure."""
    ts = data.get("timestamp")
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if ts.tzinfo is not None:
                ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
        except ValueError:
            ts = None
    data["timestamp"] = ts or datetime.utcnow()
    if data.get("raw") is None:
        data["raw"] = data.get("message", "")
    return data


def _update_ip_profile(db: Session, log: LogEntry):
    if not log.ip_address:
        return
    prof = db.query(IpProfile).filter(IpProfile.ip == log.ip_address).first()
    if prof is None:
        prof = IpProfile(ip=log.ip_address, first_seen=log.timestamp or datetime.utcnow())
        db.add(prof)
        db.flush()
    prof.last_seen = log.timestamp or datetime.utcnow()
    prof.total_requests += 1
    if log.event_type == "auth.login.failure":
        prof.failed_logins += 1
    if log.level in ("ERROR", "CRITICAL"):
        prof.error_count += 1

    score = 0
    score += min(40, prof.failed_logins * 6)
    score += min(25, prof.error_count * 2)
    score += min(35, sum(1 for _ in range(0)))  # placeholder, extended below
    # recent high-severity events weigh heavily
    score += 20 if prof.is_malicious else 0
    prof.threat_score = max(prof.threat_score, min(100, score))

    if prof.threat_score >= 60:
        prof.is_malicious = True
    labels = set(prof.labels or [])
    if prof.failed_logins >= 3:
        labels.add("brute_force_suspect")
    if log.event_type in ("web.sql_injection", "web.command_injection", "web.path_traversal"):
        labels.add("web_attacker")
        prof.threat_score = min(100, max(prof.threat_score, 70))
        prof.is_malicious = True
    if log.event_type == "web.scanner":
        labels.add("scanner")
        prof.threat_score = min(100, max(prof.threat_score, 45))
    prof.labels = sorted(labels)


def _serialize_log(log: LogEntry) -> dict:
    return {
        "id": log.id,
        "timestamp": (log.timestamp or datetime.utcnow()).isoformat() + "Z",
        "source": log.source, "host": log.host, "level": log.level,
        "category": log.category, "event_type": log.event_type,
        "severity": log.severity, "threat_score": log.threat_score,
        "message": log.message[:400], "ip_address": log.ip_address,
        "method": log.method, "path": log.path, "status_code": log.status_code,
        "bytes_sent": log.bytes_sent, "user_agent": log.user_agent,
        "username": log.username, "labels": log.labels or [],
    }


def ingest_batch(db: Session, raw_logs: list[dict], source_default: str = "api") -> dict:
    """Run a batch of log dicts through the full detection pipeline.

    Returns counts summary. Designed for single-digit-millisecond cost per
    event on typical batches.
    """
    accepted = rejected = alerts_raised = incidents_opened = 0
    log_ids: list[int] = []
    serialized_stream: list[dict] = []

    for data in raw_logs:
        try:
            data = _coerce_log(data)
            data.setdefault("source", source_default)
            data = classify(data)
            log = LogEntry(**{k: v for k, v in data.items() if k in LogEntry.__table__.columns.keys()
                              and k not in ("id",)})
            db.add(log)
            db.flush()  # get log.id for correlations

            _update_ip_profile(db, log)

            hits: list[RuleHit] = per_log_rules(log)
            try:
                hits.extend(window_rules(db, log))
            except Exception as exc:  # noqa: BLE001
                logger.warning("window rules error: %s", exc)

            for hit in hits:
                _, created = incident_svc.correlate_hit(db, hit, log)
                alerts_raised += 1
                incidents_opened += 1 if created else 0

            serialized_stream.append(_serialize_log(log))
            log_ids.append(log.id)
            accepted += 1
        except Exception as exc:  # noqa: BLE001
            logger.warning("ingest error for %r: %s", str(data)[:120], exc)
            rejected += 1

    db.commit()

    if serialized_stream:
        import asyncio
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(manager.broadcast("logs", serialized_stream[:200]))
        except RuntimeError:
            pass  # sync context (tests/CLI)

    return {
        "accepted": accepted,
        "rejected": rejected,
        "alerts_raised": alerts_raised,
        "incidents_opened": incidents_opened,
        "log_ids": log_ids,
    }


def run_anomaly_detection(db: Session, window_minutes: int = 5) -> dict:
    """Score recent IP behaviour with the Isolation Forest model and raise
    incidents for flagged outliers."""
    results = detect_anomalies(db, window_minutes=window_minutes)
    flagged = [r for r in results if r["is_anomaly"]]
    opened = 0
    for r in flagged[:5]:  # cap to avoid alert storms
        hit = ml_anomaly_hit(r, r["anomaly_score"])
        synthetic = LogEntry(
            timestamp=datetime.utcnow(), source="ml", host="anomaly-detector",
            level="WARNING", category="network", event_type="ml.anomaly",
            severity=hit.severity, threat_score=hit.threat_score or 60,
            message=hit.message, raw=hit.message, ip_address=r["ip_address"],
            labels=hit.labels, meta={"window_minutes": window_minutes,
                                     "anomaly_score": r["anomaly_score"]},
        )
        db.add(synthetic)
        db.flush()
        _, created = incident_svc.correlate_hit(db, hit, synthetic)
        opened += 1 if created else 0
    db.commit()
    return {"evaluated": len(results), "flagged": len(flagged), "incidents_opened": opened,
            "results": results[:20]}
