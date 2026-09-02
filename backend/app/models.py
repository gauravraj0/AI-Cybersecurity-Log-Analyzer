"""ORM models: users, logs, IP profiles, incidents, alerts."""
from datetime import datetime, timezone

from sqlalchemy import (JSON, Boolean, DateTime, Float, ForeignKey, Integer,
                        String, Text, Index)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), default="")
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="viewer")  # admin | analyst | viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class LogEntry(Base):
    __tablename__ = "log_entries"

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    source: Mapped[str] = mapped_column(String(64), default="api")  # api | file | simulator | syslog
    host: Mapped[str] = mapped_column(String(128), default="")
    level: Mapped[str] = mapped_column(String(10), default="INFO", index=True)  # DEBUG..CRITICAL
    category: Mapped[str] = mapped_column(String(32), default="application", index=True)  # auth|web|app|system|network|database
    event_type: Mapped[str] = mapped_column(String(48), default="generic", index=True)
    severity: Mapped[str] = mapped_column(String(10), default="INFO", index=True)  # INFO|LOW|MEDIUM|HIGH|CRITICAL
    threat_score: Mapped[int] = mapped_column(Integer, default=0)  # 0..100

    message: Mapped[str] = mapped_column(Text, default="")
    raw: Mapped[str] = mapped_column(Text, default="")

    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    method: Mapped[str | None] = mapped_column(String(10), nullable=True)
    path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bytes_sent: Mapped[int | None] = mapped_column(Integer, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)

    labels: Mapped[list] = mapped_column(JSON, default=list)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)


Index("ix_logs_ts_level", LogEntry.timestamp, LogEntry.level)


class IpProfile(Base):
    """Rolling behavioural profile of a source IP - powers IP/activity analysis."""
    __tablename__ = "ip_profiles"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    total_requests: Mapped[int] = mapped_column(Integer, default=0)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    threat_score: Mapped[int] = mapped_column(Integer, default=0)
    is_malicious: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    labels: Mapped[list] = mapped_column(JSON, default=list)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    incident_type: Mapped[str] = mapped_column(String(48), index=True)
    correlation_key: Mapped[str] = mapped_column(String(96), index=True, default="")
    severity: Mapped[str] = mapped_column(String(10), index=True)  # LOW..CRITICAL
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)  # open|investigating|contained|resolved|false_positive
    threat_score: Mapped[int] = mapped_column(Integer, default=0)

    summary: Mapped[str] = mapped_column(Text, default="")          # AI generated narrative
    recommendation: Mapped[str] = mapped_column(Text, default="")   # AI generated remediation
    ai_provider: Mapped[str] = mapped_column(String(32), default="heuristic")  # openai|anthropic|heuristic

    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    source_ips: Mapped[list] = mapped_column(JSON, default=list)
    targets: Mapped[list] = mapped_column(JSON, default=list)      # affected users/paths/hosts
    labels: Mapped[list] = mapped_column(JSON, default=list)
    mitre_tactic: Mapped[str] = mapped_column(String(64), default="")
    detection_method: Mapped[str] = mapped_column(String(32), default="rule")  # rule | ml_anomaly

    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    events: Mapped[list["IncidentEvent"]] = relationship(back_populates="incident", cascade="all, delete-orphan")


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    log_id: Mapped[int] = mapped_column(ForeignKey("log_entries.id"), index=True)
    added_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    incident: Mapped[Incident] = relationship(back_populates="events")
    log: Mapped[LogEntry] = relationship()


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(48), index=True)      # R-BRUTE-FORCE, ML-ANOMALY, ...
    rule_name: Mapped[str] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(10), index=True)
    message: Mapped[str] = mapped_column(Text)
    log_id: Mapped[int | None] = mapped_column(ForeignKey("log_entries.id"), nullable=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    acknowledged_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
