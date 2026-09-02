from __future__ import annotations

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base, utcnow


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(160))
    email: Mapped[str] = mapped_column(String(160), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="analyst")
    department: Mapped[str] = mapped_column(String(80), default="SOC")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login: Mapped[str | None] = mapped_column(DateTime(timezone=True), nullable=True)


class LogEntry(Base):
    __tablename__ = "logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[str] = mapped_column(DateTime(timezone=True), index=True)
    ingested_at: Mapped[str] = mapped_column(DateTime(timezone=True), default=utcnow)
    source: Mapped[str] = mapped_column(String(64), index=True)
    host: Mapped[str] = mapped_column(String(80), default="edge-01")
    level: Mapped[str] = mapped_column(String(24), index=True)
    message: Mapped[str] = mapped_column(Text)
    ip_address: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bytes_sent: Mapped[int] = mapped_column(Integer, default=0)
    country: Mapped[str | None] = mapped_column(String(64), nullable=True)
    city: Mapped[str | None] = mapped_column(String(64), nullable=True)
    username: Mapped[str | None] = mapped_column(String(80), nullable=True)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0)
    threat_type: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    severity: Mapped[str] = mapped_column(String(24), default="info", index=True)
    error_class: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw: Mapped[str] = mapped_column(Text, default="")
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(240))
    threat_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(24), index=True)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.82)
    description: Mapped[str] = mapped_column(Text, default="")
    ai_summary: Mapped[str] = mapped_column(Text, default="")
    mitre: Mapped[str] = mapped_column(Text, default="[]")
    source_ips: Mapped[str] = mapped_column(Text, default="[]")
    recommended_actions: Mapped[str] = mapped_column(Text, default="[]")
    indicators: Mapped[str] = mapped_column(Text, default="[]")
    first_seen: Mapped[str] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[str] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), default=utcnow)
    assigned_to: Mapped[str | None] = mapped_column(String(80), nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, default=1)

    logs = relationship("LogEntry", backref="incident")
    alerts = relationship("Alert", backref="incident")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(240))
    message: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(24), index=True)
    category: Mapped[str] = mapped_column(String(64), default="detection")
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class IPProfile(Base):
    __tablename__ = "ip_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    country: Mapped[str] = mapped_column(String(64), default="Unknown")
    city: Mapped[str] = mapped_column(String(64), default="Unknown")
    asn: Mapped[str] = mapped_column(String(80), default="AS-UNKNOWN")
    reputation: Mapped[int] = mapped_column(Integer, default=50)
    threat_level: Mapped[str] = mapped_column(String(24), default="low")
    total_requests: Mapped[int] = mapped_column(Integer, default=0)
    failed_requests: Mapped[int] = mapped_column(Integer, default=0)
    anomaly_count: Mapped[int] = mapped_column(Integer, default=0)
    tags: Mapped[str] = mapped_column(Text, default="[]")
    first_seen: Mapped[str] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[str] = mapped_column(DateTime(timezone=True), default=utcnow)
    notes: Mapped[str] = mapped_column(Text, default="")
