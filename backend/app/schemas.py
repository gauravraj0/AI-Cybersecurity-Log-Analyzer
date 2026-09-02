"""Pydantic schemas for API request/response validation."""
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------- Auth


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=6, max_length=128)
    email: str = ""
    role: str = Field(default="viewer", pattern="^(admin|analyst|viewer)$")


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# ---------------------------------------------------------------- Logs


class LogIn(BaseModel):
    """Single log event accepted by the ingestion API."""
    timestamp: Optional[datetime] = None
    source: str = "api"
    host: str = ""
    level: str = "INFO"
    category: str = "application"
    message: str
    raw: Optional[str] = None
    ip_address: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status_code: Optional[int] = None
    bytes_sent: Optional[int] = None
    user_agent: Optional[str] = None
    username: Optional[str] = None
    meta: dict[str, Any] = Field(default_factory=dict)


class LogBatch(BaseModel):
    logs: list[LogIn] = Field(max_length=5000)


class LogOut(BaseModel):
    id: int
    timestamp: datetime
    source: str
    host: str
    level: str
    category: str
    event_type: str
    severity: str
    threat_score: int
    message: str
    ip_address: Optional[str]
    method: Optional[str]
    path: Optional[str]
    status_code: Optional[int]
    bytes_sent: Optional[int]
    user_agent: Optional[str]
    username: Optional[str]
    labels: list
    meta: dict

    class Config:
        from_attributes = True


class LogPage(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[LogOut]


class IngestResult(BaseModel):
    accepted: int
    rejected: int
    alerts_raised: int
    incidents_opened: int
    log_ids: list[int]


# ---------------------------------------------------------------- Incidents


class IncidentOut(BaseModel):
    id: int
    title: str
    incident_type: str
    severity: str
    status: str
    threat_score: int
    summary: str
    recommendation: str
    ai_provider: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    source_ips: list
    targets: list
    labels: list
    mitre_tactic: str
    detection_method: str
    assignee_id: Optional[int]

    class Config:
        from_attributes = True


class IncidentDetail(IncidentOut):
    events: list[LogOut] = []


class IncidentStatusUpdate(BaseModel):
    status: str = Field(pattern="^(open|investigating|contained|resolved|false_positive)$")


# ---------------------------------------------------------------- Alerts


class AlertOut(BaseModel):
    id: int
    rule_id: str
    rule_name: str
    severity: str
    message: str
    log_id: Optional[int]
    incident_id: Optional[int]
    ip_address: Optional[str]
    acknowledged: bool
    acknowledged_by: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class AlertPage(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[AlertOut]


# ---------------------------------------------------------------- Analytics


class DashboardStats(BaseModel):
    total_logs: int
    logs_24h: int
    critical_events: int
    open_incidents: int
    unacknowledged_alerts: int
    malicious_ips: int
    error_rate: float
    logs_per_hour: list[dict]
    severity_breakdown: list[dict]
    category_breakdown: list[dict]
    top_attack_types: list[dict]
    top_risky_ips: list[dict]
    recent_alerts: list[AlertOut]


class IpProfileOut(BaseModel):
    id: int
    ip: str
    first_seen: datetime
    last_seen: datetime
    total_requests: int
    failed_logins: int
    error_count: int
    threat_score: int
    is_malicious: bool
    labels: list

    class Config:
        from_attributes = True


class AnomalyOut(BaseModel):
    window_start: datetime
    window_end: datetime
    ip_address: str | None
    request_count: int
    error_ratio: float
    failed_login_ratio: float
    anomaly_score: float
    is_anomaly: bool


# ---------------------------------------------------------------- Misc


class SimulatorStatus(BaseModel):
    running: bool
    events_generated: int


class Msg(BaseModel):
    message: str
