"""Signature / threshold detection rules.

Two kinds of rules:
1. ``LOG_RULES``      - evaluated per log entry (no context needed).
2. ``context rules``  - evaluated with DB access against a recent time window
                        (brute force, port scan, DoS, exfiltration, error spike).

Every hit produces an ``Alert`` and may escalate into an ``Incident``.
"""
import re
from collections import Counter
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from ..config import settings
from ..models import LogEntry

BRUTE_FORCE_RE = re.compile(r"(failed password|authentication failure|login failed|invalid user|401$)", re.I)
SCANNER_UA_RE = re.compile(r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|hydra)", re.I)


class RuleHit:
    """A detection result waiting to become an alert/incident."""

    def __init__(self, rule_id: str, rule_name: str, severity: str,
                 message: str, incident_type: str, mitre_tactic: str = "",
                 threat_score: int | None = None, labels: list | None = None):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.severity = severity
        self.message = message
        self.incident_type = incident_type
        self.mitre_tactic = mitre_tactic
        self.threat_score = threat_score
        self.labels = labels or []

    def __repr__(self):  # pragma: no cover
        return f"<RuleHit {self.rule_id} {self.severity}>"


# ---------------------------------------------------------------- per-log rules


def per_log_rules(log: LogEntry) -> list[RuleHit]:
    """Immediate single-event signature rules."""
    hits: list[RuleHit] = []
    ua = (log.user_agent or "")
    path = (log.path or "")
    msg = (log.message or "")

    if log.event_type == "web.sql_injection":
        hits.append(RuleHit("R-SQLI", "SQL injection attempt", "CRITICAL",
                            f"SQL injection pattern detected from {log.ip_address} targeting {path}",
                            "web_attack", "TA0006 Credential Access / Initial Access", 92,
                            ["sql_injection", "owasp:a03"]))

    if log.event_type == "web.command_injection":
        hits.append(RuleHit("R-CMDI", "Command injection attempt", "CRITICAL",
                            f"OS command injection pattern from {log.ip_address} targeting {path}",
                            "web_attack", "TA0006", 90, ["command_injection", "owasp:a03"]))

    if log.event_type == "web.path_traversal":
        hits.append(RuleHit("R-TRAVERSAL", "Path traversal attempt", "HIGH",
                            f"Directory traversal pattern from {log.ip_address}: {path}",
                            "web_attack", "TA0006", 72, ["path_traversal", "owasp:a01"]))

    if log.event_type == "web.xss":
        hits.append(RuleHit("R-XSS", "Cross-site scripting attempt", "MEDIUM",
                            f"XSS payload detected from {log.ip_address}: {path[:120]}",
                            "web_attack", "TA0006", 65, ["xss", "owasp:a03"]))

    if log.event_type == "web.scanner" or SCANNER_UA_RE.search(ua):
        hits.append(RuleHit("R-SCANNER", "Security scanner detected", "MEDIUM",
                            f"Known attack tooling user-agent from {log.ip_address}: {ua[:80]}",
                            "recon", "TA0043 Reconnaissance", 48, ["scanner", "reconnaissance"]))

    if log.event_type == "web.admin_probe":
        hits.append(RuleHit("R-ADMIN-PROBE", "Sensitive endpoint probing", "MEDIUM",
                            f"Probe of sensitive path {path} from {log.ip_address}",
                            "recon", "TA0043", 38, ["probing"]))

    if log.event_type == "auth.privilege_escalation":
        hits.append(RuleHit("R-PRIVESC", "Privilege escalation attempt", "HIGH",
                            f"Privilege escalation attempt by {log.username or 'unknown'} on {log.host or 'host'}",
                            "privilege_escalation", "TA0004 Privilege Escalation", 75,
                            ["privilege_escalation"]))

    if log.event_type == "system.malware":
        hits.append(RuleHit("R-MALWARE", "Malware signature detected", "CRITICAL",
                            f"Malware signature in event: {msg[:140]}",
                            "malware", "TA0011 External Control", 95, ["malware"]))

    if log.event_type == "network.rate_limited":
        hits.append(RuleHit("R-RATELIMIT", "Rate limiter triggered", "LOW",
                            f"Rate limit hit from {log.ip_address}", "dos", "TA0040 Impact", 35,
                            ["rate_limit"]))

    if log.event_type == "auth.login.failure" and log.username in ("root", "administrator", "admin"):
        hits.append(RuleHit("R-PRIV-LOGIN-FAIL", "Admin account brute-force attempt", "MEDIUM",
                            f"Failed login for privileged account '{log.username}' from {log.ip_address}",
                            "brute_force", "TA0006", 55, ["privileged_account", "brute_force"]))

    return hits


# ---------------------------------------------------------------- window rules


def _logs_last_minutes(db: Session, minutes: int, ip: str | None = None) -> list[LogEntry]:
    since = datetime.utcnow() - timedelta(minutes=minutes)
    q = db.query(LogEntry).filter(LogEntry.timestamp >= since)
    if ip:
        q = q.filter(LogEntry.ip_address == ip)
    return q.all()


def window_rules(db: Session, log: LogEntry) -> list[RuleHit]:
    """Threshold rules evaluated against the recent activity window."""
    hits: list[RuleHit] = []
    ip = log.ip_address
    if not ip:
        return hits

    # --- Brute force --------------------------------------------------------
    if log.event_type == "auth.login.failure":
        recent = _logs_last_minutes(db, settings.BRUTE_FORCE_WINDOW_MIN, ip)
        failures = [l for l in recent if l.event_type == "auth.login.failure"]
        users = {l.username for l in failures if l.username}
        if len(failures) >= settings.BRUTE_FORCE_THRESHOLD:
            target = ", ".join(sorted(users)) or "multiple accounts"
            hits.append(RuleHit(
                "R-BRUTE-FORCE", "Brute-force attack", "HIGH",
                f"{len(failures)} failed logins from {ip} within "
                f"{settings.BRUTE_FORCE_WINDOW_MIN} min targeting {target}",
                "brute_force", "TA0006 Credential Access", 82,
                ["brute_force", f"failures:{len(failures)}"]))

    # --- Port scan (many distinct probed ports/paths) ------------------------
    recent = _logs_last_minutes(db, 3, ip)
    if recent:
        ports = {l.meta.get("dst_port") for l in recent if isinstance(l.meta, dict) and l.meta.get("dst_port")}
        distinct_paths = {l.path for l in recent if l.path}
        n404 = sum(1 for l in recent if l.status_code == 404)
        if len(ports) >= settings.PORTSCAN_THRESHOLD or n404 >= settings.PORTSCAN_THRESHOLD \
                or len(distinct_paths) >= settings.PORTSCAN_THRESHOLD * 2:
            hits.append(RuleHit(
                "R-PORTSCAN", "Port/endpoint scanning", "HIGH",
                f"{ip} probed {max(len(ports), n404, len(distinct_paths) // 2)} distinct "
                f"targets in 3 minutes",
                "port_scan", "TA0043 Reconnaissance", 62, ["port_scan", "reconnaissance"]))

    # --- DoS / request flooding ----------------------------------------------
    rpm = len(recent)
    if rpm >= settings.DOS_RPM_THRESHOLD:
        hits.append(RuleHit(
            "R-DOS", "Request flooding / DoS", "HIGH",
            f"{rpm} requests/min from {ip} exceeds threshold {settings.DOS_RPM_THRESHOLD}",
            "dos", "TA0040 Impact", 78, ["dos", f"rpm:{rpm}"]))

    # --- Data exfiltration ----------------------------------------------------
    if log.bytes_sent:
        big = [l for l in recent if (l.bytes_sent or 0) > settings.EXFIL_BYTES_THRESHOLD // 5]
        total = sum(l.bytes_sent or 0 for l in recent)
        if (log.bytes_sent >= settings.EXFIL_BYTES_THRESHOLD or len(big) >= 4
                or total >= settings.EXFIL_BYTES_THRESHOLD * 4):
            hits.append(RuleHit(
                "R-EXFIL", "Suspected data exfiltration", "CRITICAL",
                f"{total / (1024 * 1024):.1f} MB transferred to {ip} within 3 minutes "
                f"(latest {log.bytes_sent / 1024:.0f} KB)",
                "data_exfiltration", "TA0010 Exfiltration", 88, ["exfiltration", "data_loss"]))

    # --- Systemic error spike -------------------------------------------------
    if log.level in ("ERROR", "CRITICAL"):
        window = _logs_last_minutes(db, 5)
        errs = [l for l in window if l.level in ("ERROR", "CRITICAL")]
        if len(window) >= 20 and len(errs) / len(window) >= 0.5:
            kinds = Counter(l.event_type for l in errs).most_common(3)
            kinds_str = ", ".join(f"{k} ({c})" for k, c in kinds)
            hits.append(RuleHit(
                "R-ERRSPIKE", "Error rate spike", "MEDIUM",
                f"Error rate {len(errs)}/{len(window)} in last 5 min. Top: {kinds_str}",
                "error_spike", "", 45, ["error_spike", "stability"]))

    return hits


def ml_anomaly_hit(features: dict[str, Any], score: float) -> RuleHit:
    """Build a RuleHit from an ML anomaly detection result."""
    return RuleHit(
        "ML-ANOMALY", "ML traffic anomaly", "HIGH",
        (f"Isolation Forest flagged anomalous behaviour from {features.get('ip_address', 'aggregate')}: "
         f"{features.get('request_count', 0)} req, error ratio {features.get('error_ratio', 0):.0%}, "
         f"failed-login ratio {features.get('failed_login_ratio', 0):.0%} "
         f"(anomaly score {score:.3f})"),
        "anomaly", "TA0007 Discovery", int(min(85, 55 + score * 100)),
        ["ml_anomaly", f"score:{score:.2f}"])
