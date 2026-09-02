"""AI-generated incident summaries.

Provider chain:
1. OpenAI   (if OPENAI_API_KEY is set)
2. Anthropic (if ANTHROPIC_API_KEY is set)
3. Built-in heuristic analyst engine (always available fallback) - assembles a
   structured SOC-grade narrative from the incident's evidence trail.
"""
import logging
import re
from collections import Counter
from datetime import datetime
from typing import Any

import httpx
from sqlalchemy.orm import Session

from ..config import settings
from ..models import Incident, LogEntry
from ..detection.classify import display_name

logger = logging.getLogger("ai_summary")

RECOMMENDATIONS: dict[str, list[str]] = {
    "web_attack": [
        "Block the source IP(s) at the WAF/edge and add request-body inspection rules for the matched pattern.",
        "Parameterise all database queries and deploy prepared statements to neutralise injection payloads.",
        "Review targeted endpoints for input validation gaps and add them to regression tests.",
    ],
    "brute_force": [
        "Enforce account lockout / exponential backoff on repeated failures and block the source IP(s).",
        "Require MFA for all affected accounts and rotate credentials that show failures.",
        "Cross-check successful logins from the same IP within the window for signs of compromise.",
    ],
    "dos": [
        "Apply rate limiting / connection caps per source IP and enable CDN or SYN-flood protection.",
        "Auto-scale or shed load on affected endpoints; monitor upstream dependency saturation.",
    ],
    "port_scan": [
        "Block the scanning IP and close non-essential ports exposed at the perimeter.",
        "Verify there were no successful connections following the scan on the probed services.",
    ],
    "privilege_escalation": [
        "Audit sudo/su configuration on affected hosts and restrict admin groups to named users.",
        "Review shell history and cron entries for the involved accounts; rotate privileged credentials.",
    ],
    "data_exfiltration": [
        "Quarantine the affected host and throttle outbound egress; review DLP logs for sensitive data types.",
        "Validate whether the transfer was sanctioned; if not, treat as breach and start IR playbook.",
    ],
    "anomaly": [
        "Correlate the anomalous source with firewall, VPN and EDR telemetry before clearing.",
        "Capture full packet logs for the flagged window and review for staged attack activity.",
    ],
    "error_spike": [
        "Check recent deployments and dependency health on affected services; roll back if regression.",
        "Verify the spike is not masking an attack (e.g. payload-induced exceptions) by sampling error payloads.",
    ],
    "malware": [
        "Isolate the affected endpoint from the network immediately and collect forensic images.",
        "Run a full AV/EDR sweep and block the associated hashes/domains across the estate.",
    ],
    "recon": [
        "Block the scanner IP(s) and ensure security headers and error pages do not leak stack details.",
        "Compare scan window against vulnerability scan calendar to rule out authorised testing.",
    ],
    "generic": [
        "Review raw events for this incident and extend detection coverage if a new pattern emerges.",
    ],
}

MITRE_MAP = {
    "web_attack": "T1190 Exploit Public-Facing Application",
    "brute_force": "T1110 Brute Force",
    "dos": "T1498 Network Denial of Service",
    "port_scan": "T1046 Network Service Discovery",
    "privilege_escalation": "T1068 Exploitation for Privilege Escalation",
    "data_exfiltration": "T1041 Exfiltration Over C2 Channel",
    "malware": "T1203 Exploitation for Client Execution",
    "anomaly": "T1087 Account Discovery",
}


def _fmt_dt(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "unknown"


def build_evidence(incident: Incident, logs: list[LogEntry]) -> dict[str, Any]:
    ev = {
        "top_ips": Counter(l.ip_address for l in logs if l.ip_address).most_common(5),
        "top_paths": Counter(l.path for l in logs if l.path).most_common(5),
        "top_users": Counter(l.username for l in logs if l.username).most_common(5),
        "top_event_types": Counter(l.event_type for l in logs).most_common(5),
        "levels": Counter(l.level for l in logs).most_common(),
        "hosts": {l.host for l in logs if l.host},
        "user_agents": Counter((l.user_agent or "")[:60] for l in logs if l.user_agent).most_common(3),
        "first": min((l.timestamp for l in logs if l.timestamp), default=None),
        "last": max((l.timestamp for l in logs if l.timestamp), default=None),
        "sample_messages": [l.message[:220] for l in logs[:5]],
    }
    return ev


def heuristic_summary(incident: Incident, logs: list[LogEntry]) -> tuple[str, str]:
    """Deterministic analyst-grade summary + recommendations."""
    ev = build_evidence(incident, logs)
    ips = ", ".join(ip for ip, _ in ev["top_ips"]) or "unattributed sources"
    n = incident.event_count
    window = ""
    if ev["first"] and ev["last"]:
        span = (ev["last"] - ev["first"]).total_seconds()
        window = f" over a {span / 60:.0f}-minute window" if span >= 90 else f" within {max(span, 1):.0f} seconds"

    parts: list[str] = []
    parts.append(
        f"A {incident.severity.lower()}-severity {display_name(incident.incident_type).lower()} incident "
        f"involving {n} correlated events{window} was detected via "
        f"{'machine-learning anomaly detection' if incident.detection_method == 'ml_anomaly' else 'signature and threshold rules'}."
    )

    if ev["top_ips"]:
        ip_detail = ", ".join(f"{ip} ({c} events)" for ip, c in ev["top_ips"][:3])
        parts.append(f"Primary source activity originates from: {ip_detail}.")

    if ev["top_paths"]:
        paths = ", ".join(str(p) for p, _ in ev["top_paths"][:3])
        parts.append(f"Targeted resources include: {paths}.")

    if ev["top_users"]:
        parts.append(f"Accounts referenced: {', '.join(f'{u} ({c})' for u, c in ev['top_users'][:3])}.")

    if ev["top_event_types"]:
        kinds = ", ".join(display_name(k) for k, _ in ev["top_event_types"][:3])
        parts.append(f"Dominant event signatures: {kinds}. Threat score peaked at {incident.threat_score}/100.")

    if ev["user_agents"]:
        uas = "; ".join(ua for ua, _ in ev["user_agents"][:2] if ua)
        if uas:
            parts.append(f"Client signatures observed: {uas}.")

    if incident.labels:
        parts.append(f"Detection labels: {', '.join(map(str, incident.labels[:6]))}.")

    summary = " ".join(parts)

    recs = RECOMMENDATIONS.get(incident.incident_type, RECOMMENDATIONS["generic"])
    recommendation = (
        f"1. {recs[0]}\n2. {recs[1] if len(recs) > 1 else recs[0]}\n"
        f"3. Preserve evidence (logs for {_fmt_dt(ev['first'])} - {_fmt_dt(ev['last'])}) "
        f"and update detection baselines once resolved."
    )
    return summary, recommendation


# ---------------------------------------------------------------- LLM providers


def _llm_prompt(incident: Incident, logs: list[LogEntry]) -> str:
    ev = build_evidence(incident, logs)
    lines = [
        f"Incident: {incident.title}",
        f"Type: {incident.incident_type} | Severity: {incident.severity} | Threat score: {incident.threat_score}/100",
        f"Events: {incident.event_count} between {_fmt_dt(incident.first_seen)} and {_fmt_dt(incident.last_seen)}",
        f"Source IPs: {', '.join(map(str, incident.source_ips[:8]))}",
        f"Targets: {', '.join(map(str, incident.targets[:8]))}",
        f"Detection labels: {', '.join(map(str, incident.labels[:10]))}",
        "",
        "Sample log events:",
    ]
    for l in logs[:12]:
        lines.append(f"- [{_fmt_dt(l.timestamp)}] {l.level} {l.event_type} ip={l.ip_address} user={l.username} {l.message[:160]}")
    lines += [
        "",
        "Write: (1) a factual incident summary paragraph (5-8 sentences) citing the concrete evidence,",
        "then a line starting with 'RECOMMENDATIONS:' followed by 3 numbered immediate actions.",
        "Be concise, SOC-analyst tone, no speculation beyond the evidence.",
    ]
    return "\n".join(lines)


def _parse_llm(text: str) -> tuple[str, str]:
    m = re.search(r"RECOMMENDATIONS\s*:\s*(.*)$", text, re.S | re.I)
    if m:
        return text[: m.start()].strip(), m.group(1).strip()
    return text.strip(), ""


def _openai(prompt: str) -> tuple[str, str] | None:
    if not settings.OPENAI_API_KEY:
        return None
    try:
        r = httpx.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {settings.OPENAI_API_KEY}"},
            json={"model": settings.OPENAI_MODEL,
                  "messages": [{"role": "system", "content": "You are a senior SOC incident responder."},
                               {"role": "user", "content": prompt}],
                  "temperature": 0.2, "max_tokens": 600},
            timeout=25,
        )
        r.raise_for_status()
        return _parse_llm(r.json()["choices"][0]["message"]["content"])
    except Exception as exc:  # noqa: BLE001
        logger.warning("OpenAI summary failed: %s", exc)
        return None


def _anthropic(prompt: str) -> tuple[str, str] | None:
    if not settings.ANTHROPIC_API_KEY:
        return None
    try:
        r = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": settings.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01"},
            json={"model": settings.ANTHROPIC_MODEL, "max_tokens": 700,
                  "messages": [{"role": "user", "content": prompt}]},
            timeout=25,
        )
        r.raise_for_status()
        return _parse_llm(r.json()["content"][0]["text"])
    except Exception as exc:  # noqa: BLE001
        logger.warning("Anthropic summary failed: %s", exc)
        return None


def generate_incident_summary(db: Session, incident: Incident) -> Incident:
    """Generate (or regenerate) the AI summary for an incident."""
    logs = [ie.log for ie in incident.events[:60]]
    result = _openai(_llm_prompt(incident, logs)) or _anthropic(_llm_prompt(incident, logs))
    if result:
        incident.summary, incident.recommendation = result
        incident.ai_provider = "openai" if settings.OPENAI_API_KEY else "anthropic"
    else:
        incident.summary, incident.recommendation = heuristic_summary(incident, logs)
        incident.ai_provider = "heuristic"
    db.add(incident)
    db.commit()
    return incident
