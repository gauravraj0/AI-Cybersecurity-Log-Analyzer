"""Report generation: CSV / JSON exports and executive HTML report."""
import csv
import io
from datetime import datetime, timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from ..models import Alert, Incident, LogEntry
from .ai_summary import build_evidence, heuristic_summary


def logs_to_csv(logs: list[LogEntry]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "timestamp", "source", "host", "level", "category", "event_type",
                "severity", "threat_score", "ip_address", "method", "path", "status_code",
                "bytes_sent", "username", "message"])
    for l in logs:
        w.writerow([l.id, l.timestamp, l.source, l.host, l.level, l.category, l.event_type,
                    l.severity, l.threat_score, l.ip_address, l.method, l.path, l.status_code,
                    l.bytes_sent, l.username, (l.message or "").replace("\n", " ")[:500]])
    return buf.getvalue()


def incidents_to_csv(incidents: list[Incident]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "title", "type", "severity", "status", "threat_score", "event_count",
                "source_ips", "first_seen", "last_seen", "detection_method", "mitre_tactic",
                "ai_summary"])
    for i in incidents:
        w.writerow([i.id, i.title, i.incident_type, i.severity, i.status, i.threat_score,
                    i.event_count, ";".join(map(str, i.source_ips)), i.first_seen, i.last_seen,
                    i.detection_method, i.mitre_tactic, (i.summary or "").replace("\n", " ")])
    return buf.getvalue()


def alerts_to_csv(alerts: list[Alert]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "created_at", "rule_id", "rule_name", "severity", "ip_address",
                "incident_id", "acknowledged", "message"])
    for a in alerts:
        w.writerow([a.id, a.created_at, a.rule_id, a.rule_name, a.severity, a.ip_address,
                    a.incident_id, a.acknowledged, (a.message or "").replace("\n", " ")])
    return buf.getvalue()


def executive_report(db: Session, hours: int = 24) -> dict:
    """Aggregate KPIs + per-incident AI commentary for the reporting period."""
    since = datetime.utcnow() - timedelta(hours=hours)
    logs = db.query(LogEntry).filter(LogEntry.timestamp >= since).all()
    incidents = db.query(Incident).filter(Incident.last_seen >= since).order_by(Incident.threat_score.desc()).all()
    alerts = db.query(Alert).filter(Alert.created_at >= since).all()

    total = len(logs)
    errs = sum(1 for l in logs if l.level in ("ERROR", "CRITICAL"))
    sev_counts: dict[str, int] = {}
    type_counts: dict[str, int] = {}
    ip_counts: dict[str, int] = {}
    for l in logs:
        sev_counts[l.severity] = sev_counts.get(l.severity, 0) + 1
        type_counts[l.event_type] = type_counts.get(l.event_type, 0) + 1
        if l.ip_address:
            ip_counts[l.ip_address] = ip_counts.get(l.ip_address, 0) + 1

    incident_blocks = []
    for inc in incidents[:15]:
        evidence_logs = [ie.log for ie in inc.events[:40]]
        if not inc.summary:
            inc.summary, inc.recommendation = heuristic_summary(inc, evidence_logs)
        incident_blocks.append({
            "id": inc.id, "title": inc.title, "severity": inc.severity, "status": inc.status,
            "threat_score": inc.threat_score, "event_count": inc.event_count,
            "summary": inc.summary, "recommendation": inc.recommendation,
            "source_ips": inc.source_ips, "mitre": inc.mitre_tactic,
        })

    return {
        "period": {"hours": hours, "since": since.isoformat() + "Z",
                   "generated_at": datetime.utcnow().isoformat() + "Z"},
        "kpi": {
            "total_events": total,
            "errors": errs,
            "error_rate": round(errs / total, 4) if total else 0.0,
            "incidents": len(incidents),
            "critical_incidents": sum(1 for i in incidents if i.severity == "CRITICAL"),
            "alerts": len(alerts),
            "top_attack_type": max(type_counts, key=type_counts.get) if type_counts else None,
        },
        "severity_breakdown": sev_counts,
        "top_event_types": sorted(type_counts.items(), key=lambda x: -x[1])[:10],
        "top_ips": sorted(ip_counts.items(), key=lambda x: -x[1])[:10],
        "incidents": incident_blocks,
    }


def executive_report_html(report: dict) -> str:
    sev = report["severity_breakdown"]
    kpi = report["kpi"]
    rows = "".join(
        f"<tr><td>#{i['id']}</td><td><b>{i['title']}</b></td>"
        f"<td class='sev-{i['severity'].lower()}'>{i['severity']}</td>"
        f"<td>{i['status']}</td><td>{i['event_count']}</td><td>{', '.join(map(str, i['source_ips'][:3]))}</td></tr>"
        f"<tr class='summary-row'><td colspan='6'>{i['summary']}<br><i>Actions: {i['recommendation'].replace(chr(10), ' | ')}</i></td></tr>"
        for i in report["incidents"])
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>SentinelLens Executive Security Report</title>
<style>
 body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; color: #1a202c; background:#fff; }}
 h1 {{ color: #0f172a; border-bottom: 3px solid #ef4444; padding-bottom: 8px; }}
 .kpi {{ display:flex; gap:18px; margin: 22px 0; flex-wrap:wrap; }}
 .card {{ border:1px solid #e2e8f0; border-radius:10px; padding:14px 20px; min-width:150px; background:#f8fafc; }}
 .card .num {{ font-size:30px; font-weight:700; color:#0f172a; }}
 .card .lbl {{ font-size:12px; text-transform:uppercase; color:#64748b; letter-spacing:.05em; }}
 table {{ border-collapse: collapse; width: 100%; margin-top: 12px; font-size: 14px; }}
 th, td {{ border: 1px solid #e2e8f0; padding: 8px 10px; text-align: left; vertical-align: top; }}
 th {{ background: #0f172a; color: white; text-transform: uppercase; font-size: 11px; letter-spacing: .06em; }}
 .sev-critical {{ color:#b91c1c; font-weight:700; }} .sev-high {{ color:#c2410c; font-weight:700; }}
 .sev-medium {{ color:#a16207; font-weight:600; }} .sev-low {{ color:#1d4ed8; }}
 .summary-row td {{ background:#f8fafc; font-size:13px; color:#334155; }}
 footer {{ margin-top: 30px; font-size: 12px; color: #64748b; }}
 @media print {{ body {{ margin: 12mm; }} }}
</style></head><body>
<h1>SentinelLens — Executive Security Report</h1>
<p>Reporting window: last {report['period']['hours']} hours (since {report['period']['since'][:16].replace('T',' ')} UTC)</p>
<div class="kpi">
 <div class="card"><div class="num">{kpi['total_events']:,}</div><div class="lbl">Log Events</div></div>
 <div class="card"><div class="num">{kpi['incidents']}</div><div class="lbl">Incidents</div></div>
 <div class="card"><div class="num">{kpi['critical_incidents']}</div><div class="lbl">Critical Incidents</div></div>
 <div class="card"><div class="num">{kpi['alerts']}</div><div class="lbl">Alerts</div></div>
 <div class="card"><div class="num">{kpi['error_rate']:.1%}</div><div class="lbl">Error Rate</div></div>
</div>
<h2>Severity distribution</h2>
<p>{' · '.join(f"<b>{k}</b>: {v}" for k, v in sorted(sev.items(), key=lambda x: -x[1])) or 'No events'}</p>
<h2>Top threat sources</h2>
<p>{' · '.join(f"<code>{ip}</code> ({c})" for ip, c in report['top_ips'][:8]) or 'None'}</p>
<h2>Incident register (AI-analysed)</h2>
<table><tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Events</th><th>Sources</th></tr>
{rows or "<tr><td colspan='6'>No incidents in this period.</td></tr>"}
</table>
<footer>Generated by SentinelLens AI Cybersecurity Log Analyzer · {report['period']['generated_at'][:19].replace('T',' ')} UTC · AI provider for summaries where listed: per-incident</footer>
</body></html>"""
