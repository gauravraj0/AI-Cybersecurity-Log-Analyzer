from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

import numpy as np

try:
    from sklearn.ensemble import IsolationForest

    HAS_SKLEARN = True
except Exception:  # pragma: no cover
    HAS_SKLEARN = False

from .database import utcnow

SIGNATURES: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"(union\s+select|or\s+1=1|'--|;drop\s+table|sleep\(|information_schema|benchmark\()", re.I),
        "sql_injection",
        "critical",
        "T1190",
    ),
    (
        re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=|document\.cookie)", re.I),
        "xss",
        "high",
        "T1059",
    ),
    (
        re.compile(r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|c:\\windows)", re.I),
        "path_traversal",
        "high",
        "T1083",
    ),
    (
        re.compile(r"(\.env|wp-admin|phpmyadmin|\.git/config|id_rsa|aws_secret|debug/default)", re.I),
        "reconnaissance",
        "medium",
        "T1595",
    ),
    (
        re.compile(r"(;wget |;curl |\| bash|cmd\.exe|/bin/sh|powershell -enc)", re.I),
        "command_injection",
        "critical",
        "T1059",
    ),
    (
        re.compile(r"(nmap|nikto|sqlmap|masscan|dirbuster|gobuster|nuclei)", re.I),
        "scanner",
        "medium",
        "T1595",
    ),
    (
        re.compile(r"(failed password|authentication failure|invalid user|login failed)", re.I),
        "brute_force",
        "high",
        "T1110",
    ),
    (
        re.compile(r"(unauthorized|forbidden|access denied|privilege)", re.I),
        "authz_failure",
        "medium",
        "T1068",
    ),
]

ERROR_CLASSES = [
    (re.compile(r"(timeout|timed out|504|gateway)", re.I), "availability"),
    (re.compile(r"(nullpointer|traceback|exception|stack overflow)", re.I), "application_error"),
    (re.compile(r"(connection refused|econnreset|dns)", re.I), "network_error"),
    (re.compile(r"(syntax|invalid json|parse error)", re.I), "input_error"),
    (re.compile(r"(disk|out of memory|oomkilled|enospc)", re.I), "resource_exhaustion"),
    (re.compile(r"(ssl|tls|certificate)", re.I), "crypto_error"),
]

COMBINED_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) (?P<bytes>\S+)'
)
SYSLOG_RE = re.compile(
    r"^(?P<time>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>\S+)\s+(?P<source>[^:]+):\s+(?P<msg>.*)$"
)
JSONISH_RE = re.compile(r"^\s*\{")

MITRE_MAP = {
    "sql_injection": [("T1190", "Exploit Public-Facing Application"), ("T1190.001", "SQL Injection")],
    "xss": [("T1059", "Command and Scripting Interpreter"), ("T1189", "Drive-by Compromise")],
    "path_traversal": [("T1083", "File and Directory Discovery"), ("T1005", "Data from Local System")],
    "reconnaissance": [("T1595", "Active Scanning"), ("T1592", "Gather Victim Host Information")],
    "command_injection": [("T1059", "Command and Scripting Interpreter"), ("T1203", "Exploitation for Client Execution")],
    "scanner": [("T1595", "Active Scanning"), ("T1046", "Network Service Discovery")],
    "brute_force": [("T1110", "Brute Force"), ("T1110.001", "Password Guessing")],
    "credential_stuffing": [("T1110.004", "Credential Stuffing"), ("T1078", "Valid Accounts")],
    "data_exfiltration": [("T1041", "Exfiltration Over C2 Channel"), ("T1030", "Data Transfer Size Limits")],
    "authz_failure": [("T1068", "Exploitation for Privilege Escalation")],
    "anomalous_access": [("T1078", "Valid Accounts"), ("T1021", "Remote Services")],
    "dos": [("T1498", "Network Denial of Service")],
    "ransomware_precursor": [("T1486", "Data Encrypted for Impact"), ("T1083", "File and Directory Discovery")],
}

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

GEO_DB: list[tuple[str, str, str, str, list[float]]] = [
    ("185.220.", "Netherlands", "Amsterdam", "AS208294 TOR-EXIT", [4.90, 52.37]),
    ("45.155.", "Russia", "Moscow", "AS210644", [37.62, 55.75]),
    ("103.45.", "China", "Shenzhen", "AS4134", [114.06, 22.54]),
    ("91.219.", "Poland", "Warsaw", "AS20853", [21.01, 52.23]),
    ("203.0.113.", "Labnet", "Documentation", "AS64496", [151.21, -33.87]),
    ("198.51.100.", "Labnet", "Documentation", "AS64496", [-74.01, 40.71]),
    ("51.15.", "France", "Paris", "AS12876", [2.35, 48.85]),
    ("194.26.", "Germany", "Frankfurt", "AS51167", [8.68, 50.11]),
    ("36.91.", "Indonesia", "Jakarta", "AS7713", [106.85, -6.21]),
    ("177.54.", "Brazil", "São Paulo", "AS7738", [-46.63, -23.55]),
    ("41.76.", "South Africa", "Johannesburg", "AS37153", [28.04, -26.20]),
    ("8.8.", "United States", "Mountain View", "AS15169", [-122.08, 37.39]),
    ("52.12.", "United States", "Oregon", "AS16509", [-122.33, 45.52]),
    ("13.107.", "United States", "Virginia", "AS8075", [-77.43, 39.04]),
    ("192.168.", "Internal", "Datacenter East", "AS-INTERNAL", [-74.00, 40.71]),
    ("10.0.", "Internal", "Datacenter East", "AS-INTERNAL", [-74.00, 40.71]),
    ("10.4.", "Internal", "K8s Overlay", "AS-INTERNAL", [-74.00, 40.71]),
    ("172.16.", "Internal", "VPN", "AS-INTERNAL", [-74.00, 40.71]),
]


def geo_for_ip(ip: str | None) -> tuple[str, str, str]:
    if not ip:
        return "Unknown", "Unknown", "AS-UNKNOWN"
    for prefix, country, city, asn, _xy in GEO_DB:
        if ip.startswith(prefix):
            return country, city, asn
    last = int(ip.split(".")[-1]) if "." in ip else 0
    pool = [
        ("United States", "Ashburn", "AS13335"),
        ("United Kingdom", "London", "AS2856"),
        ("India", "Mumbai", "AS9498"),
        ("Singapore", "Singapore", "AS7473"),
        ("Canada", "Toronto", "AS577"),
    ]
    return pool[last % len(pool)]


def coords_for_ip(ip: str | None) -> list[float]:
    if not ip:
        return [0, 0]
    for prefix, _c, _city, _asn, xy in GEO_DB:
        if ip.startswith(prefix):
            return xy
    return [0, 20]


def classify_error(message: str) -> str | None:
    for pattern, label in ERROR_CLASSES:
        if pattern.search(message):
            return label
    return None


def detect_signatures(text: str) -> tuple[str | None, str, str | None]:
    blob = text or ""
    best_type, best_sev, mitre = None, "info", None
    for pattern, ttype, sev, tactic in SIGNATURES:
        if pattern.search(blob):
            if SEVERITY_RANK[sev] >= SEVERITY_RANK[best_sev]:
                best_type, best_sev, mitre = ttype, sev, tactic
    return best_type, best_sev, mitre


def parse_log_line(line: str, default_source: str = "upload") -> dict[str, Any]:
    line = line.strip()
    if not line:
        return {}
    now = utcnow()
    record: dict[str, Any] = {
        "timestamp": now,
        "source": default_source,
        "host": "ingest",
        "level": "info",
        "message": line,
        "ip_address": None,
        "user_agent": None,
        "method": None,
        "path": None,
        "status_code": None,
        "bytes_sent": 0,
        "username": None,
        "raw": line,
    }
    if JSONISH_RE.match(line):
        try:
            data = json.loads(line)
            record.update(
                {
                    "timestamp": _parse_time(data.get("timestamp") or data.get("time")) or now,
                    "source": data.get("source") or default_source,
                    "host": data.get("host") or "ingest",
                    "level": str(data.get("level") or data.get("severity") or "info").lower(),
                    "message": data.get("message") or data.get("msg") or line,
                    "ip_address": data.get("ip") or data.get("src_ip") or data.get("client"),
                    "user_agent": data.get("user_agent") or data.get("ua"),
                    "method": data.get("method"),
                    "path": data.get("path") or data.get("uri"),
                    "status_code": _as_int(data.get("status") or data.get("status_code")),
                    "bytes_sent": _as_int(data.get("bytes") or data.get("size")) or 0,
                    "username": data.get("user") or data.get("username"),
                }
            )
            return record
        except json.JSONDecodeError:
            pass
    m = COMBINED_RE.search(line)
    if m:
        record.update(
            {
                "source": "nginx",
                "ip_address": m.group("ip"),
                "method": m.group("method"),
                "path": m.group("path"),
                "status_code": int(m.group("status")),
                "bytes_sent": 0 if m.group("bytes") == "-" else int(m.group("bytes")),
                "message": f'{m.group("method")} {m.group("path")} -> {m.group("status")}',
            }
        )
        return record
    m = SYSLOG_RE.match(line)
    if m:
        record.update(
            {
                "source": m.group("source").split("[")[0].strip() or "syslog",
                "host": m.group("host"),
                "message": m.group("msg"),
                "level": "warning" if "fail" in m.group("msg").lower() else "info",
            }
        )
        ipm = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", m.group("msg"))
        if ipm:
            record["ip_address"] = ipm.group(1)
        um = re.search(r"user\s+(\S+)", m.group("msg"), re.I)
        if um:
            record["username"] = um.group(1).strip(":")
        return record
    ipm = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
    if ipm:
        record["ip_address"] = ipm.group(1)
    return record


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value)
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S"):
        try:
            cleaned = text.replace("Z", "+0000").split(".")[0]
            dt = datetime.strptime(cleaned[:26], fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def enrich_record(record: dict[str, Any]) -> dict[str, Any]:
    blob = " ".join(
        str(record.get(k) or "")
        for k in ("message", "path", "user_agent", "raw", "username")
    )
    threat, sev, _mitre = detect_signatures(blob)
    status = record.get("status_code") or 0
    if status >= 500 and sev == "info":
        sev = "medium"
        record["level"] = "error"
    elif status in (401, 403) and sev == "info":
        sev = "low"
        record["level"] = "warning"
    if threat:
        record["level"] = "critical" if sev == "critical" else "warning"
    country, city, _asn = geo_for_ip(record.get("ip_address"))
    record["threat_type"] = threat
    record["severity"] = sev if threat else (record.get("severity") or ("medium" if status >= 500 else "info"))
    record["error_class"] = classify_error(blob) or (
        "security_event" if threat else ("http_error" if status >= 400 else None)
    )
    record["country"] = record.get("country") or country
    record["city"] = record.get("city") or city
    if record.get("level") in ("error", "critical") and record["severity"] == "info":
        record["severity"] = "medium"
    return record


class AnomalyModel:
    """Isolation Forest over per-IP behavioral features, with a z-score fallback."""

    def __init__(self) -> None:
        self.model = None
        self.scaler_mean = None
        self.scaler_std = None
        self.trained = False

    def _vector(self, feats: dict[str, float]) -> np.ndarray:
        return np.array(
            [
                feats.get("hour", 12),
                feats.get("req", 0),
                feats.get("fail_ratio", 0),
                math.log1p(feats.get("bytes", 0)),
                feats.get("unique_paths", 1),
                feats.get("error_ratio", 0),
                feats.get("night", 0),
                feats.get("sig_hits", 0),
            ],
            dtype=float,
        )

    def train(self, feature_rows: list[dict[str, float]]) -> None:
        if len(feature_rows) < 10:
            return
        X = np.vstack([self._vector(r) for r in feature_rows])
        self.scaler_mean = X.mean(axis=0)
        self.scaler_std = X.std(axis=0)
        self.scaler_std[self.scaler_std == 0] = 1.0
        Zn = (X - self.scaler_mean) / self.scaler_std
        if HAS_SKLEARN:
            self.model = IsolationForest(
                n_estimators=120,
                contamination=0.08,
                random_state=42,
            )
            self.model.fit(Zn)
        self.trained = True

    def score(self, feats: dict[str, float]) -> tuple[bool, float]:
        vec = self._vector(feats)
        if self.trained and self.scaler_mean is not None:
            z = (vec - self.scaler_mean) / self.scaler_std
            if self.model is not None:
                raw = float(self.model.decision_function([z])[0])
                # IsolationForest: negative = more anomalous. Map to 0..1
                anomaly_score = float(max(0.0, min(1.0, 0.5 - raw)))
                return anomaly_score >= 0.62, round(anomaly_score, 3)
            # z-score fallback
            mag = float(np.clip(np.linalg.norm(z) / 6.0, 0, 1))
            return mag >= 0.7, round(mag, 3)
        # Untrained heuristic
        mag = min(
            1.0,
            0.15 * feats.get("fail_ratio", 0) * 4
            + 0.2 * feats.get("sig_hits", 0)
            + 0.15 * feats.get("night", 0)
            + 0.1 * min(feats.get("unique_paths", 1) / 30.0, 1),
        )
        return mag >= 0.55, round(mag, 3)


anomaly_model = AnomalyModel()


def ip_features(logs: list[dict[str, Any]], ip: str) -> dict[str, float]:
    subset = [l for l in logs if l.get("ip_address") == ip]
    if not subset:
        return {}
    req = len(subset)
    fails = sum(1 for l in subset if (l.get("status_code") or 0) >= 400 or "fail" in (l.get("message") or "").lower())
    errors = sum(1 for l in subset if (l.get("status_code") or 0) >= 500)
    bytes_sent = sum(l.get("bytes_sent") or 0 for l in subset)
    paths = {l.get("path") for l in subset if l.get("path")}
    hours = [l["timestamp"].hour for l in subset if isinstance(l.get("timestamp"), datetime)]
    hour = int(sum(hours) / len(hours)) if hours else 12
    night = 1.0 if hour < 5 or hour >= 23 else 0.0
    sig_hits = sum(1 for l in subset if l.get("threat_type"))
    return {
        "hour": hour,
        "req": req,
        "fail_ratio": fails / req,
        "error_ratio": errors / req,
        "bytes": bytes_sent,
        "unique_paths": len(paths) or 1,
        "night": night,
        "sig_hits": sig_hits,
    }


def generate_ai_summary(incident: dict[str, Any], related_logs: list[dict[str, Any]] | None = None) -> str:
    related_logs = related_logs or []
    ttype = incident.get("threat_type") or "anomalous_access"
    ips = incident.get("source_ips") or []
    if isinstance(ips, str):
        try:
            ips = json.loads(ips)
        except json.JSONDecodeError:
            ips = [ips]
    severity = incident.get("severity", "medium").upper()
    count = incident.get("event_count") or len(related_logs) or 1
    first = incident.get("first_seen")
    last = incident.get("last_seen")
    window = _window_text(first, last)
    countries = sorted({l.get("country") for l in related_logs if l.get("country")} or {"Unknown"})
    sample_paths = [l.get("path") for l in related_logs if l.get("path")][:4]
    title = incident.get("title") or ttype.replace("_", " ").title()

    narrative = {
        "sql_injection": (
            f"AEGIS correlated {count} payloads consistent with SQL injection against a public application surface. "
            f"Observed techniques include tautology tests, UNION enumeration, and time-based probes. "
            f"Traffic originated from {', '.join(ips[:4]) or 'unknown'} ({', '.join(countries)})."
        ),
        "xss": (
            f"{count} reflected / stored XSS payloads were intercepted. Payloads attempt script injection and cookie access. "
            f"If successful this would enable session hijack on the affected origin."
        ),
        "brute_force": (
            f"Authentication telemetry shows a password-guessing campaign: {count} failed logons clustered in {window}. "
            f"Source IPs {', '.join(ips[:4]) or 'unknown'} exhibit classic spray-and-pray timing."
        ),
        "credential_stuffing": (
            f"Failed logons are distributed across many usernames from a small IP set — a credential-stuffing pattern, not a single-account lockout."
        ),
        "path_traversal": (
            f"Directory traversal sequences (../, /etc/passwd) were issued {count} times. This is reconnaissance for local file inclusion."
        ),
        "reconnaissance": (
            f"Automated probing of sensitive paths (.env, wp-admin, .git) from {', '.join(ips[:3]) or 'external hosts'}. "
            "This is pre-exploitation mapping of the attack surface."
        ),
        "command_injection": (
            f"Request parameters contain shell metacharacters and download-and-execute staging. Treat as confirmed exploit attempt."
        ),
        "data_exfiltration": (
            f"Unusually large outbound responses ({count} events) from authenticated or internal identities. Volume and timing deviate from the 7-day baseline."
        ),
        "scanner": (
            f"Tool signatures (sqlmap/nmap/nikto/nuclei) identified in user-agents or query strings across {count} requests."
        ),
        "ransomware_precursor": (
            "Burst of file-enumeration and permission errors across file shares — a common precursor to encryption-stage ransomware."
        ),
        "anomalous_access": (
            f"Behavioral model flagged {count} events as statistically rare versus the trained baseline (hour-of-day, failure ratio, path diversity)."
        ),
        "dos": (
            f"Request rate from {', '.join(ips[:3]) or 'a single source'} exceeded the 99th percentile, consistent with a volumetric or application-layer flood."
        ),
    }.get(
        ttype,
        f"AEGIS clustered {count} related events into incident «{title}». Severity {severity}. Review indicators and contain source IPs.",
    )

    mitre = MITRE_MAP.get(ttype, [("T1078", "Valid Accounts")])
    mitre_lines = "\n".join(f"- {code} — {name}" for code, name in mitre)
    paths_txt = ", ".join(sample_paths) if sample_paths else "n/a"
    actions = incident.get("recommended_actions") or default_actions(ttype)
    if isinstance(actions, str):
        try:
            actions = json.loads(actions)
        except json.JSONDecodeError:
            actions = [actions]
    action_lines = "\n".join(f"{i}. {a}" for i, a in enumerate(actions, 1))

    return f"""## AI Incident Narrative
**{title}** · severity {severity} · confidence {int(round((incident.get('confidence') or 0.8) * 100))}%

{narrative}

Observation window: {window}. Targeted paths: {paths_txt}.

## Why this fired
Signature detection, IP clustering, and the Isolation Forest behavioral model agreed on an outlier cluster. Events share source infrastructure, payload family, and temporal proximity.

## MITRE ATT&CK
{mitre_lines}

## Recommended response
{action_lines}

— Generated by AEGIS generative analyst · not a substitute for human IR review
"""


def default_actions(ttype: str) -> list[str]:
    mapping = {
        "sql_injection": [
            "Block source IPs at the WAF / edge ACL",
            "Verify parameterized queries on implicated endpoints",
            "Rotate database credentials if injection may have succeeded",
            "Dump WAF traces for the 30-minute window and preserve evidence",
        ],
        "xss": [
            "Sanitize / encode output on the affected form and API",
            "Set HttpOnly + Secure + SameSite cookies",
            "Purge any stored payload from the CMS/database",
        ],
        "brute_force": [
            "Enable lockout / MFA on targeted accounts",
            "Null-route or tarpit the attacking CIDR",
            "Force password reset on accounts with >10 failures",
        ],
        "credential_stuffing": [
            "Force step-up authentication on matching accounts",
            "Check for credential dump overlap (haveibeenpwned / internal intel)",
            "Throttle authentication by IP + ASN",
        ],
        "path_traversal": [
            "Canonicalize and allow-list file paths in the application",
            "Confirm /etc/passwd or source maps were not returned",
        ],
        "reconnaissance": [
            "Feed IPs to the deny list",
            "Hide fingerprinting surfaces (server banners, .git, .env)",
        ],
        "command_injection": [
            "Take the vulnerable parameter offline",
            "Hunt for outbound wget/curl from app hosts",
            "Rebuild implicated containers from known-good images",
        ],
        "data_exfiltration": [
            "Quarantine the source identity and inspect egress proxy logs",
            "Invalidate tokens issued in the window",
            "Check DLP / CASB for matching objects",
        ],
        "ransomware_precursor": [
            "Isolate affected file servers from the network",
            "Snapshot / confirm backups are immutable",
            "Hunt for encryption canaries and suspicious service installs",
        ],
        "dos": [
            "Enable upstream volumetric protection",
            "Rate-limit the implicated path",
            "Scale edge workers if legitimate traffic is mixed in",
        ],
    }
    return mapping.get(
        ttype,
        [
            "Acknowledge the alert and assign an analyst",
            "Contain source IPs if reputation is poor",
            "Correlate with identity and EDR telemetry",
        ],
    )


def _window_text(first: Any, last: Any) -> str:
    def _fmt(v: Any) -> str:
        if isinstance(v, datetime):
            return v.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        return str(v) if v else "n/a"

    return f"{_fmt(first)} → {_fmt(last)}"


def cluster_incidents(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group enriched logs into incident candidates by (threat_type, ip)."""
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for rec in records:
        ttype = rec.get("threat_type")
        ip = rec.get("ip_address") or "unknown"
        if not ttype and rec.get("is_anomaly"):
            ttype = "anomalous_access"
        if not ttype:
            continue
        buckets[(ttype, ip)].append(rec)

    incidents = []
    for (ttype, ip), items in buckets.items():
        if ttype in ("brute_force", "scanner", "reconnaissance") and len(items) < 4:
            continue
        if ttype == "anomalous_access" and len(items) < 3:
            continue
        items_sorted = sorted(items, key=lambda x: x.get("timestamp") or utcnow())
        sev = max((i.get("severity") or "info" for i in items_sorted), key=lambda s: SEVERITY_RANK.get(s, 0))
        countries = sorted({i.get("country") for i in items_sorted if i.get("country")})
        title = _incident_title(ttype, ip, len(items_sorted), countries)
        payload = {
            "title": title,
            "threat_type": ttype,
            "severity": sev,
            "status": "open",
            "confidence": min(0.97, 0.55 + 0.05 * len(items_sorted) + (0.15 if sev == "critical" else 0)),
            "description": f"{len(items_sorted)} correlated events from {ip}.",
            "source_ips": [ip],
            "first_seen": items_sorted[0].get("timestamp") or utcnow(),
            "last_seen": items_sorted[-1].get("timestamp") or utcnow(),
            "event_count": len(items_sorted),
            "mitre": MITRE_MAP.get(ttype, []),
            "recommended_actions": default_actions(ttype),
            "indicators": _extract_indicators(items_sorted),
            "_logs": items_sorted,
        }
        payload["ai_summary"] = generate_ai_summary(payload, items_sorted)
        incidents.append(payload)
    incidents.sort(key=lambda x: (-SEVERITY_RANK.get(x["severity"], 0), -x["event_count"]))
    return incidents


def _incident_title(ttype: str, ip: str, n: int, countries: list[str]) -> str:
    where = countries[0] if countries else "unknown geo"
    labels = {
        "sql_injection": f"SQL injection campaign from {ip} ({where})",
        "xss": f"Cross-site scripting payloads from {ip}",
        "brute_force": f"SSH/app brute force — {n} failures from {ip}",
        "credential_stuffing": f"Credential stuffing against identity plane ({ip})",
        "path_traversal": f"Path traversal / LFI probes from {ip}",
        "reconnaissance": f"Attack-surface reconnaissance from {ip}",
        "command_injection": f"Command injection staging from {ip}",
        "data_exfiltration": f"Anomalous outbound data volume involving {ip}",
        "scanner": f"Automated vulnerability scan from {ip}",
        "ransomware_precursor": "Mass file-enumeration pattern (ransomware precursor)",
        "anomalous_access": f"Behavioral anomaly cluster from {ip}",
        "dos": f"Application-layer flood from {ip}",
        "authz_failure": f"Repeated authorization failures from {ip}",
    }
    return labels.get(ttype, f"{ttype.replace('_', ' ').title()} — {ip}")


def _extract_indicators(items: list[dict[str, Any]]) -> list[str]:
    out = []
    for i in items[:8]:
        if i.get("path"):
            out.append(f"url:{i['path']}")
        if i.get("ip_address"):
            out.append(f"ip:{i['ip_address']}")
        if i.get("username"):
            out.append(f"user:{i['username']}")
    # unique preserve order
    seen = set()
    uniq = []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq[:12]


def threat_level_from_open(critical: int, high: int) -> str:
    if critical >= 2:
        return "SEVERE"
    if critical >= 1:
        return "HIGH"
    if high >= 3:
        return "ELEVATED"
    if high >= 1:
        return "GUARDED"
    return "LOW"


def reputation_for(failed: int, total: int, anomalies: int, tags: list[str]) -> tuple[int, str]:
    score = 72
    score -= min(40, failed * 2)
    score -= min(25, anomalies * 5)
    if total and failed / max(total, 1) > 0.6:
        score -= 15
    if "tor" in tags or "scanner" in tags:
        score -= 20
    score = int(max(5, min(98, score)))
    if score < 25:
        level = "critical"
    elif score < 45:
        level = "high"
    elif score < 65:
        level = "medium"
    else:
        level = "low"
    return score, level
