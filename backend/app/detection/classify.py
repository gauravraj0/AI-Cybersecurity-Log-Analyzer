"""Error classification and severity scoring.

Classifies every parsed log into a normalised ``event_type`` taxonomy and
assigns a 0-100 threat score + severity tier used across the dashboard,
incidents and alerts.
"""
import re
from datetime import datetime
from typing import Any

# --- Signature patterns (error / threat classification) -----------------------

PATTERNS: list[dict[str, Any]] = [
    # Web attacks -----------------------------------------------------------
    {"event_type": "web.sql_injection", "category": "web", "score": 90,
     "patterns": [
         re.compile(r"(union\s+(all\s+)?select)", re.I),
         re.compile(r"('\s*or\s*'?\d+'\s*=\s*'?|or\s+1\s*=\s*1)", re.I),
         re.compile(r"(;\s*drop\s+table|;\s*delete\s+from)", re.I),
         re.compile(r"\b(sleep|waitfor|benchmark)\s*\(", re.I),
         re.compile(r"information_schema", re.I),
         re.compile(r"'\s*--|#'|--\s*$", re.I),
     ]},
    {"event_type": "web.xss", "category": "web", "score": 65,
     "patterns": [
         re.compile(r"<script\b", re.I),
         re.compile(r"javascript:", re.I),
         re.compile(r"\bon(error|load|click|mouseover|focus)\s*=", re.I),
         re.compile(r"<img\s+[^>]*src\s*=", re.I),
     ]},
    {"event_type": "web.path_traversal", "category": "web", "score": 70,
     "patterns": [
         re.compile(r"(\.\./){2,}"),
         re.compile(r"(%2e%2e(%2f|%5c|/)){2,}", re.I),
         re.compile(r"/etc/(passwd|shadow)", re.I),
         re.compile(r"boot\.ini|win\.ini", re.I),
         re.compile(r"/proc/self/environ", re.I),
     ]},
    {"event_type": "web.command_injection", "category": "web", "score": 88,
     "patterns": [
         re.compile(r"[;&`]\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh|rm)\b", re.I),
         re.compile(r"\$\([a-z_ ]+\)", re.I),
         re.compile(r"%0a\s*(cat|id|whoami|wget|curl)", re.I),
     ]},
    {"event_type": "web.scanner", "category": "web", "score": 45,
     "patterns": [
         re.compile(r"\b(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|hydra|acunetix|nessus|metasploit)\b", re.I),
     ]},
    {"event_type": "web.admin_probe", "category": "web", "score": 35,
     "patterns": [
         re.compile(r"/(wp-admin|wp-login|administrator|phpmyadmin|\.env|\.git/config|\.aws/credentials)", re.I),
     ]},

    # Auth events ------------------------------------------------------------
    {"event_type": "auth.login.failure", "category": "auth", "score": 25,
     "patterns": [
         re.compile(r"(failed password|authentication failure|login failed|invalid user)", re.I),
         re.compile(r"(incorrect password|wrong password|bad credentials|invalid credentials)", re.I),
         re.compile(r"40[13]\s*$"),
     ]},
    {"event_type": "auth.login.success", "category": "auth", "score": 5,
     "patterns": [
         re.compile(r"(accepted password|session opened for|login successful|signed in)", re.I),
     ]},
    {"event_type": "auth.privilege_escalation", "category": "auth", "score": 70,
     "patterns": [
         re.compile(r"\bsudo\b.*\b(command not permitted|NOT in sudoers|authentication failure)", re.I),
         re.compile(r"\bsu\[\d+\]:\s*(Authentication failure|FAILED SU)", re.I),
         re.compile(r"(privilege escalation|added to sudoers|sudo:\s*\w+\s*:\s*T?)", re.I),
     ]},
    {"event_type": "auth.account_lock", "category": "auth", "score": 40,
     "patterns": [re.compile(r"(account (locked|disabled)|too many (failed )?(login )?attempts)", re.I)]},
    {"event_type": "auth.token.anomaly", "category": "auth", "score": 55,
     "patterns": [re.compile(r"(token (forge|replay|mismatch)|invalid (jwt|session)|csrf)", re.I)]},

    # System / application errors ---------------------------------------------
    {"event_type": "system.resource_exhaustion", "category": "system", "score": 55,
     "patterns": [
         re.compile(r"(out of memory|oom|disk (space )?(full|almost)|no space left)", re.I),
         re.compile(r"(cpu \d{3}%|load average.*\d\d\.\d)", re.I),
     ]},
    {"event_type": "system.malware", "category": "system", "score": 95,
     "patterns": [
         re.compile(r"(eicar|malware (signature |detected)|trojan|ransomware|cryptolocker|backdoor)", re.I),
         re.compile(r"virus\s+found", re.I),
     ]},
    {"event_type": "network.firewall_block", "category": "network", "score": 30,
     "patterns": [
         re.compile(r"\b(blocked?|dropped|denied?|rejected?)\b\s*(inbound|outbound)?\s*(tcp|udp|icmp)?", re.I),
         re.compile(r"iptables\s*:\s*drop", re.I),
     ]},
    {"event_type": "database.error", "category": "database", "score": 40,
     "patterns": [
         re.compile(r"(connection refused|too many connections|deadlock|lock wait timeout)", re.I),
         re.compile(r"(psql|mysql|postgres|ora-)\d*", re.I),
     ]},
    {"event_type": "app.exception", "category": "application", "score": 35,
     "patterns": [
         re.compile(r"\b(traceback|exception|stack trace|nullpointerexception|segfault)\b", re.I),
     ]},
    {"event_type": "app.dependency_down", "category": "application", "score": 45,
     "patterns": [
         re.compile(r"(health check failed|service unavailable|circuit (breaker )?open|redis|kafka.*(down|timeout))", re.I),
         re.compile(r"50[23]\s*$"),
     ]},
]

# Default HTTP status based classification
STATUS_CLASS = {
    200: "web.request.ok", 201: "web.request.ok", 204: "web.request.ok",
    301: "web.request.redirect", 302: "web.request.redirect",
    400: "web.request.bad_request", 401: "auth.login.failure", 403: "web.access_denied",
    404: "web.not_found", 429: "network.rate_limited", 500: "app.server_error",
    502: "app.dependency_down", 503: "app.dependency_down",
}

SEVERITY_TIERS = [(80, "CRITICAL"), (60, "HIGH"), (35, "MEDIUM"), (15, "LOW"), (0, "INFO")]


def classify(parsed: dict[str, Any]) -> dict[str, Any]:
    """Attach ``event_type``, ``category``, base ``threat_score`` and ``severity``.

    Operates on a dict produced by ``parsers.parse_line`` / the ``LogIn`` schema.
    """
    # Space-joined (never use "|" as a separator - it is itself an attack token)
    haystack = " ".join(
        str(parsed.get(k) or "")
        for k in ("message", "path", "user_agent")
    )[:4000]

    event_type, category, score = None, None, None
    for sig in PATTERNS:
        for pat in sig["patterns"]:
            if pat.search(haystack):
                event_type, category, score = sig["event_type"], sig["category"], sig["score"]
                break
        if event_type:
            break

    # HTTP status based fallbacks
    status_code = parsed.get("status_code")
    if event_type is None and status_code:
        event_type = STATUS_CLASS.get(int(status_code))
        score = {"web.access_denied": 30, "auth.login.failure": 25,
                 "network.rate_limited": 40, "web.not_found": 8,
                 "app.server_error": 38, "app.dependency_down": 42}.get(event_type, 5)

    if event_type is None:
        level = str(parsed.get("level", "INFO")).upper()
        event_type = {"ERROR": "app.error", "CRITICAL": "app.critical_error",
                      "WARNING": "app.warning"}.get(level, "generic.info")
        score = {"ERROR": 20, "CRITICAL": 45, "WARNING": 8}.get(level, 2)

    category = category or parsed.get("category") or "application"

    # --- Threat score modifiers -------------------------------------------
    modifiers: list[str] = []
    ts = parsed.get("timestamp")
    if isinstance(ts, datetime) and (ts.hour <= 4):
        score += 5
        modifiers.append("off_hours")

    ua = str(parsed.get("user_agent") or "")
    if ua and re.search(r"(python-requests|curl|wget|go-http-client|scrapy|bot)", ua, re.I) \
            and "browser" not in ua.lower():
        score += 5
        modifiers.append("non_browser_client")

    level = str(parsed.get("level", "INFO")).upper()
    if level == "CRITICAL":
        score += 10
    elif level == "ERROR":
        score += 5

    if parsed.get("username") in ("root", "administrator", "admin"):
        if "privilege" in event_type or "auth" in event_type:
            score += 8
            modifiers.append("privileged_account")

    score = max(0, min(100, int(score)))
    severity = next(tier for floor, tier in SEVERITY_TIERS if score >= floor)

    parsed["event_type"] = event_type
    parsed["category"] = category
    parsed["threat_score"] = score
    parsed["severity"] = severity
    parsed.setdefault("labels", []).extend(modifiers)
    return parsed


ATTACK_TYPES = {
    "web.sql_injection": "SQL Injection",
    "web.xss": "Cross-Site Scripting",
    "web.path_traversal": "Path Traversal",
    "web.command_injection": "Command Injection",
    "web.scanner": "Vulnerability Scanning",
    "web.admin_probe": "Admin Panel Probing",
    "auth.login.failure": "Authentication Failure",
    "auth.privilege_escalation": "Privilege Escalation",
    "system.malware": "Malware Detection",
    "network.firewall_block": "Firewall Block",
    "network.rate_limited": "Rate Limit / DoS",
    "data.exfiltration": "Data Exfiltration",
}


def display_name(event_type: str) -> str:
    if event_type in ATTACK_TYPES:
        return ATTACK_TYPES[event_type]
    return re.sub(r"[._]", " ", event_type).strip().title()
