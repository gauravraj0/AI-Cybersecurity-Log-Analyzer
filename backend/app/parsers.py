"""Multi-format log parsing.

Supported formats (auto-detected per line):
- Apache/Nginx combined & common access logs
- JSON structured logs (one object per line)
- Syslog (RFC 3164 style)
- SSH/auth logs (sshd style)
- Generic ``key=value`` pairs
- Plain messages (fallback)
"""
import json
import re
from datetime import datetime, timezone
from typing import Any, Optional

# Pre-compiled patterns -------------------------------------------------------

APACHE_RE = re.compile(
    r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)(?:\s+(?P<proto>[^"]*))?"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

SYSLOG_RE = re.compile(
    r'^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+'
    r'(?P<process>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$'
)

SSHD_RE = re.compile(
    r'^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<msg>.*)$'
)

KV_RE = re.compile(r'(\b[\w_.]+)=("[^"]*"|\S+)')

LEVEL_MAP = {
    "trace": "DEBUG", "debug": "DEBUG", "info": "INFO", "notice": "INFO",
    "warn": "WARNING", "warning": "WARNING", "error": "ERROR", "err": "ERROR",
    "critical": "CRITICAL", "crit": "CRITICAL", "fatal": "CRITICAL", "alert": "CRITICAL",
}

MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}


def _parse_apache_ts(ts: str) -> Optional[datetime]:
    try:
        dt = datetime.strptime(ts.split(" ")[0], "%d/%b/%Y:%H:%M:%S")
        return dt
    except ValueError:
        return None


def _parse_syslog_ts(ts: str) -> Optional[datetime]:
    try:
        parts = ts.split()
        month = MONTHS.get(parts[0])
        if not month:
            return None
        now = datetime.now(timezone.utc)
        return datetime(now.year, month, int(parts[1]), *(int(x) for x in parts[2].split(":")))
    except (ValueError, IndexError):
        return None


def _clean_kv_value(v: str) -> str:
    return v.strip('"')


def parse_line(line: str, default_host: str = "") -> dict[str, Any]:
    """Parse a raw log line into a structured dict.

    Returns a dict with keys compatible with ``LogIn`` schema; unknown lines
    degrade gracefully to a plain message entry.
    """
    line = line.rstrip("\n").strip()
    if not line:
        return {}

    # 1) JSON structured logs ------------------------------------------------
    if line.startswith("{"):
        try:
            data = json.loads(line)
            if isinstance(data, dict):
                return _from_json(data, line, default_host)
        except json.JSONDecodeError:
            pass

    # 2) Apache/Nginx access logs -------------------------------------------
    m = APACHE_RE.match(line)
    if m:
        g = m.groupdict()
        ts = _parse_apache_ts(g["ts"])
        return {
            "timestamp": ts,
            "source": "access_log",
            "host": default_host,
            "level": "INFO" if int(g["status"]) < 400 else ("WARNING" if int(g["status"]) < 500 else "ERROR"),
            "category": "web",
            "message": f'{g["method"]} {g["path"]} -> {g["status"]}',
            "raw": line,
            "ip_address": g["ip"],
            "method": g["method"],
            "path": g["path"],
            "status_code": int(g["status"]),
            "bytes_sent": 0 if g["bytes"] == "-" else int(g["bytes"]),
            "user_agent": g.get("ua"),
            "username": None if g["user"] == "-" else g["user"],
            "meta": {"protocol": g.get("proto"), "referrer": g.get("referrer")},
        }

    # 3) sshd / auth logs -----------------------------------------------------
    m = SSHD_RE.match(line)
    if m:
        g = m.groupdict()
        return {
            "timestamp": _parse_syslog_ts(g["ts"]),
            "source": "auth_log",
            "host": g["host"],
            "level": "INFO",
            "category": "auth",
            "message": g["msg"],
            "raw": line,
            "ip_address": _extract_ip(g["msg"]),
            "username": _extract_user(g["msg"]),
            "meta": {"process": "sshd", "pid": g["pid"]},
        }

    # 4) Generic syslog -------------------------------------------------------
    m = SYSLOG_RE.match(line)
    if m:
        g = m.groupdict()
        level = "ERROR" if any(w in g["msg"].lower() for w in ("fail", "error", "denied", "refused")) else "INFO"
        return {
            "timestamp": _parse_syslog_ts(g["ts"]),
            "source": "syslog",
            "host": g["host"],
            "level": level,
            "category": "system",
            "message": g["msg"],
            "raw": line,
            "ip_address": _extract_ip(g["msg"]),
            "meta": {"process": g["process"], "pid": g.get("pid")},
        }

    # 5) key=value pairs -------------------------------------------------------
    pairs = dict(KV_RE.findall(line))
    if pairs and ("msg" in pairs or "message" in pairs or "event" in pairs):
        lvl = LEVEL_MAP.get(pairs.get("level", pairs.get("severity", "")).lower(), "INFO")
        msg = _clean_kv_value(pairs.get("msg") or pairs.get("message") or pairs.get("event") or line)
        return {
            "timestamp": _iso_or_none(pairs.get("timestamp") or pairs.get("ts") or pairs.get("@timestamp")),
            "source": "kv",
            "host": _clean_kv_value(pairs.get("host", default_host)),
            "level": lvl,
            "category": "application",
            "message": msg,
            "raw": line,
            "ip_address": _extract_ip(line),
            "username": _clean_kv_value(pairs["user"]) if "user" in pairs else None,
            "meta": {k: _clean_kv_value(v) for k, v in pairs.items()},
        }

    # 6) Plain message fallback ------------------------------------------------
    level = "ERROR" if re.search(r"\b(error|failed|exception|denied|refused|fatal)\b", line, re.I) else "INFO"
    return {
        "timestamp": None,
        "source": "plain",
        "host": default_host,
        "level": level,
        "category": "application",
        "message": line,
        "raw": line,
        "ip_address": _extract_ip(line),
        "meta": {},
    }


def _from_json(data: dict, raw: str, default_host: str) -> dict[str, Any]:
    lvl = LEVEL_MAP.get(str(data.get("level", data.get("severity", "info"))).lower(), "INFO")
    return {
        "timestamp": _iso_or_none(data.get("timestamp") or data.get("@timestamp") or data.get("ts") or data.get("time")),
        "source": str(data.get("source", "json")),
        "host": str(data.get("host", data.get("hostname", default_host))),
        "level": lvl,
        "category": str(data.get("category", "application")),
        "message": str(data.get("message") or data.get("msg") or data.get("event") or raw),
        "raw": raw,
        "ip_address": data.get("ip") or data.get("client_ip") or data.get("remote_addr") or data.get("src_ip"),
        "method": data.get("method"),
        "path": data.get("path") or data.get("url"),
        "status_code": _int_or_none(data.get("status") or data.get("status_code")),
        "bytes_sent": _int_or_none(data.get("bytes") or data.get("bytes_sent")),
        "user_agent": data.get("user_agent") or data.get("agent"),
        "username": data.get("user") or data.get("username"),
        "meta": {k: v for k, v in data.items()
                 if k not in {"timestamp", "@timestamp", "ts", "time", "level", "severity",
                              "message", "msg", "event", "ip", "client_ip", "remote_addr",
                              "src_ip", "method", "path", "url", "status", "status_code",
                              "bytes", "bytes_sent", "user_agent", "agent", "user", "username",
                              "host", "hostname", "source", "category"}},
    }


def _extract_ip(text: str) -> Optional[str]:
    m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text)
    return m.group(1) if m else None


def _extract_user(text: str) -> Optional[str]:
    m = re.search(r"(?:user|for)\s+(?:invalid user\s+)?(\w[\w.\-]*)", text, re.I)
    return m.group(1) if m else None


def _int_or_none(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _iso_or_none(v) -> Optional[datetime]:
    if not v:
        return None
    try:
        s = str(v).replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except ValueError:
        return None


def parse_text_blob(text: str, default_host: str = "") -> list[dict[str, Any]]:
    """Parse a multi-line blob (file upload / paste) into structured entries."""
    out = []
    for line in text.splitlines():
        parsed = parse_line(line, default_host)
        if parsed:
            out.append(parsed)
    return out
