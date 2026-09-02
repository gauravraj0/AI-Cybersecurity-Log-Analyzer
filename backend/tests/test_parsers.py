"""Unit tests for log parsers."""
from app.parsers import parse_line, parse_text_blob


def test_parse_apache_combined():
    line = ('192.168.1.50 - alice [10/Oct/2025:13:55:36 +0000] "GET /api/v1/users HTTP/1.1" '
            '200 2326 "https://example.com/" "Mozilla/5.0 (Windows NT 10.0)"')
    parsed = parse_line(line)
    assert parsed["ip_address"] == "192.168.1.50"
    assert parsed["method"] == "GET"
    assert parsed["path"] == "/api/v1/users"
    assert parsed["status_code"] == 200
    assert parsed["bytes_sent"] == 2326
    assert parsed["username"] == "alice"
    assert parsed["category"] == "web"
    assert parsed["timestamp"] is not None


def test_parse_json_log():
    line = '{"timestamp": "2025-10-10T14:00:00Z", "level": "error", "message": "connection refused to db", "ip": "10.0.0.9", "status": 503}'
    parsed = parse_line(line)
    assert parsed["level"] == "ERROR"
    assert parsed["ip_address"] == "10.0.0.9"
    assert parsed["status_code"] == 503
    assert "connection refused" in parsed["message"]


def test_parse_ssh_auth_log():
    line = "Jan 12 03:14:22 web-01 sshd[4123]: Failed password for invalid user oracle from 203.0.113.9 port 44556 ssh2"
    parsed = parse_line(line)
    assert parsed["category"] == "auth"
    assert parsed["ip_address"] == "203.0.113.9"
    assert parsed["username"] == "oracle"
    assert parsed["source"] == "auth_log"


def test_parse_kv_log():
    line = 'ts=2025-10-10T12:00:00Z level=warn msg="cache miss storm" user=svc-backup ip=10.1.1.4'
    parsed = parse_line(line)
    assert parsed["level"] == "WARNING"
    assert "cache miss storm" in parsed["message"]
    assert parsed["username"] == "svc-backup"


def test_plain_fallback_detects_error():
    line = "Unhandled exception in worker thread, aborting job"
    parsed = parse_line(line)
    assert parsed["level"] == "ERROR"
    assert parsed["message"] == line


def test_blob_multi_format():
    blob = "\n".join([
        '{"level":"info","message":"ok event"}',
        '10.0.0.1 - - [10/Oct/2025:10:00:00 +0000] "POST /login HTTP/1.1" 401 128 "-" "curl/8.0"',
        "Random free-form message with ip 8.8.8.8",
    ])
    entries = parse_text_blob(blob)
    assert len(entries) == 3
