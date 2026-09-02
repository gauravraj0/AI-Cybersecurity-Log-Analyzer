"""End-to-end API tests with FastAPI TestClient (SQLite tmp DB)."""
import os
import tempfile

import pytest
from fastapi.testclient import TestClient

_tmp = tempfile.mkdtemp()
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/test_api.db"
os.environ["ANOMALY_MODEL_PATH"] = f"{_tmp}/model.pkl"

from app.main import app  # noqa: E402
from app.seed import ensure_seeded  # noqa: E402


@pytest.fixture(scope="module")
def client():
    ensure_seeded(seed_demo_data=True)
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def auth(client):
    r = client.post("/api/auth/login", data={"username": "analyst", "password": "analyst123"})
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_login_bad_credentials(client):
    r = client.post("/api/auth/login", data={"username": "analyst", "password": "wrong"})
    assert r.status_code == 401


def test_role_based_access(client):
    r = client.post("/api/auth/login", data={"username": "viewer", "password": "viewer123"})
    vtoken = {"Authorization": f"Bearer {r.json()['access_token']}"}
    # viewer cannot ingest
    r2 = client.post("/api/ingest", headers=vtoken, json={"logs": [{"message": "x"}]})
    assert r2.status_code == 403
    # viewer can read dashboard
    r3 = client.get("/api/analytics/dashboard", headers=vtoken)
    assert r3.status_code == 200
    # anonymous cannot read anything
    assert client.get("/api/logs").status_code == 401


def test_ingest_and_detection_pipeline(client, auth):
    payload = {"logs": [
        {"message": "GET /api/v1/search?q=1' UNION SELECT password FROM users-- -> 200",
         "ip_address": "203.0.113.66", "path": "/api/v1/search?q=1' UNION SELECT password FROM users--",
         "method": "GET", "status_code": 200, "category": "web", "user_agent": "sqlmap/1.8"},
        {"message": "Accepted password for alice from 10.0.0.5 port 5000 ssh2",
         "ip_address": "10.0.0.5", "category": "auth", "username": "alice"},
    ]}
    r = client.post("/api/ingest", headers=auth, json=payload)
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["accepted"] == 2
    assert body["alerts_raised"] >= 1
    assert body["incidents_opened"] >= 1

    # log is searchable and classified
    r2 = client.get("/api/logs", headers=auth, params={"search": "UNION SELECT"})
    assert r2.status_code == 200
    items = r2.json()["items"]
    assert items and items[0]["event_type"] == "web.sql_injection"
    assert items[0]["severity"] in ("HIGH", "CRITICAL")

    # incident created with AI summary
    r3 = client.get("/api/incidents", headers=auth)
    incs = r3.json()
    assert incs and incs[0]["summary"], "incident should carry an AI/heuristic summary"


def test_raw_and_file_ingestion(client, auth):
    raw = ('45.155.205.10 - - [10/Oct/2025:10:11:12 +0000] "GET /download?file=../../../etc/passwd HTTP/1.1" 403 210 "-" "Nikto/2.5.0"\n'
           "Jan 12 03:14:22 web-01 sshd[4123]: Failed password for root from 45.155.205.10 port 44556 ssh2\n")
    r = client.post("/api/ingest/raw", headers=auth, json={"text": raw, "host": "edge-01"})
    assert r.status_code == 202
    assert r.json()["accepted"] == 2
    assert r.json()["alerts_raised"] >= 1  # traversal + scanner


def test_incident_lifecycle(client, auth):
    r = client.get("/api/incidents", headers=auth, params={"status": "open"})
    assert r.status_code == 200
    inc = r.json()[0]
    r2 = client.patch(f"/api/incidents/{inc['id']}/status", headers=auth,
                      json={"status": "investigating"})
    assert r2.json()["status"] == "investigating"
    r3 = client.patch(f"/api/incidents/{inc['id']}/status", headers=auth,
                      json={"status": "resolved"})
    assert r3.json()["status"] == "resolved"


def test_alerts_ack(client, auth):
    r = client.get("/api/alerts", headers=auth, params={"acknowledged": False})
    body = r.json()
    assert body["total"] >= 1
    first = body["items"][0]
    r2 = client.post(f"/api/alerts/{first['id']}/ack", headers=auth)
    assert r2.json()["acknowledged"] is True
    assert r2.json()["acknowledged_by"] == "analyst"


def test_ip_analysis(client, auth):
    r = client.get("/api/analytics/ips", headers=auth)
    assert r.status_code == 200
    assert len(r.json()) >= 1
    ip = r.json()[0]["ip"]
    r2 = client.get(f"/api/analytics/ips/{ip}", headers=auth)
    assert r2.status_code == 200
    assert "timeline" in r2.json()


def test_reports(client, auth):
    r = client.get("/api/reports/logs.csv", headers=auth)
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]
    r2 = client.get("/api/reports/incidents.json", headers=auth)
    assert r2.status_code == 200
    r3 = client.get("/api/reports/executive.html", headers=auth)
    assert r3.status_code == 200
    assert "Executive Security Report" in r3.text


def test_admin_user_management(client):
    r = client.post("/api/auth/login", data={"username": "admin", "password": "admin123"})
    admin = {"Authorization": f"Bearer {r.json()['access_token']}"}
    r2 = client.post("/api/auth/users", headers=admin,
                     json={"username": "newbie", "password": "secret123", "role": "viewer"})
    assert r2.status_code == 201
    # analyst cannot manage users
    ra = client.post("/api/auth/login", data={"username": "analyst", "password": "analyst123"})
    analyst = {"Authorization": f"Bearer {ra.json()['access_token']}"}
    assert client.get("/api/auth/users", headers=analyst).status_code == 403


def test_websocket_stream(client):
    # login and connect
    r = client.post("/api/auth/login", data={"username": "viewer", "password": "viewer123"})
    token = r.json()["access_token"]
    with client.websocket_connect(f"/ws?token={token}") as ws:
        hello = ws.receive_json()
        assert hello["type"] == "hello"
