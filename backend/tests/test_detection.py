"""Detection engine tests: classification, severity, rules, ML anomaly."""
from datetime import datetime, timedelta

import pytest
from sqlalchemy.orm import sessionmaker

from app.database import Base, engine
from app.detection.classify import classify
from app.detection.rules import per_log_rules
from app.models import LogEntry


@pytest.fixture()
def db_session():
    Base.metadata.create_all(bind=engine)
    conn = engine.connect()
    trans = conn.begin()
    Session = sessionmaker(bind=conn)
    session = Session()
    yield session
    session.close()
    trans.rollback()
    conn.close()
    Base.metadata.drop_all(bind=engine)


def _log(**kw) -> LogEntry:
    defaults = dict(timestamp=datetime.utcnow(), source="test", level="WARNING",
                    category="web", message="test", ip_address="10.0.0.1",
                    labels=[], meta={})
    defaults.update(kw)
    return LogEntry(**defaults)


def test_classify_sql_injection():
    parsed = classify({"message": "GET /api/v1/search?q=1' UNION SELECT password FROM users-- -> 200",
                       "path": "/api/v1/search?q=1' UNION SELECT password FROM users--",
                       "timestamp": datetime.utcnow()})
    assert parsed["event_type"] == "web.sql_injection"
    assert parsed["severity"] in ("HIGH", "CRITICAL")
    assert parsed["threat_score"] >= 80


def test_classify_failed_login():
    parsed = classify({"message": "Failed password for admin from 1.2.3.4 port 5000 ssh2",
                       "timestamp": datetime.utcnow()})
    assert parsed["event_type"] == "auth.login.failure"
    assert parsed["category"] == "auth"


def test_classify_malware_critical():
    parsed = classify({"message": "Virus found: EICAR-AV-Test file quarantined",
                       "timestamp": datetime.utcnow()})
    assert parsed["event_type"] == "system.malware"
    assert parsed["severity"] == "CRITICAL"


def test_classify_generic_info_low_score():
    parsed = classify({"message": "User profile updated", "timestamp": datetime.utcnow(),
                       "level": "INFO"})
    assert parsed["threat_score"] <= 15
    assert parsed["severity"] in ("INFO", "LOW")


def test_per_log_rules_fire():
    log = _log(event_type="web.sql_injection", path="/search?q=1' OR 1=1--",
               user_agent="sqlmap/1.8")
    hits = per_log_rules(log)
    rule_ids = {h.rule_id for h in hits}
    assert "R-SQLI" in rule_ids
    assert "R-SCANNER" in rule_ids


def test_brute_force_window_rule(db_session):
    now = datetime.utcnow()
    ip = "45.1.2.3"
    for i in range(6):
        db_session.add(_log(timestamp=now - timedelta(seconds=30 * i), ip_address=ip,
                            event_type="auth.login.failure", level="WARNING",
                            message=f"Failed password for root from {ip}", category="auth",
                            username="root"))
    db_session.commit()
    trigger = _log(event_type="auth.login.failure", ip_address=ip, category="auth",
                   message=f"Failed password for root from {ip}", username="root")
    db_session.add(trigger)
    db_session.commit()

    from app.detection.rules import window_rules
    hits = window_rules(db_session, trigger)
    assert any(h.rule_id == "R-BRUTE-FORCE" for h in hits)


def test_ml_anomaly_training_and_detection(db_session):
    from app.detection.anomaly import train_baseline, detect_anomalies
    now = datetime.utcnow()
    # baseline: boring IPs
    for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"):
        for i in range(30):
            db_session.add(_log(timestamp=now - timedelta(hours=5, minutes=i),
                                ip_address=ip, event_type="web.request.ok",
                                status_code=200, path=f"/page{i % 4}", category="web",
                                level="INFO"))
    # outlier: massive failed-login IP
    for i in range(60):
        db_session.add(_log(timestamp=now - timedelta(minutes=2), ip_address="9.9.9.9",
                            event_type="auth.login.failure", category="auth",
                            level="WARNING", message=f"Failed password #{i}", username="root"))
    db_session.commit()

    res = train_baseline(db_session)
    assert res["trained"] is True
    results = detect_anomalies(db_session, window_minutes=10)
    flagged = {r["ip_address"] for r in results if r["is_anomaly"]}
    assert "9.9.9.9" in flagged


def test_no_false_positive_command_injection():
    """Regression: 'curl' UA after field separators must not look like cmd injection."""
    parsed = classify({"message": "GET /api/v1/orders -> 200", "path": "/api/v1/orders",
                       "user_agent": "curl/8.5.0", "timestamp": datetime.utcnow(),
                       "status_code": 200})
    assert parsed["event_type"] != "web.command_injection"
    assert parsed["severity"] in ("INFO", "LOW")

    parsed2 = classify({"message": "GET /health -> 200", "path": "/health",
                        "user_agent": "Mozilla/5.0 Chrome/126.0", "timestamp": datetime.utcnow(),
                        "status_code": 200})
    assert parsed2["event_type"] == "web.request.ok"


def test_firewall_and_scanner_word_boundaries():
    ok = classify({"message": "background job backdrop finished", "timestamp": datetime.utcnow()})
    assert ok["event_type"] != "network.firewall_block"
    scan = classify({"message": "request from sqlmapper script", "timestamp": datetime.utcnow()})
    # 'sqlmapper' contains sqlmap but word boundary prevents scanner match
    assert scan["event_type"] != "web.scanner"
