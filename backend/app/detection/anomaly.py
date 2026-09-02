"""Unsupervised ML anomaly detection over IP traffic behaviour.

Builds per-IP behavioural feature vectors from ``log_entries``, fits an
``IsolationForest`` and flags windows that deviate from the learned baseline.
Persists the fitted model + scaler (joblib) for reuse between calls.
"""
import logging
import os
import pickle
from datetime import datetime, timedelta
from typing import Any

import numpy as np
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..models import LogEntry

logger = logging.getLogger("anomaly")

MODEL_PATH = os.getenv("ANOMALY_MODEL_PATH", "/tmp/anomaly_iforest.pkl")
FEATURE_NAMES = [
    "request_count", "error_ratio", "failed_login_ratio", "unique_paths",
    "avg_bytes", "critical_ratio", "offhours_ratio", "distinct_status_codes",
]

_model_cache: dict | None = None


def build_ip_features(db: Session, since: datetime, until: datetime | None = None,
                      min_events: int = 3) -> list[dict[str, Any]]:
    """Aggregate per-IP behavioural features for the given time window."""
    q = db.query(LogEntry).filter(LogEntry.timestamp >= since)
    if until:
        q = q.filter(LogEntry.timestamp < until)
    rows = q.all()

    buckets: dict[str, list[LogEntry]] = {}
    for r in rows:
        if r.ip_address:
            buckets.setdefault(r.ip_address, []).append(r)

    features = []
    for ip, logs in buckets.items():
        n = len(logs)
        if n < min_events:
            continue
        errs = sum(1 for l in logs if l.level in ("ERROR", "CRITICAL"))
        auth_fail = sum(1 for l in logs if l.event_type == "auth.login.failure")
        crit = sum(1 for l in logs if l.severity in ("HIGH", "CRITICAL"))
        offhours = sum(1 for l in logs if l.timestamp and l.timestamp.hour <= 4)
        vectors = [
            n,
            errs / n,
            auth_fail / n,
            len({l.path for l in logs if l.path}),
            float(np.mean([(l.bytes_sent or 0) for l in logs])),
            crit / n,
            offhours / n,
            len({l.status_code for l in logs if l.status_code is not None}),
        ]
        features.append({
            "ip_address": ip,
            "window_start": since,
            "window_end": until or datetime.utcnow(),
            "request_count": n,
            "error_ratio": errs / n,
            "failed_login_ratio": auth_fail / n,
            "raw": vectors,
        })
    return features


def _vector(f: dict[str, Any]) -> list[float]:
    return f["raw"]


def train_baseline(db: Session, hours: int = 72) -> dict[str, Any]:
    """Fit IsolationForest on historical traffic (behavioural baseline)."""
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import RobustScaler

    since = datetime.utcnow() - timedelta(hours=hours)
    feats = build_ip_features(db, since, min_events=2)
    if len(feats) < 4:
        return {"trained": False, "reason": "insufficient baseline data", "samples": len(feats)}

    X = np.array([_vector(f) for f in feats], dtype=float)
    scaler = RobustScaler().fit(X)
    Xs = scaler.transform(X)

    contamination = min(0.15, max(0.03, 6.0 / len(X)))
    model = IsolationForest(n_estimators=150, contamination=contamination, random_state=42)
    model.fit(Xs)

    global _model_cache
    _model_cache = {"model": model, "scaler": scaler}
    try:
        with open(MODEL_PATH, "wb") as fh:
            pickle.dump(_model_cache, fh)
    except OSError:
        logger.warning("could not persist anomaly model")

    return {"trained": True, "samples": len(X), "contamination": contamination,
            "features": FEATURE_NAMES}


def _load_model() -> dict | None:
    global _model_cache
    if _model_cache is not None:
        return _model_cache
    try:
        with open(MODEL_PATH, "rb") as fh:
            _model_cache = pickle.load(fh)
        return _model_cache
    except (OSError, EOFError):
        return None


def detect_anomalies(db: Session, window_minutes: int = 5) -> list[dict[str, Any]]:
    """Score the most recent window against the trained baseline.

    Returns list of dicts sorted by anomaly score desc; flagged entries have
    ``is_anomaly = True``.
    """
    bundle = _load_model()
    if bundle is None:
        trained = train_baseline(db)
        if not trained.get("trained"):
            return []
        bundle = _load_model()
        if bundle is None:
            return []

    until = datetime.utcnow()
    since = until - timedelta(minutes=window_minutes)
    feats = build_ip_features(db, since, until, min_events=3)
    if not feats:
        return []

    X = np.array([_vector(f) for f in feats], dtype=float)
    Xs = bundle["scaler"].transform(X)
    scores = -bundle["model"].score_samples(Xs)  # higher = more anomalous
    predictions = bundle["model"].predict(Xs)    # -1 = outlier

    out = []
    for f, score, pred in zip(feats, scores, predictions):
        f.pop("raw", None)
        f["anomaly_score"] = round(float(score), 4)
        f["is_anomaly"] = bool(pred == -1 and score > 0.45)
        out.append(f)
    out.sort(key=lambda d: d["anomaly_score"], reverse=True)
    return out
