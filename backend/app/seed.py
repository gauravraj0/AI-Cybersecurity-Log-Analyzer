"""First-run seeding: default RBAC users + a realistic 72h demo dataset,
then trains the ML anomaly baseline."""
import logging
import random
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from .database import SessionLocal, Base, engine
from .models import User
from .security import hash_password

logger = logging.getLogger("seed")

DEFAULT_USERS = [
    ("admin", "admin123", "admin", "admin@sentinellens.io"),
    ("analyst", "analyst123", "analyst", "analyst@sentinellens.io"),
    ("viewer", "viewer123", "viewer", "viewer@sentinellens.io"),
]


def ensure_seeded(seed_demo_data: bool = True):
    Base.metadata.create_all(bind=engine)
    db: Session = SessionLocal()
    try:
        try:
            created_users = False
            for username, password, role, email in DEFAULT_USERS:
                if not db.query(User).filter(User.username == username).first():
                    db.add(User(username=username, hashed_password=hash_password(password),
                                role=role, email=email))
                    created_users = True
            db.commit()
            if created_users:
                logger.info("default users seeded (admin/analyst/viewer - see README)")
        except Exception as exc:  # noqa: BLE001
            logger.error("seed users failed: %s", exc)
            db.rollback()

        if seed_demo_data:
            try:
                from .models import LogEntry
                if db.query(LogEntry).count() == 0:
                    _seed_history(db)
                    _train_anomaly(db)
            except Exception as exc:  # noqa: BLE001
                logger.warning("demo seed skipped: %s", exc)
                db.rollback()
    finally:
        db.close()


def _seed_history(db: Session):
    """Populate ~72h of synthetic history: normal ops + attack bursts."""
    from .services.ingest import ingest_batch
    from .services.simulator import Simulator

    rng = random.Random(42)
    sim = Simulator()
    now = datetime.utcnow()
    total = 0

    for step in range(72 * 6):  # every 10 minutes for 3 days
        ts = now - timedelta(minutes=(72 * 6 - step) * 10)
        events = []
        n = rng.randint(2, 7)
        if 2 <= ts.hour < 6:
            n = rng.randint(1, 3)  # quiet night hours
        for _ in range(n):
            ev = sim._normal_event()
            ev["timestamp"] = ts + timedelta(seconds=rng.randint(0, 590))
            events.append(ev)

        # sprinkle historical attack bursts
        if rng.random() < 0.045:
            scenario = rng.choice(
                ["brute_force", "sqli", "scan", "dos", "exfil", "privesc", "xss", "traversal"])
            for _ in range(rng.randint(6, 12)):
                ev = sim._attack_event(scenario)
                ev["timestamp"] = ts + timedelta(seconds=rng.randint(0, 590))
                events.append(ev)

        result = ingest_batch(db, events, source_default="history")
        total += result["accepted"]

    logger.info("demo history seeded: %d events", total)


def _train_anomaly(db: Session):
    from .detection.anomaly import train_baseline
    res = train_baseline(db, hours=72)
    logger.info("anomaly baseline: %s", res)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ensure_seeded(seed_demo_data="--no-demo" not in __import__("sys").argv)
