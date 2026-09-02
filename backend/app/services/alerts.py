"""Alert helpers."""
from sqlalchemy.orm import Session

from ..models import Alert


def recent_unacknowledged(db: Session, limit: int = 20) -> list[Alert]:
    return (
        db.query(Alert)
        .filter(Alert.acknowledged.is_(False))
        .order_by(Alert.created_at.desc())
        .limit(limit)
        .all()
    )
