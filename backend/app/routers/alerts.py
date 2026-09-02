"""Alert endpoints."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Alert, User
from ..schemas import AlertPage, AlertOut, Msg
from ..security import get_current_user, require_role

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=AlertPage)
def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: str | None = None,
    acknowledged: bool | None = None,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    q = db.query(Alert)
    if severity:
        q = q.filter(Alert.severity == severity.upper())
    if acknowledged is not None:
        q = q.filter(Alert.acknowledged == acknowledged)
    total = q.count()
    items = q.order_by(Alert.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return AlertPage(total=total, page=page, page_size=page_size, items=items)


@router.post("/{alert_id}/ack", response_model=AlertOut)
def acknowledge(alert_id: int, db: Session = Depends(get_db),
                current: User = Depends(require_role("analyst", "admin"))):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    alert.acknowledged = True
    alert.acknowledged_by = current.username
    db.commit()
    db.refresh(alert)
    return alert


@router.post("/{alert_id}/unack", response_model=AlertOut)
def unacknowledge(alert_id: int, db: Session = Depends(get_db),
                  _: User = Depends(require_role("analyst", "admin"))):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    alert.acknowledged = False
    alert.acknowledged_by = None
    db.commit()
    db.refresh(alert)
    return alert
