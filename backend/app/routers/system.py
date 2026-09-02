"""System control endpoints: log-stream simulator for the real-time monitoring demo."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import SessionLocal
from ..models import User
from ..schemas import SimulatorStatus
from ..security import get_current_user, require_role
from ..services.simulator import simulator

router = APIRouter(prefix="/simulator", tags=["system"])


def _status() -> SimulatorStatus:
    return SimulatorStatus(running=simulator.running,
                           events_generated=simulator.events_generated)


@router.get("/status", response_model=SimulatorStatus)
def read_status(_: User = Depends(get_current_user)):
    return _status()


@router.post("/start", response_model=SimulatorStatus)
async def start(_: User = Depends(require_role("analyst", "admin"))):
    # async endpoint -> runs on the event loop, so create_task works
    simulator.start(SessionLocal)
    return _status()


@router.post("/stop", response_model=SimulatorStatus)
def stop(_: User = Depends(require_role("analyst", "admin"))):
    simulator.stop()
    return _status()
