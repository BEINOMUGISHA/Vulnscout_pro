"""
api/routes/schedule.py — Scan Scheduling Routes

Endpoints:
  GET    /schedules              — list all scheduled scans
  POST   /schedules              — create a new recurring scan
  GET    /schedules/{schedule_id} — get schedule detail
  PUT    /schedules/{schedule_id} — update schedule frequency/config
  DELETE /schedules/{schedule_id} — remove a schedule
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from api.dependencies import (
    AuthenticatedUser, get_scan_store, require_analyst, require_admin,
)

logger = logging.getLogger(__name__)
router = APIRouter()


# ── Request / Response models ──────────────────────────────────────────────────

class ScheduleRequest(BaseModel):
    name:           str = Field(..., min_length=1, max_length=200)
    target_id:      str = Field(..., min_length=36) # UUID
    frequency:      str = Field("weekly", pattern="^(daily|weekly|monthly|once)$")
    config_overrides: Dict = {}
    enabled:        bool = True


class ScheduleResponse(BaseModel):
    id:             str
    name:           str
    target_id:      str
    frequency:      str
    next_run:       Optional[str]
    last_run:       Optional[str]
    enabled:        bool


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.get("", response_model=List[ScheduleResponse])
async def list_schedules(
    request: Request,
    user: AuthenticatedUser = Depends(require_analyst),
):
    """List all configured scan schedules."""
    scheduler = request.app.state.scheduler
    schedules = scheduler.list_schedules()
    
    # Filter by ownership if not admin
    if not user.is_admin:
        schedules = [s for s in schedules if s.owner_id == user.user_id]
        
    return [vars(s) for s in schedules]


@router.post("", status_code=201, response_model=ScheduleResponse)
async def create_schedule(
    body: ScheduleRequest,
    request: Request,
    user: AuthenticatedUser = Depends(require_analyst),
    scan_store = Depends(get_scan_store),
):
    """Create a new recurring scan schedule."""
    # Verify target exists
    target = await scan_store.get_target(body.target_id)
    if not target:
        raise HTTPException(404, "Target not found")
        
    from core.scheduler.scan_scheduler import ScheduledScan
    sch = ScheduledScan(
        name=body.name,
        target_id=body.target_id,
        frequency=body.frequency,
        config_overrides=body.config_overrides,
        enabled=body.enabled,
        owner_id=user.user_id
    )
    
    scheduler = request.app.state.scheduler
    await scheduler.add_schedule(sch)
    
    return vars(sch)


@router.get("/{schedule_id}", response_model=ScheduleResponse)
async def get_schedule(
    schedule_id: str,
    request: Request,
    user: AuthenticatedUser = Depends(require_analyst),
):
    """Get schedule details."""
    scheduler = request.app.state.scheduler
    for sch in scheduler.list_schedules():
        if sch.id == schedule_id:
            if not user.is_admin and sch.owner_id != user.user_id:
                raise HTTPException(403, "Access denied")
            return vars(sch)
    raise HTTPException(404, "Schedule not found")


@router.put("/{schedule_id}", response_model=ScheduleResponse)
async def update_schedule(
    schedule_id: str,
    update_data: ScheduleRequest,
    request: Request,
    user: AuthenticatedUser = Depends(require_analyst),
):
    """Update schedule details."""
    scheduler = request.app.state.scheduler
    for sch in scheduler.list_schedules():
        if sch.id == schedule_id:
            if not user.is_admin and sch.owner_id != user.user_id:
                raise HTTPException(403, "Access denied")
            sch.name = update_data.name
            sch.target_id = update_data.target_id
            sch.frequency = update_data.frequency
            sch.config_overrides = update_data.config_overrides
            sch.enabled = update_data.enabled
            return vars(sch)
    raise HTTPException(404, "Schedule not found")


@router.delete("/{schedule_id}", status_code=204)
async def delete_schedule(
    schedule_id: str,
    request: Request,
    user: AuthenticatedUser = Depends(require_analyst),
):
    """Remove a schedule."""
    scheduler = request.app.state.scheduler
    # Check ownership first
    found = False
    for sch in scheduler.list_schedules():
        if sch.id == schedule_id:
            if not user.is_admin and sch.owner_id != user.user_id:
                raise HTTPException(403, "Access denied")
            found = True
            break
            
    if not found:
        raise HTTPException(404, "Schedule not found")
        
    await scheduler.remove_schedule(schedule_id)
