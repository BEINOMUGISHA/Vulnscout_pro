"""
api/routes/teams.py — Team Management Routes

Endpoints:
  GET    /teams              — list user's teams
  POST   /teams              — create a new team
  GET    /teams/{team_id}    — get team detail + members
  PUT    /teams/{team_id}    — update team metadata
  DELETE /teams/{team_id}    — dissolve a team (admin/owner)
"""

from __future__ import annotations

import asyncio
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from api.dependencies import (
    AuthenticatedUser, get_scan_store, require_analyst, require_admin,
)
from core.models.team import Team

logger = logging.getLogger(__name__)
router = APIRouter()


# ── Request / Response models ──────────────────────────────────────────────────

class TeamCreateRequest(BaseModel):
    name:        str = Field(..., min_length=1, max_length=100)
    description: str = ""


class TeamResponse(BaseModel):
    id:          str
    name:        str
    description: str
    owner_id:    str
    member_ids:  List[str]


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.get("", response_model=List[TeamResponse])
async def list_teams(
    user: AuthenticatedUser = Depends(require_analyst),
    scan_store = Depends(get_scan_store),
):
    """List teams the user belongs to."""
    # This would typically query a specialized 'TeamStore'
    # Simplified: load from 'teams.json' via scan_store helper
    raw_teams = await scan_store._load_json(scan_store._root / "teams.json")
    if not isinstance(raw_teams, list):
        return []
        
    teams = [Team.from_dict(t) for t in raw_teams]
    
    # Filter by membership
    if not user.is_admin:
        teams = [t for t in teams if user.user_id in t.member_ids or t.owner_id == user.user_id]
        
    return [t.to_dict() for t in teams]


@router.post("", status_code=201, response_model=TeamResponse)
async def create_team(
    body: TeamCreateRequest,
    user: AuthenticatedUser = Depends(require_analyst),
    scan_store = Depends(get_scan_store),
):
    """Create a new team."""
    from datetime import datetime, timezone
    new_team = Team(
        name=body.name,
        description=body.description,
        owner_id=user.user_id,
        member_ids=[user.user_id],
        created_at=datetime.now(timezone.utc).isoformat()
    )
    
    # Persist
    teams = await scan_store._load_json(scan_store._root / "teams.json")
    if not isinstance(teams, list): teams = []
    teams.append(new_team.to_dict())
    
    await asyncio.to_thread(scan_store._atomic_write, 
                           scan_store._root / "teams.json", teams)
    
    return new_team.to_dict()


@router.get("/{team_id}", response_model=TeamResponse)
async def get_team(
    team_id: str,
    user: AuthenticatedUser = Depends(require_analyst),
    scan_store = Depends(get_scan_store),
):
    """Get team details."""
    raw_teams = await scan_store._load_json(scan_store._root / "teams.json")
    if not isinstance(raw_teams, list):
        raise HTTPException(404, "Team not found")
        
    for t_dict in raw_teams:
        if t_dict["id"] == team_id:
            team = Team.from_dict(t_dict)
            if not user.is_admin and user.user_id not in team.member_ids:
                raise HTTPException(403, "Not a member of this team")
            return team.to_dict()
            
    raise HTTPException(404, "Team not found")
