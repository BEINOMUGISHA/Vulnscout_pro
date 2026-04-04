"""
api/routes/demo.py — Demo Data Routes (Development Only)

Provides sample scans, findings, and reports for testing the dashboard
without needing to run actual vulnerability scans.

Endpoints:
  POST   /demo/populate  — Create sample scans with findings
  DELETE /demo/clear     — Clear all demo data
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.dependencies import AuthenticatedUser, require_auth, require_admin, get_scan_store
from core.models.scan import Scan
from core.models.finding import Finding

logger = logging.getLogger(__name__)
router = APIRouter()


class DemoDataResponse(BaseModel):
    """Response from demo data operations."""
    message: str
    scans_created: int = 0
    findings_created: int = 0


@router.post("/populate", response_model=DemoDataResponse, tags=["demo"])
async def populate_demo_data(
    user: AuthenticatedUser = Depends(require_auth),
    scan_store = Depends(get_scan_store),
):
    """
    Dummy data population is now disabled for production safety.
    """
    logger.info("Demo data population request ignored (disabled for real-world mode)")
    return DemoDataResponse(
        message="Demo data population is disabled in this version of VulnScout Pro.",
        scans_created=0,
        findings_created=0,
    )

@router.delete("/clear", tags=["demo"])
async def clear_demo_data(
    user: AuthenticatedUser = Depends(require_auth),
    scan_store = Depends(get_scan_store),
):
    """
    Clear all demo scans (those ending with _demo).
    """
    # We allow clearing even in non-debug mode to help user clean up
    logger.warning("Clearing demo data (requested by %s)", user.email)
    count = await scan_store.clear_all_scans(demo_only=True)
    
    return {"message": f"Demo data cleared: {count} scans removed"}
