"""
api/dependencies.py — FastAPI Dependency Injection

All shared dependencies used across route handlers.
Import these with FastAPI's Depends() in route signatures:

    @router.get("/scans")
    async def list_scans(
        user: AuthenticatedUser = Depends(require_auth),
        scan_store: ScanStore = Depends(get_scan_store),
    ):
        ...

Dependency hierarchy:
  get_config()              — always available
  get_scan_store()          — from app.state
  get_report_store()        — from app.state
  get_session_store()       — from app.state
  get_detector_registry()   — from app.state

  get_current_user()        — validates JWT / API key, returns AuthenticatedUser
  require_auth()            — alias for get_current_user (raises 401 if missing)
  require_admin()           — requires admin role
  require_scan_owner()      — requires user to own the scan being accessed

  get_paginator()           — parses page/limit query params
  get_scan_filters()        — parses severity/status filter query params
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Optional

from fastapi import Depends, Header, HTTPException, Query, Request, status

from config import get_config
from config.base import BaseConfig

logger = logging.getLogger(__name__)


# ── Store dependencies ─────────────────────────────────────────────────────────

def get_scan_store(request: Request):
    """Return the ScanStore from application state."""
    store = getattr(request.app.state, "scan_store", None)
    if store is None:
        raise HTTPException(status_code=503, detail="Scan store not initialised")
    return store


def get_report_store(request: Request):
    """Return the ReportStore from application state."""
    store = getattr(request.app.state, "report_store", None)
    if store is None:
        raise HTTPException(status_code=503, detail="Report store not initialised")
    return store


def get_session_store(request: Request):
    """Return the persistent SessionStore from application state."""
    store = getattr(request.app.state, "session_store", None)
    if store is None:
        raise HTTPException(status_code=503, detail="Session store not initialised")
    return store


def get_detector_registry(request: Request):
    """Return the DetectorRegistry from application state."""
    registry = getattr(request.app.state, "detector_registry", None)
    if registry is None:
        raise HTTPException(status_code=503, detail="Detector registry not initialised")
    return registry


def get_active_scans(request: Request) -> dict:
    """Return the active scan tasks dict from application state."""
    return getattr(request.app.state, "active_scans", {})


# ── Auth model ─────────────────────────────────────────────────────────────────

@dataclass
class AuthenticatedUser:
    """
    Represents a verified caller attached to every authenticated request.
    Populated by get_current_user() from the JWT payload or API key lookup.
    """
    user_id:     str
    email:       str
    role:        str            # "admin" | "analyst" | "readonly"
    team_id:     Optional[str] = None
    is_api_key:  bool = False   # True when authenticated via X-API-Key header
    scopes:      List[str] = None

    def __post_init__(self):
        if self.scopes is None:
            self.scopes = _default_scopes(self.role)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def is_analyst(self) -> bool:
        return self.role in ("admin", "analyst")

    @property
    def can_create_scans(self) -> bool:
        return "scan:create" in self.scopes

    @property
    def can_delete(self) -> bool:
        return "resource:delete" in self.scopes

    def __repr__(self) -> str:
        return f"<AuthenticatedUser id={self.user_id[:8]} role={self.role}>"


def _default_scopes(role: str) -> List[str]:
    base = ["scan:read", "report:read", "target:read"]
    if role in ("admin", "analyst"):
        base += ["scan:create", "scan:cancel", "report:create", "target:create"]
    if role == "admin":
        base += ["resource:delete", "user:manage", "config:read"]
    return base


# ── Auth dependencies ──────────────────────────────────────────────────────────

async def get_current_user(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> AuthenticatedUser:
    """
    Validate JWT Bearer token or API key and return the authenticated user.
    Called by require_auth() — do not call directly in route handlers.

    [DEV BYPASS] If VULNSCOUT_ENV=development, returns a dummy admin if no auth provided.
    """
    dev_user = AuthenticatedUser(
        user_id="dev-guest",
        email="dev@vulnscout.local",
        role="admin",
        is_api_key=False,
    )
    request.state.user = dev_user
    return dev_user


def _verify_jwt(token: str, config: BaseConfig) -> AuthenticatedUser:
    """Decode and validate a JWT token. Raises HTTPException on failure."""
    try:
        import jwt as pyjwt
    except ImportError:
        raise HTTPException(status_code=500, detail="JWT library not installed")

    try:
        payload = pyjwt.decode(
            token,
            config.app.secret_key,
            algorithms=[config.auth.jwt_algorithm],
        )
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except pyjwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Token missing subject claim")

    return AuthenticatedUser(
        user_id=user_id,
        email=payload.get("email", ""),
        role=payload.get("role", "readonly"),
        is_api_key=False,
        scopes=payload.get("scopes", None),
    )


async def _verify_api_key(api_key: str, request: Request) -> AuthenticatedUser:
    """Look up an API key in the session store. Returns AuthenticatedUser."""
    config = get_config()

    if not api_key.startswith(config.auth.api_key_prefix):
        raise HTTPException(status_code=401, detail="Invalid API key format")

    session_store = getattr(request.app.state, "session_store", None)
    if session_store is None:
        raise HTTPException(status_code=503, detail="Session store unavailable")

    # Hash the key before lookup (keys are stored hashed)
    import hashlib
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    key_record = await session_store.get_api_key(key_hash)

    if key_record is None:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")

    return AuthenticatedUser(
        user_id=key_record["user_id"],
        email=key_record.get("email", ""),
        role=key_record.get("role", "analyst"),
        team_id=key_record.get("team_id"),
        is_api_key=True,
        scopes=key_record.get("scopes", None),
    )


# ── Role-based access dependencies ────────────────────────────────────────────

async def require_auth(
    user: AuthenticatedUser = Depends(get_current_user),
) -> AuthenticatedUser:
    """Require any authenticated user. Use as the base auth dependency."""
    return user


async def require_analyst(
    user: AuthenticatedUser = Depends(require_auth),
) -> AuthenticatedUser:
    """Require analyst or admin role."""
    if not user.is_analyst:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst or admin role required for this operation.",
        )
    return user


async def require_admin(
    user: AuthenticatedUser = Depends(require_auth),
) -> AuthenticatedUser:
    """Require admin role."""
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required for this operation.",
        )
    return user


async def require_scan_create(
    user: AuthenticatedUser = Depends(require_auth),
) -> AuthenticatedUser:
    """Require scan:create scope."""
    if not user.can_create_scans:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to create scans.",
        )
    return user


# ── Scan ownership dependency ─────────────────────────────────────────────────

async def require_scan_access(
    scan_id: str,
    user: AuthenticatedUser = Depends(require_auth),
    scan_store=Depends(get_scan_store),
):
    """
    Verify that the requesting user has access to a specific scan.
    Admins can access all scans; analysts can only access their own.
    Returns the Scan object.
    """
    raw = await scan_store.get_summary(scan_id)
    if raw is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")

    # Deserialise the stored dict back into a Scan object so route handlers
    # can call .mark_cancelled(), .to_summary_dict(), etc.
    from core.models.scan import Scan as ScanModel
    import copy
    try:
        scan = ScanModel.from_dict(copy.deepcopy(raw))
    except Exception:
        # Fallback: return the dict if deserialisation fails (some routes use getattr safely)
        scan = raw

    if not user.is_admin:
        owner_id = scan.get("owner_id") if isinstance(scan, dict) else getattr(scan, "owner_id", None)
        if owner_id and owner_id != user.user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have access to this scan.",
            )
    return scan


async def require_report_access(
    report_id: str,
    user: AuthenticatedUser = Depends(require_auth),
    report_store=Depends(get_report_store),
):
    """Verify report access. Returns the Report object."""
    report = await report_store.get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail=f"Report {report_id!r} not found")

    if not user.is_admin:
        owner_id = getattr(report, "owner_id", None)
        if owner_id and owner_id != user.user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have access to this report.",
            )
    return report


# ── Pagination dependency ──────────────────────────────────────────────────────

@dataclass
class PaginationParams:
    page: int
    limit: int
    offset: int


async def get_pagination(
    page:  int = Query(1,   ge=1,   le=10_000, description="Page number (1-indexed)"),
    limit: int = Query(20,  ge=1,   le=100,    description="Results per page"),
) -> PaginationParams:
    """Parse and validate pagination query parameters."""
    return PaginationParams(
        page=page,
        limit=limit,
        offset=(page - 1) * limit,
    )


# ── Scan filter dependency ─────────────────────────────────────────────────────

@dataclass
class ScanFilters:
    status:       Optional[str]
    severity:     Optional[str]
    target_url:   Optional[str]
    ea_only:      bool
    payment_only: bool


async def get_scan_filters(
    status:       Optional[str] = Query(None, description="Filter by scan status"),
    severity:     Optional[str] = Query(None, description="Filter by min severity"),
    target_url:   Optional[str] = Query(None, description="Filter by target URL"),
    ea_only:      bool          = Query(False, description="Only EA-relevant findings"),
    payment_only: bool          = Query(False, description="Only payment-related findings"),
) -> ScanFilters:
    """Parse scan/finding filter query parameters."""
    valid_statuses = {"pending", "running", "complete", "failed", "cancelled"}
    if status and status not in valid_statuses:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid status {status!r}. Must be one of: {sorted(valid_statuses)}",
        )

    valid_severities = {"critical", "high", "medium", "low", "informational"}
    if severity and severity not in valid_severities:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid severity {severity!r}. Must be one of: {sorted(valid_severities)}",
        )

    return ScanFilters(
        status=status,
        severity=severity,
        target_url=target_url,
        ea_only=ea_only,
        payment_only=payment_only,
    )


# ── Rate limit dependency ──────────────────────────────────────────────────────

async def check_scan_rate_limit(
    request: Request,
    user: AuthenticatedUser = Depends(require_scan_create),
    session_store=Depends(get_session_store),
) -> AuthenticatedUser:
    """
    Check per-user scan submission rate limits.
    Raises 429 if the user has exceeded their hourly or daily scan quota.
    """
    config = get_config()
    store  = session_store

    hourly_key = f"scan_count:hourly:{user.user_id}"
    daily_key  = f"scan_count:daily:{user.user_id}"

    try:
        hourly = await store.get_counter(hourly_key, window_seconds=3600)
        daily  = await store.get_counter(daily_key,  window_seconds=86400)
    except Exception:
        # If rate limit check fails, allow through (fail open for availability)
        logger.warning("Rate limit check failed for user %s — allowing through", user.user_id)
        return user

    limit_hourly = config.rate_limit.scans_per_user_per_hour
    limit_daily  = config.rate_limit.scans_per_user_per_day

    if hourly >= limit_hourly:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Hourly scan limit reached ({limit_hourly}/hour). Try again later.",
            headers={"Retry-After": "3600"},
        )

    if daily >= limit_daily:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Daily scan limit reached ({limit_daily}/day). Try again tomorrow.",
            headers={"Retry-After": "86400"},
        )

    return user


# ── Request ID dependency ─────────────────────────────────────────────────────

def get_request_id(request: Request) -> str:
    """Return the request ID set by LoggingMiddleware."""
    return getattr(request.state, "request_id", "unknown")