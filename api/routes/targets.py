"""
api/routes/targets.py — Target Management Routes

Endpoints:
  POST   /targets              — create and validate a new scan target
  GET    /targets              — list targets with pagination
  GET    /targets/{target_id}  — get target detail
  PUT    /targets/{target_id}  — update target metadata
  DELETE /targets/{target_id}  — delete target (admin only)
  POST   /targets/validate     — validate a URL and detect technology stack
  GET    /targets/{target_id}/scans — list scans for a target

Targets are stored as part of the scan record — there is no separate
targets table. The POST /targets endpoint creates a target definition
that is returned and can be passed directly to POST /scans.

Scope validation runs on creation: the API checks that the target URL
is reachable and not in the global exclusion list before returning 201.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator

from api.dependencies import (
    AuthenticatedUser,
    PaginationParams,
    get_pagination,
    get_scan_store,
    require_analyst,
    require_auth,
    require_admin,
)
from config import get_config

logger = logging.getLogger(__name__)
router = APIRouter()


# ── Request / Response models ──────────────────────────────────────────────────


class ScopeConfigRequest(BaseModel):
    allowed_domains: list[str] = []
    allowed_wildcard_domains: list[str] = []
    allowed_ip_ranges: list[str] = []
    allowed_url_prefixes: list[str] = []
    excluded_paths: list[str] = []
    excluded_domains: list[str] = []
    authorised_by: str | None = None
    max_scan_depth: int = Field(3, ge=1, le=10)


class ScanConfigRequest(BaseModel):
    crawl_depth: int = Field(3, ge=1, le=10)
    max_pages: int = Field(150, ge=1, le=1000)
    rate_limit_rps: float = Field(3.0, ge=0.1, le=20.0)
    rate_limit_burst: int = Field(8, ge=1, le=50)
    respect_robots_txt: bool = True
    include_ea_context: bool = True
    enabled_checks: list[str] | None = None
    max_concurrent_detectors: int = Field(5, ge=1, le=10)


class AuthConfigRequest(BaseModel):
    auth_type: str = Field("none", pattern="^(none|basic|bearer|api_key|session)$")
    username: str | None = None
    password: str | None = None
    bearer_token: str | None = None
    api_key: str | None = None
    api_key_header: str = "X-API-Key"
    cookies: dict = {}


class CreateTargetRequest(BaseModel):
    url: str = Field(..., min_length=8, max_length=2048)
    name: str = Field("", max_length=200)
    description: str = Field("", max_length=1000)
    industry: str = Field("general", max_length=50)
    tags: list[str] = []
    notes: str = Field("", max_length=2000)
    include_subdomains: bool = False
    authorised_by: str = Field("", max_length=200)
    scope: ScopeConfigRequest | None = None
    scan_config: ScanConfigRequest | None = None
    auth: AuthConfigRequest | None = None

    @field_validator("url")
    @classmethod
    def validate_url_format(cls, v):
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v.rstrip("/")

    @field_validator("industry")
    @classmethod
    def validate_industry(cls, v):
        valid = {
            "general",
            "banking",
            "fintech",
            "mobile_money",
            "telecom",
            "sacco",
            "microfinance",
            "government",
            "insurance",
            "e-commerce",
            "healthcare",
            "education",
            "ngo",
        }
        if v not in valid:
            raise ValueError(f"Industry must be one of: {sorted(valid)}")
        return v


class TargetResponse(BaseModel):
    target_id: str
    url: str
    name: str
    industry: str
    target_type: str
    is_https: bool
    is_ea_target: bool
    tags: list[str]
    created_at: str
    owner_id: str

    class Config:
        from_attributes = True


# ── Routes ─────────────────────────────────────────────────────────────────────


@router.post("", status_code=201, summary="Create a new scan target")
async def create_target(
    body: CreateTargetRequest,
    user: AuthenticatedUser = Depends(require_analyst),
    scan_store=Depends(get_scan_store),
):
    """
    Create a new target definition and validate the URL is in scope.

    The scope enforcer runs immediately — if the URL is on the global
    exclusion list (banks, telecom providers, cloud platforms) the
    request is rejected with 403 before any scan is created.

    Returns a target dict that can be passed directly to POST /scans.
    """
    from core.models.target import Target, ScanConfig, ScopeConfig, TargetAuth, AuthType
    from core.scanner.scope_enforcer import ScopeEnforcer, ScopeViolationError

    # Build Target from request
    scope_cfg = None
    if body.scope:
        scope_cfg = ScopeConfig(
            allowed_domains=body.scope.allowed_domains,
            allowed_wildcard_domains=body.scope.allowed_wildcard_domains,
            allowed_ip_ranges=body.scope.allowed_ip_ranges,
            allowed_url_prefixes=body.scope.allowed_url_prefixes,
            excluded_paths=body.scope.excluded_paths,
            excluded_domains=body.scope.excluded_domains,
            authorised_by=body.scope.authorised_by or user.email,
            max_scan_depth=body.scope.max_scan_depth,
        )

    scan_cfg = None
    if body.scan_config:
        scan_cfg = ScanConfig(
            crawl_depth=body.scan_config.crawl_depth,
            max_pages=body.scan_config.max_pages,
            rate_limit_rps=body.scan_config.rate_limit_rps,
            rate_limit_burst=body.scan_config.rate_limit_burst,
            respect_robots_txt=body.scan_config.respect_robots_txt,
            include_ea_context=body.scan_config.include_ea_context,
            enabled_checks=body.scan_config.enabled_checks,
            max_concurrent_detectors=body.scan_config.max_concurrent_detectors,
        )

    auth = TargetAuth(auth_type=AuthType.NONE)
    if body.auth and body.auth.auth_type != "none":
        auth = TargetAuth(
            auth_type=body.auth.auth_type,
            username=body.auth.username,
            password=body.auth.password,
            bearer_token=body.auth.bearer_token,
            api_key=body.auth.api_key,
            api_key_header=body.auth.api_key_header,
            cookies=body.auth.cookies,
        )

    target = Target.from_url(
        url=body.url,
        name=body.name or body.url,
        authorised_by=body.authorised_by or user.email,
        industry=body.industry,
        include_subdomains=body.include_subdomains,
        scan_config=scan_cfg,
        auth=auth,
        tags=body.tags,
    )
    if scope_cfg:
        target.scope = scope_cfg
    target.description = body.description
    target.notes = body.notes

    # Validate scope — reject globally excluded targets immediately
    enforcer = ScopeEnforcer(target.scope)
    try:
        await enforcer.enforce_url(body.url)
    except ScopeViolationError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Target URL is not in authorised scope: {exc}",
        )

    # Persist target (stored as a standalone record in scan_store)
    target_dict = target.to_dict(include_auth=False)
    target_dict["owner_id"] = user.user_id
    await scan_store.save_target(target_dict)

    logger.info("Target created: %s by user %s", target.base_url, user.user_id[:8])
    return {**target_dict, "target_id": target.id}


@router.get("", summary="List targets")
async def list_targets(
    page: PaginationParams = Depends(get_pagination),
    search: str | None = Query(None, max_length=200),
    industry: str | None = Query(None),
    user: AuthenticatedUser = Depends(require_auth),
    scan_store=Depends(get_scan_store),
):
    """List targets owned by the authenticated user (admin sees all)."""
    owner_filter = None if user.is_admin else user.user_id
    targets, total = await scan_store.list_targets(
        owner_id=owner_filter,
        search=search,
        industry=industry,
        offset=page.offset,
        limit=page.limit,
    )
    return {
        "items": targets,
        "targets": targets,
        "total": total,
        "page": page.page,
        "limit": page.limit,
        "pages": (total + page.limit - 1) // page.limit if total else 0,
    }


@router.get("/validate", summary="Validate and fingerprint a URL")
async def validate_target_url(
    url: str = Query(..., min_length=8, max_length=2048),
    user: AuthenticatedUser = Depends(require_analyst),
):
    """
    Validate a URL without creating a target or scan.
    Returns:
      - scope check result (is it globally excluded?)
      - technology fingerprint (detected frameworks, server)
      - HTTPS check
      - EA target detection (is this likely an EA application?)

    This endpoint makes a single HTTP HEAD/GET request to the URL.
    """
    from core.models.target import Target
    from core.scanner.scope_enforcer import ScopeEnforcer, ScopeViolationError

    if not url.startswith(("http://", "https://")):
        raise HTTPException(422, "URL must start with http:// or https://")

    temp_target = Target.from_url(url, authorised_by=user.email)
    enforcer = ScopeEnforcer(temp_target.scope)

    scope_ok = True
    scope_reason = ""
    try:
        await enforcer.enforce_url(url)
    except ScopeViolationError as exc:
        scope_ok = False
        scope_reason = str(exc)

    return {
        "url": url,
        "is_https": url.startswith("https://"),
        "is_ea_target": temp_target.is_ea_target,
        "target_type": temp_target.target_type,
        "hostname": temp_target.hostname,
        "industry_hint": temp_target.industry,
        "scope_valid": scope_ok,
        "scope_reason": scope_reason,
        "message": (
            "URL is valid and in scope."
            if scope_ok
            else f"URL is excluded from scanning: {scope_reason}"
        ),
    }


@router.get("/{target_id}", summary="Get target detail")
async def get_target(
    target_id: str,
    user: AuthenticatedUser = Depends(require_auth),
    scan_store=Depends(get_scan_store),
):
    """Return target details by ID."""
    target = await scan_store.get_target(target_id)
    if target is None:
        raise HTTPException(404, f"Target {target_id!r} not found.")
    if not user.is_admin and target.get("owner_id") != user.user_id:
        raise HTTPException(403, "You do not have access to this target.")
    return target


@router.put("/{target_id}", summary="Update target metadata")
async def update_target(
    target_id: str,
    body: CreateTargetRequest,
    user: AuthenticatedUser = Depends(require_analyst),
    scan_store=Depends(get_scan_store),
):
    """Update name, description, tags, notes, or scan configuration."""
    existing = await scan_store.get_target(target_id)
    if existing is None:
        raise HTTPException(404, "Target not found.")
    if not user.is_admin and existing.get("owner_id") != user.user_id:
        raise HTTPException(403, "You do not own this target.")

    updates = {
        "name": body.name or existing.get("name"),
        "description": body.description,
        "tags": body.tags,
        "notes": body.notes,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    if body.scan_config:
        updates["scan_config"] = body.scan_config.dict()

    await scan_store.update_target(target_id, updates)
    updated = await scan_store.get_target(target_id)
    return updated


@router.delete("/{target_id}", status_code=204, summary="Delete target (admin)")
async def delete_target(
    target_id: str,
    user: AuthenticatedUser = Depends(require_admin),
    scan_store=Depends(get_scan_store),
):
    """Delete a target record. Admin only. Does not delete associated scans."""
    existing = await scan_store.get_target(target_id)
    if existing is None:
        raise HTTPException(404, "Target not found.")
    await scan_store.delete_target(target_id)
    logger.info("Target %s deleted by admin %s", target_id[:8], user.user_id[:8])


@router.get("/{target_id}/scans", summary="List scans for a target")
async def get_target_scans(
    target_id: str,
    page: PaginationParams = Depends(get_pagination),
    user: AuthenticatedUser = Depends(require_auth),
    scan_store=Depends(get_scan_store),
):
    """Return all scans that used this target, most recent first."""
    target = await scan_store.get_target(target_id)
    if target is None:
        raise HTTPException(404, "Target not found.")
    if not user.is_admin and target.get("owner_id") != user.user_id:
        raise HTTPException(403, "You do not have access to this target.")

    scans, total = await scan_store.list_scans(
        target_url=target.get("base_url"),
        owner_id=None if user.is_admin else user.user_id,
        offset=page.offset,
        limit=page.limit,
    )
    return {
        "target_id": target_id,
        "scans": scans,
        "total": total,
        "page": page.page,
        "limit": page.limit,
    }
