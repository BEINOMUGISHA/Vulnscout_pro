"""
api/routes/scans.py — Scan Lifecycle Routes

Endpoints:
  POST   /scans                          — submit a new scan
  GET    /scans                          — list scans (paginated, filterable)
  GET    /scans/{scan_id}                — full scan detail + summary stats
  DELETE /scans/{scan_id}                — cancel a running scan / delete record
  GET    /scans/{scan_id}/status         — lightweight status poll (SSE-ready)
  GET    /scans/{scan_id}/findings       — paginated findings with filters
  GET    /scans/{scan_id}/findings/{fid} — single finding detail
  GET    /scans/{scan_id}/events         — audit event log for a scan
  POST   /scans/{scan_id}/cancel         — cancel a running scan
  GET    /scans/{scan_id}/export/csv     — download findings as CSV
  GET    /scans/{scan_id}/export/json    — download full scan as JSON

Scan lifecycle:
  PENDING → RUNNING → COMPLETE | FAILED | CANCELLED | SCOPE_BLOCKED

Async execution:
  Scans run as asyncio Tasks tracked in app.state.active_scans.
  The POST /scans endpoint returns immediately with scan_id and PENDING status.
  Clients poll GET /scans/{id}/status or use GET /scans/{id} for full detail.
  Server-Sent Events (SSE) for real-time progress available via /status?stream=true.

Rate limiting:
  Enforced by check_scan_rate_limit dependency.
  Hourly + daily quotas per user, configurable in config.rate_limit.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Form, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse, RedirectResponse
from pydantic import BaseModel, Field, model_validator, field_validator

from api.dependencies import (
    AuthenticatedUser,
    PaginationParams,
    ScanFilters,
    check_scan_rate_limit,
    get_active_scans,
    get_detector_registry,
    get_pagination,
    get_scan_filters,
    get_scan_store,
    require_auth,
    require_scan_access,
)
from config import get_config

logger = logging.getLogger(__name__)
router = APIRouter()

audit = logging.getLogger("vulnscout.audit")


# ── Request / Response models ──────────────────────────────────────────────────

class ScanRequest(BaseModel):
    """
    Scan submission payload.
    Either target_url (quick scan) or target_id (stored target) must be set.
    """
    target_url:    str | None = Field(None, min_length=8, max_length=2048)
    target_id:     str | None = None

    # ── Scan tuning ──────────────────────────────────────────────────────────
    crawl_depth:         int | None   = Field(None, ge=1, le=10)
    max_pages:           int | None   = Field(None, ge=1, le=1000)
    rate_limit_rps:      float | None = Field(None, ge=0.1, le=20.0)
    include_ea_context:  bool | None  = None
    enabled_checks:      list[str] | None = None
    respect_robots_txt:  bool | None  = None

    # ── Authentication (PRO) ──────────────────────────────────────────────────
    auth_type:     str = Field("none", pattern="^(none|basic|bearer|session|macro)$")
    auth_username: str | None = Field(None, max_length=200)
    auth_password: str | None = Field(None, max_length=500)
    auth_token:    str | None = Field(None, max_length=4096)   # JWT / Bearer
    auth_cookies:  str | None = Field(None, max_length=2048)   # raw cookie string
    # Macro login: list of steps [{url, method, payload, success_pattern}]
    auth_macro:    list[dict[str, Any]] | None = None

    # ── Advanced discovery (PRO) ──────────────────────────────────────────────
    target_arch:  str = Field("web_app", pattern="^(web_app|spa|rest|graphql)$")
    scan_strategy: str = Field("standard", pattern="^(standard|aggressive|stealth)$")
    js_render:    bool | None = None   # Execute JavaScript / headless browser
    api_fuzzing:  bool | None = None   # Deep API parameter discovery

    # ── Concurrency & Performance (PRO UNLOCKED) ──────────────────────────────
    high_concurrency: bool | None = None  # Unthrottled parallel engine

    # ── Authorisation (compliance) ────────────────────────────────────────────
    authorised_by:       str = Field("", max_length=200)
    authorisation_notes: str = Field("", max_length=1000)

    # ── Auto-report ───────────────────────────────────────────────────────────
    auto_report:         bool = False
    report_type:         str  = Field("technical", pattern="^(executive|technical|compliance)$")
    report_prepared_for: str  = Field("", max_length=200)

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, v):
        if v and not v.startswith(("http://", "https://")):
            raise ValueError("target_url must start with http:// or https://")
        return v

    @field_validator("enabled_checks")
    @classmethod
    def validate_check_names(cls, v):
        valid = {"sqli", "xss", "xxe", "ssrf", "idor", "auth_bypass",
                 "misconfig", "sensitive_data", "graphql", "jwt", "rate_limit",
                 "cms_deep", "weak_passwords", "llm"}
        for item in v:
            if item not in valid:
                raise ValueError(f"Unknown check: {item!r}. Valid: {sorted(valid)}")
        return v

    @model_validator(mode='after')
    def require_target(self) -> 'ScanRequest':
        if not self.target_url and not self.target_id:
            raise ValueError("Either target_url or target_id must be provided.")
        return self


class ScanResponse(BaseModel):
    id:         str
    scan_id:    str
    status:     str
    target_url: str
    created_at: str
    message:    str


class FindingFilter(BaseModel):
    severity:     str | None = None
    vuln_type:    str | None = None
    ea_only:      bool = False
    payment_only: bool = False
    min_cvss:     float | None = Field(None, ge=0.0, le=10.0)
    confirmed:    bool | None = None


class PatchFindingRequest(BaseModel):
    remediation_status: str | None = Field(None, pattern="^(open|fixed|verified|ignored)$")
    assigned_to:        str | None = None


# ── Scan submission ────────────────────────────────────────────────────────────

@router.post("", status_code=202, response_model=ScanResponse, summary="Submit a new scan")
async def create_scan(
    body:             ScanRequest,
    request:          Request,
    user:             AuthenticatedUser = Depends(check_scan_rate_limit),
    scan_store        = Depends(get_scan_store),
    detector_registry = Depends(get_detector_registry),
    active_scans: dict = Depends(get_active_scans),
):
    """
    Submit a new vulnerability scan. Returns 202 Accepted immediately.

    The scan runs asynchronously. Poll GET /scans/{scan_id}/status
    or GET /scans/{scan_id} for progress and results.

    A scan requires explicit authorisation — the authorised_by field
    is included in the compliance audit trail and reports. In production
    this should be the name or email of the person who authorised the test.
    """
    config = get_config()

    # ── Resolve target ─────────────────────────────────────────────────────────
    target = await _resolve_target(body, user, scan_store)

    # ── Apply request overrides to scan config ─────────────────────────────────
    if body.crawl_depth is not None:
        target.scan_config.crawl_depth = body.crawl_depth
    if body.max_pages is not None:
        target.scan_config.max_pages = body.max_pages
    if body.rate_limit_rps is not None:
        target.scan_config.rate_limit_rps = body.rate_limit_rps
    if body.include_ea_context is not None:
        target.scan_config.include_ea_context = body.include_ea_context
    if body.enabled_checks is not None:
        target.scan_config.enabled_checks = body.enabled_checks
    if body.respect_robots_txt is not None:
        target.scan_config.respect_robots_txt = body.respect_robots_txt

    # ── Pro feature overrides ──────────────────────────────────────────────────
    if body.js_render is not None:
        target.scan_config.js_render = body.js_render
    if body.api_fuzzing is not None:
        target.scan_config.api_fuzzing = body.api_fuzzing
    if body.high_concurrency is not None:
        target.scan_config.high_concurrency = body.high_concurrency

    # Apply strategy presets
    if body.scan_strategy == "aggressive":
        target.scan_config.rate_limit_rps = min(
            target.scan_config.rate_limit_rps * 3, 20.0
        )
        target.scan_config.max_concurrent_detectors = 20
        target.scan_config.high_concurrency = True
    elif body.scan_strategy == "stealth":
        target.scan_config.rate_limit_rps = 0.5
        target.scan_config.rate_limit_burst = 2
        target.scan_config.max_concurrent_detectors = 1

    # Apply target architecture hints
    if body.target_arch == "spa":
        target.scan_config.js_render = True
    elif body.target_arch in ("rest", "graphql"):
        target.scan_config.api_fuzzing = True

    # Apply authentication credentials
    if body.auth_type != "none":
        from core.models.target import AuthType, TargetAuth
        auth = TargetAuth(auth_type=body.auth_type)
        if body.auth_type == "basic":
            auth.username = body.auth_username
            auth.password = body.auth_password
        elif body.auth_type == "bearer":
            auth.bearer_token = body.auth_token
        elif body.auth_type == "session" and body.auth_cookies:
            # Parse "key=value" lines into dict
            cookies = {}
            for line in body.auth_cookies.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    cookies[k.strip()] = v.strip()
            auth.cookies = cookies
        target.auth = auth

    # ── Check concurrent scan limit ────────────────────────────────────────────
    running = sum(
        1 for t in active_scans.values()
        if not t.done()
    )
    if running >= config.scan.max_concurrent_scans:
        raise HTTPException(
            status_code=503,
            detail=(
                f"Maximum concurrent scans ({config.scan.max_concurrent_scans}) reached. "
                "Please wait for a running scan to complete."
            ),
        )

    # ── Build scan record ──────────────────────────────────────────────────────
    from core.models.scan import Scan

    scan = Scan()
    scan.target = target
    scan.config = target.scan_config
    scan.owner_id = user.user_id
    scan.team_id = user.team_id
    scan.status = "running"
    # authorised_by / authorisation_notes are not Scan dataclass fields —
    # store them safely so they don't cause AttributeError
    scan._authorised_by = body.authorised_by or user.email
    scan._authorisation_notes = body.authorisation_notes

    await scan_store.save_summary(scan)

    orchestrator = ScanOrchestrator(
        config=target.scan_config,
        detector_registry=detector_registry,
    )
    task = asyncio.create_task(
        _run_scan(
            scan=scan,
            detector_registry=detector_registry,
            scan_store=scan_store,
            active_scans=active_scans,
            auto_report=body.auto_report,
            report_type=body.report_type,
            report_prepared_for=body.report_prepared_for,
            owner_id=user.user_id,
            orchestrator_instance=orchestrator,
        ),
        name=f"scan-{scan.id[:8]}",
    )
    task.orchestrator = orchestrator
    active_scans[scan.id] = task

    audit.info(
        "SCAN_STARTED scan_id=%s target=%s user_id=%s authorised_by=%s",
        scan.id[:8], target.base_url, user.user_id[:8], scan._authorised_by,
    )

    return ScanResponse(
        id=scan.id,
        scan_id=scan.id,
        status="running",
        target_url=target.base_url,
        created_at=scan.created_at,
        message=(
            f"Scanning initiated for {target.base_url}. Real-time monitoring active."
        ),
    )


async def _resolve_target(body: ScanRequest, user: AuthenticatedUser, scan_store):
    """Resolve ScanRequest to a Target model."""
    from core.models.target import Target
    from config import get_config
    config = get_config()

    if body.target_id:
        stored = await scan_store.get_target(body.target_id)
        if not stored:
            raise HTTPException(404, f"Target {body.target_id!r} not found.")
        if not user.is_admin:
            owner_id = stored.get("owner_id")
            team_id = stored.get("team_id")
            if owner_id != user.user_id and (not team_id or team_id != user.team_id):
                raise HTTPException(403, "You do not have access to this target.")
        # Deserialise stored target
        return Target.from_dict(stored)

    if body.target_url:
        target = Target.from_url(
            url=body.target_url,
            authorised_by=body.authorised_by or user.email,
        )
        # Apply global scan defaults
        target.scan_config.crawl_depth     = config.scan.crawl_depth
        target.scan_config.max_pages       = config.scan.max_pages
        target.scan_config.rate_limit_rps  = config.scan.rate_limit_rps
        target.scan_config.include_ea_context = config.scan.include_ea_context
        target.scan_config.enabled_checks  = list(config.scan.enabled_checks)
        return target

    raise HTTPException(422, "Either target_url or target_id must be provided.")


# ── Async scan runner ──────────────────────────────────────────────────────────

async def _run_scan(
    scan,
    detector_registry,
    scan_store,
    active_scans: dict,
    auto_report: bool,
    report_type: str,
    report_prepared_for: str,
    owner_id: str,
    orchestrator_instance = None,
) -> None:
    """
    Async task that orchestrates the full scan lifecycle.
    Runs in the background; scan_store is updated at each phase transition.
    """
    try:
        from core.scanner.orchestrator import ScanOrchestrator
        
        # 1. Update state to RUNNING immediately
        scan.mark_started()
        await scan_store.save_summary(scan)

        last_save_time = 0.0
        SAVE_INTERVAL = 1.5  # Throttle same-phase metric ticks to avoid excessive I/O

        # 2. Progress callback to sync UI
        async def on_progress(progress_data):
            nonlocal last_save_time

            # ── Phase advance ─────────────────────────────────────────────────
            phase_changed = (scan.current_phase != progress_data.phase)
            if phase_changed:
                scan.advance_phase(progress_data.phase)

            # ── Always-updated fields ──────────────────────────────────────────
            scan.progress = max(1, progress_data.percent_complete)
            scan.active_detectors = list(progress_data.active_detectors)
            scan.findings_by_class = dict(progress_data.findings_by_class)

            # ── Metrics ────────────────────────────────────────────────────────
            scan.metrics.pages_crawled = progress_data.discovered_endpoints
            scan.metrics.endpoints_discovered = progress_data.discovered_endpoints
            scan.metrics.detectors_run = progress_data.detector_tasks_done
            scan.metrics.detector_tasks_total = progress_data.detector_tasks_total
            scan.metrics.detector_tasks_done = progress_data.detector_tasks_done

            # ── Persist: always on phase change; throttled otherwise ───────────
            now = asyncio.get_event_loop().time()
            if phase_changed or (now - last_save_time >= SAVE_INTERVAL):
                await scan_store.save_summary(scan)
                if phase_changed:
                    await scan_store.save_events(scan)
                last_save_time = now

        async def on_finding(findings_list):
            from core.models.finding import Finding
            import copy
            for f in findings_list:
                try:
                    finding = Finding.from_dict(copy.deepcopy(f))
                    scan.add_finding(finding)
                except Exception as exc:
                    logger.warning("Failed to deserialize real-time finding: %s", exc)
            # Persist immediately so SSE picks it up
            await scan_store.save_summary(scan)

        if orchestrator_instance:
             orchestrator = orchestrator_instance
             orchestrator.progress_callback = on_progress
             orchestrator.finding_callback = on_finding
        else:
             orchestrator = ScanOrchestrator(
                config=scan.config,
                detector_registry=detector_registry,
                progress_callback=on_progress,
                finding_callback=on_finding
             )
        
        result = await orchestrator.run(scan.target)

        # Deserialize orchestrator findings (dicts) into Finding objects
        from core.models.finding import Finding
        import copy
        raw_findings = result.get("findings", [])
        for f in raw_findings:
            try:
                finding = Finding.from_dict(copy.deepcopy(f))
                scan.add_finding(finding)
            except Exception as exc:
                logger.warning("Failed to deserialize finding: %s", exc)

        # Update scan metrics from orchestrator stats
        stats = result.get("stats", {})
        by_sev = stats.get("by_severity", {})
        scan.metrics.raw_findings       = len(raw_findings)
        scan.metrics.confirmed_findings = sum(1 for f in scan.findings if getattr(f, "confirmed", True))

        # 3. Mark as COMPLETE
        scan.mark_complete()

    except asyncio.CancelledError:
        scan.mark_cancelled()
        logger.info("Scan %s cancelled", scan.id[:8])

    except Exception as exc:
        scan.mark_failed(str(exc))
        logger.exception("Scan %s failed: %s", scan.id[:8], exc)

    finally:
        # Persist final state
        try:
            await scan_store.save_summary(scan)
            await scan_store.save_findings(scan)
            await scan_store.save_events(scan)
        except Exception as exc:
            logger.error("Failed to persist scan %s results: %s", scan.id[:8], exc)

        # Remove from active tasks registry
        active_scans.pop(scan.id, None)

        audit.info(
            "SCAN_COMPLETED scan_id=%s status=%s findings=%d duration_s=%.1f",
            scan.id[:8],
            scan.status,
            len(scan.findings),
            scan.duration_seconds or 0,
        )

        # Auto-generate report if requested
        if auto_report and scan.status == "complete":
            try:
                await _auto_generate_report(scan, report_type, report_prepared_for, owner_id)
            except Exception as exc:
                logger.error("Auto-report generation failed for scan %s: %s", scan.id[:8], exc)


async def _auto_generate_report(scan, report_type: str, prepared_for: str, owner_id: str) -> None:
    """Generate a report on scan completion. Errors propagate to the caller."""
    logger.info("Auto-generating %s report for scan %s", report_type, scan.id[:8])
    from reporting.builder import ReportBuilder
    builder = ReportBuilder(scan)
    await builder.build(
        report_type=report_type,
        format="pdf",
        prepared_for=prepared_for,
    )
    logger.info("Successfully generated auto-report for scan %s", scan.id[:8])


@router.get("/stats", summary="Get global scan statistics")
async def get_global_stats(
    user: AuthenticatedUser = Depends(require_auth),
    scan_store = Depends(get_scan_store),
):
    """Return aggregated statistics for the dashboard."""
    return await scan_store.stats()


@router.get("/findings/recent", summary="Get recent findings across all scans")
async def get_recent_findings(
    limit:  int = Query(5, ge=1, le=50),
    user:   AuthenticatedUser = Depends(require_auth),
    scan_store = Depends(get_scan_store),
):
    """
    Load the most recent findings across all scans.
    This is used for the Global Intelligence Feed on the dashboard.
    """
    # 1. Get recent scans
    scans, _ = await scan_store.list_scans(limit=10) # check last 10 scans
    all_recent = []
    
    for s in scans:
        sid = s.get("id") or s.get("scan_id")
        findings = await scan_store.load_findings(sid)
        # Add scan metadata to each finding for context
        for f in findings:
            f["target_url"] = s.get("target_url")
            all_recent.append(f)
            
    # 2. Sort by timestamp (most recent first) and return top N
    # Assumes finding has 'discovered_at' field
    all_recent.sort(key=lambda x: x.get("discovered_at", ""), reverse=True)
    return all_recent[:limit]


# ── List / detail ──────────────────────────────────────────────────────────────

@router.get("", summary="List scans")
async def list_scans(
    page:      PaginationParams = Depends(get_pagination),
    filters:   ScanFilters      = Depends(get_scan_filters),
    user:      AuthenticatedUser = Depends(require_auth),
    scan_store = Depends(get_scan_store),
):
    """
    List scans with pagination and optional filters.
    Analysts see only their own scans. Admins see all.
    """
    owner_filter = None if user.is_admin else user.user_id

    scans, total = await scan_store.list_scans(
        owner_id=owner_filter,
        status=filters.status,
        target_url=filters.target_url,
        offset=page.offset,
        limit=page.limit,
    )

    # Normalize: ensure every summary has a flat target_url, total_findings,
    # and finding_count so the frontend never needs to dig into nested dicts.
    def _normalize(s: dict) -> dict:
        if not s.get("target_url"):
            t = s.get("target") or {}
            s["target_url"] = (
                t.get("base_url") or t.get("url") or
                t.get("target_url") or ""
            )
        stats = s.get("stats") or {}
        if "total_findings" not in s:
            s["total_findings"] = stats.get("total", 0)
        if "finding_count" not in s:
            s["finding_count"] = stats.get("total", 0)
        if "critical_count" not in s:
            s["critical_count"] = stats.get("critical", 0)
        return s

    scans = [_normalize(s) for s in scans]

    return {
        "items":  scans,
        "scans":  scans,
        "total":  total,
        "page":   page.page,
        "limit":  page.limit,
        "pages":  (total + page.limit - 1) // page.limit if total else 0,
    }


@router.get("/findings", summary="Get all findings across scans")
async def list_all_findings(
    severity:  str | None = Query(None, description="Filter by severity: critical, high, medium, low, info"),
    page:      PaginationParams = Depends(get_pagination),
    user:      AuthenticatedUser = Depends(require_auth),
    scan_store = Depends(get_scan_store),
):
    """
    List all findings across all user's scans (or all scans if admin).
    Returns paginated findings with filters.
    """
    owner_filter = None if user.is_admin else user.user_id
    
    # Get all scans for this user
    scans, _ = await scan_store.list_scans(
        owner_id=owner_filter,
        status=None,
        target_url=None,
        offset=0,
        limit=10000,  # Get all scans
    )
    
    # Aggregate findings from all scans
    all_findings = []
    for scan in scans:
        scan_id = scan.get("id") or scan.get("scan_id") if isinstance(scan, dict) else scan.id
        target_url = scan.get("target_url") if isinstance(scan, dict) else scan.target_url
        
        findings = await scan_store.load_findings(scan_id)
        for finding in findings:
            # Handle both dict and object findings
            finding_severity = (
                finding.get("severity", "").lower() if isinstance(finding, dict)
                else getattr(finding, "severity", "").lower()
            )
            
            # Filter by severity if specified
            if severity and finding_severity != severity.lower():
                continue
            
            # Convert finding to dict
            if isinstance(finding, dict):
                finding_dict = finding.copy()
            else:
                finding_dict = finding.to_dict(include_evidence=False, include_remediation=False)
            
            finding_dict['scan_id'] = scan_id
            finding_dict['target_url'] = target_url
            all_findings.append(finding_dict)
    
    # Sort by CVSS (highest first)
    all_findings.sort(key=lambda f: float(f.get('cvss_score', 0.0)), reverse=True)
    
    # Paginate
    total = len(all_findings)
    start = page.offset
    end = start + page.limit
    paginated = all_findings[start:end]
    
    return {
        "findings": paginated,
        "total": total,
        "page": page.page,
        "limit": page.limit,
        "pages": (total + page.limit - 1) // page.limit if total else 0,
    }


@router.get("/{scan_id}", summary="Get scan detail")
async def get_scan(
    scan_id:   str,
    include_findings: bool = Query(False, description="Include full findings list"),
    user:      AuthenticatedUser = Depends(require_auth),
    scan       = Depends(require_scan_access),
    scan_store = Depends(get_scan_store),
):
    """
    Return full scan record including summary stats.

    By default returns the scan without the findings list (lightweight).
    Set include_findings=true to include all findings inline — use only
    for scans with < 50 findings; for larger result sets use
    GET /scans/{id}/findings with pagination.
    """
    data = scan.to_summary_dict()

    if include_findings:
        findings = await scan_store.load_findings(scan_id)
        data["findings"] = [
            f.to_dict(include_evidence=False, include_remediation=True)
            for f in findings
        ]
        data["finding_count"] = len(findings)

    return data


@router.get("/{scan_id}/status", summary="Poll scan status")
async def get_scan_status(
    scan_id:    str,
    stream:     bool = Query(False, description="Stream status via SSE"),
    user:       AuthenticatedUser = Depends(require_auth),
    scan        = Depends(require_scan_access),
    active_scans: dict = Depends(get_active_scans),
    scan_store  = Depends(get_scan_store),
):
    """
    Lightweight status endpoint. Returns current phase, finding counts, eta.

    Set ?stream=true for Server-Sent Events (SSE) — the connection stays
    open and events are pushed as the scan progresses. Reconnect on 503.
    """
    if stream:
        return _sse_stream(scan_id, active_scans, scan_store)

    # One-shot status response
    task = active_scans.get(scan_id)
    is_running = task is not None and not task.done()

    metrics = scan.metrics
    return {
        "scan_id":        scan_id,
        "status":         scan.status,
        "phase":          scan.current_phase,
        "is_running":     is_running,
        "pages_crawled":  metrics.pages_crawled if metrics else 0,
        "findings_so_far": len(scan.findings),
        "critical_count": sum(1 for f in scan.findings if getattr(f, "severity", "") == "critical"),
        "high_count":     sum(1 for f in scan.findings if getattr(f, "severity", "") == "high"),
        "duration_seconds": scan.duration_seconds,
        "started_at":     scan.started_at,
        "completed_at":   scan.completed_at,
        "error":          scan.error,
    }


@router.get("/analytics/risk-score", summary="Get global risk analytics score")
async def get_analytics_risk_score(
    user: AuthenticatedUser = Depends(require_auth),
    scan_store = Depends(get_scan_store),
):
    """
    Return the global risk score aggregated from all scans.
    Calculated as a weighted priority score across critical and high findings.
    """
    stats = await scan_store.stats()
    # Premium risk formula: (critical * 15) + (total * 2)
    critical = stats.get("critical_count", 0)
    total = stats.get("total_findings", 0)
    score = min(100, (critical * 15) + ((total - critical) * 2))
    return {"risk_score": score, "critical_count": critical, "total_findings": total}


def _sse_stream(scan_id: str, active_scans: dict, scan_store):
    """Return a streaming SSE response for real-time scan progress."""
    async def event_generator():
        last_finding_count = 0
        last_event_count = 0
        while True:
            task = active_scans.get(scan_id)
            is_done = task is None or task.done()

            # Reload scan from store on every tick
            try:
                raw = await scan_store.get_summary(scan_id) or {}
                # Also load findings if the count changed to get the latest one
                current_count = raw.get("finding_count", 0)
                latest_finding = None
                
                if current_count > last_finding_count:
                    all_findings = await scan_store.load_findings(scan_id)
                    if all_findings:
                        f = all_findings[-1]
                        latest_finding = {
                            "id": f.get("id") or f.get("scan_id"),
                            "title": f.get("title"),
                            "severity": f.get("severity"),
                            "vuln_type": f.get("vuln_type"),
                            "target_url": raw.get("target_url")
                        }
                
                new_findings = current_count - last_finding_count
                last_finding_count = current_count

                # Load latest event for audit log streaming
                all_events = await scan_store.load_events(scan_id)
                latest_event = None
                if len(all_events) > last_event_count:
                    latest_event = all_events[-1]
                    last_event_count = len(all_events)

                # Extract progress metrics
                progress_pct = raw.get("progress", 0.0)
                if isinstance(raw.get("metrics"), dict):
                    crawled = raw["metrics"].get("pages_crawled", 0)
                else:
                    crawled = 0

                event_data = json.dumps({
                    "status":         raw.get("status", "running"),
                    "phase":          raw.get("current_phase", "crawling"),
                    "current_phase":  raw.get("current_phase", "crawling"),
                    "progress":       progress_pct,
                    "total_findings": current_count,
                    "finding_count":  current_count,
                    "new_findings":   new_findings,
                    "latest_finding": latest_finding,
                    "event":          latest_event,
                    "pages_crawled":  crawled,
                    "target_url":     raw.get("target_url", ""),
                    "active_detectors": raw.get("active_detectors", []),
                    "findings_by_class": raw.get("findings_by_class", {}),
                    "critical_count": raw.get("critical_count", 0),
                    "duration_s":    raw.get("duration_seconds"),
                })
                yield f"data: {event_data}\n\n"

            except Exception as e:
                logger.error("SSE stream error for %s: %s", scan_id, e)
                yield f"data: {json.dumps({'error': 'stream_interrupted'})}\n\n"

            if is_done:
                yield "event: complete\ndata: {}\n\n"
                break

            await asyncio.sleep(0.75)  # Poll every 750ms for higher responsiveness

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ── Cancel ─────────────────────────────────────────────────────────────────────

@router.post("/{scan_id}/cancel", summary="Cancel a running scan")
async def cancel_scan(
    scan_id:      str,
    user:         AuthenticatedUser = Depends(require_auth),
    scan          = Depends(require_scan_access),
    active_scans: dict = Depends(get_active_scans),
    scan_store    = Depends(get_scan_store),
):
    """
    Cancel a running scan. Already complete or failed scans cannot be cancelled.
    The scanner completes the current HTTP request before stopping — there may
    be a delay of up to one rate-limit interval.
    """
    if scan.status not in ("pending", "running"):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot cancel a scan with status {scan.status!r}.",
        )

    task = active_scans.get(scan_id)
    if task and not task.done():
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=5.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass

    scan.mark_cancelled()
    await scan_store.save_summary(scan)

    audit.info("SCAN_CANCELLED scan_id=%s user_id=%s", scan_id[:8], user.user_id[:8])
    return {"scan_id": scan_id, "status": "cancelled", "message": "Scan has been cancelled."}


@router.post("/{scan_id}/recover", summary="Initiate tactical recovery for a scan")
async def recover_scan(
    scan_id:      str,
    user:         AuthenticatedUser = Depends(require_auth),
    scan          = Depends(require_scan_access),
    active_scans: dict = Depends(get_active_scans),
):
    """
    Initiate tactical recovery to force a scan to bypass its current stall.
    Only effective for 'running' scans stuck in the CRAWLING phase.
    """
    if scan.status != "running":
        raise HTTPException(400, "Recovery can only be initiated on running scans.")

    task = active_scans.get(scan_id)
    if not task or not hasattr(task, "orchestrator"):
        raise HTTPException(404, "Active orchestrator not found for this scan.")

    # Execute recovery logic on the orchestrator
    logger.info("Recovery trigger requested for scan %s by user %s", scan_id[:8], user.user_id[:8])
    await task.orchestrator.recover()

    return {
        "scan_id": scan_id, 
        "status": "recovery_initiated", 
        "message": "Tactical recovery initiated. Scanning should resume shortly."
    }


@router.delete("/{scan_id}", status_code=204, summary="Delete scan record")
async def delete_scan(
    scan_id:   str,
    user:      AuthenticatedUser = Depends(require_auth),
    scan       = Depends(require_scan_access),
    scan_store = Depends(get_scan_store),
    active_scans: dict = Depends(get_active_scans),
):
    """
    Permanently delete a scan and all its findings, events, and exports.
    Running scans are cancelled first. Admin can delete any scan.
    """
    if not user.is_admin and scan.status == "running":
        raise HTTPException(
            409,
            "Cannot delete a running scan. Cancel it first via POST /cancel.",
        )

    # Cancel if running
    task = active_scans.pop(scan_id, None)
    if task and not task.done():
        task.cancel()

    await scan_store.delete_scan(scan_id)
    audit.info("SCAN_DELETED scan_id=%s user_id=%s", scan_id[:8], user.user_id[:8])


# ── Findings ───────────────────────────────────────────────────────────────────

@router.get("/{scan_id}/findings", summary="List findings for a scan")
async def list_findings(
    scan_id:      str,
    page:         PaginationParams = Depends(get_pagination),
    severity:     Optional[str] = Query(None, description="Filter by severity"),
    vuln_type:    Optional[str] = Query(None, description="Filter by vulnerability type"),
    ea_only:      bool = Query(False, description="Only EA-relevant findings"),
    payment_only: bool = Query(False, description="Only payment-related findings"),
    min_cvss:     Optional[float] = Query(None, ge=0.0, le=10.0),
    include_evidence:    bool = Query(False),
    include_remediation: bool = Query(True),
    sort:         str = Query("risk_priority", description="Sort field"),
    user:         AuthenticatedUser = Depends(require_auth),
    scan          = Depends(require_scan_access),
    scan_store    = Depends(get_scan_store),
):
    """
    Return findings for a scan with filtering, sorting, and pagination.

    Findings are sorted by risk_priority (ascending = most critical first)
    by default. Other sort options: cvss_score, severity, vuln_type.

    Use include_evidence=true only when viewing a single finding's detail
    — evidence includes raw payloads which increase response size significantly.
    """
    all_findings = await scan_store.load_findings(scan_id)

    # Apply filters
    filtered = _filter_findings(
        all_findings,
        severity=severity,
        vuln_type=vuln_type,
        ea_only=ea_only,
        payment_only=payment_only,
        min_cvss=min_cvss,
    )

    # Sort
    filtered = _sort_findings(filtered, sort)

    # Paginate
    total = len(filtered)
    page_findings = filtered[page.offset: page.offset + page.limit]

    return {
        "scan_id":  scan_id,
        "findings": [
            f.to_dict(
                include_evidence=include_evidence,
                include_remediation=include_remediation,
            )
            for f in page_findings
        ],
        "total":   total,
        "page":    page.page,
        "limit":   page.limit,
        "pages":   (total + page.limit - 1) // page.limit if total else 0,
        "filters": {
            "severity":     severity,
            "vuln_type":    vuln_type,
            "ea_only":      ea_only,
            "payment_only": payment_only,
            "min_cvss":     min_cvss,
        },
    }


@router.get("/{scan_id}/findings/{finding_id}", summary="Get finding detail")
async def get_finding(
    scan_id:    str,
    finding_id: str,
    include_evidence:    bool = Query(True),
    include_remediation: bool = Query(True),
    user:       AuthenticatedUser = Depends(require_auth),
    scan        = Depends(require_scan_access),
    scan_store  = Depends(get_scan_store),
):
    """
    Return a single finding with full evidence and remediation guide.

    Evidence includes the exact HTTP request that triggered the finding,
    the matched response pattern, and timing information for blind findings.
    """
    all_findings = await scan_store.load_findings(scan_id)
    finding = next((f for f in all_findings if f.id == finding_id), None)

    if finding is None:
        raise HTTPException(404, f"Finding {finding_id!r} not found in scan {scan_id!r}.")

    return finding.to_dict(
        include_evidence=include_evidence,
        include_remediation=include_remediation,
    )


@router.patch("/{scan_id}/findings/{finding_id}", summary="Update finding status")
async def patch_finding(
    scan_id:    str,
    finding_id: str,
    body:       PatchFindingRequest,
    user:       AuthenticatedUser = Depends(require_auth),
    scan        = Depends(require_scan_access),
    scan_store  = Depends(get_scan_store),
):
    """
    Update finding remediation status or assignment.
    Analysts can assign to themselves or mark as fixed.
    Admin can change any status.
    """
    all_findings = await scan_store.load_findings(scan_id)
    finding_dict = next((f for f in all_findings if f.get("id") == finding_id), None)
    
    if finding_dict is None:
        raise HTTPException(404, "Finding not found")
        
    if body.remediation_status:
            finding_dict["remediation_status"] = body.remediation_status
            if body.remediation_status == "fixed":
                finding_dict["fixed_at"] = datetime.now(timezone.utc).isoformat()
            
    if body.assigned_to:
        finding_dict["assigned_to"] = body.assigned_to
        
    scan.findings = all_findings
    await scan_store.save_findings(scan)
    return finding_dict


# ── Events ─────────────────────────────────────────────────────────────────────

@router.get("/{scan_id}/events", summary="Get scan audit event log")
async def get_scan_events(
    scan_id:   str,
    page:      PaginationParams = Depends(get_pagination),
    level:     Optional[str] = Query(None, description="Filter by event level"),
    user:      AuthenticatedUser = Depends(require_auth),
    scan       = Depends(require_scan_access),
    scan_store = Depends(get_scan_store),
):
    """
    Return the immutable audit event log for a scan.

    Events record every phase transition, scope check, rate limit hit,
    and error. Used in compliance reports to demonstrate scan methodology.
    """
    events = await scan_store.load_events(scan_id)

    if level:
        events = [e for e in events if getattr(e, "level", "info").lower() == level.lower()]

    total = len(events)
    page_events = events[page.offset: page.offset + page.limit]

    return {
        "scan_id": scan_id,
        "events":  [e.to_dict() if hasattr(e, "to_dict") else e for e in page_events],
        "total":   total,
        "page":    page.page,
        "limit":   page.limit,
    }


# ── Exports ────────────────────────────────────────────────────────────────────

@router.get("/{scan_id}/export/csv", summary="Export findings as CSV")
async def export_csv(
    scan_id:   str,
    severity:  Optional[str] = Query(None),
    ea_only:   bool = Query(False),
    user:      AuthenticatedUser = Depends(require_auth),
    scan       = Depends(require_scan_access),
    scan_store = Depends(get_scan_store),
):
    """
    Download all findings as a CSV file.
    Includes all core finding fields but not raw evidence payloads.
    Suitable for import into vulnerability management tools.
    """
    all_findings = await scan_store.load_findings(scan_id)
    filtered = _filter_findings(all_findings, severity=severity, ea_only=ea_only)
    sorted_findings = _sort_findings(filtered, "risk_priority")

    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    writer.writerow([
        "risk_priority", "severity", "cvss_score", "effective_cvss",
        "vuln_type", "vuln_label", "url", "parameter",
        "parameter_location", "confidence", "owasp_category",
        "cwe_id", "ea_relevant", "affects_payments",
        "discovered_at", "fingerprint",
    ])

    for f in sorted_findings:
        row = getattr(f, "to_csv_row", lambda: {})()
        if isinstance(row, dict):
            writer.writerow([
                row.get("risk_priority", ""),
                row.get("severity", ""),
                row.get("cvss_score", ""),
                row.get("effective_cvss", ""),
                row.get("vuln_type", ""),
                row.get("vuln_label", ""),
                row.get("url", ""),
                row.get("parameter_name", ""),
                row.get("parameter_location", ""),
                row.get("confidence", ""),
                row.get("owasp_category", ""),
                row.get("cwe_id", ""),
                row.get("ea_relevant", ""),
                row.get("affects_payments", ""),
                row.get("discovered_at", ""),
                row.get("fingerprint", ""),
            ])

    output.seek(0)
    filename = f"vulnscout-{scan_id[:8]}-findings.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{scan_id}/export/json", summary="Export full scan as JSON")
async def export_json(
    scan_id:          str,
    include_evidence: bool = Query(False, description="Include raw HTTP evidence"),
    user:             AuthenticatedUser = Depends(require_auth),
    scan              = Depends(require_scan_access),
    scan_store        = Depends(get_scan_store),
):
    """
    Download the complete scan record as JSON including all findings,
    metrics, and events. Suitable for archiving or importing into other tools.

    Evidence (raw HTTP payloads) is excluded by default to keep file size
    manageable. Set include_evidence=true for the full record.
    """
    findings = await scan_store.load_findings(scan_id)
    events   = await scan_store.load_events(scan_id)

    scan_data = scan.to_full_dict(
        include_evidence=include_evidence,
        include_events=True,
        include_scope_audit=True,
    )
    scan_data["findings"] = [
        f.to_dict(include_evidence=include_evidence, include_remediation=True)
        for f in findings
    ]
    scan_data["events"] = [
        e.to_dict() if hasattr(e, "to_dict") else e for e in events
    ]
    scan_data["export_meta"] = {
        "exported_at":    datetime.now(timezone.utc).isoformat(),
        "exported_by":    user.user_id[:8],
        "include_evidence": include_evidence,
        "tool":           "VulnScout Pro",
        "tool_version":   get_config().app.version,
    }

    filename = f"vulnscout-{scan_id[:8]}-full.json"
    return StreamingResponse(
        iter([json.dumps(scan_data, indent=2, default=str)]),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{scan_id}/export/logs", summary="Export audit events as TXT")
async def export_logs(
    scan_id:   str,
    user:      AuthenticatedUser = Depends(require_auth),
    scan       = Depends(require_scan_access),
    scan_store = Depends(get_scan_store),
):
    """
    Download the complete immutable scan audit log as a raw text file.
    """
    events = await scan_store.load_events(scan_id)
    
    output = io.StringIO()
    output.write(f"VULNSCOUT PRO — AUDIT EVENT LOG\n")
    output.write(f"SCAN_ID: {scan_id}\n")
    output.write(f"EXPORTED: {datetime.now(timezone.utc).isoformat()}Z\n")
    output.write("="*80 + "\n\n")

    for e in events:
        ts = e.timestamp.isoformat() if hasattr(e.timestamp, 'isoformat') else str(e.timestamp)
        output.write(f"[{ts}] {e.level.upper():8} | {e.phase.upper():12} | {e.message}\n")
    
    output.seek(0)
    filename = f"vulnscout-{scan_id[:8]}-audit.log"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{scan_id}/report", summary="Download scan report")
async def get_scan_report(
    scan_id:     str,
    format:      str = Query("pdf", description="Report format (pdf, html, json, csv)"),
    report_type: str = Query("technical", description="Report type (executive, technical, compliance)"),
    user:        AuthenticatedUser = Depends(require_auth),
    scan         = Depends(require_scan_access),
):
    """
    Generate and download a professional vulnerability report.
    Supports PDF (default), HTML, JSON, and CSV formats.
    """
    from reporting.builder import ReportBuilder
    builder = ReportBuilder(scan)
    try:
        report_bytes = await builder.build(report_type=report_type, format=format)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except RuntimeError as e:
        raise HTTPException(500, f"Report generation failed: {str(e)}")

    media_types = {
        "pdf": "application/pdf",
        "html": "text/html",
        "json": "application/json",
        "csv": "text/csv",
    }

    filename = f"vulnscout-report-{scan_id[:8]}.{format}"
    return Response(
        content=report_bytes,
        media_type=media_types.get(format, "application/octet-stream"),
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Internal helpers ───────────────────────────────────────────────────────────

def _filter_findings(
    findings: list,
    severity:     Optional[str] = None,
    vuln_type:    Optional[str] = None,
    ea_only:      bool = False,
    payment_only: bool = False,
    min_cvss:     Optional[float] = None,
) -> list:
    """Apply multi-dimensional filters to a findings list."""
    result = findings

    if severity:
        _sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
        min_rank = _sev_order.get(severity.lower(), 0)
        result = [
            f for f in result
            if _sev_order.get(getattr(f, "severity", "").lower(), -1) >= min_rank
        ]

    if vuln_type:
        result = [
            f for f in result
            if getattr(f, "vuln_type", "").lower() == vuln_type.lower()
        ]

    if ea_only:
        result = [
            f for f in result
            if getattr(getattr(f, "ea_context", None), "ea_relevant", False)
        ]

    if payment_only:
        result = [f for f in result if getattr(f, "affects_payments", False)]

    if min_cvss is not None:
        result = [f for f in result if getattr(f, "cvss_score", 0.0) >= min_cvss]

    return result


def _sort_findings(findings: list, sort: str) -> list:
    """Sort findings list by the given field name."""
    _SORT_KEYS: Dict[str, Any] = {
        "risk_priority": lambda f: getattr(f, "risk_priority", 9999),
        "cvss_score":    lambda f: -(getattr(f, "cvss_score", 0.0)),
        "effective_cvss": lambda f: -(getattr(f, "effective_cvss", 0.0)),
        "severity":      lambda f: -{"critical": 4, "high": 3, "medium": 2,
                                      "low": 1, "informational": 0}.get(
                                      getattr(f, "severity", ""), 0),
        "vuln_type":     lambda f: getattr(f, "vuln_type", ""),
        "url":           lambda f: getattr(f, "url", ""),
        "confidence":    lambda f: -(getattr(f, "confidence", 0.0)),
        "discovered_at": lambda f: getattr(f, "discovered_at", ""),
    }
    key_fn = _SORT_KEYS.get(sort, _SORT_KEYS["risk_priority"])
    try:
        return sorted(findings, key=key_fn)
    except Exception:
        return findings


# ── Compatibility Aliases for No-JS Forms ─────────────────────────────────────

@router.post("/new", summary="Submit a new scan (Form alias)")
async def submit_scan_form(
    request:          Request,
    target_url:       str = Form(...),
    authorised_by:    str = Form(""),
    authorisation_notes: str = Form(""),
    crawl_depth:      int = Form(3),
    rate_limit_rps:   float = Form(2.0),
    enabled_checks:   List[str] = Form(default_factory=list),
    auth_type:        str = Form("none"),
    auth_username:    Optional[str] = Form(None),
    auth_password:    Optional[str] = Form(None),
    auth_token:       Optional[str] = Form(None),
    user:             AuthenticatedUser = Depends(check_scan_rate_limit),
    scan_store        = Depends(get_scan_store),
    detector_registry = Depends(get_detector_registry),
    active_scans: dict = Depends(get_active_scans),
):
    """Bridges the HTML form submission to the internal create_scan logic."""
    try:
        body = ScanRequest(
            target_url=target_url,
            authorised_by=authorised_by,
            authorisation_notes=authorisation_notes,
            crawl_depth=crawl_depth,
            rate_limit_rps=rate_limit_rps,
            enabled_checks=enabled_checks,
            auth_type=auth_type,
            auth_username=auth_username,
            auth_password=auth_password,
            auth_token=auth_token,
        )
        res = await create_scan(body, request, user, scan_store, detector_registry, active_scans)
        return RedirectResponse(url=f"/scans/{res.scan_id}", status_code=303)
    except Exception as exc:
        logger.warning("Scan form submission failed: %s", exc)
        # Redirect back to the new scan page with an error message
        # (Assuming scan_new.html can show an 'error' context variable)
        return RedirectResponse(url=f"/scans/new?error={str(exc)}", status_code=303)


@router.post("/{scan_id}/stop", summary="Stop a running scan (Form alias)")
async def stop_scan_form(
    scan_id:   str,
    user:      AuthenticatedUser = Depends(require_auth),
    scan       = Depends(require_scan_access),
    active_scans: dict = Depends(get_active_scans),
    scan_store = Depends(get_scan_store),
):
    """Alias for cancel_scan that redirects back to detail page."""
    await cancel_scan(scan_id, user, scan, active_scans, scan_store)
    return RedirectResponse(url=f"/scans/{scan_id}", status_code=303)


@router.post("/{scan_id}/findings/{finding_id}/status", summary="Update finding status (Form alias)")
async def update_finding_status_form(
    scan_id:    str,
    finding_id: str,
    status:     str = Form(...),
    user:       AuthenticatedUser = Depends(require_auth),
    scan        = Depends(require_scan_access),
    scan_store  = Depends(get_scan_store),
):
    """Alias for patch_finding that redirects back to detail page."""
    body = PatchFindingRequest(remediation_status=status)
    await patch_finding(scan_id, finding_id, body, user, scan, scan_store)
    return RedirectResponse(url=f"/scans/{scan_id}", status_code=303)
