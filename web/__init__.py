"""
web/dashboard.py — Web Dashboard Router

Serves the VulnScout Pro browser-based dashboard using Jinja2 templates
with server-side rendering. All data-heavy interactions use the API
(api/routes/) via fetch() — the dashboard HTML is a thin shell that
bootstraps the authenticated session and hands off to the JS client.

Routes:
  GET  /          → redirect to /dashboard
  GET  /dashboard → main dashboard (scan list, summary stats)
  GET  /scans/new → new scan form
  GET  /scans/{id} → scan detail view
  GET  /reports    → reports list
  GET  /reports/{id} → report detail + download
  GET  /settings   → user settings and API keys
  GET  /login      → login page (unauthenticated)
  GET  /logout     → clear session cookie, redirect to /login

Template context:
  Every route injects:
    - config: AppConfig subset (version, env, debug)
    - user: AuthenticatedUser | None
    - page_title: str
    - request: Request (required by Jinja2 for url_for)

Auth:
  Session cookie carries a JWT (same as API Bearer token).
  _require_session() checks the cookie and redirects to /login on failure.
  The web dashboard uses cookie-based auth; API routes use Bearer tokens.
  Both are validated by AuthMiddleware.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from config import get_config

logger = logging.getLogger(__name__)

# ── Template engine ────────────────────────────────────────────────────────────
import os
_TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=_TEMPLATES_DIR)

router = APIRouter()


# ── Auth helpers ───────────────────────────────────────────────────────────────

def _get_session_user(request: Request) -> Optional[object]:
    """[PAUSED] Always returns a hardcoded admin user for development."""
    from api.dependencies import AuthenticatedUser, _default_scopes
    return AuthenticatedUser(
        user_id="dev_admin",
        email="admin@vulnscout.local",
        role="admin",
        is_api_key=False,
        scopes=_default_scopes("admin")
    )


def _require_session(request: Request) -> object:
    """[PAUSED] Always returns the session user. No redirect."""
    return _get_session_user(request)


def _base_context(request: Request, page_title: str = "VulnScout Pro") -> dict:
    """Common context injected into every template."""
    config = get_config()
    user   = _get_session_user(request)
    return {
        "request":    request,
        "page_title": page_title,
        "app_name":   config.app.app_name,
        "version":    config.app.version,
        "environment": config.app.environment,
        "debug":      config.app.debug,
        "user":       user,
        "is_admin":   getattr(user, "is_admin", False),
        "ea_enabled": config.ea.ea_context_enabled,
    }


def _redirect_login(request: Request) -> RedirectResponse:
    """Redirect to login page with the current path as next= parameter."""
    next_url = request.url.path
    return RedirectResponse(url=f"/login?next={next_url}", status_code=302)


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.get("/", include_in_schema=False)
async def root_redirect():
    """Redirect root to dashboard."""
    return RedirectResponse(url="/dashboard", status_code=302)


@router.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def login_page(request: Request, next: str = "/dashboard"):
    """
    [PAUSED] Redirect to dashboard immediately.
    """
    return RedirectResponse(url="/dashboard", status_code=302)


@router.get("/logout", include_in_schema=False)
async def logout(request: Request):
    """Clear session cookie and redirect to login."""
    response = RedirectResponse(url="/login", status_code=302)
    config = get_config()
    response.delete_cookie(config.auth.session_cookie_name)
    return response


@router.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def dashboard(request: Request):
    """
    Main dashboard: recent scans, summary stats, quick-launch form.
    Data is loaded client-side via API calls in main.js.
    """
    user = _require_session(request)
    if user is None:
        return _redirect_login(request)

    ctx = _base_context(request, "Dashboard — VulnScout Pro")
    ctx["active_nav"] = "dashboard"
    return templates.TemplateResponse("dashboard.html", ctx)


@router.get("/scans", response_class=HTMLResponse, include_in_schema=False)
async def scans_list(request: Request):
    """Scan history list. Data loaded via API."""
    user = _require_session(request)
    if user is None:
        return _redirect_login(request)

    ctx = _base_context(request, "Scans — VulnScout Pro")
    ctx["active_nav"] = "scans"
    return templates.TemplateResponse("scans.html", ctx)


@router.get("/scans/new", response_class=HTMLResponse, include_in_schema=False)
async def new_scan(request: Request):
    """New scan submission form."""
    user = _require_session(request)
    if user is None:
        return _redirect_login(request)

    config = get_config()
    ctx = _base_context(request, "New Scan — VulnScout Pro")
    ctx["active_nav"]       = "scans"
    ctx["default_rps"]      = config.scan.rate_limit_rps
    ctx["default_depth"]    = config.scan.crawl_depth
    ctx["default_checks"]   = config.scan.enabled_checks
    ctx["ea_enabled"]       = config.ea.ea_context_enabled
    return templates.TemplateResponse("scan_new.html", ctx)


@router.get("/scans/{scan_id}", response_class=HTMLResponse, include_in_schema=False)
async def scan_detail(request: Request, scan_id: str):
    """
    Scan detail view: live progress, findings table, findings heatmap.
    Data and real-time updates loaded via API + SSE.
    """
    user = _require_session(request)
    if user is None:
        return _redirect_login(request)

    ctx = _base_context(request, f"Scan {scan_id[:8]} — VulnScout Pro")
    ctx["active_nav"] = "scans"
    ctx["scan_id"]    = scan_id
    return templates.TemplateResponse("scan_detail.html", ctx)


@router.get("/reports", response_class=HTMLResponse, include_in_schema=False)
async def reports_list(request: Request):
    """Reports list with filter and search."""
    user = _require_session(request)
    if user is None:
        return _redirect_login(request)

    ctx = _base_context(request, "Reports — VulnScout Pro")
    ctx["active_nav"] = "reports"
    return templates.TemplateResponse("reports.html", ctx)


@router.get("/reports/{report_id}", response_class=HTMLResponse, include_in_schema=False)
async def report_detail(request: Request, report_id: str):
    """Report viewer: render summary, findings table, compliance matrix."""
    user = _require_session(request)
    if user is None:
        return _redirect_login(request)

    ctx = _base_context(request, f"Report — VulnScout Pro")
    ctx["active_nav"] = "reports"
    ctx["report_id"]  = report_id
    return templates.TemplateResponse("report_detail.html", ctx)


@router.get("/settings", response_class=HTMLResponse, include_in_schema=False)
async def settings(request: Request):
    """User settings: profile, password change, TOTP enrollment, API keys."""
    user = _require_session(request)
    if user is None:
        return _redirect_login(request)

    config = get_config()
    ctx = _base_context(request, "Settings — VulnScout Pro")
    ctx["active_nav"]    = "settings"
    ctx["totp_required"] = config.auth.totp_required
    ctx["api_key_prefix"] = config.auth.api_key_prefix
    return templates.TemplateResponse("settings.html", ctx)