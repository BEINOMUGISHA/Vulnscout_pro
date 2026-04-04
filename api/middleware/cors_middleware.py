"""
api/middleware/cors_middleware.py — Security Headers Middleware

Named cors_middleware.py to match the project structure, but this file
contains SecurityHeadersMiddleware — the component that attaches all
security-related HTTP response headers.

FastAPI's CORSMiddleware (from starlette) handles actual CORS preflight
and is registered separately in main.py. This middleware adds the headers
that CORSMiddleware does not: HSTS, CSP, X-Frame-Options, etc.

Headers applied to every response:
  Strict-Transport-Security — HTTPS enforcement (production only)
  Content-Security-Policy   — XSS mitigation
  X-Frame-Options           — clickjacking protection
  X-Content-Type-Options    — MIME sniffing protection
  Referrer-Policy           — referrer leakage control
  Permissions-Policy        — browser feature restrictions
  X-VulnScout-Version       — version disclosure (controlled)
  Cache-Control             — prevent caching of sensitive API responses

Headers explicitly NOT set:
  Server                    — remove or mask the server identity
  X-Powered-By              — remove framework disclosure
"""

from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)

# Paths that serve static assets — different cache policy applies
_STATIC_PREFIXES = ("/static/", "/favicon.ico", "/robots.txt")

# API response paths — no-store cache to prevent sensitive data caching
_API_PREFIX = "/api/"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Attaches security headers to every HTTP response.
    Reads header values from the active configuration at request time
    (not at middleware construction) so config changes during testing
    are reflected without restarting.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        self._apply_headers(request, response)
        return response

    def _apply_headers(self, request: Request, response: Response) -> None:
        from config import get_config
        config = get_config()
        sec = config.security
        path = request.url.path

        # ── HSTS ──────────────────────────────────────────────────────────────
        if sec.hsts_enabled:
            hsts = f"max-age={sec.hsts_max_age_seconds}"
            if sec.hsts_include_subdomains:
                hsts += "; includeSubDomains"
            if sec.hsts_preload:
                hsts += "; preload"
            response.headers["Strict-Transport-Security"] = hsts

        # ── CSP ───────────────────────────────────────────────────────────────
        if sec.csp_enabled:
            response.headers["Content-Security-Policy"] = sec.csp_header_value()

        # ── Anti-clickjacking ─────────────────────────────────────────────────
        response.headers["X-Frame-Options"] = sec.x_frame_options

        # ── MIME sniffing protection ──────────────────────────────────────────
        response.headers["X-Content-Type-Options"] = sec.x_content_type_options

        # ── Referrer policy ───────────────────────────────────────────────────
        response.headers["Referrer-Policy"] = sec.referrer_policy

        # ── Permissions policy ────────────────────────────────────────────────
        response.headers["Permissions-Policy"] = sec.permissions_policy

        # ── Cache control ─────────────────────────────────────────────────────
        if path.startswith(_API_PREFIX):
            # Sensitive API data — never cache
            response.headers["Cache-Control"] = (
                "no-store, no-cache, must-revalidate, private"
            )
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        elif any(path.startswith(p) for p in _STATIC_PREFIXES):
            # Static assets — cache for 1 hour
            response.headers["Cache-Control"] = "public, max-age=3600, immutable"

        # ── Remove server identity headers ────────────────────────────────────
        for header in ["Server", "X-Powered-By"]:
            if header in response.headers:
                del response.headers[header]

        # ── VulnScout version header (controlled disclosure) ──────────────────
        response.headers["X-VulnScout-Version"] = config.app.version