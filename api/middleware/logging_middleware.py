"""
api/middleware/logging_middleware.py — Request/Response Logging Middleware

Produces one structured log line per request containing:
  - request_id   — UUID attached to all subsequent log lines for this request
  - method, path, status, duration_ms
  - user_id      — if authenticated (never email or other PII)
  - ip_address   — respects X-Forwarded-For when behind_proxy=True
  - user_agent   — truncated to 100 chars

Also attaches request_id to the response via X-Request-ID header
so clients can correlate their request to server-side logs.

Sensitive paths are logged at DEBUG level only (login, token endpoints)
to prevent credential leakage into INFO-level log aggregators.

Slow request threshold: 5000ms → WARNING (alerts on hung scans / slow queries)
Very slow threshold: 30000ms → ERROR  (circuit breaker candidate)
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("vulnscout.http")

# Paths where request bodies / query strings should not be logged
_SENSITIVE_PATHS = frozenset([
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/auth/refresh",
    "/api/v1/auth/reset-password",
    "/api/v1/auth/forgot-password",
])

_SLOW_REQUEST_MS   = 5_000
_CRITICAL_DELAY_MS = 30_000


class LoggingMiddleware(BaseHTTPMiddleware):
    """
    Attaches a request_id to every request and logs request/response pairs.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Generate or inherit request ID
        request_id = (
            request.headers.get("X-Request-ID")
            or str(uuid.uuid4())
        )
        request.state.request_id = request_id

        start = time.monotonic()
        status_code = 500

        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception:
            logger.exception(
                "Unhandled exception | request_id=%s %s %s",
                request_id, request.method, request.url.path,
            )
            raise
        finally:
            elapsed_ms = round((time.monotonic() - start) * 1000, 2)
            self._log(request, request_id, status_code, elapsed_ms)

        # Attach request ID to response headers
        response.headers["X-Request-ID"] = request_id
        return response

    def _log(
        self,
        request: Request,
        request_id: str,
        status_code: int,
        elapsed_ms: float,
    ) -> None:
        """Emit structured log line at appropriate level."""
        path  = request.url.path
        is_sensitive = path in _SENSITIVE_PATHS

        user_id = ""
        user = getattr(request.state, "user", None)
        if user:
            user_id = getattr(user, "user_id", "")[:8]

        ip = self._get_client_ip(request)
        ua = (request.headers.get("User-Agent", "")[:100])

        log_data = {
            "request_id": request_id,
            "method":     request.method,
            "path":       path if not is_sensitive else path + " [SENSITIVE]",
            "status":     status_code,
            "duration_ms": elapsed_ms,
            "user_id":    user_id,
            "ip":         ip,
            "ua":         ua if not is_sensitive else "[REDACTED]",
        }

        # Choose log level based on status code and timing
        if elapsed_ms >= _CRITICAL_DELAY_MS:
            log_level = logging.ERROR
            log_data["alert"] = "very_slow_request"
        elif elapsed_ms >= _SLOW_REQUEST_MS:
            log_level = logging.WARNING
            log_data["alert"] = "slow_request"
        elif status_code >= 500:
            log_level = logging.ERROR
        elif status_code >= 400:
            log_level = logging.WARNING
        elif is_sensitive:
            log_level = logging.DEBUG
        else:
            log_level = logging.INFO

        logger.log(
            log_level,
            "%s %s %d %.0fms request_id=%s user=%s ip=%s",
            log_data["method"],
            log_data["path"],
            log_data["status"],
            log_data["duration_ms"],
            log_data["request_id"][:8],
            log_data["user_id"] or "anon",
            log_data["ip"],
            extra=log_data,
        )

    @staticmethod
    def _get_client_ip(request: Request) -> str:
        """
        Extract real client IP, respecting X-Forwarded-For when behind a proxy.
        Only uses forwarded header when config.server.behind_proxy is True.
        """
        from config import get_config
        config = get_config()

        if config.server.behind_proxy:
            forwarded_for = request.headers.get("X-Forwarded-For", "")
            if forwarded_for:
                # X-Forwarded-For: client, proxy1, proxy2
                # First address is the original client
                first = forwarded_for.split(",")[0].strip()
                if first:
                    return first

        client = request.client
        if client:
            return client.host
        return "unknown"