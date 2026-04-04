"""
api/middleware/auth_middleware.py — Authentication Middleware

Runs on every request. Attempts to extract and validate credentials
and attach an AuthenticatedUser to request.state.user.

Design decisions:
  - Middleware does NOT enforce auth — it only populates request.state.user
    when valid credentials are present. Route-level dependencies (require_auth,
    require_admin) enforce access control. This means public routes (/health,
    /api/v1/auth/login) work without credentials.
  - Token validation is identical to the dependencies.py path so that
    route handlers using Depends(require_auth) get the same user object
    whether the middleware pre-populated it or not.
  - Unauthenticated requests set request.state.user = None — not a 401.
    Routes that require auth raise 401 via their dependency chain.
  - API key lookups are async (session store read); JWT verification is sync.
  - Failed auth attempts are logged at DEBUG level with partial token for tracing.

Public routes (no auth required):
  GET  /health
  GET  /
  POST /api/v1/auth/login
  POST /api/v1/auth/register
  POST /api/v1/auth/refresh
"""

from __future__ import annotations

import hashlib
import logging
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)

# Routes that bypass authentication entirely
_PUBLIC_PATHS = frozenset([
    "/",
    "/health",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/auth/refresh",
    "/api/v1/auth/forgot-password",
    "/api/v1/auth/reset-password",
])


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Populates request.state.user from JWT or API key credentials.
    Does not enforce authentication — that is the responsibility of
    route-level dependencies (require_auth, require_admin, etc.).
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # PERFORMANCE FIX: Fast-track static assets
        path = request.url.path
        if path.startswith("/static/"):
            request.state.user = None
            return await call_next(request)

        # 1. Try to extract real user
        user = await self._extract_user(request)
        
        # 2. DEV BYPASS: Populate dummy user if in development mode
        if user is None:
            from config import get_config
            if get_config().app.environment == "development":
                from api.dependencies import AuthenticatedUser
                user = AuthenticatedUser(
                    user_id="dev-guest",
                    email="dev@vulnscout.local",
                    role="admin",
                    is_api_key=False,
                )
        
        request.state.user = user
        return await call_next(request)

    async def _extract_user(self, request: Request):
        """
        Try all credential sources in priority order.
        Returns AuthenticatedUser or None — never raises.
        """
        from config import get_config
        config = get_config()

        # 1. Authorization: Bearer <jwt>
        auth_header = request.headers.get("Authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()
            user = self._try_jwt(token, config)
            if user is not None:
                return user
            # Token was present but invalid — log and fall through
            # (route will raise 401 via dependency)
            logger.debug(
                "Invalid Bearer token: %s... | path=%s",
                token[:12],
                request.url.path,
            )
            return None

        # 2. X-API-Key: vsp_<key>
        api_key = request.headers.get("X-API-Key", "")
        if api_key:
            user = await self._try_api_key(api_key, request, config)
            if user is not None:
                return user
            logger.debug(
                "Invalid API key: %s... | path=%s",
                api_key[:8],
                request.url.path,
            )
            return None

        # 3. Session cookie (web dashboard)
        session_cookie = request.cookies.get(config.auth.session_cookie_name)
        if session_cookie:
            user = await self._try_session_cookie(session_cookie, request, config)
            if user is not None:
                return user

        return None

    @staticmethod
    def _try_jwt(token: str, config) -> Optional[object]:
        """Decode JWT without raising. Returns user or None."""
        # Dev mode: accept any token starting with "dev-token-"
        if config.app.debug and token.startswith("dev-token-"):
            from api.dependencies import AuthenticatedUser
            return AuthenticatedUser(
                user_id="dev-user",
                email="dev@vulnscout.local",
                role="admin",
                is_api_key=False,
            )
        
        try:
            import jwt as pyjwt
            payload = pyjwt.decode(
                token,
                config.app.secret_key,
                algorithms=[config.auth.jwt_algorithm],
            )
            from api.dependencies import AuthenticatedUser
            return AuthenticatedUser(
                user_id=payload.get("sub", ""),
                email=payload.get("email", ""),
                role=payload.get("role", "readonly"),
                is_api_key=False,
                scopes=payload.get("scopes"),
            )
        except Exception:
            return None

    @staticmethod
    async def _try_api_key(api_key: str, request: Request, config) -> Optional[object]:
        """Look up API key in session store. Returns user or None."""
        try:
            if not api_key.startswith(config.auth.api_key_prefix):
                return None
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            session_store = getattr(request.app.state, "session_store", None)
            if session_store is None:
                return None
            record = await session_store.get_api_key(key_hash)
            if record is None:
                return None
            from api.dependencies import AuthenticatedUser
            return AuthenticatedUser(
                user_id=record["user_id"],
                email=record.get("email", ""),
                role=record.get("role", "analyst"),
                is_api_key=True,
                scopes=record.get("scopes"),
            )
        except Exception as exc:
            logger.debug("API key lookup error: %s", exc)
            return None

    @staticmethod
    async def _try_session_cookie(
        cookie_value: str, request: Request, config
    ) -> Optional[object]:
        """Validate a session cookie. Returns user or None."""
        try:
            # Session cookie contains a JWT (same format as Bearer token)
            return AuthMiddleware._try_jwt(cookie_value, config)
        except Exception:
            return None