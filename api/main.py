"""
api/main.py — FastAPI Application Factory

Application entry point. Creates and configures the FastAPI instance,
registers all middleware in the correct order, mounts all routers,
and manages the application lifespan (startup / shutdown).

Middleware order (outermost to innermost — each wraps the next):
  1. CORSMiddleware      — handles preflight before auth runs
  2. SecurityHeadersMiddleware — attaches security headers to every response
  3. LoggingMiddleware   — times request/response, attaches request_id
  4. AuthMiddleware      — validates JWT / API key on protected routes

Startup sequence:
  1. Load and validate configuration
  2. Initialise storage directories
  3. Load detector registry
  4. Configure structured logging
  5. Bind API routes

Shutdown sequence:
  1. Signal running scans to cancel gracefully
  2. Flush audit log
  3. Close any open aiohttp sessions

Usage:
  uvicorn api.main:app --host 0.0.0.0 --port 8000
  uvicorn api.main:app --reload  (development)
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from config import get_config
from core.proxy.interceptor import proxy_engine

logger = logging.getLogger(__name__)


# ── Lifespan ───────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan manager (No-DB mode).
    Everything before 'yield' runs on startup; after yield runs on shutdown.
    
    In no-DB mode:
    - Single in-memory user with TOTP 2FA
    - All scan/report data is ephemeral (RAM-only)
    - No persistence, no database
    """
    config = get_config()

    # ── Startup ────────────────────────────────────────────────────────────────
    logger.info(
        "VulnScout Pro %s starting up [env=%s] — NO DATABASE MODE",
        config.app.version,
        config.app.environment,
    )

    # Initialise persistent session store
    from storage import SessionStore
    from auth.auth_manager import AuthManager
    from auth.audit_log import get_audit_log
    
    app.state.session_store = SessionStore(config.storage.data_dir)
    app.state.audit_log = get_audit_log()
    app.state.auth = AuthManager(app.state.session_store, app.state.audit_log)
    logger.info("Persistent AuthManager initialized at %s", config.storage.data_dir)

    # Initialise detector registry
    from core.detection.registry import DetectorRegistry
    app.state.detector_registry = DetectorRegistry.default()
    logger.info(
        "Loaded %d detection modules",
        len(app.state.detector_registry),
    )

    # Initialise storage (Flat-File Scan & Report Stores)
    from storage import mount_stores
    mount_stores(app)
    logger.info("Scan and Report stores initialized at %s", config.storage.data_dir)

    # Initialise scheduler
    from core.scheduler.scan_scheduler import ScanScheduler
    parallel_engine = getattr(app.state, "parallel_engine", None) # If exists
    app.state.scheduler = ScanScheduler(scan_store=app.state.scan_store, parallel_engine=parallel_engine)
    await app.state.scheduler.start()
    logger.info("Scan scheduler initialized")

    # Start the Interceptor Proxy Engine
    logger.info("Starting Burp-style Proxy Engine on port 8080...")
    try:
        await proxy_engine.start()
    except OSError as e:
        logger.warning(f"Could not start proxy engine (port possibly in use): {e}")

    logger.info("VulnScout Pro ready — listening on port %d (NO-DB MODE)", config.server.port)
    yield
    
    # ── Shutdown ───────────────────────────────────────────────────────────────
    logger.info("VulnScout Pro shutting down (no-DB mode)...")
    
    # In-memory storage is automatically freed by Python GC,
    # no persistence to flush
    
    # Stop the Interceptor Proxy Engine
    logger.info("Stopping Proxy Engine...")
    try:
        await proxy_engine.stop()
    except Exception as e:
        logger.warning(f"Error stopping proxy engine: {e}")
    
    # Stop scheduler
    if hasattr(app.state, "scheduler"):
        await app.state.scheduler.stop()
    
    logger.info("Shutdown complete")


# ── Application factory ────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    """
    Build and return the configured FastAPI application.
    Called once at module load time — the result is the ASGI app.
    """
    config = get_config()

    app = FastAPI(
        title=config.app.app_name,
        description=config.app.app_description,
        version=config.app.version,
        docs_url="/docs" if config.app.debug else None,
        redoc_url="/redoc" if config.app.debug else None,
        openapi_url="/openapi.json" if config.app.debug else None,
        lifespan=lifespan,
    )

    _register_middleware(app, config)
    _register_routes(app)
    _register_exception_handlers(app)

    return app


def _register_middleware(app: FastAPI, config) -> None:
    """
    Register middleware in reverse order — FastAPI wraps middleware
    so the last added is the outermost (first to handle requests).
    We want: CORS → Security Headers → Logging → Auth (innermost)

    Add in reverse: Auth → Logging → Security → CORS
    """
    # 4. Auth middleware (innermost — runs last on request, first on response)
    from api.middleware.auth_middleware import AuthMiddleware
    app.add_middleware(AuthMiddleware)

    # 3. Logging middleware
    from api.middleware.logging_middleware import LoggingMiddleware
    app.add_middleware(LoggingMiddleware)

    # 2. Security headers (applied to every response)
    from api.middleware.cors_middleware import SecurityHeadersMiddleware
    app.add_middleware(SecurityHeadersMiddleware)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.security.cors_allowed_origins if config.security.cors_allowed_origins else ["http://localhost:3000", "http://localhost:3001", "http://127.0.0.1:3000", "http://127.0.0.1:3001", "http://localhost:8000"],
        allow_credentials=config.security.cors_allow_credentials,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-API-Key",
                       "X-Request-ID", "Accept"],
        max_age=config.security.cors_max_age_seconds,
    )


def _register_routes(app: FastAPI) -> None:
    """Mount all API route groups."""
    import os
    from api.routes.auth    import router as auth_router
    from api.routes.targets import router as targets_router
    from api.routes.scans   import router as scans_router
    from api.routes.reports import router as reports_router
    from api.routes.webhooks import router as webhooks_router
    from api.routes.schedule import router as schedule_router
    from api.routes.teams    import router as teams_router
    from api.routes.demo     import router as demo_router
    from api.routes.proxy    import router as proxy_router
    from api.routes.terminal import router as terminal_router
    from api.routes.settings import router as settings_router
    from api.routes.compliance import router as compliance_router
    from web.dashboard import router as web_router

    API_PREFIX = "/api/v1"

    app.include_router(auth_router,    prefix=f"{API_PREFIX}/auth",    tags=["Authentication"])
    app.include_router(targets_router, prefix=f"{API_PREFIX}/targets", tags=["Targets"])
    app.include_router(scans_router,   prefix=f"{API_PREFIX}/scans",   tags=["Scans"])
    app.include_router(reports_router, prefix=f"{API_PREFIX}/reports", tags=["Reports"])
    app.include_router(webhooks_router, prefix=f"{API_PREFIX}/webhooks", tags=["Webhooks"])
    app.include_router(schedule_router, prefix=f"{API_PREFIX}/schedules", tags=["Schedules"])
    app.include_router(teams_router,    prefix=f"{API_PREFIX}/teams",     tags=["Teams"])
    app.include_router(proxy_router,    prefix=f"{API_PREFIX}/proxy",     tags=["Proxy"])
    app.include_router(terminal_router, prefix=f"{API_PREFIX}/terminal",  tags=["Terminal"])
    app.include_router(settings_router, prefix=f"{API_PREFIX}/settings",  tags=["Settings"])
    app.include_router(compliance_router, prefix=f"{API_PREFIX}/compliance",  tags=["Compliance"])
    app.include_router(demo_router,     prefix=f"{API_PREFIX}/demo",      tags=["Demo"], include_in_schema=False)

    # Health check (no auth required — used by load balancers / monitoring)
    @app.get("/health", tags=["Health"], include_in_schema=False)
    async def health_check():
        return {
            "status": "ok",
            "version": get_config().app.version,
            "environment": get_config().app.environment,
        }

    # Static files (CSS, JS, images) - must be mounted before the catch-all
    _static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web", "static")
    if os.path.isdir(_static_dir):
        app.mount("/static", StaticFiles(directory=_static_dir), name="static")

    # Web dashboard (HTML pages — must be included after static mount)
    app.include_router(web_router, tags=["Dashboard"])


def _register_exception_handlers(app: FastAPI) -> None:
    """Register global exception handlers for clean error responses."""

    from core.scanner.scope_enforcer import ScopeViolationError
    from config.base import ConfigError

    @app.exception_handler(ScopeViolationError)
    async def scope_violation_handler(request: Request, exc: ScopeViolationError):
        logger.warning("Scope violation: %s | path=%s", exc, request.url.path)
        return JSONResponse(
            status_code=403,
            content={
                "error": "scope_violation",
                "message": "The requested target is outside the authorised scan scope.",
                "detail": str(exc),
            },
        )

    @app.exception_handler(ValueError)
    async def value_error_handler(request: Request, exc: ValueError):
        return JSONResponse(
            status_code=422,
            content={"error": "validation_error", "message": str(exc)},
        )

    @app.exception_handler(PermissionError)
    async def permission_error_handler(request: Request, exc: PermissionError):
        return JSONResponse(
            status_code=403,
            content={"error": "forbidden", "message": str(exc)},
        )

    @app.exception_handler(FileNotFoundError)
    async def not_found_handler(request: Request, exc: FileNotFoundError):
        return JSONResponse(
            status_code=404,
            content={"error": "not_found", "message": str(exc)},
        )

    @app.exception_handler(Exception)
    async def generic_handler(request: Request, exc: Exception):
        config = get_config()
        logger.exception("Unhandled exception: %s %s", request.method, request.url.path)
        # Never expose internal details in production
        detail = str(exc) if config.app.debug else "An internal error occurred."
        return JSONResponse(
            status_code=500,
            content={"error": "internal_error", "message": detail},
        )


# ── ASGI app instance ──────────────────────────────────────────────────────────
# This is the object uvicorn imports: `uvicorn api.main:app`

app = create_app()