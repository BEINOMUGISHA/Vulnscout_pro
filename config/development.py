"""
config/development.py — Development Configuration

Overrides for local development. Prioritises:
  - Fast feedback (auto-reload, verbose logging, relaxed limits)
  - Debugging visibility (debug mode, stack traces, no TLS requirement)
  - Permissive security (no 2FA, wildcard CORS, any host)
  - Conservative scanning (low rate limits to avoid hitting live dev targets)

NEVER import this in production. The production loader rejects this config
if VULNSCOUT_ENV=production.

Typical usage:
  VULNSCOUT_ENV=development uvicorn api.main:app --reload
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from config.base import (
    AppConfig, AuthConfig, DefaultScanConfig, EAConfig, LoggingConfig,
    RateLimitConfig, ReportingConfig, SecurityConfig, ServerConfig,
    StorageConfig, BaseConfig,
)


@dataclass
class DevelopmentAppConfig(AppConfig):
    environment:   str  = "development"
    debug:         bool = True
    allowed_hosts: List[str] = field(default_factory=lambda: ["*"])


@dataclass
class DevelopmentServerConfig(ServerConfig):
    host:    str  = "127.0.0.1"   # Local only — never bind 0.0.0.0 in dev
    port:    int  = 8000
    workers: int  = 1              # Single worker for easy debugging
    reload:  bool = True           # Auto-reload on code changes
    # TLS explicitly disabled in dev — use HTTP locally
    tls_enabled: bool = False


@dataclass
class DevelopmentStorageConfig(StorageConfig):
    """Store dev data in a local .dev/ directory — excluded from git."""
    data_dir: str = field(
        default_factory=lambda: str(
            __import__("pathlib").Path(__file__).parent.parent / ".dev" / "data"
        )
    )
    # Short retention in dev — don't accumulate test data
    scan_retention_days:    int = 7
    report_retention_days:  int = 14
    session_retention_days: int = 1
    # Permissive file permissions in dev
    dir_permissions:  int = 0o755
    file_permissions: int = 0o644


@dataclass
class DevelopmentAuthConfig(AuthConfig):
    """
    Relaxed auth for development.
    Short token lifetimes make session behaviour easy to test.
    """
    jwt_access_expire_min:   int  = 60 * 8    # 8 hours — survive a work day
    jwt_refresh_expire_days: int  = 1
    session_expire_minutes:  int  = 480
    session_cookie_secure:   bool = False      # HTTP cookies in dev
    totp_required:           bool = False      # No 2FA in dev
    max_login_attempts:      int  = 100        # Don't lock yourself out
    lockout_duration_min:    int  = 1


@dataclass
class DevelopmentScanConfig(DefaultScanConfig):
    """
    Conservative scan defaults for development.
    Prevents accidentally hammering local or staging targets.
    """
    crawl_depth:              int   = 2
    max_pages:                int   = 30
    rate_limit_rps:           float = 2.0     # Slow — protect local dev servers
    rate_limit_burst:         int   = 5
    max_concurrent_detectors: int   = 3
    max_concurrent_scans:     int   = 2
    include_ea_context:       bool  = True

    # Run all detectors in dev so everything gets exercised
    enabled_checks: List[str] = field(default_factory=lambda: [
        "sqli", "xss", "xxe", "ssrf", "idor",
        "auth_bypass", "misconfig", "sensitive_data",
    ])


@dataclass
class DevelopmentRateLimitConfig(RateLimitConfig):
    """Very high limits in dev — don't interrupt testing."""
    api_requests_per_minute:   int = 600
    api_requests_per_hour:     int = 10_000
    ip_requests_per_minute:    int = 600
    scans_per_user_per_day:    int = 100
    scans_per_user_per_hour:   int = 50


@dataclass
class DevelopmentLoggingConfig(LoggingConfig):
    """Verbose human-readable logs in development."""
    level:              str  = "DEBUG"
    format:             str  = "text"          # Human-readable, not JSON
    redact_sensitive:   bool = False           # Show full values in dev logs
    audit_log_enabled:  bool = False           # Skip audit log overhead in dev


@dataclass
class DevelopmentSecurityConfig(SecurityConfig):
    """Permissive security headers in dev — don't fight the browser."""
    cors_allowed_origins: List[str] = field(default_factory=lambda: [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:8001",
    ])
    hsts_enabled:   bool = False   # No HSTS on HTTP
    csp_enabled:    bool = False   # Disable CSP in dev — don't block hot reloads
    x_frame_options: str = "SAMEORIGIN"   # Allow framing in dev tools


@dataclass
class DevelopmentEAConfig(EAConfig):
    """All EA features enabled in dev — exercise full code paths."""
    ea_context_enabled:        bool = True
    ussd_detection_enabled:    bool = True
    mtn_momo_checks:           bool = True
    airtel_money_checks:       bool = True
    local_framework_detection: bool = True
    regulatory_mapping:        bool = True
    # Use a test company name in dev reports
    company_name:              str  = "VulnScout Pro [DEV]"


@dataclass
class DevelopmentReportingConfig(ReportingConfig):
    watermark_draft:        bool = True    # Always watermark dev reports
    watermark_confidential: bool = False   # Skip confidential mark on test reports
    default_prepared_by:    str  = "VulnScout Dev Instance"


@dataclass
class DevelopmentConfig(BaseConfig):
    """
    Complete development configuration.

    Usage:
        from config.development import DevelopmentConfig
        config = DevelopmentConfig().validate()
    """
    app:        DevelopmentAppConfig        = field(default_factory=DevelopmentAppConfig)
    server:     DevelopmentServerConfig     = field(default_factory=DevelopmentServerConfig)
    storage:    DevelopmentStorageConfig    = field(default_factory=DevelopmentStorageConfig)
    auth:       DevelopmentAuthConfig       = field(default_factory=DevelopmentAuthConfig)
    scan:       DevelopmentScanConfig       = field(default_factory=DevelopmentScanConfig)
    rate_limit: DevelopmentRateLimitConfig  = field(default_factory=DevelopmentRateLimitConfig)
    logging:    DevelopmentLoggingConfig    = field(default_factory=DevelopmentLoggingConfig)
    security:   DevelopmentSecurityConfig   = field(default_factory=DevelopmentSecurityConfig)
    ea:         DevelopmentEAConfig         = field(default_factory=DevelopmentEAConfig)
    reporting:  DevelopmentReportingConfig  = field(default_factory=DevelopmentReportingConfig)

    def quick_start_banner(self) -> str:
        """Print a helpful startup banner in development mode."""
        return (
            "\n"
            "╔══════════════════════════════════════════════════════╗\n"
            "║         VulnScout Pro — Development Mode             ║\n"
            "╠══════════════════════════════════════════════════════╣\n"
            f"║  API:        http://{self.server.host}:{self.server.port}/api/v1       ║\n"
            f"║  Dashboard:  http://{self.server.host}:{self.server.port}/             ║\n"
            f"║  API Docs:   http://{self.server.host}:{self.server.port}/docs         ║\n"
            f"║  Data dir:   {self.storage.data_dir[:40]:<40}  ║\n"
            "╠══════════════════════════════════════════════════════╣\n"
            "║  ⚠  DEBUG MODE — Do not expose to internet          ║\n"
            "║  ⚠  TLS disabled — HTTP only                        ║\n"
            "║  ⚠  2FA not required                                ║\n"
            "╚══════════════════════════════════════════════════════╝\n"
        )