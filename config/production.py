"""
config/production.py — Production Configuration

Strict, hardened configuration for a deployed VulnScout Pro instance.
Every security control is at maximum. Secrets come exclusively from
environment variables — nothing sensitive is hardcoded here.

Required environment variables (startup will fail without these):
  VULNSCOUT_SECRET_KEY          — 64+ char random string for JWT/CSRF signing
  VULNSCOUT_ALLOWED_HOSTS       — comma-separated list of allowed hostnames
  VULNSCOUT_CORS_ORIGINS        — comma-separated list of allowed origins
  VULNSCOUT_TLS_CERT_PATH       — path to TLS certificate file
  VULNSCOUT_TLS_KEY_PATH        — path to TLS private key file

Recommended environment variables:
  VULNSCOUT_DATA_DIR            — persistent storage path (survives deploys)
  VULNSCOUT_WORKERS             — number of uvicorn workers (default: 4)
  VULNSCOUT_TOTP_REQUIRED       — true to enforce 2FA (strongly recommended)
  VULNSCOUT_LOG_LEVEL           — INFO (default) or WARNING
  VULNSCOUT_COMPANY_NAME        — your organisation name for reports
  VULNSCOUT_COMPANY_EMAIL       — security contact email for reports
  VULNSCOUT_TIMEZONE            — e.g. Africa/Kampala (default)
  VULNSCOUT_MAX_CONCURRENT_SCANS — max parallel scans (default: 3)

Deployment checklist:
  [ ] VULNSCOUT_SECRET_KEY is a fresh 64+ char random value
  [ ] VULNSCOUT_TLS_* points to valid, non-expired certificate
  [ ] VULNSCOUT_ALLOWED_HOSTS is your actual domain(s)
  [ ] VULNSCOUT_CORS_ORIGINS is your dashboard origin only
  [ ] VULNSCOUT_TOTP_REQUIRED=true
  [ ] Data directory is on a persistent volume (not ephemeral)
  [ ] Log directory has logrotate configured
  [ ] Firewall allows only 443 inbound (redirect 80→443 at load balancer)
  [ ] systemd service file has RestrictAddressFamilies=AF_INET AF_INET6
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

from config.base import (
    AppConfig, AuthConfig, DefaultScanConfig, EAConfig, LoggingConfig,
    RateLimitConfig, ReportingConfig, SecurityConfig, ServerConfig,
    StorageConfig, BaseConfig, ConfigError, _env, _env_bool, _env_int,
    _env_list,
)


@dataclass
class ProductionAppConfig(AppConfig):
    environment:   str  = "production"
    debug:         bool = False           # IMMUTABLE — debug must be False

    def validate(self) -> None:
        super().validate()
        if self.debug:
            # Belt-and-suspenders: base validates this too, but be explicit
            raise ConfigError(
                "CRITICAL: debug=True in production configuration. "
                "This would expose stack traces and internal state to attackers."
            )


@dataclass
class ProductionServerConfig(ServerConfig):
    host:         str  = field(default_factory=lambda: _env("HOST", "0.0.0.0"))
    port:         int  = field(default_factory=lambda: _env_int("PORT", 8000))
    workers:      int  = field(default_factory=lambda: _env_int("WORKERS", 4))
    reload:       bool = False            # IMMUTABLE — never reload in production
    tls_enabled:  bool = field(
        default_factory=lambda: _env_bool("TLS_ENABLED", True)
    )
    # TLS termination can be at the load balancer; if so, set BEHIND_PROXY=true
    # and TLS_ENABLED=false (TLS handled upstream)
    behind_proxy: bool = field(
        default_factory=lambda: _env_bool("BEHIND_PROXY", False)
    )
    trusted_proxy_ips: List[str] = field(
        default_factory=lambda: _env_list("TRUSTED_PROXY_IPS", ["127.0.0.1"])
    )

    # Tighter timeouts in production
    request_timeout_seconds:    int = 25
    keep_alive_timeout_seconds: int = 3


@dataclass
class ProductionStorageConfig(StorageConfig):
    data_dir: str = field(
        default_factory=lambda: _env(
            "DATA_DIR",
            "/var/lib/vulnscout"    # Standard Linux service data path
        )
    )
    # Retain data longer in production — compliance requirements
    scan_retention_days:    int = field(
        default_factory=lambda: _env_int("SCAN_RETENTION_DAYS", 90)
    )
    report_retention_days:  int = field(
        default_factory=lambda: _env_int("REPORT_RETENTION_DAYS", 365)
    )
    session_retention_days: int = field(
        default_factory=lambda: _env_int("SESSION_RETENTION_DAYS", 30)
    )
    # Strict permissions in production
    dir_permissions:  int = 0o750
    file_permissions: int = 0o640


@dataclass
class ProductionAuthConfig(AuthConfig):
    """
    Maximum authentication security for production.
    2FA strongly encouraged; session cookies are HTTPS-only with Strict SameSite.
    """
    jwt_access_expire_min:    int  = field(
        default_factory=lambda: _env_int("JWT_ACCESS_EXPIRE_MIN", 15)
    )
    jwt_refresh_expire_days:  int  = field(
        default_factory=lambda: _env_int("JWT_REFRESH_EXPIRE_DAYS", 7)
    )
    session_expire_minutes:   int  = field(
        default_factory=lambda: _env_int("SESSION_EXPIRE_MIN", 30)
    )
    session_cookie_secure:    bool = True      # HTTPS only — immutable in production
    session_cookie_httponly:  bool = True      # No JS access — immutable
    session_cookie_samesite:  str  = "Strict"  # CSRF protection — immutable
    totp_required:            bool = field(
        default_factory=lambda: _env_bool("TOTP_REQUIRED", True)
    )
    max_login_attempts:       int  = 5
    lockout_duration_min:     int  = 15
    lockout_progressive:      bool = True
    # Stronger password requirements in production
    min_password_length:      int  = 14
    password_history:         int  = 10


@dataclass
class ProductionScanConfig(DefaultScanConfig):
    """
    Conservative, polite scan defaults for production.
    Operators can override per-scan but these are safe baselines.
    """
    crawl_depth:              int   = 3
    max_pages:                int   = 150
    rate_limit_rps:           float = 3.0
    rate_limit_burst:         int   = 8
    max_concurrent_detectors: int   = 5
    max_concurrent_scans:     int   = field(
        default_factory=lambda: _env_int("MAX_CONCURRENT_SCANS", 3)
    )
    respect_robots_txt:       bool  = True
    include_ea_context:       bool  = True


@dataclass
class ProductionRateLimitConfig(RateLimitConfig):
    """
    Strict API rate limits in production.
    Protect against scan submission abuse and report generation storms.
    """
    api_requests_per_minute:   int = 60
    api_requests_per_hour:     int = 1_000
    api_requests_per_day:      int = 10_000
    ip_requests_per_minute:    int = 20
    ip_requests_per_hour:      int = 200
    scans_per_user_per_day:    int = field(
        default_factory=lambda: _env_int("SCANS_PER_USER_PER_DAY", 10)
    )
    scans_per_user_per_hour:   int = 3
    reports_per_user_per_hour: int = 20


@dataclass
class ProductionLoggingConfig(LoggingConfig):
    """
    Structured JSON logging for production — machine-parseable by log aggregators.
    Sensitive values always redacted.
    """
    level:             str  = field(
        default_factory=lambda: _env("LOG_LEVEL", "INFO").upper()
    )
    format:            str  = "json"       # JSON for log aggregators (ELK, Loki, etc.)
    redact_sensitive:  bool = True         # Always redact in production
    audit_log_enabled: bool = True         # Security-critical audit trail
    max_bytes:         int  = 52_428_800   # 50 MB
    backup_count:      int  = 10


@dataclass
class ProductionSecurityConfig(SecurityConfig):
    """
    Maximum security headers and strict CORS for production.
    CORS origins MUST be explicitly configured — no wildcards.
    """
    cors_allowed_origins: List[str] = field(
        default_factory=lambda: _env_list("CORS_ORIGINS", [])
    )
    cors_allow_credentials: bool = True
    # Strict CSP for production — no unsafe-inline except trusted styles
    csp_directives: Dict[str, str] = field(default_factory=lambda: {
        "default-src":      "'self'",
        "script-src":       "'self'",
        "style-src":        "'self'",
        "img-src":          "'self' data:",
        "connect-src":      "'self'",
        "font-src":         "'self'",
        "frame-src":        "'none'",
        "object-src":       "'none'",
        "base-uri":         "'self'",
        "form-action":      "'self'",
        "upgrade-insecure-requests": "",   # Force HTTPS sub-resources
    })
    hsts_enabled:          bool = True
    hsts_max_age_seconds:  int  = 31_536_000   # 1 year
    hsts_include_subdomains: bool = True
    hsts_preload:          bool = False         # Set True only after preload submission
    x_frame_options:       str  = "DENY"        # No framing at all
    x_content_type_options: str = "nosniff"
    referrer_policy:       str  = "strict-origin-when-cross-origin"
    permissions_policy:    str  = "geolocation=(), microphone=(), camera=()"

    def validate(self, environment: str) -> None:
        super().validate(environment)
        if not self.cors_allowed_origins:
            raise ConfigError(
                "VULNSCOUT_CORS_ORIGINS must be set in production. "
                "Example: VULNSCOUT_CORS_ORIGINS=https://vulnscout.yourdomain.com"
            )
        for origin in self.cors_allowed_origins:
            if not origin.startswith("https://"):
                raise ConfigError(
                    f"All CORS origins must use HTTPS in production. "
                    f"Found: {origin!r}"
                )


@dataclass
class ProductionEAConfig(EAConfig):
    """All EA features enabled in production."""
    ea_context_enabled:        bool = True
    ussd_detection_enabled:    bool = True
    mtn_momo_checks:           bool = True
    airtel_money_checks:       bool = True
    local_framework_detection: bool = True
    regulatory_mapping:        bool = True

    company_name:    str = field(
        default_factory=lambda: _env("COMPANY_NAME", "VulnScout Pro")
    )
    company_address: str = field(
        default_factory=lambda: _env("COMPANY_ADDRESS", "Kampala, Uganda")
    )
    company_email:   str = field(
        default_factory=lambda: _env("COMPANY_EMAIL", "")
    )
    timezone: str = field(
        default_factory=lambda: _env("TIMEZONE", "Africa/Kampala")
    )


@dataclass
class ProductionReportingConfig(ReportingConfig):
    watermark_draft:        bool = False   # No DRAFT watermark on real reports
    watermark_confidential: bool = True    # Always mark as CONFIDENTIAL
    default_prepared_by:    str  = field(
        default_factory=lambda: _env(
            "REPORT_PREPARED_BY", "VulnScout Pro Automated Scanner"
        )
    )


@dataclass
class ProductionConfig(BaseConfig):
    """
    Complete production configuration.

    Usage:
        from config.production import ProductionConfig
        config = ProductionConfig().validate()

    Or via the environment loader:
        VULNSCOUT_ENV=production
    """
    app:        ProductionAppConfig        = field(default_factory=ProductionAppConfig)
    server:     ProductionServerConfig     = field(default_factory=ProductionServerConfig)
    storage:    ProductionStorageConfig    = field(default_factory=ProductionStorageConfig)
    auth:       ProductionAuthConfig       = field(default_factory=ProductionAuthConfig)
    scan:       ProductionScanConfig       = field(default_factory=ProductionScanConfig)
    rate_limit: ProductionRateLimitConfig  = field(default_factory=ProductionRateLimitConfig)
    logging:    ProductionLoggingConfig    = field(default_factory=ProductionLoggingConfig)
    security:   ProductionSecurityConfig   = field(default_factory=ProductionSecurityConfig)
    ea:         ProductionEAConfig         = field(default_factory=ProductionEAConfig)
    reporting:  ProductionReportingConfig  = field(default_factory=ProductionReportingConfig)

    def validate(self) -> "ProductionConfig":
        super().validate()
        self._check_critical_env_vars()
        return self

    def _check_critical_env_vars(self) -> None:
        """
        Fail loudly if required production secrets are missing.
        The application should not start without these.
        """
        required = {
            "SECRET_KEY":   "JWT signing key (generate: python -c \"import secrets; print(secrets.token_urlsafe(64))\")",
            "ALLOWED_HOSTS": "Comma-separated list of allowed hostnames",
        }
        missing = []
        for key, hint in required.items():
            if not _env(key):
                missing.append(f"  VULNSCOUT_{key}: {hint}")

        # TLS required unless terminating at proxy
        if not self.server.behind_proxy:
            if not _env("TLS_CERT_PATH"):
                missing.append(
                    "  VULNSCOUT_TLS_CERT_PATH: Path to TLS certificate "
                    "(or set VULNSCOUT_BEHIND_PROXY=true if TLS terminates at load balancer)"
                )
            if not _env("TLS_KEY_PATH"):
                missing.append("  VULNSCOUT_TLS_KEY_PATH: Path to TLS private key")

        if missing:
            raise ConfigError(
                "Missing required production environment variables:\n"
                + "\n".join(missing)
                + "\n\nSee docs/deployment_guide.md for setup instructions."
            )

    def startup_checks(self) -> List[str]:
        """
        Return list of warnings about suboptimal (but non-fatal) production config.
        Logged as warnings at application startup.
        """
        warnings = []
        if not self.auth.totp_required:
            warnings.append(
                "2FA is not required (VULNSCOUT_TOTP_REQUIRED=false). "
                "Strongly recommended for a security tool handling client data."
            )
        if not self.ea.company_email:
            warnings.append(
                "VULNSCOUT_COMPANY_EMAIL not set — "
                "security contact will be blank in compliance reports."
            )
        if self.auth.jwt_access_expire_min > 60:
            warnings.append(
                f"JWT access token lifetime is {self.auth.jwt_access_expire_min} min. "
                "Consider ≤30 min for a security tool."
            )
        return warnings