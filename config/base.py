"""
config/base.py — Base Configuration

All configuration lives here as typed dataclasses with explicit defaults,
validation, and documentation. Environment-specific configs (dev/prod/testing)
inherit from these and override only what differs.

Design principles:
  - Every setting is typed and documented inline
  - Secrets are NEVER set here — they come from environment variables only
  - validate() raises ConfigError with a clear message on bad values
  - All paths are resolved relative to PROJECT_ROOT at load time
  - Sensitive fields are masked in to_dict() / __repr__
  - EA-specific defaults are conservative for production safety

Configuration hierarchy:
  BaseConfig
    ├── AppConfig         — application metadata, env name, debug flag
    ├── ServerConfig      — host, port, workers, HTTPS
    ├── StorageConfig     — file paths for scan/report/session stores
    ├── ScanConfig        — default scan parameters (mirrors core/models/target.py)
    ├── AuthConfig        — JWT settings, session lifetime, 2FA
    ├── RateLimitConfig   — API and scanner rate limits
    ├── LoggingConfig     — log level, format, rotation
    ├── SecurityConfig    — CORS, CSP, allowed hosts
    └── EAConfig          — East Africa-specific feature flags and settings

Environment variables take precedence over all file-based config.
Naming convention: VULNSCOUT_<SECTION>_<KEY>  e.g. VULNSCOUT_DB_PASSWORD
"""

from __future__ import annotations

import os
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


# ── Project root ───────────────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent.parent


# ── Exceptions ─────────────────────────────────────────────────────────────────

class ConfigError(Exception):
    """Raised when configuration validation fails."""


# ── Helpers ────────────────────────────────────────────────────────────────────

def _env(key: str, default: str = "") -> str:
    """Read an environment variable with VULNSCOUT_ prefix."""
    return os.environ.get(f"VULNSCOUT_{key}", default)


def _env_int(key: str, default: int) -> int:
    raw = _env(key)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        raise ConfigError(f"VULNSCOUT_{key} must be an integer, got: {raw!r}")


def _env_bool(key: str, default: bool) -> bool:
    raw = _env(key, "").lower()
    if not raw:
        return default
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"VULNSCOUT_{key} must be a boolean value, got: {raw!r}")


def _env_list(key: str, default: List[str]) -> List[str]:
    raw = _env(key)
    if not raw:
        return default
    return [s.strip() for s in raw.split(",") if s.strip()]


def _mask(value: str) -> str:
    """Mask a secret for safe display."""
    if not value:
        return "(not set)"
    if len(value) <= 8:
        return "****"
    return value[:4] + "****" + value[-2:]


# ── App config ─────────────────────────────────────────────────────────────────

@dataclass
class AppConfig:
    """Core application metadata and runtime mode."""

    environment: str = "development"       # development | production | testing
    debug: bool = False                    # NEVER True in production
    version: str = "1.0.0"
    app_name: str = "VulnScout Pro"
    app_description: str = (
        "Professional Web Vulnerability Scanner for Uganda & East Africa"
    )

    # Secret key for JWT signing and CSRF protection
    # MUST be set via VULNSCOUT_SECRET_KEY in production
    secret_key: str = field(
        default_factory=lambda: _env("SECRET_KEY", secrets.token_urlsafe(64))
    )

    # Allowed hosts (prevents Host header injection)
    # Populated with * in dev; must be explicit in production
    allowed_hosts: List[str] = field(
        default_factory=lambda: _env_list("ALLOWED_HOSTS", ["*"])
    )

    def validate(self) -> None:
        if self.environment not in ("development", "production", "testing"):
            raise ConfigError(
                f"Invalid environment: {self.environment!r}. "
                "Must be development, production, or testing."
            )
        if self.environment == "production":
            if self.debug:
                raise ConfigError("debug must be False in production.")
            if not _env("SECRET_KEY"):
                raise ConfigError(
                    "VULNSCOUT_SECRET_KEY must be set in production. "
                    "Generate with: python -c \"import secrets; print(secrets.token_urlsafe(64))\""
                )
            if "*" in self.allowed_hosts:
                raise ConfigError(
                    "VULNSCOUT_ALLOWED_HOSTS must not contain '*' in production."
                )

    def to_dict(self) -> Dict:
        return {
            "environment": self.environment,
            "debug": self.debug,
            "version": self.version,
            "app_name": self.app_name,
            "secret_key": _mask(self.secret_key),
            "allowed_hosts": self.allowed_hosts,
        }


# ── Server config ──────────────────────────────────────────────────────────────

@dataclass
class ServerConfig:
    """HTTP server binding and TLS settings."""

    host: str = field(default_factory=lambda: _env("HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: _env_int("PORT", 8000))
    workers: int = field(default_factory=lambda: _env_int("WORKERS", 4))
    reload: bool = False                   # uvicorn --reload, dev only

    # TLS (required in production for payment endpoints)
    tls_enabled: bool = field(
        default_factory=lambda: _env_bool("TLS_ENABLED", False)
    )
    tls_cert_path: str = field(
        default_factory=lambda: _env("TLS_CERT_PATH", "")
    )
    tls_key_path: str = field(
        default_factory=lambda: _env("TLS_KEY_PATH", "")
    )

    # Timeouts
    request_timeout_seconds: int = 30
    keep_alive_timeout_seconds: int = 5

    # Proxy settings (for deployments behind nginx/Caddy)
    behind_proxy: bool = field(
        default_factory=lambda: _env_bool("BEHIND_PROXY", False)
    )
    trusted_proxy_ips: List[str] = field(
        default_factory=lambda: _env_list("TRUSTED_PROXY_IPS", ["127.0.0.1"])
    )

    def validate(self, environment: str) -> None:
        if not (1 <= self.port <= 65535):
            raise ConfigError(f"Invalid port: {self.port}. Must be 1–65535.")
        if self.workers < 1:
            raise ConfigError(f"Workers must be ≥ 1, got {self.workers}.")
        if environment == "production":
            if not self.tls_enabled:
                raise ConfigError(
                    "TLS must be enabled in production (VULNSCOUT_TLS_ENABLED=true). "
                    "VulnScout Pro handles payment data and security findings — "
                    "plaintext HTTP is prohibited."
                )
            if self.tls_enabled and not self.tls_cert_path:
                raise ConfigError(
                    "VULNSCOUT_TLS_CERT_PATH must be set when TLS is enabled."
                )
            if self.tls_enabled and not self.tls_key_path:
                raise ConfigError(
                    "VULNSCOUT_TLS_KEY_PATH must be set when TLS is enabled."
                )

    def to_dict(self) -> Dict:
        return {
            "host": self.host,
            "port": self.port,
            "workers": self.workers,
            "tls_enabled": self.tls_enabled,
            "behind_proxy": self.behind_proxy,
        }


# ── Storage config ─────────────────────────────────────────────────────────────

@dataclass
class StorageConfig:
    """
    Flat-file JSON storage paths.
    All paths resolve relative to PROJECT_ROOT unless absolute.
    """

    # Root data directory
    data_dir: str = field(
        default_factory=lambda: _env(
            "DATA_DIR", str(PROJECT_ROOT / "data")
        )
    )

    # Subdirectories (relative to data_dir)
    scans_dir:    str = "scans"
    reports_dir:  str = "reports"
    sessions_dir: str = "sessions"
    logs_dir:     str = "logs"
    exports_dir:  str = "exports"
    uploads_dir:  str = "uploads"     # Temporary storage for file uploads

    # Retention policies (days; 0 = keep forever)
    scan_retention_days:    int = field(
        default_factory=lambda: _env_int("SCAN_RETENTION_DAYS", 90)
    )
    report_retention_days:  int = field(
        default_factory=lambda: _env_int("REPORT_RETENTION_DAYS", 365)
    )
    session_retention_days: int = field(
        default_factory=lambda: _env_int("SESSION_RETENTION_DAYS", 30)
    )
    upload_retention_hours: int = 24   # Uploaded files cleaned after 24h

    # Data Encryption (Disabled)
    encryption_enabled: bool = False
    master_key:         str  = ""

    # File permissions (octal)
    dir_permissions:  int = 0o750      # Owner+group read/execute; no world access
    file_permissions: int = 0o640      # Owner read/write; group read

    def resolve(self) -> "StorageConfig":
        """Resolve all paths relative to PROJECT_ROOT."""
        base = Path(self.data_dir)
        if not base.is_absolute():
            base = PROJECT_ROOT / base
        self.data_dir = str(base)
        return self

    def path(self, subdir: str) -> Path:
        """Return absolute Path for a storage subdirectory."""
        return Path(self.data_dir) / subdir

    @property
    def scans_path(self) -> Path:
        return self.path(self.scans_dir)

    @property
    def reports_path(self) -> Path:
        return self.path(self.reports_dir)

    @property
    def sessions_path(self) -> Path:
        return self.path(self.sessions_dir)

    @property
    def exports_path(self) -> Path:
        return self.path(self.exports_dir)

    @property
    def uploads_path(self) -> Path:
        return self.path(self.uploads_dir)

    def create_dirs(self) -> None:
        """Create all required storage directories with correct permissions."""
        for subdir in (
            self.scans_dir, self.reports_dir, self.sessions_dir,
            self.logs_dir, self.exports_dir, self.uploads_dir,
        ):
            p = self.path(subdir)
            p.mkdir(parents=True, exist_ok=True)
            try:
                p.chmod(self.dir_permissions)
            except OSError:
                pass   # chmod may fail on some filesystems (NTFS, Docker volumes)

    def validate(self) -> None:
        base = Path(self.data_dir)
        if base.exists() and not base.is_dir():
            raise ConfigError(f"data_dir is not a directory: {self.data_dir}")
        if self.scan_retention_days < 0:
            raise ConfigError("scan_retention_days must be ≥ 0")

    def to_dict(self) -> Dict:
        return {
            "data_dir": self.data_dir,
            "scan_retention_days": self.scan_retention_days,
            "report_retention_days": self.report_retention_days,
        }


# ── Auth config ────────────────────────────────────────────────────────────────

@dataclass
class AuthConfig:
    """
    Authentication and session security settings.
    VulnScout Pro requires 2FA for all accounts in production.
    """

    # JWT settings
    jwt_algorithm:         str = "HS256"
    jwt_access_expire_min: int = field(
        default_factory=lambda: _env_int("JWT_ACCESS_EXPIRE_MIN", 30)
    )
    jwt_refresh_expire_days: int = field(
        default_factory=lambda: _env_int("JWT_REFRESH_EXPIRE_DAYS", 7)
    )

    # Session settings
    session_expire_minutes: int = field(
        default_factory=lambda: _env_int("SESSION_EXPIRE_MIN", 60)
    )
    session_cookie_name:    str = "vulnscout_session"
    session_cookie_secure:  bool = True      # HTTPS only
    session_cookie_httponly: bool = True     # No JS access
    session_cookie_samesite: str = "Strict"  # CSRF protection

    # 2FA (TOTP)
    totp_required:          bool = field(
        default_factory=lambda: _env_bool("TOTP_REQUIRED", False)
    )
    totp_issuer:            str = "VulnScout Pro"
    totp_window:            int = 1          # Clock drift tolerance (±30s windows)

    # Password policy
    min_password_length:    int = 12
    require_uppercase:      bool = True
    require_lowercase:      bool = True
    require_digits:         bool = True
    require_special:        bool = True
    password_history:       int = 5          # Prevent reuse of last N passwords

    # Brute-force protection
    max_login_attempts:     int = 5
    lockout_duration_min:   int = 15
    lockout_progressive:    bool = True      # Double lockout time on repeat failures

    # API key settings
    api_key_length:         int = 48
    api_key_prefix:         str = "vsp_"    # VulnScout Pro prefix for key identification

    # Google OAuth
    google_client_id:       str = field(default_factory=lambda: _env("GOOGLE_CLIENT_ID", ""))
    google_client_secret:   str = field(default_factory=lambda: _env("GOOGLE_CLIENT_SECRET", ""))
    google_enabled:         bool = field(default_factory=lambda: _env_bool("GOOGLE_ENABLED", False))

    # Registration
    open_registration:      bool = field(default_factory=lambda: _env_bool("OPEN_REGISTRATION", True))

    def validate(self, environment: str) -> None:
        if self.jwt_algorithm not in ("HS256", "HS384", "HS512", "RS256"):
            raise ConfigError(f"Invalid JWT algorithm: {self.jwt_algorithm!r}")
        if self.jwt_access_expire_min < 1:
            raise ConfigError("jwt_access_expire_min must be ≥ 1")
        if self.min_password_length < 8:
            raise ConfigError("min_password_length must be ≥ 8")
        if environment == "production" and not self.totp_required:
            import warnings
            warnings.warn(
                "TOTP_REQUIRED is False in production. "
                "VulnScout Pro handles security findings — 2FA is strongly recommended. "
                "Set VULNSCOUT_TOTP_REQUIRED=true to enforce.",
                stacklevel=3,
            )
        if self.session_cookie_samesite not in ("Strict", "Lax", "None"):
            raise ConfigError(
                f"Invalid session_cookie_samesite: {self.session_cookie_samesite!r}"
            )

    def to_dict(self) -> Dict:
        return {
            "jwt_algorithm": self.jwt_algorithm,
            "jwt_access_expire_min": self.jwt_access_expire_min,
            "totp_required": self.totp_required,
            "session_cookie_secure": self.session_cookie_secure,
            "session_cookie_httponly": self.session_cookie_httponly,
            "min_password_length": self.min_password_length,
            "max_login_attempts": self.max_login_attempts,
            "lockout_duration_min": self.lockout_duration_min,
        }


# ── Scan defaults ──────────────────────────────────────────────────────────────

@dataclass
class DefaultScanConfig:
    """
    Default scan parameters applied to every new scan unless overridden.
    These map 1:1 to core/models/target.ScanConfig.
    """

    crawl_depth:               int = 3
    max_pages:                 int = 150
    rate_limit_rps:            float = 3.0     # Requests per second
    rate_limit_burst:          int = 8
    request_timeout_seconds:   int = 15
    max_concurrent_detectors:  int = 5
    max_concurrent_scans:      int = field(
        default_factory=lambda: _env_int("MAX_CONCURRENT_SCANS", 3)
    )
    respect_robots_txt:        bool = True
    include_ea_context:        bool = True     # Uganda/EA specific checks enabled
    allow_all_targets:         bool = field(
        default_factory=lambda: _env_bool("SCAN_ALLOW_ALL_TARGETS", False)
    )
    high_concurrency:          bool = field(
        default_factory=lambda: _env_bool("SCAN_HIGH_CONCURRENCY", False)
    )
    unthrottled:               bool = field(
        default_factory=lambda: _env_bool("SCAN_UNTHROTTLED", False)
    )

    # Detection modules enabled by default
    enabled_checks: List[str] = field(default_factory=lambda: [
        "sqli", "xss", "xxe", "ssrf", "idor",
        "auth_bypass", "misconfig", "sensitive_data",
    ])

    # Hard limits (cannot be overridden by user)
    max_crawl_depth_absolute:  int = 10
    max_pages_absolute:        int = 1000
    max_rps_absolute:          float = 20.0
    max_payload_size_bytes:    int = 8192
    max_response_size_bytes:   int = 5_242_880   # 5 MB

    # User agent string — identifies VulnScout to target admins
    user_agent: str = (
        "VulnScout-Pro/1.0 (Authorised Security Scanner; "
        "+https://vulnscout.ug/scanner-info)"
    )

    def validate(self) -> None:
        if self.crawl_depth < 1 or self.crawl_depth > self.max_crawl_depth_absolute:
            raise ConfigError(
                f"crawl_depth must be 1–{self.max_crawl_depth_absolute}"
            )
        if self.rate_limit_rps <= 0 or self.rate_limit_rps > self.max_rps_absolute:
            raise ConfigError(
                f"rate_limit_rps must be 0–{self.max_rps_absolute}"
            )
        if self.max_concurrent_scans < 1:
            raise ConfigError("max_concurrent_scans must be ≥ 1")
        unknown = set(self.enabled_checks) - {
            "sqli", "xss", "xxe", "ssrf", "idor",
            "auth_bypass", "misconfig", "sensitive_data",
        }
        if unknown:
            raise ConfigError(f"Unknown detection modules: {unknown}")

    def to_dict(self) -> Dict:
        return {
            "crawl_depth": self.crawl_depth,
            "max_pages": self.max_pages,
            "rate_limit_rps": self.rate_limit_rps,
            "max_concurrent_scans": self.max_concurrent_scans,
            "include_ea_context": self.include_ea_context,
            "enabled_checks": self.enabled_checks,
            "user_agent": self.user_agent,
        }


# ── Rate limit config ──────────────────────────────────────────────────────────

@dataclass
class RateLimitConfig:
    """
    API-level rate limiting (distinct from scan-level rate limiting).
    Protects the VulnScout API from abuse.
    Uses sliding window counters stored in session store.
    """

    # Per-user API limits
    api_requests_per_minute:    int = 60
    api_requests_per_hour:      int = 1000
    api_requests_per_day:       int = 10_000

    # Per-IP limits (unauthenticated)
    ip_requests_per_minute:     int = 20
    ip_requests_per_hour:       int = 200

    # Scan submission limits
    scans_per_user_per_day:     int = field(
        default_factory=lambda: _env_int("SCANS_PER_USER_PER_DAY", 10)
    )
    scans_per_user_per_hour:    int = 3

    # Report generation limits
    reports_per_user_per_hour:  int = 20

    # Rate limit response
    rate_limit_header:          bool = True    # Include X-RateLimit-* headers
    rate_limit_retry_after:     bool = True    # Include Retry-After header

    def to_dict(self) -> Dict:
        return {
            "api_requests_per_minute": self.api_requests_per_minute,
            "api_requests_per_hour":   self.api_requests_per_hour,
            "scans_per_user_per_day":  self.scans_per_user_per_day,
        }


# ── Logging config ─────────────────────────────────────────────────────────────

@dataclass
class LoggingConfig:
    """Structured logging configuration."""

    level: str = field(
        default_factory=lambda: _env("LOG_LEVEL", "INFO").upper()
    )
    format: str = "json"           # json | text
    include_request_id: bool = True
    include_user_id: bool = True
    include_scan_id: bool = True
    redact_sensitive: bool = True   # Mask API keys, tokens in log lines

    # Log rotation
    max_bytes:      int = 10_485_760   # 10 MB
    backup_count:   int = 5

    # Audit log — separate file for security-relevant events
    audit_log_enabled: bool = True
    audit_log_file:    str = "audit.log"

    # Events that always appear in audit log regardless of log level
    audit_events: List[str] = field(default_factory=lambda: [
        "user.login", "user.logout", "user.login_failed",
        "scan.started", "scan.completed", "scan.cancelled",
        "report.generated", "report.downloaded",
        "scope.violation", "api_key.created", "api_key.revoked",
        "user.created", "user.deleted", "user.password_changed",
        "totp.enrolled", "totp.verified_failed",
    ])

    def validate(self) -> None:
        valid_levels = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
        if self.level not in valid_levels:
            raise ConfigError(
                f"Invalid log level: {self.level!r}. "
                f"Must be one of: {valid_levels}"
            )
        if self.format not in ("json", "text"):
            raise ConfigError(f"log format must be 'json' or 'text'")

    def to_dict(self) -> Dict:
        return {
            "level": self.level,
            "format": self.format,
            "redact_sensitive": self.redact_sensitive,
            "audit_log_enabled": self.audit_log_enabled,
        }


# ── Security config ────────────────────────────────────────────────────────────

@dataclass
class SecurityConfig:
    """
    HTTP security settings — CORS, CSP, security headers.
    These are applied by the API middleware layer.
    """

    # CORS
    cors_enabled:          bool = True
    cors_allowed_origins:  List[str] = field(
        default_factory=lambda: _env_list("CORS_ORIGINS", [])
    )
    cors_allow_credentials: bool = True
    cors_max_age_seconds:  int = 3600

    # Content Security Policy
    csp_enabled: bool = True
    csp_directives: Dict[str, str] = field(default_factory=lambda: {
        "default-src":  "'self'",
        "script-src":   "'self'",
        "style-src":    "'self' 'unsafe-inline'",   # Allow inline styles for dashboard
        "img-src":      "'self' data:",
        "connect-src":  "'self'",
        "font-src":     "'self'",
        "frame-src":    "'none'",
        "object-src":   "'none'",
        "base-uri":     "'self'",
        "form-action":  "'self'",
    })

    # Security response headers
    hsts_enabled:          bool = True
    hsts_max_age_seconds:  int = 31_536_000    # 1 year
    hsts_include_subdomains: bool = True
    hsts_preload:          bool = False        # Only set True after HSTS preload submission
    x_frame_options:       str = "DENY"
    x_content_type_options: str = "nosniff"
    referrer_policy:       str = "strict-origin-when-cross-origin"
    permissions_policy:    str = "geolocation=(), microphone=(), camera=()"

    # File upload security
    allowed_upload_extensions: List[str] = field(default_factory=lambda: [
        ".json", ".xml", ".csv", ".txt",
        ".har",                              # HTTP Archive (scan import)
        ".yaml", ".yml",                     # OpenAPI specs
    ])
    
    max_upload_size_bytes: int = 10_485_760   # 10 MB

    def validate(self, environment: str) -> None:
        if environment == "production":
            if not self.cors_allowed_origins:
                import warnings
                warnings.warn(
                    "cors_allowed_origins is empty — all origins blocked. "
                    "Set VULNSCOUT_CORS_ORIGINS to allow the web dashboard.",
                    stacklevel=3,
                )
        valid_x_frame = ("DENY", "SAMEORIGIN")
        if self.x_frame_options not in valid_x_frame:
            raise ConfigError(
                f"x_frame_options must be one of {valid_x_frame}"
            )

    def csp_header_value(self) -> str:
        return "; ".join(
            f"{k} {v}" for k, v in self.csp_directives.items()
        )

    def to_dict(self) -> Dict:
        return {
            "cors_enabled": self.cors_enabled,
            "cors_allowed_origins": self.cors_allowed_origins,
            "csp_enabled": self.csp_enabled,
            "hsts_enabled": self.hsts_enabled,
            "x_frame_options": self.x_frame_options,
        }


# ── EA config ──────────────────────────────────────────────────────────────────

@dataclass
class EAConfig:
    """
    East Africa-specific feature flags and operational settings.
    These are the features that differentiate VulnScout Pro from
    generic global scanners.
    """

    # Feature flags
    ea_context_enabled:      bool = False    # Contextual regional enrichment
    ussd_detection_enabled:  bool = False
    mtn_momo_checks:         bool = False
    airtel_money_checks:     bool = False
    local_framework_detection: bool = False
    regulatory_mapping:      bool = False    # Regulatory compliance mapping (BOU, UCC, etc.)

    # Regional scope settings
    # Targets matching these TLDs get EA context applied automatically
    ea_tlds: List[str] = field(default_factory=lambda: [
        ".ug", ".ke", ".tz", ".rw", ".et", ".ng", ".gh", ".zm",
    ])

    # Industries that trigger enhanced EA checks
    ea_regulated_industries: List[str] = field(default_factory=lambda: [
        "banking", "fintech", "mobile_money", "telecom",
        "sacco", "microfinance", "government", "insurance",
    ])

    # Regulatory report formats (Disabled)
    bou_report_enabled:   bool = False
    ucc_report_enabled:   bool = False
    nita_u_report_enabled: bool = False

    # Currency for financial impact estimates
    currency:             str = "UGX"
    currency_symbol:      str = "UGX"

    # Timezone for report timestamps
    timezone:             str = field(
        default_factory=lambda: _env("TIMEZONE", "Africa/Kampala")
    )

    # Contact details for regulatory report headers
    company_name:    str = field(
        default_factory=lambda: _env("COMPANY_NAME", "VulnScout Pro")
    )
    company_address: str = field(
        default_factory=lambda: _env("COMPANY_ADDRESS", "Kampala, Uganda")
    )
    company_email:   str = field(
        default_factory=lambda: _env("COMPANY_EMAIL", "")
    )

    def to_dict(self) -> Dict:
        return {
            "ea_context_enabled": self.ea_context_enabled,
            "ussd_detection_enabled": self.ussd_detection_enabled,
            "mtn_momo_checks": self.mtn_momo_checks,
            "airtel_money_checks": self.airtel_money_checks,
            "regulatory_mapping": self.regulatory_mapping,
            "currency": self.currency,
            "timezone": self.timezone,
        }


# ── Reporting config ───────────────────────────────────────────────────────────

@dataclass
class ReportingConfig:
    """Report generation settings."""

    # PDF
    pdf_engine:              str = "weasyprint"    # weasyprint | reportlab
    pdf_page_size:           str = "A4"
    pdf_logo_path:           str = field(
        default_factory=lambda: str(
            PROJECT_ROOT / "web" / "static" / "img" / "logo.png"
        )
    )

    # Watermarks
    watermark_draft:         bool = True    # Add DRAFT watermark to dev reports
    watermark_confidential:  bool = True    # Add CONFIDENTIAL to all reports

    # Default report metadata
    default_prepared_by:     str = field(
        default_factory=lambda: _env("REPORT_PREPARED_BY", "VulnScout Pro Scanner")
    )

    # Findings threshold for executive summary callouts
    critical_callout_threshold: int = 0    # Always call out criticals
    high_callout_threshold:     int = 3    # Call out if > 3 high findings

    def to_dict(self) -> Dict:
        return {
            "watermark_draft": self.watermark_draft,
            "watermark_confidential": self.watermark_confidential,
        }


# ── Integration config ─────────────────────────────────────────────────────────

@dataclass
class IntegrationConfig:
    """Outbound integration settings (Slack, Jira, Webhooks)."""
    
    # Slack
    slack_enabled: bool = field(default_factory=lambda: _env_bool("SLACK_ENABLED", False))
    slack_webhook_url: str = field(default_factory=lambda: _env("SLACK_WEBHOOK_URL", ""))
    
    # Teams
    teams_enabled: bool = field(default_factory=lambda: _env_bool("TEAMS_ENABLED", False))
    teams_webhook_url: str = field(default_factory=lambda: _env("TEAMS_WEBHOOK_URL", ""))
    
    # Jira
    jira_enabled: bool = field(default_factory=lambda: _env_bool("JIRA_ENABLED", False))
    jira_url: str = field(default_factory=lambda: _env("JIRA_URL", ""))
    jira_user: str = field(default_factory=lambda: _env("JIRA_USER", ""))
    jira_token: str = field(default_factory=lambda: _env("JIRA_TOKEN", ""))
    jira_project: str = field(default_factory=lambda: _env("JIRA_PROJECT", ""))
    
    # Generic Webhooks (stored as JSON string list in env)
    webhooks: List[Dict] = field(default_factory=list)
    
    # CI/CD
    fail_on_critical: bool = True
    fail_on_high: bool = True
    max_high_allowed: int = 0

    def to_dict(self) -> Dict:
        return {
            "slack_enabled": self.slack_enabled,
            "teams_enabled": self.teams_enabled,
            "jira_enabled": self.jira_enabled,
            "jira_url": self.jira_url,
            "webhooks_count": len(self.webhooks),
        }


# ── AI config ──────────────────────────────────────────────────────────────────

@dataclass
class AIConfig:
    """
    Settings for AI-powered features (Triage, Analysis).
    """
    gemini_api_key: str = field(default_factory=lambda: _env("AI_GEMINI_API_KEY", ""))
    enabled: bool = field(default_factory=lambda: _env_bool("AI_ENABLED", True))
    model_name: str = "gemini-pro"

    def to_dict(self) -> Dict:
        return {
            "gemini_api_key": _mask(self.gemini_api_key),
            "enabled": self.enabled,
            "model_name": self.model_name,
        }


# ── Root config container ──────────────────────────────────────────────────────

@dataclass
class BaseConfig:
    """
    Root configuration container.
    Instantiated once at startup; passed via dependency injection.

    Usage:
        from config import get_config
        config = get_config()
        print(config.server.port)
    """

    app:        AppConfig        = field(default_factory=AppConfig)
    server:     ServerConfig     = field(default_factory=ServerConfig)
    storage:    StorageConfig    = field(default_factory=StorageConfig)
    auth:       AuthConfig       = field(default_factory=AuthConfig)
    scan:       DefaultScanConfig = field(default_factory=DefaultScanConfig)
    rate_limit: RateLimitConfig  = field(default_factory=RateLimitConfig)
    logging:    LoggingConfig    = field(default_factory=LoggingConfig)
    security:   SecurityConfig   = field(default_factory=SecurityConfig)
    ea:         EAConfig         = field(default_factory=EAConfig)
    reporting:  ReportingConfig  = field(default_factory=ReportingConfig)
    integrations: IntegrationConfig = field(default_factory=IntegrationConfig)
    ai:         AIConfig         = field(default_factory=AIConfig)

    def validate(self) -> "BaseConfig":
        """
        Validate all config sections.
        Call once at application startup — fails fast on misconfiguration.
        """
        env = self.app.environment
        self.app.validate()
        self.server.validate(env)
        self.storage.validate()
        self.auth.validate(env)
        self.scan.validate()
        self.logging.validate()
        self.security.validate(env)
        return self

    def to_dict(self, masked: bool = True) -> Dict:
        """
        Serialise config to dict.
        Secrets are always masked regardless of masked parameter.
        """
        return {
            "app":        self.app.to_dict(),
            "server":     self.server.to_dict(),
            "storage":    self.storage.to_dict(),
            "auth":       self.auth.to_dict(),
            "scan":       self.scan.to_dict(),
            "rate_limit": self.rate_limit.to_dict(),
            "logging":    self.logging.to_dict(),
            "security":   self.security.to_dict(),
            "ea":         self.ea.to_dict(),
            "reporting":  self.reporting.to_dict(),
        }

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} "
            f"env={self.app.environment!r} "
            f"port={self.server.port} "
            f"debug={self.app.debug}>"
        )