"""
target.py — Scan Target Model

The Target represents what is being scanned: a URL, host, IP range,
or named application. It carries all authorisation metadata required
by the scope enforcer and is the root object attached to every Scan.

Design principles:
  - Immutable after construction (frozen=True on dataclass would be ideal,
    but we need post-init normalisation, so we enforce via properties)
  - All URL normalisation happens at construction time — consumers get clean data
  - Scope config is embedded in the Target so it travels with the scan record
  - Supports both web app targets (URL-based) and API targets (base URL + spec)
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urlparse, urlunparse


# ── Enums / constants ──────────────────────────────────────────────────────────

class TargetType:
    WEB_APP      = "web_app"       # Standard web application
    REST_API     = "rest_api"      # REST API with spec (OpenAPI/Swagger)
    MOBILE_MONEY = "mobile_money"  # Mobile money integration endpoint
    USSD_BACKEND = "ussd_backend"  # USSD gateway backend
    GOVERNMENT   = "government"    # Government portal/API
    ADMIN_PANEL  = "admin_panel"   # Admin dashboard

class AuthType:
    NONE         = "none"
    BASIC        = "basic"
    BEARER       = "bearer"
    SESSION      = "session"
    API_KEY      = "api_key"
    OAUTH2       = "oauth2"
    MFA          = "mfa"           # Session with MFA
    MACRO        = "macro"         # Macro-based scripted login
    CUSTOM       = "custom"


# ── Auth config ────────────────────────────────────────────────────────────────

@dataclass
class TargetAuth:
    """
    Authentication credentials for accessing the target.
    Used by the crawler and injector to maintain an authenticated session.
    Credentials are NEVER written to scan results or reports.
    """
    auth_type: str = AuthType.NONE

    # Basic / form-based
    username: str | None = None
    password: str | None = None
    login_url: str | None = None
    login_payload: dict[str, str] | None = None   # Custom form fields

    # Token-based
    bearer_token: str | None = None
    api_key: str | None = None
    api_key_header: str = "X-API-Key"

    # Session
    cookies: dict[str, str] = field(default_factory=dict)
    session_headers: dict[str, str] = field(default_factory=dict)

    # MFA
    mfa_secret: str | None = None

    # Macros / multi-step login sequences
    macro_steps: list[dict] = field(default_factory=list)

    def has_credentials(self) -> bool:
        return self.auth_type != AuthType.NONE

    def to_headers(self) -> Dict[str, str]:
        """Produce HTTP headers dict from auth config (never logs values)."""
        headers = dict(self.session_headers)
        if self.auth_type == AuthType.BEARER and self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        elif self.auth_type == AuthType.API_KEY and self.api_key:
            headers[self.api_key_header] = self.api_key
        return headers

    def redacted(self) -> Dict:
        """Safe representation with all credential values masked."""
        return {
            "auth_type": self.auth_type,
            "username": self.username,
            "has_password": bool(self.password),
            "has_token": bool(self.bearer_token or self.api_key),
            "has_cookies": bool(self.cookies),
            "has_mfa": bool(self.mfa_secret),
            "macro_steps_count": len(self.macro_steps),
        }


# ── Scope config ───────────────────────────────────────────────────────────────

@dataclass
class ScopeConfig:
    """
    Authorised scan scope — embedded in Target so it's always co-located
    with the scan authorisation metadata. Mirrors the ScopeEnforcer's config.
    """
    allowed_domains: list[str] = field(default_factory=list)
    allowed_wildcard_domains: list[str] = field(default_factory=list)
    allowed_ip_ranges: list[str] = field(default_factory=list)
    allowed_url_prefixes: list[str] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)
    excluded_domains: list[str] = field(default_factory=list)
    authorisation_token: str | None = None
    authorised_by: str | None = None
    authorised_at: str | None = None
    max_scan_depth: int = 3

    def is_empty(self) -> bool:
        return not any([
            self.allowed_domains,
            self.allowed_wildcard_domains,
            self.allowed_ip_ranges,
            self.allowed_url_prefixes,
        ])

    def to_dict(self) -> Dict:
        return {
            "allowed_domains": self.allowed_domains,
            "allowed_wildcard_domains": self.allowed_wildcard_domains,
            "allowed_ip_ranges": self.allowed_ip_ranges,
            "allowed_url_prefixes": self.allowed_url_prefixes,
            "excluded_paths": self.excluded_paths,
            "excluded_domains": self.excluded_domains,
            "authorised_by": self.authorised_by,
            "authorised_at": self.authorised_at,
        }

    @classmethod
    def from_url(
        cls,
        base_url: str,
        authorised_by: Optional[str] = None,
        include_subdomains: bool = False,
    ) -> "ScopeConfig":
        """Build a minimal ScopeConfig from a single target URL."""
        parsed = urlparse(base_url)
        host = parsed.hostname or ""
        wildcards = [f"*.{host}"] if include_subdomains else []
        return cls(
            allowed_url_prefixes=[base_url],
            allowed_domains=[host],
            allowed_wildcard_domains=wildcards,
            authorised_by=authorised_by,
            authorised_at=datetime.now(timezone.utc).isoformat(),
        )


# ── Scan config ────────────────────────────────────────────────────────────────

@dataclass
class ScanConfig:
    """
    Tuning parameters for a scan run.
    Defaults are conservative — suitable for production targets.
    """
    # Crawling
    crawl_depth: int = 3
    max_pages: int = 150
    respect_robots_txt: bool = True
    user_agent: str = "VulnScout-Pro/1.0 (Authorised Security Scanner)"
    follow_redirects: bool = True

    # Rate limiting
    rate_limit_rps: float = 12.0        # Boosted from 3.0 for High-Velocity Ops
    rate_limit_burst: int = 24          # Boosted from 8

    # Detection
    enabled_checks: list[str] = field(default_factory=lambda: [
        "sqli", "xss", "xxe", "ssrf", "idor",
        "auth_bypass", "misconfig", "sensitive_data",
    ])
    max_concurrent_detectors: int = 15   # Boosted from 5
    include_ea_context: bool = True      # Enable Uganda/EA-specific checks
    
    # Advanced Pro Features
    js_render: bool = False             # Execute JavaScript in crawler
    api_fuzzing: bool = False           # Deep API parameter discovery
    high_concurrency: bool = False      # Enable unthrottled engine
    unthrottled: bool = True            # Bypass all rate limiting in fast mode
    fast_mode: bool = True              # TURBO: Strip heavy AI/remediation overhead

    # Reporting
    min_severity: str = "low"           # Minimum severity to include in report
    include_informational: bool = False

    # Scope
    scope: ScopeConfig = field(default_factory=ScopeConfig)

    def to_dict(self) -> Dict:
        return {
            "crawl_depth": self.crawl_depth,
            "max_pages": self.max_pages,
            "respect_robots_txt": self.respect_robots_txt,
            "rate_limit_rps": self.rate_limit_rps,
            "enabled_checks": self.enabled_checks,
            "max_concurrent_detectors": self.max_concurrent_detectors,
            "include_ea_context": self.include_ea_context,
            "min_severity": self.min_severity,
            "js_render": self.js_render,
            "api_fuzzing": self.api_fuzzing,
            "high_concurrency": self.high_concurrency,
            "unthrottled": self.unthrottled,
            "fast_mode": self.fast_mode,
        }

    @classmethod
    def fast(cls) -> "ScanConfig":
        """Aggressive config for internal/lab targets — maximum speed, zero overhead."""
        return cls(
            crawl_depth=2,
            max_pages=100,
            rate_limit_rps=50.0,
            rate_limit_burst=100,
            max_concurrent_detectors=40,
            unthrottled=True,
            fast_mode=True,
        )

    @classmethod
    def deep(cls) -> "ScanConfig":
        """Thorough config — slower but more comprehensive."""
        return cls(
            crawl_depth=5,
            max_pages=500,
            rate_limit_rps=2.0,
            rate_limit_burst=5,
            max_concurrent_detectors=3,
        )

    @classmethod
    def stealth(cls) -> "ScanConfig":
        """Low-and-slow config to avoid WAF/IDS triggering."""
        return cls(
            crawl_depth=3,
            max_pages=100,
            rate_limit_rps=0.5,
            rate_limit_burst=2,
            max_concurrent_detectors=1,
            respect_robots_txt=True,
        )


# ── Target model ───────────────────────────────────────────────────────────────

@dataclass
class Target:
    """
    Represents a scan target with all metadata required for a full scan.

    A Target is created by the user (CLI, API, or web UI) and passed
    to the orchestrator. It is embedded in the resulting Scan object.

    Example:
        target = Target.from_url(
            url="https://example.com",
            name="Example Web App",
            authorised_by="security@example.com",
        )
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    base_url: str = ""
    name: str = ""
    description: str = ""
    target_type: str = TargetType.WEB_APP
    industry: str = "general"             # Used for regulatory risk weighting

    # Authorisation (required)
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    auth: TargetAuth = field(default_factory=TargetAuth)
    scan_config: ScanConfig = field(default_factory=ScanConfig)

    # Optional metadata
    tags: list[str] = field(default_factory=list)
    custom_headers: dict[str, str] = field(default_factory=dict)
    notes: str = ""

    # API spec (if target is a REST API)
    openapi_spec_url: str | None = None
    openapi_spec_path: str | None = None

    # Timestamps
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self) -> None:
        self.base_url = self._normalise_url(self.base_url)
        if not self.name:
            self.name = self._infer_name()
        # Ensure scope always covers at least the base URL
        if self.scope.is_empty() and self.base_url:
            self.scope = ScopeConfig.from_url(self.base_url)
        # Sync scope into scan_config
        self.scan_config.scope = self.scope

    # ── Factories ──────────────────────────────────────────────────────────────

    @classmethod
    def from_url(
        cls,
        url: str,
        name: str = "",
        authorised_by: str | None = None,
        industry: str = "general",
        include_subdomains: bool = False,
        scan_config: ScanConfig | None = None,
        auth: TargetAuth | None = None,
        tags: list[str] | None = None,
    ) -> "Target":
        """Most common factory — create a target from a single URL."""
        scope = ScopeConfig.from_url(
            url,
            authorised_by=authorised_by,
            include_subdomains=include_subdomains,
        )
        return cls(
            base_url=url,
            name=name,
            target_type=cls._infer_type_from_url(url, industry),
            industry=industry,
            scope=scope,
            auth=auth or TargetAuth(),
            scan_config=scan_config or ScanConfig(),
            tags=tags or [],
        )

    @classmethod
    def from_dict(cls, data: Dict) -> "Target":
        """Deserialise from dict (e.g. loaded from JSON storage)."""
        scope_data = data.pop("scope", {})
        auth_data = data.pop("auth", {})
        config_data = data.pop("scan_config", {})

        scope = ScopeConfig(**{
            k: v for k, v in scope_data.items()
            if k in ScopeConfig.__dataclass_fields__
        })
        auth = TargetAuth(**{
            k: v for k, v in auth_data.items()
            if k in TargetAuth.__dataclass_fields__
        })
        config = ScanConfig(**{
            k: v for k, v in config_data.items()
            if k in ScanConfig.__dataclass_fields__
        })

        return cls(
            **{k: v for k, v in data.items() if k in cls.__dataclass_fields__},
            scope=scope,
            auth=auth,
            scan_config=config,
        )

    # ── Properties ─────────────────────────────────────────────────────────────

    @property
    def hostname(self) -> str:
        parsed = urlparse(self.base_url)
        return parsed.hostname or ""

    @property
    def scheme(self) -> str:
        return urlparse(self.base_url).scheme

    @property
    def is_https(self) -> bool:
        return self.scheme == "https"

    @property
    def is_ea_target(self) -> bool:
        """Heuristic: is this likely an East African application?"""
        ea_tlds = (".ug", ".ke", ".tz", ".rw", ".et", ".ng")
        ea_domains = ("mtn.com", "airtel.com", "safaricom.com",
                      "pesapal.com", "africastalking.com", "flutterwave.com",
                      "interswitchng.com", "kopokopo.com")
        host = self.hostname.lower()
        return (
            any(host.endswith(tld) for tld in ea_tlds)
            or any(d in host for d in ea_domains)
            or self.industry in (
                "mobile_money", "telecom", "sacco", "microfinance",
                "banking", "fintech", "government",
            )
        )

    # ── Serialisation ──────────────────────────────────────────────────────────

    def to_dict(self, include_auth: bool = False) -> Dict:
        result = {
            "id": self.id,
            "url": self.base_url,
            "base_url": self.base_url,
            "name": self.name,
            "description": self.description,
            "target_type": self.target_type,
            "industry": self.industry,
            "hostname": self.hostname,
            "is_https": self.is_https,
            "is_ea_target": self.is_ea_target,
            "tags": self.tags,
            "notes": self.notes,
            "openapi_spec_url": self.openapi_spec_url,
            "scope": self.scope.to_dict(),
            "scan_config": self.scan_config.to_dict(),
            "created_at": self.created_at,
        }
        if include_auth:
            result["auth"] = self.auth.redacted()
        return result

    def to_json(self, include_auth: bool = False) -> str:
        import json
        return json.dumps(self.to_dict(include_auth=include_auth), indent=2)

    # ── Internal helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _normalise_url(url: str) -> str:
        """Ensure URL has scheme, strip trailing slash from path."""
        if not url:
            return url
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        parsed = urlparse(url)
        # Remove trailing slash from path only
        path = parsed.path.rstrip("/") if parsed.path != "/" else parsed.path
        return urlunparse(parsed._replace(path=path))

    def _infer_name(self) -> str:
        return self.hostname or self.base_url or "Unnamed Target"

    @staticmethod
    def _infer_type_from_url(url: str, industry: str) -> str:
        lower = url.lower()
        if industry in ("mobile_money", "fintech"):
            return TargetType.MOBILE_MONEY
        if industry in ("government",):
            return TargetType.GOVERNMENT
        if any(x in lower for x in ("/api/", "/v1/", "/v2/", "/graphql")):
            return TargetType.REST_API
        if any(x in lower for x in ("/admin", "/dashboard", "/manage")):
            return TargetType.ADMIN_PANEL
        if any(x in lower for x in ("ussd", "momo", "airtel-money")):
            return TargetType.USSD_BACKEND
        return TargetType.WEB_APP

    def __repr__(self) -> str:
        return f"<Target id={self.id[:8]} name={self.name!r} url={self.base_url!r}>"