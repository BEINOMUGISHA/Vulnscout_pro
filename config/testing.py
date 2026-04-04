"""
config/testing.py — Testing Configuration

Deterministic, hermetic configuration for the test suite.
All external dependencies are isolated:
  - Storage uses a temp directory (cleaned per test)
  - Scan rate limits are removed (tests need to run fast)
  - Auth tokens use fixed secrets (deterministic test assertions)
  - Logging is suppressed by default (set LOG_LEVEL=DEBUG for verbose)
  - No real HTTP requests to external services
  - EA context enabled (we test EA code paths explicitly)
  - All detectors enabled (full coverage in integration tests)

Provides:
  TestingConfig          — main config dataclass
  TestConfigFactory      — builds configs for specific test scenarios
  fixture helpers        — convenience functions for pytest fixtures
  VULNERABLE_APP_CONFIG  — config for the built-in vulnerable app target

Usage in pytest:
    @pytest.fixture
    def config():
        return TestingConfig()

    @pytest.fixture
    def ea_fintech_config():
        return TestConfigFactory.fintech_scan()
"""

from __future__ import annotations

import os
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from config.base import (
    AppConfig, AuthConfig, DefaultScanConfig, EAConfig, LoggingConfig,
    RateLimitConfig, ReportingConfig, SecurityConfig, ServerConfig,
    StorageConfig, BaseConfig,
)


# ── Fixed test secrets ─────────────────────────────────────────────────────────
# These are committed deliberately — they are only ever used in test runs
# and must never appear in production configuration.

TEST_SECRET_KEY    = "test_secret_key_vulnscout_pro_not_for_production_00000000000000000000"
TEST_JWT_SECRET    = "test_jwt_secret_not_for_production_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
TEST_API_KEY       = "vsp_test_api_key_00000000000000000000000000000000000000000000"
TEST_TOTP_SECRET   = "JBSWY3DPEHPK3PXP"  # Standard test TOTP secret

# Fixed user IDs for test fixtures
TEST_USER_ID       = "00000000-0000-0000-0000-000000000001"
TEST_ADMIN_ID      = "00000000-0000-0000-0000-000000000002"
TEST_READONLY_ID   = "00000000-0000-0000-0000-000000000003"

# Vulnerable app URL (started by conftest.py)
VULNERABLE_APP_URL = "http://localhost:8999"


@dataclass
class TestingAppConfig(AppConfig):
    environment:   str  = "testing"
    debug:         bool = True
    secret_key:    str  = TEST_SECRET_KEY
    allowed_hosts: List[str] = field(default_factory=lambda: ["*", "testserver"])


@dataclass
class TestingServerConfig(ServerConfig):
    host:        str  = "127.0.0.1"
    port:        int  = 8001            # Different from dev to allow parallel runs
    workers:     int  = 1
    reload:      bool = False
    tls_enabled: bool = False


@dataclass
class TestingStorageConfig(StorageConfig):
    """
    Uses a per-session temp directory.
    Call create_dirs() in a pytest fixture and cleanup via tmp_path.
    """
    data_dir: str = field(
        default_factory=lambda: str(
            Path(tempfile.gettempdir()) / f"vulnscout_test_{uuid.uuid4().hex[:8]}"
        )
    )
    scan_retention_days:    int = 0    # Keep everything during test run
    report_retention_days:  int = 0
    session_retention_days: int = 0
    dir_permissions:  int = 0o755
    file_permissions: int = 0o644


@dataclass
class TestingAuthConfig(AuthConfig):
    jwt_access_expire_min:    int  = 60 * 24    # 24h — never expire during tests
    jwt_refresh_expire_days:  int  = 30
    session_expire_minutes:   int  = 60 * 24
    session_cookie_secure:    bool = False       # HTTP in tests
    totp_required:            bool = False        # No 2FA in tests
    max_login_attempts:       int  = 1000        # Never lock out test users
    lockout_duration_min:     int  = 0
    lockout_progressive:      bool = False
    min_password_length:      int  = 8           # Minimum allowed by validator
    password_history:         int  = 0


@dataclass
class TestingScanConfig(DefaultScanConfig):
    """
    Minimal scan config for unit tests — no real HTTP requests.
    Integration tests override this with TestConfigFactory.
    """
    crawl_depth:              int   = 1
    max_pages:                int   = 5
    rate_limit_rps:           float = 100.0     # No throttling — tests must be fast
    rate_limit_burst:         int   = 100
    max_concurrent_detectors: int   = 8         # Full concurrency in tests
    max_concurrent_scans:     int   = 10
    respect_robots_txt:       bool  = False     # Test server has no robots.txt
    include_ea_context:       bool  = True      # Always test EA code paths

    # All detectors enabled — we want full coverage
    enabled_checks: List[str] = field(default_factory=lambda: [
        "sqli", "xss", "xxe", "ssrf", "idor",
        "auth_bypass", "misconfig", "sensitive_data",
    ])

    # Override absolute limits for testing
    max_crawl_depth_absolute: int   = 20
    max_pages_absolute:       int   = 100
    max_rps_absolute:         float = 1000.0


@dataclass
class TestingRateLimitConfig(RateLimitConfig):
    """No rate limiting in tests."""
    api_requests_per_minute:   int = 100_000
    api_requests_per_hour:     int = 100_000
    api_requests_per_day:      int = 100_000
    ip_requests_per_minute:    int = 100_000
    ip_requests_per_hour:      int = 100_000
    scans_per_user_per_day:    int = 1_000
    scans_per_user_per_hour:   int = 1_000
    reports_per_user_per_hour: int = 1_000


@dataclass
class TestingLoggingConfig(LoggingConfig):
    """
    Quiet by default. Set LOG_LEVEL=DEBUG to see scanner output during tests.
    """
    level:             str  = os.environ.get("LOG_LEVEL", "WARNING").upper()
    format:            str  = "text"
    redact_sensitive:  bool = False    # Show values in test logs
    audit_log_enabled: bool = False    # No audit log in tests


@dataclass
class TestingSecurityConfig(SecurityConfig):
    cors_allowed_origins: List[str] = field(default_factory=lambda: [
        "http://localhost:3000",
        "http://testserver",
    ])
    hsts_enabled:  bool = False
    csp_enabled:   bool = False


@dataclass
class TestingEAConfig(EAConfig):
    """All EA features on — we want to test every EA-specific code path."""
    ea_context_enabled:        bool = True
    ussd_detection_enabled:    bool = True
    mtn_momo_checks:           bool = True
    airtel_money_checks:       bool = True
    local_framework_detection: bool = True
    regulatory_mapping:        bool = True
    company_name:              str  = "VulnScout Test Instance"
    company_email:             str  = "test@vulnscout.test"
    timezone:                  str  = "Africa/Kampala"


@dataclass
class TestingReportingConfig(ReportingConfig):
    watermark_draft:        bool = True
    watermark_confidential: bool = False
    default_prepared_by:    str  = "VulnScout Test Runner"


@dataclass
class TestingConfig(BaseConfig):
    """
    Complete testing configuration.
    All external dependencies isolated; all rate limits removed.
    """
    app:        TestingAppConfig        = field(default_factory=TestingAppConfig)
    server:     TestingServerConfig     = field(default_factory=TestingServerConfig)
    storage:    TestingStorageConfig    = field(default_factory=TestingStorageConfig)
    auth:       TestingAuthConfig       = field(default_factory=TestingAuthConfig)
    scan:       TestingScanConfig       = field(default_factory=TestingScanConfig)
    rate_limit: TestingRateLimitConfig  = field(default_factory=TestingRateLimitConfig)
    logging:    TestingLoggingConfig    = field(default_factory=TestingLoggingConfig)
    security:   TestingSecurityConfig   = field(default_factory=TestingSecurityConfig)
    ea:         TestingEAConfig         = field(default_factory=TestingEAConfig)
    reporting:  TestingReportingConfig  = field(default_factory=TestingReportingConfig)

    def validate(self) -> "TestingConfig":
        # Testing config skips some production-only validations
        self.app.validate()
        self.storage.validate()
        self.auth.validate("testing")
        self.scan.validate()
        self.logging.validate()
        return self

    def with_temp_storage(self) -> "TestingConfig":
        """Return a copy with a fresh temp directory. Use in pytest fixtures."""
        import copy
        clone = copy.deepcopy(self)
        clone.storage.data_dir = str(
            Path(tempfile.gettempdir()) / f"vulnscout_test_{uuid.uuid4().hex[:8]}"
        )
        clone.storage.create_dirs()
        return clone


# ── Test config factory ────────────────────────────────────────────────────────

class TestConfigFactory:
    """
    Builds pre-configured TestingConfig instances for specific test scenarios.
    Used in integration tests where scan behaviour matters.
    """

    @staticmethod
    def base() -> TestingConfig:
        """Base test config with fresh temp storage."""
        return TestingConfig().with_temp_storage()

    @staticmethod
    def fintech_scan() -> TestingConfig:
        """Config tuned for testing EA fintech / mobile money targets."""
        config = TestConfigFactory.base()
        config.scan.include_ea_context = True
        config.scan.enabled_checks = [
            "sqli", "idor", "auth_bypass", "sensitive_data", "misconfig",
        ]
        config.ea.mtn_momo_checks = True
        config.ea.airtel_money_checks = True
        return config

    @staticmethod
    def government_scan() -> TestingConfig:
        """Config for testing government portal targets."""
        config = TestConfigFactory.base()
        config.scan.enabled_checks = [
            "sqli", "idor", "sensitive_data", "misconfig",
        ]
        config.ea.regulatory_mapping = True
        config.ea.ussd_detection_enabled = False
        return config

    @staticmethod
    def deep_scan() -> TestingConfig:
        """High crawl depth for integration tests needing full coverage."""
        config = TestConfigFactory.base()
        config.scan.crawl_depth = 3
        config.scan.max_pages = 50
        return config

    @staticmethod
    def minimal_scan() -> TestingConfig:
        """Absolute minimum — for unit tests that just need a config object."""
        config = TestConfigFactory.base()
        config.scan.crawl_depth = 1
        config.scan.max_pages = 2
        config.scan.enabled_checks = ["sqli"]
        config.ea.ea_context_enabled = False
        return config

    @staticmethod
    def no_ea_context() -> TestingConfig:
        """Config with all EA features disabled — tests global code paths only."""
        config = TestConfigFactory.base()
        config.scan.include_ea_context = False
        config.ea.ea_context_enabled = False
        config.ea.mtn_momo_checks = False
        config.ea.airtel_money_checks = False
        config.ea.regulatory_mapping = False
        config.ea.ussd_detection_enabled = False
        return config


# ── pytest fixture helpers ─────────────────────────────────────────────────────

def make_test_target(
    url: str = VULNERABLE_APP_URL,
    industry: str = "general",
    name: str = "Test Target",
    include_subdomains: bool = False,
) -> "Target":  # type: ignore[name-defined]
    """Build a test Target object. Import avoids circular deps."""
    from core.models.target import Target
    return Target.from_url(
        url=url,
        name=name,
        authorised_by="test_runner@vulnscout.test",
        industry=industry,
        include_subdomains=include_subdomains,
    )


def make_test_scan(
    target_url: str = VULNERABLE_APP_URL,
    industry: str = "general",
) -> "Scan":  # type: ignore[name-defined]
    """Build a minimal test Scan object with a Target attached."""
    from core.models.scan import Scan
    target = make_test_target(target_url, industry)
    scan = Scan()
    scan.target = target
    scan.config = TestingScanConfig()
    return scan


def make_test_finding(
    vuln_type: str = "sqli",
    severity: str = "high",
    url: str = f"{VULNERABLE_APP_URL}/search",
    parameter: str = "q",
    cvss_score: float = 7.5,
    ea_relevant: bool = False,
) -> "Finding":  # type: ignore[name-defined]
    """Build a minimal confirmed test Finding."""
    from core.models.finding import Finding, FindingEvidence, EAContext
    from core.models.finding import VulnType
    evidence = FindingEvidence(
        request_url=url,
        request_method="GET",
        injected_parameter=parameter,
        injected_payload="' OR '1'='1",
        response_status=200,
        response_body_excerpt="MySQL syntax error",
        matched_pattern="you have an error in your sql syntax",
    )
    ea_context = EAContext(ea_relevant=ea_relevant)
    return Finding(
        url=url,
        parameter_name=parameter,
        parameter_location="query",
        vuln_type=vuln_type,
        cvss_score=cvss_score,
        severity=severity,
        confidence=0.85,
        evidence=evidence,
        ea_context=ea_context,
    )


# ── Vulnerable app configuration ───────────────────────────────────────────────

VULNERABLE_APP_CONFIG = {
    "url": VULNERABLE_APP_URL,
    "name": "VulnScout Test Vulnerable App",
    "description": (
        "Built-in intentionally vulnerable application for integration testing. "
        "Contains one confirmed instance of each supported vulnerability type."
    ),
    "expected_findings": {
        "sqli":           {"count": 2, "min_severity": "high"},
        "xss_reflected":  {"count": 1, "min_severity": "medium"},
        "xxe":            {"count": 1, "min_severity": "high"},
        "ssrf":           {"count": 1, "min_severity": "high"},
        "idor":           {"count": 2, "min_severity": "high"},
        "auth_bypass":    {"count": 1, "min_severity": "critical"},
        "misconfig":      {"count": 3, "min_severity": "low"},
        "sensitive_data": {"count": 1, "min_severity": "critical"},
    },
    "ea_expected_findings": {
        "ipn_forgery":           {"count": 1},
        "mm_credential_exposure": {"count": 1},
    },
}