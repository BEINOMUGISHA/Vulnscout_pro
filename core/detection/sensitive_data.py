"""
sensitive_data.py — Sensitive Data Exposure Detector

Covers:
  - API keys / secrets in HTML, JS, and JSON responses
  - Database connection strings
  - Private keys (RSA, EC, PGP)
  - JWT tokens in responses
  - Ugandan NIN, URA TIN in API responses (PII exposure)
  - NSSF member numbers, account numbers in responses
  - Plaintext passwords in responses or URL params
  - AWS/GCP/Azure credentials in JS bundles
  - Session tokens in URL query strings (logged by proxies)
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Pattern, Tuple

from core.detection.base_detector import BaseDetector, DetectorMeta, Payload
from core.models.finding import VulnType, Finding, FindingEvidence

_CVSS_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"  # 9.1
_CVSS_HIGH     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # 7.5
_CVSS_MEDIUM   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"  # 5.3


@dataclass
class SecretPattern:
    """A pattern for detecting a specific type of secret or sensitive data."""
    name: str
    pattern: str           # Main regex
    context_pattern: str = ""  # Optional: must also match to reduce FP
    severity: str = "high"
    cvss: str = _CVSS_HIGH
    description: str = ""
    ea_specific: bool = False
    is_pii: bool = False       # PII data has special regulatory treatment
    group: str = "api_keys"    # Grouping for reporting

    _compiled: Optional[Pattern] = field(default=None, repr=False, compare=False)
    _ctx_compiled: Optional[Pattern] = field(default=None, repr=False, compare=False)

    def compile(self):
        if self._compiled is None:
            try:
                self._compiled = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
            except re.error:
                pass
        if self.context_pattern and self._ctx_compiled is None:
            try:
                self._ctx_compiled = re.compile(self.context_pattern, re.IGNORECASE)
            except re.error:
                pass
        return self

    def matches(self, text: str) -> List[str]:
        self.compile()
        if self._compiled is None:
            return []
        hits = []
        for m in self._compiled.finditer(text):
            val = m.group(0)
            # If context pattern required, check a window around the match
            if self._ctx_compiled:
                start = max(0, m.start() - 100)
                end = min(len(text), m.end() + 100)
                window = text[start:end]
                if not self._ctx_compiled.search(window):
                    continue
            hits.append(val)
        return hits


SECRET_PATTERNS: List[SecretPattern] = [

    # ── Cloud provider credentials ─────────────────────────────────────────────
    SecretPattern(
        name="AWS Access Key ID",
        pattern=r"AKIA[0-9A-Z]{16}",
        severity="critical",
        cvss=_CVSS_CRITICAL,
        description="AWS Access Key ID",
        group="cloud",
    ),
    SecretPattern(
        name="AWS Secret Access Key",
        pattern=r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
        severity="critical",
        cvss=_CVSS_CRITICAL,
        description="AWS Secret Access Key",
        group="cloud",
    ),
    SecretPattern(
        name="Google API Key",
        pattern=r"AIza[0-9A-Za-z\-_]{35}",
        severity="high",
        cvss=_CVSS_HIGH,
        description="Google API Key",
        group="cloud",
    ),
    SecretPattern(
        name="GCP Service Account Key",
        pattern=r'"private_key"\s*:\s*"-----BEGIN (RSA )?PRIVATE KEY-----',
        severity="critical",
        cvss=_CVSS_CRITICAL,
        description="GCP service account private key",
        group="cloud",
    ),

    # ── Generic API keys ───────────────────────────────────────────────────────
    SecretPattern(
        name="Generic API Key in JavaScript",
        pattern=r"""(?x)(api_key|apiKey|api-key|auth_token|authToken|access_token|accessToken)
                    \s*[=:]\s*['"][a-zA-Z0-9_\-\.]{20,}['"]""",
        severity="high",
        cvss=_CVSS_HIGH,
        description="Generic API key or token in JavaScript",
        group="api_keys",
    ),
    SecretPattern(
        name="Bearer Token in Response",
        pattern=r"Bearer\s+[A-Za-z0-9\-_\.]{40,}",
        context_pattern=r"(?i)(Authorization|access_token|token)",
        severity="critical",
        cvss=_CVSS_CRITICAL,
        description="Live Bearer token in HTTP response",
        group="tokens",
    ),
    SecretPattern(
        name="JWT Token in Response",
        pattern=r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
        severity="high",
        cvss=_CVSS_HIGH,
        description="JWT token returned in response body",
        group="tokens",
    ),

    # ── Private keys ───────────────────────────────────────────────────────────
    SecretPattern(
        name="RSA Private Key",
        pattern=r"-----BEGIN (RSA )?PRIVATE KEY-----",
        severity="critical",
        cvss=_CVSS_CRITICAL,
        description="RSA private key in response",
        group="keys",
    ),
    SecretPattern(
        name="EC Private Key",
        pattern=r"-----BEGIN EC PRIVATE KEY-----",
        severity="critical",
        cvss=_CVSS_CRITICAL,
        description="EC private key in response",
        group="keys",
    ),

    # ── Database credentials ───────────────────────────────────────────────────
    SecretPattern(
        name="Database Connection String",
        pattern=r"(?i)(mysql|postgres|mongodb|mssql|sqlite)://[^\s'\"<>]{10,}",
        severity="critical",
        cvss=_CVSS_CRITICAL,
        description="Database connection string with credentials",
        group="database",
    ),
    SecretPattern(
        name="DB Password in Config",
        pattern=r"""(?i)(db_password|database_password|DB_PASS|MYSQL_PASSWORD)\s*[=:]\s*['"][^'"]{4,}['"]""",
        severity="critical",
        cvss=_CVSS_CRITICAL,
        description="Database password in config/env file",
        group="database",
    ),

    # ── Uganda PII (PDPA 2019 special categories) ─────────────────────────────
    SecretPattern(
        name="Uganda National ID Number (NIN)",
        pattern=r"\bCM[A-Z0-9]{14}\b",
        severity="high",
        cvss=_CVSS_HIGH,
        description="Uganda National Identification Number (NIN) in response — PDPA violation",
        ea_specific=True,
        is_pii=True,
        group="pii_uganda",
    ),
    SecretPattern(
        name="Uganda URA TIN",
        pattern=r"\b\d{10}\b",
        context_pattern=r"(?i)(tin|tax.?identification|taxpayer)",
        severity="high",
        cvss=_CVSS_HIGH,
        description="URA Tax Identification Number in response — PDPA violation",
        ea_specific=True,
        is_pii=True,
        group="pii_uganda",
    ),
    SecretPattern(
        name="East African Phone Number (MSISDN)",
        pattern=r"\b(256|254|255|250|251)\d{9}\b",
        context_pattern=r"(?i)(msisdn|phone|mobile|phoneNumber|subscriber)",
        severity="medium",
        cvss=_CVSS_MEDIUM,
        description="MSISDN (phone number) bulk exposure in API response",
        ea_specific=True,
        is_pii=True,
        group="pii_uganda",
    ),
    SecretPattern(
        name="NSSF Member Number",
        pattern=r"\bNSS[F]?\d{6,10}\b",
        severity="high",
        cvss=_CVSS_HIGH,
        description="NSSF member number in response — PII exposure",
        ea_specific=True,
        is_pii=True,
        group="pii_uganda",
    ),

    # ── Session tokens in URLs ─────────────────────────────────────────────────
    SecretPattern(
        name="Session Token in URL",
        pattern=r"[?&](token|session|auth|key|secret|api_key)=[a-zA-Z0-9_\-\.]{20,}",
        severity="high",
        cvss=_CVSS_HIGH,
        description="Session/auth token in URL query string — logged by proxies/WAF",
        group="tokens",
    ),
    SecretPattern(
        name="Password in URL",
        pattern=r"[?&](password|passwd|pass|pwd)=[^&\s]{4,}",
        severity="critical",
        cvss=_CVSS_CRITICAL,
        description="Password in URL query string",
        group="tokens",
    ),

    # ── WordPress / CMS ───────────────────────────────────────────────────────
    SecretPattern(
        name="WordPress Auth Keys in Source",
        pattern=r"define\s*\(\s*'(AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY)'",
        severity="critical",
        cvss=_CVSS_CRITICAL,
        description="WordPress secret keys/salts exposed (wp-config.php accessible)",
        group="cms",
    ),
]


class SensitiveDataDetector(BaseDetector):

    def __init__(self) -> None:
        super().__init__()
        # Pre-compile all patterns
        for p in SECRET_PATTERNS:
            p.compile()

    @property
    def meta(self) -> DetectorMeta:
        return DetectorMeta(
            detector_id="sensitive_data",
            name="Sensitive Data Exposure",
            description=(
                "Detects API keys, PII, private keys, "
                "and database credentials in HTTP responses"
            ),
            vuln_types=[VulnType.SENSITIVE_DATA],
            owasp_categories=["A02:2021 – Cryptographic Failures"],
            estimated_requests_per_endpoint=2,
        )

    @property
    def payloads(self) -> List[Payload]:
        return []   # Passive analysis — no injection needed

    async def detect(self, target, crawl_result, injector) -> list:
        """
        Passive scan — analyses the response body for secret patterns.
        No injection; no additional requests beyond what the crawler already made.
        """
        findings = []

        # Get response body — stored on crawl_result by the crawler
        body = getattr(crawl_result, "_raw_body", "") or ""
        if not body:
            return findings

        url = crawl_result.url
        seen: Dict[str, bool] = {}   # Dedup by (url, pattern_name)

        for sp in SECRET_PATTERNS:
            key = f"{url}:{sp.name}"
            if key in seen:
                continue

            hits = sp.matches(body)
            if not hits:
                continue

            seen[key] = True

            # Redact the matched value for safe storage
            redacted = self._redact_value(hits[0])
            context   = self._safe_excerpt(body, hits[0], context=150)

            self._log_hit(self.meta.detector_id, url, sp.name, sp.description)

            evidence = FindingEvidence(
                request_url=url,
                request_method=crawl_result.method,
                response_status=crawl_result.status_code,
                response_body_excerpt=context,
                matched_pattern=sp.name,
                injected_payload="",   # Passive — no injection
                injected_parameter=sp.name,
            )

            # Choose vuln_type
            vuln_type = VulnType.SENSITIVE_DATA

            ea_ctx = self._build_ea_context(sp, target)

            finding = Finding(
                id=str(uuid.uuid4()),
                url=url,
                parameter_name=sp.name,
                parameter_location="response_body",
                vuln_type=vuln_type,
                cvss_vector=sp.cvss,
                confidence=0.85,
                evidence=evidence,
                evidence_pattern=sp.name,
                ea_context=ea_ctx,
            )
            findings.append(finding)

        return findings

    @staticmethod
    def _redact_value(value: str) -> str:
        """Show first 4 and last 4 chars, mask the middle."""
        if len(value) <= 8:
            return "*" * len(value)
        return value[:4] + "*" * (len(value) - 8) + value[-4:]

    def _build_ea_context(self, sp: SecretPattern, target) -> dict:
        return {"ea_relevant": False}