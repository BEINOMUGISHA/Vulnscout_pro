"""
mobile_money/base_provider.py — Abstract Mobile Money Provider

Defines the base interface and shared vulnerability patterns for all
mobile money provider integrations in VulnScout Pro.

Mobile money platforms are the highest-value attack surface in Uganda/EA —
a single vulnerability can expose millions of transactions. This base class
ensures every provider implementation tests the same core vulnerability classes
with provider-specific extensions on top.

Core vulnerability classes for all MM providers:
  1. API credential exposure         — keys in JS/HTML/config files
  2. Callback/IPN forgery            — webhook endpoint with no auth
  3. Amount tampering                — client-supplied amounts not server-verified
  4. Transaction reference IDOR      — predictable/sequential transaction IDs
  5. Race conditions                 — duplicate payments via concurrent requests
  6. PIN/token extraction            — session replay, token fixation
  7. Insufficient TLS                — weak cipher suites on payment endpoints
  8. Redirect URL injection          — unvalidated returnUrl/redirectUrl
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ── Shared vulnerability test templates ───────────────────────────────────────

@dataclass
class MMVulnTest:
    """A single vulnerability test for a mobile money integration."""
    test_id: str
    name: str
    description: str
    vuln_class: str            # Maps to detection module vuln_type
    severity: str
    http_method: str
    endpoint_pattern: str     # Regex matching endpoints to test
    payload: Optional[str]
    payload_parameter: str
    evidence_pattern: str     # Regex to confirm vulnerability in response
    false_positive_check: Optional[str] = None  # Regex that indicates FP
    requires_auth: bool = False
    provider: str = "generic"

    def to_dict(self) -> dict:
        return {
            "test_id": self.test_id,
            "name": self.name,
            "vuln_class": self.vuln_class,
            "severity": self.severity,
            "provider": self.provider,
        }


# ── Generic MM tests applied to ALL providers ─────────────────────────────────

GENERIC_MM_TESTS: List[MMVulnTest] = [

    # IPN/callback authentication
    MMVulnTest(
        test_id="MM-GEN-001",
        name="Unauthenticated IPN/Callback Endpoint",
        description=(
            "POST a fake payment notification to the IPN/callback endpoint "
            "without any authentication headers. If the app processes it, "
            "orders can be confirmed without real payment."
        ),
        vuln_class="auth_bypass",
        severity="critical",
        http_method="POST",
        endpoint_pattern=r"/ipn|/callback|/notify|/payment.*notify|/webhook.*pay",
        payload='{"status":"SUCCESS","amount":"100","reference":"FAKE_REF_001"}',
        payload_parameter="body",
        evidence_pattern=r"order.*confirm|payment.*success|thank.*you|status.*200",
        false_positive_check=r"invalid.*signature|unauthorized|401|403",
        provider="generic",
    ),

    # Amount tampering via POST body
    MMVulnTest(
        test_id="MM-GEN-002",
        name="Amount Tampering — Client-Supplied Amount",
        description=(
            "Modify the transaction amount to a lower value at checkout. "
            "If the backend processes the client-supplied amount without "
            "verifying against the order total, payment is accepted at wrong amount."
        ),
        vuln_class="sqli",   # Reuses injector path; actually a logic flaw
        severity="critical",
        http_method="POST",
        endpoint_pattern=r"/payment|/checkout|/pay|/initiate.*transaction",
        payload="1",
        payload_parameter="amount",
        evidence_pattern=r"transaction.*initiated|payment.*started|reference.*generated",
        false_positive_check=r"invalid.*amount|minimum.*amount|amount.*required",
        provider="generic",
    ),

    # Negative amount
    MMVulnTest(
        test_id="MM-GEN-003",
        name="Negative Amount Transaction",
        description="Submit a negative transaction amount to test for credit reversal.",
        vuln_class="sqli",
        severity="critical",
        http_method="POST",
        endpoint_pattern=r"/payment|/checkout|/pay",
        payload="-100",
        payload_parameter="amount",
        evidence_pattern=r"transaction.*initiated|payment.*started",
        false_positive_check=r"invalid|negative|must be positive",
        provider="generic",
    ),

    # Transaction reference enumeration
    MMVulnTest(
        test_id="MM-GEN-004",
        name="Transaction Reference IDOR",
        description=(
            "Probe sequential transaction reference IDs to access other users' "
            "payment details."
        ),
        vuln_class="idor",
        severity="high",
        http_method="GET",
        endpoint_pattern=r"/transaction/|/payment/status|/order/",
        payload="TXN000001",
        payload_parameter="reference",
        evidence_pattern=r"amount|msisdn|phone|payer|status",
        false_positive_check=r"not found|403|401|invalid",
        provider="generic",
    ),

    # Open redirect via returnUrl
    MMVulnTest(
        test_id="MM-GEN-005",
        name="Open Redirect via Return URL",
        description=(
            "Inject a malicious returnUrl/redirectUrl to redirect users to "
            "phishing sites after payment."
        ),
        vuln_class="misconfig",
        severity="medium",
        http_method="POST",
        endpoint_pattern=r"/payment|/checkout|/initiate",
        payload="https://evil.example.com/phish",
        payload_parameter="returnUrl",
        evidence_pattern=r"Location: https://evil|redirect.*evil",
        false_positive_check=r"invalid.*url|url.*not allowed",
        provider="generic",
    ),

    # SSL/TLS check (informational)
    MMVulnTest(
        test_id="MM-GEN-006",
        name="Payment Endpoint Missing HTTPS",
        description="Payment endpoint served over HTTP instead of HTTPS.",
        vuln_class="misconfig",
        severity="critical",
        http_method="GET",
        endpoint_pattern=r"^http://.*payment|^http://.*checkout|^http://.*pay",
        payload="",
        payload_parameter="",
        evidence_pattern=r".*",  # Any response over HTTP is a finding
        provider="generic",
    ),
]


# ── Base provider class ────────────────────────────────────────────────────────

class BaseMobileMoneyProvider(ABC):
    """
    Abstract base class for mobile money provider integrations.

    Each concrete provider (MTN MoMo, Airtel Money) extends this class with:
      - Provider-specific API endpoint patterns
      - Credential exposure signatures
      - Provider-specific vulnerability tests
      - Integration-specific IPN/callback patterns

    Usage by detectors:
        provider = MTNMoMoProvider()
        tests = provider.get_tests_for_endpoint(url, params)
        for test in tests:
            result = await injector.inject(...)
            if provider.confirm_vulnerability(test, result):
                yield Finding(...)
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable provider name."""

    @property
    @abstractmethod
    def provider_id(self) -> str:
        """Short identifier: 'mtn_momo', 'airtel_money'."""

    @property
    @abstractmethod
    def credential_patterns(self) -> List[re.Pattern]:
        """
        Regex patterns that match exposed API credentials for this provider.
        Used by the sensitive_data detector.
        """

    @property
    @abstractmethod
    def endpoint_patterns(self) -> List[re.Pattern]:
        """URL patterns that indicate this provider's API is in use."""

    @property
    @abstractmethod
    def provider_tests(self) -> List[MMVulnTest]:
        """Provider-specific vulnerability tests beyond the generic set."""

    # ── Concrete shared methods ────────────────────────────────────────────────

    def get_all_tests(self) -> List[MMVulnTest]:
        """Return generic tests + provider-specific tests."""
        return GENERIC_MM_TESTS + self.provider_tests

    def get_tests_for_endpoint(
        self,
        url: str,
        params: List[str],
        severity_filter: Optional[List[str]] = None,
    ) -> List[MMVulnTest]:
        """Return tests applicable to a specific endpoint."""
        applicable = []
        for test in self.get_all_tests():
            try:
                if re.search(test.endpoint_pattern, url, re.IGNORECASE):
                    if severity_filter is None or test.severity in severity_filter:
                        applicable.append(test)
            except re.error:
                continue
        return applicable

    def is_provider_endpoint(self, url: str, body: str, headers: dict) -> bool:
        """Quick check — does this URL/response involve this provider?"""
        for pattern in self.endpoint_patterns:
            if pattern.search(url):
                return True
        content = f"{body} {' '.join(headers.values())}"
        for pattern in self.credential_patterns:
            if pattern.search(content):
                return True
        return False

    def confirm_vulnerability(
        self, test: MMVulnTest, response_body: str, status_code: int
    ) -> tuple:
        """
        Check if a test response confirms a vulnerability.
        Returns (confirmed: bool, evidence: str).
        """
        if not response_body:
            return False, "Empty response"

        try:
            evidence_match = re.search(
                test.evidence_pattern, response_body, re.IGNORECASE | re.DOTALL
            )
        except re.error:
            return False, "Invalid evidence pattern"

        if not evidence_match:
            return False, "Evidence pattern not found in response"

        # Check false positive signals
        if test.false_positive_check:
            try:
                fp_match = re.search(
                    test.false_positive_check, response_body, re.IGNORECASE
                )
                if fp_match:
                    return False, f"False positive signal found: {fp_match.group(0)[:50]}"
            except re.error:
                pass

        # Status code check
        if status_code in (401, 403):
            return False, f"Request rejected with {status_code}"

        evidence_text = evidence_match.group(0)[:100]
        return True, f"Evidence: '{evidence_text}' in response (status {status_code})"

    def extract_credentials_from_body(self, body: str) -> List[Dict[str, str]]:
        """
        Extract any exposed API credentials from a response body.
        Returns list of {credential_type, value, pattern} dicts.
        """
        found = []
        for pattern in self.credential_patterns:
            for match in pattern.finditer(body):
                found.append({
                    "credential_type": self.provider_id,
                    "pattern": pattern.pattern,
                    "context": body[max(0, match.start()-20):match.end()+20],
                })
        return found

    def get_probe_endpoints(self) -> List[Dict[str, str]]:
        """
        Return endpoint paths to proactively probe on detected targets.
        Each dict has: path, method, description.
        """
        return []

    def build_finding_context(self, test: MMVulnTest, url: str) -> dict:
        """Build the context dict attached to a Finding for this provider."""
        return {
            "provider": self.name,
            "provider_id": self.provider_id,
            "test_id": test.test_id,
            "test_name": test.name,
            "vuln_class": test.vuln_class,
            "ea_context": True,
            "regulatory_exposure": [
                "BOU Mobile Money Guidelines",
                "Uganda Data Protection and Privacy Act 2019",
                "FIA AML/CFT Requirements",
            ],
        }


# ── Provider registry ──────────────────────────────────────────────────────────

class MobileMoneyProviderRegistry:
    """Registry of all active mobile money provider modules."""

    def __init__(self) -> None:
        self._providers: Dict[str, BaseMobileMoneyProvider] = {}

    def register(self, provider: BaseMobileMoneyProvider) -> None:
        self._providers[provider.provider_id] = provider

    def get(self, provider_id: str) -> Optional[BaseMobileMoneyProvider]:
        return self._providers.get(provider_id)

    def all_providers(self) -> List[BaseMobileMoneyProvider]:
        return list(self._providers.values())

    def detect_provider(
        self, url: str, body: str, headers: dict
    ) -> Optional[BaseMobileMoneyProvider]:
        """Return the first provider that claims this endpoint."""
        for provider in self._providers.values():
            if provider.is_provider_endpoint(url, body, headers):
                return provider
        return None

    def detect_all_providers(
        self, url: str, body: str, headers: dict
    ) -> List[BaseMobileMoneyProvider]:
        """Return all providers that match this endpoint (there can be multiple)."""
        return [
            p for p in self._providers.values()
            if p.is_provider_endpoint(url, body, headers)
        ]


# Module-level registry
registry = MobileMoneyProviderRegistry()