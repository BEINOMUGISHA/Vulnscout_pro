"""
ussd_patterns.py — USSD Attack Surface Intelligence

USSD (Unstructured Supplementary Service Data) is the backbone of mobile
services across East Africa. Unlike REST APIs, USSD flows are stateful
session-based dialogs routed through telecom gateways — with unique
vulnerability patterns that standard web scanners miss entirely.

This module provides:
  - USSD session flow patterns and state machine definitions
  - Attack payloads crafted for USSD parameter injection
  - Detection signatures for USSD-exposed web backends
  - Uganda/EA-specific USSD shortcode catalogue
  - Vulnerability patterns unique to USSD gateway integrations

Key USSD vulnerability classes:
  1. Session fixation — USSD sessions identified by MSISDN + sessionId
  2. MSISDN spoofing — gateways trust X-MSISDN headers from aggregators
  3. Input injection — USSD menus accept numeric input; some backends eval it
  4. State manipulation — jumping menu states by replaying session tokens
  5. Race conditions — concurrent USSD sessions on same MSISDN
  6. Gateway authentication bypass — aggregator APIs often use weak auth
  7. Amount tampering — mobile money amounts passed as USSD input

References:
  - GSMA USSD Security Guidelines
  - Uganda Communications Commission (UCC) technical standards
  - Africa's Talking API security model
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Pattern


# ── USSD Session State Model ───────────────────────────────────────────────────

class USSDSessionState(str, Enum):
    INITIATED    = "CON"    # Continuation — session ongoing, awaiting input
    ENDED        = "END"    # Session terminated
    TIMEOUT      = "TIMEOUT"
    ERROR        = "ERROR"


@dataclass
class USSDMenuNode:
    """Represents a single node in a USSD menu tree."""
    node_id: str
    prompt: str
    expected_input_type: str        # "numeric", "alphanumeric", "amount", "pin"
    min_length: int = 1
    max_length: int = 20
    transitions: Dict[str, str] = field(default_factory=dict)  # input → next_node_id
    is_sensitive: bool = False       # PIN entry, confirmation, amount
    is_terminal: bool = False

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "prompt": self.prompt[:80],
            "expected_input": self.expected_input_type,
            "is_sensitive": self.is_sensitive,
            "is_terminal": self.is_terminal,
        }


@dataclass
class USSDFlow:
    """Complete USSD application flow with all states."""
    shortcode: str
    provider: str
    service_name: str
    root_node: USSDMenuNode
    all_nodes: Dict[str, USSDMenuNode] = field(default_factory=dict)
    backend_url: Optional[str] = None         # webhook endpoint if known
    uses_session_token: bool = True
    amount_in_flow: bool = False
    pin_in_flow: bool = False

    @property
    def attack_surface_score(self) -> int:
        """
        Rough attack surface score (0-10).
        Higher = more interesting to test.
        """
        score = 0
        if self.amount_in_flow:
            score += 4
        if self.pin_in_flow:
            score += 3
        if self.backend_url:
            score += 2
        if not self.uses_session_token:
            score += 1
        return score


# ── Uganda/EA USSD Shortcode Catalogue ────────────────────────────────────────

UGANDAN_USSD_SHORTCODES: Dict[str, dict] = {
    # MTN Uganda
    "*165#":  {"provider": "MTN", "service": "MoMo Main Menu",        "has_payments": True},
    "*162#":  {"provider": "MTN", "service": "MoMo Send Money",       "has_payments": True},
    "*164#":  {"provider": "MTN", "service": "MoMo Withdraw",         "has_payments": True},
    "*166#":  {"provider": "MTN", "service": "MoMo Pay Bill",         "has_payments": True},
    "*167#":  {"provider": "MTN", "service": "MoMo Buy Airtime",      "has_payments": True},
    "*170#":  {"provider": "MTN", "service": "MTN Menu",              "has_payments": False},
    "*160#":  {"provider": "MTN", "service": "MTN Balance",           "has_payments": False},

    # Airtel Uganda
    "*185#":  {"provider": "Airtel", "service": "Airtel Money Main",  "has_payments": True},
    "*182#":  {"provider": "Airtel", "service": "Airtel Money Send",  "has_payments": True},
    "*180#":  {"provider": "Airtel", "service": "Airtel Menu",        "has_payments": False},

    # Africell Uganda
    "*100#":  {"provider": "Africell", "service": "Africell Menu",    "has_payments": False},
    "*109#":  {"provider": "Africell", "service": "Africell Money",   "has_payments": True},

    # Common service shortcodes
    "*200#":  {"provider": "Generic", "service": "Customer Care",     "has_payments": False},
    "*131#":  {"provider": "Generic", "service": "Balance Check",     "has_payments": False},

    # Fintech / Banking USSD (common patterns)
    "*222#":  {"provider": "Stanbic", "service": "Stanbic FlexiPay",  "has_payments": True},
    "*288#":  {"provider": "Centenary", "service": "CenteVault",      "has_payments": True},
    "*268#":  {"provider": "DFCU", "service": "DFCU Quick Banking",   "has_payments": True},
    "*220#":  {"provider": "Equity", "service": "Equity Eazzy",       "has_payments": True},
}


# ── USSD-Specific Attack Payloads ──────────────────────────────────────────────

class USSDPayloadCategory(str, Enum):
    SESSION_FIXATION   = "session_fixation"
    MSISDN_SPOOFING    = "msisdn_spoofing"
    INPUT_INJECTION    = "input_injection"
    STATE_MANIPULATION = "state_manipulation"
    AMOUNT_TAMPERING   = "amount_tampering"
    PIN_EXTRACTION     = "pin_extraction"
    RACE_CONDITION     = "race_condition"


@dataclass
class USSDPayload:
    category: USSDPayloadCategory
    payload: str
    parameter_target: str           # Which HTTP param to inject into
    description: str
    severity: str                   # critical, high, medium, low
    evidence_pattern: Optional[str] = None   # Regex to confirm vulnerability

    def to_dict(self) -> dict:
        return {
            "category": self.category.value,
            "payload": self.payload,
            "parameter": self.parameter_target,
            "description": self.description,
            "severity": self.severity,
        }


# Master payload list — all payloads are designed to detect, not exploit
USSD_PAYLOADS: List[USSDPayload] = [

    # ── Session fixation probes ────────────────────────────────────────────────
    USSDPayload(
        category=USSDPayloadCategory.SESSION_FIXATION,
        payload="FIXED_SESSION_001",
        parameter_target="sessionId",
        description="Inject a known sessionId to test session fixation",
        severity="high",
        evidence_pattern=r"CON|Welcome|Menu",
    ),
    USSDPayload(
        category=USSDPayloadCategory.SESSION_FIXATION,
        payload="00000000-0000-0000-0000-000000000000",
        parameter_target="sessionId",
        description="Null UUID session fixation test",
        severity="high",
        evidence_pattern=r"CON|Welcome",
    ),

    # ── MSISDN spoofing probes ────────────────────────────────────────────────
    # Many USSD aggregators pass MSISDN in an HTTP header; if the app trusts
    # this without server-side validation, any MSISDN can be impersonated.
    USSDPayload(
        category=USSDPayloadCategory.MSISDN_SPOOFING,
        payload="256700000000",
        parameter_target="X-MSISDN",
        description="Spoof MSISDN via X-MSISDN header (Africa's Talking pattern)",
        severity="critical",
        evidence_pattern=r"balance|account|name|CON",
    ),
    USSDPayload(
        category=USSDPayloadCategory.MSISDN_SPOOFING,
        payload="256700000000",
        parameter_target="msisdn",
        description="MSISDN spoofing via query parameter",
        severity="critical",
        evidence_pattern=r"balance|account|CON",
    ),
    USSDPayload(
        category=USSDPayloadCategory.MSISDN_SPOOFING,
        payload="256700000000",
        parameter_target="phoneNumber",
        description="MSISDN spoofing via phoneNumber parameter",
        severity="critical",
        evidence_pattern=r"balance|account|CON",
    ),

    # ── Input injection (USSD inputs fed to SQL/code) ──────────────────────────
    USSDPayload(
        category=USSDPayloadCategory.INPUT_INJECTION,
        payload="1' OR '1'='1",
        parameter_target="text",
        description="SQL injection via USSD text input",
        severity="critical",
        evidence_pattern=r"error|sql|mysql|syntax|query",
    ),
    USSDPayload(
        category=USSDPayloadCategory.INPUT_INJECTION,
        payload="1*1*1*1",
        parameter_target="text",
        description="USSD menu traversal injection — wildcard separators",
        severity="medium",
        evidence_pattern=r"CON|invalid|error",
    ),
    USSDPayload(
        category=USSDPayloadCategory.INPUT_INJECTION,
        payload="0#",
        parameter_target="text",
        description="USSD session terminator injection",
        severity="low",
        evidence_pattern=r"END|goodbye|thank you",
    ),
    USSDPayload(
        category=USSDPayloadCategory.INPUT_INJECTION,
        payload="<script>alert(1)</script>",
        parameter_target="text",
        description="XSS via USSD input reflected in web dashboard",
        severity="high",
        evidence_pattern=r"<script>|alert\(1\)",
    ),

    # ── State manipulation ─────────────────────────────────────────────────────
    USSDPayload(
        category=USSDPayloadCategory.STATE_MANIPULATION,
        payload="1*2*3*4*5",
        parameter_target="text",
        description="Deep state jump — skip menu levels via concatenated input",
        severity="high",
        evidence_pattern=r"confirm|amount|PIN|send",
    ),
    USSDPayload(
        category=USSDPayloadCategory.STATE_MANIPULATION,
        payload="00",
        parameter_target="text",
        description="Back-to-root navigation to check for state reset",
        severity="medium",
        evidence_pattern=r"Welcome|Main Menu|CON",
    ),

    # ── Amount tampering ───────────────────────────────────────────────────────
    USSDPayload(
        category=USSDPayloadCategory.AMOUNT_TAMPERING,
        payload="0",
        parameter_target="amount",
        description="Zero amount transaction probe",
        severity="high",
        evidence_pattern=r"success|confirm|proceed",
    ),
    USSDPayload(
        category=USSDPayloadCategory.AMOUNT_TAMPERING,
        payload="-1",
        parameter_target="amount",
        description="Negative amount (credit reversal probe)",
        severity="critical",
        evidence_pattern=r"success|confirm|credited|added",
    ),
    USSDPayload(
        category=USSDPayloadCategory.AMOUNT_TAMPERING,
        payload="0.001",
        parameter_target="amount",
        description="Sub-unit amount probe (below minimum transaction)",
        severity="medium",
        evidence_pattern=r"success|confirm",
    ),
    USSDPayload(
        category=USSDPayloadCategory.AMOUNT_TAMPERING,
        payload="999999999",
        parameter_target="amount",
        description="Overflow amount probe",
        severity="high",
        evidence_pattern=r"error|overflow|invalid|exceeds",
    ),
]


# ── USSD Backend Detection Signatures ─────────────────────────────────────────

@dataclass
class USSDBackendSignature:
    """Identifies a USSD gateway/aggregator integration from HTTP traffic."""
    name: str
    description: str
    header_patterns: List[str] = field(default_factory=list)   # Response header patterns
    body_patterns: List[str] = field(default_factory=list)     # Body content patterns
    path_patterns: List[str] = field(default_factory=list)     # URL path patterns
    param_patterns: List[str] = field(default_factory=list)    # Parameter name patterns
    vendor: str = "unknown"


USSD_BACKEND_SIGNATURES: List[USSDBackendSignature] = [
    USSDBackendSignature(
        name="Africa's Talking USSD",
        vendor="Africa's Talking",
        description="Africa's Talking USSD gateway integration",
        header_patterns=["apiKey", "AT-"],
        body_patterns=["sessionId", "serviceCode", "phoneNumber", "networkCode"],
        path_patterns=["/ussd", "/africastalking", "/at/ussd"],
        param_patterns=["sessionId", "phoneNumber", "networkCode", "serviceCode"],
    ),
    USSDBackendSignature(
        name="Yo! Uganda USSD",
        vendor="Yo! Uganda",
        description="Yo! Payments USSD gateway",
        body_patterns=["MSN", "USSD_STRING", "NETWORK"],
        path_patterns=["/yo/ussd", "/youganda", "/ussd/yo"],
        param_patterns=["MSN", "USSD_STRING", "NETWORK", "SHORTCODE"],
    ),
    USSDBackendSignature(
        name="Comviva USSD",
        vendor="Comviva",
        description="Comviva MobiLytix USSD platform",
        body_patterns=["sessionid", "msisdn", "serviceid"],
        path_patterns=["/comviva", "/mobilitix", "/mvas"],
        param_patterns=["sessionid", "msisdn", "serviceid", "input"],
    ),
    USSDBackendSignature(
        name="Generic USSD Webhook",
        vendor="custom",
        description="Custom USSD backend webhook",
        body_patterns=["CON ", "END ", "sessionId", "MSISDN"],
        path_patterns=["/ussd", "/webhook/ussd", "/api/ussd", "/ussd/callback"],
        param_patterns=["sessionId", "msisdn", "text", "phoneNumber"],
    ),
]


# ── USSD Vulnerability Scanner Helpers ────────────────────────────────────────

class USSDPatternAnalyzer:
    """
    Analyses HTTP requests/responses to identify USSD integration points
    and generate targeted test cases.
    """

    def __init__(self) -> None:
        self._compiled_body: List[tuple] = [
            (sig, [re.compile(p, re.IGNORECASE) for p in sig.body_patterns])
            for sig in USSD_BACKEND_SIGNATURES
        ]
        self._compiled_path: List[tuple] = [
            (sig, [re.compile(p, re.IGNORECASE) for p in sig.path_patterns])
            for sig in USSD_BACKEND_SIGNATURES
        ]

    def identify_backend(
        self,
        url: str,
        response_body: str,
        response_headers: dict,
        request_params: List[str],
    ) -> Optional[USSDBackendSignature]:
        """
        Identify which USSD backend/aggregator is in use.
        Returns the best matching signature or None.
        """
        scores: Dict[str, int] = {}

        for sig, body_patterns in self._compiled_body:
            for pattern in body_patterns:
                if pattern.search(response_body):
                    scores[sig.name] = scores.get(sig.name, 0) + 2

        for sig, path_patterns in self._compiled_path:
            for pattern in path_patterns:
                if pattern.search(url):
                    scores[sig.name] = scores.get(sig.name, 0) + 3

        for sig in USSD_BACKEND_SIGNATURES:
            for param in sig.param_patterns:
                if param in request_params:
                    scores[sig.name] = scores.get(sig.name, 0) + 1

        if not scores:
            return None

        best = max(scores, key=lambda k: scores[k])
        if scores[best] >= 2:
            return next((s for s in USSD_BACKEND_SIGNATURES if s.name == best), None)
        return None

    def get_payloads_for_backend(
        self,
        signature: USSDBackendSignature,
        categories: Optional[List[USSDPayloadCategory]] = None,
    ) -> List[USSDPayload]:
        """Return relevant payloads for a detected USSD backend."""
        if categories:
            return [p for p in USSD_PAYLOADS if p.category in categories]
        # For payment-related backends, prioritise amount tampering and spoofing
        if "money" in signature.name.lower() or "payment" in signature.name.lower():
            priority = {
                USSDPayloadCategory.AMOUNT_TAMPERING,
                USSDPayloadCategory.MSISDN_SPOOFING,
                USSDPayloadCategory.SESSION_FIXATION,
                USSDPayloadCategory.INPUT_INJECTION,
            }
            return [p for p in USSD_PAYLOADS if p.category in priority]
        return USSD_PAYLOADS

    @staticmethod
    def is_ussd_endpoint(url: str, params: List[str]) -> bool:
        """Quick check — is this likely a USSD-related endpoint?"""
        ussd_path_hints = re.compile(
            r"/ussd|/momo|/mobile.?money|/mm/|/wallet|/pay|/shortcode",
            re.IGNORECASE,
        )
        ussd_param_hints = {"sessionId", "msisdn", "phoneNumber", "text",
                            "serviceCode", "networkCode", "USSD_STRING", "MSN"}
        return (
            bool(ussd_path_hints.search(url))
            or bool(ussd_param_hints.intersection(set(params)))
        )

    @staticmethod
    def extract_msisdn_from_body(body: str) -> Optional[str]:
        """
        Extract MSISDN (phone number) from response body.
        Useful for confirming MSISDN reflection vulnerabilities.
        """
        # East African MSISDN patterns: 256XXXXXXXXX, +256XXXXXXXXX, 07XXXXXXXX
        patterns = [
            r'\b256[0-9]{9}\b',
            r'\+256[0-9]{9}\b',
            r'\b07[0-9]{8}\b',
            r'\b254[0-9]{9}\b',   # Kenya
            r'\b255[0-9]{9}\b',   # Tanzania
            r'\b250[0-9]{9}\b',   # Rwanda
        ]
        for pattern in patterns:
            match = re.search(pattern, body)
            if match:
                return match.group(0)
        return None

    @staticmethod
    def build_ussd_flow_map(menu_responses: List[dict]) -> Dict[str, USSDMenuNode]:
        """
        Build a state map from a series of USSD menu responses.
        Used to understand the full flow before targeted testing.
        """
        nodes: Dict[str, USSDMenuNode] = {}
        for i, resp in enumerate(menu_responses):
            body = resp.get("body", "")
            state = "CON" if body.startswith("CON ") else "END"
            prompt = body[4:] if body.startswith(("CON ", "END ")) else body

            node_id = f"node_{i}"
            is_terminal = state == "END"
            is_sensitive = bool(re.search(r"PIN|password|secret|amount|confirm", prompt, re.I))
            expected_type = "pin" if "PIN" in prompt.upper() else \
                           "amount" if re.search(r"amount|how much", prompt, re.I) else \
                           "numeric"

            nodes[node_id] = USSDMenuNode(
                node_id=node_id,
                prompt=prompt[:200],
                expected_input_type=expected_type,
                is_sensitive=is_sensitive,
                is_terminal=is_terminal,
            )
        return nodes


# ── Module-level convenience exports ──────────────────────────────────────────

def get_payloads_by_severity(severity: str) -> List[USSDPayload]:
    return [p for p in USSD_PAYLOADS if p.severity == severity]


def get_payloads_by_category(category: USSDPayloadCategory) -> List[USSDPayload]:
    return [p for p in USSD_PAYLOADS if p.category == category]


def get_shortcode_info(shortcode: str) -> Optional[dict]:
    return UGANDAN_USSD_SHORTCODES.get(shortcode)


# Singleton analyzer for use by detectors
analyzer = USSDPatternAnalyzer()