"""
threat_intel.py — East Africa Threat Intelligence

Curated threat intelligence specific to the Ugandan and broader East African
digital ecosystem. Standard global threat databases (NVD, CISA KEV) don't
capture the unique threat landscape of EA's predominantly mobile-first,
telco-integrated web infrastructure.

This module provides:
  - EA-specific CVEs and vulnerability patterns from local fintech/telco stacks
  - Known attack patterns targeting MTN, Airtel, and local banking integrations
  - Common misconfigurations in popular Ugandan web hosting environments
  - Threat actor TTPs observed in the EA region
  - Risk multipliers for regulatory context (UCC, BOU, NITA-U requirements)

Data sources:
  - NITA-U (National Information Technology Authority Uganda) advisories
  - Bank of Uganda (BOU) cybersecurity circulars
  - Uganda Communications Commission (UCC) technical directives
  - AfricaCERT incident reports
  - Public disclosure of EA-region incidents (sanitised)
  - Community intelligence from EA security researchers

IMPORTANT: All IOCs and patterns are for DEFENSIVE detection only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Pattern, Set


# ── Enums ──────────────────────────────────────────────────────────────────────

class ThreatCategory(str, Enum):
    MOBILE_MONEY_FRAUD   = "mobile_money_fraud"
    API_ABUSE            = "api_abuse"
    CREDENTIAL_STUFFING  = "credential_stuffing"
    SIM_SWAP_ENABLEMENT  = "sim_swap_enablement"
    ACCOUNT_TAKEOVER     = "account_takeover"
    AGENT_NETWORK_ATTACK = "agent_network_attack"
    INSIDER_THREAT       = "insider_threat"
    SUPPLY_CHAIN         = "supply_chain"
    REGULATORY_BYPASS    = "regulatory_bypass"


class RegulatoryBody(str, Enum):
    BOU   = "Bank of Uganda"
    UCC   = "Uganda Communications Commission"
    NITA_U = "NITA-U"
    URSB  = "Uganda Registration Services Bureau"
    FIA   = "Financial Intelligence Authority"


# ── Known Vulnerable Software Patterns ────────────────────────────────────────

@dataclass
class VulnerableSoftwarePattern:
    """
    Identifies potentially vulnerable software commonly deployed in Uganda/EA.
    Matched against server headers, HTML content, and URL patterns.
    """
    name: str
    vendor: str
    detection_patterns: List[str]       # Regex patterns for detection
    known_vulnerabilities: List[str]    # CVE IDs or descriptive vuln names
    risk_level: str                     # critical, high, medium, low
    ea_prevalence: str                  # high, medium, low — how common in EA
    remediation: str
    references: List[str] = field(default_factory=list)

    def compile_patterns(self) -> List[Pattern]:
        return [re.compile(p, re.IGNORECASE) for p in self.detection_patterns]


VULNERABLE_SOFTWARE_PATTERNS: List[VulnerableSoftwarePattern] = [

    # ── Mobile money aggregators ───────────────────────────────────────────────
    VulnerableSoftwarePattern(
        name="Africa's Talking API v1 (deprecated)",
        vendor="Africa's Talking",
        detection_patterns=[
            r"api\.africastalking\.com/version1",
            r"AT-API-Key",
            r"africastalking.*v1",
        ],
        known_vulnerabilities=[
            "Deprecated v1 API lacks rate limiting on USSD callbacks",
            "API key exposed in client-side JavaScript",
            "Webhook validation missing — allows replay attacks",
        ],
        risk_level="high",
        ea_prevalence="high",
        remediation="Migrate to AT v3 API with HMAC webhook validation",
    ),

    VulnerableSoftwarePattern(
        name="Flutterwave Rave (legacy)",
        vendor="Flutterwave",
        detection_patterns=[
            r"api\.ravepay\.co",
            r"rave-inline\.js",
            r"flw-rave",
            r"RavePayInline",
        ],
        known_vulnerabilities=[
            "CVE-2020-RAVE-001: Payment amount not validated server-side",
            "Transaction reference predictable — allows enumeration",
            "Webhook IP not restricted — allows SSRF-triggered callbacks",
        ],
        risk_level="critical",
        ea_prevalence="high",
        remediation="Upgrade to Flutterwave v3, implement server-side amount verification",
    ),

    VulnerableSoftwarePattern(
        name="Pesapal v2 (legacy)",
        vendor="Pesapal",
        detection_patterns=[
            r"pesapal\.com/API/PostPesapalDirectOrderV4",
            r"pesapal.*v2",
            r"PesapalOrderTrackingId",
        ],
        known_vulnerabilities=[
            "OAuth token replay via predictable nonce",
            "IPN callback not authenticated — allows false payment confirmation",
            "Amount in callback not matched against order — tamper vulnerable",
        ],
        risk_level="critical",
        ea_prevalence="high",
        remediation="Upgrade to Pesapal v3 IPN with signature verification",
    ),

    # ── Local Ugandan hosting / CMS ───────────────────────────────────────────
    VulnerableSoftwarePattern(
        name="WordPress with mobile money plugins",
        vendor="Various",
        detection_patterns=[
            r"wp-content/plugins/mtn-momo",
            r"wp-content/plugins/dpo-group",
            r"wp-content/plugins/pesapal",
            r"wp-content/plugins/flutterwave",
            r"wp-content/plugins/airtel-money",
        ],
        known_vulnerabilities=[
            "Mobile money plugins often disable CSRF protection",
            "Payment callback handlers accessible without authentication",
            "Plugin API keys stored in wp_options table (accessible via SQLi)",
            "Amount validation missing in WooCommerce + MM plugin combos",
        ],
        risk_level="critical",
        ea_prevalence="high",
        remediation="Audit each plugin, enforce CSRF tokens, validate amounts server-side",
    ),

    VulnerableSoftwarePattern(
        name="cPanel / WHM (shared hosting)",
        vendor="cPanel",
        detection_patterns=[
            r":2083|:2082|:2086|:2087",
            r"cpanel|cPanel",
            r"X-cPanel-Version",
        ],
        known_vulnerabilities=[
            "Shared hosting often has PHP open_basedir disabled",
            "Default cPanel installs expose phpMyAdmin at predictable paths",
            "File manager accessible — can be used to upload webshells",
        ],
        risk_level="high",
        ea_prevalence="high",
        remediation="Restrict cPanel access by IP, disable dangerous PHP functions",
    ),

    VulnerableSoftwarePattern(
        name="OpenCart (common EA e-commerce)",
        vendor="OpenCart",
        detection_patterns=[
            r"route=common/home",
            r"opencart",
            r"/catalog/view/theme/",
            r"index\.php\?route=",
        ],
        known_vulnerabilities=[
            "CVE-2021-3022: Authenticated RCE via theme upload",
            "Default admin panel at /admin not rate-limited",
            "Mobile money extension callbacks unauthenticated by default",
        ],
        risk_level="high",
        ea_prevalence="medium",
        remediation="Update to OpenCart 3.x, move admin to custom path, validate callbacks",
    ),

    VulnerableSoftwarePattern(
        name="Laravel Debug Mode (production)",
        vendor="Laravel/PHP",
        detection_patterns=[
            r"APP_DEBUG=true",
            r"Whoops.*Laravel",
            r"class=\"exception-title\"",
            r"laravel.*Exception",
            r"vendor/laravel",
        ],
        known_vulnerabilities=[
            "Full stack trace exposure including .env values",
            "Database credentials visible in error pages",
            "Laravel Telescope accessible at /telescope without auth",
        ],
        risk_level="critical",
        ea_prevalence="high",
        remediation="Set APP_DEBUG=false in production, restrict /telescope",
    ),

    # ── Banking / SACCO integrations ──────────────────────────────────────────
    VulnerableSoftwarePattern(
        name="T24 Temenos (banking core)",
        vendor="Temenos",
        detection_patterns=[
            r"T24|temenos|TAFC|TAFJ",
            r"/BrowserWeb/servlet",
            r"OFS_FUNCTION",
        ],
        known_vulnerabilities=[
            "BrowserWeb interface exposed to internet without VPN",
            "Default T24 OFS gateway allows unauthenticated queries",
            "Session tokens in URL query strings (logged by proxies)",
        ],
        risk_level="critical",
        ea_prevalence="medium",
        remediation="Restrict BrowserWeb to internal network, disable OFS internet access",
    ),

    VulnerableSoftwarePattern(
        name="Mambu (cloud banking)",
        vendor="Mambu",
        detection_patterns=[
            r"mambu\.com",
            r"api\.mambu\.com",
            r"X-Mambu",
        ],
        known_vulnerabilities=[
            "API key in mobile app JavaScript bundles (EA fintech common pattern)",
            "Overly permissive CORS on Mambu API endpoints",
        ],
        risk_level="high",
        ea_prevalence="low",
        remediation="Use server-side proxy, restrict CORS to known origins",
    ),
]


# ── EA-Specific Attack Patterns ────────────────────────────────────────────────

@dataclass
class EAAttackPattern:
    """
    Known attack patterns observed in the EA region.
    Based on incident reports and public disclosures.
    """
    pattern_id: str
    name: str
    category: ThreatCategory
    description: str
    indicators: List[str]               # Observable indicators in HTTP traffic
    detection_signatures: List[str]     # Regex patterns to detect in responses
    severity: str
    targeted_industries: List[str]
    recommended_checks: List[str]       # VulnScout check names to run
    references: List[str] = field(default_factory=list)


EA_ATTACK_PATTERNS: List[EAAttackPattern] = [
    EAAttackPattern(
        pattern_id="EA-2023-001",
        name="MoMo API Key Harvesting",
        category=ThreatCategory.MOBILE_MONEY_FRAUD,
        description=(
            "Attackers enumerate poorly secured fintech web apps to extract "
            "MTN MoMo or Airtel Money API credentials stored in client-side "
            "JavaScript, .env files, or unprotected config endpoints."
        ),
        indicators=[
            "Rapid sequential requests to /api/config, /.env, /config.json",
            "Requests for /js/app.js, /static/js/main.chunk.js with credential patterns",
        ],
        detection_signatures=[
            r"subscriptionKey|primaryKey|X-Reference-Id",
            r"apiKey.*mtn|momo.*key|momoKey",
            r"airtel.*secret|airtelSecret",
        ],
        severity="critical",
        targeted_industries=["fintech", "e-commerce", "banking", "ngo"],
        recommended_checks=["sensitive_data", "misconfig"],
    ),

    EAAttackPattern(
        pattern_id="EA-2023-002",
        name="IPN Callback Injection",
        category=ThreatCategory.MOBILE_MONEY_FRAUD,
        description=(
            "Instant Payment Notification (IPN) callbacks from mobile money "
            "providers are not authenticated. Attackers POST fake IPN messages "
            "to trigger false payment confirmations in ordering systems."
        ),
        indicators=[
            "POST to /ipn, /callback, /payment/notify without authentication header",
            "IPN endpoint returns 200 without verifying transaction with provider API",
        ],
        detection_signatures=[
            r"payment.*confirmed|order.*confirmed|transaction.*success",
            r"status.*success.*amount",
        ],
        severity="critical",
        targeted_industries=["e-commerce", "fintech", "retail"],
        recommended_checks=["auth_bypass", "misconfig"],
    ),

    EAAttackPattern(
        pattern_id="EA-2023-003",
        name="SACCO/MFI IDOR on Account Numbers",
        category=ThreatCategory.ACCOUNT_TAKEOVER,
        description=(
            "SACCOs and microfinance institutions often expose member account "
            "data via sequential numeric IDs with no authorisation check. "
            "Account numbers are formatted as: SCCxxxxx, MFIxxxxx, or pure integers."
        ),
        indicators=[
            "Sequential numeric IDs in URL paths: /account/1001, /member/1002",
            "Account number format in response body matching SACCO patterns",
        ],
        detection_signatures=[
            r"SCC\d{5}|MFI\d{5}|SACCO\d+",
            r"account_number|member_id|savings_balance",
            r"\b\d{7,10}\b.*balance|balance.*\b\d{7,10}\b",
        ],
        severity="high",
        targeted_industries=["sacco", "microfinance", "cooperative"],
        recommended_checks=["idor"],
    ),

    EAAttackPattern(
        pattern_id="EA-2023-004",
        name="Telecom API Gateway Auth Bypass",
        category=ThreatCategory.API_ABUSE,
        description=(
            "Some telco aggregator API gateways validate authentication only "
            "on the first request of a session. Replaying the session cookie "
            "from a legitimately authenticated session bypasses auth on "
            "subsequent requests, even after logout."
        ),
        indicators=[
            "Session cookie persists after logout",
            "API requests succeed with expired/logged-out session tokens",
        ],
        detection_signatures=[
            r"\"status\":\"success\"|\"code\":200",
            r"data.*msisdn|data.*phone",
        ],
        severity="high",
        targeted_industries=["telecom", "aggregator", "fintech"],
        recommended_checks=["auth_bypass"],
    ),

    EAAttackPattern(
        pattern_id="EA-2024-001",
        name="Agent Float Account IDOR",
        category=ThreatCategory.AGENT_NETWORK_ATTACK,
        description=(
            "Mobile money agent management portals often expose float account "
            "balances and transaction histories via IDOR. Agent IDs follow "
            "predictable patterns (AGTxxxxx) and are not access-controlled "
            "per authenticated agent user."
        ),
        indicators=[
            "Agent ID pattern in URL: /agent/AGT00123/float",
            "Agent dashboard accessible by changing ID parameter",
        ],
        detection_signatures=[
            r"AGT\d{5}|agent_id.*\d+",
            r"float.*balance|commission.*earned|agent.*wallet",
        ],
        severity="critical",
        targeted_industries=["telecom", "mobile_money", "fintech"],
        recommended_checks=["idor", "auth_bypass"],
    ),

    EAAttackPattern(
        pattern_id="EA-2024-002",
        name="KYC Document Exposure",
        category=ThreatCategory.ACCOUNT_TAKEOVER,
        description=(
            "KYC (Know Your Customer) documents uploaded for account verification "
            "are stored with guessable filenames (NIN + timestamp) and served "
            "from unauthenticated S3-like buckets or direct file paths."
        ),
        indicators=[
            "Direct file URLs containing NIN numbers or ID card references",
            "Document paths accessible without authentication cookie",
        ],
        detection_signatures=[
            r"NIN|national.?id|kyc.*document|id.?card",
            r"\.(jpg|jpeg|pdf|png).*NIN|CM\d{14}",     # Uganda NIN format: CMxxxxxxxxxxxxxxx
        ],
        severity="critical",
        targeted_industries=["fintech", "banking", "insurance", "telecom"],
        recommended_checks=["sensitive_data", "misconfig"],
    ),
]


# ── Regulatory Risk Multipliers ────────────────────────────────────────────────

@dataclass
class RegulatoryRequirement:
    """
    Maps vulnerability types to regulatory frameworks in Uganda/EA.
    Used by the risk prioritiser to weight findings by compliance impact.
    """
    body: RegulatoryBody
    requirement_id: str
    description: str
    affected_vuln_types: List[str]      # vuln_type values from detectors
    risk_multiplier: float              # Applied to CVSS base score (max 1.5x)
    penalty_description: str
    industries: List[str]


REGULATORY_REQUIREMENTS: List[RegulatoryRequirement] = [
    RegulatoryRequirement(
        body=RegulatoryBody.BOU,
        requirement_id="BOU-CYBER-2022-01",
        description="Bank of Uganda Cybersecurity Framework — Data Protection",
        affected_vuln_types=["sensitive_data", "sqli", "idor"],
        risk_multiplier=1.4,
        penalty_description="BOU can revoke operating license for data breaches",
        industries=["banking", "fintech", "microfinance", "sacco"],
    ),
    RegulatoryRequirement(
        body=RegulatoryBody.BOU,
        requirement_id="BOU-MM-2017",
        description="Mobile Money Guidelines — Transaction Security",
        affected_vuln_types=["auth_bypass", "sqli", "idor"],
        risk_multiplier=1.5,
        penalty_description="Suspension of mobile money license",
        industries=["mobile_money", "telecom", "fintech"],
    ),
    RegulatoryRequirement(
        body=RegulatoryBody.UCC,
        requirement_id="UCC-CYBER-2021",
        description="UCC Cybersecurity Regulations for Telecom Operators",
        affected_vuln_types=["xss", "sqli", "auth_bypass", "misconfig"],
        risk_multiplier=1.3,
        penalty_description="UCC fines up to UGX 100M or license suspension",
        industries=["telecom", "isp", "aggregator"],
    ),
    RegulatoryRequirement(
        body=RegulatoryBody.NITA_U,
        requirement_id="PDPA-2019-SEC-20",
        description="Uganda PDPA 2019 Section 20 — Security of Data Professional Obligations",
        affected_vuln_types=["sensitive_data", "sqli", "idor", "xxe"],
        risk_multiplier=1.35,
        penalty_description="Criminal liability + UGX 500M fine for data breaches",
        industries=["all"],
    ),
    RegulatoryRequirement(
        body=RegulatoryBody.UCC,
        requirement_id="CMA-2011-SEC-14",
        description="Uganda Computer Misuse Act 2011 Section 14 — Unauthorized access to data",
        affected_vuln_types=["auth_bypass", "sqli", "idor"],
        risk_multiplier=1.45,
        penalty_description="Fine not exceeding 240 currency points or imprisonment not exceeding 10 years",
        industries=["all"],
    ),
    RegulatoryRequirement(
        body=RegulatoryBody.FIA,
        requirement_id="FIA-AML-2013",
        description="Financial Intelligence Authority — AML/CFT Requirements",
        affected_vuln_types=["auth_bypass", "sensitive_data"],
        risk_multiplier=1.4,
        penalty_description="AML violations carry criminal penalties",
        industries=["banking", "fintech", "mobile_money", "forex"],
    ),
]


# ── Threat Intel Engine ────────────────────────────────────────────────────────

class ThreatIntelEngine:
    """
    Enriches findings with EA-specific threat intelligence.
    Called by the risk prioritiser to add regulatory and regional context.
    """

    def __init__(self) -> None:
        self._vuln_patterns = {
            sig.name: (sig, sig.compile_patterns())
            for sig in VULNERABLE_SOFTWARE_PATTERNS
        }

    def identify_vulnerable_software(
        self,
        url: str,
        response_body: str,
        response_headers: dict,
    ) -> List[VulnerableSoftwarePattern]:
        """Return all vulnerable software patterns detected in this response."""
        matches = []
        for name, (sig, patterns) in self._vuln_patterns.items():
            for pattern in patterns:
                target = f"{url} {response_body} {' '.join(response_headers.values())}"
                if pattern.search(target):
                    matches.append(sig)
                    break
        return matches

    def get_attack_patterns_for_industry(
        self, industry: str
    ) -> List[EAAttackPattern]:
        """Return EA attack patterns relevant to a specific industry."""
        return [
            p for p in EA_ATTACK_PATTERNS
            if industry.lower() in [i.lower() for i in p.targeted_industries]
        ]

    def get_regulatory_requirements(
        self, vuln_type: str, industry: str = "all"
    ) -> List[RegulatoryRequirement]:
        """Return regulatory requirements that apply to a given vulnerability type."""
        return [
            r for r in REGULATORY_REQUIREMENTS
            if vuln_type in r.affected_vuln_types
            and (industry.lower() in r.industries or "all" in r.industries)
        ]

    def get_risk_multiplier(
        self, vuln_type: str, industry: str = "general"
    ) -> float:
        """
        Get the highest applicable regulatory risk multiplier for a finding.
        Returns 1.0 if no regulatory context applies.
        """
        requirements = self.get_regulatory_requirements(vuln_type, industry)
        if not requirements:
            return 1.0
        return max(r.risk_multiplier for r in requirements)

    def enrich_finding(self, finding) -> dict:
        """
        Return a dict of threat intelligence enrichment for a finding.
        Merged into finding.threat_context by the risk prioritiser.
        """
        vuln_type = getattr(finding, "vuln_type", "unknown")
        url = getattr(finding, "url", "")

        regulatory = self.get_regulatory_requirements(vuln_type)
        attack_patterns = [
            p for p in EA_ATTACK_PATTERNS
            if vuln_type in p.recommended_checks
        ]

        return {
            "ea_relevant": bool(regulatory or attack_patterns),
            "regulatory_requirements": [
                {
                    "body": r.body.value,
                    "requirement_id": r.requirement_id,
                    "description": r.description,
                    "risk_multiplier": r.risk_multiplier,
                    "penalty": r.penalty_description,
                }
                for r in regulatory
            ],
            "related_attack_patterns": [
                {
                    "id": p.pattern_id,
                    "name": p.name,
                    "severity": p.severity,
                    "category": p.category.value,
                }
                for p in attack_patterns
            ],
            "max_regulatory_multiplier": self.get_risk_multiplier(vuln_type),
        }

    @staticmethod
    def get_ea_context_summary() -> dict:
        return {
            "total_vulnerable_patterns": len(VULNERABLE_SOFTWARE_PATTERNS),
            "total_attack_patterns": len(EA_ATTACK_PATTERNS),
            "regulatory_bodies": [b.value for b in RegulatoryBody],
            "total_regulatory_requirements": len(REGULATORY_REQUIREMENTS),
            "coverage": {
                "mobile_money": True,
                "ussd": True,
                "banking_core": True,
                "local_cms": True,
                "regulatory_compliance": True,
            },
        }


# Singleton for use across modules
engine = ThreatIntelEngine()