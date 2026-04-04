"""
local_frameworks.py — Uganda/EA Local Framework & Stack Fingerprinting

East African web applications are built on a distinct mix of global frameworks
deployed in local configurations, homegrown fintech platforms, and regional
SaaS products. This module fingerprints these stacks and maps them to their
known vulnerability surfaces.

Frameworks and platforms covered:
  - Uganda Revenue Authority (URA) integration patterns
  - National Social Security Fund (NSSF) API patterns
  - Local e-government portals (NIRA, URSB, KCCA)
  - EA-region fintech (Kopo Kopo, Craft Silicon, Interswitch)
  - Local hosting configurations (Raxio, ICTEA, Pearl Networks)
  - Common PHP frameworks deployed locally
  - Government payment gateway (URA e-Tax, GePG Tanzania)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Pattern


# ── Framework fingerprint ──────────────────────────────────────────────────────

@dataclass
class FrameworkFingerprint:
    """
    Identifies a specific framework, platform, or stack from HTTP signals.
    Each fingerprint maps to known vulnerability patterns for that platform.
    """
    name: str
    category: str               # "government", "fintech", "cms", "framework", "hosting"
    description: str
    country_context: str        # "uganda", "kenya", "ea_region", "global_ea_deployed"

    # Detection signals
    header_patterns: List[str] = field(default_factory=list)
    body_patterns: List[str] = field(default_factory=list)
    url_patterns: List[str] = field(default_factory=list)
    cookie_patterns: List[str] = field(default_factory=list)
    response_code_patterns: Dict[str, int] = field(default_factory=dict)  # path → expected code

    # Vulnerability intelligence
    common_vulns: List[str] = field(default_factory=list)
    default_credentials: List[Dict[str, str]] = field(default_factory=list)
    exposed_paths: List[str] = field(default_factory=list)    # Paths to probe
    injectable_params: List[str] = field(default_factory=list)

    severity_weight: float = 1.0    # Multiplier on base CVSS score for this stack
    references: List[str] = field(default_factory=list)

    def compile_patterns(self) -> Dict[str, List[Pattern]]:
        return {
            "header": [re.compile(p, re.IGNORECASE) for p in self.header_patterns],
            "body":   [re.compile(p, re.IGNORECASE) for p in self.body_patterns],
            "url":    [re.compile(p, re.IGNORECASE) for p in self.url_patterns],
            "cookie": [re.compile(p, re.IGNORECASE) for p in self.cookie_patterns],
        }

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "country_context": self.country_context,
            "common_vulns": self.common_vulns,
            "exposed_paths": self.exposed_paths,
            "severity_weight": self.severity_weight,
        }


# ── Framework Registry ─────────────────────────────────────────────────────────

FRAMEWORK_REGISTRY: List[FrameworkFingerprint] = [

    # ── Uganda Government Portals ──────────────────────────────────────────────

    FrameworkFingerprint(
        name="URA eTax Portal",
        category="government",
        description="Uganda Revenue Authority online tax management system",
        country_context="uganda",
        url_patterns=[r"ura\.go\.ug", r"etax\.ura\.go\.ug", r"ura.*etax"],
        body_patterns=[r"URA|Uganda Revenue Authority", r"TIN|tax.*identification"],
        cookie_patterns=[r"URA_SESSION", r"etax"],
        common_vulns=[
            "Session tokens in URL query parameters",
            "TIN number enumeration via profile lookup",
            "IDOR on tax return documents by TIN",
            "File upload without type validation (returns/documents)",
        ],
        exposed_paths=[
            "/etax/",
            "/etax/login",
            "/api/taxpayer/",
            "/reports/",
        ],
        injectable_params=["tin", "taxPayerName", "returnId", "period"],
        severity_weight=1.4,
    ),

    FrameworkFingerprint(
        name="NIRA (National Identification) Portal",
        category="government",
        description="Uganda National Identification & Registration Authority",
        country_context="uganda",
        url_patterns=[r"nira\.go\.ug", r"verify\.nira"],
        body_patterns=[r"NIRA|National Identification", r"NIN.*verify", r"CardNumber"],
        common_vulns=[
            "NIN verification endpoint accessible without rate limiting",
            "Personal data returned in full on NIN lookup (PDPA violation)",
            "IDOR on registration records",
            "API lacks authentication for verification endpoint",
        ],
        exposed_paths=[
            "/api/verify",
            "/nin/verify",
            "/api/citizen",
        ],
        injectable_params=["nin", "cardNumber", "surname", "dateOfBirth"],
        severity_weight=1.5,
    ),

    FrameworkFingerprint(
        name="URSB Business Portal",
        category="government",
        description="Uganda Registration Services Bureau company registry",
        country_context="uganda",
        url_patterns=[r"ursb\.go\.ug"],
        body_patterns=[r"URSB|business.*registration|company.*search"],
        common_vulns=[
            "Company search leaks full director PII without auth",
            "Document download IDOR (file ID increment)",
            "Registration number enumeration",
        ],
        exposed_paths=["/api/company/", "/company/search", "/documents/"],
        injectable_params=["companyNumber", "companyName", "directorId"],
        severity_weight=1.2,
    ),

    FrameworkFingerprint(
        name="NSSF Uganda Member Portal",
        category="government",
        description="National Social Security Fund member self-service",
        country_context="uganda",
        url_patterns=[r"nssf\.or\.ug", r"my\.nssf"],
        body_patterns=[r"NSSF|national social security", r"member.*number"],
        cookie_patterns=[r"NSSF_SESSION"],
        common_vulns=[
            "Member number (NSSF ID) is sequential — IDOR on statements",
            "Employer contribution data accessible by member (oversharing)",
            "PDF statements served from unauthenticated paths",
            "Benefit calculation inputs not validated (integer overflow)",
        ],
        exposed_paths=[
            "/member/statement",
            "/api/member/",
            "/employer/",
        ],
        injectable_params=["memberNumber", "employerId", "period", "nin"],
        severity_weight=1.3,
    ),

    FrameworkFingerprint(
        name="KCCA e-Services Portal",
        category="government",
        description="Kampala Capital City Authority digital services",
        country_context="uganda",
        url_patterns=[r"kcca\.go\.ug"],
        body_patterns=[r"KCCA|Kampala Capital City"],
        common_vulns=[
            "Business permit IDOR by permit number",
            "Property rates lookup exposes owner PII",
            "Payment callback handler unauthenticated",
        ],
        exposed_paths=["/permit/", "/property/", "/payment/callback"],
        injectable_params=["permitNo", "propertyId", "businessId"],
        severity_weight=1.2,
    ),

    # ── Regional Fintech Platforms ─────────────────────────────────────────────

    FrameworkFingerprint(
        name="Craft Silicon eMobile",
        category="fintech",
        description="Craft Silicon mobile banking platform (widely deployed EA)",
        country_context="ea_region",
        url_patterns=[r"craftsilicon", r"emobile", r"craft.*banking"],
        body_patterns=[r"eMobile|Craft Silicon", r"craft.*bank"],
        header_patterns=[r"X-Craft-", r"CS-API"],
        common_vulns=[
            "Default admin credentials: admin/admin on installation",
            "Transaction history IDOR by account number",
            "PIN reset via SMS OTP with predictable token format",
            "Mobile API lacks certificate pinning",
        ],
        default_credentials=[
            {"username": "admin", "password": "admin"},
            {"username": "sysadmin", "password": "sysadmin123"},
            {"username": "craftadmin", "password": "craft@123"},
        ],
        exposed_paths=[
            "/emobile/admin",
            "/api/v1/account/",
            "/api/v1/transaction/",
            "/admin/",
        ],
        injectable_params=["accountNumber", "customerId", "transactionId"],
        severity_weight=1.45,
    ),

    FrameworkFingerprint(
        name="Interswitch Webpay (EA)",
        category="fintech",
        description="Interswitch payment gateway (common in Uganda, Kenya, Nigeria)",
        country_context="ea_region",
        url_patterns=[r"interswitchng|webpay\.interswitchng", r"isw"],
        body_patterns=[r"Interswitch|WebPAY|isw_pay"],
        common_vulns=[
            "MAC signature not validated on some merchant integrations",
            "Transaction reference predictable — allows status enumeration",
            "Redirect URL not validated — open redirect to phishing sites",
        ],
        exposed_paths=["/webpay/", "/api/v2/purchases/"],
        injectable_params=["merchantCode", "payItemId", "amount", "redirectUrl"],
        severity_weight=1.3,
    ),

    FrameworkFingerprint(
        name="Kopo Kopo Connect",
        category="fintech",
        description="Kopo Kopo merchant payment platform (Kenya/EA)",
        country_context="ea_region",
        url_patterns=[r"kopokopo|k2\.co\.ke", r"app\.kopokopo"],
        body_patterns=[r"KopoKopo|k2.*merchant"],
        header_patterns=[r"X-KopoKopo"],
        common_vulns=[
            "Webhook endpoint lacks signature verification on older integrations",
            "Merchant ID enumeration via payment link patterns",
        ],
        exposed_paths=["/api/v1/", "/webhooks/"],
        injectable_params=["merchantId", "callbackUrl", "amount"],
        severity_weight=1.2,
    ),

    FrameworkFingerprint(
        name="DPO Group PayGate",
        category="fintech",
        description="DPO (Direct Pay Online) payment gateway widely used in EA",
        country_context="ea_region",
        url_patterns=[r"secure\.3gdirectpay|dpo.*pay", r"3gdirectpay"],
        body_patterns=[r"DPO|3G Direct Pay|CompanyToken"],
        common_vulns=[
            "CompanyToken exposed in HTML source or JS files",
            "Transaction verification not performed after payment (IPN forgery)",
            "XML payload in CreateToken not sanitised (XXE risk)",
        ],
        exposed_paths=["/API/v6/", "/payv2.php"],
        injectable_params=["CompanyToken", "Request", "TransactionToken"],
        severity_weight=1.35,
    ),

    # ── Local Hosting / Infrastructure ─────────────────────────────────────────

    FrameworkFingerprint(
        name="PHP 5.x / 7.0 (EOL)",
        category="framework",
        description="End-of-life PHP versions common on legacy EA hosting",
        country_context="global_ea_deployed",
        header_patterns=[
            r"X-Powered-By: PHP/5\.",
            r"X-Powered-By: PHP/7\.0",
            r"X-Powered-By: PHP/7\.1",
        ],
        body_patterns=[r"PHP Version 5\.|PHP Version 7\.0"],
        common_vulns=[
            "Multiple EOL CVEs with public exploits",
            "PHP 5.x type juggling vulnerabilities in authentication",
            "register_globals may be enabled",
            "magic_quotes may be disabled without proper escaping",
        ],
        exposed_paths=["/phpinfo.php", "/info.php", "/php.php"],
        severity_weight=1.3,
    ),

    FrameworkFingerprint(
        name="Shared cPanel Hosting (Uganda ISPs)",
        category="hosting",
        description="Shared hosting environment from Ugandan ISPs (MTN, Airtel, ICTEA)",
        country_context="uganda",
        url_patterns=[r":2083|/cpanel|/cPanel"],
        header_patterns=[r"X-cPanel-Version", r"Server: LiteSpeed"],
        body_patterns=[r"cPanel|Webmail|WHM"],
        common_vulns=[
            "phpMyAdmin accessible at /phpmyadmin/ without IP restriction",
            "Default MySQL root password on some ISP provisioned accounts",
            "File permissions set too broadly (777 on upload directories)",
            ".htaccess not enforced on IIS-based shared hosts",
        ],
        default_credentials=[
            {"service": "cPanel", "username": "root", "password": ""},
            {"service": "phpMyAdmin", "username": "root", "password": ""},
        ],
        exposed_paths=[
            "/phpmyadmin/",
            "/phpMyAdmin/",
            "/.env",
            "/wp-config.php",
            "/config.php",
            "/database.php",
        ],
        severity_weight=1.2,
    ),

    FrameworkFingerprint(
        name="CodeIgniter (common EA PHP framework)",
        category="framework",
        description="CodeIgniter PHP framework — popular in EA for custom systems",
        country_context="global_ea_deployed",
        url_patterns=[r"/index\.php/", r"ci_session"],
        body_patterns=[r"CodeIgniter|A PHP Error Was Encountered"],
        cookie_patterns=[r"ci_session"],
        header_patterns=[r"X-Powered-By.*PHP"],
        common_vulns=[
            "CI 2.x CSRF bypass via session manipulation",
            "Unserialise vulnerability in older CI session handlers",
            "Debug mode enabled: /index.php shows full stack trace",
            "Default encryption key 'a1b2c3d4e5f6h7i8' still in use",
        ],
        exposed_paths=[
            "/index.php/admin",
            "/application/config/database.php",
            "/system/",
        ],
        injectable_params=["id", "page", "search", "q"],
        severity_weight=1.15,
    ),
]


# ── Framework Detector ─────────────────────────────────────────────────────────

class LocalFrameworkDetector:
    """
    Detects which local/regional frameworks are present on a target.
    Returns matched fingerprints with detection confidence scores.
    """

    def __init__(self) -> None:
        self._compiled: List[tuple] = [
            (fp, fp.compile_patterns())
            for fp in FRAMEWORK_REGISTRY
        ]

    def detect(
        self,
        url: str,
        response_body: str,
        response_headers: Dict[str, str],
        cookies: Dict[str, str],
    ) -> List[Dict]:
        """
        Detect frameworks from HTTP response.
        Returns list of matches with scores, sorted by confidence.
        """
        results = []
        headers_str = " ".join(f"{k}: {v}" for k, v in response_headers.items())
        cookies_str = " ".join(f"{k}={v}" for k, v in cookies.items())

        for fp, compiled in self._compiled:
            score = 0
            matched_signals = []

            for pattern in compiled.get("url", []):
                if pattern.search(url):
                    score += 3
                    matched_signals.append(f"url:{pattern.pattern}")

            for pattern in compiled.get("header", []):
                if pattern.search(headers_str):
                    score += 2
                    matched_signals.append(f"header:{pattern.pattern}")

            for pattern in compiled.get("body", []):
                if pattern.search(response_body[:50000]):   # Cap body search
                    score += 2
                    matched_signals.append(f"body:{pattern.pattern}")

            for pattern in compiled.get("cookie", []):
                if pattern.search(cookies_str):
                    score += 2
                    matched_signals.append(f"cookie:{pattern.pattern}")

            if score >= 2:
                results.append({
                    "framework": fp.to_dict(),
                    "confidence_score": score,
                    "matched_signals": matched_signals,
                    "paths_to_probe": fp.exposed_paths,
                    "injectable_params": fp.injectable_params,
                    "severity_weight": fp.severity_weight,
                    "default_credentials": fp.default_credentials,
                    "common_vulns": fp.common_vulns,
                })

        return sorted(results, key=lambda r: r["confidence_score"], reverse=True)

    def get_exposed_paths_for_stack(self, detected_frameworks: List[Dict]) -> List[str]:
        """Aggregate all paths to probe from all detected frameworks."""
        paths = set()
        for match in detected_frameworks:
            paths.update(match.get("paths_to_probe", []))
        return sorted(paths)

    def get_default_credentials(self, detected_frameworks: List[Dict]) -> List[Dict]:
        """Aggregate default credential pairs to test from detected frameworks."""
        creds = []
        seen = set()
        for match in detected_frameworks:
            for cred in match.get("default_credentials", []):
                key = f"{cred.get('username')}:{cred.get('password')}"
                if key not in seen:
                    seen.add(key)
                    creds.append({
                        **cred,
                        "source": match["framework"]["name"],
                    })
        return creds

    @staticmethod
    def get_severity_weight(detected_frameworks: List[Dict]) -> float:
        """Return the highest severity weight across all detected frameworks."""
        if not detected_frameworks:
            return 1.0
        return max(f.get("severity_weight", 1.0) for f in detected_frameworks)


# ── EA-specific probe path list ────────────────────────────────────────────────

# Common paths to always probe on EA targets, regardless of detected framework
EA_COMMON_PROBE_PATHS: List[str] = [
    # Config and credential files
    "/.env",
    "/.env.production",
    "/.env.local",
    "/config.php",
    "/database.php",
    "/wp-config.php",
    "/application/config/database.php",
    "/config/database.yml",

    # Admin panels
    "/admin",
    "/admin/login",
    "/administrator",
    "/dashboard",
    "/manage",
    "/cp",
    "/panel",

    # API discovery
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/swagger.json",
    "/swagger-ui.html",
    "/openapi.json",
    "/api-docs",

    # Mobile money specific
    "/momo",
    "/mobile-money",
    "/payment",
    "/pay",
    "/ipn",
    "/callback",
    "/webhook",
    "/notify",
    "/payment/callback",
    "/payment/ipn",
    "/payment/notify",

    # USSD backends
    "/ussd",
    "/ussd/callback",
    "/api/ussd",

    # Government integration patterns
    "/ura",
    "/nira",
    "/verify",
    "/tin",

    # Backup and debug files
    "/backup",
    "/db.sql",
    "/dump.sql",
    "/database.sql",
    "/phpinfo.php",
    "/info.php",
    "/.git/HEAD",
    "/.git/config",
    "/server-status",
    "/server-info",
]


# Singleton detector instance
detector = LocalFrameworkDetector()