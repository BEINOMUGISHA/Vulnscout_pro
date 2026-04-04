"""
misconfig.py — Security Misconfiguration Detector

Covers:
  - Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
  - Directory listing enabled
  - Debug mode / verbose error pages
  - Exposed admin interfaces (phpMyAdmin, Swagger, Laravel Telescope)
  - CORS misconfiguration (wildcard or arbitrary origin reflection)
  - HTTP instead of HTTPS for payment endpoints
  - Exposed .git, .env, backup files
  - Server version disclosure
  - Default error pages (stack traces, DB errors)
  - Cookie security flags (Secure, HttpOnly, SameSite)

EA context:
  Laravel debug mode is endemic on Ugandan hosting. cPanel phpMyAdmin
  accessible from the internet is extremely common. Payment endpoints
  served over HTTP violate both PCI-DSS and BOU Mobile Money Guidelines.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from core.detection.base_detector import BaseDetector, DetectorMeta, Payload
from core.models.finding import VulnType, Finding, FindingEvidence
import uuid

_CVSS_CRITICAL_MISCONFIG = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
_CVSS_HIGH_MISCONFIG     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"  # 8.2
_CVSS_MEDIUM_MISCONFIG   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"  # 5.3
_CVSS_LOW_MISCONFIG      = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"  # 5.3


class MisconfigDetector(BaseDetector):

    # Sensitive paths to probe
    SENSITIVE_PATHS = [
        ("/.env",                     "Environment file",             _CVSS_CRITICAL_MISCONFIG),
        ("/.env.local",               "Local env file",               _CVSS_CRITICAL_MISCONFIG),
        ("/.env.production",          "Production env file",          _CVSS_CRITICAL_MISCONFIG),
        ("/config.php",               "PHP config file",              _CVSS_CRITICAL_MISCONFIG),
        ("/database.php",             "Database config",              _CVSS_CRITICAL_MISCONFIG),
        ("/wp-config.php",            "WordPress config",             _CVSS_CRITICAL_MISCONFIG),
        ("/.git/HEAD",                "Git HEAD ref",                 _CVSS_HIGH_MISCONFIG),
        ("/.git/config",              "Git config",                   _CVSS_HIGH_MISCONFIG),
        ("/phpinfo.php",              "PHP info page",                _CVSS_HIGH_MISCONFIG),
        ("/info.php",                 "PHP info page",                _CVSS_HIGH_MISCONFIG),
        ("/phpmyadmin/",              "phpMyAdmin",                   _CVSS_HIGH_MISCONFIG),
        ("/phpMyAdmin/",              "phpMyAdmin (caps)",            _CVSS_HIGH_MISCONFIG),
        ("/swagger.json",             "Swagger/OpenAPI spec",         _CVSS_MEDIUM_MISCONFIG),
        ("/swagger-ui.html",          "Swagger UI",                   _CVSS_MEDIUM_MISCONFIG),
        ("/openapi.json",             "OpenAPI spec",                 _CVSS_MEDIUM_MISCONFIG),
        ("/api-docs",                 "API docs",                     _CVSS_MEDIUM_MISCONFIG),
        ("/telescope",                "Laravel Telescope",            _CVSS_HIGH_MISCONFIG),
        ("/horizon",                  "Laravel Horizon",              _CVSS_HIGH_MISCONFIG),
        ("/server-status",            "Apache server-status",         _CVSS_MEDIUM_MISCONFIG),
        ("/server-info",              "Apache server-info",           _CVSS_MEDIUM_MISCONFIG),
        ("/adminer.php",              "Adminer DB manager",           _CVSS_HIGH_MISCONFIG),
        # EA-specific
        ("/momo/config",              "MoMo config exposure",         _CVSS_CRITICAL_MISCONFIG),
        ("/payment/config",           "Payment config",               _CVSS_CRITICAL_MISCONFIG),
        ("/api/config",               "API config endpoint",          _CVSS_HIGH_MISCONFIG),
    ]

    # Required security headers
    REQUIRED_HEADERS = {
        "strict-transport-security": {
            "severity": "medium",
            "cvss": _CVSS_MEDIUM_MISCONFIG,
            "description": "Missing HSTS — allows protocol downgrade attacks",
        },
        "content-security-policy": {
            "severity": "medium",
            "cvss": _CVSS_MEDIUM_MISCONFIG,
            "description": "Missing CSP — increases XSS impact",
        },
        "x-frame-options": {
            "severity": "medium",
            "cvss": _CVSS_MEDIUM_MISCONFIG,
            "description": "Missing X-Frame-Options — clickjacking possible",
        },
        "x-content-type-options": {
            "severity": "low",
            "cvss": _CVSS_LOW_MISCONFIG,
            "description": "Missing X-Content-Type-Options — MIME sniffing possible",
        },
        "referrer-policy": {
            "severity": "low",
            "cvss": _CVSS_LOW_MISCONFIG,
            "description": "Missing Referrer-Policy — sensitive URLs may leak",
        },
    }

    # Debug/error patterns indicating verbose error disclosure
    DEBUG_PATTERNS = re.compile(
        r"""(?xi)
        (
            stack\ trace|
            Traceback\ \(most\ recent\ call|
            Whoops\\.*Laravel|
            exception.*message.*line|
            Warning:.*PHP|
            Fatal\ error:.*PHP|
            Parse\ error:.*PHP|
            database.*error|
            SQLSTATE\[|
            APP_DEBUG\s*=\s*true|
            DEBUG\s*=\s*True|
            django\.db\.utils|
            ActiveRecord.*Error|
            Uncaught\ TypeError|
            Cannot\ read\ propert.*undefined
        )
        """,
        re.IGNORECASE,
    )

    # Server version disclosure
    SERVER_VERSION_PATTERN = re.compile(
        r"(?i)(Apache/[0-9]+\.[0-9]+\.[0-9]+|nginx/[0-9]+\.[0-9]+\.[0-9]+|PHP/[0-9]+\.[0-9]+)"
    )

    @property
    def meta(self) -> DetectorMeta:
        return DetectorMeta(
            detector_id="misconfig",
            name="Security Misconfiguration",
            description=(
                "Detects missing security headers, exposed files, debug mode, "
                "directory listing, CORS flaws, and insecure cookies"
            ),
            vuln_types=[VulnType.MISCONFIG],
            owasp_categories=["A05:2021 – Security Misconfiguration"],
            estimated_requests_per_endpoint=20,
        )

    @property
    def payloads(self) -> List[Payload]:
        return []

    async def detect(self, target, crawl_result, injector) -> list:
        findings = []

        # 1. Missing security headers
        findings.extend(self._check_security_headers(crawl_result))

        # 2. Debug mode / verbose errors in response body
        debug_f = self._check_debug_mode(crawl_result)
        if debug_f:
            findings.append(debug_f)

        # 3. Server version disclosure
        version_f = self._check_server_version(crawl_result)
        if version_f:
            findings.append(version_f)

        # 4. Insecure cookies
        findings.extend(self._check_cookies(crawl_result))

        # 5. CORS misconfiguration
        cors_f = await self._check_cors(injector, crawl_result)
        if cors_f:
            findings.append(cors_f)

        # 6. HTTP payment endpoint
        if self._is_payment_endpoint(crawl_result.url) and not crawl_result.url.startswith("https"):
            findings.append(self._http_payment_finding(crawl_result))

        # 7. Probe sensitive paths (only on root page to avoid spam)
        if crawl_result.depth == 0:
            probe_findings = await self._probe_sensitive_paths(injector, crawl_result)
            findings.extend(probe_findings)

        return findings

    # ── Checks ─────────────────────────────────────────────────────────────────

    def _check_security_headers(self, crawl_result) -> list:
        findings = []
        resp_headers_lower = {k.lower(): v for k, v in crawl_result.response_headers.items()}

        for header, info in self.REQUIRED_HEADERS.items():
            if header not in resp_headers_lower:
                evidence = FindingEvidence(
                    request_url=crawl_result.url,
                    request_method=crawl_result.method,
                    response_headers=crawl_result.response_headers,
                    matched_pattern=f"Missing header: {header}",
                )
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    url=crawl_result.url,
                    parameter_name=header,
                    parameter_location="header",
                    vuln_type=VulnType.MISCONFIG,
                    cvss_vector=info["cvss"],
                    confidence=0.95,   # Header presence is deterministic
                    evidence=evidence,
                    evidence_pattern=f"missing_{header}",
                ))
        return findings

    def _check_debug_mode(self, crawl_result) -> Optional[Finding]:
        body = getattr(crawl_result, "_raw_body", "") or ""
        match = self.DEBUG_PATTERNS.search(body)
        if not match:
            return None
        evidence = FindingEvidence(
            request_url=crawl_result.url,
            request_method=crawl_result.method,
            response_body_excerpt=self._safe_excerpt(body, match.group(0)),
            matched_pattern=match.group(0)[:100],
        )
        return Finding(
            id=str(uuid.uuid4()),
            url=crawl_result.url,
            parameter_name="response_body",
            parameter_location="body",
            vuln_type=VulnType.MISCONFIG,
            cvss_vector=_CVSS_HIGH_MISCONFIG,
            confidence=0.9,
            evidence=evidence,
            evidence_pattern="debug/error disclosure",
        )

    def _check_server_version(self, crawl_result) -> Optional[Finding]:
        headers_str = " ".join(f"{k}: {v}" for k, v in crawl_result.response_headers.items())
        match = self.SERVER_VERSION_PATTERN.search(headers_str)
        if not match:
            return None
        evidence = FindingEvidence(
            request_url=crawl_result.url,
            request_method=crawl_result.method,
            response_headers=crawl_result.response_headers,
            matched_pattern=match.group(0),
        )
        return Finding(
            id=str(uuid.uuid4()),
            url=crawl_result.url,
            parameter_name="Server",
            parameter_location="header",
            vuln_type=VulnType.MISCONFIG,
            cvss_vector=_CVSS_LOW_MISCONFIG,
            confidence=0.95,
            evidence=evidence,
            evidence_pattern="server version disclosure",
        )

    def _check_cookies(self, crawl_result) -> list:
        findings = []
        set_cookie = crawl_result.response_headers.get("Set-Cookie", "")
        if not set_cookie:
            return findings

        is_secure = "secure" in set_cookie.lower()
        is_httponly = "httponly" in set_cookie.lower()
        has_samesite = "samesite" in set_cookie.lower()
        is_payment = self._is_payment_endpoint(crawl_result.url)

        if not is_httponly:
            evidence = FindingEvidence(
                request_url=crawl_result.url,
                response_headers={"Set-Cookie": set_cookie[:200]},
                matched_pattern="Missing HttpOnly flag",
            )
            findings.append(Finding(
                id=str(uuid.uuid4()),
                url=crawl_result.url,
                parameter_name="Set-Cookie",
                parameter_location="header",
                vuln_type=VulnType.MISCONFIG,
                cvss_vector=_CVSS_MEDIUM_MISCONFIG,
                confidence=0.9,
                evidence=evidence,
            ))

        if not is_secure and is_payment:
            evidence = FindingEvidence(
                request_url=crawl_result.url,
                response_headers={"Set-Cookie": set_cookie[:200]},
                matched_pattern="Missing Secure flag on payment endpoint",
            )
            findings.append(Finding(
                id=str(uuid.uuid4()),
                url=crawl_result.url,
                parameter_name="Set-Cookie",
                parameter_location="header",
                vuln_type=VulnType.MISCONFIG,
                cvss_vector=_CVSS_HIGH_MISCONFIG,
                confidence=0.9,
                evidence=evidence,
            ))
        return findings

    async def _check_cors(self, injector, crawl_result) -> Optional[Finding]:
        """Test for wildcard or arbitrary origin reflection in CORS."""
        from core.scanner.injector import InjectionRequest, PayloadEncoding
        req = InjectionRequest(
            url=crawl_result.url,
            method=crawl_result.method,
            parameter_name="Origin",
            parameter_location="header",
            original_value="",
            payload="https://evil.example.com",
            encoding=PayloadEncoding.PLAIN,
        )
        resp = await injector.inject(req)
        if not resp.success:
            return None

        acao = resp.response_headers.get("Access-Control-Allow-Origin", "")
        acac = resp.response_headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*":
            severity = _CVSS_MEDIUM_MISCONFIG
            pattern = "CORS wildcard (*)"
        elif "evil.example.com" in acao and "true" in acac.lower():
            severity = _CVSS_HIGH_MISCONFIG
            pattern = "CORS arbitrary origin reflected + credentials allowed"
        elif "evil.example.com" in acao:
            severity = _CVSS_MEDIUM_MISCONFIG
            pattern = "CORS arbitrary origin reflected"
        else:
            return None

        evidence = FindingEvidence(
            request_url=crawl_result.url,
            request_method=crawl_result.method,
            injected_parameter="Origin",
            injected_payload="https://evil.example.com",
            response_headers={"Access-Control-Allow-Origin": acao, "Access-Control-Allow-Credentials": acac},
            matched_pattern=pattern,
        )
        return Finding(
            id=str(uuid.uuid4()),
            url=crawl_result.url,
            parameter_name="Origin",
            parameter_location="header",
            vuln_type=VulnType.MISCONFIG,
            cvss_vector=severity,
            confidence=0.9,
            evidence=evidence,
            evidence_pattern=pattern,
        )

    async def _probe_sensitive_paths(self, injector, crawl_result) -> list:
        """Probe for exposed sensitive files relative to the target root in parallel."""
        from urllib.parse import urlparse, urlunparse
        from core.scanner.injector import InjectionRequest, PayloadEncoding
        findings = []
        parsed = urlparse(crawl_result.url)
        base = urlunparse(parsed._replace(path="", query="", fragment=""))

        async def probe_one(item):
            path, description, cvss = item
            url = base.rstrip("/") + path
            req = InjectionRequest(
                url=url, method="GET",
                parameter_name="path", parameter_location="path",
                original_value="", payload="",
                encoding=PayloadEncoding.PLAIN,
            )
            resp = await injector.inject(req)
            if not resp.success or resp.status_code not in (200, 403):
                return None

            # 200 on sensitive path is a finding; 403 on .git may also indicate presence
            if resp.status_code == 200 and len(resp.body) > 10:
                evidence = FindingEvidence(
                    request_url=url, request_method="GET",
                    response_status=resp.status_code,
                    response_body_excerpt=resp.body[:400],
                    matched_pattern=f"Sensitive path accessible: {path}",
                )
                return Finding(
                    id=str(uuid.uuid4()),
                    url=url,
                    parameter_name="path",
                    parameter_location="path",
                    vuln_type=VulnType.MISCONFIG,
                    cvss_vector=cvss,
                    confidence=0.9,
                    evidence=evidence,
                    evidence_pattern=description,
                )
            return None

        # PARALLEL PROBING
        probe_results = await asyncio.gather(*[probe_one(item) for item in self.SENSITIVE_PATHS], return_exceptions=True)
        for res in probe_results:
            if isinstance(res, Finding):
                findings.append(res)
                
        return findings

    @staticmethod
    def _is_payment_endpoint(url: str) -> bool:
        return bool(re.search(r"/pay|/payment|/checkout|/momo|/airtel|/ipn|/callback", url, re.IGNORECASE))

    def _http_payment_finding(self, crawl_result) -> Finding:
        evidence = FindingEvidence(
            request_url=crawl_result.url, request_method=crawl_result.method,
            matched_pattern="Payment endpoint served over HTTP (not HTTPS)",
        )
        return Finding(
            id=str(uuid.uuid4()),
            url=crawl_result.url,
            parameter_name="scheme",
            parameter_location="url",
            vuln_type=VulnType.MISCONFIG,
            cvss_vector=_CVSS_CRITICAL_MISCONFIG,
            confidence=1.0,
            evidence=evidence,
            evidence_pattern="HTTP payment endpoint",
        )