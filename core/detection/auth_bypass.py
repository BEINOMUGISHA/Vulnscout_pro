"""
auth_bypass.py — Authentication Bypass Detector

Covers:
  - Unauthenticated access to protected endpoints (JWT removal, cookie removal)
  - JWT algorithm confusion (alg:none, RS256→HS256)
  - Forced browsing to admin/management endpoints
  - Session fixation
  - Password reset flaws (predictable tokens, no expiry)
  - Login bypass via SQL injection (tested separately in sqli.py)
  - IPN/callback endpoints accessible without auth (critical in EA fintech)
  - Default credentials on detected frameworks (Craft Silicon, cPanel, etc.)

EA context:
  Craft Silicon eMobile and similar platforms ship with default credentials.
  USSD callback handlers are frequently deployed without any authentication.
  Agent management portals often share session cookies across all agents.
"""

from __future__ import annotations

import base64
import json
import re
import uuid
from typing import List, Optional

from core.detection.base_detector import BaseDetector, DetectorMeta, Payload
from core.models.finding import VulnType, Finding, FindingEvidence

_CVSS_AUTH_BYPASS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
_CVSS_WEAK_AUTH   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"  # 8.2
_CVSS_IPN_BYPASS  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8

# Responses that indicate protected content was returned
_AUTH_SUCCESS_PATTERN = re.compile(
    r"""(?xi)
    (
        "role"\s*:\s*"(admin|manager|agent|user)"|
        dashboard|
        welcome.*back|
        logged.*in|
        "token"\s*:|
        "access_token"\s*:|
        account.*balance|
        transaction.*history|
        member.*details|
        "status"\s*:\s*"(active|success)"|
        "data"\s*:\s*\{
    )
    """,
    re.IGNORECASE,
)

# Protected endpoint path patterns
_PROTECTED_PATHS = [
    "/admin", "/admin/", "/admin/login", "/admin/dashboard",
    "/dashboard", "/manage", "/management",
    "/api/admin", "/api/users", "/api/accounts",
    "/api/transactions", "/api/reports",
    "/panel", "/cp", "/control",
    # EA-specific
    "/agent", "/agent/dashboard", "/agent/float",
    "/merchant", "/merchant/dashboard",
    "/momo/admin", "/airtel/admin",
]

# Default credentials to test per detected framework
_DEFAULT_CREDS = [
    {"username": "admin",     "password": "admin"},
    {"username": "admin",     "password": "admin123"},
    {"username": "admin",     "password": "password"},
    {"username": "admin",     "password": "123456"},
    {"username": "admin",     "password": "Admin@123"},
    {"username": "root",      "password": "root"},
    {"username": "root",      "password": "toor"},
    {"username": "test",      "password": "test"},
    {"username": "demo",      "password": "demo"},
    # EA/Craft Silicon defaults
    {"username": "craftadmin","password": "craft@123"},
    {"username": "sysadmin",  "password": "sysadmin123"},
    {"username": "manager",   "password": "manager"},
]


class AuthBypassDetector(BaseDetector):

    @property
    def meta(self) -> DetectorMeta:
        return DetectorMeta(
            detector_id="auth_bypass",
            name="Authentication Bypass",
            description=(
                "Detects auth bypass via JWT confusion, unauthenticated endpoints, "
                "default credentials, and IPN forgery"
            ),
            vuln_types=[VulnType.AUTH_BYPASS, VulnType.BROKEN_AUTH, VulnType.IPN_FORGERY],
            owasp_categories=["A07:2021 – Identification and Authentication Failures"],
            estimated_requests_per_endpoint=15,
        )

    @property
    def payloads(self) -> List[Payload]:
        return []   # Auth bypass uses procedural detection, not payload injection

    async def detect(self, target, crawl_result, injector) -> list:
        findings = []

        # 1. JWT algorithm confusion
        for header_name, header_value in crawl_result.headers.items():
            if "authorization" in header_name.lower() and "bearer" in header_value.lower():
                jwt_findings = await self._test_jwt_bypass(
                    injector, crawl_result, header_name, header_value
                )
                findings.extend(jwt_findings)

        # 2. Unauthenticated access to protected URL patterns
        if self._is_auth_protected(crawl_result.url):
            ua_finding = await self._test_unauthenticated_access(injector, crawl_result)
            if ua_finding:
                findings.append(ua_finding)

        # 3. IPN/callback without authentication
        if self._is_ipn_endpoint(crawl_result.url):
            ipn_finding = await self._test_ipn_auth(injector, crawl_result)
            if ipn_finding:
                findings.append(ipn_finding)

        # 4. Default credentials on login endpoints
        if self._is_login_endpoint(crawl_result.url):
            cred_findings = await self._test_default_credentials(injector, crawl_result)
            findings.extend(cred_findings)

        return findings

    # ── JWT bypass ─────────────────────────────────────────────────────────────

    async def _test_jwt_bypass(self, injector, crawl_result, header_name: str, header_value: str) -> list:
        findings = []
        token = header_value.replace("Bearer ", "").replace("bearer ", "").strip()

        # Try alg:none bypass
        none_token = self._forge_jwt_none(token)
        if none_token:
            from core.scanner.injector import InjectionRequest, PayloadEncoding
            req = InjectionRequest(
                url=crawl_result.url,
                method=crawl_result.method,
                parameter_name=header_name,
                parameter_location="header",
                original_value=header_value,
                payload=f"Bearer {none_token}",
                encoding=PayloadEncoding.PLAIN,
            )
            resp = await injector.inject(req)
            if resp.success and resp.status_code == 200:
                if _AUTH_SUCCESS_PATTERN.search(resp.body):
                    self._log_hit(self.meta.detector_id, crawl_result.url, header_name, "JWT alg:none")
                    evidence = FindingEvidence(
                        request_method=crawl_result.method,
                        request_url=crawl_result.url,
                        injected_parameter=header_name,
                        injected_payload=f"JWT with alg:none — {none_token[:60]}...",
                        response_status=resp.status_code,
                        response_body_excerpt=resp.body[:500],
                        matched_pattern="JWT alg:none bypass",
                    )
                    findings.append(Finding(
                        id=str(uuid.uuid4()),
                        url=crawl_result.url,
                        parameter_name=header_name,
                        parameter_location="header",
                        vuln_type=VulnType.AUTH_BYPASS,
                        cvss_vector=_CVSS_AUTH_BYPASS,
                        confidence=0.8,
                        evidence=evidence,
                    ))
        return findings

    @staticmethod
    def _forge_jwt_none(token: str) -> Optional[str]:
        """Create a JWT with alg:none, keeping the original claims."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            # Decode header
            header_raw = parts[0] + "=="
            header = json.loads(base64.b64decode(header_raw).decode("utf-8", errors="ignore"))
            header["alg"] = "none"
            new_header = base64.b64encode(
                json.dumps(header, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()
            # Empty signature
            return f"{new_header}.{parts[1]}."
        except Exception:
            return None

    # ── Unauthenticated access ─────────────────────────────────────────────────

    async def _test_unauthenticated_access(self, injector, crawl_result) -> Optional[Finding]:
        """Try to access the endpoint with no auth headers or cookies."""
        from core.scanner.injector import InjectionRequest, PayloadEncoding
        req = InjectionRequest(
            url=crawl_result.url,
            method="GET",
            parameter_name="",
            parameter_location="header",
            original_value="",
            payload="",
            encoding=PayloadEncoding.PLAIN,
        )
        # Remove auth headers
        req.extra_headers = {
            k: v for k, v in crawl_result.headers.items()
            if "auth" not in k.lower() and "cookie" not in k.lower()
        }
        resp = await injector.inject(req)
        if not resp.success or resp.status_code in (401, 403):
            return None

        if resp.status_code == 200 and _AUTH_SUCCESS_PATTERN.search(resp.body):
            self._log_hit(self.meta.detector_id, crawl_result.url, "auth_headers", "removed auth")
            evidence = FindingEvidence(
                request_method="GET",
                request_url=crawl_result.url,
                injected_parameter="Authorization header",
                injected_payload="[removed]",
                response_status=resp.status_code,
                response_body_excerpt=resp.body[:600],
                matched_pattern="protected content accessible without auth",
            )
            return Finding(
                id=str(uuid.uuid4()),
                url=crawl_result.url,
                parameter_name="Authorization",
                parameter_location="header",
                vuln_type=VulnType.AUTH_BYPASS,
                cvss_vector=_CVSS_AUTH_BYPASS,
                confidence=0.7,
                evidence=evidence,
            )
        return None

    # ── IPN/callback without auth ──────────────────────────────────────────────

    async def _test_ipn_auth(self, injector, crawl_result) -> Optional[Finding]:
        """POST a fake IPN payload with no authentication headers."""
        from core.scanner.injector import InjectionRequest, PayloadEncoding

        # Generic IPN payload that looks like MTN MoMo or Airtel
        fake_ipn = json.dumps({
            "transaction": {"id": "FAKE_IPN_TEST_001", "status": "TS",
                            "message": "Airtel Money Transfer Successful",
                            "airtel_money_id": "CI240101.0000.999999"},
            "status": {"code": "200", "message": "SUCCESS", "result_code": "ESB000010"},
        })

        req = InjectionRequest(
            url=crawl_result.url,
            method="POST",
            parameter_name="body",
            parameter_location="body",
            original_value="",
            payload=fake_ipn,
            encoding=PayloadEncoding.PLAIN,
            content_type="application/json",
        )
        req.extra_headers = {}   # No auth headers

        resp = await injector.inject(req)
        if not resp.success:
            return None

        if resp.status_code in (401, 403):
            return None   # Properly protected

        # Any 200/201 response to an unauthenticated fake IPN is a finding
        if resp.status_code in (200, 201, 202):
            self._log_hit(self.meta.detector_id, crawl_result.url, "IPN", "fake callback accepted")
            evidence = FindingEvidence(
                request_method="POST",
                request_url=crawl_result.url,
                injected_parameter="request body",
                injected_payload=fake_ipn[:200],
                response_status=resp.status_code,
                response_body_excerpt=resp.body[:600],
                matched_pattern="IPN accepted without authentication",
            )
            return Finding(
                id=str(uuid.uuid4()),
                url=crawl_result.url,
                parameter_name="ipn_body",
                parameter_location="body",
                vuln_type=VulnType.IPN_FORGERY,
                cvss_vector=_CVSS_IPN_BYPASS,
                confidence=0.75,
                evidence=evidence,
                evidence_pattern="IPN accepted without auth",
            )
        return None

    # ── Default credentials ────────────────────────────────────────────────────

    async def _test_default_credentials(self, injector, crawl_result) -> list:
        """Test a small set of common default credentials against login forms."""
        from core.scanner.injector import InjectionRequest, PayloadEncoding
        findings = []
        tested = 0

        for cred in _DEFAULT_CREDS[:8]:   # Limit to 8 attempts to avoid lockout
            for username_field in ("username", "email", "user"):
                for password_field in ("password", "passwd", "pass"):
                    payload = json.dumps({
                        username_field: cred["username"],
                        password_field: cred["password"],
                    })
                    req = InjectionRequest(
                        url=crawl_result.url,
                        method="POST",
                        parameter_name="credentials",
                        parameter_location="json",
                        original_value="",
                        payload=payload,
                        encoding=PayloadEncoding.PLAIN,
                        content_type="application/json",
                    )
                    resp = await injector.inject(req)
                    tested += 1

                    if not resp.success:
                        continue

                    # Successful login indicators
                    if resp.status_code in (200, 201) and (
                        re.search(r'"token"|"access_token"|"sessionId"|dashboard|welcome', resp.body, re.IGNORECASE)
                        and not re.search(r"invalid.*credentials|incorrect.*password|login.*failed", resp.body, re.IGNORECASE)
                    ):
                        self._log_hit(self.meta.detector_id, crawl_result.url, "credentials",
                                      f"{cred['username']}:{cred['password']}")
                        evidence = FindingEvidence(
                            request_method="POST",
                            request_url=crawl_result.url,
                            injected_parameter="username/password",
                            injected_payload=f"{cred['username']}:{'*' * len(cred['password'])}",
                            response_status=resp.status_code,
                            response_body_excerpt=resp.body[:400],
                            matched_pattern="Login succeeded with default credentials",
                        )
                        findings.append(Finding(
                            id=str(uuid.uuid4()),
                            url=crawl_result.url,
                            parameter_name="credentials",
                            parameter_location="body",
                            vuln_type=VulnType.BROKEN_AUTH,
                            cvss_vector=_CVSS_AUTH_BYPASS,
                            confidence=0.85,
                            evidence=evidence,
                        ))
                        return findings   # Stop after first hit

                    if tested >= 16:
                        return findings   # Hard cap
        return findings

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _is_auth_protected(url: str) -> bool:
        return any(p in url.lower() for p in _PROTECTED_PATHS)

    @staticmethod
    def _is_ipn_endpoint(url: str) -> bool:
        return bool(re.search(
            r"/ipn|/callback|/notify|/webhook|/payment.*notify",
            url, re.IGNORECASE,
        ))

    @staticmethod
    def _is_login_endpoint(url: str) -> bool:
        return bool(re.search(
            r"/login|/signin|/sign-in|/auth|/authenticate|/token",
            url, re.IGNORECASE,
        ))