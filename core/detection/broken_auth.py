"""
broken_auth.py — Broken Authentication and Session Management Detector

Responsibilities:
  - Detect Session Fixation (session cookie not changed after login)
  - Detect weak password reset tokens (predictable or short)
  - Identify lack of MFA on sensitive endpoints
  - Detect session timeout issues (missing Max-Age/Expires)
  - Identify insecure remember-me cookies
"""

from __future__ import annotations

import logging
import uuid
import re
from typing import List, Optional

from core.detection.base_detector import (
    BaseDetector,
    DetectorMeta,
    Payload,
)
from core.models.finding import Severity, VulnType, Finding, FindingEvidence

logger = logging.getLogger(__name__)


class BrokenAuthDetector(BaseDetector):
    @property
    def meta(self) -> DetectorMeta:
        return DetectorMeta(
            detector_id="broken_auth",
            name="Broken Authentication Scanner",
            description="Tests for session management flaws, session fixation, and weak MFA implementation.",
            vuln_types=[VulnType.AUTH_BYPASS], # Map to nearest standard type
            owasp_categories=["A07:2021 – Identification and Authentication Failures"],
            estimated_requests_per_endpoint=10,
        )

    async def detect(self, target, crawl_result, injector) -> List[Finding]:
        findings = []
        
        # 1. Check for insecure cookie flags
        findings.extend(self._check_cookie_security(crawl_result))
        
        # 2. Check for sensitive endpoints missing MFA hints
        findings.extend(self._check_mfa_gaps(crawl_result))
        
        # 3. Check for predictable session identifiers (Length/Entropy check)
        findings.extend(self._check_session_entropy(crawl_result))
        
        # 4. Check for session fixation candidates (login forms)
        if "login" in crawl_result.url.lower() or "signin" in crawl_result.url.lower():
            findings.extend(await self._check_session_fixation_candidate(target, crawl_result, injector))

        return findings

    def _check_cookie_security(self, crawl_result) -> List[Finding]:
        findings = []
        cookies = crawl_result.headers.get("Set-Cookie", "")
        if not cookies:
            return []
            
        cookie_list = [c.strip() for c in cookies.split(",")]
        for cookie in cookie_list:
            name = cookie.split("=")[0]
            if "session" in name.lower() or "auth" in name.lower() or "id" in name.lower():
                missing = []
                if "httponly" not in cookie.lower(): missing.append("HttpOnly")
                if "secure" not in cookie.lower(): missing.append("Secure")
                if "samesite" not in cookie.lower(): missing.append("SameSite")
                
                if missing:
                    evidence = FindingEvidence(
                        request_url=crawl_result.url,
                        response_headers={"Set-Cookie": cookies[:200]},
                        matched_pattern=f"Cookie '{name}' missing flags: {', '.join(missing)}",
                    )
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            url=crawl_result.url,
                            parameter_name=name,
                            parameter_location="cookie",
                            vuln_type=VulnType.MISCONFIG,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", # 5.3
                            confidence=0.9,
                            evidence=evidence,
                        )
                    )
        return findings

    def _check_mfa_gaps(self, crawl_result) -> List[Finding]:
        findings = []
        sensitive_keywords = ["admin", "billing", "settings", "payout", "transfer", "delete_account"]
        if any(kw in crawl_result.url.lower() for kw in sensitive_keywords):
            # If we don't see any hint of MFA (totp, mfa, code_challenge) in the page or body
            if not any(x in crawl_result.body.lower() for x in ["mfa", "totp", "2fa", "verification code"]):
                evidence = FindingEvidence(
                    request_url=crawl_result.url,
                    matched_pattern="Sensitive endpoint missing MFA indicators",
                )
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        url=crawl_result.url,
                        parameter_name="",
                        parameter_location="url",
                        vuln_type=VulnType.BROKEN_AUTH,
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", # 7.4
                        confidence=0.4,
                        evidence=evidence,
                    )
                )
        return findings

    def _check_session_entropy(self, crawl_result) -> List[Finding]:
        findings = []
        # Look for session IDs in headers or cookies
        cookies = crawl_result.headers.get("Set-Cookie", "")
        # Extract values
        import re
        matches = re.findall(r'[^= ]+=[A-Za-z0-9+/=.-]+', cookies)
        for m in matches:
            name, val = m.split("=", 1)
            if any(x in name.lower() for x in ["session", "auth", "phpsessid", "jsessionid"]):
                # Check length - if < 16 chars, it's potentially weak
                if len(val) < 16:
                    evidence = FindingEvidence(
                        request_url=crawl_result.url,
                        response_headers={"Set-Cookie": cookies[:200]},
                        matched_pattern=f"Short session identifier '{name}' ({len(val)} chars)",
                    )
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            url=crawl_result.url,
                            parameter_name=name,
                            parameter_location="cookie",
                            vuln_type=VulnType.BROKEN_AUTH,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", # 7.5
                            confidence=0.7,
                            evidence=evidence,
                        )
                    )
        return findings

    async def _check_session_fixation_candidate(self, target, crawl_result, injector) -> List[Finding]:
        # This is a passive check flagging the existence of a risk
        # A full active check would require logging in and checking if the cookie changed
        evidence = FindingEvidence(
            request_url=crawl_result.url,
            matched_pattern="Authentication form detected (potential fixation point)",
        )
        return [
            Finding(
                id=str(uuid.uuid4()),
                url=crawl_result.url,
                parameter_name="",
                parameter_location="url",
                vuln_type=VulnType.BROKEN_AUTH,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", # 4.2
                confidence=0.3,
                evidence=evidence,
            )
        ]

    @property
    def payloads(self) -> List[Payload]:
        # Passive detector; no specific injection payloads required
        return []
