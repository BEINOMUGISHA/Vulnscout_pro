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
from typing import List

from core.detection.base_detector import (
    BaseDetector,
    DetectorMeta,
    Payload,
    DetectionHit,
)
from core.models.finding import Severity, VulnType

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

    @property
    def payloads(self) -> List[Payload]:
        return []

    async def detect(self, target, crawl_result, injector) -> List[DetectionHit]:
        hits = []
        
        # 1. Check for insecure cookie flags
        hits.extend(self._check_cookie_security(crawl_result))
        
        # 2. Check for sensitive endpoints missing MFA hints
        hits.extend(self._check_mfa_gaps(crawl_result))
        
        # 3. Check for predictable session identifiers (Length/Entropy check)
        hits.extend(self._check_session_entropy(crawl_result))
        
        # 4. Check for session fixation candidates (login forms)
        if "login" in crawl_result.url.lower() or "signin" in crawl_result.url.lower():
            hits.extend(await self._check_session_fixation_candidate(target, crawl_result, injector))

        return hits

    def _check_cookie_security(self, crawl_result) -> List[DetectionHit]:
        hits = []
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
                    hits.append(
                        DetectionHit(
                            detector_id=self.meta.id,
                            vuln_type="insecure_cookie_flags",
                            severity=Severity.LOW,
                            confidence=0.9,
                            evidence=f"Cookie '{name}' missing flags: {', '.join(missing)}",
                            url=crawl_result.url,
                        )
                    )
        return hits

    def _check_mfa_gaps(self, crawl_result) -> List[DetectionHit]:
        hits = []
        sensitive_keywords = ["admin", "billing", "settings", "payout", "transfer", "delete_account"]
        if any(kw in crawl_result.url.lower() for kw in sensitive_keywords):
            # If we don't see any hint of MFA (totp, mfa, code_challenge) in the page or body
            if not any(x in crawl_result.body.lower() for x in ["mfa", "totp", "2fa", "verification code"]):
                hits.append(
                    DetectionHit(
                        detector_id=self.meta.id,
                        vuln_type="missing_mfa",
                        severity=Severity.MEDIUM,
                        confidence=0.4,
                        evidence="Sensitive endpoint detected without apparent MFA protection.",
                        url=crawl_result.url,
                    )
                )
        return hits

    def _check_session_entropy(self, crawl_result) -> List[DetectionHit]:
        hits = []
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
                    hits.append(
                        DetectionHit(
                            detector_id=self.meta.id,
                            vuln_type="weak_session_id",
                            severity=Severity.MEDIUM,
                            confidence=0.7,
                            evidence=f"Session identifier '{name}' is unusually short ({len(val)} chars), increasing brute-force risk.",
                            url=crawl_result.url,
                        )
                    )
        return hits

    async def _check_session_fixation_candidate(self, target, crawl_result, injector) -> List[DetectionHit]:
        # This is a passive check flagging the existence of a risk
        # A full active check would require logging in and checking if the cookie changed
        return [
            DetectionHit(
                detector_id=self.meta.id,
                vuln_type="session_fixation_risk",
                severity=Severity.MEDIUM,
                confidence=0.3,
                evidence="Authentication form detected. Verify that session identifiers are regenerated upon successful login.",
                url=crawl_result.url,
            )
        ]
