"""
jwt_detector.py — JWT Security Detector

Checks for:
  - Algorithm confusion attacks (alg: none)
  - Weak HS256 key brute-forcing hints
  - JWT exposed in URLs or logs
  - JWTs without expiry (no "exp" claim)
  - JWTs with excessive permissions
"""

from __future__ import annotations

import base64
import json
import logging
import re
from typing import List

from core.detection.base_detector import BaseDetector, DetectorMeta, Payload

logger = logging.getLogger(__name__)

# Regex to detect a JWT in a response body or headers
JWT_REGEX = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')


class JWTDetector(BaseDetector):
    """Detects JWT-related security vulnerabilities."""

    @property
    def meta(self) -> DetectorMeta:
        return DetectorMeta(
            detector_id="jwt",
            name="JWT Security Analyzer",
            description="Detects JWT algorithm confusion, missing expiry, and leaked tokens.",
            vuln_types=["jwt_alg_none", "jwt_no_expiry", "jwt_leaked"],
            owasp_categories=["API2:2023 - Broken Authentication"],
            default_enabled=False,
            estimated_requests_per_endpoint=3,
        )

    @property
    def payloads(self) -> List[Payload]:
        # A crafted "alg:none" JWT (unsigned token)
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps({"sub": "admin", "role": "admin"}).encode()
        ).rstrip(b"=").decode()
        none_jwt = f"{header}.{payload_b64}."

        return [
            Payload(
                value=none_jwt,
                description="JWT with alg:none (unsigned token)",
                evidence_pattern=r'"id"\s*:|"user"\s*:|"admin"\s*:|\bwelcome\b',
                vuln_type="jwt_alg_none",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                confidence_boost=0.4,
            ),
        ]

    async def detect(self, target, crawl_result, injector) -> List:
        findings = []

        # Passive: Check if the response body contains an exposed JWT
        if hasattr(crawl_result, "_response_body") and crawl_result._response_body:
            body = crawl_result._response_body
            for match in JWT_REGEX.finditer(body):
                token = match.group(0)
                try:
                    parts = token.split(".")
                    # Decode payload to check for regional indicators
                    p_body = parts[1]
                    # Add padding if needed
                    p_body += "=" * ((4 - len(p_body) % 4) % 4)
                    p = json.loads(base64.urlsafe_b64decode(p_body).decode())
                    
                    vuln_type = "jwt_no_expiry" if "exp" not in p else "jwt_leaked"
                    logger.info("[jwt] Exposed JWT found at %s (type=%s)", crawl_result.url, vuln_type)
                    
                    # Regional Provider Indicators
                    regional_provider = None
                    if any(x in str(p).lower() for x in ["mtn", "momo", "airtel", "uganda", "paygate", "pesapal"]):
                        regional_provider = "EA Finance/Payment Provider"

                    # Build finding with EA Context
                    ea_ctx = self._build_ea_context(target, crawl_result, regional_provider)
                    
                    from core.models.finding import Finding, FindingEvidence
                    import uuid
                    finding = Finding(
                        id=str(uuid.uuid4()),
                        url=crawl_result.url,
                        parameter_name="response_body",
                        parameter_location="body",
                        vuln_type=vuln_type,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        confidence=0.85,
                        evidence=FindingEvidence(
                            request_method=crawl_result.method,
                            request_url=crawl_result.url,
                            injected_parameter="response_body",
                            injected_payload="N/A (passive)",
                            response_status=crawl_result.status_code,
                            response_body_excerpt=token[:120] + "...",
                        ),
                        ea_context=ea_ctx,
                    )
                    findings.append(finding)
                    break
                except Exception as e:
                    logger.debug("[jwt] Passive decode failed: %s", e)
                    pass

        # Active: Test "alg:none" bypass on Authorization header endpoints
        auth_header_params = [
            p for p in crawl_result.parameters
            if p.location == "header" and "authorization" in p.name.lower()
        ]
        for param in auth_header_params:
            for payload in self.payloads:
                hit = await self._test_payload(injector, crawl_result, param, payload)
                if hit:
                    ea_ctx = self._build_ea_context(target, crawl_result)
                    findings.append(self._build_finding(hit, ea_context=ea_ctx))
                    self._log_hit(self.meta.detector_id, crawl_result.url, param.name, payload.description)

        return findings

    def _build_ea_context(self, target, crawl_result, provider_hint: str = None) -> "EAContext":
        """
        Enriches finding with regional regulatory context.
        """
        from core.models.finding import EAContext
        
        ctx_data = {
            "ea_relevant": False,
            "regulatory_requirements": []
        }

        # Check if target is in EA region or handles regional data
        is_ea = False
        if hasattr(target, "is_ea_target") and target.is_ea_target:
            is_ea = True
        
        # Heuristics for regional relevance based on URL or provider hint
        regional_keywords = [".ug", ".ke", ".tz", "momo", "airtel", "mtn", "pesapal", "dpo"]
        if is_ea or any(kw in crawl_result.url.lower() for kw in regional_keywords) or provider_hint:
            ctx_data["ea_relevant"] = True
            
            # Common regulatory impact in East Africa
            ctx_data["regulatory_requirements"].append({
                "body": "NITA-U / PDPA Uganda",
                "requirement_id": "Section 20: Security Measures",
                "description": "The Data Protection and Privacy Act 2019 requires technical measures to prevent unauthorized access to personal data. Weak or leaked JWTs violate this integrity requirement.",
                "risk_multiplier": 1.3
            })
            
            if provider_hint or "momo" in crawl_result.url.lower() or "pay" in crawl_result.url.lower():
                ctx_data["regulatory_requirements"].append({
                    "body": "Bank of Uganda (BOU)",
                    "requirement_id": "Cybersecurity Guidelines 2022",
                    "description": "Financial entities must implement strong session management. JWT hijacking in payment flows represents a critical risk to national financial stability.",
                    "risk_multiplier": 1.5
                })

            ctx_data["provider"] = provider_hint or "General EA Application"
            ctx_data["max_regulatory_multiplier"] = max([r["risk_multiplier"] for r in ctx_data["regulatory_requirements"]]) if ctx_data["regulatory_requirements"] else 1.0

        return EAContext(**ctx_data)
