"""
business_logic.py — Business Logic Vulnerability Detector

Responsibilities:
  - Detect Price Manipulation (changing 'amount' or 'total' in requests)
  - Detect Coupon/Discount abuse (multiple coupons, negative discounts)
  - Identify Transaction Bypasses (skipping payment step)
  - Verify integrity of high-value business parameters
"""

from __future__ import annotations

import logging
import uuid
from typing import List, Optional

from core.detection.base_detector import (
    BaseDetector,
    DetectorMeta,
    Payload,
)
from core.models.finding import Severity, VulnType, Finding, FindingEvidence

logger = logging.getLogger(__name__)


class BusinessLogicDetector(BaseDetector):
    @property
    def meta(self) -> DetectorMeta:
        return DetectorMeta(
            detector_id="business_logic",
            name="Business Logic Scanner",
            description="Tests for logical flaws such as price manipulation, coupon abuse, and workflow bypass.",
            vuln_types=[
                VulnType.PRICE_MANIPULATION, 
                VulnType.COUPON_ABUSE, 
                VulnType.PARAM_POLLUTION,
                VulnType.WORKFLOW_BYPASS
            ],
            owasp_categories=["A04:2021 – Insecure Design"],
            estimated_requests_per_endpoint=15,
        )

    @property
    def payloads(self) -> List[Payload]:
        return []

    async def detect(self, target, crawl_result, injector) -> List[Finding]:
        findings = []
        
        # 1. Price Manipulation checks
        findings.extend(await self._check_price_manipulation(target, crawl_result, injector))
        
        # 2. Coupon/Discount Logic checks
        findings.extend(await self._check_coupon_logic(target, crawl_result, injector))
        
        # 3. Transaction/Flow Integrity
        findings.extend(await self._check_parameter_pollution(target, crawl_result, injector))

        # 4. Workflow Bypass
        findings.extend(await self._check_workflow_bypass(target, crawl_result, injector))

        return findings

    async def _check_price_manipulation(self, target, crawl_result, injector) -> List[Finding]:
        findings = []
        price_params = ["price", "amount", "total", "cost", "unit_price", "grand_total", "fee"]
        
        for param in crawl_result.parameters:
            if any(p in param.name.lower() for p in price_params):
                # Try setting price to 0, 0.01, or negative
                payloads = ["0.00", "0.01", "-1.00"]
                for p in payloads:
                    from core.scanner.injector import InjectionRequest
                    req = InjectionRequest(
                        url=crawl_result.url,
                        method=crawl_result.method,
                        parameter_name=param.name,
                        parameter_location=param.location,
                        original_value=param.value,
                        payload=p,
                    )
                    resp = await injector.inject(req)
                    
                    # If the response doesn't error out (400) and displays the new value
                    # or shows "Success", it's a high potential hit
                    if resp.status_code in [200, 201] and p in resp.body:
                        evidence = FindingEvidence(
                            request_method=crawl_result.method,
                            request_url=crawl_result.url,
                            injected_parameter=param.name,
                            injected_payload=p,
                            response_status=resp.status_code,
                            response_body_excerpt=resp.body[:500],
                            matched_pattern=f"Price parameter accepted injected value '{p}'",
                        )
                        findings.append(
                            Finding(
                                id=str(uuid.uuid4()),
                                url=crawl_result.url,
                                parameter_name=param.name,
                                parameter_location=param.location,
                                vuln_type=VulnType.PRICE_MANIPULATION,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", # 7.5
                                confidence=0.6,
                                evidence=evidence,
                            )
                        )
        return findings

    async def _check_coupon_logic(self, target, crawl_result, injector) -> List[Finding]:
        findings = []
        coupon_params = ["coupon", "discount", "promo", "voucher"]
        
        for param in crawl_result.parameters:
            if any(c in param.name.lower() for c in coupon_params):
                # Try injecting weird discount values
                payloads = ["100", "999", "-50"] 
                for p in payloads:
                    from core.scanner.injector import InjectionRequest
                    req = InjectionRequest(
                        url=crawl_result.url,
                        method=crawl_result.method,
                        parameter_name=param.name,
                        parameter_location=param.location,
                        original_value=param.value,
                        payload=p,
                    )
                    resp = await injector.inject(req)
                    
                    if resp.status_code == 200 and ("applied" in resp.body.lower() or "success" in resp.body.lower()):
                         evidence = FindingEvidence(
                            request_method=crawl_result.method,
                            request_url=crawl_result.url,
                            injected_parameter=param.name,
                            injected_payload=p,
                            response_status=resp.status_code,
                            response_body_excerpt=resp.body[:500],
                            matched_pattern=f"Coupon/Promo parameter accepted test value '{p}'",
                        )
                         findings.append(
                            Finding(
                                id=str(uuid.uuid4()),
                                url=crawl_result.url,
                                parameter_name=param.name,
                                parameter_location=param.location,
                                vuln_type=VulnType.COUPON_ABUSE,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", # 5.4
                                confidence=0.5,
                                evidence=evidence,
                            )
                        )
        return findings

    async def _check_parameter_pollution(self, target, crawl_result, injector) -> List[Finding]:
        findings = []
        # HTTP Parameter Pollution (HPP) - sending same param twice
        # If we see a significant change in response or success when doubled
        if len(crawl_result.parameters) > 0:
            target_p = crawl_result.parameters[0]
            if target_p.location == "query":
                from core.scanner.injector import InjectionRequest
                # Payload is "original_value" doubled
                polluted_payload = f"{target_p.value}&{target_p.name}=polluted"
                req = InjectionRequest(
                    url=crawl_result.url,
                    method=crawl_result.method,
                    parameter_name=target_p.name,
                    parameter_location="query",
                    original_value=target_p.value,
                    payload=polluted_payload,
                )
                resp = await injector.inject(req)
                
                if resp.status_code == 200 and "polluted" in resp.body:
                    evidence = FindingEvidence(
                        request_method=crawl_result.method,
                        request_url=crawl_result.url,
                        injected_parameter=target_p.name,
                        injected_payload=polluted_payload,
                        response_status=resp.status_code,
                        response_body_excerpt=resp.body[:500],
                        matched_pattern=f"Reflected value from polluted parameter '{target_p.name}'",
                    )
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            url=crawl_result.url,
                            parameter_name=target_p.name,
                            parameter_location="query",
                            vuln_type=VulnType.PARAM_POLLUTION,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", # 5.3
                            confidence=0.7,
                            evidence=evidence,
                        )
                    )
        return findings

    async def _check_workflow_bypass(self, target, crawl_result, injector) -> List[Finding]:
        """Detects if 'final' or 'execute' endpoints can be reached directly."""
        findings = []
        bypass_keywords = ["confirm", "final", "execute", "apply", "checkout", "process", "success"]
        url_lower = crawl_result.url.lower()
        
        # If the URL looks like a final step but we reached it via simple crawl/GET
        if any(kw in url_lower for kw in bypass_keywords) and crawl_result.method == "GET":
             evidence = FindingEvidence(
                request_method="GET",
                request_url=crawl_result.url,
                response_status=crawl_result.status_code,
                matched_pattern=f"Endpoint contains workflow keywords and is accessible via GET",
             )
             findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    url=crawl_result.url,
                    parameter_name="",
                    parameter_location="url",
                    vuln_type=VulnType.WORKFLOW_BYPASS,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", # 5.4
                    confidence=0.3,
                    evidence=evidence,
                )
             )
        return findings
