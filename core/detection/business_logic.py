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
from typing import List

from core.detection.base_detector import (
    BaseDetector,
    DetectorMeta,
    Payload,
    DetectionHit,
)
from core.models.finding import Severity, VulnType

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

    async def detect(self, target, crawl_result, injector) -> List[DetectionHit]:
        hits = []
        
        # 1. Price Manipulation checks
        hits.extend(await self._check_price_manipulation(target, crawl_result, injector))
        
        # 2. Coupon/Discount Logic checks
        hits.extend(await self._check_coupon_logic(target, crawl_result, injector))
        
        # 3. Transaction/Flow Integrity
        hits.extend(await self._check_parameter_pollution(target, crawl_result, injector))

        # 4. Workflow Bypass
        hits.extend(await self._check_workflow_bypass(target, crawl_result, injector))

        return hits

    async def _check_price_manipulation(self, target, crawl_result, injector) -> List[DetectionHit]:
        hits = []
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
                        hits.append(
                            DetectionHit(
                                detector_id=self.meta.detector_id,
                                vuln_type=VulnType.PRICE_MANIPULATION,
                                severity=Severity.HIGH,
                                confidence=0.6,
                                evidence=f"Price parameter '{param.name}' accepted value '{p}' (Status {resp.status_code})",
                                url=crawl_result.url,
                                parameter=param.name,
                            )
                        )
        return hits

    async def _check_coupon_logic(self, target, crawl_result, injector) -> List[DetectionHit]:
        hits = []
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
                         hits.append(
                            DetectionHit(
                                detector_id=self.meta.detector_id,
                                vuln_type=VulnType.COUPON_ABUSE,
                                severity=Severity.MEDIUM,
                                confidence=0.5,
                                evidence=f"Coupon/Promo parameter '{param.name}' accepted test value '{p}'",
                                url=crawl_result.url,
                                parameter=param.name,
                            )
                        )
        return hits

    async def _check_parameter_pollution(self, target, crawl_result, injector) -> List[DetectionHit]:
        hits = []
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
                    hits.append(
                        DetectionHit(
                            detector_id=self.meta.detector_id,
                            vuln_type=VulnType.PARAM_POLLUTION,
                            severity=Severity.LOW,
                            confidence=0.7,
                            evidence=f"Reflected value from polluted parameter '{target_p.name}'.",
                            url=crawl_result.url,
                            parameter=target_p.name,
                        )
                    )
        return hits

    async def _check_workflow_bypass(self, target, crawl_result, injector) -> List[DetectionHit]:
        """Detects if 'final' or 'execute' endpoints can be reached directly."""
        hits = []
        bypass_keywords = ["confirm", "final", "execute", "apply", "checkout", "process", "success"]
        url_lower = crawl_result.url.lower()
        
        # If the URL looks like a final step but we reached it via simple crawl/GET
        if any(kw in url_lower for kw in bypass_keywords) and crawl_result.method == "GET":
             # This is a weak signal on its own, but we mark it for manual review
             hits.append(
                DetectionHit(
                    detector_id=self.meta.detector_id,
                    vuln_type=VulnType.WORKFLOW_BYPASS,
                    severity=Severity.LOW,
                    confidence=0.3,
                    evidence=f"Endpoint '{crawl_result.url}' contains final-step keywords and is accessible via GET.",
                    url=crawl_result.url,
                    parameter=None
                )
             )
        return hits
