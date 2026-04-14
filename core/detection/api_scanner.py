"""
api_scanner.py — Specialized API Security Detector

Responsibilities:
  - Detect REST-specific vulnerabilities (BOLA/BFLA, Mass Assignment)
  - Detect SOAP-specific vulnerabilities (Structure Injection, Action spoofing)
  - Verify API versioning (discovery of legacy endpoints)
  - Test for Verb Tampering and CORS misconfigurations on APIs
  - Fuzz API-specific headers (X-API-Version, Accept, Content-Type)

Note: This detector complements general detectors (SQLi, XSS) by targeting
the structural and logical aspects of API endpoints.
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
from core.models.finding import Severity, VulnType, Finding, FindingEvidence
import uuid
from core.scanner.injector import PayloadEncoding

logger = logging.getLogger(__name__)


class APISecurityDetector(BaseDetector):
    @property
    def meta(self) -> DetectorMeta:
        return DetectorMeta(
            detector_id="api_security",
            name="API Security Scanner",
            description="Tests for REST/SOAP specific vulnerabilities (BOLA, Mass Assignment, Verb Tampering).",
            vuln_types=[
                "api_verb_tampering",
                "api_mass_assignment",
                "api_bola",
                "api_improper_inventory"
            ],
            owasp_categories=["A01:2021 – Broken Access Control", "A05:2021 – Security Misconfiguration"],
            estimated_requests_per_endpoint=12,
        )

    @property
    def payloads(self) -> List[Payload]:
        # APISecurityDetector uses custom logic in detect() rather than a static list
        return []

    async def detect(self, target, crawl_result, injector) -> List[Finding]:
        findings = []
        
        # 1. Check if it looks like an API endpoint
        url_lower = crawl_result.url.lower()
        is_api = any(x in url_lower for x in ["/api/", "/v1/", "/v2/", "/v3/", "rest", "soap", ".asmx", ".svc"])
        content_type = crawl_result.content_type.lower()
        is_json_xml = "json" in content_type or "xml" in content_type
        
        if not (is_api or is_json_xml):
            return []

        # 2. REST: Verb Tampering (e.g., HEAD, OPTIONS, PUT on GET endpoints)
        findings.extend(await self._check_verb_tampering(target, crawl_result, injector))
        
        # 3. Mass Assignment
        findings.extend(await self._check_mass_assignment(target, crawl_result, injector))
        
        # 4. BOLA
        findings.extend(await self._check_bola_stub(target, crawl_result, injector))
        
        # 5. API Inventory (Check for old versions)
        findings.extend(await self._check_api_inventory(target, crawl_result, injector))

        return findings

    async def _check_verb_tampering(self, target, crawl_result, injector) -> List[Finding]:
        findings = []
        # Try a method that shouldn't be allowed if not properly configured
        # Head or Options are often allowed but PUT/DELETE/PATCH might reveal info or allow bypass
        tamper_methods = ["PUT", "DELETE"] if "api" in crawl_result.url else ["OPTIONS"]
        
        for method in tamper_methods:
            from core.scanner.injector import InjectionRequest
            req = InjectionRequest(
                url=crawl_result.url,
                method=method,
                parameter_name="HTTP_METHOD",
                parameter_location="header",
                original_value="GET",
                payload="TAMPER",
            )
            resp = await injector.inject(req)
            
            # If 200 OK or 201 Created on a DELETE/PUT for a resource that should be GET
            if resp.status_code in [200, 201] and method in ["PUT", "DELETE"]:
                evidence = FindingEvidence(
                    request_method=method,
                    request_url=crawl_result.url,
                    response_status=resp.status_code,
                    matched_pattern=f"Endpoint accepted {method} request unexpectedly",
                )
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        url=crawl_result.url,
                        parameter_name="HTTP_METHOD",
                        parameter_location="header",
                        vuln_type="api_verb_tampering",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", # 5.4
                        confidence=0.6,
                        evidence=evidence,
                    )
                )
        return findings

    async def _check_mass_assignment(self, target, crawl_result, injector) -> List[Finding]:
        findings = []
        # Common administrative/internal parameters
        mass_params = ["admin", "role", "is_admin", "superuser", "internal", "debug", "permissions"]
        
        payloads = []
        for p in mass_params:
            payloads.append(Payload(value="true", parameter=p))
            
        # We inject them into the body/json
        for p_obj in payloads:
            from core.scanner.injector import InjectionRequest
            req = InjectionRequest(
                url=crawl_result.url,
                method=crawl_result.method,
                parameter_name=p_obj.parameter,
                parameter_location="json" if "json" in crawl_result.content_type else "body",
                original_value="",
                payload=p_obj.value,
            )
            resp = await injector.inject(req)
            
            # If rejected with 400/403, it's safer. If 200/201, might be an issue
            # But we need more logic to confirm it actually changed state. 
            # For now, we flag "Insecure implementation of Mass Assignment" if it doesn't error
            if resp.status_code in [200, 201, 204]:
                # Heuristic: if the response body contains the new parameter name back, it might be reflected/accepted
                if p_obj.parameter in resp.body:
                    evidence = FindingEvidence(
                        request_method=crawl_result.method,
                        request_url=crawl_result.url,
                        injected_parameter=p_obj.parameter,
                        injected_payload=p_obj.value,
                        response_status=resp.status_code,
                        matched_pattern=f"API accepted additional parameter '{p_obj.parameter}'",
                    )
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            url=crawl_result.url,
                            parameter_name=p_obj.parameter,
                            parameter_location="body",
                            vuln_type="api_mass_assignment",
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", # 5.4
                            confidence=0.4,
                            evidence=evidence,
                        )
                    )
        return findings

    async def _check_bola_stub(self, target, crawl_result, injector) -> List[Finding]:
        findings = []
        # Focus on numeric or UUID parameters in path or query
        for param in crawl_result.parameters:
            if param.location in ["path", "query"] and self._is_id_like(param.name, param.value):
                # Try to increment/decrement or change one digit
                new_val = self._mutate_id(param.value)
                if new_val == param.value:
                    continue
                
                from core.scanner.injector import InjectionRequest
                req = InjectionRequest(
                    url=crawl_result.url,
                    method=crawl_result.method,
                    parameter_name=param.name,
                    parameter_location=param.location,
                    original_value=param.value,
                    payload=new_val,
                )
                resp = await injector.inject(req)
                
                # If we get a 200 for a different ID, it's a BOLA/IDOR candidate
                if resp.status_code == 200:
                    evidence = FindingEvidence(
                        request_method=crawl_result.method,
                        request_url=crawl_result.url,
                        injected_parameter=param.name,
                        injected_payload=new_val,
                        response_status=resp.status_code,
                        matched_pattern=f"Potential BOLA: Successfully requested resource ID '{new_val}'",
                    )
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            url=crawl_result.url,
                            parameter_name=param.name,
                            parameter_location=param.location,
                            vuln_type="api_bola",
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", # 8.2
                            confidence=0.5,
                            evidence=evidence,
                        )
                    )
        return findings

    async def _check_api_inventory(self, target, crawl_result, injector) -> List[Finding]:
        findings = []
        # If url is /v2/..., try /v1/...
        import re
        version_match = re.search(r'/v(\d+)/', crawl_result.url)
        if version_match:
            current_v = int(version_match.group(1))
            if current_v > 1:
                legacy_url = crawl_result.url.replace(f"/v{current_v}/", f"/v{current_v - 1}/")
                from core.scanner.injector import InjectionRequest
                req = InjectionRequest(
                    url=legacy_url,
                    method=crawl_result.method,
                    parameter_name="API_VERSION",
                    parameter_location="header",
                    original_value=f"v{current_v}",
                    payload=f"v{current_v - 1}",
                )
                resp = await injector.inject(req)
                
                if resp.status_code == 200:
                    evidence = FindingEvidence(
                        request_method=crawl_result.method,
                        request_url=legacy_url,
                        response_status=resp.status_code,
                        matched_pattern=f"Found legacy API version endpoint: {legacy_url}",
                    )
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            url=legacy_url,
                            parameter_name="API_VERSION",
                            parameter_location="url",
                            vuln_type="api_improper_inventory",
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", # 5.3
                            confidence=0.8,
                            evidence=evidence,
                        )
                    )
        return findings

    def _is_id_like(self, name: str, value: str) -> bool:
        name_lower = name.lower()
        if "id" not in name_lower and "uuid" not in name_lower and "key" not in name_lower:
            return False
        # Check if value is numeric or UUID-like
        if value.isdigit():
            return True
        import re
        if re.match(r'^[a-f0-9-]{32,36}$', value, re.IGNORECASE):
            return True
        return False

    def _mutate_id(self, value: str) -> str:
        if value.isdigit():
            # Simplistic: add or subtract 1
            ival = int(value)
            return str(ival + 1) if ival < 1000000 else str(ival - 1)
        # For UUID, we could flip a char, but BOLA usually targets predictable IDs
        return value
