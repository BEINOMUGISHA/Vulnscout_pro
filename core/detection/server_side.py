"""
server_side.py — Server-Side Vulnerability Detector (SSTI, Command Injection)

Responsibilities:
  - Detect Server-Side Template Injection (Jinaj2, Mako, Twig, Freelance, Smarty)
  - Detect OS Command Injection (Unix/Windows)
  - Complement existing SSRF and XXE detectors with advanced polyglots
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


class ServerSideDetector(BaseDetector):
    @property
    def meta(self) -> DetectorMeta:
        return DetectorMeta(
            detector_id="server_side",
            name="Server-Side Vulnerability Scanner",
            description="Tests for SSTI, OS Command Injection, and advanced backend flaws.",
            vuln_types=[VulnType.SSTI, VulnType.COMMAND_INJECTION],
            owasp_categories=["A03:2021 – Injection"],
            estimated_requests_per_endpoint=20,
        )

    @property
    def payloads(self) -> List[Payload]:
        return []

    async def detect(self, target, crawl_result, injector) -> List[Finding]:
        findings = []
        
        # 1. SSTI Checks
        findings.extend(await self._check_ssti(target, crawl_result, injector))
        
        # 2. OS Command Injection Checks
        findings.extend(await self._check_command_injection(target, crawl_result, injector))

        return findings

    async def _check_ssti(self, target, crawl_result, injector) -> List[Finding]:
        findings = []
        # Mathematical polyglot payloads for different template engines
        # {{7*7}} -> 49 (Jinja2, Twig)
        # ${7*7} -> 49 (Mako, FreeMarker)
        # <%= 7*7 %> -> 49 (ERB)
        # {7*7} -> 49 (Smarty)
        
        ssti_payloads = [
            ("{{7*7}}", "49", "Jinja2/Twig"),
            ("${7*7}", "49", "Mako/FreeMarker/JSP"),
            ("<%= 7*7 %>", "49", "ERB"),
            ("{7*7}", "49", "Smarty"),
            ("{{ 7 * '7' }}", "7777777", "Jinja2/Python/Mako"),
        ]
        
        for param in crawl_result.parameters:
            for payload_val, expected, engine in ssti_payloads:
                from core.scanner.injector import InjectionRequest
                req = InjectionRequest(
                    url=crawl_result.url,
                    method=crawl_result.method,
                    parameter_name=param.name,
                    parameter_location=param.location,
                    original_value=param.value,
                    payload=payload_val,
                )
                resp = await injector.inject(req)
                
                # Check for successful evaluation and NO reflection of the actual payload chars like '*'
                if expected in resp.body and payload_val not in resp.body:
                    evidence = FindingEvidence(
                        request_method=crawl_result.method,
                        request_url=crawl_result.url,
                        injected_parameter=param.name,
                        injected_payload=payload_val,
                        response_status=resp.status_code,
                        response_body_excerpt=resp.body[:500],
                        matched_pattern=f"SSTI detected ({engine}): '{payload_val}' evaluated to '{expected}'",
                    )
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            url=crawl_result.url,
                            parameter_name=param.name,
                            parameter_location=param.location,
                            vuln_type=VulnType.SSTI,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", # 9.8
                            confidence=0.9,
                            evidence=evidence,
                        )
                    )
        return findings

    async def _check_command_injection(self, target, crawl_result, injector) -> List[Finding]:
        findings = []
        # Time-based and error-based command injection payloads
        cmd_payloads = [
            ("| sleep 10", "time"),
            ("; sleep 10", "time"),
            ("`sleep 10`", "time"),
            ("& timeout /t 10", "time"), # Windows
            ("| id", "id"),
            ("; id", "uid="),
            ("`id`", "uid="),
            ("|| id", "uid="),
            ("&& id", "uid="),
            (";whoami", "www-data"),
        ]
        
        for param in crawl_result.parameters:
            for payload_val, type_check in cmd_payloads:
                from core.scanner.injector import InjectionRequest
                req = InjectionRequest(
                    url=crawl_result.url,
                    method=crawl_result.method,
                    parameter_name=param.name,
                    parameter_location=param.location,
                    original_value=param.value,
                    payload=payload_val,
                )
                
                import time
                start = time.time()
                resp = await injector.inject(req)
                duration = time.time() - start
                
                # Time-based check
                if type_check == "time" and duration >= 9.5: # Allow for network latency
                    evidence = FindingEvidence(
                        request_method=crawl_result.method,
                        request_url=crawl_result.url,
                        injected_parameter=param.name,
                        injected_payload=payload_val,
                        response_status=resp.status_code,
                        timing_delta_ms=duration * 1000,
                        matched_pattern=f"Time-based command injection detected",
                    )
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            url=crawl_result.url,
                            parameter_name=param.name,
                            parameter_location=param.location,
                            vuln_type=VulnType.COMMAND_INJECTION,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", # 9.8
                            confidence=0.8,
                            evidence=evidence,
                        )
                    )
                # Reflection-based check (e.g., id output)
                elif type_check == "uid=" and "uid=" in resp.body and "gid=" in resp.body:
                    evidence = FindingEvidence(
                        request_method=crawl_result.method,
                        request_url=crawl_result.url,
                        injected_parameter=param.name,
                        injected_payload=payload_val,
                        response_status=resp.status_code,
                        response_body_excerpt=resp.body[:500],
                        matched_pattern=f"Reflected command injection detected",
                    )
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            url=crawl_result.url,
                            parameter_name=param.name,
                            parameter_location=param.location,
                            vuln_type=VulnType.COMMAND_INJECTION,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", # 9.8
                            confidence=1.0,
                            evidence=evidence,
                        )
                    )
        return findings
