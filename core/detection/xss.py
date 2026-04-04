"""
xss.py — Cross-Site Scripting (XSS) Detector

Covers:
  - Reflected XSS: payload echoed directly in HTML response
  - Stored XSS: payload stored and served to other users (differential approach)
  - DOM XSS indicators: dangerous JS sinks detected in source
"""

from __future__ import annotations

import re
from typing import List

from core.detection.base_detector import BaseDetector, DetectorMeta, Payload
from core.models.finding import VulnType

_CVSS_REFLECTED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"   # 6.1
_CVSS_STORED    = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N"   # 5.4
_CVSS_DOM       = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N"   # 4.7

# Unique canary appended to payloads for precise reflection detection
_CANARY = "v5c0u7t"


class XSSDetector(BaseDetector):

    @property
    def meta(self) -> DetectorMeta:
        return DetectorMeta(
            detector_id="xss",
            name="Cross-Site Scripting (XSS)",
            description="Detects reflected, stored, and DOM-based XSS",
            vuln_types=[VulnType.XSS_REFLECTED, VulnType.XSS_STORED, VulnType.XSS_DOM],
            owasp_categories=["A03:2021 – Injection"],
            estimated_requests_per_endpoint=12,
        )

    @property
    def payloads(self) -> List[Payload]:
        c = _CANARY
        return [
            # ── Reflected XSS ──────────────────────────────────────────────────
            Payload(
                value=f'<script>alert("{c}")</script>',
                description="Basic script tag injection",
                evidence_pattern=rf'<script>alert\("{c}"\)</script>',
                false_positive_pattern=r"(?i)(sanitized|escaped|encoded|&lt;script)",
                vuln_type=VulnType.XSS_REFLECTED,
                cvss_vector=_CVSS_REFLECTED,
                confidence_boost=0.45,
            ),
            Payload(
                value=f'"><script>alert("{c}")</script>',
                description="Attribute breakout + script tag",
                evidence_pattern=rf'"><script>alert\("{c}"\)</script>',
                vuln_type=VulnType.XSS_REFLECTED,
                cvss_vector=_CVSS_REFLECTED,
                confidence_boost=0.45,
            ),
            Payload(
                value=f"'><img src=x onerror=alert('{c}')>",
                description="Single quote breakout + onerror handler",
                evidence_pattern=rf"onerror=alert\('{c}'\)",
                vuln_type=VulnType.XSS_REFLECTED,
                cvss_vector=_CVSS_REFLECTED,
                confidence_boost=0.4,
            ),
            Payload(
                value=f'<svg onload=alert("{c}")>',
                description="SVG onload — bypasses many HTML filters",
                evidence_pattern=rf'onload=alert\("{c}"\)',
                vuln_type=VulnType.XSS_REFLECTED,
                cvss_vector=_CVSS_REFLECTED,
                confidence_boost=0.4,
            ),
            Payload(
                value=f'<img src=x onerror=alert("{c}")>',
                description="img onerror injection",
                evidence_pattern=rf'onerror=alert\("{c}"\)',
                vuln_type=VulnType.XSS_REFLECTED,
                cvss_vector=_CVSS_REFLECTED,
                confidence_boost=0.4,
            ),
            # WAF-bypass variants
            Payload(
                value=f'<ScRiPt>alert("{c}")</ScRiPt>',
                description="Mixed-case tag bypass",
                evidence_pattern=rf'(?i)<script>alert\("{c}"\)</script>',
                vuln_type=VulnType.XSS_REFLECTED,
                cvss_vector=_CVSS_REFLECTED,
                confidence_boost=0.35,
            ),
            Payload(
                value=f'<scr\x00ipt>alert("{c}")</scr\x00ipt>',
                description="Null-byte tag bypass",
                evidence_pattern=rf'alert\("{c}"\)',
                vuln_type=VulnType.XSS_REFLECTED,
                cvss_vector=_CVSS_REFLECTED,
                confidence_boost=0.35,
            ),
            Payload(
                value=f'javascript:alert("{c}")',
                description="javascript: protocol in href/src context",
                evidence_pattern=rf'javascript:alert\("{c}"\)',
                vuln_type=VulnType.XSS_REFLECTED,
                cvss_vector=_CVSS_REFLECTED,
                confidence_boost=0.35,
            ),
            # JSON context
            Payload(
                value=f'"}}</script><script>alert("{c}")</script>',
                description="JSON context breakout",
                evidence_pattern=rf'<script>alert\("{c}"\)</script>',
                vuln_type=VulnType.XSS_REFLECTED,
                cvss_vector=_CVSS_REFLECTED,
                confidence_boost=0.4,
            ),

            # ── Stored XSS probes ──────────────────────────────────────────────
            # These use a distinctive marker to identify persistence
            Payload(
                value=f'<b id="vsxss_{c}">XSStest</b>',
                description="Stored XSS — persistent HTML tag probe",
                evidence_pattern=rf'id="vsxss_{c}"',
                vuln_type=VulnType.XSS_STORED,
                cvss_vector=_CVSS_STORED,
                confidence_boost=0.4,
            ),

            # Context-Aware / Encoding Bypasses
            Payload(
                value=f'javascript:alert(document.domain)//{c}',
                description="javascript: protocol handler (XSS in <a> href)",
                evidence_pattern=rf'href="javascript:alert\(document\.domain\)//{c}"',
                vuln_type=VulnType.XSS_REFLECTED,
                cvss_vector=_CVSS_REFLECTED,
                confidence_boost=0.45,
            ),
            Payload(
                value=f'%3cscript%3ealert(%22{c}%22)%3c/script%3e',
                description="URL-encoded script tag (bypasses basic URL filters)",
                evidence_pattern=rf'<script>alert\("{c}"\)</script>',
                vuln_type=VulnType.XSS_REFLECTED,
                cvss_vector=_CVSS_REFLECTED,
                confidence_boost=0.35,
            ),
            Payload(
                value=f'"-alert("{c}")-"',
                description="JavaScript string context escape",
                evidence_pattern=rf'alert\("{c}"\)',
                vuln_type=VulnType.XSS_REFLECTED,
                cvss_vector=_CVSS_REFLECTED,
                confidence_boost=0.4,
            ),
        ]

    # DOM XSS sink patterns (detected statically from JS source)
    _DOM_SINKS = re.compile(
        r"""(?x)
        (document\.write\s*\(|
         innerHTML\s*=|
         outerHTML\s*=|
         eval\s*\(|
         setTimeout\s*\(|
         setInterval\s*\(|
         location\.href\s*=|
         location\.assign\s*\(|
         location\.replace\s*\(|
         window\.open\s*\()
        """,
        re.IGNORECASE,
    )
    _DOM_SOURCES = re.compile(
        r"""(?x)
        (location\.search|
         location\.hash|
         document\.referrer|
         document\.URL|
         document\.documentURI|
         URLSearchParams|
         window\.name)
        """,
        re.IGNORECASE,
    )

    async def detect(self, target, crawl_result, injector) -> list:
        findings = []

        # 1. Parameter-based reflection testing in parallel
        async def test_parameter(param):
            if not self._should_test_parameter(param, crawl_result):
                return None
            if param.location == "header":
                return None

            # Establish baseline
            baseline = await self._get_baseline(injector, crawl_result, param)

            # Test all payloads for this parameter concurrently
            async def test_one(payload):
                return await self._test_payload(injector, crawl_result, param, payload, baseline)

            payload_results = await asyncio.gather(*[test_one(p) for p in self.payloads], return_exceptions=True)
            
            param_findings = []
            for hit in payload_results:
                if isinstance(hit, DetectionHit) and hit:
                    self._log_hit(self.meta.detector_id, crawl_result.url, param.name, hit.matched_text)
                    ea_ctx = self._build_ea_context(target)
                    param_findings.append(self._build_finding(hit, ea_context=ea_ctx))
            return param_findings

        # Orchestrate all parameters concurrently
        results = await asyncio.gather(*[test_parameter(p) for p in crawl_result.parameters], return_exceptions=True)
        for res in results:
            if isinstance(res, list):
                findings.extend(res)

        # 2. DOM XSS static analysis on HTML/JS response
        if "text/html" in crawl_result.content_type or ".js" in crawl_result.url:
            dom_findings = self._check_dom_xss(crawl_result)
            findings.extend(dom_findings)

        return findings

    def _check_dom_xss(self, crawl_result) -> list:
        """
        Static analysis for DOM XSS sink+source patterns in page source.
        Only flags when both a source and a dangerous sink are present.
        """
        from core.models.finding import Finding, FindingEvidence, EAContext
        import uuid

        body = getattr(crawl_result, "_raw_body", "")
        if not body:
            return []

        has_sink   = bool(self._DOM_SINKS.search(body))
        has_source = bool(self._DOM_SOURCES.search(body))

        if not (has_sink and has_source):
            return []

        sink_match   = self._DOM_SINKS.search(body)
        source_match = self._DOM_SOURCES.search(body)

        evidence = FindingEvidence(
            request_url=crawl_result.url,
            request_method=crawl_result.method,
            response_body_excerpt=(
                f"Dangerous sink: {sink_match.group(0)} | "
                f"Taint source: {source_match.group(0)}"
            ),
            matched_pattern="DOM sink + source pattern",
        )

        return [Finding(
            id=str(uuid.uuid4()),
            url=crawl_result.url,
            parameter_name="DOM",
            parameter_location="dom",
            vuln_type=VulnType.XSS_DOM,
            cvss_vector=_CVSS_DOM,
            confidence=0.55,
            evidence=evidence,
            evidence_pattern="DOM XSS static analysis",
        )]

    def _build_ea_context(self, target) -> dict:
        return {"ea_relevant": False}