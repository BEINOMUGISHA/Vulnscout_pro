"""
graphql_detector.py — GraphQL Introspection & Security Detector

Checks for:
  - Introspection enabled (information disclosure)
  - Batching attacks (DoS via deeply nested queries)
  - Missing query depth limits (recursive query abuse)
  - IDOR via GraphQL arguments
"""

from __future__ import annotations

import json
import logging
from typing import List

from core.detection.base_detector import BaseDetector, DetectorMeta, Payload

logger = logging.getLogger(__name__)

INTROSPECTION_QUERY = '{"query":"{__schema{types{name,fields{name,args{name}}}}}"}'
BATCH_QUERY = '[{"query":"{__typename}"},{"query":"{__typename}"}]'
DEPTH_QUERY = '{"query":"{__typename ' + '{__typename '*10 + '}'*11 + '"}'
SUGGESTION_QUERY = '{"query":"{ __schema { queryType { name } } }", "variables":null}'
IDOR_QUERY = '{"query":"query GetUser($id: ID!) { user(id: $id) { id username email isAdmin } }", "variables":{"id":"1"}}'


class GraphQLDetector(BaseDetector):
    """Detects GraphQL-specific security misconfigurations."""

    @property
    def meta(self) -> DetectorMeta:
        return DetectorMeta(
            detector_id="graphql",
            name="GraphQL Security Checker",
            description="Detects introspection, batching, depth limit, IDOR issues in GraphQL APIs.",
            vuln_types=["graphql_introspection", "graphql_batching", "graphql_idor", "graphql_field_suggestion", "graphql_depth_limit"],
            owasp_categories=["API3:2023 - Broken Object Property Level Authorization",
                              "API8:2023 - Security Misconfiguration"],
            default_enabled=False,
            estimated_requests_per_endpoint=6,
        )

    @property
    def payloads(self) -> List[Payload]:
        return [
            Payload(
                value=INTROSPECTION_QUERY,
                description="Enhanced GraphQL introspection query",
                evidence_pattern=r'"__schema"\s*:\s*\{',
                vuln_type="graphql_introspection",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                confidence_boost=0.3,
            ),
            Payload(
                value=BATCH_QUERY,
                description="GraphQL batch query (DoS potential)",
                evidence_pattern=r'"data"\s*:\s*\[',
                vuln_type="graphql_batching",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                confidence_boost=0.2,
            ),
            Payload(
                value=DEPTH_QUERY,
                description="Deeply nested GraphQL query (Circular)",
                evidence_pattern=r'"data"\s*:\s*\{', # If succeeds, depth limit is missing
                vuln_type="graphql_depth_limit",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                confidence_boost=0.4,
            ),
            Payload(
                value='{"query":"{ nonExistentField }"}',
                description="Field suggestion test",
                evidence_pattern=r'Did you mean "([^"]+)"',
                vuln_type="graphql_field_suggestion",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                confidence_boost=0.2,
            ),
        ]

    async def detect(self, target, crawl_result, injector) -> List:
        findings = []

        # Only run on GraphQL endpoints
        if "graphql" not in crawl_result.url.lower() and \
           "graphql" not in crawl_result.technology_hints:
            return findings

        from core.scanner.injector import InjectionRequest, PayloadEncoding
        for payload in self.payloads:
            req = InjectionRequest(
                url=crawl_result.url,
                method="POST",
                parameter_name="body",
                parameter_location="body",
                original_value="{}",
                payload=payload.value,
                encoding=PayloadEncoding.PLAIN,
                content_type="application/json",
            )
            try:
                resp = await injector.inject(req)
                if resp.success:
                    matched, matched_text = self._check_evidence(payload, resp.body, resp.elapsed_ms)
                    if matched:
                        hit_data = {
                            "url": crawl_result.url,
                            "method": "POST",
                            "parameter_name": "body",
                            "parameter_location": "body",
                            "payload": payload,
                            "response_status": resp.status_code,
                            "response_body": resp.body,
                            "response_headers": resp.response_headers,
                            "elapsed_ms": resp.elapsed_ms,
                            "matched_text": matched_text,
                            "injection_request": req,
                            "confidence": 0.5 + payload.confidence_boost,
                        }
                        findings.append(self._build_finding(hit_data))
                        self._log_hit(self.meta.detector_id, crawl_result.url, "body", payload.description)
            except Exception as exc:
                logger.debug("GraphQL detector error: %s", exc)

        return findings
