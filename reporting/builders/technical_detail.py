"""
reporting/builders/technical_detail.py — Technical Findings Builder

Detailed breakdown of every discovered vulnerability, including
evidence, request/reproduction steps, and CVSS vectors.
"""

from __future__ import annotations

from typing import Dict, List
from core.models.scan import Scan

class TechnicalDetailBuilder:
    def __init__(self, scan: Scan) -> None:
        self.scan = scan

    def build(self, include_evidence: bool = True) -> List[Dict]:
        """Return a list of detailed finding blocks."""
        return [
            self._format_finding(f, include_evidence)
            for f in sorted(self.scan.findings, key=lambda x: getattr(x, "risk_priority", 999))
        ]

    def _format_finding(self, finding, include_evidence: bool) -> Dict:
        data = {
            "id": finding.id,
            "vuln_type": finding.vuln_type,
            "vuln_label": finding.vuln_label,
            "severity": finding.severity.upper() if hasattr(finding.severity, "upper") else str(finding.severity).upper(),
            "url": finding.url,
            "parameter": finding.parameter_name,
            "description": finding.description,
            "impact": getattr(finding, "business_impact", "Exploitation of this vulnerability allows unauthorized access to sensitive application components and data stores."),
            "cvss": {
                "score": finding.cvss_score,
                "vector": finding.cvss_vector,
                "effective_score": getattr(finding, "effective_cvss", finding.cvss_score)
            },
            "location": f"{finding.url} [{finding.parameter_name or 'N/A'}]",
            "source_context": getattr(finding, "parameter_location", "Request Parameter"),
            "confidence": finding.confidence,
        }

        if include_evidence:
            data["evidence"] = {
                "request": getattr(finding.evidence, "request_body", "") or "[No Body]",
                "response": getattr(finding.evidence, "response_body_excerpt", "") or "[No Excerpt]",
                "explanation": getattr(finding, "confirmation_evidence", ""),
                "method": getattr(finding.evidence, "request_method", "GET"),
                "headers": getattr(finding.evidence, "request_headers", {})
            }

        if hasattr(finding, "ea_context") and finding.ea_context:
            data["ea_context"] = {
                "regulatory_multiplier": finding.ea_context.max_regulatory_multiplier,
                "compliance_impact": [req["description"] for req in finding.ea_context.regulatory_requirements]
            }

        return data
