"""
reporting/builders/remediation_guide.py — Remediation Advice Builder

Provides actionable fix guidance, code snippets, and verification 
steps for developers.
"""

from __future__ import annotations

from typing import Dict, List
from core.models.scan import Scan

class RemediationGuideBuilder:
    def __init__(self, scan: Scan) -> None:
        self.scan = scan

    def build(self) -> Dict[str, Dict]:
        """
        Group remediation guidance by vulnerability class.
        """
        guides = {}
        for finding in self.scan.findings:
            if finding.vuln_type not in guides:
                guides[finding.vuln_type] = {
                    "title": finding.vuln_type,
                    "summary": getattr(finding.remediation, "summary", "No summary available."),
                    "steps": getattr(finding.remediation, "steps", []),
                    "links": getattr(finding.remediation, "references", []),
                    "affected_endpoints": set()
                }
            guides[finding.vuln_type]["affected_endpoints"].add(finding.url)
        
        # Convert sets to lists for JSON compatibility
        for g in guides.values():
            g["affected_endpoints"] = sorted(list(g["affected_endpoints"]))
            
        return guides
