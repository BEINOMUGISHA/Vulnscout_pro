"""
sarif_exporter.py — SARIF v2.1.0 Report Exporter

Responsibilities:
  - Convert VulnScout Finding objects to SARIF format
  - Map our internal vuln_types to CWE IDs
  - Provide evidence and location data in SARIF structures
"""

from __future__ import annotations

import json
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


class SarifExporter:
    """
    Exports findings as SARIF v2.1.0 JSON.
    """

    async def export(self, report_data: Dict) -> bytes:
        """
        Build the SARIF document.
        """
        findings = report_data.get("findings", [])
        if not findings and "technical" in report_data:
             findings = [t.get("finding", t) for t in report_data["technical"]]

        sarif = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "VulnScout Pro",
                            "semanticVersion": "1.0.0",
                            "informationUri": "https://vulnscout.com",
                            "rules": self._build_rules(findings)
                        }
                    },
                    "results": self._build_results(findings)
                }
            ]
        }
        return json.dumps(sarif, indent=2).encode("utf-8")

    def _build_rules(self, findings: List[Dict]) -> List[Dict]:
        rules = {}
        for f in findings:
            vuln_type = f.get("vuln_type")
            if vuln_type not in rules:
                rules[vuln_type] = {
                    "id": vuln_type,
                    "shortDescription": {"text": f.get("vuln_label")},
                    "helpUri": f"https://vulnscout.com/vulns/{vuln_type}",
                    "properties": {
                        "problem.severity": self._map_severity(f.get("severity")),
                        "security-severity": str(f.get("cvss_score", 0.0))
                    }
                }
        return list(rules.values())

    def _build_results(self, findings: List[Dict]) -> List[Dict]:
        results = []
        for f in findings:
            results.append({
                "ruleId": f.get("vuln_type"),
                "level": self._map_sarif_level(f.get("severity")),
                "message": {"text": f.get("vuln_label")},
                "locations": [
                    {
                        "physicalLocation": {
                            "address": {
                                "fullyQualifiedName": f.get("url")
                            }
                        }
                    }
                ],
                "partialFingerprints": {
                    "primary": f.get("fingerprint", f.get("id"))
                }
            })
        return results

    def _map_severity(self, severity: str) -> str:
        s = severity.lower()
        if s in ["critical", "high"]: return "error"
        if s == "medium": return "warning"
        return "recommendation"

    def _map_sarif_level(self, severity: str) -> str:
        s = severity.lower()
        if s in ["critical", "high"]: return "error"
        if s == "medium": return "warning"
        return "note"
