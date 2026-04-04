"""
reporting/exporters/csv_exporter.py — CSV Data Exporter

Flattens findings into a spreadsheet-compatible comma-separated format.
"""

from __future__ import annotations

import csv
import io
from typing import Dict

class CSVExporter:
    async def export(self, report_data: Dict) -> bytes:
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Professional Security Header
        writer.writerow([
            "ID", "Type", "Label", "Severity", "Score", "Vector", 
            "CWE", "URL", "Parameter", "Confidence", "Status",
            "EA Relevant", "Breach Cost (UGX)"
        ])
        
        # Rows - Handling both technical sections and raw findings
        findings = report_data.get("findings", [])
        if not findings and "technical" in report_data:
             findings = [t.get("finding", t) for t in report_data["technical"]]

        for f in findings:
            cvss = f.get("cvss", {})
            if not isinstance(cvss, dict):
                 cvss = {}
                 
            ea = f.get("ea_context", {})
            if not isinstance(ea, dict):
                 ea = {}

            writer.writerow([
                f.get("id", "N/A"),
                f.get("vuln_type", "N/A"),
                f.get("vuln_label", "N/A"),
                f.get("severity", "N/A"),
                cvss.get("score", "0.0"),
                cvss.get("vector", "N/A"),
                f.get("cwe_id", "N/A"),
                f.get("url", "N/A"),
                f.get("parameter_name", f.get("parameter", "N/A")),
                f.get("confidence", "N/A"),
                f.get("remediation_status", "Open"),
                ea.get("ea_relevant", False),
                ea.get("potential_breach_cost", 0)
            ])
            
        return output.getvalue().encode("utf-8")
