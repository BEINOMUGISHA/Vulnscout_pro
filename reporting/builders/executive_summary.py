"""
reporting/builders/executive_summary.py — Executive Overview Builder

Generates high-level scan statistics, risk posture assessment, 
and critical finding callouts for non-technical stakeholders.
"""

from __future__ import annotations

from typing import Dict, List, Optional
from core.models.scan import Scan
from core.models.finding import Severity

class ExecutiveSummaryBuilder:
    def __init__(self, scan: Scan, trend_data: Optional[List[Dict]] = None) -> None:
        self.scan = scan
        self.trend_data = trend_data or []

    def build(self) -> Dict:
        findings = self.scan.findings
        
        # Calculate severity counts
        severity_counts = {
            "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            "high":     sum(1 for f in findings if f.severity == Severity.HIGH),
            "medium":   sum(1 for f in findings if f.severity == Severity.MEDIUM),
            "low":      sum(1 for f in findings if f.severity == Severity.LOW),
            "info":     sum(1 for f in findings if f.severity == Severity.INFORMATIONAL),
        }

        # Calculate high-level metrics
        active_duration = 0
        if self.scan.started_at and self.scan.completed_at:
            # Simplified duration calculation
            active_duration = 120 # Placeholder

        return {
            "risk_score": getattr(self.scan, "ea_risk_score", 0.0),
            "severity_counts": severity_counts,
            "total_findings": len(findings),
            "critical_callouts": self._get_critical_callouts(findings),
            "scan_metrics": {
                "duration_seconds": active_duration,
                "endpoints_crawled": getattr(self.scan.metrics, "pages_crawled", 0),
                "total_requests": getattr(self.scan.metrics, "total_requests_sent", 0),
            },
            "status_summary": self._generate_status_text(severity_counts),
            "trend_analysis": self._get_trend_analysis(),
            "remediation_priority": self._get_remediation_priority_matrix(findings)
        }

    def _get_critical_callouts(self, findings: List) -> List[Dict]:
        """Call out the top 3 most critical findings."""
        sorted_findings = sorted(
            findings, 
            key=lambda f: getattr(f, "risk_priority", 999)
        )
        return [
            {
                "title": f.vuln_type,
                "severity": f.severity.value,
                "url": f.url,
                "impact": f.description[:100] + "..."
            }
            for f in sorted_findings[:3]
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]

    def _generate_status_text(self, counts: Dict) -> str:
        if counts["critical"] > 0:
            return "CRITICAL: Immediate remediation required. Multiple high-impact vulnerabilities were detected."
        if counts["high"] > 0:
            return "HIGH: Significant risks detected. Remediation should be prioritised."
        if counts["medium"] > 0:
            return "WARNING: Moderate risks detected. Schedule remediation in the next maintenance window."
        return "SECURE: No critical or high risks detected."

    def _get_trend_analysis(self) -> Dict:
        """Analyze changes compared to previous scans."""
        if not self.trend_data or len(self.trend_data) < 2:
            return {"available": False, "message": "Insufficient data for trend analysis."}
        
        # Compare current with previous
        current = self.trend_data[0].get("stats", {})
        previous = self.trend_data[1].get("stats", {})
        
        diff = current.get("total", 0) - previous.get("total", 0)
        direction = "up" if diff > 0 else "down" if diff < 0 else "unchanged"
        
        return {
            "available": True,
            "direction": direction,
            "difference": abs(diff),
            "message": f"Vulnerability count has gone {direction} by {abs(diff)} since last scan."
        }

    def _get_remediation_priority_matrix(self, findings: List) -> List[Dict]:
        """Categorize findings for immediate action vs scheduled fix."""
        matrix = []
        for f in sorted(findings, key=lambda x: getattr(x, "risk_priority", 100)):
            if len(matrix) >= 5: break # Top 5 only
            
            matrix.append({
                "vuln": f.vuln_type,
                "priority_rank": getattr(f, "risk_priority", "--"),
                "urgency": "Immediate" if f.severity == Severity.CRITICAL else "Next Sprint",
                "business_impact": getattr(f, "business_impact", "Standard"),
                "ea_regulatory": getattr(getattr(f, "ea_context", None), "ea_relevant", False)
            })
        return matrix
