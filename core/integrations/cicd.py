"""
cicd.py — CI/CD Pipeline Integrations

Responsibilities:
  - Integrate with CI/CD platforms to gate builds based on security findings
  - Output results in pipeline-friendly formats (SARIF, JUnit XML, JSON)
  - Provide platform-specific status reporting (Deployment statuses, PR comments)
"""

from __future__ import annotations

import logging
import json
import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class BuildGateResult:
    passed: bool
    fail_reason: Optional[str] = None
    finding_summary: Optional[Dict] = None


class CICDIntegration:
    """
    Base class for CI/CD platform integrations.
    """

    def __init__(self, platform_name: str, config: Optional[Dict] = None) -> None:
        self.platform_name = platform_name
        self.config = config or {}

    def check_gate(self, scan_result: Dict) -> BuildGateResult:
        """
        Check if the scan results should fail the build based on configured thresholds.
        Default: Fail on any Critical or High finding.
        """
        stats = scan_result.get("stats", {})
        critical = stats.get("critical", 0)
        high = stats.get("high", 0)
        
        # Thresholds from config or defaults
        fail_on_critical = self.config.get("fail_on_critical", True)
        fail_on_high = self.config.get("fail_on_high", True)
        max_high_allowed = self.config.get("max_high_allowed", 0)
        
        if fail_on_critical and critical > 0:
            return BuildGateResult(
                passed=False,
                fail_reason=f"Build failed: {critical} Critical vulnerabilities detected.",
                finding_summary=stats
            )
            
        if fail_on_high and high > max_high_allowed:
            return BuildGateResult(
                passed=False,
                fail_reason=f"Build failed: {high} High vulnerabilities detected (Threshold: {max_high_allowed}).",
                finding_summary=stats
            )
            
        return BuildGateResult(passed=True, finding_summary=stats)

    def generate_sarif(self, findings: List[Dict], target_url: str) -> str:
        """
        Generate a SARIF v2.1.0 report for GitHub/GitLab security tabs.
        """
        results = []
        rules = {}

        for f in findings:
            rule_id = f.get("vuln_type", "unknown")
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": f.get("vuln_label", rule_id)},
                    "fullDescription": {"text": f.get("description", "")},
                    "defaultConfiguration": {"level": self._map_severity_to_sarif(f.get("severity", "medium"))}
                }

            results.append({
                "ruleId": rule_id,
                "message": {"text": f.get("vuln_title", f.get("vuln_label"))},
                "locations": [{
                    "physicalLocation": {
                        "address": {"fullyQualifiedName": f.get("url", target_url)}
                    }
                }]
            })

        sarif = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "VulnScout Pro",
                        "version": "1.0",
                        "informationUri": "https://vulnscout.ug",
                        "rules": list(rules.values())
                    }
                },
                "results": results
            }]
        }
        return json.dumps(sarif, indent=2)

    def generate_junit_xml(self, findings: List[Dict], target_url: str) -> str:
        """Convert findings to JUnit XML for Jenkins/GitLab reporting."""
        time_str = datetime.now().isoformat()
        test_cases = []
        
        if not findings:
            # Pass case
            test_cases.append(f'  <testcase name="SecurityScan" classname="VulnScout" time="0" />')
        else:
            for f in findings:
                name = f.get('vuln_label', 'Vulnerability')
                severity = f.get('severity', 'medium')
                url = f.get('url', target_url)
                test_cases.append(
                    f'  <testcase name="{name}" classname="VulnScout.{severity}" time="0">\n'
                    f'    <failure message="Vulnerability found at {url}">{f.get("description")}</failure>\n'
                    f'  </testcase>'
                )

        xml = (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<testsuites>\n'
            f' <testsuite name="VulnScout Scan" tests="{max(1, len(findings))}" failures="{len(findings)}" timestamp="{time_str}">\n'
            + "\n".join(test_cases) + "\n"
            f' </testsuite>\n'
            f'</testsuites>'
        )
        return xml

    def _map_severity_to_sarif(self, severity: str) -> str:
        s = severity.lower()
        if s == "critical" or s == "high": return "error"
        if s == "medium": return "warning"
        return "note"


class GitHubActionsIntegration(CICDIntegration):
    def __init__(self, config: Optional[Dict] = None) -> None:
        super().__init__("github_actions", config)

    def report_status(self, scan_id: str, status: str, conclusion: Optional[str] = None):
        """Set a GitHub 'check run' status."""
        # Note: In a real implementation, this would use octokit or aiohttp to call GitHub API
        # Here we log the intention for the 'gate' logic to verify.
        logger.info("[GH Actions] Reporting check_run status='%s' conclusion='%s' for scan %s", 
                    status, conclusion, scan_id)


class GitLabIntegration(CICDIntegration):
    def __init__(self, config: Optional[Dict] = None) -> None:
        super().__init__("gitlab", config)

    def export_gl_security_report(self, findings: List[Dict]) -> str:
        """Format findings for GitLab Security Dashboard (JSON)."""
        gl_findings = []
        for f in findings:
            gl_findings.append({
                "id": str(uuid.uuid4()),
                "category": "sast", # Generic map
                "name": f.get("vuln_label"),
                "message": f.get("vuln_title"),
                "description": f.get("description"),
                "severity": f.get("severity").capitalize(),
                "scanner": {"id": "vulnscout_pro", "name": "VulnScout Pro"},
                "location": {"file": f.get("url"), "start_line": 0}
            })
        return json.dumps({"version": "15.0.0", "vulnerabilities": gl_findings, "remediations": []}, indent=2)


class JenkinsIntegration(CICDIntegration):
    def __init__(self, config: Optional[Dict] = None) -> None:
        super().__init__("jenkins", config)
        # Inherits generate_junit_xml
