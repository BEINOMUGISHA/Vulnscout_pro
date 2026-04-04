"""
compliance_builder.py — Regulatory Compliance Mapping Builder

Responsibilities:
  - Map Finding objects to specific compliance requirements/controls
  - Generate compliance-specific summaries for reports
  - Support multiple frameworks: PCI DSS, HIPAA, GDPR, ISO 27001, NIST 800-53
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ComplianceMapping:
    framework: str
    requirement_id: str
    requirement_title: str
    control_description: str


class ComplianceReportBuilder:
    """
    Builds a compliance-focused view of scan results.
    """

    # Static mapping of vuln_type to global compliance controls
    MAPPINGS = {
        "sqli": [
            ComplianceMapping("PCI DSS v4.0", "6.2.4.1", "Injection attacks", "Address injection flaws including SQL injection."),
            ComplianceMapping("ISO 27001:2022", "8.28", "Secure coding", "Secure coding principles shall be applied to software development."),
            ComplianceMapping("OWASP Top 10:2021", "A03", "Injection", "Vulnerabilities involving untrusted data being sent to an interpreter."),
        ],
        "xss_reflected": [
            ComplianceMapping("PCI DSS v4.0", "6.2.4.2", "Cross-Site Scripting (XSS)", "Address XSS flaws."),
            ComplianceMapping("NIST SP 800-53", "SI-10", "Information Input Validation", "The organization checks the validity of information inputs."),
        ],
        "sensitive_data": [
            ComplianceMapping("GDPR", "Article 32", "Security of processing", "Implementation of appropriate technical and organisational measures."),
            ComplianceMapping("HIPAA", "164.312(a)(1)", "Access Control", "Implement technical policies and procedures for electronic information systems."),
        ],
        "idor": [
            ComplianceMapping("OWASP Top 10:2021", "A01", "Broken Access Control", "Failures in access control allowing users to act outside intended permissions."),
            ComplianceMapping("ISO 27001:2022", "8.2", "Privileged access rights", "Allocation and use of privileged access rights shall be restricted."),
        ],
        # ... Add more mappings for all VulnTypes
    }

    def build_compliance_summary(self, findings: List[Dict]) -> Dict:
        """
        Groups findings by compliance framework and requirement.
        """
        results = {
            "pci_dss": {"status": "PASS", "violations": []},
            "gdpr": {"status": "PASS", "violations": []},
            "iso_27001": {"status": "PASS", "violations": []},
            "owasp_top_10": {"status": "PASS", "violations": []},
            "uganda_pdpa": {"status": "PASS", "violations": []},
            "uganda_cma": {"status": "PASS", "violations": []},
            "bou_cyber": {"status": "PASS", "violations": []},
        }
        
        from core.context.threat_intel import engine as threat_engine
        
        for f in findings:
            vuln_type = f.get("vuln_type")
            mappings = self.MAPPINGS.get(vuln_type, [])
            
            # Global mappings
            for m in mappings:
                key = m.framework.lower().replace(" ", "_").split(":")[0].split("v")[0].rstrip("_")
                # ... rest of global mapping logic remains same ...
                if key in results:
                    results[key]["violations"].append({
                        "finding_id": f.get("id"),
                        "vuln_type": vuln_type,
                        "requirement": m.requirement_id,
                        "description": m.control_description
                    })

            # Integrated EA-specific mappings from threat_intel
            ea_reqs = threat_engine.get_regulatory_requirements(vuln_type, industry=f.get("industry", "general"))
            for r in ea_reqs:
                framework_key = "uganda_pdpa" if "PDPA" in r.requirement_id else \
                               "uganda_cma" if "CMA" in r.requirement_id else \
                               "bou_cyber" if "BOU" in r.requirement_id else None
                
                if framework_key and framework_key in results:
                    results[framework_key]["violations"].append({
                        "finding_id": f.get("id"),
                        "vuln_type": vuln_type,
                        "requirement": r.requirement_id,
                        "description": r.description
                    })
                    
            # Update status for all frameworks based on finding severity
            severity = f.get("severity", "").lower()
            if severity in ["critical", "high", "medium"]:
                # If we have any major finding, all related frameworks fail
                for key in results.keys():
                    if any(v["finding_id"] == f.get("id") for v in results[key]["violations"]):
                        results[key]["status"] = "FAIL"
                        
        return results

    def get_mappings_for_finding(self, finding: Dict) -> List[ComplianceMapping]:
        return self.MAPPINGS.get(finding.get("vuln_type"), [])
