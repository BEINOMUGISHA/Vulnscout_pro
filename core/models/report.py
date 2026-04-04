"""
report.py — Report Model

A Report is the final deliverable of VulnScout Pro — the document that
gets handed to a client, developer team, or compliance officer.

Three report types are supported, each with different audiences:

  EXECUTIVE  — For management, board, or non-technical stakeholders.
               No payloads, no technical detail. Business risk language.
               Includes regulatory exposure (BOU, UCC, NITA-U) and
               estimated financial impact framed in UGX.

  TECHNICAL  — For developers and security engineers.
               Full evidence, payloads, CVSS vectors, PoC steps.
               Ordered by risk priority, grouped by vuln type.
               Includes remediation code examples per finding.

  COMPLIANCE — For auditors and regulators (BOU, UCC, NITA-U, FIA).
               Maps every finding to a specific regulatory clause.
               Includes pass/fail status per requirement section.
               Suitable for submission to Bank of Uganda or UCC.

Design principles:
  - Report is generated from a completed Scan — never from a live scan
  - Template data is kept separate from the Report model (no HTML in here)
  - All monetary estimates are in UGX unless specified
  - Reports are versioned so re-generation produces a new record
  - Sensitive evidence is stripped from executive/compliance reports
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from core.models.finding import Finding, FindingCollection, Severity
from core.models.scan import Scan, ScanSummary


# ── Report type & format ───────────────────────────────────────────────────────

class ReportType:
    EXECUTIVE  = "executive"
    TECHNICAL  = "technical"
    COMPLIANCE = "compliance"

    ALL = [EXECUTIVE, TECHNICAL, COMPLIANCE]


class ReportFormat:
    PDF  = "pdf"
    JSON = "json"
    CSV  = "csv"
    HTML = "html"


class ReportStatus:
    PENDING    = "pending"
    GENERATING = "generating"
    COMPLETE   = "complete"
    FAILED     = "failed"


# ── Risk rating model ──────────────────────────────────────────────────────────

@dataclass
class OverallRiskRating:
    """
    Holistic risk rating for the entire scan.
    Combines CVSS, EA context, and business impact.
    """
    label: str                  # CRITICAL, HIGH, MEDIUM, LOW, MINIMAL
    score: float                # 0.0–10.0 composite score
    rationale: str
    ea_adjusted: bool = False   # True if EA regulatory multipliers changed the rating
    payment_exposure: bool = False

    # Financial impact estimates (UGX)
    estimated_breach_cost_ugx_low: int = 0
    estimated_breach_cost_ugx_high: int = 0

    def to_dict(self) -> Dict:
        return {
            "label": self.label,
            "score": self.score,
            "rationale": self.rationale,
            "ea_adjusted": self.ea_adjusted,
            "payment_exposure": self.payment_exposure,
            "financial_impact_ugx": {
                "low": self.estimated_breach_cost_ugx_low,
                "high": self.estimated_breach_cost_ugx_high,
                "currency": "UGX",
            },
        }

    @classmethod
    def from_scan(cls, scan: Scan) -> "OverallRiskRating":
        stats = scan.summary_stats
        total = stats["total"]

        if total == 0:
            return cls(label="MINIMAL", score=0.0, rationale="No vulnerabilities found.")

        # Weighted score
        score = (
            stats.get(Severity.CRITICAL, 0) * 10.0 +
            stats.get(Severity.HIGH, 0)     *  7.0 +
            stats.get(Severity.MEDIUM, 0)   *  4.0 +
            stats.get(Severity.LOW, 0)      *  2.0
        ) / max(total, 1)
        score = min(10.0, score)

        # Apply EA multiplier
        ea_multiplier = scan.ea_risk_score / 10.0 if scan.ea_risk_score > 0 else 1.0
        ea_adjusted = ea_multiplier > 1.0
        adjusted_score = min(10.0, score * ea_multiplier)

        label = (
            "CRITICAL" if adjusted_score >= 8.5 else
            "HIGH"     if adjusted_score >= 6.5 else
            "MEDIUM"   if adjusted_score >= 4.0 else
            "LOW"      if adjusted_score >= 2.0 else
            "MINIMAL"
        )

        # Rough breach cost estimate (UGX)
        base_cost_low = 50_000_000     # UGX 50M base
        base_cost_high = 500_000_000   # UGX 500M base
        payment_exposure = scan.has_payment_findings
        if payment_exposure:
            base_cost_low  *= 5
            base_cost_high *= 10
        if stats.get(Severity.CRITICAL, 0) > 0:
            base_cost_low  *= 2
            base_cost_high *= 3

        rationale = (
            f"Scan identified {total} finding(s): "
            f"{stats.get(Severity.CRITICAL, 0)} critical, "
            f"{stats.get(Severity.HIGH, 0)} high, "
            f"{stats.get(Severity.MEDIUM, 0)} medium. "
        )
        if ea_adjusted:
            rationale += (
                f"EA regulatory context increased effective risk score to {adjusted_score:.1f}/10. "
            )
        if payment_exposure:
            rationale += "Mobile money / payment system findings present."

        return cls(
            label=label,
            score=round(adjusted_score, 2),
            rationale=rationale,
            ea_adjusted=ea_adjusted,
            payment_exposure=payment_exposure,
            estimated_breach_cost_ugx_low=base_cost_low,
            estimated_breach_cost_ugx_high=base_cost_high,
        )


# ── Compliance mapping ─────────────────────────────────────────────────────────

@dataclass
class ComplianceSection:
    """A single compliance requirement section with pass/fail status."""
    requirement_id: str
    body: str                           # "Bank of Uganda", "NITA-U", etc.
    description: str
    status: str                         # "PASS", "FAIL", "PARTIAL", "N/A"
    affected_findings: List[str]        # Finding IDs
    evidence_summary: str
    remediation_required: bool
    deadline_days: Optional[int] = None

    def to_dict(self) -> Dict:
        return {
            "requirement_id": self.requirement_id,
            "body": self.body,
            "description": self.description,
            "status": self.status,
            "affected_findings_count": len(self.affected_findings),
            "affected_finding_ids": self.affected_findings,
            "evidence_summary": self.evidence_summary,
            "remediation_required": self.remediation_required,
            "deadline_days": self.deadline_days,
        }


@dataclass
class ComplianceReport:
    """Compliance section summary for all applicable regulatory bodies."""
    sections: List[ComplianceSection] = field(default_factory=list)

    @property
    def pass_count(self) -> int:
        return sum(1 for s in self.sections if s.status == "PASS")

    @property
    def fail_count(self) -> int:
        return sum(1 for s in self.sections if s.status == "FAIL")

    @property
    def overall_status(self) -> str:
        if not self.sections:
            return "N/A"
        if any(s.status == "FAIL" for s in self.sections):
            return "NON-COMPLIANT"
        if any(s.status == "PARTIAL" for s in self.sections):
            return "PARTIALLY COMPLIANT"
        return "COMPLIANT"

    def to_dict(self) -> Dict:
        return {
            "overall_status": self.overall_status,
            "total_requirements": len(self.sections),
            "pass": self.pass_count,
            "fail": self.fail_count,
            "partial": sum(1 for s in self.sections if s.status == "PARTIAL"),
            "na": sum(1 for s in self.sections if s.status == "N/A"),
            "sections": [s.to_dict() for s in self.sections],
        }


# ── Report section models ──────────────────────────────────────────────────────

@dataclass
class ExecutiveSummary:
    """Non-technical summary for management audiences."""
    overall_risk: OverallRiskRating
    key_findings: List[str]             # Plain-English bullet points
    business_impact: str
    immediate_actions: List[str]        # Top 3-5 things to do right now
    positive_observations: List[str]    # What was done right
    ea_regulatory_exposure: List[str]   # Applicable laws and their implications
    recommended_timeline: str           # "Remediate critical findings within 48 hours"

    def to_dict(self) -> Dict:
        return {
            "overall_risk": self.overall_risk.to_dict(),
            "key_findings": self.key_findings,
            "business_impact": self.business_impact,
            "immediate_actions": self.immediate_actions,
            "positive_observations": self.positive_observations,
            "ea_regulatory_exposure": self.ea_regulatory_exposure,
            "recommended_timeline": self.recommended_timeline,
        }


@dataclass
class TechnicalSection:
    """Technical detail section — one per vulnerability finding."""
    finding: Finding
    reproduction_steps: List[str]
    fix_code_examples: Dict[str, str]   # lang → code snippet
    references: List[str]
    similar_findings: List[str]         # IDs of related findings in same scan

    def to_dict(self, include_evidence: bool = True) -> Dict:
        return {
            "finding": self.finding.to_dict(include_evidence=include_evidence),
            "reproduction_steps": self.reproduction_steps,
            "fix_code_examples": self.fix_code_examples,
            "references": self.references,
            "similar_findings": self.similar_findings,
        }


# ── Report model ───────────────────────────────────────────────────────────────

@dataclass
class Report:
    """
    Final deliverable report generated from a completed Scan.

    One Report can have multiple formats (PDF + JSON) but they all
    derive from the same Report object.

    Typical construction:
        builder = ReportBuilder(scan)
        report = builder.build(report_type=ReportType.TECHNICAL)
        pdf_path = pdf_exporter.export(report)
    """

    # Identity
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str = ""
    owner_id: str = ""
    report_type: str = ReportType.TECHNICAL
    version: int = 1

    # Content
    scan_summary: Optional[ScanSummary] = None
    overall_risk: Optional[OverallRiskRating] = None
    executive_summary: Optional[ExecutiveSummary] = None
    findings: List[Finding] = field(default_factory=list)
    technical_sections: List[TechnicalSection] = field(default_factory=list)
    compliance: Optional[ComplianceReport] = None

    # Metadata
    report_title: str = ""
    generated_by: str = "VulnScout Pro"
    prepared_for: str = ""              # Client / organisation name
    prepared_by: str = ""               # Security analyst name
    confidentiality_notice: str = (
        "CONFIDENTIAL — This report contains sensitive security findings. "
        "Distribution is restricted to authorised personnel only."
    )
    scope_statement: str = ""

    # Status
    status: ReportStatus = field(default=ReportStatus.PENDING)
    error: Optional[str] = None

    # Exports (path → format)
    exports: Dict[str, str] = field(default_factory=dict)

    # Timestamps
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self) -> None:
        if not self.report_title and self.scan_summary:
            target_name = self.scan_summary.target_name or self.scan_summary.target_url
            self.report_title = (
                f"Vulnerability Assessment Report — {target_name} — "
                f"{datetime.now(timezone.utc).strftime('%B %Y')}"
            )

    # ── Properties ─────────────────────────────────────────────────────────────

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def is_complete(self) -> bool:
        return self.status == ReportStatus.COMPLETE

    @property
    def findings_by_severity(self) -> Dict[str, List[Finding]]:
        groups: Dict[str, List[Finding]] = {s: [] for s in Severity.ALL}
        for f in self.findings:
            groups.setdefault(f.severity, []).append(f)
        return groups

    @property
    def findings_by_type(self) -> Dict[str, List[Finding]]:
        groups: Dict[str, List[Finding]] = {}
        for f in self.findings:
            groups.setdefault(f.vuln_type, []).append(f)
        return groups

    @property
    def ea_relevant_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.ea_context.ea_relevant]

    @property
    def payment_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.affects_payments]

    # ── Serialisation ──────────────────────────────────────────────────────────

    def to_dict(
        self,
        include_evidence: bool = True,
        include_technical: bool = True,
    ) -> Dict:

        result: Dict = {
            "id": self.id,
            "scan_id": self.scan_id,
            "report_type": self.report_type,
            "version": self.version,
            "report_title": self.report_title,
            "generated_by": self.generated_by,
            "prepared_for": self.prepared_for,
            "prepared_by": self.prepared_by,
            "confidentiality_notice": self.confidentiality_notice,
            "scope_statement": self.scope_statement,
            "generated_at": self.generated_at,
            "status": self.status,
        }

        if self.scan_summary:
            result["scan_summary"] = self.scan_summary.to_dict()

        if self.overall_risk:
            result["overall_risk"] = self.overall_risk.to_dict()

        if self.executive_summary:
            result["executive_summary"] = self.executive_summary.to_dict()

        if self.compliance:
            result["compliance"] = self.compliance.to_dict()

        # For executive reports — strip technical detail
        if self.report_type == ReportType.EXECUTIVE:
            result["findings"] = [
                {
                    "id": f.id,
                    "severity": f.severity,
                    "vuln_label": f.vuln_label,
                    "url": f.url,
                    "business_impact": (
                        f.remediation.summary if f.remediation else ""
                    ),
                    "ea_relevant": f.ea_context.ea_relevant,
                    "remediation_effort": (
                        f.remediation.effort_estimate if f.remediation else ""
                    ),
                }
                for f in self.findings
            ]
        else:
            result["findings"] = [
                f.to_dict(include_evidence=include_evidence)
                for f in self.findings
            ]

        if include_technical and self.technical_sections:
            result["technical_sections"] = [
                s.to_dict(include_evidence=include_evidence)
                for s in self.technical_sections
            ]

        result["exports"] = self.exports
        return result

    def to_json(self, **kwargs) -> str:
        import json
        return json.dumps(self.to_dict(**kwargs), indent=2, default=str)

    # ── Report statistics for cover page ──────────────────────────────────────

    def cover_stats(self) -> Dict:
        """Stats block for the PDF cover page and HTML header."""
        stats = {s: 0 for s in Severity.ALL}
        for f in self.findings:
            stats[f.severity] = stats.get(f.severity, 0) + 1
        return {
            "report_type": self.report_type.upper(),
            "report_title": self.report_title,
            "generated_at": self.generated_at,
            "prepared_for": self.prepared_for,
            "prepared_by": self.prepared_by,
            "overall_risk_label": self.overall_risk.label if self.overall_risk else "N/A",
            "overall_risk_score": self.overall_risk.score if self.overall_risk else 0.0,
            "finding_totals": {
                "total": self.finding_count,
                **stats,
            },
            "ea_relevant": len(self.ea_relevant_findings),
            "payment_related": len(self.payment_findings),
            "compliance_status": (
                self.compliance.overall_status if self.compliance else "Not assessed"
            ),
        }

    def __repr__(self) -> str:
        return (
            f"<Report id={self.id[:8]} type={self.report_type} "
            f"findings={self.finding_count} status={self.status}>"
        )


# ── ReportRequest (user-facing input model) ────────────────────────────────────

@dataclass
class ReportRequest:
    """
    Input model for requesting report generation.
    Passed to the report builder from the API or CLI.
    """
    scan_id: str
    report_type: str = ReportType.TECHNICAL
    formats: List[str] = field(default_factory=lambda: [ReportFormat.PDF, ReportFormat.JSON])
    prepared_for: str = ""
    prepared_by: str = ""
    include_evidence: bool = True
    include_ea_context: bool = True
    min_severity: str = Severity.LOW
    custom_title: str = ""

    def to_dict(self) -> Dict:
        return {
            "scan_id": self.scan_id,
            "report_type": self.report_type,
            "formats": self.formats,
            "prepared_for": self.prepared_for,
            "prepared_by": self.prepared_by,
            "include_evidence": self.include_evidence,
            "include_ea_context": self.include_ea_context,
            "min_severity": self.min_severity,
        }