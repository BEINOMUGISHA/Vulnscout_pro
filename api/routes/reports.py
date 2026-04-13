"""
api/routes/reports.py — Report Generation and Delivery Routes

Endpoints:
  POST   /reports                           — generate a new report from a scan
  GET    /reports                           — list reports (paginated)
  GET    /reports/{report_id}               — get report metadata
  DELETE /reports/{report_id}              — delete report (admin / owner)
  GET    /reports/{report_id}/download/pdf  — download PDF report
  GET    /reports/{report_id}/download/json — download JSON report
  GET    /reports/{report_id}/download/csv  — download CSV findings
  POST   /reports/{report_id}/regenerate   — regenerate with new options
  GET    /reports/{report_id}/summary      — get executive summary section only
  GET    /reports/{report_id}/compliance   — get compliance section only

Report types:
  executive  — management-facing, business risk language, no raw payloads,
               UGX breach cost estimates, EA regulatory exposure summary.
  technical  — developer-facing, full evidence, CVSS vectors, PoC steps,
               remediation code examples, fix effort estimates.
  compliance — auditor-facing, BOU/UCC/NITA-U requirement mapping,
               pass/fail per clause, penalty exposure, remediation deadlines.

Generation is async — POST returns 202 with report_id.
Poll GET /reports/{id} for status. Download when status=complete.

Confidentiality:
  All reports are marked CONFIDENTIAL by default.
  PDF reports include a watermark in production.
  Report access is scoped to the owner (admin can access all).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator

from api.dependencies import (
    AuthenticatedUser,
    PaginationParams,
    get_pagination,
    get_report_store,
    get_scan_store,
    require_analyst,
    require_auth,
    require_report_access,
    require_admin,
)
from config import get_config

logger = logging.getLogger(__name__)
router = APIRouter()
audit = logging.getLogger("vulnscout.audit")


# ── Request / Response models ──────────────────────────────────────────────────


class GenerateReportRequest(BaseModel):
    scan_id: str = Field(..., min_length=36, max_length=36)
    report_type: str = Field("technical", pattern="^(executive|technical|compliance)$")
    formats: list[str] = Field(
        ["pdf", "json"], description="Output formats to generate"
    )
    prepared_for: str = Field("", max_length=200, description="Client / recipient name")
    prepared_by: str = Field("", max_length=200, description="Assessor name")
    include_evidence: bool = Field(
        False, description="Include raw HTTP payloads in report"
    )
    include_ea_context: bool = Field(True, description="Include EA regulatory context")
    min_severity: str = Field(
        "informational", pattern="^(critical|high|medium|low|informational)$"
    )
    custom_title: str | None = Field(None, max_length=200)
    executive_summary_override: str | None = Field(
        None,
        max_length=2000,
        description="Override the auto-generated executive summary text",
    )

    @field_validator("formats")
    @classmethod
    def validate_format(cls, v):
        valid = {"pdf", "json", "csv", "html", "sarif"}
        for item in v:
            if item not in valid:
                raise ValueError(
                    f"Invalid format {item!r}. Valid formats: {sorted(valid)}"
                )
        return v


class RegenerateRequest(BaseModel):
    formats: list[str] | None = None
    include_evidence: bool | None = None
    include_ea_context: bool | None = None
    min_severity: str | None = None


class ReportResponse(BaseModel):
    report_id: str
    scan_id: str
    report_type: str
    status: str
    created_at: str
    message: str


# ── Report generation ──────────────────────────────────────────────────────────


@router.post(
    "", status_code=202, response_model=ReportResponse, summary="Generate report"
)
async def generate_report(
    body: GenerateReportRequest,
    background: BackgroundTasks,
    user: AuthenticatedUser = Depends(require_analyst),
    scan_store=Depends(get_scan_store),
    report_store=Depends(get_report_store),
):
    """
    Queue a new report for generation. Returns 202 immediately.

    Reports are generated asynchronously from the stored scan data.
    Poll GET /reports/{report_id} for status=complete before downloading.

    Compliance reports require the scan to be complete — a report cannot
    be generated from a running or failed scan.

    The prepared_for field appears in the report header and is required
    for formal client-facing reports (executive, compliance).
    """
    # Verify scan exists and is accessible
    scan = await scan_store.get_summary(body.scan_id)
    if scan is None:
        raise HTTPException(404, f"Scan {body.scan_id!r} not found.")

    scan_owner = getattr(scan, "owner_id", None)
    if not user.is_admin and scan_owner and scan_owner != user.user_id:
        raise HTTPException(403, "You do not have access to this scan.")

    # Compliance reports require a completed scan
    if body.report_type == "compliance" and getattr(scan, "status", "") != "complete":
        raise HTTPException(
            409,
            f"Compliance reports require a completed scan. "
            f"Current status: {getattr(scan, 'status', 'unknown')!r}.",
        )

    config = get_config()

    from core.models.report import Report, ReportType, ReportRequest
    from core.models.scan import ScanSummary

    report_request = ReportRequest(
        scan_id=body.scan_id,
        report_type=body.report_type,
        formats=body.formats,
        prepared_for=body.prepared_for,
        prepared_by=body.prepared_by or config.reporting.default_prepared_by,
        include_evidence=body.include_evidence,
        include_ea_context=body.include_ea_context,
        min_severity=body.min_severity,
        custom_title=body.custom_title,
    )

    report = Report(
        scan_id=body.scan_id,
        report_type=body.report_type,
        owner_id=user.user_id,
        report_title=(
            body.custom_title
            or _default_title(body.report_type, getattr(scan, "target_url", ""))
        ),
        prepared_for=body.prepared_for,
        prepared_by=body.prepared_by or config.reporting.default_prepared_by,
        confidentiality_notice=(
            "CONFIDENTIAL — This report contains sensitive security findings. "
            "Distribute only to authorised personnel."
        ),
    )

    await report_store.save(report)

    # Queue async generation
    background.add_task(
        _generate_report_async,
        report=report,
        request=report_request,
        scan=scan,
        scan_store=scan_store,
        report_store=report_store,
        executive_override=body.executive_summary_override,
    )

    audit.info(
        "REPORT_GENERATION_QUEUED report_id=%s scan_id=%s type=%s user=%s",
        report.id[:8],
        body.scan_id[:8],
        body.report_type,
        user.user_id[:8],
    )

    return ReportResponse(
        report_id=report.id,
        scan_id=body.scan_id,
        report_type=body.report_type,
        status="pending",
        created_at=report.generated_at or datetime.now(timezone.utc).isoformat(),
        message=(
            f"Report generation queued. "
            f"Poll GET /api/v1/reports/{report.id} for status."
        ),
    )


async def _generate_report_async(
    report,
    request,
    scan,
    scan_store,
    report_store,
    executive_override: str | None = None,
) -> None:
    """
    Background task that drives the full report generation pipeline.
    Loads findings, runs the builder, exports to requested formats,
    and updates the report record with status=complete.
    """
    try:
        report.status = "generating"
        await report_store.save(report)

        # Load full findings for this scan
        findings = await scan_store.load_findings(report.scan_id)

        # Filter by min_severity
        if request.min_severity and request.min_severity != "informational":
            _sev = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
            min_rank = _sev.get(request.min_severity, 0)
            findings = [
                f
                for f in findings
                if _sev.get(getattr(f, "severity", "").lower(), -1) >= min_rank
            ]

        # Attach findings to report
        report.findings = findings

        # Build type-specific sections
        _build_report_sections(report, scan, findings, request, executive_override)

        # Export to each requested format
        config = get_config()
        for fmt in request.formats:
            try:
                path = await _export_format(report, fmt, report_store)
                report.exports[path] = fmt
            except Exception as exc:
                logger.error(
                    "Report %s export to %s failed: %s", report.id[:8], fmt, exc
                )

        report.status = "complete"
        await report_store.save(report)

        audit.info(
            "REPORT_COMPLETE report_id=%s scan_id=%s type=%s formats=%s",
            report.id[:8],
            report.scan_id[:8],
            report.report_type,
            request.formats,
        )

    except Exception as exc:
        report.status = "failed"
        report.error = str(exc)
        await report_store.save(report)
        logger.exception("Report %s generation failed: %s", report.id[:8], exc)


def _build_report_sections(report, scan, findings, request, executive_override):
    """Populate report sections based on report_type."""
    from core.models.report import (
        OverallRiskRating,
        ExecutiveSummary,
        ComplianceSection,
        ComplianceReport,
    )

    from core.models.scan import ScanSummary

    if isinstance(scan, dict):
        scan = ScanSummary.from_dict(scan)

    # Overall risk rating — always computed
    report.overall_risk = OverallRiskRating.from_scan(scan)

    if report.report_type in ("executive", "technical", "compliance"):
        # Executive summary for all types
        report.executive_summary = _build_executive_summary(
            report, scan, findings, executive_override
        )

    if report.report_type == "compliance":
        report.compliance = _build_compliance_section(findings)

    if report.report_type == "technical":
        report.technical_sections = _build_technical_sections(findings)


def _build_executive_summary(report, scan, findings, override_text):
    """Build the executive summary section."""
    from core.models.report import ExecutiveSummary

    critical = [f for f in findings if getattr(f, "severity", "") == "critical"]
    high = [f for f in findings if getattr(f, "severity", "") == "high"]
    payment = [f for f in findings if getattr(f, "affects_payments", False)]
    ea = [
        f
        for f in findings
        if getattr(getattr(f, "ea_context", None), "ea_relevant", False)
    ]

    key_findings = []
    for f in sorted(critical + high, key=lambda x: getattr(x, "risk_priority", 999))[
        :5
    ]:
        key_findings.append(
            f"{getattr(f, 'vuln_label', f.vuln_type)} found at "
            f"{getattr(f, 'url', 'unknown URL')} — "
            f"CVSS {getattr(f, 'cvss_score', 0.0):.1f}"
        )

    immediate_actions = []
    if critical:
        immediate_actions.append(
            f"Immediately remediate {len(critical)} critical finding(s) — "
            "these represent immediate business risk."
        )
    if payment:
        immediate_actions.append(
            f"Prioritise {len(payment)} payment system finding(s) to maintain "
            "compliance with Bank of Uganda Mobile Money Guidelines."
        )
    if high:
        immediate_actions.append(
            f"Schedule remediation of {len(high)} high-severity finding(s) "
            "within 30 days."
        )

    business_impact = override_text or (
        f"The assessment identified {len(findings)} vulnerabilities across "
        f"{getattr(report.overall_risk, 'label', 'Unknown')} overall risk. "
        f"{len(payment)} finding(s) directly affect payment systems."
        + (f" EA regulatory exposure identified in {len(ea)} finding(s)." if ea else "")
    )

    return ExecutiveSummary(
        overall_risk=report.overall_risk,
        key_findings=key_findings,
        business_impact=business_impact,
        immediate_actions=immediate_actions,
        ea_regulatory_exposure=bool(ea),
    )


def _build_compliance_section(findings):
    """Map findings to BOU / NITA-U / UCC regulatory requirements."""
    from core.models.report import ComplianceSection, ComplianceReport

    # BOU Cybersecurity Framework requirements
    bou_requirements = [
        {
            "id": "BOU-CYBER-2022-01",
            "body": "Bank of Uganda",
            "description": "Secure coding practices and vulnerability management",
            "vuln_types": [
                "sqli",
                "sqli_blind",
                "sqli_error",
                "xss_reflected",
                "xss_stored",
                "xxe",
                "ssrf",
            ],
        },
        {
            "id": "BOU-CYBER-2022-02",
            "body": "Bank of Uganda",
            "description": "Access control and authentication security",
            "vuln_types": ["auth_bypass", "broken_auth", "idor"],
        },
        {
            "id": "BOU-MM-2017-SEC",
            "body": "Bank of Uganda",
            "description": "Mobile Money Guidelines — API and transaction security",
            "vuln_types": [
                "ipn_forgery",
                "amount_tampering",
                "mm_credential_exposure",
                "msisdn_spoofing",
            ],
        },
    ]

    # NITA-U / Uganda PDPA requirements
    nita_requirements = [
        {
            "id": "NITA-U-PDPA-2019-01",
            "body": "NITA-U",
            "description": "Protection of personal data from unauthorised access",
            "vuln_types": ["idor", "sensitive_data", "sqli", "auth_bypass"],
        },
        {
            "id": "NITA-U-PDPA-2019-02",
            "body": "NITA-U",
            "description": "Data minimisation and security measures",
            "vuln_types": ["sensitive_data", "misconfig"],
        },
    ]

    # UCC Cybersecurity requirements
    ucc_requirements = [
        {
            "id": "UCC-CYBER-01",
            "body": "UCC",
            "description": "Network security and perimeter protection",
            "vuln_types": ["ssrf", "misconfig", "xxe"],
        },
    ]

    all_vuln_types = {getattr(f, "vuln_type", "") for f in findings}
    sections = []

    for req in bou_requirements + nita_requirements + ucc_requirements:
        affected = [
            f for f in findings if getattr(f, "vuln_type", "") in req["vuln_types"]
        ]
        status = (
            "PASS"
            if not affected
            else (
                "FAIL"
                if any(
                    getattr(f, "severity", "") in ("critical", "high") for f in affected
                )
                else "PARTIAL"
            )
        )
        sections.append(
            ComplianceSection(
                requirement_id=req["id"],
                body=req["body"],
                description=req["description"],
                status=status,
                affected_findings=[getattr(f, "id", "") for f in affected],
                evidence_summary=(
                    f"{len(affected)} finding(s): "
                    + ", ".join(
                        {getattr(f, "vuln_label", f.vuln_type) for f in affected[:3]}
                    )
                    if affected
                    else "No related findings."
                ),
                remediation_required=(status != "PASS"),
                deadline_days=7
                if status == "FAIL"
                else 30
                if status == "PARTIAL"
                else 0,
            )
        )

    fail_count = sum(1 for s in sections if s.status == "FAIL")
    pass_count = sum(1 for s in sections if s.status == "PASS")
    partial_count = sum(1 for s in sections if s.status == "PARTIAL")

    overall = (
        "NON-COMPLIANT"
        if fail_count
        else "PARTIALLY COMPLIANT"
        if partial_count
        else "COMPLIANT"
    )

    return ComplianceReport(
        sections=sections,
        pass_count=pass_count,
        fail_count=fail_count,
        partial_count=partial_count,
        overall_status=overall,
    )


def _build_technical_sections(findings):
    """Build per-finding technical sections with PoC and remediation detail."""
    from core.models.report import TechnicalSection

    sections = []
    sorted_findings = sorted(findings, key=lambda f: getattr(f, "risk_priority", 999))

    for finding in sorted_findings:
        rem = getattr(finding, "remediation", None)
        sections.append(
            TechnicalSection(
                finding=finding,
                reproduction_steps=_reproduction_steps(finding),
                fix_code_examples=getattr(rem, "code_examples", {}) if rem else {},
                references=getattr(rem, "references", []) if rem else [],
            )
        )
    return sections


def _reproduction_steps(finding) -> List[str]:
    """Generate ordered reproduction steps from finding evidence."""
    ev = getattr(finding, "evidence", None)
    if not ev:
        return ["See finding evidence for reproduction details."]

    steps = []
    url = getattr(ev, "request_url", getattr(finding, "url", "TARGET_URL"))
    method = getattr(ev, "request_method", "GET")
    param = getattr(
        ev, "injected_parameter", getattr(finding, "parameter_name", "PARAMETER")
    )
    payload = getattr(ev, "injected_payload", "PAYLOAD")
    timing = getattr(ev, "timing_delta_ms", 0)

    steps.append(f"Navigate to or send a {method} request to: {url}")
    steps.append(
        f"Set the {param!r} parameter to: {payload[:100]}"
        + ("..." if len(payload) > 100 else "")
    )
    if timing > 1000:
        steps.append(
            f"Observe the response delay of ~{timing:.0f}ms "
            "(confirms time-based blind injection)."
        )
    else:
        pattern = getattr(ev, "matched_pattern", "")
        if pattern:
            steps.append(f"Observe the response for pattern: {pattern[:80]}")
    steps.append(
        f"A {getattr(ev, 'response_status', 200)} response containing evidence "
        "of the vulnerability confirms the finding."
    )
    return steps


async def _export_format(report, fmt: str, report_store) -> str:
    """Export report to the given format and return the storage path."""
    # Convert report object to dict for exporters
    report_dict = report.to_dict(include_evidence=True, include_technical=True)

    if fmt == "json":
        from reporting.exporters.json_exporter import JSONExporter

        exporter = JSONExporter()
        content = await exporter.export(report_dict)
        return await report_store.save_export(report.id, "json", content)

    if fmt == "csv":
        from reporting.exporters.csv_exporter import CSVExporter

        exporter = CSVExporter()
        content = await exporter.export(report_dict)
        return await report_store.save_export(report.id, "csv", content)

    if fmt == "sarif":
        from reporting.exporters.sarif_exporter import SarifExporter

        exporter = SarifExporter()
        content = await exporter.export(report_dict)
        return await report_store.save_export(report.id, "sarif", content)

    if fmt == "pdf":
        from reporting.exporters.pdf_exporter import PDFExporter

        exporter = PDFExporter()
        try:
            content = await exporter.export(report_dict)
            return await report_store.save_export(report.id, "pdf", content)
        except Exception as exc:
            logger.error("PDF export failed for report %s: %s", report.id[:8], exc)
            # Save error info as placeholder so user knows why it failed
            err_msg = f"# PDF Generation Failed\n\nError: {exc}".encode()
            return await report_store.save_export(report.id, "pdf", err_msg)

    raise ValueError(f"Unsupported format: {fmt!r}")


def _default_title(report_type: str, target_url: str) -> str:
    from datetime import date

    today = date.today().strftime("%Y-%m-%d")
    type_label = {
        "executive": "Executive",
        "technical": "Technical",
        "compliance": "Compliance",
    }.get(report_type, report_type.title())
    return f"VulnScout Pro {type_label} Security Assessment — {target_url} — {today}"


# ── Report listing and retrieval ───────────────────────────────────────────────


@router.get("", summary="List reports")
async def list_reports(
    page: PaginationParams = Depends(get_pagination),
    scan_id: str | None = Query(None),
    report_type: str | None = Query(None),
    status: str | None = Query(None),
    user: AuthenticatedUser = Depends(require_auth),
    report_store=Depends(get_report_store),
):
    """List reports owned by the authenticated user. Admins see all."""
    owner_filter = None if user.is_admin else user.user_id

    reports, total = await report_store.list(
        owner_id=owner_filter,
        scan_id=scan_id,
        report_type=report_type,
        status=status,
        offset=page.offset,
        limit=page.limit,
    )

    return {
        "items": reports,
        "reports": reports,
        "total": total,
        "page": page.page,
        "limit": page.limit,
        "pages": (total + page.limit - 1) // page.limit if total else 0,
    }


@router.get("/{report_id}", summary="Get report metadata and status")
async def get_report(
    report_id: str,
    user: AuthenticatedUser = Depends(require_auth),
    report=Depends(require_report_access),
):
    """
    Return report metadata, status, and available download formats.
    Does not return the full report body — use /download/* for the content.
    """
    return {
        "report_id": report.id,
        "scan_id": report.scan_id,
        "report_type": report.report_type,
        "status": report.status,
        "title": report.report_title,
        "prepared_for": report.prepared_for,
        "prepared_by": report.prepared_by,
        "finding_count": report.finding_count
        if hasattr(report, "finding_count")
        else 0,
        "critical_count": getattr(report, "critical_count", 0),
        "high_count": getattr(report, "high_count", 0),
        "available_formats": list(report.exports.values()) if report.exports else [],
        "overall_risk": report.overall_risk.to_dict() if report.overall_risk else None,
        "generated_at": report.generated_at,
        "error": report.error,
        "cover_stats": report.cover_stats() if hasattr(report, "cover_stats") else {},
    }


@router.get("/{report_id}/summary", summary="Get executive summary section")
async def get_report_summary(
    report_id: str,
    user: AuthenticatedUser = Depends(require_auth),
    report=Depends(require_report_access),
):
    """Return only the executive summary section of a report."""
    if report.status != "complete":
        raise HTTPException(
            409, f"Report is not yet complete (status: {report.status!r})."
        )
    if not report.executive_summary:
        raise HTTPException(404, "This report has no executive summary section.")

    es = report.executive_summary
    return {
        "overall_risk": report.overall_risk.to_dict() if report.overall_risk else None,
        "key_findings": getattr(es, "key_findings", []),
        "business_impact": getattr(es, "business_impact", ""),
        "immediate_actions": getattr(es, "immediate_actions", []),
        "ea_regulatory_exposure": getattr(es, "ea_regulatory_exposure", False),
        "positive_observations": getattr(es, "positive_observations", []),
        "recommended_timeline": getattr(es, "recommended_timeline", ""),
    }


@router.get("/{report_id}/compliance", summary="Get compliance section")
async def get_report_compliance(
    report_id: str,
    body: str | None = Query(None, description="Filter by regulatory body"),
    user: AuthenticatedUser = Depends(require_auth),
    report=Depends(require_report_access),
):
    """
    Return the compliance mapping section of a compliance report.
    Only available on report_type=compliance.
    """
    if report.status != "complete":
        raise HTTPException(409, "Report is not complete yet.")
    if report.report_type != "compliance":
        raise HTTPException(
            400,
            "Compliance section is only available on compliance-type reports. "
            f"This is a {report.report_type!r} report.",
        )
    if not report.compliance:
        raise HTTPException(404, "No compliance section found.")

    comp = report.compliance
    sections = comp.sections if hasattr(comp, "sections") else []

    if body:
        sections = [
            s for s in sections if getattr(s, "body", "").upper() == body.upper()
        ]

    return {
        "overall_status": getattr(comp, "overall_status", "UNKNOWN"),
        "pass_count": getattr(comp, "pass_count", 0),
        "fail_count": getattr(comp, "fail_count", 0),
        "partial_count": getattr(comp, "partial_count", 0),
        "sections": [
            {
                "requirement_id": s.requirement_id,
                "body": s.body,
                "description": s.description,
                "status": s.status,
                "affected_finding_count": len(s.affected_findings),
                "evidence_summary": s.evidence_summary,
                "remediation_required": s.remediation_required,
                "deadline_days": s.deadline_days,
            }
            for s in sections
        ],
    }


# ── Downloads ──────────────────────────────────────────────────────────────────


@router.get(
    "/{report_id}/download/{format}", summary="Download report in a specific format"
)
async def download_report(
    report_id: str,
    format: str,
    user: AuthenticatedUser = Depends(require_auth),
    report=Depends(require_report_access),
    report_store=Depends(get_report_store),
):
    """
    Download a generated report in the specified format.

    Formats: pdf, json, csv, html
    The report must have status=complete and the format must have been
    requested when the report was generated.

    Access is logged to the audit trail for compliance purposes.
    """
    valid_formats = {"pdf", "json", "csv", "html"}
    if format not in valid_formats:
        raise HTTPException(
            422, f"Invalid format {format!r}. Valid: {sorted(valid_formats)}"
        )

    if report.status != "complete":
        raise HTTPException(
            409,
            f"Report is not ready for download (status: {report.status!r}). "
            "Poll GET /reports/{report_id} until status=complete.",
        )

    # Check format was generated
    available = list(report.exports.values()) if report.exports else []
    if format not in available:
        raise HTTPException(
            404,
            f"Format {format!r} was not generated for this report. "
            f"Available: {available}. Regenerate with the desired format.",
        )

    content = await report_store.load_export(report.id, format)
    if content is None:
        raise HTTPException(
            500, f"Report file not found on disk for format {format!r}."
        )

    audit.info(
        "REPORT_DOWNLOADED report_id=%s format=%s user_id=%s",
        report_id[:8],
        format,
        user.user_id[:8],
    )

    # MIME types
    mime_types = {
        "pdf": "application/pdf",
        "json": "application/json",
        "csv": "text/csv",
        "html": "text/html",
    }
    ext_map = {"pdf": ".pdf", "json": ".json", "csv": ".csv", "html": ".html"}
    fname = f"vulnscout-report-{report_id[:8]}{ext_map[format]}"

    return StreamingResponse(
        iter([content]),
        media_type=mime_types[format],
        headers={
            "Content-Disposition": f'attachment; filename="{fname}"',
            "Content-Length": str(len(content)),
        },
    )


# ── Regeneration and deletion ──────────────────────────────────────────────────


@router.post("/{report_id}/regenerate", status_code=202, summary="Regenerate report")
async def regenerate_report(
    report_id: str,
    body: RegenerateRequest,
    background: BackgroundTasks,
    user: AuthenticatedUser = Depends(require_analyst),
    report=Depends(require_report_access),
    scan_store=Depends(get_scan_store),
    report_store=Depends(get_report_store),
):
    """
    Re-generate an existing report with updated options.
    The original report record is updated in-place.
    Use when new findings have been confirmed or report options need updating.
    """
    scan = await scan_store.get_summary(report.scan_id)
    if not scan:
        raise HTTPException(404, "Associated scan not found.")

    # Apply overrides
    request_formats = body.formats or list(report.exports.values()) or ["pdf", "json"]
    include_evidence = body.include_evidence
    if include_evidence is None:
        include_evidence = False

    from core.models.report import ReportRequest

    request = ReportRequest(
        scan_id=report.scan_id,
        report_type=report.report_type,
        formats=request_formats,
        prepared_for=report.prepared_for,
        prepared_by=report.prepared_by,
        include_evidence=include_evidence,
        include_ea_context=body.include_ea_context
        if body.include_ea_context is not None
        else True,
        min_severity=body.min_severity or "informational",
    )

    report.status = "pending"
    report.error = None
    report.exports = {}
    await report_store.save(report)

    background.add_task(
        _generate_report_async,
        report=report,
        request=request,
        scan=scan,
        scan_store=scan_store,
        report_store=report_store,
        executive_override=None,
    )

    audit.info(
        "REPORT_REGENERATED report_id=%s user_id=%s", report_id[:8], user.user_id[:8]
    )
    return {
        "report_id": report_id,
        "status": "pending",
        "message": "Report regeneration queued.",
    }


@router.delete("/{report_id}", status_code=204, summary="Delete report")
async def delete_report(
    report_id: str,
    user: AuthenticatedUser = Depends(require_auth),
    report=Depends(require_report_access),
    report_store=Depends(get_report_store),
):
    """
    Permanently delete a report and all its export files.
    Owners can delete their own reports. Admins can delete any report.
    """
    if not user.is_admin:
        owner = getattr(report, "owner_id", None)
        if owner and owner != user.user_id:
            raise HTTPException(403, "You can only delete your own reports.")

    await report_store.delete(report_id)
    audit.info(
        "REPORT_DELETED report_id=%s user_id=%s", report_id[:8], user.user_id[:8]
    )
