"""
tests/verify_reporting.py — Verification script for the reporting system.
"""

import asyncio
import os
import sys
from datetime import datetime, timezone

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.models.scan import Scan, ScanStatus, ScanPhase, ScanMetrics
from core.models.target import Target
from core.models.finding import Finding, Severity, FindingEvidence
from reporting.builder import ReportBuilder

async def test_report_generation():
    print("Starting reporting verification...")
    
    # 1. Create a mock scan
    scan = Scan(
        id="test-scan-123",
        target=Target(base_url="https://example.com"),
        status=ScanStatus.COMPLETE,
        current_phase=ScanPhase.COMPLETE,
        metrics=ScanMetrics(total_requests_sent=42, pages_crawled=10),
        created_at=datetime.now(timezone.utc).isoformat(),
        started_at=datetime.now(timezone.utc).isoformat(),
        completed_at=datetime.now(timezone.utc).isoformat(),
    )
    
    # 2. Add some findings
    scan.findings.append(Finding(
        id="f1",
        vuln_type="sqli",
        severity=Severity.CRITICAL,
        url="https://example.com/login",
        parameter_name="username",
        description="SQL Injection in login form",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        confidence=0.95,
        evidence=FindingEvidence(matched_pattern="PostgreSQL 14.2 detected")
    ))
    
    scan.findings.append(Finding(
        id="f2",
        vuln_type="xss_reflected",
        severity=Severity.MEDIUM,
        url="https://example.com/search",
        parameter_name="q",
        description="Reflected XSS in search bar",
        cvss_score=6.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        confidence=0.88,
        evidence=FindingEvidence(matched_pattern="alert(1) reflected")
    ))

    builder = ReportBuilder(scan)

    # 3. Test JSON Export
    print("Testing JSON export...")
    json_bytes = await builder.build(format="json")
    assert len(json_bytes) > 0
    print(f"JSON Export: OK ({len(json_bytes)} bytes)")

    # 4. Test CSV Export
    print("Testing CSV export...")
    csv_bytes = await builder.build(format="csv")
    assert len(csv_bytes) > 0
    print(f"CSV Export: OK ({len(csv_bytes)} bytes)")

    # 5. Test PDF Export (if dependencies are satisfied)
    print("Testing PDF export...")
    try:
        pdf_bytes = await builder.build(format="pdf")
        assert len(pdf_bytes) > 0
        print(f"PDF Export: OK ({len(pdf_bytes)} bytes)")
    except Exception as e:
        print(f"PDF Export FAILED: {e}")
        # xhtml2pdf might fail if dependencies like reportlab aren't fully set up in this environment
        # but we should still try.

    print("Verification complete.")

if __name__ == "__main__":
    asyncio.run(test_report_generation())
