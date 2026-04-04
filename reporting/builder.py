"""
reporting/builder.py — Report Orchestration Engine

Coordinates the construction of vulnerability reports from scan results.
Dispatches to specific builders for sections (Executive, Technical, Remediation)
and formats them via exporters (PDF, JSON, CSV).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Union

from core.models.scan import Scan
from reporting.builders.executive_summary import ExecutiveSummaryBuilder
from reporting.builders.technical_detail import TechnicalDetailBuilder
from reporting.builders.remediation_guide import RemediationGuideBuilder
from reporting.exporters.pdf_exporter import PDFExporter
from reporting.exporters.json_exporter import JSONExporter
from reporting.exporters.csv_exporter import CSVExporter
from reporting.exporters.sarif_exporter import SarifExporter

logger = logging.getLogger(__name__)

class ReportBuilder:
    """
    Orchestrates the build of a security report from a completed Scan object.
    
    Usage:
        builder = ReportBuilder(scan)
        report_path = await builder.build(format="pdf", prepared_for="ACME Banking")
    """

    def __init__(self, scan: Scan) -> None:
        self.scan = scan
        self.executive_builder = ExecutiveSummaryBuilder(scan)
        self.technical_builder = TechnicalDetailBuilder(scan)
        self.remediation_builder = RemediationGuideBuilder(scan)

    async def build(
        self, 
        report_type: str = "full", 
        format: str = "pdf", 
        prepared_for: str = "Confidential",
        include_evidence: bool = True
    ) -> bytes:
        """
        Generate the report bytes in the specified format.
        """
        logger.info(
            "Building %s report for scan %s in %s format", 
            report_type, self.scan.id, format
        )

        # 1. Gather report data (Offload CPU-bound building tasks)
        import asyncio
        loop = asyncio.get_event_loop()
        
        summary_task = loop.run_in_executor(None, self.executive_builder.build)
        technical_task = loop.run_in_executor(None, lambda: self.technical_builder.build(include_evidence=include_evidence))
        remediation_task = loop.run_in_executor(None, self.remediation_builder.build)
        
        # Wait for all sections concurrently
        summary, technical, remediation = await asyncio.gather(
            summary_task, technical_task, remediation_task
        )

        report_data = {
            "metadata": {
                "scan_id": self.scan.id,
                "target_url": self.scan.target.base_url if self.scan.target else "",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "prepared_for": prepared_for,
                "report_type": report_type,
                "scanner_version": "1.0.0",
            },
            "summary": summary,
            "technical": technical,
            "remediation": remediation,
            "ea_context": getattr(self.scan, "ea_risk_score", 0.0) # Placeholder
        }

        # 2. Export to requested format
        exporter = self._get_exporter(format)
        return await exporter.export(report_data)

    def _get_exporter(self, format: str):
        format = format.lower()
        if format == "pdf":
            return PDFExporter()
        elif format == "json":
            return JSONExporter()
        elif format == "csv":
            return CSVExporter()
        elif format == "sarif":
            return SarifExporter()
        else:
            raise ValueError(f"Unsupported report format: {format}")
