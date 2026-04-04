"""
reporting/exporters/pdf_exporter.py — PDF Document Exporter

Converts HTML-templated report data into a professional PDF document.
"""

from __future__ import annotations

import io
import logging
import os
from typing import Dict

from jinja2 import Environment, FileSystemLoader
try:
    from xhtml2pdf import pisa
    PDF_SUPPORT = True
except ImportError:
    PDF_SUPPORT = False

logger = logging.getLogger(__name__)

class PDFExporter:
    def __init__(self) -> None:
        template_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), 
            "templates", "html"
        )
        self.jinja_env = Environment(loader=FileSystemLoader(template_dir))

    async def export(self, report_data: Dict) -> bytes:
        """
        Render HTML via Jinja2 and convert to PDF via xhtml2pdf.
        """
        if not PDF_SUPPORT:
            logger.error("PDF support is disabled because xhtml2pdf is not installed.")
            raise RuntimeError("PDF export requires xhtml2pdf library.")

        try:
            template = self.jinja_env.get_template("report_base.html")
            html_content = template.render(**report_data)
            
            result = io.BytesIO()
            pisa_status = pisa.CreatePDF(
                io.BytesIO(html_content.encode("utf-8")),
                dest=result
            )
            
            if pisa_status.err:
                logger.error("PDF generation failed: %s", pisa_status.err)
                raise RuntimeError(f"PDF generation failed with error {pisa_status.err}")
                
            return result.getvalue()
            
        except Exception as exc:
            logger.error("Exception during PDF export: %s", exc)
            raise
