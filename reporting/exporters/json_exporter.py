"""
reporting/exporters/json_exporter.py — JSON Data Exporter

Serialises report data to a machine-readable JSON format.
"""

from __future__ import annotations

import json
from typing import Dict

class JSONExporter:
    """
    Professional JSON Exporter.
    Supports full report structures including EA context and technical evidence.
    """
    async def export(self, report_data: Dict) -> bytes:
        # We ensure a clean, sorted JSON for better diffing/version control
        return json.dumps(
            report_data, 
            indent=2, 
            default=str,
            sort_keys=True
        ).encode("utf-8")
