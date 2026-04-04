"""
iast_sensor.py — IAST Agent Management and Correlation

Responsibilities:
  - Receive runtime telemetry from backend agents (IAST Sensors)
  - Correlate DAST payloads with actual execution sinks in backend code
  - Pinpoint exact file and line number for verified vulnerabilities
  - Enhance DAST confidence by matching external hits with internal sensor data
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class SensorEvent:
    sensor_id: str
    request_id: str
    sink_type: str        # e.g., "sql_query", "file_open", "process_exec"
    sink_details: str     # e.g., "SELECT * FROM user WHERE id = '1' OR '1'='1'"
    stack_trace: List[str]
    file_path: str
    line_number: int
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class IASTSensorManager:
    """
    Manages communication with IAST sensors deployed in target applications.
    """

    def __init__(self) -> None:
        self._active_sensors: Dict[str, Dict] = {}
        self._event_queue: Dict[str, List[SensorEvent]] = {} # request_id -> events

    async def register_sensor(self, sensor_info: Dict) -> str:
        s_id = str(uuid.uuid4())
        self._active_sensors[s_id] = sensor_info
        logger.info("IAST: New sensor registered: %s (%s)", s_id, sensor_info.get("language"))
        return s_id

    async def report_event(self, event: SensorEvent):
        """Receive an event from a sensor."""
        if event.request_id not in self._event_queue:
            self._event_queue[event.request_id] = []
        self._event_queue[event.request_id].append(event)
        logger.debug("IAST: Event received for request %s", event.request_id)

    def get_events_for_request(self, request_id: str) -> List[SensorEvent]:
        return self._event_queue.get(request_id, [])

    def correlate_finding(self, finding_url: str, request_id: str) -> Optional[SensorEvent]:
        """
        Attempt to find a matching sensor event that explains a DAST finding.
        """
        events = self.get_events_for_request(request_id)
        if not events:
            return None
            
        # Simplistic: return the first event matching the request_id
        # In PRD, we'd check if sink_details matches the injected payload
        return events[0]
