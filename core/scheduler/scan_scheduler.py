"""
scan_scheduler.py — Recurring Scan Scheduler

Responsibilities:
  - Manage scheduled scan definitions (Target + Config + Frequency)
  - Execute a background loop to trigger scans when their time is due
  - Track next_run and last_run timestamps for all schedules
  - Support Daily, Weekly, and Monthly frequencies (simple cron-like logic)
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ScheduledScan:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    target_id: str = ""
    config_overrides: Dict = field(default_factory=dict)
    frequency: str = "weekly"  # daily, weekly, monthly, once
    next_run: Optional[str] = None
    last_run: Optional[str] = None
    enabled: bool = True
    owner_id: str = ""

    def calculate_next_run(self, from_date: Optional[datetime] = None) -> datetime:
        now = from_date or datetime.now(timezone.utc)
        if self.frequency == "daily":
            return now + timedelta(days=1)
        elif self.frequency == "weekly":
            return now + timedelta(weeks=1)
        elif self.frequency == "monthly":
            # Rough monthly jump
            return now + timedelta(days=30)
        else:
            return now + timedelta(days=7) # Default weekly


class ScanScheduler:
    """
    Background scheduler for automated recurring scans.
    """

    def __init__(self, scan_store=None, parallel_engine=None) -> None:
        self.scan_store = scan_store
        self.engine = parallel_engine
        self._schedules: Dict[str, ScheduledScan] = {}
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self):
        """Start the background scheduling loop."""
        if self._running:
            return
        self._running = True
        # Load schedules from store
        await self._load_schedules()
        self._task = asyncio.create_task(self._scheduler_loop())
        logger.info("ScanScheduler: Started background loop")

    async def stop(self):
        """Stop the background scheduling loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                # Wait up to 2 seconds for clean exit
                await asyncio.wait_for(self._task, timeout=2.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
        logger.info("ScanScheduler: Stopped background loop")

    async def _load_schedules(self):
        """Load schedules from persistent storage."""
        if self.scan_store:
            raw = await self.scan_store._load_json(self.scan_store._root / "schedules.json")
            if isinstance(raw, list):
                for item in raw:
                    sch = ScheduledScan(**item)
                    self._schedules[sch.id] = sch

    async def _save_schedules(self):
        """Save schedules to persistent storage."""
        if self.scan_store:
            data = [vars(s) for s in self._schedules.values()]
            await asyncio.to_thread(self.scan_store._atomic_write, 
                                   self.scan_store._root / "schedules.json", data)

    async def _scheduler_loop(self):
        """Main loop that checks for due scans every 60 seconds."""
        while self._running:
            try:
                now = datetime.now(timezone.utc)
                for sch in list(self._schedules.values()):
                    if not sch.enabled or not sch.next_run:
                        continue
                        
                    next_run_dt = datetime.fromisoformat(sch.next_run)
                    if now >= next_run_dt:
                        await self._trigger_scan(sch)
                        
                await asyncio.sleep(60) # Poll every minute
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception("ScanScheduler loop error: %s", e)
                await asyncio.sleep(60)

    async def _trigger_scan(self, sch: ScheduledScan):
        """Execute a scheduled scan."""
        logger.info("ScanScheduler: Triggering scan '%s' (Target: %s)", sch.name, sch.target_id)
        
        # 1. Update schedule timestamps
        sch.last_run = datetime.now(timezone.utc).isoformat()
        sch.next_run = sch.calculate_next_run().isoformat()
        await self._save_schedules()
        
        # 2. Start the scan (Mock logic — in reality we'd pull Target from scan_store)
        if self.engine:
            target_data = await self.scan_store.get_target(sch.target_id)
            if target_data:
                from core.models.target import Target, ScanConfig
                # Reconstruct Target and Config objects
                target = Target.from_dict(target_data)
                config = target.scan_config or ScanConfig() 
                # Apply overrides if any
                await self.engine.submit_scan(target, config)
            else:
                logger.warning("ScanScheduler: Target %s not found for schedule %s", 
                               sch.target_id, sch.id)

    async def add_schedule(self, sch: ScheduledScan):
        if not sch.next_run:
            sch.next_run = sch.calculate_next_run().isoformat()
        self._schedules[sch.id] = sch
        await self._save_schedules()

    async def remove_schedule(self, sch_id: str):
        if sch_id in self._schedules:
            del self._schedules[sch_id]
            await self._save_schedules()

    def list_schedules(self) -> List[ScheduledScan]:
        return list(self._schedules.values())
