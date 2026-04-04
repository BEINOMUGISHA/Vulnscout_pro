"""
parallel_engine.py — High-Concurrency Scan Orchestrator

Responsibilities:
  - Manage multiple concurrent ScanOrchestrator instances
  - Enforce global concurrency limits (total active scans)
  - Coordinate resource sharing (shared connection pool, results streaming)
  - Handle global cancellation and gracefully shut down all active scans
  - Provide a central API for starting/stopping/monitoring clusters of scans
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from core.scanner.orchestrator import ScanOrchestrator, ScanStatus

logger = logging.getLogger(__name__)


@dataclass
class EngineStatus:
    total_scans: int = 0
    active_scans: int = 0
    completed_scans: int = 0
    failed_scans: int = 0
    global_rps: float = 0.0
    memory_usage_mb: float = 0.0


class ParallelScanEngine:
    """
    Orchestrates multiple ScanOrchestrator instances.
    Ensures the system doesn't exceed its resource limits when multiple scans are run.
    """

    def __init__(self, max_parallel_scans: int = 3) -> None:
        self.max_parallel_scans = max_parallel_scans
        self._active_scans: Dict[str, ScanOrchestrator] = {}
        self._pending_scans: asyncio.Queue = asyncio.Queue()
        self._semaphore = asyncio.Semaphore(max_parallel_scans)
        self._stop_event = asyncio.Event()
        self._tasks: Set[asyncio.Task] = set()

    async def submit_scan(self, target, config, progress_callback=None) -> str:
        """
        Submit a new scan to the engine. Returns the scan ID immediately.
        The scan will start as soon as a slot is available mapping to max_parallel_scans.
        """
        orchestrator = ScanOrchestrator(config, progress_callback=progress_callback)
        scan_id = orchestrator.scan_id
        
        # We put it in the pending queue
        await self._pending_scans.put((scan_id, target, orchestrator))
        
        # Start a management task if not already running
        task = asyncio.create_task(self._run_scan_task(scan_id, target, orchestrator))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        
        return scan_id

    async def _run_scan_task(self, scan_id: str, target, orchestrator: ScanOrchestrator):
        """
        Background task that waits for a slot and executes the scan.
        """
        async with self._semaphore:
            if self._stop_event.is_set():
                return

            self._active_scans[scan_id] = orchestrator
            logger.info("ParallelEngine: Starting scan %s (Slots: %d/%d)", 
                        scan_id, len(self._active_scans), self.max_parallel_scans)
            
            try:
                await orchestrator.run(target)
            except Exception as e:
                logger.error("ParallelEngine: Scan %s failed: %s", scan_id, e)
            finally:
                self._active_scans.pop(scan_id, None)
                logger.info("ParallelEngine: Scan %s finished (Slots: %d/%d)", 
                            scan_id, len(self._active_scans), self.max_parallel_scans)

    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a specific scan by ID."""
        if scan_id in self._active_scans:
            await self._active_scans[scan_id].cancel()
            return True
        return False

    async def stop(self) -> None:
        """Shut down the engine and all active scans."""
        self._stop_event.set()
        logger.info("ParallelEngine: Stopping engine and cancelling %d scans", len(self._active_scans))
        
        # Cancel all active orchestrators
        cancel_tasks = [orch.cancel() for orch in self._active_scans.values()]
        if cancel_tasks:
            await asyncio.gather(*cancel_tasks, return_exceptions=True)
            
        # Cancel all management tasks
        for task in self._tasks:
            task.cancel()
        
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
            
        self._active_scans.clear()

    @property
    def status(self) -> EngineStatus:
        # Simplistic status report
        return EngineStatus(
            total_scans=len(self._active_scans) + len(self._tasks), # Rough estimate
            active_scans=len(self._active_scans),
            completed_scans=0, # Would need a counter
        )

    def get_orchestrator(self, scan_id: str) -> Optional[ScanOrchestrator]:
        return self._active_scans.get(scan_id)
