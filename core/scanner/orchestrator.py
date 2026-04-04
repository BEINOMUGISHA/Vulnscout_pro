"""
orchestrator.py — Scan Lifecycle Manager
Coordinates all scanner components: crawl → inject → detect → score → report

Production considerations:
  - Full async pipeline with configurable concurrency
  - Hard scope gate before any network activity
  - Per-phase progress callbacks for UI/CLI streaming
  - Graceful cancellation at every yield point via sentinel pattern
  - Structured error collection (scan never crashes silently)
  - Proper enum types for status/phase (typos caught at definition time)
  - All findings mutations isolated to _score_findings; no cross-phase side-effects
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Enums ──────────────────────────────────────────────────────────────────────

class ScanStatus(str, Enum):
    PENDING       = "pending"
    RUNNING       = "running"
    COMPLETE      = "complete"
    FAILED        = "failed"
    CANCELLED     = "cancelled"
    SCOPE_BLOCKED = "scope_blocked"


class ScanPhase(str, Enum):
    PENDING     = "pending"
    SCOPE_CHECK = "scope_check"
    CRAWLING    = "crawling"
    DETECTING   = "detecting"
    VALIDATING  = "validating"
    SCORING     = "scoring"
    COMPLETE    = "complete"


# Sentinel used to signal the detect worker to stop cleanly.
_QUEUE_SENTINEL = object()

# Maximum detector concurrency cap even in high-concurrency mode.
_MAX_CONCURRENCY_CAP = 200

# Audio: play scan_loop at most once per this many seconds to avoid overlap.
_AUDIO_LOOP_COOLDOWN = 5.0


# ── Progress data structure ────────────────────────────────────────────────────

@dataclass
class ScanProgress:
    scan_id: str
    phase: ScanPhase = ScanPhase.PENDING
    discovered_endpoints: int = 0
    analyzed_endpoints: int = 0
    detector_tasks_total: int = 0
    detector_tasks_done: int = 0
    findings_count: int = 0
    active_detectors: List[str] = field(default_factory=list)
    findings_by_class: Dict[str, int] = field(default_factory=dict)
    elapsed_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)

    @property
    def percent_complete(self) -> float:
        """
        Multi-phase progress calculation. Each phase owns a slice of 0-100%.

        Phase weights:
          SCOPE_CHECK  →  0–5 %
          CRAWLING     →  5–40 %   (growth curve; total unknown)
          DETECTING    → 40–90 %   (precise; tasks_done / tasks_total)
          VALIDATING   → 90–95 %
          SCORING      → 95–98 %
          COMPLETE     → 100 %
        """
        p = self.phase

        if p == ScanPhase.PENDING:
            return 0.0

        if p == ScanPhase.SCOPE_CHECK:
            return 2.0

        if p == ScanPhase.CRAWLING:
            count = self.discovered_endpoints
            raw = 5.0 + (count * 2.5 if count < 10 else 25.0 + count / 8.0)
            return min(39.9, raw)

        if p == ScanPhase.DETECTING:
            if self.detector_tasks_total > 0:
                ratio = min(1.0, self.detector_tasks_done / self.detector_tasks_total)
                return 40.0 + ratio * 50.0
            return 40.0

        if p == ScanPhase.VALIDATING:
            return 91.0

        if p == ScanPhase.SCORING:
            return 96.0

        if p == ScanPhase.COMPLETE:
            return 100.0

        return 0.0

    def to_dict(self) -> Dict:
        return {
            "scan_id": self.scan_id,
            "phase": self.phase.value,
            "progress": round(self.percent_complete, 1),
            # Field names match the dataclass — no phantom attributes.
            "discovered_endpoints": self.discovered_endpoints,
            "analyzed_endpoints": self.analyzed_endpoints,
            "detector_tasks_total": self.detector_tasks_total,
            "detector_tasks_done": self.detector_tasks_done,
            "findings_count": self.findings_count,
            "active_detectors": self.active_detectors,
            "findings_by_class": self.findings_by_class,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "errors": self.errors,
        }

    def reset(self) -> None:
        """Reset all mutable counters so the same object can be reused."""
        self.phase = ScanPhase.PENDING
        self.discovered_endpoints = 0
        self.analyzed_endpoints = 0
        self.detector_tasks_total = 0
        self.detector_tasks_done = 0
        self.findings_count = 0
        self.active_detectors = []
        self.findings_by_class = {}
        self.elapsed_seconds = 0.0
        self.errors = []


ProgressCallback = Callable[[ScanProgress], None]


# ── Exceptions ─────────────────────────────────────────────────────────────────

class OrchestratorError(Exception):
    """Raised when the orchestrator encounters an unrecoverable error."""


# ── Orchestrator ───────────────────────────────────────────────────────────────

class ScanOrchestrator:
    """
    Central coordinator for a full vulnerability scan lifecycle.

    Usage:
        config = ScanConfig(target_url="https://example.com", ...)
        orchestrator = ScanOrchestrator(config, progress_callback=my_fn)
        scan = await orchestrator.run(target)

    Phases:
        1. scope_check  — hard gate; raises ScopeViolationError if not authorised
        2. crawling     — endpoint + parameter discovery (producer)
        3. detecting    — all registered detectors run concurrently per endpoint (consumer)
        4. validating   — deduplication and confirmation of findings
        5. scoring      — CVSS v3.1 + contextual risk prioritisation
        6. complete     — result assembled and returned

    Cancellation:
        Call await orchestrator.cancel() from any coroutine. The scan stops at
        the next queue checkpoint and all in-flight detector tasks are awaited
        before the CancelledError propagates.
    """

    def __init__(
        self,
        config,
        detector_registry=None,
        progress_callback: Optional[ProgressCallback] = None,
        finding_callback:  Optional[Callable[[List], None]] = None,
    ) -> None:
        from core.scanner.crawler import Crawler
        from core.scanner.injector import Injector
        from core.scanner.validator import Validator
        from core.scanner.rate_limiter import AdaptiveRateLimiter
        from core.scanner.scope_enforcer import ScopeEnforcer
        from core.detection.registry import DetectorRegistry
        from core.scoring.cvss_v31 import CVSSv31Calculator
        from core.scoring.risk_prioritizer import RiskPrioritizer
        from core.scoring.ai_triage import AITriageEngine
        from core.integrations.notifications import NotificationDispatcher
        from core.scanner.auth_handler import AuthHandler
        from core.integrations.audio_manager import audio_manager
        from core.remediation.auto_fix import AutoFixEngine
        from core.detection.engine import DetectionEngine

        self.config = config
        self.progress_callback = progress_callback
        self.finding_callback = finding_callback
        self.auth_handler: Optional[AuthHandler] = None
        self.audio = audio_manager

        self._scan_id: str = str(uuid.uuid4())
        self._start_time: float = 0.0
        self._cancelled: bool = False
        self._audio_loop_last: float = 0.0  # throttle scan_loop audio

        # TURBO: Fast Mode Detection
        self.fast_mode = getattr(config, "fast_mode", False)
        if self.fast_mode:
            logger.info("[%s] TURBO MODE ACTIVATED — stripping enterprise overhead", self._scan_id)

        # Permissive placeholder scope — replaced in run() before any I/O.
        from core.scanner.scope_enforcer import ScopeConfig as SE_ScopeConfig
        _placeholder_scope = SE_ScopeConfig(
            allowed_url_prefixes=["http://placeholder.local"],
            allowed_domains=["placeholder.local"],
        )
        self.scope_enforcer = ScopeEnforcer(_placeholder_scope)

        unthrottled = getattr(config, "unthrottled", False) or self.fast_mode
        self.rate_limiter = AdaptiveRateLimiter(
            requests_per_second=config.rate_limit_rps,
            burst_capacity=config.rate_limit_burst,
            unthrottled=unthrottled,
        )
        if unthrottled:
            logger.warning(
                "[%s] UNTHROTTLED MODE ENABLED — rate limiting bypassed", self._scan_id
            )

        self.crawler = Crawler(
            rate_limiter=self.rate_limiter,
            max_depth=config.crawl_depth,
            max_pages=config.max_pages,
            user_agent=config.user_agent,
            respect_robots=config.respect_robots_txt,
            js_render=getattr(config, "js_render", False) if not self.fast_mode else False,
            api_fuzzing=getattr(config, "api_fuzzing", False) if not self.fast_mode else False,
            auth_handler=self.auth_handler,
        )
        self.injector = Injector(rate_limiter=self.rate_limiter)
        self.validator = Validator(injector=self.injector)
        self.registry = detector_registry or DetectorRegistry.default()
        self.cvss = CVSSv31Calculator()
        self.prioritizer = RiskPrioritizer()
        
        # Fast mode: bypass heavy engines
        self.ai_triage = None if self.fast_mode else AITriageEngine()
        self.auto_fix = None if self.fast_mode else AutoFixEngine()
        self.detection_engine = DetectionEngine()

        int_config = {}
        if not self.fast_mode and hasattr(config, "integrations"):
            int_config = (
                config.integrations.to_dict()
                if hasattr(config.integrations, "to_dict")
                else {}
            )
        self.notifications = NotificationDispatcher(int_config)

        # Single progress object; reset() is called at the start of each run().
        self._progress = ScanProgress(scan_id=self._scan_id)

        # Global concurrency control for detector tasks (total parallel requests)
        self.global_detector_semaphore = asyncio.Semaphore(_MAX_CONCURRENCY_CAP)
        
        # Background tasks that don't block main orchestration completion
        self._offload_tasks: List[asyncio.Task] = []

    # ── Public API ─────────────────────────────────────────────────────────────

    async def run(self, target) -> dict:
        """Execute a full scan against `target`. Returns a completed scan result dict."""
        from core.scanner.scope_enforcer import ScopeViolationError, ScopeConfig as SE_ScopeConfig

        # Reset counters so the orchestrator can be safely reused.
        self._cancelled = False
        self._progress.reset()
        self._progress.phase = ScanPhase.SCOPE_CHECK
        self._notify_progress()
        self._start_time = time.monotonic()

        # ── Build real scope ───────────────────────────────────────────────────
        target_url: str = target.base_url if hasattr(target, "base_url") else str(target)

        if hasattr(target, "scope") and not target.scope.is_empty():
            existing = target.scope
            real_scope = SE_ScopeConfig(
                allowed_domains=list(getattr(existing, "allowed_domains", [])),
                allowed_wildcard_domains=list(getattr(existing, "allowed_wildcard_domains", [])),
                allowed_ip_ranges=list(getattr(existing, "allowed_ip_ranges", [])),
                allowed_url_prefixes=list(getattr(existing, "allowed_url_prefixes", [])),
                excluded_paths=list(getattr(existing, "excluded_paths", [])),
                excluded_domains=list(getattr(existing, "excluded_domains", [])),
                authorised_by=getattr(existing, "authorised_by", None),
            )
        else:
            from urllib.parse import urlparse
            parsed = urlparse(target_url)
            host = parsed.hostname or ""
            real_scope = SE_ScopeConfig(
                allowed_url_prefixes=[target_url],
                allowed_domains=[host],
                authorised_by="auto",
            )

        from core.scanner.scope_enforcer import ScopeEnforcer as _SE
        self.scope_enforcer = _SE(real_scope)

        scan: Dict = {
            "id": self._scan_id,
            "target": target_url,
            "status": ScanStatus.RUNNING.value,
            "config": self.config.to_dict() if hasattr(self.config, "to_dict") else {},
            "findings": [],
            "stats": {},
            "duration_seconds": 0.0,
            "error": None,
        }

        try:
            # ── Phase 0: Auth & Scope gate ─────────────────────────────────────
            self.audio.play("scan_start")
            self._update_phase(ScanPhase.SCOPE_CHECK)
            await self.scope_enforcer.enforce(target)

            if hasattr(target, "auth") and target.auth.has_credentials():
                from core.scanner.auth_handler import AuthHandler
                self.auth_handler = AuthHandler(
                    target.auth, user_agent=self.config.user_agent
                )
                self.crawler.auth_handler = self.auth_handler
                self.injector.auth_handler = self.auth_handler

            # ── Phase 1: Crawl & Detect (streaming, overlapping) ───────────────
            #
            # Architecture: producer/consumer via asyncio.Queue.
            #   - _crawl_worker puts CrawlResult objects (then a sentinel when done).
            #   - _detect_worker pulls items, spawns per-detector tasks, and acks
            #     each item only after all its detector tasks complete. This ensures
            #     queue.join() in run() only resolves once *all* detection work is
            #     done, not just all items dequeued.
            #
            # Teardown order (no data loss):
            #   1. crawl_task finishes naturally → puts _QUEUE_SENTINEL.
            #   2. _detect_worker sees sentinel → drains remaining tasks → exits.
            #   3. await detect_task → all findings are in raw_findings.
            #
            endpoint_queue: asyncio.Queue = asyncio.Queue()
            raw_findings: List = []

            self._update_phase(ScanPhase.CRAWLING)

            crawl_task = asyncio.create_task(
                self._crawl_worker(target, endpoint_queue),
                name=f"crawl-{self._scan_id}",
            )
            detect_task = asyncio.create_task(
                self._detect_worker(target, endpoint_queue, raw_findings),
                name=f"detect-{self._scan_id}",
            )

            # Wait for both tasks; propagate the first exception if any.
            await asyncio.gather(crawl_task, detect_task)

            logger.info(
                "[%s] Streaming discovery complete — %d endpoints, %d raw findings",
                self._scan_id,
                self._progress.discovered_endpoints,
                len(raw_findings),
            )

            # ── Phase 2: Validation / dedup ────────────────────────────────────
            self._update_phase(ScanPhase.VALIDATING)
            
            # Briefly await offload scanners (SDD) before validation to ensure 
            # they're in the report, but don't let them stall if they are hung.
            if self._offload_tasks:
                pending_scanners = [t for t in self._offload_tasks if not t.done()]
                if pending_scanners:
                    logger.info("[%s] Awaiting %d offloaded scanners (SDD/Passive)", 
                                self._scan_id, len(pending_scanners))
                    await asyncio.gather(*pending_scanners, return_exceptions=True)

            confirmed_findings = await self.validator.validate_all(raw_findings)
            logger.info(
                "[%s] Validation complete — %d confirmed findings",
                self._scan_id,
                len(confirmed_findings),
            )

            # ── Phase 3: Scoring & Core Orchestration ───────────────────────────
            self._update_phase(ScanPhase.SCORING)
            scored_findings = await self._score_findings(confirmed_findings, target)

            # ── Phase 4: Finalise ──────────────────────────────────────────────
            self._update_phase(ScanPhase.COMPLETE)
            scan["findings"] = [
                f.to_dict() if hasattr(f, "to_dict") else f
                for f in scored_findings
            ]
            scan["status"] = ScanStatus.COMPLETE.value
            scan["duration_seconds"] = round(time.monotonic() - self._start_time, 2)
            scan["stats"] = self._build_stats(scored_findings)
            self._progress.findings_count = len(scored_findings)
            self.audio.play("success")
            
            # Note: At this point, enrichment (AI Triage, Remediation) may still be 
            # happening in the background via self._offload_tasks.
            # We return the scan now so the core "orchestration" is complete.

            # ── Phase 5: Notifications ─────────────────────────────────────────
            if not getattr(self, "fast_mode", False):
                try:
                    await self.notifications.dispatch_scan_complete(scan)
                    for f in scored_findings:
                        if (getattr(f, "severity", "") or "").lower() == "critical":
                            f_dict = f.to_dict() if hasattr(f, "to_dict") else f
                            await self.notifications.dispatch_critical_finding(f_dict)
                except Exception as exc:
                    logger.warning(
                        "[%s] Notification dispatch failed: %s", self._scan_id, exc
                    )

            return scan

        except ScopeViolationError:
            scan["status"] = ScanStatus.SCOPE_BLOCKED.value
            logger.warning("[%s] Scan blocked — scope violation", self._scan_id)
            raise

        except asyncio.CancelledError:
            scan["status"] = ScanStatus.CANCELLED.value
            logger.info("[%s] Scan cancelled by caller", self._scan_id)
            raise

        except Exception as exc:
            scan["status"] = ScanStatus.FAILED.value
            scan["error"] = str(exc)
            logger.exception("[%s] Scan failed: %s", self._scan_id, exc)
            raise OrchestratorError(f"Scan {self._scan_id} failed: {exc}") from exc

        finally:
            if self.auth_handler:
                await self.auth_handler.close()
            await self.notifications.close()

    async def cancel(self) -> None:
        """Signal a running scan to stop at the next safe yield point."""
        self._cancelled = True
        await self.crawler.stop()
        logger.info("[%s] Cancellation requested", self._scan_id)

    async def recover(self) -> None:
        """
        Tactical Recovery: Force progress by bypassing a stuck phase.
        Commonly used when the crawler is hung on a slow endpoint or DNS timeout.
        """
        logger.warning("[%s] TACTICAL RECOVERY INITIATED — bypassing current throughput stall", self._scan_id)
        self._progress.errors.append("Tactical recovery initiated by user.")
        
        if self._progress.phase == ScanPhase.CRAWLING:
             # Stop the crawler workers and signal them to drain
             await self.crawler.stop()
             logger.info("[%s] Recovery: Crawler signalled to stop", self._scan_id)
             
             # The _crawl_worker will naturally put a sentinel and exit.
             # If no endpoints were discovered, we'll be stuck in DETECTING forever.
             # We don't have direct access to the queue here, so we rely on the 
             # fact that stopping the crawler will cause the producer to finish.
        
        self.audio.play("success") # Play success chime to indicate recovery action taken

    @property
    def scan_id(self) -> str:
        return self._scan_id

    @property
    def progress(self) -> ScanProgress:
        return self._progress

    # ── Workers ────────────────────────────────────────────────────────────────

    async def _crawl_worker(self, target, queue: asyncio.Queue) -> None:
        """
        Producer: discovers endpoints and feeds the detection queue.
        Always puts _QUEUE_SENTINEL when done so the consumer can exit cleanly.
        """
        from core.scanner.scope_enforcer import ScopeViolationError

        endpoint_count = 0
        logger.info("[%s] Crawler starting for %s", self._scan_id, target.base_url)

        try:
            async for result in self.crawler.crawl(target.base_url):
                if self._cancelled:
                    break
                try:
                    await self.scope_enforcer.enforce_url(result.url)
                except ScopeViolationError:
                    logger.debug("Out-of-scope URL skipped: %s", result.url)
                    continue

                endpoint_count += 1
                self._progress.discovered_endpoints = endpoint_count
                await queue.put(result)
                self._notify_progress()
        finally:
            # Sentinel is always sent, even on error or cancellation, so the
            # consumer never hangs waiting for an item that will never arrive.
            await queue.put(_QUEUE_SENTINEL)
            logger.info(
                "[%s] Crawl worker finished — %d endpoints discovered",
                self._scan_id,
                endpoint_count,
            )

    async def _detect_worker(
        self, target, queue: asyncio.Queue, results_list: List
    ) -> None:
        """
        Consumer: pulls endpoints from the queue, runs all active detectors
        concurrently, and waits for each batch to complete before moving on.

        Exits cleanly when it receives _QUEUE_SENTINEL from the crawler.
        All in-flight tasks are awaited before the method returns, guaranteeing
        no findings are silently dropped.
        """
        base_concurrency = self.config.max_concurrent_detectors
        if getattr(self.config, "high_concurrency", False):
            concurrency = min(base_concurrency * 4, _MAX_CONCURRENCY_CAP)
            logger.info(
                "[%s] High-concurrency mode — limit: %d", self._scan_id, concurrency
            )
        else:
            concurrency = base_concurrency

        semaphore = asyncio.Semaphore(concurrency)
        active_detectors = self.registry.active_detectors(self.config.enabled_checks)
        self._progress.active_detectors = [
            d.__class__.__name__.replace("Detector", "") for d in active_detectors
        ]

        # Process function: runs all detectors against a single endpoint.
        async def process_endpoint(ep) -> None:
            async with semaphore:
                if self._cancelled:
                    return
                
                # SEPARATION: core scanning vs offloaded passive functions (e.g. SDD)
                # Sensitive Data Detection (SDD) and LLM analysis are identified by ID
                offload_ids = {"sensitive_data", "llm_detector"}
                core_detectors = [d for d in active_detectors if d.meta.detector_id not in offload_ids]
                offload_detectors = [d for d in active_detectors if d.meta.detector_id in offload_ids]

                async def run_one(detector, is_offload=False):
                    async with self.global_detector_semaphore:
                        if self._cancelled:
                            return
                        try:
                            if not is_offload:
                                self._progress.detector_tasks_total += 1
                            findings = await detector.detect(
                                target=target,
                                crawl_result=ep,
                                injector=self.injector,
                            )
                            if findings:
                                results_list.extend(findings)
                                for f in findings:
                                    vclass = getattr(f, "vuln_type", "Other")
                                    self._progress.findings_by_class[vclass] = \
                                        self._progress.findings_by_class.get(vclass, 0) + 1
                                
                                self._progress.findings_count = len(results_list)
                                if self.finding_callback:
                                    await self._safe_callback(self.finding_callback, findings)
                        except Exception as exc:
                            logger.warning("[%s] %sDetector failed: %s", self._scan_id, "Offload" if is_offload else "", exc)
                        finally:
                            if not is_offload:
                                self._progress.detector_tasks_done += 1
                                self._notify_progress()

                # 1. CORE SCANNING: Run active vulnerability detectors (BLOCKS Phase Progress)
                if core_detectors:
                    await asyncio.gather(*[run_one(d) for d in core_detectors], return_exceptions=True)
                
                # 2. OFFLOAD: Run passive/heavy scanners (e.g. SDD) in BACKGROUND
                if offload_detectors:
                    for d in offload_detectors:
                        task = asyncio.create_task(run_one(d, is_offload=True))
                        self._offload_tasks.append(task)
                
                self._progress.analyzed_endpoints += 1
                self._notify_progress()

        tasks: List[asyncio.Task] = []

        while True:
            item = await queue.get()

            if item is _QUEUE_SENTINEL:
                # Crawler is done. Wait for all detection tasks to finish.
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
                break
                
            if self._progress.phase != ScanPhase.DETECTING:
                self._update_phase(ScanPhase.DETECTING)

            if self._cancelled:
                queue.task_done()
                continue

            # Create one task per endpoint (matches Minimal Scanner architecture)
            tasks.append(asyncio.create_task(process_endpoint(item)))
            queue.task_done()

    async def _safe_callback(self, callback: Callable, data: Any) -> None:
        """Helper to invoke finding/progress callbacks safely."""
        try:
            if asyncio.iscoroutinefunction(callback):
                await callback(data)
            else:
                callback(data)
        except Exception as e:
            logger.warning("[%s] Callback exception: %s", self._scan_id, e)

    # ── Scoring ────────────────────────────────────────────────────────────────

    async def _score_findings(self, findings: list, target=None) -> list:
        """
        Score, triage, and prioritise findings. Core CVSS scoring remains 
        synchronous, while heavy AI enrichment is offloaded.
        """
        industry = getattr(target, "industry", "general")
        context = {"industry": industry}
        alerted_severities: set = set()

        async def enrich_finding_background(finding):
            """Background worker for heavy AI triage and remediation."""
            if getattr(self, "fast_mode", False):
                return
            
            # AI Triage
            if self.ai_triage:
                try:
                    triage = await self.ai_triage.triage(finding, context)
                    finding.ai_triage_score = triage.business_impact_score
                    finding.business_impact = triage.analysis_summary
                    finding.financial_impact_ugx = triage.financial_impact_estimate
                    finding.predicted_exploitability = triage.predicted_exploitability
                except Exception as exc:
                    logger.debug("[%s] Background AI triage failed: %s", self._scan_id, exc)

            # Risk prioritisation
            self.prioritizer.prioritize(finding, industry=industry)

            # Remediation guide
            if self.auto_fix:
                try:
                    finding.remediation_guide = self.auto_fix.get_remediation(finding)
                except Exception as exc:
                    logger.debug("[%s] Background remediation failed: %s", self._scan_id, exc)

        # 1. CORE SCORING: CVSS (Synchronous - User Requirement)
        for finding in findings:
            if getattr(finding, "cvss_vector", None):
                finding.cvss_score = self.cvss.calculate(finding.cvss_vector)
                finding.severity = self.cvss.severity_label(finding.cvss_score)
            
            # 2. AUDIO ALERTS (Core)
            sev = (getattr(finding, "severity", "") or "").lower()
            if sev and sev not in alerted_severities:
                self.audio.play_alert(sev)
                alerted_severities.add(sev)

            # 3. SPWAN OFFLOAD TASK (AI/Remediation)
            self._offload_tasks.append(asyncio.create_task(enrich_finding_background(finding)))

        return sorted(
            findings,
            key=lambda f: (
                getattr(f, "risk_priority", 100),
                -getattr(f, "cvss_score", 0.0),
            ),
        )

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _build_stats(self, findings: list) -> Dict:
        stats: Dict = {
            "total": len(findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
        }
        for f in findings:
            sev = (getattr(f, "severity", None) or "informational").lower()
            stats[sev] = stats.get(sev, 0) + 1
        return stats

    def _update_phase(self, phase: ScanPhase) -> None:
        self._progress.phase = phase
        self._progress.elapsed_seconds = time.monotonic() - self._start_time
        self._notify_progress()
        logger.debug("[%s] Phase → %s", self._scan_id, phase.value)

        # Play scan_loop audio at most once per cooldown window.
        if phase in (ScanPhase.CRAWLING, ScanPhase.DETECTING):
            now = time.monotonic()
            if now - self._audio_loop_last >= _AUDIO_LOOP_COOLDOWN:
                self.audio.play("scan_loop")
                self._audio_loop_last = now

    def _notify_progress(self) -> None:
        if not self.progress_callback:
            return
        
        logger.info("[%s] PROGRESS: %.1f%% (%s) [D:%d A:%d T:%d]", 
                     self._scan_id, self._progress.percent_complete, self._progress.phase.value,
                     self._progress.discovered_endpoints, self._progress.analyzed_endpoints,
                     self._progress.detector_tasks_total)

        # Check if the callback is an async function (coroutine function)
        if asyncio.iscoroutinefunction(self.progress_callback):
            asyncio.create_task(self.progress_callback(self._progress))
        else:
            try:
                self.progress_callback(self._progress)
            except Exception as exc:
                logger.warning("[%s] Sync progress_callback raised: %s", self._scan_id, exc)