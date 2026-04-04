"""
scan.py — Scan Lifecycle Model

A Scan is the top-level record for a single scanning session.
It contains the target, configuration, all findings, timing data,
and the full audit trail of every scope check.

Design principles:
  - Scan is the unit of storage — one JSON file per scan in storage/
  - Status transitions are explicit and logged
  - Stats are computed lazily from findings (not stored redundantly)
  - The scan record is self-contained: loading it gives you everything
    needed to reproduce the report without re-scanning
  - Large fields (findings, evidence) are kept separate so the scan
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from core.models.finding import Finding, FindingCollection, Severity
from core.models.target import Target, ScanConfig


# ── Status & Phase enums ───────────────────────────────────────────────────────

class ScanStatus:
    PENDING       = "pending"
    RUNNING       = "running"
    COMPLETE      = "complete"
    FAILED        = "failed"
    CANCELLED     = "cancelled"
    SCOPE_BLOCKED = "scope_blocked"

    TERMINAL = {COMPLETE, FAILED, CANCELLED, SCOPE_BLOCKED}

    @staticmethod
    def is_terminal(status: str) -> bool:
        return status in ScanStatus.TERMINAL


class ScanPhase:
    PENDING     = "pending"
    SCOPE_CHECK = "scope_check"
    CRAWLING    = "crawling"
    DETECTING   = "detecting"
    VALIDATING  = "validating"
    SCORING     = "scoring"
    COMPLETE    = "complete"

    ORDERED = [PENDING, SCOPE_CHECK, CRAWLING, DETECTING, VALIDATING, SCORING, COMPLETE]

    @staticmethod
    def index(phase: str) -> int:
        try:
            return ScanPhase.ORDERED.index(phase)
        except ValueError:
            return -1


# ── Scan event log ─────────────────────────────────────────────────────────────

@dataclass
class ScanEvent:
    """
    A single timestamped event in the scan's audit trail.
    Events are immutable once created.
    """
    timestamp: str
    phase: str
    message: str
    level: str = "info"         # info, warning, error
    data: dict | None = None

    @classmethod
    def now(cls, phase: str, message: str, level: str = "info", data: dict | None = None) -> "ScanEvent":
        return cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            phase=phase,
            message=message,
            level=level,
            data=data,
        )

    def to_dict(self) -> Dict:
        result = {
            "timestamp": self.timestamp,
            "phase": self.phase,
            "message": self.message,
            "level": self.level,
        }
        if self.data:
            result["data"] = self.data
        return result


# ── Scan metrics ───────────────────────────────────────────────────────────────

@dataclass
class ScanMetrics:
    """
    Performance and coverage metrics collected during a scan.
    Attached to the scan record for QA and auditing purposes.
    """
    # Crawl metrics
    pages_crawled: int = 0
    endpoints_discovered: int = 0
    forms_discovered: int = 0
    parameters_discovered: int = 0
    out_of_scope_blocked: int = 0

    # Detection metrics
    total_requests_sent: int = 0
    total_payloads_tested: int = 0
    detectors_run: int = 0
    detector_tasks_total: int = 0
    detector_tasks_done: int = 0
    raw_findings: int = 0
    confirmed_findings: int = 0
    false_positives_suppressed: int = 0
    duplicates_removed: int = 0

    # Performance
    crawl_duration_seconds: float = 0.0
    detection_duration_seconds: float = 0.0
    validation_duration_seconds: float = 0.0
    total_duration_seconds: float = 0.0
    avg_response_time_ms: float = 0.0
    peak_rps: float = 0.0

    # Errors
    network_errors: int = 0
    timeout_errors: int = 0
    detector_errors: int = 0

    def to_dict(self) -> dict:
        return {
            "crawl": {
                "pages_crawled": self.pages_crawled,
                "endpoints_discovered": self.endpoints_discovered,
                "forms_discovered": self.forms_discovered,
                "parameters_discovered": self.parameters_discovered,
                "out_of_scope_blocked": self.out_of_scope_blocked,
            },
            "detection": {
                "total_requests_sent": self.total_requests_sent,
                "payloads_tested": self.total_payloads_tested,
                "detectors_run": self.detectors_run,
                "detector_tasks_total": self.detector_tasks_total,
                "detector_tasks_done": self.detector_tasks_done,
                "raw_findings": self.raw_findings,
                "confirmed_findings": self.confirmed_findings,
                "false_positives_suppressed": self.false_positives_suppressed,
                "duplicates_removed": self.duplicates_removed,
            },
            "performance": {
                "total_duration_seconds": round(self.total_duration_seconds, 2),
                "crawl_duration_seconds": round(self.crawl_duration_seconds, 2),
                "detection_duration_seconds": round(self.detection_duration_seconds, 2),
                "avg_response_time_ms": round(self.avg_response_time_ms, 2),
                "peak_rps": round(self.peak_rps, 2),
            },
            "errors": {
                "network": self.network_errors,
                "timeout": self.timeout_errors,
                "detector": self.detector_errors,
            },
        }


# ── Scan model ─────────────────────────────────────────────────────────────────

@dataclass
class Scan:
    """
    Complete record of a single vulnerability scan.

    Storage layout (via scan_store.py):
      scans/{scan_id}/summary.json    — Scan without findings (fast load)
      scans/{scan_id}/findings.json   — Full findings list
      scans/{scan_id}/events.json     — Audit trail / event log
    """

    # Identity
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    owner_id: str = ""
    team_id: str | None = None

    # Core components
    target: Target | None = None
    config: ScanConfig | None = None

    # Lifecycle
    status: str = ScanStatus.PENDING
    current_phase: str = ScanPhase.PENDING
    progress: float = 0.0
    error: str | None = None

    # Findings
    findings: list[Finding] = field(default_factory=list)

    # Real-time detector state (populated by on_progress callback)
    active_detectors: list = field(default_factory=list)
    findings_by_class: dict = field(default_factory=dict)

    # Metrics & audit
    metrics: ScanMetrics = field(default_factory=ScanMetrics)
    events: list[ScanEvent] = field(default_factory=list)
    scope_audit: list[dict] = field(default_factory=list)

    # Timestamps
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    started_at: str | None = None
    completed_at: str | None = None

    def __post_init__(self) -> None:
        self._findings_collection: Optional[FindingCollection] = None

    # ── Lifecycle transitions ──────────────────────────────────────────────────

    def mark_started(self) -> None:
        self.status = ScanStatus.RUNNING
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.add_event(ScanPhase.PENDING, "Scan started")

    def mark_complete(self) -> None:
        self.status = ScanStatus.COMPLETE
        self.current_phase = ScanPhase.COMPLETE
        self.completed_at = datetime.now(timezone.utc).isoformat()
        self.add_event(
            ScanPhase.COMPLETE,
            f"Scan complete — {len(self.findings)} findings",
            data=self.summary_stats,
        )

    def mark_failed(self, error: str) -> None:
        self.status = ScanStatus.FAILED
        self.error = error
        self.completed_at = datetime.now(timezone.utc).isoformat()
        self.add_event(ScanPhase.COMPLETE, f"Scan failed: {error}", level="error")

    def mark_cancelled(self) -> None:
        self.status = ScanStatus.CANCELLED
        self.completed_at = datetime.now(timezone.utc).isoformat()
        self.add_event(ScanPhase.COMPLETE, "Scan cancelled by user", level="warning")

    def mark_scope_blocked(self, reason: str) -> None:
        self.status = ScanStatus.SCOPE_BLOCKED
        self.completed_at = datetime.now(timezone.utc).isoformat()
        self.add_event(ScanPhase.SCOPE_CHECK, f"Scope blocked: {reason}", level="warning")

    def advance_phase(self, phase: str) -> None:
        self.current_phase = phase
        self.add_event(phase, f"Phase started: {phase}")

    def add_event(
        self,
        phase: str,
        message: str,
        level: str = "info",
        data: dict | None = None,
    ) -> None:
        self.events.append(ScanEvent.now(phase, message, level, data))

    # ── Finding management ─────────────────────────────────────────────────────

    def add_finding(self, finding: Finding) -> None:
        finding.scan_id = self.id
        self.findings.append(finding)
        self._findings_collection = None    # Invalidate cache

    @property
    def finding_collection(self) -> FindingCollection:
        if self._findings_collection is None:
            self._findings_collection = FindingCollection(self.findings)
        return self._findings_collection

    # ── Stats & properties ─────────────────────────────────────────────────────

    @property
    def summary_stats(self) -> dict:
        """Severity breakdown — computed from findings, never stored redundantly."""
        stats: dict = {s: 0 for s in Severity.ALL}
        stats["total"] = len(self.findings)
        for f in self.findings:
            sev = f.severity or Severity.INFORMATIONAL
            stats[sev] = stats.get(sev, 0) + 1
        return stats

    @property
    def duration_seconds(self) -> float:
        """Wall-clock scan duration in seconds."""
        return self.metrics.total_duration_seconds

    @property
    def is_complete(self) -> bool:
        return ScanStatus.is_terminal(self.status)

    @property
    def has_critical(self) -> bool:
        return any(f.severity == Severity.CRITICAL for f in self.findings)

    @property
    def has_payment_findings(self) -> bool:
        return any(f.affects_payments for f in self.findings)

    @property
    def ea_risk_score(self) -> float:
        """
        Composite EA risk score (0–10).
        Weighted average of effective_cvss scores for EA-relevant findings.
        """
        ea_findings = [f for f in self.findings if f.ea_context.ea_relevant]
        if not ea_findings:
            return 0.0
        return round(sum(f.effective_cvss for f in ea_findings) / len(ea_findings), 2)

    # ── Serialisation ──────────────────────────────────────────────────────────

    def to_summary_dict(self) -> dict:
        """
        Lightweight summary — no findings list, no evidence.
        Used for scan listing / dashboard views.
        """
        target_dict = self.target.to_dict() if self.target else {}
        stats = self.summary_stats
        return {
            "id": self.id,
            "owner_id": self.owner_id,
            "team_id": self.team_id,
            "status": self.status,
            "current_phase": self.current_phase,
            "progress": self.progress,
            # Flat target_url so frontend doesn't need to dig into nested 'target'
            "target_url": target_dict.get("base_url") or target_dict.get("url") or "",
            "target": target_dict,
            "stats": stats,
            # Convenience counts used by the dashboard
            "total_findings": stats.get("total", 0),
            "critical_count": stats.get("critical", 0),
            "finding_count":  stats.get("total", 0),
            "metrics": self.metrics.to_dict(),
            # Real-time detector state
            "active_detectors": self.active_detectors,
            "findings_by_class": self.findings_by_class,
            "ea_risk_score": self.ea_risk_score,
            "has_critical": self.has_critical,
            "has_payment_findings": self.has_payment_findings,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error": self.error,
        }

    def to_full_dict(
        self,
        include_evidence: bool = True,
        include_events: bool = True,
        include_scope_audit: bool = False,
    ) -> Dict:
        """
        Complete scan record. Used for JSON storage and full report generation.
        """
        result = self.to_summary_dict()
        result["findings"] = [
            f.to_dict(include_evidence=include_evidence)
            for f in self.findings
        ]
        if include_events:
            result["events"] = [e.to_dict() for e in self.events]
        if include_scope_audit:
            result["scope_audit"] = self.scope_audit
        return result

    def to_json(self, **kwargs) -> str:
        import json
        return json.dumps(self.to_full_dict(**kwargs), indent=2, default=str)

    @classmethod
    def from_dict(cls, data: Dict) -> "Scan":
        """Deserialise from stored dict."""
        target_data = data.pop("target", None)
        config_data = data.pop("config", None)
        findings_data = data.pop("findings", [])
        events_data = data.pop("events", [])
        metrics_data = data.pop("metrics", {})

        target = Target.from_dict(target_data) if target_data else None
        config = ScanConfig(**{
            k: v for k, v in (config_data or {}).items()
            if k in ScanConfig.__dataclass_fields__
        }) if config_data else None

        findings = [Finding.from_dict(f) for f in findings_data]

        events = [
            ScanEvent(**e) for e in events_data
            if all(k in e for k in ("timestamp", "phase", "message"))
        ]

        # Flatten metrics dict for ScanMetrics
        flat_metrics = {}
        if metrics_data:
            for section in metrics_data.values():
                if isinstance(section, dict):
                    flat_metrics.update(section)

        metrics = ScanMetrics(**{
            k: v for k, v in flat_metrics.items()
            if k in ScanMetrics.__dataclass_fields__
        })

        scan = cls(
            **{
                k: v for k, v in data.items()
                if k in cls.__dataclass_fields__
                and k not in ("target", "config", "findings", "events", "metrics")
            },
            target=target,
            config=config,
            findings=findings,
            events=events,
            metrics=metrics,
        )
        return scan

    def __repr__(self) -> str:
        return (
            f"<Scan id={self.id[:8]} status={self.status} "
            f"findings={len(self.findings)} target={self.target.base_url if self.target else 'None'}>"
        )


# ── ScanSummary (lightweight listing object) ───────────────────────────────────

@dataclass
class ScanSummary:
    """
    Minimal scan record for listing views.
    Loaded from summary.json without touching findings.json.
    """
    id: str
    status: str
    target_url: str
    target_name: str
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    informational: int
    ea_risk_score: float
    has_payment_findings: bool
    duration_seconds: float
    created_at: str
    completed_at: Optional[str]

    @classmethod
    def from_scan(cls, scan: Scan) -> "ScanSummary":
        stats = scan.summary_stats
        return cls(
            id=scan.id,
            status=scan.status,
            target_url=scan.target.base_url if scan.target else "",
            target_name=scan.target.name if scan.target else "",
            total_findings=stats["total"],
            critical=stats.get(Severity.CRITICAL, 0),
            high=stats.get(Severity.HIGH, 0),
            medium=stats.get(Severity.MEDIUM, 0),
            low=stats.get(Severity.LOW, 0),
            informational=stats.get(Severity.INFORMATIONAL, 0),
            ea_risk_score=scan.ea_risk_score,
            has_payment_findings=scan.has_payment_findings,
            duration_seconds=scan.duration_seconds,
            created_at=scan.created_at,
            completed_at=scan.completed_at,
        )

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "status": self.status,
            "target_url": self.target_url,
            "target_name": self.target_name,
            "findings": {
                "total": self.total_findings,
                "critical": self.critical,
                "high": self.high,
                "medium": self.medium,
                "low": self.low,
                "informational": self.informational,
            },
            "ea_risk_score": self.ea_risk_score,
            "has_payment_findings": self.has_payment_findings,
            "duration_seconds": round(self.duration_seconds, 2),
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }