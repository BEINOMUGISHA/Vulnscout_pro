"""
auth/audit_log.py — Security Audit Log

Immutable, structured audit trail for all security-relevant events.
Every event is written to both the named 'vulnscout.audit' logger
(which the logging config routes to a separate audit.log file) and
persisted to flat-file JSON storage for compliance export.

Design:
  - Events are immutable once written — no update/delete methods
  - Every event carries: event_id, timestamp, actor, ip_address,
    event_type, outcome, resource, detail
  - actor is always a user_id (never email — minimise PII in logs)
  - ip_address is always recorded for accountability
  - outcome: "success" | "failure" | "blocked" | "error"
  - Structured JSON so log aggregators (ELK, Loki) can query/alert

Event taxonomy (AUDIT_EVENTS dict):
  auth.*         — login, logout, lockout, token operations
  scan.*         — scan lifecycle
  report.*       — report generation and downloads
  user.*         — account management
  api_key.*      — API key lifecycle
  scope.*        — scope violations
  totp.*         — 2FA operations
  rbac.*         — permission denials

Compliance exports:
  AuditLog.export_range(start, end)  → List[AuditEvent]
  AuditLog.export_json(path)         → writes NDJSON file
  AuditLog.export_csv(path)          → writes CSV for BOU submissions

Retention:
  Per config.logging.audit_retention_days (default: 365).
  Retention purge is idempotent — safe to run in a cron job.
"""

from __future__ import annotations

import csv
import json
import logging
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger("vulnscout.audit")


# ── Event taxonomy ─────────────────────────────────────────────────

AUDIT_EVENTS: Dict[str, str] = {
    # Authentication
    "auth.login.success":          "User authenticated successfully",
    "auth.login.failure":          "Authentication attempt failed",
    "auth.login.blocked":          "Login blocked — account locked out",
    "auth.logout":                 "User session terminated",
    "auth.token.refreshed":        "Access token refreshed",
    "auth.token.invalid":          "Invalid or expired token presented",
    "auth.lockout.applied":        "Account locked after repeated failures",
    "auth.lockout.cleared":        "Account lockout cleared on success",
    "auth.password.changed":       "User password changed",
    "auth.password.reset_request": "Password reset requested",
    "auth.password.reset_applied": "Password reset completed",

    # TOTP / 2FA
    "totp.enrolled":               "TOTP 2FA enrolled",
    "totp.verified":               "TOTP code verified",
    "totp.verify_failed":          "TOTP code verification failed",
    "totp.removed":                "TOTP 2FA removed from account",

    # API keys
    "api_key.created":             "API key created",
    "api_key.used":                "API key authenticated request",
    "api_key.revoked":             "API key revoked",
    "api_key.invalid":             "Invalid API key presented",

    # User management
    "user.created":                "User account created",
    "user.deleted":                "User account deleted",
    "user.role_changed":           "User role changed",
    "user.suspended":              "User account suspended",

    # Scan lifecycle
    "scan.started":                "Scan submitted and started",
    "scan.completed":              "Scan completed",
    "scan.failed":                 "Scan failed with error",
    "scan.cancelled":              "Scan cancelled by user",
    "scan.deleted":                "Scan record deleted",

    # Scope
    "scope.violation":             "Target URL rejected — out of scope",
    "scope.check.passed":          "Target URL passed scope check",

    # Reports
    "report.generated":            "Report generation queued",
    "report.completed":            "Report generation completed",
    "report.downloaded":           "Report downloaded",
    "report.deleted":              "Report deleted",

    # RBAC
    "rbac.denied":                 "Permission denied — insufficient role/scope",
    "rbac.escalation_attempt":     "Possible privilege escalation attempt detected",

    # System
    "system.startup":              "VulnScout Pro started",
    "system.shutdown":             "VulnScout Pro shutting down",
    "system.config_loaded":        "Configuration loaded and validated",
}

OUTCOME_SUCCESS = "success"
OUTCOME_FAILURE = "failure"
OUTCOME_BLOCKED = "blocked"
OUTCOME_ERROR   = "error"


# ── Audit event dataclass ──────────────────────────────────────────

@dataclass
class AuditEvent:
    """
    A single immutable audit record.
    Once created, no fields should be modified.
    """
    event_type:    str
    outcome:       str                     # success | failure | blocked | error
    actor_id:      str                     # user_id (never email)
    ip_address:    str = "unknown"
    resource_type: str = ""                # "scan" | "report" | "user" | "api_key" | ""
    resource_id:   str = ""                # ID of the affected resource
    detail:        Dict[str, Any] = field(default_factory=dict)
    user_agent:    str = ""

    # Auto-populated
    event_id:      str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:     str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def description(self) -> str:
        return AUDIT_EVENTS.get(self.event_type, self.event_type)

    def to_dict(self) -> Dict:
        return {
            "event_id":    self.event_id,
            "timestamp":   self.timestamp,
            "event_type":  self.event_type,
            "description": self.description,
            "outcome":     self.outcome,
            "actor_id":    self.actor_id,
            "ip_address":  self.ip_address,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "detail":      self.detail,
            "user_agent":  self.user_agent[:100] if self.user_agent else "",
        }

    def to_log_line(self) -> str:
        """Compact single-line representation for log files."""
        resource = (
            f" {self.resource_type}={self.resource_id}"
            if self.resource_id else ""
        )
        detail_str = " ".join(
            f"{k}={v}" for k, v in self.detail.items()
            if isinstance(v, (str, int, float, bool)) and v
        )
        return (
            f"{self.event_type} outcome={self.outcome}"
            f" actor={self.actor_id[:8] if self.actor_id else 'anon'}"
            f" ip={self.ip_address}"
            f"{resource}"
            + (f" {detail_str}" if detail_str else "")
        )

    def to_csv_row(self) -> List[str]:
        return [
            self.event_id,
            self.timestamp,
            self.event_type,
            self.outcome,
            self.actor_id,
            self.ip_address,
            self.resource_type,
            self.resource_id,
            json.dumps(self.detail, default=str),
            self.user_agent[:80] if self.user_agent else "",
        ]


CSV_HEADERS = [
    "event_id", "timestamp", "event_type", "outcome",
    "actor_id", "ip_address", "resource_type", "resource_id",
    "detail", "user_agent",
]


# ── AuditLog main interface ────────────────────────────────────────

class AuditLog:
    """
    Main interface for recording and querying audit events.

    Usage:
        audit = AuditLog(storage_path)

        # Record an event
        audit.log(AuditEvent(
            event_type="auth.login.success",
            outcome=OUTCOME_SUCCESS,
            actor_id=user.user_id,
            ip_address=request_ip,
            detail={"role": user.role},
        ))

        # Query events
        events = audit.query(actor_id=user_id, limit=50)

        # Export for compliance
        audit.export_json(Path("/tmp/audit-export.json"), days=90)
    """

    def __init__(self, storage_path: Path) -> None:
        self._path = storage_path / "audit"
        self._path.mkdir(parents=True, exist_ok=True)

    # ── Write ───────────────────────────────────────────────────────

    def log(self, event: AuditEvent) -> None:
        """
        Record an audit event.
        Writes to:
          1. Named logger 'vulnscout.audit' (→ audit.log file)
          2. Daily NDJSON shard in storage (for query/export)
        Never raises — audit failures must not block the application.
        """
        try:
            # Structured logger (goes to audit.log via logging config)
            log_level = (
                logging.INFO    if event.outcome == OUTCOME_SUCCESS else
                logging.WARNING if event.outcome == OUTCOME_FAILURE else
                logging.ERROR   if event.outcome == OUTCOME_ERROR   else
                logging.WARNING
            )
            logger.log(log_level, event.to_log_line(), extra=event.to_dict())

            # Append to daily shard file
            self._append_to_shard(event)

        except Exception as exc:
            # Log to stderr only — don't use the audit logger (infinite recursion risk)
            import sys
            print(
                f"AUDIT_LOG_ERROR: {exc} | event={event.event_type}",
                file=sys.stderr,
            )

    def _append_to_shard(self, event: AuditEvent) -> None:
        """Append event JSON to the daily shard file."""
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        shard = self._path / f"audit-{date_str}.ndjson"
        with shard.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event.to_dict(), default=str) + "\n")

    # ── Convenience factory methods ─────────────────────────────────

    def auth_success(self, actor_id: str, ip: str, **detail) -> AuditEvent:
        return self._log_and_return(AuditEvent(
            event_type="auth.login.success", outcome=OUTCOME_SUCCESS,
            actor_id=actor_id, ip_address=ip, detail=detail,
        ))

    def auth_failure(self, actor_id: str, ip: str, reason: str = "") -> AuditEvent:
        return self._log_and_return(AuditEvent(
            event_type="auth.login.failure", outcome=OUTCOME_FAILURE,
            actor_id=actor_id, ip_address=ip,
            detail={"reason": reason} if reason else {},
        ))

    def auth_lockout(self, actor_id: str, ip: str, duration_min: int) -> AuditEvent:
        return self._log_and_return(AuditEvent(
            event_type="auth.lockout.applied", outcome=OUTCOME_BLOCKED,
            actor_id=actor_id, ip_address=ip,
            detail={"lockout_duration_min": duration_min},
        ))

    def scope_violation(self, actor_id: str, ip: str, url: str, reason: str) -> AuditEvent:
        return self._log_and_return(AuditEvent(
            event_type="scope.violation", outcome=OUTCOME_BLOCKED,
            actor_id=actor_id, ip_address=ip,
            resource_type="url",
            detail={"url": url, "reason": reason},
        ))

    def scan_started(
        self, actor_id: str, ip: str,
        scan_id: str, target_url: str, authorised_by: str
    ) -> AuditEvent:
        return self._log_and_return(AuditEvent(
            event_type="scan.started", outcome=OUTCOME_SUCCESS,
            actor_id=actor_id, ip_address=ip,
            resource_type="scan", resource_id=scan_id,
            detail={"target_url": target_url, "authorised_by": authorised_by},
        ))

    def scan_completed(
        self, actor_id: str, scan_id: str,
        finding_count: int, critical_count: int, duration_s: float
    ) -> AuditEvent:
        return self._log_and_return(AuditEvent(
            event_type="scan.completed", outcome=OUTCOME_SUCCESS,
            actor_id=actor_id,
            resource_type="scan", resource_id=scan_id,
            detail={
                "finding_count": finding_count,
                "critical_count": critical_count,
                "duration_s": round(duration_s, 1),
            },
        ))

    def report_downloaded(
        self, actor_id: str, ip: str,
        report_id: str, fmt: str
    ) -> AuditEvent:
        return self._log_and_return(AuditEvent(
            event_type="report.downloaded", outcome=OUTCOME_SUCCESS,
            actor_id=actor_id, ip_address=ip,
            resource_type="report", resource_id=report_id,
            detail={"format": fmt},
        ))

    def rbac_denied(
        self, actor_id: str, ip: str,
        required_role: str, resource: str, action: str
    ) -> AuditEvent:
        return self._log_and_return(AuditEvent(
            event_type="rbac.denied", outcome=OUTCOME_BLOCKED,
            actor_id=actor_id, ip_address=ip,
            detail={
                "required_role": required_role,
                "resource": resource,
                "action": action,
            },
        ))

    def _log_and_return(self, event: AuditEvent) -> AuditEvent:
        self.log(event)
        return event

    # ── Query ───────────────────────────────────────────────────────

    def query(
        self,
        actor_id:    Optional[str] = None,
        event_type:  Optional[str] = None,
        outcome:     Optional[str] = None,
        resource_id: Optional[str] = None,
        ip_address:  Optional[str] = None,
        since:       Optional[datetime] = None,
        until:       Optional[datetime] = None,
        limit:       int = 100,
        offset:      int = 0,
    ) -> List[AuditEvent]:
        """
        Query audit events with optional filters.
        Scans shard files in reverse chronological order (most recent first).
        For large date ranges this is O(n) — add an index if needed.
        """
        results: List[AuditEvent] = []

        for shard in sorted(self._path.glob("audit-*.ndjson"), reverse=True):
            if len(results) >= offset + limit:
                break

            # Quick date range check from filename
            try:
                shard_date_str = shard.stem.replace("audit-", "")
                shard_date = datetime.strptime(shard_date_str, "%Y-%m-%d").replace(
                    tzinfo=timezone.utc
                )
                if until and shard_date > until:
                    continue
                if since and shard_date + timedelta(days=1) < since:
                    break
            except ValueError:
                pass

            for line in shard.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    if actor_id    and data.get("actor_id", "")[:8] != actor_id[:8]: continue
                    if event_type  and not data.get("event_type","").startswith(event_type): continue
                    if outcome     and data.get("outcome") != outcome: continue
                    if resource_id and data.get("resource_id","")[:8] != resource_id[:8]: continue
                    if ip_address  and data.get("ip_address") != ip_address: continue

                    ts_str = data.get("timestamp", "")
                    if ts_str:
                        try:
                            ts = datetime.fromisoformat(ts_str)
                            if since and ts < since: continue
                            if until and ts > until: continue
                        except ValueError:
                            pass

                    results.append(self._from_dict(data))
                except (json.JSONDecodeError, KeyError):
                    continue

        total = len(results)
        return results[offset: offset + limit]

    @staticmethod
    def _from_dict(data: Dict) -> AuditEvent:
        return AuditEvent(
            event_id=data.get("event_id", ""),
            timestamp=data.get("timestamp", ""),
            event_type=data.get("event_type", ""),
            outcome=data.get("outcome", ""),
            actor_id=data.get("actor_id", ""),
            ip_address=data.get("ip_address", ""),
            resource_type=data.get("resource_type", ""),
            resource_id=data.get("resource_id", ""),
            detail=data.get("detail", {}),
            user_agent=data.get("user_agent", ""),
        )

    # ── Export ──────────────────────────────────────────────────────

    def export_json(
        self, output_path: Path,
        days: int = 90,
        actor_id: Optional[str] = None,
    ) -> int:
        """
        Export audit events to a NDJSON file.
        Returns number of events exported.
        Used for BOU / NITA-U compliance submissions.
        """
        since = datetime.now(timezone.utc) - timedelta(days=days)
        events = self.query(since=since, actor_id=actor_id, limit=100_000)
        with output_path.open("w", encoding="utf-8") as fh:
            for ev in events:
                fh.write(json.dumps(ev.to_dict(), default=str) + "\n")
        return len(events)

    def export_csv(
        self, output_path: Path,
        days: int = 90,
    ) -> int:
        """
        Export audit events to CSV.
        Returns number of events exported.
        """
        since = datetime.now(timezone.utc) - timedelta(days=days)
        events = self.query(since=since, limit=100_000)
        with output_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(CSV_HEADERS)
            for ev in events:
                writer.writerow(ev.to_csv_row())
        return len(events)

    # ── Retention purge ─────────────────────────────────────────────

    def purge_old_shards(self, retention_days: int = 365) -> int:
        """
        Delete shard files older than retention_days.
        Returns number of files deleted.
        Safe to run in a cron job — idempotent.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        deleted = 0
        for shard in self._path.glob("audit-*.ndjson"):
            try:
                date_str = shard.stem.replace("audit-", "")
                shard_date = datetime.strptime(date_str, "%Y-%m-%d").replace(
                    tzinfo=timezone.utc
                )
                if shard_date < cutoff:
                    shard.unlink()
                    deleted += 1
            except (ValueError, OSError):
                continue
        if deleted:
            logger.info("Purged %d audit shard(s) older than %d days", deleted, retention_days)
        return deleted

    # ── Summary stats ───────────────────────────────────────────────

    def stats(self, days: int = 30) -> Dict:
        """Return summary statistics for a recent period."""
        since = datetime.now(timezone.utc) - timedelta(days=days)
        events = self.query(since=since, limit=100_000)

        by_type: Dict[str, int] = {}
        by_outcome: Dict[str, int] = {}
        by_actor: Dict[str, int] = {}

        for ev in events:
            by_type[ev.event_type]     = by_type.get(ev.event_type, 0) + 1
            by_outcome[ev.outcome]     = by_outcome.get(ev.outcome, 0) + 1
            actor_key = ev.actor_id[:8] if ev.actor_id else "anon"
            by_actor[actor_key]        = by_actor.get(actor_key, 0) + 1

        return {
            "period_days":  days,
            "total_events": len(events),
            "by_outcome":   by_outcome,
            "top_events":   sorted(by_type.items(), key=lambda x: -x[1])[:10],
            "top_actors":   sorted(by_actor.items(), key=lambda x: -x[1])[:10],
            "failure_count": by_outcome.get(OUTCOME_FAILURE, 0),
            "blocked_count": by_outcome.get(OUTCOME_BLOCKED, 0),
        }


# ── Module-level singleton factory ─────────────────────────────────

_instance: Optional[AuditLog] = None


def get_audit_log() -> AuditLog:
    """Return the module-level AuditLog singleton, creating it on first call."""
    global _instance
    if _instance is None:
        from config import get_config
        config = get_config()
        _instance = AuditLog(Path(config.storage.data_dir))
    return _instance