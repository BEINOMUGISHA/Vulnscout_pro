"""
storage/scan_store.py — Async Flat-File Scan Store

Persists all scan lifecycle data to the filesystem.
No database. No SQLite. Pure JSON files, atomic writes.

Directory layout (under config.storage.data_dir/scans/):
  scans/
    {scan_id}/
      summary.json          — Scan object (status, metrics, config, timestamps)
      findings.json         — List[Finding] serialised
      events.json           — List[ScanEvent] serialised
  targets/
    {target_id}.json        — Target definition
    owner_index/
      {owner_id}.json       — [target_id, ...] for list operations

All writes are atomic: write to .tmp then os.replace().
All I/O runs in asyncio.to_thread() — the event loop is never blocked.

Public API (matches exactly what api/routes/scans.py + targets.py call):

  await store.save_summary(scan)
  await store.get(scan_id)             → Scan | None
  await store.get_summary(scan_id)     → dict | None  (same as get, returns dict)
  await store.save_findings(scan)
  await store.load_findings(scan_id)   → List[Finding]
  await store.save_events(scan)
  await store.load_events(scan_id)     → List[ScanEvent]
  await store.list_scans(...)          → (List[dict], int)
  await store.delete_scan(scan_id)
  await store.save_target(target_dict)
  await store.get_target(target_id)    → dict | None
  await store.list_targets(...)        → (List[dict], int)
  await store.delete_target(target_id)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ── Serialisation helpers ──────────────────────────────────────────

def _serialise(obj: Any) -> Any:
    """Recursively serialise an object to a JSON-safe structure."""
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, (list, tuple)):
        return [_serialise(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _serialise(v) for k, v in obj.items()}
    if is_dataclass(obj):
        return {k: _serialise(v) for k, v in asdict(obj).items()}
    # Pydantic v1 / v2
    if hasattr(obj, "model_dump"):
        return _serialise(obj.model_dump())
    if hasattr(obj, "dict"):
        return _serialise(obj.dict())
    # Handle objects where attrs live in instance dict OR class dict
    # (covers dataclass instances, simple namespaces, test stubs)
    if hasattr(obj, "__dict__") or hasattr(obj, "__class__"):
        d = {}
        # Class-level attributes first (for type('X', (), {...})() pattern)
        for k, v in vars(type(obj)).items():
            if not k.startswith("_") and not callable(v):
                d[k] = v
        # Instance attributes override class-level
        for k, v in vars(obj).items():
            if not k.startswith("_"):
                d[k] = v
        if d:
            return {k: _serialise(v) for k, v in d.items()}
    return str(obj)


# ── Atomic file helpers ────────────────────────────────────────────

def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_text(
            json.dumps(_serialise(data), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        os.replace(tmp, path)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


def _read_json(path: Path) -> Optional[Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as exc:
        logger.error("Corrupt JSON at %s: %s — file will be ignored", path, exc)
        return None


# ── ScanStore ──────────────────────────────────────────────────────

class ScanStore:
    """
    Async flat-file store for scan summaries, findings, events, and targets.
    One instance per application; attach to app.state.scan_store in lifespan.
    """

    def __init__(self, data_dir: str) -> None:
        base = Path(data_dir)
        self._scans_dir   = base / "scans"
        self._targets_dir = base / "targets"
        self._owner_idx   = base / "targets" / "owner_index"
        self._lock        = asyncio.Lock() # Prevent concurrent writes to same files
        # Ensure directories exist synchronously at construction
        for d in [self._scans_dir, self._targets_dir, self._owner_idx]:
            d.mkdir(parents=True, exist_ok=True)

    @property
    def _root(self) -> Path:
        """Compatibility property for legacy routes."""
        return self._scans_dir.parent

    # ── Thread-pool wrapper ─────────────────────────────────────────

    async def _run(self, fn, *args):
        return await asyncio.to_thread(fn, *args)

    async def _load_json(self, path: Path) -> Optional[Any]:
        """Compatibility method for legacy routes."""
        return await self._run(_read_json, path)

    @staticmethod
    def _atomic_write(path: Path, data: Any) -> None:
        """Compatibility method for legacy routes."""
        _write_json(path, data)

    # ── Scan summary ────────────────────────────────────────────────

    def _scan_dir(self, scan_id: str) -> Path:
        return self._scans_dir / scan_id

    def _summary_path(self, scan_id: str) -> Path:
        return self._scan_dir(scan_id) / "summary.json"

    async def save_summary(self, scan) -> None:
        """Persist a Scan object's summary to disk."""
        scan_id = getattr(scan, "id", None) or getattr(scan, "scan_id", None)
        if not scan_id:
            raise ValueError("Scan has no id field")
        path = self._summary_path(scan_id)
        # ── REMOVED LOCK ── 
        # Writing to summary.json is atomic via os.replace in _write_json.
        # Removing the lock prevents slow serialisation from blocking the entire UI.
        await self._run(_write_json, path, scan)
        logger.debug("Saved scan summary %s", scan_id[:8])

    async def get(self, scan_id: str) -> Optional[Any]:
        """
        Load a scan by ID. Returns a dict-like object with attribute access.
        The dependency layer calls this and accesses .owner_id on the result.
        """
        path = self._summary_path(scan_id)
        data = await self._run(_read_json, path)
        if data is None:
            return None
        return _DictObj(data)

    async def get_summary(self, scan_id: str) -> Optional[Dict]:
        """Load scan summary as a plain dict (used by reports route)."""
        path = self._summary_path(scan_id)
        return await self._run(_read_json, path)

    # ── Findings ────────────────────────────────────────────────────

    def _findings_path(self, scan_id: str) -> Path:
        return self._scan_dir(scan_id) / "findings.json"

    async def save_findings(self, scan) -> None:
        """Persist all findings from a Scan object to disk."""
        scan_id  = getattr(scan, "id", None) or getattr(scan, "scan_id", None)
        findings = getattr(scan, "findings", []) or []
        path     = self._findings_path(scan_id)
        # Atomicity provided by _write_json's os.replace
        await self._run(_write_json, path, findings)
        logger.debug("Saved %d findings for scan %s", len(findings), scan_id[:8])

    async def load_findings(self, scan_id: str) -> List[Dict]:
        """
        Load findings list for a scan.
        Returns a list of dicts — the routes iterate and filter these.
        """
        path = self._findings_path(scan_id)
        async with self._lock:
            data = await self._run(_read_json, path)
        if data is None:
            return []
        return data if isinstance(data, list) else []

    # ── Events ──────────────────────────────────────────────────────

    def _events_path(self, scan_id: str) -> Path:
        return self._scan_dir(scan_id) / "events.json"

    async def save_events(self, scan) -> None:
        """Persist scan events (phase changes, log lines) to disk."""
        scan_id = getattr(scan, "id", None) or getattr(scan, "scan_id", None)
        events  = getattr(scan, "events", []) or []
        path    = self._events_path(scan_id)
        await self._run(_write_json, path, events)

    async def load_events(self, scan_id: str) -> List[Dict]:
        """Load the scan event log."""
        path = self._events_path(scan_id)
        data = await self._run(_read_json, path)
        if data is None:
            return []
        return data if isinstance(data, list) else []

    # ── Scan list ───────────────────────────────────────────────────

    async def list_scans(
        self,
        owner_id:   Optional[str] = None,
        status:     Optional[str] = None,
        target_url: Optional[str] = None,
        offset:     int = 0,
        limit:      int = 20,
    ) -> Tuple[List[Dict], int]:
        """
        List scans with optional filters.
        Returns (list_of_summary_dicts, total_count).
        Most-recent-first ordering.
        """
        def _list():
            if not self._scans_dir.exists():
                return [], 0
            results = []
            for scan_dir in sorted(
                self._scans_dir.iterdir(),
                key=lambda p: p.stat().st_mtime if p.is_dir() else 0,
                reverse=True,
            ):
                if not scan_dir.is_dir():
                    continue
                summary = _read_json(scan_dir / "summary.json")
                if summary is None:
                    continue

                # Apply filters
                if owner_id and summary.get("owner_id") != owner_id:
                    continue
                if status and summary.get("status") != status:
                    continue
                if target_url:
                    t = summary.get("target", {})
                    url = t.get("url", "") if isinstance(t, dict) else str(t)
                    if target_url.lower() not in url.lower():
                        continue

                results.append(summary)

            total = len(results)
            return results[offset: offset + limit], total

        return await self._run(_list)

    # ── Delete ──────────────────────────────────────────────────────

    async def delete_scan(self, scan_id: str) -> None:
        """Remove all scan data: summary, findings, and events."""
        scan_dir = self._scan_dir(scan_id)
        def _delete():
            if scan_dir.exists():
                shutil.rmtree(str(scan_dir), ignore_errors=True)
        await self._run(_delete)
        logger.info("Deleted scan %s", scan_id[:8])

    # ── Targets ─────────────────────────────────────────────────────

    def _target_path(self, target_id: str) -> Path:
        return self._targets_dir / f"{target_id}.json"

    def _owner_index_path(self, owner_id: str) -> Path:
        return self._owner_idx / f"{owner_id}.json"

    async def save_target(self, target) -> None:
        """Persist a target definition. Accepts dict or object."""
        data = _serialise(target)
        if not isinstance(data, dict):
            raise ValueError("Target must serialise to a dict")
        target_id = data.get("target_id") or data.get("id")
        if not target_id:
            raise ValueError("Target has no target_id / id field")
        owner_id  = data.get("owner_id")

        def _save():
            _write_json(self._target_path(target_id), data)
            if owner_id:
                idx_path = self._owner_index_path(owner_id)
                idx = _read_json(idx_path) or []
                if target_id not in idx:
                    idx.append(target_id)
                _write_json(idx_path, idx)

        await self._run(_save)

    async def get_target(self, target_id: str) -> Optional[Dict]:
        """Load a target by ID."""
        data = await self._run(_read_json, self._target_path(target_id))
        if data and "target_id" not in data and "id" in data:
            data["target_id"] = data["id"]
        return data

    async def list_targets(
        self,
        owner_id: Optional[str] = None,
        search: Optional[str] = None,
        industry: Optional[str] = None,
        offset: int = 0,
        limit: int = 20,
    ) -> Tuple[List[Dict], int]:
        """List targets, most recently created first, optionally filtered."""
        def _list():
            if not self._targets_dir.exists():
                return [], 0
            if owner_id:
                idx  = _read_json(self._owner_index_path(owner_id)) or []
                recs = []
                for tid in reversed(idx):
                    t = _read_json(self._target_path(tid))
                    if t:
                        if "target_id" not in t and "id" in t:
                            t["target_id"] = t["id"]
                        recs.append(t)
            else:
                recs = []
                for p in sorted(
                    self._targets_dir.glob("*.json"),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                ):
                    if p.parent == self._owner_idx:
                        continue
                    t = _read_json(p)
                    if t:
                        if "target_id" not in t and "id" in t:
                            t["target_id"] = t["id"]
                        recs.append(t)

            # Apply filters
            filtered = []
            search_lower = search.lower() if search else None
            for rec in recs:
                if industry and rec.get("industry") != industry:
                    continue
                if search_lower:
                    name = rec.get("name", "").lower()
                    url = rec.get("url", "").lower()
                    if search_lower not in name and search_lower not in url:
                        continue
                filtered.append(rec)

            total = len(filtered)
            return filtered[offset: offset + limit], total

        return await self._run(_list)

    async def delete_target(self, target_id: str) -> bool:
        """Delete a target and remove from owner index."""
        def _delete():
            path = self._target_path(target_id)
            data = _read_json(path)
            if data is None:
                return False
            # Remove from owner index
            owner_id = data.get("owner_id")
            if owner_id:
                idx_path = self._owner_index_path(owner_id)
                idx = _read_json(idx_path) or []
                updated = [t for t in idx if t != target_id]
                _write_json(idx_path, updated)
            path.unlink(missing_ok=True)
            return True

        return await self._run(_delete)

    # ── Webhooks (legacy support) ───────────────────────────────────

    def _webhooks_path(self) -> Path:
        return self._root / "webhooks.json"

    async def list_webhooks(self) -> List[Dict]:
        """Load all webhooks from global config file."""
        data = await self._run(_read_json, self._webhooks_path())
        return data if isinstance(data, list) else []

    async def save_webhooks(self, webhooks: List[Dict]) -> None:
        """Save all webhooks to global config file."""
        await self._run(_write_json, self._webhooks_path(), webhooks)

    # ── Maintenance ─────────────────────────────────────────────────

    async def purge_old_scans(self, keep_days: int = 90) -> int:
        """Delete scan directories older than keep_days. Returns count deleted."""
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=keep_days)

        def _purge():
            if not self._scans_dir.exists():
                return 0
            count = 0
            for scan_dir in self._scans_dir.iterdir():
                if not scan_dir.is_dir():
                    continue
                summary = _read_json(scan_dir / "summary.json")
                if summary is None:
                    shutil.rmtree(str(scan_dir), ignore_errors=True)
                    count += 1
                    continue
                created_str = summary.get("created_at") or summary.get("started_at", "")
                if not created_str:
                    continue
                try:
                    created = datetime.fromisoformat(created_str)
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)
                    if created < cutoff:
                        shutil.rmtree(str(scan_dir), ignore_errors=True)
                        count += 1
                except ValueError:
                    continue
            return count

        n = await self._run(_purge)
        if n:
            logger.info("Purged %d old scan directories", n)
        return n

    async def stats(self) -> Dict:
        """Return quick summary statistics for the dashboard."""
        def _stats():
            if not self._scans_dir.exists():
                return {"total_scans": 0, "status_counts": {}, "total_findings": 0, "critical_count": 0}
            status_counts: Dict[str, int] = {}
            total_findings = 0
            critical_count = 0

            for scan_dir in self._scans_dir.iterdir():
                if not scan_dir.is_dir():
                    continue
                summary = _read_json(scan_dir / "summary.json")
                if not summary:
                    continue
                s = summary.get("status", "unknown")
                status_counts[s] = status_counts.get(s, 0) + 1

                metrics = summary.get("metrics") or {}
                total_findings += metrics.get("total_findings", 0)
                critical_count += metrics.get("critical_count", 0)

            return {
                "total_scans":    sum(status_counts.values()),
                "status_counts":  status_counts,
                "total_findings": total_findings,
                "critical_count": critical_count,
            }

        return await self._run(_stats)


# ── Dict with attribute access ─────────────────────────────────────

class _DictObj:
    """
    Wraps a dict so attributes can be accessed as obj.field.
    Used so require_scan_access can call scan.owner_id without
    the store needing to reconstruct full Scan dataclasses.
    """
    def __init__(self, data: Dict) -> None:
        self._data = data

    def __getattr__(self, name: str):
        try:
            return self._data[name]
        except KeyError:
            raise AttributeError(name)

    def get(self, key, default=None):
        return self._data.get(key, default)

    def __getitem__(self, key):
        return self._data[key]

    def __contains__(self, key):
        return key in self._data

    def __repr__(self):
        scan_id = self._data.get("id", "?")
        status  = self._data.get("status", "?")
        return f"<Scan id={scan_id[:8]} status={status}>"


# ── Module-level singleton ─────────────────────────────────────────

_instance: Optional[ScanStore] = None


def get_scan_store() -> ScanStore:
    """Return the process-wide ScanStore singleton."""
    global _instance
    if _instance is None:
        raise RuntimeError("ScanStore not initialised. Call init_scan_store(data_dir) first.")
    return _instance


def init_scan_store(data_dir: str | Path) -> ScanStore:
    """Create (or replace) the global ScanStore and return it."""
    global _instance
    _instance = ScanStore(str(data_dir))
    logger.info("scan_store: initialised at %s", data_dir)
    return _instance


def get_scan_store_instance() -> ScanStore:
    """Return the module-level ScanStore singleton (auto-init if needed)."""
    global _instance
    if _instance is None:
        from config import get_config
        config    = get_config()
        _instance = ScanStore(config.storage.data_dir)
    return _instance