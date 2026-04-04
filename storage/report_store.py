"""
storage/report_store.py — Async Flat-File Report Store

Persists report metadata and generated export files (PDF, JSON, CSV, HTML).

Directory layout (under config.storage.data_dir/reports/):
  reports/
    {report_id}/
      meta.json             — Report object (status, type, scan_id, exports map)
      export.json           — JSON export bytes
      export.csv            — CSV export bytes
      export.pdf            — PDF export bytes
      export.html           — HTML export bytes
  _indexes/
    owner/{owner_id}.json   — [report_id, ...] newest-first
    scan/{scan_id}.json     — [report_id, ...]

All writes are atomic. All I/O is in asyncio.to_thread().

Public API (matches exactly what api/routes/reports.py calls):

  await store.save(report)
  await store.get(report_id)             → _DictObj | None
  await store.list(...)                  → (List[dict], int)
  await store.delete(report_id)
  await store.save_export(report_id, fmt, content: bytes) → str (path)
  await store.load_export(report_id, fmt)                 → bytes | None
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

# Export format → file extension mapping
_FMT_EXT = {
    "json": "json",
    "csv":  "csv",
    "pdf":  "pdf",
    "html": "html",
}


# ── Serialisation (shared with scan_store pattern) ─────────────────

def _serialise(obj: Any) -> Any:
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
    if hasattr(obj, "model_dump"):
        return _serialise(obj.model_dump())
    if hasattr(obj, "dict"):
        return _serialise(obj.dict())
    if hasattr(obj, "__dict__") or hasattr(obj, "__class__"):
        d = {}
        for k, v in vars(type(obj)).items():
            if not k.startswith("_") and not callable(v):
                d[k] = v
        for k, v in vars(obj).items():
            if not k.startswith("_"):
                d[k] = v
        if d:
            return {k: _serialise(v) for k, v in d.items()}
    return str(obj)


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
        logger.error("Corrupt JSON at %s: %s", path, exc)
        return None


# ── ReportStore ────────────────────────────────────────────────────

class ReportStore:
    """
    Async flat-file store for report metadata and export files.
    One instance per application; attach to app.state.report_store.
    """

    def __init__(self, data_dir: str) -> None:
        base = Path(data_dir)
        self._reports_dir  = base / "reports"
        self._owner_idx    = base / "reports" / "_indexes" / "owner"
        self._scan_idx     = base / "reports" / "_indexes" / "scan"
        for d in [self._reports_dir, self._owner_idx, self._scan_idx]:
            d.mkdir(parents=True, exist_ok=True)

    async def _run(self, fn, *args):
        return await asyncio.to_thread(fn, *args)

    # ── Report paths ────────────────────────────────────────────────

    def _report_dir(self, report_id: str) -> Path:
        return self._reports_dir / report_id

    def _meta_path(self, report_id: str) -> Path:
        return self._report_dir(report_id) / "meta.json"

    def _export_path(self, report_id: str, fmt: str) -> Path:
        ext = _FMT_EXT.get(fmt, fmt)
        return self._report_dir(report_id) / f"export.{ext}"

    # ── Save / Get ──────────────────────────────────────────────────

    async def save(self, report) -> None:
        """
        Persist a Report object. Updates indexes atomically.
        Accepts dataclass, Pydantic model, or dict.
        """
        data = _serialise(report)
        if not isinstance(data, dict):
            raise ValueError("Report must serialise to a dict")

        report_id = data.get("id") or data.get("report_id")
        if not report_id:
            raise ValueError("Report has no id / report_id field")

        owner_id = data.get("owner_id")
        scan_id  = data.get("scan_id")

        def _save():
            _write_json(self._meta_path(report_id), data)
            # Update owner index
            if owner_id:
                idx_path = self._owner_idx / f"{owner_id}.json"
                idx = _read_json(idx_path) or []
                if report_id not in idx:
                    idx.insert(0, report_id)   # newest first
                _write_json(idx_path, idx)
            # Update scan index
            if scan_id:
                idx_path = self._scan_idx / f"{scan_id}.json"
                idx = _read_json(idx_path) or []
                if report_id not in idx:
                    idx.insert(0, report_id)
                _write_json(idx_path, idx)

        await self._run(_save)
        logger.debug("Saved report %s (status=%s)", report_id[:8], data.get("status"))

    async def get(self, report_id: str) -> Optional[Any]:
        """
        Load a report by ID. Returns a dict-like object with attribute access.
        require_report_access accesses .owner_id and .status on the result.
        """
        data = await self._run(_read_json, self._meta_path(report_id))
        if data is None:
            return None
        return _DictObj(data)

    # ── List ────────────────────────────────────────────────────────

    async def list(
        self,
        owner_id:    Optional[str] = None,
        scan_id:     Optional[str] = None,
        report_type: Optional[str] = None,
        status:      Optional[str] = None,
        offset:      int = 0,
        limit:       int = 20,
    ) -> Tuple[List[Dict], int]:
        """List reports with optional filters. Returns (records, total)."""
        def _list():
            # Build candidate ID list
            if not self._reports_dir.exists():
                return [], 0
                
            if scan_id:
                candidate_ids = _read_json(
                    self._scan_idx / f"{scan_id}.json"
                ) or []
                if owner_id:
                    owner_ids = set(
                        _read_json(self._owner_idx / f"{owner_id}.json") or []
                    )
                    candidate_ids = [i for i in candidate_ids if i in owner_ids]
            elif owner_id:
                candidate_ids = _read_json(
                    self._owner_idx / f"{owner_id}.json"
                ) or []
            else:
                # All reports — scan all directories, newest first
                candidate_ids = [
                    p.name
                    for p in sorted(
                        self._reports_dir.iterdir(),
                        key=lambda p: p.stat().st_mtime if p.is_dir() else 0,
                        reverse=True,
                    )
                    if p.is_dir() and not p.name.startswith("_")
                ]

            results = []
            for rid in candidate_ids:
                meta = _read_json(self._meta_path(rid))
                if meta is None:
                    continue
                if report_type and meta.get("report_type") != report_type:
                    continue
                if status and meta.get("status") != status:
                    continue
                results.append(meta)

            total = len(results)
            return results[offset: offset + limit], total

        return await self._run(_list)

    # ── Delete ──────────────────────────────────────────────────────

    async def delete(self, report_id: str) -> bool:
        """Delete all report data including export files. Returns False if not found."""
        def _delete():
            meta = _read_json(self._meta_path(report_id))
            if meta is None:
                return False

            # Clean up indexes
            owner_id = meta.get("owner_id")
            scan_id  = meta.get("scan_id")

            if owner_id:
                idx_path = self._owner_idx / f"{owner_id}.json"
                idx      = _read_json(idx_path) or []
                _write_json(idx_path, [i for i in idx if i != report_id])

            if scan_id:
                idx_path = self._scan_idx / f"{scan_id}.json"
                idx      = _read_json(idx_path) or []
                _write_json(idx_path, [i for i in idx if i != report_id])

            # Remove report directory (meta + all exports)
            rdir = self._report_dir(report_id)
            if rdir.exists():
                shutil.rmtree(str(rdir), ignore_errors=True)
            return True

        result = await self._run(_delete)
        if result:
            logger.info("Deleted report %s", report_id[:8])
        return result

    # ── Export file store / retrieve ────────────────────────────────

    async def save_export(
        self,
        report_id: str,
        fmt:       str,
        content:   bytes,
    ) -> str:
        """
        Persist a generated export file.
        Returns the relative path string (stored in report.exports dict).
        """
        path = self._export_path(report_id, fmt)

        def _save():
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            try:
                tmp.write_bytes(content)
                os.replace(tmp, path)
            except Exception:
                tmp.unlink(missing_ok=True)
                raise

        await self._run(_save)
        logger.debug(
            "Saved %s export for report %s (%d bytes)",
            fmt, report_id[:8], len(content),
        )
        return str(path)

    async def load_export(self, report_id: str, fmt: str) -> Optional[bytes]:
        """Load a previously saved export file. Returns None if not found."""
        path = self._export_path(report_id, fmt)

        def _load():
            try:
                return path.read_bytes()
            except FileNotFoundError:
                return None

        return await self._run(_load)

    async def export_exists(self, report_id: str, fmt: str) -> bool:
        """Check whether an export file exists without reading it."""
        path = self._export_path(report_id, fmt)
        return await self._run(lambda p: p.exists(), path)

    # ── Maintenance ─────────────────────────────────────────────────

    async def purge_old_reports(self, keep_days: int = 180) -> int:
        """Delete reports older than keep_days. Returns count deleted."""
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=keep_days)

        def _purge():
            if not self._reports_dir.exists():
                return 0
            count = 0
            for rdir in self._reports_dir.iterdir():
                if not rdir.is_dir() or rdir.name.startswith("_"):
                    continue
                meta = _read_json(rdir / "meta.json")
                if meta is None:
                    shutil.rmtree(str(rdir), ignore_errors=True)
                    count += 1
                    continue
                created_str = meta.get("created_at", "")
                if not created_str:
                    continue
                try:
                    created = datetime.fromisoformat(created_str)
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)
                    if created < cutoff:
                        shutil.rmtree(str(rdir), ignore_errors=True)
                        count += 1
                except ValueError:
                    continue
            return count

        n = await self._run(_purge)
        if n:
            logger.info("Purged %d old reports", n)
        return n

    async def disk_usage(self) -> Dict:
        """Return storage statistics for the admin dashboard."""
        def _usage():
            if not self._reports_dir.exists():
                return {"report_count": 0, "total_bytes": 0, "total_mb": 0, "export_counts": {}}
                
            total_bytes    = 0
            report_count   = 0
            export_counts: Dict[str, int] = {}

            for rdir in self._reports_dir.iterdir():
                if not rdir.is_dir() or rdir.name.startswith("_"):
                    continue
                report_count += 1
                for f in rdir.iterdir():
                    total_bytes += f.stat().st_size
                    if f.name.startswith("export."):
                        ext = f.suffix.lstrip(".")
                        export_counts[ext] = export_counts.get(ext, 0) + 1

            return {
                "report_count":  report_count,
                "total_bytes":   total_bytes,
                "total_mb":      round(total_bytes / 1_048_576, 2),
                "export_counts": export_counts,
            }

        return await self._run(_usage)


# ── Dict with attribute access ─────────────────────────────────────

class _DictObj:
    """Wraps a dict so attributes work as obj.field."""
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
        report_id = self._data.get("id", "?")
        status    = self._data.get("status", "?")
        return f"<Report id={report_id[:8]} status={status}>"


# ── Module-level singleton ─────────────────────────────────────────

_instance: Optional[ReportStore] = None


def get_report_store() -> ReportStore:
    """Return the process-wide ReportStore singleton."""
    global _instance
    if _instance is None:
        raise RuntimeError("ReportStore not initialised. Call init_report_store(data_dir) first.")
    return _instance


def init_report_store(data_dir: str | Path) -> ReportStore:
    """Create (or replace) the global ReportStore and return it."""
    global _instance
    _instance = ReportStore(str(data_dir))
    logger.info("report_store: initialised at %s", data_dir)
    return _instance


def get_report_store_instance() -> ReportStore:
    """Return the module-level ReportStore singleton (auto-init if needed)."""
    global _instance
    if _instance is None:
        from config import get_config
        config    = get_config()
        _instance = ReportStore(config.storage.data_dir)
    return _instance