"""
auth/session.py — Session and Token Store

Flat-file backed persistent storage for all auth state:
  - User records (email, password_hash, role, TOTP secret)
  - Refresh tokens (SHA-256 hash → user_id + expiry)
  - Password reset tokens (hash → user_id + expiry)
  - Session counters (rate limit, login failure tracking)
  - API keys (SHA-256 hash → user_id + metadata)

Storage layout (all under config.storage.data_dir/sessions/):
  sessions/
    users/
      {user_id}.json          — full user record
      email_index.json        — {email: user_id} lookup
    tokens/
      refresh/
        {hash_prefix}/{hash}.json
      reset/
        {hash_prefix}/{hash}.json
    api_keys/
      by_hash/
        {hash_prefix}/{key_hash}.json
      by_id/
        {key_id}.json         — metadata only (no hash)
      user_index/
        {user_id}.json        — [key_id, ...] for list operations
    counters/
      {key}.json              — {value, window_start, window_seconds}

Design decisions:
  - Two-level directory sharding (first 2 chars of hash as prefix dir)
    prevents directory inode exhaustion on large deployments
  - email_index.json is updated atomically (write-then-rename)
    to prevent partial-read corruption on concurrent writes
  - All JSON files are written atomically via a temp file + rename
  - All async methods are truly async (use asyncio.to_thread for
    blocking file I/O so the FastAPI event loop is not blocked)
  - Counters use a sliding window: if now > window_start + window_seconds,
    the counter resets before incrementing
  - No in-memory caching of user records — this is a flat-file store,
    not a high-throughput database. For production scale, swap this
    class for a Redis/Postgres-backed implementation with the same API.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Atomic file write helper ───────────────────────────────────────

def _write_json(path: Path, data: Any) -> None:
    """
    Write JSON to a file atomically using write-to-temp + rename.
    The rename is atomic on POSIX systems, so readers never see
    a partial write.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_text(
            json.dumps(data, indent=2, default=str),
            encoding="utf-8",
        )
        os.replace(tmp, path)  # atomic on POSIX
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


def _read_json(path: Path) -> Optional[Any]:
    """Read JSON from a file. Returns None if the file does not exist."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as exc:
        logger.error("Corrupt JSON at %s: %s", path, exc)
        return None


def _shard_prefix(key: str) -> str:
    """Return the 2-char directory prefix for a hash key."""
    return key[:2] if len(key) >= 2 else "00"


# ── SessionStore ───────────────────────────────────────────────────

class SessionStore:
    """
    Async flat-file store for all auth session state.
    All blocking file I/O runs in asyncio.to_thread() so the
    FastAPI event loop is never blocked.
    """

    def __init__(self, storage_config) -> None:
        base = Path(storage_config.data_dir) / "sessions"
        self._users_dir      = base / "users"
        self._email_idx      = base / "users" / "email_index.json"
        self._refresh_dir    = base / "tokens" / "refresh"
        self._reset_dir      = base / "tokens" / "reset"
        self._api_key_hash   = base / "api_keys" / "by_hash"
        self._api_key_id     = base / "api_keys" / "by_id"
        self._api_key_user   = base / "api_keys" / "user_index"
        self._counters_dir   = base / "counters"

        # Create directory skeleton synchronously at construction
        for d in [
            self._users_dir, self._refresh_dir, self._reset_dir,
            self._api_key_hash, self._api_key_id,
            self._api_key_user, self._counters_dir,
        ]:
            d.mkdir(parents=True, exist_ok=True)

    # ── Internal thread-pool wrapper ────────────────────────────────

    async def _run(self, fn, *args):
        """Run a blocking function in the default thread pool."""
        return await asyncio.to_thread(fn, *args)

    # ── User records ────────────────────────────────────────────────

    async def create_user(self, record: Dict) -> None:
        """
        Persist a new user record and update the email index.
        Raises ValueError if the user_id already exists.
        """
        user_id = record["user_id"]
        path    = self._users_dir / f"{user_id}.json"

        def _write():
            if path.exists():
                raise ValueError(f"User {user_id} already exists")
            _write_json(path, record)
            # Update email index atomically
            idx = _read_json(self._email_idx) or {}
            idx[record["email"].lower()] = user_id
            _write_json(self._email_idx, idx)

        await self._run(_write)
        logger.debug("User created: %s", user_id[:8])

    async def get_user(self, user_id: str) -> Optional[Dict]:
        """Load a user record by user_id."""
        path = self._users_dir / f"{user_id}.json"
        return await self._run(_read_json, path)

    async def get_user_by_email(self, email: str) -> Optional[Dict]:
        """Load a user record by email address (case-insensitive)."""
        def _lookup():
            idx = _read_json(self._email_idx) or {}
            uid = idx.get(email.lower())
            if not uid:
                return None
            return _read_json(self._users_dir / f"{uid}.json")
        return await self._run(_lookup)

    async def update_user(self, user_id: str, updates: Dict) -> bool:
        """
        Apply a partial update to a user record.
        Returns False if the user does not exist.
        """
        path = self._users_dir / f"{user_id}.json"

        def _update():
            record = _read_json(path)
            if record is None:
                return False
            # Handle email change — update index
            if "email" in updates and updates["email"] != record.get("email"):
                idx = _read_json(self._email_idx) or {}
                old_email = record.get("email", "").lower()
                if old_email in idx:
                    del idx[old_email]
                idx[updates["email"].lower()] = user_id
                _write_json(self._email_idx, idx)
            record.update(updates)
            _write_json(path, record)
            return True

        return await self._run(_update)

    async def delete_user(self, user_id: str) -> bool:
        """Delete a user record and remove from email index."""
        path = self._users_dir / f"{user_id}.json"

        def _delete():
            record = _read_json(path)
            if record is None:
                return False
            # Remove from email index
            idx = _read_json(self._email_idx) or {}
            email = record.get("email", "").lower()
            if email in idx:
                del idx[email]
                _write_json(self._email_idx, idx)
            path.unlink(missing_ok=True)
            return True

        return await self._run(_delete)

    async def list_users(
        self,
        offset: int = 0,
        limit: int = 50,
        role: Optional[str] = None,
    ) -> tuple[List[Dict], int]:
        """List all users. Returns (records, total_count)."""
        def _list():
            records = []
            for p in sorted(self._users_dir.glob("*.json")):
                if p.name == "email_index.json":
                    continue
                r = _read_json(p)
                if r is None:
                    continue
                if role and r.get("role") != role:
                    continue
                # Never include password hash in list results
                r = {k: v for k, v in r.items() if k != "password_hash"}
                records.append(r)
            total = len(records)
            return records[offset: offset + limit], total

        return await self._run(_list)

    # ── Refresh tokens ──────────────────────────────────────────────

    async def store_refresh_token(
        self, token_hash: str, user_id: str, expires_at: str
    ) -> None:
        """Store a refresh token record."""
        prefix = _shard_prefix(token_hash)
        path   = self._refresh_dir / prefix / f"{token_hash}.json"
        await self._run(_write_json, path, {
            "token_hash": token_hash,
            "user_id":    user_id,
            "expires_at": expires_at,
            "created_at": _now_iso(),
        })

    async def get_refresh_token(self, token_hash: str) -> Optional[Dict]:
        """Look up a refresh token by its hash."""
        prefix = _shard_prefix(token_hash)
        path   = self._refresh_dir / prefix / f"{token_hash}.json"
        return await self._run(_read_json, path)

    async def delete_refresh_token(self, token_hash: str) -> None:
        """Invalidate a refresh token (logout / rotation)."""
        prefix = _shard_prefix(token_hash)
        path   = self._refresh_dir / prefix / f"{token_hash}.json"
        await self._run(lambda p: p.unlink(missing_ok=True), path)

    async def purge_expired_refresh_tokens(self) -> int:
        """Delete all expired refresh token files. Returns count deleted."""
        def _purge():
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc)
            count = 0
            for path in self._refresh_dir.rglob("*.json"):
                record = _read_json(path)
                if record is None:
                    path.unlink(missing_ok=True)
                    count += 1
                    continue
                try:
                    exp = datetime.fromisoformat(record["expires_at"])
                    if now > exp:
                        path.unlink(missing_ok=True)
                        count += 1
                except (KeyError, ValueError):
                    path.unlink(missing_ok=True)
                    count += 1
            return count

        n = await self._run(_purge)
        if n:
            logger.info("Purged %d expired refresh tokens", n)
        return n

    # ── Password reset tokens ───────────────────────────────────────

    async def store_reset_token(
        self, token_hash: str, user_id: str, expires_at: str
    ) -> None:
        prefix = _shard_prefix(token_hash)
        path   = self._reset_dir / prefix / f"{token_hash}.json"
        await self._run(_write_json, path, {
            "token_hash": token_hash,
            "user_id":    user_id,
            "expires_at": expires_at,
            "created_at": _now_iso(),
        })

    async def get_reset_token(self, token_hash: str) -> Optional[Dict]:
        prefix = _shard_prefix(token_hash)
        path   = self._reset_dir / prefix / f"{token_hash}.json"
        return await self._run(_read_json, path)

    async def delete_reset_token(self, token_hash: str) -> None:
        prefix = _shard_prefix(token_hash)
        path   = self._reset_dir / prefix / f"{token_hash}.json"
        await self._run(lambda p: p.unlink(missing_ok=True), path)

    # ── API keys ────────────────────────────────────────────────────

    async def store_api_key(self, record: Dict) -> None:
        """
        Store an API key record.
        record must include: key_id, key_hash, user_id, role, scopes, name.
        """
        key_hash = record["key_hash"]
        key_id   = record["key_id"]
        user_id  = record["user_id"]

        def _store():
            # By-hash lookup (for authentication)
            prefix = _shard_prefix(key_hash)
            _write_json(
                self._api_key_hash / prefix / f"{key_hash}.json",
                record,
            )
            # By-ID lookup (for revocation / display)
            safe_meta = {k: v for k, v in record.items() if k != "key_hash"}
            _write_json(self._api_key_id / f"{key_id}.json", safe_meta)
            # User index (for list operations)
            idx_path = self._api_key_user / f"{user_id}.json"
            idx = _read_json(idx_path) or []
            if key_id not in idx:
                idx.append(key_id)
            _write_json(idx_path, idx)

        await self._run(_store)

    async def get_api_key(self, key_hash: str) -> Optional[Dict]:
        """Look up an API key by SHA-256 hash. Returns full record or None."""
        prefix = _shard_prefix(key_hash)
        path   = self._api_key_hash / prefix / f"{key_hash}.json"
        return await self._run(_read_json, path)

    async def get_api_key_by_id(self, key_id: str) -> Optional[Dict]:
        """Look up API key metadata by key_id (no hash returned)."""
        path = self._api_key_id / f"{key_id}.json"
        return await self._run(_read_json, path)

    async def list_api_keys(self, user_id: str) -> List[Dict]:
        """Return metadata for all API keys belonging to a user."""
        def _list():
            idx_path = self._api_key_user / f"{user_id}.json"
            key_ids  = _read_json(idx_path) or []
            keys = []
            for kid in key_ids:
                meta = _read_json(self._api_key_id / f"{kid}.json")
                if meta:
                    keys.append(meta)
            return keys

        return await self._run(_list)

    async def delete_api_key(self, key_id: str) -> bool:
        """Revoke an API key. Removes hash lookup, ID record, and user index entry."""
        def _delete():
            meta = _read_json(self._api_key_id / f"{key_id}.json")
            if meta is None:
                return False

            # We need the hash to remove the by-hash entry.
            # The hash is NOT in the by-id record (by design) so we must
            # scan the by-hash directory. This is O(n) but revocation is rare.
            for prefix_dir in self._api_key_hash.iterdir():
                for p in prefix_dir.glob("*.json"):
                    rec = _read_json(p)
                    if rec and rec.get("key_id") == key_id:
                        p.unlink(missing_ok=True)
                        break

            # Remove by-ID record
            (self._api_key_id / f"{key_id}.json").unlink(missing_ok=True)

            # Remove from user index
            user_id  = meta.get("user_id", "")
            idx_path = self._api_key_user / f"{user_id}.json"
            idx      = _read_json(idx_path) or []
            updated  = [k for k in idx if k != key_id]
            _write_json(idx_path, updated)
            return True

        return await self._run(_delete)

    # ── Generic key-value store (for small ephemeral values) ────────
    # Used for: TOTP pending secrets, login failure counters,
    #           lockout flags, TOTP replay codes

    async def set_value(self, key: str, value: str, ttl_seconds: int = 0) -> None:
        """Store a string value under an arbitrary key."""
        safe_key = _safe_filename(key)
        path     = self._counters_dir / f"{safe_key}.json"
        record   = {
            "key":        key,
            "value":      value,
            "expires_at": (time.time() + ttl_seconds) if ttl_seconds else 0,
        }
        await self._run(_write_json, path, record)

    async def get_value(self, key: str) -> Optional[str]:
        """Retrieve a string value. Returns None if not found or expired."""
        safe_key = _safe_filename(key)
        path     = self._counters_dir / f"{safe_key}.json"

        def _read():
            record = _read_json(path)
            if record is None:
                return None
            expires_at = record.get("expires_at", 0)
            if expires_at and time.time() > expires_at:
                path.unlink(missing_ok=True)
                return None
            return record.get("value")

        return await self._run(_read)

    async def delete_value(self, key: str) -> None:
        """Delete a key-value entry."""
        safe_key = _safe_filename(key)
        path     = self._counters_dir / f"{safe_key}.json"
        await self._run(lambda p: p.unlink(missing_ok=True), path)

    # ── Sliding window counters ─────────────────────────────────────

    async def increment_counter(
        self, key: str, window_seconds: int = 3600
    ) -> int:
        """
        Increment a sliding-window counter. Returns the new count.
        If the window has expired, the counter resets to 1.

        Used for:
          - Login failure tracking (key: login:fails:{email})
          - Hourly scan rate limits (key: scan_count:hourly:{user_id})
          - Daily scan quotas     (key: scan_count:daily:{user_id})
        """
        safe_key = _safe_filename(key)
        path     = self._counters_dir / f"{safe_key}.json"

        def _increment():
            now    = time.time()
            record = _read_json(path)

            if record is None or now > record.get("window_start", 0) + window_seconds:
                # New window — start fresh
                new_record = {
                    "key":            key,
                    "value":          1,
                    "window_start":   now,
                    "window_seconds": window_seconds,
                }
            else:
                new_record = {
                    "key":            key,
                    "value":          record["value"] + 1,
                    "window_start":   record["window_start"],
                    "window_seconds": window_seconds,
                }

            _write_json(path, new_record)
            return new_record["value"]

        return await self._run(_increment)

    async def get_counter(
        self, key: str, window_seconds: int = 3600
    ) -> int:
        """
        Return the current sliding-window counter value without incrementing.
        Returns 0 if the key does not exist or the window has expired.
        """
        safe_key = _safe_filename(key)
        path     = self._counters_dir / f"{safe_key}.json"

        def _read():
            now    = time.time()
            record = _read_json(path)
            if record is None:
                return 0
            if now > record.get("window_start", 0) + window_seconds:
                return 0
            return record.get("value", 0)

        return await self._run(_read)

    async def reset_counter(self, key: str) -> None:
        """Reset a counter (e.g., after successful login)."""
        await self.delete_value(key)

    # ── Maintenance ─────────────────────────────────────────────────

    async def purge_expired_counters(self) -> int:
        """Remove expired counter/kv files. Returns count deleted."""
        def _purge():
            now   = time.time()
            count = 0
            for path in self._counters_dir.glob("*.json"):
                record = _read_json(path)
                if record is None:
                    path.unlink(missing_ok=True)
                    count += 1
                    continue
                expires_at   = record.get("expires_at", 0)
                window_start = record.get("window_start", 0)
                window_s     = record.get("window_seconds", 0)
                if expires_at and now > expires_at:
                    path.unlink(missing_ok=True)
                    count += 1
                elif window_s and now > window_start + window_s:
                    path.unlink(missing_ok=True)
                    count += 1
            return count

        n = await self._run(_purge)
        if n:
            logger.debug("Purged %d expired counter/kv files", n)
        return n


# ── Utilities ──────────────────────────────────────────────────────

def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _safe_filename(key: str) -> str:
    """
    Convert an arbitrary key string to a safe filename.
    Replaces characters that are unsafe in file names with underscores.
    Example: "login:fails:user@example.com" → "login_fails_user_example_com"
    """
    import re
    return re.sub(r"[^\w\-]", "_", key)[:128]