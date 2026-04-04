import json
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import asyncio
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _atomic_write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

def _load_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None

# ── SessionStore ──────────────────────────────────────────────────────────────

class SessionStore:
    """
    Async flat-file storage for users, tokens, API keys, and transient KV data.
    """
    def __init__(self, data_dir: str | Path) -> None:
        self._root = Path(data_dir)
        self._users_dir = self._root / "users"
        self._tokens_dir = self._root / "tokens"
        self._keys_dir = self._root / "api_keys"
        self._kv_dir = self._root / "kv"
        self._counters_dir = self._root / "counters"
        
        for d in [self._users_dir, self._tokens_dir, self._keys_dir, self._kv_dir, self._counters_dir]:
            d.mkdir(parents=True, exist_ok=True)
            
        self._email_index_path = self._users_dir / "_index_email.json"
        self._lock = asyncio.Lock()

    # ── Key-Value / Lockout / Rate Limiting ───────────────────────────────────

    async def get_value(self, key: str) -> Optional[str]:
        path = self._kv_dir / f"{self._safe_key(key)}.json"
        data = await asyncio.to_thread(_load_json, path)
        if not data:
            return None
        
        # Check TTL
        if "expires_at" in data:
            if time.time() > data["expires_at"]:
                await self.delete_value(key)
                return None
        return data.get("value")

    async def set_value(self, key: str, value: str, ttl_seconds: Optional[int] = None) -> None:
        path = self._kv_dir / f"{self._safe_key(key)}.json"
        data: Dict[str, Any] = {"value": value}
        if ttl_seconds:
            data["expires_at"] = time.time() + ttl_seconds
        await asyncio.to_thread(_atomic_write_json, path, data)

    async def delete_value(self, key: str) -> None:
        path = self._kv_dir / f"{self._safe_key(key)}.json"
        if path.exists():
            await asyncio.to_thread(os.remove, path)

    async def increment_counter(self, key: str, window_seconds: int) -> int:
        path = self._counters_dir / f"{self._safe_key(key)}.json"
        async with self._lock:
            data = await asyncio.to_thread(_load_json, path) or {"count": 0, "reset_at": 0}
            now = time.time()
            
            if now > data["reset_at"]:
                data = {"count": 1, "reset_at": now + window_seconds}
            else:
                data["count"] += 1
                
            await asyncio.to_thread(_atomic_write_json, path, data)
            return data["count"]

    async def get_counter(self, key: str, window_seconds: int) -> int:
        return data["count"]

    async def reset_counter(self, key: str) -> None:
        path = self._counters_dir / f"{self._safe_key(key)}.json"
        if path.exists():
            await asyncio.to_thread(os.remove, path)

    def _safe_key(self, key: str) -> str:
        """Hash a key to make it safe for use as a filename on Windows."""
        import hashlib
        return hashlib.sha256(key.encode()).hexdigest()

    # ── User Management ───────────────────────────────────────────────────────

    async def create_user(self, user_data: Dict) -> None:
        user_id = user_data["user_id"]
        email = user_data["email"].lower()
        path = self._users_dir / f"{user_id}.json"
        
        async with self._lock:
            # Update email index
            index = await asyncio.to_thread(_load_json, self._email_index_path) or {}
            index[email] = user_id
            await asyncio.to_thread(_atomic_write_json, self._email_index_path, index)
            # Save user
            await asyncio.to_thread(_atomic_write_json, path, user_data)

    async def get_user(self, user_id: str) -> Optional[Dict]:
        path = self._users_dir / f"{user_id}.json"
        return await asyncio.to_thread(_load_json, path)

    async def get_user_by_email(self, email: str) -> Optional[Dict]:
        index = await asyncio.to_thread(_load_json, self._email_index_path) or {}
        user_id = index.get(email.lower())
        if not user_id:
            return None
        return await self.get_user(user_id)

    async def update_user(self, user_id: str, updates: Dict) -> None:
        path = self._users_dir / f"{user_id}.json"
        async with self._lock:
            user = await asyncio.to_thread(_load_json, path)
            if not user:
                return
            user.update(updates)
            await asyncio.to_thread(_atomic_write_json, path, user)

    # ── Tokens (Refresh & Reset) ──────────────────────────────────────────────

    async def store_refresh_token(self, token_hash: str, user_id: str, expires_at: str) -> None:
        path = self._tokens_dir / "refresh" / f"{token_hash}.json"
        await asyncio.to_thread(_atomic_write_json, path, {"user_id": user_id, "expires_at": expires_at})

    async def get_refresh_token(self, token_hash: str) -> Optional[Dict]:
        path = self._tokens_dir / "refresh" / f"{token_hash}.json"
        return await asyncio.to_thread(_load_json, path)

    async def delete_refresh_token(self, token_hash: str) -> None:
        path = self._tokens_dir / "refresh" / f"{token_hash}.json"
        if path.exists():
            await asyncio.to_thread(os.remove, path)

    async def store_reset_token(self, token_hash: str, user_id: str, expires_at: str) -> None:
        path = self._tokens_dir / "reset" / f"{token_hash}.json"
        await asyncio.to_thread(_atomic_write_json, path, {"user_id": user_id, "expires_at": expires_at})

    async def get_reset_token(self, token_hash: str) -> Optional[Dict]:
        path = self._tokens_dir / "reset" / f"{token_hash}.json"
        return await asyncio.to_thread(_load_json, path)

    async def delete_reset_token(self, token_hash: str) -> None:
        path = self._tokens_dir / "reset" / f"{token_hash}.json"
        if path.exists():
            await asyncio.to_thread(os.remove, path)

    # ── Generic Session Tokens (Login / MFA) ───────────────────────────────────

    async def create_session_token(self, user_id: str, token: str, expires_in_seconds: int) -> None:
        path = self._tokens_dir / "session" / f"{self._safe_key(token)}.json"
        data = {
            "user_id": user_id,
            "expires_at": time.time() + expires_in_seconds
        }
        await asyncio.to_thread(_atomic_write_json, path, data)

    async def verify_token(self, token: str) -> Optional[str]:
        path = self._tokens_dir / "session" / f"{self._safe_key(token)}.json"
        data = await asyncio.to_thread(_load_json, path)
        if not data:
            return None
        
        if time.time() > data["expires_at"]:
            await self.invalidate_token(token)
            return None
            
        return data["user_id"]

    async def invalidate_token(self, token: str) -> None:
        path = self._tokens_dir / "session" / f"{self._safe_key(token)}.json"
        if path.exists():
            await asyncio.to_thread(os.remove, path)

    # ── API Keys ──────────────────────────────────────────────────────────────

    async def store_api_key(self, key_data: Dict) -> None:
        key_id = key_data["key_id"]
        key_hash = key_data["key_hash"]
        user_id = key_data["user_id"]
        
        # Save key by ID and by Hash for lookup
        await asyncio.to_thread(_atomic_write_json, self._keys_dir / f"id_{key_id}.json", key_data)
        await asyncio.to_thread(_atomic_write_json, self._keys_dir / f"hash_{key_hash}.json", key_data)
        
        # Update user key index
        async with self._lock:
            idx_path = self._keys_dir / f"user_{user_id}.json"
            user_keys = await asyncio.to_thread(_load_json, idx_path) or []
            user_keys.append(key_id)
            await asyncio.to_thread(_atomic_write_json, idx_path, user_keys)

    async def get_api_key(self, key_hash: str) -> Optional[Dict]:
        return await asyncio.to_thread(_load_json, self._keys_dir / f"hash_{key_hash}.json")

    async def get_api_key_by_id(self, key_id: str) -> Optional[Dict]:
        return await asyncio.to_thread(_load_json, self._keys_dir / f"id_{key_id}.json")

    async def list_api_keys(self, user_id: str) -> List[Dict]:
        idx_path = self._keys_dir / f"user_{user_id}.json"
        key_ids = await asyncio.to_thread(_load_json, idx_path) or []
        keys = []
        for kid in key_ids:
            key = await self.get_api_key_by_id(kid)
            if key:
                keys.append(key)
        return keys

    async def delete_api_key(self, key_id: str) -> None:
        key = await self.get_api_key_by_id(key_id)
        if not key:
            return
        
        async with self._lock:
            # Delete files
            id_path = self._keys_dir / f"id_{key_id}.json"
            hash_path = self._keys_dir / f"hash_{key['key_hash']}.json"
            if id_path.exists(): await asyncio.to_thread(os.remove, id_path)
            if hash_path.exists(): await asyncio.to_thread(os.remove, hash_path)
            
            # Update user index
            idx_path = self._keys_dir / f"user_{key['user_id']}.json"
            user_keys = await asyncio.to_thread(_load_json, idx_path) or []
            if key_id in user_keys:
                user_keys.remove(key_id)
                await asyncio.to_thread(_atomic_write_json, idx_path, user_keys)
