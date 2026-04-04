"""
auth/session_memory.py — In-memory Session Store

Single-user, no-database backend. Stores:
  - Active JWT tokens (access + refresh)
  - TOTP secret and verified status
  - Session metadata

All data is ephemeral — lost on app restart.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, Optional
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

# ─── HARDCODED USER ───────────────────────────────────────────────────────────
# Single user for demo/no-DB mode
DEMO_USER = {
    "user_id": "demo-user-1",
    "email": "demo@vulnscout.local",
    "name": "Demo User",
    "role": "admin",  # Single user gets full admin access
}

# TOTP Secret (Base32) - this is a demo secret for testing
# To generate a new one: python -c "import pyotp; print(pyotp.random_base32())"
DEMO_TOTP_SECRET = "JBSWY3DPEBLW64TMMQ======"  # Demo-only, well-known seed


@dataclass
class SessionToken:
    """Active JWT session token."""
    token: str
    token_hash: str  # SHA-256 for lookup
    user_id: str
    created_at: float
    expires_at: float
    refresh_token: Optional[str] = None


@dataclass
class SessionState:
    """In-memory session state for a user."""
    user_id: str
    email: str
    totp_verified: bool = False
    totp_verified_at: Optional[float] = None
    last_activity: float = field(default_factory=time.time)
    active_tokens: Dict[str, SessionToken] = field(default_factory=dict)
    totp_secret: str = ""
    totp_backup_codes: list = field(default_factory=list)

    def is_2fa_verified(self) -> bool:
        """Check if 2FA was verified in this session."""
        return self.totp_verified


class InMemorySessionStore:
    """Single-user, in-memory session manager."""

    def __init__(self):
        """Initialize with demo user."""
        self.sessions: Dict[str, SessionState] = {}
        self.users: Dict[str, dict] = {}  # email -> user_info
        self.token_index: Dict[str, str] = {}  # token_hash → user_id
        self._init_demo_user()

    def _init_demo_user(self) -> None:
        """Set up demo user with TOTP secret."""
        self.users[DEMO_USER["email"].lower()] = {
            **DEMO_USER,
            "password_hash": "demo123456",  # In demo mode, we use plain text comparison for simplicity
            "totp_secret": DEMO_TOTP_SECRET
        }

        session = SessionState(
            user_id=DEMO_USER["user_id"],
            email=DEMO_USER["email"],
            totp_secret=DEMO_TOTP_SECRET,
            totp_backup_codes=[],
        )
        self.sessions[DEMO_USER["user_id"]] = session
        logger.info(
            "Demo user initialized: %s (%s)",
            DEMO_USER["name"],
            DEMO_USER["email"],
        )

    def get_user_session(self, user_id: str) -> Optional[SessionState]:
        """Get session state for user."""
        return self.sessions.get(user_id)

    def get_demo_user(self) -> dict:
        """Return demo user info."""
        return DEMO_USER.copy()

    def register_user(self, email: str, password: str, name: str, totp_secret: str) -> dict:
        """Register a new user dynamically."""
        user_id = f"user-{secrets.token_hex(4)}"
        user_info = {
            "user_id": user_id,
            "email": email,
            "name": name,
            "role": "analyst",  # New signups default to analyst
            "password_hash": password,  # Storing plain for the demo as requested
            "totp_secret": totp_secret
        }
        self.users[email.lower()] = user_info
        
        # Create initial session state
        self.sessions[user_id] = SessionState(
            user_id=user_id,
            email=email,
            totp_secret=totp_secret
        )
        
        return user_info

    def validate_credentials(self, email: str, password: str) -> Optional[dict]:
        """Validate email and password against stored users."""
        user = self.users.get(email.lower())
        if user and user["password_hash"] == password:
            return user
        return None

    def create_session_token(
        self,
        user_id: str,
        token: str,
        refresh_token: Optional[str] = None,
        expires_in_seconds: int = 3600,
    ) -> SessionToken:
        """Create and store a new session token."""
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        now = time.time()
        expires_at = now + expires_in_seconds

        session_token = SessionToken(
            token=token,
            token_hash=token_hash,
            user_id=user_id,
            created_at=now,
            expires_at=expires_at,
            refresh_token=refresh_token,
        )

        session = self.sessions.get(user_id)
        if session:
            session.active_tokens[token_hash] = session_token
            self.token_index[token_hash] = user_id
            session.last_activity = now

        return session_token

    def verify_token(self, token: str) -> Optional[str]:
        """Verify token and return user_id if valid, None otherwise."""
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        user_id = self.token_index.get(token_hash)

        if not user_id:
            return None

        session = self.sessions.get(user_id)
        if not session:
            return None

        session_token = session.active_tokens.get(token_hash)
        if not session_token:
            return None

        # Check expiry
        if time.time() > session_token.expires_at:
            session.active_tokens.pop(token_hash, None)
            self.token_index.pop(token_hash, None)
            return None

        session.last_activity = time.time()
        return user_id

    def mark_2fa_verified(self, user_id: str) -> None:
        """Mark user as having verified 2FA in this session."""
        session = self.sessions.get(user_id)
        if session:
            session.totp_verified = True
            session.totp_verified_at = time.time()
            logger.info("2FA verified for user: %s", user_id)

    def is_2fa_complete(self, user_id: str) -> bool:
        """Check if user has completed 2FA verification."""
        session = self.sessions.get(user_id)
        return session.is_2fa_verified() if session else False

    def get_totp_secret(self, user_id: str) -> Optional[str]:
        """Get TOTP secret for user."""
        session = self.sessions.get(user_id)
        return session.totp_secret if session else None

    def invalidate_token(self, token: str) -> None:
        """Invalidate a token (logout)."""
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        user_id = self.token_index.get(token_hash)

        if user_id:
            session = self.sessions.get(user_id)
            if session:
                session.active_tokens.pop(token_hash, None)
            self.token_index.pop(token_hash, None)

    def cleanup_expired_tokens(self) -> None:
        """Remove expired tokens (can be called periodically)."""
        now = time.time()
        for user_id, session in self.sessions.items():
            expired = [
                h
                for h, t in session.active_tokens.items()
                if now > t.expires_at
            ]
            for token_hash in expired:
                session.active_tokens.pop(token_hash, None)
                self.token_index.pop(token_hash, None)


# Global singleton instance
_store: Optional[InMemorySessionStore] = None


def get_session_store() -> InMemorySessionStore:
    """Get or create the global session store."""
    global _store
    if _store is None:
        _store = InMemorySessionStore()
    return _store


def init_session_store() -> InMemorySessionStore:
    """Initialize the session store (idempotent)."""
    return get_session_store()
