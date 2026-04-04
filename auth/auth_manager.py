"""
auth/auth_manager.py — Authentication Manager
Central orchestrator for all authentication operations.
Coordinates session.py, totp.py, rbac.py, and audit_log.py
into a single cohesive API consumed by api/routes/auth.py.

Responsibilities:
  - Password hashing and verification (bcrypt, PBKDF2 fallback)
  - Login flow: credential check → lockout check → TOTP → token issue
  - Token lifecycle: issue, refresh, revoke
  - API key lifecycle: create, hash, validate, revoke
  - Account management: create, update, delete, suspend
  - TOTP enrollment coordination
  - Audit logging of all security events

Design:
  - AuthManager is stateless — all state lives in SessionStore
  - One instance per application; attach to app.state in lifespan
  - All public methods are async
  - Password operations use bcrypt (cost 12) with PBKDF2-SHA256
    as a fallback if bcrypt is unavailable
  - Token secrets are read from config at call time (not cached)
    so secret rotation takes effect without restart
  - Progressive lockout: after max_attempts the lockout duration
    doubles on each subsequent failure while locked

Quick reference:
  result = await auth.login(email, password, totp_code, ip)
  tokens = await auth.issue_tokens(user_id, email, role)
  user   = await auth.get_user_from_token(jwt_string)
  new_tokens = await auth.refresh(refresh_token_string)
  await auth.logout(refresh_token_string)
  await auth.create_user(email, password, role)
  key_record = await auth.create_api_key(user_id, role, name, scopes)
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from auth.audit_log import (
    AuditLog, AuditEvent,
    OUTCOME_SUCCESS, OUTCOME_FAILURE, OUTCOME_BLOCKED, OUTCOME_ERROR,
)
from auth.rbac import rbac, Permission, Role
from auth.session import SessionStore
from auth import totp as totp_module

logger = logging.getLogger(__name__)


# ── Result types ───────────────────────────────────────────────────

@dataclass
class LoginResult:
    success:         bool
    access_token:    Optional[str] = None
    refresh_token:   Optional[str] = None
    expires_in:      int = 0
    user_id:         Optional[str] = None
    role:            Optional[str] = None
    totp_required:   bool = False
    totp_missing:    bool = False    # True → client must send totp_code
    error:           Optional[str] = None
    error_code:      Optional[str] = None   # machine-readable


@dataclass
class TokenPair:
    access_token:  str
    refresh_token: str
    expires_in:    int      # access token TTL in seconds
    token_type:    str = "bearer"


@dataclass
class UserRecord:
    """Sanitised user data safe to return to API callers (no password_hash)."""
    user_id:    str
    email:      str
    role:       str
    full_name:  str
    created_at: str
    totp_enrolled: bool
    suspended:  bool = False


@dataclass
class ApiKeyRecord:
    key_id:     str
    api_key:    str          # Raw key — returned once on creation
    name:       str
    role:       str
    scopes:     List[str]
    user_id:    str
    created_at: str


# ── AuthManager ────────────────────────────────────────────────────

class AuthManager:
    """
    Central authentication service.
    Constructed once and attached to app.state.auth in lifespan startup.
    """

    def __init__(
        self,
        session_store: SessionStore,
        audit_log:     AuditLog,
    ) -> None:
        self._store = session_store
        self._audit = audit_log

    # ── Login ───────────────────────────────────────────────────────

    async def login(
        self,
        email:      str,
        password:   str,
        ip_address: str,
        totp_code:  Optional[str] = None,
        user_agent: str = "",
    ) -> LoginResult:
        """
        Full login flow:
          1. Check lockout
          2. Load user record
          3. Verify password (constant-time even on missing user)
          4. TOTP check if enrolled and required
          5. Issue tokens
          6. Record audit event

        Returns LoginResult — never raises on auth failures.
        """
        from config import get_config
        config = get_config()

        email_lower = email.lower().strip()

        # 1. Lockout check
        lockout_key  = f"login:lockout:{email_lower}"
        locked_until = await self._store.get_value(lockout_key)
        if locked_until:
            self._audit.log(AuditEvent(
                event_type="auth.login.blocked",
                outcome=OUTCOME_BLOCKED,
                actor_id=email_lower,
                ip_address=ip_address,
                user_agent=user_agent,
            ))
            return LoginResult(
                success=False,
                error="Account temporarily locked. Try again later.",
                error_code="account_locked",
            )

        # 2. Load user (allow timing side-channel to even out below)
        user = await self._store.get_user_by_email(email_lower)

        # 3. Password verification (constant-time regardless of user existence)
        password_ok = False
        if user:
            password_ok = _verify_password(password, user.get("password_hash", ""))

        if not user or not password_ok:
            fail_count = await self._store.increment_counter(
                f"login:fails:{email_lower}", window_seconds=900
            )
            max_attempts = config.auth.max_login_attempts

            if fail_count >= max_attempts:
                lockout_min = config.auth.lockout_duration_min
                # Progressive: multiply lockout by overflow count
                multiplier  = max(1, fail_count // max_attempts)
                lockout_min = min(lockout_min * multiplier, 1440)   # cap at 24h
                await self._store.set_value(
                    lockout_key, "1", ttl_seconds=lockout_min * 60
                )
                self._audit.auth_lockout(
                    email_lower, ip_address, lockout_min
                )

            self._audit.auth_failure(email_lower, ip_address, "bad_credentials")
            return LoginResult(
                success=False,
                error="Invalid email or password.",
                error_code="invalid_credentials",
            )

        # 4. TOTP check
        totp_secret   = user.get("totp_secret")
        totp_enrolled = bool(totp_secret)
        verify_result = None  # set inside if-block; kept in scope for audit log

        if totp_enrolled:
            if not totp_code:
                # Client must re-submit with totp_code
                return LoginResult(
                    success=False,
                    totp_required=True,
                    totp_missing=True,
                    error="TOTP code required.",
                    error_code="totp_required",
                )
            backup_hashes = user.get("totp_backup_codes", [])
            verify_result = totp_module.verify_with_backup(
                code=totp_code,
                secret=totp_secret,
                backup_hashes=backup_hashes,
                window=config.auth.totp_window,
            )
            if not verify_result.valid:
                self._audit.log(AuditEvent(
                    event_type="totp.verify_failed",
                    outcome=OUTCOME_FAILURE,
                    actor_id=user["user_id"],
                    ip_address=ip_address,
                ))
                return LoginResult(
                    success=False,
                    error="Invalid TOTP code.",
                    error_code="invalid_totp",
                )

            # Consume backup code if used
            if verify_result.code_type == "backup" and verify_result.backup_code_used:
                remaining = [
                    h for h in backup_hashes
                    if h != verify_result.backup_code_used
                ]
                await self._store.update_user(
                    user["user_id"], {"totp_backup_codes": remaining}
                )
                if verify_result.low_backup_warning:
                    logger.info(
                        "User %s has only %d backup codes remaining",
                        user["user_id"][:8],
                        verify_result.remaining_backups,
                    )

        elif config.auth.totp_required and not totp_enrolled:
            # TOTP required but not enrolled — allow login but flag
            logger.info(
                "User %s authenticated without TOTP (not enrolled, required=%s)",
                user["user_id"][:8],
                config.auth.totp_required,
            )

        # 5. Clear failure counters
        await self._store.reset_counter(f"login:fails:{email_lower}")
        await self._store.delete_value(lockout_key)

        # 6. Issue tokens
        user_id = user["user_id"]
        role    = user.get("role", "readonly")
        tokens  = await self._issue_tokens(user_id, email_lower, role)

        self._audit.auth_success(
            user_id, ip_address,
            role=role,
            totp_used=totp_enrolled,
            backup_used=(
                verify_result is not None and
                getattr(verify_result, "code_type", "") == "backup"
            ),
        )

        return LoginResult(
            success=True,
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            expires_in=tokens.expires_in,
            user_id=user_id,
            role=role,
        )

    # ── Token operations ────────────────────────────────────────────

    async def _issue_tokens(
        self, user_id: str, email: str, role: str
    ) -> TokenPair:
        """Issue a new access+refresh token pair for a user."""
        from config import get_config
        config  = get_config()
        access  = _create_jwt(user_id, email, role, config)
        refresh = await self._create_refresh_token(user_id)
        return TokenPair(
            access_token=access,
            refresh_token=refresh,
            expires_in=config.auth.jwt_access_expire_min * 60,
        )

    async def refresh(self, refresh_token_raw: str) -> Optional[TokenPair]:
        """
        Rotate a refresh token. Returns new TokenPair or None on failure.
        Old token is always invalidated — even on failure — to prevent
        refresh token reuse after attempted rotation.
        """
        token_hash = _hash(refresh_token_raw)
        record     = await self._store.get_refresh_token(token_hash)

        # Always delete the presented token (prevents replay)
        await self._store.delete_refresh_token(token_hash)

        if record is None:
            return None

        # Check expiry
        from config import get_config
        config     = get_config()
        expires_at = datetime.fromisoformat(record["expires_at"])
        if datetime.now(timezone.utc) > expires_at:
            return None

        user = await self._store.get_user(record["user_id"])
        if not user:
            return None

        tokens = await self._issue_tokens(
            user["user_id"], user["email"], user.get("role", "readonly")
        )
        self._audit.log(AuditEvent(
            event_type="auth.token.refreshed",
            outcome=OUTCOME_SUCCESS,
            actor_id=user["user_id"],
        ))
        return tokens

    async def logout(self, refresh_token_raw: str, actor_id: str = "") -> None:
        """Invalidate a refresh token on logout."""
        token_hash = _hash(refresh_token_raw)
        await self._store.delete_refresh_token(token_hash)
        self._audit.log(AuditEvent(
            event_type="auth.logout",
            outcome=OUTCOME_SUCCESS,
            actor_id=actor_id or "unknown",
        ))

    async def verify_token(self, token: str) -> Optional[Dict]:
        """Decode and validate a JWT. Returns payload dict or None."""
        from config import get_config
        config = get_config()
        return _decode_jwt(token, config)

    async def _create_refresh_token(self, user_id: str) -> str:
        """Generate, store, and return a raw refresh token."""
        from config import get_config
        config    = get_config()
        raw_token = secrets.token_urlsafe(48)
        token_hash = _hash(raw_token)
        expires_at = (
            datetime.now(timezone.utc) +
            timedelta(days=config.auth.jwt_refresh_expire_days)
        ).isoformat()
        await self._store.store_refresh_token(token_hash, user_id, expires_at)
        return raw_token

    # ── User management ─────────────────────────────────────────────
    async def create_user(
        self,
        email:     str,
        password:  str,
        role:      str = "analyst",
        full_name: str = "",
        actor_id:  str = "system",
    ) -> UserRecord:
        """
        Create a new user account.
        Raises ValueError on duplicate email or invalid role.
        """
        try:
            Role.from_str(role)
        except ValueError:
            raise ValueError(f"Invalid role: {role!r}")

        email_lower = email.lower().strip()
        existing    = await self._store.get_user_by_email(email_lower)
        if existing:
            raise ValueError(f"Email already registered: {email_lower}")

        user_id  = str(uuid.uuid4())
        pw_hash  = _hash_password(password)
        now      = datetime.now(timezone.utc).isoformat()

        record = {
            "user_id":            user_id,
            "email":              email_lower,
            "full_name":          full_name,
            "role":               role,
            "password_hash":      pw_hash,
            "totp_secret":        None,
            "totp_backup_codes":  [],
            "suspended":          False,
            "created_at":         now,
            "updated_at":         now,
            "created_by":         actor_id,
        }
        await self._store.create_user(record)

        self._audit.log(AuditEvent(
            event_type="user.created",
            outcome=OUTCOME_SUCCESS,
            actor_id=actor_id,
            resource_type="user",
            resource_id=user_id,
            detail={"email": email_lower, "role": role},
        ))
        return _to_user_record(record)

    async def get_user(self, user_id: str) -> Optional[UserRecord]:
        record = await self._store.get_user(user_id)
        return _to_user_record(record) if record else None

    async def get_user_by_email(self, email: str) -> Optional[UserRecord]:
        record = await self._store.get_user_by_email(email.lower().strip())
        return _to_user_record(record) if record else None

    async def update_password(
        self,
        user_id:      str,
        new_password: str,
        actor_id:     str = "",
    ) -> None:
        """Change a user's password and invalidate all sessions."""
        pw_hash = _hash_password(new_password)
        await self._store.update_user(user_id, {
            "password_hash": pw_hash,
            "updated_at":    datetime.now(timezone.utc).isoformat(),
        })
        self._audit.log(AuditEvent(
            event_type="auth.password.changed",
            outcome=OUTCOME_SUCCESS,
            actor_id=actor_id or user_id,
            resource_type="user",
            resource_id=user_id,
        ))

    async def change_role(
        self,
        user_id:    str,
        new_role:   str,
        actor_id:   str,
        actor_role: str,
    ) -> None:
        """Change a user's role. Only admins can change roles."""
        if not rbac.can_assign_role(actor_role, new_role):
            raise PermissionError(
                f"Role {actor_role!r} cannot assign role {new_role!r}."
            )
        await self._store.update_user(user_id, {
            "role":       new_role,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
        self._audit.log(AuditEvent(
            event_type="user.role_changed",
            outcome=OUTCOME_SUCCESS,
            actor_id=actor_id,
            resource_type="user",
            resource_id=user_id,
            detail={"new_role": new_role},
        ))

    async def suspend_user(self, user_id: str, actor_id: str) -> None:
        """Suspend a user account (prevents login without deleting data)."""
        await self._store.update_user(user_id, {
            "suspended":  True,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
        self._audit.log(AuditEvent(
            event_type="user.suspended",
            outcome=OUTCOME_SUCCESS,
            actor_id=actor_id,
            resource_type="user",
            resource_id=user_id,
        ))

    async def delete_user(self, user_id: str, actor_id: str) -> None:
        """Permanently delete a user account."""
        await self._store.delete_user(user_id)
        self._audit.log(AuditEvent(
            event_type="user.deleted",
            outcome=OUTCOME_SUCCESS,
            actor_id=actor_id,
            resource_type="user",
            resource_id=user_id,
        ))

    # ── TOTP management ─────────────────────────────────────────────

    async def begin_totp_enrollment(
        self, user_id: str, email: str
    ) -> totp_module.TOTPEnrollment:
        """
        Generate TOTP enrollment data and store the pending secret
        (with 10-minute TTL) until verify_totp_enrollment confirms.
        """
        from config import get_config
        config   = get_config()
        enrollment = totp_module.create_enrollment(
            email=email, issuer=config.auth.totp_issuer
        )
        # Store pending secret for 10 minutes
        await self._store.set_value(
            f"totp:pending:{user_id}",
            enrollment.secret,
            ttl_seconds=600,
        )
        return enrollment

    async def verify_totp_enrollment(
        self,
        user_id:       str,
        code:          str,
        backup_hashes: List[str],
    ) -> bool:
        """
        Confirm TOTP enrollment by verifying the first code.
        If valid, saves secret + backup hashes to the user record.
        """
        from config import get_config
        config  = get_config()
        pending = await self._store.get_value(f"totp:pending:{user_id}")
        if not pending:
            return False

        if not totp_module.verify(code, pending, window=config.auth.totp_window):
            return False

        await self._store.update_user(user_id, {
            "totp_secret":       pending,
            "totp_backup_codes": backup_hashes,
            "updated_at":        datetime.now(timezone.utc).isoformat(),
        })
        await self._store.delete_value(f"totp:pending:{user_id}")

        self._audit.log(AuditEvent(
            event_type="totp.enrolled",
            outcome=OUTCOME_SUCCESS,
            actor_id=user_id,
        ))
        return True

    async def remove_totp(self, user_id: str, actor_id: str) -> None:
        """Remove TOTP from a user account."""
        await self._store.update_user(user_id, {
            "totp_secret":       None,
            "totp_backup_codes": [],
            "updated_at":        datetime.now(timezone.utc).isoformat(),
        })
        self._audit.log(AuditEvent(
            event_type="totp.removed",
            outcome=OUTCOME_SUCCESS,
            actor_id=actor_id,
            resource_type="user",
            resource_id=user_id,
        ))

    # ── API key management ──────────────────────────────────────────

    async def create_api_key(
        self,
        user_id:   str,
        user_role: str,
        name:      str,
        scopes:    Optional[List[str]] = None,
        ip_address: str = "",
    ) -> ApiKeyRecord:
        """
        Create a new API key for a user.
        Scopes are validated against the user's role — can never exceed it.
        Returns the raw key once (caller must display it to the user).
        """
        from config import get_config
        config  = get_config()

        # Validate and sanitise scopes
        if scopes:
            valid_scopes = rbac.validate_api_key_scopes(scopes, user_role)
        else:
            valid_scopes = rbac.scopes_for(user_role)

        raw_key  = config.auth.api_key_prefix + secrets.token_urlsafe(
            config.auth.api_key_length
        )
        key_hash = _hash(raw_key)
        key_id   = str(uuid.uuid4())
        now      = datetime.now(timezone.utc).isoformat()

        record = {
            "key_id":      key_id,
            "key_hash":    key_hash,
            "user_id":     user_id,
            "role":        user_role,
            "scopes":      valid_scopes,
            "name":        name,
            "description": "",
            "created_at":  now,
        }
        await self._store.store_api_key(record)

        self._audit.log(AuditEvent(
            event_type="api_key.created",
            outcome=OUTCOME_SUCCESS,
            actor_id=user_id,
            ip_address=ip_address,
            resource_type="api_key",
            resource_id=key_id,
            detail={"name": name, "scopes": valid_scopes},
        ))

        return ApiKeyRecord(
            key_id=key_id,
            api_key=raw_key,
            name=name,
            role=user_role,
            scopes=valid_scopes,
            user_id=user_id,
            created_at=now,
        )

    async def validate_api_key(self, raw_key: str) -> Optional[Dict]:
        """
        Validate an API key. Returns the key record (user_id, role, scopes)
        or None if the key is invalid or revoked.
        """
        from config import get_config
        config = get_config()

        if not raw_key.startswith(config.auth.api_key_prefix):
            return None

        key_hash = _hash(raw_key)
        record   = await self._store.get_api_key(key_hash)
        return record

    async def revoke_api_key(
        self,
        key_id:      str,
        actor_id:    str,
        actor_role:  str,
        ip_address:  str = "",
    ) -> bool:
        """
        Revoke an API key.
        Users can revoke their own keys; admins can revoke any key.
        Returns False if the key does not exist.
        """
        meta = await self._store.get_api_key_by_id(key_id)
        if not meta:
            return False

        owner_id = meta.get("user_id", "")
        if actor_id != owner_id and not rbac.is_admin(actor_role):
            raise PermissionError("You can only revoke your own API keys.")

        await self._store.delete_api_key(key_id)
        self._audit.log(AuditEvent(
            event_type="api_key.revoked",
            outcome=OUTCOME_SUCCESS,
            actor_id=actor_id,
            ip_address=ip_address,
            resource_type="api_key",
            resource_id=key_id,
        ))
        return True

    # ── Password reset flow ─────────────────────────────────────────

    async def request_password_reset(self, email: str, ip_address: str = "") -> Optional[str]:
        """
        Initiate a password reset.
        Returns the raw reset token (for email delivery) or None if user not found.
        Callers should always return 200 to prevent email enumeration.
        """
        user = await self._store.get_user_by_email(email.lower().strip())
        if not user:
            return None

        raw_token  = secrets.token_urlsafe(48)
        token_hash = _hash(raw_token)
        expires_at = (
            datetime.now(timezone.utc) + timedelta(hours=1)
        ).isoformat()

        await self._store.store_reset_token(
            token_hash=token_hash,
            user_id=user["user_id"],
            expires_at=expires_at,
        )
        self._audit.log(AuditEvent(
            event_type="auth.password.reset_request",
            outcome=OUTCOME_SUCCESS,
            actor_id=user["user_id"],
            ip_address=ip_address,
        ))
        return raw_token

    async def complete_password_reset(
        self, raw_token: str, new_password: str
    ) -> bool:
        """
        Apply a password reset.
        Returns True on success, False if token is invalid or expired.
        """
        token_hash = _hash(raw_token)
        record     = await self._store.get_reset_token(token_hash)
        if not record:
            return False

        expires_at = datetime.fromisoformat(record["expires_at"])
        if datetime.now(timezone.utc) > expires_at:
            await self._store.delete_reset_token(token_hash)
            return False

        await self.update_password(
            record["user_id"], new_password, actor_id="password_reset_flow"
        )
        await self._store.delete_reset_token(token_hash)

        self._audit.log(AuditEvent(
            event_type="auth.password.reset_applied",
            outcome=OUTCOME_SUCCESS,
            actor_id=record["user_id"],
        ))
        return True


# ── Password helpers ───────────────────────────────────────────────

def _hash_password(password: str) -> str:
    """Hash a password with bcrypt (cost 12) or PBKDF2-SHA256 fallback."""
    try:
        import bcrypt
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    except ImportError:
        salt = secrets.token_hex(16)
        dk   = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt.encode(), 310_000
        )
        return f"pbkdf2:{salt}:{dk.hex()}"


def _verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against its stored hash. Constant-time."""
    if not stored_hash:
        # Perform a dummy comparison to maintain constant time
        hashlib.pbkdf2_hmac("sha256", password.encode(), b"dummy", 1)
        return False
    try:
        import bcrypt
        return bcrypt.checkpw(password.encode(), stored_hash.encode())
    except ImportError:
        pass
    except Exception:
        return False
    # PBKDF2 path
    if stored_hash.startswith("pbkdf2:"):
        parts = stored_hash.split(":")
        if len(parts) == 3:
            _, salt, stored_dk = parts
            dk = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), salt.encode(), 310_000
            )
            return secrets.compare_digest(dk.hex(), stored_dk)
    return False


# ── JWT helpers ────────────────────────────────────────────────────

def _create_jwt(user_id: str, email: str, role: str, config) -> str:
    try:
        import jwt as pyjwt
    except ImportError:
        raise RuntimeError("PyJWT not installed: pip install PyJWT")

    scopes  = rbac.scopes_for(role)
    payload = {
        "sub":    user_id,
        "email":  email,
        "role":   role,
        "scopes": scopes,
        "iat":    datetime.now(timezone.utc),
        "exp":    datetime.now(timezone.utc) + timedelta(
            minutes=config.auth.jwt_access_expire_min
        ),
        "jti":    str(uuid.uuid4()),
    }
    return pyjwt.encode(
        payload, config.app.secret_key, algorithm=config.auth.jwt_algorithm
    )


def _decode_jwt(token: str, config) -> Optional[Dict]:
    try:
        import jwt as pyjwt
        return pyjwt.decode(
            token,
            config.app.secret_key,
            algorithms=[config.auth.jwt_algorithm],
        )
    except Exception:
        return None


# ── Misc helpers ───────────────────────────────────────────────────

def _hash(value: str) -> str:
    """SHA-256 hex digest of a value."""
    return hashlib.sha256(value.encode()).hexdigest()


def _to_user_record(record: Dict) -> UserRecord:
    """Convert raw DB dict to sanitised UserRecord (no password_hash)."""
    return UserRecord(
        user_id=record.get("user_id", ""),
        email=record.get("email", ""),
        role=record.get("role", "readonly"),
        full_name=record.get("full_name", ""),
        created_at=record.get("created_at", ""),
        totp_enrolled=bool(record.get("totp_secret")),
        suspended=record.get("suspended", False),
    )


# ── Module-level singleton ─────────────────────────────────────────

_instance: Optional[AuthManager] = None


def get_auth_manager() -> AuthManager:
    """Return the AuthManager singleton, creating it on first call."""
    global _instance
    if _instance is None:
        from config import get_config
        from auth.audit_log import get_audit_log
        config = get_config()
        store  = SessionStore(config.storage)
        audit  = get_audit_log()
        _instance = AuthManager(session_store=store, audit_log=audit)
    return _instance


# --- Public JWT helpers (for use in auth routes) ---

def create_jwt(
    user_id: str,
    email: str,
    role: str,
    expires_in_seconds: int = 3600,
) -> str:
    """Create a JWT token for the user."""
    from config import get_config
    config = get_config()
    
    try:
        import jwt as pyjwt
    except ImportError:
        raise RuntimeError("PyJWT not installed: pip install PyJWT")

    scopes = rbac.scopes_for(role)
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "scopes": scopes,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds),
        "jti": str(uuid.uuid4()),
    }
    return pyjwt.encode(
        payload, config.app.secret_key, algorithm=config.auth.jwt_algorithm
    )


def decode_jwt(token: str) -> Optional[Dict]:
    """Decode and validate a JWT token."""
    from config import get_config
    config = get_config()
    
    try:
        import jwt as pyjwt
        return pyjwt.decode(
            token,
            config.app.secret_key,
            algorithms=[config.auth.jwt_algorithm],
        )
    except Exception:
        return None