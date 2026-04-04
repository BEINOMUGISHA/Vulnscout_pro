"""
auth/two_factor.py — Advanced Two-Factor Authentication Engine

Implements a multi-method 2FA system supporting:
  - TOTP (RFC 6238) via pyotp — Authenticator apps (Google, Authy, etc.)
  - Email OTP — 6-digit numeric code with 5-minute expiry
  - Hardware Tokens — WebAuthn/FIDO2 stub (future-proof)

Security features:
  - Per-user rate limiting: max 5 attempts per 60-second window
  - Backup code support (8 single-use codes)
  - Replay protection (inherits from totp.py)
  - Future-proof WebAuthn interface

Usage:
    tfa = TwoFactorAuth()
    enrollment = await tfa.enroll_user("user@example.com", method="totp")
    ok = tfa.verify("user@example.com", code="123456", method="totp")
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import string
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import pyotp
import qrcode
import qrcode.image.svg
import io, base64

from auth import totp as totp_module

logger = logging.getLogger(__name__)


# ── Rate Limiter ──────────────────────────────────────────────────────────────

class _RateLimiter:
    """Simple in-memory sliding-window rate limiter (5 attempts / 60 seconds)."""

    def __init__(self, max_attempts: int = 5, window_seconds: float = 60.0):
        self._max = max_attempts
        self._window = window_seconds
        self._log: Dict[str, List[float]] = {}  # user_id → [timestamp, ...]

    def exceeded(self, user_id: str) -> bool:
        now = time.monotonic()
        attempts = self._log.setdefault(user_id, [])
        # Evict stale timestamps
        self._log[user_id] = [t for t in attempts if now - t < self._window]
        return len(self._log[user_id]) >= self._max

    def record(self, user_id: str) -> None:
        self._log.setdefault(user_id, []).append(time.monotonic())

    def reset(self, user_id: str) -> None:
        self._log.pop(user_id, None)


# ── WebAuthn Stub ─────────────────────────────────────────────────────────────

class WebAuthnSupport:
    """
    Future-proof WebAuthn / FIDO2 hardware token interface.
    Stubs out the registration and assertion flows for YubiKey, etc.
    Integrate with `py_webauthn` library when hardware tokens are needed.
    """

    async def register(self, user_id: str) -> Dict[str, Any]:
        logger.info("WebAuthn registration stub invoked for user: %s", user_id)
        return {
            "method": "hardware_token",
            "status": "not_implemented",
            "message": (
                "WebAuthn/FIDO2 hardware token support is planned. "
                "Install `py_webauthn` and configure a Relying Party to enable."
            ),
        }

    async def verify(self, user_id: str, assertion: Dict) -> bool:
        logger.warning("WebAuthn verify stub — always returns False")
        return False


# ── Email OTP Store ───────────────────────────────────────────────────────────

@dataclass
class EmailOTPRecord:
    code: str
    issued_at: float
    expires_in: float = 300.0  # 5 minutes

    def is_valid(self, code: str) -> bool:
        if time.monotonic() - self.issued_at > self.expires_in:
            return False
        return secrets.compare_digest(self.code, code)


# ── TwoFactorAuth Engine ──────────────────────────────────────────────────────

class TwoFactorAuth:
    """
    Unified multi-method Two-Factor Authentication engine.

    Methods:
      - 'totp'           → Authenticator app (Google Authenticator, Authy, etc.)
      - 'email_otp'      → Numeric OTP sent to user email (for non-smartphone users)
      - 'hardware_token' → WebAuthn / YubiKey (future-proof stub)
      - 'backup'         → Single-use recovery codes

    Rate limiting: 5 verification attempts per 60 seconds per user.
    """

    def __init__(self) -> None:
        self.totp = pyotp.TOTP
        self.backup_codes: List[str] = []
        self.webauthn = WebAuthnSupport()
        self._rate_limiter = _RateLimiter(max_attempts=5, window_seconds=60.0)

        # In-memory stores (ephemeral per process)
        self._email_otps: Dict[str, EmailOTPRecord] = {}   # user_id → EmailOTPRecord
        self._totp_secrets: Dict[str, str] = {}            # user_id → base32 secret
        self._backup_hashes: Dict[str, List[str]] = {}     # user_id → hashed backup codes

    # ── Enrollment ────────────────────────────────────────────────────────────

    async def enroll_user(self, user_id: str, method: str) -> Dict[str, Any]:
        """
        Enroll a user in a 2FA method.

        Args:
            user_id: User identifier (usually email address).
            method:  One of 'totp', 'email_otp', 'hardware_token'.

        Returns:
            A dict appropriate for the chosen method.
        """
        if method == "totp":
            secret = pyotp.random_base32()
            uri = pyotp.TOTP(secret).provisioning_uri(
                name=user_id,
                issuer_name="VulnScout Pro",
            )
            backup_codes, backup_hashes = self._generate_backup_codes(8)

            # Persist in-memory
            self._totp_secrets[user_id] = secret
            self._backup_hashes[user_id] = backup_hashes

            return {
                "method": "totp",
                "secret": secret,
                "qr_code": self._generate_qr_base64(uri),
                "provisioning_uri": uri,
                "backup_codes": backup_codes,       # Show once, never again
            }

        elif method == "email_otp":
            code = self._generate_numeric_code(6)
            self._email_otps[user_id] = EmailOTPRecord(code=code, issued_at=time.monotonic())

            # Attempt to send via email service (non-fatal if unavailable)
            await self._send_email_otp(user_id, code)

            return {"method": "email", "expires_in": 300}

        elif method == "hardware_token":
            return await self.webauthn.register(user_id)

        else:
            raise ValueError(f"Unsupported 2FA method: {method!r}")

    # ── Verification ──────────────────────────────────────────────────────────

    def verify(self, user_id: str, code: str, method: str) -> bool:
        """
        Verify a 2FA code for a user.

        Rate limiting: 5 attempts per minute per user.
        On success, the rate-limit counter is reset.

        Args:
            user_id: User identifier.
            code:    The code to verify.
            method:  'totp', 'email', or 'backup'.

        Returns:
            True if the code is valid, False otherwise.
        """
        if self._rate_limiter.exceeded(user_id):
            logger.warning("2FA rate limit exceeded for user: %s", user_id)
            return False

        self._rate_limiter.record(user_id)

        if method == "totp":
            secret = self._totp_secrets.get(user_id)
            if not secret:
                logger.warning("No TOTP secret enrolled for user: %s", user_id)
                return False
            result = totp_module.verify(code, secret)

        elif method == "email":
            record = self._email_otps.get(user_id)
            result = bool(record and record.is_valid(code))
            if result:
                del self._email_otps[user_id]  # Consume single-use code

        elif method == "backup":
            stored_hashes = self._backup_hashes.get(user_id, [])
            result, consumed_idx = self._verify_backup_code(code, stored_hashes)
            if result and consumed_idx is not None:
                # Remove the used backup code
                self._backup_hashes[user_id] = [
                    h for i, h in enumerate(stored_hashes) if i != consumed_idx
                ]
                remaining = len(self._backup_hashes[user_id])
                if remaining < 3:
                    logger.warning("User %s has only %d backup codes remaining", user_id, remaining)

        else:
            logger.warning("Unknown 2FA method: %s", method)
            result = False

        if result:
            self._rate_limiter.reset(user_id)

        return result

    # ── Private helpers ───────────────────────────────────────────────────────

    def _generate_backup_codes(self, count: int = 8):
        """Return (plain_codes, bcrypt_hashes) pairs."""
        import hashlib
        alphabet = string.ascii_uppercase + string.digits
        codes = []
        hashes = []
        for _ in range(count):
            raw = "".join(secrets.choice(alphabet) for _ in range(5))
            raw2 = "".join(secrets.choice(alphabet) for _ in range(5))
            code = f"{raw}-{raw2}"
            codes.append(code)
            hashes.append(hashlib.sha256(code.encode()).hexdigest())
        return codes, hashes

    def _verify_backup_code(self, code: str, stored_hashes: List[str]):
        """Returns (valid: bool, index: int | None)."""
        import hashlib
        normalized = code.upper().replace(" ", "")
        h = hashlib.sha256(normalized.encode()).hexdigest()
        for idx, stored in enumerate(stored_hashes):
            if secrets.compare_digest(h, stored):
                return True, idx
        return False, None

    def _generate_numeric_code(self, length: int = 6) -> str:
        return "".join(secrets.choice(string.digits) for _ in range(length))

    def _generate_qr_base64(self, uri: str) -> str:
        """Generate a base64-encoded PNG QR code from an otpauth:// URI."""
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()

    async def _send_email_otp(self, user_id: str, code: str) -> None:
        """Fire-and-forget email send. Non-fatal if email service is unavailable."""
        try:
            # Import EmailService lazily to avoid circular imports
            from core.integrations.email_service import EmailService
            service = EmailService()
            await service.send(
                to=user_id,
                template="otp",
                data={"code": code, "expires": "5 minutes"},
            )
            logger.info("Email OTP sent to %s", user_id)
        except Exception as exc:
            logger.warning("Email OTP could not be sent to %s: %s", user_id, exc)


# ── Module-level singleton ────────────────────────────────────────────────────

two_factor_auth = TwoFactorAuth()
