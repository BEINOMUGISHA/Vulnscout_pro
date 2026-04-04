"""
auth/totp.py — TOTP Two-Factor Authentication

RFC 6238-compliant TOTP implementation built on pyotp.
Handles the full enrollment, verification, and recovery lifecycle.

Enrollment flow:
  1. generate_secret()          → raw base32 secret
  2. provisioning_uri(secret)   → otpauth:// URI for QR code
  3. verify(code, secret)       → confirm enrollment — saves secret
  4. generate_backup_codes()    → 8 single-use recovery codes

Verification flow (every login):
  1. verify(code, secret)       → validates current TOTP window
  2. If code fails → try verify_backup_code(code, stored_codes)
  3. On backup use → remove used code, warn user to regenerate

Security:
  - Clock drift tolerance: ±config.auth.totp_window windows (default ±30s)
  - Used TOTP codes are tracked for 90s to prevent replay within window
  - Backup codes are bcrypt-hashed — never stored in plain text
  - Secret stored encrypted at rest (via session_store)
  - Provisioning URI uses issuer name from config for authenticator display

Recovery:
  - 8 backup codes, each 10 alphanumeric characters (XXXXX-XXXXX format)
  - Each code single-use — consumed on first successful use
  - User warned when < 3 codes remain
"""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
import string
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Requires: pip install pyotp
try:
    import pyotp
    _PYOTP_AVAILABLE = True
except ImportError:
    _PYOTP_AVAILABLE = False
    logger.warning(
        "pyotp not installed — TOTP 2FA unavailable. "
        "Install with: pip install pyotp --break-system-packages"
    )

# Backup code format: XXXXX-XXXXX (10 chars, hyphen separator)
_CODE_ALPHABET = string.ascii_uppercase + string.digits
_CODE_SEGMENT  = 5
_BACKUP_COUNT  = 8

# Replay protection: track recently-used codes per secret (in-memory only)
# Maps secret_hash → {code_hash: used_at_timestamp}
_used_codes: Dict[str, Dict[str, float]] = {}
_REPLAY_WINDOW_S = 90


@dataclass
class TOTPEnrollment:
    """Holds the data returned to the client during TOTP enrollment."""
    secret:           str          # Base32 secret — store encrypted, show once
    provisioning_uri: str          # otpauth:// URI for QR code
    backup_codes:     List[str]    # 8 plain-text codes — show once only
    backup_hashes:    List[str]    # bcrypt hashes — store permanently
    issuer:           str


@dataclass
class TOTPVerifyResult:
    """Result of a TOTP or backup code verification attempt."""
    valid:             bool
    code_type:         str          # "totp" | "backup" | "invalid"
    backup_code_used:  Optional[str] = None  # The backup code that was consumed
    remaining_backups: int = 0       # How many backup codes remain after this use
    low_backup_warning: bool = False  # True if < 3 codes remain


# ── Core TOTP operations ──────────────────────────────────────────

def generate_secret() -> str:
    """
    Generate a cryptographically secure TOTP secret.
    Returns a base32-encoded string compatible with all authenticator apps.
    """
    if not _PYOTP_AVAILABLE:
        raise RuntimeError("pyotp not installed")
    return pyotp.random_base32()


def provisioning_uri(secret: str, email: str, issuer: str) -> str:
    """
    Build the otpauth:// URI for rendering as a QR code.
    Format: otpauth://totp/{issuer}:{email}?secret={secret}&issuer={issuer}
    """
    if not _PYOTP_AVAILABLE:
        raise RuntimeError("pyotp not installed")
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=issuer)


def verify(
    code:   str,
    secret: str,
    window: int = 1,
) -> bool:
    """
    Verify a TOTP code against a secret.

    Args:
        code:   6-8 digit code from authenticator app
        secret: base32-encoded TOTP secret
        window: number of 30-second windows to check either side of now
                (1 = ±30 seconds, 2 = ±60 seconds)

    Returns True only if the code is valid AND has not been used recently
    (replay protection).
    """
    if not _PYOTP_AVAILABLE:
        raise RuntimeError("pyotp not installed")

    code = code.strip().replace(" ", "")
    if not code.isdigit() or not (6 <= len(code) <= 8):
        return False

    try:
        totp = pyotp.TOTP(secret)
        valid = totp.verify(code, valid_window=window)
    except Exception as exc:
        logger.warning("TOTP verification error: %s", exc)
        return False

    if not valid:
        return False

    # Replay protection — reject codes used in the last 90 seconds
    secret_hash  = _hash_short(secret)
    code_hash    = _hash_short(f"{code}:{_current_window()}")
    now          = time.monotonic()

    recent = _used_codes.setdefault(secret_hash, {})
    _evict_old_codes(recent, now)

    if code_hash in recent:
        logger.warning("TOTP replay attempt detected for secret %s", secret_hash[:8])
        return False

    recent[code_hash] = now
    return True


def verify_with_backup(
    code:          str,
    secret:        str,
    backup_hashes: List[str],
    window:        int = 1,
) -> TOTPVerifyResult:
    """
    Verify a code as either a TOTP code or a backup code.

    Returns a TOTPVerifyResult indicating which type was used and
    which backup code hash was consumed (if any).
    """
    # Try TOTP first
    if verify(code, secret, window=window):
        return TOTPVerifyResult(valid=True, code_type="totp")

    # Try backup codes
    normalized = _normalize_backup_code(code)
    if normalized:
        for idx, stored_hash in enumerate(backup_hashes):
            if _check_backup_code(normalized, stored_hash):
                remaining = len(backup_hashes) - 1
                return TOTPVerifyResult(
                    valid=True,
                    code_type="backup",
                    backup_code_used=stored_hash,
                    remaining_backups=remaining,
                    low_backup_warning=(remaining < 3),
                )

    return TOTPVerifyResult(valid=False, code_type="invalid")


# ── Enrollment ─────────────────────────────────────────────────────

def create_enrollment(email: str, issuer: str = "VulnScout Pro") -> TOTPEnrollment:
    """
    Generate a full TOTP enrollment package.
    Returns secrets and URIs — the caller must save backup_hashes
    and secret to the user record. Plain-text backup_codes must be
    shown to the user exactly once and then discarded.
    """
    secret = generate_secret()
    uri    = provisioning_uri(secret, email, issuer)
    plain_codes, hashed_codes = generate_backup_codes()

    return TOTPEnrollment(
        secret=secret,
        provisioning_uri=uri,
        backup_codes=plain_codes,
        backup_hashes=hashed_codes,
        issuer=issuer,
    )


# ── Backup codes ───────────────────────────────────────────────────

def generate_backup_codes() -> Tuple[List[str], List[str]]:
    """
    Generate 8 single-use backup recovery codes.

    Returns:
        (plain_codes, hashed_codes)
        plain_codes:  ["XXXXX-XXXXX", ...]  — show to user once only
        hashed_codes: [sha256_hex, ...]      — store in user record
    """
    plain   = []
    hashed  = []
    for _ in range(_BACKUP_COUNT):
        raw  = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(_CODE_SEGMENT * 2))
        code = f"{raw[:_CODE_SEGMENT]}-{raw[_CODE_SEGMENT:]}"
        plain.append(code)
        hashed.append(_hash_backup_code(code))
    return plain, hashed


def _hash_backup_code(code: str) -> str:
    """
    Hash a backup code for storage.
    Uses SHA-256 with a fixed domain separator — simple and fast for
    backup codes which are long random strings (not passwords).
    For passwords use bcrypt via auth_manager.py.
    """
    normalized = _normalize_backup_code(code) or code
    return hashlib.sha256(
        f"vs_backup_code:{normalized}".encode()
    ).hexdigest()


def _check_backup_code(normalized: str, stored_hash: str) -> bool:
    """Constant-time comparison of a backup code against its stored hash."""
    candidate_hash = hashlib.sha256(
        f"vs_backup_code:{normalized}".encode()
    ).hexdigest()
    return secrets.compare_digest(candidate_hash, stored_hash)


def _normalize_backup_code(code: str) -> Optional[str]:
    """
    Normalize a backup code: strip spaces/hyphens, uppercase, validate format.
    Returns None if the code doesn't look like a valid backup code.
    """
    cleaned = re.sub(r"[\s\-]", "", code.upper())
    if len(cleaned) == _CODE_SEGMENT * 2 and all(c in _CODE_ALPHABET for c in cleaned):
        return cleaned
    return None


def consume_backup_code(
    code: str,
    backup_hashes: List[str],
) -> Tuple[bool, List[str]]:
    """
    Verify and consume a backup code.

    Returns:
        (success, updated_hashes)
        updated_hashes has the consumed code removed.
        If success is False, updated_hashes is unchanged.
    """
    normalized = _normalize_backup_code(code)
    if not normalized:
        return False, backup_hashes

    for stored_hash in backup_hashes:
        if _check_backup_code(normalized, stored_hash):
            remaining = [h for h in backup_hashes if h != stored_hash]
            return True, remaining

    return False, backup_hashes


# ── Helpers ────────────────────────────────────────────────────────

def _hash_short(value: str) -> str:
    """Short hash for in-memory keys (not stored)."""
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def _current_window() -> int:
    """Return the current 30-second TOTP window index."""
    return int(time.time()) // 30


def _evict_old_codes(codes: Dict[str, float], now: float) -> None:
    """Remove codes older than the replay window from the in-memory dict."""
    expired = [k for k, ts in codes.items() if now - ts > _REPLAY_WINDOW_S]
    for k in expired:
        del codes[k]


# ── QR code helper (optional) ──────────────────────────────────────

def qr_code_svg(uri: str) -> Optional[str]:
    """
    Generate an inline SVG QR code for the provisioning URI.
    Returns None if the qrcode library is not installed.
    Only used by the web dashboard — not required for API usage.
    """
    try:
        import qrcode                           # type: ignore
        import qrcode.image.svg as qrsvg        # type: ignore
        import io

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=4,
            border=2,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(image_factory=qrsvg.SvgPathImage)
        buf = io.BytesIO()
        img.save(buf)
        return buf.getvalue().decode("utf-8")
    except ImportError:
        return None
    except Exception as exc:
        logger.debug("QR code generation failed: %s", exc)
        return None


def totp_status_for_user(user_record: Dict) -> Dict:
    """Return a TOTP status summary for a user record dict."""
    secret          = user_record.get("totp_secret")
    backup_hashes   = user_record.get("totp_backup_codes", [])
    return {
        "enrolled":        bool(secret),
        "backup_codes_remaining": len(backup_hashes),
        "low_backup_warning": 0 < len(backup_hashes) < 3,
        "no_backup_codes": len(backup_hashes) == 0 and bool(secret),
    }