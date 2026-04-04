"""
auth/jwt_helpers.py — Simple JWT creation and decoding

Used by the simplified no-DB auth routes.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, Optional
import uuid

from auth.rbac import rbac


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
