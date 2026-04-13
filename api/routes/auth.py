"""
api/routes/auth.py — Persistent Authentication Routes

Handles user registration, login (multi-factor), token issuance, and profile management.
Uses the AuthManager orchestrator and persistent SessionStore.
"""

from __future__ import annotations

import logging
import secrets
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Header, Request, status
from pydantic import BaseModel, Field

from auth.auth_manager import LoginResult, TokenPair, UserRecord, create_jwt, decode_jwt
from auth.totp import verify as verify_totp, provisioning_uri, qr_code_svg
from config import get_config
from api.dependencies import get_current_user, AuthenticatedUser

logger = logging.getLogger(__name__)
audit = logging.getLogger("vulnscout.audit")
router = APIRouter()

# ── Request / Response models ──────────────────────────────────────────────────

class LoginRequest(BaseModel):
    """Initial login with credentials."""
    email: str = Field(..., min_length=5, max_length=254)
    password: str = Field(..., min_length=1, max_length=256)

class SignupRequest(BaseModel):
    """User registration request."""
    email: str = Field(..., min_length=5, max_length=254)
    password: str = Field(..., min_length=8, max_length=256)
    name: str = Field(..., min_length=2, max_length=100)

class TOTPVerifyRequest(BaseModel):
    """Verify TOTP code to complete login."""
    login_token: str = Field(..., min_length=20)
    code: str = Field(..., min_length=6, max_length=8, pattern=r"^\d{6,8}$")

class TokenResponse(BaseModel):
    """JWT token response."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class UserResponse(BaseModel):
    """Current user profile."""
    user_id: str
    email: str
    name: str
    role: str
    totp_verified: bool

class LoginResponse(BaseModel):
    """Initial login response. Can be MFA-pending or full success."""
    access_token: str | None = None
    refresh_token: str | None = None
    expires_in: int | None = None
    user: UserResponse | None = None
    login_token: str | None = None  # Temporary token for MFA
    totp_required: bool = False
    message: str = "Success"


class PasswordResetRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=254)


class PasswordResetCompleteRequest(BaseModel):
    token: str = Field(..., min_length=20)
    password: str = Field(..., min_length=8, max_length=256)

# ── Auth Header Helper ─────────────────────────────────────────────────────────

async def _get_token_from_header(
    authorization: str | None = Header(None),
) -> str:
    """Extract Bearer token from Authorization header."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format",
        )

    return parts[1]

# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/login", response_model=LoginResponse, tags=["auth"])
async def login(req: LoginRequest, request: Request) -> LoginResponse:
    """
    Step 1: Validate email + password. Returns a temporary login token.
    """
    auth_manager = request.app.state.auth
    result = await auth_manager.login(
        email=req.email,
        password=req.password,
        ip_address=request.client.host if request.client else "127.0.0.1"
    )

    if not result.success:
        if result.error_code == "lockout":
            raise HTTPException(status_code=403, detail=result.error)
        raise HTTPException(status_code=401, detail=result.error or "Invalid credentials")

    # If TOTP is required, return the partial state
    if result.totp_required:
        return LoginResponse(
            login_token=result.access_token, # Temporary token for TOTP verify
            totp_required=True,
            message="TOTP code required to complete login"
        )

    # Success (Non-MFA)
    return LoginResponse(
        access_token=result.access_token,
        refresh_token=result.refresh_token,
        expires_in=result.expires_in,
        user=UserResponse(
            user_id=result.user_id,
            email=req.email,
            name=req.email.split("@")[0].title(),
            role=result.role or "analyst",
            totp_verified=False
        ),
        totp_required=False,
        message="Login successful"
    )

@router.post("/signup", tags=["auth"])
async def signup(req: SignupRequest, request: Request):
    """
    Register a new user and return TOTP enrollment data.
    """
    auth_manager = request.app.state.auth
    
    try:
        user = await auth_manager.create_user(
            email=req.email,
            password=req.password,
            full_name=req.name,
            role="analyst",
            actor_id="self_signup"
        )
        
        # Begin TOTP enrollment
        enrollment = await auth_manager.begin_totp_enrollment(user.user_id, user.email)
        
        # Generate SVG QR code
        svg = qr_code_svg(enrollment.provisioning_uri)
        
        audit.info("New persistent user registered: %s", req.email)

        return {
            "message": "User registered successfully. Scan the QR code to finish setup.",
            "user_id": user.user_id,
            "login_token": await session_store.create_token(user.user_id, ttl_seconds=600),
            "totp_secret": enrollment.secret,
            "provisioning_uri": enrollment.provisioning_uri,
            "qr_svg": svg
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/totp/verify", response_model=TokenResponse, tags=["auth"])
async def totp_verify(req: TOTPVerifyRequest, request: Request) -> TokenResponse:
    """
    Verify TOTP code and return JWT access token.
    """
    auth_manager = request.app.state.auth
    session_store = request.app.state.session_store
    config = get_config()

    # 1. Validate temporary login token to get user_id
    user_id = await session_store.verify_token(req.login_token)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired login token")

    # 2. Get user record to check TOTP secret
    user_record = await session_store.get_user(user_id)
    if not user_record or not user_record.get("totp_secret"):
        raise HTTPException(status_code=401, detail="2FA not configured for this user")

    # 3. Verify TOTP code
    is_valid = verify_totp(req.code, user_record["totp_secret"])
    if not is_valid:
        audit.warning("Invalid TOTP code for user %s", user_id)
        raise HTTPException(status_code=401, detail="Invalid TOTP code")

    # 4. Issue full JWT tokens
    expire_secs = config.auth.jwt_access_expire_min * 60
    access_token = create_jwt(
        user_id=user_id,
        email=user_record["email"],
        role=user_record["role"],
        expires_in_seconds=expire_secs
    )

    # 5. Invalidate the temporary login token
    await session_store.invalidate_token(req.login_token)

    audit.info("User %s successfully authenticated with 2FA", user_record["email"])

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expire_secs
    )

@router.get("/me", response_model=UserResponse, tags=["auth"])
async def get_me(user: AuthenticatedUser = Depends(get_current_user)) -> UserResponse:
    """
    Get current authenticated user profile.
    """
    return UserResponse(
        user_id=user.user_id,
        email=user.email,
        name=user.email.split("@")[0].title(), # Fallback since name isn't in AuthenticatedUser
        role=user.role,
        totp_verified=True
    )

@router.post("/logout", tags=["auth"])
async def logout(request: Request, token: str = Depends(_get_token_from_header)) -> dict:
    """
    Invalidate the current token.
    """
    session_store = request.app.state.session_store
    await session_store.invalidate_token(token)
    audit.info("User logged out")
    return {"message": "Logged out successfully"}


@router.post("/password/reset-request", tags=["auth"])
async def password_reset_request(req: PasswordResetRequest, request: Request):
    """
    Step 1: Request a password reset. Returns a token (simulates email dispatch).
    """
    auth_manager = request.app.state.auth
    token = await auth_manager.request_password_reset(
        email=req.email,
        ip_address=request.client.host if request.client else "127.0.0.1"
    )
    # Simulation: always return success to prevent enumeration, but include token for dev
    return {
        "message": "Operational override initiated. Check secure comms for reset token.",
        "dev_token": token if request.app.state.config.app.debug else None
    }


@router.post("/password/reset-complete", tags=["auth"])
async def password_reset_complete(req: PasswordResetCompleteRequest, request: Request):
    """
    Step 2: Complete password reset using the token.
    """
    auth_manager = request.app.state.auth
    success = await auth_manager.complete_password_reset(
        raw_token=req.token,
        new_password=req.password
    )
    if not success:
        raise HTTPException(
            status_code=400, 
            detail="Override sequence expired or invalid. Authorization denied."
        )
    return {"message": "Access restored. New credentials synchronized."}

@router.post("/dev-login", response_model=TokenResponse, tags=["auth"])
async def dev_login(request: Request) -> TokenResponse:
    """
    ⚠️ DEVELOPMENT ONLY — Auth Bypass
    """
    config = get_config()
    if not config.app.debug:
        raise HTTPException(status_code=403, detail="Dev login only available in debug mode")
    
    auth_manager = request.app.state.auth
    # Use a fixed dev user ID
    user_id = "dev-operative-007"
    email = "dev@vulnscout.local"
    role = "admin"

    expire_secs = config.auth.jwt_access_expire_min * 60
    jwt_token = create_jwt(
        user_id=user_id,
        email=email,
        role=role,
        expires_in_seconds=expire_secs
    )
    
    return TokenResponse(
        access_token=jwt_token,
        token_type="bearer",
        expires_in=expire_secs
    )

@router.post("/refresh", response_model=TokenResponse, tags=["auth"])
async def refresh(user: AuthenticatedUser = Depends(get_current_user)) -> TokenResponse:
    """
    Refresh the current JWT access token.
    """
    config = get_config()
    expire_secs = config.auth.jwt_access_expire_min * 60
    new_token = create_jwt(
        user_id=user.user_id,
        email=user.email,
        role=user.role,
        expires_in_seconds=expire_secs,
    )

    return TokenResponse(
        access_token=new_token,
        token_type="bearer",
        expires_in=expire_secs,
    )
