# VulnScout Pro — No-Database, 2FA Mode

## Overview

This is a **single-user, no-database, in-memory** version of VulnScout Pro optimized for:
- ✅ **Single hardcoded user** with demo credentials
- ✅ **TOTP 2FA** requirement (Google Authenticator, Authy, Microsoft Authenticator, etc.)
- ✅ **Ephemeral data** — all scans/reports lost on server restart
- ✅ **Zero persistence** — no database, no filesystem writes
- ✅ **Fast startup** — minimal dependencies
- ✅ **Security-first** — JWT tokens + 2FA validation

## Architecture

```
Frontend (React)            Backend (FastAPI - No-DB Mode)
   ↓                                ↓
localhost:3000      ←→      localhost:8000
   War Room UI               In-Memory Session Store
 (demo attacks)              └─ Demo User (TOTP verified)
                             └─ Detector Registry
                             └─ Scanner Engine (RAM only)
```

## Demo Credentials

| Field | Value |
|-------|-------|
| Email | `demo@vulnscout.local` |
| Password | `demo123456` |
| TOTP Secret | `JBSWY3DPEBLW64TMMQ======` (well-known seed for testing) |

**TOTP Codes** (use a TOTP app or generator):
- Install: Google Authenticator, Authy, or similar
- Add manual entry with: `JBSWY3DPEBLW64TMMQ======`
- Get 6-digit codes every 30 seconds

## Auth Flow

### 1. Login (POST /auth/login)
```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "demo@vulnscout.local",
    "password": "demo123456"
  }'
```

**Response:**
```json
{
  "login_token": "...",
  "totp_required": true,
  "message": "TOTP code required to complete login"
}
```

### 2. Verify TOTP (POST /auth/totp/verify)
```bash
curl -X POST http://localhost:8000/auth/totp/verify \
  -H "Content-Type: application/json" \
  -d '{
    "login_token": "...",
    "code": "123456"    # 6-digit TOTP code
  }'
```

**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

### 3. Use Access Token
```bash
curl -X GET http://localhost:8000/auth/me \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc..."
```

## Data Storage

| Data Type | Storage | Lifespan |
|-----------|---------|----------|
| Active Sessions | In-Memory Dict | Until logout or expiry |
| JWT Tokens | In-Memory Dict | Until expiry (1 hour default) |
| Scan Data | In-Memory Dict on `app.state.scans` | Until server restart |
| Findings | In-Memory Dict on `app.state.findings` | Until server restart |
| Events | In-Memory Dict on `app.state.events` | Until server restart |

**No Persistence ⚠️**
- All data is lost when the server restarts
- This is by design for security + simplicity
- Perfect for demos, testing, and CI/CD pipelines

## System Requirements

```bash
# Python dependencies
pip install -r requirements/prod.txt

# Key packages
- fastapi
- uvicorn
- pydantic
- PyJWT
- pyotp (for TOTP)
```

## Running the Server

```bash
# Activate venv (Windows)
venv\Scripts\Activate.ps1

# Start server
uvicorn api.main:app --reload --port 8000
```

**Expected Startup Logs:**
```
INFO:     VulnScout Pro X.X.X starting up [env=development] — NO DATABASE MODE
INFO:     In-memory session store initialized (demo user: demo@vulnscout.local)
INFO:     Loaded 14 detection modules
INFO:     VulnScout Pro ready — listening on port 8000 (NO-DB MODE)
```

## Key Classes

### `auth/session_memory.py`
- `InMemorySessionStore` — stores active tokens + TOTP secrets
- `SessionToken` — JWT token record with expiry
- `SessionState` — user session with 2FA status

### `auth/jwt_helpers.py`
- `create_jwt()` — issue access tokens
- `decode_jwt()` — validate tokens

### `api/routes/auth.py`
Simplified endpoints:
- `POST /auth/login` — password → login_token
- `POST /auth/totp/verify` — login_token + TOTP code → access_token
- `GET /auth/me` — return user profile
- `POST /auth/logout` — invalidate token

### `api/main.py`
Updated lifespan:
- ✅ Initializes `InMemorySessionStore`
- ✅ Initializes detector registry
- ✅ Skips all persistent storage
- ✅ Skips scan scheduler
- ✅ No data persistence on shutdown

## Frontend Integration

The React frontend connects via:
1. **Login Page** → `POST /auth/login`
2. **TOTP Verification** → `POST /auth/totp/verify`
3. **Get Token** → Store JWT in localStorage
4. **Authenticated Requests** → `Authorization: Bearer {token}`

Example:
```javascript
// 1. Login
const loginRes = await fetch('http://localhost:8000/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'demo@vulnscout.local',
    password: 'demo123456'
  })
});
const { login_token } = await loginRes.json();

// 2. Verify TOTP
const totpRes = await fetch('http://localhost:8000/auth/totp/verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    login_token,
    code: '123456'  // from TOTP app
  })
});
const { access_token } = await totpRes.json();
localStorage.setItem('token', access_token);

// 3. Use token
const meRes = await fetch('http://localhost:8000/auth/me', {
  headers: { 'Authorization': `Bearer ${access_token}` }
});
```

## Configuration

No configuration needed! All settings are hardcoded for demo mode:
- Demo password: `demo123456` (from config.auth.demo_password)
- TOTP Window: ±30 seconds (from config.auth.totp_window)
- JWT Expire: 1 hour (from config.auth.jwt_access_expire_min)

To change demo password, edit `config/base.py` or `config/development.py`:
```python
class DevelopmentAuthConfig:
    demo_password = "your-new-password"
```

## Security Considerations

| Security Feature | Status | Details |
|------------------|--------|---------|
| **Password** | ✅ Checked on login | Constant-time verification |
| **2FA (TOTP)** | ✅ Required | RFC 6238 compliant |
| **JWT Tokens** | ✅ Signed | HS256 with app secret key |
| **Token Expiry** | ✅ Enforced | 1 hour access, auto-invalidate |
| **User Isolation** | ✅ Single user | No multi-user concerns |
| **Database** | ❌ None | All in-memory (no SQL injection) |
| **Persistence** | ❌ None | Data lost on restart (ok for demo) |

## Testing

### 1. Test Login
```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"demo@vulnscout.local","password":"demo123456"}'
```

### 2. Get a TOTP Code
Using `pyotp`:
```python
import pyotp
secret = "JBSWY3DPEBLW64TMMQ======"
totp = pyotp.TOTP(secret)
print(totp.now())  # 6-digit code, changes every 30s
```

### 3. test TOTP Verify
```bash
curl -X POST http://localhost:8000/auth/totp/verify \
  -H "Content-Type: application/json" \
  -d '{
    "login_token": "...",
    "code": "123456"
  }'
```

### 4. Test /auth/me
```bash
curl -X GET http://localhost:8000/auth/me \
  -H "Authorization: Bearer {access_token}"
```

## Troubleshooting

**"TOTP not configured"**
- Demo user TOTP secret not initialized
- Check `auth/session_memory.py` — `DEMO_TOTP_SECRET` defined?

**"Invalid TOTP code"**
- Time sync issue (client ≠ server clock)
- Check system time on both machines
- TOTP has ±30s tolerance

**"Invalid or expired login token"**
- Login token expires in 5 minutes
- Restart login flow

**"JWT not installed"**
- Run: `pip install PyJWT`

**"pyotp not installed"**
- Run: `pip install pyotp`

## What's Not Included

❌ User registration  
❌ Password reset  
❌ API key management  
❌ Role-based access (single admin user)  
❌ Audit logging  
❌ Database persistence  
❌ Multi-user support  
❌ Rate limiting per user  
❌ Sessions table  
❌ Refresh tokens  

## Future Enhancements

If you need persistence, use the original `/storage/` implementation:
1. Restore `storage/session_store.py`
2. Restore `storage/scan_store.py`
3. Update `api/main.py` lifespan
4. Add user registration endpoint
5. Add role-based security

## Next Steps

1. ✅ Start backend: `uvicorn api.main:app --reload --port 8000`
2. ✅ Start frontend: `cd frontend && npm run dev` (port 3000)
3. ✅ Open browser: http://localhost:3000
4. ✅ Login with credentials above
5. ✅ Use War Room UI for demo attacks

---

**Created**: February 2026  
**Mode**: No-Database, Single-User, TOTP 2FA
