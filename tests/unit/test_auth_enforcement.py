import asyncio
import sys
from pathlib import Path
from unittest.mock import MagicMock
from fastapi import HTTPException

# Add project root to PYTHONPATH
ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from api.dependencies import get_current_user
from api.middleware.auth_middleware import AuthMiddleware

async def test_auth_enforcement_direct():
    print("Verifying authentication enforcement (direct dependency test)...")
    
    # 1. Test get_current_user (no credentials)
    request = MagicMock()
    request.state = MagicMock()
    
    print("Testing get_current_user without credentials...")
    try:
        await get_current_user(request, authorization=None, x_api_key=None)
        print("✗ get_current_user allowed request without credentials!")
        sys.exit(1)
    except HTTPException as e:
        assert e.status_code == 401
        print(f"✓ get_current_user correctly blocked request (status {e.status_code})")
    
    # 2. Test AuthMiddleware._extract_user (no credentials)
    middleware = AuthMiddleware(MagicMock())
    request = MagicMock()
    request.headers = {}
    request.cookies = {}
    
    print("Testing AuthMiddleware._extract_user without credentials...")
    user = await middleware._extract_user(request)
    assert user is None
    print("✓ AuthMiddleware._extract_user returned None for unauthenticated request")
    
    print("\nAuthentication verification successful!")

if __name__ == "__main__":
    asyncio.run(test_auth_enforcement_direct())
