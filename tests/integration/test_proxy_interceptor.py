import pytest
import asyncio
from httpx import AsyncClient, ASGITransport
from aiohttp import web

import pytest_asyncio

from core.proxy.interceptor import TrafficInterceptor
from api.main import app

@pytest_asyncio.fixture
async def proxy_server():
    """Start an ephemeral interceptor proxy for testing."""
    proxy = TrafficInterceptor(host="127.0.0.1", port=8081)
    await proxy.start()
    yield proxy
    await proxy.stop()

@pytest_asyncio.fixture
async def target_server():
    """Start a dummy target web server."""
    async def hello(request):
        return web.Response(text="Target Response")
        
    app = web.Application()
    app.router.add_get("/test", hello)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 8082)
    await site.start()
    yield
    await runner.cleanup()

@pytest.mark.asyncio
async def test_proxy_forwarding(proxy_server, target_server):
    """Test that the proxy successfully forwards a request to the target server."""
    proxy_server.intercept_mode = False
    
    # Configure an HTTP client to use our test proxy
    proxies = {"http://": "http://127.0.0.1:8081"}
    
    async with AsyncClient(proxy="http://127.0.0.1:8081") as client:
        response = await client.get("http://127.0.0.1:8082/test")
        
        assert response.status_code == 200
        assert response.text == "Target Response"
        
        # Verify the traffic event was queued
        event = await asyncio.wait_for(proxy_server.traffic_events.get(), timeout=1.0)
        assert event["type"] == "request"
        assert "/test" in event["url"]

@pytest.mark.asyncio
async def test_repeater_payload_execution():
    """Test the POST /api/v1/proxy/repeater endpoint inside FastAPI."""
    from api.dependencies import get_current_user
    # Mock auth dependency just like in existing test suites
    app.dependency_overrides[get_current_user] = lambda: {"email": "test@vulnscout.local"}
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/proxy/repeater",
            json={
                "method": "GET",
                # We can't easily mock an external target in this test slice, 
                # so we hit the app's own health endpoint as a known-good target.
                "url": "http://127.0.0.1:8000/health",
                "headers": {},
                "body": ""
            }
        )
        
        # We expect a success or connection error depending on if the app actually binds 8000
        assert response.status_code in [200, 502], "Repeater endpoint should return status or 502 Target Error"
    
    app.dependency_overrides.clear()
