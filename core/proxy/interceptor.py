"""
core/proxy/interceptor.py — BurpSuite-style Async HTTP Proxy

Responsibilities:
  - Run a lightweight aiohttp web server acting as a forward proxy.
  - Capture all incoming HTTP requests from the user's browser or device.
  - Stream the captured request and response metadata to the frontend UI via WebSockets.
  - Optional support for pausing/blocking requests (Intercept Mode) until manual approval.
"""

import asyncio
import logging
from typing import Dict, Any, Optional
from aiohttp import web, ClientSession

logger = logging.getLogger(__name__)

class TrafficInterceptor:
    """
    An async forward proxy that intercepts HTTP traffic and emits events.
    In the context of VulnScout Pro, this routes target traffic while
    recording it for the 'History' tab or pausing it for the 'Repeater'.
    """
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self.app = web.Application()
        self.runner: Optional[web.AppRunner] = None
        self.session: Optional[ClientSession] = None
        
        # We catch all routes to proxy them
        self.app.router.add_route('*', '/{path_info:.*}', self.handle_request)
        
        # Async queue to broadcast captured traffic to WebSocket clients
        self.traffic_events: asyncio.Queue = asyncio.Queue()
        
        # If true, requests hang until an external signal releases them
        self.intercept_mode: bool = False
        
        # Pending requests awaiting manual approval
        self.pending_requests: Dict[str, asyncio.Event] = {}

    async def start(self) -> None:
        """Start the proxy server."""
        self.session = ClientSession(auto_decompress=False)
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, self.host, self.port)
        await site.start()
        logger.info(f"Burp-style Intercept Proxy started on http://{self.host}:{self.port}")

    async def stop(self) -> None:
        """Stop the proxy server cleanly."""
        if self.runner:
            await self.runner.cleanup()
        if self.session:
            await self.session.close()

    async def handle_request(self, request: web.Request) -> web.StreamResponse:
        """
        Core proxy handler:
        1. Parse incoming request
        2. Wait if intercept mode is ON
        3. Forward request to actual destination
        4. Capture response
        5. Forward response to client
        """
        req_id = id(request)
        target_url = str(request.url)
        
        # The frontend UI itself shouldn't be proxied back through the proxy
        if "localhost:5173" in target_url or "localhost:8000" in target_url:
            return web.Response(status=403, text="Proxy Loop Detected")

        headers = dict(request.headers)
        
        # Strip hop-by-hop headers
        for h in ['Host', 'Cookie', 'Transfer-Encoding', 'Connection']:
            headers.pop(h, None)

        body = await request.read()
        
        req_data = {
            "id": req_id,
            "type": "request",
            "method": request.method,
            "url": target_url,
            "headers": headers,
            "body": body.decode('utf-8', errors='replace') if body else ""
        }
        
        # Push to WS queue for the frontend 'History' tab
        await self.traffic_events.put(req_data)

        # Pause if interception is enabled
        if self.intercept_mode:
            event = asyncio.Event()
            self.pending_requests[str(req_id)] = event
            await event.wait()
            del self.pending_requests[str(req_id)]

        # Forward the request
        try:
            async with self.session.request(
                method=request.method,
                url=target_url,
                headers=headers,
                data=body,
                allow_redirects=False
            ) as resp:
                
                resp_headers = dict(resp.headers)
                resp_body = await resp.read()
                
                resp_data = {
                    "id": req_id,
                    "type": "response",
                    "status": resp.status,
                    "headers": resp_headers,
                    "body": resp_body.decode('utf-8', errors='replace') if resp_body else ""
                }
                
                # Push response to WS queue
                await self.traffic_events.put(resp_data)
                
                # Stream the real response back to the client
                proxy_resp = web.StreamResponse(status=resp.status, headers=resp_headers)
                await proxy_resp.prepare(request)
                if resp_body:
                    await proxy_resp.write(resp_body)
                return proxy_resp
                
        except Exception as e:
            err_data = {
                "id": req_id,
                "type": "error",
                "error": str(e)
            }
            await self.traffic_events.put(err_data)
            return web.Response(status=502, text=f"Bad Gateway: {str(e)}")

# Global singleton so FastAPI routes can access the queue and intercept states
proxy_engine = TrafficInterceptor()
