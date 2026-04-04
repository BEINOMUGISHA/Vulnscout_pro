"""
api/routes/proxy.py — WebSockets and Config for Intercept Proxy

Exposes an endpoint to toggle intercept mode and a WebSocket stream
to push HTTP traffic data to the frontend Repeater/History.
"""

import asyncio
import logging
from typing import Dict, Any

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from core.proxy.engine import proxy_engine
from api.dependencies import get_current_user, AuthenticatedUser

router = APIRouter(tags=["proxy"])
logger = logging.getLogger(__name__)

class ProxyModeRequest(BaseModel):
    intercept_enabled: bool


@router.post("/mode", status_code=200)
async def set_proxy_mode(
    request: ProxyModeRequest,
    current_user: AuthenticatedUser = Depends(get_current_user)
) -> Dict[str, Any]:
    """Enable or disable interception. When enabled, requests hang."""
    proxy_engine.intercept_mode = request.intercept_enabled
    logger.warning(f"User {current_user.email} toggled Intercept Mode: {proxy_engine.intercept_mode}")
    return {"status": "success", "intercept_mode": proxy_engine.intercept_mode}


@router.post("/forward/{request_id}", status_code=200)
async def forward_intercepted_request(
    request_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user)
) -> Dict[str, str]:
    """Release a paused request in the intercept queue."""
    if request_id in proxy_engine.pending_requests:
        event = proxy_engine.pending_requests[request_id]
        event.set()
        return {"status": "forwarded", "id": request_id}
    return {"status": "not_found", "id": request_id}


@router.post("/drop/{request_id}", status_code=200)
async def drop_intercepted_request(
    request_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user)
) -> Dict[str, str]:
    """Drop a paused request in the intercept queue (don't forward it)."""
    if request_id in proxy_engine.pending_requests:
        proxy_engine.drop_request(request_id)
        return {"status": "dropped", "id": request_id}
    return {"status": "not_found", "id": request_id}


@router.get("/status", status_code=200)
async def get_proxy_status(
    current_user: AuthenticatedUser = Depends(get_current_user)
) -> Dict[str, Any]:
    """Get current intercept mode and pending count."""
    return {
        "status": "success",
        "intercept_mode": proxy_engine.intercept_mode,
        "pending_count": len(proxy_engine.pending_requests)
    }


@router.get("/ca-cert", status_code=200)
async def download_ca_certificate(
    current_user: AuthenticatedUser = Depends(get_current_user)
):
    """Download the ProxyEngine root CA certificate for browser installation."""
    from fastapi.responses import Response
    ca_pem = proxy_engine.get_ca_cert_pem()
    return Response(
        content=ca_pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": 'attachment; filename="vulnscout-ca.crt"'},
    )


@router.get("/credentials", status_code=200)
async def get_captured_credentials(
    current_user: AuthenticatedUser = Depends(get_current_user)
) -> Dict[str, Any]:
    """Retrieve auth tokens captured by the proxy for use in authenticated scans."""
    return {
        "status": "success",
        "count": len(proxy_engine.captured_credentials),
        "credentials": proxy_engine.captured_credentials,
    }


@router.delete("/credentials", status_code=200)
async def clear_captured_credentials(
    current_user: AuthenticatedUser = Depends(get_current_user)
) -> Dict[str, str]:
    """Wipe the captured credential store."""
    proxy_engine.captured_credentials.clear()
    return {"status": "cleared"}


@router.get("/payloads", status_code=200)
async def get_repeater_payloads(
    current_user: AuthenticatedUser = Depends(get_current_user)
) -> Dict[str, Any]:
    """Retrieve specialized EA Fintech payloads for the Repeater."""
    import json
    import os
    payload_file = os.path.join(os.path.dirname(__file__), "..", "..", "core", "detection", "payloads", "ea_fintech.json")
    try:
        with open(payload_file, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load ea_fintech.json: {e}")
        return {"categories": {}}

class RepeaterRequest(BaseModel):
    method: str
    url: str
    headers: Dict[str, str] = {}
    body: str = ""

@router.post("/repeater", status_code=200)
async def execute_repeater_request(
    request: RepeaterRequest,
    current_user: AuthenticatedUser = Depends(get_current_user)
) -> Dict[str, Any]:
    """Execute a manual payload injection from the Repeater UI."""
    import aiohttp
    
    # In a real Burp setting, we ignore TLS checks for manual hacking
    connector = aiohttp.TCPConnector(ssl=False)
    
    # Strip local proxy headers if any existed
    headers = {k: v for k, v in request.headers.items() if k.lower() not in ['host', 'connection', 'accept-encoding']}
    
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.request(
                method=request.method,
                url=request.url,
                headers=headers,
                data=request.body,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
                resp_headers = dict(resp.headers)
                resp_body = await resp.read()
                
                return {
                    "status": resp.status,
                    "headers": resp_headers,
                    "body": resp_body.decode('utf-8', errors='replace') if resp_body else ""
                }
    except Exception as e:
        logger.error(f"Repeater execution failed for {request.url}: {e}")
        from fastapi import HTTPException
        raise HTTPException(status_code=502, detail=f"Repeater Target Error: {str(e)}")


@router.websocket("/ws")
async def proxy_websocket_endpoint(websocket: WebSocket):
    """
    Stream live proxy traffic to the connected frontend.
    Accepts generic WebSocket connections for the Repeater UI.
    Requires ?token=xxxx in query params.
    """
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008)
        return
        
    await websocket.accept()
    logger.info("Repeater UI connected to Proxy Event Stream.")
    
    # Send current proxy state immediately
    await websocket.send_json({
        "type": "state",
        "intercept_mode": proxy_engine.intercept_mode
    })

    try:
        while True:
            # Poll the aiohttp proxy queue for new traffic
            event_data = await proxy_engine.traffic_events.get()
            await websocket.send_json(event_data)
            
    except WebSocketDisconnect:
        logger.info("Repeater UI disconnected from Proxy Event Stream.")
    except Exception as e:
        logger.error(f"Proxy WebSocket Error: {e}")
        try:
            await websocket.close()
        except:
            pass
