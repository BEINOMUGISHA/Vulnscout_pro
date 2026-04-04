"""
api/routes/webhooks.py — Webhook Management Routes

Endpoints:
  GET    /webhooks              — list all configured webhooks
  POST   /webhooks              — create a new webhook
  GET    /webhooks/{webhook_id} — get webhook detail
  PUT    /webhooks/{webhook_id} — update webhook
  DELETE /webhooks/{webhook_id} — delete a webhook
  POST   /webhooks/{webhook_id}/ping — test a webhook
"""

from __future__ import annotations

import logging
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, HttpUrl

from api.dependencies import (
    AuthenticatedUser, get_scan_store, require_admin,
)

logger = logging.getLogger(__name__)
router = APIRouter()


# ── Request / Response models ──────────────────────────────────────────────────

class WebhookRequest(BaseModel):
    url:        HttpUrl
    name:       str = Field(..., min_length=1, max_length=100)
    secret:     Optional[str] = Field(None, max_length=128)
    enabled:    bool = True
    events:     List[str] = Field(default_factory=lambda: ["scan_complete", "finding_detected"])


class WebhookResponse(BaseModel):
    id:         str
    url:        str
    name:       str
    enabled:    bool
    events:     List[str]


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.get("", response_model=List[WebhookResponse])
async def list_webhooks(
    user: AuthenticatedUser = Depends(require_admin),
    scan_store = Depends(get_scan_store),
):
    """List all global webhook configurations. Admin only."""
    return await scan_store.list_webhooks()


@router.post("", status_code=201, response_model=WebhookResponse)
async def create_webhook(
    body: WebhookRequest,
    user: AuthenticatedUser = Depends(require_admin),
    scan_store = Depends(get_scan_store),
):
    """Create a new outbound webhook."""
    webhooks = await scan_store.list_webhooks()
    
    new_wh = {
        "id": str(uuid.uuid4()),
        "url": str(body.url),
        "name": body.name,
        "secret": body.secret,
        "enabled": body.enabled,
        "events": body.events,
    }
    
    webhooks.append(new_wh)
    await scan_store.save_webhooks(webhooks)
    
    logger.info("Webhook %s created by admin %s", new_wh["id"], user.user_id)
    return new_wh


@router.get("/{webhook_id}", response_model=WebhookResponse)
async def get_webhook(
    webhook_id: str,
    user: AuthenticatedUser = Depends(require_admin),
    scan_store = Depends(get_scan_store),
):
    """Get webhook details."""
    webhooks = await scan_store.list_webhooks()
    for wh in webhooks:
        if wh["id"] == webhook_id:
            return wh
    raise HTTPException(404, "Webhook not found")


@router.put("/{webhook_id}", response_model=WebhookResponse)
async def update_webhook(
    webhook_id: str,
    body: WebhookRequest,
    user: AuthenticatedUser = Depends(require_admin),
    scan_store = Depends(get_scan_store),
):
    """Update an existing webhook."""
    webhooks = await scan_store.list_webhooks()
    found = False
    updated = None
    
    for i, wh in enumerate(webhooks):
        if wh["id"] == webhook_id:
            webhooks[i].update({
                "url": str(body.url),
                "name": body.name,
                "secret": body.secret,
                "enabled": body.enabled,
                "events": body.events,
            })
            updated = webhooks[i]
            found = True
            break
            
    if not found:
        raise HTTPException(404, "Webhook not found")
        
    await scan_store.save_webhooks(webhooks)
    return updated


@router.delete("/{webhook_id}", status_code=204)
async def delete_webhook(
    webhook_id: str,
    user: AuthenticatedUser = Depends(require_admin),
    scan_store = Depends(get_scan_store),
):
    """Delete a webhook."""
    webhooks = await scan_store.list_webhooks()
    webhooks = [wh for wh in webhooks if wh["id"] != webhook_id]
    await scan_store.save_webhooks(webhooks)
    logger.info("Webhook %s deleted by admin %s", webhook_id, user.user_id)


@router.post("/{webhook_id}/ping")
async def ping_webhook(
    webhook_id: str,
    user: AuthenticatedUser = Depends(require_admin),
    scan_store = Depends(get_scan_store),
):
    """Send a test ping to the webhook URL."""
    webhooks = await scan_store.list_webhooks()
    wh = next((w for w in webhooks if w["id"] == webhook_id), None)
    if not wh:
        raise HTTPException(404, "Webhook not found")
        
    from core.integrations.notifications import NotificationDispatcher
    dispatcher = NotificationDispatcher()
    
    test_data = {
        "event": "webhook_ping",
        "webhook_id": webhook_id,
        "message": "VulnScout Pro Webhook Test"
    }
    
    try:
        await dispatcher._ensure_session()
        await dispatcher._send_webhook(wh, test_data)
        await dispatcher.close()
        return {"status": "success", "message": "Ping sent successfully"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
