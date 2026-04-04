import logging
from typing import Dict, Any
from fastapi import APIRouter
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter()

# In-memory storage for settings
_SETTINGS_DB = {
    "general": {
        "Global Scan Concurrency": 5,
        "Telemetry Retention (Days)": 90,
        "Operational Environment ID": "VULNSCOUT-PRO-PROD-01"
    },
    "security": {
        "Two-Factor Encryption (2FA)": True,
        "Air-Gapped Mode": False
    },
    "api": {
        "Production Gateway": "VS_PRO_AAAAAAAAAAAAAAAA",
        "Analytics Socket": "VS_PRO_BBBBBBBBBBBBBBBB",
        "Compliance Node": "VS_PRO_CCCCCCCCCCCCCCCC"
    },
    "notifications": {
        "Critical Vulnerability": True,
        "Scan Start/Stop": True,
        "Node Offline": True
    }
}

class SettingsUpdate(BaseModel):
    category: str
    settings: Dict[str, Any]

@router.get("")
async def get_settings():
    return {"status": "success", "settings": _SETTINGS_DB}

@router.put("")
async def update_settings(update: SettingsUpdate):
    if update.category in _SETTINGS_DB:
        _SETTINGS_DB[update.category].update(update.settings)
        return {"status": "success", "settings": _SETTINGS_DB}
    return {"status": "error", "message": "Invalid category"}

@router.post("/reset")
async def reset_settings():
    global _SETTINGS_DB
    _SETTINGS_DB = {
        "general": {
            "Global Scan Concurrency": 5,
            "Telemetry Retention (Days)": 90,
            "Operational Environment ID": "VULNSCOUT-PRO-PROD-01"
        },
        "security": {
            "Two-Factor Encryption (2FA)": True,
            "Air-Gapped Mode": False
        },
        "api": {
            "Production Gateway": "VS_PRO_AAAAAAAAAAAAAAAA",
            "Analytics Socket": "VS_PRO_BBBBBBBBBBBBBBBB",
            "Compliance Node": "VS_PRO_CCCCCCCCCCCCCCCC"
        },
        "notifications": {
            "Critical Vulnerability": True,
            "Scan Start/Stop": True,
            "Node Offline": True
        }
    }
    return {"status": "success", "settings": _SETTINGS_DB}
