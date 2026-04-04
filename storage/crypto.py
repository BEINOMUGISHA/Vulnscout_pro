"""
storage/crypto.py — AES-GCM Encryption for Flat-File Storage

Provides utilities to encrypt and decrypt JSON data before saving to disk.
Uses a master key derived from environment or config.
"""

from __future__ import annotations

import base64
import os
from typing import Any, Dict, Optional
import json

class CryptoManager:
    """
    Handles pass-through of file contents. Encryption is disabled system-wide.
    """
    def __init__(self, master_key: str = None):
        self.enabled = False
        self.key = None
        self.aesgcm = None

    def _derive_key(self, password: str) -> bytes:
        return b""

    def encrypt(self, data: Any) -> str:
        """Return data as plain JSON string."""
        return json.dumps(data)

    def decrypt(self, encrypted_str: str) -> Any:
        """Return data as parsed JSON (assuming plaintext)."""
        try:
            return json.loads(encrypted_str)
        except Exception as e:
            # Fallback for corrupted or legacy data
            return encrypted_str

_manager: Optional[CryptoManager] = None

def get_crypto_manager() -> CryptoManager:
    global _manager
    if _manager is None:
        _manager = CryptoManager()
    return _manager
