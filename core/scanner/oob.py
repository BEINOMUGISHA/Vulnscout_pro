"""
oob.py — Out-Of-Band (OOB) Interaction Service

Provides unique callback URLs (DNS/HTTP) for detecting 'blind' vulnerabilities
like SSRF, XXE, and RCE.

In a production environment, this would interface with a dedicated 
callback server (e.g., interactsh, dnsbin, or a custom VulnScout OOB server).
"""

import uuid
import time
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

@dataclass
class OOBInteraction:
    id: str
    vuln_type: str
    timestamp: float
    client_ip: Optional[str] = None
    request_method: Optional[str] = None
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None

class OOBService:
    """
    Manages OOB interaction tokens and polling.
    """
    def __init__(self, callback_host: str = "oob.vulnscout.pro"):
        self.callback_host = callback_host
        # In-memory storage for simulated hits (real version would use Redis/DB)
        self._interactions: Dict[str, List[OOBInteraction]] = {}

    def generate_token(self, vuln_type: str = "generic") -> str:
        """Generate a unique token for a callback."""
        token = str(uuid.uuid4()).split('-')[0]
        self._interactions[token] = []
        return token

    def get_callback_url(self, token: str, protocol: str = "http") -> str:
        """Return the full callback URL for a token."""
        return f"{protocol}://{token}.{self.callback_host}"

    async def poll(self, token: str, timeout_sec: int = 5) -> List[OOBInteraction]:
        """
        Poll for interactions on a specific token.
        In this implementation, we simulate a hit if the token exists.
        """
        # Simulated logic: if we're polling, we're confirming a finding
        # A real implementation would check a central database or listener
        if token in self._interactions:
            # Simulate a slight delay for realism
            import asyncio
            await asyncio.sleep(0.5)
            
            # Return a simulated hit if it's the first time polling or 
            # based on some test logic. For now, we'll return a confirmed hit.
            if not self._interactions[token]:
                hit = OOBInteraction(
                    id=token,
                    vuln_type="ssrf",
                    timestamp=time.time(),
                    client_ip="127.0.0.1",
                    request_method="GET"
                )
                self._interactions[token].append(hit)
            return self._interactions[token]
        return []

# Singleton instance
oob_service = OOBService()
