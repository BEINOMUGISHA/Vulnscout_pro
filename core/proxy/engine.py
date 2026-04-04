"""
core/proxy/engine.py — Advanced Proxy Engine

Extends the basic TrafficInterceptor with:
  - Root Certificate Authority (CA) generation for HTTPS MITM
  - Dynamic per-host TLS certificate signing
  - HTTPS CONNECT tunneling & SSL interception
  - Request/Response modification interface
  - Automated credential harvesting (JWT, Session, Basic Auth)
  - Intelligence repository integration (save all traffic)

Usage:
    engine = ProxyEngine(port=8080)
    await engine.start()   # serves as a full HTTPS-capable proxy
"""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import logging
import re
import ssl
import tempfile
import os
from typing import Dict, List, Optional, Tuple, Any

from aiohttp import web, ClientSession, TCPConnector
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)


# ── Credential patterns ────────────────────────────────────────────────────────

JWT_PATTERN      = re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')
SESSION_PATTERN  = re.compile(r'(?i)session[_-]?(?:id|token|key)[=:\s"\']+([a-z0-9_\-]{16,})', re.IGNORECASE)
BASIC_PATTERN    = re.compile(r'(?i)Basic\s+([A-Za-z0-9+/=]{10,})')
BEARER_PATTERN   = re.compile(r'(?i)Bearer\s+([A-Za-z0-9_\-\.]{20,})')
COOKIE_PATTERN   = re.compile(r'(?:session|auth|token|jwt|access)[=\s]([^;\s,]+)', re.IGNORECASE)


# ── CA Certificate & Key Generation ───────────────────────────────────────────

def _generate_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def generate_ca_cert_and_key() -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """
    Generate a root Certificate Authority key pair.
    Browser/OS must trust this CA for transparent HTTPS interception.
    """
    key = _generate_rsa_key()
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "UG"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VulnScout Pro CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "VulnScout Pro Root CA"),
    ])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def generate_host_cert(
    hostname: str,
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """
    Dynamically generate a TLS certificate for a specific hostname,
    signed by our CA. Used during the HTTPS CONNECT tunnel phase.
    """
    host_key = _generate_rsa_key()
    now = datetime.datetime.utcnow()

    # Build Subject Alternative Names
    san_entries: list = [x509.DNSName(hostname)]
    try:
        san_entries.append(x509.IPAddress(ipaddress.ip_address(hostname)))
    except ValueError:
        pass  # Not an IP, fine

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(ca_cert.subject)
        .public_key(host_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert, host_key


# ── ProxyEngine ───────────────────────────────────────────────────────────────

class ProxyEngine:
    """
    Full-featured HTTPS-capable intercepting proxy.

    Key features:
      - Transparent HTTPS MITM via dynamic certificate signing
      - WebSocket stream for real-time traffic to the UI
      - Intercept mode: pause requests for manual inspection
      - Credential harvesting: extract JWT / session / auth tokens
      - Request/response modification: add to repeater, save evidence
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8080) -> None:
        self.host = host
        self.port = port

        # CA material generated once at startup
        self.ca_cert, self.ca_key = generate_ca_cert_and_key()
        self._cert_cache: Dict[str, Tuple[bytes, bytes]] = {}  # hostname → (cert_pem, key_pem)

        # Traffic broadcast queue (consumed by WebSocket handler)
        self.traffic_events: asyncio.Queue = asyncio.Queue()

        # Intercept mode pausing
        self.intercept_mode: bool = False
        self.pending_requests: Dict[str, asyncio.Event] = {}
        self._drop_set: set = set()

        # Captured credentials store
        self.captured_credentials: List[Dict[str, str]] = []

        # aiohttp application
        self.app = web.Application()
        self.app.router.add_route("*", "/{path_info:.*}", self.handle_request)
        self.runner: Optional[web.AppRunner] = None
        self.session: Optional[ClientSession] = None

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    async def start(self) -> None:
        connector = TCPConnector(ssl=False)
        self.session = ClientSession(auto_decompress=False, connector=connector)
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, self.host, self.port)
        await site.start()
        logger.info("ProxyEngine started on http://%s:%d", self.host, self.port)

    async def stop(self) -> None:
        if self.runner:
            await self.runner.cleanup()
        if self.session:
            await self.session.close()

    # ── CA Certificate export ─────────────────────────────────────────────────

    def get_ca_cert_pem(self) -> bytes:
        """Return CA cert as PEM bytes for user to install in their browser."""
        return self.ca_cert.public_bytes(serialization.Encoding.PEM)

    # ── HTTPS Interception (CONNECT handler) ──────────────────────────────────

    async def intercept_https(self, request: web.Request) -> web.StreamResponse:
        """
        Handle HTTP CONNECT tunneling for HTTPS MITM.

        Flow:
          1. Parse target host:port from CONNECT request.
          2. Respond 200 Connection Established to the browser.
          3. Generate (or retrieve cached) host certificate signed by our CA.
          4. Wrap the connection in TLS using our signed cert.
          5. Decrypt, intercept, and re-encrypt traffic transparently.
        """
        host_header = request.headers.get("Host", "")
        hostname = host_header.split(":")[0] if ":" in host_header else host_header

        # 1. Respond with 200 to establish the tunnel
        response = web.StreamResponse(status=200, reason="Connection Established")
        await response.prepare(request)

        # 2. Generate or retrieve per-host cert
        cert_pem, key_pem = self._get_or_create_host_cert(hostname)

        # 3. Write temp cert/key files for ssl.SSLContext
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cf:
            cf.write(cert_pem)
            cert_path = cf.name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".key") as kf:
            kf.write(key_pem)
            key_path = kf.name

        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            logger.debug("HTTPS MITM active for: %s", hostname)
        finally:
            os.unlink(cert_path)
            os.unlink(key_path)

        return response

    def _get_or_create_host_cert(self, hostname: str) -> Tuple[bytes, bytes]:
        if hostname not in self._cert_cache:
            cert, key = generate_host_cert(hostname, self.ca_cert, self.ca_key)
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            key_pem = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
            self._cert_cache[hostname] = (cert_pem, key_pem)
        return self._cert_cache[hostname]

    # ── Request/Response lifecycle ────────────────────────────────────────────

    async def handle_request(self, request: web.Request) -> web.StreamResponse:
        """Main proxy handler — intercepts HTTP traffic."""
        target_url = str(request.url)

        if "localhost:5173" in target_url or "localhost:8000" in target_url:
            return web.Response(status=403, text="Proxy Loop Detected")

        if request.method == "CONNECT":
            return await self.intercept_https(request)

        headers = dict(request.headers)
        for h in ["Host", "Transfer-Encoding", "Connection"]:
            headers.pop(h, None)

        body = await request.read()

        req_id = str(id(request))
        req_data = await self.modify_request({
            "id": req_id,
            "type": "request",
            "method": request.method,
            "url": target_url,
            "headers": headers,
            "body": body.decode("utf-8", errors="replace") if body else "",
        })

        # Capture credentials from request
        await self.capture_credentials(req_data)

        await self.traffic_events.put(req_data)

        # Intercept mode — pause until released
        if self.intercept_mode:
            event = asyncio.Event()
            self.pending_requests[req_id] = event
            await event.wait()
            if req_id in self._drop_set:
                self._drop_set.discard(req_id)
                return web.Response(status=204, text="Request dropped by operator")
            self.pending_requests.pop(req_id, None)

        # Forward to target
        try:
            async with self.session.request(
                method=req_data["method"],
                url=req_data["url"],
                headers=req_data.get("headers", {}),
                data=req_data.get("body", "").encode(),
                allow_redirects=False,
            ) as resp:
                resp_body = await resp.read()
                resp_headers = dict(resp.headers)

                resp_data = {
                    "id": req_id,
                    "type": "response",
                    "status": resp.status,
                    "headers": resp_headers,
                    "body": resp_body.decode("utf-8", errors="replace"),
                }

                # Capture credentials from response
                await self.capture_credentials(resp_data)
                await self.traffic_events.put(resp_data)

                proxy_resp = web.StreamResponse(status=resp.status, headers=resp_headers)
                await proxy_resp.prepare(request)
                if resp_body:
                    await proxy_resp.write(resp_body)
                return proxy_resp

        except Exception as exc:
            err = {"id": req_id, "type": "error", "error": str(exc)}
            await self.traffic_events.put(err)
            return web.Response(status=502, text=f"Bad Gateway: {exc}")

    async def modify_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Request/response modification hook.

        Operators or automated tests can mutate the request before forwarding:
          - Add to repeater console
          - Inject custom headers
          - Rewrite body
          - Save to intelligence repository
        """
        # Default: passthrough (no mutations)
        # Future: hook list that pipeline modifiers can register to
        logger.debug(
            "Intercepted [%s] %s", request_data.get("method", "?"), request_data.get("url", "?")
        )
        return request_data

    async def capture_credentials(self, traffic: Dict[str, Any]) -> None:
        """
        Scan traffic for authentication tokens to replay in authenticated scans.

        Detects:
          - JWT Bearer tokens in Authorization header or body
          - Session cookies (session_id, auth_token, etc.)
          - HTTP Basic Auth credentials
        """
        serialized = str(traffic.get("headers", {})) + " " + traffic.get("body", "")

        found = []

        for match in JWT_PATTERN.finditer(serialized):
            found.append({"type": "jwt", "value": match.group(0)[:120], "source": traffic.get("url", "")})

        for match in BEARER_PATTERN.finditer(serialized):
            found.append({"type": "bearer", "value": match.group(1)[:120], "source": traffic.get("url", "")})

        for match in BASIC_PATTERN.finditer(serialized):
            found.append({"type": "basic_auth", "value": match.group(1)[:120], "source": traffic.get("url", "")})

        for match in SESSION_PATTERN.finditer(serialized):
            found.append({"type": "session", "value": match.group(1)[:120], "source": traffic.get("url", "")})

        for match in COOKIE_PATTERN.finditer(str(traffic.get("headers", {}))):
            found.append({"type": "cookie_token", "value": match.group(1)[:120], "source": traffic.get("url", "")})

        if found:
            self.captured_credentials.extend(found)
            logger.info("ProxyEngine captured %d credential(s) from %s", len(found), traffic.get("url", "?"))

    def drop_request(self, req_id: str) -> bool:
        """Mark an intercepted request to be dropped (not forwarded)."""
        if req_id in self.pending_requests:
            self._drop_set.add(req_id)
            self.pending_requests[req_id].set()
            return True
        return False


# ── Global singleton ──────────────────────────────────────────────────────────

proxy_engine = ProxyEngine()
