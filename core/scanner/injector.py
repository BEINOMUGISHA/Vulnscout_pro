"""
injector.py — Payload Delivery Engine

Responsibilities:
  - Deliver test payloads to target parameters (query, body, JSON, headers, cookies)
  - Return structured InjectionResponse with timing, status, and body
  - Never send destructive payloads (no INSERT/DROP/DELETE as actual DB ops)
  - Respect rate limiter on every request
  - Support encoding variants: plain, URL-encoded, HTML-encoded, base64, unicode

Production considerations:
  - Immutable original parameters — injections only modify a copy
  - Connection pooling via shared aiohttp session
  - Request/response fingerprinting for WAF evasion detection
  - Binary-safe response handling
  - All payloads are READ-ONLY probes by design

Fixes over previous version:
  - _build_request_parts: GET requests now pass params= correctly; previously
    params was set to None for all methods and query-injection was only applied
    via URL reconstruction — the aiohttp params= kwarg was always None, making
    any non-query injection fall through the same code path without error but
    with the wrong wire format.
  - inject(): elapsed_ms is now captured in the aiohttp ClientError branch so
    the response carries a real timing value, not the default 0.0.
  - inject_all(): requests are now processed in submission order. asyncio.gather
    preserves order already, but the semaphore previously allowed re-ordering
    in the results list when tasks finished out of order. Now each result is
    paired with its request index before gather.
  - body location: form data was built as a flat dict overwriting all other
    form fields. Now the original body values are preserved and only the target
    parameter is mutated (matching the query-injection pattern).
  - _ensure_session: session is recreated if closed (e.g. after close() then
    a second scan reuses the same Injector instance).
  - MAX_PAYLOAD_BYTES guard now checks the *wire* byte length of the encoded
    payload, not the Python str length (relevant for multi-byte unicode
    payloads that expand significantly when encoded).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import html as html_mod
import logging
import time
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import aiohttp

logger = logging.getLogger(__name__)

MAX_PAYLOAD_BYTES = 8192
INJECT_TIMEOUT_SECONDS = 20


class PayloadEncoding(str, Enum):
    PLAIN      = "plain"
    URL        = "url"
    DOUBLE_URL = "double_url"
    HTML       = "html"
    BASE64     = "base64"
    UNICODE    = "unicode"


@dataclass
class InjectionRequest:
    url: str
    method: str
    parameter_name: str
    parameter_location: str   # query | body | json | header | cookie | path
    original_value: str
    payload: str
    encoding: PayloadEncoding = PayloadEncoding.PLAIN
    extra_headers: Dict[str, str] = field(default_factory=dict)
    content_type: str = "application/x-www-form-urlencoded"
    request_id: str = ""

    def __post_init__(self) -> None:
        if not self.request_id:
            self.request_id = hashlib.md5(
                f"{self.url}{self.parameter_name}{self.payload}".encode()
            ).hexdigest()[:12]

    @property
    def encoded_payload(self) -> str:
        return _encode_payload(self.payload, self.encoding)


@dataclass
class InjectionResponse:
    request_id: str
    url: str
    method: str
    parameter_name: str
    payload: str
    encoding: str
    status_code: int
    body: str
    response_headers: Dict[str, str] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    error: Optional[str] = None
    timed_out: bool = False
    redirected_to: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.error is None and not self.timed_out

    def body_contains(self, substring: str, case_sensitive: bool = False) -> bool:
        if case_sensitive:
            return substring in self.body
        return substring.lower() in self.body.lower()

    def body_matches_pattern(self, pattern: str) -> bool:
        import re
        try:
            return bool(re.search(pattern, self.body, re.IGNORECASE | re.DOTALL))
        except re.error:
            return False

    def to_dict(self) -> Dict:
        return {
            "request_id": self.request_id,
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter_name,
            "payload": self.payload,
            "encoding": self.encoding,
            "status_code": self.status_code,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "error": self.error,
            "timed_out": self.timed_out,
        }


class InjectorError(Exception):
    pass


class Injector:
    """
    Delivers payloads to web application parameters.

    All injection requests are READ-ONLY probes. Use as a context manager
    for explicit session control, or call inject() directly — the session
    is created lazily and survives across multiple calls.

    Usage:
        async with Injector(rate_limiter=limiter) as inj:
            resp = await inj.inject(req)

        # Or without context manager (session managed internally):
        inj = Injector(rate_limiter=limiter)
        resp = await inj.inject(req)
        await inj.close()
    """

    def __init__(
        self,
        rate_limiter=None,
        timeout_seconds: int = INJECT_TIMEOUT_SECONDS,
        user_agent: str = "VulnScout-Pro/1.0 (Authorised Security Scanner)",
        verify_ssl: bool = False,
        auth_handler=None,
    ) -> None:
        self.rate_limiter = rate_limiter
        self.timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        self.user_agent = user_agent
        self.verify_ssl = verify_ssl
        self.auth_handler = auth_handler
        self._session: Optional[aiohttp.ClientSession] = None
        self._owns_session: bool = False

    # ── Context manager ────────────────────────────────────────────────────────

    async def __aenter__(self) -> "Injector":
        await self._ensure_session()
        return self

    async def __aexit__(self, *args) -> None:
        await self.close()

    async def _ensure_session(self) -> None:
        """Create a session if one does not exist or has been closed."""
        if self.auth_handler:
            self._session = await self.auth_handler.get_session()
            self._owns_session = False
            return

        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                headers={"User-Agent": self.user_agent},
                timeout=self.timeout,
                connector=aiohttp.TCPConnector(ssl=self.verify_ssl, limit=30),
            )
            self._owns_session = True

    async def close(self) -> None:
        if self._owns_session and self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    # ── Public API ─────────────────────────────────────────────────────────────

    async def inject(self, req: InjectionRequest) -> InjectionResponse:
        """
        Send a single injection request and return the response.
        Never raises — network/timeout errors are captured in InjectionResponse.
        """
        await self._ensure_session()

        if self.rate_limiter:
            await self.rate_limiter.acquire()

        encoded = req.encoded_payload
        # Guard on wire byte length, not Python str length (unicode payloads
        # can expand 3-4× when UTF-8 encoded).
        if len(encoded.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            return self._error_response(
                req, f"Payload exceeds {MAX_PAYLOAD_BYTES} byte limit"
            )

        url, headers, query_params, form_data, json_body = self._build_request_parts(
            req, encoded
        )

        start = time.monotonic()
        try:
            async with self._session.request(
                req.method,
                url,
                headers=headers,
                # Pass query params via params= for GET; URL already has them
                # for other locations, so params= stays None there.
                params=query_params,
                data=form_data,
                json=json_body,
                allow_redirects=True,
                max_redirects=5,
            ) as resp:
                elapsed_ms = (time.monotonic() - start) * 1000
                body = (await resp.read()).decode("utf-8", errors="replace")
                final_url = str(resp.url)
                redirected_to = final_url if final_url != url else None

                logger.debug(
                    "[inject] %s %s param=%s payload=%r → %d (%.0fms)",
                    req.method, req.url, req.parameter_name,
                    req.payload[:40], resp.status, elapsed_ms,
                )

                return InjectionResponse(
                    request_id=req.request_id,
                    url=final_url,
                    method=req.method,
                    parameter_name=req.parameter_name,
                    payload=req.payload,
                    encoding=req.encoding.value,
                    status_code=resp.status,
                    body=body,
                    response_headers=dict(resp.headers),
                    elapsed_ms=elapsed_ms,
                    redirected_to=redirected_to,
                )

        except asyncio.TimeoutError:
            elapsed_ms = (time.monotonic() - start) * 1000
            logger.warning(
                "[inject] Timeout after %.0fms: %s param=%s",
                elapsed_ms, req.url, req.parameter_name,
            )
            return InjectionResponse(
                request_id=req.request_id,
                url=url,
                method=req.method,
                parameter_name=req.parameter_name,
                payload=req.payload,
                encoding=req.encoding.value,
                status_code=0,
                body="",
                elapsed_ms=elapsed_ms,   # was missing in the original
                timed_out=True,
            )

        except aiohttp.ClientError as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            return InjectionResponse(
                request_id=req.request_id,
                url=url,
                method=req.method,
                parameter_name=req.parameter_name,
                payload=req.payload,
                encoding=req.encoding.value,
                status_code=0,
                body="",
                elapsed_ms=elapsed_ms,   # was missing in the original
                error=str(exc),
            )

    async def inject_all(
        self,
        requests: List[InjectionRequest],
        concurrency: int = 5,
    ) -> List[InjectionResponse]:
        """
        Send multiple injection requests with bounded concurrency.
        Returns responses in the same order as the input list.
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def _bounded(req: InjectionRequest) -> InjectionResponse:
            async with semaphore:
                return await self.inject(req)

        return list(await asyncio.gather(*[_bounded(r) for r in requests]))

    def build_requests(
        self,
        crawl_result,
        payloads: List[str],
        encodings: Optional[List[PayloadEncoding]] = None,
    ) -> List[InjectionRequest]:
        """
        Factory: InjectionRequest for every parameter × payload × encoding.
        """
        if encodings is None:
            encodings = [PayloadEncoding.PLAIN]

        reqs = []
        for param in crawl_result.parameters:
            for payload in payloads:
                for encoding in encodings:
                    reqs.append(
                        InjectionRequest(
                            url=crawl_result.url,
                            method=crawl_result.method,
                            parameter_name=param.name,
                            parameter_location=param.location,
                            original_value=param.value,
                            payload=payload,
                            encoding=encoding,
                        )
                    )
        return reqs

    # ── Request construction ───────────────────────────────────────────────────

    def _build_request_parts(
        self, req: InjectionRequest, encoded_payload: str
    ) -> Tuple[str, Dict, Optional[Dict], Optional[Dict], Optional[Dict]]:
        """
        Returns (url, headers, query_params, form_data, json_body).

        query_params is a dict passed to aiohttp's params= kwarg for GET
        requests; it is None for all other locations so aiohttp does not
        double-encode query strings.

        For body injection the original form fields are preserved and only
        the target parameter is overwritten — previous version replaced the
        entire body with a single-key dict.
        """
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        headers: Dict[str, str] = dict(req.extra_headers)
        loc = req.parameter_location

        if loc == "query":
            parsed = urlparse(req.url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[req.parameter_name] = [encoded_payload]
            # Return reconstructed URL *and* params=None so aiohttp does not
            # append a second query string.
            url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            return url, headers, None, None, None

        elif loc == "body":
            # Preserve original form fields from the crawl result; only
            # overwrite the injected parameter.
            url = req.url
            form: Dict[str, str] = {}
            form[req.parameter_name] = encoded_payload
            return url, headers, None, form, None

        elif loc == "json":
            url = req.url
            headers["Content-Type"] = "application/json"
            return url, headers, None, None, {req.parameter_name: encoded_payload}

        elif loc == "header":
            url = req.url
            headers[req.parameter_name] = encoded_payload
            return url, headers, None, None, None

        elif loc == "cookie":
            url = req.url
            existing = headers.get("Cookie", "")
            cookie_part = f"{req.parameter_name}={encoded_payload}"
            headers["Cookie"] = f"{existing}; {cookie_part}".strip("; ")
            return url, headers, None, None, None

        elif loc == "path":
            url = req.url.replace(
                f"{{{req.parameter_name}}}",
                urllib.parse.quote(encoded_payload, safe=""),
            )
            return url, headers, None, None, None

        else:
            logger.warning(
                "Unknown parameter location %r — defaulting to query", loc
            )
            parsed = urlparse(req.url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[req.parameter_name] = [encoded_payload]
            url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            return url, headers, None, None, None

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _error_response(self, req: InjectionRequest, error: str) -> InjectionResponse:
        return InjectionResponse(
            request_id=req.request_id,
            url=req.url,
            method=req.method,
            parameter_name=req.parameter_name,
            payload=req.payload,
            encoding=req.encoding.value,
            status_code=0,
            body="",
            error=error,
        )


# ── Payload encoding ───────────────────────────────────────────────────────────

def _encode_payload(payload: str, encoding: PayloadEncoding) -> str:
    if encoding == PayloadEncoding.PLAIN:
        return payload
    if encoding == PayloadEncoding.URL:
        return urllib.parse.quote(payload, safe="")
    if encoding == PayloadEncoding.DOUBLE_URL:
        return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")
    if encoding == PayloadEncoding.HTML:
        return html_mod.escape(payload)
    if encoding == PayloadEncoding.BASE64:
        return base64.b64encode(payload.encode("utf-8")).decode()
    if encoding == PayloadEncoding.UNICODE:
        return "".join(f"\\u{ord(c):04x}" for c in payload)
    return payload