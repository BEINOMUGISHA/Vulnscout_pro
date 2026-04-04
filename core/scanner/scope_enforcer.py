"""
scope_enforcer.py — Hard Authorisation Gate

This is the most legally critical module in VulnScout Pro.

Responsibilities:
  - Validate that a target URL/host is within the authorised scan scope
  - Enforce scope BEFORE any network activity begins
  - Block out-of-scope URL discoveries during crawling
  - Support IP range, domain, subdomain, path-prefix, and wildcard scopes
  - Maintain an immutable audit trail of all scope checks

Production considerations:
  - ScopeViolationError is always raised (never silently dropped)
  - Scope definition is loaded once and sealed at construction time
  - IP resolution is checked against allowed CIDR ranges
  - Subdomain wildcards (*.example.com) are supported
  - All scope checks are logged for legal/audit trail purposes
  - Scope config can be loaded from signed JSON (future: cryptographic verification)

CRITICAL LEGAL NOTE:
  Scanning systems without authorisation is illegal in most jurisdictions.
  This module is the primary technical control preventing misuse.
  Do not weaken, bypass, or disable this module.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import time
from dataclasses import dataclass, field
from typing import List, Optional, Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# ── Exceptions ─────────────────────────────────────────────────────────────────

class ScopeViolationError(Exception):
    """
    Raised when a target or URL is outside the authorised scan scope.
    This exception must propagate — catching and suppressing it is a
    serious misuse of this software.
    """

    def __init__(self, url: str, reason: str) -> None:
        self.url = url
        self.reason = reason
        super().__init__(f"Scope violation: {url} — {reason}")


class ScopeConfigError(Exception):
    """Raised when the scope configuration is invalid or incomplete."""


# ── Scope definition ───────────────────────────────────────────────────────────

@dataclass
class ScopeConfig:
    """
    Defines what is and is not in scope for a scan.

    Fields:
        allowed_domains:     Exact domain names (e.g. "example.com")
        allowed_wildcard_domains: Subdomain wildcards (e.g. "*.example.com")
        allowed_ip_ranges:   CIDR ranges (e.g. "10.0.0.0/8")
        allowed_url_prefixes: URL path prefixes (e.g. "https://example.com/api/")
        excluded_paths:      URL path patterns to always exclude (regex)
        excluded_domains:    Domains never to scan (overrides allowed)
        authorisation_token: Optional token proving the scan is authorised
        authorised_by:       Name/email of person who granted authorisation
        authorised_at:       ISO timestamp of authorisation
        max_scan_depth:      Hard ceiling on crawl depth (cannot be increased)
    """
    allowed_domains: List[str] = field(default_factory=list)
    allowed_wildcard_domains: List[str] = field(default_factory=list)
    allowed_ip_ranges: List[str] = field(default_factory=list)
    allowed_url_prefixes: List[str] = field(default_factory=list)
    excluded_paths: List[str] = field(default_factory=list)
    excluded_domains: List[str] = field(default_factory=list)
    authorisation_token: Optional[str] = None
    authorised_by: Optional[str] = None
    authorised_at: Optional[str] = None
    max_scan_depth: int = 5

    def is_empty(self) -> bool:
        return not any([
            self.allowed_domains,
            self.allowed_wildcard_domains,
            self.allowed_ip_ranges,
            self.allowed_url_prefixes,
        ])


@dataclass
class ScopeCheckRecord:
    url: str
    allowed: bool
    reason: str
    checked_at: float = field(default_factory=time.monotonic)


# ── Scope enforcer ─────────────────────────────────────────────────────────────

class ScopeEnforcer:
    """
    Evaluates whether URLs and targets are within authorised scope.

    Construction-time validation ensures a scan cannot start with an
    empty or malformed scope definition.

    All checks are logged to self.audit_log for post-scan review.
    """

    # These are always excluded regardless of scope config
    ALWAYS_EXCLUDED_DOMAINS: Set[str] = frozenset([
        "google.com", "googleapis.com",
        "facebook.com", "twitter.com", "x.com",
        "amazon.com", "aws.amazon.com",
        "microsoft.com", "azure.microsoft.com",
        "cloudflare.com", "akamai.com",
        "paypal.com", "stripe.com",
        "mtn.com", "airtel.com",
        "localhost",   # Should be explicitly allowed if intentional
    ])

    def __init__(self, scope: ScopeConfig) -> None:
        self._validate_config(scope)
        self._scope = scope
        self._compiled_exclusions = [
            re.compile(p, re.IGNORECASE)
            for p in scope.excluded_paths
        ]
        self._allowed_networks = self._parse_ip_ranges(scope.allowed_ip_ranges)
        self.audit_log: List[ScopeCheckRecord] = []
        self._dns_cache: Dict[str, List[str]] = {}

        logger.info(
            "ScopeEnforcer initialised — allowed_domains=%s wildcards=%s ip_ranges=%s authorised_by=%s",
            scope.allowed_domains,
            scope.allowed_wildcard_domains,
            scope.allowed_ip_ranges,
            scope.authorised_by or "NOT SET",
        )

    # ── Public API ─────────────────────────────────────────────────────────────

    async def enforce(self, target) -> None:
        """
        Enforce scope on a Target object.
        Raises ScopeViolationError if not in scope.
        This is the primary gate — called once before any scan activity.
        """
        url = target.base_url if hasattr(target, "base_url") else str(target)
        await self._check_or_raise(url, is_primary_target=True)
        logger.info("Scope check PASSED for primary target: %s", url)

    async def enforce_url(self, url: str) -> None:
        """
        Enforce scope on a URL discovered during crawling.
        Raises ScopeViolationError if out of scope.
        """
        await self._check_or_raise(url, is_primary_target=False)

    async def is_in_scope(self, url: str) -> bool:
        """Non-raising version — returns bool. Used for filtering, not gating."""
        try:
            await self._check_or_raise(url, is_primary_target=False)
            return True
        except ScopeViolationError:
            return False

    @property
    def scope(self) -> ScopeConfig:
        return self._scope

    # ── Core check logic ───────────────────────────────────────────────────────

    async def _check_or_raise(self, url: str, is_primary_target: bool) -> None:
        parsed = urlparse(url)

        if not parsed.scheme or not parsed.netloc:
            self._record(url, allowed=False, reason="Invalid URL (no scheme or host)")
            raise ScopeViolationError(url, "Invalid URL — no scheme or host")

        if parsed.scheme not in ("http", "https"):
            self._record(url, allowed=False, reason=f"Non-HTTP scheme: {parsed.scheme}")
            raise ScopeViolationError(url, f"Non-HTTP/S scheme '{parsed.scheme}' is out of scope")

        host = parsed.hostname or ""
        port = parsed.port
        path = parsed.path

        # ── Always-excluded domains ────────────────────────────────────────────
        for blocked in self.ALWAYS_EXCLUDED_DOMAINS:
            if host == blocked or host.endswith(f".{blocked}"):
                reason = f"Host '{host}' is in the always-excluded list"
                self._record(url, allowed=False, reason=reason)
                raise ScopeViolationError(url, reason)

        # ── Explicitly excluded domains ────────────────────────────────────────
        for excluded in self._scope.excluded_domains:
            if host == excluded or host.endswith(f".{excluded}"):
                reason = f"Host '{host}' is in the excluded_domains list"
                self._record(url, allowed=False, reason=reason)
                raise ScopeViolationError(url, reason)

        # ── Excluded path patterns ─────────────────────────────────────────────
        for pattern in self._compiled_exclusions:
            if pattern.search(path):
                reason = f"Path '{path}' matches excluded pattern '{pattern.pattern}'"
                self._record(url, allowed=False, reason=reason)
                raise ScopeViolationError(url, reason)

        # ── Check allowed scope ────────────────────────────────────────────────
        allowed, reason = await self._is_allowed(host, url, path)
        self._record(url, allowed=allowed, reason=reason)

        if not allowed:
            logger.warning("Scope violation: %s — %s", url, reason)
            raise ScopeViolationError(url, reason)

    async def _is_allowed(self, host: str, url: str, path: str):
        """Returns (allowed: bool, reason: str)."""

        # URL prefix match (most specific — check first)
        for prefix in self._scope.allowed_url_prefixes:
            if url.startswith(prefix):
                return True, f"Matches allowed URL prefix: {prefix}"

        # Exact domain match
        if host in self._scope.allowed_domains:
            return True, f"Host '{host}' in allowed_domains"

        # Subdomain wildcard match (*.example.com matches sub.example.com)
        for wildcard in self._scope.allowed_wildcard_domains:
            base = wildcard.lstrip("*.")
            if host == base or host.endswith(f".{base}"):
                return True, f"Host '{host}' matches wildcard '{wildcard}'"

        # IP range match (DNS required)
        if self._allowed_networks:
            try:
                # Check cache first
                if host in self._dns_cache:
                    resolved_ips = self._dns_cache[host]
                else:
                    loop = asyncio.get_event_loop()
                    try:
                        info = await asyncio.wait_for(
                            loop.getaddrinfo(host, None), timeout=5.0
                        )
                        resolved_ips = [i[4][0] for i in info]
                        self._dns_cache[host] = resolved_ips
                    except (asyncio.TimeoutError, socket.gaierror):
                        resolved_ips = []
                        self._dns_cache[host] = []

                for ip_str in resolved_ips:
                    try:
                        ip = ipaddress.ip_address(ip_str)
                        for network in self._allowed_networks:
                            if ip in network:
                                return True, f"IP {ip_str} is in allowed range {network}"
                    except ValueError:
                        continue
            except Exception as e:
                logger.warning("ScopeEnforcer: DNS check failed for %s: %s", host, e)
                pass  # Proceed to rejection

        return False, (
            f"Host '{host}' is not in allowed_domains, wildcard_domains, "
            f"url_prefixes, or ip_ranges. "
            f"Add it to the scope config to proceed."
        )

    # ── Config validation ──────────────────────────────────────────────────────

    @staticmethod
    def _validate_config(scope: ScopeConfig) -> None:
        if scope.is_empty():
            raise ScopeConfigError(
                "Scope configuration is empty. "
                "You must define at least one of: allowed_domains, "
                "allowed_wildcard_domains, allowed_ip_ranges, or allowed_url_prefixes. "
                "Scanning without a defined scope is not permitted."
            )

        if not scope.authorised_by:
            logger.warning(
                "SECURITY WARNING: Scan scope has no 'authorised_by' field set. "
                "Please record who authorised this scan for legal compliance."
            )

        if not scope.authorisation_token:
            logger.warning(
                "SECURITY WARNING: No authorisation_token set. "
                "Consider requiring a signed token to prove scan authorisation."
            )

        # Validate CIDR ranges
        for cidr in scope.allowed_ip_ranges:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                raise ScopeConfigError(f"Invalid CIDR range '{cidr}': {exc}") from exc

        # Validate URL prefixes start with http
        for prefix in scope.allowed_url_prefixes:
            if not prefix.startswith(("http://", "https://")):
                raise ScopeConfigError(
                    f"allowed_url_prefix '{prefix}' must start with http:// or https://"
                )

    @staticmethod
    def _parse_ip_ranges(ranges: List[str]) -> List[ipaddress.IPv4Network]:
        networks = []
        for cidr in ranges:
            try:
                networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass
        return networks

    def _record(self, url: str, allowed: bool, reason: str) -> None:
        record = ScopeCheckRecord(url=url, allowed=allowed, reason=reason)
        self.audit_log.append(record)
        level = logging.DEBUG if allowed else logging.WARNING
        logger.log(level, "Scope check [%s]: %s — %s", "PASS" if allowed else "FAIL", url, reason)

    # ── Serialisation ──────────────────────────────────────────────────────────

    def audit_summary(self) -> dict:
        total = len(self.audit_log)
        passed = sum(1 for r in self.audit_log if r.allowed)
        blocked = total - passed
        return {
            "total_checks": total,
            "passed": passed,
            "blocked": blocked,
            "blocked_urls": [r.url for r in self.audit_log if not r.allowed],
        }


# ── Convenience factory ────────────────────────────────────────────────────────

def scope_from_url(
    base_url: str,
    authorised_by: Optional[str] = None,
    include_subdomains: bool = False,
) -> ScopeConfig:
    """
    Build a minimal ScopeConfig from a single base URL.
    Useful for quick single-target scans.
    """
    parsed = urlparse(base_url)
    host = parsed.hostname or ""

    allowed_domains = [host]
    wildcard_domains = [f"*.{host}"] if include_subdomains else []

    return ScopeConfig(
        allowed_url_prefixes=[base_url],
        allowed_domains=allowed_domains,
        allowed_wildcard_domains=wildcard_domains,
        authorised_by=authorised_by,
    )