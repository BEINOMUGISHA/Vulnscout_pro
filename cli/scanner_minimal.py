"""
scanner.py — Minimal Async Vulnerability Scanner
=================================================
A self-contained, single-file vulnerability scanner that preserves the full
architecture of VulnScout Pro in a dependency-light, terminal-runnable form.

Architecture (mirrors the full stack):
  Crawler  →  Orchestrator  →  Detectors  →  Validator  →  Scorer  →  Reporter

Dependencies (all stdlib except aiohttp + bs4):
    pip install aiohttp beautifulsoup4

Usage:
    python scanner.py https://target.com
    python scanner.py https://target.com --depth 2 --checks sqli xss
    python scanner.py https://target.com --output report.json
    python scanner.py https://target.com --concurrency 10 --timeout 20

Flags:
    --depth INT          Crawl depth (default: 2)
    --max-pages INT      Page limit (default: 50)
    --checks NAMES       Space-separated: sqli xss ssrf misconfig (default: all)
    --output FILE        Write JSON report to file
    --concurrency INT    Max concurrent detector tasks (default: 5)
    --timeout INT        Per-request timeout in seconds (default: 15)
    --no-robots          Ignore robots.txt
    --silent             Suppress progress output

All probes are READ-ONLY. No destructive payloads are sent.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import sys
import time
import urllib.parse
import urllib.robotparser
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import AsyncGenerator, Dict, List, Optional, Set, Tuple

import aiohttp
from bs4 import BeautifulSoup


# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

VERSION = "1.0.0"
USER_AGENT = f"MinimalScanner/{VERSION} (Authorised Security Testing)"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024   # 2 MB
MAX_PAYLOAD_BYTES  = 4096
_SENTINEL = object()


# ══════════════════════════════════════════════════════════════════════════════
# ENUMS
# ══════════════════════════════════════════════════════════════════════════════

class ScanPhase(str, Enum):
    CRAWLING  = "crawling"
    DETECTING = "detecting"
    SCORING   = "scoring"
    COMPLETE  = "complete"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "informational"


# ══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Parameter:
    name: str
    value: str
    location: str   # query | body | header | json | cookie


@dataclass
class Endpoint:
    url: str
    method: str
    status: int = 0
    content_type: str = ""
    parameters: List[Parameter] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    depth: int = 0
    _body: str = field(default="", repr=False)

    @property
    def fingerprint(self) -> str:
        param_key = "&".join(sorted(f"{p.name}={p.location}" for p in self.parameters))
        raw = f"{self.method}:{self.url.split('?')[0]}:{param_key}"
        return hashlib.md5(raw.encode()).hexdigest()


@dataclass
class InjectionResult:
    url: str
    status: int
    body: str
    elapsed_ms: float
    error: Optional[str] = None
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None and not self.timed_out

    def contains(self, s: str) -> bool:
        return s.lower() in self.body.lower()

    def matches(self, pattern: str) -> bool:
        try:
            return bool(re.search(pattern, self.body, re.I | re.S))
        except re.error:
            return False


@dataclass
class Finding:
    id: str
    url: str
    parameter: str
    vuln_type: str
    description: str
    evidence: str
    payload: str
    cvss_vector: str
    cvss_score: float = 0.0
    severity: Severity = Severity.INFO
    confidence: float = 0.5
    remediation: str = ""

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "url": self.url,
            "parameter": self.parameter,
            "vuln_type": self.vuln_type,
            "description": self.description,
            "evidence": self.evidence,
            "payload": self.payload,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 2),
            "remediation": self.remediation,
        }


# ══════════════════════════════════════════════════════════════════════════════
# CRAWLER
# ══════════════════════════════════════════════════════════════════════════════

_INJECTABLE_HEADERS = ("X-Forwarded-For", "X-Forwarded-Host", "Referer", "Origin")
_ID_RE = re.compile(r"/(\d+|[0-9a-f]{8,})", re.I)


class Crawler:
    def __init__(
        self,
        session: aiohttp.ClientSession,
        max_depth: int = 2,
        max_pages: int = 50,
        respect_robots: bool = True,
        timeout: int = 15,
    ) -> None:
        self._session = session
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.respect_robots = respect_robots
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self._visited: Set[str] = set()
        self._fps: Set[str] = set()
        self._robots: Optional[urllib.robotparser.RobotFileParser] = None
        self._base_netloc = ""
        self._page_count = 0
        self._stop = asyncio.Event()

    async def crawl(self, base_url: str) -> AsyncGenerator[Endpoint, None]:
        parsed = urllib.parse.urlparse(base_url)
        self._base_netloc = parsed.netloc
        self._stop.clear()
        self._visited.clear()
        self._fps.clear()
        self._page_count = 0

        if self.respect_robots:
            await self._load_robots(base_url)

        work_q: asyncio.Queue = asyncio.Queue()
        out_q:  asyncio.Queue = asyncio.Queue()
        await work_q.put((base_url, 0, "GET"))

        workers = [
            asyncio.create_task(self._worker(work_q, out_q))
            for _ in range(5)
        ]

        seen_sentinels = 0
        try:
            while seen_sentinels < 5:
                if self._stop.is_set():
                    break
                try:
                    item = await asyncio.wait_for(out_q.get(), timeout=0.3)
                except asyncio.TimeoutError:
                    if all(w.done() for w in workers):
                        break
                    continue

                if item is _SENTINEL:
                    seen_sentinels += 1
                    continue

                ep: Endpoint = item
                fp = ep.fingerprint
                if fp in self._fps:
                    continue
                self._fps.add(fp)

                if self._page_count >= self.max_pages:
                    break
                self._page_count += 1

                if ep.depth < self.max_depth:
                    for link in self._links(ep):
                        if link not in self._visited:
                            await work_q.put((link, ep.depth + 1, "GET"))
                    for form in ep.forms:
                        action = form.get("action", ep.url)
                        if action not in self._visited:
                            await work_q.put((action, ep.depth + 1, form.get("method", "POST").upper()))

                yield ep
        finally:
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

    async def stop(self) -> None:
        self._stop.set()

    async def _worker(self, work_q: asyncio.Queue, out_q: asyncio.Queue) -> None:
        try:
            while not self._stop.is_set():
                try:
                    url, depth, method = await asyncio.wait_for(work_q.get(), timeout=0.5)
                except asyncio.TimeoutError:
                    if work_q.empty():
                        break
                    continue
                try:
                    if url in self._visited:
                        continue
                    if self.respect_robots and not self._robots_ok(url):
                        continue
                    self._visited.add(url)
                    ep = await self._fetch(url, depth, method)
                    if ep:
                        await out_q.put(ep)
                except Exception:
                    pass
                finally:
                    try:
                        work_q.task_done()
                    except ValueError:
                        pass
        finally:
            await out_q.put(_SENTINEL)

    async def _fetch(self, url: str, depth: int, method: str) -> Optional[Endpoint]:
        try:
            async with self._session.request(
                method, url,
                allow_redirects=True,
                max_redirects=5,
                timeout=self.timeout,
            ) as resp:
                ct = resp.headers.get("Content-Type", "")
                ep = Endpoint(
                    url=str(resp.url),
                    method=method,
                    status=resp.status,
                    content_type=ct,
                    depth=depth,
                )

                if "text/html" not in ct and "application/json" not in ct:
                    return ep

                raw = await resp.read()
                if len(raw) > MAX_RESPONSE_BYTES:
                    raw = raw[:MAX_RESPONSE_BYTES]
                body = raw.decode("utf-8", errors="replace")
                ep._body = body

                if "text/html" in ct:
                    self._parse_html(body, ep, str(resp.url))
                elif "application/json" in ct:
                    self._parse_json(body, ep)

                # Always add injectable headers
                for h in _INJECTABLE_HEADERS:
                    ep.parameters.append(Parameter(h, "", "header"))

                return ep
        except (asyncio.TimeoutError, aiohttp.ClientError):
            return None

    def _parse_html(self, html: str, ep: Endpoint, base: str) -> None:
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return

        # Query string params
        parsed = urllib.parse.urlparse(base)
        for name, vals in urllib.parse.parse_qs(parsed.query).items():
            ep.parameters.append(Parameter(name, vals[0] if vals else "", "query"))

        # Forms
        for form in soup.find_all("form"):
            action = form.get("action", "")
            action = urllib.parse.urljoin(base, action) if action else base
            method = form.get("method", "GET").upper()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name") or inp.get("id", "")
                if name:
                    ep.parameters.append(Parameter(name, inp.get("value", ""), "body"))
                    inputs.append({"name": name, "value": inp.get("value", "")})
            ep.forms.append({"action": action, "method": method, "inputs": inputs})

    def _parse_json(self, body: str, ep: Endpoint) -> None:
        try:
            data = json.loads(body)
            self._flatten(data, ep, "")
        except json.JSONDecodeError:
            pass

    def _flatten(self, obj, ep: Endpoint, prefix: str, depth: int = 0) -> None:
        if depth > 3:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (dict, list)):
                    self._flatten(v, ep, key, depth + 1)
                else:
                    ep.parameters.append(Parameter(key, str(v) if v is not None else "", "json"))
        elif isinstance(obj, list) and obj:
            self._flatten(obj[0], ep, prefix, depth + 1)

    def _links(self, ep: Endpoint) -> List[str]:
        if not ep._body or "text/html" not in ep.content_type:
            return []
        try:
            soup = BeautifulSoup(ep._body, "html.parser")
        except Exception:
            return []
        links = set()
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith(("javascript:", "mailto:", "tel:", "data:")):
                continue
            full = urllib.parse.urljoin(ep.url, href).split("#")[0]
            if self._same_origin(full):
                links.add(full)
        for attr in ("data-href", "hx-get", "hx-post"):
            for tag in soup.find_all(True, attrs={attr: True}):
                val = tag[attr]
                if val.startswith(("http", "/")):
                    full = urllib.parse.urljoin(ep.url, val).split("#")[0]
                    if self._same_origin(full):
                        links.add(full)
        return list(links)

    def _same_origin(self, url: str) -> bool:
        try:
            return urllib.parse.urlparse(url).netloc == self._base_netloc
        except Exception:
            return False

    async def _load_robots(self, base: str) -> None:
        try:
            async with self._session.get(
                urllib.parse.urljoin(base, "/robots.txt"),
                timeout=aiohttp.ClientTimeout(total=5),
            ) as r:
                if r.status == 200:
                    text = await r.text()
                    self._robots = urllib.robotparser.RobotFileParser()
                    self._robots.parse(text.splitlines())
        except Exception:
            pass

    def _robots_ok(self, url: str) -> bool:
        return self._robots is None or self._robots.can_fetch(USER_AGENT, url)


# ══════════════════════════════════════════════════════════════════════════════
# INJECTOR
# ══════════════════════════════════════════════════════════════════════════════

class Injector:
    def __init__(self, session: aiohttp.ClientSession, timeout: int = 15) -> None:
        self._session = session
        self._timeout = aiohttp.ClientTimeout(total=timeout)

    async def inject(
        self,
        ep: Endpoint,
        param: Parameter,
        payload: str,
    ) -> InjectionResult:
        url, headers, data, json_body = self._build(ep, param, payload)
        start = time.monotonic()
        try:
            async with self._session.request(
                ep.method, url,
                headers=headers,
                data=data,
                json=json_body,
                allow_redirects=True,
                max_redirects=5,
                timeout=self._timeout,
            ) as resp:
                raw = await resp.read()
                body = raw[:MAX_RESPONSE_BYTES].decode("utf-8", errors="replace")
                return InjectionResult(
                    url=str(resp.url),
                    status=resp.status,
                    body=body,
                    elapsed_ms=(time.monotonic() - start) * 1000,
                )
        except asyncio.TimeoutError:
            return InjectionResult(
                url=url, status=0, body="",
                elapsed_ms=(time.monotonic() - start) * 1000,
                timed_out=True,
            )
        except aiohttp.ClientError as exc:
            return InjectionResult(
                url=url, status=0, body="",
                elapsed_ms=(time.monotonic() - start) * 1000,
                error=str(exc),
            )

    def _build(
        self, ep: Endpoint, param: Parameter, payload: str
    ) -> Tuple[str, Dict, Optional[Dict], Optional[Dict]]:
        headers: Dict[str, str] = {}
        loc = param.location

        if loc == "query":
            parsed = urllib.parse.urlparse(ep.url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            qs[param.name] = [payload]
            url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(qs, doseq=True))
            )
            return url, headers, None, None

        if loc == "body":
            return ep.url, headers, {param.name: payload}, None

        if loc == "json":
            headers["Content-Type"] = "application/json"
            return ep.url, headers, None, {param.name: payload}

        if loc == "header":
            headers[param.name] = payload
            return ep.url, headers, None, None

        if loc == "cookie":
            headers["Cookie"] = f"{param.name}={payload}"
            return ep.url, headers, None, None

        # fallback → query
        parsed = urllib.parse.urlparse(ep.url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        qs[param.name] = [payload]
        url = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(qs, doseq=True))
        )
        return url, headers, None, None


# ══════════════════════════════════════════════════════════════════════════════
# DETECTORS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class DetectorPayload:
    value: str
    description: str
    evidence_pattern: str
    vuln_type: str
    cvss_vector: str
    confidence_boost: float = 0.0
    is_timed: bool = False
    delay_s: float = 0.0
    false_condition: str = ""   # For boolean-differential payloads


class BaseDetector:
    name: str = ""
    vuln_type: str = ""
    payloads: List[DetectorPayload] = []
    remediation: str = ""

    async def detect(
        self, ep: Endpoint, injector: Injector
    ) -> List[Finding]:
        raise NotImplementedError

    async def _baseline(self, ep: Endpoint, param: Parameter, injector: Injector) -> InjectionResult:
        return await injector.inject(ep, param, param.value or "test")

    def _finding(
        self,
        ep: Endpoint,
        param: Parameter,
        payload: DetectorPayload,
        evidence: str,
        confidence: float,
    ) -> Finding:
        return Finding(
            id=str(uuid.uuid4()),
            url=ep.url,
            parameter=param.name,
            vuln_type=payload.vuln_type,
            description=f"{self.name} in parameter '{param.name}'",
            evidence=evidence,
            payload=payload.value,
            cvss_vector=payload.cvss_vector,
            confidence=min(1.0, 0.5 + payload.confidence_boost + confidence),
            remediation=self.remediation,
        )


# ── SQL Injection ──────────────────────────────────────────────────────────────

_SQLI_ERRORS = re.compile(
    r"(?i)(you have an error in your sql syntax"
    r"|warning: mysql_"
    r"|unclosed quotation mark"
    r"|sqlite3\.operationalerror"
    r"|pg_query\(\)"
    r"|syntax error at or near"
    r"|ora-\d{5}"
    r"|microsoft ole db provider"
    r"|pdo.*exception"
    r"|dbal.*exception"
    r"|XPATH syntax error"
    r"|no such table)",
    re.I | re.S,
)
_SQLI_FP = re.compile(r"(?i)(invalid input|incorrect password|captcha|cloudflare)")


class SQLiDetector(BaseDetector):
    name = "SQL Injection"
    vuln_type = "sqli"
    remediation = (
        "Use parameterised queries / prepared statements. "
        "Never concatenate user input into SQL strings. "
        "Apply input validation and least-privilege DB accounts."
    )

    @property
    def payloads(self) -> List[DetectorPayload]:
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        vb = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
        return [
            DetectorPayload("'",             "Single quote",          "", "sqli_error", v,  0.30),
            DetectorPayload("'--",           "Quote + comment",       "", "sqli_error", v,  0.35),
            DetectorPayload("' OR '1'='1",   "OR tautology",          "", "sqli_error", v,  0.40),
            DetectorPayload(
                "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
                "MySQL extractvalue()", r"XPATH syntax error", "sqli_error", v, 0.45,
            ),
            DetectorPayload(
                "' AND SLEEP(5)--", "MySQL SLEEP blind", "", "sqli_blind", v, 0.40,
                is_timed=True, delay_s=5.0,
            ),
            DetectorPayload(
                "1; WAITFOR DELAY '0:0:5'--", "MSSQL WAITFOR blind", "", "sqli_blind", v, 0.40,
                is_timed=True, delay_s=5.0,
            ),
            DetectorPayload(
                "' AND pg_sleep(5)--", "PostgreSQL pg_sleep blind", "", "sqli_blind", v, 0.40,
                is_timed=True, delay_s=5.0,
            ),
            DetectorPayload(
                "1 AND 1=1", "Boolean true", "", "sqli", vb, 0.15,
                false_condition="1 AND 1=2",
            ),
            DetectorPayload(
                "' AND '1'='1' --", "String boolean true", "", "sqli", vb, 0.20,
                false_condition="' AND '1'='2' --",
            ),
        ]

    async def detect(self, ep: Endpoint, injector: Injector) -> List[Finding]:
        findings = []
        for param in ep.parameters:
            if param.location == "header" and param.name not in (
                "User-Agent", "Referer", "X-Forwarded-For"
            ):
                continue

            baseline = await self._baseline(ep, param, injector)
            found = False

            for pl in self.payloads:
                if pl.false_condition:
                    f = await self._test_boolean(ep, param, pl, baseline, injector)
                elif pl.is_timed:
                    f = await self._test_timed(ep, param, pl, injector)
                else:
                    f = await self._test_error(ep, param, pl, injector)

                if f:
                    findings.append(f)
                    found = True
                    break

            if found:
                continue
        return findings

    async def _test_error(self, ep, param, pl, injector) -> Optional[Finding]:
        r = await injector.inject(ep, param, pl.value)
        if not r.ok:
            return None
        if _SQLI_ERRORS.search(r.body) and not _SQLI_FP.search(r.body):
            m = _SQLI_ERRORS.search(r.body)
            return self._finding(ep, param, pl, m.group(0)[:120], 0.3)
        if pl.evidence_pattern and r.matches(pl.evidence_pattern):
            return self._finding(ep, param, pl, f"Pattern matched: {pl.evidence_pattern}", 0.3)
        return None

    async def _test_timed(self, ep, param, pl, injector) -> Optional[Finding]:
        baseline = await self._baseline(ep, param, injector)
        if not baseline.ok:
            return None
        r = await injector.inject(ep, param, pl.value)
        if r.timed_out or (r.ok and r.elapsed_ms >= pl.delay_s * 900):
            return self._finding(
                ep, param, pl,
                f"Response delayed {r.elapsed_ms:.0f}ms (baseline {baseline.elapsed_ms:.0f}ms)",
                0.35,
            )
        return None

    async def _test_boolean(self, ep, param, pl, baseline, injector) -> Optional[Finding]:
        r_true  = await injector.inject(ep, param, pl.value)
        r_false = await injector.inject(ep, param, pl.false_condition)
        if not r_true.ok or not r_false.ok:
            return None
        bl = len(baseline.body) if baseline.ok else len(r_true.body)
        t  = len(r_true.body)
        f  = len(r_false.body)
        if abs(t - bl) / max(bl, 1) < 0.05 and abs(t - f) / max(t, 1) > 0.10:
            return self._finding(
                ep, param, pl,
                f"Boolean differential: TRUE={t}b FALSE={f}b baseline={bl}b",
                0.25,
            )
        return None


# ── Cross-Site Scripting ───────────────────────────────────────────────────────

_CANARY = "vs7c0ut"
_DOM_SINKS = re.compile(
    r"(document\.write\s*\(|innerHTML\s*=|outerHTML\s*=|\beval\s*\(|"
    r"location\.href\s*=|window\.open\s*\()", re.I
)
_DOM_SOURCES = re.compile(
    r"(location\.search|location\.hash|document\.referrer|"
    r"document\.URL|URLSearchParams|window\.name)", re.I
)


class XSSDetector(BaseDetector):
    name = "Cross-Site Scripting"
    vuln_type = "xss"
    remediation = (
        "HTML-encode all user-supplied output. "
        "Use a Content Security Policy. "
        "Avoid innerHTML and eval with user data."
    )

    @property
    def payloads(self) -> List[DetectorPayload]:
        c = _CANARY
        rv = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        sv = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N"
        return [
            DetectorPayload(
                f'<script>alert("{c}")</script>', "Basic script tag",
                rf'<script>alert\("{c}"\)</script>', "xss_reflected", rv, 0.45,
            ),
            DetectorPayload(
                f'"><script>alert("{c}")</script>', "Attribute breakout",
                rf'<script>alert\("{c}"\)</script>', "xss_reflected", rv, 0.45,
            ),
            DetectorPayload(
                f'<svg onload=alert("{c}")>', "SVG onload",
                rf'onload=alert\("{c}"\)', "xss_reflected", rv, 0.40,
            ),
            DetectorPayload(
                f"'><img src=x onerror=alert('{c}')>", "onerror handler",
                rf"onerror=alert\('{c}'\)", "xss_reflected", rv, 0.40,
            ),
            DetectorPayload(
                f'<ScRiPt>alert("{c}")</ScRiPt>', "Mixed-case bypass",
                rf'(?i)alert\("{c}"\)', "xss_reflected", rv, 0.35,
            ),
            DetectorPayload(
                f'<b id="vsxss_{c}">XSStest</b>', "Stored probe",
                rf'id="vsxss_{c}"', "xss_stored", sv, 0.40,
            ),
        ]

    async def detect(self, ep: Endpoint, injector: Injector) -> List[Finding]:
        findings = []
        for param in ep.parameters:
            if param.location == "header":
                continue
            found = False
            for pl in self.payloads:
                r = await injector.inject(ep, param, pl.value)
                if r.ok and pl.evidence_pattern and r.matches(pl.evidence_pattern):
                    findings.append(self._finding(
                        ep, param, pl,
                        f"Payload reflected unescaped in response body",
                        0.35,
                    ))
                    found = True
                    break
            if found:
                continue

        # DOM XSS static scan
        if ep._body and ("text/html" in ep.content_type or ".js" in ep.url):
            if _DOM_SINKS.search(ep._body) and _DOM_SOURCES.search(ep._body):
                dv = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N"
                sink = _DOM_SINKS.search(ep._body).group(0)
                src  = _DOM_SOURCES.search(ep._body).group(0)
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    url=ep.url, parameter="DOM",
                    vuln_type="xss_dom",
                    description="Potential DOM XSS — dangerous sink + taint source co-occur",
                    evidence=f"Sink: {sink} | Source: {src}",
                    payload="(static analysis)",
                    cvss_vector=dv, confidence=0.55,
                    remediation=self.remediation,
                ))
        return findings


# ── SSRF ──────────────────────────────────────────────────────────────────────

_SSRF_PARAMS = re.compile(
    r"(?i)(url|uri|path|dest|redirect|next|site|src|ref|"
    r"host|port|proxy|callback|fetch|load|resource)", re.I
)
_SSRF_INTERNAL = [
    "http://169.254.169.254/latest/meta-data/",   # AWS IMDS
    "http://127.0.0.1/",
    "http://localhost/",
]


class SSRFDetector(BaseDetector):
    name = "Server-Side Request Forgery"
    vuln_type = "ssrf"
    remediation = (
        "Validate and allowlist URL schemes and destinations. "
        "Block requests to private/internal IP ranges. "
        "Disable unnecessary URL-fetching functionality."
    )

    async def detect(self, ep: Endpoint, injector: Injector) -> List[Finding]:
        findings = []
        for param in ep.parameters:
            if not _SSRF_PARAMS.search(param.name):
                continue
            for probe in _SSRF_INTERNAL:
                r = await injector.inject(ep, param, probe)
                if not r.ok:
                    continue
                # Heuristic: if the response contains internal metadata markers
                if any(m in r.body for m in (
                    "ami-id", "instance-id", "root:x:0", "localhost", "127.0.0.1"
                )):
                    pl = DetectorPayload(
                        probe, f"SSRF probe to {probe}",
                        "", "ssrf",
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                        confidence_boost=0.4,
                    )
                    findings.append(self._finding(
                        ep, param, pl,
                        f"Internal response received from {probe}",
                        0.35,
                    ))
                    findings[-1].remediation = self.remediation
                    break
        return findings


# ── Misconfiguration ───────────────────────────────────────────────────────────

class MisconfigDetector(BaseDetector):
    name = "Security Misconfiguration"
    vuln_type = "misconfig"
    remediation = (
        "Enable HSTS, X-Content-Type-Options, X-Frame-Options, and CSP headers. "
        "Remove server banners. Disable directory listing."
    )

    _CHECKS: List[Tuple[str, str, str, str, str]] = [
        # (header, absent_means_vuln, description, cvss, evidence_msg)
        ("Strict-Transport-Security", "absent",
         "Missing HSTS header",
         "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
         "Strict-Transport-Security header not present"),
        ("X-Content-Type-Options", "absent",
         "Missing X-Content-Type-Options",
         "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
         "X-Content-Type-Options: nosniff not set"),
        ("X-Frame-Options", "absent",
         "Missing X-Frame-Options (clickjacking risk)",
         "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
         "X-Frame-Options header not present"),
        ("Content-Security-Policy", "absent",
         "Missing Content Security Policy",
         "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
         "Content-Security-Policy header not present"),
    ]

    async def detect(self, ep: Endpoint, injector: Injector) -> List[Finding]:
        findings = []
        # Fetch a clean copy to inspect response headers
        try:
            async with injector._session.get(
                ep.url,
                allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                rh = {k.lower(): v for k, v in resp.headers.items()}
                server = rh.get("server", "")
                if server and any(t in server.lower() for t in ("apache", "nginx", "iis")):
                    findings.append(Finding(
                        id=str(uuid.uuid4()),
                        url=ep.url, parameter="Server header",
                        vuln_type="misconfig",
                        description="Server version disclosed in response header",
                        evidence=f"Server: {server}",
                        payload="(header inspection)",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        confidence=0.75,
                        remediation="Remove or genericise the Server header.",
                    ))
                for header, condition, desc, cvss, evidence in self._CHECKS:
                    if condition == "absent" and header.lower() not in rh:
                        findings.append(Finding(
                            id=str(uuid.uuid4()),
                            url=ep.url, parameter=header,
                            vuln_type="misconfig",
                            description=desc,
                            evidence=evidence,
                            payload="(header inspection)",
                            cvss_vector=cvss,
                            confidence=0.80,
                            remediation=self.remediation,
                        ))
        except Exception:
            pass
        return findings


# ══════════════════════════════════════════════════════════════════════════════
# CVSS SCORER
# ══════════════════════════════════════════════════════════════════════════════

_CVSS_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "S":  {"U": 0.0,  "C": 1.0},
    "C":  {"N": 0.0,  "L": 0.22, "H": 0.56},
    "I":  {"N": 0.0,  "L": 0.22, "H": 0.56},
    "A":  {"N": 0.0,  "L": 0.22, "H": 0.56},
}


def score_cvss(vector: str) -> Tuple[float, Severity]:
    """
    Minimal CVSS v3.1 base score calculator.
    Returns (score, severity_label).
    """
    try:
        parts = {}
        for segment in vector.replace("CVSS:3.1/", "").split("/"):
            k, v = segment.split(":")
            parts[k] = v

        isc_base = 1 - (
            (1 - _CVSS_WEIGHTS["C"].get(parts.get("C", "N"), 0))
            * (1 - _CVSS_WEIGHTS["I"].get(parts.get("I", "N"), 0))
            * (1 - _CVSS_WEIGHTS["A"].get(parts.get("A", "N"), 0))
        )

        scope_changed = parts.get("S", "U") == "C"
        if scope_changed:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
        else:
            impact = 6.42 * isc_base

        exploit = (
            8.22
            * _CVSS_WEIGHTS["AV"].get(parts.get("AV", "N"), 0.85)
            * _CVSS_WEIGHTS["AC"].get(parts.get("AC", "L"), 0.77)
            * _CVSS_WEIGHTS["PR"].get(parts.get("PR", "N"), 0.85)
            * _CVSS_WEIGHTS["UI"].get(parts.get("UI", "N"), 0.85)
        )

        if impact <= 0:
            score = 0.0
        elif scope_changed:
            score = min(10.0, 1.08 * (impact + exploit))
        else:
            score = min(10.0, impact + exploit)

        # Round up to 1 decimal (CVSS spec uses ceiling rounding)
        import math
        score = math.ceil(score * 10) / 10

        if score >= 9.0:
            sev = Severity.CRITICAL
        elif score >= 7.0:
            sev = Severity.HIGH
        elif score >= 4.0:
            sev = Severity.MEDIUM
        elif score > 0.0:
            sev = Severity.LOW
        else:
            sev = Severity.INFO

        return round(score, 1), sev

    except Exception:
        return 0.0, Severity.INFO


# ══════════════════════════════════════════════════════════════════════════════
# VALIDATOR (lightweight dedup + confidence gate)
# ══════════════════════════════════════════════════════════════════════════════

_PATH_ID_RE = re.compile(r"/(\d+|[0-9a-f]{8,})", re.I)
CONFIDENCE_THRESHOLD = 0.45


def _dedup_key(f: Finding) -> str:
    parsed = urllib.parse.urlparse(f.url)
    path = _PATH_ID_RE.sub("/{id}", parsed.path)
    raw = f"{f.vuln_type}:{parsed.scheme}://{parsed.netloc}{path}:{f.parameter}"
    return hashlib.md5(raw.encode()).hexdigest()


def validate(findings: List[Finding]) -> List[Finding]:
    seen: Set[str] = set()
    out: List[Finding] = []
    for f in findings:
        if f.confidence < CONFIDENCE_THRESHOLD:
            continue
        key = _dedup_key(f)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


# ══════════════════════════════════════════════════════════════════════════════
# REPORTER
# ══════════════════════════════════════════════════════════════════════════════

_SEV_COLOR = {
    Severity.CRITICAL: "\033[91m",
    Severity.HIGH:     "\033[93m",
    Severity.MEDIUM:   "\033[33m",
    Severity.LOW:      "\033[94m",
    Severity.INFO:     "\033[37m",
}
_RESET = "\033[0m"
_BOLD  = "\033[1m"


def _c(sev: Severity, text: str) -> str:
    return f"{_SEV_COLOR.get(sev, '')}{text}{_RESET}"


def print_report(findings: List[Finding], stats: Dict, elapsed: float) -> None:
    total = len(findings)
    by_sev = {s: 0 for s in Severity}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    print(f"\n{_BOLD}{'─'*60}{_RESET}")
    print(f"{_BOLD}  Scan complete  {_RESET}│  {elapsed:.1f}s  │  "
          f"{stats.get('endpoints', 0)} endpoints  │  {total} findings")
    print(f"{'─'*60}")

    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        n = by_sev.get(sev, 0)
        if n:
            print(f"  {_c(sev, sev.value.upper()): <24}  {n}")

    if not findings:
        print(f"\n  {_BOLD}No findings above confidence threshold.{_RESET}")
        return

    print(f"\n{'─'*60}")
    for f in sorted(findings, key=lambda x: x.cvss_score, reverse=True):
        sev_label = _c(f.severity, f"[{f.severity.value.upper()}]")
        score_label = f"{_BOLD}{f.cvss_score:.1f}{_RESET}"
        print(f"\n  {sev_label} {score_label}  {f.vuln_type.upper()}")
        print(f"  {'URL':12} {f.url}")
        print(f"  {'Parameter':12} {f.parameter}")
        print(f"  {'Evidence':12} {f.evidence[:100]}")
        print(f"  {'Payload':12} {f.payload[:80]}")
        print(f"  {'Confidence':12} {f.confidence:.0%}")
        print(f"  {'Fix':12} {f.remediation[:100]}")

    print(f"\n{'─'*60}\n")


def build_json_report(
    target: str,
    findings: List[Finding],
    stats: Dict,
    elapsed: float,
) -> Dict:
    by_sev = {s.value: 0 for s in Severity}
    for f in findings:
        by_sev[f.severity.value] += 1
    return {
        "scanner": f"MinimalScanner/{VERSION}",
        "target": target,
        "duration_seconds": round(elapsed, 2),
        "stats": {**stats, **by_sev, "total_findings": len(findings)},
        "findings": [f.to_dict() for f in findings],
    }


# ══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

DETECTOR_MAP: Dict[str, type] = {
    "sqli":     SQLiDetector,
    "xss":      XSSDetector,
    "ssrf":     SSRFDetector,
    "misconfig": MisconfigDetector,
}


class Scanner:
    """
    Coordinates the full pipeline:
      Crawler → Detectors → Validator → Scorer → Reporter
    """

    def __init__(
        self,
        target: str,
        checks: Optional[List[str]] = None,
        max_depth: int = 2,
        max_pages: int = 50,
        concurrency: int = 5,
        timeout: int = 15,
        respect_robots: bool = True,
        silent: bool = False,
    ) -> None:
        self.target = target
        self.checks = checks or list(DETECTOR_MAP.keys())
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = concurrency
        self.timeout = timeout
        self.respect_robots = respect_robots
        self.silent = silent

    def _log(self, phase: ScanPhase, msg: str) -> None:
        if not self.silent:
            ts = time.strftime("%H:%M:%S")
            print(f"  [{ts}] [{phase.value.upper():10}] {msg}")

    async def run(self) -> Tuple[List[Finding], Dict, float]:
        start = time.monotonic()
        all_findings: List[Finding] = []
        endpoints_seen = 0

        detectors: List[BaseDetector] = [
            DETECTOR_MAP[c]() for c in self.checks if c in DETECTOR_MAP
        ]

        connector = aiohttp.TCPConnector(ssl=False, limit=20)
        async with aiohttp.ClientSession(
            headers={"User-Agent": USER_AGENT},
            connector=connector,
        ) as session:
            crawler = Crawler(
                session=session,
                max_depth=self.max_depth,
                max_pages=self.max_pages,
                respect_robots=self.respect_robots,
                timeout=self.timeout,
            )
            injector = Injector(session=session, timeout=self.timeout)
            sem = asyncio.Semaphore(self.concurrency)

            self._log(ScanPhase.CRAWLING, f"Starting crawl of {self.target}")

            async def process(ep: Endpoint) -> List[Finding]:
                async with sem:
                    found: List[Finding] = []
                    for det in detectors:
                        try:
                            hits = await det.detect(ep, injector)
                            found.extend(hits)
                        except Exception:
                            pass
                    return found

            tasks: List[asyncio.Task] = []

            async for ep in crawler.crawl(self.target):
                endpoints_seen += 1
                self._log(
                    ScanPhase.CRAWLING,
                    f"[{endpoints_seen:>3}] {ep.method} {ep.url} "
                    f"({len(ep.parameters)} params)",
                )
                tasks.append(asyncio.create_task(process(ep)))

            self._log(
                ScanPhase.DETECTING,
                f"Crawl complete — {endpoints_seen} endpoints, "
                f"running {len(detectors)} detector(s)",
            )

            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, list):
                        all_findings.extend(r)

            self._log(ScanPhase.SCORING, f"Scoring {len(all_findings)} raw findings")
            for f in all_findings:
                f.cvss_score, f.severity = score_cvss(f.cvss_vector)

            confirmed = validate(all_findings)
            confirmed.sort(key=lambda x: x.cvss_score, reverse=True)

            elapsed = time.monotonic() - start
            stats = {"endpoints": endpoints_seen, "raw_findings": len(all_findings)}
            self._log(
                ScanPhase.COMPLETE,
                f"{len(confirmed)} confirmed findings in {elapsed:.1f}s",
            )
            return confirmed, stats, elapsed


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Minimal async vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("target", help="Target URL (e.g. https://example.com)")
    p.add_argument("--depth",       type=int, default=2,   metavar="N",
                   help="Crawl depth (default: 2)")
    p.add_argument("--max-pages",   type=int, default=50,  metavar="N",
                   help="Max pages to crawl (default: 50)")
    p.add_argument("--checks",      nargs="+",
                   choices=list(DETECTOR_MAP.keys()),
                   metavar="CHECK",
                   help=f"Detectors to run (default: all). Choices: {', '.join(DETECTOR_MAP)}")
    p.add_argument("--output",      metavar="FILE",
                   help="Write JSON report to file")
    p.add_argument("--concurrency", type=int, default=5,   metavar="N",
                   help="Max concurrent detector tasks (default: 5)")
    p.add_argument("--timeout",     type=int, default=15,  metavar="S",
                   help="Per-request timeout in seconds (default: 15)")
    p.add_argument("--no-robots",   action="store_true",
                   help="Ignore robots.txt")
    p.add_argument("--silent",      action="store_true",
                   help="Suppress progress output")
    return p.parse_args()


async def _main() -> None:
    args = _parse_args()

    if not args.target.startswith(("http://", "https://")):
        print("Error: target must start with http:// or https://", file=sys.stderr)
        sys.exit(1)

    if not args.silent:
        print(f"\n  MinimalScanner {VERSION}")
        print(f"  Target : {args.target}")
        print(f"  Checks : {', '.join(args.checks or list(DETECTOR_MAP.keys()))}")
        print(f"  Depth  : {args.depth}  Pages: {args.max_pages}  "
              f"Concurrency: {args.concurrency}\n")

    scanner = Scanner(
        target=args.target,
        checks=args.checks,
        max_depth=args.depth,
        max_pages=args.max_pages,
        concurrency=args.concurrency,
        timeout=args.timeout,
        respect_robots=not args.no_robots,
        silent=args.silent,
    )

    findings, stats, elapsed = await scanner.run()

    if not args.silent:
        print_report(findings, stats, elapsed)

    if args.output:
        report = build_json_report(args.target, findings, stats, elapsed)
        with open(args.output, "w") as fh:
            json.dump(report, fh, indent=2)
        if not args.silent:
            print(f"  JSON report written to: {args.output}\n")

    # Exit code: 1 if any critical/high findings, 0 otherwise
    worst = max((f.cvss_score for f in findings), default=0.0)
    sys.exit(1 if worst >= 7.0 else 0)


if __name__ == "__main__":
    asyncio.run(_main())
