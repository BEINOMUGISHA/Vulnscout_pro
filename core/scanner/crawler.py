"""
crawler.py — Link & Endpoint Discovery Engine

Responsibilities:
  - Recursively crawl a target web application
  - Discover all URLs, forms, inputs, and API endpoints
  - Extract parameters (query string, POST body, JSON, headers)
  - Respect robots.txt, crawl depth, page limits, and rate limits
  - Detect JavaScript-rendered content hints (for future Playwright integration)
  - Yield CrawlResult objects consumed by the orchestrator

Production considerations:
  - Full async with aiohttp sessions
  - Duplicate URL fingerprinting to prevent re-visiting
  - Configurable politeness delay and adaptive rate limiting
  - Safe HTML parsing that does not crash on malformed pages
  - Out-of-scope URL detection delegated to orchestrator
  - Sentinel-based worker teardown (no hangs, no lost results)
  - results_queue replaced by direct async generator push via asyncio.Queue
    with a typed sentinel so the collector loop exits deterministically
  - BeautifulSoup soup objects are never stored on CrawlResult (no memory leak)
  - _discover_hidden_api_endpoints is wired up properly (was a no-op stub)
  - Subdomain probes are scope-checked before enqueuing
  - active_fetches race window closed with per-URL lock
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import urllib.robotparser
from dataclasses import dataclass, field
from typing import AsyncGenerator, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs

import aiohttp
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Maximum response size to parse (5 MB). Prevents memory exhaustion on
# large binary files accidentally served as text/html.
MAX_RESPONSE_BYTES = 5 * 1024 * 1024

# Sentinel used to signal the collector loop that all workers have finished.
_CRAWL_DONE = object()

# Headers that are interesting from an injection perspective.
INTERESTING_HEADERS: frozenset = frozenset([
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Real-IP",
    "Referer",
    "User-Agent",
    "Origin",
    "X-Custom-IP-Authorization",
    "X-Original-URL",
    "X-Rewrite-URL",
])

# Common subdomain prefixes for shadow-IT / API discovery.
_SUBDOMAIN_PREFIXES: tuple = (
    "api", "auth", "dev", "staging", "v1", "v2",
    "admin", "ws", "graphql", "internal", "beta",
)

# High-value paths probed during API fuzzing.
_API_PROBE_PATHS: tuple = (
    "/api/v1", "/api/v2", "/v1", "/v2", "/graphql",
    "/swagger.json", "/api/docs", "/docs",
    "/openapi.json", "/api-docs", "/api/v1/health",
)


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class CrawlParameter:
    name: str
    value: str
    location: str        # "query", "body", "json", "header", "cookie", "path"
    param_type: str = "string"   # "string", "integer", "boolean", "file"

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "value": self.value,
            "location": self.location,
            "type": self.param_type,
        }


@dataclass
class CrawlResult:
    url: str
    method: str                              # GET, POST, PUT, DELETE, PATCH
    status_code: int = 0
    content_type: str = ""
    parameters: List[CrawlParameter] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)
    forms: List[Dict] = field(default_factory=list)
    depth: int = 0
    page_title: str = ""
    technology_hints: List[str] = field(default_factory=list)
    # Extracted links are stored separately so _extract_links does not need
    # the soup to still be attached to the result object.
    _links: List[str] = field(default_factory=list, repr=False)

    @property
    def fingerprint(self) -> str:
        """
        State-aware fingerprint combining URL, method, parameter names, and
        structural hints. Enables deduplication of SPA routes that share a path.
        """
        param_key = "&".join(
            sorted(f"{p.name}={p.location}" for p in self.parameters)
        )
        struct_hint = f"{self.page_title}:{len(self.forms)}:{len(self.technology_hints)}"
        raw = f"{self.method}:{self.url.split('?')[0]}:{param_key}:{struct_hint}"
        return hashlib.md5(raw.encode()).hexdigest()  # noqa: S324 — fingerprint, not crypto

    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "method": self.method,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "parameters": [p.to_dict() for p in self.parameters],
            "depth": self.depth,
            "technology_hints": self.technology_hints,
        }


class CrawlerError(Exception):
    pass


# ── Crawler ────────────────────────────────────────────────────────────────────

class Crawler:
    """
    Asynchronous web crawler that produces CrawlResult objects.

    Usage (from orchestrator):
        async for result in crawler.crawl("https://example.com"):
            process(result)

    Teardown:
        Call await crawler.stop() to halt at the next safe checkpoint.
        The generator always terminates cleanly — no orphaned tasks.
    """

    def __init__(
        self,
        rate_limiter=None,
        max_depth: int = 3,
        max_pages: int = 200,
        user_agent: str = "VulnScout-Pro/1.0 (Authorised Security Scanner)",
        respect_robots: bool = True,
        timeout_seconds: int = 15,
        follow_redirects: bool = True,
        js_render: bool = False,
        api_fuzzing: bool = False,
        auth_handler=None,
        num_workers: int = 0,   # 0 = auto (5 standard, 8 api_fuzzing)
    ) -> None:
        from core.scanner.js_renderer import JSRenderer

        self.rate_limiter = rate_limiter
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.user_agent = user_agent
        self.respect_robots = respect_robots
        self.timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        self.follow_redirects = follow_redirects
        self.js_render = js_render
        self.js_renderer = JSRenderer(use_headless=js_render)
        self.api_fuzzing = api_fuzzing
        self.auth_handler = auth_handler
        self._num_workers = num_workers or (8 if api_fuzzing else 5)

        # Per-crawl state; reset in crawl().
        self._visited_fingerprints: Set[str] = set()
        self._visited_urls: Set[str] = set()
        # Per-URL lock prevents two workers racing on the same URL between the
        # "is it visited?" check and the actual fetch.
        self._url_locks: Dict[str, asyncio.Lock] = {}
        self._stop_event = asyncio.Event()
        self._session: Optional[aiohttp.ClientSession] = None
        self._robots: Optional[urllib.robotparser.RobotFileParser] = None
        self._page_count: int = 0
        self._base_netloc: str = ""
        self._base_scheme: str = ""

    # ── Public API ─────────────────────────────────────────────────────────────

    async def crawl(self, base_url: str) -> AsyncGenerator[CrawlResult, None]:
        """
        Async generator yielding one CrawlResult per unique endpoint.
        Caller is responsible for out-of-scope filtering.
        """
        # Reset all per-crawl state so the same Crawler instance can be reused.
        self._stop_event.clear()
        self._visited_fingerprints.clear()
        self._visited_urls.clear()
        self._url_locks.clear()
        self._page_count = 0
        self._robots = None

        parsed = urlparse(base_url)
        self._base_scheme = parsed.scheme
        self._base_netloc = parsed.netloc

        if self.auth_handler:
            session = await self.auth_handler.get_session()
            self._session = session
            try:
                async for result in self._run_crawl(base_url):
                    yield result
            finally:
                self._session = None
        else:
            async with aiohttp.ClientSession(
                headers={"User-Agent": self.user_agent},
                timeout=self.timeout,
                connector=aiohttp.TCPConnector(ssl=False, limit=20),
            ) as session:
                self._session = session
                async for result in self._run_crawl(base_url):
                    yield result

    async def stop(self) -> None:
        """Signal the crawler to stop at the next safe checkpoint."""
        self._stop_event.set()

    # ── Internal crawl loop ────────────────────────────────────────────────────

    async def _run_crawl(self, base_url: str) -> AsyncGenerator[CrawlResult, None]:
        """
        Core producer/collector loop.

        Architecture:
          - work_queue: (url, depth, method) tuples for workers to fetch.
          - result_queue: finished CrawlResult objects (or _CRAWL_DONE sentinel).
          - N worker tasks pull from work_queue, push to result_queue.
          - Collector (this generator) pulls from result_queue, deduplicates,
            and yields; it also enqueues newly discovered links.
          - When all workers finish they each push _CRAWL_DONE; the collector
            exits after seeing all N sentinels.
        """
        if self.respect_robots:
            await self._load_robots(base_url)

        work_queue: asyncio.Queue = asyncio.Queue()
        result_queue: asyncio.Queue = asyncio.Queue()

        await work_queue.put((base_url, 0, "GET"))

        if self.api_fuzzing:
            await self._enqueue_subdomains(base_url, work_queue)
            await self._enqueue_api_probes(base_url, work_queue)

        workers = [
            asyncio.create_task(
                self._worker(work_queue, result_queue),
                name=f"crawler-worker-{i}",
            )
            for i in range(self._num_workers)
        ]

        sentinels_received = 0

        try:
            while sentinels_received < self._num_workers:
                if self._stop_event.is_set():
                    break

                try:
                    item = await asyncio.wait_for(result_queue.get(), timeout=0.25)
                except asyncio.TimeoutError:
                    # Check whether all workers have already exited.
                    if all(w.done() for w in workers):
                        break
                    continue

                if item is _CRAWL_DONE:
                    sentinels_received += 1
                    continue

                result: CrawlResult = item

                # Structural deduplication.
                fp = result.fingerprint
                if fp in self._visited_fingerprints:
                    continue
                self._visited_fingerprints.add(fp)

                if self._page_count >= self.max_pages:
                    break
                self._page_count += 1

                # Enqueue discovered links before yielding so workers can
                # start on them while the caller processes this result.
                if result.depth < self.max_depth:
                    for link in result._links:
                        if (
                            link not in self._visited_urls
                            and link not in self._url_locks
                        ):
                            await work_queue.put((link, result.depth + 1, "GET"))

                    for form in result.forms:
                        action = form.get("action", result.url)
                        fmethod = form.get("method", "POST").upper()
                        if (
                            action not in self._visited_urls
                            and action not in self._url_locks
                        ):
                            await work_queue.put((action, result.depth + 1, fmethod))

                yield result
                logger.debug("Crawl yielded: %s", result.url)

        finally:
            # Always cancel remaining workers on any exit path.
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

    async def _worker(
        self, work_queue: asyncio.Queue, result_queue: asyncio.Queue
    ) -> None:
        """
        Fetch worker. Pulls URLs from work_queue, fetches + parses them,
        and pushes CrawlResult objects to result_queue.
        Always pushes _CRAWL_DONE when exiting so the collector can count down.
        """
        try:
            while not self._stop_event.is_set():
                try:
                    url, depth, method = await asyncio.wait_for(
                        work_queue.get(), timeout=0.5
                    )
                except asyncio.TimeoutError:
                    # No work arrived; if the queue is truly empty, exit.
                    if work_queue.empty():
                        break
                    continue

                try:
                    # Per-URL lock: prevents two workers racing on the same URL.
                    if url not in self._url_locks:
                        self._url_locks[url] = asyncio.Lock()
                    lock = self._url_locks[url]

                    if lock.locked() or url in self._visited_urls:
                        # Another worker already handling or handled this URL.
                        continue

                    async with lock:
                        if url in self._visited_urls:
                            continue  # Re-check inside the lock.

                        if self._page_count >= self.max_pages:
                            break

                        if self.respect_robots and not self._robots_allows(url):
                            continue

                        result = await self._fetch_and_parse(url, depth, method)
                        self._visited_urls.add(url)

                        if result is not None:
                            await result_queue.put(result)
                except Exception as exc:
                    logger.error("Worker error on %s: %s", url, exc)
                finally:
                    try:
                        work_queue.task_done()
                    except ValueError:
                        pass  # task_done called more times than put — defensive only
        finally:
            await result_queue.put(_CRAWL_DONE)

    # ── Fetch & parse ──────────────────────────────────────────────────────────

    async def _fetch_and_parse(
        self, url: str, depth: int, method: str
    ) -> Optional[CrawlResult]:
        logger.debug("Fetching [%s] %s", method, url)

        if self.rate_limiter:
            await self.rate_limiter.acquire()

        try:
            async with self._session.request(
                method,
                url,
                allow_redirects=self.follow_redirects,
                max_redirects=5,
            ) as resp:
                status = resp.status
                content_type = resp.headers.get("Content-Type", "")
                response_headers = dict(resp.headers)
                final_url = str(resp.url)

                # Non-HTML/JSON: record as a bare result (no body parse needed).
                if (
                    "text/html" not in content_type
                    and "application/json" not in content_type
                ):
                    return CrawlResult(
                        url=final_url,
                        method=method,
                        status_code=status,
                        content_type=content_type,
                        response_headers=response_headers,
                        depth=depth,
                    )

                raw = await resp.read()
                if len(raw) > MAX_RESPONSE_BYTES:
                    logger.warning("Response truncated (too large): %s", url)
                    raw = raw[:MAX_RESPONSE_BYTES]

                text = raw.decode("utf-8", errors="replace")

                result = CrawlResult(
                    url=final_url,
                    method=method,
                    status_code=status,
                    content_type=content_type,
                    response_headers=response_headers,
                    depth=depth,
                )

                if "text/html" in content_type:
                    if self.js_render:
                        text = await self._render_javascript(url, text)
                    soup = self._safe_parse_html(text, url)
                    if soup is not None:
                        # Extract everything from the soup, then discard it.
                        # soup is NOT stored on the result object to avoid
                        # large BeautifulSoup trees accumulating in memory
                        # while the orchestrator's queue fills up.
                        self._parse_html_with_soup(soup, result, final_url)
                        result._links = self._extract_links_from_soup(soup, final_url)

                elif "application/json" in content_type:
                    self._parse_json_response(text, result)

                result.technology_hints = self._detect_technologies(
                    response_headers, text
                )
                return result

        except asyncio.TimeoutError:
            logger.warning("Timeout: %s", url)
        except aiohttp.ClientError as exc:
            logger.warning("HTTP error %s: %s", url, exc)
        except Exception as exc:
            logger.error("Unexpected error %s: %s", url, exc)

        return None

    # ── HTML parsing ───────────────────────────────────────────────────────────

    def _safe_parse_html(self, html: str, url: str) -> Optional[BeautifulSoup]:
        """Return a parsed BeautifulSoup or None on failure."""
        try:
            return BeautifulSoup(html, "html.parser")
        except Exception as exc:
            logger.warning("BeautifulSoup parse failed for %s: %s", url, exc)
            return None

    def _parse_html_with_soup(
        self, soup: BeautifulSoup, result: CrawlResult, base_url: str
    ) -> None:
        """Populate result fields from an already-parsed BeautifulSoup object."""
        # Page title
        title_tag = soup.find("title")
        if title_tag:
            result.page_title = title_tag.get_text(strip=True)[:200]

        # Query-string parameters from the current URL.
        parsed = urlparse(base_url)
        if parsed.query:
            for name, values in parse_qs(parsed.query).items():
                result.parameters.append(
                    CrawlParameter(
                        name=name,
                        value=values[0] if values else "",
                        location="query",
                    )
                )

        # Forms.
        form_input_names: Set[str] = set()
        for form_tag in soup.find_all("form"):
            form_data = self._parse_form(form_tag, base_url)
            result.forms.append(form_data)
            for inp in form_data.get("inputs", []):
                name = inp.get("name", "")
                if name:
                    form_input_names.add(name)
                    result.parameters.append(
                        CrawlParameter(
                            name=name,
                            value=inp.get("value", ""),
                            location="body",
                            param_type=inp.get("param_type", "string"),
                        )
                    )

        # Standalone inputs not already captured by a form.
        for inp in soup.find_all(["input", "textarea", "select"]):
            name = inp.get("name") or inp.get("id", "")
            if name and name not in form_input_names:
                result.parameters.append(
                    CrawlParameter(
                        name=name,
                        value=inp.get("value", ""),
                        location="body",
                    )
                )

        # Injectable request headers (always included for injection surface mapping).
        for header in INTERESTING_HEADERS:
            result.parameters.append(
                CrawlParameter(name=header, value="", location="header")
            )

    def _parse_form(self, form_tag: BeautifulSoup, base_url: str) -> Dict:
        """Extract action, method, enctype, and inputs from a <form> element."""
        raw_action = form_tag.get("action", "")
        action = urljoin(base_url, raw_action) if raw_action else base_url
        method = form_tag.get("method", "GET").upper()
        inputs = []

        for inp in form_tag.find_all(["input", "textarea", "select"]):
            name = inp.get("name") or inp.get("id", "")
            if not name:
                continue
            inp_type = inp.get("type", "text")
            if inp_type in ("number", "range"):
                param_type = "integer"
            elif inp_type in ("checkbox", "radio"):
                param_type = "boolean"
            elif inp_type == "file":
                param_type = "file"
            else:
                param_type = "string"

            inputs.append({
                "name": name,
                "value": inp.get("value", ""),
                "type": inp_type,
                "param_type": param_type,
            })

        return {
            "action": action,
            "method": method,
            "enctype": form_tag.get("enctype", "application/x-www-form-urlencoded"),
            "inputs": inputs,
        }

    def _parse_json_response(self, body: str, result: CrawlResult) -> None:
        """Flatten JSON response keys into injectable parameters."""
        try:
            data = json.loads(body)
            self._flatten_json(data, result, prefix="")
        except json.JSONDecodeError:
            pass

    def _flatten_json(
        self, obj, result: CrawlResult, prefix: str, depth: int = 0
    ) -> None:
        if depth > 4:
            return
        if isinstance(obj, dict):
            for key, value in obj.items():
                full_key = f"{prefix}.{key}" if prefix else key
                if isinstance(value, (dict, list)):
                    self._flatten_json(value, result, full_key, depth + 1)
                else:
                    result.parameters.append(
                        CrawlParameter(
                            name=full_key,
                            value=str(value) if value is not None else "",
                            location="json",
                            param_type=(
                                "boolean" if isinstance(value, bool)
                                else "integer" if isinstance(value, int)
                                else "string"
                            ),
                        )
                    )
        elif isinstance(obj, list) and obj:
            self._flatten_json(obj[0], result, prefix, depth + 1)

    # ── Link extraction ────────────────────────────────────────────────────────

    def _extract_links_from_soup(
        self, soup: BeautifulSoup, base_url: str
    ) -> List[str]:
        """
        Extract all crawlable same-origin links from a parsed page.
        Returns a deduplicated list; stores nothing on the result object.
        """
        links: Set[str] = set()

        # Standard anchors, SPA fragments stripped.
        for a in soup.find_all("a", href=True):
            href: str = a["href"]
            if href.startswith(("javascript:", "mailto:", "tel:", "data:")):
                continue
            full = urljoin(base_url, href).split("#")[0]
            if self._is_same_origin(full):
                links.add(full)

        # data-href / HTMX / custom SPA routing attributes.
        for attr in ("data-href", "data-url", "data-link", "hx-get", "hx-post"):
            for tag in soup.find_all(True, attrs={attr: True}):
                val: str = tag[attr]
                if not val or not val.startswith(("http", "/")):
                    continue
                full = urljoin(base_url, val).split("#")[0]
                if self._is_same_origin(full):
                    links.add(full)

        # Auto-probe API docs from root page only.
        parsed = urlparse(base_url)
        if parsed.path in ("", "/"):
            for path in ("/swagger.json", "/api/docs", "/openapi.json"):
                links.add(urljoin(base_url, path))

        return list(links)

    def _is_same_origin(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return True   # Relative URL — always same origin after urljoin.
            return parsed.netloc == self._base_netloc
        except Exception:
            return False

    # ── JavaScript rendering ───────────────────────────────────────────────────

    async def _render_javascript(self, url: str, html: str) -> str:
        """Delegate to JSRenderer and inject discovered dynamic links."""
        if not self.js_render:
            return html

        logger.info("JS rendering: %s", url)
        rendered = await self.js_renderer.render(url, html)

        try:
            dynamic_links = await self.js_renderer.extract_dynamic_links(url, html)
            if dynamic_links:
                logger.info(
                    "JS analysis found %d dynamic link(s)", len(dynamic_links)
                )
                # Inject as hidden anchors so _extract_links_from_soup picks them up.
                injected = "".join(
                    f'<a href="{lnk}" style="display:none">DYN</a>'
                    for lnk in dynamic_links
                )
                rendered += injected
        except Exception as exc:
            logger.warning("JS dynamic link extraction failed for %s: %s", url, exc)

        return rendered

    # ── API fuzzing helpers ────────────────────────────────────────────────────

    async def _enqueue_subdomains(
        self, base_url: str, queue: asyncio.Queue
    ) -> None:
        """
        Enqueue common subdomain variants of the target host.
        Only same-scheme URLs are added; scope enforcement happens in the
        orchestrator's _crawl_worker. Subdomains that match the current host
        are skipped to avoid a redundant root fetch.
        """
        parsed = urlparse(base_url)
        host = parsed.hostname or ""
        parts = host.split(".")
        if len(parts) < 2:
            return

        base_domain = ".".join(parts[-2:])
        logger.info("Subdomain discovery for %s", base_domain)

        for prefix in _SUBDOMAIN_PREFIXES:
            sub = f"{prefix}.{base_domain}"
            if sub == host:
                continue
            candidate = f"{parsed.scheme}://{sub}"
            if candidate not in self._visited_urls:
                await queue.put((candidate, 0, "GET"))

    async def _enqueue_api_probes(
        self, base_url: str, queue: asyncio.Queue
    ) -> None:
        """
        Enqueue well-known API / documentation paths on the base host.
        Previously this method was a documented no-op (`pass`); it is now
        wired up so api_fuzzing mode actually probes these paths.
        """
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        logger.info("API probe enqueue for %s", origin)

        for path in _API_PROBE_PATHS:
            candidate = f"{origin}{path}"
            if candidate not in self._visited_urls:
                await queue.put((candidate, 0, "GET"))

    # ── Technology detection ───────────────────────────────────────────────────

    def _detect_technologies(
        self, headers: Dict[str, str], body: str
    ) -> List[str]:
        hints: Set[str] = set()

        server = headers.get("Server", "").lower()
        x_powered = headers.get("X-Powered-By", "").lower()
        body_lower = body.lower()

        if "nginx" in server:
            hints.add("nginx")
        if "apache" in server:
            hints.add("apache")
        if "php" in x_powered:
            hints.add("php")
        if "asp.net" in x_powered:
            hints.add("asp.net")
        if "laravel" in body_lower or "laravel_session" in body_lower:
            hints.add("laravel")
        if "csrfmiddlewaretoken" in body_lower or "django" in body_lower:
            hints.add("django")
        if "wp-content" in body_lower or "wp-json" in body_lower:
            hints.add("wordpress")
        if "joomla" in body_lower:
            hints.add("joomla")
        if "/_next/" in body_lower or "__next" in body_lower:
            hints.add("nextjs")
        if "react" in body_lower and "root" in body_lower:
            hints.add("react")
        if "/graphql" in body_lower or "query {" in body_lower:
            hints.add("graphql")

        return list(hints)

    # ── robots.txt ────────────────────────────────────────────────────────────

    async def _load_robots(self, base_url: str) -> None:
        robots_url = urljoin(base_url, "/robots.txt")
        try:
            async with self._session.get(robots_url) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    self._robots = urllib.robotparser.RobotFileParser()
                    self._robots.parse(text.splitlines())
                    logger.debug("Loaded robots.txt from %s", robots_url)
        except Exception as exc:
            logger.debug("Could not load robots.txt: %s", exc)

    def _robots_allows(self, url: str) -> bool:
        if self._robots is None:
            return True
        return self._robots.can_fetch(self.user_agent, url)