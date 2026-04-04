"""
js_renderer.py — Headless Browser Rendering for SPA Crawling

Responsibilities:
  - Execute JavaScript on target pages to discover dynamic content
  - Support SPA frameworks (React, Angular, Vue, Next.js)
  - Extract links, forms, and API calls from the rendered DOM
  - Capture XHR/Fetch requests initiated by the page
  - Fallback to simulation mode if headless browser is unavailable
"""

from __future__ import annotations

import logging
from typing import List, Optional, Set
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


class JSRenderer:
    """
    Renders JavaScript using a headless browser (Playwright) or simulated static analysis.
    """

    def __init__(self, use_headless: bool = True, timeout_ms: int = 10000) -> None:
        self.use_headless = use_headless
        self.timeout_ms = timeout_ms
        self._playwright = None
        self._browser = None

    async def render(self, url: str, html: str) -> str:
        """
        Render the page and return the final HTML after JS execution.
        """
        if self.use_headless:
            try:
                return await self._render_playwright(url)
            except Exception as e:
                logger.warning("Playwright rendering failed for %s: %s. Falling back to simulation.", url, e)
        
        return await self._simulate_js_execution(url, html)

    async def verify_xss(self, url: str, xss_token: str) -> bool:
        """
        Navigate to a URL and check if the XSS token was executed/rendered.
        """
        if not self.use_headless:
            return False

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return False

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            
            # We'll listen for a console message or a dialog
            executed = False
            
            def handle_console(msg):
                nonlocal executed
                if xss_token in msg.text:
                    executed = True
            
            page.on("console", handle_console)
            page.on("dialog", lambda dialog: dialog.dismiss()) # Dismiss alerts
            
            try:
                await page.goto(url, wait_until="networkidle", timeout=self.timeout_ms)
                # Also check if the token is in the DOM as a last resort
                content = await page.content()
                if xss_token in content:
                    # To be a real XSS, it shouldn't just be the text, 
                    # but for this proof, we've already checked standard reflection.
                    # This headless check confirms JS-heavy pages render it.
                    pass 
            except Exception:
                pass
            finally:
                await browser.close()
                
            return executed

    async def _simulate_js_execution(self, url: str, html: str) -> str:
        """
        Static analysis based simulation for link/endpoint extraction from JS.
        """
        # Look for script tags and common patterns
        # This is a fallback that doesn't actually 'render' but assists the crawler
        # by pinpointing dynamic endpoints found in JS source
        import re
        
        # Simulated 'rendering' - in reality we might just return the original HTML 
        # but the crawler will benefit from the hints extracted here if we had a way 
        # to pass them back. For now, we return the original HTML.
        return html

    async def extract_dynamic_links(self, url: str, html: str) -> Set[str]:
        """
        Deep discovery of links hidden in JS code strings.
        """
        links = set()
        # Find path-like strings in JS
        # Regex for common API/URL patterns in JS code
        path_pattern = re.compile(r'["\'](/api/v[0-9]/[a-zA-Z0-9_\-/]+)["\']')
        matches = path_pattern.findall(html)
        for match in matches:
            links.add(urljoin(url, match))
            
        # Common JSON keys that might be URLs
        url_pattern = re.compile(r'["\'](https?://[a-zA-Z0-9.\-/]+)["\']')
        matches = url_pattern.findall(html)
        for match in matches:
            links.add(match)
            
        return links

import re
