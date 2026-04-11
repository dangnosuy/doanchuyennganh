"""
BrowserAgent — BFS web crawler with full HTTP traffic interception.

Adapted from LogiScythe-Ultimate/crawler.py (pls_dont_die team).
Uses Playwright to crawl target, intercept ALL requests/responses,
click buttons, submit forms, extract links from HTML + JS.

Key changes from original:
- run_crawl() sync wrapper runs in separate thread (avoids asyncio conflict with MCPManager)
- Response body capped at 2000 chars
- Configurable max_pages/max_depth
- CLI mode: JSON output to stdout, all logs to stderr
"""

import argparse
import asyncio
import json
import os
import re
import sys
import threading
from collections import deque
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any, Set, Optional, Tuple

from playwright.async_api import async_playwright, Page, Request, BrowserContext

# URLs containing these keywords are never visited (prevent logout/destruction)
BLACKLISTED_KEYWORDS = ['logout', 'delete', 'signout', 'exit', 'quit', 'destroy', 'remove']

# Static file extensions to skip in link extraction (NOT in traffic capture)
STATIC_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".mp3", ".webm", ".ogg",
    ".pdf", ".zip", ".gz", ".map",
)


def _log(msg: str):
    """Print log message to stderr (keeps stdout clean for JSON output)."""
    print(msg, file=sys.stderr)


class BrowserAgent:
    """BFS web crawler with Playwright request/response interception."""

    def __init__(self, headless: bool = True, timeout: int = 30000):
        self.headless = headless
        self.timeout = timeout
        self.http_traffic: List[Dict[str, Any]] = []
        self.target_domain: str = ""
        self.discovered_from_requests: Set[str] = set()
        self.url_pattern_counts: Dict[str, int] = {}
        self.external_links: Set[str] = set()

    # ── URL helpers ──────────────────────────────────────────────

    def _get_url_pattern(self, url: str) -> str:
        try:
            p = urlparse(url)
            return f"{p.scheme}://{p.netloc}{p.path}"
        except Exception:
            return url

    def _should_queue_url(self, url: str) -> bool:
        pattern = self._get_url_pattern(url)
        count = self.url_pattern_counts.get(pattern, 0)
        if count >= 1:
            return False
        self.url_pattern_counts[pattern] = count + 1
        return True

    @staticmethod
    def _is_blacklisted(url: str) -> bool:
        lower = url.lower()
        return any(kw in lower for kw in BLACKLISTED_KEYWORDS)

    @staticmethod
    def _is_static(url: str) -> bool:
        return url.lower().split("?")[0].endswith(STATIC_EXTENSIONS)

    # ── Request/Response interception ────────────────────────────

    async def _intercept_request(self, request: Request):
        """Callback: capture every request within target domain."""
        if self.target_domain not in request.url:
            return
        if request.resource_type in ('image', 'stylesheet', 'font', 'media'):
            return

        response = await request.response()
        resp_status = response.status if response else None
        resp_headers = dict(await response.all_headers()) if response else {}

        # Capture response body (capped)
        resp_body = None
        try:
            if response and request.resource_type in ('document', 'xhr', 'fetch', 'script', 'other'):
                text = await response.text()
                resp_body = text[:2000] if text else None
        except Exception:
            pass

        try:
            parent_url = request.frame.url if request.frame else None
        except Exception:
            parent_url = None

        self.http_traffic.append({
            "method": request.method,
            "url": request.url,
            "headers": dict(await request.all_headers()),
            "postData": request.post_data,
            "response_status": resp_status,
            "response_headers": resp_headers,
            "resource_type": request.resource_type,
            "response_body": resp_body,
            "parent_url": parent_url,
            "form_fields": None,
        })

        # Enqueue discovered same-domain URLs
        try:
            ru = urlparse(request.url)
            if ru.netloc and self.target_domain in ru.netloc and not self._is_blacklisted(request.url):
                if request.method == "GET":
                    self.discovered_from_requests.add(request.url)
                else:
                    loc = resp_headers.get("location") or resp_headers.get("Location")
                    if loc:
                        abs_loc = urljoin(request.url, loc)
                        if self.target_domain in urlparse(abs_loc).netloc:
                            self.discovered_from_requests.add(abs_loc)
        except Exception:
            pass

    # ── Link extraction ──────────────────────────────────────────

    async def _extract_links(self, page: Page, base_url: str) -> List[str]:
        links = set()
        try:
            for el in await page.query_selector_all("a[href]"):
                href = await el.get_attribute("href")
                if href:
                    links.add(href.strip())
        except Exception:
            pass
        try:
            html = await page.content()
            for href in re.findall(r'href\s*=\s*["\']([^"\'#>\s]+)', html, re.IGNORECASE):
                links.add(href.strip())
        except Exception:
            pass

        valid = []
        for href in links:
            url = urljoin(base_url, href)
            if not url.startswith(("http://", "https://")):
                continue
            if self._is_static(url):
                continue
            parsed = urlparse(url)
            if self.target_domain not in parsed.netloc:
                if not self._is_blacklisted(url):
                    self.external_links.add(url)
                continue
            if self._is_blacklisted(url):
                continue
            valid.append(url)
        return valid

    # ── Action extraction (buttons, forms) ───────────────────────

    async def _extract_actions(self, page: Page, base_url: str, visited_actions: Set) -> List[Dict]:
        actions = []

        # Clickable elements
        try:
            for sel in ["button", "input[type='submit']", "input[type='button']",
                        "[onclick]", "[role='button']"]:
                count = await page.locator(sel).count()
                for i in range(count):
                    full_sel = f"{sel} >> nth={i}"
                    key = (base_url, "click", full_sel)
                    if key not in visited_actions:
                        actions.append({"type": "click", "url": base_url, "selector": full_sel})
        except Exception:
            pass

        # Forms
        try:
            forms = await page.locator("form").all()
            for i, form in enumerate(forms):
                key = (base_url, "form", i)
                if key not in visited_actions:
                    actions.append({"type": "form", "url": base_url, "form_index": i})

                # Record form metadata in traffic
                action_attr = await form.get_attribute("action")
                method_attr = await form.get_attribute("method")
                action_url = urljoin(base_url, action_attr) if action_attr else base_url
                method_val = (method_attr or "GET").upper()

                fields = await self._extract_form_fields(form)
                self.http_traffic.append({
                    "method": method_val, "url": action_url,
                    "headers": {}, "postData": None,
                    "response_status": None, "response_headers": {},
                    "resource_type": "form", "response_body": None,
                    "parent_url": base_url, "form_fields": fields,
                })
        except Exception:
            pass

        return actions

    async def _extract_form_fields(self, form) -> List[Dict]:
        fields = []
        try:
            for el in await form.locator("input, textarea, select").all():
                name = await el.get_attribute("name") or await el.get_attribute("id")
                if not name:
                    continue
                tag = await el.evaluate("el => el.tagName.toLowerCase()")
                fields.append({
                    "name": name,
                    "type": await el.get_attribute("type") if tag == "input" else tag,
                    "value": await el.get_attribute("value"),
                })
        except Exception:
            pass
        return fields

    # ── BFS actions: visit, click, form submit ───────────────────

    async def _visit(self, page: Page, url: str, visited: Set, queue: deque,
                     visited_actions: Set, seen: Set) -> bool:
        try:
            await page.goto(url, wait_until="networkidle", timeout=self.timeout)
            await page.wait_for_timeout(1500)
            visited.add(url)
        except Exception:
            return False

        for link in await self._extract_links(page, url):
            if link not in seen and self._should_queue_url(link):
                seen.add(link)
                queue.append({"type": "visit", "url": link})

        for action in await self._extract_actions(page, url, visited_actions):
            queue.append(action)

        return True

    async def _click(self, page: Page, action: Dict, visited_actions: Set,
                     queue: deque, seen: Set):
        key = (action["url"], "click", action["selector"])
        if key in visited_actions:
            return
        visited_actions.add(key)
        try:
            await page.goto(action["url"], wait_until="networkidle", timeout=self.timeout)
            await page.wait_for_timeout(500)
            el = page.locator(action["selector"])
            if await el.is_hidden() or not await el.is_enabled():
                return
            await el.click(timeout=5000)
            await page.wait_for_load_state("networkidle", timeout=self.timeout)
            await page.wait_for_timeout(1500)
            for link in await self._extract_links(page, page.url):
                if link not in seen and self._should_queue_url(link):
                    seen.add(link)
                    queue.append({"type": "visit", "url": link})
        except Exception:
            pass

    async def _submit_form(self, page: Page, action: Dict, visited_actions: Set,
                           queue: deque, seen: Set):
        key = (action["url"], "form", action["form_index"])
        if key in visited_actions:
            return
        visited_actions.add(key)
        try:
            await page.goto(action["url"], wait_until="networkidle", timeout=self.timeout)
            await page.wait_for_timeout(500)
            form = page.locator(f"form >> nth={action['form_index']}")

            # Fill dummy data
            for input_type, value in [("text", "test"), ("email", "test@example.com"),
                                      ("password", "Test123!"), ("number", "1"),
                                      ("tel", "0123456789")]:
                try:
                    inp = form.locator(f"input[type='{input_type}']").first
                    if await inp.count() > 0 and await inp.is_visible():
                        await inp.fill(value, timeout=2000)
                except Exception:
                    pass
            # Fill textarea
            try:
                ta = form.locator("textarea").first
                if await ta.count() > 0 and await ta.is_visible():
                    await ta.fill("test comment", timeout=2000)
            except Exception:
                pass

            # Submit
            sb = form.locator("input[type='submit'], button[type='submit']")
            if await sb.count() > 0:
                await sb.first.click(timeout=5000)
            else:
                await page.evaluate("form => form.submit()", await form.element_handle())

            await page.wait_for_load_state("networkidle", timeout=self.timeout)
            await page.wait_for_timeout(1500)

            for link in await self._extract_links(page, page.url):
                if link not in seen and self._should_queue_url(link):
                    seen.add(link)
                    queue.append({"type": "visit", "url": link})
        except Exception:
            pass

    # ── Main crawl logic ─────────────────────────────────────────

    async def _crawl_logic(
        self,
        start_url: str,
        domain: str,
        max_rounds: int = 2,
        max_pages: int = 50,
        initial_cookies: Optional[List[Dict[str, Any]]] = None,
    ):
        self.target_domain = domain

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.headless)
            context = await browser.new_context(ignore_https_errors=True)

            if initial_cookies:
                await context.add_cookies(initial_cookies)
                _log(f"[CRAWLER] Injected {len(initial_cookies)} cookies")

            page = await context.new_page()
            page.on("request", self._intercept_request)

            for round_num in range(1, max_rounds + 1):
                _log(f"[CRAWLER] === Round {round_num}/{max_rounds} ===")
                self.url_pattern_counts = {}
                self.discovered_from_requests = set()

                queue = deque([{"type": "visit", "url": start_url}])
                visited = set()
                visited_actions = set()
                seen = {start_url}
                pages_visited = 0

                while queue and pages_visited < max_pages:
                    action = queue.popleft()
                    atype = action["type"]

                    if atype == "visit":
                        ok = await self._visit(page, action["url"], visited, queue, visited_actions, seen)
                        if ok:
                            pages_visited += 1
                        elif action["url"] == start_url and round_num == 1:
                            _log(f"[CRAWLER] Cannot reach {start_url}, aborting")
                            await browser.close()
                            return self.http_traffic, [], self.external_links
                    elif atype == "click":
                        await self._click(page, action, visited_actions, queue, seen)
                    elif atype == "form":
                        await self._submit_form(page, action, visited_actions, queue, seen)

                    # Enqueue network-discovered URLs
                    for disc_url in list(self.discovered_from_requests):
                        if disc_url not in seen and self._should_queue_url(disc_url):
                            seen.add(disc_url)
                            queue.append({"type": "visit", "url": disc_url})
                    self.discovered_from_requests.clear()

                _log(f"[CRAWLER] Round {round_num} done: {pages_visited} pages, {len(self.http_traffic)} requests")

            cookies = await context.cookies()
            await browser.close()
            return self.http_traffic, cookies, self.external_links


# ═══════════════════════════════════════════════════════════════
# SYNC WRAPPER — runs in separate thread to avoid asyncio conflict
# ═══════════════════════════════════════════════════════════════

def run_crawl(
    start_url: str,
    cookies: list[dict] | None = None,
    max_rounds: int = 2,
    max_pages: int = 50,
    headless: bool = True,
    timeout: int = 300,
) -> tuple[list[dict], list[dict], set[str]]:
    """Sync wrapper — safe to call from any thread.

    Creates its own thread + event loop to avoid conflict
    with MCPManager's background asyncio loop.
    """
    domain = urlparse(start_url).netloc
    result = None
    error = None

    def _run():
        nonlocal result, error
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                agent = BrowserAgent(headless=headless)
                result = loop.run_until_complete(
                    agent._crawl_logic(start_url, domain, max_rounds=max_rounds,
                                       max_pages=max_pages, initial_cookies=cookies)
                )
            finally:
                loop.close()
        except Exception as e:
            error = e

    thread = threading.Thread(target=_run)
    thread.start()
    thread.join(timeout=timeout)

    if thread.is_alive():
        raise TimeoutError(f"Crawler timed out after {timeout}s")
    if error:
        raise error
    return result


# ═══════════════════════════════════════════════════════════════
# CLI — JSON output to stdout, logs to stderr
# ═══════════════════════════════════════════════════════════════

def _parse_header(header_str: str) -> tuple[str, str]:
    """Parse 'Key: Value' header string."""
    key, _, value = header_str.partition(":")
    return key.strip(), value.strip()


def _headers_to_cookies(headers: list[str]) -> list[dict]:
    """Convert -H 'Cookie: name=val; name2=val2' headers to cookie dicts for injection."""
    cookies = []
    for h in headers:
        key, value = _parse_header(h)
        if key.lower() == "cookie":
            for pair in value.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    name, _, val = pair.partition("=")
                    cookies.append({
                        "name": name.strip(),
                        "value": val.strip(),
                        "domain": "",  # filled later from URL
                        "path": "/",
                    })
    return cookies


def main():
    parser = argparse.ArgumentParser(
        description="BFS web crawler with HTTP traffic interception. Outputs JSON to stdout."
    )
    parser.add_argument("--url", required=True, help="Target URL to crawl")
    parser.add_argument(
        "-H", "--header", action="append", default=[],
        help="HTTP header (repeatable). e.g. -H 'Cookie: session=abc'"
    )
    parser.add_argument("--max-pages", type=int, default=50, help="Max pages per round (default: 50)")
    parser.add_argument("--max-rounds", type=int, default=2, help="Number of BFS rounds (default: 2)")
    parser.add_argument("--timeout", type=int, default=300, help="Timeout in seconds (default: 300)")
    parser.add_argument("--headless", action="store_true", default=True, help="Run headless (default)")
    parser.add_argument("--no-headless", action="store_true", help="Run with visible browser")

    args = parser.parse_args()
    headless = not args.no_headless

    # Parse cookies from -H headers
    inject_cookies = None
    if args.header:
        cookie_list = _headers_to_cookies(args.header)
        if cookie_list:
            # Fill domain from URL
            domain = urlparse(args.url).netloc
            for c in cookie_list:
                c["domain"] = domain
            inject_cookies = cookie_list

    _log(f"[CRAWLER-CLI] Target: {args.url}")
    _log(f"[CRAWLER-CLI] max_pages={args.max_pages}, max_rounds={args.max_rounds}, "
         f"timeout={args.timeout}s, headless={headless}")
    if inject_cookies:
        _log(f"[CRAWLER-CLI] Injecting {len(inject_cookies)} cookies: "
             f"{[c['name'] for c in inject_cookies]}")

    try:
        traffic, cookies, external = run_crawl(
            start_url=args.url,
            cookies=inject_cookies,
            max_rounds=args.max_rounds,
            max_pages=args.max_pages,
            headless=headless,
            timeout=args.timeout,
        )

        # Convert set to list for JSON serialization
        output = {
            "http_traffic": traffic,
            "cookies": cookies,
            "external_links": sorted(external),
        }

        # JSON to stdout
        json.dump(output, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")

        _log(f"[CRAWLER-CLI] Done: {len(traffic)} requests, "
             f"{len(cookies)} cookies, {len(external)} external links")

    except Exception as e:
        _log(f"[CRAWLER-CLI] ERROR: {e}")
        # Output error as JSON too
        json.dump({"error": str(e), "http_traffic": [], "cookies": [], "external_links": []},
                   sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
