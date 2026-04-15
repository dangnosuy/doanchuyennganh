"""
CrawlAgent — Standalone recon agent for MARL.

Crawls target website (anonymous + authenticated), collects HTTP traffic,
then uses LLM to analyze and write a structured recon.md report.

Usage:
    python agents/crawl_agent.py "https://target.com/"
    python agents/crawl_agent.py "https://target.com/ credentials: admin:password"
"""

import json
import os
import re
import sys
import subprocess
from pathlib import Path
from urllib.parse import urlparse, urljoin

import httpx
from openai import OpenAI

# ── Ensure project root is on sys.path so we can import mcp_client ──
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from mcp_client import MCPManager
from shared.utils import (
    extract_send_block, extract_next_tag, strip_tag,
    truncate, parse_prompt,
    SEND_BLOCK_PATTERN, TAG_PATTERN,
)


# ═══════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "gho_token")
SERVER_URL = os.getenv("MARL_SERVER_URL", "http://127.0.0.1:5000/v1")
MODEL = os.getenv("MARL_CRAWL_MODEL", os.getenv("MARL_EXECUTOR_MODEL", "gpt-4.1"))
DEBUG = os.getenv("MARL_DEBUG", "").lower() in ("1", "true", "yes")
PROMPT_PATH = "prompts/crawl"

# Colors
YELLOW = "\033[93m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _debug(msg: str):
    """Print debug message only when MARL_DEBUG is enabled."""
    if DEBUG:
        print(f"{CYAN}[DEBUG] {msg}{RESET}")

# Limits
MAX_TOOL_ROUNDS = 30
MAX_CONSECUTIVE_ERRORS = 3
TRUNCATE_LIMIT = 15000

# Path to crawler CLI
_CRAWLER_CLI = str(Path(__file__).resolve().parent.parent / "tools" / "crawler.py")


def load_prompt(task: str) -> str:
    try:
        with open(f"{PROMPT_PATH}/{task}.md", "r") as f:
            prompt = f.read()
            if len(prompt) == 0:
                raise Exception
            return prompt
    except:
        print(f"{task}.md not found or empty. Script will now halt.")
        exit(0)

# ═══════════════════════════════════════════════════════════════
# RECON SYSTEM PROMPT
# ═══════════════════════════════════════════════════════════════


RECON_SYSTEM_PROMPT = load_prompt("recon")

# ═══════════════════════════════════════════════════════════════
# DONE TAG — simpler than debate tags
# ═══════════════════════════════════════════════════════════════

_DONE_PATTERN = re.compile(r"\[DONE\]\s*$", re.MULTILINE)


def _has_done_tag(text: str) -> bool:
    return bool(_DONE_PATTERN.search(text))


# ═══════════════════════════════════════════════════════════════
# CRAWL AGENT CLASS
# ═══════════════════════════════════════════════════════════════

class CrawlAgent:
    """Standalone recon agent: crawl → login → crawl again → LLM analysis → recon.md."""

    def __init__(self, working_dir: str = "./workspace"):
        self.working_dir = os.path.abspath(working_dir)
        os.makedirs(self.working_dir, exist_ok=True)
        self.client = OpenAI(api_key=GITHUB_TOKEN, base_url=SERVER_URL)

        print(f"\n{YELLOW}{BOLD}[CRAWL-AGENT] Khoi tao MCP tools...{RESET}")
        self.mcp = MCPManager()
        self.mcp.add_shell_server()
        self.mcp.add_fetch_server()
        self.mcp.add_filesystem_server([self.working_dir])

        self.tools = self.mcp.get_openai_tools()
        print(f"{YELLOW}[CRAWL-AGENT] Da san sang — {len(self.tools)} tools{RESET}")
        self.mcp.display_tools()
        print()

    # ─── Public API ──────────────────────────────────────────────

    def run(self, user_prompt: str) -> str:
        """Run full recon pipeline. Returns path to recon.md.

        Flow:
        1. Parse prompt → URL + credentials
        2. Anonymous crawl via tools/crawler.py CLI
        3. Login (if credentials) via httpx
        4. Authenticated crawl (if login succeeded)
        5. LLM analysis → write recon.md

        Args:
            user_prompt: User input containing URL and optionally credentials.

        Returns:
            Absolute path to the generated recon.md file.
        """
        url, credentials = parse_prompt(user_prompt)
        if not url:
            print(f"{RED}[CRAWL-AGENT] ERROR: Khong tim thay URL trong prompt.{RESET}")
            return ""

        print(f"{GREEN}{BOLD}[CRAWL-AGENT] Target: {url}{RESET}")
        _debug(f"Parsed prompt: url={url}, credentials={credentials}")
        _debug(f"Config: MODEL={MODEL}, SERVER_URL={SERVER_URL}")
        _debug(f"Working dir: {self.working_dir}")

        # ── Phase 1: Anonymous crawl ──
        print(f"\n{YELLOW}{BOLD}[CRAWL-AGENT] Phase 1: Anonymous crawl...{RESET}")
        anon_data = self._run_crawler(url)

        # ── Phase 2: Login (if credentials) ──
        login_cookies = None
        if credentials:
            print(f"\n{YELLOW}{BOLD}[CRAWL-AGENT] Phase 2: Login...{RESET}")
            login_cookies = self._login(url, credentials)
            if login_cookies:
                print(f"{GREEN}[CRAWL-AGENT] Login OK — {len(login_cookies)} cookies{RESET}")
            else:
                print(f"{YELLOW}[CRAWL-AGENT] Login failed, skipping authenticated crawl{RESET}")
        else:
            print(f"\n{DIM}[CRAWL-AGENT] Phase 2: No credentials, skipping login{RESET}")

        # ── Phase 3: Authenticated crawl (if login OK) ──
        auth_data = None
        if login_cookies:
            print(f"\n{YELLOW}{BOLD}[CRAWL-AGENT] Phase 3: Authenticated crawl...{RESET}")
            # Build cookie header string
            cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in login_cookies)
            _debug(f"Injecting {len(login_cookies)} cookies into crawler: {cookie_str[:100]}...")
            auth_data = self._run_crawler(url, cookie_header=cookie_str)
            if auth_data:
                _debug(f"Auth crawl done: {len(auth_data.get('http_traffic', []))} requests")
            else:
                _debug(f"Auth crawl returned no data!")

        # ── Phase 4: Auto-recrawl new URLs discovered during crawl ──
        print(f"\n{YELLOW}{BOLD}[CRAWL-AGENT] Phase 4: Checking for new URLs to recrawl...{RESET}")
        recrawl_data = None
        crawl_source = auth_data if auth_data else anon_data
        
        if crawl_source:
            new_urls = self._extract_new_urls(url, crawl_source)
            if new_urls:
                # Use authenticated cookies if available
                recrawl_cookie_header = None
                if login_cookies:
                    recrawl_cookie_header = "; ".join(f"{c['name']}={c['value']}" for c in login_cookies)
                
                recrawl_data = self.recrawl_new_urls(new_urls, recrawl_cookie_header)
                
                # Merge recrawl data back into main crawl data
                if recrawl_data:
                    if auth_data:
                        auth_data["http_traffic"].extend(recrawl_data.get("http_traffic", []))
                        auth_data["cookies"].extend(recrawl_data.get("cookies", []))
                        auth_data["external_links"].extend(recrawl_data.get("external_links", []))
                    elif anon_data:
                        anon_data["http_traffic"].extend(recrawl_data.get("http_traffic", []))
                        anon_data["cookies"].extend(recrawl_data.get("cookies", []))
                        anon_data["external_links"].extend(recrawl_data.get("external_links", []))
                    print(f"{GREEN}[CRAWL-AGENT] Merged recrawl data into main dataset{RESET}")
            else:
                print(f"{DIM}[CRAWL-AGENT] No new same-domain URLs found to recrawl{RESET}")
        
        # ── Phase 5: LLM analysis → recon.md ──
        print(f"\n{YELLOW}{BOLD}[CRAWL-AGENT] Phase 5: LLM analysis...{RESET}")
        _debug(f"Sending to LLM: anon_data={'YES' if anon_data else 'NO'}, "
               f"auth_data={'YES' if auth_data else 'NO'}, "
               f"recrawl_data={'YES' if recrawl_data else 'NO'}")
        recon_path = self._analyze(url, anon_data, auth_data)

        return recon_path

    def _extract_new_urls(self, base_url: str, crawl_data: dict | None) -> list[str]:
        """Extract new same-domain or subdomain URLs from crawl data.

        Args:
            base_url: Base target URL to compare against
            crawl_data: Crawl data dict containing external_links and http_traffic

        Returns:
            List of new URLs to crawl (filtered to same domain/subdomains only)
        """
        if not crawl_data:
            return []

        base_domain = urlparse(base_url).netloc
        new_urls = []
        seen = {base_url}  # Don't recrawl the base URL

        # Extract from external_links
        for url in crawl_data.get("external_links", []):
            if url in seen:
                continue
            try:
                domain = urlparse(url).netloc
                # Only recrawl same domain or subdomains
                if domain == base_domain or domain.endswith("." + base_domain):
                    new_urls.append(url)
                    seen.add(url)
            except Exception:
                pass

        # Also extract unique URLs from HTTP traffic that weren't already visited
        visited_urls = {r.get("url") for r in crawl_data.get("http_traffic", []) if r.get("url")}
        for url in crawl_data.get("external_links", []):
            if url not in visited_urls and url not in seen:
                try:
                    domain = urlparse(url).netloc
                    if domain == base_domain or domain.endswith("." + base_domain):
                        new_urls.append(url)
                        seen.add(url)
                except Exception:
                    pass

        _debug(f"Extracted {len(new_urls)} new same-domain URLs for recrawl")
        return new_urls[:10]  # Limit to 10 new URLs per pass to avoid explosion

    def recrawl_new_urls(self, new_urls: list[str], cookie_header: str | None = None) -> dict | None:
        """Recrawl additional URLs discovered during analysis.

        Args:
            new_urls: List of new URLs to crawl
            cookie_header: Optional cookie header for authenticated crawl

        Returns:
            Combined crawl data from all URLs, or None if no data
        """
        if not new_urls:
            return None

        print(f"\n{YELLOW}{BOLD}[CRAWL-AGENT] Recrawling {len(new_urls)} new URLs...{RESET}")
        combined_data = {
            "http_traffic": [],
            "cookies": [],
            "external_links": []
        }

        for url in new_urls:
            print(f"{DIM}[CRAWL-AGENT] Recrawling: {url}{RESET}")
            try:
                data = self._run_crawler(url, cookie_header, max_pages=15, max_rounds=1, timeout=120)
                if data:
                    combined_data["http_traffic"].extend(data.get("http_traffic", []))
                    combined_data["cookies"].extend(data.get("cookies", []))
                    combined_data["external_links"].extend(data.get("external_links", []))
            except Exception as e:
                _debug(f"Error recrawling {url}: {e}")
                continue

        n_traffic = len(combined_data["http_traffic"])
        if n_traffic > 0:
            print(f"{GREEN}[CRAWL-AGENT] Recrawl complete: {n_traffic} total requests from new URLs{RESET}")
            return combined_data
        else:
            print(f"{DIM}[CRAWL-AGENT] Recrawl found no additional traffic{RESET}")
            return None

    def generate_report_summary(self, recon_path: str) -> str:
        """Generate a summary report for the recon results.

        Args:
            recon_path: Path to the recon.md file

        Returns:
            Summary string for reporting
        """
        if not Path(recon_path).exists():
            return "Recon report not found."

        content = Path(recon_path).read_text(encoding="utf-8")
        lines = content.split("\n")

        # Extract key sections
        summary = []
        current_section = None

        for line in lines[:50]:  # First 50 lines for summary
            if line.startswith("#"):
                current_section = line.strip("# ").lower()
            elif current_section == "target overview" and line.strip():
                summary.append(f"Target: {line.strip()}")
                break

        summary.append(f"Recon file: {recon_path}")
        summary.append(f"Report length: {len(lines)} lines")

        return "\n".join(summary)

    def shutdown(self):
        """Clean up MCP servers."""
        print(f"{YELLOW}[CRAWL-AGENT] Shutting down MCP...{RESET}")
        self.mcp.stop_all()
        print(f"{YELLOW}[CRAWL-AGENT] Done.{RESET}")

    # ─── Internal: Run crawler CLI ───────────────────────────────

    def _run_crawler(
        self,
        url: str,
        cookie_header: str | None = None,
        max_pages: int = 50,
        max_rounds: int = 2,
        timeout: int = 300,
    ) -> dict | None:
        """Run tools/crawler.py as subprocess, return parsed JSON output."""
        cmd = [
            sys.executable, _CRAWLER_CLI,
            "--url", url,
            "--max-pages", str(max_pages),
            "--max-rounds", str(max_rounds),
            "--timeout", str(timeout),
            "--headless",
        ]
        if cookie_header:
            cmd.extend(["-H", f"Cookie: {cookie_header}"])

        _debug(f"Full crawler command: {' '.join(cmd)}")
        if cookie_header:
            _debug(f"Cookie header: {cookie_header[:80]}...")
        print(f"{DIM}[CRAWL-AGENT] Running: {' '.join(cmd[:6])}...{RESET}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 30,  # extra buffer over crawler timeout
                cwd=_PROJECT_ROOT,
            )

            # Show stderr logs
            if result.stderr:
                for line in result.stderr.strip().split("\n"):
                    print(f"{DIM}  {line}{RESET}")

            if result.returncode != 0:
                print(f"{YELLOW}[CRAWL-AGENT] Crawler exited with code {result.returncode}{RESET}")

            # Parse JSON stdout
            if result.stdout.strip():
                data = json.loads(result.stdout)
                n_traffic = len(data.get("http_traffic", []))
                n_cookies = len(data.get("cookies", []))
                n_external = len(data.get("external_links", []))
                print(f"{GREEN}[CRAWL-AGENT] Crawl result: {n_traffic} requests, "
                      f"{n_cookies} cookies, {n_external} external links{RESET}")

                # Debug: show sampled traffic
                if DEBUG:
                    traffic = data.get("http_traffic", [])
                    _debug(f"Traffic breakdown:")
                    by_type = {}
                    for r in traffic:
                        rt = r.get("resource_type", "unknown")
                        by_type[rt] = by_type.get(rt, 0) + 1
                    for rt, count in sorted(by_type.items()):
                        _debug(f"  {rt}: {count}")
                    # Show unique URLs
                    urls = set()
                    for r in traffic:
                        if r.get("resource_type") in ("document", "xhr", "fetch", "form"):
                            urls.add(f"{r.get('method', '?')} {r.get('url', '?')} -> {r.get('response_status', '?')}")
                    _debug(f"Interesting requests ({len(urls)}):")
                    for u in sorted(urls)[:30]:
                        _debug(f"  {u}")
                    # Show cookies
                    for c in data.get("cookies", []):
                        _debug(f"Cookie: {c.get('name')}={c.get('value', '')[:30]}... "
                               f"(domain={c.get('domain')}, httpOnly={c.get('httpOnly')}, "
                               f"secure={c.get('secure')})")

                return data
            else:
                print(f"{YELLOW}[CRAWL-AGENT] No output from crawler{RESET}")
                return None

        except subprocess.TimeoutExpired:
            print(f"{RED}[CRAWL-AGENT] Crawler timed out after {timeout + 30}s{RESET}")
            return None
        except json.JSONDecodeError as e:
            print(f"{RED}[CRAWL-AGENT] Failed to parse crawler JSON: {e}{RESET}")
            return None
        except Exception as e:
            print(f"{RED}[CRAWL-AGENT] Crawler error: {e}{RESET}")
            return None

    # ─── Internal: Login via httpx ───────────────────────────────

    def _login(self, target_url: str, credentials: dict) -> list[dict] | None:
        """Login via httpx. Returns list of cookie dicts or None."""
        domain = urlparse(target_url).netloc
        _debug(f"Login target: {target_url}, domain: {domain}")
        _debug(f"Credentials: username={credentials.get('username')}, "
               f"password={'*' * len(credentials.get('password', ''))}")

        try:
            with httpx.Client(follow_redirects=True, timeout=15, verify=False) as client:
                # ── Step 1: Discover login URL from homepage links ──
                login_paths = []
                try:
                    home_resp = client.get(target_url)
                    if home_resp.status_code == 200:
                        # Extract hrefs that look like login/signin/account pages
                        hrefs = re.findall(
                            r'href=["\']([^"\']*)["\']', home_resp.text, re.IGNORECASE,
                        )
                        login_keywords = re.compile(
                            r'(?:log.?in|sign.?in|auth|account|session)',
                            re.IGNORECASE,
                        )
                        for href in hrefs:
                            if login_keywords.search(href):
                                # Normalize relative → absolute
                                full = urljoin(target_url, href)
                                path = urlparse(full).path
                                if path and path not in login_paths:
                                    login_paths.append(path)
                                    _debug(f"Discovered login path from homepage: {path}")
                except Exception as e:
                    _debug(f"Homepage scan failed: {e}")

                # ── Step 2: Fallback to original hardcoded paths ──
                common_paths = [
                    "/login", "/my-account", "/account/login", "/signin",
                ]
                for p in common_paths:
                    if p not in login_paths:
                        login_paths.append(p)

                _debug(f"Login paths to try ({len(login_paths)}): {login_paths}")

                # Find login page
                login_url = None
                resp = None

                for path in login_paths:
                    try_url = urljoin(target_url, path)
                    _debug(f"Trying login path: GET {try_url}")
                    resp = client.get(try_url)
                    _debug(f"  -> Status: {resp.status_code}, "
                           f"URL after redirect: {resp.url}, "
                           f"Has 'password' field: {'password' in resp.text.lower()}")
                    if resp.status_code == 200 and ("password" in resp.text.lower()):
                        login_url = try_url
                        _debug(f"  -> MATCH! Using this as login page")
                        break
                    else:
                        _debug(f"  -> SKIP (status={resp.status_code}, "
                               f"has_password={'password' in resp.text.lower()})")

                if not login_url or not resp:
                    print(f"{YELLOW}[LOGIN] Khong tim thay trang login{RESET}")
                    _debug(f"Tried paths: {login_paths} — none had status 200 + password field")
                    return None

                # Extract all forms for debug
                if DEBUG:
                    forms_found = re.findall(
                        r'<form[^>]*>([\s\S]*?)</form>',
                        resp.text, re.IGNORECASE,
                    )
                    _debug(f"Found {len(forms_found)} <form> on login page")
                    for i, form_html in enumerate(forms_found):
                        # Extract action
                        action_m = re.search(r'action=["\']([^"\']*)["\']', form_html)
                        method_m = re.search(r'method=["\']([^"\']*)["\']', form_html)
                        _debug(f"  Form {i}: action={action_m.group(1) if action_m else 'NONE'}, "
                               f"method={method_m.group(1) if method_m else 'NONE'}")
                        # Extract all input fields
                        inputs = re.findall(
                            r'<input[^>]*?(?:name=["\']([^"\']*)["\'])?[^>]*?'
                            r'(?:type=["\']([^"\']*)["\'])?[^>]*?>',
                            form_html, re.IGNORECASE,
                        )
                        for name, ftype in inputs:
                            if name:
                                value_m = re.search(
                                    rf'name=["\']{ re.escape(name) }["\'][^>]*?value=["\']([^"\']*)["\']',
                                    form_html, re.IGNORECASE,
                                )
                                val = value_m.group(1) if value_m else ""
                                _debug(f"    input: name={name}, type={ftype or '?'}, "
                                       f"value={val[:50] if val else '(empty)'}")

                # Extract CSRF token
                csrf_token = None
                csrf_patterns = [
                    ("csrf", re.compile(r'name=["\']csrf["\'][\s\S]*?value=["\']([^"\']+)["\']')),
                    ("csrf-reverse", re.compile(r'value=["\']([^"\']+)["\'][\s\S]*?name=["\']csrf["\']')),
                    ("_token", re.compile(r'name=["\']_token["\'][\s\S]*?value=["\']([^"\']+)["\']')),
                ]
                for pat_name, pat in csrf_patterns:
                    m = pat.search(resp.text)
                    if m:
                        csrf_token = m.group(1)
                        _debug(f"CSRF token found via pattern '{pat_name}': {csrf_token[:30]}...")
                        break
                    else:
                        _debug(f"CSRF pattern '{pat_name}': no match")

                if not csrf_token:
                    _debug("WARNING: No CSRF token found — POST may fail if server requires one")

                # POST login
                post_data = {
                    "username": credentials["username"],
                    "password": credentials["password"],
                }
                if csrf_token:
                    post_data["csrf"] = csrf_token

                _debug(f"POST {login_url}")
                _debug(f"  Fields: {list(post_data.keys())}")
                _debug(f"  Data: { {k: (v if k != 'password' else '***') for k, v in post_data.items()} }")

                # Cookies before login
                pre_cookies = list(client.cookies.jar)
                _debug(f"  Cookies BEFORE POST: {[c.name for c in pre_cookies]}")

                login_resp = client.post(login_url, data=post_data)

                _debug(f"  -> Response status: {login_resp.status_code}")
                _debug(f"  -> Final URL: {login_resp.url}")
                _debug(f"  -> Response headers: { {k: v for k, v in login_resp.headers.items() if k.lower() in ('location', 'set-cookie', 'content-type')} }")

                # Check for error indicators in response
                if DEBUG:
                    body_lower = login_resp.text.lower()
                    error_keywords = ["invalid", "incorrect", "wrong", "error", "failed", "denied"]
                    found_errors = [kw for kw in error_keywords if kw in body_lower]
                    if found_errors:
                        _debug(f"  -> WARNING: Response body contains error words: {found_errors}")
                        _debug(f"  -> Body snippet: {login_resp.text[:500]}")
                    else:
                        _debug(f"  -> No obvious error keywords in response body")

                # Extract cookies
                all_cookies = []
                for cookie in client.cookies.jar:
                    all_cookies.append({
                        "name": cookie.name,
                        "value": cookie.value,
                        "domain": domain,
                        "path": cookie.path or "/",
                    })

                _debug(f"Cookies AFTER POST: {[(c['name'], c['value'][:20]+'...') for c in all_cookies]}")

                # Check if session cookie actually changed (login success indicator)
                if DEBUG and pre_cookies and all_cookies:
                    pre_values = {c.name: c.value for c in pre_cookies}
                    for c in all_cookies:
                        if c["name"] in pre_values:
                            changed = c["value"] != pre_values[c["name"]]
                            _debug(f"  Cookie '{c['name']}' changed: {changed}")
                        else:
                            _debug(f"  Cookie '{c['name']}' is NEW (not present before login)")

                if all_cookies:
                    print(f"{GREEN}[LOGIN] Cookies: {[c['name'] for c in all_cookies]}{RESET}")
                    return all_cookies
                else:
                    print(f"{YELLOW}[LOGIN] Khong co cookies sau login{RESET}")
                    return None

        except Exception as e:
            print(f"{YELLOW}[LOGIN] Error: {e}{RESET}")
            _debug(f"Exception type: {type(e).__name__}, details: {e}")
            return None

    # ─── Internal: LLM analysis ──────────────────────────────────

    def _analyze(self, url: str, anon_data: dict | None, auth_data: dict | None) -> str:
        """Send crawl data to LLM, let it write recon.md via tools.

        Returns:
            Absolute path to recon.md.
        """
        recon_path = os.path.join(self.working_dir, "recon.md")

        # Build data summary for LLM
        parts = []
        parts.append(f"TARGET: {url}")
        parts.append(f"WORKSPACE: {self.working_dir}")
        parts.append(f"OUTPUT FILE: {recon_path}")
        parts.append("")

        if anon_data:
            parts.append("=" * 60)
            parts.append("ANONYMOUS CRAWL DATA")
            parts.append("=" * 60)
            parts.append(self._format_crawl_data(anon_data))
            parts.append("")

        if auth_data:
            parts.append("=" * 60)
            parts.append("AUTHENTICATED CRAWL DATA")
            parts.append("=" * 60)
            parts.append(self._format_crawl_data(auth_data))
            parts.append("")

        if not anon_data and not auth_data:
            parts.append("WARNING: No crawl data available. Write a minimal report noting the failure.")

        data_text = truncate("\n".join(parts))

        messages = [
            {"role": "system", "content": RECON_SYSTEM_PROMPT},
            {"role": "user", "content": data_text},
        ]

        self._tool_loop(messages)

        # Verify recon.md was created
        if os.path.exists(recon_path):
            size = os.path.getsize(recon_path)
            print(f"{GREEN}{BOLD}[CRAWL-AGENT] recon.md written: {recon_path} ({size} bytes){RESET}")
        else:
            # Fallback: write a basic report ourselves
            print(f"{YELLOW}[CRAWL-AGENT] LLM did not write recon.md, creating fallback...{RESET}")
            with open(recon_path, "w") as f:
                f.write(f"# Recon Report — {url}\n\n")
                f.write("LLM analysis failed to produce output.\n\n")
                f.write("## Raw Data\n\n")
                f.write(data_text)
            print(f"{GREEN}[CRAWL-AGENT] Fallback recon.md written: {recon_path}{RESET}")

        return recon_path

    def _format_crawl_data(self, data: dict) -> str:
        """Format crawler JSON output into readable text for LLM."""
        parts = []

        # Cookies
        cookies = data.get("cookies", [])
        if cookies:
            parts.append("## Cookies")
            for c in cookies:
                parts.append(f"  {c.get('name', '?')}={c.get('value', '')}"
                             f"  (domain={c.get('domain', '?')}, path={c.get('path', '/')}"
                             f", httpOnly={c.get('httpOnly', False)}, secure={c.get('secure', False)})")
            parts.append("")

        # HTTP Traffic
        traffic = data.get("http_traffic", [])
        if traffic:
            # Filter out noise
            keep_types = {"document", "xhr", "fetch", "form", "websocket", "other", "script"}
            filtered = [r for r in traffic
                        if r.get("resource_type", "other") in keep_types
                        and r.get("method", "").upper() != "OPTIONS"]

            # Pages
            pages = [r for r in filtered if r.get("resource_type") == "document"]
            if pages:
                seen = set()
                parts.append("## Pages Visited")
                for r in pages:
                    u = r.get("url", "?")
                    if u not in seen:
                        seen.add(u)
                        parts.append(f"  [{r.get('response_status', '?')}] {u}")
                parts.append("")

            # API requests
            api = [r for r in filtered if r.get("resource_type") in ("xhr", "fetch", "other")]
            if api:
                interesting_headers = {"content-type", "authorization", "cookie",
                                       "set-cookie", "location", "x-csrf-token"}
                parts.append("## API/XHR Requests")
                for r in api:
                    parts.append(f"REQUEST: {r.get('method', '?')} {r.get('url', '?')}")
                    req_h = r.get("headers", {})
                    shown = {k: v for k, v in req_h.items() if k.lower() in interesting_headers}
                    if shown:
                        parts.append(f"  Headers: {shown}")
                    if r.get("postData"):
                        parts.append(f"  Body: {r['postData'][:500]}")
                    parts.append(f"RESPONSE: {r.get('response_status', '?')}")
                    resp_h = r.get("response_headers", {})
                    shown_resp = {k: v for k, v in resp_h.items() if k.lower() in interesting_headers}
                    if shown_resp:
                        parts.append(f"  Headers: {shown_resp}")
                    if r.get("response_body"):
                        parts.append(f"  Body: {r['response_body'][:500]}")
                    parts.append("---")
                parts.append("")

            # Forms
            forms = [r for r in traffic if r.get("resource_type") == "form"]
            if forms:
                parts.append("## Forms")
                for r in forms:
                    parts.append(f"  {r.get('method', '?')} {r.get('url', '?')} "
                                 f"(on: {r.get('parent_url', '?')})")
                    if r.get("form_fields"):
                        for f in r["form_fields"]:
                            parts.append(f"    - {f.get('name', '?')} "
                                         f"(type={f.get('type', '?')}, value={f.get('value', '')})")
                parts.append("")

            parts.append(f"Summary: {len(traffic)} total, {len(filtered)} useful, "
                         f"{len(pages)} pages, {len(api)} API, {len(forms)} forms")

        # External links
        external = data.get("external_links", [])
        if external:
            parts.append(f"\n## External Links ({len(external)})")
            for u in external[:20]:
                parts.append(f"  {u}")
            if len(external) > 20:
                parts.append(f"  ... and {len(external) - 20} more")

        return "\n".join(parts)

    # ─── Internal: Tool-calling loop (simplified) ────────────────

    def _tool_loop(self, messages: list[dict]) -> str:
        """Run tool calls until LLM produces text with [DONE] tag.

        Simplified version of ExecutorAgent._tool_loop:
        - Only handles shell + fetch + filesystem tools
        - Max 30 rounds
        - [DONE] tag signals completion
        """
        consecutive_errors = 0
        tool_count = 0
        nudge_count = 0
        max_nudges = 3
        consecutive_repeats = 0
        last_tool_signature = None

        for round_idx in range(MAX_TOOL_ROUNDS):
            try:
                tool_choice = "required" if round_idx == 0 and self.tools else "auto"

                response = self.client.chat.completions.create(
                    model=MODEL,
                    messages=messages,
                    tools=self.tools if self.tools else None,
                    tool_choice=tool_choice if self.tools else None,
                    temperature=0.3,
                    max_tokens=8192,
                )
            except Exception as e:
                consecutive_errors += 1
                print(f"{DIM}[CRAWL-AGENT] API error ({consecutive_errors}): {e}{RESET}")
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                    return f"[API Error after {consecutive_errors} retries: {e}]\n[DONE]"
                continue

            consecutive_errors = 0
            choice = response.choices[0]
            msg = choice.message

            # ── Tool calls ──
            if msg.tool_calls:
                messages.append({
                    "role": "assistant",
                    "content": msg.content or "",
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                        }
                        for tc in msg.tool_calls
                    ],
                })

                for tc in msg.tool_calls:
                    tool_count += 1
                    fn_name = tc.function.name
                    try:
                        fn_args = json.loads(tc.function.arguments)
                    except json.JSONDecodeError:
                        fn_args = {}

                    # Detect repeated calls
                    tool_sig = (fn_name, tc.function.arguments)
                    if tool_sig == last_tool_signature:
                        consecutive_repeats += 1
                    else:
                        consecutive_repeats = 0
                        last_tool_signature = tool_sig

                    print(f"{DIM}[CRAWL-AGENT] Tool {tool_count}: "
                          f"{fn_name}({json.dumps(fn_args, ensure_ascii=False)[:120]}){RESET}")

                    try:
                        result = self.mcp.execute_tool(fn_name, fn_args)
                        result_text = truncate(str(result))
                        consecutive_errors = 0
                    except Exception as e:
                        result_text = f"Error: {e}"
                        consecutive_errors += 1

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": result_text,
                    })

                # Break repeated loops
                if consecutive_repeats >= 3:
                    print(f"{YELLOW}[CRAWL-AGENT] Repeated tool call detected, forcing continue{RESET}")
                    messages.append({
                        "role": "user",
                        "content": (
                            f"STOP. You called {last_tool_signature[0]} with the same args "
                            f"{consecutive_repeats + 1} times. Move on. "
                            "If you have written the report, respond with [DONE]."
                        ),
                    })
                    consecutive_repeats = 0

                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                    messages.append({
                        "role": "user",
                        "content": (
                            f"The last {MAX_CONSECUTIVE_ERRORS} tool calls FAILED. "
                            "STOP retrying. Write what you have and respond with [DONE]."
                        ),
                    })
                    consecutive_errors = 0

                nudge_count = 0

                # Approaching limit
                if round_idx >= MAX_TOOL_ROUNDS - 3:
                    messages.append({
                        "role": "user",
                        "content": (
                            "IMPORTANT: Running out of tool rounds. "
                            "Finalize recon.md NOW and respond with [DONE]."
                        ),
                    })

                continue

            # ── Text response ──
            text = msg.content or ""

            if _has_done_tag(text):
                return text

            nudge_count += 1
            if nudge_count >= max_nudges:
                return text + "\n[DONE]"

            messages.append({"role": "assistant", "content": text})
            messages.append({
                "role": "user",
                "content": "Continue. Use write_file to save the report. When done, respond with [DONE].",
            })

        return f"[CrawlAgent reached {MAX_TOOL_ROUNDS} tool rounds limit]\n[DONE]"


# ═══════════════════════════════════════════════════════════════
# CLI — standalone test
# ═══════════════════════════════════════════════════════════════

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} \"<URL> [credentials: user:pass]\"")
        print(f"Example: python {sys.argv[0]} \"http://testphp.vulnweb.com/\"")
        print(f"Example: python {sys.argv[0]} \"https://target.com/ credentials: admin:password\"")
        sys.exit(1)

    user_prompt = sys.argv[1]
    agent = CrawlAgent()

    try:
        recon_path = agent.run(user_prompt)
        if recon_path:
            print(f"\n{GREEN}{BOLD}{'=' * 60}{RESET}")
            print(f"{GREEN}{BOLD}  RECON COMPLETE: {recon_path}{RESET}")
            print(f"{GREEN}{BOLD}{'=' * 60}{RESET}")
        else:
            print(f"\n{RED}Recon failed — no output generated.{RESET}")
            sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted.{RESET}")
    finally:
        agent.shutdown()


if __name__ == "__main__":
    main()
