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
from collections import Counter
from html import unescape
from pathlib import Path
from urllib.parse import urlparse, urljoin, parse_qsl

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
    truncate, parse_prompt_llm,
)


# ═══════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "gho_token")
SERVER_URL = os.getenv("MARL_SERVER_URL", "http://127.0.0.1:5000/v1")
MODEL = os.getenv("MARL_CRAWL_MODEL", os.getenv("MARL_EXECUTOR_MODEL", "ollama/gemma4:31b-cloud"))
TOOLCALL_MODEL = os.getenv("MARL_CRAWL_TOOLCALL_MODEL", os.getenv("MARL_TOOLCALL_MODEL", MODEL))
DEBUG = os.getenv("MARL_DEBUG", "").lower() in ("1", "true", "yes")

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
RECON_TOOL_ROUNDS = 8
MAX_CONSECUTIVE_ERRORS = 3
TRUNCATE_LIMIT = 15000
CRAWL_DATA_BODY_LIMIT = 8000
RECON_FILE_INLINE_PREVIEW_LIMIT = 4000
RECON_CONCRETE_URL_SAMPLE_LIMIT = 6
RECON_ROUTE_CLUE_LIMIT = 8
RECON_ROUTE_TABLE_LIMIT = 80
RECON_ALLOWED_TOOL_NAMES = {
    "read_text_file",
    "write_file",
    "edit_file",
    "list_directory",
    "search_files",
}
RECON_SINGLE_READ_FILES = {
    "crawl_data.txt",
    "crawl_raw.json",
}
IDENTITY_COOKIE_NAMES = {
    "role", "roles", "user_id", "userid", "user", "uid", "account_id",
    "accountid", "is_admin", "isadmin", "admin", "privilege", "permission",
}
SECURITY_COOKIE_NAMES = {
    "session", "sessionid", "phpsessid", "jsessionid", "sid", "auth",
    "auth_token", "token", "csrf", "xsrf",
}

# Path to crawler CLI
_CRAWLER_CLI = str(Path(__file__).resolve().parent.parent / "tools" / "crawler.py")


# ═══════════════════════════════════════════════════════════════
# RECON SYSTEM PROMPT
# ═══════════════════════════════════════════════════════════════

RECON_SYSTEM_PROMPT = """You are a web reconnaissance analyst specialized in BAC (Broken Access Control) and BLF (Business Logic Flaw).

You have access to:
- crawl_data.txt: formatted full crawl evidence
- crawl_raw.json: raw captured HTTP traffic

Your job: produce a rich recon.md that lets a human quickly understand:
1. this website does what,
2. which endpoints exist,
3. what each important endpoint appears to do,
4. what parameters and forms are involved,
5. what HTML/JSON responses reveal,
6. where the BAC/BLF attack surface is.

MANDATORY FIRST STEPS:
1. Read crawl_data.txt fully with read_text_file.
2. If needed, read crawl_raw.json for extra detail.
3. Then write recon.md to the exact output path provided.
4. Do not use shell/cat/wc/jq-style commands during recon writing. Read each crawl artifact at most once, then summarize and write the report.

=== SCOPE ===
Focus on BAC and BLF attack surface, but the report must still explain the application's functional surface clearly.
Out of scope for findings: XSS, SQLi, SSRF, XXE, generic header issues, vague best practices.

=== REPORT GOAL ===
recon.md must be useful for BOTH:
- humans reading the app for the first time
- downstream agents that need concrete endpoint/function/parameter evidence

=== REQUIRED REPORT STRUCTURE ===

## Target Overview
- URL
- app theme / business purpose
- auth mechanism
- observed user roles / cookies / session hints

## Functional Map
A concise map of the application's major functions:
- browsing products/content
- authentication/account/profile
- cart/checkout/order/payment/transfer/admin/etc.

## Endpoint Inventory
Table:
| Method | Endpoint | Auth | Response Type | Main Function | Key Params / Fields | Notes |

Include ALL meaningful endpoints discovered from pages, XHR/fetch, and forms.

## Endpoint Details
For each important endpoint, include:
- what the endpoint appears to do
- whether it seems anonymous or authenticated
- request parameters / form fields / body fields
- notable response details in prose
- if HTML: title, headings, forms, admin/account/cart/order indicators
- if JSON: important keys / objects / flags

## Forms And Input Surface
List important forms with:
- page found on
- action URL
- method
- fields
- hidden / numeric / identifier / role / workflow-related inputs

## Session And Role Observations
- cookies observed
- differences between anonymous and authenticated traffic
- any admin/account/profile/order/cart endpoints

## BAC / BLF Attack Surface
Concrete observations only. Explain why each endpoint is interesting for:
- IDOR / ownership checks
- privilege escalation
- forced browsing
- numeric manipulation
- workflow/state manipulation
- price / quantity / amount / transfer logic

## Evidence Snippets
Keep important raw snippets that future agents may need:
- exact request params
- exact form fields
- exact notable HTML titles/headings/text
- exact JSON keys / sample values

## Structured Route Families
Preserve the deterministic route-family appendix that will be appended after your narrative sections.
Do not rewrite raw HTML/JSON dumps into the narrative. Summarize behaviors in prose:
- what each endpoint returns
- what identifiers or mutable fields it accepts
- what role/session context it appeared under
- why it matters for BAC/BLF follow-up

=== RULES ===
- Do not hallucinate missing endpoints or parameters.
- Use actual endpoint paths, params, field names, cookies, and response clues from crawl evidence.
- Prefer completeness over brevity.
- Keep markdown readable and structured.
- Prefer prose summaries over large pasted response bodies.
- Use write_file to save recon.md.
- Do not repeatedly inspect crawl_raw.json. If the first read is enough, write recon.md immediately.
- When done, respond with [DONE]."""


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
        1. LLM parse prompt → URL + list credentials + focus
        2. Anonymous crawl via tools/crawler.py CLI
        3. Loop qua từng account: login → authenticated crawl
        4. LLM analysis → write recon.md (có session comparison nếu ≥2 accounts)

        Args:
            user_prompt: User input chứa URL và tuỳ ý nhiều cặp credentials.

        Returns:
            Absolute path to the generated recon.md file.
        """
        # ── Parse prompt bằng LLM ──
        print(f"\n{YELLOW}{BOLD}[CRAWL-AGENT] Parsing prompt...{RESET}")
        parsed = parse_prompt_llm(user_prompt, self.client)
        url = parsed["url"]
        credentials_list = parsed["credentials"]
        focus = parsed.get("focus", "")

        if not url:
            print(f"{RED}[CRAWL-AGENT] ERROR: Khong tim thay URL trong prompt.{RESET}")
            return ""

        print(f"{GREEN}{BOLD}[CRAWL-AGENT] Target: {url}{RESET}")
        if credentials_list:
            labels = [c["label"] for c in credentials_list]
            print(f"{GREEN}[CRAWL-AGENT] Accounts ({len(credentials_list)}): {labels}{RESET}")
        else:
            print(f"{DIM}[CRAWL-AGENT] Khong co credentials{RESET}")
        if focus:
            print(f"{GREEN}[CRAWL-AGENT] Focus: {focus}{RESET}")

        _debug(f"Parsed: url={url}, credentials={[c['label'] for c in credentials_list]}, focus={focus}")
        _debug(f"Config: MODEL={MODEL}, TOOLCALL_MODEL={TOOLCALL_MODEL}, SERVER_URL={SERVER_URL}")
        _debug(f"Working dir: {self.working_dir}")

        # ── Phase 1: Anonymous crawl ──
        print(f"\n{YELLOW}{BOLD}[CRAWL-AGENT] Phase 1: Anonymous crawl...{RESET}")
        anon_data = self._run_crawler(url)

        # ── Phase 2+3: Loop qua từng account ──
        auth_sessions: list[dict] = []
        for idx, cred in enumerate(credentials_list):
            label = cred["label"]
            print(f"\n{YELLOW}{BOLD}[CRAWL-AGENT] Phase 2: Login [{label}]...{RESET}")
            login_cookies = self._login(url, cred)

            if login_cookies:
                print(f"{GREEN}[CRAWL-AGENT] Login [{label}] OK — {len(login_cookies)} cookies{RESET}")
                print(f"\n{YELLOW}{BOLD}[CRAWL-AGENT] Phase 3: Authenticated crawl [{label}]...{RESET}")
                cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in login_cookies)
                _debug(f"[{label}] Injecting {len(login_cookies)} cookies: {cookie_str[:100]}...")
                data = self._run_crawler(url, cookie_header=cookie_str, max_pages=25, max_rounds=1, timeout=180)
                if data:
                    auth_verified = self._auth_crawl_verified(anon_data, data)
                    auth_sessions.append({
                        "label": label,
                        "cookies": login_cookies,
                        "data": data,
                        "auth_verified": auth_verified,
                    })
                    _debug(f"[{label}] Auth crawl done: {len(data.get('http_traffic', []))} requests")

                    # ── Verify authenticated crawl actually differs from anonymous ──
                    if anon_data:
                        anon_urls = set()
                        for r in anon_data.get("http_traffic", []):
                            if r.get("resource_type") in ("document", "xhr", "fetch"):
                                anon_urls.add(f"{r.get('method', '?')} {r.get('url', '?')}")
                        auth_urls = set()
                        for r in data.get("http_traffic", []):
                            if r.get("resource_type") in ("document", "xhr", "fetch"):
                                auth_urls.add(f"{r.get('method', '?')} {r.get('url', '?')}")

                        new_urls = auth_urls - anon_urls
                        if auth_verified:
                            print(f"{GREEN}[CRAWL-AGENT] Auth crawl [{label}] verified — "
                                  f"authenticated responses differ from anonymous crawl{RESET}")
                        elif new_urls:
                            print(f"{GREEN}[CRAWL-AGENT] Auth crawl [{label}] discovered "
                                  f"{len(new_urls)} new URL(s) vs anonymous{RESET}")
                            _debug(f"[{label}] New URLs: {sorted(new_urls)[:10]}")
                        elif auth_urls == anon_urls:
                            print(f"{YELLOW}[CRAWL-AGENT] WARNING: Auth crawl [{label}] returned "
                                  f"IDENTICAL URLs to anonymous crawl — authentication may have "
                                  f"failed or cookies were not injected properly{RESET}")
                        else:
                            print(f"{YELLOW}[CRAWL-AGENT] Auth crawl [{label}]: "
                                  f"{len(auth_urls)} URLs (anon had {len(anon_urls)}){RESET}")
                else:
                    print(f"{YELLOW}[CRAWL-AGENT] Auth crawl [{label}] returned no data{RESET}")
            else:
                print(f"{YELLOW}[CRAWL-AGENT] Login [{label}] failed, skipping authenticated crawl{RESET}")

        if not credentials_list:
            print(f"\n{DIM}[CRAWL-AGENT] Phase 2+3: No credentials, skipping login{RESET}")

        # ── Phase 4: Lưu crawl data đầy đủ ──
        self._save_crawl_data(url, anon_data, auth_sessions, focus)

        # ── Phase 5: Tóm tắt crawl data thành recon.md ──
        print(f"\n{YELLOW}{BOLD}[CRAWL-AGENT] Phase 5: Recon summary...{RESET}")
        recon_path = self._analyze(url, anon_data, auth_sessions, focus)
        print(f"\n{GREEN}[CRAWL-AGENT] Done — recon.md generated.{RESET}")

        return recon_path

    def shutdown(self):
        """Clean up MCP servers."""
        print(f"{YELLOW}[CRAWL-AGENT] Shutting down MCP...{RESET}")
        self.mcp.stop_all()
        print(f"{YELLOW}[CRAWL-AGENT] Done.{RESET}")

    def rebuild_recon_from_saved_artifacts(self, user_prompt: str) -> str:
        """Regenerate recon.md from existing crawl_data.txt/crawl_raw.json without re-crawling."""
        parsed = parse_prompt_llm(user_prompt, self.client)
        url = parsed["url"]
        focus = parsed.get("focus", "")

        raw_crawl_path = os.path.join(self.working_dir, "crawl_raw.json")
        anon_data = None
        auth_sessions: list[dict] = []
        if os.path.isfile(raw_crawl_path):
            try:
                raw_payload = json.loads(Path(raw_crawl_path).read_text(encoding="utf-8"))
                anon_data = raw_payload.get("anonymous")
                auth_sessions = raw_payload.get("authenticated", []) or []
            except Exception as e:
                print(f"{YELLOW}[CRAWL-AGENT] Could not parse saved crawl_raw.json: {e}{RESET}")

        return self._analyze(url, anon_data, auth_sessions, focus)

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

    @staticmethod
    def _auth_crawl_verified(anon_data: dict | None, auth_data: dict | None) -> bool:
        """Return True if authenticated crawl shows meaningful auth-only evidence."""
        if not auth_data:
            return False

        auth_traffic = [
            r for r in auth_data.get("http_traffic", [])
            if r.get("resource_type") in ("document", "xhr", "fetch")
        ]
        if not auth_traffic:
            return False

        def key(r: dict) -> str:
            return f"{r.get('method', 'GET')} {r.get('url', '')}"

        anon_by_key = {}
        if anon_data:
            for r in anon_data.get("http_traffic", []):
                if r.get("resource_type") in ("document", "xhr", "fetch"):
                    anon_by_key[key(r)] = r

        auth_only_markers = (
            "logout", "log out", "sign out", "my account", "my-account",
            "your account", "admin panel", "admin interface", "change email",
            "đăng xuất", "tai khoan", "tài khoản",
        )
        # Generic "something changed" markers — signal auth worked even without explicit markers
        auth_generic_markers = (
            "welcome", "dashboard", "profile", "settings", "orders",
            "history", "previous orders", "your name", "email address",
            "account details", "manage", "purchases",
        )

        for r in auth_traffic:
            url = r.get("url", "")
            status = r.get("response_status")
            body = (r.get("response_body") or "").lower()
            location = ""
            for h, v in (r.get("response_headers") or {}).items():
                if h.lower() == "location":
                    location = str(v).lower()
                    break

            if "/my-account" in url and status == 200 and "login" not in location:
                return True
            if any(marker in body for marker in auth_only_markers):
                return True

            anon_r = anon_by_key.get(key(r))
            if anon_r:
                anon_status = anon_r.get("response_status")
                anon_body = (anon_r.get("response_body") or "")[:800]
                auth_body = (r.get("response_body") or "")[:800]
                if status != anon_status and status not in (301, 302, 303, 307, 308):
                    return True
                # If content meaningfully changed, auth likely worked
                if auth_body and anon_body and auth_body != anon_body:
                    # Require SOME content signal (either explicit auth marker or generic)
                    if any(marker in body for marker in auth_only_markers + auth_generic_markers):
                        return True
                    # Or: URL is clearly an auth-protected page (not login/register)
                    if any(kw in url.lower() for kw in ("account", "order", "cart", "profile", "dashboard", "settings", "admin")):
                        return True

        return False

    # ─── Internal: Login via httpx ───────────────────────────────

    def _login(self, target_url: str, credentials: dict) -> list[dict] | None:
        """Login via httpx. Returns list of cookie dicts or None.

        Args:
            credentials: dict có ít nhất "username" và "password".
                         Có thể là CredentialEntry (có thêm "label") hoặc plain dict.
        """
        label = credentials.get("label", credentials.get("username", "?"))
        domain = urlparse(target_url).netloc
        _debug(f"[{label}] Login target: {target_url}, domain: {domain}")
        _debug(f"[{label}] Credentials: username={credentials.get('username')}, "
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

                # ── Verify login success ──

                # Check 1: Response status — reject server errors (4xx/5xx except 302/303 redirects)
                status_ok = login_resp.status_code in (200, 302, 303) or (
                    300 <= login_resp.status_code < 400
                )
                _debug(f"  -> Status check: {login_resp.status_code} — {'OK' if status_ok else 'FAIL'}")

                # Check 2: Error keywords in response body
                body_lower = login_resp.text.lower()
                error_keywords = ["incorrect", "wrong password", "wrong username", "login failed",
                                  "authentication failed", "sai mật khẩu", "không đúng"]
                found_errors = [kw for kw in error_keywords if kw in body_lower]
                has_errors = bool(found_errors)
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

                # Check 3: Did any session cookie VALUE change or is there a NEW cookie?
                pre_values = {c.name: c.value for c in pre_cookies}
                cookie_changed = False
                new_cookie_added = False
                for c in all_cookies:
                    if c["name"] in pre_values:
                        changed = c["value"] != pre_values[c["name"]]
                        _debug(f"  Cookie '{c['name']}' changed: {changed}")
                        if changed:
                            cookie_changed = True
                    else:
                        _debug(f"  Cookie '{c['name']}' is NEW (not present before login)")
                        new_cookie_added = True

                session_changed = cookie_changed or new_cookie_added

                # ── Decision: login success requires cookies AND verification ──
                if not all_cookies:
                    print(f"{YELLOW}[LOGIN] Khong co cookies sau login{RESET}")
                    return None

                if has_errors:
                    print(f"{YELLOW}[LOGIN] Login failed — response contains error keywords: {found_errors}{RESET}")
                    return None

                if not status_ok:
                    print(f"{YELLOW}[LOGIN] Login failed — unexpected status code: {login_resp.status_code}{RESET}")
                    return None

                # Check 3: session cookie change is not required — servers that revalidate the
                # same anonymous session (no new cookie needed) are valid logins.
                # Success is already guaranteed by the has_errors + status_ok checks above.

                # Check 4: verify an authenticated page with the same httpx session.
                verify_paths = []
                for path in ("/my-account", "/account", "/profile"):
                    verify_paths.append(urljoin(target_url, path))
                verified = False
                for verify_url in verify_paths:
                    try:
                        verify_resp = client.get(verify_url)
                        verify_body = verify_resp.text.lower()
                        final_path = urlparse(str(verify_resp.url)).path.lower()
                        redirected_to_login = "login" in final_path and "password" in verify_body
                        has_auth_marker = any(
                            marker in verify_body
                            for marker in ("logout", "log out", "my account", "your account", "change email", "admin")
                        )
                        _debug(f"  -> Verify GET {verify_url}: status={verify_resp.status_code}, "
                               f"final={verify_resp.url}, auth_marker={has_auth_marker}, "
                               f"redirected_to_login={redirected_to_login}")
                        if verify_resp.status_code == 200 and has_auth_marker and not redirected_to_login:
                            verified = True
                            break
                    except Exception as e:
                        _debug(f"  -> Verify GET {verify_url} failed: {e}")

                if not verified:
                    print(f"{YELLOW}[LOGIN] WARNING: Cookie changed but authenticated page was not verified. "
                          f"Authenticated crawl may still be anonymous.{RESET}")

                print(f"{GREEN}[LOGIN] Login verified OK — cookies: {[c['name'] for c in all_cookies]}, "
                      f"session_changed={session_changed}, auth_page_verified={verified}, "
                      f"status={login_resp.status_code}{RESET}")
                return all_cookies

        except Exception as e:
            print(f"{YELLOW}[LOGIN] Error: {e}{RESET}")
            _debug(f"Exception type: {type(e).__name__}, details: {e}")
            return None

    # ─── Internal: LLM analysis ──────────────────────────────────

    def _analyze(
        self,
        url: str,
        anon_data: dict | None,
        auth_sessions: list[dict],
        focus: str = "",
    ) -> str:
        """Send crawl data to LLM, let it write recon.md via tools.

        Args:
            auth_sessions: list of {"label": str, "cookies": list, "data": dict}
                           Rỗng nếu không có credentials.
            focus: từ khóa mục tiêu ("IDOR", "BLF"...) từ user prompt.

        Returns:
            Absolute path to recon.md.
        """
        recon_path = os.path.join(self.working_dir, "recon.md")
        raw_crawl_path = os.path.join(self.working_dir, "crawl_raw.json")
        crawl_data_path = os.path.join(self.working_dir, "crawl_data.txt")

        # Build a compact manifest and let the agent read the full crawl files directly.
        parts = []
        parts.append("=== RECON JOB ===")
        parts.append(f"TARGET: {url}")
        parts.append(f"WORKSPACE: {self.working_dir}")
        parts.append(f"OUTPUT FILE: {recon_path}")
        parts.append(f"CRAWL DATA FILE: {crawl_data_path}")
        parts.append(f"RAW CRAWL JSON FILE: {raw_crawl_path}")
        if focus:
            parts.append(f"FOCUS: {focus}")
        if anon_data:
            parts.append(f"ANONYMOUS REQUESTS: {len(anon_data.get('http_traffic', []))}")
        if auth_sessions:
            labels = ", ".join(s["label"] for s in auth_sessions)
            parts.append(f"AUTHENTICATED SESSIONS: {labels}")
        for session in auth_sessions:
            label = session["label"]
            auth_verified = session.get("auth_verified", False)
            req_count = len(session.get("data", {}).get("http_traffic", []))
            parts.append(
                f"- session={label} requests={req_count} auth_verified={auth_verified}"
            )

        if not anon_data and not auth_sessions:
            parts.append("WARNING: No crawl data available. Write a minimal report noting the failure.")
        parts.append("")
        parts.append("MANDATORY:")
        parts.append(f"1. Read full crawl data from {crawl_data_path}")
        parts.append(f"2. If needed, read full raw JSON from {raw_crawl_path}")
        parts.append(f"3. Write the final markdown report to {recon_path}")
        parts.append("4. Include endpoint inventory, endpoint details, forms, params, response clues, and BAC/BLF attack surface.")
        parts.append("5. Pay special attention to client-controlled cookies/state such as role, user_id, is_admin, account_id.")
        parts.append("6. Do not call shell commands such as cat, wc, jq, grep, sed. Use read_text_file/write_file only.")
        parts.append("7. Read each crawl artifact at most once, then write recon.md and finish with [DONE].")
        parts.append("")
        parts.append("Quick preview from crawl_data.txt:")
        try:
            preview = Path(crawl_data_path).read_text(encoding="utf-8")
            parts.append(truncate(preview, RECON_FILE_INLINE_PREVIEW_LIMIT))
        except Exception as e:
            parts.append(f"(Could not read preview: {e})")

        messages = [
            {"role": "system", "content": RECON_SYSTEM_PROMPT},
            {"role": "user", "content": "\n".join(parts)},
        ]

        self._tool_loop(
            messages,
            max_rounds=RECON_TOOL_ROUNDS,
            allowed_tool_names=RECON_ALLOWED_TOOL_NAMES,
        )

        structured_appendix = self._render_structured_recon_appendix(anon_data, auth_sessions)

        # Verify recon.md was created
        if os.path.exists(recon_path):
            size = os.path.getsize(recon_path)
            if structured_appendix:
                try:
                    existing = Path(recon_path).read_text(encoding="utf-8")
                    if "## Structured Route Families" not in existing:
                        merged = existing.rstrip() + "\n\n" + structured_appendix
                        Path(recon_path).write_text(merged, encoding="utf-8")
                        size = os.path.getsize(recon_path)
                    elif "## Client-Controlled State / Cookie Attack Surface" not in existing:
                        cookie_appendix = self._render_cookie_recon_appendix(auth_sessions)
                        if cookie_appendix:
                            merged = existing.rstrip() + "\n\n" + cookie_appendix
                            Path(recon_path).write_text(merged, encoding="utf-8")
                            size = os.path.getsize(recon_path)
                except Exception as e:
                    print(f"{YELLOW}[CRAWL-AGENT] Could not append structured recon appendix: {e}{RESET}")
            print(f"{GREEN}{BOLD}[CRAWL-AGENT] recon.md written: {recon_path} ({size} bytes){RESET}")
        else:
            # Fallback: write a basic report ourselves
            print(f"{YELLOW}[CRAWL-AGENT] LLM did not write recon.md, creating fallback...{RESET}")
            with open(recon_path, "w") as f:
                f.write(f"# Recon Report — {url}\n\n")
                f.write("LLM analysis failed to produce output.\n\n")
                f.write("## Crawl Data Preview\n\n")
                try:
                    f.write(truncate(
                        Path(crawl_data_path).read_text(encoding="utf-8"),
                        RECON_FILE_INLINE_PREVIEW_LIMIT,
                    ))
                except Exception as e:
                    f.write(f"(Could not read crawl_data.txt: {e})\n")
                if structured_appendix:
                    f.write("\n\n")
                    f.write(structured_appendix)
            print(f"{GREEN}[CRAWL-AGENT] Fallback recon.md written: {recon_path}{RESET}")

        return recon_path


    # ─── Internal: Save crawl data to files (no LLM) ────────────

    def _save_crawl_data(
        self,
        url: str,
        anon_data: dict | None,
        auth_sessions: list[dict],
        focus: str = "",
    ) -> None:
        """Lưu crawl data ra crawl_data.txt và crawl_raw.json. Không gọi LLM."""
        parts = []
        parts.append(f"TARGET: {url}")
        parts.append(f"WORKSPACE: {self.working_dir}")
        parts.append(f"RAW CRAWL DATA FILE: {os.path.join(self.working_dir, 'crawl_raw.json')}")
        parts.append(f"FORMATTED CRAWL DATA FILE: {os.path.join(self.working_dir, 'crawl_data.txt')}")
        if focus:
            parts.append(f"FOCUS: {focus}")
        if auth_sessions:
            label_list = ", ".join(s["label"] for s in auth_sessions)
            parts.append(f"SESSIONS: anonymous + {len(auth_sessions)} authenticated ({label_list})")
        else:
            parts.append("SESSIONS: anonymous")
        parts.append("")

        if anon_data:
            parts.append("=" * 60)
            parts.append("ANONYMOUS CRAWL DATA")
            parts.append("=" * 60)
            parts.append(self._format_crawl_data(anon_data))
            parts.append("")

        for session in auth_sessions:
            label = session["label"]
            data  = session["data"]
            auth_verified = session.get("auth_verified", False)
            parts.append("=" * 60)
            parts.append(f"AUTHENTICATED CRAWL — account: {label}")
            if not auth_verified:
                parts.append("WARNING: AUTHENTICATED CRAWL NOT VERIFIED")
            parts.append("=" * 60)
            parts.append(self._format_crawl_data(data))
            parts.append("")

        if not anon_data and not auth_sessions:
            parts.append("WARNING: No crawl data available.")

        formatted_text = "\n".join(parts)

        # Save crawl_raw.json
        raw_crawl_path = os.path.join(self.working_dir, "crawl_raw.json")
        try:
            raw_payload = {
                "target": url,
                "anonymous": anon_data,
                "authenticated": [
                    {
                        "label": s["label"],
                        "auth_verified": s.get("auth_verified", False),
                        "cookies": s.get("cookies", []),
                        "data": s.get("data", {}),
                    }
                    for s in auth_sessions
                ],
            }
            with open(raw_crawl_path, "w", encoding="utf-8") as f:
                json.dump(raw_payload, f, ensure_ascii=False, indent=2)
            print(f"{GREEN}[CRAWL-AGENT] Raw crawl JSON saved: {raw_crawl_path}{RESET}")
        except Exception as e:
            print(f"{YELLOW}[CRAWL-AGENT] Could not save crawl_raw.json: {e}{RESET}")

        # Save crawl_data.txt
        crawl_data_path = os.path.join(self.working_dir, "crawl_data.txt")
        try:
            with open(crawl_data_path, "w", encoding="utf-8") as f:
                f.write(formatted_text)
            print(f"{GREEN}[CRAWL-AGENT] Crawl data saved: {crawl_data_path} "
                  f"({len(formatted_text)} chars){RESET}")
        except Exception as e:
            print(f"{YELLOW}[CRAWL-AGENT] Could not save crawl_data.txt: {e}{RESET}")


    @staticmethod
    def _clean_html_text(text: str) -> str:
        """Collapse HTML-ish text into a readable single-line snippet."""
        text = unescape(text or "")
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    @staticmethod
    def _extract_request_fields(url: str, post_data: str | None) -> list[str]:
        """Extract human-readable request parameters from query/body."""
        lines: list[str] = []

        parsed = urlparse(url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if query_pairs:
            lines.append(
                "    Query params: " + ", ".join(f"{k}={v}" for k, v in query_pairs[:20])
            )

        if post_data:
            body_pairs = parse_qsl(post_data, keep_blank_values=True)
            if body_pairs:
                lines.append(
                    "    Body params: " + ", ".join(f"{k}={v}" for k, v in body_pairs[:30])
                )
            else:
                lines.append(f"    Raw body: {post_data[:2000]}")

        return lines

    @classmethod
    def _extract_response_clues(
        cls,
        body: str,
        content_type: str,
    ) -> list[str]:
        """Extract notable HTML/JSON clues for recon summaries."""
        if not body:
            return []

        lines: list[str] = []
        lower_ct = content_type.lower()
        stripped = body.strip()

        is_jsonish = "json" in lower_ct or stripped.startswith("{") or stripped.startswith("[")
        if is_jsonish:
            try:
                data = json.loads(stripped)
                if isinstance(data, dict):
                    lines.append("    JSON keys: " + ", ".join(list(data.keys())[:20]))
                elif isinstance(data, list):
                    lines.append(f"    JSON list length sample: {len(data)}")
                    if data and isinstance(data[0], dict):
                        lines.append("    JSON item keys: " + ", ".join(list(data[0].keys())[:20]))
            except Exception:
                lines.append("    JSON-like response present (could not parse fully).")
            return lines

        lower_body = body.lower()
        if "<html" in lower_body or "</html>" in lower_body:
            title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
            if title_match:
                title = cls._clean_html_text(title_match.group(1))
                if title:
                    lines.append(f"    HTML title: {title[:200]}")

            headings = [
                cls._clean_html_text(m)
                for m in re.findall(r"<h[1-3][^>]*>(.*?)</h[1-3]>", body, re.IGNORECASE | re.DOTALL)
            ]
            headings = [h for h in headings if h]
            if headings:
                lines.append("    Headings: " + " | ".join(headings[:5]))

            forms_found = len(re.findall(r"<form\b", body, re.IGNORECASE))
            if forms_found:
                lines.append(f"    HTML forms on page: {forms_found}")

            notable_keywords = []
            for label, keywords in (
                ("admin", ("admin", "dashboard", "user management")),
                ("account", ("profile", "my account", "account details")),
                ("cart", ("cart", "checkout", "quantity", "coupon")),
                ("order", ("order", "transfer", "payment", "status")),
                ("auth", ("login", "register", "logout", "password")),
            ):
                if any(k in lower_body for k in keywords):
                    notable_keywords.append(label)
            if notable_keywords:
                lines.append("    Notable HTML features: " + ", ".join(notable_keywords))
            return lines

        snippet = cls._clean_html_text(body)
        if snippet:
            lines.append(f"    Text snippet: {snippet[:300]}")
        return lines

    @staticmethod
    def _normalize_path_segment(segment: str) -> str:
        if re.fullmatch(r"\d+", segment):
            return "{id}"
        if re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            segment,
        ):
            return "{uuid}"
        if re.fullmatch(r"[0-9a-fA-F]{12,}", segment):
            return "{token}"
        return segment

    @classmethod
    def _route_family(cls, url: str) -> str:
        parsed = urlparse(url)
        segments = [cls._normalize_path_segment(seg) for seg in parsed.path.split("/") if seg]
        if not segments:
            return "/"
        return "/" + "/".join(segments)

    @staticmethod
    def _extract_param_names(url: str, post_data: str | None) -> list[str]:
        names: list[str] = []
        seen: set[str] = set()

        parsed = urlparse(url)
        for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
            if key and key not in seen:
                names.append(key)
                seen.add(key)

        if post_data:
            for key, _ in parse_qsl(post_data, keep_blank_values=True):
                if key and key not in seen:
                    names.append(key)
                    seen.add(key)

        return names

    @staticmethod
    def _extract_query_param_names(url: str) -> list[str]:
        return [key for key, _ in parse_qsl(urlparse(url).query, keep_blank_values=True) if key]

    @staticmethod
    def _extract_body_param_names(post_data: str | None) -> list[str]:
        if not post_data:
            return []
        return [key for key, _ in parse_qsl(post_data, keep_blank_values=True) if key]

    @classmethod
    def _summarize_route_family_records(
        cls,
        anon_data: dict | None,
        auth_sessions: list[dict],
    ) -> list[dict]:
        families: dict[str, dict] = {}

        def ensure_family(method: str, url: str) -> dict:
            family = cls._route_family(url)
            key = f"{method.upper()} {family}"
            entry = families.get(key)
            if entry is None:
                entry = {
                    "key": key,
                    "family": family,
                    "method": method.upper(),
                    "contexts": set(),
                    "resource_types": set(),
                    "status_counts": Counter(),
                    "content_types": Counter(),
                    "concrete_urls": [],
                    "concrete_seen": set(),
                    "parents": set(),
                    "query_params": [],
                    "query_seen": set(),
                    "body_params": [],
                    "body_seen": set(),
                    "form_fields": [],
                    "form_seen": set(),
                    "response_clues": [],
                    "response_seen": set(),
                    "instances": 0,
                    "interesting_reasons": [],
                    "reason_seen": set(),
                }
                families[key] = entry
            return entry

        def add_reason(entry: dict, reason: str) -> None:
            if reason not in entry["reason_seen"]:
                entry["reason_seen"].add(reason)
                entry["interesting_reasons"].append(reason)

        def feed_record(record: dict, context_label: str) -> None:
            method = str(record.get("method", "GET") or "GET").upper()
            url = str(record.get("url", "") or "")
            if not url:
                return
            resource_type = str(record.get("resource_type", "other") or "other")
            if resource_type not in {"document", "xhr", "fetch", "form", "websocket", "other", "script"}:
                return

            entry = ensure_family(method, url)
            entry["instances"] += 1
            entry["contexts"].add(context_label)
            entry["resource_types"].add(resource_type)

            status = record.get("response_status")
            if status is not None:
                entry["status_counts"][str(status)] += 1

            resp_headers = record.get("response_headers") or {}
            content_type = str(resp_headers.get("content-type") or resp_headers.get("Content-Type") or "")
            if content_type:
                entry["content_types"][content_type] += 1

            if url not in entry["concrete_seen"] and len(entry["concrete_urls"]) < RECON_CONCRETE_URL_SAMPLE_LIMIT:
                entry["concrete_seen"].add(url)
                entry["concrete_urls"].append(url)

            parent_url = str(record.get("parent_url", "") or "")
            if parent_url:
                entry["parents"].add(parent_url)

            for name in cls._extract_query_param_names(url):
                if name not in entry["query_seen"]:
                    entry["query_seen"].add(name)
                    entry["query_params"].append(name)

            for name in cls._extract_body_param_names(record.get("postData")):
                if name not in entry["body_seen"]:
                    entry["body_seen"].add(name)
                    entry["body_params"].append(name)

            for field in record.get("form_fields") or []:
                field_name = str(field.get("name", "")).strip()
                if not field_name or field_name in entry["form_seen"]:
                    continue
                entry["form_seen"].add(field_name)
                entry["form_fields"].append({
                    "name": field_name,
                    "type": str(field.get("type", "?") or "?"),
                    "value": str(field.get("value", "") or "")[:80],
                })

            for clue in cls._extract_response_clues(record.get("response_body") or "", content_type):
                normalized = clue.strip()
                if normalized and normalized not in entry["response_seen"]:
                    entry["response_seen"].add(normalized)
                    entry["response_clues"].append(normalized.replace("    ", "", 1))

            lower_family = entry["family"].lower()
            all_fields = entry["query_params"] + entry["body_params"] + [
                str(field.get("name", "")).strip() for field in entry["form_fields"]
            ]

            if "{id}" in entry["family"] or "{uuid}" in entry["family"]:
                add_reason(entry, "route uses direct object identifiers in the path")
            if any(token in lower_family for token in ("admin", "manage", "users")):
                add_reason(entry, "administrative route visible in crawl")
            if any(token in lower_family for token in ("order", "profile", "wallet", "transfer", "checkout", "cart")):
                add_reason(entry, "stateful account/order/payment workflow surface")
            if any(name in {"qty", "quantity", "amount", "price", "stock", "balance"} for name in all_fields):
                add_reason(entry, "mutable numeric input observed")
            if any(name in {"role", "user_id", "userId", "is_admin", "isAdmin"} for name in all_fields):
                add_reason(entry, "client-controlled identity/role field observed")
            if method in {"POST", "PUT", "PATCH", "DELETE"}:
                add_reason(entry, "state-changing method observed")

        if anon_data:
            for record in anon_data.get("http_traffic", []) or []:
                feed_record(record, "anonymous")

        for session in auth_sessions:
            label = str(session.get("label", "auth") or "auth")
            for record in session.get("data", {}).get("http_traffic", []) or []:
                feed_record(record, f"auth:{label}")

        ranked = sorted(
            families.values(),
            key=lambda item: (
                0 if item["interesting_reasons"] else 1,
                item["family"],
                item["method"],
            ),
        )
        return ranked[:RECON_ROUTE_TABLE_LIMIT]

    @staticmethod
    def _cookie_value_sample(value: str) -> str:
        text = str(value or "")
        if len(text) <= 32:
            return text or "(empty)"
        return text[:18] + "..." + text[-8:]

    @classmethod
    def _cookie_probe_hint(cls, name: str, value: str) -> str:
        lower_name = name.lower()
        lower_value = str(value or "").lower()
        if "role" in lower_name or "privilege" in lower_name or "permission" in lower_name:
            return "compare baseline request, then tamper role-like cookie value such as user -> admin"
        if lower_name in {"is_admin", "isadmin", "admin"}:
            return "compare baseline request, then try boolean admin values such as 1/true"
        if lower_name in {"user_id", "userid", "uid", "account_id", "accountid", "user"}:
            if lower_value.isdigit():
                return "compare baseline request, then try nearby object/user ids"
            return "compare baseline request, then try alternate identity value if observed"
        if lower_name in SECURITY_COOKIE_NAMES:
            return "treat as session/auth cookie; do not forge unless structure is clearly client-controlled"
        return "compare baseline request with and without this client-visible cookie"

    @classmethod
    def _summarize_cookie_attack_surface(cls, auth_sessions: list[dict]) -> list[dict]:
        surfaces: list[dict] = []
        seen: set[tuple[str, str, str]] = set()
        for session in auth_sessions or []:
            label = str(session.get("label", "authenticated") or "authenticated")
            for cookie in session.get("cookies", []) or []:
                if not isinstance(cookie, dict):
                    continue
                name = str(cookie.get("name", "") or "").strip()
                value = str(cookie.get("value", "") or "").strip()
                if not name:
                    continue
                lower_name = name.lower()
                http_only = bool(cookie.get("httpOnly", False))
                secure = bool(cookie.get("secure", False))
                identity_like = lower_name in IDENTITY_COOKIE_NAMES
                client_visible = not http_only
                security_cookie = lower_name in SECURITY_COOKIE_NAMES
                interesting = identity_like or (client_visible and not security_cookie)
                if not interesting:
                    continue
                key = (label, lower_name, value[:32])
                if key in seen:
                    continue
                seen.add(key)
                if identity_like and client_visible:
                    signal = "client-visible identity/role cookie"
                elif identity_like:
                    signal = "identity/role cookie"
                elif client_visible:
                    signal = "client-visible application state cookie"
                else:
                    signal = "cookie state"
                surfaces.append({
                    "session": label,
                    "name": name,
                    "value": value,
                    "value_sample": cls._cookie_value_sample(value),
                    "http_only": str(http_only),
                    "secure": str(secure),
                    "signal": signal,
                    "probe": cls._cookie_probe_hint(name, value),
                    "interesting": interesting,
                })
        return surfaces[:20]

    @classmethod
    def _render_cookie_recon_appendix(cls, auth_sessions: list[dict]) -> str:
        cookie_surfaces = cls._summarize_cookie_attack_surface(auth_sessions)
        if not cookie_surfaces:
            return ""
        lines = [
            "## Client-Controlled State / Cookie Attack Surface",
            "",
            "| Session | Cookie | Value Sample | HttpOnly | Secure | BAC/BLF Signal | Suggested Generic Probe |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        for item in cookie_surfaces:
            lines.append(
                f"| `{item['session']}` | `{item['name']}` | `{item['value_sample']}` | "
                f"{item['http_only']} | {item['secure']} | {item['signal']} | {item['probe']} |"
            )
        lines.extend([
            "",
            "These are generic follow-up candidates. They are not proof by themselves; "
            "Red/Exec must compare baseline user behavior against a tampered or alternate request "
            "and verify concrete server-side impact.",
            "",
        ])
        return "\n".join(lines).rstrip() + "\n"

    @classmethod
    def _render_structured_recon_appendix(
        cls,
        anon_data: dict | None,
        auth_sessions: list[dict],
    ) -> str:
        profiles = cls._summarize_route_family_records(anon_data, auth_sessions)
        cookie_surfaces = cls._summarize_cookie_attack_surface(auth_sessions)
        if not profiles and not cookie_surfaces:
            return ""

        lines: list[str] = []
        if profiles:
            lines.append("## Structured Route Families")
            lines.append("")
            lines.append("| Route Family | Contexts | Params / Fields | Response Summary | Signals |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")

            for item in profiles:
                contexts = ", ".join(sorted(item["contexts"])) or "-"
                params = item["query_params"] + item["body_params"]
                form_field_names = [str(field.get("name", "")).strip() for field in item["form_fields"]]
                param_text = ", ".join((params + form_field_names)[:6]) or "-"
                response_bits = []
                if item["status_counts"]:
                    status_text = ", ".join(
                        f"{status}x{count}" for status, count in item["status_counts"].most_common(3)
                    )
                    response_bits.append(f"statuses {status_text}")
                if item["response_clues"]:
                    clue = item["response_clues"][0]
                    response_bits.append(clue[:90])
                response_text = "; ".join(response_bits) or "-"
                signal_text = "; ".join(item["interesting_reasons"][:2]) or "-"
                lines.append(
                    f"| `{item['key']}` | {contexts} | {param_text} | {response_text} | {signal_text} |"
                )

            lines.append("")

        if cookie_surfaces:
            lines.append(cls._render_cookie_recon_appendix(auth_sessions).rstrip())
            lines.append("")

        if profiles:
            lines.append("## Endpoint Dossiers")
            lines.append("")

            for item in profiles:
                lines.append(f"### `{item['key']}`")
                lines.append(f"- Contexts seen: {', '.join(sorted(item['contexts'])) or '(none)'}")
                lines.append(
                    f"- Concrete URLs observed ({len(item['concrete_urls'])} sample): "
                    + (", ".join(f"`{u}`" for u in item["concrete_urls"]) if item["concrete_urls"] else "(none)")
                )

                request_bits = []
                if item["query_params"]:
                    request_bits.append("query params: " + ", ".join(f"`{p}`" for p in item["query_params"][:8]))
                if item["body_params"]:
                    request_bits.append("body params: " + ", ".join(f"`{p}`" for p in item["body_params"][:8]))
                if item["form_fields"]:
                    field_bits = []
                    for field in item["form_fields"][:8]:
                        field_bits.append(f"`{field['name']}` ({field['type']})")
                    request_bits.append("form fields: " + ", ".join(field_bits))
                lines.append("- Request shape: " + ("; ".join(request_bits) if request_bits else "no explicit params captured"))

                response_bits = []
                if item["status_counts"]:
                    response_bits.append(
                        "statuses " + ", ".join(
                            f"{status}x{count}" for status, count in item["status_counts"].most_common(4)
                        )
                    )
                if item["content_types"]:
                    response_bits.append(
                        "content types " + ", ".join(
                            f"`{ct}`" for ct, _ in item["content_types"].most_common(3)
                        )
                    )
                if item["response_clues"]:
                    response_bits.append(
                        "observed behavior: " + " | ".join(item["response_clues"][:RECON_ROUTE_CLUE_LIMIT])
                    )
                lines.append("- Response summary: " + ("; ".join(response_bits) if response_bits else "no response details captured"))

                if item["parents"]:
                    lines.append("- Seen from pages: " + ", ".join(f"`{u}`" for u in sorted(item["parents"])[:5]))
                if item["interesting_reasons"]:
                    lines.append("- BAC/BLF follow-up value: " + "; ".join(item["interesting_reasons"]))
                lines.append("")

        interesting = [item for item in profiles if item["interesting_reasons"]]
        if interesting:
            lines.append("## Candidate BAC/BLF Signals")
            lines.append("")
            for item in interesting:
                lines.append(
                    f"- `{item['key']}`: " + "; ".join(item["interesting_reasons"][:3])
                )
            for item in cookie_surfaces:
                if item["interesting"]:
                    lines.append(
                        f"- Cookie `{item['name']}` in session `{item['session']}`: "
                        f"{item['signal']}; probe: {item['probe']}"
                    )
            lines.append("")

        return "\n".join(lines).rstrip() + "\n"

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

            # Security-relevant headers to extract for pages and API
            interesting_headers = {"content-type", "authorization", "cookie",
                                   "set-cookie", "location", "x-csrf-token"}

            # Pages — now includes response headers, body snippet, and postData
            pages = [r for r in filtered if r.get("resource_type") == "document"]
            if pages:
                best_entry = {}  # dedup_key -> (entry_r, body_len) with longest body
                for r in pages:
                    u = r.get("url", "?")
                    method = r.get("method", "GET")
                    dedup_key = f"{method} {u}"
                    current_body = r.get("response_body", "") or ""

                    existing_body_len = best_entry.get(dedup_key, (None, 0))[1]
                    if current_body and len(current_body) > existing_body_len:
                        best_entry[dedup_key] = (r, len(current_body))

                parts.append("## Pages Visited")
                for r, _ in best_entry.values():
                    parts.append(f"  [{r.get('response_status', '?')}] {r.get('method', 'GET')} {r.get('url', '?')}")

                    for line in self._extract_request_fields(r.get("url", ""), r.get("postData")):
                        parts.append(line)

                    # Response headers (security-relevant only)
                    resp_h = r.get("response_headers", {})
                    shown_resp = {k: v for k, v in resp_h.items()
                                  if k.lower() in interesting_headers}
                    if shown_resp:
                        parts.append(f"    Response headers: {shown_resp}")
                    content_type = str(resp_h.get("content-type") or resp_h.get("Content-Type") or "")
                    if content_type:
                        parts.append(f"    Content-Type: {content_type}")
                    for line in self._extract_response_clues(
                        r.get("response_body") or "",
                        content_type,
                    ):
                        parts.append(line)

                    # Response body snippet. Crawler caps body; keep enough for forms/admin panels.
                    if r.get("response_body"):
                        parts.append(
                            f"    Body (captured, up to {CRAWL_DATA_BODY_LIMIT} chars):\n"
                            f"    ```\n{r['response_body'][:CRAWL_DATA_BODY_LIMIT]}\n    ```"
                        )
                parts.append("")

            # API requests
            api = [r for r in filtered if r.get("resource_type") in ("xhr", "fetch", "other")]
            if api:
                parts.append("## API/XHR Requests")
                for r in api:
                    parts.append(f"REQUEST: {r.get('method', '?')} {r.get('url', '?')}")
                    req_h = r.get("headers", {})
                    shown = {k: v for k, v in req_h.items() if k.lower() in interesting_headers}
                    if shown:
                        parts.append(f"  Headers: {shown}")
                    for line in self._extract_request_fields(r.get("url", ""), r.get("postData")):
                        parts.append(line.replace("    ", "  ", 1))
                    parts.append(f"RESPONSE: {r.get('response_status', '?')}")
                    resp_h = r.get("response_headers", {})
                    shown_resp = {k: v for k, v in resp_h.items() if k.lower() in interesting_headers}
                    if shown_resp:
                        parts.append(f"  Headers: {shown_resp}")
                    content_type = str(resp_h.get("content-type") or resp_h.get("Content-Type") or "")
                    if content_type:
                        parts.append(f"  Content-Type: {content_type}")
                    for line in self._extract_response_clues(
                        r.get("response_body") or "",
                        content_type,
                    ):
                        parts.append(line.replace("    ", "  ", 1))
                    if r.get("response_body"):
                        parts.append(
                            f"  Body (captured, up to {CRAWL_DATA_BODY_LIMIT} chars): "
                            f"{r['response_body'][:CRAWL_DATA_BODY_LIMIT]}"
                        )
                    parts.append("---")
                parts.append("")

            # Forms — now includes action URL and method more prominently
            forms = [r for r in traffic if r.get("resource_type") == "form"]
            if forms:
                parts.append("## Forms")
                for r in forms:
                    form_method = r.get("method", "?")
                    form_action = r.get("url", "?")
                    parent = r.get("parent_url", "?")
                    parts.append(f"  FORM: {form_method} {form_action}")
                    parts.append(f"    Found on page: {parent}")
                    if r.get("form_fields"):
                        parts.append(f"    Fields:")
                        for f in r["form_fields"]:
                            parts.append(f"      - {f.get('name', '?')} "
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

    def _tool_loop(
        self,
        messages: list[dict],
        *,
        max_rounds: int | None = None,
        allowed_tool_names: set[str] | None = None,
    ) -> str:
        """Run tool calls until LLM produces text with [DONE] tag.

        Simplified version of ExecutorAgent._tool_loop:
        - Only handles shell + fetch + filesystem tools
        - Max tool rounds are configurable per phase
        - [DONE] tag signals completion
        """
        active_tools = self.tools
        if allowed_tool_names is not None:
            active_tools = [
                tool for tool in self.tools
                if tool.get("function", {}).get("name") in allowed_tool_names
            ]

        round_limit = max_rounds or MAX_TOOL_ROUNDS
        consecutive_errors = 0
        tool_count = 0
        nudge_count = 0
        max_nudges = 3
        consecutive_repeats = 0
        last_tool_signature = None
        single_read_counts: dict[str, int] = {}

        for round_idx in range(round_limit):
            try:
                tool_choice = "required" if round_idx == 0 and active_tools else "auto"
                try:
                    response = self.client.chat.completions.create(
                        model=TOOLCALL_MODEL,
                        messages=messages,
                        tools=active_tools if active_tools else None,
                        tool_choice=tool_choice if active_tools else None,
                        temperature=0.3,
                        max_tokens=8192,
                    )
                except Exception as e:
                    error_text = str(e).lower()
                    if (
                        tool_choice == "required"
                        and active_tools
                        and ("tool_choice" in error_text or "tool use" in error_text)
                    ):
                        print(
                            f"{DIM}[CRAWL-AGENT] Provider rejected tool_choice=required; "
                            f"retrying with tool_choice=auto.{RESET}"
                        )
                        response = self.client.chat.completions.create(
                            model=TOOLCALL_MODEL,
                            messages=messages,
                            tools=active_tools,
                            tool_choice="auto",
                            temperature=0.3,
                            max_tokens=8192,
                        )
                    else:
                        raise
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

                    result_text = None
                    if allowed_tool_names is not None and fn_name not in allowed_tool_names:
                        result_text = (
                            f"[Blocked] Tool '{fn_name}' is not allowed in this phase. "
                            "Use read_text_file/write_file and finish recon.md."
                        )
                    elif fn_name == "read_text_file":
                        requested_path = str(fn_args.get("path", ""))
                        requested_name = os.path.basename(requested_path)
                        if requested_name in RECON_SINGLE_READ_FILES:
                            single_read_counts[requested_name] = single_read_counts.get(requested_name, 0) + 1
                            if single_read_counts[requested_name] > 1:
                                result_text = (
                                    f"[Blocked repeated read] {requested_name} was already read. "
                                    "Use the existing context, write recon.md now, and respond with [DONE]."
                                )

                    if result_text is None:
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
                if round_idx >= round_limit - 3:
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

        return f"[CrawlAgent reached {round_limit} tool rounds limit]\n[DONE]"


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
