"""
CrawlAgent — Standalone recon agent for MARL.

Crawls target website (anonymous + authenticated), collects HTTP traffic,
then uses LLM to analyze and write a structured recon.md report.

Usage:
    python agents/crawl_agent.py "https://target.com/"
    python agents/crawl_agent.py "https://target.com/ credentials: admin:password"
"""

import json
import hashlib
import os
import re
import sys
import subprocess
import threading
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
from shared.auth_context import (
    auth_context_path,
    bearer_token_from_session,
    cookie_header_from_cookie_objects,
    load_auth_context,
    normalize_cookie_objects,
    save_auth_context,
    storage_state_path,
    storage_state_has_material,
    upsert_auth_session,
)
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
DISCOVERY_CANDIDATE_LIMIT = 70
DISCOVERY_BODY_SNIPPET_LIMIT = 2000
DISCOVERY_TIMEOUT = 8
DISCOVERY_METHODS = ("GET", "OPTIONS")
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
STATIC_PATH_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".map", ".webp", ".mp4", ".pdf",
)
BAC_DISCOVERY_PATHS = (
    "/admin", "/admin/", "/admin/dashboard", "/admin/users", "/admin/orders",
    "/admin/products", "/admin/product", "/admin/settings", "/admin/manage",
    "/administrator", "/management", "/manage", "/dashboard", "/console",
    "/settings", "/users", "/user/list", "/accounts", "/roles",
    "/api/users", "/api/admin/users", "/api/admin", "/api/v1/users",
    "/api/v1/admin", "/api/v1/admin/users", "/internal/users",
    "/internal/admin", "/internal/admin/users",
)
BLF_DISCOVERY_PATHS = (
    "/cart", "/basket", "/checkout", "/orders", "/order", "/payment",
    "/payments", "/transfer", "/wallet", "/balance", "/coupon", "/coupons",
    "/discount", "/discounts", "/promo", "/promotions", "/invoice",
    "/invoices", "/api/cart", "/api/checkout", "/api/orders",
    "/api/payment", "/api/transfer", "/api/wallet", "/api/coupons",
    "/api/v1/cart", "/api/v1/checkout", "/api/v1/orders",
    "/api/v1/payment", "/api/v1/transfer", "/api/v1/wallet",
    "/api/v1/coupons",
)

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
        self._auth_fingerprint: list[dict] = []  # Auth endpoint probing results
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
        print(f"\n{YELLOW}{BOLD}══════════════════════════════════════════════════{RESET}")
        print(f"{YELLOW}{BOLD}[CRAWL-AGENT] Phase 1: ANONYMOUS CRAWL{RESET}")
        print(f"{YELLOW}{BOLD}══════════════════════════════════════════════════{RESET}")
        print(f"{DIM}[CRAWL-AGENT] Target: {url}{RESET}")
        print(f"{DIM}[CRAWL-AGENT] Mode: Unauthenticated — no cookies/tokens{RESET}")

        # Detect SPA targets → reduce page limit to avoid timeout
        is_spa, spa_framework = self._detect_spa(url)
        crawl_max_pages = 15 if is_spa else 50
        if is_spa:
            print(f"{YELLOW}[CRAWL-AGENT] SPA detected ({spa_framework}) — max_pages={crawl_max_pages}{RESET}")

        anon_data = self._run_crawler(url, max_pages=crawl_max_pages)

        # Fallback: if crawler returned no useful data (timeout/empty), try API discovery
        if not anon_data or not anon_data.get("http_traffic"):
            print(f"{YELLOW}[CRAWL-AGENT] Crawler trả về rỗng — thử API discovery fallback...{RESET}")
            fallback_data = self._api_discovery_fallback(url)
            if fallback_data and fallback_data.get("http_traffic"):
                print(f"{GREEN}[CRAWL-AGENT] API fallback: {len(fallback_data['http_traffic'])} requests{RESET}")
                anon_data = fallback_data
            elif not anon_data:
                # Retry crawler with very conservative settings
                print(f"{YELLOW}[CRAWL-AGENT] Retry crawler (max_pages=5, 1 round)...{RESET}")
                anon_data = self._run_crawler(url, max_pages=5, max_rounds=1, timeout=60)

        # ── Tóm tắt Anonymous crawl ──
        anon_request_count = len(anon_data.get("http_traffic", [])) if anon_data else 0
        anon_page_count = len(anon_data.get("pages", [])) if anon_data else 0
        print(f"\n{GREEN}[CRAWL-AGENT] ── Anonymous Crawl Summary ──{RESET}")
        print(f"{GREEN}[CRAWL-AGENT]   Requests captured: {anon_request_count}{RESET}")
        print(f"{GREEN}[CRAWL-AGENT]   Pages visited: {anon_page_count}{RESET}")
        if anon_data:
            anon_endpoints = set()
            for r in anon_data.get("http_traffic", []):
                if r.get("resource_type") in ("document", "xhr", "fetch"):
                    anon_endpoints.add(f"{r.get('method', '?')} {urlparse(r.get('url', '')).path}")
            print(f"{GREEN}[CRAWL-AGENT]   Unique endpoints: {len(anon_endpoints)}{RESET}")
            for ep in sorted(anon_endpoints)[:15]:
                print(f"{DIM}[CRAWL-AGENT]     {ep}{RESET}")

        # ── Phase 2+3: Loop qua từng account ──
        auth_sessions: list[dict] = []
        for idx, cred in enumerate(credentials_list):
            label = cred["label"]
            print(f"\n{YELLOW}{BOLD}══════════════════════════════════════════════════{RESET}")
            print(f"{YELLOW}{BOLD}[CRAWL-AGENT] Phase 2: LOGIN [{label}]{RESET}")
            print(f"{YELLOW}{BOLD}══════════════════════════════════════════════════{RESET}")
            print(f"{DIM}[CRAWL-AGENT] Credentials: {cred.get('username', '?')} / {'*' * len(cred.get('password', ''))}{RESET}")
            login_context = self._login_context(url, cred)
            login_cookies = login_context.get("cookies", []) if login_context else []

            if login_context:
                storage_state = login_context.get("storage_state_path") or ""
                auth_material_bits = []
                if login_cookies:
                    auth_material_bits.append(f"{len(login_cookies)} cookies")
                if storage_state:
                    auth_material_bits.append("Playwright storage_state")
                if login_context.get("bearer_token"):
                    auth_material_bits.append("bearer/localStorage token")
                material_note = ", ".join(auth_material_bits) if auth_material_bits else "auth context"
                auth_mechanism = login_context.get("login_discovery", {}).get("auth_mechanism", "unknown")
                print(f"{GREEN}[CRAWL-AGENT] Login [{label}] OK — {material_note}{RESET}")
                print(f"{GREEN}[CRAWL-AGENT]   Auth mechanism: {auth_mechanism}{RESET}")
                print(f"{GREEN}[CRAWL-AGENT]   Created by: {login_context.get('created_by', '?')}{RESET}")
                if login_context.get("bearer_token"):
                    token = login_context["bearer_token"]
                    print(f"{GREEN}[CRAWL-AGENT]   Bearer token: {token[:20]}...{token[-10:]}{RESET}")

                print(f"\n{YELLOW}{BOLD}══════════════════════════════════════════════════{RESET}")
                print(f"{YELLOW}{BOLD}[CRAWL-AGENT] Phase 3: AUTHENTICATED CRAWL [{label}]{RESET}")
                print(f"{YELLOW}{BOLD}══════════════════════════════════════════════════{RESET}")
                cookie_str = cookie_header_from_cookie_objects(login_cookies)
                _debug(f"[{label}] Injecting {len(login_cookies)} cookies: {cookie_str[:100]}...")
                data = self._run_crawler(
                    url,
                    cookie_header=cookie_str or None,
                    storage_state_path=storage_state or None,
                    max_pages=25,
                    max_rounds=1,
                    timeout=180,
                )
                if not data or not data.get("http_traffic"):
                    print(f"{YELLOW}[CRAWL-AGENT] Auth browser crawl [{label}] rỗng — thử authenticated API fallback...{RESET}")
                    data = self._api_discovery_fallback(url, auth_session=login_context, session_label=label)
                    if data and data.get("http_traffic"):
                        print(
                            f"{GREEN}[CRAWL-AGENT] Auth API fallback [{label}]: "
                            f"{len(data['http_traffic'])} requests{RESET}"
                        )

                if data:
                    auth_verified = self._auth_crawl_verified(anon_data, data) or bool(login_context.get("auth_verified"))
                    session_record = {
                        **login_context,
                        "label": label,
                        "cookies": login_cookies,
                        "data": data,
                        "auth_verified": auth_verified,
                    }
                    auth_sessions.append(session_record)
                    self._persist_auth_context(url, session_record)
                    _debug(f"[{label}] Auth crawl done: {len(data.get('http_traffic', []))} requests")

                    # ── Compare: authenticated vs anonymous ──
                    auth_request_count = len(data.get("http_traffic", []))
                    print(f"\n{GREEN}[CRAWL-AGENT] ── Authenticated Crawl Summary [{label}] ──{RESET}")
                    print(f"{GREEN}[CRAWL-AGENT]   Auth verified: {auth_verified}{RESET}")
                    print(f"{GREEN}[CRAWL-AGENT]   Requests captured: {auth_request_count}{RESET}")

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
                        print(f"{GREEN}[CRAWL-AGENT]   New endpoints (auth-only): {len(new_urls)}{RESET}")
                        for u in sorted(new_urls)[:10]:
                            print(f"{GREEN}[CRAWL-AGENT]     [AUTH-ONLY] {u}{RESET}")

                        if auth_verified:
                            print(f"{GREEN}[CRAWL-AGENT]   ✓ Authenticated session confirmed{RESET}")
                        elif new_urls:
                            print(f"{GREEN}[CRAWL-AGENT]   ✓ New URLs discovered — auth likely working{RESET}")
                        elif auth_urls == anon_urls:
                            print(f"{YELLOW}[CRAWL-AGENT]   ✗ WARNING: Identical URLs to anonymous — "
                                  f"auth may have failed{RESET}")
                        else:
                            print(f"{YELLOW}[CRAWL-AGENT]   Auth crawl [{label}]: "
                                  f"{len(auth_urls)} URLs (anon had {len(anon_urls)}){RESET}")
                else:
                    print(f"{YELLOW}[CRAWL-AGENT] Auth crawl [{label}] returned no data — preserving auth context anyway{RESET}")
                    session_record = {
                        **login_context,
                        "label": label,
                        "cookies": login_cookies,
                        "data": {"http_traffic": [], "cookies": login_cookies, "external_links": []},
                        "auth_verified": bool(login_context.get("auth_verified")),
                    }
                    auth_sessions.append(session_record)
                    self._persist_auth_context(url, session_record)
            else:
                print(f"{YELLOW}[CRAWL-AGENT] ✗ Login [{label}] FAILED — skipping authenticated crawl{RESET}")
                print(f"{YELLOW}[CRAWL-AGENT]   Pipeline will only have anonymous endpoints{RESET}")

        if not credentials_list:
            print(f"\n{DIM}[CRAWL-AGENT] Phase 2+3: No credentials, skipping login{RESET}")

        # ── Phase 4: Active discovery for BAC/BLF route candidates ──
        print(f"\n{YELLOW}{BOLD}══════════════════════════════════════════════════{RESET}")
        print(f"{YELLOW}{BOLD}[CRAWL-AGENT] Phase 4: BAC/BLF DISCOVERY PROBES{RESET}")
        print(f"{YELLOW}{BOLD}══════════════════════════════════════════════════{RESET}")
        discovery_data = self._run_bac_blf_discovery(url, anon_data, auth_sessions, focus)

        # ── Phase 5: Lưu crawl data đầy đủ ──
        self._save_crawl_data(url, anon_data, auth_sessions, focus, discovery_data)

        # ── Phase 6: Tóm tắt crawl data thành recon.md ──
        print(f"\n{YELLOW}{BOLD}[CRAWL-AGENT] Phase 6: Recon summary...{RESET}")
        recon_path = self._analyze(url, anon_data, auth_sessions, focus, discovery_data)
        print(f"\n{GREEN}[CRAWL-AGENT] Done — recon.md generated.{RESET}")

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

    # ─── Internal: bounded BAC/BLF active discovery ───────────────

    def _run_bac_blf_discovery(
        self,
        base_url: str,
        anon_data: dict | None,
        auth_sessions: list[dict],
        focus: str = "",
    ) -> dict:
        """Probe a bounded read-only candidate set for BAC/BLF-relevant routes.

        This phase is intentionally separate from normal crawl evidence:
        guessed paths are recorded as discovery probes with provenance and only
        promoted into raw endpoint evidence when the response indicates a real
        route instead of a generic homepage/404 fallback.
        """
        candidates = self._build_bac_blf_discovery_candidates(base_url, anon_data, auth_sessions, focus)
        contexts = self._build_discovery_contexts(auth_sessions)

        result = {
            "strategy": {
                "name": "bounded_read_only_bac_blf_discovery",
                "scope": "GET/OPTIONS only; no state-changing requests",
                "covers": ["BAC", "BLF"],
                "candidate_limit": DISCOVERY_CANDIDATE_LIMIT,
                "methods": list(DISCOVERY_METHODS),
                "notes": [
                    "Candidates are not endpoint evidence until probed.",
                    "Generic homepage/404/login fallbacks are not promoted.",
                    "Tampered contexts are only used with read-only methods.",
                ],
            },
            "candidates": candidates,
            "contexts": [
                {
                    "label": ctx["label"],
                    "type": ctx["type"],
                    "source_session": ctx.get("source_session", ""),
                    "tamper_notes": ctx.get("tamper_notes", []),
                }
                for ctx in contexts
            ],
            "probes": [],
            "summary": {},
        }

        if not candidates:
            result["summary"] = {"candidates": 0, "probes": 0, "route_exists": 0}
            print(f"{DIM}[CRAWL-AGENT] Discovery skipped: no candidates{RESET}")
            return result

        print(
            f"{DIM}[CRAWL-AGENT] Discovery strategy: read-only GET/OPTIONS, "
            f"{len(candidates)} candidates, {len(contexts)} context(s){RESET}"
        )

        probes: list[dict] = []
        progress_width = 150
        total = len(candidates) * len(contexts) * len(DISCOVERY_METHODS)
        done = 0

        try:
            with httpx.Client(timeout=DISCOVERY_TIMEOUT, follow_redirects=False, verify=False) as client:
                baselines = {
                    ctx["label"]: self._collect_discovery_baselines(client, base_url, ctx)
                    for ctx in contexts
                }

                for candidate in candidates:
                    path = candidate["path"]
                    full_url = urljoin(base_url, path)
                    for ctx in contexts:
                        for method in DISCOVERY_METHODS:
                            done += 1
                            progress = (
                                f"[DISCOVERY] {done}/{total} {method} {path} "
                                f"context={ctx['label']}"
                            )
                            if len(progress) > progress_width:
                                progress = progress[: progress_width - 3] + "..."
                            sys.__stdout__.write("\r" + f"{DIM}{progress.ljust(progress_width)}{RESET}")
                            sys.__stdout__.flush()

                            try:
                                headers = dict(ctx.get("headers") or {})
                                headers.setdefault("Accept", "text/html,application/json,*/*")
                                resp = client.request(method, full_url, headers=headers)
                                probe = self._build_discovery_probe_record(
                                    base_url=base_url,
                                    candidate=candidate,
                                    context=ctx,
                                    method=method,
                                    response=resp,
                                    baseline=baselines.get(ctx["label"], {}),
                                )
                                probes.append(probe)
                            except Exception as e:
                                probes.append({
                                    "method": method,
                                    "path": path,
                                    "url": full_url,
                                    "context": ctx["label"],
                                    "context_type": ctx["type"],
                                    "candidate_sources": candidate.get("sources", []),
                                    "candidate_reason": candidate.get("reason", ""),
                                    "error": str(e),
                                    "route_exists": False,
                                    "classification": "request_error",
                                    "bac_signals": [],
                                    "blf_signals": [],
                                })
        finally:
            sys.__stdout__.write("\r" + " " * (progress_width + 8) + "\r")
            sys.__stdout__.flush()

        route_exists_count = sum(1 for p in probes if p.get("route_exists"))
        sensitive_count = sum(1 for p in probes if p.get("bac_signals") or p.get("blf_signals"))
        interesting = [
            p for p in probes
            if p.get("route_exists") and (p.get("bac_signals") or p.get("blf_signals"))
        ]
        result["probes"] = probes
        result["summary"] = {
            "candidates": len(candidates),
            "contexts": len(contexts),
            "probes": len(probes),
            "route_exists": route_exists_count,
            "with_bac_or_blf_signals": sensitive_count,
            "promotable": len(interesting),
        }

        print(
            f"{GREEN}[CRAWL-AGENT] Discovery complete: {route_exists_count} route-like responses, "
            f"{sensitive_count} BAC/BLF signal(s){RESET}"
        )
        for probe in interesting[:10]:
            signals = ", ".join((probe.get("bac_signals") or []) + (probe.get("blf_signals") or []))
            print(
                f"{GREEN}[CRAWL-AGENT]   [DISCOVERED] {probe.get('method')} {probe.get('path')} "
                f"ctx={probe.get('context')} status={probe.get('status')} signals={signals}{RESET}"
            )
        return result

    def _build_bac_blf_discovery_candidates(
        self,
        base_url: str,
        anon_data: dict | None,
        auth_sessions: list[dict],
        focus: str = "",
    ) -> list[dict]:
        """Build bounded candidates from playbook seeds plus observed app clues."""
        base_host = urlparse(base_url).netloc
        observed_paths = self._observed_paths_from_crawl(anon_data, auth_sessions)
        candidates: dict[str, dict] = {}

        def add_candidate(path: str, source: str, reason: str) -> None:
            normalized = self._normalize_discovery_path(base_url, path)
            if not normalized:
                return
            parsed = urlparse(urljoin(base_url, normalized))
            if parsed.netloc and parsed.netloc != base_host:
                return
            if parsed.path in observed_paths and "observed" not in source:
                return
            if parsed.path.lower().endswith(STATIC_PATH_EXTENSIONS):
                return
            entry = candidates.setdefault(normalized, {
                "path": normalized,
                "sources": [],
                "reason": "",
            })
            if source not in entry["sources"]:
                entry["sources"].append(source)
            if reason and reason not in entry["reason"]:
                entry["reason"] = (entry["reason"] + "; " + reason).strip("; ")

        focus_lower = (focus or "").lower()
        seed_reason = "bounded playbook seed for BAC/admin forced-browsing discovery"
        for path in BAC_DISCOVERY_PATHS:
            add_candidate(path, "bac_seed", seed_reason)

        blf_reason = "bounded playbook seed for BLF workflow/state discovery"
        for path in BLF_DISCOVERY_PATHS:
            add_candidate(path, "blf_seed", blf_reason)

        if "bac" in focus_lower or "access" in focus_lower or "admin" in focus_lower:
            for path in BAC_DISCOVERY_PATHS:
                add_candidate(path, "focus_bac", "user focus mentions BAC/access/admin")
        if "blf" in focus_lower or "logic" in focus_lower or "business" in focus_lower:
            for path in BLF_DISCOVERY_PATHS:
                add_candidate(path, "focus_blf", "user focus mentions BLF/business logic")

        for path, source_url in self._extract_candidate_paths_from_crawl(base_url, anon_data, auth_sessions):
            add_candidate(path, "observed_link_or_script", f"path string observed in {source_url}")

        observed_text = self._combined_response_text(anon_data, auth_sessions).lower()
        if any(token in observed_text for token in ("admin", "isadmin", "is_admin", "role", "privilege")):
            for path in BAC_DISCOVERY_PATHS:
                add_candidate(path, "html_or_js_bac_signal", "admin/role keyword observed in crawled response")
        if any(token in observed_text for token in ("cart", "checkout", "coupon", "discount", "order", "payment", "transfer", "balance")):
            for path in BLF_DISCOVERY_PATHS:
                add_candidate(path, "html_or_js_blf_signal", "workflow/commerce keyword observed in crawled response")

        ranked = sorted(
            candidates.values(),
            key=lambda item: (
                0 if any(src.startswith("observed") for src in item["sources"]) else 1,
                0 if any(src.startswith("html_or_js") for src in item["sources"]) else 1,
                item["path"].count("/"),
                item["path"],
            ),
        )
        return ranked[:DISCOVERY_CANDIDATE_LIMIT]

    @staticmethod
    def _normalize_discovery_path(base_url: str, raw_path: str) -> str:
        text = str(raw_path or "").strip()
        if not text or text.startswith(("mailto:", "tel:", "javascript:", "#")):
            return ""
        text = unescape(text).strip("\"'")
        full = urljoin(base_url, text)
        parsed = urlparse(full)
        path = parsed.path or "/"
        if not path.startswith("/"):
            path = "/" + path
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return path

    @classmethod
    def _observed_paths_from_crawl(cls, anon_data: dict | None, auth_sessions: list[dict]) -> set[str]:
        paths: set[str] = set()

        def feed(data: dict | None) -> None:
            if not data:
                return
            for record in data.get("http_traffic", []) or []:
                url_str = record.get("url")
                if not url_str:
                    continue
                paths.add(urlparse(url_str).path or "/")

        feed(anon_data)
        for session in auth_sessions or []:
            feed(session.get("data"))
        return paths

    @classmethod
    def _combined_response_text(cls, anon_data: dict | None, auth_sessions: list[dict]) -> str:
        chunks: list[str] = []

        def feed(data: dict | None) -> None:
            if not data:
                return
            for record in data.get("http_traffic", []) or []:
                body = record.get("response_body")
                if body:
                    chunks.append(str(body)[:5000])

        feed(anon_data)
        for session in auth_sessions or []:
            feed(session.get("data"))
        return "\n".join(chunks)

    @classmethod
    def _extract_candidate_paths_from_crawl(
        cls,
        base_url: str,
        anon_data: dict | None,
        auth_sessions: list[dict],
    ) -> list[tuple[str, str]]:
        """Extract same-origin path strings from HTML/JS without calling them facts."""
        base_host = urlparse(base_url).netloc
        found: list[tuple[str, str]] = []
        seen: set[str] = set()
        attr_re = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
        js_path_re = re.compile(
            r"""["'](/(?:api|admin|manage|dashboard|orders?|cart|checkout|payment|transfer|wallet|coupon|discount|users?)[^"' <>)\\]*)["']""",
            re.IGNORECASE,
        )

        def feed(data: dict | None) -> None:
            if not data:
                return
            for record in data.get("http_traffic", []) or []:
                source_url = record.get("url") or base_url
                body = record.get("response_body") or ""
                if not body:
                    continue
                for match in list(attr_re.findall(body)) + list(js_path_re.findall(body)):
                    full = urljoin(source_url, match)
                    parsed = urlparse(full)
                    if parsed.netloc and parsed.netloc != base_host:
                        continue
                    path = parsed.path or "/"
                    if path.lower().endswith(STATIC_PATH_EXTENSIONS):
                        continue
                    if parsed.query:
                        path = f"{path}?{parsed.query}"
                    if path not in seen:
                        seen.add(path)
                        found.append((path, source_url))

        feed(anon_data)
        for session in auth_sessions or []:
            feed(session.get("data"))
        return found[:80]

    @classmethod
    def _build_discovery_contexts(cls, auth_sessions: list[dict]) -> list[dict]:
        contexts = [{
            "label": "anonymous",
            "type": "anonymous",
            "headers": {},
            "source_session": "",
            "tamper_notes": [],
        }]

        for session in (auth_sessions or [])[:2]:
            label = str(session.get("label", "auth") or "auth")
            cookies = session.get("cookies") or []
            token = session.get("bearer_token") or bearer_token_from_session(session)
            if token:
                contexts.append({
                    "label": f"auth:{label}:bearer",
                    "type": "authenticated_bearer",
                    "headers": {"Authorization": f"Bearer {token}"},
                    "source_session": label,
                    "tamper_notes": [],
                })

            cookie_header = cookie_header_from_cookie_objects(cookies)
            if cookie_header:
                contexts.append({
                    "label": f"auth:{label}",
                    "type": "authenticated",
                    "headers": {"Cookie": cookie_header},
                    "source_session": label,
                    "tamper_notes": [],
                })

            tampered, notes = cls._tamper_identity_cookies(cookies)
            tampered_header = cookie_header_from_cookie_objects(tampered)
            if tampered_header and notes and tampered_header != cookie_header:
                contexts.append({
                    "label": f"tampered:{label}",
                    "type": "tampered_identity_cookie",
                    "headers": {"Cookie": tampered_header},
                    "source_session": label,
                    "tamper_notes": notes,
                })

        return contexts

    @staticmethod
    def _tamper_identity_cookies(cookies: list[dict]) -> tuple[list[dict], list[str]]:
        tampered: list[dict] = []
        notes: list[str] = []
        for cookie in cookies or []:
            if not isinstance(cookie, dict):
                continue
            c = dict(cookie)
            name = str(c.get("name", "") or "")
            value = str(c.get("value", "") or "")
            lower = name.lower()
            new_value = value
            if lower in {"role", "roles", "privilege", "permission"} and value.lower() not in {"admin", "administrator"}:
                new_value = "admin"
            elif lower in {"is_admin", "isadmin", "admin"} and value.lower() not in {"1", "true", "yes"}:
                new_value = "true"
            elif lower in {"user_id", "userid", "uid", "account_id", "accountid"} and value.isdigit() and value != "1":
                new_value = "1"

            if new_value != value:
                c["value"] = new_value
                notes.append(f"{name}={value} -> {new_value}")
            tampered.append(c)
        return tampered, notes

    @staticmethod
    def _response_signature(text: str) -> str:
        normalized = re.sub(r"\s+", " ", CrawlAgent._clean_html_text(text or "").lower()).strip()
        return hashlib.sha256(normalized[:1200].encode("utf-8", "ignore")).hexdigest()

    def _collect_discovery_baselines(
        self,
        client: httpx.Client,
        base_url: str,
        context: dict,
    ) -> dict:
        headers = dict(context.get("headers") or {})
        headers.setdefault("Accept", "text/html,application/json,*/*")
        baselines: dict[str, dict] = {}
        baseline_paths = {
            "home": "/",
            "missing": "/__marl_missing_probe_404__",
        }
        for name, path in baseline_paths.items():
            try:
                resp = client.get(urljoin(base_url, path), headers=headers)
                baselines[name] = {
                    "status": resp.status_code,
                    "location": resp.headers.get("location", ""),
                    "signature": self._response_signature(resp.text),
                    "content_type": resp.headers.get("content-type", ""),
                }
            except Exception:
                baselines[name] = {}
        return baselines

    def _build_discovery_probe_record(
        self,
        base_url: str,
        candidate: dict,
        context: dict,
        method: str,
        response: httpx.Response,
        baseline: dict,
    ) -> dict:
        path = candidate["path"]
        text = response.text or ""
        content_type = response.headers.get("content-type", "")
        signature = self._response_signature(text)
        status = response.status_code
        location = response.headers.get("location", "")

        classification, route_exists = self._classify_discovery_response(
            method=method,
            status=status,
            location=location,
            signature=signature,
            content_type=content_type,
            body=text,
            baseline=baseline,
        )
        bac_signals, blf_signals = self._extract_probe_security_signals(path, text, content_type)

        return {
            "method": method,
            "path": path,
            "url": str(response.request.url),
            "context": context["label"],
            "context_type": context["type"],
            "source_session": context.get("source_session", ""),
            "tamper_notes": context.get("tamper_notes", []),
            "candidate_sources": candidate.get("sources", []),
            "candidate_reason": candidate.get("reason", ""),
            "status": status,
            "redirect_location": location,
            "content_type": content_type,
            "classification": classification,
            "route_exists": route_exists,
            "bac_signals": bac_signals,
            "blf_signals": blf_signals,
            "response": {
                "headers": {
                    k: v for k, v in response.headers.items()
                    if k.lower() in ("content-type", "location", "set-cookie", "www-authenticate", "allow")
                },
                "body_snippet": text[:DISCOVERY_BODY_SNIPPET_LIMIT],
                "body_size": len(text),
                "body_signature": signature,
            },
            "request": {
                "headers": {
                    k: v for k, v in (context.get("headers") or {}).items()
                    if k.lower() in ("cookie", "authorization")
                },
                "body": None,
            },
        }

    @staticmethod
    def _classify_discovery_response(
        method: str,
        status: int,
        location: str,
        signature: str,
        content_type: str,
        body: str,
        baseline: dict,
    ) -> tuple[str, bool]:
        method = str(method or "GET").upper()
        lower_body = (body or "").lower()
        home_sig = (baseline.get("home") or {}).get("signature", "")
        missing = baseline.get("missing") or {}
        missing_sig = missing.get("signature", "")
        missing_status = missing.get("status")
        missing_location = missing.get("location", "")

        if method == "OPTIONS":
            if status in {401, 403, 405}:
                return "options_protected_or_method_limited_signal", False
            return "options_preflight_signal", False
        if status == 404:
            return "not_found", False
        if status >= 500 and "unexpected path:" in lower_body:
            return "framework_unexpected_path_fallback", False
        if missing_status and status == missing_status and signature and signature == missing_sig:
            return "same_as_missing_baseline", False
        if status in {301, 302, 303, 307, 308}:
            loc_lower = (location or "").lower()
            if missing_status == status and location == missing_location:
                return "same_redirect_as_missing_baseline", False
            if any(token in loc_lower for token in ("login", "signin", "auth")):
                return "auth_redirect_route_candidate", True
            return "redirect_route_candidate", True
        if status in {401, 403, 405}:
            return "protected_or_method_limited_route", True
        if status >= 500:
            return "server_error_signal", False
        if 200 <= status < 300:
            if signature and home_sig and signature == home_sig and "json" not in content_type.lower():
                return "generic_homepage_fallback", False
            return "live_response", True
        return "other_response", False

    @staticmethod
    def _extract_probe_security_signals(
        path: str,
        body: str,
        content_type: str,
    ) -> tuple[list[str], list[str]]:
        text = f"{path}\n{body[:5000]}".lower()
        bac_signals: list[str] = []
        blf_signals: list[str] = []

        def add(target: list[str], value: str) -> None:
            if value not in target:
                target.append(value)

        if any(token in text for token in ("admin", "administrator", "management", "privilege", "role", "is_admin")):
            add(bac_signals, "admin_or_role_surface")
        if any(token in text for token in ("users", "user list", "email", "role")) and any(token in text for token in ("admin", "user_id", "id")):
            add(bac_signals, "user_or_role_data_surface")
        if "json" in content_type.lower() and any(token in text for token in ("email", "role", "password", "token", "user_id")):
            add(bac_signals, "sensitive_json_identity_fields")
        if any(token in text for token in ("profile", "account", "user_id", "account_id")):
            add(bac_signals, "account_or_object_reference_surface")

        if any(token in text for token in ("cart", "basket", "checkout", "quantity", "coupon", "discount")):
            add(blf_signals, "cart_checkout_or_discount_surface")
        if any(token in text for token in ("order", "invoice", "payment", "transfer", "wallet", "balance", "amount", "price")):
            add(blf_signals, "order_payment_or_value_surface")
        if any(token in text for token in ("stock", "inventory", "shipping", "status", "cancel", "refund")):
            add(blf_signals, "workflow_state_surface")

        return bac_signals, blf_signals

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

    def rebuild_recon_from_saved_artifacts(self, user_prompt: str) -> str:
        """Regenerate recon.md from existing crawl_data.txt/crawl_raw.json without re-crawling."""
        parsed = parse_prompt_llm(user_prompt, self.client)
        url = parsed["url"]
        focus = parsed.get("focus", "")

        raw_crawl_path = os.path.join(self.working_dir, "crawl_raw.json")
        anon_data = None
        auth_sessions: list[dict] = []
        discovery_data: dict | None = None
        if os.path.isfile(raw_crawl_path):
            try:
                raw_payload = json.loads(Path(raw_crawl_path).read_text(encoding="utf-8"))
                anon_data = raw_payload.get("anonymous")
                auth_sessions = raw_payload.get("authenticated", []) or []
                discovery_data = raw_payload.get("discovery_probes") or None
            except Exception as e:
                print(f"{YELLOW}[CRAWL-AGENT] Could not parse saved crawl_raw.json: {e}{RESET}")

        return self._analyze(url, anon_data, auth_sessions, focus, discovery_data)

    # ─── Internal: Run crawler CLI ───────────────────────────────

    def _run_crawler(
        self,
        url: str,
        cookie_header: str | None = None,
        storage_state_path: str | None = None,
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
        if storage_state_path:
            cmd.extend(["--storage-state", storage_state_path])

        _debug(f"Full crawler command: {' '.join(cmd)}")
        if cookie_header:
            _debug(f"Cookie header: {cookie_header[:80]}...")
        if storage_state_path:
            _debug(f"Storage state path: {storage_state_path}")
        print(f"{DIM}[CRAWL-AGENT] Running: {' '.join(cmd[:6])}...{RESET}")

        progress_width = 140
        progress_active = False

        def _terminal_progress(line: str) -> None:
            nonlocal progress_active
            clean = line.replace("[CRAWLER-PROGRESS]", "Crawling").strip()
            if len(clean) > progress_width:
                clean = clean[: progress_width - 3] + "..."
            sys.__stdout__.write("\r" + f"{DIM}  {clean.ljust(progress_width)}{RESET}")
            sys.__stdout__.flush()
            progress_active = True

        def _clear_terminal_progress() -> None:
            nonlocal progress_active
            if not progress_active:
                return
            sys.__stdout__.write("\r" + " " * (progress_width + 8) + "\r")
            sys.__stdout__.flush()
            progress_active = False

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=_PROJECT_ROOT,
                bufsize=1,
            )

            stdout_chunks: list[str] = []

            def _read_stdout() -> None:
                if proc.stdout is None:
                    return
                for chunk in iter(lambda: proc.stdout.read(8192), ""):
                    if not chunk:
                        break
                    stdout_chunks.append(chunk)

            def _read_stderr() -> None:
                if proc.stderr is None:
                    return
                buf = ""
                for ch in iter(lambda: proc.stderr.read(1), ""):
                    if ch == "\r":
                        line = buf.strip()
                        buf = ""
                        if line:
                            if line.startswith("[CRAWLER-PROGRESS]"):
                                _terminal_progress(line)
                            else:
                                _clear_terminal_progress()
                                print(f"{DIM}  {line}{RESET}")
                    elif ch == "\n":
                        line = buf.strip()
                        buf = ""
                        if not line:
                            continue
                        if line.startswith("[CRAWLER-PROGRESS]"):
                            _terminal_progress(line)
                        else:
                            _clear_terminal_progress()
                            print(f"{DIM}  {line}{RESET}")
                    else:
                        buf += ch
                line = buf.strip()
                if line:
                    if line.startswith("[CRAWLER-PROGRESS]"):
                        _terminal_progress(line)
                    else:
                        _clear_terminal_progress()
                        print(f"{DIM}  {line}{RESET}")

            stdout_thread = threading.Thread(target=_read_stdout, daemon=True)
            stderr_thread = threading.Thread(target=_read_stderr, daemon=True)
            stdout_thread.start()
            stderr_thread.start()

            try:
                proc.wait(timeout=timeout + 30)  # extra buffer over crawler timeout
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
                _clear_terminal_progress()
                print(f"{RED}[CRAWL-AGENT] Crawler timed out after {timeout + 30}s{RESET}")
                return None

            stdout_thread.join(timeout=5)
            stderr_thread.join(timeout=5)
            _clear_terminal_progress()

            if proc.returncode != 0:
                print(f"{YELLOW}[CRAWL-AGENT] Crawler exited with code {proc.returncode}{RESET}")

            # Parse JSON stdout
            stdout_text = "".join(stdout_chunks)
            if stdout_text.strip():
                data = json.loads(stdout_text)
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

        except json.JSONDecodeError as e:
            _clear_terminal_progress()
            print(f"{RED}[CRAWL-AGENT] Failed to parse crawler JSON: {e}{RESET}")
            return None
        except Exception as e:
            _clear_terminal_progress()
            print(f"{RED}[CRAWL-AGENT] Crawler error: {e}{RESET}")
            return None

    # ─── Internal: SPA detection ─────────────────────────────────

    @staticmethod
    def _detect_spa(url: str) -> tuple[bool, str]:
        """Detect if target is a Single Page Application (Angular/React/Vue).

        Returns:
            (is_spa, framework_name)
        """
        try:
            resp = httpx.get(url, timeout=10, follow_redirects=True, verify=False)
            html = resp.text.lower()

            # Angular
            if "<app-root" in html or "ng-version" in html:
                return True, "Angular"
            # React
            if '<div id="root"' in html or '<div id="app"' in html or "_reactroot" in html:
                return True, "React"
            # Vue
            if '<div id="app"' in html and ("vue" in html or "v-cloak" in html):
                return True, "Vue"
            # Generic SPA detection: very little text content, lots of JS
            script_count = html.count("<script")
            text_len = len(resp.text.replace(" ", "").replace("\n", ""))
            if script_count >= 5 and "<body" in html:
                body_start = html.find("<body")
                body_end = html.find("</body>")
                if body_start >= 0 and body_end > body_start:
                    body_content = html[body_start:body_end]
                    # SPA bodies are mostly empty (just a root div + scripts)
                    non_script = re.sub(r"<script[^>]*>[\s\S]*?</script>", "", body_content)
                    non_script = re.sub(r"<[^>]+>", "", non_script).strip()
                    if len(non_script) < 200:
                        return True, "Generic SPA"

            return False, ""
        except Exception:
            return False, ""

    # ─── Internal: API discovery fallback ─────────────────────────

    def _api_discovery_fallback(
        self,
        url: str,
        auth_session: dict | None = None,
        session_label: str = "anonymous",
    ) -> dict | None:
        """Probe common REST API patterns when browser crawler fails.

        This is a lightweight HTTP-only fallback for SPA targets where the
        browser crawler times out or returns no useful data.
        """
        # Common API prefixes to probe
        api_prefixes = ["/api/", "/rest/", "/api/v1/", "/api/v2/"]
        # Common REST endpoints
        common_endpoints = [
            # User/Auth
            "users", "Users", "user", "accounts", "login", "register",
            "profile", "me",
            # Products/Commerce
            "products", "Products", "items", "orders", "Orders",
            "cart", "basket", "Baskets",
            # Admin
            "admin", "config", "configuration", "settings",
            # Common patterns
            "categories", "reviews", "feedback", "Feedbacks",
            "complaints", "Complaints",
            "recycles", "Recycles",
            "SecurityQuestions", "SecurityAnswers",
            "Challenges", "Quantitys",
        ]
        # REST-style search/action endpoints
        rest_endpoints = [
            "products/search?q=",
            "admin/application-version",
            "admin/application-configuration",
            "languages",
            "captcha",
        ]

        traffic = []
        discovered_urls = set()

        auth_headers: dict[str, str] = {}
        if auth_session:
            token = auth_session.get("bearer_token") or bearer_token_from_session(auth_session)
            if token:
                auth_headers["Authorization"] = f"Bearer {token}"
            cookie_header = auth_session.get("cookie_header") or cookie_header_from_cookie_objects(auth_session.get("cookies") or [])
            if cookie_header:
                auth_headers["Cookie"] = cookie_header

        try:
            with httpx.Client(timeout=8, follow_redirects=True, verify=False) as client:
                # 1. First check homepage for embedded API hints
                try:
                    home_resp = client.get(url, headers=auth_headers or None)
                    home_body = home_resp.text

                    # Extract API URLs from JavaScript source
                    api_patterns = re.findall(
                        r'["\'](/(?:api|rest)/[^"\'>\s]+)["\']',
                        home_body, re.IGNORECASE,
                    )
                    for path in api_patterns[:20]:
                        full_url = urljoin(url, path)
                        if full_url not in discovered_urls:
                            discovered_urls.add(full_url)
                except Exception:
                    pass

                # 2. Probe common API prefixes + endpoints
                for prefix in api_prefixes:
                    for endpoint in common_endpoints:
                        probe_url = urljoin(url, f"{prefix}{endpoint}")
                        if probe_url in discovered_urls:
                            continue
                        discovered_urls.add(probe_url)

                # 3. Probe REST-style endpoints
                for endpoint in rest_endpoints:
                    for prefix in ["/rest/", "/api/"]:
                        probe_url = urljoin(url, f"{prefix}{endpoint}")
                        if probe_url not in discovered_urls:
                            discovered_urls.add(probe_url)

                # 4. Actually probe each URL
                mode_note = f" [{session_label}]" if session_label != "anonymous" else ""
                print(f"{DIM}[CRAWL-AGENT] API fallback{mode_note}: probing {len(discovered_urls)} endpoints...{RESET}")
                for probe_url in sorted(discovered_urls):
                    try:
                        resp = client.get(probe_url, headers=auth_headers or None)
                        content_type = resp.headers.get("content-type", "")
                        body = None
                        if resp.status_code < 500:
                            body = resp.text[:12000] if resp.text else None

                        traffic.append({
                            "method": "GET",
                            "url": str(resp.url),
                            "headers": dict(resp.request.headers),
                            "postData": None,
                            "response_status": resp.status_code,
                            "response_headers": dict(resp.headers),
                            "resource_type": "xhr" if "json" in content_type else "document",
                            "response_body": body,
                            "parent_url": url,
                            "form_fields": None,
                        })
                    except Exception:
                        pass

                # Extract cookies
                cookies = []
                domain = urlparse(url).netloc
                for cookie in client.cookies.jar:
                    cookies.append({
                        "name": cookie.name,
                        "value": cookie.value,
                        "domain": domain,
                        "path": cookie.path or "/",
                    })

        except Exception as e:
            print(f"{YELLOW}[CRAWL-AGENT] API fallback error: {e}{RESET}")
            return None

        if not traffic:
            return None

        # Filter out 404s — only keep endpoints that actually exist
        useful_traffic = [t for t in traffic if t.get("response_status") and t["response_status"] < 404]
        mode_note = f" [{session_label}]" if session_label != "anonymous" else ""
        print(f"{GREEN}[CRAWL-AGENT] API fallback{mode_note}: {len(useful_traffic)} live endpoints found "
              f"(out of {len(traffic)} probed){RESET}")

        # ── Auth endpoint probing: fingerprint login/register mechanisms ──
        if not auth_session:
            auth_fingerprint = self._probe_auth_endpoints(url, useful_traffic)
            if auth_fingerprint:
                self._auth_fingerprint = auth_fingerprint
                print(f"{GREEN}[CRAWL-AGENT] Auth fingerprint: {len(auth_fingerprint)} auth endpoint(s) probed{RESET}")

        return {
            "http_traffic": useful_traffic,
            "cookies": cookies,
            "external_links": [],
        }

    def _probe_auth_endpoints(self, base_url: str, traffic: list[dict]) -> list[dict]:
        """Actively probe auth-related endpoints to fingerprint login/register mechanisms.

        For each login/register/auth endpoint found, send test POST requests with
        dummy JSON/form payloads and record raw request/response to understand:
        - Correct endpoint path and method
        - Required Content-Type (JSON vs form)
        - Expected body fields (email vs username)
        - Response structure (JWT token location, Set-Cookie, error format)

        Returns list of auth fingerprint dicts.
        """
        # Identify auth-related endpoints from traffic
        auth_keywords = re.compile(
            r"(?:login|signin|sign-in|auth|session|register|signup|sign-up|token|user/login)",
            re.IGNORECASE,
        )
        auth_urls: list[str] = []
        for entry in traffic:
            ep_url = entry.get("url", "")
            if auth_keywords.search(ep_url):
                if ep_url not in auth_urls:
                    auth_urls.append(ep_url)

        # Also probe common REST login paths that may not have been in GET traffic
        common_auth_paths = [
            "/rest/user/login", "/api/Users/login", "/api/login",
            "/api/auth/login", "/api/auth/signin", "/auth/login",
            "/rest/user/register", "/api/Users",
        ]
        for path in common_auth_paths:
            full = urljoin(base_url, path)
            if full not in auth_urls:
                auth_urls.append(full)

        if not auth_urls:
            return []

        fingerprints: list[dict] = []
        dummy_email = "probe-test@example.com"
        dummy_password = "ProbeTest123!"

        # Body variants to try for each endpoint
        body_variants = [
            ("json_email", "application/json", {"email": dummy_email, "password": dummy_password}),
            ("json_username", "application/json", {"username": dummy_email, "password": dummy_password}),
            ("form_email", "application/x-www-form-urlencoded", {"email": dummy_email, "password": dummy_password}),
        ]

        try:
            with httpx.Client(timeout=8, follow_redirects=True, verify=False) as client:
                for probe_url in auth_urls[:12]:  # Limit to 12 endpoints
                    fp: dict = {
                        "url": probe_url,
                        "path": urlparse(probe_url).path,
                        "is_login": bool(re.search(r"login|signin|auth|session|token", probe_url, re.I)),
                        "is_register": bool(re.search(r"register|signup|sign-up", probe_url, re.I)),
                        "probes": [],
                    }

                    for variant_name, content_type, body in body_variants:
                        try:
                            if "json" in content_type:
                                resp = client.post(
                                    probe_url,
                                    json=body,
                                    headers={"Content-Type": content_type, "Accept": "application/json"},
                                )
                            else:
                                resp = client.post(
                                    probe_url,
                                    data=body,
                                    headers={"Accept": "application/json"},
                                )

                            resp_body = resp.text[:2000] if resp.text else ""

                            # Analyze response for auth clues
                            has_token = False
                            token_location = ""
                            try:
                                resp_json = resp.json() if resp_body.strip().startswith("{") else {}
                                if isinstance(resp_json, dict):
                                    # Check common token locations
                                    if resp_json.get("authentication", {}).get("token"):
                                        has_token = True
                                        token_location = "body.authentication.token"
                                    elif resp_json.get("token"):
                                        has_token = True
                                        token_location = "body.token"
                                    elif resp_json.get("access_token"):
                                        has_token = True
                                        token_location = "body.access_token"
                            except Exception:
                                resp_json = {}

                            has_set_cookie = bool(resp.headers.get("set-cookie"))

                            probe_result = {
                                "variant": variant_name,
                                "content_type": content_type,
                                "body_fields": list(body.keys()),
                                "status": resp.status_code,
                                "response_content_type": resp.headers.get("content-type", ""),
                                "response_body_preview": resp_body[:500],
                                "has_token_in_body": has_token,
                                "token_location": token_location,
                                "has_set_cookie": has_set_cookie,
                                "set_cookie_header": resp.headers.get("set-cookie", "")[:200],
                                "raw_request": f"POST {probe_url}\nContent-Type: {content_type}\nBody: {json.dumps(body)}",
                                "raw_response": f"HTTP {resp.status_code}\nContent-Type: {resp.headers.get('content-type', '')}\n\n{resp_body[:500]}",
                            }
                            fp["probes"].append(probe_result)

                            # If we got a meaningful response (not 404/405), mark endpoint as accepting POST
                            if resp.status_code not in (404, 405, 501):
                                fp["accepts_post"] = True
                                fp[f"status_{variant_name}"] = resp.status_code

                        except Exception as e:
                            _debug(f"Auth probe {variant_name} on {probe_url} failed: {e}")
                            continue

                    # Determine best auth approach for this endpoint
                    if fp.get("probes"):
                        # Find the probe that got the most useful response
                        best = None
                        for p in fp["probes"]:
                            if p["has_token_in_body"]:
                                best = p
                                break
                            if p["has_set_cookie"] and p["status"] in (200, 201, 401):
                                best = p
                            elif not best and p["status"] not in (404, 405, 501):
                                best = p
                        if best:
                            fp["recommended_content_type"] = best["content_type"]
                            fp["recommended_body_fields"] = best["body_fields"]
                            fp["token_location"] = best.get("token_location", "")
                            fp["auth_mechanism"] = (
                                "jwt_bearer" if best["has_token_in_body"]
                                else "cookie_session" if best["has_set_cookie"]
                                else "unknown"
                            )

                    fingerprints.append(fp)

        except Exception as e:
            print(f"{YELLOW}[CRAWL-AGENT] Auth probing error: {e}{RESET}")

        return fingerprints

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

    # ─── Internal: Login context orchestration ───────────────────────

    def _login_context(self, target_url: str, credentials: dict) -> dict | None:
        """Create a reusable auth context using REST API first, then HTTP form, then Playwright."""
        label = credentials.get("label") or credentials.get("username") or "authenticated"
        username = credentials.get("username", "")
        password = credentials.get("password", "")

        # ── Step 0: Try REST API (JWT) login first using auth fingerprint ──
        api_session = self._login_rest_api(target_url, credentials)
        if api_session:
            api_session["label"] = label
            self._persist_auth_context(target_url, api_session)
            return api_session

        # ── Step 1: HTML form login ──
        http_cookies = self._login(target_url, credentials)
        if http_cookies:
            session = {
                "label": label,
                "username": credentials.get("username", ""),
                "created_by": "crawl_httpx",
                "auth_verified": False,
                "cookies": normalize_cookie_objects(http_cookies, target_url),
                "cookie_header": cookie_header_from_cookie_objects(http_cookies),
                "storage_state_path": "",
                "storage_state": {},
                "bearer_token": "",
                "verified_url": "",
                "notes": "HTTP form login returned auth material; auth crawl will verify response difference.",
            }
            self._persist_auth_context(target_url, session)
            return session

        print(f"{YELLOW}[LOGIN] HTTP login did not produce reusable cookies — trying Playwright login{RESET}")
        browser_session = self._login_playwright(target_url, credentials)
        if browser_session:
            self._persist_auth_context(target_url, browser_session)
            return browser_session
        return None

    def _login_rest_api(self, target_url: str, credentials: dict) -> dict | None:
        """Try REST API login endpoints (JSON POST) to get JWT/cookie session.

        Uses auth fingerprint from _probe_auth_endpoints if available,
        otherwise tries common REST login patterns.
        """
        username = credentials.get("username", "")
        password = credentials.get("password", "")
        label = credentials.get("label") or username or "authenticated"
        if not username or not password:
            return None

        domain = urlparse(target_url).netloc

        # Build candidate list: fingerprinted endpoints first, then common paths
        candidates: list[tuple[str, str, dict]] = []

        # Prioritize fingerprinted login endpoints
        for fp in getattr(self, "_auth_fingerprint", []):
            if not fp.get("is_login"):
                continue
            ep_url = fp["url"]
            ct = fp.get("recommended_content_type", "application/json")
            fields = fp.get("recommended_body_fields", ["email", "password"])
            body: dict = {"password": password}
            if "email" in fields:
                body["email"] = username
            else:
                body["username"] = username
            candidates.append((ep_url, ct, body))

        # Fallback: common REST login paths
        common_logins = [
            ("/rest/user/login", {"email": username, "password": password}),
            ("/api/Users/login", {"email": username, "password": password}),
            ("/api/login", {"email": username, "password": password}),
            ("/api/login", {"username": username, "password": password}),
            ("/api/auth/login", {"email": username, "password": password}),
            ("/api/auth/login", {"username": username, "password": password}),
            ("/auth/login", {"email": username, "password": password}),
        ]
        for path, body in common_logins:
            full_url = urljoin(target_url, path)
            # Don't duplicate fingerprinted entries
            if not any(c[0] == full_url and c[2] == body for c in candidates):
                candidates.append((full_url, "application/json", body))

        if not candidates:
            return None

        print(f"{DIM}[LOGIN] Trying {len(candidates)} REST API login endpoints...{RESET}")

        try:
            with httpx.Client(timeout=12, follow_redirects=True, verify=False) as client:
                for login_url, content_type, body in candidates:
                    try:
                        _debug(f"[REST LOGIN] POST {login_url} ct={content_type} fields={list(body.keys())}")
                        if "json" in content_type:
                            resp = client.post(
                                login_url,
                                json=body,
                                headers={"Content-Type": content_type, "Accept": "application/json"},
                            )
                        else:
                            resp = client.post(login_url, data=body)

                        _debug(f"[REST LOGIN] → status={resp.status_code}")

                        if resp.status_code not in (200, 201):
                            continue

                        # Try to extract JWT token from response body
                        token = ""
                        token_location = ""
                        try:
                            data = resp.json()
                            if isinstance(data, dict):
                                # Juice Shop style: {"authentication": {"token": "..."}}
                                auth_obj = data.get("authentication")
                                if isinstance(auth_obj, dict) and auth_obj.get("token"):
                                    token = str(auth_obj["token"])
                                    token_location = "body.authentication.token"
                                # Generic: {"token": "..."}
                                elif data.get("token"):
                                    token = str(data["token"])
                                    token_location = "body.token"
                                # OAuth style: {"access_token": "..."}
                                elif data.get("access_token"):
                                    token = str(data["access_token"])
                                    token_location = "body.access_token"
                        except Exception:
                            pass

                        # Extract cookies
                        cookies = []
                        for cookie in client.cookies.jar:
                            cookies.append({
                                "name": cookie.name,
                                "value": cookie.value,
                                "domain": domain,
                                "path": cookie.path or "/",
                            })

                        has_set_cookie = bool(resp.headers.get("set-cookie"))

                        if token or has_set_cookie or cookies:
                            auth_mechanism = "jwt_bearer" if token else "cookie_session"
                            print(f"{GREEN}[LOGIN] REST API login SUCCESS — {login_url} "
                                  f"(mechanism={auth_mechanism}, token={'yes' if token else 'no'}, "
                                  f"cookies={len(cookies)}){RESET}")

                            # Save login discovery info for downstream agents
                            login_discovery = {
                                "login_endpoint": urlparse(login_url).path,
                                "login_method": "POST",
                                "login_content_type": content_type,
                                "login_body_fields": list(body.keys()),
                                "auth_mechanism": auth_mechanism,
                                "token_location": token_location,
                            }
                            # Write login discovery to auth_fingerprint
                            self._auth_fingerprint.insert(0, {
                                **login_discovery,
                                "url": login_url,
                                "path": urlparse(login_url).path,
                                "is_login": True,
                                "login_success": True,
                            })

                            session = {
                                "label": label,
                                "username": username,
                                "created_by": "crawl_rest_api",
                                "auth_verified": True,
                                "cookies": normalize_cookie_objects(cookies, target_url),
                                "cookie_header": cookie_header_from_cookie_objects(cookies),
                                "storage_state_path": "",
                                "storage_state": {},
                                "bearer_token": token,
                                "verified_url": login_url,
                                "notes": (
                                    f"REST API login via {login_url}. "
                                    f"Mechanism: {auth_mechanism}. "
                                    f"Token location: {token_location or 'N/A'}. "
                                    f"Body fields: {list(body.keys())}."
                                ),
                                "login_discovery": login_discovery,
                            }
                            return session

                    except Exception as e:
                        _debug(f"[REST LOGIN] POST {login_url} error: {e}")
                        continue

        except Exception as e:
            print(f"{YELLOW}[LOGIN] REST API login error: {e}{RESET}")

        # ── Fallback: auto-register then retry login ──
        if not getattr(self, "_auto_register_attempted", False):
            self._auto_register_attempted = True
            print(f"{YELLOW}[LOGIN] REST login failed — trying auto-register then retry...{RESET}")
            registered = self._auto_register(target_url, credentials)
            if registered:
                print(f"{GREEN}[LOGIN] Auto-register succeeded — retrying REST login...{RESET}")
                return self._login_rest_api(target_url, registered.get("credentials", credentials))
            else:
                print(f"{YELLOW}[LOGIN] Auto-register also failed{RESET}")

        _debug("[REST LOGIN] No REST API login succeeded")
        return None

    def _auto_register(self, target_url: str, credentials: dict) -> dict | None:
        """Auto-register account on target when REST login fails (e.g. account doesn't exist).

        Tries common registration endpoints with the given credentials.
        Returns dict with 'credentials' key on success, None on failure.
        """
        username = credentials.get("username", "")
        password = credentials.get("password", "")
        if not username or not password:
            return None

        register_endpoints = [
            "/api/Users",
            "/rest/user/register",
            "/api/register",
            "/register",
            "/api/auth/register",
            "/api/signup",
            "/signup",
        ]

        # Build body variants: email-based and username-based
        body_variants = [
            {"email": username, "password": password},
            {"username": username, "password": password},
            {"email": username, "password": password, "passwordRepeat": password},
        ]

        try:
            with httpx.Client(timeout=10, verify=False) as client:
                for endpoint in register_endpoints:
                    reg_url = urljoin(target_url, endpoint)
                    for body in body_variants:
                        try:
                            _debug(f"[AUTO-REGISTER] POST {reg_url} body_keys={list(body.keys())}")
                            resp = client.post(
                                reg_url, json=body,
                                headers={"Content-Type": "application/json", "Accept": "application/json"},
                            )
                            _debug(f"[AUTO-REGISTER] → status={resp.status_code}")
                            if resp.status_code in (200, 201):
                                print(f"{GREEN}[LOGIN] Auto-registered account via {endpoint} "
                                      f"(status={resp.status_code}){RESET}")
                                return {"credentials": credentials, "register_url": reg_url}
                        except Exception as e:
                            _debug(f"[AUTO-REGISTER] POST {reg_url} error: {e}")
                            continue
        except Exception as e:
            _debug(f"[AUTO-REGISTER] Error: {e}")

        return None


    def _persist_auth_context(self, target_url: str, session: dict) -> None:
        """Persist reusable session metadata for Manager/Exec without raw response bloat."""
        if not session:
            return
        clean = {
            "label": session.get("label") or "authenticated",
            "username": session.get("username", ""),
            "created_by": session.get("created_by", "crawl"),
            "auth_verified": bool(session.get("auth_verified", False)),
            "cookies": normalize_cookie_objects(session.get("cookies") or [], target_url),
            "cookie_header": cookie_header_from_cookie_objects(session.get("cookies") or []),
            "storage_state_path": session.get("storage_state_path", ""),
            "storage_state": session.get("storage_state") or {},
            "bearer_token": session.get("bearer_token", ""),
            "verified_url": session.get("verified_url", ""),
            "notes": session.get("notes", ""),
        }
        token = clean["bearer_token"] or bearer_token_from_session(clean)
        if token:
            clean["bearer_token"] = token
        try:
            path = upsert_auth_session(self.working_dir, target_url, clean)
            _debug(f"Auth context saved: {path}")
        except Exception as e:
            print(f"{YELLOW}[CRAWL-AGENT] Could not save auth_context.json: {e}{RESET}")

    def _login_playwright(self, target_url: str, credentials: dict) -> dict | None:
        """Generic Playwright login that preserves cookies + localStorage storage_state."""
        username = credentials.get("username", "")
        password = credentials.get("password", "")
        label = credentials.get("label") or username or "authenticated"
        if not username or not password:
            return None

        try:
            from playwright.sync_api import sync_playwright
        except Exception as e:
            print(f"{YELLOW}[LOGIN] Playwright unavailable: {e}{RESET}")
            return None

        candidates = self._candidate_login_urls(target_url)
        state_path = storage_state_path(self.working_dir, label)
        last_note = ""

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()

                login_page_found = False
                for login_url in candidates:
                    try:
                        page.goto(login_url, wait_until="domcontentloaded", timeout=20000)
                        page.wait_for_timeout(800)
                        # Dismiss SPA overlays (popups, banners, cookie consent)
                        self._dismiss_spa_overlays(page)
                        self._try_click_login_entry(page)
                        # Re-dismiss in case click_login_entry navigated to a new page with overlays
                        self._dismiss_spa_overlays(page)
                        password_count = page.locator('input[type="password"], input[name*="pass" i]').count()
                        last_note = f"{login_url}: password_inputs={password_count}"
                        if password_count > 0:
                            login_page_found = True
                            break
                    except Exception as e:
                        last_note = f"{login_url}: {type(e).__name__}: {e}"
                        continue

                if not login_page_found:
                    print(f"{YELLOW}[LOGIN] Playwright could not find a login form ({last_note}){RESET}")
                    browser.close()
                    return None

                user_field = self._first_visible_locator(page, [
                    'input[type="email"]',
                    'input[name*="email" i]',
                    'input[id*="email" i]',
                    'input[name*="user" i]',
                    'input[id*="user" i]',
                    'input[autocomplete="username"]',
                    'input[type="text"]',
                ])
                pass_field = self._first_visible_locator(page, [
                    'input[type="password"]',
                    'input[name*="pass" i]',
                    'input[id*="pass" i]',
                    'input[autocomplete="current-password"]',
                ])
                if not user_field or not pass_field:
                    print(f"{YELLOW}[LOGIN] Playwright found page but not username/password inputs{RESET}")
                    browser.close()
                    return None

                user_field.fill(username, timeout=5000)
                pass_field.fill(password, timeout=5000)

                submit = self._first_visible_locator(page, [
                    'button[type="submit"]',
                    'input[type="submit"]',
                    'button:has-text("Login")',
                    'button:has-text("Log in")',
                    'button:has-text("Sign in")',
                    'button:has-text("Submit")',
                    '[role="button"]:has-text("Login")',
                    '[role="button"]:has-text("Sign in")',
                    'button',
                ])
                if submit:
                    submit.click(timeout=8000)
                else:
                    pass_field.press("Enter", timeout=5000)
                page.wait_for_load_state("networkidle", timeout=15000)
                page.wait_for_timeout(1000)

                storage_state = context.storage_state(path=str(state_path))
                cookies = normalize_cookie_objects(storage_state.get("cookies") or context.cookies(), target_url)
                token = bearer_token_from_session({"storage_state": storage_state})
                verified, verified_url, verify_note = self._verify_playwright_auth(page, context, target_url, username)

                browser.close()

                if not cookies and not storage_state_has_material(storage_state):
                    print(f"{YELLOW}[LOGIN] Playwright login produced no cookies/localStorage token{RESET}")
                    return None

                print(
                    f"{GREEN}[LOGIN] Playwright login captured auth context — "
                    f"cookies={len(cookies)}, token={'yes' if token else 'no'}, verified={verified}{RESET}"
                )
                return {
                    "label": label,
                    "username": username,
                    "created_by": "crawl_playwright",
                    "auth_verified": verified,
                    "cookies": cookies,
                    "cookie_header": cookie_header_from_cookie_objects(cookies),
                    "storage_state_path": str(state_path),
                    "storage_state": storage_state,
                    "bearer_token": token,
                    "verified_url": verified_url,
                    "notes": verify_note,
                }
        except Exception as e:
            print(f"{YELLOW}[LOGIN] Playwright login error: {e}{RESET}")
            return None

    def _candidate_login_urls(self, target_url: str) -> list[str]:
        """Build generic login candidates, including hash routes used by SPAs."""
        candidates: list[str] = []

        def add(path_or_url: str) -> None:
            if not path_or_url:
                return
            if path_or_url.startswith(("http://", "https://")):
                full = path_or_url
            elif path_or_url.startswith("#"):
                full = target_url.rstrip("/") + "/" + path_or_url
            else:
                full = urljoin(target_url.rstrip("/") + "/", path_or_url)
            if full not in candidates:
                candidates.append(full)

        try:
            resp = httpx.get(target_url, timeout=10, follow_redirects=True, verify=False)
            hrefs = re.findall(r'href=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
            hrefs += re.findall(r'["\'](#[^"\']*(?:login|signin|account)[^"\']*)["\']', resp.text, re.IGNORECASE)
            login_keywords = re.compile(r"(?:log.?in|sign.?in|auth|account|session)", re.IGNORECASE)
            for href in hrefs:
                if login_keywords.search(href):
                    add(href)
        except Exception as e:
            _debug(f"Playwright login candidate discovery failed: {e}")

        for path in (
            "/login", "/signin", "/account/login", "/my-account", "/account",
            "/#/login", "/#/signin", "/#/account", "/#/user/login", "#/login", "#/signin",
        ):
            add(path)
        return candidates[:14]

    @staticmethod
    def _first_visible_locator(page, selectors: list[str]):
        for selector in selectors:
            try:
                loc = page.locator(selector).first
                if loc.count() > 0 and loc.is_visible(timeout=1200) and loc.is_enabled(timeout=1200):
                    return loc
            except Exception:
                continue
        return None

    @staticmethod
    def _dismiss_spa_overlays(page) -> None:
        """Dismiss common SPA overlays (popups, banners, cookie consent) before interacting.

        Covers: Juice Shop welcome/cookie banners, Angular CDK overlays,
        generic modals, cookie consent bars, and common close buttons.
        """
        dismiss_selectors = [
            # Juice Shop specific
            'button.close-dialog',
            'button[aria-label="Close Welcome Banner"]',
            'a.cc-dismiss',                       # Cookie consent dismiss
            'a.cc-btn.cc-dismiss',
            # Angular CDK / Material overlays
            '.cdk-overlay-backdrop',
            'button.mat-focus-indicator.close-dialog',
            # Generic modals
            '.modal .close', 'button.modal-close', '.modal-close-btn',
            'button.btn-close',
            '[aria-label="Close"]', '[aria-label="Dismiss"]',
            '[aria-label="close"]', '[aria-label="dismiss"]',
            # Cookie consent / GDPR
            'button:has-text("Accept")',
            'button:has-text("Got it")',
            'button:has-text("OK")',
            'button:has-text("I agree")',
            'button:has-text("Accept all")',
            'button:has-text("Agree")',
            # Generic dismiss
            '.dismiss', '.close-banner',
        ]
        dismissed_count = 0
        for selector in dismiss_selectors:
            try:
                loc = page.locator(selector).first
                if loc.count() > 0 and loc.is_visible(timeout=400):
                    loc.click(timeout=1500)
                    page.wait_for_timeout(250)
                    dismissed_count += 1
            except Exception:
                continue
        if dismissed_count > 0:
            _debug(f"Dismissed {dismissed_count} SPA overlay(s)")

    @staticmethod
    def _try_click_login_entry(page) -> None:
        """On SPA homepages, click a login/account entry before looking for fields."""
        selectors = [
            'a:has-text("Login")', 'button:has-text("Login")',
            'a:has-text("Log in")', 'button:has-text("Log in")',
            'a:has-text("Sign in")', 'button:has-text("Sign in")',
            'a:has-text("Account")', 'button:has-text("Account")',
            '[aria-label*="login" i]', '[aria-label*="account" i]',
        ]
        for selector in selectors:
            try:
                loc = page.locator(selector).first
                if loc.count() > 0 and loc.is_visible(timeout=700) and loc.is_enabled(timeout=700):
                    loc.click(timeout=2500)
                    page.wait_for_timeout(700)
                    return
            except Exception:
                continue

    @staticmethod
    def _verify_playwright_auth(page, context, target_url: str, username: str) -> tuple[bool, str, str]:
        """Best-effort generic auth verification for pages and SPA API endpoints."""
        markers = (
            "logout", "log out", "sign out", "my account", "profile", "dashboard",
            "orders", "basket", "cart", "account", username.lower(),
        )
        error_markers = (
            "invalid email", "invalid username", "invalid password", "incorrect",
            "login failed", "authentication failed", "wrong password",
        )

        try:
            body = page.locator("body").inner_text(timeout=2500).lower()
            if any(marker in body for marker in error_markers):
                return False, page.url, "login error marker visible after submit"
            if any(marker in body for marker in markers) and page.locator('input[type="password"]').count() == 0:
                return True, page.url, "authenticated page marker visible"
        except Exception:
            pass

        for path in ("/rest/user/whoami", "/api/users/me", "/api/me", "/profile", "/account", "/my-account", "/#/profile", "/#/basket"):
            verify_url = urljoin(target_url.rstrip("/") + "/", path.lstrip("/"))
            try:
                if path.startswith("/#/"):
                    page.goto(verify_url, wait_until="domcontentloaded", timeout=10000)
                    page.wait_for_timeout(800)
                    body = page.locator("body").inner_text(timeout=2500).lower()
                    if any(marker in body for marker in markers) and "password" not in body[:500]:
                        return True, verify_url, "SPA authenticated route marker visible"
                    continue
                resp = context.request.get(verify_url, timeout=10000)
                text = (resp.text() or "")[:3000].lower()
                if resp.status < 400 and (
                    username.lower() in text
                    or any(marker in text for marker in ("authenticated", "email", "username", "role", "basket", "orders"))
                ):
                    return True, verify_url, f"auth probe status={resp.status}"
            except Exception:
                continue
        return False, page.url, "auth material captured but no generic verify endpoint confirmed"

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
        discovery_data: dict | None = None,
    ) -> str:
        """Render recon.md from crawl/discovery facts without endpoint invention.

        Args:
            auth_sessions: list of {"label": str, "cookies": list, "data": dict}
                           Rỗng nếu không có credentials.
            focus: từ khóa mục tiêu ("IDOR", "BLF"...) từ user prompt.

        Returns:
            Absolute path to recon.md.
        """
        recon_path = os.path.join(self.working_dir, "recon.md")
        raw_crawl_path = os.path.join(self.working_dir, "crawl_raw.json")

        raw_payload: dict = {}
        try:
            raw_payload = json.loads(Path(raw_crawl_path).read_text(encoding="utf-8"))
        except Exception as e:
            print(f"{YELLOW}[CRAWL-AGENT] Could not read crawl_raw.json for recon render: {e}{RESET}")
            raw_payload = {
                "target": url,
                "raw_endpoints": self._extract_raw_endpoints(anon_data, auth_sessions),
                "discovery_probes": discovery_data or {},
            }

        if discovery_data and not raw_payload.get("discovery_probes"):
            raw_payload["discovery_probes"] = discovery_data

        report = self._render_fact_recon_report(
            url=url,
            anon_data=anon_data,
            auth_sessions=auth_sessions,
            focus=focus,
            raw_payload=raw_payload,
        )
        Path(recon_path).write_text(report, encoding="utf-8")
        size = os.path.getsize(recon_path)
        print(f"{GREEN}{BOLD}[CRAWL-AGENT] deterministic recon.md written: {recon_path} ({size} bytes){RESET}")

        return recon_path

    def _render_fact_recon_report(
        self,
        url: str,
        anon_data: dict | None,
        auth_sessions: list[dict],
        focus: str,
        raw_payload: dict,
    ) -> str:
        """Build recon.md from structured crawl artifacts only."""
        raw_endpoints = raw_payload.get("raw_endpoints") or []
        discovery_data = raw_payload.get("discovery_probes") or {}
        discovery_summary = discovery_data.get("summary") or {}
        auth_fp = raw_payload.get("auth_fingerprint") or getattr(self, "_auth_fingerprint", [])

        lines: list[str] = []
        lines.append(f"# Recon Report - {url}")
        lines.append("")
        lines.append("> This report is rendered from crawl artifacts only. It does not list unprobed or hallucinated endpoints as facts.")
        lines.append("")

        lines.append("## Crawl Summary")
        lines.append("")
        lines.append(f"- Target: `{url}`")
        if focus:
            lines.append(f"- User focus: `{focus}`")
        lines.append(f"- Anonymous requests captured: {len((anon_data or {}).get('http_traffic', []) or [])}")
        lines.append(f"- Authenticated sessions: {len(auth_sessions or [])}")
        for session in auth_sessions or []:
            lines.append(
                f"  - `{session.get('label', 'auth')}`: "
                f"verified={bool(session.get('auth_verified'))}, "
                f"requests={len(session.get('data', {}).get('http_traffic', []) or [])}, "
                f"source={session.get('created_by', '?')}"
            )
        lines.append(f"- Raw endpoint examples: {len(raw_endpoints)}")
        if discovery_summary:
            lines.append(
                "- Active discovery probes: "
                + ", ".join(f"{k}={v}" for k, v in discovery_summary.items())
            )
        lines.append("")

        lines.append("## Evidence Rules")
        lines.append("")
        lines.append("- `provenance=crawl` means the crawler observed the request during normal anonymous/authenticated crawl.")
        lines.append("- `provenance=active_discovery` means the bounded read-only discovery layer actively probed the path.")
        lines.append("- HTML/CSS/JS keywords are recorded as signals only; they are not endpoint evidence by themselves.")
        lines.append("- A guessed candidate is promoted into endpoint inventory only when the probe classified it as route-like.")
        lines.append("")

        lines.append("## Observed Endpoint Inventory")
        lines.append("")
        if raw_endpoints:
            lines.append("| Method | Path | Status | Auth/Context | Provenance | Response Type | Notes |")
            lines.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
            for ep in raw_endpoints[:160]:
                response = ep.get("response") or {}
                headers = response.get("headers") or {}
                content_type = (
                    headers.get("content-type")
                    or headers.get("Content-Type")
                    or ""
                )
                notes: list[str] = []
                discovery = ep.get("discovery") or {}
                if discovery.get("classification"):
                    notes.append(discovery["classification"])
                signals = (discovery.get("bac_signals") or []) + (discovery.get("blf_signals") or [])
                if signals:
                    notes.append("signals: " + ", ".join(signals[:3]))
                snippet = self._clean_html_text(response.get("body_snippet") or "")
                if snippet and not notes:
                    notes.append(snippet[:80])
                lines.append(
                    f"| `{ep.get('method', '?')}` | `{ep.get('path', '/')}` | "
                    f"{ep.get('status', '?')} | `{ep.get('auth_session', '-')}` | "
                    f"`{ep.get('provenance', 'crawl')}` | `{content_type[:45] or '-'}` | "
                    f"{self._md_cell('; '.join(notes) or '-')} |"
                )
            if len(raw_endpoints) > 160:
                lines.append(f"| ... | ... | ... | ... | ... | ... | {len(raw_endpoints) - 160} more endpoints omitted |")
        else:
            lines.append("_No endpoint examples captured._")
        lines.append("")

        discovery_section = self._render_discovery_recon_section(discovery_data)
        if discovery_section:
            lines.append(discovery_section.rstrip())
            lines.append("")

        auth_section = self._render_auth_mechanism_section(auth_fp)
        if auth_section:
            lines.append(auth_section.rstrip())
            lines.append("")

        structured = self._render_structured_recon_appendix(anon_data, auth_sessions)
        if structured:
            lines.append(structured.rstrip())
            lines.append("")

        lines.append("## BAC / BLF Strategy From Observed Evidence")
        lines.append("")
        lines.append("The crawl strategy now separates facts from candidates:")
        lines.append("")
        lines.append("1. Normal crawl records observed pages, forms, XHR/fetch calls, cookies, params, and response clues.")
        lines.append("2. Bounded discovery probes common BAC and BLF surfaces using only GET/OPTIONS.")
        lines.append("3. BAC coverage focuses on admin/management/API/user/role surfaces and client-visible identity cookies.")
        lines.append("4. BLF coverage focuses on cart, checkout, order, payment, transfer, coupon, balance, price, quantity, and workflow-state surfaces.")
        lines.append("5. Downstream agents should only create exploit strategies from rows in `Observed Endpoint Inventory` or active probes with `route_exists=true`.")
        lines.append("6. Rows with only signals require verification; status 200 alone is not proof of BAC/BLF.")
        lines.append("")

        return "\n".join(lines).rstrip() + "\n"

    @staticmethod
    def _md_cell(text: str) -> str:
        return str(text or "").replace("|", "\\|").replace("\n", " ").strip()

    @classmethod
    def _render_discovery_recon_section(cls, discovery_data: dict) -> str:
        if not discovery_data:
            return ""
        probes = discovery_data.get("probes") or []
        if not probes:
            return ""

        route_like = [p for p in probes if p.get("route_exists")]
        signal_only = [
            p for p in probes
            if not p.get("route_exists") and (p.get("bac_signals") or p.get("blf_signals"))
        ]

        lines: list[str] = []
        lines.append("## Active Discovery Probes")
        lines.append("")
        strategy = discovery_data.get("strategy") or {}
        lines.append(f"- Strategy: `{strategy.get('name', 'bounded_read_only_bac_blf_discovery')}`")
        lines.append(f"- Scope: {strategy.get('scope', 'GET/OPTIONS only')}")
        lines.append("- Important: failed/generic candidates are not endpoint evidence.")
        lines.append("")

        if route_like:
            lines.append("### Route-Like Probe Results")
            lines.append("")
            lines.append("| Method | Path | Context | Status | Classification | BAC Signals | BLF Signals | Source |")
            lines.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
            for probe in route_like[:120]:
                lines.append(
                    f"| `{probe.get('method', '?')}` | `{probe.get('path', '/')}` | "
                    f"`{probe.get('context', '-')}` | {probe.get('status', '?')} | "
                    f"{cls._md_cell(probe.get('classification', '-'))} | "
                    f"{cls._md_cell(', '.join(probe.get('bac_signals') or []) or '-')} | "
                    f"{cls._md_cell(', '.join(probe.get('blf_signals') or []) or '-')} | "
                    f"{cls._md_cell(', '.join(probe.get('candidate_sources') or []) or '-')} |"
                )
            lines.append("")

        if signal_only:
            lines.append("### Signal-Only Probe Results")
            lines.append("")
            lines.append("These responses had keywords but were not classified as route-like. Treat them as clues only.")
            lines.append("")
            for probe in signal_only[:40]:
                signals = (probe.get("bac_signals") or []) + (probe.get("blf_signals") or [])
                lines.append(
                    f"- `{probe.get('method', '?')} {probe.get('path', '/')}` "
                    f"context=`{probe.get('context', '-')}` status={probe.get('status', '?')} "
                    f"classification={probe.get('classification', '-')} signals={', '.join(signals)}"
                )
            lines.append("")

        return "\n".join(lines).rstrip() + "\n"

    @staticmethod
    def _render_auth_mechanism_section(auth_fp: list[dict]) -> str:
        if not auth_fp:
            return ""
        lines: list[str] = []
        lines.append("## Auth Mechanism Discovery")
        lines.append("")
        for entry in auth_fp[:10]:
            path = entry.get("path") or entry.get("url") or "?"
            lines.append(f"### `{path}`")
            lines.append(f"- Is login: {bool(entry.get('is_login'))}")
            lines.append(f"- Is register: {bool(entry.get('is_register'))}")
            if entry.get("login_success"):
                lines.append("- Login success observed: true")
                lines.append(f"- Method: `{entry.get('login_method', 'POST')}`")
                lines.append(f"- Content-Type: `{entry.get('login_content_type', '?')}`")
                lines.append(f"- Body fields: `{', '.join(entry.get('login_body_fields') or [])}`")
                lines.append(f"- Auth mechanism: `{entry.get('auth_mechanism', 'unknown')}`")
                if entry.get("token_location"):
                    lines.append(f"- Token location: `{entry.get('token_location')}`")
            elif entry.get("recommended_content_type"):
                lines.append(f"- Recommended Content-Type: `{entry.get('recommended_content_type')}`")
                lines.append(f"- Recommended body fields: `{', '.join(entry.get('recommended_body_fields') or [])}`")
                lines.append(f"- Auth mechanism hint: `{entry.get('auth_mechanism', 'unknown')}`")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"


    # ─── Internal: Save crawl data to files (no LLM) ────────────

    def _save_crawl_data(
        self,
        url: str,
        anon_data: dict | None,
        auth_sessions: list[dict],
        focus: str = "",
        discovery_data: dict | None = None,
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
            parts.append(f"AUTH CONTEXT FILE: {auth_context_path(self.working_dir)}")
            for session in auth_sessions:
                material = []
                if session.get("cookies"):
                    material.append(f"cookies={len(session.get('cookies') or [])}")
                if session.get("storage_state_path"):
                    material.append("playwright_storage_state=yes")
                if session.get("bearer_token") or bearer_token_from_session(session):
                    material.append("bearer_or_localStorage_token=yes")
                parts.append(
                    f"- AUTH SESSION {session.get('label', '?')}: "
                    f"verified={bool(session.get('auth_verified'))}; "
                    f"source={session.get('created_by', '?')}; "
                    f"{', '.join(material) if material else 'auth_material=unknown'}"
                )
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

        # ── Auth Fingerprint Evidence (raw request/response for auth endpoints) ──
        auth_fp = getattr(self, "_auth_fingerprint", [])
        if auth_fp:
            parts.append("")
            parts.append("=" * 60)
            parts.append("AUTH ENDPOINT FINGERPRINT (Critical for BAC/BLF exploitation)")
            parts.append("=" * 60)
            parts.append("")
            parts.append("These are raw request/response captures from actively probing")
            parts.append("login, register, and auth-related endpoints. Use this data to")
            parts.append("understand the EXACT auth mechanism, body format, and token location.")
            parts.append("")
            for fp_entry in auth_fp:
                ep_path = fp_entry.get("path", fp_entry.get("url", "?"))
                parts.append(f"--- Endpoint: {ep_path} ---")
                parts.append(f"  URL: {fp_entry.get('url', '?')}")
                parts.append(f"  Is Login: {fp_entry.get('is_login', False)}")
                parts.append(f"  Is Register: {fp_entry.get('is_register', False)}")
                if fp_entry.get("login_success"):
                    parts.append(f"  ★ LOGIN SUCCESS — use this endpoint for authentication")
                    parts.append(f"    Method: {fp_entry.get('login_method', 'POST')}")
                    parts.append(f"    Content-Type: {fp_entry.get('login_content_type', '?')}")
                    parts.append(f"    Body Fields: {fp_entry.get('login_body_fields', [])}")
                    parts.append(f"    Auth Mechanism: {fp_entry.get('auth_mechanism', '?')}")
                    parts.append(f"    Token Location: {fp_entry.get('token_location', 'N/A')}")
                if fp_entry.get("recommended_content_type"):
                    parts.append(f"  Recommended Content-Type: {fp_entry['recommended_content_type']}")
                    parts.append(f"  Recommended Body Fields: {fp_entry.get('recommended_body_fields', [])}")
                    parts.append(f"  Auth Mechanism: {fp_entry.get('auth_mechanism', '?')}")
                    if fp_entry.get("token_location"):
                        parts.append(f"  Token Location: {fp_entry['token_location']}")
                for probe in fp_entry.get("probes", []):
                    parts.append(f"")
                    parts.append(f"  [Probe: {probe.get('variant', '?')}]")
                    parts.append(f"  == Raw Request ==")
                    parts.append(f"  {probe.get('raw_request', 'N/A')}")
                    parts.append(f"  == Raw Response ==")
                    parts.append(f"  {probe.get('raw_response', 'N/A')}")
                    parts.append(f"  Status: {probe.get('status', '?')}")
                    if probe.get("has_token_in_body"):
                        parts.append(f"  ★ TOKEN FOUND in response body at: {probe.get('token_location', '?')}")
                    if probe.get("has_set_cookie"):
                        parts.append(f"  ★ SET-COOKIE: {probe.get('set_cookie_header', '?')}")
                parts.append("")

        if discovery_data:
            parts.append("")
            parts.append("=" * 60)
            parts.append("ACTIVE BAC/BLF DISCOVERY PROBES")
            parts.append("=" * 60)
            parts.append("")
            parts.append(self._format_discovery_data(discovery_data))

        formatted_text = "\n".join(parts)

        # Save crawl_raw.json
        raw_crawl_path = os.path.join(self.working_dir, "crawl_raw.json")
        try:
            # Build raw_endpoints: clean HTTP examples for each live endpoint
            raw_endpoints = self._extract_raw_endpoints(anon_data, auth_sessions)
            discovery_endpoints = self._raw_endpoints_from_discovery(discovery_data or {})
            raw_endpoints = self._merge_raw_endpoint_examples(raw_endpoints, discovery_endpoints)

            raw_payload = {
                "target": url,
                "raw_endpoints": raw_endpoints,
                "discovery_probes": discovery_data or {},
                "anonymous": anon_data,
                "authenticated": [
                    {
                        "label": s["label"],
                        "auth_verified": s.get("auth_verified", False),
                        "cookies": s.get("cookies", []),
                        "cookie_header": cookie_header_from_cookie_objects(s.get("cookies", [])),
                        "storage_state_path": s.get("storage_state_path", ""),
                        "storage_state": s.get("storage_state", {}),
                        "bearer_token": s.get("bearer_token", "") or bearer_token_from_session(s),
                        "created_by": s.get("created_by", ""),
                        "verified_url": s.get("verified_url", ""),
                        "notes": s.get("notes", ""),
                        "data": s.get("data", {}),
                    }
                    for s in auth_sessions
                ],
                "auth_context_file": str(auth_context_path(self.working_dir)),
                "auth_fingerprint": auth_fp,
            }
            with open(raw_crawl_path, "w", encoding="utf-8") as f:
                json.dump(raw_payload, f, ensure_ascii=False, indent=2)
            print(f"{GREEN}[CRAWL-AGENT] Raw crawl JSON saved: {raw_crawl_path} "
                  f"({len(raw_endpoints)} raw endpoints){RESET}")
        except Exception as e:
            print(f"{YELLOW}[CRAWL-AGENT] Could not save crawl_raw.json: {e}{RESET}")

        # Save compact auth_context.json as the source of truth for Manager/Exec.
        try:
            if auth_sessions:
                for session in auth_sessions:
                    self._persist_auth_context(url, session)
            # Enrich auth_context.json with login discovery from fingerprint
            if auth_fp:
                ctx = load_auth_context(self.working_dir)
                login_discovery = {}
                for fp_entry in auth_fp:
                    if fp_entry.get("login_success"):
                        login_discovery = {
                            "login_endpoint": fp_entry.get("login_endpoint") or fp_entry.get("path", ""),
                            "login_method": fp_entry.get("login_method", "POST"),
                            "login_content_type": fp_entry.get("login_content_type", "application/json"),
                            "login_body_fields": fp_entry.get("login_body_fields", []),
                            "auth_mechanism": fp_entry.get("auth_mechanism", "unknown"),
                            "token_location": fp_entry.get("token_location", ""),
                        }
                        break
                if not login_discovery:
                    # Use best guess from probes
                    for fp_entry in auth_fp:
                        if fp_entry.get("is_login") and fp_entry.get("recommended_content_type"):
                            login_discovery = {
                                "login_endpoint": fp_entry.get("path", ""),
                                "login_method": "POST",
                                "login_content_type": fp_entry["recommended_content_type"],
                                "login_body_fields": fp_entry.get("recommended_body_fields", []),
                                "auth_mechanism": fp_entry.get("auth_mechanism", "unknown"),
                                "token_location": fp_entry.get("token_location", ""),
                            }
                            break
                if login_discovery:
                    ctx["login_discovery"] = login_discovery
                    save_auth_context(self.working_dir, ctx)
            ctx = load_auth_context(self.working_dir)
            if ctx.get("sessions") or ctx.get("login_discovery"):
                print(
                    f"{GREEN}[CRAWL-AGENT] Auth context saved: {auth_context_path(self.working_dir)} "
                    f"({len(ctx.get('sessions', []))} session(s), "
                    f"login_discovery={'yes' if ctx.get('login_discovery') else 'no'}){RESET}"
                )
        except Exception as e:
            print(f"{YELLOW}[CRAWL-AGENT] Could not persist auth context: {e}{RESET}")

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

    @staticmethod
    def _format_discovery_data(discovery_data: dict) -> str:
        if not discovery_data:
            return "No active discovery probes were run."

        lines: list[str] = []
        strategy = discovery_data.get("strategy") or {}
        summary = discovery_data.get("summary") or {}
        lines.append(f"Strategy: {strategy.get('name', 'bounded_read_only_bac_blf_discovery')}")
        lines.append(f"Scope: {strategy.get('scope', 'GET/OPTIONS only')}")
        lines.append(
            "Summary: "
            + ", ".join(f"{k}={v}" for k, v in summary.items())
        )
        lines.append("")
        lines.append("Important rule: candidates below are only facts after a probe returns route_exists=true.")
        lines.append("")

        probes = discovery_data.get("probes") or []
        interesting = [
            p for p in probes
            if p.get("route_exists") or p.get("bac_signals") or p.get("blf_signals")
        ]
        if not interesting:
            lines.append("No route-like discovery responses found.")
            return "\n".join(lines)

        for probe in interesting[:120]:
            signals = (probe.get("bac_signals") or []) + (probe.get("blf_signals") or [])
            lines.append(
                f"- [{probe.get('status', '?')}] {probe.get('method', '?')} {probe.get('path', '?')} "
                f"context={probe.get('context', '?')} route_exists={probe.get('route_exists', False)} "
                f"classification={probe.get('classification', '?')}"
            )
            if probe.get("candidate_sources"):
                lines.append(f"  sources: {', '.join(probe.get('candidate_sources') or [])}")
            if probe.get("tamper_notes"):
                lines.append(f"  tamper: {', '.join(probe.get('tamper_notes') or [])}")
            if signals:
                lines.append(f"  BAC/BLF signals: {', '.join(signals)}")
            response = probe.get("response") or {}
            snippet = CrawlAgent._clean_html_text(response.get("body_snippet") or "")
            if snippet:
                lines.append(f"  body snippet: {snippet[:300]}")
        return "\n".join(lines)

    @staticmethod
    def _raw_endpoints_from_discovery(discovery_data: dict) -> list[dict]:
        endpoints: list[dict] = []
        for probe in (discovery_data or {}).get("probes", []) or []:
            if not probe.get("route_exists"):
                continue
            if str(probe.get("method", "")).upper() != "GET":
                continue
            response = probe.get("response") or {}
            request = probe.get("request") or {}
            endpoints.append({
                "method": "GET",
                "path": probe.get("path", "/"),
                "status": probe.get("status") or 0,
                "request": {
                    "headers": request.get("headers") or {},
                    "body": None,
                },
                "response": {
                    "headers": response.get("headers") or {},
                    "body_snippet": response.get("body_snippet") or "",
                    "body_size": response.get("body_size") or 0,
                },
                "auth_session": probe.get("context", "active_discovery"),
                "resource_type": "active_discovery",
                "provenance": "active_discovery",
                "discovery": {
                    "classification": probe.get("classification", ""),
                    "candidate_sources": probe.get("candidate_sources", []),
                    "candidate_reason": probe.get("candidate_reason", ""),
                    "bac_signals": probe.get("bac_signals", []),
                    "blf_signals": probe.get("blf_signals", []),
                    "tamper_notes": probe.get("tamper_notes", []),
                },
            })
        return endpoints

    @staticmethod
    def _merge_raw_endpoint_examples(primary: list[dict], discovered: list[dict]) -> list[dict]:
        merged: dict[str, dict] = {}

        def rank(entry: dict) -> tuple[int, int, int]:
            provenance = entry.get("provenance", "crawl")
            status = int(entry.get("status") or 0)
            status_rank = 0 if 200 <= status < 300 else 1 if status in {301, 302, 303, 307, 308, 401, 403, 405} else 2
            auth_rank = 0 if entry.get("auth_session") != "anonymous" else 1
            provenance_rank = 0 if provenance != "active_discovery" else 1
            return (status_rank, auth_rank, provenance_rank)

        for entry in (primary or []) + (discovered or []):
            key = f"{str(entry.get('method', 'GET')).upper()} {entry.get('path', '/')}"
            existing = merged.get(key)
            if existing is None or rank(entry) < rank(existing):
                merged[key] = entry

        return sorted(merged.values(), key=lambda e: (e.get("path", ""), e.get("method", "")))

    def _extract_raw_endpoints(
        self,
        anon_data: dict | None,
        auth_sessions: list[dict],
    ) -> list[dict]:
        """Extract clean HTTP request/response examples from crawl traffic.

        For each unique endpoint (method + path), saves:
        - method, path, status
        - request headers (filtered), body
        - response headers (filtered), body snippet
        - auth_session: which session captured it (anonymous or label)

        This data feeds directly into VulnHunter bug candidates and Exec exploit context.
        """
        seen: dict[str, dict] = {}  # key: "METHOD /path" → best example

        def _add_traffic(traffic: list[dict], session_label: str) -> None:
            for req in traffic:
                if not isinstance(req, dict):
                    continue
                method = req.get("method", "GET")
                url_str = req.get("url", "")
                if not url_str:
                    continue
                # Extract path from URL
                try:
                    parsed = urlparse(url_str)
                    path = parsed.path or "/"
                except Exception:
                    path = "/"

                resource_type = req.get("resource_type", "")
                status = req.get("response_status") or 0

                # Only keep document/xhr/fetch traffic (skip images, css, fonts etc.)
                if resource_type not in ("document", "xhr", "fetch", ""):
                    continue
                # Skip static assets
                if any(path.endswith(ext) for ext in (".js", ".css", ".png", ".jpg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".map")):
                    continue

                key = f"{method} {path}"
                # Keep the best example: prefer 2xx, then auth over anon
                existing = seen.get(key)
                if existing:
                    def score(entry: dict) -> tuple[int, int]:
                        st = int(entry.get("status") or 0)
                        if 200 <= st < 300:
                            status_rank = 0
                        elif st in {301, 302, 303, 307, 308, 401, 403, 405}:
                            status_rank = 1
                        elif st >= 500:
                            status_rank = 3
                        else:
                            status_rank = 2
                        auth_rank = 0 if entry.get("auth_session") != "anonymous" else 1
                        return status_rank, auth_rank

                    candidate_entry = {"status": status, "auth_session": session_label}
                    if score(existing) <= score(candidate_entry):
                        continue

                # Extract request body
                req_body = req.get("postData") or None
                if isinstance(req_body, str) and len(req_body) > 500:
                    req_body = req_body[:500] + "..."

                # Extract response body snippet
                resp_body = req.get("response_body") or ""
                if isinstance(resp_body, str) and len(resp_body) > 300:
                    resp_body = resp_body[:300] + "..."

                # Filter headers to useful ones only
                req_headers = req.get("headers") or {}
                useful_req_headers = {
                    k: v for k, v in req_headers.items()
                    if k.lower() in ("content-type", "authorization", "cookie", "accept", "x-requested-with")
                }

                resp_headers = req.get("response_headers") or {}
                useful_resp_headers = {
                    k: v for k, v in resp_headers.items()
                    if k.lower() in ("content-type", "set-cookie", "location", "www-authenticate", "x-powered-by")
                }

                seen[key] = {
                    "method": method,
                    "path": path,
                    "status": status,
                    "request": {
                        "headers": useful_req_headers,
                        "body": req_body,
                    },
                    "response": {
                        "headers": useful_resp_headers,
                        "body_snippet": resp_body,
                        "body_size": len(req.get("response_body") or ""),
                    },
                    "auth_session": session_label,
                    "resource_type": resource_type,
                    "provenance": "crawl",
                }

        # Process anonymous traffic
        if anon_data:
            _add_traffic(anon_data.get("http_traffic", []), "anonymous")

        # Process authenticated traffic
        for session in auth_sessions:
            data = session.get("data", {})
            if data:
                _add_traffic(data.get("http_traffic", []), session.get("label", "authenticated"))

        # Sort by path for readability
        endpoints = sorted(seen.values(), key=lambda e: (e["path"], e["method"]))
        _debug(f"Extracted {len(endpoints)} raw endpoint examples")
        return endpoints

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
