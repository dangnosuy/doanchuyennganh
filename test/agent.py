"""
Executor Agent — "Culi" cho hệ thống MARL debate.

Copy pattern từ giaotiep.py / toaan.py (system prompt ngắn gọn, _call_llm đơn giản).
Executor là agent duy nhất có MCP tools (Playwright, shell, fetch, ...).

Tag system:
  - [REDTEAM] ở cuối text = "xong rồi, gửi cho Red Team"
  - [BLUETEAM] ở cuối text = "xong rồi, gửi cho Blue Team"
  - =========SEND========= ... =========END-SEND========= = phần data gửi đi
"""

import json
import os
import re
import sys
from urllib.parse import urlparse, urljoin

import httpx
from openai import OpenAI
from mcp_client import MCPManager
from crawler import run_crawl
from shared.utils import (
    extract_send_block, extract_next_tag, strip_tag,
    truncate as _truncate, parse_prompt as _parse_prompt,
    SEND_BLOCK_PATTERN, TAG_PATTERN,
)

# ═══════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "gho_token")
SERVER_URL = os.getenv("MARL_SERVER_URL", "http://127.0.0.1:5000/v1")
MODEL = os.getenv("MARL_EXECUTOR_MODEL", "gpt-5-mini")

# Colors
YELLOW = "\033[93m"
GREEN = "\033[92m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Limits
MAX_TOOL_ROUNDS = 50
MAX_CONSECUTIVE_ERRORS = 3
TRUNCATE_LIMIT = 15000


# ═══════════════════════════════════════════════════════════════
# SYSTEM PROMPTS (English — short, imperative, LLM follows better)
# ═══════════════════════════════════════════════════════════════

# --- CRAWL prompt: Executor crawls website, collects network requests ---
CRAWL_SYSTEM_PROMPT = """You are a web crawler with Playwright browser tools, fetch, and shell.

GOAL: Navigate the target website, login if credentials given, visit all reachable pages,
and collect HTTP traffic (requests + responses) for security analysis.

CAPTURE PRIORITIES:
- Authentication flows (login, session tokens, cookies)
- State-changing actions (forms, POST/PUT/DELETE endpoints)
- Access control boundaries (admin paths, other user resources, IDOR params)
- Response bodies for important endpoints (not just request URLs)
- Edge cases: submit forms with valid AND invalid input, compare responses

OUTPUT: Wrap results in =========SEND=========...=========END-SEND========= block.
Include: cookies, pages visited, interesting request/response pairs, forms, observations.
End with [REDTEAM].

RULES:
- Act immediately — do not describe plans.
- If a tool fails, try a different approach. After 2 failures, skip and note it.
- Do NOT suggest attacks. Only collect data.
- Every response that has no tool_calls MUST end with a tag on the last line."""


# --- EXECUTOR prompt: runs commands from Red/Blue team ---
EXECUTOR_SYSTEM_PROMPT = """You are a command executor with shell, filesystem, fetch, and browser tools.

JOB: Receive Python PoC scripts, save to file, execute with python3, report full output.

RULES:
- ALWAYS save scripts into the workspace directory (given in the first message). NEVER write files outside it.
- Save and run code AS-IS. Do NOT replicate logic manually with browser.
- Report full stdout + stderr in =========SEND=========...=========END-SEND========= block.
- End with the return tag given ([REDTEAM] or [BLUETEAM]).
- Every response that has no tool_calls MUST end with a tag on the last line."""


# --- ANSWER prompt: Executor answers questions from Red/Blue team ---
ANSWER_SYSTEM_PROMPT = """You are a research assistant for a security analysis team with browser and fetch tools.

JOB: Answer questions about the TARGET WEBSITE based on crawl data provided. Use browser/fetch tools to look up info on the TARGET if needed.

OUTPUT: Put answer in =========SEND=========...=========END-SEND========= block.
End with the return tag given ([REDTEAM] or [BLUETEAM]).

RULES:
- Answer factually based on data. Do not speculate.
- Do NOT suggest attacks. Just answer the question.
- NEVER read local project files (*.py, *.json, etc.) — they are NOT the target. Only interact with the TARGET website.
- Every response that has no tool_calls MUST end with a tag on the last line."""


# --- FILTER prompt: Executor filters + ranks crawl traffic for Red/Blue team ---
FILTER_SYSTEM_PROMPT = """You are a security data filter. You receive raw HTTP traffic from a web crawler.

JOB: Filter and rank the traffic by pentest relevance. Remove noise, highlight what matters.

REMOVE:
- Static assets (images, CSS, JS bundles, fonts, favicon)
- Health checks, CORS preflight (OPTIONS), analytics/tracking
- Duplicate requests (keep one representative example)

RANK (highest → lowest priority):
1. State-changing actions (POST/PUT/DELETE to forms, APIs) — include full request + response
2. Authentication flows (login, logout, session, token refresh)
3. Access control boundaries (admin paths, user-specific resources, IDOR-like params)
4. Read endpoints with sensitive data (user profiles, settings, lists)
5. Everything else (low priority — summarize briefly or omit)

OUTPUT FORMAT — follow EXACTLY:

=========SEND=========
## High Priority (state-changing / auth / access control)
[Ranked entries with full request + response details]

## Medium Priority (read endpoints with interesting data)
[Entries with key details]

## Observations
[Patterns noticed: missing auth checks, IDOR params, cookie anomalies, etc.]

## Summary
[Total requests seen, kept, removed. Key endpoints to focus on.]
=========END-SEND=========

[REDTEAM]

RULES:
- Be aggressive in filtering — Red/Blue Team needs signal, not noise.
- Preserve EXACT URLs, parameters, headers, response bodies — do not paraphrase.
- If traffic is already clean and small (<30 entries), keep most of it and just re-rank.
- Do NOT suggest attacks. Only organize data."""


# ═══════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS (imported from shared.utils)
# ═══════════════════════════════════════════════════════════════
# SEND_BLOCK_PATTERN, TAG_PATTERN, extract_send_block, extract_next_tag,
# strip_tag, _truncate (as truncate), _parse_prompt (as parse_prompt)
# are imported at the top of this file from shared.utils.


# ═══════════════════════════════════════════════════════════════
# FORMAT HTTP TRAFFIC (BrowserAgent output → readable text)
# ═══════════════════════════════════════════════════════════════

# Resource types to keep (skip image/stylesheet/font/media/manifest/ping)
_KEEP_TYPES = {"document", "xhr", "fetch", "form", "websocket", "other", "script"}
# Headers worth showing in formatted output
_INTERESTING_HEADERS = {"content-type", "authorization", "cookie", "set-cookie", "location", "x-csrf-token"}


def format_http_traffic(
    http_traffic: list[dict],
    cookies: list[dict],
    external: set[str],
    start_url: str,
) -> str:
    """Format BrowserAgent crawl results into structured text for Red/Blue Team.

    Filters out static resources, groups by category, truncates to TRUNCATE_LIMIT.
    """
    parts: list[str] = []

    # ── Cookies ──
    if cookies:
        parts.append("## Cookies")
        for c in cookies:
            parts.append(f"  {c.get('name', '?')}={c.get('value', '')}"
                         f"  (domain={c.get('domain', '?')}, path={c.get('path', '/')}"
                         f", httpOnly={c.get('httpOnly', False)}, secure={c.get('secure', False)})")
        parts.append("")

    # ── Filter traffic ──
    filtered = [
        r for r in http_traffic
        if r.get("resource_type", "other") in _KEEP_TYPES
        and r.get("method", "").upper() != "OPTIONS"
    ]

    # ── Pages visited (document type) ──
    pages = [r for r in filtered if r.get("resource_type") == "document"]
    if pages:
        seen_urls = set()
        parts.append("## Pages Visited")
        for r in pages:
            url = r.get("url", "?")
            if url not in seen_urls:
                seen_urls.add(url)
                status = r.get("response_status", "?")
                parts.append(f"  [{status}] {url}")
        parts.append("")

    # ── Interesting Requests + Responses (xhr, fetch, form, other) ──
    api_requests = [r for r in filtered if r.get("resource_type") in ("xhr", "fetch", "other")]
    if api_requests:
        parts.append("## Interesting Requests + Responses")
        for r in api_requests:
            method = r.get("method", "?")
            url = r.get("url", "?")
            status = r.get("response_status", "?")

            parts.append(f"REQUEST: {method} {url}")

            # Selected request headers
            req_headers = r.get("headers", {})
            shown = {k: v for k, v in req_headers.items() if k.lower() in _INTERESTING_HEADERS}
            if shown:
                parts.append(f"  Headers: {shown}")
            if r.get("postData"):
                post = r["postData"][:500]
                parts.append(f"  Body: {post}")

            parts.append(f"RESPONSE: {status}")
            resp_headers = r.get("response_headers", {})
            shown_resp = {k: v for k, v in resp_headers.items() if k.lower() in _INTERESTING_HEADERS}
            if shown_resp:
                parts.append(f"  Headers: {shown_resp}")
            if r.get("response_body"):
                body = r["response_body"][:500]
                parts.append(f"  Body: {body}")
            parts.append("---")
        parts.append("")

    # ── Forms Found ──
    forms = [r for r in http_traffic if r.get("resource_type") == "form"]
    if forms:
        parts.append("## Forms Found")
        for r in forms:
            method = r.get("method", "?")
            url = r.get("url", "?")
            parent = r.get("parent_url", "?")
            parts.append(f"  {method} {url} (on page: {parent})")
            if r.get("form_fields"):
                for f in r["form_fields"]:
                    parts.append(f"    - {f.get('name', '?')} (type={f.get('type', '?')}, value={f.get('value', '')})")
        parts.append("")

    # ── Script URLs (for endpoint mining) ──
    scripts = [r for r in filtered if r.get("resource_type") == "script"]
    if scripts:
        seen_scripts = set()
        parts.append("## Script URLs (potential endpoint mining)")
        for r in scripts:
            url = r.get("url", "?")
            if url not in seen_scripts:
                seen_scripts.add(url)
                parts.append(f"  {url}")
        parts.append("")

    # ── External Links ──
    if external:
        parts.append("## External Links")
        for url in sorted(external)[:20]:
            parts.append(f"  {url}")
        if len(external) > 20:
            parts.append(f"  ... and {len(external) - 20} more")
        parts.append("")

    # ── Summary ──
    parts.append("## Summary")
    parts.append(f"  Target: {start_url}")
    parts.append(f"  Total requests captured: {len(http_traffic)}")
    parts.append(f"  Filtered (useful): {len(filtered)}")
    parts.append(f"  Pages: {len(pages)}")
    parts.append(f"  API/XHR requests: {len(api_requests)}")
    parts.append(f"  Forms: {len(forms)}")
    parts.append(f"  Cookies: {len(cookies)}")
    parts.append(f"  External links: {len(external)}")

    text = "\n".join(parts)
    return _truncate(text)


# ═══════════════════════════════════════════════════════════════
# PARSE PROMPT — imported from shared.utils as _parse_prompt
# ═══════════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════════
# LOGIN SYSTEM PROMPT — LLM only logs in and captures cookies
# ═══════════════════════════════════════════════════════════════

LOGIN_SYSTEM_PROMPT = """You are a login bot. Your ONLY job: log into the website and capture cookies.

PROCEDURE:
1. browser_navigate to the target URL.
2. browser_snapshot to find the login form.
3. browser_type username into the username/email field.
4. browser_type password into the password field.
5. Check for "Remember me" / "Stay logged in" checkbox — click if present.
6. browser_click the login/submit button.
7. Wait for navigation. browser_snapshot to confirm login success.
8. Capture ALL cookies (including httpOnly) using browser_run_code with EXACTLY this code:
   ```
   const cookies = await page.context().cookies();
   console.log(JSON.stringify(cookies));
   ```
   This returns ALL cookies including httpOnly session cookies.
   Parse the JSON output to extract name=value pairs.

OUTPUT FORMAT — follow EXACTLY:

=========SEND=========
LOGIN_STATUS: SUCCESS or FAILED
COOKIES:
name1=value1
name2=value2
...
=========END-SEND=========

[REDTEAM]

RULES:
- Do NOT browse the site after login. Just login, capture cookies, output, done.
- If login fails (wrong page, error message), report LOGIN_STATUS: FAILED.
- Minimize tool calls — aim for ≤8 total.
- Every response that has no tool_calls MUST end with a tag on the last line."""


# ═══════════════════════════════════════════════════════════════
# EXECUTOR AGENT CLASS
# ═══════════════════════════════════════════════════════════════

class ExecutorAgent:
    """Executor agent with MCP tools (Playwright, shell, fetch, filesystem)."""

    def __init__(self, working_dir: str = "./workspace"):
        self.working_dir = os.path.abspath(working_dir)
        os.makedirs(self.working_dir, exist_ok=True)
        self.target_url = ""  # set by crawl()
        self.client = OpenAI(api_key=GITHUB_TOKEN, base_url=SERVER_URL)

        print(f"\n{YELLOW}{BOLD}[EXECUTOR] Khoi tao MCP tools...{RESET}")
        self.mcp = MCPManager()
        self.mcp.add_filesystem_server([self.working_dir])
        self.mcp.add_shell_server()
        self.mcp.add_fetch_server()
        self.mcp.add_web_search()
        self.mcp.add_playwright_server(headless=True)

        self.tools = self.mcp.get_openai_tools()
        print(f"{YELLOW}[EXECUTOR] Da san sang — {len(self.tools)} tools{RESET}")
        self.mcp.display_tools()
        print()

    def crawl(self, user_prompt: str) -> str:
        """Phase 1: Crawl target using BrowserAgent (fast, no tokens) with LLM login + fallback.

        Strategy:
        1. Parse prompt → URL + credentials
        2. If credentials → LLM logs in via Playwright → capture cookies
        3. BrowserAgent BFS crawl (with cookies if available)
        4. Format results → SEND block
        5. If BrowserAgent fails → fallback to LLM crawl

        Returns raw text (contains SEND block + [REDTEAM] tag).
        """
        url, credentials = _parse_prompt(user_prompt)
        if not url:
            return (
                "=========SEND=========\n"
                "ERROR: Khong tim thay URL trong prompt. Vui long nhap URL target.\n"
                "=========END-SEND=========\n\n[REDTEAM]"
            )

        print(f"{GREEN}{BOLD}[EXECUTOR] Target: {url}{RESET}")
        self.target_url = url  # save for later use by answer()

        # ── Step 1: Login (if credentials provided) ──
        login_cookies = None
        if credentials:
            print(f"{YELLOW}[EXECUTOR] Co credentials, dang login...{RESET}")
            try:
                login_cookies = self._login_only(url, credentials)
                if login_cookies:
                    print(f"{GREEN}[EXECUTOR] Login thanh cong — {len(login_cookies)} cookies{RESET}")
                else:
                    print(f"{YELLOW}[EXECUTOR] Login that bai, crawl anonymous{RESET}")
            except Exception as e:
                print(f"{YELLOW}[EXECUTOR] Login error: {e}, crawl anonymous{RESET}")

        # ── Step 2: BrowserAgent BFS crawl ──
        try:
            print(f"{YELLOW}[EXECUTOR] BrowserAgent dang crawl...{RESET}")
            http_traffic, cookies, external = run_crawl(
                start_url=url,
                cookies=login_cookies,
                max_rounds=2,
                max_pages=50,
                headless=True,
                timeout=300,
            )
            print(f"{GREEN}[EXECUTOR] Crawl xong: {len(http_traffic)} requests, "
                  f"{len(cookies)} cookies, {len(external)} external links{RESET}")

            # ── Step 3: Format results ──
            formatted = format_http_traffic(http_traffic, cookies, external, url)
            result = (
                f"=========SEND=========\n"
                f"{formatted}\n"
                f"=========END-SEND=========\n\n"
                f"[REDTEAM]"
            )
            return result

        except Exception as e:
            print(f"{YELLOW}{BOLD}[EXECUTOR] BrowserAgent FAIL: {e}{RESET}")
            print(f"{YELLOW}[EXECUTOR] Fallback sang LLM crawl...{RESET}")
            return self._crawl_llm_fallback(user_prompt)

    def _login_only(self, target_url: str, credentials: dict) -> list[dict] | None:
        """Login via Python httpx (no LLM, no Playwright). Fast and reliable.

        Strategy:
        1. GET login page -> extract CSRF token
        2. POST credentials -> follow redirect
        3. Extract session cookies from response

        Args:
            target_url: Target base URL.
            credentials: {"username": ..., "password": ...}

        Returns:
            List of cookie dicts for BrowserAgent injection, or None if login fails.
        """
        domain = urlparse(target_url).netloc

        try:
            with httpx.Client(follow_redirects=True, timeout=15, verify=False) as client:
                # Step 1: Find login page
                login_paths = ["/login", "/my-account", "/account/login", "/signin"]
                login_url = None
                resp = None

                for path in login_paths:
                    try_url = urljoin(target_url, path)
                    resp = client.get(try_url)
                    if resp.status_code == 200 and ("password" in resp.text.lower()):
                        login_url = try_url
                        break

                if not login_url or not resp:
                    print(f"{YELLOW}[LOGIN] Khong tim thay trang login{RESET}")
                    return None

                # Step 2: Extract CSRF token
                csrf_token = None
                csrf_patterns = [
                    re.compile(r'name=["\']csrf["\'][\s\S]*?value=["\']([^"\']+)["\']'),
                    re.compile(r'value=["\']([^"\']+)["\'][\s\S]*?name=["\']csrf["\']'),
                    re.compile(r'name=["\']_token["\'][\s\S]*?value=["\']([^"\']+)["\']'),
                ]
                for pat in csrf_patterns:
                    m = pat.search(resp.text)
                    if m:
                        csrf_token = m.group(1)
                        break

                # Step 3: POST login
                post_data = {
                    "username": credentials["username"],
                    "password": credentials["password"],
                }
                if csrf_token:
                    post_data["csrf"] = csrf_token

                login_resp = client.post(login_url, data=post_data)

                # Step 4: Extract cookies
                all_cookies = []
                for cookie in client.cookies.jar:
                    all_cookies.append({
                        "name": cookie.name,
                        "value": cookie.value,
                        "domain": domain,
                        "path": cookie.path or "/",
                    })

                if all_cookies:
                    print(f"{GREEN}[LOGIN] Cookies: {[c['name'] for c in all_cookies]}{RESET}")
                    return all_cookies
                else:
                    print(f"{YELLOW}[LOGIN] Khong co cookies sau login{RESET}")
                    return None

        except Exception as e:
            print(f"{YELLOW}[LOGIN] Error: {e}{RESET}")
            return None

    def _crawl_llm_fallback(self, user_prompt: str) -> str:
        """Fallback: LLM crawl using Playwright MCP (old approach).

        Used when BrowserAgent fails (network error, timeout, etc.).
        """
        print(f"{YELLOW}[EXECUTOR] LLM crawl fallback...{RESET}")
        messages = [{"role": "system", "content": CRAWL_SYSTEM_PROMPT}]
        messages.append({
            "role": "user",
            "content": f"Crawl this target and collect all HTTP requests:\n\n{user_prompt}",
        })
        return self._tool_loop(messages)

    def process(self, conversation: list[dict], caller: str = "REDTEAM") -> str:
        """Phase 2: Execute command from Red/Blue team.

        Finds the PoC code from Red Team (skipping APPROVED/REJECTED messages)
        + the crawl context to avoid Executor re-crawling.

        Args:
            conversation: Full debate conversation.
            caller: Who called Executor — "REDTEAM" or "BLUETEAM".
                    Executor will end with [<caller>] tag to return control.

        Returns raw LLM output (contains SEND block + tag).
        """
        return_tag = f"[{caller}]"
        messages = [{"role": "system", "content": EXECUTOR_SYSTEM_PROMPT}]

        # Find the crawl result (first message with CRAWL)
        crawl_context = ""
        for msg in conversation:
            if "CRAWL" in msg["content"][:50]:
                crawl_context = msg["content"]
                break

        # Find the PoC/instruction to execute.
        # Strategy: find the last REDTEAM message that contains code (```python).
        # Fallback: last REDTEAM message. Then fallback: last BLUETEAM message.
        last_instruction = ""
        last_redteam_msg = ""
        for msg in reversed(conversation):
            content = msg["content"]
            speaker = msg.get("speaker", "")

            # Best: Red Team message with Python code
            if speaker == "REDTEAM" and "```python" in content:
                last_instruction = content
                break
            # Backup: any Red Team message
            if speaker == "REDTEAM" and not last_redteam_msg:
                last_redteam_msg = content
            # Skip Blue Team APPROVED/REJECTED messages — they're not instructions
            if speaker == "BLUETEAM":
                continue

        if not last_instruction:
            last_instruction = last_redteam_msg

        # If still nothing, use the very last message
        if not last_instruction and conversation:
            last_instruction = conversation[-1]["content"]

        # Build focused message: crawl context + specific instruction
        user_content = f"=== WORKSPACE DIRECTORY ===\n{self.working_dir}\nALL files MUST be saved inside this directory.\n\n"
        if self.target_url:
            user_content += f"=== TARGET URL ===\n{self.target_url}\n\n"
        if crawl_context:
            user_content += f"=== TARGET CONTEXT ===\n{crawl_context}\n\n"
        user_content += f"=== INSTRUCTION TO EXECUTE ===\n{last_instruction}\n\n"
        user_content += (
            "IMPORTANT: The instruction above contains Python code (inside ```python blocks). "
            "You MUST:\n"
            "1. Extract the Python code from the instruction.\n"
            "2. Save it to a .py file using your filesystem tools.\n"
            "3. Run it with: execute_command python3 <filename>.py\n"
            "4. Report the FULL output (stdout + stderr).\n"
            "Do NOT rewrite the code. Do NOT use browser tools to manually replicate what the code does. "
            "Just save and run the code AS-IS.\n"
        )
        user_content += f"When done, put results in a SEND block and end with {return_tag}."

        messages.append({"role": "user", "content": user_content})

        return self._tool_loop(messages, default_tag=caller)

    def answer(self, conversation: list[dict], caller: str = "REDTEAM") -> str:
        """Answer a question from Red/Blue team based on crawl data + tools if needed.

        Args:
            conversation: Full debate conversation.
            caller: Who asked the question — "REDTEAM" or "BLUETEAM".

        Returns raw LLM output (contains SEND block + tag).
        """
        return_tag = f"[{caller}]"
        messages = [{"role": "system", "content": ANSWER_SYSTEM_PROMPT}]

        # Find the crawl result (first message with CRAWL)
        crawl_context = ""
        for msg in conversation:
            if "CRAWL" in msg["content"][:50]:
                crawl_context = msg["content"]
                break

        # Find the LAST message = the question being asked
        last_question = ""
        if conversation:
            last_question = conversation[-1]["content"]

        # Build focused message: crawl context + question
        user_content = ""
        if self.target_url:
            user_content += f"=== TARGET URL ===\n{self.target_url}\nALL browser/fetch requests MUST use this URL as the base. Do NOT use localhost.\n\n"
        if crawl_context:
            user_content += f"=== TARGET CRAWL DATA ===\n{crawl_context}\n\n"
        user_content += f"=== QUESTION ===\n{last_question}\n\n"
        user_content += f"Answer the question above. When done, put your answer in a SEND block and end with {return_tag}."

        messages.append({"role": "user", "content": user_content})

        return self._tool_loop(messages, default_tag=caller)

    def filter_traffic(self, raw_traffic: str) -> str:
        """Filter and rank raw crawl traffic using LLM reasoning (no tools).

        Args:
            raw_traffic: Raw HTTP traffic text from crawl phase.

        Returns:
            Filtered + ranked traffic as text (contains SEND block).
        """
        messages = [
            {"role": "system", "content": FILTER_SYSTEM_PROMPT},
            {"role": "user", "content": f"Filter and rank the following crawl data:\n\n{raw_traffic}"},
        ]

        try:
            resp = self.client.chat.completions.create(
                model=MODEL,
                messages=messages,
                temperature=0.3,
                max_tokens=8192,
            )
            result = resp.choices[0].message.content or ""
            return result
        except Exception as e:
            print(f"{YELLOW}[EXECUTOR] Filter failed: {e} — returning raw traffic{RESET}")
            return raw_traffic

    def shutdown(self):
        """Clean up MCP servers."""
        print(f"{YELLOW}[EXECUTOR] Shutting down MCP...{RESET}")
        self.mcp.stop_all()
        print(f"{YELLOW}[EXECUTOR] Done.{RESET}")

    # ─── Internal tool-calling loop ───────────────────────────────

    def _tool_loop(self, messages: list[dict], default_tag: str = "REDTEAM") -> str:
        """Run tool calls until LLM produces text with a tag ([REDTEAM]/[BLUETEAM]).

        Args:
            messages: LLM messages list.
            default_tag: Tag to use in nudges/fallbacks (e.g. "REDTEAM" or "BLUETEAM").

        Simple logic (same pattern as toaan.py _call_llm, but with tool support):
        1. Call LLM with tools.
        2. If response has tool_calls → execute them → append results → loop.
        3. If response is text → check for tag → if tag found, return.
        4. If text but no tag → append as assistant, add nudge, loop.
        """
        consecutive_errors = 0
        tool_count = 0
        nudge_count = 0
        max_nudges = 3  # max times we nudge before forcing a tag
        consecutive_repeats = 0       # đếm tool call lặp lại liên tiếp
        last_tool_signature = None    # (fn_name, fn_args_str) của tool call trước
        MAX_CONSECUTIVE_REPEATS = 3   # sau 3 lần lặp → can thiệp

        for round_idx in range(MAX_TOOL_ROUNDS):
            try:
                # Force tool use on first round to avoid "planning" responses
                tool_choice = "required" if round_idx == 0 and self.tools else "auto"

                response = self.client.chat.completions.create(
                    model=MODEL,
                    messages=messages,
                    tools=self.tools if self.tools else None,
                    tool_choice=tool_choice if self.tools else None,
                    temperature=0.3,
                    max_tokens=4096,
                )
            except Exception as e:
                consecutive_errors += 1
                print(f"{DIM}[EXECUTOR] API error ({consecutive_errors}): {e}{RESET}")
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                    return f"[API Error after {consecutive_errors} retries: {e}]\n[{default_tag}]"
                continue

            consecutive_errors = 0
            choice = response.choices[0]
            msg = choice.message

            # ── Tool calls: execute and continue ──
            if msg.tool_calls:
                # Append assistant message with tool calls
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

                    # ── Detect repeated tool calls ──
                    tool_sig = (fn_name, tc.function.arguments)
                    if tool_sig == last_tool_signature:
                        consecutive_repeats += 1
                    else:
                        consecutive_repeats = 0
                        last_tool_signature = tool_sig

                    print(f"{DIM}[EXECUTOR] Tool {tool_count}: {fn_name}({json.dumps(fn_args, ensure_ascii=False)[:120]}){RESET}")

                    try:
                        result = self.mcp.execute_tool(fn_name, fn_args)
                        result_text = _truncate(str(result))
                        consecutive_errors = 0
                    except Exception as e:
                        result_text = f"Error: {e}"
                        consecutive_errors += 1

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": result_text,
                    })

                # ── Break out of repeated tool call loops ──
                if consecutive_repeats >= MAX_CONSECUTIVE_REPEATS:
                    print(f"{YELLOW}[EXECUTOR] Detected {consecutive_repeats + 1}x repeated tool call: {last_tool_signature[0]}. Forcing summary.{RESET}")
                    messages.append({
                        "role": "user",
                        "content": (
                            f"STOP. You have called {last_tool_signature[0]} with the SAME arguments "
                            f"{consecutive_repeats + 1} times in a row. This is a loop. "
                            "Do NOT call this tool again. Move on to the next step, "
                            "or if you have enough data, summarize everything you found so far "
                            f"inside a =========SEND========= block and end with [{default_tag}]."
                        ),
                    })
                    consecutive_repeats = 0

                # If tools keep failing, force LLM to stop and summarize
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                    messages.append({
                        "role": "user",
                        "content": (
                            f"The last {MAX_CONSECUTIVE_ERRORS} tool calls FAILED. "
                            "STOP retrying. Summarize what you have collected so far "
                            f"inside a =========SEND========= block and end with [{default_tag}]."
                        ),
                    })
                    consecutive_errors = 0

                nudge_count = 0  # reset nudge counter after tool use

                # ── Approaching limit: force LLM to summarize ──
                if round_idx >= MAX_TOOL_ROUNDS - 3:
                    messages.append({
                        "role": "user",
                        "content": (
                            "IMPORTANT: You are running out of tool rounds. "
                            "STOP using tools NOW. Summarize everything you found so far "
                            f"inside a =========SEND========= block and end with [{default_tag}]."
                        ),
                    })

                continue  # back to top of loop

            # ── Text response: check for tag ──
            text = msg.content or ""
            tag = extract_next_tag(text)

            if tag:
                # LLM is done — return full text
                return text

            # No tag — LLM spoke but didn't signal completion.
            nudge_count += 1
            if nudge_count >= max_nudges:
                # Force end — append tag ourselves
                return text + f"\n[{default_tag}]"

            # Append and nudge it to continue working.
            messages.append({"role": "assistant", "content": text})
            messages.append({
                "role": "user",
                "content": f"Continue. Use your tools to complete the task. When done, put results in a SEND block and end with [{default_tag}].",
            })

        # Max rounds hit
        return f"[Executor reached {MAX_TOOL_ROUNDS} tool rounds limit]\n[{default_tag}]"
