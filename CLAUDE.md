# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MARL is an authorized penetration testing tool that uses LLM-powered multi-agent debate to generate and validate Proof-of-Concept exploits for web application vulnerabilities (BAC — Broken Access Control, BLF — Business Logic Flaw). All prompts, system messages, and terminal output are in Vietnamese.

## Running

### Start the proxy server (must be running first)
```bash
python server/server.py
# Runs on http://127.0.0.1:5000 by default. Set PORT env var to change.
```

### Run the main pipeline
```bash
python main.py
python main.py "Test https://target.com user:admin pass:secret"
```

### Run standalone agents
```bash
python agents/crawl_agent.py "https://target.com/"
python agents/crawl_agent.py "https://target.com/ credentials: admin:password"
```

### Run legacy debate modules (in test/)
```bash
python test/debate.py       # Tag-driven debate (legacy, incompatible message format)
python test/giaotiep.py     # Round-based debate (simpler, human-in-the-loop)
python test/toaan.py        # Courtroom roleplay simulation (unrelated to pentest)
```

### Alternative backend
```bash
python main_trollllm.py     # Same 5-phase pipeline but uses TrollLLM API instead of Copilot proxy
```

### Dependencies
```bash
pip install fastapi uvicorn httpx openai mcp ddgs readabilipy playwright python-dotenv
npx playwright install  # browser binaries for Playwright
npm install -g @modelcontextprotocol/server-filesystem @playwright/mcp
```

### Debug mode
```bash
MARL_DEBUG=1 python agents/crawl_agent.py "https://target.com/"
# Enables verbose output in CrawlAgent: HTTP traffic breakdown, cookie diffs, CSRF extraction details
```

## Architecture

### Pipeline Flow (`main.py`)
```
Phase 1: RECON
  CrawlAgent: anonymous BFS crawl → login via httpx → authenticated crawl
  → LLM analyzes traffic → writes workspace/recon.md

Phase 2: DEBATE (max 30 steps, max 5 reject/revise rounds)
  ManageAgent orchestrates: Red writes strategy → Blue reviews
  → ManageAgent infers intent (APPROVE/REVISE/STOP) from content
  → Blue approval gates execution

Phase 3: EXECUTION
  ExecAgent generates a Python exploit for the approved strategy
  → py_compile → run script → save artifacts → self-verify with FINAL/result.json

Phase 4: MANAGER DECISION
  ManageAgent reads Exec output/result.json
  → EXPLOITED goes NEXT_BUG, SCRIPT_ERROR/PARTIAL retries once, FAILED stops bug

Phase 5: REPORT
  Generate workspace/report.md/report_final_vi.md with findings and false-positive candidates
```

ManageAgent handles retries per bug inside the tick loop. Exec retry is capped to one retry by default.

### Guardrails

- **Blue strategy gate**: Exec only runs after the current Red strategy has Blue approval.
- **Current workflow scoping**: Manager uses the current in-memory strategy, not a stale strategy from an older bug.

### Logging

`TeeLogger` in `main.py` mirrors all stdout/stderr to `{run_dir}/marl.log` (ANSI codes stripped, each line timestamped). Flushed with `os.fsync()` after every write — survives Ctrl+C.

### Workspace Outputs

Each run creates `workspace/{domain}_{YYYYMMDD_HHMMSS}/` (gitignored):
- `recon.md` — CrawlAgent's reconnaissance report (Phase 1)
- `report.md` / `report_final_vi.md` — final report with exploited findings and false-positive candidates
- `marl.log` — full session log with timestamps
- PoC scripts and evidence files created by ExecAgent during Phase 3

All agent file I/O (filesystem MCP, shell) is scoped to this run directory.

### Agent Isolation Model

Agents operate in **isolation** — each agent works in its own "room" and does not know other agents exist. Red Team does not know about Blue Team or ExecAgent. Blue Team does not know about Red Team or ExecAgent. ExecAgent does not know about Red/Blue. ManageAgent is the **sole orchestrator** that bridges communication between agents. This prevents agents from bypassing the debate process (e.g., Red directly commanding ExecAgent to run exploits) and keeps each agent focused on its specific role.

### Conversation Format and Message Flow

The conversation is a shared list of dicts passed across all phases:

```python
{"speaker": "REDTEAM" | "BLUETEAM" | "AGENT" | "USER" | "SYSTEM", "content": "[SPEAKER]: <text>"}
```

Each agent's `_build_messages()` converts this to OpenAI format:
- Own speaker → `role: "assistant"`
- All other speakers → `role: "user"`
- **Must append a synthetic `user` message if the last message isn't `user` role** (Copilot API requirement — the upstream rejects requests where the final message is `assistant`)

Legacy modules in `test/` use `{"role": ..., "content": ...}` format and are incompatible.

### Intent-Based Routing

Red/Blue agents no longer emit routing tags. ManageAgent reads the **content** of each response to determine intent via `_infer_dialog_intent()` in `manage_agent.py`. This function uses keyword analysis (primary) with tag detection as fallback — if an LLM still emits a tag, it's honored but not required.

| Intent | Keywords detected | Action |
|---|---|---|
| APPROVE | "approved", "đồng ý", "chấp thuận" (Blue only) | ManageAgent triggers `EXECUTE_BUG` |
| REVISE | "reject", "chưa đủ", "không đồng ý" (Blue only) | ManageAgent routes back to Red |
| STOP | "stopped", "không khả thi", "out of scope" | ManageAgent stops current bug |
| NONE | Default / strategy text | ManageAgent decides via LLM or shortcut logic |

`extract_next_tag()` and `normalize_routing_tags()` in `shared/utils.py` still exist for ExecAgent's SEND block parsing and as fallback in `_infer_dialog_intent()`.

### SEND Block Pattern

ExecAgent wraps its substantive output in delimiters that `extract_send_block()` can parse:
```
=========SEND=========
<actual payload>
=========END-SEND=========
```
Regex requires at least 5 `=` on each side. This lets the LLM add commentary outside the block without breaking downstream parsing.

### Tool Loop Safety (`_tool_loop` in ExecAgent/CrawlAgent)

Both agents share the same `_tool_loop` pattern with safety mechanisms:
- **Round 0**: `tool_choice="required"` forces immediate tool use (prevents planning monologues)
- **Repeated call detection**: 3 identical tool calls → inject "STOP" message forcing summary
- **Consecutive errors**: 3 tool failures → inject message forcing summary
- **Nudge counter**: 3 text responses without a tag → force-append tag
- **Approaching limit**: Round ≥ (MAX_TOOL_ROUNDS - 3) → inject "running out of rounds" nudge
- Timeouts: 300s for shell tools, 120s for all others

### Agent Details

**CrawlAgent** (`agents/crawl_agent.py`): Runs `tools/crawler.py` as a subprocess (JSON to stdout, logs to stderr). Two-pass crawl: anonymous → login (httpx finds `/login` from 4 candidate paths, extracts CSRF with 3 regex patterns, POSTs credentials) → authenticated. LLM analyzes both passes using filesystem MCP tools → writes `workspace/recon.md`. Uses `[DONE]` tag (not debate tags). Has shell + fetch + filesystem MCP tools (no Playwright/web_search).

**ExecAgent** (`agents/exec_agent.py`): Main execution modes:
- `answer()` → `ANSWER_SYSTEM_PROMPT`: answers Red/Blue questions using MCP tools
- `execute()` → `EXECUTE_SYSTEM_PROMPT`: extracts PoC Python code → saves → runs
- `run_workflow()` → **Two-phase execution**:
  - Phase 1 (SESSION PREP): reuse crawl cookies/base session first, then deterministic HTTP login, then browser fallback if needed.
  - Phase 2 (EXPLOIT): generate a Python exploit for the approved strategy, run `py_compile`, execute it, save artifacts, and let the script self-verify via `FINAL`/`result.json`.

Has all 5 MCP tools: shell, browser (Playwright), fetch, filesystem, web search (DuckDuckGo). Runtime hot path no longer has a separate post-Exec verifier; Manager reads Exec's self-verified output directly.

**RedTeamAgent** (`agents/red_team.py`): Writes numbered attack workflows ("CHIEN LUOC") with login, CSRF, verify steps and an `EXECUTION SHOT PLAN`. System prompt is baked at init with target_url + recon_context + BAC/BLF playbook from `knowledge/bac_blf_playbook.py` (17 patterns: 8 BAC + 9 BLF). Truncates messages over `MAX_MSG_CHARS` (6000 chars). No MCP tools — text-only LLM calls. **No routing tags** — ManageAgent reads response content to determine intent. `respond()` calls LLM once and returns text directly (no retry loop).

**BlueTeamAgent** (`agents/blue_team.py`): Reviews Red's strategy against criteria before Exec runs. System prompt also bakes playbook. Same `MAX_MSG_CHARS` (6000) truncation. No MCP tools — text-only LLM calls. **No routing tags** — ManageAgent reads response content to determine intent (APPROVE/REVISE/STOP). `respond()` calls LLM once and returns text directly (no retry loop). Blue does not review post-Exec evidence.

**ManageAgent** (`agents/manage_agent.py`): LLM-driven orchestrator that replaces the hand-coded retry loop in `main.py`. ManageAgent is called on every tick and decides which action to take next by emitting one of these tags: `DEBATE_RED`, `DEBATE_BLUE`, `EXECUTE_BUG`, `RETRY_RED`, `RETRY_BLUE`, `RETRY_EXEC`, `STOP_BUG`, `NEXT_BUG`, `REPORT_SUCCESS`, `REPORT_FAIL`. Uses `_infer_dialog_intent()` to read Red/Blue response content and route accordingly. All child agents are invoked only through ManageAgent — no agent calls another agent directly. After Exec runs, Manager reads `FINAL`, `SUCCESS`, `result.json`, and evidence summary directly, then decides `EXPLOITED`, retry, or stop. Controlled by `MARL_MANAGER_MODEL` and capped at `MAX_TICKS` (60) total pipeline ticks.

### MCP Client (`mcp_client.py`)

Runs a background asyncio event loop in a daemon thread. Manages up to 5 MCP servers:
1. **Filesystem** (`npx @modelcontextprotocol/server-filesystem`) — whitelisted to 5 tools: `read_text_file`, `write_file`, `edit_file`, `list_directory`, `search_files`
2. **Shell** (`python -m mcp_server_shell`)
3. **Fetch** (`python -m mcp_server_fetch --ignore-robots-txt`) — pre-installs readabilipy node deps to avoid npm stdout pollution
4. **Playwright** (`npx @playwright/mcp --headless`)
5. **Web search** — built-in virtual tool using `ddgs` library (DuckDuckGo, no API key). Has HTML lite fallback.

Schema descriptions are truncated (tool desc → 150 chars, property desc → 80 chars) to save tokens. Synchronous wrappers (`_run_async`) bridge the async MCP calls.

### BFS Crawler (`tools/crawler.py`)

Playwright-based BFS crawler with HTTP traffic interception. CLI tool: JSON to stdout, logs to stderr.
- CLI args: `--url`, `--max-pages` (default 50), `--max-rounds` (default 2), `--timeout` (default 300), `--headless`, `-H` (inject headers like `Cookie:`)
- Intercepts same-domain requests (skips images/stylesheets/fonts), caps response bodies at 2000 chars
- Performs actions: clicks buttons, submits forms with smart dummy data (email→`test@example.com`, password→`Test123!`)
- Blacklists destructive URLs containing: logout, delete, signout, exit, quit, destroy, remove
- `run_crawl()` sync wrapper runs in a separate thread to avoid asyncio event loop conflicts

### Proxy Server (`server/server.py`)

FastAPI proxy: OpenAI SDK → GitHub Copilot endpoints (`api.individual.githubcopilot.com`).
- Accepts GitHub `gho_*` tokens directly via Authorization header
- Caches Copilot session tokens (double-check locking, 1h TTL)
- Exponential backoff retry (3 attempts, 2s base, retryable statuses: 429, 500, 502, 503, 504) with automatic token refresh on 401
- Upstream timeouts: connect=15s, read=300s, write=15s, pool=15s
- Strips Copilot-specific metadata for SDK compatibility; supports SSE streaming
- **GPT Codex routing**: models in `GPT_CODEX_RESPONSES_MODELS` (e.g. `gpt-5.1-codex-mini`, `gpt-5.4`) are routed to Copilot's `/responses` endpoint (Responses API) instead of `/chat/completions`. The proxy converts the request/response format transparently.

### Knowledge Base (`knowledge/bac_blf_playbook.py`)

Contains 17 attack pattern templates (8 BAC, 9 BLF) used by Red and Blue Team system prompts. Each pattern has: ID, name, indicators (what to look for in recon data), attack steps, and verification criteria. `get_playbook_text()` returns the full text. Red uses patterns to write strategies; Blue uses them to validate strategies.

## Environment Variables

| Variable | Default | Used in |
|---|---|---|
| `GITHUB_TOKEN` | `gho_token` (placeholder) | all modules |
| `MARL_SERVER_URL` | `http://127.0.0.1:5000/v1` | agents, main.py |
| `MARL_CRAWL_MODEL` | inherits `MARL_EXECUTOR_MODEL` | crawl_agent.py |
| `MARL_EXECUTOR_MODEL` | `gpt-4.1` | exec_agent.py |
| `MARL_RED_MODEL` | `gpt-5-mini` | red_team.py |
| `MARL_BLUE_MODEL` | `gpt-5-mini` | blue_team.py |
| `MARL_MANAGER_MODEL` | `gpt-5-mini` | manage_agent.py |
| `MARL_DEBUG` | (unset) | crawl_agent.py (set to `1`/`true`/`yes` for verbose) |
| `PORT` | `5000` | server/server.py |

All agents load `.env` from project root via `python-dotenv`.

## Key Constants

| Constant | Value | Location | Purpose |
|---|---|---|---|
| `MAX_DEBATE_STEPS` | 30 | main.py | Total turns in debate phase |
| `MAX_ROUNDS` | 5 | main.py | Red↔Blue reject/revise cycles |
| `MAX_EXEC_RETRIES` | 1 | main.py/manage_agent.py | Retry attempts after execution failure |
| `MAX_TICKS` | 60 | manage_agent.py | Total pipeline ticks for ManageAgent |
| `MIN_DEBATE_ROUNDS` | 0 | main.py/manage_agent.py | Deterministic Red→Blue gate handles minimum flow |
| `MAX_TOOL_ROUNDS` | 30 | exec_agent.py | Tool calls per ExecAgent answer/execute |
| `MAX_WORKFLOW_LOGIN_ROUNDS` | 8 | exec_agent.py | Login/session-prep fallback rounds |
| `MAX_TOOL_ROUNDS` | 30 | crawl_agent.py | Tool calls per CrawlAgent invocation |
| `MAX_CONSECUTIVE_ERRORS` | 3 | exec_agent, crawl_agent | Tool failures before forcing summary |
| `MAX_CONSECUTIVE_REPEATS` | 3 | exec_agent.py | Identical tool calls before breaking loop |
| ~~MAX_TAG_RETRIES~~ | ~~2~~ | ~~red_team, blue_team~~ | Removed — routing tags no longer required |
| `MAX_MSG_CHARS` | 6000 | red_team, blue_team | Message truncation in `_build_messages()` |
| `TRUNCATE_LIMIT` | 15000 | shared/utils.py | Output truncation threshold |
| LLM `temperature` | 0.3 | exec_agent, crawl_agent, blue_team | |
| LLM `temperature` | 0.4 | red_team.py | Slightly higher creativity for Red |
| LLM `max_tokens` | 4096 | exec_agent, red_team, blue_team | |
| LLM `max_tokens` | 8192 | crawl_agent.py | Larger for recon analysis |

## Additional Shared Modules (not yet in main pipeline)

### PolicyAgent (`agents/policy_agent.py`)
Two-phase guardrail that runs **before** ManageAgent executes each action:
1. **Hard rules** (no LLM): validates actions against `VALID_ACTIONS` set, checks state fields (`tick`, `round_num`, `exec_attempts`, `has_workflow`, `has_exec`, `red_spoke`). For recoverable states (e.g. EXECUTE before workflow exists), returns SUGGEST with a fallback action instead of hard BLOCK to prevent infinite loops. Hard BLOCK is reserved for truly invalid transitions (e.g. RETRY_DEBATE before any execution).
2. **LLM semantic check**: sends 6 recent messages + state JSON to an LLM (low temperature 0.1, max 256 tokens) — detects semantic violations like executing after a fresh Blue reject, or infinite loops. Fails **open** on parse error (returns ALLOW).

Returns `PolicyVerdict(verdict, reason, suggested_action)`. Verdict is one of `ALLOW / BLOCK / SUGGEST`. Only wired into `ManageAgent` (not `main.py`'s hand-coded pipeline).

### ContextManager (`shared/context_manager.py`)
Conversation compression for long runs. Called per tick inside ManageAgent:
- `compress_if_needed(conversation, trigger_len=20, keep_recent=6)`: if the conversation exceeds `trigger_len` messages, LLM-summarises the oldest `n - 6` messages, saves them to MemoryStore, and replaces them with a single `SYSTEM` summary message. Modifies the list **in-place** and returns it.
- `get_context_for_agent(agent_id, conversation, keywords)`: assembles a summary + relevant MemoryStore findings block to prepend to an agent's prompt.

### MemoryStore (`shared/memory_store.py`)
File-backed persistent store scoped to `{run_dir}/memory/`. Never crashes the pipeline (all I/O is try/except). Files:
- `task_registry.json` — structured task tracking (`register_task`, `update_task`, `list_tasks`)
- `findings.json` — typed facts (`add_finding(category, key, value, agent)`, canonical categories: `endpoint / credential / vulnerability / note`)
- `conversation_full.jsonl` — append-only full log (`append_message`)
- `conversation_summary.md` — rolling LLM-generated summary (`update_summary` / `get_summary`)
- `scratchpad/{agent}_notes.json` — per-agent key-value notes (`scratchpad_write`, `scratchpad_read`, `scratchpad_search`)

`get_relevant_context(agent, keywords, max_chars=2000)` does keyword search across findings + scratchpad + summary to build a RAG-style context block.

### Multi-account credentials (`shared/utils.py`)
`ParsedTarget` TypedDict supports multiple accounts: `{url, credentials: [{label, username, password}], focus}`. `parse_prompt_llm(user_prompt, client)` uses an LLM call to extract structured credentials from free-text prompts. `parse_prompt()` is the regex-based fallback used in `main.py`.

## Known Issues

- `mcp_client.py` has unreachable code after `return results` in `_ddg_search_html_fallback()` (lines 310-313)
- `strip_tag()` is duplicated — exists in both `shared/utils.py` (uses `TAG_PATTERN.sub()`) and `main.py` (different regex with `re.IGNORECASE` and `AGENT(?::run)?` variant)
- Legacy modules in `test/` hardcode GitHub tokens instead of using env vars
- `test/debate.py` conversation format (`role`-based) is incompatible with `agents/` format (`speaker`-based)
- No explicit token counting — relies on upstream truncation; large `recon.md` can fill context quickly
- CrawlAgent's httpx login only tries 4 hardcoded paths (`/login`, `/my-account`, `/account/login`, `/signin`); sites with non-standard login URLs will fail
- ExecAgent's exploit phase removes Playwright from tool list to force curl usage, but `answer()` and `execute()` modes still have browser tools and may waste tokens on Playwright calls
