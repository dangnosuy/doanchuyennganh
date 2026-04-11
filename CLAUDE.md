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
  Red Team writes attack workflow (can ask ExecAgent via [AGENT] tag)
  → Blue Team reviews against criteria
  → [APPROVED] or [REDTEAM] (reject) or [AGENT] (verify)

Phase 3: EXECUTION
  ExecAgent executes approved workflow step-by-step via MCP tools

Phase 4: EVALUATION (max 5 eval steps)
  Red Team evaluates results → [DONE] or [BLUETEAM] (new strategy, up to 2 retries)
  Red can call [AGENT] for read-only verification (VERIFY_SYSTEM_PROMPT)

Phase 5: REPORT
  Generate workspace/report.md with verdict, workflow, execution output
```

The outer loop retries Phases 2–4 up to `MAX_EXEC_RETRIES + 1` (3) times if Red requests a new strategy. The conversation accumulates across retries.

### Guardrails

- **MIN_DEBATE_ROUNDS (2)**: Blue's `[APPROVED]` is blocked if fewer than 2 Red↔Blue rounds have completed. The orchestrator injects a `SYSTEM` message telling Blue to keep reviewing.
- **Workflow extraction**: `_extract_last_workflow()` scans the conversation backwards for Red's most recent message containing keywords (`chiến lược`, `workflow`, `attack plan`, `bước 1`, etc.). Falls back to the last Red message.

### Logging

`TeeLogger` in `main.py` mirrors all stdout/stderr to `{run_dir}/marl.log` (ANSI codes stripped, each line timestamped). Flushed with `os.fsync()` after every write — survives Ctrl+C.

### Workspace Outputs

Each run creates `workspace/{domain}_{YYYYMMDD_HHMMSS}/` (gitignored):
- `recon.md` — CrawlAgent's reconnaissance report (Phase 1)
- `report.md` — final penetration test report with verdict, workflow, execution output, Red evaluation (Phase 5)
- `marl.log` — full session log with timestamps
- PoC scripts and evidence files created by ExecAgent during Phase 3

All agent file I/O (filesystem MCP, shell) is scoped to this run directory.

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

### Tag-Driven Routing

Agents signal the next handler via tags at the end of their response. `extract_next_tag()` in `shared/utils.py` finds all tags matching `\[(TAG)\]\s*$` (multiline regex), then returns the **highest-priority** one: AGENT > DONE > APPROVED > REDTEAM > BLUETEAM > USER. This means `[APPROVED]` + `[AGENT]` in the same message → returns `"AGENT"` (agent runs first).

| Tag | Meaning | Emitted by |
|---|---|---|
| `[AGENT]` | Ask ExecAgent a question | Red, Blue |
| `[REDTEAM]` | Pass turn to Red Team | Blue (reject) |
| `[BLUETEAM]` | Pass turn to Blue Team | Red (submit for review) |
| `[APPROVED]` | Approve workflow → trigger execution | Blue |
| `[DONE]` | Exploitation complete | Red (after evaluation) |

If the LLM forgets a tag, agents retry up to `MAX_TAG_RETRIES` (2) times with a nudge, then force-append the expected tag (Red→`[BLUETEAM]`, Blue→`[REDTEAM]`).

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

**ExecAgent** (`agents/exec_agent.py`): Four system prompts for different modes:
- `answer()` → `ANSWER_SYSTEM_PROMPT`: answers Red/Blue questions using MCP tools
- `answer(read_only=True)` → `VERIFY_SYSTEM_PROMPT`: Phase 4 read-only verification (no POST/exploit)
- `execute()` → `EXECUTE_SYSTEM_PROMPT`: extracts PoC Python code → saves → runs
- `run_workflow()` → `WORKFLOW_SYSTEM_PROMPT`: step-by-step execution with evidence capture

Has all 5 MCP tools: shell, browser (Playwright), fetch, filesystem (5 whitelisted tools), web search (DuckDuckGo).

**RedTeamAgent** (`agents/red_team.py`): Writes numbered attack workflows ("CHIEN LUOC") with login, CSRF, verify steps. System prompt is baked at init with target_url + recon_context + BAC/BLF playbook from `knowledge/bac_blf_playbook.py` (17 patterns: 8 BAC + 9 BLF). Truncates messages over `MAX_MSG_CHARS` (6000 chars). No MCP tools — text-only LLM calls.

**BlueTeamAgent** (`agents/blue_team.py`): Reviews Red's strategy against criteria. System prompt also bakes playbook. Can call `[AGENT]` to verify endpoints. Same `MAX_MSG_CHARS` (6000) truncation. No MCP tools — text-only LLM calls.

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
| `MARL_DEBUG` | (unset) | crawl_agent.py (set to `1`/`true`/`yes` for verbose) |
| `PORT` | `5000` | server/server.py |

All agents load `.env` from project root via `python-dotenv`.

## Key Constants

| Constant | Value | Location | Purpose |
|---|---|---|---|
| `MAX_DEBATE_STEPS` | 30 | main.py | Total turns in debate phase |
| `MAX_ROUNDS` | 5 | main.py | Red↔Blue reject/revise cycles |
| `MAX_EXEC_RETRIES` | 2 | main.py | Retry attempts after execution failure |
| `MIN_DEBATE_ROUNDS` | 2 | main.py | Minimum Red↔Blue rounds before approve allowed |
| `MAX_TOOL_ROUNDS` | 50 | exec_agent.py | Tool calls per ExecAgent invocation |
| `MAX_TOOL_ROUNDS` | 30 | crawl_agent.py | Tool calls per CrawlAgent invocation |
| `MAX_CONSECUTIVE_ERRORS` | 3 | exec_agent, crawl_agent | Tool failures before forcing summary |
| `MAX_CONSECUTIVE_REPEATS` | 3 | exec_agent.py | Identical tool calls before breaking loop |
| `MAX_TAG_RETRIES` | 2 | red_team, blue_team | Nudges before force-appending tag |
| `MAX_MSG_CHARS` | 6000 | red_team, blue_team | Message truncation in `_build_messages()` |
| `TRUNCATE_LIMIT` | 15000 | shared/utils.py | Output truncation threshold |
| `max_eval_steps` | 5 | main.py `phase_evaluate()` | Max Agent calls during evaluation |
| LLM `temperature` | 0.3 | exec_agent, crawl_agent, blue_team | |
| LLM `temperature` | 0.4 | red_team.py | Slightly higher creativity for Red |
| LLM `max_tokens` | 4096 | exec_agent, red_team, blue_team | |
| LLM `max_tokens` | 8192 | crawl_agent.py | Larger for recon analysis |

## Known Issues

- `mcp_client.py` has unreachable code after `return results` in `_ddg_search_html_fallback()` (lines 310-313)
- `strip_tag()` is duplicated — exists in both `shared/utils.py` (uses `TAG_PATTERN.sub()`) and `main.py` (different regex with `re.IGNORECASE` and `AGENT(?::run)?` variant)
- Legacy modules in `test/` hardcode GitHub tokens instead of using env vars
- `test/debate.py` conversation format (`role`-based) is incompatible with `agents/` format (`speaker`-based)
- No explicit token counting — relies on upstream truncation; large `recon.md` can fill context quickly
- No `requirements.txt` / `pyproject.toml` — dependencies are undeclared
- CrawlAgent's httpx login only tries 4 hardcoded paths (`/login`, `/my-account`, `/account/login`, `/signin`); sites with non-standard login URLs will fail
- ExecAgent system prompts warn about `fetch()` being stateless (no cookies) — this is a recurring source of bugs where the LLM uses fetch instead of curl for authenticated requests
