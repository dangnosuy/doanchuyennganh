# AGENTS.md

Guidance for AI coding agents working in the MARL repository.
MARL is an LLM-powered multi-agent penetration testing tool using Red/Blue Team debate.
All user-facing output and system prompts are in Vietnamese.

## Build & Run Commands

```bash
# Start the proxy server (must be running before main pipeline)
python server/server.py                # default port 5000; set PORT env var to change

# Run the main pipeline
python main.py
python main.py "Test https://target.com user:admin pass:secret"

# Run standalone agents
python agents/crawl_agent.py "https://target.com/"
python agents/crawl_agent.py "https://target.com/ credentials: admin:password"

# Run with alternative backend
python main_trollllm.py

# Debug mode (verbose crawl output)
MARL_DEBUG=1 python agents/crawl_agent.py "https://target.com/"
```

### Dependencies

```bash
pip install fastapi uvicorn httpx openai mcp ddgs readabilipy playwright python-dotenv
npx playwright install
npm install -g @modelcontextprotocol/server-filesystem @playwright/mcp
```

No `requirements.txt` or `pyproject.toml` exists. No linter, formatter, or type-checker is configured.

### Tests

There is no test suite. Files in `test/` are legacy/standalone modules, not automated tests:
- `test/debate.py` — tag-driven debate (incompatible message format)
- `test/giaotiep.py` — round-based debate with human-in-the-loop
- `test/toaan.py` — courtroom roleplay simulation (unrelated to pentest)

To run legacy modules: `python test/debate.py`, `python test/giaotiep.py`, etc.

## Project Structure

```
MARL/
├── main.py              # 5-phase orchestrator (recon → debate → execute → evaluate → report)
├── main_trollllm.py     # Same pipeline, TrollLLM backend
├── mcp_client.py        # MCP server manager (5 servers: filesystem, shell, fetch, playwright, web_search)
├── agents/
│   ├── crawl_agent.py   # BFS crawl + LLM analysis → recon.md
│   ├── exec_agent.py    # Tool-calling agent (4 modes: answer, verify, execute, workflow)
│   ├── red_team.py      # Attack strategy writer (text-only, no tools)
│   └── blue_team.py     # Strategy reviewer (text-only, no tools)
├── shared/
│   └── utils.py         # Regex patterns, text extraction, prompt parsing (stdlib only)
├── knowledge/
│   └── bac_blf_playbook.py  # 17 attack patterns (8 BAC + 9 BLF)
├── server/
│   ├── server.py        # FastAPI proxy: OpenAI SDK → GitHub Copilot API
│   └── server_trollllm.py
├── tools/
│   └── crawler.py       # Playwright BFS crawler (CLI: JSON to stdout, logs to stderr)
├── test/                # Legacy standalone modules, NOT automated tests
└── workspace/           # Gitignored per-run output directories
```

## Code Style

### Python Version

Python 3.10+ required. Uses `str | None` union syntax (PEP 604), `tuple[str | None, dict | None]` (PEP 585).

### Formatting

No formatter (black/ruff) is configured. Observed conventions:
- **4-space indentation** throughout
- **Double quotes** for strings (predominant), single quotes also used occasionally
- **Max line length**: not enforced, lines commonly reach 100-120+ characters
- **Trailing commas**: inconsistent; not required

### Imports

Three groups, though blank-line separation between groups is inconsistent:

1. **Stdlib**: `import os`, `import re`, `import json`, `import sys`, `from pathlib import Path`, `from typing import ...`
2. **Third-party**: `import httpx`, `from openai import OpenAI`, `from fastapi import ...`
3. **Local**: Always preceded by `sys.path` manipulation:
   ```python
   _PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
   if _PROJECT_ROOT not in sys.path:
       sys.path.insert(0, _PROJECT_ROOT)
   ```
   Then: `from shared.utils import ...`, `from mcp_client import MCPManager`, etc.

Imports are NOT alphabetically sorted. `TYPE_CHECKING` guards used for circular imports:
```python
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from agents.exec_agent import ExecAgent
```

`main.py` uses **lazy imports** inside phase functions to avoid circular deps and allow env vars to be set first.

### Naming Conventions

| Element | Convention | Examples |
|---------|-----------|----------|
| Variables | `snake_case` | `target_url`, `recon_context`, `round_num` |
| Functions | `snake_case` | `extract_send_block()`, `phase_recon()` |
| Private | Leading `_` | `_build_messages()`, `_tool_loop()`, `_debug()` |
| Classes | `PascalCase` | `CrawlAgent`, `ExecAgent`, `RedTeamAgent`, `MCPManager` |
| Constants | `UPPER_SNAKE_CASE` | `MAX_TOOL_ROUNDS`, `TRUNCATE_LIMIT`, `SERVER_URL` |
| Color codes | `UPPER_SNAKE_CASE` | `RED`, `GREEN`, `CYAN`, `RESET` (or short: `R`, `G`, `C`, `RST`) |
| System prompts | `UPPER_SNAKE_CASE` | `RECON_SYSTEM_PROMPT`, `RED_PROMPT`, `BLUE_PROMPT` |
| Regex patterns | `UPPER_SNAKE_CASE` or `_UPPER` | `TAG_PATTERN`, `_URL_PATTERN`, `_CRED_PATTERNS` |

### Type Hints

Used on **public function signatures** (parameters and return types). Not used on local variables or private helpers consistently. Examples:
```python
def extract_send_block(text: str) -> str | None:
def parse_prompt(user_prompt: str) -> tuple[str | None, dict | None]:
def truncate(text: str, limit: int = TRUNCATE_LIMIT) -> str:
```

No type-checker (mypy/pyright) is configured.

### Docstrings

- **Module-level**: All files have multi-line triple-quoted docstrings describing purpose.
- **Class-level**: Present on all classes.
- **Public methods**: Loose Google-style with `Args:` and `Returns:` sections.
- **Private methods**: Docstrings optional; inline comments used instead.

### Section Separators

Heavy use of decorative Unicode box-drawing for section headers in source files:
```python
# ═══════════════════════════════════════════════════════════════
# SECTION NAME
# ═══════════════════════════════════════════════════════════════
```

### Error Handling

- **No `logging` module in agents** — all output via `print()` with ANSI color codes to stdout/stderr.
- `server/server.py` is the only module using Python `logging`.
- LLM API errors: catch broad `Exception`, print colored error, return error string with forced routing tag.
- Tool errors: return `[Tool Error]` or `[Lỗi tool]` strings; never raise.
- Pipeline-level (`main.py`): `RuntimeError` for expected failures, broad `Exception` + `traceback.print_exc()` for unexpected.
- Non-critical operations use silent `except Exception: pass` (e.g., MCP disconnect).

### Conversation Format

Shared list of dicts across all phases:
```python
{"speaker": "REDTEAM" | "BLUETEAM" | "AGENT" | "USER" | "SYSTEM", "content": "[SPEAKER]: <text>"}
```

Legacy modules in `test/` use `{"role": ..., "content": ...}` — incompatible format.

### Tag Routing

Agents emit routing tags at end of response. Priority: `AGENT > DONE > APPROVED > REDTEAM > BLUETEAM > USER`. Tag regex: `\[(TAG)\]\s*$` (multiline). If LLM omits a tag, agents retry up to `MAX_TAG_RETRIES` (2) then force-append.

## Environment Variables

| Variable | Default | Used in |
|----------|---------|---------|
| `GITHUB_TOKEN` | `gho_token` (placeholder) | all modules |
| `MARL_SERVER_URL` | `http://127.0.0.1:5000/v1` | agents, main.py |
| `MARL_EXECUTOR_MODEL` | `gpt-4.1` | exec_agent.py |
| `MARL_CRAWL_MODEL` | inherits `MARL_EXECUTOR_MODEL` | crawl_agent.py |
| `MARL_RED_MODEL` | `gpt-5-mini` | red_team.py |
| `MARL_BLUE_MODEL` | `gpt-5-mini` | blue_team.py |
| `MARL_DEBUG` | (unset) | crawl_agent.py |
| `PORT` | `5000` | server/server.py |

All agents load `.env` from project root via `python-dotenv`. Never commit `.env`.

## Known Issues to Be Aware Of

- `strip_tag()` is duplicated in `shared/utils.py` and `main.py` with different regex
- `mcp_client.py` has unreachable code after `return` in `_ddg_search_html_fallback()`
- Legacy `test/` modules hardcode tokens and use incompatible conversation format
- No `requirements.txt` — dependencies are undeclared
- CrawlAgent login only tries 4 hardcoded paths; non-standard login URLs will fail
- ExecAgent `fetch()` tool is stateless (no cookies) — LLM often misuses it for authenticated requests
- No token counting — large `recon.md` can fill LLM context silently
