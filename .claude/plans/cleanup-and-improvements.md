# Plan: Cleanup file output paths + remove lab-specific prompts + improve recon

## Problem Summary

1. **Stray files in repo root**: Shell MCP server is unrestricted — ExecAgent's LLM can (and does) write files like `cookiejar.txt`, `login2.har`, `step1_raw.txt` etc. to CWD instead of workspace/. Also `.playwright-mcp/` dumps screenshots/console logs in repo root.
2. **Lab-specific prompt language**: ExecAgent's WORKFLOW_SYSTEM_PROMPT references "Congratulations"/"lab solved" — should be removed since tool now focuses on PoC generation, not solving labs.
3. **CrawlAgent login path is hardcoded**: Only tries `/login`, `/my-account`, `/account/login`, `/signin` — misses many real-world apps.
4. **All runs dump to same `workspace/` flat dir**: No per-target isolation.

## Changes

### 1. Per-target workspace directories

**Files**: `main.py`, `agents/exec_agent.py`, `agents/crawl_agent.py`

Create workspace subdirectory per run based on domain + timestamp:
```
workspace/{domain}_{YYYYMMDD_HHMMSS}/
  recon.md
  report.md
  marl_*.log
  (PoC scripts, evidence files from ExecAgent)
```

**main.py** changes:
- After `parse_prompt()` extracts target_url, compute `run_dir`:
  ```python
  from urllib.parse import urlparse
  domain = urlparse(target_url).netloc.replace(":", "_")
  timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
  run_dir = os.path.join(WORKSPACE, f"{domain}_{timestamp}")
  os.makedirs(run_dir, exist_ok=True)
  ```
- Pass `run_dir` (not `WORKSPACE`) to CrawlAgent, ExecAgent, TeeLogger
- Move `setup_logging()` call to AFTER parse_prompt so we know the domain
- Update `phase_report()` to write to `run_dir/report.md`

**agents/exec_agent.py** changes:
- `working_dir` already gets passed in — no structural change needed
- Add `cwd=self.working_dir` concept: tell shell MCP to use working_dir as CWD, OR add instruction to WORKFLOW_SYSTEM_PROMPT telling LLM to always write files inside workspace path

**agents/crawl_agent.py** changes:
- Already uses `self.working_dir` — just receives new path from main.py

### 2. Constrain shell commands to workspace dir

**File**: `agents/exec_agent.py`

Add to WORKFLOW_SYSTEM_PROMPT and EXECUTE_SYSTEM_PROMPT:
```
=== FILE OUTPUT (QUAN TRONG) ===
Tat ca file output (PoC script, evidence, logs) PHAI nam trong workspace: {workspace}
Khi dung execute_command, LUON cd vao workspace truoc: cd {workspace} && <command>
KHONG ghi file ra thu muc khac.
```

Also add to ANSWER_SYSTEM_PROMPT similarly.

### 3. Remove lab-specific prompt language

**File**: `agents/exec_agent.py`

In EXECUTE_SYSTEM_PROMPT (line ~103):
- Remove: `- NEVER say "Congratulations", "lab solved", "success" unless that EXACT text appears`
- Remove: `- NEVER claim "Congratulations" or "solved" unless you see that EXACT string in page content.`

In WORKFLOW_SYSTEM_PROMPT (line ~199):
- Remove: `- Neu ban KHONG thay chuoi "Congratulations" hoac "solved" trong response body, thi KHONG DUOC viet la da thay.`
- Replace with generic anti-hallucination: `- KHONG duoc tuyen bo exploit thanh cong neu KHONG co evidence ro rang trong response body.`

### 4. Improve CrawlAgent login discovery

**File**: `agents/crawl_agent.py`

Expand `login_paths` list (line 356):
```python
login_paths = [
    "/login", "/signin", "/sign-in", "/log-in",
    "/my-account", "/account/login", "/auth/login",
    "/user/login", "/users/sign_in",          # Rails/Django common
    "/admin/login", "/admin",                  # Admin panels
    "/wp-login.php",                           # WordPress
    "/accounts/login",                         # Django allauth
]
```

Also: before hardcoded paths, try to discover login link from homepage HTML:
- Fetch homepage
- Search for `<a>` tags with href containing "login", "signin", "sign-in", "log-in", "auth"
- If found, try that URL first

### 5. Clean up .gitignore

**File**: `.gitignore`

Add patterns for stray files that shouldn't be committed:
```
*.har
cookiejar*.txt
cookies.txt
step*.txt
.playwright-mcp/
```

## Order of Implementation

1. `.gitignore` cleanup (independent, quick)
2. Per-target workspace dirs in `main.py` (core change)
3. Update ExecAgent prompts (remove lab language + add workspace constraint)
4. Update CrawlAgent login discovery
5. Verify all paths flow correctly end-to-end

## What This Does NOT Change

- Pipeline phases (1-5) remain identical
- Red/Blue Team prompts are already generic — no changes needed
- Tag system unchanged
- Debate logic unchanged
- MCP client unchanged
