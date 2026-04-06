"""
ExecAgent — Agent thực thi (culi) cho hệ thống MARL debate.

Nhận lệnh từ Red Team / Blue Team, dùng MCP tools để:
  - answer(): trả lời câu hỏi về target website (BAC/BLF focus)
  - execute(): tìm PoC code, save file, chạy python3, report kết quả
  - run_workflow(): thực thi attack workflow step-by-step bằng MCP tools
  - process(): alias cho execute() — backward-compat với debate.py cũ

Tag system (giống agent.py):
  - [REDTEAM] / [BLUETEAM] ở cuối text = "xong rồi, trả về cho team"
  - =========SEND========= ... =========END-SEND========= = phần data gửi đi

KHÔNG có crawl() — crawl do CrawlAgent handle riêng.

Usage (từ debate loop):
    from agents.exec_agent import ExecAgent

    agent = ExecAgent(target_url="https://target.com", recon_md="workspace/recon.md")
    result = agent.answer(conversation, caller="REDTEAM")
    result = agent.execute(conversation, caller="REDTEAM")
    result = agent.run_workflow(workflow_text, conversation)
    agent.shutdown()
"""

import json
import os
import sys
from pathlib import Path

from openai import OpenAI

# ── Đảm bảo project root trên sys.path để import mcp_client, shared ──
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from mcp_client import MCPManager
from shared.utils import (
    extract_send_block, extract_next_tag, strip_tag,
    truncate,
    SEND_BLOCK_PATTERN, TAG_PATTERN,
)


# ═══════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "gho_token")
SERVER_URL = os.getenv("MARL_SERVER_URL", "http://127.0.0.1:5000/v1")
MODEL = os.getenv("MARL_EXECUTOR_MODEL", "gpt-4.1")

# Colors
YELLOW = "\033[93m"
GREEN = "\033[92m"
RED = "\033[91m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Limits
MAX_TOOL_ROUNDS = 50
MAX_CONSECUTIVE_ERRORS = 3
MAX_CONSECUTIVE_REPEATS = 3
TRUNCATE_LIMIT = 15000


# ═══════════════════════════════════════════════════════════════
# SYSTEM PROMPTS — BAC / BLF Pentest Only
# ═══════════════════════════════════════════════════════════════

ANSWER_SYSTEM_PROMPT = """You are a research assistant for a BAC/BLF penetration testing team.
You have shell, browser, fetch, filesystem, and web search tools.

JOB: Answer questions about the TARGET WEBSITE by using tools and reporting RAW RESULTS.
You are an information gatherer — you fetch data, you do NOT analyze or strategize.
SCOPE: Only BAC (Broken Access Control) and BLF (Business Logic Flaw). Do NOT test for XSS, SQLi, SSRF, or other vuln classes.

RULES:
- Use tools to interact with the TARGET website and collect data.
- Report RAW facts: HTTP status codes, response bodies, page content, form fields.
- Do NOT write attack strategies, do NOT suggest exploitation steps.
- Do NOT say "this indicates a vulnerability" or "we could exploit this by...".
- Just answer the specific question asked with raw evidence.
- NEVER read local *.py, *.json project files — they are NOT the target.

=== SESSION / COOKIE (QUAN TRONG) ===
- fetch() tool la stateless GET — KHONG mang cookie, KHONG co session.
- Khi can request CO SESSION (authenticated), LUON dung curl qua execute_command:
    execute_command({"command": "curl -s -b 'session=COOKIE_VALUE' URL"})
    execute_command({"command": "curl -s -b 'session=COOKIE_VALUE' -d 'param=value' URL"})
- KHONG BAO GIO dung fetch() roi ky vong no co session cua curl. Chung KHONG share cookie.
- Neu can login: dung browser_navigate + browser_fill_form + browser_click, roi lay cookie bang browser_evaluate({"function": "() => document.cookie"}).
- Sau khi co cookie, dung curl cho TAT CA request (ca GET lan POST).

=== ANTI-HALLUCINATION (CRITICAL) ===
- ONLY report data you ACTUALLY received from tools. NEVER fabricate, infer, or guess.
- If a tool returns HTML, quote the EXACT relevant snippet — do NOT paraphrase.
- If you did NOT see a string in the response, do NOT claim it exists.
- NEVER claim a vulnerability is confirmed unless you have concrete evidence in the raw tool output.
- When uncertain, say "INCONCLUSIVE — raw response did not contain [X]".

=== WORKSPACE ===
- Save ALL files (scripts, evidence, etc.) inside the workspace directory given in the first message.
- NEVER write files outside the workspace directory.

OUTPUT: Put answer in =========SEND========= ... =========END-SEND========= block.
End with the return tag given ([REDTEAM] or [BLUETEAM]).
Every response without tool_calls MUST end with a tag on the last line."""


VERIFY_SYSTEM_PROMPT = """You are a VERIFICATION assistant for a penetration testing team.
You have browser and fetch tools to CHECK results — that is ALL.

JOB: Verify whether a previous attack was successful by OBSERVING the current state.
You ONLY look — you do NOT attack, exploit, modify, or send POST requests.

ALLOWED actions (READ-ONLY):
- browser_navigate to a page and browser_snapshot to see content
- browser_evaluate to read page text (document.body.innerText)
- execute_command with curl -s -b 'session=COOKIE' URL to GET a page with session
- browser_run_code to GET a page programmatically

NOTE: fetch() tool is stateless — it has NO cookies/session.
If you need to check an AUTHENTICATED page, use curl with -b cookie, NOT fetch().

FORBIDDEN actions (will cause incorrect results):
- Do NOT send POST/PUT/DELETE requests
- Do NOT fill forms, click submit buttons, or login
- Do NOT use curl with -X POST or --data
- Do NOT attempt any exploitation steps
- Do NOT retry the attack with modified parameters

=== ANTI-HALLUCINATION (CRITICAL) ===
- Base your verdict EXCLUSIVELY on raw data from tools. NEVER assume or infer.
- You MUST quote the exact text/HTML snippet that proves success or failure.
- If the page does NOT contain a success indicator, verdict = VERIFIED FAIL or INCONCLUSIVE.
- NEVER claim a vulnerability is confirmed unless you see concrete evidence in raw tool output.
- If tool output is ambiguous, say INCONCLUSIVE — do NOT guess.

OUTPUT: Put verification result in =========SEND========= ... =========END-SEND========= block.
State clearly: VERIFIED SUCCESS / VERIFIED FAIL / INCONCLUSIVE
Include raw evidence (exact page content quotes, HTTP status).
End with the return tag given ([REDTEAM] or [BLUETEAM]).
Every response without tool_calls MUST end with a tag on the last line."""


EXECUTE_SYSTEM_PROMPT = """You are a command executor for a BAC/BLF penetration testing team.
You have shell, browser, fetch, filesystem, and web search tools.

JOB: Receive Python PoC scripts from Red Team, save to file, execute, report output.

WORKFLOW:
1. Extract Python code from the instruction (inside ```python blocks).
2. Save it to a .py file in the workspace directory.
3. Run: execute_command python3 <filename>.py
4. Report FULL stdout + stderr.

OUTPUT: Put results in =========SEND========= ... =========END-SEND========= block.
End with the return tag given ([REDTEAM] or [BLUETEAM]).

RULES:
- Save and run code AS-IS. Do NOT rewrite or modify the PoC.
- Do NOT manually replicate PoC logic with browser tools — just run the script.
- If execution fails, report the FULL error. Do NOT retry with modified code.
- ALWAYS save files into the workspace directory (given in first message).
- Report ONLY what stdout/stderr actually printed. NEVER add your own interpretation.
- Every response without tool_calls MUST end with a tag on the last line."""


WORKFLOW_SYSTEM_PROMPT = """\
Ban la executor. Ban nhan ATTACK WORKFLOW va thuc thi tung buoc bang tools.
Ban KHONG suy nghi, KHONG phan tich, KHONG thay doi ke hoach.

=== QUY TRINH HIEU QUA ===
1. Login bang BROWSER (browser_navigate → browser_fill_form → browser_click).
2. NGAY SAU KHI LOGIN, lay cookie:
   browser_evaluate({{"function": "() => document.cookie"}})
3. Tu day TRO DI, dung CURL cho tat ca request (nhanh hon browser):
   execute_command({{"command": "curl -s -b 'session=COOKIE' -d 'param=value' URL"}})
4. KHONG login lai. KHONG dung browser cho cac buoc sau khi da co cookie.
   Ngoai tru: khi can lay CSRF token moi (browser_evaluate de lay tu trang hien tai).

=== QUY TAC ===
- Thuc thi TUNG BUOC theo thu tu. KHONG bo buoc.
- Neu workflow co buoc a, b, c (bien the): thu a truoc. Neu fail → thu b. Neu fail → thu c.
- Buoc fail → ghi raw error + response body → chuyen buoc tiep (hoac bien the tiep).
- KHONG viet doan van. Chi ghi raw facts.

=== SESSION / COOKIE (QUAN TRONG) ===
- fetch() tool la stateless GET — KHONG co cookie, KHONG co session.
- SAU KHI CO COOKIE, KHONG DUOC dung fetch(). Chi dung curl qua execute_command.
- Kiem tra ket qua (GET) cung phai dung curl -b 'session=...' de giu session.
- VD: execute_command({{"command": "curl -s -b 'session=COOKIE' https://target/cart"}})

=== CHONG AO TUONG (CRITICAL — DOC KY) ===
- CHI BAO CAO du lieu THAT tu tool output. TUYET DOI KHONG bia, khong suy dien.
- Khi curl/browser tra ve HTML: trich NGUYEN VAN doan HTML lien quan. KHONG tom tat.
- KHONG DUOC tuyen bo co lo hong neu KHONG co bang chung cu the trong response body.
- Khi khong chac ket qua: ghi "KHONG XAC DINH — response khong chua [X]".
- KHONG DUOC tu them thong tin ma tool khong tra ve.
- Moi buoc PHAI co BANG CHUNG (HTTP status + response body snippet).

=== WORKSPACE ===
- Luu TAT CA file (script, evidence, ...) vao thu muc workspace (duoc cho trong message dau tien).
- TUYET DOI KHONG ghi file ra ngoai thu muc workspace.

=== OUTPUT FORMAT ===
Khi xong, viet bao cao trong =========SEND========= block.
Moi buoc ghi theo format:

Step N: <METHOD> <PATH> (<mo ta>)
Tool: <tool da dung>
Result: <HTTP status>, <TRICH NGUYEN VAN response body — 1-3 dong quan trong nhat>
Status: SUCCESS / FAIL

Cuoi bao cao, ket thuc bang [REDTEAM].
"""


# ═══════════════════════════════════════════════════════════════
# HELPER FUNCTIONS — tìm context / PoC trong conversation
# ═══════════════════════════════════════════════════════════════

def _find_crawl_context(conversation: list[dict]) -> str:
    """Tìm message đầu tiên chứa 'CRAWL' trong conversation.

    Dùng khi ExecAgent không được cung cấp recon_md — fallback scan
    conversation để tìm crawl data (thường do Executor hoặc CrawlAgent gửi).
    """
    for msg in conversation:
        content = msg.get("content", "")
        if "CRAWL" in content[:50]:
            return content
    return ""


def _find_poc_instruction(conversation: list[dict]) -> str:
    """Tìm PoC instruction trong conversation.

    Ưu tiên:
    1. REDTEAM message cuối cùng có ```python block
    2. Fallback: REDTEAM message cuối cùng
    3. Fallback: message cuối cùng trong conversation
    """
    last_with_code = ""
    last_redteam = ""

    for msg in reversed(conversation):
        speaker = msg.get("speaker", "")
        content = msg.get("content", "")

        # Tìm REDTEAM msg có Python code block
        if speaker == "REDTEAM" and "```python" in content and not last_with_code:
            last_with_code = content
            break  # Tìm thấy rồi, dừng

        # Backup: REDTEAM msg bất kỳ
        if speaker == "REDTEAM" and not last_redteam:
            last_redteam = content

    return (
        last_with_code
        or last_redteam
        or (conversation[-1].get("content", "") if conversation else "")
    )


# ═══════════════════════════════════════════════════════════════
# EXEC AGENT CLASS
# ═══════════════════════════════════════════════════════════════

class ExecAgent:
    """Agent thực thi với MCP tools — nhận lệnh từ Red/Blue Team.

    Khác ExecutorAgent cũ (agent.py):
    - KHÔNG có crawl() — crawl do CrawlAgent riêng
    - Nhận target_url + recon_md upfront thay vì scan conversation
    - System prompts focus BAC/BLF cụ thể hơn
    - Cùng _tool_loop() pattern (proven, robust)

    Args:
        working_dir: Thư mục workspace lưu files (default: ./workspace)
        target_url: URL target website (optional, fallback scan conversation)
        recon_md: Path tới recon.md từ CrawlAgent (optional)
    """

    def __init__(
        self,
        working_dir: str = "./workspace",
        target_url: str | None = None,
        recon_md: str | None = None,
    ):
        self.working_dir = os.path.abspath(working_dir)
        os.makedirs(self.working_dir, exist_ok=True)
        self.target_url = target_url or ""
        self.recon_context = ""

        # Load recon.md nếu có
        if recon_md and os.path.isfile(recon_md):
            self.recon_context = Path(recon_md).read_text(encoding="utf-8")
            print(f"{GREEN}[EXEC-AGENT] Loaded recon: {recon_md} "
                  f"({len(self.recon_context)} chars){RESET}")

        # OpenAI client → proxy server
        self.client = OpenAI(api_key=GITHUB_TOKEN, base_url=SERVER_URL)

        # MCP: đủ 5 tools
        print(f"\n{YELLOW}{BOLD}[EXEC-AGENT] Khoi tao MCP tools...{RESET}")
        self.mcp = MCPManager()
        self.mcp.add_shell_server()
        self.mcp.add_fetch_server()
        self.mcp.add_filesystem_server([self.working_dir])
        self.mcp.add_playwright_server(headless=True)
        self.mcp.add_web_search()

        self.tools = self.mcp.get_openai_tools()
        print(f"{YELLOW}[EXEC-AGENT] Da san sang — {len(self.tools)} tools{RESET}")
        self.mcp.display_tools()
        print()

    # ─── Public API ──────────────────────────────────────────────

    def answer(self, conversation: list[dict], caller: str = "REDTEAM",
               read_only: bool = False) -> str:
        """Red/Blue Team hỏi câu hỏi → Agent dùng tools trả lời.

        Build message: system prompt + (target URL + recon data + question).
        Gọi _tool_loop để LLM dùng tools tìm thêm info nếu cần.

        Args:
            conversation: Debate conversation (list of speaker/content dicts).
            caller: Ai gọi — "REDTEAM" hoặc "BLUETEAM". Agent sẽ trả với tag này.
            read_only: True → dùng VERIFY_SYSTEM_PROMPT (chỉ observe, không exploit).
                       Dùng cho Phase 4 (evaluation) để Agent không tự re-do attack.

        Returns:
            Raw text chứa SEND block + [REDTEAM] hoặc [BLUETEAM] tag.
        """
        sys_prompt = VERIFY_SYSTEM_PROMPT if read_only else ANSWER_SYSTEM_PROMPT
        return_tag = f"[{caller}]"
        messages = [{"role": "system", "content": sys_prompt}]

        # ── Build context block ──
        user_content = ""

        if self.target_url:
            user_content += f"=== TARGET URL ===\n{self.target_url}\n\n"

        if self.recon_context:
            user_content += f"=== RECON DATA ===\n{truncate(self.recon_context)}\n\n"
        else:
            # Fallback: scan conversation cho crawl data
            crawl_ctx = _find_crawl_context(conversation)
            if crawl_ctx:
                user_content += f"=== RECON DATA ===\n{truncate(crawl_ctx)}\n\n"

        # ── Session context: ke thua cookie tu Phase 3 ──
        if read_only:
            cookie_path = os.path.join(self.working_dir, "cookies.txt")
            if os.path.isfile(cookie_path):
                try:
                    cookie_data = Path(cookie_path).read_text(encoding="utf-8").strip()
                    if cookie_data:
                        user_content += (
                            f"=== SESSION TU PHASE 3 (cookies.txt) ===\n"
                            f"File: {cookie_path}\n"
                            f"Dung curl -b cookies.txt de giu session thay vi login lai.\n"
                            f"Noi dung:\n{cookie_data[:2000]}\n\n"
                        )
                except Exception:
                    pass

        # Question = last message trong conversation
        last_question = conversation[-1].get("content", "") if conversation else ""
        user_content += f"=== QUESTION ===\n{last_question}\n\n"
        user_content += f"When done, put answer in SEND block and end with {return_tag}."

        messages.append({"role": "user", "content": user_content})

        return self._tool_loop(messages, default_tag=caller)

    def execute(self, conversation: list[dict], caller: str = "REDTEAM") -> str:
        """Tìm PoC code trong conversation → save file → chạy python3 → trả kết quả.

        Build message: system prompt + (workspace + target URL + recon context + instruction).
        Gọi _tool_loop để LLM extract code, save, run, report.

        Args:
            conversation: Debate conversation (list of speaker/content dicts).
            caller: Ai gọi — "REDTEAM" hoặc "BLUETEAM". Agent sẽ trả với tag này.

        Returns:
            Raw text chứa SEND block + [REDTEAM] hoặc [BLUETEAM] tag.
        """
        return_tag = f"[{caller}]"
        messages = [{"role": "system", "content": EXECUTE_SYSTEM_PROMPT}]

        # Tìm PoC instruction trong conversation
        instruction = _find_poc_instruction(conversation)

        # ── Build user message ──
        user_content = (
            f"=== WORKSPACE ===\n{self.working_dir}\n"
            f"ALL files MUST be saved inside this directory.\n\n"
        )

        if self.target_url:
            user_content += f"=== TARGET URL ===\n{self.target_url}\n\n"

        if self.recon_context:
            user_content += (
                f"=== TARGET CONTEXT ===\n"
                f"{truncate(self.recon_context, 5000)}\n\n"
            )

        user_content += f"=== INSTRUCTION ===\n{instruction}\n\n"
        user_content += (
            "Extract Python code, save to .py file, run with python3, report output.\n"
            f"When done, put results in SEND block and end with {return_tag}."
        )

        messages.append({"role": "user", "content": user_content})

        return self._tool_loop(messages, default_tag=caller)

    def process(self, conversation: list[dict], caller: str = "REDTEAM") -> str:
        """Alias cho execute() — backward-compat với debate.py cũ."""
        return self.execute(conversation, caller)

    def run_workflow(
        self,
        workflow_text: str,
        conversation: list[dict] | None = None,
    ) -> str:
        """Thực thi attack workflow bằng MCP tools.

        Khác answer()/execute():
        - System prompt chuyên cho workflow execution (step-by-step).
        - Input là workflow text (danh sách bước) KHÔNG phải câu hỏi.
        - Agent tự chọn tool phù hợp cho mỗi bước (browser, shell, fetch...).
        - Luôn trả kết quả về [REDTEAM] để Red đánh giá.

        Args:
            workflow_text: Chiến lược tấn công từ Red Team (đã được Blue approve).
            conversation: Conversation context (optional — dùng để lấy thêm context).

        Returns:
            Raw text chứa SEND block (execution report) + [REDTEAM] tag.
        """
        messages = [{"role": "system", "content": WORKFLOW_SYSTEM_PROMPT}]

        # ── Build user message ──
        user_content = ""

        if self.target_url:
            user_content += f"=== TARGET URL ===\n{self.target_url}\n\n"

        user_content += f"=== WORKSPACE ===\n{self.working_dir}\n"
        user_content += "ALL files MUST be saved inside this directory.\n\n"

        user_content += f"=== ATTACK WORKFLOW (EXECUTE THIS) ===\n{workflow_text}\n\n"
        user_content += (
            "Thuc thi tung buoc theo thu tu. Ghi lai evidence moi buoc. "
            "Xong het thi viet bao cao trong SEND block va ket thuc bang [REDTEAM]."
        )

        messages.append({"role": "user", "content": user_content})

        return self._tool_loop(messages, default_tag="REDTEAM")

    def shutdown(self):
        """Cleanup MCP connections."""
        print(f"{YELLOW}[EXEC-AGENT] Shutting down MCP...{RESET}")
        self.mcp.stop_all()
        print(f"{YELLOW}[EXEC-AGENT] Done.{RESET}")

    # ─── Internal: Tool-calling loop (robust, proven pattern) ────

    def _tool_loop(self, messages: list[dict], default_tag: str = "REDTEAM") -> str:
        """Chạy tool calls cho đến khi LLM trả text có tag ([REDTEAM]/[BLUETEAM]).

        Copy pattern từ agent.py _tool_loop (đã proven):
        1. Gọi LLM với tools.
        2. Nếu response có tool_calls → execute → append results → loop.
        3. Nếu response là text → check tag → có tag thì return.
        4. Text không có tag → nudge LLM tiếp tục.

        Safety mechanisms:
        - tool_choice="required" round 0: force tool use, tránh LLM "planning"
        - Repeated tool detection (3x same args → force summary)
        - Consecutive errors (3 failures → force summarize)
        - Nudge counter (3 text-no-tag → force append tag)
        - Approaching limit (round >= 47 → nudge "hết rounds, tổng kết đi")

        Args:
            messages: LLM messages list (system + user + ...).
            default_tag: Tag dùng cho nudges/fallbacks (e.g. "REDTEAM").

        Returns:
            Raw LLM text (chứa SEND block + tag).
        """
        consecutive_errors = 0
        tool_count = 0
        nudge_count = 0
        max_nudges = 3
        consecutive_repeats = 0
        last_tool_signature = None  # (fn_name, fn_args_str) của tool call trước

        for round_idx in range(MAX_TOOL_ROUNDS):
            try:
                # Force tool use ở round đầu để tránh LLM "lên kế hoạch" thay vì làm
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
                print(f"{DIM}[EXEC-AGENT] API error ({consecutive_errors}): {e}{RESET}")
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                    return (
                        f"[API Error after {consecutive_errors} retries: {e}]\n"
                        f"[{default_tag}]"
                    )
                continue

            consecutive_errors = 0
            choice = response.choices[0]
            msg = choice.message

            # ── Tool calls: execute rồi loop tiếp ──
            if msg.tool_calls:
                # Append assistant message với tool calls
                messages.append({
                    "role": "assistant",
                    "content": msg.content or "",
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments,
                            },
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

                    print(
                        f"{DIM}[EXEC-AGENT] Tool {tool_count}: "
                        f"{fn_name}({json.dumps(fn_args, ensure_ascii=False)[:120]})"
                        f"{RESET}"
                    )

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

                # ── Phá vòng lặp tool call lặp lại ──
                if consecutive_repeats >= MAX_CONSECUTIVE_REPEATS:
                    print(
                        f"{YELLOW}[EXEC-AGENT] Detected "
                        f"{consecutive_repeats + 1}x repeated tool call: "
                        f"{last_tool_signature[0]}. Forcing summary.{RESET}"
                    )
                    messages.append({
                        "role": "user",
                        "content": (
                            f"STOP. You have called {last_tool_signature[0]} with "
                            f"the SAME arguments {consecutive_repeats + 1} times "
                            f"in a row. This is a loop. "
                            "Do NOT call this tool again. Move on to the next step, "
                            "or if you have enough data, summarize everything you "
                            "found so far inside a =========SEND========= block "
                            f"and end with [{default_tag}]."
                        ),
                    })
                    consecutive_repeats = 0

                # Nếu tools liên tục fail → force LLM dừng lại tổng kết
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                    messages.append({
                        "role": "user",
                        "content": (
                            f"The last {MAX_CONSECUTIVE_ERRORS} tool calls FAILED. "
                            "STOP retrying. Summarize what you have collected so far "
                            f"inside a =========SEND========= block and end with "
                            f"[{default_tag}]."
                        ),
                    })
                    consecutive_errors = 0

                nudge_count = 0  # reset nudge sau khi dùng tools

                # ── Gần hết rounds → nudge LLM tổng kết ──
                if round_idx >= MAX_TOOL_ROUNDS - 3:
                    messages.append({
                        "role": "user",
                        "content": (
                            "IMPORTANT: You are running out of tool rounds. "
                            "STOP using tools NOW. Summarize everything you found "
                            "so far inside a =========SEND========= block and end "
                            f"with [{default_tag}]."
                        ),
                    })

                continue  # quay lại đầu loop

            # ── Text response: check tag ──
            text = msg.content or ""
            tag = extract_next_tag(text)

            if tag:
                # LLM xong — return full text
                return text

            # Không có tag — LLM nói nhưng chưa signal done
            nudge_count += 1
            if nudge_count >= max_nudges:
                # Force kết thúc — tự thêm tag
                return text + f"\n[{default_tag}]"

            # Append và nudge LLM tiếp tục
            messages.append({"role": "assistant", "content": text})
            messages.append({
                "role": "user",
                "content": (
                    "Continue. Use your tools to complete the task. When done, "
                    f"put results in a SEND block and end with [{default_tag}]."
                ),
            })

        # Max rounds đạt limit
        return (
            f"[ExecAgent reached {MAX_TOOL_ROUNDS} tool rounds limit]\n"
            f"[{default_tag}]"
        )
