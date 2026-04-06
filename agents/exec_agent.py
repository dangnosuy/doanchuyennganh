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
PROMPT_PATH = "prompts/exec"

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
# SYSTEM PROMPTS — BAC / BLF Pentest Only
# ═══════════════════════════════════════════════════════════════

ANSWER_SYSTEM_PROMPT = load_prompt("answer")
VERIFY_SYSTEM_PROMPT = load_prompt("verify")
EXECUTE_SYSTEM_PROMPT = load_prompt("execute")
WORKFLOW_SYSTEM_PROMPT = load_prompt("workflow")

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
