"""
ExecAgent — Agent thực thi (culi) cho hệ thống MARL debate.

Nhận lệnh từ ManageAgent dựa trên strategy Red đã được Blue approve, dùng MCP tools để:
  - answer(): trả lời câu hỏi về target website (BAC/BLF focus)
  - execute(): tìm PoC code, save file, chạy python3, report kết quả
  - run_workflow(): sinh Python exploit, chạy script, lưu artifact, tự verify
  - process(): alias cho execute() — backward-compat với debate.py cũ

Completion protocol:
  - =========SEND========= ... =========END-SEND========= = phần data gửi về Manager

KHÔNG có crawl() — crawl do CrawlAgent handle riêng.

Usage (từ Manager loop):
    from agents.exec_agent import ExecAgent

    agent = ExecAgent(target_url="https://target.com", recon_md="workspace/recon.md")
    result = agent.answer(conversation)
    result = agent.execute(conversation)
    result = agent.run_workflow(workflow_text, conversation)
    agent.shutdown()
"""

import json
import hashlib
import os
import re
import shutil
import shlex
import sys
from html import unescape
from pathlib import Path
from urllib.parse import urljoin, urlparse

from openai import OpenAI

# ── Đảm bảo project root trên sys.path để import mcp_client, shared ──
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from mcp_client import MCPManager
from shared.utils import (
    extract_send_block,
    truncate,
)


# ═══════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "gho_token")
SERVER_URL = os.getenv("MARL_SERVER_URL", "http://127.0.0.1:5000/v1")
MODEL = os.getenv("MARL_EXECUTOR_MODEL", "ollama/gemma4:31b-cloud")
TOOLCALL_MODEL = os.getenv("MARL_EXEC_TOOLCALL_MODEL", os.getenv("MARL_TOOLCALL_MODEL", MODEL))

# Colors
YELLOW = "\033[93m"
GREEN = "\033[92m"
RED = "\033[91m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Limits
MAX_TOOL_ROUNDS = 30
MAX_WORKFLOW_LOGIN_ROUNDS = 8
MAX_ITERATIVE_WORKFLOW_ROUNDS = 36
DEFAULT_SCRIPT_SHOTS = 1
RETRY_SCRIPT_SHOTS = 2
MAX_CONSECUTIVE_ERRORS = 3
MAX_CONSECUTIVE_REPEATS = 3
TRUNCATE_LIMIT = 15000
BASE_COOKIES_FILENAME = "base_cookies.txt"


def _send_block(content: str) -> str:
    """Wrap final Exec output in the manager-readable SEND block."""
    return f"=========SEND=========\n{content.rstrip()}\n=========END-SEND========="


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
- You have a generous tool budget. Do NOT stop after checking a single page if the question asks multiple checks.
- If the question contains multiple numbered items, gather raw evidence for EACH item before summarizing.
- Prefer a deeper evidence pass over an early shallow answer.

=== SESSION / COOKIE (QUAN TRONG) ===
- fetch() tool la stateless GET — KHONG mang cookie, KHONG co session.
- Khi can request CO SESSION (authenticated), LUON dung curl qua execute_command:
    execute_command({"command": "curl -s -b 'session=COOKIE_VALUE' URL"})
    execute_command({"command": "curl -s -b 'session=COOKIE_VALUE' -d 'param=value' URL"})
- KHONG BAO GIO dung fetch() roi ky vong no co session cua curl. Chung KHONG share cookie.
- Neu can login: dung browser_navigate + browser_fill_form + browser_click, roi lay cookie bang browser_run_code_unsafe({"code": "(async () => { return await page.context().cookies(); })()"}). Tim cookie co name 'session' trong JSON. KHONG dung document.cookie vi no KHONG thay HttpOnly cookies.
- Sau khi co cookie, dung curl cho TAT CA request (ca GET lan POST).

=== CSRF TOKEN (CRITICAL) ===
- Moi POST request deu CAN CSRF token. Quy trinh CHUAN:
  1. GET trang login → lay Set-Cookie session AND gia tri csrf tu HTML (input[name=csrf]).
  2. POST login VOI CUNG SESSION COOKIE vua nhan (dung -b va -c cung 1 file cookies.txt):
     curl -c cookies.txt -b cookies.txt -X POST /login -d "csrf=TOKEN&username=X&password=Y"
  3. Session sau login la session MOI trong cookies.txt — dung no cho cac request tiep theo.
- KHONG dung CSRF token cu cho session moi. CSRF token gan lien voi session cookie.
- LUON dung cung 1 file cookies.txt cho ca -c (ghi) va -b (doc) trong toan bo flow.

=== ANTI-HALLUCINATION (CRITICAL) ===
- ONLY report data you ACTUALLY received from tools. NEVER fabricate, infer, or guess.
- If a tool returns HTML, quote the EXACT relevant snippet — do NOT paraphrase.
- If you did NOT see a string in the response, do NOT claim it exists.
- NEVER claim a vulnerability is confirmed unless you have concrete evidence in the raw tool output.
- When uncertain, say "INCONCLUSIVE — raw response did not contain [X]".

=== WORKSPACE ===
- Save ALL files (scripts, evidence, etc.) inside the workspace directory given in the first message.
- NEVER write files outside the workspace directory.

OUTPUT: Put answer in =========SEND========= ... =========END-SEND========= block."""


EXECUTE_SYSTEM_PROMPT = """You are a command executor for a BAC/BLF penetration testing team.
You have shell, browser, fetch, filesystem, and web search tools.

JOB: Receive Python PoC scripts from Red Team, save to file, execute, report output.

WORKFLOW:
1. Extract Python code from the instruction (inside ```python blocks).
2. Save it to a .py file in the workspace directory.
3. Run: execute_command python3 <filename>.py
4. Report FULL stdout + stderr.

OUTPUT: Put results in =========SEND========= ... =========END-SEND========= block.

RULES:
- Save and run code AS-IS. Do NOT rewrite or modify the PoC.
- Do NOT manually replicate PoC logic with browser tools — just run the script.
- If execution fails, report the FULL error. Do NOT retry with modified code.
- ALWAYS save files into the workspace directory (given in first message).
- Report ONLY what stdout/stderr actually printed. NEVER add your own interpretation."""


WORKFLOW_LOGIN_PROMPT = """\
Ban la executor. NHIEM VU DUY NHAT: LOGIN vao website va lay session cookie.

LUU Y: He thong Python se co gang login deterministic truoc khi goi ban. Neu ban duoc goi,
nghia la fallback dang chay. TUYET DOI KHONG dung document.cookie.

=== QUY TRINH ===
1. browser_navigate toi trang login.
2. browser_evaluate de lay CSRF token tu HTML:
   browser_evaluate({{"function": "() => {{ const el = document.querySelector('input[name=csrf],input[name=_csrf],input[name=csrfToken]'); return el ? el.value : null; }}"}})
3. browser_fill_form dien username + password (CSRF field la hidden, browser tu gui).
4. browser_click nut submit.
5. LAY COOKIE — QUAN TRONG: Session cookie thuong la HttpOnly.
   Dung browser_run_code_unsafe de lay TAT CA cookies (ke ca HttpOnly):
   browser_run_code_unsafe({{"code": "(async () => {{ return await page.context().cookies(); }})()"}}
   Tim cookie co name 'session' trong JSON result.
   Bao cao: SESSION_COOKIE: session=<value>

=== QUY TAC ===
- CHI THUC HIEN LOGIN. KHONG lam buoc nao khac trong workflow.
- Sau khi co cookie, TRA VE NGAY LAP TUC.
- KHONG navigate toi trang khac sau khi login.
- KHONG dung fetch() — no khong mang cookie.
- KHONG dung document.cookie — no KHONG thay HttpOnly cookies.

=== OUTPUT ===
Khi co cookie, viet ket qua trong =========SEND========= block voi format:
SESSION_COOKIE: <gia tri cookie day du, VD: session=abc123>
CSRF_NOTE: <ghi chu ve CSRF neu can>
Khong them routing tag.
"""

WORKFLOW_SCRIPT_PROMPT = """\
Ban la executor. NHIEM VU DUY NHAT: Viet MOT Python exploit file cho SHOT HIEN TAI.

=== KET QUA CHO PHEP ===

CHỈ ĐƯỢC VIẾT:
- 1 Python 3 script hoàn chỉnh trong ```python ...``` block
- Mỗi dòng tối đa 120 ký tự
- Standard library + requests

KHÔNG ĐƯỢC VIẾT:
- Bất kỳ giải thích nào trước hoặc sau script
- Không có dòng mô tả chiến lược, không có "đây là script", không có tóm tắt
- Không có code block khác ngoài ```python```

=== VI PHẠM = SAI ===
Nếu bạn viết bất kỳ dòng nào không phải Python code trong code block,
output của bạn SẼ bị coi là LỖI và script không được chạy.

=== STRUCTURE BẮT BUỘC ===

Dòng 1: `#!/usr/bin/env python3`
Dòng 2+: import chuẩn, helper request/parse/save artifact
Mỗi step dùng biến bool step_n_ok.
Cuối: print("=== FINAL: EXPLOITED/PARTIAL/FAILED ==="); sys.exit(0/1/2)
Script phai tu verify va tu ket luan. Manager se doc verdict cua script, khong co verifier thu hai.

Ví dụ đúng:
```python
#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path
from urllib.parse import urljoin

import requests

WORKDIR = Path(os.environ.get("WORKDIR", "."))
STATE_DIR = Path(os.environ.get("STATE_DIR", WORKDIR / "exploit_state" / "bug-unknown"))
TARGET = os.environ.get("TARGET", "http://example.com").rstrip("/") + "/"
STATE_DIR.mkdir(parents=True, exist_ok=True)

session = requests.Session()
cookie_file = WORKDIR / "cookies.txt"
if cookie_file.exists():
    # Minimal Netscape cookie import for authenticated shots.
    for line in cookie_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) >= 7:
            session.cookies.set(parts[5], parts[6], domain=parts[0].lstrip("."), path=parts[2])

def save(name, content):
    (STATE_DIR / name).write_text(str(content), encoding="utf-8")

print("=== STEP 1: Probe ===")
resp = session.get(urljoin(TARGET, "admin"), timeout=15, allow_redirects=True)
save("probe.resp.txt", resp.text[:5000])
ok = resp.status_code == 200 and "Admin" in resp.text
print(f"REQUEST_SUMMARY: GET /admin status={resp.status_code} marker_admin={ok}")
print(f"SHOT_RESULT: {'EXPLOITED' if ok else 'FAILED'}")
print("VERIFY_COMPLETED: yes" if ok else "VERIFY_COMPLETED: no")
print("EARLY_STOP_ALLOWED: yes" if ok else "EARLY_STOP_ALLOWED: no")
print("FINAL_REASON: admin marker visible" if ok else "FINAL_REASON: marker not visible")
print(f"=== FINAL: {'EXPLOITED' if ok else 'FAILED'} ===")
(STATE_DIR / "result.json").write_text(json.dumps({"status": "EXPLOITED" if ok else "FAILED"}), encoding="utf-8")
sys.exit(0 if ok else 1)
```

Ví dụ SAI (sẽ bị reject):
```
Đây là script khai thác BAC:
#!/usr/bin/env python3
...
```
→ Dòng "Đây là script..." là VI PHẠM → script bị reject.

=== CAC LUU Y BAT BUOC ===

0. ANTI-OVERFITTING / MINIMUM SUFFICIENT PROOF
   - Khong hardcode marker/endpoint cua mot lab. Lay endpoint, marker, account, payload tu approved workflow/dossier.
   - Khong tu them endpoint phu lam dieu kien thanh cong neu workflow khong yeu cau.
   - Neu da dat minimum proof cua hypothesis, in SHOT_RESULT: EXPLOITED va FINAL: EXPLOITED ngay.
   - BAC vertical: low-privileged session thay privileged page/control/admin marker la EXPLOITED.
   - IDOR/BAC horizontal: user A doc duoc object/data cua user B la EXPLOITED.
   - BLF/stateful: gia/balance/cart/order/state thay doi trai logic la EXPLOITED.

1. MOI STEP PHAI CHAY DUNG, KE CA STEP KHAC FAIL
   - KHONG sys.exit(1) ngay khi 1 step fail neu con step doc lap khac
   - Dung bien: step1_ok=True/False, step2_ok=True/False, ... de theo doi
   - Van chay tiep cac step con lai cho du step truoc fail

2. STEP PHA THUOC: parse output tu step truoc
   - Dung requests.Session() de giu cookie.
   - Dung allow_redirects=True khi doc HTML/state.
   - Parse HTML bang re/html.parser/bs4 neu co san; khong phu thuoc vao shell grep/sed.
   - Neu cookie_file la Netscape jar, import vao requests.Session truoc khi probe.

3. KHONG tao shell script con
   - Khong viet bash heredoc/curl pipeline phuc tap trong Python.
   - Neu can request HTTP, dung requests truc tiep.

4. NEU CO VARIANTS (a, b, c): thu lan luot, gap fail thi thu tiep

5. EXIT CODE CUOI CUNG:
   - exit 0 = exploited (co success indicator)
   - exit 1 = failed (workflow that bai)
   - exit 2 = partial (co progress nhung chua exploited)

6. MOI STEP: print "=== STEP N: <mo ta> ===" + detail + print "StepN: SUCCESS/FAIL/EXPLOITED"
   - Moi request nen in tom tat ngan: METHOD PATH status=<code> marker=<text ngan>.
   - Neu response body/status co 405/403/404/500/error page thi step do PHAI FAIL, khong duoc SUCCESS.

7. VERIFY STATEFUL BUG:
   - Neu workflow can before/after, phai in ro baseline va gia tri sau exploit.
   - KHONG duoc echo "FINAL: EXPLOITED" neu marker verify rong, parse fail, hoac delta = 0.
   - Neu chi gui request thanh cong nhung chua verify state, ket luan FINAL: PARTIAL.
   - Chi "request sent", "302 redirect", hoac "response received" KHONG du de EXPLOITED.
   - Shot baseline/discovery chi duoc FINAL: PARTIAL neu chua co verify impact.

8. NEU CO EXECUTION SHOT PLAN:
   - Chi thuc thi dung `CURRENT SHOT SCOPE`, khong gom tat ca shot vao 1 script.
   - Mac dinh shot plan la single-script: baseline/probe/verify nam trong cung script.
   - Neu bat buoc luu artifact, chi luu vao `$STATE_DIR` voi ten trong ARTIFACT CONTRACT.
   - Shot action/exploit chi doc artifact tu shot truoc neu artifact do nam trong `$STATE_DIR`.
   - Verify trong script phai bam minimum proof cua approved workflow.
   - Khong doi them endpoint/tac dong phu neu endpoint/marker hien tai da chung minh hypothesis.
   - Voi BAC/IDOR read-only bang GET/HEAD: neu current shot da tu login/access/verify du bang chung
     (role/session dung, status 2xx, response marker cu the), duoc ket luan EXPLOITED va in
     `VERIFY_COMPLETED: yes`, `EARLY_STOP_ALLOWED: yes`.
   - Neu shot hien tai tao tien de nhung chua chung minh bug, ket luan FINAL: PARTIAL va exit 2.
   - Neu artifact bat buoc bi thieu, in ro thieu file nao va ket luan FINAL: PARTIAL/FAILED.

9. STRUCTURED SUMMARY CUOI SCRIPT:
   Truoc FINAL, print cac dong ngan sau neu co the:
   SHOT_RESULT: EXPLOITED/PARTIAL/FAILED
   REQUEST_SUMMARY: <method path status va marker chinh>
   EVIDENCE_SUMMARY: <baseline/action/after hoac object A/B ngan gon>
   ERRORS: <none hoac loi thuc te nhu 405/parse fail/missing marker>
   VERIFY_COMPLETED: yes/no
   EARLY_STOP_ALLOWED: yes/no
   EARLY_STOP_REASON: <none hoac ly do bang chung da du cho BAC/IDOR read-only>
   FINAL_REASON: <1 cau giai thich vi sao EXPLOITED/PARTIAL/FAILED>

=== INPUT ===

TARGET: <TARGET>
WORKDIR: <WORKDIR>
SESSION: <SESSION/CTX>

=== WORKFLOW / SHOT SCOPE ===
<WORKFLOW>

=== KET QUA ===
Viet script -> tra ve 1 ```python...``` block chứa script hoàn chỉnh.
KHÔNG viết gì khác ngoài script block.
"""


WORKFLOW_EXPLOIT_PROMPT = """\
Ban la executor cho BAC/BLF workflow fallback.

NHIEM VU:
- Bo qua buoc login neu da co `cookies.txt`.
- Dung tool calls de thuc thi cac buoc exploit con lai mot cach tuan tu.
- Uu tien `execute_command` voi `curl` va `cookies.txt`; chi dung browser neu that su can doc giao dien.
- KHONG viet script file. O mode nay ban thuc hien truc tiep bang tools.

QUY TAC:
- Chi bao cao du lieu THUC TE tu tool output.
- Neu gap lap lai cung mot request ma khong co ket qua moi, dung lai va tong hop.
- Ket qua cuoi phai nam trong `=========SEND========= ... =========END-SEND=========` block.
"""


WORKFLOW_ITERATIVE_PROMPT = """\
Ban la executor cho BAC/BLF workflow kho, can nhieu vong LLM + tool de chot exploit.

NHIEM VU:
- Lam viec theo vong: observe -> reason -> act -> observe -> verify.
- Khong duoc ket thuc sau 1 request neu chua co baseline hoac success indicator ro rang.
- Uu tien `execute_command` voi `curl` va `cookies.txt`; browser chi dung khi can doc giao dien
  hoac xac nhan state ma curl khong de nhin.
- Neu lan verify dau tien khong ro, thu mot cach doc state khac truoc khi tong hop.

PHA LAM VIEC:
1. Baseline:
   - Doc trang/endpoint lien quan.
   - Xac dinh marker verify on dinh: tong tien, balance, role, ownership, order content, admin text...
2. Action:
   - Thuc thi tung buoc nho bang tool calls. Khong can gom tat ca vao 1 script duy nhat.
3. Verify:
   - Doc lai state sau action.
   - Neu marker cu khong parse duoc, doi cach verify: grep khac, body text, browser snapshot,
     response status, redirect target, noi dung object, v.v.
4. Final:
   - Chi ket luan EXPLOITED khi co bang chung ro.
   - Neu co tien trien nhung verify chua du, ket luan PARTIAL va noi ro dieu gi dang thieu.

QUY TAC:
- Chi bao cao du lieu THUC TE tu tool output.
- Khong viet script file neu khong can; co the dung curl truc tiep, hoac tao helper ngan neu that su can.
- Khong loop vo han cung mot request neu khong co thong tin moi.
- Ket qua cuoi phai nam trong `=========SEND========= ... =========END-SEND=========` block.
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


def _estimate_min_tool_calls(
    text: str,
    *,
    read_only: bool = False,
) -> int:
    """Estimate a sane minimum number of tool calls before allowing summary."""
    import re

    lower = text.lower()
    base = 2 if read_only else 4
    numbered_items = len(re.findall(r"(?:^|\n)\s*(?:\d+[\)\.]|[-*])\s+", text))

    if numbered_items >= 3:
        base = max(base, 5 if not read_only else 3)
    if any(
        kw in lower
        for kw in (
            "raw evidence", "headers", "csrf", "coupon", "productid",
            "từng mục", "tung muc", "liệt kê", "liet ke", "xác nhận", "xac nhan",
        )
    ):
        base = max(base, 5 if not read_only else 3)

    return base


def _looks_like_empty_cookie(cookie: str) -> bool:
    """Return True for LLM placeholders that are not usable Cookie headers."""
    if not cookie:
        return True
    lower = cookie.strip().lower()
    bad_markers = (
        "empty", "rỗng", "rong", "không lấy", "khong lay", "not found",
        "none", "null", "undefined", "no cookie", "failed",
    )
    if any(marker in lower for marker in bad_markers):
        return True
    if "=" not in cookie:
        return True
    name, _, value = cookie.partition("=")
    return not name.strip() or not value.strip() or any(ch in name for ch in " (),;")


# ═══════════════════════════════════════════════════════════════
# EXEC AGENT CLASS
# ═══════════════════════════════════════════════════════════════

class ExecAgent:
    """Agent thực thi với MCP tools — nhận lệnh từ ManageAgent.

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
        *,
        model: str | None = None,
        memory_store=None,
    ):
        self.working_dir = os.path.abspath(working_dir)
        os.makedirs(self.working_dir, exist_ok=True)
        self.target_url = target_url or ""
        self.model = model or MODEL
        self.toolcall_model = os.getenv("MARL_EXEC_TOOLCALL_MODEL", os.getenv("MARL_TOOLCALL_MODEL", self.model))
        self.recon_context = ""
        self.memory_store = memory_store
        if self.memory_store:
            self.memory_store.register_task("exec_init", "exec", "INIT",
                                             f"ExecAgent khởi tạo cho {self.target_url}")

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

    def answer(self, conversation: list[dict], caller: str = "MANAGER") -> str:
        """Manager-routed question → Agent dùng tools trả lời.

        Build message: system prompt + (target URL + recon data + question).
        Gọi _tool_loop để LLM dùng tools tìm thêm info nếu cần.

        Args:
            conversation: Debate conversation (list of speaker/content dicts).
            caller: Agent label cho SEND fallback/log, chỉ dùng backward-compat.

        Returns:
            Raw text chứa SEND block.
        """
        messages = [{"role": "system", "content": ANSWER_SYSTEM_PROMPT}]

        # ── Build context block ──
        user_content = ""

        if self.target_url:
            user_content += f"=== TARGET URL ===\n{self.target_url}\n\n"

        if self.recon_context:
            recon_str = truncate(self.recon_context)
            user_content += f"=== RECON DATA ===\n{recon_str}\n\n"
        else:
            # Fallback: scan conversation cho crawl data
            crawl_ctx = _find_crawl_context(conversation)
            if crawl_ctx:
                user_content += f"=== RECON DATA ===\n{truncate(crawl_ctx)}\n\n"

        # Question = last message trong conversation
        last_question = conversation[-1].get("content", "") if conversation else ""
        min_tool_calls = _estimate_min_tool_calls(last_question, read_only=False)
        user_content += f"=== QUESTION ===\n{last_question}\n\n"
        user_content += (
            "Tool budget cua ban rong. Neu cau hoi co nhieu muc, hay thu thap bang chung "
            "cho tung muc thay vi dung som.\n\n"
        )
        user_content += "When done, put answer in a complete SEND block. Do not add routing tags."

        messages.append({"role": "user", "content": user_content})

        if self.memory_store:
            mem_ctx = self.memory_store.get_relevant_context(
                agent="exec",
                keywords=["endpoint", "credential", "cookie", "csrf", "lỗ hổng", "verify"],
                max_chars=1200,
            )
            if mem_ctx:
                for m in reversed(messages):
                    if m["role"] == "user":
                        m["content"] = mem_ctx + "\n\n" + m["content"]
                        break

        result = self._tool_loop(
            messages,
            default_tag=caller,
            max_tool_rounds=MAX_TOOL_ROUNDS,
            min_tool_calls_before_finalize=min_tool_calls,
            mode_label="answer",
        )
        if self.memory_store:
            self._save_answer_to_scratchpad(result)
        return result

    def execute(self, conversation: list[dict], caller: str = "MANAGER") -> str:
        """Tìm PoC code trong conversation → save file → chạy python3 → trả kết quả.

        Build message: system prompt + (workspace + target URL + recon context + instruction).
        Gọi _tool_loop để LLM extract code, save, run, report.

        Args:
            conversation: Debate conversation (list of speaker/content dicts).
            caller: Agent label cho SEND fallback/log, chỉ dùng backward-compat.

        Returns:
            Raw text chứa SEND block.
        """
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
            "When done, put results in a complete SEND block. Do not add routing tags."
        )

        messages.append({"role": "user", "content": user_content})

        return self._tool_loop(messages, default_tag=caller)

    def process(self, conversation: list[dict], caller: str = "MANAGER") -> str:
        """Alias cho execute() — backward-compat với debate.py cũ."""
        return self.execute(conversation, caller)

    def run_workflow(
        self,
        workflow_text: str,
        conversation: list[dict] | None = None,
        *,
        max_script_shots: int = DEFAULT_SCRIPT_SHOTS,
        allow_tool_loop: bool = False,
        artifact_prefix: str | None = None,
    ) -> str:
        """Thực thi attack workflow — LOGIN rồi EXPLOIT theo bounded script shots.

        Phase 1 (LOGIN): Dùng Playwright deterministic login để lấy session cookie.
        Phase 2 (EXPLOIT):
          - Manager cấp shot budget hữu hạn (vd. 2-shot hoặc 3-shot).
          - Mỗi shot: LLM viết/revise 1 Python exploit hoàn chỉnh → execute_command 1 lần → parse kết quả.
          - Không tự rơi sang tool-loop trừ khi Manager bật rõ allow_tool_loop.

        Args:
            workflow_text: Chiến lược tấn công từ Red Team (đã được Blue approve).
            conversation: Conversation context (optional).
            artifact_prefix: Prefix để lưu script PoC theo bug, ví dụ bug-001.

        Returns:
            Raw text chứa execution report trong SEND block.
        """

        # ── Phase 1: SESSION PREP (reuse baseline -> import crawl cookies -> HTTP login -> browser fallback) ──
        print(f"\n{YELLOW}{BOLD}[EXEC-AGENT] Phase 1: SESSION PREP{RESET}")

        auth_needed = self._workflow_requires_auth(workflow_text, conversation)
        if auth_needed:
            login_result, session_cookie = self._prepare_authenticated_session(workflow_text, conversation)
        else:
            self._clear_working_cookies()
            login_result = _send_block(
                "LOGIN_STATUS: SKIPPED\n"
                "REASON: Workflow hien tai khong can authenticated session."
            )
            session_cookie = ""

        # ── Phase 2: EXPLOIT ──
        print(
            f"\n{YELLOW}{BOLD}[EXEC-AGENT] Phase 2: EXPLOIT "
            f"(python exploit mode, max_shots={max_script_shots}){RESET}"
        )
        exploit_result = self._run_script_shots(
            workflow_text,
            conversation,
            session_cookie,
            max_script_shots=max_script_shots,
            allow_tool_loop=allow_tool_loop,
            artifact_prefix=artifact_prefix,
        )

        combined = f"=== LOGIN PHASE ===\n{login_result}\n\n=== EXPLOIT PHASE ===\n{exploit_result}"
        if self.memory_store:
            self._save_workflow_result(combined)
        return combined

    def _should_start_iterative(
        self,
        workflow_text: str,
        conversation: list[dict] | None = None,
    ) -> tuple[bool, str]:
        """Decide whether Exec should skip one-shot mode and start iterative immediately."""
        lower = workflow_text.lower()
        hard_keywords = (
            "baseline", "before/after", "before and after", "compare",
            "quantity", "qty", "cart", "checkout", "balance", "wallet",
            "transfer", "business logic", "negative", "decrease", "increase",
            "total", "stateful", "multi-step",
        )
        if any(keyword in lower for keyword in hard_keywords):
            return True, "Workflow looks stateful or needs before/after verification."

        recent_feedback = self._recent_exec_feedback(conversation)
        if recent_feedback:
            lower_feedback = recent_feedback.lower()
            if any(
                marker in lower_feedback
                for marker in (
                    "=== success: partial ===",
                    "partial or unclear",
                    "cannot parse",
                    "failed to parse",
                    "regex",
                    "baseline",
                    "verify",
                    "total",
                    "balance",
                    "cart",
                    "transfer",
                    "runtime/script",
                )
            ):
                return True, "Previous Exec output suggests partial verification or a hard workflow."

        return False, ""

    @staticmethod
    def _result_declares_verify_completed(result: str) -> bool:
        text = str(result or "").lower()
        return bool(
            re.search(r"\bverify_completed\s*:\s*yes\b", text)
            or re.search(r"\bearly_stop_allowed\s*:\s*yes\b", text)
        )

    @staticmethod
    def _workflow_success_requires_final_verify(workflow_text: str) -> bool:
        """Return True for workflows where early script success should keep going."""
        lower = str(workflow_text or "").lower()
        stateful_markers = (
            "blf", "business logic", "stateful", "baseline", "before/after",
            "before and after", "delta", "compare", "cart", "qty", "quantity",
            "checkout", "coupon", "transfer", "balance", "wallet", "total",
            "amount", "negative", "profile/edit", "state-changing",
            "state changing", "mass assignment",
        )
        return any(marker in lower for marker in stateful_markers)

    def _should_continue_after_script_success(
        self,
        *,
        workflow_text: str,
        result: str,
        shot_index: int,
        total_shots: int,
    ) -> bool:
        if shot_index >= total_shots:
            return False
        if self._result_declares_verify_completed(result):
            return False
        return self._workflow_success_requires_final_verify(workflow_text)

    def _workflow_requires_auth(
        self,
        workflow_text: str,
        conversation: list[dict] | None = None,
    ) -> bool:
        """Infer whether the current workflow needs an authenticated session."""
        chunks = [workflow_text]
        if conversation:
            chunks.extend(msg.get("content", "") for msg in conversation[-8:])
        text = "\n".join(chunks)
        lower = text.lower()

        if "auth: required=false" in lower or "auth_required: false" in lower:
            return False
        if "auth: anonymous/mixed" in lower and not self._extract_credentials(workflow_text, conversation)[0]:
            return False
        if self._extract_credentials(workflow_text, conversation)[0]:
            return True
        auth_markers = (
            "auth: required", "authenticated", "login", "dang nhap", "đăng nhập",
            "session", "cookie", "/profile", "/my-account", "/account", "/cart",
            "/checkout", "/transfer", "/orders", "/admin",
        )
        return any(marker in lower for marker in auth_markers)

    def _run_script_shots(
        self,
        workflow_text: str,
        conversation: list[dict] | None,
        session_cookie: str,
        *,
        max_script_shots: int,
        allow_tool_loop: bool,
        artifact_prefix: str | None = None,
    ) -> str:
        """Run a bounded number of script-generation attempts before any other fallback."""
        planned_shots = self._count_execution_shots(workflow_text)
        requested_shots = max(1, min(int(max_script_shots or 1), RETRY_SCRIPT_SHOTS))
        total_shots = requested_shots
        if planned_shots > requested_shots:
            print(
                f"{YELLOW}[EXEC-AGENT] Shot plan has {planned_shots} shots; "
                f"capping to Manager budget={requested_shots}.{RESET}"
            )
        attempts: list[dict] = []
        cookies_path = self._working_cookies_path()

        for shot_index in range(1, total_shots + 1):
            print(f"{YELLOW}[EXEC-AGENT] Script shot {shot_index}/{total_shots}{RESET}")
            script_content = self._generate_exploit_script(
                workflow_text,
                cookies_path,
                session_cookie,
                shot_index=shot_index,
                total_shots=total_shots,
                previous_attempts=attempts,
                artifact_prefix=artifact_prefix,
            )

            if not script_content:
                result = _send_block(
                    "=== EXECUTION OUTPUT ===\n"
                    "[EXEC-AGENT] LLM did not generate a runnable python block.\n\n"
                    "=== SUCCESS: PARTIAL ===\n"
                    "Need another script attempt with clearer correction feedback."
                )
            else:
                result = self._execute_exploit_script(
                    script_content,
                    workflow_text,
                    artifact_prefix=artifact_prefix,
                )

            attempts.append({
                "shot": shot_index,
                "script": script_content,
                "result": result,
            })
            self._log_script_attempt_live(attempts[-1])

            if self._shot_failure_blocks_next(
                workflow_text=workflow_text,
                result=result,
                shot_index=shot_index,
                total_shots=total_shots,
            ):
                print(
                    f"{YELLOW}[EXEC-AGENT] Shot {shot_index} failed a prerequisite; "
                    f"stopping remaining dependent shots.{RESET}"
                )
                break

            if self._script_result_is_success(result):
                if self._should_continue_after_script_success(
                    workflow_text=workflow_text,
                    result=result,
                    shot_index=shot_index,
                    total_shots=total_shots,
                ):
                    print(
                        f"{YELLOW}[EXEC-AGENT] Candidate success before final verify; "
                        f"continuing to next shot.{RESET}"
                    )
                    continue
                break

        final_attempt = attempts[-1]
        final_body = extract_send_block(final_attempt["result"]) or final_attempt["result"]
        history_lines = [
            self._summarize_script_attempt(attempt)
            for attempt in attempts[:-1]
        ]
        if history_lines:
            final_body = (
                f"{final_body.rstrip()}\n\n"
                "=== SCRIPT SHOT HISTORY ===\n"
                + "\n".join(history_lines)
            )

        artifact_lines = []
        for attempt in attempts:
            for artifact in self._extract_script_artifacts(attempt.get("result", "")):
                artifact_lines.append(f"SHOT: {attempt.get('shot', '?')}")
                artifact_lines.append(f"SCRIPT_PATH: {artifact.get('path', '')}")
                if artifact.get("sha256_16"):
                    artifact_lines.append(f"SCRIPT_SHA256: {artifact.get('sha256_16')}")
        if artifact_lines:
            final_body = (
                f"{final_body.rstrip()}\n\n"
                "=== SCRIPT ARTIFACTS ===\n"
                + "\n".join(artifact_lines)
            )

        if (
            allow_tool_loop
            and not self._script_result_is_success(final_attempt["result"])
            and self._script_result_is_runtime_failure(final_attempt["result"])
        ):
            print(f"{YELLOW}[EXEC-AGENT] Manager allowed tool-loop fallback after script shots.{RESET}")
            tool_loop_result = self._execute_iterative_workflow(
                workflow_text,
                "All script shots failed with infrastructure/runtime issues.",
            )
            tool_loop_body = extract_send_block(tool_loop_result) or tool_loop_result
            final_body = (
                f"{final_body.rstrip()}\n\n"
                "=== TOOL LOOP FALLBACK ===\n"
                f"{tool_loop_body.rstrip()}"
            )

        return _send_block(final_body)

    @classmethod
    def _extract_execution_shot_plan(cls, workflow_text: str) -> str:
        """Return the Manager-approved execution shot plan, if present."""
        text = str(workflow_text or "")
        match = re.search(
            r"===\s*EXECUTION SHOT PLAN\s*===\s*(.*?)\s*===\s*END EXECUTION SHOT PLAN\s*===",
            text,
            re.IGNORECASE | re.DOTALL,
        )
        if match:
            return match.group(1).strip()

        # Lenient fallback for older Red output that starts a shot plan but omits the end marker.
        match = re.search(
            r"===\s*EXECUTION SHOT PLAN\s*===\s*(.*)",
            text,
            re.IGNORECASE | re.DOTALL,
        )
        return match.group(1).strip() if match else ""

    @classmethod
    def _count_execution_shots(cls, workflow_text: str) -> int:
        """Count planned execution shots, capped by RETRY_SCRIPT_SHOTS."""
        plan = cls._extract_execution_shot_plan(workflow_text)
        if not plan:
            return 0
        numbers = [
            int(match.group(1))
            for match in re.finditer(r"(?im)^\s*Shot\s+(\d+)\b", plan)
        ]
        if not numbers:
            return 0
        return max(1, min(max(numbers), RETRY_SCRIPT_SHOTS))

    @classmethod
    def _extract_current_shot_scope(cls, workflow_text: str, shot_index: int) -> str:
        """Extract the scope block for the current planned shot."""
        plan = cls._extract_execution_shot_plan(workflow_text)
        if not plan:
            return ""

        pattern = (
            rf"(?ims)^\s*Shot\s+{shot_index}\b.*?"
            rf"(?=^\s*Shot\s+\d+\b|\Z)"
        )
        match = re.search(pattern, plan)
        if match:
            return match.group(0).strip()
        return ""

    def _prepare_authenticated_session(
        self,
        workflow_text: str,
        conversation: list[dict] | None = None,
    ) -> tuple[str, str]:
        """Prepare a clean authenticated session for this bug without relogging unnecessarily."""
        preferred_label = self._preferred_session_label(workflow_text, conversation)
        base_path = self._base_cookies_path(preferred_label)
        work_path = self._working_cookies_path()

        existing_header = self._cookie_header_from_netscape_file(base_path)
        if existing_header:
            self._copy_cookie_file(base_path, work_path)
            print(f"{GREEN}[EXEC-AGENT] Reusing baseline cookies from {base_path}{RESET}")
            return (
                _send_block(
                    "LOGIN_STATUS: REUSED_BASELINE\n"
                    f"COOKIE_FILE: {work_path}\n"
                    f"SESSION_COOKIE: {existing_header}\n"
                    "REASON: Reused clean baseline cookies for this run."
                ),
                existing_header,
            )

        crawl_summary, crawl_header = self._import_crawl_authenticated_session(workflow_text, conversation)
        if crawl_header:
            print(f"{GREEN}[EXEC-AGENT] Imported authenticated cookies from crawl artifacts.{RESET}")
            return crawl_summary, crawl_header

        http_summary, http_header = self._deterministic_http_login(workflow_text, conversation)
        if http_header:
            print(f"{GREEN}[EXEC-AGENT] HTTP login succeeded — baseline session created.{RESET}")
            return http_summary, http_header

        print(f"{YELLOW}[EXEC-AGENT] HTTP login failed — falling back to browser login.{RESET}")
        login_result, session_cookie = self._deterministic_browser_login(workflow_text, conversation)
        if session_cookie and not _looks_like_empty_cookie(session_cookie):
            self._save_cookies_file(session_cookie, path=base_path)
            self._copy_cookie_file(base_path, work_path)
            return login_result, session_cookie

        print(f"{YELLOW}[EXEC-AGENT] Deterministic browser login failed — falling back to LLM login.{RESET}")
        login_messages = [{"role": "system", "content": WORKFLOW_LOGIN_PROMPT}]

        login_content = ""
        if self.target_url:
            login_content += f"=== TARGET URL ===\n{self.target_url}\n\n"
        login_content += f"=== WORKSPACE ===\n{self.working_dir}\n\n"

        login_steps = self._extract_login_steps(workflow_text)
        login_content += f"=== LOGIN INSTRUCTIONS ===\n{login_steps}\n\n"
        login_content += "Login va lay session cookie. Xong thi tra ve trong SEND block day du. Khong them routing tag."

        login_messages.append({"role": "user", "content": login_content})

        login_result = self._tool_loop(
            login_messages,
            default_tag="REDTEAM",
            max_tool_rounds=MAX_WORKFLOW_LOGIN_ROUNDS,
            min_tool_calls_before_finalize=3,
            mode_label="login",
        )

        session_cookie = self._extract_cookie_from_result(login_result)
        if not session_cookie:
            session_cookie = self._extract_cookie_from_browser()
        if session_cookie and not _looks_like_empty_cookie(session_cookie):
            self._save_cookies_file(session_cookie, path=base_path)
            self._copy_cookie_file(base_path, work_path)
            return login_result, session_cookie

        self._clear_working_cookies()
        return login_result, ""

    def _preferred_session_label(
        self,
        workflow_text: str,
        conversation: list[dict] | None = None,
    ) -> str:
        username, _password = self._extract_credentials(workflow_text, conversation)
        return username.strip() if username else ""

    def _base_cookies_path(self, label: str = "") -> str:
        if label:
            safe_label = re.sub(r"[^A-Za-z0-9_.-]+", "_", label)
            return os.path.join(self.working_dir, f"base_cookies_{safe_label}.txt")
        return os.path.join(self.working_dir, BASE_COOKIES_FILENAME)

    def _working_cookies_path(self) -> str:
        return os.path.join(self.working_dir, "cookies.txt")

    def _clear_working_cookies(self) -> None:
        path = self._working_cookies_path()
        if os.path.isfile(path):
            try:
                os.remove(path)
            except OSError:
                pass

    @staticmethod
    def _copy_cookie_file(src: str, dst: str) -> None:
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(src, dst)

    @staticmethod
    def _cookie_header_from_cookie_objects(cookies: list[dict]) -> str:
        pairs: list[str] = []
        for cookie_obj in cookies:
            if not isinstance(cookie_obj, dict):
                continue
            name = str(cookie_obj.get("name", "")).strip()
            value = str(cookie_obj.get("value", "")).strip()
            if name and value:
                pairs.append(f"{name}={value}")
        return "; ".join(pairs)

    @staticmethod
    def _normalize_cookie_domain(domain: str, fallback_host: str = "") -> str:
        raw = (domain or "").strip()
        if not raw:
            return fallback_host
        if "://" in raw:
            parsed = urlparse(raw)
            return parsed.hostname or fallback_host or raw
        parsed = urlparse(f"//{raw}")
        return parsed.hostname or raw.split(":", 1)[0] or fallback_host

    @staticmethod
    def _cookie_header_from_netscape_file(path: str) -> str:
        if not os.path.isfile(path):
            return ""
        pairs: list[str] = []
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    parts = stripped.split("\t")
                    if len(parts) >= 7 and parts[5] and parts[6]:
                        pairs.append(f"{parts[5]}={parts[6]}")
        except OSError:
            return ""
        return "; ".join(pairs)

    def _import_crawl_authenticated_session(
        self,
        workflow_text: str,
        conversation: list[dict] | None = None,
    ) -> tuple[str, str]:
        """Import a clean authenticated cookie set from crawl_raw.json when available."""
        path = Path(self.working_dir) / "crawl_raw.json"
        if not path.is_file():
            return "", ""

        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return "", ""

        authenticated = payload.get("authenticated", []) or []
        if not isinstance(authenticated, list):
            return "", ""

        preferred_label = self._preferred_session_label(workflow_text, conversation).lower()
        chosen: dict | None = None
        for entry in authenticated:
            if not isinstance(entry, dict):
                continue
            label = str(entry.get("label", "")).strip().lower()
            cookies = entry.get("cookies", []) or []
            if preferred_label and label == preferred_label and cookies:
                chosen = entry
                break

        if chosen is None:
            for entry in authenticated:
                if isinstance(entry, dict) and entry.get("auth_verified") and entry.get("cookies"):
                    chosen = entry
                    break

        if chosen is None:
            for entry in authenticated:
                if isinstance(entry, dict) and entry.get("cookies"):
                    chosen = entry
                    break

        if not chosen:
            return "", ""

        cookies = chosen.get("cookies", []) or []
        header = self._cookie_header_from_cookie_objects(cookies)
        if not header:
            return "", ""

        base_path = self._base_cookies_path(preferred_label)
        work_path = self._working_cookies_path()
        self._save_cookie_objects_file(cookies, path=base_path)
        self._copy_cookie_file(base_path, work_path)

        label = str(chosen.get("label", "authenticated")).strip() or "authenticated"
        verified = bool(chosen.get("auth_verified"))
        summary = _send_block(
            "LOGIN_STATUS: IMPORTED_FROM_CRAWL\n"
            f"ACCOUNT_LABEL: {label}\n"
            f"AUTH_VERIFIED_DURING_CRAWL: {verified}\n"
            f"COOKIE_FILE: {work_path}\n"
            f"SESSION_COOKIE: {header}\n"
            "REASON: Imported authenticated cookies captured during crawl."
        )
        return summary, header

    def _deterministic_http_login(
        self,
        workflow_text: str,
        conversation: list[dict] | None = None,
    ) -> tuple[str, str]:
        """Login via direct HTTP requests before falling back to browser/LLM."""
        username, password = self._extract_credentials(workflow_text, conversation)
        if not self.target_url or not username or not password:
            return (
                _send_block(
                    "LOGIN_STATUS: SKIPPED\n"
                    "REASON: Khong tim thay target URL hoac credentials ro rang cho HTTP login."
                ),
                "",
            )

        try:
            import httpx
        except Exception as e:
            return (_send_block(f"LOGIN_STATUS: FAIL\nREASON: httpx import error: {e}"), "")

        login_urls = self._candidate_login_urls()
        last_note = "No suitable login form found."

        with httpx.Client(follow_redirects=True, timeout=20.0) as client:
            for login_url in login_urls:
                try:
                    resp = client.get(login_url)
                except Exception as e:
                    last_note = f"GET {login_url} failed: {e}"
                    continue

                form_info = self._extract_login_form(resp.text, str(resp.url))
                if not form_info:
                    last_note = f"No login form found at {resp.url}"
                    continue

                payload = dict(form_info["hidden_fields"])
                payload[form_info["username_field"]] = username
                payload[form_info["password_field"]] = password

                try:
                    post_resp = client.post(form_info["action_url"], data=payload)
                except Exception as e:
                    last_note = f"POST {form_info['action_url']} failed: {e}"
                    continue

                body_lower = post_resp.text.lower()
                error_keywords = (
                    "incorrect", "wrong password", "wrong username", "login failed",
                    "authentication failed", "sai mật khẩu", "không đúng",
                )
                if any(keyword in body_lower for keyword in error_keywords):
                    last_note = f"HTTP login rejected at {form_info['action_url']}"
                    continue

                cookies = [
                    {
                        "name": cookie.name,
                        "value": cookie.value,
                        "domain": cookie.domain or (urlparse(str(post_resp.url)).hostname or ""),
                        "path": cookie.path or "/",
                        "httpOnly": False,
                        "secure": bool(cookie.secure),
                    }
                    for cookie in client.cookies.jar
                ]
                header = self._cookie_header_from_cookie_objects(cookies)
                if not header:
                    last_note = f"No cookies issued after POST {form_info['action_url']}"
                    continue

                preferred_label = self._preferred_session_label(workflow_text, conversation)
                base_path = self._base_cookies_path(preferred_label)
                work_path = self._working_cookies_path()
                self._save_cookie_objects_file(cookies, path=base_path)
                self._copy_cookie_file(base_path, work_path)

                verified, verify_note = self._verify_http_login_session(client)
                summary = _send_block(
                    "LOGIN_STATUS: HTTP_LOGIN_SUCCESS\n"
                    f"USERNAME: {username}\n"
                    f"LOGIN_URL: {form_info['action_url']}\n"
                    f"COOKIE_FILE: {work_path}\n"
                    f"SESSION_COOKIE: {header}\n"
                    f"VERIFY_NOTE: {verify_note}\n"
                    f"AUTH_PAGE_VERIFIED: {verified}"
                )
                return summary, header

        return (_send_block(f"LOGIN_STATUS: FAIL\nREASON: {last_note}"), "")

    def _generate_exploit_script(
        self,
        workflow_text: str,
        cookies_path: str,
        session_cookie: str,
        *,
        shot_index: int = 1,
        total_shots: int = 1,
        previous_attempts: list[dict] | None = None,
        artifact_prefix: str | None = None,
    ) -> str:
        """Gọi LLM 1 lần để generate/revise Python exploit."""
        messages = [{"role": "system", "content": WORKFLOW_SCRIPT_PROMPT}]

        user_content = ""
        if self.target_url:
            user_content += f"=== TARGET URL ===\n{self.target_url}\n\n"
        user_content += f"=== WORKSPACE ===\n{self.working_dir}\n\n"
        user_content += f"=== SCRIPT SHOT ===\nShot {shot_index}/{total_shots}\n\n"
        safe_prefix = self._safe_artifact_prefix(artifact_prefix or "bug-unknown")
        state_dir = os.path.join(self.working_dir, "exploit_state", safe_prefix)
        user_content += (
            "=== ARTIFACT CONTRACT ===\n"
            f"BUG_ID: {safe_prefix}\n"
            f"STATE_DIR: {state_dir}\n"
            "Script must create STATE_DIR and save only these shared artifact names when relevant:\n"
            "- baseline.req.txt, baseline.resp.txt\n"
            "- probe.req.txt, probe.resp.txt\n"
            "- verify.req.txt, verify.resp.txt\n"
            "- result.json\n"
            "Do not depend on ad-hoc names such as admin_page.html, own_order_id.txt, or vulnerable_id.txt.\n"
            "For one-shot plans, do baseline/probe/verify inside the same script instead of chaining files.\n\n"
        )
        shot_plan = self._extract_execution_shot_plan(workflow_text)
        shot_scope = self._extract_current_shot_scope(workflow_text, shot_index)

        if session_cookie:
            user_content += (
                f"=== SESSION (tu buoc login) ===\n"
                f"Cookie: {session_cookie}\n"
                f"COOKIE_FILE: {cookies_path}\n"
                f"Dung absolute path: curl -sS -L -b '{cookies_path}' ...\n"
                "Session prep da tao/import cookie hop le truoc khi script duoc sinh. "
                "KHONG login lai cho primary user neu CURRENT SHOT chi can baseline/access voi session hien co; "
                "hay validate session bang GET trang lien quan va dung COOKIE_FILE. "
                "Chi tao/login user bo sung neu shot scope yeu cau provisioning user B/user moi.\n"
                "Khi doc state HTML de verify, BAT BUOC dung -L de follow redirect.\n\n"
            )
        else:
            user_content += (
                "=== SESSION ===\n"
                "Chua co cookie tu buoc login.\n"
                "Neu co file cookies.txt ton tai, dung no cho buoc login.\n"
                "Neu khong, script phai tu login bang curl truoc.\n\n"
                "Khi doc state HTML de verify, BAT BUOC dung curl -sS -L de follow redirect.\n\n"
            )

        if previous_attempts:
            history_lines = []
            for attempt in previous_attempts[-2:]:
                history_lines.append(self._summarize_script_attempt(attempt))
            if history_lines:
                user_content += (
                    "=== PREVIOUS SHOT FEEDBACK ===\n"
                    + "\n".join(history_lines)
                    + "\n\n"
                )
                user_content += (
                    "Sua script de tranh lap lai cac loi tren. "
                    "Khong lap lai cung mot cach verify neu no da fail o shot truoc.\n\n"
                )

        if shot_plan:
            user_content += (
                "=== APPROVED EXECUTION SHOT PLAN ===\n"
                f"{shot_plan}\n\n"
            )
            if shot_scope:
                user_content += (
                    "=== CURRENT SHOT SCOPE (ONLY THIS SHOT) ===\n"
                    f"{shot_scope}\n\n"
                    "Chi viet script cho CURRENT SHOT SCOPE. "
                    "Khong thuc hien truoc cac shot sau neu shot hien tai chi la baseline/action.\n"
                    "Dung thu muc `$WORKDIR/exploit_state` de luu/doc artifact giua cac shot.\n"
                    "Ngoai le: neu BAC/IDOR read-only va shot hien tai da tu verify du bang chung "
                    "(role/session dung, status 2xx, marker response cu the), hay in VERIFY_COMPLETED: yes "
                    "va EARLY_STOP_ALLOWED: yes. Khong yeu cau them endpoint/tac dong phu neu minimum proof "
                    "da chung minh hypothesis.\n\n"
                )
            else:
                user_content += (
                    "=== CURRENT SHOT SCOPE ===\n"
                    "Khong tim thay scope rieng cho shot nay trong shot plan. "
                    "Hay thuc thi phan tiep theo hop ly nhat cua workflow va in ro PARTIAL neu chua verify.\n\n"
                )

        user_content += f"=== FULL ATTACK WORKFLOW ===\n{workflow_text}\n\n"
        user_content += (
                "Viet Python exploit file, chay no, bao cao ket qua.\n"
            "Xong thi tra ve trong SEND block day du. Khong them routing tag."
        )

        messages.append({"role": "user", "content": user_content})

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.3,
                max_tokens=4096,
            )
        except Exception as e:
            print(f"{RED}[EXEC-AGENT] Script generation LLM call failed: {e}{RESET}")
            return ""

        text = response.choices[0].message.content or ""

        # Extract Python script from markdown code block
        match = re.search(r"```(?:python|py)\s*(.*?)\s*```", text, re.DOTALL | re.IGNORECASE)
        if match:
            script = self._normalize_generated_python(match.group(1).strip())
            print(f"{GREEN}[EXEC-AGENT] Generated Python exploit ({len(script)} chars){RESET}")
            return script

        # Fallback: if no code block, signal failure so caller falls back to tool_loop
        print(f"{YELLOW}[EXEC-AGENT] No python block found in LLM output — will use fallback.{RESET}")
        return ""

    def _execute_exploit_script(
        self,
        script_content: str,
        workflow_text: str,
        *,
        artifact_prefix: str | None = None,
    ) -> str:
        """Execute a Python exploit script and return structured output."""
        try:
            script_path, script_sha = self._save_exploit_script_artifact(
                script_content,
                artifact_prefix,
            )
        except Exception as e:
            return _send_block(f"[EXEC-AGENT] Failed to save script artifact: {e}")
        syntax_log_path = self._artifact_log_path(script_path, ".syntax.txt")
        exec_output_path = self._artifact_log_path(script_path, ".output.txt")
        syntax_cmd = f"python3 -m py_compile {shlex.quote(script_path)} 2>&1"
        safe_prefix = self._safe_artifact_prefix(artifact_prefix or "bug-unknown")
        state_dir = Path(self.working_dir) / "exploit_state" / safe_prefix
        state_dir.mkdir(parents=True, exist_ok=True)
        runtime_env = (
            f"WORKDIR={shlex.quote(self.working_dir)} "
            f"BUG_ID={shlex.quote(safe_prefix)} "
            f"STATE_DIR={shlex.quote(str(state_dir))} "
            f"TARGET={shlex.quote(self.target_url)}"
        )
        runtime_cmd = (
            f"cd {shlex.quote(self.working_dir)} && "
            f"{runtime_env} python3 {shlex.quote(script_path)} 2>&1"
        )

        lines = script_content.strip().split("\n")
        # Line 1 must be a Python shebang — no prose before it.
        first_line = lines[0].strip() if lines else ""
        valid_shebang = first_line.startswith("#!/") and "python" in first_line.lower()
        has_http_client = any(
            re.search(r"\b(requests|urllib\.request|http\.client)\b|session\.(get|post|put|patch|delete)\(", l)
            for l in lines
        )
        has_artifact_io = any(
            re.search(r"\b(open|Path|write_text|read_text|json\.dump|json\.dumps)\b", l)
            for l in lines
        )
        has_code = any(l.strip() and not l.strip().startswith("#") for l in lines[1:])
        has_final_marker = "=== FINAL:" in script_content
        # Check first lines for prose outside comments/imports.
        is_prose = any(
            len(l.strip()) > 150
            and not l.strip().startswith("#")
            and not l.strip().startswith(("import ", "from ", "def ", "class ", "if ", "for ", "while ", "print("))
            for l in lines[:8]
        )

        if not valid_shebang or not (has_http_client or has_artifact_io) or not has_code or not has_final_marker or is_prose:
            print(f"{YELLOW}[EXEC-AGENT] Python exploit validation FAILED — returning invalid-script feedback.{RESET}")
            print(
                f"{YELLOW}  valid_shebang={valid_shebang} has_http_client={has_http_client} "
                f"has_artifact_io={has_artifact_io} has_code={has_code} "
                f"has_final_marker={has_final_marker} is_prose={is_prose}{RESET}"
            )
            return _send_block(
                "=== EXECUTION ARTIFACT ===\n"
                f"SCRIPT_PATH: {script_path}\n"
                f"SCRIPT_SHA256: {script_sha}\n"
                "SYNTAX_CHECK: SKIPPED\n"
                f"SYNTAX_LOG_PATH: {syntax_log_path}\n"
                f"EXEC_OUTPUT_PATH: {exec_output_path}\n\n"
                "=== EXECUTION OUTPUT ===\n"
                "[EXEC-AGENT] Python exploit validation failed before execution.\n"
                f"valid_shebang={valid_shebang} has_http_client={has_http_client} "
                f"has_artifact_io={has_artifact_io} has_code={has_code} "
                f"has_final_marker={has_final_marker} is_prose={is_prose}\n\n"
                "=== SUCCESS: PARTIAL ===\n"
                "Need a corrected Python exploit in the next shot."
            )

        syntax_check = self.mcp.execute_tool("execute_command", {
            "command": syntax_cmd
        })
        syntax_raw = str(syntax_check)
        self._write_text_artifact(syntax_log_path, syntax_raw)
        syntax_output = self._extract_bash_output(syntax_raw)
        if self._extract_return_code(syntax_raw) != 0:
            print(f"{YELLOW}[EXEC-AGENT] python py_compile FAILED — returning syntax feedback.{RESET}")
            syntax_preview = self._preview_output_lines(syntax_output, max_lines=8)
            if syntax_preview:
                print(f"{DIM}[EXEC-AGENT]   syntax summary:{RESET}")
                for line in syntax_preview:
                    print(f"{DIM}[EXEC-AGENT]     {line}{RESET}")
            return _send_block(
                "=== EXECUTION ARTIFACT ===\n"
                f"SCRIPT_PATH: {script_path}\n"
                f"SCRIPT_SHA256: {script_sha}\n"
                "SYNTAX_CHECK: FAIL\n"
                f"SYNTAX_LOG_PATH: {syntax_log_path}\n"
                f"EXEC_OUTPUT_PATH: {exec_output_path}\n\n"
                "=== EXECUTION OUTPUT ===\n"
                f"{truncate(syntax_raw, 3000)}\n\n"
                "=== SUCCESS: PARTIAL ===\n"
                "Need a corrected Python exploit in the next shot."
            )

        # Execute the script
        print(f"{YELLOW}[EXEC-AGENT] Running Python exploit: {self._display_path(script_path)}{RESET}")
        try:
            result = self.mcp.execute_tool("execute_command", {
                "command": runtime_cmd
            })
            raw_output = str(result)
        except Exception as e:
            raw_output = f"Script execution error: {e}"
        self._write_text_artifact(exec_output_path, self._extract_bash_output(raw_output))

        # Extract process exit code
        process_exit_code = self._extract_return_code(raw_output)

        # Parse for success/failure signals — priority: script's own === FINAL: line
        lower = raw_output.lower()
        final_exploited = "=== final: exploited ===" in lower
        final_partial = "=== final: partial ===" in lower
        final_failed = "=== final: failed ===" in lower
        evidence_warning = self._stateful_evidence_warning(raw_output, workflow_text) if final_exploited else ""

        # Check SUCCESS verdict from script header (set by _execute_exploit_script itself)
        m_verdict = re.search(r"=== success:\s*(\w+)", lower)
        script_verdict = m_verdict.group(1) if m_verdict else ""

        # Determine verdict with correct priority
        if final_exploited and evidence_warning:
            verdict = "PARTIAL"
        elif final_exploited:
            verdict = "YES"
        elif final_failed:
            verdict = "NO"
        elif final_partial:
            verdict = "PARTIAL"
        elif script_verdict == "yes":
            verdict = "YES"
        elif script_verdict == "no":
            verdict = "NO"
        elif script_verdict == "partial":
            verdict = "PARTIAL"
        elif process_exit_code == 0:
            # Exit 0 without a FINAL marker is not enough proof for Manager.
            verdict = "PARTIAL"
        else:
            verdict = "PARTIAL"  # Ambiguous — don't mark as failure

        artifact_contract = self._validate_state_dir_artifacts(state_dir)
        artifact_contract_lines = self._format_artifact_contract_lines(artifact_contract)

        report = (
            "=========SEND=========\n"
            "=== EXECUTION ARTIFACT ===\n"
            f"SCRIPT_PATH: {script_path}\n"
            f"SCRIPT_SHA256: {script_sha}\n"
            "SYNTAX_CHECK: PASS\n"
            f"SYNTAX_LOG_PATH: {syntax_log_path}\n"
            f"EXEC_OUTPUT_PATH: {exec_output_path}\n"
            f"STATE_DIR: {artifact_contract['state_dir']}\n"
            f"RESULT_JSON_PATH: {artifact_contract['result_json_path']}\n"
            f"ARTIFACT_CONTRACT: {artifact_contract['status']}\n"
            f"{artifact_contract_lines}"
            + (f"EVIDENCE_GUARD: DOWNGRADED - {evidence_warning}\n" if evidence_warning else "")
            + "\n"
            f"=== EXECUTION OUTPUT ===\n"
            f"{truncate(raw_output, 5000)}\n\n"
            f"=== SUCCESS: {verdict} ===\n"
            f"Exit code signals: {'exploit may have worked' if verdict == 'YES' else 'partial or unclear' if verdict == 'PARTIAL' else 'failed'}\n"
            "=========END-SEND========="
        )
        return report

    def _save_exploit_script_artifact(
        self,
        script_content: str,
        artifact_prefix: str | None,
    ) -> tuple[str, str]:
        """Persist each generated exploit shot without overwriting previous PoCs."""
        prefix = self._safe_artifact_prefix(artifact_prefix or "bug-unknown")
        exploits_dir = Path(self.working_dir) / "exploits"
        exploits_dir.mkdir(parents=True, exist_ok=True)

        next_index = self._next_exploit_index(exploits_dir, prefix)
        script_path = exploits_dir / f"{prefix}-exploit{next_index}.py"
        content = script_content.rstrip() + "\n"
        script_path.write_text(content, encoding="utf-8")
        os.chmod(script_path, 0o755)

        # Backward-compatible alias for older debugging habits; named artifacts remain source of truth.
        latest_path = Path(self.working_dir) / "exploit.py"
        shutil.copyfile(script_path, latest_path)
        os.chmod(latest_path, 0o755)

        digest = hashlib.sha256(script_path.read_bytes()).hexdigest()
        print(f"{GREEN}[EXEC-AGENT] Saved script: {self._display_path(script_path)}{RESET}")
        return str(script_path), digest[:16]

    def _display_path(self, path: str | Path) -> str:
        """Return a readable workspace-relative path for live logs."""
        path_obj = Path(path)
        try:
            return str(path_obj.relative_to(Path(self.working_dir)))
        except ValueError:
            return str(path_obj)

    @staticmethod
    def _safe_artifact_prefix(prefix: str) -> str:
        safe = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(prefix).strip().lower())
        safe = re.sub(r"-+", "-", safe).strip("-")
        return safe or "bug-unknown"

    @staticmethod
    def _normalize_generated_python(script: str) -> str:
        """Normalize a generated Python exploit block before saving it."""
        text = str(script or "").strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:python|py)?\s*", "", text, flags=re.IGNORECASE)
            text = re.sub(r"\s*```$", "", text)
        return text

    @staticmethod
    def _next_exploit_index(exploits_dir: Path, prefix: str) -> int:
        pattern = re.compile(rf"^{re.escape(prefix)}-exploit(\d+)\.(?:py|sh)$")
        max_index = 0
        for path in list(exploits_dir.glob(f"{prefix}-exploit*.py")) + list(exploits_dir.glob(f"{prefix}-exploit*.sh")):
            match = pattern.match(path.name)
            if match:
                max_index = max(max_index, int(match.group(1)))
        return max_index + 1

    @staticmethod
    def _extract_return_code(raw_output: str) -> int:
        m_rc = re.search(r'"return_code"\s*:\s*(-?\d+)', raw_output)
        if not m_rc:
            return -1
        try:
            return int(m_rc.group(1))
        except ValueError:
            return -1

    @staticmethod
    def _extract_script_artifacts(result: str) -> list[dict]:
        paths = re.findall(r"^SCRIPT_PATH:\s*(.+?)\s*$", str(result), re.MULTILINE)
        shas = re.findall(r"^SCRIPT_SHA256:\s*(.+?)\s*$", str(result), re.MULTILINE)
        artifacts = []
        for idx, path in enumerate(paths):
            item = {"path": path.strip()}
            if idx < len(shas):
                item["sha256_16"] = shas[idx].strip()
            artifacts.append(item)
        return artifacts

    @staticmethod
    def _extract_bash_output(raw_output: str) -> str:
        """Extract decoded command stdout/stderr from MCP execute_command output."""
        m_out = re.search(r'"output"\s*:\s*"([^"]*(?:\\.[^"]*)*)"', raw_output, re.DOTALL)
        if not m_out:
            return raw_output
        return m_out.group(1).encode().decode("unicode_escape", errors="ignore")

    @staticmethod
    def _extract_json_string_value(raw_output: str, key: str) -> str:
        match = re.search(rf'"{re.escape(key)}"\s*:\s*"([^"]*(?:\\.[^"]*)*)"', str(raw_output), re.DOTALL)
        if not match:
            return ""
        return match.group(1).encode().decode("unicode_escape", errors="ignore")

    @staticmethod
    def _artifact_log_path(script_path: str, suffix: str) -> str:
        return f"{script_path}{suffix}"

    @staticmethod
    def _write_text_artifact(path: str, content: str) -> None:
        Path(path).write_text(str(content or ""), encoding="utf-8")

    @classmethod
    def _validate_state_dir_artifacts(cls, state_dir: Path) -> dict:
        """Check the lightweight artifact contract without blocking execution."""
        result_json_path = state_dir / "result.json"
        expected_evidence = (
            "baseline.req.txt", "baseline.resp.txt",
            "probe.req.txt", "probe.resp.txt",
            "verify.req.txt", "verify.resp.txt",
        )
        existing_evidence = [
            name for name in expected_evidence
            if (state_dir / name).is_file() and (state_dir / name).stat().st_size > 0
        ]
        warnings: list[str] = []

        result_json_status = "MISSING"
        if result_json_path.is_file() and result_json_path.stat().st_size > 0:
            try:
                data = json.loads(result_json_path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    result_json_status = "VALID_JSON"
                    useful_keys = {
                        "status", "verdict", "final", "result", "evidence",
                        "evidence_summary", "request_summary", "errors",
                        "shot_result", "exploit_status", "final_reason",
                        "verify_completed", "early_stop_reason",
                    }
                    if not any(key in data for key in useful_keys):
                        warnings.append("result.json valid JSON but lacks status/evidence keys")
                else:
                    result_json_status = "INVALID_SHAPE"
                    warnings.append("result.json is JSON but not an object")
            except Exception as exc:
                result_json_status = "INVALID_JSON"
                warnings.append(f"result.json invalid JSON: {type(exc).__name__}")
        else:
            warnings.append("result.json missing or empty")

        if not existing_evidence:
            warnings.append("no baseline/probe/verify req/resp artifacts saved")

        return {
            "status": "PASS" if not warnings else "WARN",
            "state_dir": str(state_dir),
            "result_json_path": str(result_json_path),
            "result_json_status": result_json_status,
            "evidence_files": existing_evidence,
            "warnings": warnings[:4],
        }

    @staticmethod
    def _format_artifact_contract_lines(contract: dict) -> str:
        lines = [
            f"RESULT_JSON_STATUS: {contract.get('result_json_status', 'UNKNOWN')}\n",
        ]
        evidence_files = contract.get("evidence_files") or []
        if evidence_files:
            lines.append(f"EVIDENCE_FILES_SAVED: {', '.join(evidence_files[:8])}\n")
        warnings = contract.get("warnings") or []
        if warnings:
            lines.append("ARTIFACT_WARNINGS:\n")
            for warning in warnings:
                lines.append(f"- {warning}\n")
        return "".join(lines)

    @staticmethod
    def _script_preview_lines(script_content: str, max_lines: int = 12) -> list[str]:
        lines = [line.rstrip("\n") for line in str(script_content or "").splitlines()]
        if not lines:
            return []
        preview = [f"{idx:02d}: {line}" for idx, line in enumerate(lines[:max_lines], start=1)]
        if len(lines) > max_lines:
            preview.append(f"... ({len(lines) - max_lines} more lines)")
        return preview

    @staticmethod
    def _preview_output_lines(text: str, max_lines: int = 10) -> list[str]:
        lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
        if not lines:
            return []
        preview = [truncate(line, 180) for line in lines[:max_lines]]
        if len(lines) > max_lines:
            preview.append(f"... ({len(lines) - max_lines} more lines)")
        return preview

    @classmethod
    def _stateful_evidence_warning(cls, raw_output: str, workflow_text: str) -> str:
        """Downgrade weak stateful proofs that print FINAL: EXPLOITED without measurable evidence."""
        output = cls._extract_bash_output(raw_output)
        lower = output.lower()
        workflow_lower = workflow_text.lower()
        stateful_keywords = (
            "balance", "số dư", "so du", "amount", "transfer", "wallet",
            "total", "cart", "qty", "quantity", "profile/edit", "before", "after",
            "baseline", "negative",
        )
        if not any(keyword in workflow_lower for keyword in stateful_keywords):
            return ""

        empty_value_patterns = (
            r"(balance before|balance after|current balance|new balance|baseline total|"
            r"total before|total after|old values[^:\n]*|new values[^:\n]*)\s*:\s*(?:\n|$)",
            r"before attack \(step\d+\)\s*:\s*\n\s*after attack",
            r"before[^:\n]*:\s*\n\s*after[^:\n]*:\s*(?:\n|$)",
        )
        for pattern in empty_value_patterns:
            if re.search(pattern, lower):
                return "stateful verify marker is empty"

        if "difference: 0" in lower and any(k in workflow_lower for k in ("balance", "amount", "transfer")):
            return "stateful before/after delta is zero"

        weak_markers = (
            "405 method not allowed",
            "method not allowed",
            "403 forbidden",
            "404 not found",
            "500 internal server error",
            "could not parse",
            "failed to parse",
            "not expected",
            "unchanged",
            "redirecting...</title>",
        )
        if any(marker in lower for marker in weak_markers):
            strong_markers = (
                "step4: exploited",
                "step5: exploited",
                "confirmed",
                "negative quantity detected",
                "admin dashboard",
            )
            if not any(marker in lower for marker in strong_markers):
                return "output contains weak/redirect evidence without a confirmed marker"

        return ""

    @staticmethod
    def _should_escalate_after_script(exploit_result: str) -> bool:
        """Return True when a one-shot script should be followed by iterative execution."""
        lower = exploit_result.lower()
        if "=== success: yes ===" in lower:
            return False
        if "=== success: partial ===" in lower:
            return True
        fragile_markers = (
            "partial or unclear",
            "cannot parse",
            "failed to parse",
            "regex",
            "not found",
            "empty",
            "unclear",
            "timed out",
            "syntax error",
            "syntax_check: fail",
            "script validation failed",
            "python py_compile failed",
            "need a corrected python exploit",
            "command not found",
            "script execution error",
        )
        return any(marker in lower for marker in fragile_markers)

    @staticmethod
    def _script_result_is_success(exploit_result: str) -> bool:
        lower = exploit_result.lower()
        return "=== success: yes ===" in lower

    @classmethod
    def _script_result_is_failed(cls, exploit_result: str) -> bool:
        lower = str(exploit_result or "").lower()
        if "=== success: no ===" in lower or "=== final: failed ===" in lower:
            return True
        rc = cls._extract_return_code(str(exploit_result or ""))
        return rc == 1

    @classmethod
    def _shot_failure_blocks_next(
        cls,
        *,
        workflow_text: str,
        result: str,
        shot_index: int,
        total_shots: int,
    ) -> bool:
        """Stop chained shot plans when a required setup shot failed."""
        if shot_index >= total_shots or not cls._script_result_is_failed(result):
            return False

        output = cls._extract_bash_output(str(result or "")).lower()
        current_scope = cls._extract_current_shot_scope(workflow_text, shot_index).lower()
        next_scope = cls._extract_current_shot_scope(workflow_text, shot_index + 1).lower()
        if not next_scope:
            return False

        failed_setup_markers = (
            "login failed",
            "registration failed",
            "could not determine",
            "could not establish",
            "cannot proceed",
            "missing",
            "not found",
            "no session",
            "no cookie",
            "khong tao",
            "không tạo",
            "khong co",
            "không có",
        )
        next_dependency_markers = (
            "input:",
            "from shot",
            "tu shot",
            "từ shot",
            "artifact",
            "must save",
            "baseline",
            "session b",
            "user_id b",
            "cookies_user",
            "user_b_id",
            "exploit_response",
            "verify_response",
        )
        current_setup_markers = (
            "baseline",
            "provisioning",
            "login",
            "register",
            "discovery",
            "thiết lập",
            "thiet lap",
            "tao user",
            "tạo user",
        )
        return (
            any(marker in output for marker in failed_setup_markers)
            and any(marker in next_scope for marker in next_dependency_markers)
            and any(marker in current_scope for marker in current_setup_markers)
        )

    @staticmethod
    def _script_result_is_runtime_failure(exploit_result: str) -> bool:
        lower = exploit_result.lower()
        runtime_markers = (
            "[api error",
            "[llm error",
            "connection error",
            "command not found",
            "syntax error",
            "syntax_check: fail",
            "script validation failed",
            "python py_compile failed",
            "need a corrected python exploit",
            "[timeout]",
            "timed out",
            "script execution error",
            "failed to save script",
        )
        if any(marker in lower for marker in runtime_markers):
            return True
        m_rc = re.search(r'"return_code"\s*:\s*(\d+)', exploit_result, re.DOTALL)
        return bool(m_rc and int(m_rc.group(1)) == 127)

    @classmethod
    def _summarize_script_attempt(cls, attempt: dict) -> str:
        shot = attempt.get("shot", "?")
        result = str(attempt.get("result", ""))
        lower = result.lower()
        verdict = "UNKNOWN"
        if "=== success: yes ===" in lower:
            verdict = "YES"
        elif "=== success: no ===" in lower or "=== final: failed ===" in lower:
            verdict = "NO"
        elif "=== success: partial ===" in lower or "=== final: partial ===" in lower:
            verdict = "PARTIAL"

        key_lines = cls._extract_key_output_lines(result)
        if key_lines:
            snippet = " | ".join(key_lines[:6])
        else:
            snippet = extract_send_block(result) or result
            snippet = re.sub(r"\s+", " ", snippet).strip()
        snippet = truncate(snippet, 260)
        return f"- Shot {shot}: verdict={verdict}; note={snippet}"

    @classmethod
    def _log_script_attempt_live(cls, attempt: dict) -> None:
        shot = attempt.get("shot", "?")
        result = str(attempt.get("result", ""))
        verdict = cls._script_attempt_verdict(result)
        syntax_status = cls._extract_send_value(result, "SYNTAX_CHECK")
        rc = cls._extract_return_code(result)
        final_marker = cls._extract_final_marker(result)
        output_lines = cls._extract_key_output_lines(result)

        print(
            f"{YELLOW}[EXEC-AGENT] Shot {shot} result: verdict={verdict} "
            f"rc={rc} syntax={syntax_status or 'UNKNOWN'} final={final_marker or 'NONE'}{RESET}"
        )
        if output_lines:
            print(f"{DIM}[EXEC-AGENT]   output summary:{RESET}")
            for idx, line in enumerate(output_lines[:6], start=1):
                print(f"{DIM}[EXEC-AGENT]     {idx:02d}. {line}{RESET}")
        else:
            print(f"{DIM}[EXEC-AGENT]   output summary: <no concise lines captured>{RESET}")

    @staticmethod
    def _extract_send_value(result: str, key: str) -> str:
        match = re.search(rf"^{re.escape(key)}:\s*(.+?)\s*$", str(result), re.MULTILINE)
        return match.group(1).strip() if match else ""

    @classmethod
    def _script_attempt_verdict(cls, result: str) -> str:
        lower = str(result).lower()
        if "=== success: yes ===" in lower:
            return "YES"
        if "=== success: no ===" in lower or "=== final: failed ===" in lower:
            return "NO"
        if "=== success: partial ===" in lower or "=== final: partial ===" in lower:
            return "PARTIAL"
        return "UNKNOWN"

    @classmethod
    def _extract_final_marker(cls, result: str) -> str:
        output = cls._extract_bash_output(str(result))
        match = re.search(r"=== FINAL:\s*([A-Z_ ]+?)\s*===", output)
        if match:
            return match.group(1).strip()
        return ""

    @classmethod
    def _extract_key_output_lines(cls, result: str) -> list[str]:
        output = cls._extract_bash_output(str(result))
        interesting: list[str] = []
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            lower = line.lower()
            if (
                line.startswith("=== STEP")
                or line.startswith("=== FINAL")
                or line.startswith("=== VERIFICATION")
                or line.startswith("Step")
                or line.startswith("Baseline")
                or line.startswith("Before")
                or line.startswith("After")
                or line.startswith("Current")
                or line.startswith("Error")
                or line.startswith("Final")
                or line.startswith("Delta")
                or line.startswith("Found ")
                or line.startswith("Trying ")
                or line.startswith("Login response")
                or line.startswith("Response length")
                or line.startswith("Orders page")
                or line.startswith("Products page")
                or line.startswith("Cart page")
                or line.startswith("Profile ")
                or line.startswith("My order response")
                or line.startswith("Using ")
                or line.startswith("HTTP Code:")
                or "verified" in lower
                or "vulnerable" in lower
                or "success" in lower and (
                    lower.startswith("step")
                    or lower.startswith("login")
                    or lower.startswith("baseline")
                    or lower.startswith("final")
                )
                or "forbidden" in lower
                or "not found" in lower
                or "method not allowed" in lower
                or "internal server error" in lower
                or "redirect" in lower
                or "syntax error" in lower
                or "command not found" in lower
                or "permission denied" in lower
                or "could not" in lower
            ):
                interesting.append(line)
        if len(interesting) > 12:
            interesting = interesting[-12:]
        return interesting

    @staticmethod
    def _recent_exec_feedback(conversation: list[dict] | None = None) -> str:
        """Return the latest Exec-related message from the conversation, if any."""
        if not conversation:
            return ""
        for msg in reversed(conversation):
            speaker = msg.get("speaker", "")
            content = msg.get("content", "")
            if speaker == "AGENT" and "execution result" in content.lower():
                return content
            if speaker == "SYSTEM" and "manager instruction:" in content.lower():
                return content
        return ""

    def _execute_iterative_workflow(self, workflow_text: str, reason: str = "") -> str:
        """Run a multi-turn exploit loop for stateful or verification-fragile workflows."""
        return self._execute_via_tool_loop(
            workflow_text,
            reason=reason,
            prompt=WORKFLOW_ITERATIVE_PROMPT,
            max_tool_rounds=MAX_ITERATIVE_WORKFLOW_ROUNDS,
            min_tool_calls_before_finalize=4,
            allow_browser=True,
        )

    def _execute_via_tool_loop(
        self,
        workflow_text: str,
        *,
        reason: str = "",
        prompt: str = WORKFLOW_EXPLOIT_PROMPT,
        max_tool_rounds: int = 25,
        min_tool_calls_before_finalize: int = 0,
        allow_browser: bool = False,
    ) -> str:
        """Fallback: step-by-step exploit via _tool_loop (original method)."""
        print(f"{YELLOW}[EXEC-AGENT] Falling back to _tool_loop for exploit{RESET}")
        active_tools = (
            self.tools
            if allow_browser
            else self.mcp.get_openai_tools(exclude_servers={"playwright"})
        )
        exploit_messages = [{"role": "system", "content": prompt}]
        exploit_content = ""
        if self.target_url:
            exploit_content += f"=== TARGET URL ===\n{self.target_url}\n\n"
        exploit_content += f"=== WORKSPACE ===\n{self.working_dir}\n\n"
        cookies_path = os.path.join(self.working_dir, "cookies.txt")
        if os.path.isfile(cookies_path):
            exploit_content += f"COOKIE_FILE: {cookies_path}\n\n"
        if reason:
            exploit_content += f"=== EXECUTION NOTE ===\n{reason}\n\n"
        exploit_content += f"=== ATTACK WORKFLOW ===\n{workflow_text}\n\n"
        if allow_browser:
            exploit_content += (
                "Bo qua buoc login (da xong). Lam theo vong observe -> act -> verify. "
                "Neu verify dau tien khong ro, thu cach doc state khac truoc khi ket thuc."
            )
        else:
            exploit_content += "Bo qua buoc login (da xong). Thuc thi cac buoc con lai bang CURL."
        exploit_messages.append({"role": "user", "content": exploit_content})
        result = self._tool_loop(
            exploit_messages,
            default_tag="REDTEAM",
            max_tool_rounds=max_tool_rounds,
            min_tool_calls_before_finalize=min_tool_calls_before_finalize,
            mode_label="workflow",
            tools_override=active_tools,
        )
        if extract_send_block(result):
            return result
        return _send_block(f"=== EXECUTION OUTPUT ===\n{truncate(result, 5000)}")

    @staticmethod
    def _extract_login_steps(workflow_text: str) -> str:
        """Extract login-related steps from workflow text."""
        lines = workflow_text.split("\n")
        login_lines = []
        in_login = False
        for line in lines:
            lower = line.lower()
            if any(kw in lower for kw in ("login", "dang nhap", "đăng nhập", "credentials", "buoc 1", "bước 1", "step 1")):
                in_login = True
            if in_login:
                login_lines.append(line)
                if any(kw in lower for kw in ("cookie", "session", "buoc 2", "bước 2", "step 2")) and len(login_lines) > 2:
                    login_lines.append(line)
                    break
        if not login_lines:
            return "Login vao website voi credentials trong workflow. Lay session cookie."
        return "\n".join(login_lines[:20])

    def _deterministic_browser_login(
        self,
        workflow_text: str,
        conversation: list[dict] | None = None,
    ) -> tuple[str, str]:
        """Login with Playwright MCP directly and extract HttpOnly cookies.

        This avoids relying on the LLM to remember that document.cookie cannot
        see HttpOnly session cookies.
        """
        username, password = self._extract_credentials(workflow_text, conversation)
        if not self.target_url or not username or not password:
            return (
                _send_block(
                    "LOGIN_STATUS: SKIPPED\n"
                    "REASON: Không tìm thấy target URL hoặc credentials rõ ràng."
                ),
                "",
            )

        login_urls = self._candidate_login_urls()
        code = self._build_login_browser_code(login_urls, username, password)

        try:
            result = self.mcp.execute_tool("browser_run_code_unsafe", {"code": code})
        except Exception as e:
            return (
                _send_block(f"LOGIN_STATUS: FAIL\nREASON: browser_run_code_unsafe error: {e}"),
                "",
            )

        result_text = str(result)
        cookie = self._extract_cookie_from_result(result_text)
        status = "SUCCESS" if cookie else "FAIL"
        summary = (
            "=========SEND=========\n"
            f"LOGIN_STATUS: {status}\n"
            f"USERNAME: {username}\n"
            f"SESSION_COOKIE: {cookie or '(not found)'}\n"
            f"RAW_BROWSER_RESULT:\n{truncate(result_text, 3000)}\n"
            "=========END-SEND========="
        )
        return summary, cookie

    def _candidate_login_urls(self) -> list[str]:
        """Build likely login URLs from recon and common paths."""
        candidates: list[str] = []

        def add(path_or_url: str) -> None:
            full = urljoin(self.target_url, path_or_url)
            if full not in candidates:
                candidates.append(full)

        for match in re.findall(r"https?://[^\s`'\")]+/[^ \n`'\")]*login[^ \n`'\")]*", self.recon_context, re.I):
            add(match)
        for match in re.findall(r"(?<![\w.-])/(?:login|my-account|account/login|signin)[^\s`'\")]?", self.recon_context, re.I):
            add(match)
        for path in ("/login", "/my-account", "/account/login", "/signin"):
            add(path)

        return candidates[:8]

    @staticmethod
    def _extract_login_form(html: str, current_url: str) -> dict | None:
        """Extract a likely login form and its hidden fields from HTML."""
        forms = re.findall(r"<form\b[^>]*>(.*?)</form>", html, re.IGNORECASE | re.DOTALL)
        form_blocks = re.finditer(r"<form\b([^>]*)>(.*?)</form>", html, re.IGNORECASE | re.DOTALL)
        chosen_attrs = ""
        chosen_body = ""
        for match in form_blocks:
            attrs = match.group(1)
            body = match.group(2)
            if re.search(r'input[^>]+type=["\']?password', body, re.IGNORECASE):
                chosen_attrs = attrs
                chosen_body = body
                break
        if not chosen_body and forms:
            chosen_body = forms[0]

        if not chosen_body:
            return None

        action_match = re.search(r'action=["\']?([^"\'>\s]+)', chosen_attrs, re.IGNORECASE)
        action_url = urljoin(current_url, action_match.group(1)) if action_match else current_url

        hidden_fields: dict[str, str] = {}
        for input_match in re.finditer(r"<input\b([^>]*)>", chosen_body, re.IGNORECASE):
            attrs = input_match.group(1)
            type_match = re.search(r'type=["\']?([^"\'>\s]+)', attrs, re.IGNORECASE)
            name_match = re.search(r'name=["\']?([^"\'>\s]+)', attrs, re.IGNORECASE)
            value_match = re.search(r'value=["\']([^"\']*)', attrs, re.IGNORECASE)
            input_type = (type_match.group(1).strip().lower() if type_match else "text")
            input_name = name_match.group(1).strip() if name_match else ""
            input_value = unescape(value_match.group(1)) if value_match else ""
            if not input_name:
                continue
            if input_type == "hidden":
                hidden_fields[input_name] = input_value

        user_field_match = re.search(
            r'<input\b[^>]*name=["\']([^"\']*(?:username|user|email)[^"\']*)["\'][^>]*>',
            chosen_body,
            re.IGNORECASE,
        )
        pass_field_match = re.search(
            r'<input\b[^>]*name=["\']([^"\']*(?:password|pass)[^"\']*)["\'][^>]*>',
            chosen_body,
            re.IGNORECASE,
        )
        if not user_field_match:
            user_field_match = re.search(
                r'<input\b[^>]*type=["\'](?:email|text)["\'][^>]*name=["\']([^"\']+)["\'][^>]*>',
                chosen_body,
                re.IGNORECASE,
            )
        if not pass_field_match:
            pass_field_match = re.search(
                r'<input\b[^>]*type=["\']password["\'][^>]*name=["\']([^"\']+)["\'][^>]*>',
                chosen_body,
                re.IGNORECASE,
            )
        if not user_field_match or not pass_field_match:
            return None

        return {
            "action_url": action_url,
            "username_field": user_field_match.group(1).strip(),
            "password_field": pass_field_match.group(1).strip(),
            "hidden_fields": hidden_fields,
        }

    def _verify_http_login_session(self, client) -> tuple[bool, str]:
        """Verify whether an HTTP-login session appears authenticated."""
        verify_paths = ["/my-account", "/account", "/profile", "/cart"]
        for path in verify_paths:
            verify_url = urljoin(self.target_url, path)
            try:
                resp = client.get(verify_url)
            except Exception as e:
                continue
            body_lower = resp.text.lower()
            final_path = urlparse(str(resp.url)).path.lower()
            redirected_to_login = "login" in final_path and "password" in body_lower
            has_auth_marker = any(
                marker in body_lower
                for marker in (
                    "logout", "log out", "my account", "your account",
                    "change email", "profile", "cart", "đăng xuất", "gio hàng",
                )
            )
            if resp.status_code == 200 and has_auth_marker and not redirected_to_login:
                return True, f"Verified at {resp.url}"
        return False, "Could not positively verify authenticated page; cookies still captured."

    @staticmethod
    def _extract_credentials(
        workflow_text: str,
        conversation: list[dict] | None = None,
    ) -> tuple[str, str]:
        """Extract username/password from workflow or original conversation."""
        chunks = [workflow_text]
        if conversation:
            chunks.extend(msg.get("content", "") for msg in conversation)
        text = "\n".join(chunks)

        patterns = [
            r"(?:username|user|tài khoản|tai khoan)\s*[:=]\s*([^\s,;/]+).*?(?:password|pass|mật khẩu|mat khau)\s*[:=]\s*([^\s,;/]+)",
            r"(?:credentials?|login)\s*[:=]\s*([^\s:;/]+)\s*[:/]\s*([^\s,;/]+)",
            r"\b(wiener|carlos|administrator|admin)\s*/\s*([^\s,;/]+)",
            r"\b(wiener|carlos|administrator|admin)\s*:\s*([^\s,;/]+)",
        ]
        for pat in patterns:
            m = re.search(pat, text, re.IGNORECASE | re.DOTALL)
            if m:
                return m.group(1).strip("`'\""), m.group(2).strip("`'\"")
        return "", ""

    @staticmethod
    def _build_login_browser_code(login_urls: list[str], username: str, password: str) -> str:
        """Build JS for browser_run_code_unsafe to perform login."""
        return f"""
async (page) => {{
  const loginUrls = {json.dumps(login_urls)};
  const username = {json.dumps(username)};
  const password = {json.dumps(password)};
  const out = {{tried: [], finalUrl: "", title: "", cookies: [], body: ""}};

  async function firstVisible(selectors) {{
    for (const sel of selectors) {{
      const loc = page.locator(sel).first();
      try {{
        if (await loc.count() > 0 && await loc.isVisible({{timeout: 1200}})) return loc;
      }} catch (_) {{}}
    }}
    return null;
  }}

  let found = false;
  for (const url of loginUrls) {{
    try {{
      await page.goto(url, {{waitUntil: "domcontentloaded", timeout: 20000}});
      await page.waitForTimeout(500);
      const hasPassword = await page.locator('input[type="password"], input[name*="pass" i]').count();
      out.tried.push({{url, hasPassword}});
      if (hasPassword > 0) {{
        found = true;
        break;
      }}
    }} catch (e) {{
      out.tried.push({{url, error: String(e).slice(0, 160)}});
    }}
  }}

  if (!found) {{
    out.finalUrl = page.url();
    out.title = await page.title().catch(() => "");
    out.body = await page.locator("body").innerText({{timeout: 2000}}).catch(() => "");
    return JSON.stringify(out);
  }}

  const userField = await firstVisible([
    'input[name="username"]', '#username', 'input[name="user"]',
    'input[name="email"]', 'input[type="email"]', 'input[type="text"]'
  ]);
  const passField = await firstVisible([
    'input[name="password"]', '#password', 'input[type="password"]'
  ]);
  if (!userField || !passField) {{
    out.finalUrl = page.url();
    out.title = await page.title().catch(() => "");
    out.body = await page.locator("body").innerText({{timeout: 2000}}).catch(() => "");
    return JSON.stringify(out);
  }}

  await userField.fill(username);
  await passField.fill(password);

  const submit = await firstVisible([
    'button[type="submit"]', 'input[type="submit"]', 'button', '[role="button"]'
  ]);
  if (submit) {{
    await Promise.all([
      page.waitForLoadState("networkidle", {{timeout: 15000}}).catch(() => {{}}),
      submit.click({{timeout: 8000}})
    ]);
  }} else {{
    await passField.press("Enter");
    await page.waitForLoadState("networkidle", {{timeout: 15000}}).catch(() => {{}});
  }}
  await page.waitForTimeout(1000);

  out.finalUrl = page.url();
  out.title = await page.title().catch(() => "");
  out.cookies = await page.context().cookies();
  out.body = await page.locator("body").innerText({{timeout: 3000}}).catch(() => "");
  return JSON.stringify(out);
}}
"""

    @staticmethod
    def _extract_cookie_from_result(result: str) -> str:
        """Extract session cookie value from login phase result.

        Handles multiple formats:
        1. SESSION_COOKIE: session=<value> (from LLM output)
        2. JSON cookies array from browser_run_code_unsafe (CDP cookies)
        3. Set-Cookie header from network requests
        4. Raw session=<value> pattern anywhere in text
        """
        import re

        # 1. Explicit SESSION_COOKIE line from LLM
        m = re.search(r'SESSION_COOKIE:\s*(.+)', result)
        if m:
            cookie = m.group(1).strip()
            if not _looks_like_empty_cookie(cookie):
                return cookie

        # 2. JSON cookies array from browser_run_code_unsafe (CDP via Playwright)
        # Use proper JSON parsing instead of fragile regex
        import json
        start = result.find("[")
        if start != -1:
            try:
                cookies = json.loads(result[start:])
                if isinstance(cookies, list):
                    cookie_header = ExecAgent._cookie_header_from_cookies(cookies)
                    if cookie_header:
                        return cookie_header
            except (json.JSONDecodeError, TypeError, KeyError):
                pass

        # Also try individual cookie objects: {"name":"session","value":"..."}
        cookie_obj_matches = re.finditer(
            r'\{\s*[^{}]*"name"\s*:\s*"session"[^{}]*"value"\s*:\s*"([^"]+)"[^{}]*\}',
            result, re.DOTALL
        )
        for cm in cookie_obj_matches:
            value = cm.group(1).strip()
            if value:
                return f"session={value}"

        # Also try reversed key order: {"value":"...","name":"session"}
        cookie_obj_matches_rev = re.finditer(
            r'\{\s*[^{}]*"value"\s*:\s*"([^"]+)"[^{}]*"name"\s*:\s*"session"[^{}]*\}',
            result, re.DOTALL
        )
        for cm in cookie_obj_matches_rev:
            value = cm.group(1).strip()
            if value:
                return f"session={value}"

        # 3. Set-Cookie header
        m = re.search(r'Set-Cookie:\s*(session=[^\s;]+)', result, re.IGNORECASE)
        if m:
            return m.group(1).strip()

        # 4. Raw session=<value> pattern
        m = re.search(r'(?:session)=([a-zA-Z0-9%._~+/=-]{10,})', result)
        if m:
            return m.group(0).strip()
        return ""

    @staticmethod
    def _cookie_header_from_cookies(cookies: list[dict]) -> str:
        """Pick the best authenticated cookie from Playwright cookie objects."""
        if not cookies:
            return ""

        preferred = ("session", "sessionid", "phpsessid", "jsessionid", "sid", "auth_token", "connect.sid")
        for name in preferred:
            for cookie_obj in cookies:
                if not isinstance(cookie_obj, dict):
                    continue
                c_name = str(cookie_obj.get("name", ""))
                c_val = str(cookie_obj.get("value", ""))
                if c_name.lower() == name and c_val:
                    return f"{c_name}={c_val}"

        for cookie_obj in cookies:
            if not isinstance(cookie_obj, dict):
                continue
            c_name = str(cookie_obj.get("name", ""))
            c_val = str(cookie_obj.get("value", ""))
            if c_name and c_val and cookie_obj.get("httpOnly", False):
                return f"{c_name}={c_val}"

        return ""

    def _extract_cookie_from_browser(self) -> str:
        """Fallback: extract session cookie from browser using CDP via browser_run_code_unsafe.

        Uses Playwright's context.cookies() API through CDP to get ALL cookies
        including HttpOnly ones that document.cookie cannot see.
        """
        import re

        # Primary: use browser_run_code_unsafe to call CDP for all cookies
        try:
            result = self.mcp.execute_tool("browser_run_code_unsafe", {
                "code": "(async () => { return await page.context().cookies(); })()"
            })
            result_text = str(result)
            print(f"{DIM}[EXEC-AGENT] CDP cookies raw: {result_text[:300]}{RESET}")

            # Parse JSON cookies array using proper JSON extraction (not regex)
            try:
                import json
                # Use JSONDecoder to find JSON array starting at first '['
                start = result_text.find("[")
                if start != -1:
                    try:
                        cookies = json.loads(result_text[start:])
                        if isinstance(cookies, list):
                            cookie = self._cookie_header_from_cookies(cookies)
                            if cookie:
                                print(f"{GREEN}[EXEC-AGENT] Extracted HttpOnly cookie via CDP: {cookie[:60]}{RESET}")
                                return cookie
                    except json.JSONDecodeError:
                        pass
            except Exception as e:
                print(f"{DIM}[EXEC-AGENT] CDP cookie JSON parse failed: {e}{RESET}")

        except Exception as e:
            print(f"{DIM}[EXEC-AGENT] CDP cookie extraction failed: {e}{RESET}")

        # Secondary fallback: try network requests for Set-Cookie header
        try:
            result = self.mcp.execute_tool("browser_network_requests", {"static": False})
            result_text = str(result)
            requests_with_login = [
                i for i, line in enumerate(result_text.split("\n"))
                if "login" in line.lower() or "my-account" in line.lower()
            ]
            for idx_line in reversed(requests_with_login):
                match = re.search(r'(\d+)\.\s', result_text.split("\n")[idx_line])
                if match:
                    req_idx = int(match.group(1))
                    try:
                        detail = self.mcp.execute_tool("browser_network_request", {
                            "index": req_idx,
                            "part": "response-headers",
                        })
                        detail_text = str(detail)
                        cookie_match = re.search(
                            r'set-cookie:\s*(session=[^\s;]+)', detail_text, re.IGNORECASE
                        )
                        if cookie_match:
                            cookie = cookie_match.group(1).strip()
                            print(f"{GREEN}[EXEC-AGENT] Extracted HttpOnly cookie from network: {cookie[:60]}{RESET}")
                            return cookie
                    except Exception:
                        continue
        except Exception as e:
            print(f"{DIM}[EXEC-AGENT] Network cookie extraction also failed: {e}{RESET}")

        return ""

    def _save_cookie_objects_file(self, cookies: list[dict], path: str | None = None) -> None:
        """Save structured cookie objects to a Netscape cookie file."""
        cookies_path = path or self._working_cookies_path()
        try:
            with open(cookies_path, "w", encoding="utf-8") as f:
                f.write("# Netscape HTTP Cookie File\n")
                for cookie_obj in cookies:
                    if not isinstance(cookie_obj, dict):
                        continue
                    fallback_host = urlparse(self.target_url).hostname or ""
                    domain = self._normalize_cookie_domain(
                        str(cookie_obj.get("domain", "")),
                        fallback_host=fallback_host,
                    )
                    path_value = str(cookie_obj.get("path", "/") or "/")
                    secure = "TRUE" if bool(cookie_obj.get("secure")) else "FALSE"
                    name = str(cookie_obj.get("name", "")).strip()
                    value = str(cookie_obj.get("value", "")).strip()
                    if not name or not value:
                        continue
                    f.write(f"{domain}\tFALSE\t{path_value}\t{secure}\t0\t{name}\t{value}\n")
        except Exception as e:
            print(f"{DIM}[EXEC-AGENT] Failed to save structured cookies: {e}{RESET}")

    def _save_cookies_file(self, session_cookie: str, path: str | None = None) -> None:
        """Save cookie header text to a Netscape cookie file for curl -b."""
        cookies_path = path or self._working_cookies_path()
        try:
            domain = urlparse(self.target_url).hostname or "" if self.target_url else ""

            cookie_name = "session"
            cookie_value = session_cookie
            if "=" in session_cookie:
                parts = session_cookie.split("=", 1)
                cookie_name = parts[0]
                cookie_value = parts[1]

            with open(cookies_path, "w", encoding="utf-8") as f:
                f.write("# Netscape HTTP Cookie File\n")
                # Handle multi-cookie strings (e.g., "session=abc; csrf=xyz")
                for cookie_part in cookie_value.split(";"):
                    cookie_part = cookie_part.strip()
                    if cookie_part:
                        if "=" in cookie_part:
                            c_name, c_value = cookie_part.split("=", 1)
                            f.write(f"{domain}\tFALSE\t/\tFALSE\t0\t{c_name.strip()}\t{c_value.strip()}\n")
                        else:
                            f.write(f"{domain}\tFALSE\t/\tFALSE\t0\t{cookie_name}\t{cookie_part}\n")

            print(f"{GREEN}[EXEC-AGENT] Saved cookies to: {cookies_path}{RESET}")
        except Exception as e:
            print(f"{DIM}[EXEC-AGENT] Failed to save cookies.txt: {e}{RESET}")

    def _save_answer_to_scratchpad(self, result: str) -> None:
        if not self.memory_store:
            return
        import re
        self.memory_store.scratchpad_write("exec", "last_answer", result[:800])
        statuses = re.findall(r'HTTP/\d\.?\d?\s+(\d{3})', result)
        if statuses:
            self.memory_store.scratchpad_write("exec", "last_http_statuses",
                                               ", ".join(statuses[:5]))
        cookies = re.findall(r'(?:session|token|auth|csrf)[=:]\s*([^\s;,"\'<>]+)',
                              result, re.IGNORECASE)
        if cookies:
            self.memory_store.scratchpad_write("exec", "found_cookies",
                                               ", ".join(cookies[:3]))
            self.memory_store.add_finding("credential", "cookies_found",
                                           ", ".join(cookies[:3]), agent="exec")
        endpoints = re.findall(r'(?:GET|POST|PUT|DELETE|PATCH)\s+(\/[^\s"\'<>]+)', result)
        if endpoints:
            self.memory_store.scratchpad_write("exec", "accessed_endpoints",
                                               ", ".join(endpoints[:10]))
            for ep in endpoints[:5]:
                self.memory_store.add_finding("endpoint", ep.replace("/", "_")[:40],
                                               ep, agent="exec")

    def _save_workflow_result(self, result: str) -> None:
        if not self.memory_store:
            return
        self.memory_store.scratchpad_write("exec", "last_workflow_result", result[:1000])
        success_kw = ["200 ok", "thành công", "success", "confirmed", "xác nhận"]
        lower = result.lower()
        if any(kw in lower for kw in success_kw):
            self.memory_store.scratchpad_write("exec", "workflow_success_hint", "True")
            self.memory_store.add_finding("vulnerability", "workflow_result_success",
                                           result[:500], agent="exec")
        self.memory_store.update_task("exec_init", "completed")

    def shutdown(self):
        """Cleanup MCP connections."""
        print(f"{YELLOW}[EXEC-AGENT] Shutting down MCP...{RESET}")
        self.mcp.stop_all()
        print(f"{YELLOW}[EXEC-AGENT] Done.{RESET}")

    # ─── Internal: Tool-calling loop (robust, proven pattern) ────

    def _tool_loop(
        self,
        messages: list[dict],
        default_tag: str = "REDTEAM",
        max_tool_rounds: int = MAX_TOOL_ROUNDS,
        min_tool_calls_before_finalize: int = 0,
        mode_label: str = "task",
        tools_override: list | None = None,
    ) -> str:
        """Chạy tool calls cho đến khi LLM trả text có SEND block.

        Args:
            messages: LLM messages list (system + user + ...).
            default_tag: Backward-compatible caller label; routing tags are ignored.
            tools_override: Custom tool list (e.g. without Playwright for curl-only phase).

        Returns:
            Raw LLM text chứa SEND block.
        """
        consecutive_errors = 0
        tool_count = 0
        nudge_count = 0
        max_nudges = 3
        consecutive_repeats = 0
        last_tool_signature = None  # (fn_name, fn_args_str) của tool call trước
        active_tools = tools_override if tools_override is not None else self.tools

        for round_idx in range(max_tool_rounds):
            try:
                tool_choice = "required" if round_idx == 0 and active_tools else "auto"

                try:
                    response = self.client.chat.completions.create(
                        model=self.toolcall_model,
                        messages=messages,
                        tools=active_tools if active_tools else None,
                        tool_choice=tool_choice if active_tools else None,
                        temperature=0.3,
                        max_tokens=6144,
                    )
                except Exception as e:
                    err_lower = str(e).lower()
                    if (
                        tool_choice == "required"
                        and active_tools
                        and ("tool_choice" in err_lower or "tool use" in err_lower)
                    ):
                        print(
                            f"{DIM}[EXEC-AGENT] Provider rejected tool_choice=required; "
                            f"retrying with tool_choice=auto.{RESET}"
                        )
                        response = self.client.chat.completions.create(
                            model=self.toolcall_model,
                            messages=messages,
                            tools=active_tools,
                            tool_choice="auto",
                            temperature=0.3,
                            max_tokens=6144,
                        )
                    else:
                        raise
            except Exception as e:
                consecutive_errors += 1
                print(f"{DIM}[EXEC-AGENT] API error ({consecutive_errors}): {e}{RESET}")
                err_lower = str(e).lower()
                if "429" in err_lower or "rate limit" in err_lower or "rate_limited" in err_lower:
                    return _send_block(
                        "[RATE_LIMIT] LLM API hit rate limit; stopping this agent loop to avoid burning budget.\n"
                        f"Raw error: {e}"
                    )
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                    return _send_block(f"[API Error after {consecutive_errors} retries: {e}]")
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

                    # ── Extra: browser_navigate loop = immediate STOP ──
                    if fn_name == "browser_navigate" and consecutive_repeats >= 2:
                        print(
                            f"{YELLOW}[EXEC-AGENT] Detected browser_navigate loop "
                            f"({consecutive_repeats + 1}x same URL). Stopping LLM immediately.{RESET}"
                        )
                        messages.append({
                            "role": "user",
                            "content": (
                                "STOP. You have called browser_navigate with the same URL "
                                f"{consecutive_repeats + 1} times in a row. "
                                "This is a loop. Do NOT call browser_navigate again. "
                                "Use fetch or execute_command (curl) for this URL instead. "
                                "Summarize your findings in a complete =========SEND========= "
                                "... =========END-SEND========= block."
                            ),
                        })
                        break

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
                            "found so far inside a complete =========SEND========= "
                            "... =========END-SEND========= block."
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
                            "inside a complete =========SEND========= ... "
                            "=========END-SEND========= block."
                        ),
                    })
                    consecutive_errors = 0

                nudge_count = 0  # reset nudge sau khi dùng tools

                # ── Gần hết rounds → nudge LLM tổng kết ──
                if round_idx >= max_tool_rounds - 3:
                    messages.append({
                        "role": "user",
                        "content": (
                            "IMPORTANT: You are running out of tool rounds. "
                            "STOP using tools NOW. Summarize everything you found "
                            "so far inside a complete =========SEND========= ... "
                            "=========END-SEND========= block."
                        ),
                    })

                continue  # quay lại đầu loop

            # ── Text response: SEND block means Exec is done ──
            text = msg.content or ""
            has_send_block = bool(extract_send_block(text))

            if has_send_block:
                if tool_count < min_tool_calls_before_finalize and round_idx < max_tool_rounds - 1:
                    messages.append({"role": "assistant", "content": text})
                    messages.append({
                        "role": "user",
                        "content": (
                            f"You are trying to finish the {mode_label} too early after only "
                            f"{tool_count} tool calls. The current task needs deeper evidence. "
                            "Do NOT summarize yet. Continue using tools, answer the remaining "
                            "sub-questions, and only finish when you have enough raw evidence."
                        ),
                    })
                    continue
                # LLM xong — return full text
                return text

            # Không có SEND block — LLM nói nhưng chưa signal done
            nudge_count += 1
            if nudge_count >= max_nudges:
                # Force kết thúc — tự bọc vào SEND block để Manager luôn parse được.
                return _send_block(text or "[ExecAgent stopped after repeated non-final replies]")

            # Append và nudge LLM tiếp tục
            messages.append({"role": "assistant", "content": text})
            messages.append({
                "role": "user",
                "content": (
                    "Continue. Use your tools to complete the task. When done, "
                    "put results in a complete SEND block. Do not add routing tags."
                ),
            })

        # Max rounds đạt limit
        return _send_block(f"[ExecAgent reached {max_tool_rounds} tool rounds limit]")
