"""
ManageAgent — "Sếp" LLM điều phối toàn bộ pipeline pentest.

Thay thế toàn bộ retry loop + phase_debate/execute/evaluate/report trong main.py.
ManageAgent là agent LLM thật — mỗi tick gọi LLM để quyết định action tiếp theo,
inject hướng dẫn vào conversation, rồi gọi đúng agent con.

Đội ngũ:
  - Nhóm tấn công  (RedTeamAgent):  viết chiến lược tấn công
  - Nhóm phản biện (BlueTeamAgent): review, phản biện chiến lược
  - Nhóm thực thi  (ExecAgent):     chạy Python exploit tự xác minh trong script

Các agent làm việc cách ly — không biết nhau tồn tại, tất cả qua ManageAgent.
"""

import json
import hashlib
import os
import re
import signal
from pathlib import Path

from openai import OpenAI

from shared.utils import extract_send_block, truncate
from shared.memory_store import MemoryStore
from shared.context_manager import ContextManager
from shared.bug_dossier import load_and_enrich_risk_bugs
from agents.policy_agent import PolicyAgent

# ── Env / Connection ─────────────────────────────────────────
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "gho_token")
SERVER_URL   = os.environ.get("MARL_SERVER_URL", "http://127.0.0.1:5000/v1")
MODEL        = os.environ.get("MARL_MANAGER_MODEL", "ollama/gemma4:31b-cloud")

# ── Guardrail constants ──────────────────────────────────────
MAX_ROUNDS        = 2    # số vòng strategy revision tối đa
MIN_DEBATE_ROUNDS = 0    # deterministic state machine handles Red -> Blue gating
MAX_EXEC_RETRIES  = 1    # retry Exec tối đa 1 lần để tránh loop phức tạp
MAX_TICKS         = 60   # tổng số tick tối đa cho toàn pipeline
EXEC_TIMEOUT = 4800  # giây — ExecAgent bị kill sau 80 phút để tránh treo vĩnh viễn
COMPRESS_TRIGGER_LEN = 20
COMPRESS_KEEP_RECENT = 6

# ── ANSI colors ──────────────────────────────────────────────
R   = "\033[91m"
G   = "\033[92m"
Y   = "\033[93m"
C   = "\033[96m"
M   = "\033[95m"
B   = "\033[1m"
RST = "\033[0m"

# ── Action tags ManageAgent có thể emit ──────────────────────
VALID_ACTIONS = {
    "DEBATE_RED",      # Red viết exploit approach cho BUG hiện tại
    "DEBATE_BLUE",     # Blue đánh giá tư duy Red
    "EXECUTE_BUG",     # Thực thi approach đã approved cho BUG hiện tại
    "RETRY_RED",       # Red chạy lại (do connection error hoặc exec fail)
    "RETRY_BLUE",      # Blue chạy lại (do connection error)
    "RETRY_EXEC",      # Exec chạy lại (do connection error hoặc script lỗi)
    "STOP_BUG",        # Dừng bug hiện tại (NOT_EXPLOITED / OOS_SCOPE)
    "NEXT_BUG",        # Chuyển sang bug tiếp theo
    "REPORT_SUCCESS",  # Tất cả bug xong, viết report thành công
    "REPORT_FAIL",     # Không tìm được bug nào, viết report thất bại
}

ACTION_PATTERN = re.compile(
    r"\[ACTION:\s*(" + "|".join(VALID_ACTIONS) + r")\]",
    re.IGNORECASE,
)

NOTE_PATTERN = re.compile(r"<note>(.*?)</note>", re.DOTALL | re.IGNORECASE)

APPROVE_HINTS = (
    "approve", "approved", "chấp thuận", "chap thuan", "đồng ý", "dong y",
    "ok triển khai", "ok trien khai", "được phép execute", "duoc phep execute",
)
REJECT_HINTS = (
    "reject", "từ chối", "tu choi", "cần sửa", "can sua",
    "chưa đủ", "chua du", "thiếu", "thieu", "bổ sung", "bo sung",
)
STOP_HINTS = (
    "stopped", "stop bug", "dung bug", "khong the khai thac", "không thể khai thác",
    "not_found", "not found", "no signal", "no differential", "khong con kha thi",
)

MANAGER_PROMPT = """\
Ban la MANAGER dieu phoi pipeline pentest BAC/BLF.
Ban khong truc tiep khai thac. Ban chi chon action tiep theo dua tren state va evidence.

=== TARGET ===
{target_url}

=== BUGS ===
{risk_bugs_summary}

=== RECON ===
{recon_summary}

=== STATE ===
{state_context_display}

=== HOT PATH ===
1. DEBATE_RED: Red viet strategy ngan + execution shot plan cho dung 1 bug.
2. DEBATE_BLUE: Blue review strategy/shot plan truoc khi thuc thi.
3. EXECUTE_BUG: Exec chay bounded script shots va luu raw request/response/artifacts.
4. Manager doc Exec verdict/evidence va quyet dinh ngay: EXPLOITED / retry / stop.
5. EXPLOITED -> NEXT_BUG. SCRIPT_ERROR -> RETRY_EXEC. FAILED -> STOP_BUG. Het bug -> report.

=== ACTIONS ===
[ACTION: DEBATE_RED]     — Viet strategy ngan cho bug hien tai.
[ACTION: EXECUTE_BUG]    — Chay Python exploit self-verify cho strategy da co.
[ACTION: RETRY_RED]      — Sua strategy khi endpoint/verify sai.
[ACTION: RETRY_EXEC]     — Chay lai Exec khi loi runtime/script hoac evidence thieu nhung strategy dung.
[ACTION: STOP_BUG]       — Dung bug hien tai.
[ACTION: NEXT_BUG]       — Chuyen bug tiep theo.
[ACTION: REPORT_SUCCESS] — Viet report co finding validated.
[ACTION: REPORT_FAIL]    — Viet report khong co finding validated.
[ACTION: DEBATE_BLUE]    — Blue review strategy/shot plan cua Red truoc Exec.
[ACTION: RETRY_BLUE]     — Goi lai Blue khi response loi/rong.

=== RULES ===
- Sau Red strategy hop le, phai DEBATE_BLUE truoc khi EXECUTE_BUG.
- Chi EXECUTE_BUG khi co current workflow va Blue da approve.
- Exec script tu verify va in FINAL/SUCCESS. Manager doc verdict/evidence de quyet dinh.
- Minimum sufficient proof: neu evidence khop hypothesis toi thieu cua bug thi chap nhan EXPLOITED, khong bat them endpoint/tac dong phu.
- Anti-overfitting: khong hardcode endpoint/marker cua lab; dung dossier, recon, strategy va artifact hien tai.
- Neu Exec loi syntax/runtime/script, uu tien RETRY_EXEC de Exec tu sua script.
- Neu Exec chay dung nhung evidence sai/khong khop hypothesis, route RETRY_RED de sua strategy.
- Neu Exec tra FAILED/PARTIAL sau retry, dung bug de tiet kiem tick.
- Chi BAC/BLF. Khong brute force, DDoS, SQLi/XSS/SSRF.

Tra loi 1-2 cau tieng Viet + <note> ngan + dung mot action tag.
"""
def _strip_tag_display(text: str) -> str:
    """Xóa routing-tag cũ nếu còn sót trong output legacy."""
    return re.sub(
        r"\[(?:REDTEAM|BLUETEAM|AGENT(?::run)?|APPROVED|DONE)\]\s*$",
        "", text, flags=re.IGNORECASE,
    ).rstrip()


def _extract_exec_result(raw: str) -> str:
    """Extract all Exec SEND blocks; workflow output can include login + exploit blocks."""
    blocks = re.findall(
        r"={5,}SEND={5,}\s*\n(.+?)\n\s*={5,}END-SEND={5,}",
        raw or "",
        re.DOTALL,
    )
    if blocks:
        return "\n\n".join(block.strip() for block in blocks if block.strip())
    return extract_send_block(raw) or raw


def _extract_exec_output(exec_result: str) -> str:
    """Extract decoded process stdout/stderr from an Exec SEND block."""
    match = re.search(r'"output"\s*:\s*"([^"]*(?:\\.[^"]*)*)"', str(exec_result), re.DOTALL)
    if not match:
        return ""
    return match.group(1).encode().decode("unicode_escape", errors="ignore")


def _bug_label(bug_id: object) -> str:
    """Return a stable display label without producing BUG-BUG-001."""
    raw = str(bug_id or "?").strip()
    return raw if raw.upper().startswith("BUG-") else f"BUG-{raw}"


def _summarize_exec_output(exec_result: str, max_lines: int = 5) -> str:
    """Return a short human-readable summary of the Exec output."""
    output = _extract_exec_output(exec_result) or extract_send_block(exec_result) or str(exec_result or "")
    if not output:
        return "no output captured"

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
            or line.startswith("Response length")
            or line.startswith("Login response")
            or line.startswith("My order response")
            or line.startswith("Orders page")
            or line.startswith("Products page")
            or line.startswith("Cart page")
            or line.startswith("HTTP Code:")
            or line.startswith("SHOT_RESULT:")
            or line.startswith("REQUEST_SUMMARY:")
            or line.startswith("EVIDENCE_SUMMARY:")
            or line.startswith("ERRORS:")
            or line.startswith("VERIFY_COMPLETED:")
            or line.startswith("FINAL_REASON:")
            or "verified" in lower
            or "vulnerable" in lower
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
    if not interesting:
        interesting = [line.strip() for line in output.splitlines() if line.strip()][:max_lines]
    if len(interesting) > max_lines:
        interesting = interesting[:max_lines]
    return " | ".join(interesting) if interesting else "no concise summary"


def _summarize_exec_result(exec_result: str) -> str:
    """Summarize verdict + useful output for manager-level logs."""
    if not exec_result:
        return "empty execution result"

    lower_exec = exec_result.lower()
    verdict = "UNKNOWN"
    if "=== success: yes ===" in lower_exec:
        verdict = "YES"
    elif "=== success: partial ===" in lower_exec or "=== final: partial ===" in lower_exec:
        verdict = "PARTIAL"
    elif "=== success: no ===" in lower_exec or "=== final: failed ===" in lower_exec:
        verdict = "NO"

    m_json = re.search(r'\{[^}]*"return_code"\s*:\s*(-?\d+)', exec_result, re.DOTALL)
    rc = m_json.group(1) if m_json else "?"
    return f"verdict={verdict} rc={rc} summary={_summarize_exec_output(exec_result)}"


def _extract_exec_status_hits(exec_result: str) -> list[dict]:
    """Extract compact METHOD path status observations from Exec output."""
    output = _extract_exec_output(exec_result) or exec_result
    hits: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    patterns = (
        r"\b(GET|POST|PUT|PATCH|DELETE)\s+(/[^\s|]+).*?\bstatus\s*[=:]\s*(\d{3})",
        r"\b(GET|POST|PUT|PATCH|DELETE)\s+(/[^\s|]+).*?\bHTTP\s+(\d{3})",
        r"\b([A-Z]+)\s+(/[^\s|]+)=?(\d{3})\b",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, output, re.IGNORECASE):
            method, path, status = match.group(1).upper(), match.group(2), match.group(3)
            if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                continue
            key = (method, path, status)
            if key in seen:
                continue
            seen.add(key)
            hits.append({"method": method, "path": path, "status": status})
    return hits[:20]


def _exec_final_marker(exec_result: str) -> str:
    output = _extract_exec_output(exec_result) or exec_result
    match = re.search(r"===\s*FINAL:\s*([A-Z_ ]+?)\s*===", output, re.IGNORECASE)
    return match.group(1).strip().upper() if match else ""


def _exec_success_verdict(exec_result: str) -> str:
    match = re.search(r"===\s*success:\s*(\w+)", str(exec_result or ""), re.IGNORECASE)
    return match.group(1).strip().upper() if match else ""


def _classify_exec_attempt(exec_result: str, current_bug: dict) -> dict:
    """Classify an Exec attempt for Manager's attempt ledger."""
    output = _extract_exec_output(exec_result) or exec_result
    lower = output.lower()
    result_lower = str(exec_result or "").lower()
    status_hits = _extract_exec_status_hits(exec_result)
    success_verdict = _exec_success_verdict(exec_result)
    final_marker = _exec_final_marker(exec_result)
    digest = hashlib.sha256(str(exec_result or "").encode("utf-8", errors="ignore")).hexdigest()[:16]

    proof_markers = (
        "admin dashboard", "admin panel", "admin", "privileged",
        "different user", "other user", "another user", "not owner",
        "idor vulnerability confirmed", "leaked", "api key", "balance changed",
        "price changed", "quantity changed", "order", "delta", "verified",
        "verify_completed: yes", "shot_result: exploited",
    )
    error_markers = (
        "syntax error", "command not found", "[timeout]", "timed out",
        "[api error", "[llm error", "connection error",
        "syntax_check: fail", "script validation failed",
        "python py_compile failed", "need a corrected python exploit",
    )
    contradiction = (
        ("fail" in lower and "found marker" in lower)
        or ("final: failed" in lower and "found" in lower and "marker" in lower)
        or ("success" in lower and any(code in lower for code in (" 403", " 404", " 405", "method not allowed")))
    )
    has_2xx = any(hit["status"].startswith("2") for hit in status_hits)
    has_only_negative_status = bool(status_hits) and not has_2xx
    has_marker = any(marker in lower for marker in proof_markers)
    runtime_error = any(marker in result_lower or marker in lower for marker in error_markers)
    explicit_failed = final_marker == "FAILED" or success_verdict == "NO"
    partial = final_marker == "PARTIAL" or success_verdict == "PARTIAL"
    candidate_success = success_verdict == "YES" or final_marker == "EXPLOITED"

    if runtime_error:
        signal = "RUNTIME_ERROR"
    elif contradiction:
        signal = "CONTRADICTION"
    elif candidate_success and has_marker:
        signal = "PROOF_CANDIDATE"
    elif has_2xx and has_marker:
        signal = "NEW_LEAD"
    elif partial:
        signal = "PARTIAL"
    elif explicit_failed or has_only_negative_status:
        signal = "NO_SIGNAL"
    else:
        signal = "UNCLEAR"

    return {
        "sha256_16": digest,
        "signal": signal,
        "success_verdict": success_verdict or "NONE",
        "final_marker": final_marker or "NONE",
        "status_hits": status_hits,
        "summary": _summarize_exec_output(exec_result, max_lines=8),
    }


def _get_last_red_content(conversation: list[dict]) -> str:
    """Lấy nội dung message Red Team cuối cùng."""
    for msg in reversed(conversation):
        if msg["speaker"] == "REDTEAM":
            clean = msg["content"]
            return _strip_tag_display(clean)
    return ""


def _is_agent_failure_response(content: str) -> bool:
    """Return True for empty/provider-failure agent outputs that must not drive state."""
    text = _strip_tag_display(str(content or "")).strip()
    return not text or text.startswith("[LLM Error:") or text.startswith("[API Error")


def _is_valid_red_approach(content: str) -> bool:
    """Check whether Red produced an executable strategy for Blue/Exec."""
    text = _strip_tag_display(str(content or "")).strip()
    if _is_agent_failure_response(text):
        return False
    lower = text.lower()
    has_strategy = (
        "=== chien luoc" in lower
        or "=== chiến lược" in lower
        or "muc tieu:" in lower
        or "mục tiêu:" in lower
    )
    has_shot_plan = "=== execution shot plan ===" in lower
    return has_strategy and has_shot_plan


def _get_last_valid_red_content(conversation: list[dict]) -> str:
    """Return the most recent Red strategy that is non-empty and has a shot plan."""
    for msg in reversed(conversation):
        if msg["speaker"] == "REDTEAM":
            clean = _strip_tag_display(msg["content"])
            if _is_valid_red_approach(clean):
                return clean
    return ""


def _get_last_blue_content(conversation: list[dict]) -> str:
    """Lấy nội dung message Blue Team cuối cùng."""
    for msg in reversed(conversation):
        if msg["speaker"] == "BLUETEAM":
            clean = msg["content"]
            return _strip_tag_display(clean)
    return ""


def _contains_any(text: str, hints: tuple[str, ...]) -> bool:
    lower = text.lower()
    return any(h in lower for h in hints)


def _infer_dialog_intent(speaker: str, content: str) -> str:
    """Suy luan y dinh tu noi dung Red/Blue, khong dung routing tag."""
    clean = _strip_tag_display(content)
    lower = clean.lower()
    stripped = lower.strip()

    # Blue: APPROVE/REVISE check first so explanation wording cannot hide approval.
    if speaker == "BLUETEAM":
        # Prefix status from Blue should take absolute precedence over explanation text.
        if stripped.startswith("approved"):
            return "APPROVE"
        if stripped.startswith("rejected"):
            return "REVISE"
        if stripped.startswith("stopped"):
            return "STOP"

        # APPROVE check BEFORE reject check — "APPROVED" in Blue's response should take precedence
        has_approve = _contains_any(lower, APPROVE_HINTS)
        has_reject = _contains_any(lower, REJECT_HINTS)
        has_stop = _contains_any(lower, STOP_HINTS)
        if has_approve and not has_reject:
            return "APPROVE"
        if has_stop and not has_approve:
            return "STOP"
        if has_reject:
            return "REVISE"
        # Explicit approval wording is enough; workers no longer emit routing tags.
        if "approved" in lower and not has_reject:
            return "APPROVE"
        if "stopped" in lower:
            return "STOP"

    return "NONE"


class ManageAgent:
    """'Sếp' LLM điều phối toàn bộ pipeline pentest.

    ManageAgent sở hữu và khởi tạo tất cả agent con bên trong.
    main.py chỉ cần gọi manage_agent.run(conversation).

    Mỗi tick:
      1. PolicyAgent xác thực action đề xuất (hard rules + LLM semantic)
      2. Gọi LLM → quyết định [ACTION: XXX] + <note> hướng dẫn
      3. In quyết định ra console
      4. Inject note vào conversation (nếu có)
      5. Gọi agent tương ứng
      6. ContextManager nén conversation nếu cần (trigger_len=20)
      7. Lặp lại cho đến REPORT_* hoặc hết MAX_TICKS
    """

    def __init__(
        self,
        target_url: str,
        recon_content: str,
        run_dir: str,
        *,
        model: str | None = None,
        max_rounds: int = MAX_ROUNDS,
        min_debate_rounds: int = MIN_DEBATE_ROUNDS,
        max_exec_retries: int = MAX_EXEC_RETRIES,
    ):
        self.target_url      = target_url
        self.recon_content   = recon_content
        self.run_dir         = run_dir
        self.model           = model or MODEL
        self.max_rounds      = max_rounds
        self.min_debate_rounds = min_debate_rounds
        self.max_exec_retries  = max_exec_retries

        # Load risk-bug.json if exists
        risk_bugs_path = Path(run_dir) / "risk-bug.json"
        self.risk_bugs: list[dict] = []
        self.current_bug_index: int = 0
        if risk_bugs_path.exists():
            try:
                self.risk_bugs = load_and_enrich_risk_bugs(run_dir)
                print(f"{C}[MANAGER] Loaded {len(self.risk_bugs)} bugs from risk-bug.json{RST}")
            except Exception as e:
                print(f"{Y}[MANAGER] Could not load risk-bug.json: {e}{RST}")

        # Build risk_bugs_summary for manager prompt
        if self.risk_bugs:
            lines = []
            for b in self.risk_bugs:
                lines.append(self._format_bug_summary_line(b))
            risk_bugs_summary = "\n".join(lines)
        else:
            risk_bugs_summary = "(chua co bug nao — VulnHunter chua chay)"

        self.client = OpenAI(api_key=GITHUB_TOKEN, base_url=SERVER_URL)
        self.system_prompt = MANAGER_PROMPT.format(
            target_url         = target_url,
            recon_summary      = truncate(recon_content, 4000),
            risk_bugs_summary  = risk_bugs_summary,
            state_context_display = "{state_context_display}",
        )

        # ── Shared memory + context + policy ────────────────────
        self.memory  = MemoryStore(run_dir)
        self.ctx_mgr = ContextManager(self.memory, self.client, self.model)
        self.policy  = PolicyAgent(
            model             = self.model,
            max_rounds        = max_rounds,
            min_debate_rounds = min_debate_rounds,
            max_exec_retries  = max_exec_retries,
            max_ticks         = MAX_TICKS,
            target_url        = target_url,
            recon_summary     = recon_content,
        )

        # Ghi finding recon vào memory ngay khi khởi tạo
        self.memory.add_finding("recon", "recon_content",
                                truncate(recon_content, 3000), agent="crawl")
        self._report_state = {
            "verdict": "PENDING",
            "workflow": "",
            "exec_report": "",
            "red_evaluation": "",
            "debate_rounds": 0,
        }

    @staticmethod
    def _compact_list(values: list[str], limit: int = 5) -> str:
        cleaned = [str(v).strip() for v in values if str(v).strip()]
        if not cleaned:
            return "-"
        return ", ".join(cleaned[:limit])

    def _format_bug_summary_line(self, bug: dict) -> str:
        bid = bug.get("id", "?")
        pid = bug.get("pattern_id", "?")
        lvl = bug.get("risk_level", "?")
        sts = bug.get("status", "PENDING")
        method = bug.get("method", "?")
        endpoint = bug.get("endpoint", "?")
        auth_labels = self._compact_list(bug.get("auth_credentials_needed") or [])
        params = self._compact_list(bug.get("request_params") or [])
        clue = truncate((bug.get("response_clues") or ["-"])[0], 90)
        return (
            f"- {bid}: [{pid}/{lvl}] {method} {endpoint} [{sts}] | "
            f"auth={bug.get('auth_required', False)} ({auth_labels}) | "
            f"params={params} | clue={clue}"
        )

    def _format_current_bug_dossier(self, bug: dict) -> str:
        if not bug:
            return "(không có bug hiện tại)"

        example_lines = []
        for example in (bug.get("http_examples") or [])[:2]:
            request = truncate(str(example.get("request", "")).replace("\n", " | "), 220)
            why = truncate(str(example.get("why_relevant", "")), 180)
            status = example.get("response_status", "?")
            session = example.get("session_label", "anonymous")
            example_lines.append(
                f"- [{status}] session={session} | request={request} | why={why}"
            )
        if not example_lines:
            example_lines.append("- (chưa có http example)")

        form_fields = [
            f"{f.get('name', '?')}:{f.get('type', '?')}"
            for f in (bug.get("form_fields") or [])
            if isinstance(f, dict)
        ]
        cookie_lines = []
        for item in (bug.get("cookie_attack_surface") or [])[:6]:
            if not isinstance(item, dict):
                continue
            cookie_lines.append(
                f"{item.get('name', '?')}={item.get('value_sample', '?')} "
                f"(session={item.get('session', '?')}, httpOnly={item.get('httpOnly', '?')}, "
                f"{item.get('signal', '?')}) -> {item.get('probe', '?')}"
            )
        variant_lines = [
            f"- {truncate(str(v), 180)}"
            for v in (bug.get("attack_variants") or [])[:6]
            if str(v).strip()
        ]
        return (
            f"ID: {bug.get('id', '?')} | Pattern: {bug.get('pattern_id', '?')} | Risk: {bug.get('risk_level', '?')}\n"
            f"Endpoint: {bug.get('method', '?')} {bug.get('endpoint', '?')} | Status: {bug.get('status', 'PENDING')}\n"
            f"Function: {truncate(str(bug.get('endpoint_function', '-') or '-'), 220)}\n"
            f"Auth: required={bug.get('auth_required', False)} | observation={truncate(str(bug.get('auth_observation', '-') or '-'), 180)}\n"
            f"Params: {self._compact_list(bug.get('request_params') or [])}\n"
            f"Form fields: {self._compact_list(form_fields)}\n"
            f"Hypothesis: {truncate(str(bug.get('hypothesis', '-') or '-'), 260)}\n"
            f"Exploit approach hint: {truncate(str(bug.get('exploit_approach', '-') or '-'), 260)}\n"
            f"Verify method: {truncate(str(bug.get('verify_method', '-') or '-'), 260)}\n"
            f"Response clues: {self._compact_list(bug.get('response_clues') or [], limit=6)}\n"
            f"Cookie/client-state surface: {self._compact_list(cookie_lines, limit=6)}\n"
            f"Suggested attack variants:\n" + ("\n".join(variant_lines) if variant_lines else "-") + "\n"
            f"HTTP examples:\n" + "\n".join(example_lines)
        )

    # ══════════════════════════════════════════════════════════
    # PUBLIC API
    # ══════════════════════════════════════════════════════════

    def run(self, conversation: list[dict]) -> None:
        """Per-bug pipeline: DEBATE_RED → DEBATE_BLUE → EXECUTE_BUG → NEXT_BUG → REPORT.

        Không trả về giá trị — kết quả được ghi vào run_dir/report.md.
        """
        from agents.red_team  import RedTeamAgent
        from agents.exec_agent import ExecAgent

        print(f"\n{M}{B}{'='*60}")
        print(f"  MANAGE AGENT — Per-bug Pipeline")
        print(f"{'='*60}{RST}\n")

        # Nếu không có bug nào → REPORT_FAIL ngay
        if not self.risk_bugs:
            print(f"{R}[!] Không có bug nào trong risk-bug.json — REPORT_FAIL{RST}")
            self._write_report_fail("Không có bug nào để khai thác.")
            return

        exec_agent = ExecAgent(
            working_dir = self.run_dir,
            target_url  = self.target_url,
            recon_md    = str(Path(self.run_dir) / "recon.md"),
            memory_store = self.memory,
        )
        red = RedTeamAgent(
            target_url    = self.target_url,
            recon_context = self.recon_content,
            memory_store  = self.memory,
        )

        old_handlers = self._install_signal_handlers()

        try:
            self._run_loop(red, exec_agent, conversation)
        except RuntimeError as e:
            print(f"\n{R}[!] ManageAgent: {e}{RST}")
            self._write_report_fail(f"Pipeline kết thúc do lỗi: {e}")
        except KeyboardInterrupt as e:
            print(f"\n{Y}[!] ManageAgent bị ngắt: {e}{RST}")
            self._save_report_checkpoint()
        finally:
            self._restore_signal_handlers(old_handlers)
            try:
                exec_agent.shutdown()
            except Exception:
                pass

    # ══════════════════════════════════════════════════════════
    # INTERNAL — per-bug loop
    # ══════════════════════════════════════════════════════════

    def _run_loop(
        self,
        red,
        exec_agent,
        conversation: list[dict],
    ) -> None:
        """Per-bug loop: DEBATE_RED → DEBATE_BLUE → EXECUTE_BUG → NEXT_BUG → REPORT."""
        from agents.blue_team import BlueTeamAgent

        # Per-bug state (all local)
        current_bug_index: int = 0
        current_bug: dict      = self.risk_bugs[0]
        red_approved: bool = False
        red_attempts: int = 0
        exec_retry_count: int = 0
        current_approach: str = ""
        bugs_processed_count: int = 0
        blue: BlueTeamAgent | None = None

        self._persist_new_messages(conversation, start_idx=0)

        for tick in range(MAX_TICKS):
            tick_start_len = len(conversation)

            # Build state context for _decide
            state_context = {
                "tick":                 tick,
                "current_bug_index":    current_bug_index,
                "current_bug_id":       current_bug.get("id", "?"),
                "current_bug":          current_bug,
                "total_bugs":           len(self.risk_bugs),
                "red_approved":         red_approved,
                "red_attempts":         red_attempts,
                "exec_retry_count":     exec_retry_count,
                "bugs_processed_count": bugs_processed_count,
                "last_action":          getattr(self, "_last_action", ""),
                "blue_approved":        red_approved,  # legacy key; means Blue approved now
                "has_workflow":          bool(current_approach),
                "exec_result_status":   current_bug.get("exec_result_status", ""),
                "exec_result_reason":   current_bug.get("exec_result_reason", ""),
            }
            print(f"\n{M}{'─'*60}{RST}")

            action, note = self._decide(conversation, state_context)

            # PolicyAgent validates action
            verdict = self.policy.validate(action, state_context, conversation)
            if verdict is not None and verdict.verdict == "BLOCK":
                consecutive_blocks = getattr(self, "_consecutive_blocks", 0) + 1
                self._consecutive_blocks = consecutive_blocks
                print(f"{Y}[POLICY tick={tick}] BLOCK '{action}' → {verdict.reason[:100]}{RST}")
                if consecutive_blocks >= 3:
                    if not red_approved:
                        action = "DEBATE_RED"
                    else:
                        action = "EXECUTE_BUG"
                    print(f"{Y}[RECOVERY] {consecutive_blocks} BLOCKs → force {action}{RST}")
                    note = f"Recovery sau {consecutive_blocks} policy blocks."
                    self._consecutive_blocks = 0
                else:
                    self._persist_new_messages(conversation, tick_start_len)
                    self.ctx_mgr.compress_if_needed(
                        conversation,
                        trigger_len=COMPRESS_TRIGGER_LEN,
                        keep_recent=COMPRESS_KEEP_RECENT,
                    )
                    continue
            elif verdict is not None and verdict.verdict == "SUGGEST" and verdict.suggested_action:
                print(f"{Y}[POLICY tick={tick}] SUGGEST '{action}' → '{verdict.suggested_action}': {verdict.reason[:80]}{RST}")
                action = verdict.suggested_action
                note = f"Policy điều chỉnh: {verdict.reason}"

            self._last_action = action
            self._consecutive_blocks = 0

            print(f"\n{M}{B}[MANAGER tick={tick}] → {action}{RST}", end="")
            if note:
                print(f"  |  {note}")
            else:
                print()

            # Log tick state
            print(
                f"{Y}[MANAGER tick={tick}] "
                f"bug={current_bug_index + 1}/{len(self.risk_bugs)} "
                f"({current_bug.get('id', '?')}) "
                f"red_attempts={red_attempts}/2 "
                f"approved={'✓' if red_approved else '✗'}{RST}"
            )

            # Inject Manager note into conversation
            if note:
                conversation.append({
                    "speaker": "SYSTEM",
                    "content": f"Manager instruction: {note}",
                })

            # ══════════════════════════════════════════════════════
            # ROUTING
            # ══════════════════════════════════════════════════════

            # DEBATE_RED
            if action == "DEBATE_RED":
                print(f"\n{R}{B}══ RED TEAM — Bug {current_bug_index + 1}/{len(self.risk_bugs)} ══{RST}")
                red.set_current_bug(current_bug)
                response = red.respond(conversation)

                if response.startswith("[LLM Error:"):
                    print(f"{R}{response}{RST}")
                    # Lỗi kết nối → Manager quyết định retry hay stop
                    conversation.append({
                        "speaker": "REDTEAM",
                        "content": response,
                    })
                    # Để Manager đánh giá và quyết định
                else:
                    conversation.append({
                        "speaker": "REDTEAM",
                        "content": response,
                    })
                    print(f"{R}{_strip_tag_display(response)}{RST}")
                    if _is_valid_red_approach(response):
                        current_approach = _strip_tag_display(response)
                        red_approved = False
                        exec_retry_count = 0
                        self._record_strategy(
                            current_bug,
                            current_approach,
                            "PENDING_BLUE_REVIEW: Red strategy captured; Blue must approve before Exec.",
                        )
                        print(f"{G}[MANAGER] Red strategy captured — sending to Blue review{RST}")

            # DEBATE_BLUE
            elif action == "DEBATE_BLUE":
                if blue is None:
                    blue = BlueTeamAgent(
                        target_url    = self.target_url,
                        recon_context = self.recon_content,
                        memory_store  = self.memory,
                    )
                print(f"\n{C}{B}══ BLUE TEAM — Review ══{RST}")
                blue.set_current_bug(current_bug)
                response = blue.respond(conversation)

                if response.startswith("[LLM Error:"):
                    print(f"{R}{response}{RST}")
                    # Lỗi kết nối → vẫn ghi vào conversation để Manager thấy
                else:
                    print(f"{C}{_strip_tag_display(response)}{RST}")

                conversation.append({
                    "speaker": "BLUETEAM",
                    "content": response,
                })

                # Infer Blue intent: APPROVED / REJECTED / STOPPED
                blue_intent_raw = _infer_dialog_intent("BLUETEAM", response)
                if blue_intent_raw == "APPROVE":
                    candidate_approach = current_approach
                    if not candidate_approach:
                        red_approved = False
                        print(
                            f"{Y}[MANAGER] Blue APPROVED but no current Red strategy/shot plan exists — "
                            f"forcing Red retry{RST}"
                        )
                    else:
                        red_approved = True
                        exec_retry_count = 0
                        self._record_strategy(current_bug, current_approach, response)
                        print(f"{G}[MANAGER] Blue APPROVED — approach recorded{RST}")
                elif blue_intent_raw == "REVISE":
                    red_approved = False
                    current_approach = ""
                    red_attempts += 1
                    print(f"{Y}[MANAGER] Blue REJECTED — red_attempts={red_attempts}/2{RST}")
                    if red_attempts >= 2:
                        # Exhausted revision attempts → mark NOT_EXPLOITED
                        print(f"{R}[!] 2× REJECTED — mark STOPPED → NEXT_BUG{RST}")
                        self._mark_bug_not_exploited(
                            current_bug,
                            f"Blue rejected strategy twice. Last review: {response[:400]}",
                            current_approach,
                        )
                        bugs_processed_count += 1
                        result = self._advance_bug(
                            conversation, current_bug, current_bug_index,
                            bugs_processed_count, red, exec_agent
                        )
                        if result in ("REPORT_SUCCESS", "REPORT_FAIL"):
                            return
                        current_bug_index = self.current_bug_index
                        current_bug = self.risk_bugs[current_bug_index]
                        red_approved = False
                        red_attempts = 0
                        exec_retry_count = 0
                        current_approach = ""
                        blue = None
                        self._last_action = "NEXT_BUG"
                elif blue_intent_raw == "STOP":
                    print(f"{Y}[MANAGER] Blue STOPPED — mark NOT_EXPLOITED and next bug{RST}")
                    self._mark_bug_not_exploited(
                        current_bug,
                        f"Blue stopped exploitation. Last review: {response[:400]}",
                        current_approach,
                    )
                    bugs_processed_count += 1
                    result = self._advance_bug(
                        conversation, current_bug, current_bug_index,
                        bugs_processed_count, red, exec_agent
                    )
                    if result in ("REPORT_SUCCESS", "REPORT_FAIL"):
                        return
                    current_bug_index = self.current_bug_index
                    current_bug = self.risk_bugs[current_bug_index]
                    red_approved = False
                    red_attempts = 0
                    exec_retry_count = 0
                    current_approach = ""
                    blue = None
                    self._last_action = "NEXT_BUG"
                else:
                    red_approved = False

            # RETRY_RED — Red chạy lại
            elif action == "RETRY_RED":
                print(f"\n{R}{B}══ RED TEAM (RETRY) — Bug {current_bug_index + 1}/{len(self.risk_bugs)} ══{RST}")
                red.set_current_bug(current_bug)
                response = red.respond(conversation)
                if response.startswith("[LLM Error:"):
                    print(f"{R}{response}{RST}")
                else:
                    print(f"{R}{_strip_tag_display(response)}{RST}")
                conversation.append({
                    "speaker": "REDTEAM",
                    "content": response,
                })
                red_attempts += 1
                if _is_valid_red_approach(response):
                    current_approach = _strip_tag_display(response)
                    red_approved = False
                    exec_retry_count = 0
                    self._record_strategy(
                        current_bug,
                        current_approach,
                        "PENDING_BLUE_REVIEW: Red retry strategy captured; Blue must approve before Exec.",
                    )
                    print(f"{G}[MANAGER] Red retry strategy captured — sending to Blue review{RST}")
                else:
                    red_approved = False
                    current_approach = ""
                print(f"{Y}[MANAGER] Red revision consumed — red_attempts={red_attempts}/2{RST}")

            # RETRY_BLUE — Blue chạy lại
            elif action == "RETRY_BLUE":
                if blue is None:
                    blue = BlueTeamAgent(
                        target_url    = self.target_url,
                        recon_context = self.recon_content,
                        memory_store  = self.memory,
                    )
                print(f"\n{C}{B}══ BLUE TEAM (RETRY) — Review ══{RST}")
                blue.set_current_bug(current_bug)
                response = blue.respond(conversation)
                if response.startswith("[LLM Error:"):
                    print(f"{R}{response}{RST}")
                else:
                    print(f"{C}{_strip_tag_display(response)}{RST}")
                conversation.append({
                    "speaker": "BLUETEAM",
                    "content": response,
                })
                # Update intent after retry
                blue_intent_raw = _infer_dialog_intent("BLUETEAM", response)
                if blue_intent_raw == "APPROVE":
                    red_approved = True
                    exec_retry_count = 0
                    candidate_approach = current_approach
                    if not candidate_approach:
                        red_approved = False
                        print(
                            f"{Y}[MANAGER] Blue APPROVED (retry) but no current Red strategy/shot plan exists — "
                            f"forcing Red retry{RST}"
                        )
                    else:
                        self._record_strategy(current_bug, current_approach, response)
                        print(f"{G}[MANAGER] Blue APPROVED (retry) — approach recorded{RST}")
                elif blue_intent_raw == "REVISE":
                    red_approved = False
                    current_approach = ""
                    red_attempts += 1
                    print(f"{Y}[MANAGER] Blue REJECTED (retry) — red_attempts={red_attempts}/2{RST}")
                elif blue_intent_raw == "STOP":
                    print(f"{Y}[MANAGER] Blue STOPPED (retry) — mark NOT_EXPLOITED and next bug{RST}")
                    self._mark_bug_not_exploited(
                        current_bug,
                        f"Blue stopped exploitation on retry. Last review: {response[:400]}",
                        current_approach,
                    )
                    bugs_processed_count += 1
                    result = self._advance_bug(
                        conversation, current_bug, current_bug_index,
                        bugs_processed_count, red, exec_agent
                    )
                    if result in ("REPORT_SUCCESS", "REPORT_FAIL"):
                        return
                    current_bug_index = self.current_bug_index
                    current_bug = self.risk_bugs[current_bug_index]
                    red_approved = False
                    red_attempts = 0
                    exec_retry_count = 0
                    current_approach = ""
                    blue = None
                    self._last_action = "NEXT_BUG"
                else:
                    red_approved = False

            # EXECUTE_BUG
            elif action == "EXECUTE_BUG":
                if not current_approach:
                    print(f"{R}[!] EXECUTE_BUG but no approach — fallback DEBATE_RED{RST}")
                    red_approved = False
                    self._last_action = ""
                    conversation.append({
                        "speaker": "SYSTEM",
                        "content": "Manager guard: EXECUTE_BUG blocked because no valid Red strategy/shot plan exists.",
                    })
                    continue

                print(f"\n{C}{B}{'='*60}")
                print(f"  EXECUTE_BUG — {current_bug.get('id', '?')}")
                print(f"{'='*60}{RST}\n")
                print(
                    f"{G}[MANAGER] → EXECUTE_BUG | bug={current_bug.get('id', '?')} "
                    f"endpoint={current_bug.get('endpoint', '?')} shots=auto(base=1){RST}"
                )
                print(f"{G}[MANAGER] input: accepted Red strategy sent to Exec{RST}\n")

                def _run_with_timeout():
                    import threading
                    result = {"value": None, "error": None}
                    def target():
                        try:
                            result["value"] = exec_agent.run_workflow(
                                current_approach,
                                conversation,
                                max_script_shots=1,
                                allow_tool_loop=False,
                                artifact_prefix=current_bug.get("id", "bug-unknown"),
                            )
                        except Exception as e:
                            result["error"] = str(e)
                    t = threading.Thread(target=target, daemon=True)
                    t.start()
                    t.join(timeout=EXEC_TIMEOUT)
                    if t.is_alive():
                        return "[TIMEOUT] ExecAgent treo quá giới hạn"
                    if result["error"]:
                        return f"[ERROR] {result['error']}"
                    return result["value"] or ""

                raw = _run_with_timeout()
                exec_result = _extract_exec_result(raw)

                conversation.append({
                    "speaker": "AGENT",
                    "content": f"Execution result:\n{exec_result}",
                })
                print(f"{G}[MANAGER] Exec output: {_summarize_exec_result(exec_result)}{RST}")

                # Lưu exec_result vào instance để _decide đọc được
                self._last_exec_result = exec_result
                self._record_exec_result(current_bug, current_approach, exec_result)

            # RETRY_EXEC — Exec chạy lại
            elif action == "RETRY_EXEC":
                if not current_approach:
                    print(f"{R}[!] RETRY_EXEC but no approach — fallback DEBATE_RED{RST}")
                    red_approved = False
                    self._last_action = ""
                    conversation.append({
                        "speaker": "SYSTEM",
                        "content": "Manager guard: RETRY_EXEC blocked because no valid Red strategy/shot plan exists.",
                    })
                    continue
                exec_retry_count += 1
                print(f"\n{C}{B}{'='*60}")
                print(f"  RETRY_EXEC — {current_bug.get('id', '?')}")
                print(f"{'='*60}{RST}\n")
                print(
                    f"{G}[MANAGER] → RETRY_EXEC | bug={current_bug.get('id', '?')} "
                    f"endpoint={current_bug.get('endpoint', '?')} shots=auto(base=1){RST}"
                )
                print(f"{G}[MANAGER] input: retry after partial/failed exploit evidence{RST}\n")

                def _run_with_timeout():
                    import threading
                    result = {"value": None, "error": None}
                    def target():
                        try:
                            result["value"] = exec_agent.run_workflow(
                                current_approach,
                                conversation,
                                max_script_shots=1,
                                allow_tool_loop=False,
                                artifact_prefix=current_bug.get("id", "bug-unknown"),
                            )
                        except Exception as e:
                            result["error"] = str(e)
                    t = threading.Thread(target=target, daemon=True)
                    t.start()
                    t.join(timeout=EXEC_TIMEOUT)
                    if t.is_alive():
                        return "[TIMEOUT] ExecAgent treo quá giới hạn"
                    if result["error"]:
                        return f"[ERROR] {result['error']}"
                    return result["value"] or ""

                raw = _run_with_timeout()
                exec_result = _extract_exec_result(raw)

                conversation.append({
                    "speaker": "AGENT",
                    "content": f"Execution result:\n{exec_result}",
                })
                print(f"{G}[MANAGER] Exec output: {_summarize_exec_result(exec_result)}{RST}")
                self._last_exec_result = exec_result
                self._record_exec_result(current_bug, current_approach, exec_result)

            # STOP_BUG
            elif action == "STOP_BUG":
                # Manager quyết định dừng bug hiện tại (đọc từ note hoặc conversation)
                # Default: NOT_EXPLOITED, có thể override bằng OOS_SCOPE
                stop_reason = "NOT_EXPLOITED"
                for msg in reversed(conversation):
                    if "OOS_SCOPE" in msg.get("content", "").upper():
                        stop_reason = "OOS_SCOPE"
                        break
                current_bug["status"] = stop_reason
                current_bug["PoC"] = current_bug.get("PoC", "")
                current_bug["failure_reason"] = note or f"Manager stopped bug as {stop_reason}."
                self._save_risk_bugs()
                bugs_processed_count += 1
                print(f"{Y}[MANAGER] STOP_BUG — {current_bug.get('id','?')} marked {stop_reason}{RST}")

                result = self._advance_bug(
                    conversation, current_bug, current_bug_index,
                    bugs_processed_count, red, exec_agent
                )
                if result in ("REPORT_SUCCESS", "REPORT_FAIL"):
                    return
                current_bug_index = self.current_bug_index
                current_bug = self.risk_bugs[current_bug_index]
                red_approved = False
                red_attempts = 0
                exec_retry_count = 0
                current_approach = ""
                blue = None
                self._last_action = "NEXT_BUG"

            # NEXT_BUG
            elif action == "NEXT_BUG":
                prior_action = state_context.get("last_action", "")
                if prior_action in ("EXECUTE_BUG", "RETRY_EXEC") and current_bug.get("status") == "EXPLOITED":
                    current_bug["PoC"] = current_bug.get("PoC") or getattr(self, "_last_exec_result", "")
                    self._save_risk_bugs()
                    print(f"{G}[MANAGER] {current_bug.get('id', '?')} marked EXPLOITED{RST}")
                elif current_bug.get("status", "PENDING") == "PENDING":
                    self._mark_bug_not_exploited(
                        current_bug,
                        "Manager advanced before a confirmed exploit was captured.",
                        current_approach,
                    )
                    print(
                        f"{Y}[MANAGER] {current_bug.get('id', '?')} marked NOT_EXPLOITED "
                        f"before advancing{RST}"
                    )
                bugs_processed_count += 1
                result = self._advance_bug(
                    conversation, current_bug, current_bug_index,
                    bugs_processed_count, red, exec_agent
                )
                if result in ("REPORT_SUCCESS", "REPORT_FAIL"):
                    return
                # Sync local state after _advance_bug updates self
                current_bug_index = self.current_bug_index
                current_bug = self.risk_bugs[current_bug_index]
                red_approved = False
                red_attempts = 0
                exec_retry_count = 0
                current_approach = ""
                blue = None

            # REPORT_SUCCESS
            elif action == "REPORT_SUCCESS":
                self._write_report_success()
                return

            # REPORT_FAIL
            elif action == "REPORT_FAIL":
                self._write_report_fail("Không có bug nào được khai thác thành công.")
                return

            else:
                print(f"{Y}[!] Action không hợp lệ '{action}' → fallback DEBATE_RED{RST}")

            # End of tick: persist + compress
            self._persist_new_messages(conversation, tick_start_len)
            self.ctx_mgr.compress_if_needed(
                conversation,
                trigger_len=COMPRESS_TRIGGER_LEN,
                keep_recent=COMPRESS_KEEP_RECENT,
            )

        # MAX_TICKS exhausted
        print(f"\n{R}[!] Hết {MAX_TICKS} ticks — REPORT_FAIL{RST}")
        self._write_report_fail(f"Hết giới hạn {MAX_TICKS} ticks.")

    def _advance_bug(
        self,
        conversation: list[dict],
        current_bug: dict,
        current_bug_index: int,
        bugs_processed_count: int,
        red,
        exec_agent,
    ) -> str:
        """Move to next bug.

        Returns:
            "CONTINUE" — more bugs remain, loop should continue
            "REPORT_SUCCESS" — all bugs done, success report written
            "REPORT_FAIL" — all bugs done, fail report written
        """
        n = len(self.risk_bugs)
        next_index = current_bug_index + 1

        if next_index >= n:
            # All bugs processed
            exploitable = [b for b in self.risk_bugs if b.get("status") == "EXPLOITED"]
            if exploitable:
                self._write_report_success()
                return "REPORT_SUCCESS"
            else:
                self._write_report_fail("Không có bug nào được khai thác thành công.")
                return "REPORT_FAIL"
        else:
            # Advance state on self
            self.current_bug_index = next_index
            self._last_exec_result = ""

            # Reset per-bug state on self (used by _decide)
            next_bug = self.risk_bugs[next_index]
            conversation.append({
                "speaker": "SYSTEM",
                "content": (
                    f"Manager switched to next bug: "
                    f"{next_bug.get('id', '?')} — {next_bug.get('title', '?')}"
                ),
            })
            print(
                f"{M}[MANAGER] NEXT_BUG → {next_index + 1}/{n} "
                f"({next_bug.get('id', '?')}){RST}"
            )
            return "CONTINUE"

    def _record_strategy(
        self,
        current_bug: dict,
        approach: str,
        blue_review: str | None = None,
    ) -> None:
        """Persist the approved/revised exploitation procedure for final reporting."""
        if approach:
            current_bug["exploit_procedure"] = approach
        if current_bug.get("status") != "EXPLOITED":
            current_bug["status"] = "PENDING"
            for key in (
                "validation_status",
                "validation_reason",
                "post_exec_review",
                "exec_verify_status",
                "exec_verify_result",
                "validated_evidence_summary",
                "evidence_guard",
                "failure_reason",
                "exec_result_status",
                "exec_result_reason",
                "exec_result_evidence",
                "exploited_evidence_summary",
                "manager_exec_review",
                "manager_review_status",
                "result_summary",
            ):
                current_bug.pop(key, None)
        if blue_review:
            reviews = current_bug.setdefault("blue_reviews", [])
            review_text = truncate(blue_review, 1200)
            if review_text not in reviews:
                reviews.append(review_text)
        self._save_risk_bugs()

    def _record_exec_attempt(
        self,
        current_bug: dict,
        approach: str,
        exec_result: str,
    ) -> None:
        """Persist the latest Exec evidence and script artifact paths for reports."""
        if approach:
            current_bug["exploit_procedure"] = approach
        if exec_result:
            current_bug["last_exec_result"] = exec_result

        artifacts = self._extract_script_artifacts(exec_result)
        if artifacts:
            existing = current_bug.setdefault("exploit_artifacts", [])
            seen_paths = {item.get("path") for item in existing if isinstance(item, dict)}
            for item in artifacts:
                if item.get("path") not in seen_paths:
                    existing.append(item)
                    seen_paths.add(item.get("path"))
        self._save_risk_bugs()

    def _record_exec_result(
        self,
        current_bug: dict,
        approach: str,
        exec_result: str,
    ) -> dict:
        """Persist Exec's self-verified result and keep Manager routing simple."""
        self._record_exec_attempt(current_bug, approach, exec_result)
        decision = self._exec_decision(exec_result, current_bug)
        status = decision["status"]

        current_bug["exec_result_status"] = status
        current_bug["exec_result_reason"] = decision["reason"]
        current_bug["exec_result_evidence"] = decision["evidence"]
        current_bug["status"] = "EXPLOITED" if status == "EXPLOITED" else "PENDING"

        for key in (
            "validation_status",
            "validation_reason",
            "post_exec_review",
            "exec_verify_status",
            "exec_verify_result",
            "validated_evidence_summary",
            "evidence_guard",
            "manager_exec_review",
            "manager_review_status",
            "result_summary",
        ):
            current_bug.pop(key, None)

        if status == "EXPLOITED":
            current_bug["PoC"] = exec_result
            current_bug["exploited_evidence_summary"] = truncate(decision["evidence"], 1600)
            current_bug.pop("failure_reason", None)
            print(
                f"{G}[MANAGER] Exec decision: EXPLOITED — "
                f"{truncate(decision['evidence'], 220)}{RST}"
            )
        elif status == "SCRIPT_ERROR":
            current_bug["failure_reason"] = truncate(decision["reason"], 1000)
            print(f"{Y}[MANAGER] Exec decision: SCRIPT_ERROR — {truncate(decision['reason'], 220)}{RST}")
        elif status == "PARTIAL":
            current_bug["failure_reason"] = truncate(decision["reason"], 1000)
            print(f"{Y}[MANAGER] Exec decision: PARTIAL — {truncate(decision['reason'], 220)}{RST}")
        else:
            current_bug["status"] = "NOT_EXPLOITED"
            current_bug["failure_reason"] = truncate(decision["reason"], 1000)
            print(f"{Y}[MANAGER] Exec decision: FAILED — {truncate(decision['reason'], 220)}{RST}")

        self._save_risk_bugs()
        return decision

    def _mark_bug_not_exploited(
        self,
        current_bug: dict,
        reason: str,
        approach: str = "",
    ) -> None:
        current_bug["status"] = "NOT_EXPLOITED"
        if (
            reason.startswith("Manager advanced before")
            and current_bug.get("validation_reason")
        ):
            reason = str(current_bug.get("validation_reason"))
        current_bug["failure_reason"] = truncate(reason, 1200)
        if approach:
            current_bug["exploit_procedure"] = approach
        if getattr(self, "_last_exec_result", ""):
            self._record_exec_attempt(current_bug, approach, self._last_exec_result)
        else:
            self._save_risk_bugs()

    @staticmethod
    def _extract_script_artifacts(exec_result: str) -> list[dict]:
        if not exec_result:
            return []
        paths = re.findall(r"^SCRIPT_PATH:\s*(.+?)\s*$", exec_result, re.MULTILINE)
        shas = re.findall(r"^SCRIPT_SHA256:\s*(.+?)\s*$", exec_result, re.MULTILINE)
        syntax_logs = re.findall(r"^SYNTAX_LOG_PATH:\s*(.+?)\s*$", exec_result, re.MULTILINE)
        exec_outputs = re.findall(r"^EXEC_OUTPUT_PATH:\s*(.+?)\s*$", exec_result, re.MULTILINE)
        state_dirs = re.findall(r"^STATE_DIR:\s*(.+?)\s*$", exec_result, re.MULTILINE)
        result_jsons = re.findall(r"^RESULT_JSON_PATH:\s*(.+?)\s*$", exec_result, re.MULTILINE)
        contracts = re.findall(r"^ARTIFACT_CONTRACT:\s*(.+?)\s*$", exec_result, re.MULTILINE)
        artifacts = []
        for idx, path in enumerate(paths):
            item = {"path": path.strip()}
            if idx < len(shas):
                item["sha256_16"] = shas[idx].strip()
            if idx < len(syntax_logs):
                item["syntax_log_path"] = syntax_logs[idx].strip()
            if idx < len(exec_outputs):
                item["exec_output_path"] = exec_outputs[idx].strip()
            if idx < len(state_dirs):
                item["state_dir"] = state_dirs[idx].strip()
            if idx < len(result_jsons):
                item["result_json_path"] = result_jsons[idx].strip()
            if idx < len(contracts):
                item["artifact_contract"] = contracts[idx].strip()
            artifacts.append(item)
        return artifacts

    @staticmethod
    def _safe_code_block(text: str) -> str:
        return str(text or "").replace("```", "` ` `")

    def _display_run_path(self, path: str | None) -> str:
        if not path:
            return "-"
        path_obj = Path(path)
        try:
            return str(path_obj.relative_to(Path(self.run_dir)))
        except Exception:
            return str(path_obj)

    def _format_artifact_list(self, bug: dict) -> str:
        artifacts = bug.get("exploit_artifacts") or []
        if not artifacts:
            return "_No saved exploit script artifacts._"
        lines = []
        for item in artifacts:
            if not isinstance(item, dict):
                continue
            path = item.get("path", "")
            sha = item.get("sha256_16", "")
            suffix = f" — sha256[:16]=`{sha}`" if sha else ""
            lines.append(f"- `{path}`{suffix}")
            if item.get("exec_output_path"):
                lines.append(f"- `output`: `{item.get('exec_output_path')}`")
            if item.get("syntax_log_path"):
                lines.append(f"- `syntax`: `{item.get('syntax_log_path')}`")
            if item.get("result_json_path"):
                lines.append(f"- `result`: `{item.get('result_json_path')}`")
            if item.get("artifact_contract"):
                lines.append(f"- `artifact_contract`: `{item.get('artifact_contract')}`")
        return "\n".join(lines) if lines else "_No saved exploit script artifacts._"

    def _format_bug_report_section(self, bug: dict) -> str:
        status = bug.get("status", "PENDING")
        evidence = bug.get("PoC") or bug.get("last_exec_result") or "(no execution evidence captured)"
        procedure = bug.get("exploit_procedure") or bug.get("exploit_approach") or "(no procedure captured)"
        failure_reason = bug.get("failure_reason", "")
        status_note = f"\n**Failure / False-positive reason:** {failure_reason}\n" if failure_reason else ""

        return f"""## {bug.get('id', '?')} — {bug.get('title', '?')}
**Status:** {status}
**Pattern:** {bug.get('pattern_id', '?')}
**Risk Level:** {bug.get('risk_level', '?')}
**Endpoint:** `{bug.get('method', '?')} {bug.get('endpoint', '?')}`
**Hypothesis:** {bug.get('hypothesis', '-')}
**Verify Method:** {bug.get('verify_method', '-')}
{status_note}
### Exploit Scripts
{self._format_artifact_list(bug)}

### Procedure Used
```
{self._safe_code_block(procedure)}
```

### Execution Evidence
```
{self._safe_code_block(truncate(evidence, 7000))}
```
"""

    def _save_risk_bugs(self) -> None:
        """Save updated risk_bugs list to disk."""
        path = Path(self.run_dir) / "risk-bug.json"
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.risk_bugs, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"{Y}[!] Could not save risk-bug.json: {e}{RST}")

    def _exec_decision(self, exec_result: str, current_bug: dict) -> dict:
        """Classify Exec's self-verified exploit result without a second verifier."""
        output = _extract_exec_output(exec_result) or exec_result or ""
        lower_result = str(exec_result or "").lower()
        lower_output = str(output or "").lower()
        success_verdict = _exec_success_verdict(exec_result)
        final_marker = _exec_final_marker(exec_result)
        attempt = _classify_exec_attempt(exec_result, current_bug)
        result_json = self._load_exec_result_json(exec_result)
        json_status = str(result_json.get("status", "") or result_json.get("verdict", "")).upper()
        return_code = self._extract_exec_return_code(exec_result)
        evidence = _summarize_exec_output(exec_result, max_lines=8)

        runtime_markers = (
            "syntax_check: fail", "script validation failed", "python py_compile failed",
            "syntax error", "command not found", "[timeout]", "timed out",
            "[api error", "[llm error", "connection error",
        )
        if any(marker in lower_result or marker in lower_output for marker in runtime_markers):
            return {
                "status": "SCRIPT_ERROR",
                "reason": evidence or "Exec script/runtime error.",
                "evidence": evidence,
            }

        if json_status == "EXPLOITED" or success_verdict == "YES" or final_marker == "EXPLOITED":
            return {
                "status": "EXPLOITED",
                "reason": evidence or "Exec reported EXPLOITED.",
                "evidence": evidence,
            }

        # Anti-overfitting: accept minimum sufficient proof from the current dossier/strategy.
        # A read-only BAC/IDOR proof can be a 2xx response plus a privileged/object marker;
        # it does not need extra endpoints or stronger side effects.
        if attempt.get("signal") in {"PROOF_CANDIDATE", "NEW_LEAD"}:
            return {
                "status": "EXPLOITED",
                "reason": evidence or "Exec observed a candidate proof matching the bug hypothesis.",
                "evidence": evidence,
            }

        if self._result_json_has_positive_marker(result_json):
            return {
                "status": "EXPLOITED",
                "reason": evidence or "result.json contains a positive proof marker.",
                "evidence": evidence,
            }

        if json_status in {"PARTIAL", "INCONCLUSIVE"} or success_verdict == "PARTIAL" or final_marker == "PARTIAL" or return_code == 2:
            return {
                "status": "PARTIAL",
                "reason": evidence or "Exec found some signal but did not mark the exploit complete.",
                "evidence": evidence,
            }

        if json_status in {"FAILED", "NO", "NOT_EXPLOITED"} or success_verdict == "NO" or final_marker == "FAILED" or return_code == 1:
            return {
                "status": "FAILED",
                "reason": evidence or "Exec marked the exploit as failed.",
                "evidence": evidence,
            }

        return {
            "status": "PARTIAL",
            "reason": evidence or "Exec result is ambiguous.",
            "evidence": evidence,
        }

    @staticmethod
    def _extract_exec_return_code(exec_result: str) -> int:
        match = re.search(r'\{[^}]*"return_code"\s*:\s*(-?\d+)', str(exec_result or ""), re.DOTALL)
        if not match:
            return -1
        try:
            return int(match.group(1))
        except ValueError:
            return -1

    @staticmethod
    def _load_exec_result_json(exec_result: str) -> dict:
        paths = re.findall(r"^RESULT_JSON_PATH:\s*(.+?)\s*$", str(exec_result or ""), re.MULTILINE)
        for path in reversed(paths):
            try:
                path_obj = Path(path.strip())
                if path_obj.is_file():
                    data = json.loads(path_obj.read_text(encoding="utf-8"))
                    if isinstance(data, dict):
                        return data
            except Exception:
                continue
        return {}

    @staticmethod
    def _result_json_has_positive_marker(data: dict) -> bool:
        if not isinstance(data, dict):
            return False
        for key, value in data.items():
            key_lower = str(key).lower()
            if isinstance(value, bool) and value and any(
                marker in key_lower
                for marker in ("marker", "admin", "proof", "changed", "delta", "leak", "access")
            ):
                return True
            if isinstance(value, (int, float)) and value != 0 and "delta" in key_lower:
                return True
        return False

    def _exec_succeeded(self, exec_result: str) -> bool:
        """Backward-compatible success check for older callers."""
        return self._exec_decision(exec_result, {}).get("status") == "EXPLOITED"

    def _recommendation_for_bug(self, bug: dict) -> str:
        text = " ".join(str(bug.get(k, "") or "") for k in ("category", "title", "endpoint", "hypothesis")).lower()
        if "cart" in text or "qty" in text or "amount" in text or "transfer" in text or "checkout" in text:
            return (
                "Validate toàn bộ giá trị nghiệp vụ ở server-side; từ chối số âm/giá trị ngoài miền hợp lệ; "
                "tính lại tổng tiền/số dư từ dữ liệu tin cậy phía server thay vì tin input client."
            )
        if "admin" in text or "role" in text or "promote" in text:
            return (
                "Áp dụng kiểm tra phân quyền server-side cho từng endpoint quản trị; không tin role từ cookie/client; "
                "chỉ cho phép tài khoản có quyền admin thực hiện thao tác thay đổi vai trò/xóa user."
            )
        if "profile" in text or "order" in text or "idor" in text:
            return (
                "Kiểm tra ownership trên server cho từng object ID; chỉ trả dữ liệu khi object thuộc user hiện tại "
                "hoặc user có quyền phù hợp; thêm test regression cho IDOR."
            )
        return (
            "Bổ sung kiểm tra authorization và validation server-side, ghi log các thao tác nhạy cảm, "
            "và thêm test tự động cho luồng BAC/BLF tương ứng."
        )

    def _format_final_vi_finding(self, bug: dict) -> str:
        evidence = (
            bug.get("exploited_evidence_summary")
            or bug.get("exec_result_evidence")
            or bug.get("last_exec_result")
            or "(chưa có tóm tắt evidence)"
        )
        artifacts = bug.get("exploit_artifacts") or []
        artifact_lines = []
        for item in artifacts[:4]:
            if isinstance(item, dict) and item.get("path"):
                artifact_lines.append(f"- Script: `{item.get('path')}`")
                if item.get("exec_output_path"):
                    artifact_lines.append(f"- Output: `{item.get('exec_output_path')}`")
                if item.get("result_json_path"):
                    artifact_lines.append(f"- Result JSON: `{item.get('result_json_path')}`")
                if item.get("artifact_contract"):
                    artifact_lines.append(f"- Artifact contract: `{item.get('artifact_contract')}`")
        artifacts_text = "\n".join(artifact_lines) if artifact_lines else "- Không có artifact script được lưu."
        return f"""## {bug.get('id', '?')} — {bug.get('title', '?')}

### FINDING
Endpoint `{bug.get('method', '?')} {bug.get('endpoint', '?')}` có dấu hiệu lỗ hổng {bug.get('category', 'BAC/BLF')} đã được xác thực.

### MÔ TẢ
{bug.get('hypothesis', '-')}

### TÁC ĐỘNG
{bug.get('risk_level', 'UNKNOWN')} — lỗ hổng có thể dẫn tới truy cập trái phép dữ liệu/chức năng hoặc thao túng logic nghiệp vụ tùy theo endpoint bị ảnh hưởng.

### POC
Trạng thái Exec: `{bug.get('exec_result_status') or bug.get('status', 'EXPLOITED')}`.

Tóm tắt evidence:
```
{self._safe_code_block(truncate(evidence, 1800))}
```

Artifact:
{artifacts_text}

### KHUYẾN NGHỊ KHẮC PHỤC
{self._recommendation_for_bug(bug)}
"""

    def _format_final_vi_unvalidated(self, bug: dict) -> str:
        reason = (
            bug.get("exec_result_reason")
            or bug.get("validation_reason")
            or bug.get("failure_reason")
            or "Chưa có bằng chứng đủ mạnh để xác thực finding."
        )
        return (
            f"- **{bug.get('id', '?')} — {bug.get('title', '?')}** "
            f"(`{bug.get('method', '?')} {bug.get('endpoint', '?')}`): "
            f"`{bug.get('exec_result_status') or bug.get('status') or 'NOT_EXPLOITED'}` — "
            f"{truncate(str(reason), 420)}"
        )

    def _write_report_success(self) -> None:
        exploitable = [
            b for b in self.risk_bugs
            if b.get("status") == "EXPLOITED"
        ]
        not_exploitable = [
            b for b in self.risk_bugs
            if b not in exploitable
        ]

        print(f"\n{C}{B}{'='*60}")
        print(f"  REPORT_SUCCESS — {len(exploitable)} validated bug(s)")
        print(f"{'='*60}{RST}\n")
        for b in exploitable:
            print(f"{G}  [{b.get('id', '?')}] {b.get('title', '?')}{RST}")
            print(f"    Status: {b.get('status')}")
            print(f"    PoC: {str(b.get('PoC', ''))[:200]}...")
            print()

        exploited_text = (
            "\n".join(self._format_bug_report_section(b) for b in exploitable)
            if exploitable
            else "_No exploited bugs captured._"
        )
        not_exploited_text = (
            "\n".join(self._format_bug_report_section(b) for b in not_exploitable)
            if not_exploitable
            else "_No unexploited or false-positive findings._"
        )

        raw_report_md = f"""# MARL Raw Penetration Test Report
**Target:** {self.target_url}
**Verdict:** ✅ SUCCESS
**Validated Bugs:** {len(exploitable)} / {len(self.risk_bugs)}

## Executive Summary
{len(exploitable)} vulnerability/ies were validated out of {len(self.risk_bugs)} identified candidates.
The sections below preserve approved procedures, saved exploit scripts, Exec self-verification notes, and raw execution evidence.

## Validated Findings

{exploited_text}

## Not Validated / False Positive Candidates

{not_exploited_text}
"""

        raw_report_md += """
## Remediation
- Enforce server-side authorization on every sensitive endpoint.
- Validate business rules server-side; never trust client-controlled price, quantity, role, userId, or workflow state.
- Bind CSRF/session checks to authenticated user and intended action.
- Add regression tests for the reproduced BAC/BLF path.

## Evidence Handling
- Raw recon artifacts are in `recon.md`.
- Full conversation and task memory are in `memory/` for this run.
"""

        final_sections = (
            "\n\n".join(self._format_final_vi_finding(b) for b in exploitable)
            if exploitable
            else "_Không có finding nào đạt `status=EXPLOITED`._"
        )
        unvalidated_sections = (
            "\n".join(self._format_final_vi_unvalidated(b) for b in not_exploitable)
            if not_exploitable
            else "_Không có false positive/chưa xác thực._"
        )
        final_report_md = f"""# Báo Cáo Kiểm Thử BAC/BLF

**Mục tiêu:** {self.target_url}
**Kết luận:** {"THÀNH CÔNG" if exploitable else "CHƯA XÁC THỰC ĐƯỢC LỖ HỔNG"}
**Finding đã xác thực:** {len(exploitable)} / {len(self.risk_bugs)}

## Tóm Tắt
Hệ thống đã xác thực {len(exploitable)} finding qua Python exploit self-verify.
Các candidate không đủ bằng chứng được giữ riêng ở mục cuối để tránh overclaim.

## Finding Đã Xác Thực

{final_sections}

## Candidate Chưa Đủ Bằng Chứng / False Positive

{unvalidated_sections}

## Ghi Chú Evidence
- Bản report này chỉ tính finding có `status=EXPLOITED`.
- Bản raw đầy đủ nằm ở `report_raw.md`.
- Script và output PoC nằm trong thư mục `exploits/`.
"""

        raw_path = Path(self.run_dir) / "report_raw.md"
        final_path = Path(self.run_dir) / "report_final_vi.md"
        report_path = Path(self.run_dir) / "report.md"
        raw_path.write_text(raw_report_md, encoding="utf-8")
        final_path.write_text(final_report_md, encoding="utf-8")
        report_path.write_text(final_report_md, encoding="utf-8")
        print(f"\n{G}[+] Report saved: {report_path.resolve()}{RST}")
        print(f"{G}[+] Raw report saved: {raw_path.resolve()}{RST}")
        print(f"{G}[+] Final Vietnamese report saved: {final_path.resolve()}{RST}")

    def _write_report_fail(self, reason: str) -> None:
        print(f"\n{C}{B}{'='*60}")
        print(f"  REPORT_FAIL")
        print(f"{'='*60}{RST}\n")
        print(f"{R}Reason: {reason}{RST}")

        raw_report_md = f"""# MARL Raw Penetration Test Report
**Target:** {self.target_url}
**Verdict:** ❌ FAIL

## Executive Summary
No bugs were successfully exploited. Reason: {reason}

## Bugs Processed
"""
        raw_report_md += "\n".join(self._format_bug_report_section(b) for b in self.risk_bugs)

        raw_report_md += """
## Evidence Handling
- Raw recon artifacts are in `recon.md`.
- Full conversation and task memory are in `memory/` for this run.
"""

        final_report_md = f"""# Báo Cáo Kiểm Thử BAC/BLF

**Mục tiêu:** {self.target_url}
**Kết luận:** CHƯA XÁC THỰC ĐƯỢC LỖ HỔNG
**Lý do:** {reason}

## Candidate Chưa Đủ Bằng Chứng / False Positive

{chr(10).join(self._format_final_vi_unvalidated(b) for b in self.risk_bugs)}

## Ghi Chú Evidence
- Không có finding nào đạt `status=EXPLOITED`.
- Bản raw đầy đủ nằm ở `report_raw.md`.
"""

        raw_path = Path(self.run_dir) / "report_raw.md"
        final_path = Path(self.run_dir) / "report_final_vi.md"
        report_path = Path(self.run_dir) / "report.md"
        raw_path.write_text(raw_report_md, encoding="utf-8")
        final_path.write_text(final_report_md, encoding="utf-8")
        report_path.write_text(final_report_md, encoding="utf-8")
        print(f"\n{G}[+] Report saved: {report_path.resolve()}{RST}")
        print(f"{G}[+] Raw report saved: {raw_path.resolve()}{RST}")
        print(f"{G}[+] Final Vietnamese report saved: {final_path.resolve()}{RST}")

    # ══════════════════════════════════════════════════════════
    # INTERNAL — Manager LLM decision
    # ══════════════════════════════════════════════════════════

    def _decide(
        self,
        conversation: list[dict],
        state_context: dict,
    ) -> tuple[str, str]:
        """Gọi LLM để quyết định action tiếp theo trong per-bug pipeline.

        Returns:
            (action, note)
            - action: một trong VALID_ACTIONS
            - note:   hướng dẫn bổ sung cho agent tiếp theo (có thể rỗng)
        """
        # ── Shortcut: after DEBATE_BLUE, decide next step based on Blue's intent ──
        if state_context.get("last_action") == "DEBATE_BLUE":
            last_blue = _get_last_blue_content(conversation)
            if last_blue:
                if _is_agent_failure_response(last_blue):
                    return "RETRY_BLUE", "Blue trả response rỗng/lỗi. Gọi Blue lại."
                lower_blue = last_blue.lower().strip()
                has_valid_approach = bool(state_context.get("has_workflow", False))
                if (
                    state_context.get("red_approved", False)
                    and has_valid_approach
                    and (lower_blue.startswith("approved") or "approved" in lower_blue[:20])
                ):
                    return "EXECUTE_BUG", "Blue đã approve — thực thi exploit."
                blue_intent = _infer_dialog_intent("BLUETEAM", last_blue)
                if blue_intent == "APPROVE" and state_context.get("red_approved", False) and has_valid_approach:
                    return "EXECUTE_BUG", "Blue đã approve — thực thi exploit."
                if blue_intent == "APPROVE" and not has_valid_approach:
                    return "RETRY_RED", "Blue approve nhưng không có strategy Red hợp lệ. Yêu cầu Red viết lại."
                if blue_intent == "STOP":
                    stop_reason = last_blue[:400]
                    return "STOP_BUG", f"Blue kết luận nên dừng bug. Lý do: {stop_reason}"
                if blue_intent == "REVISE":
                    rejection_reason = last_blue[:400]
                    return "DEBATE_RED", f"Blue reject. Lý do: {rejection_reason}"

        if state_context.get("last_action") in ("DEBATE_RED", "RETRY_RED"):
            last_red = _get_last_red_content(conversation)
            if _is_agent_failure_response(last_red):
                if state_context.get("red_attempts", 0) >= 2:
                    return "NEXT_BUG", "Red lỗi/rỗng quá số lần cho phép. Dừng candidate hiện tại."
                return "RETRY_RED", "Red trả response rỗng/lỗi. Gọi Red lại."
            if _is_valid_red_approach(last_red):
                return "DEBATE_BLUE", "Red đã viết strategy/shot plan hợp lệ. Chuyển Blue review trước khi Exec."

        # ── Handle connection errors: Manager decides retry or stop ──
        last_action = state_context.get("last_action", "")
        last_exec = getattr(self, "_last_exec_result", None) or ""

        # Check if last agent call had connection error
        conn_error_in_conv = any(
            "[LLM Error:" in m.get("content", "") or
            "[API Error" in m.get("content", "")
            for m in conversation[-6:]
        )
        # Connection error after Red/Blue → RETRY (Manager decides to retry)
        if conn_error_in_conv and last_action in ("DEBATE_RED", "DEBATE_BLUE", "RETRY_RED", "RETRY_BLUE"):
            bug_id = state_context.get("current_bug_id", "?")
            bug_label = _bug_label(bug_id)
            if last_action in ("DEBATE_RED", "RETRY_RED"):
                return "RETRY_RED", f"Connection error khi Red chạy {bug_label}. Retry Red."
            if last_action in ("DEBATE_BLUE", "RETRY_BLUE"):
                return "RETRY_BLUE", f"Connection error khi Blue review {bug_label}. Retry Blue."

        # ── Handle exec outcome (Manager evaluates result) ──
        if last_action in ("EXECUTE_BUG", "RETRY_EXEC"):
            if not last_exec:
                return "STOP_BUG", "Exec không có kết quả. STOP bug."

            bug_id = state_context.get("current_bug_id", "?")
            bug_label = _bug_label(bug_id)
            retry_count = state_context.get("exec_retry_count", 0)
            current_bug = state_context.get("current_bug") or {}
            decision = self._exec_decision(last_exec, current_bug)
            status = str(current_bug.get("exec_result_status") or decision.get("status", "")).upper()
            reason = truncate(str(current_bug.get("exec_result_reason") or decision.get("reason", "")), 220)

            if status == "EXPLOITED":
                return "NEXT_BUG", f"Exec {bug_label} tự verify EXPLOITED. {reason}"
            if status == "SCRIPT_ERROR":
                if retry_count < 1:
                    return "RETRY_EXEC", f"Exec {bug_label} lỗi script/runtime. Retry Exec một lần. {reason}"
                return "STOP_BUG", f"Exec {bug_label} vẫn lỗi script sau retry. STOP bug."
            if status == "PARTIAL":
                if retry_count < 1:
                    return "RETRY_EXEC", f"Exec {bug_label} PARTIAL. Retry Exec một lần để chốt evidence. {reason}"
                return "STOP_BUG", f"Exec {bug_label} vẫn PARTIAL sau retry. STOP bug để tránh overfitting."
            return "STOP_BUG", f"Exec {bug_label} FAILED/NO_SIGNAL. {reason}"

        # ── Shortcut: first tick → always start with DEBATE_RED ──
        if state_context.get("tick", 0) == 0:
            bug_id = state_context.get("current_bug_id", "?")
            return "DEBATE_RED", f"Bug đầu tiên ({bug_id}) — Red hãy đề xuất approach."

        if (
            state_context.get("last_action") == "NEXT_BUG"
            and not state_context.get("has_workflow", False)
        ):
            bug_id = state_context.get("current_bug_id", "?")
            return "DEBATE_RED", f"Bug mới ({bug_id}) — Red phải viết strategy riêng cho candidate này."

        # ── Shortcut: 2 red_attempts with no approval → mark STOPPED ──
        if (state_context.get("red_attempts", 0) >= 2 and
                not state_context.get("red_approved", False)):
            return "NEXT_BUG", "2 lần Red mà không có strategy hợp lệ — mark STOPPED, next bug."

        # ── Shortcut: all bugs processed ──
        current_idx = state_context.get("current_bug_index", 0)
        total = state_context.get("total_bugs", 0)
        if current_idx >= total:
            # Check if any bugs were exploitable
            return "NEXT_BUG", "Đã xử lý hết bugs."

        non_summary_msgs = [
            m for m in conversation
            if not m.get("content", "").startswith("[CONTEXT SUMMARY")
        ]
        recent_msgs = non_summary_msgs[-10:] if len(non_summary_msgs) > 10 else non_summary_msgs
        conv_text = "\n".join(
            f"[{m['speaker']}]: {truncate(m['content'], 600)}"
            for m in recent_msgs
        )

        mem_ctx = self.ctx_mgr.get_context_for_agent(
            agent_id="manager",
            conversation=conversation,
            keywords=["bug", "approach", "approved", "exploit", "poc"],
        )
        current_bug_dossier = self._format_current_bug_dossier(state_context.get("current_bug") or {})

        user_msg = (
            f"=== TRẠNG THÁI HIỆN TẠI ===\n"
            f"Tick: {state_context['tick']} / {MAX_TICKS}\n"
            f"Bug: {state_context['current_bug_index'] + 1} / {state_context['total_bugs']} "
            f"({state_context.get('current_bug_id', '?')})\n"
            f"Red attempts: {state_context['red_attempts']} / 2 | Strategy ready: {state_context['red_approved']}\n"
            f"Bugs processed: {state_context['bugs_processed_count']}\n"
            f"Last action: {state_context['last_action'] or '(none)'}\n\n"
            f"=== BUG DOSSIER HIỆN TẠI ===\n{current_bug_dossier}\n\n"
            + (f"=== MEMORY CONTEXT ===\n{mem_ctx}\n\n" if mem_ctx else "")
            + f"=== LỊCH SỬ HỘI THOẠI GẦN NHẤT ===\n"
            f"{conv_text}\n\n"
            f"Bạn là Manager. Phân tích kết quả, ưu tiên hot path Red -> Blue review -> Exec self-verify.\n"
            f"Nhớ: emit đúng 1 action tag [ACTION: XXX] ở cuối."
        )

        messages = [
            {"role": "system", "content": self.system_prompt.replace(
                "{state_context_display}",
                f"=== TRẠNG THÁI HIỆN TẠI ===\n"
                f"Tick: {state_context['tick']} / {MAX_TICKS}\n"
                f"Bug: {state_context['current_bug_index'] + 1} / {state_context['total_bugs']} "
                f"({state_context.get('current_bug_id', '?')})\n"
                f"Red attempts: {state_context['red_attempts']} / 2 | Strategy ready: {state_context['red_approved']}\n"
                f"Bugs processed: {state_context['bugs_processed_count']}\n"
                f"Last action: {state_context['last_action'] or '(none)'}\n"
                f"Exec last result: {getattr(self, '_last_exec_result', None) or '(none)'}\n\n"
                f"=== BUG DOSSIER HIỆN TẠI ===\n{current_bug_dossier}"
            )},
            {"role": "user",   "content": user_msg},
        ]

        try:
            resp = self.client.chat.completions.create(
                model       = self.model,
                messages    = messages,
                temperature = 0.2,
                max_tokens  = 512,
            )
            text = resp.choices[0].message.content or ""
        except Exception as e:
            print(f"{Y}[!] Manager LLM error: {e} — fallback logic{RST}")
            text = ""

        action = self._extract_action(text, state_context)
        note_match = NOTE_PATTERN.search(text)
        note = note_match.group(1).strip() if note_match else ""

        return action, note

    def _extract_action(self, text: str, state_context: dict) -> str:
        """Đọc [ACTION: XXX] từ Manager LLM response.

        Fallback deterministic dựa trên state per-bug.
        """
        match = ACTION_PATTERN.search(text)
        if match:
            return match.group(1).upper()

        # Fallback deterministic
        red_approved = state_context.get("red_approved", False)
        red_attempts = state_context.get("red_attempts", 0)
        last_action = state_context.get("last_action", "")

        if last_action == "":
            return "DEBATE_RED"
        if last_action in ("DEBATE_RED", "RETRY_RED"):
            return "DEBATE_BLUE"
        if last_action == "DEBATE_BLUE":
            if red_approved:
                return "EXECUTE_BUG"
            if red_attempts >= 2:
                return "NEXT_BUG"
            return "DEBATE_RED"
        if last_action in ("EXECUTE_BUG", "RETRY_EXEC"):
            return "NEXT_BUG"
        return "DEBATE_RED"

    def _persist_new_messages(self, conversation: list[dict], start_idx: int) -> None:
        """Ghi tất cả message mới phát sinh trong tick vào full log."""
        if start_idx >= len(conversation):
            return
        for msg in conversation[start_idx:]:
            if not msg.get("content", "").startswith("[CONTEXT SUMMARY"):
                self.memory.append_message(msg)

    def _install_signal_handlers(self) -> dict[int, object]:
        """Bắt SIGINT/SIGTERM để vẫn ghi được report khi pipeline bị dừng."""
        handled: dict[int, object] = {}

        def _raise_interrupt(signum, _frame):
            raise KeyboardInterrupt(f"Nhận signal {signum}")

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                handled[sig] = signal.getsignal(sig)
                signal.signal(sig, _raise_interrupt)
            except Exception:
                continue
        return handled

    def _restore_signal_handlers(self, handlers: dict[int, object]) -> None:
        for sig, handler in handlers.items():
            try:
                signal.signal(sig, handler)
            except Exception:
                continue

    def _update_report_state(self, **kwargs) -> None:
        for key, value in kwargs.items():
            if value is not None and key in self._report_state:
                self._report_state[key] = value

    def _save_report_checkpoint(self) -> None:
        report_path = Path(self.run_dir) / "report.md"
        report_path.write_text(self._build_report_md(**self._report_state), encoding="utf-8")

    # ══════════════════════════════════════════════════════════
    # INTERNAL — Report writer
    # ══════════════════════════════════════════════════════════

    def _build_report_md(
        self,
        verdict: str,
        workflow: str,
        exec_report: str,
        red_evaluation: str,
        debate_rounds: int,
    ) -> str:
        icon = {
            "SUCCESS": "✅",
            "FAIL": "❌",
            "PENDING": "⏳",
            "INTERRUPTED": "⚠️",
        }.get(verdict, "ℹ️")
        remediation = (
            "N/A — pipeline chưa xác nhận được lỗ hổng cụ thể."
            if verdict != "SUCCESS"
            else (
                "- Enforce server-side authorization on every sensitive endpoint.\n"
                "- Validate business rules server-side; never trust client-controlled price, quantity, role, userId, or workflow state.\n"
                "- Bind CSRF/session checks to authenticated user and intended action.\n"
                "- Add regression tests for the reproduced BAC/BLF path."
            )
        )
        return f"""# MARL Penetration Test Report
**Target:** {self.target_url}
**Verdict:** {icon} {verdict}
**Debate rounds:** {debate_rounds}

## Executive Summary
Pipeline verdict: **{verdict}**. Evidence below is copied from the execution/evaluation phases and should be treated as the source of truth.

## Approved Attack Workflow
{workflow or "N/A"}

## Execution Report
```
{exec_report or "N/A"}
```

## Red Team Evaluation
{red_evaluation or "N/A"}

## Impact
{("Confirmed BAC/BLF impact based on the execution evidence above." if verdict == "SUCCESS" else "No confirmed business impact. Review execution output for blockers and partial evidence.")}

## Remediation
{remediation}

## Evidence Handling
- Raw recon artifacts are in `recon.md`, `crawl_data.txt`, and `crawl_raw.json` when available.
- Full conversation and task memory are in `memory/` for this run.
"""
