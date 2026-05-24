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
from shared.auth_context import (
    bearer_token_from_session,
    cookie_header_from_cookie_objects,
    load_auth_context,
    session_has_auth_material,
)
from shared.logger import log
from agents.policy_agent import PolicyAgent
from knowledge.bac_blf_playbook import get_playbook_text

# ── Env / Connection ─────────────────────────────────────────
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "gho_token")
SERVER_URL   = os.environ.get("MARL_SERVER_URL", "http://127.0.0.1:5000/v1")
MODEL        = os.environ.get("MARL_MANAGER_MODEL", "ollama/gemma4:31b-cloud")

# ── Guardrail constants ──────────────────────────────────────
MAX_ROUNDS        = 2    # số vòng strategy revision tối đa
MIN_DEBATE_ROUNDS = 0    # deterministic state machine handles Red -> Blue gating
MAX_EXEC_RETRIES  = 1    # retry Exec tối đa 1 lần để tránh loop phức tạp
MAX_TICKS         = 60   # base ticks (sẽ tính dynamic theo số bugs trong __init__)
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

AUTH_BLOCK_STATUSES = {"BLOCKED_AUTH", "AUTH_BLOCKED"}
NON_EXPLOITED_STATUSES = {"NOT_EXPLOITED", "OOS_SCOPE", "SKIPPED_DUPLICATE", *AUTH_BLOCK_STATUSES}

MANAGER_PROMPT = """\
Ban la MANAGER — Lead chuyen gia BAC/BLF dieu phoi pipeline pentest.
Ban co kien thuc sau ve Broken Access Control va Business Logic Flaw.
Ban khong truc tiep khai thac. Ban DIEU PHOI va PHAN TICH ket qua tu cac agent con.

=== VAI TRO CUA BAN ===
- Ban la "Sep" thong thai: HIEU tai sao exploit thanh cong hay that bai.
- Khi Exec fail, ban PHAN TICH nguyen nhan TRUOC khi quyet dinh buoc tiep theo.
- Ban co the yeu cau Red VIET LAI strategy dua tren phan tich cua ban.
- Ban KHONG bao gio stop bug ma khong hieu tai sao no fail.

=== KIEN THUC BAC/BLF ===
{playbook_summary}

=== TARGET ===
{target_url}

=== BUGS ===
{risk_bugs_summary}

=== RECON ===
{recon_summary}

=== STATE ===
{state_context_display}

=== KHUNG PHAN TICH THAT BAI ===
Khi Exec that bai, ban PHAI phan tich theo 4 nguyen nhan:
1. RECON_GAP: Thieu du lieu recon (chua login, thieu endpoint, thieu form fields)
   → Giai phap: yeu cau bo sung recon hoac chi dan Red dua tren du lieu hien co
2. STRATEGY_GAP: Red viet strategy sai (sai endpoint, sai logic, sai hypothesis)
   → Giai phap: RETRY_RED voi feedback cu the tu phan tich cua ban
3. TARGETING_GAP: Exec nham resource ID, sai URL, sai params
   → Giai phap: RETRY_EXEC hoac RETRY_RED voi chi dan ID/URL dung
4. NOT_VULNERABLE: Endpoint thuc su khong co loi -> dung bug
   → Giai phap: STOP_BUG voi ly do cu the

=== HOT PATH ===
1. DEBATE_RED: Red viet strategy ngan + execution shot plan cho dung 1 bug.
2. DEBATE_BLUE: Blue review strategy/shot plan truoc khi thuc thi.
3. EXECUTE_BUG: Exec chay bounded script shots va luu raw request/response/artifacts.
4. Manager doc Exec verdict/evidence va PHAN TICH: EXPLOITED / retry / stop.
5. EXPLOITED -> NEXT_BUG. SCRIPT_ERROR -> RETRY_EXEC. FAILED -> PHAN TICH -> quyet dinh.

=== ACTIONS ===
[ACTION: DEBATE_RED]     — Viet strategy ngan cho bug hien tai.
[ACTION: EXECUTE_BUG]    — Chay Python exploit self-verify cho strategy da co.
[ACTION: RETRY_RED]      — Sua strategy khi endpoint/verify sai. KEM THEO LY DO FAIL.
[ACTION: RETRY_EXEC]     — Chay lai Exec khi loi runtime/script hoac evidence thieu nhung strategy dung.
[ACTION: STOP_BUG]       — Dung bug hien tai SAU KHI DA PHAN TICH nguyen nhan.
[ACTION: NEXT_BUG]       — Chuyen bug tiep theo.
[ACTION: REPORT_SUCCESS] — Viet report co finding validated.
[ACTION: REPORT_FAIL]    — Viet report khong co finding validated.
[ACTION: DEBATE_BLUE]    — Blue review strategy/shot plan cua Red truoc Exec.
[ACTION: RETRY_BLUE]     — Goi lai Blue khi response loi/rong.

=== RULES ===
- Sau Red strategy hop le, phai DEBATE_BLUE truoc khi EXECUTE_BUG.
- Chi EXECUTE_BUG khi co current workflow va Blue da approve.
- Exec script tu verify va in FINAL/SUCCESS. Manager doc verdict/evidence de quyet dinh.
- Auth context co the la cookie, Playwright storage_state, hoac localStorage/JWT token.
  Neu Auth context da co, dung no de mo rong recon/Exec, khong coi bug auth_required la blocked chi vi khong co HTTP form login.
- Proof gate bat buoc truoc khi chap nhan EXPLOITED:
  * BAC-01/admin: phai thay control/admin API quyen cao that, khong chi status 200/admin marker/challenge metadata.
  * BAC-02/privilege escalation: phai chung minh cookie/role tamper DAN TOI truy cap admin/privileged resources. Day la vertical escalation, KHONG phai IDOR.
  * BAC-03/IDOR: phai chung minh object ownership bypass/cross-user access. Public list leak UserId/comment chi la INFO_EXPOSURE_ONLY.
  * BAC-04+/method bypass: phai chung minh unauthorized action execution hoac admin access qua method switching/override.
  * BLF/stateful: phai co before/after state, non-zero delta, hoac invalid state transition da verify.
- PROOF_QUALITY_FAIL: cho retry 1 lan voi huong dan cu the truoc khi STOP. Script error cho retry 2 lan.
- Khi script Exec bao EXPLOITED (FINAL: EXPLOITED, verdict=YES), tin tuong script — KHONG override boi heuristic (WRONG_TARGET, etc.).
- Khi Exec FAILED/PARTIAL: PHAN TICH nguyen nhan TRUOC. Neu la STRATEGY_GAP → RETRY_RED. Neu NOT_VULNERABLE → STOP_BUG.
- Neu Exec loi syntax/runtime/script, uu tien RETRY_EXEC de Exec tu sua script.
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
    """Classify an Exec attempt for Manager's attempt ledger.

    Priority order:
      1. Runtime/syntax error → RUNTIME_ERROR
      2. Explicit FINAL marker (EXPLOITED/FAILED/PARTIAL) → trust the script
      3. Heuristic proof markers (only when script is ambiguous)
    """
    output = _extract_exec_output(exec_result) or exec_result
    lower = output.lower()
    result_lower = str(exec_result or "").lower()
    status_hits = _extract_exec_status_hits(exec_result)
    success_verdict = _exec_success_verdict(exec_result)
    final_marker = _exec_final_marker(exec_result)
    digest = hashlib.sha256(str(exec_result or "").encode("utf-8", errors="ignore")).hexdigest()[:16]

    # ── Proof markers: chỉ giữ những từ khóa đặc trưng, loại bỏ generic ──
    proof_markers = (
        "admin dashboard", "admin panel", "privileged",
        "different user", "other user", "another user", "not owner",
        "idor vulnerability confirmed", "leaked", "api key",
        "balance changed", "balance increased", "balance decreased",
        "price changed", "quantity changed",
        "shot_result: exploited",
    )
    # ── Negative markers: chỉ ra script THỰC SỰ fail, chặn false positive ──
    negative_markers = (
        "missing data", "could not", "cannot", "not found",
        "balance=none", "balance_extracted=false",
        "no admin marker", "no marker found", "no unauthorized",
        "same or missing", "same as current",
        "failed to get", "did not increase", "did not change",
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
    all_404 = bool(status_hits) and all(hit["status"] == "404" for hit in status_hits)
    has_marker = any(marker in lower for marker in proof_markers)
    has_negative = any(marker in lower for marker in negative_markers)
    runtime_error = any(marker in result_lower or marker in lower for marker in error_markers)
    explicit_failed = final_marker == "FAILED" or success_verdict == "NO"
    partial = final_marker == "PARTIAL" or success_verdict == "PARTIAL"
    candidate_success = success_verdict == "YES" or final_marker == "EXPLOITED"

    # ── Classification logic: script's own verdict wins ──
    if runtime_error:
        signal = "RUNTIME_ERROR"
    elif all_404:
        signal = "WRONG_TARGET"
    elif contradiction:
        signal = "CONTRADICTION"
    elif candidate_success and has_marker and not has_negative:
        signal = "PROOF_CANDIDATE"
    elif explicit_failed:
        # Script nói FAILED → tôn trọng, KHÔNG override bởi heuristic
        signal = "NO_SIGNAL"
    elif has_2xx and has_marker and not has_negative and not explicit_failed:
        signal = "NEW_LEAD"
    elif partial:
        signal = "PARTIAL"
    elif has_only_negative_status:
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
    # Accept EXECUTION GUIDE (new format) OR EXECUTION SHOT PLAN (legacy)
    has_plan = (
        "=== execution guide ===" in lower
        or "execution guide" in lower
        or "=== execution shot plan ===" in lower
    )
    return has_strategy and has_plan


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
                log.debug(f"[MANAGER] Loaded {len(self.risk_bugs)} bugs from risk-bug.json")
            except Exception as e:
                log.debug(f"[MANAGER] Could not load risk-bug.json: {e}")

        # Build risk_bugs_summary for manager prompt
        if self.risk_bugs:
            lines = []
            for b in self.risk_bugs:
                lines.append(self._format_bug_summary_line(b))
            risk_bugs_summary = "\n".join(lines)
        else:
            risk_bugs_summary = "(chua co bug nao — VulnHunter chua chay)"

        # Build compact playbook summary for Manager (shorter than full playbook)
        playbook_summary = self._build_playbook_summary()

        self.client = OpenAI(api_key=GITHUB_TOKEN, base_url=SERVER_URL)
        self.system_prompt = MANAGER_PROMPT.format(
            target_url         = target_url,
            recon_summary      = truncate(recon_content, 4000),
            risk_bugs_summary  = risk_bugs_summary,
            playbook_summary   = playbook_summary,
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
        self.auth_context_summary = self._auth_context_summary()
        self.has_authenticated_context = self._has_authenticated_context()
        if self.auth_context_summary:
            self.memory.add_finding("auth", "auth_context", self.auth_context_summary, agent="crawl")
        self._report_state = {
            "verdict": "PENDING",
            "workflow": "",
            "exec_report": "",
            "red_evaluation": "",
            "debate_rounds": 0,
        }
        # Track tested endpoint+pattern combos to detect duplicate bugs
        self._tested_endpoints: set[str] = set()

        # Dynamic tick budget: 8 ticks per bug, minimum 60
        self._max_ticks = max(MAX_TICKS, len(self.risk_bugs) * 8)

    @staticmethod
    def _compact_list(values: list[str], limit: int = 5) -> str:
        cleaned = [str(v).strip() for v in values if str(v).strip()]
        if not cleaned:
            return "-"
        return ", ".join(cleaned[:limit])

    @staticmethod
    def _build_playbook_summary() -> str:
        """Build compact BAC/BLF pattern summary for Manager prompt.

        Shorter than full playbook — only IDs, names, key indicators, and success criteria.
        """
        from knowledge.bac_blf_playbook import BAC_PATTERNS, BLF_PATTERNS
        lines = ["BAC Patterns:"]
        for p in BAC_PATTERNS:
            indicators_short = "; ".join(ind[:60] for ind in p["indicators"][:2])
            lines.append(f"  {p['id']}: {p['name']} [{p['severity']}] — {indicators_short}")
        lines.append("BLF Patterns:")
        for p in BLF_PATTERNS:
            indicators_short = "; ".join(ind[:60] for ind in p["indicators"][:2])
            lines.append(f"  {p['id']}: {p['name']} [{p['severity']}] — {indicators_short}")
        return "\n".join(lines)

    def _diagnose_failure(
        self,
        current_bug: dict,
        exec_result: str,
        exec_status: str,
        retry_count: int,
    ) -> tuple[str, str]:
        """Phân tích nguyên nhân Exec fail — intelligent diagnosis.

        Key intelligence:
        - Detect "all probes same status" = server whitelist → STOP immediately
        - Detect duplicate endpoint already tested → STOP
        - Detect auth problem + check if auth available now → suggest auth fix
        - Count negative probes: 10+ all negative → STOP (not vulnerable)

        Returns:
            (action, diagnosis_note): action để _decide routing, note chứa phân tích.
        """
        bug_id = current_bug.get("id", "?")
        bug_label = _bug_label(bug_id)
        evidence = _summarize_exec_output(exec_result, max_lines=12)
        hypothesis = current_bug.get("hypothesis", "")
        pattern_id = current_bug.get("pattern_id", "")
        endpoint = current_bug.get("endpoint", "")
        method = current_bug.get("method", "")
        auth_required = current_bug.get("auth_required", False)
        exec_reason = current_bug.get("exec_result_reason", "")

        lower_evidence = evidence.lower()
        lower_reason = (exec_reason or "").lower()

        # ── Intelligence 1: Detect "all probes same error" pattern ──
        # If exec ran multiple probes and ALL returned same error status → server is clearly blocking
        import re as _re
        status_pattern = _re.findall(r'status[=:]\s*(\d{3})', lower_evidence)
        if len(status_pattern) >= 5:
            unique_statuses = set(status_pattern)
            if len(unique_statuses) == 1 and unique_statuses.pop() in ('400', '401', '403', '500'):
                return "STOP_BUG", (
                    f"[PHÂN TÍCH] {bug_label}: INTELLIGENT_STOP — "
                    f"Exec đã chạy {len(status_pattern)} probes, TẤT CẢ trả cùng status. "
                    f"Server rõ ràng validate/whitelist fields cho endpoint {endpoint}. "
                    f"Kết luận: NOT_VULNERABLE — tiếp tục retry là vô ích."
                )

        # ── Intelligence 2: Detect "no admin marker" mass-assignment dead end ──
        no_marker_count = lower_evidence.count("no admin marker") + lower_evidence.count("no field")
        if no_marker_count >= 3:
            return "STOP_BUG", (
                f"[PHÂN TÍCH] {bug_label}: INTELLIGENT_STOP — "
                f"Exec đã thử {no_marker_count}+ probe variants cho mass-assignment trên {endpoint}, "
                f"tất cả đều bị server ignore/override. "
                f"Kết luận: Endpoint này KHÔNG có lỗ hổng mass-assignment."
            )

        # ── Intelligence 3: Check for duplicate endpoint already tested ──
        if hasattr(self, '_tested_endpoints'):
            endpoint_key = f"{method}:{endpoint}:{pattern_id}"
            if endpoint_key in self._tested_endpoints:
                return "STOP_BUG", (
                    f"[PHÂN TÍCH] {bug_label}: DUPLICATE_SKIP — "
                    f"Endpoint {method} {endpoint} với pattern {pattern_id} đã được test "
                    f"bởi bug trước và fail. Không cần test lại."
                )

        # ── Deterministic diagnosis (fast, no LLM) ──

        # 1. WRONG_TARGET / 404
        if exec_status == "WRONG_TARGET" or lower_evidence.count("404") >= 3:
            if retry_count < 1:
                return "RETRY_RED", (
                    f"[PHÂN TÍCH] {bug_label} thất bại do TARGETING_GAP: "
                    f"Tất cả request trả 404 — endpoint {endpoint} hoặc resource ID không tồn tại. "
                    f"Red cần kiểm tra lại recon.md để chọn endpoint/ID thực tế có trong hệ thống."
                )
            return "STOP_BUG", (
                f"[PHÂN TÍCH] {bug_label}: Đã retry nhưng endpoint {endpoint} vẫn 404. "
                f"Kết luận: NOT_VULNERABLE — endpoint không tồn tại trên target."
            )

        # 2. Auth required nhưng không có session — check if auth available NOW
        if auth_required and ("401" in lower_evidence or "403" in lower_evidence):
            # Re-check auth context (may have been created by Exec for earlier bug)
            self.has_authenticated_context = self._has_authenticated_context()
            self.auth_context_summary = self._auth_context_summary()
            if self.has_authenticated_context:
                if retry_count < 1:
                    return "RETRY_EXEC", (
                        f"[PHÂN TÍCH] {bug_label}: AUTH_NOW_AVAILABLE — "
                        f"Bug gặp 401/403 nhưng auth_context.json giờ đã có session (từ Exec trước). "
                        f"Retry Exec để sử dụng session mới."
                    )
            return "STOP_BUG", (
                f"[PHÂN TÍCH] {bug_label}: BLOCKED_AUTH — bug yêu cầu authenticated session "
                f"nhưng Exec/recon không có session hợp lệ (401/403). Dừng candidate."
            )

        # 3. Metadata-only evidence
        if "metadata_only_proof" in lower_evidence or "challenge metadata" in lower_evidence:
            return "STOP_BUG", (
                f"[PHÂN TÍCH] {bug_label}: METADATA_ONLY_PROOF — evidence chỉ đến từ "
                f"metadata/challenge text, không chứng minh được endpoint/chức năng BAC/BLF thực tế."
            )

        if exec_status in {"INFO_EXPOSURE_ONLY"}:
            return "STOP_BUG", (
                f"[PHÂN TÍCH] {bug_label}: {exec_status} — "
                f"{truncate(exec_reason or evidence, 420)}"
            )

        # PROOF_QUALITY_FAIL: cho retry 1 lần với hướng dẫn cụ thể thay vì STOP ngay
        if exec_status == "PROOF_QUALITY_FAIL":
            if retry_count < 1:
                return "RETRY_RED", (
                    f"[PHÂN TÍCH] {bug_label}: PROOF_QUALITY_FAIL — evidence chưa đủ mạnh. "
                    f"Red hãy thiết kế strategy MỚI tập trung vào lấy BẰNG CHỨNG CỤ THỂ: "
                    f"admin marker, before/after delta, hoặc cross-user access proof. "
                    f"Reason: {truncate(exec_reason or evidence, 300)}"
                )
            return "STOP_BUG", (
                f"[PHÂN TÍCH] {bug_label}: {exec_status} — "
                f"{truncate(exec_reason or evidence, 420)}"
            )

        # 4. Script ran OK nhưng evidence không match hypothesis
        if exec_status == "FAILED" and ("not found" in lower_evidence or "missing" in lower_evidence):
            if retry_count < 1:
                return "RETRY_RED", (
                    f"[PHÂN TÍCH] {bug_label} thất bại do STRATEGY_GAP: "
                    f"Script chạy OK nhưng evidence không khớp hypothesis '{truncate(hypothesis, 100)}'. "
                    f"Red cần xem lại recon và đề xuất approach KHÁC BIỆT HOÀN TOÀN cho pattern {pattern_id}. "
                    f"KHÔNG được lặp lại approach cũ với cùng endpoint."
                )
            return "STOP_BUG", (
                f"[PHÂN TÍCH] {bug_label}: Strategy đã retry nhưng vẫn fail. "
                f"Kết luận: NOT_VULNERABLE — endpoint {endpoint} không có lỗ hổng {pattern_id}."
            )

        # 5. SCRIPT_ERROR — cho phép 2 lần retry (syntax error là lỗi kỹ thuật, không phải exploit fail)
        if exec_status == "SCRIPT_ERROR":
            if retry_count < 2:
                return "RETRY_EXEC", (
                    f"[PHÂN TÍCH] {bug_label}: Lỗi script/runtime (lần {retry_count + 1}) — "
                    f"Exec cần sửa code và chạy lại."
                )
            return "STOP_BUG", (
                f"[PHÂN TÍCH] {bug_label}: Script vẫn lỗi sau 2 lần retry. STOP bug."
            )

        # 6. PARTIAL — kiểm tra có tín hiệu thực sự hay chỉ là "partial vì retry hết"
        if exec_status == "PARTIAL":
            # Intelligence: nếu evidence chứa "all probes negative" / "no marker" → treat as FAILED
            if ("all probe" in lower_evidence and "negative" in lower_evidence) \
                    or "server likely validates" in lower_evidence \
                    or "server whitelists" in lower_evidence:
                return "STOP_BUG", (
                    f"[PHÂN TÍCH] {bug_label}: PARTIAL nhưng TẤT CẢ probes negative — "
                    f"thực chất là NOT_VULNERABLE. Server rõ ràng chặn approach này. Dừng bug."
                )
            if retry_count < 1:
                return "RETRY_EXEC", (
                    f"[PHÂN TÍCH] {bug_label}: PARTIAL — có tín hiệu nhưng chưa đủ evidence. "
                    f"Exec retry 1 lần để chốt."
                )
            return "STOP_BUG", (
                f"[PHÂN TÍCH] {bug_label}: PARTIAL sau nhiều lần thử. Dừng bug."
            )

        # 7. Default FAILED
        if retry_count < 1:
            return "RETRY_RED", (
                f"[PHÂN TÍCH] {bug_label} FAILED. Manager yêu cầu Red phân tích lại: "
                f"Evidence cho thấy: '{truncate(evidence, 150)}'. "
                f"Red hãy đổi approach HOÀN TOÀN KHÁC cho pattern {pattern_id} trên endpoint {method} {endpoint}. "
                f"KHÔNG lặp lại cùng mass-assignment/probe approach nếu đã thất bại."
            )

        return "STOP_BUG", (
            f"[PHÂN TÍCH] {bug_label}: Đã thử nhiều hướng, endpoint {endpoint} "
            f"không có lỗ hổng {pattern_id}. NOT_VULNERABLE."
        )

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
            f"Authenticated recon available: {self.has_authenticated_context}\n"
            f"Auth context summary: {truncate(self.auth_context_summary or '-', 260)}\n"
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

        log.phase_banner(2, "KHAI THÁC", f"Pipeline xử lý {len(self.risk_bugs)} bug candidates")
        log.bug_table(self.risk_bugs)

        # Nếu không có bug nào → REPORT_FAIL ngay
        if not self.risk_bugs:
            log.error("Không có bug nào trong risk-bug.json — REPORT_FAIL")
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

        # ── Phase 0: CONTEXT REVIEW — Orchestrator đánh giá state trước dispatch ──
        ctx = self._phase0_context_review()
        log.phase_banner(0, "CONTEXT REVIEW", "Orchestrator đánh giá điều kiện trước khi dispatch")
        log.info(f"Recon quality: {ctx['recon_quality']} ({ctx['endpoint_count']} endpoints)")
        log.info(f"Auth status: {ctx['auth_status']}")
        log.info(f"Bugs: {ctx['total_bugs']} total, {ctx['anon_bugs']} anonymous, {ctx['auth_bugs']} auth-required")
        log.info(f"Recommendation: {ctx['recommendation']}")

        if ctx["recommendation"] == "exec_login_first":
            log.info("→ Thử giao Exec login/register trước khi chạy per-bug pipeline")
            self._ensure_auth_or_skip(exec_agent, conversation)

        # Sort bugs: anonymous first, then auth-required
        # This maximizes chance of getting auth context from exec before auth-required bugs
        self._sort_bugs_by_auth_priority()

        old_handlers = self._install_signal_handlers()

        try:
            self._run_loop(red, exec_agent, conversation)
        except RuntimeError as e:
            log.error(f"ManageAgent: {e}")
            self._write_report_fail(f"Pipeline kết thúc do lỗi: {e}")
        except KeyboardInterrupt as e:
            log.warn(f"ManageAgent bị ngắt: {e}")
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

        for tick in range(self._max_ticks):
            tick_start_len = len(conversation)

            preflight_result = self._preflight_current_bug(
                conversation, current_bug, current_bug_index, bugs_processed_count,
                red, exec_agent,
            )
            if preflight_result == "CONTINUE":
                bugs_processed_count += 1
                current_bug_index = self.current_bug_index
                current_bug = self.risk_bugs[current_bug_index]
                red_approved = False
                red_attempts = 0
                exec_retry_count = 0
                current_approach = ""
                blue = None
                self._last_action = "NEXT_BUG"
                continue
            if preflight_result in ("REPORT_SUCCESS", "REPORT_FAIL"):
                return

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

            # Bug header khi bắt đầu bug mới
            if tick == 0 or getattr(self, '_last_action', '') == 'NEXT_BUG':
                log.bug_header(current_bug_index + 1, len(self.risk_bugs), current_bug)

            action, note = self._decide(conversation, state_context)

            verdict = self.policy.validate(action, state_context, conversation)
            if verdict is not None and verdict.verdict == "BLOCK":
                consecutive_blocks = getattr(self, "_consecutive_blocks", 0) + 1
                self._consecutive_blocks = consecutive_blocks
                log.policy_log(tick, "BLOCK", action, verdict.reason[:100])
                if consecutive_blocks >= 3:
                    if not red_approved:
                        action = "DEBATE_RED"
                    else:
                        action = "EXECUTE_BUG"
                    log.debug(f"[RECOVERY] {consecutive_blocks} BLOCKs → force {action}")
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
                log.policy_log(tick, "SUGGEST", action, f"→ '{verdict.suggested_action}': {verdict.reason[:80]}")
                action = verdict.suggested_action
                note = f"Policy điều chỉnh: {verdict.reason}"

            self._last_action = action
            self._consecutive_blocks = 0

            # Manager decision — terminal + log
            log.manager_decision(tick, action, current_bug.get('id', '?'), note)
            log.manager_tick_state(tick, current_bug_index, len(self.risk_bugs),
                                   current_bug.get('id', '?'), red_attempts, red_approved)

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
                log.debug(f"[RED TEAM] Bug {current_bug_index + 1}/{len(self.risk_bugs)}")
                red.set_current_bug(current_bug)
                response = red.respond(conversation)

                if response.startswith("[LLM Error:"):
                    log.red_brief(response, is_valid=False)
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
                    is_valid = _is_valid_red_approach(response)
                    log.red_brief(response, is_valid=is_valid)
                    if is_valid:
                        current_approach = _strip_tag_display(response)
                        red_approved = False
                        exec_retry_count = 0
                        self._record_strategy(
                            current_bug,
                            current_approach,
                            "PENDING_BLUE_REVIEW: Red strategy captured; Blue must approve before Exec.",
                        )
                        log.debug("[MANAGER] Red strategy captured — sending to Blue review")

            # DEBATE_BLUE
            elif action == "DEBATE_BLUE":
                if blue is None:
                    blue = BlueTeamAgent(
                        target_url    = self.target_url,
                        recon_context = self.recon_content,
                        memory_store  = self.memory,
                    )
                log.debug(f"[BLUE TEAM] Review")
                blue.set_current_bug(current_bug)
                response = blue.respond(conversation)

                if response.startswith("[LLM Error:"):
                    log.blue_brief(response, "ERROR")
                else:
                    blue_intent_preview = _infer_dialog_intent("BLUETEAM", response)
                    log.blue_brief(response, blue_intent_preview)

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
                        log.debug("[MANAGER] Blue APPROVED — approach recorded")
                elif blue_intent_raw == "REVISE":
                    red_approved = False
                    current_approach = ""
                    red_attempts += 1
                    log.debug(f"[MANAGER] Blue REJECTED — red_attempts={red_attempts}/2")
                    if red_attempts >= 2:
                        log.warn(f"2× bị từ chối — dừng bug và chuyển tiếp")
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
                    log.debug("[MANAGER] Blue STOPPED — mark NOT_EXPLOITED and next bug")
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
                log.debug(f"[RED TEAM] RETRY — Bug {current_bug_index + 1}/{len(self.risk_bugs)}")
                red.set_current_bug(current_bug)
                response = red.respond(conversation)
                if response.startswith("[LLM Error:"):
                    log.red_brief(response, is_valid=False)
                else:
                    is_valid = _is_valid_red_approach(response)
                    log.red_brief(response, is_valid=is_valid)
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
                    log.debug("[MANAGER] Red retry strategy captured — sending to Blue review")
                else:
                    red_approved = False
                    current_approach = ""
                log.debug(f"[MANAGER] Red revision consumed — red_attempts={red_attempts}/2")

            # RETRY_BLUE — Blue chạy lại
            elif action == "RETRY_BLUE":
                if blue is None:
                    blue = BlueTeamAgent(
                        target_url    = self.target_url,
                        recon_context = self.recon_content,
                        memory_store  = self.memory,
                    )
                log.debug(f"[BLUE TEAM] RETRY — Review")
                blue.set_current_bug(current_bug)
                response = blue.respond(conversation)
                if response.startswith("[LLM Error:"):
                    log.blue_brief(response, "ERROR")
                else:
                    blue_intent_preview_r = _infer_dialog_intent("BLUETEAM", response)
                    log.blue_brief(response, blue_intent_preview_r)
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
                        log.debug("[MANAGER] Blue APPROVED (retry) but no strategy — forcing Red retry")
                    else:
                        self._record_strategy(current_bug, current_approach, response)
                        log.debug("[MANAGER] Blue APPROVED (retry) — approach recorded")
                elif blue_intent_raw == "REVISE":
                    red_approved = False
                    current_approach = ""
                    red_attempts += 1
                    log.debug(f"[MANAGER] Blue REJECTED (retry) — red_attempts={red_attempts}/2")
                elif blue_intent_raw == "STOP":
                    log.debug("[MANAGER] Blue STOPPED (retry) — mark NOT_EXPLOITED and next bug")
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
                    log.debug("[!] EXECUTE_BUG but no approach — fallback DEBATE_RED")
                    red_approved = False
                    self._last_action = ""
                    conversation.append({
                        "speaker": "SYSTEM",
                        "content": "Manager guard: EXECUTE_BUG blocked because no valid Red strategy/shot plan exists.",
                    })
                    continue

                log.exec_phase(
                    f"THỰC THI — {current_bug.get('id', '?')}",
                    f"Endpoint: {current_bug.get('method', '?')} {current_bug.get('endpoint', '?')}",
                )
                log.debug(
                    f"[MANAGER] → EXECUTE_BUG | bug={current_bug.get('id', '?')} "
                    f"endpoint={current_bug.get('endpoint', '?')} shots=auto(base=1)"
                )

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
                                current_bug=current_bug,
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

                # Parse and display exec output on terminal
                exec_output = _extract_exec_output(exec_result)
                if exec_output:
                    log.parse_and_display_exec_output(exec_output)
                
                # Show verdict
                decision_preview = self._exec_decision(exec_result, current_bug)
                log.verdict_box(
                    decision_preview.get('status', 'UNKNOWN'),
                    evidence=decision_preview.get('evidence', ''),
                    reason=decision_preview.get('reason', ''),
                )
                log.debug(f"[MANAGER] Exec output: {_summarize_exec_result(exec_result)}")

                # Lưu exec_result vào instance để _decide đọc được
                self._last_exec_result = exec_result
                self._record_exec_result(current_bug, current_approach, exec_result)

            # RETRY_EXEC — Exec chạy lại
            elif action == "RETRY_EXEC":
                if not current_approach:
                    log.debug("[!] RETRY_EXEC but no approach — fallback DEBATE_RED")
                    red_approved = False
                    self._last_action = ""
                    conversation.append({
                        "speaker": "SYSTEM",
                        "content": "Manager guard: RETRY_EXEC blocked because no valid Red strategy/shot plan exists.",
                    })
                    continue
                exec_retry_count += 1
                log.exec_phase(
                    f"THỰC THI LẠI — {current_bug.get('id', '?')}",
                    f"Endpoint: {current_bug.get('method', '?')} {current_bug.get('endpoint', '?')} (lần thử {exec_retry_count})",
                )

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
                                current_bug=current_bug,
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

                exec_output = _extract_exec_output(exec_result)
                if exec_output:
                    log.parse_and_display_exec_output(exec_output)
                
                decision_preview = self._exec_decision(exec_result, current_bug)
                log.verdict_box(
                    decision_preview.get('status', 'UNKNOWN'),
                    evidence=decision_preview.get('evidence', ''),
                    reason=decision_preview.get('reason', ''),
                )
                log.debug(f"[MANAGER] Exec output: {_summarize_exec_result(exec_result)}")
                self._last_exec_result = exec_result
                self._record_exec_result(current_bug, current_approach, exec_result)

            # STOP_BUG
            elif action == "STOP_BUG":
                # Manager quyết định dừng bug hiện tại (đọc từ note hoặc conversation)
                # Default: NOT_EXPLOITED, có thể override bằng OOS_SCOPE
                stop_reason = "NOT_EXPLOITED"
                if note and "BLOCKED_AUTH" in note.upper():
                    stop_reason = "BLOCKED_AUTH"
                for msg in reversed(conversation):
                    if "OOS_SCOPE" in msg.get("content", "").upper():
                        stop_reason = "OOS_SCOPE"
                        break
                current_bug["status"] = stop_reason
                current_bug["PoC"] = current_bug.get("PoC", "")
                current_bug["failure_reason"] = note or f"Manager stopped bug as {stop_reason}."
                self._save_risk_bugs()
                
                # Ghi nhận endpoint đã test để dedup các bug sau
                if hasattr(self, '_tested_endpoints') and current_bug.get("endpoint") and current_bug.get("method"):
                    endpoint_key = f"{current_bug.get('method')}:{current_bug.get('endpoint')}:{current_bug.get('pattern_id', '')}"
                    self._tested_endpoints.add(endpoint_key)
                
                bugs_processed_count += 1
                log.debug(f"[MANAGER] STOP_BUG — {current_bug.get('id','?')} marked {stop_reason}")

                result = self._advance_bug(
                    conversation, current_bug, current_bug_index,
                    bugs_processed_count, red, exec_agent
                )
                if result in ("REPORT_SUCCESS", "REPORT_FAIL"):
                    return
                current_bug_index = self.current_bug_index
                current_bug = self.risk_bugs[current_bug_index]
                # ── Dedup: skip nếu endpoint đã EXPLOITED ở bug trước ──
                current_bug, current_bug_index = self._skip_duplicate_endpoints(
                    conversation, current_bug, current_bug_index,
                    bugs_processed_count, red, exec_agent,
                )
                if current_bug is None:
                    return  # hết bug
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
                    log.info(f"{current_bug.get('id', '?')} → KHAI THÁC THÀNH CÔNG")
                elif current_bug.get("status", "PENDING") == "PENDING":
                    self._mark_bug_not_exploited(
                        current_bug,
                        "Manager advanced before a confirmed exploit was captured.",
                        current_approach,
                    )
                    log.debug(
                        f"[MANAGER] {current_bug.get('id', '?')} marked NOT_EXPLOITED "
                        f"before advancing"
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
                # ── Dedup: skip nếu endpoint đã EXPLOITED ở bug trước ──
                current_bug, current_bug_index = self._skip_duplicate_endpoints(
                    conversation, current_bug, current_bug_index,
                    bugs_processed_count, red, exec_agent,
                )
                if current_bug is None:
                    return  # hết bug
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
                log.debug(f"[!] Action không hợp lệ '{action}' → fallback DEBATE_RED")

            # End of tick: persist + compress
            self._persist_new_messages(conversation, tick_start_len)
            self.ctx_mgr.compress_if_needed(
                conversation,
                trigger_len=COMPRESS_TRIGGER_LEN,
                keep_recent=COMPRESS_KEEP_RECENT,
            )

        # _max_ticks exhausted
        log.warn(f"Hết {self._max_ticks} ticks — REPORT_FAIL")
        self._write_report_fail(f"Hết giới hạn {self._max_ticks} ticks.")

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
            log.bug_header(next_index + 1, n, next_bug)
            return "CONTINUE"

    def _preflight_current_bug(
        self,
        conversation: list[dict],
        current_bug: dict,
        current_bug_index: int,
        bugs_processed_count: int,
        red,
        exec_agent,
    ) -> str:
        """Skip candidates whose prerequisites are absent before spending Red/Blue/Exec turns."""
        status = str(current_bug.get("status", "PENDING") or "PENDING").upper()
        if status != "PENDING":
            return ""

        bug_id = current_bug.get("id", "?")
        http_examples = current_bug.get("http_examples") or []
        
        # ── Re-evaluate auth context dynamically ──
        # Exec-Agent may have successfully logged in during a prior bug.
        self.has_authenticated_context = self._has_authenticated_context()
        self.auth_context_summary = self._auth_context_summary()
        
        if current_bug.get("auth_required") and self.has_authenticated_context:
            current_bug["auth_context_available"] = True
            existing_auth_evidence = str(current_bug.get("auth_evidence") or "").upper()
            if (
                not existing_auth_evidence
                or "NO_VERIFIED_AUTH_CONTEXT" in existing_auth_evidence
                or "BLOCKED_AUTH" in existing_auth_evidence
                or "AUTH_REQUIRED_WITH_LIMITED_EVIDENCE" in existing_auth_evidence
            ):
                current_bug["auth_evidence"] = f"AUTH_CONTEXT_AVAILABLE: {self.auth_context_summary or 'authenticated material captured'}"
                self._save_risk_bugs()
        if current_bug.get("auth_required") and not self.has_authenticated_context and not http_examples:
            # ── NEW: Try Exec login recovery before blocking ──
            # If we have login_discovery info, let Exec try to establish auth
            login_discovery = self._get_login_discovery_info()
            if login_discovery:
                log.info(f"{bug_id}: Auth required but no session — attempting Exec login recovery")
                auth_recovered = self._ensure_auth_or_skip(exec_agent, conversation)
                if auth_recovered:
                    current_bug["auth_context_available"] = True
                    current_bug["auth_evidence"] = f"AUTH_CONTEXT_AVAILABLE: {self.auth_context_summary or 'recovered via Exec login'}"
                    self._save_risk_bugs()
                    log.info(f"{bug_id}: Auth recovered — continuing with bug")
                    return ""  # Don't block, continue with bug

            reason = (
                "BLOCKED_AUTH: candidate yêu cầu authenticated context nhưng crawl không có "
                "authenticated session verified và bug không có http_examples để Exec bám theo."
            )
            current_bug["status"] = "BLOCKED_AUTH"
            current_bug["failure_reason"] = reason
            self._save_risk_bugs()
            log.warn(f"{bug_id} bị chặn preflight: {reason}")
            return self._advance_bug(
                conversation, current_bug, current_bug_index,
                bugs_processed_count + 1, red, exec_agent,
            )

        if self._is_challenge_metadata_candidate(current_bug):
            reason = (
                "SKIPPED_METADATA: candidate chỉ dựa trên metadata /api/Challenges của lab "
                "(tên challenge/admin marker), không phải endpoint/chức năng BAC/BLF thực tế."
            )
            current_bug["status"] = "SKIPPED_METADATA"
            current_bug["failure_reason"] = reason
            self._save_risk_bugs()
            log.warn(f"{bug_id} bị chặn preflight: {reason}")
            return self._advance_bug(
                conversation, current_bug, current_bug_index,
                bugs_processed_count + 1, red, exec_agent,
            )

        return ""

    # ══════════════════════════════════════════════════════════
    # ORCHESTRATOR METHODS — Phase 0 context review + auth recovery
    # ══════════════════════════════════════════════════════════

    def _phase0_context_review(self) -> dict:
        """Orchestrator reads and evaluates all context before dispatching per-bug pipeline.

        Returns a dict with recon quality assessment, auth status, bug breakdown,
        and a recommendation for how to proceed.
        """
        # Count recon endpoints
        recon_text = self.recon_content or ""
        import re as _re
        endpoint_patterns = _re.findall(
            r'(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(/[^\s]+)',
            recon_text,
        )
        endpoint_count = len(set(endpoint_patterns))

        # Classify bugs
        anon_bugs = [b for b in self.risk_bugs if not b.get("auth_required")]
        auth_bugs = [b for b in self.risk_bugs if b.get("auth_required")]
        bugs_with_examples = [b for b in self.risk_bugs if b.get("http_examples")]

        # Recon quality
        if endpoint_count < 5 and not bugs_with_examples:
            recon_quality = "poor"
        elif endpoint_count < 10:
            recon_quality = "minimal"
        else:
            recon_quality = "rich"

        # Auth status
        if self.has_authenticated_context:
            auth_status = "verified"
        elif self.auth_context_summary:
            auth_status = "partial"
        else:
            auth_status = "none"

        # Recommendation
        if auth_status == "none" and len(auth_bugs) > len(anon_bugs):
            recommendation = "exec_login_first"
        elif recon_quality == "poor":
            recommendation = "proceed_cautious"
        else:
            recommendation = "proceed"

        return {
            "recon_quality": recon_quality,
            "auth_status": auth_status,
            "endpoint_count": endpoint_count,
            "total_bugs": len(self.risk_bugs),
            "anon_bugs": len(anon_bugs),
            "auth_bugs": len(auth_bugs),
            "bugs_with_examples": len(bugs_with_examples),
            "recommendation": recommendation,
        }

    def _ensure_auth_or_skip(self, exec_agent, conversation: list[dict]) -> bool:
        """If auth is needed but missing, have Exec try to establish a session.

        Uses the login discovery info from crawl to attempt REST login + auto-register.
        Returns True if auth was successfully established.
        """
        if self.has_authenticated_context:
            return True

        login_info = self._get_login_discovery_info()
        if not login_info:
            log.warn("Không có login_discovery info — không thể thử Exec login recovery")
            return False

        log.info(f"Attempting Exec login recovery via {login_info.get('login_endpoint', '?')}...")

        try:
            # Use Exec's _prepare_authenticated_session if available
            # Build a minimal workflow text that triggers login
            login_workflow = (
                f"Auth: required=true\n"
                f"Login endpoint: {login_info.get('login_endpoint', '')}\n"
                f"Auth mechanism: {login_info.get('auth_mechanism', 'unknown')}\n"
                f"TASK: Establish authenticated session for subsequent exploit workflows.\n"
            )
            # Pass it through Exec's session prep
            login_result, session_cookie = exec_agent._prepare_authenticated_session(
                login_workflow, conversation
            )
            if session_cookie and not session_cookie.startswith("("):
                log.info(f"Exec login recovery succeeded — session cookie/token obtained")
                self.has_authenticated_context = self._has_authenticated_context()
                self.auth_context_summary = self._auth_context_summary()
                return self.has_authenticated_context
        except Exception as e:
            log.warn(f"Exec login recovery error: {e}")

        # Re-check in case something was saved by the attempt
        self.has_authenticated_context = self._has_authenticated_context()
        self.auth_context_summary = self._auth_context_summary()
        return self.has_authenticated_context

    def _sort_bugs_by_auth_priority(self) -> None:
        """Sort bugs: anonymous first, then auth-required.

        This maximizes chance of establishing auth context from successful
        anonymous exploits before needing it for auth-required bugs.
        Also sorts by risk level within each group (critical first).
        """
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        def sort_key(bug):
            auth_priority = 1 if bug.get("auth_required") else 0
            risk = risk_order.get(str(bug.get("risk_level", "medium")).lower(), 2)
            return (auth_priority, risk)

        self.risk_bugs.sort(key=sort_key)
        self._save_risk_bugs()
        log.debug(f"Bugs sorted: {[b.get('id','?') for b in self.risk_bugs]}")

    def _get_login_discovery_info(self) -> dict | None:
        """Extract login discovery info from auth_context.json or crawl_raw.json."""
        try:
            context = load_auth_context(self.run_dir)
            for session in context.get("sessions", []) or []:
                ld = session.get("login_discovery")
                if isinstance(ld, dict) and ld.get("login_endpoint"):
                    return ld
        except Exception:
            pass

        # Fallback: look in crawl_raw.json
        raw_path = Path(self.run_dir) / "crawl_raw.json"
        if raw_path.is_file():
            try:
                raw = json.loads(raw_path.read_text(encoding="utf-8"))
                ld = raw.get("login_discovery")
                if isinstance(ld, dict) and ld.get("login_endpoint"):
                    return ld
            except Exception:
                pass

        return None

    def _has_authenticated_context(self) -> bool:
        """Return True when crawl captured reusable auth material, including SPA storage_state."""
        try:
            context = load_auth_context(self.run_dir)
            for session in context.get("sessions", []) or []:
                if session_has_auth_material(session):
                    return True
        except Exception:
            pass

        path = Path(self.run_dir) / "crawl_raw.json"
        if not path.is_file():
            return False
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return False
        authenticated = payload.get("authenticated", []) or []
        if not isinstance(authenticated, list):
            return False
        for entry in authenticated:
            if not isinstance(entry, dict):
                continue
            cookies = entry.get("cookies", []) or []
            if not cookies:
                continue
            header = "; ".join(
                f"{c.get('name')}={c.get('value')}"
                for c in cookies
                if isinstance(c, dict) and c.get("name") and c.get("value")
            )
            if header and "<value>" not in header and "placeholder" not in header.lower():
                return True
            token = bearer_token_from_session(entry)
            if token:
                return True
            storage_path = entry.get("storage_state_path")
            if storage_path and Path(str(storage_path)).is_file():
                return True
        return False

    def _auth_context_summary(self) -> str:
        """Compact auth context summary for Manager/Red/Blue routing decisions."""
        try:
            context = load_auth_context(self.run_dir)
        except Exception:
            context = {}
        sessions = []
        for session in context.get("sessions", []) or []:
            if not isinstance(session, dict):
                continue
            material = []
            header = cookie_header_from_cookie_objects(session.get("cookies") or [])
            if header:
                cookie_names = [
                    part.split("=", 1)[0]
                    for part in header.split("; ")
                    if "=" in part
                ][:5]
                material.append(f"cookies={','.join(cookie_names)}")
            if session.get("storage_state_path"):
                material.append("storage_state")
            if bearer_token_from_session(session):
                material.append("token")
            if not material and not session_has_auth_material(session):
                continue
            sessions.append(
                f"{session.get('label', 'authenticated')}("
                f"verified={bool(session.get('auth_verified'))}; "
                f"source={session.get('created_by', '?')}; "
                f"{'+'.join(material) if material else 'material=unknown'}"
                f")"
            )
        if sessions:
            return "; ".join(sessions[:4])

        # Backward-compatible fallback from crawl_raw.json.
        path = Path(self.run_dir) / "crawl_raw.json"
        if not path.is_file():
            return ""
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return ""
        raw_sessions = []
        for entry in payload.get("authenticated", []) or []:
            if not isinstance(entry, dict):
                continue
            header = cookie_header_from_cookie_objects(entry.get("cookies") or [])
            token = bearer_token_from_session(entry)
            if header or token or entry.get("storage_state_path"):
                raw_sessions.append(
                    f"{entry.get('label', 'authenticated')}"
                    f"(verified={bool(entry.get('auth_verified'))}; "
                    f"{'cookies' if header else ''}{'+token' if token else ''}"
                    f"{'+storage_state' if entry.get('storage_state_path') else ''})"
                )
        return "; ".join(raw_sessions[:4])

    @staticmethod
    def _is_challenge_metadata_candidate(bug: dict) -> bool:
        endpoint = str(bug.get("endpoint", "") or "").lower()
        http_examples = bug.get("http_examples") or []
        text = " ".join(
            str(bug.get(k, "") or "")
            for k in ("title", "hypothesis", "exploit_approach", "verify_method")
        ).lower()
        clues = " ".join(str(c) for c in (bug.get("response_clues") or [])).lower()
        combined = f"{text}\n{clues}"
        metadata_markers = (
            "challenge metadata",
            "challenge list",
            "adminsectionchallenge",
            "registeradminchallenge",
            "admin registration",
            "admin section",
            "challenge key",
            "contains admin-related challenges",
            "recon notes mention admin-related challenges",
            "key includes",
        )
        if "challenge" in endpoint:
            return any(marker in combined for marker in metadata_markers)
        if http_examples:
            return False
        return any(marker in combined for marker in metadata_markers)

    def _skip_duplicate_endpoints(
        self,
        conversation: list[dict],
        current_bug: dict,
        current_bug_index: int,
        bugs_processed_count: int,
        red,
        exec_agent,
    ) -> tuple[dict | None, int]:
        """Skip bugs whose endpoint was already EXPLOITED by a prior bug.

        Returns (current_bug, current_bug_index) after skipping, or
        (None, -1) if all remaining bugs were skipped and report was written.
        """
        n = len(self.risk_bugs)
        exploited_endpoints = {
            b.get("endpoint")
            for b in self.risk_bugs[:current_bug_index]
            if b.get("status") == "EXPLOITED" and b.get("endpoint")
        }

        while current_bug.get("endpoint") in exploited_endpoints:
            log.info(
                f"⏭ {current_bug.get('id', '?')} — endpoint "
                f"{current_bug.get('endpoint')} đã EXPLOITED ở bug trước → bỏ qua"
            )
            current_bug["status"] = "SKIPPED_DUPLICATE"
            current_bug["failure_reason"] = (
                f"Endpoint {current_bug.get('endpoint')} đã được khai thác thành công "
                f"ở bug khác — không cần test lại."
            )
            self._save_risk_bugs()
            bugs_processed_count += 1

            result = self._advance_bug(
                conversation, current_bug, current_bug_index,
                bugs_processed_count, red, exec_agent,
            )
            if result in ("REPORT_SUCCESS", "REPORT_FAIL"):
                return None, -1
            current_bug_index = self.current_bug_index
            current_bug = self.risk_bugs[current_bug_index]

        return current_bug, current_bug_index

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
        log.debug(
            f"[MANAGER] Exec decision: status={status} "
            f"signal={decision.get('signal', '?')} reason={truncate(decision.get('reason', ''), 150)}"
        )

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
            log.debug(
                f"[MANAGER] Exec decision: EXPLOITED — "
                f"{truncate(decision['evidence'], 220)}"
            )
        elif status == "SCRIPT_ERROR":
            current_bug["failure_reason"] = truncate(decision["reason"], 1000)
            log.debug(f"[MANAGER] Exec decision: SCRIPT_ERROR — {truncate(decision['reason'], 220)}")
        elif status == "WRONG_TARGET":
            # 404 trên tất cả request → resource ID sai, xử lý như PARTIAL để cho retry
            current_bug["failure_reason"] = truncate(decision["reason"], 1000)
            current_bug["exec_result_status"] = "WRONG_TARGET"
            log.warn(f"[MANAGER] Exec decision: WRONG_TARGET — endpoint/resource ID không tồn tại. Có thể retry.")
        elif status == "PARTIAL":
            current_bug["failure_reason"] = truncate(decision["reason"], 1000)
            log.debug(f"[MANAGER] Exec decision: PARTIAL — {truncate(decision['reason'], 220)}")
        else:
            current_bug["status"] = "NOT_EXPLOITED"
            current_bug["failure_reason"] = truncate(decision["reason"], 1000)
            log.debug(f"[MANAGER] Exec decision: FAILED — {truncate(decision['reason'], 220)}")

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
            log.debug(f"[!] Could not save risk-bug.json: {e}")

    def _exec_decision(self, exec_result: str, current_bug: dict) -> dict:
        """Classify Exec's self-verified exploit result.

        Priority (top → bottom, first match wins):
          1. Runtime/syntax error → SCRIPT_ERROR
          2. All 404s → WRONG_TARGET (resource không tồn tại, cần retry khác ID)
          3. Script's explicit FINAL marker (EXPLOITED/FAILED) → trust script
          4. result.json status → trust JSON
          5. Heuristic signal (chỉ khi script ko rõ ràng)
        """
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

        # ── 1. Runtime/syntax error ──
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

        # ── 2. Script nói rõ EXPLOITED → tin tưởng (HIGHEST PRIORITY after errors) ──
        #    EXPLOITED verdict từ script PHẢI thắng mọi heuristic (WRONG_TARGET, etc.)
        if final_marker == "EXPLOITED" or success_verdict == "YES":
            return self._confirmed_exploit_decision(
                exec_result,
                current_bug,
                result_json,
                evidence,
                "Exec reported EXPLOITED.",
            )

        # ── 3. All 404 = targeting sai resource ID (chỉ khi script KHÔNG nói EXPLOITED) ──
        if attempt.get("signal") == "WRONG_TARGET":
            return {
                "status": "WRONG_TARGET",
                "reason": evidence or "Tất cả request đều trả 404 — endpoint/resource ID sai.",
                "evidence": evidence,
            }

        # ── 4. Script nói rõ FAILED → tin tưởng, KHÔNG override bởi heuristic ──
        #    Đây là fix chống false positive: khi script in FINAL: FAILED + rc=1,
        #    trước đây heuristic vẫn có thể override lên EXPLOITED.
        if final_marker == "FAILED" or (success_verdict == "NO" and return_code == 1):
            return {
                "status": "FAILED",
                "reason": evidence or "Exec marked the exploit as failed.",
                "evidence": evidence,
            }

        # ── 5. result.json status ──
        if json_status == "EXPLOITED":
            return self._confirmed_exploit_decision(
                exec_result,
                current_bug,
                result_json,
                evidence,
                "result.json reports EXPLOITED.",
            )
        if json_status in {"FAILED", "NO", "NOT_EXPLOITED"}:
            return {
                "status": "FAILED",
                "reason": evidence or "result.json reports FAILED.",
                "evidence": evidence,
            }

        # ── 6. result.json có positive marker cụ thể ──
        if self._result_json_has_positive_marker(result_json):
            return self._confirmed_exploit_decision(
                exec_result,
                current_bug,
                result_json,
                evidence,
                "result.json contains a positive proof marker.",
            )

        # ── 7. Heuristic signal (chỉ khi script ko rõ ràng) ──
        if attempt.get("signal") == "PROOF_CANDIDATE":
            return self._confirmed_exploit_decision(
                exec_result,
                current_bug,
                result_json,
                evidence,
                "Heuristic: proof candidate matching hypothesis.",
            )

        if json_status in {"PARTIAL", "INCONCLUSIVE"} or success_verdict == "PARTIAL" or final_marker == "PARTIAL" or return_code == 2:
            return {
                "status": "PARTIAL",
                "reason": evidence or "Exec found some signal but exploit incomplete.",
                "evidence": evidence,
            }

        if success_verdict == "NO" or return_code == 1:
            return {
                "status": "FAILED",
                "reason": evidence or "Exec indicated failure.",
                "evidence": evidence,
            }

        return {
            "status": "PARTIAL",
            "reason": evidence or "Exec result is ambiguous.",
            "evidence": evidence,
        }

    def _confirmed_exploit_decision(
        self,
        exec_result: str,
        current_bug: dict,
        result_json: dict,
        evidence: str,
        default_reason: str,
    ) -> dict:
        """Accept EXPLOITED only after BAC/BLF proof-quality gates pass."""
        quality_block = self._proof_quality_block(exec_result, current_bug, result_json)
        if quality_block:
            return quality_block
        return {
            "status": "EXPLOITED",
            "reason": evidence or default_reason,
            "evidence": evidence,
        }

    def _proof_quality_block(
        self,
        exec_result: str,
        current_bug: dict,
        result_json: dict,
    ) -> dict:
        """Downgrade weak success claims that do not prove the target BAC/BLF pattern."""
        metadata_reason = self._metadata_only_exec_proof_reason(exec_result, current_bug)
        if metadata_reason:
            return {
                "status": "PROOF_QUALITY_FAIL",
                "reason": metadata_reason,
                "evidence": metadata_reason,
            }

        pattern_id = str(current_bug.get("pattern_id", "") or "").upper()
        category = str(current_bug.get("category", "") or "").lower()
        bug_text = " ".join(
            str(current_bug.get(k, "") or "")
            for k in ("title", "hypothesis", "endpoint", "verify_method", "exploit_approach")
        ).lower()
        exec_text = str(exec_result or "").lower()
        json_text = self._json_text(result_json)

        # ── BAC-01: Admin access — cần admin marker/control.
        # Do not apply this to BAC-03 just because the IDOR target is an admin user.
        if pattern_id == "BAC-01" or (not pattern_id and "admin" in bug_text and "bac" in category):
            if not self._has_concrete_admin_control(exec_text, json_text):
                reason = (
                    "PROOF_QUALITY_FAIL: BAC-01/admin proof requires a concrete privileged "
                    "control or admin API capability. Status 200, generic admin text, or "
                    "challenge markers alone are not accepted."
                )
                return {"status": "PROOF_QUALITY_FAIL", "reason": reason, "evidence": reason}

        # ── BAC-02: Privilege escalation (vertical) — cần admin marker HOẶC
        #    differential proof (baseline vs probe show different access levels).
        #    KHÔNG phải IDOR — không yêu cầu ownership bypass. ──
        if pattern_id == "BAC-02":
            # Privilege escalation: chấp nhận nếu có admin marker HOẶC role/cookie tamper evidence
            has_admin = self._has_concrete_admin_control(exec_text, json_text)
            has_priv_escalation = self._has_privilege_escalation_proof(exec_text, json_text)
            if not has_admin and not has_priv_escalation:
                reason = (
                    "PROOF_QUALITY_FAIL: BAC-02 privilege escalation proof requires "
                    "demonstrating access to admin/privileged functionality after cookie/role "
                    "tampering. No admin marker or differential access found."
                )
                return {"status": "PROOF_QUALITY_FAIL", "reason": reason, "evidence": reason}

        # ── BAC-03: IDOR (horizontal) — cần ownership bypass ──
        if pattern_id == "BAC-03" or ("idor" in bug_text and pattern_id != "BAC-02"):
            if not self._has_object_ownership_bypass(result_json, exec_text):
                if self._has_public_info_exposure_signal(result_json, exec_text):
                    reason = (
                        "INFO_EXPOSURE_ONLY: response exposes user-linked data publicly, "
                        "but Exec did not prove object ownership bypass/cross-user access. "
                        "Do not count this as confirmed BAC/IDOR."
                    )
                    return {"status": "INFO_EXPOSURE_ONLY", "reason": reason, "evidence": reason}
                reason = (
                    "PROOF_QUALITY_FAIL: BAC-03/IDOR proof requires accessing an object/data "
                    "record owned by another user or role. The current evidence does not "
                    "show ownership bypass."
                )
                return {"status": "PROOF_QUALITY_FAIL", "reason": reason, "evidence": reason}

        # ── BAC-04+: Method/role bypass — chấp nhận nếu có admin marker hoặc
        #    script nói EXPLOITED (script tự verify rồi) ──
        if pattern_id in {"BAC-04", "BAC-05", "BAC-06"}:
            # Method/role bypass: script nói EXPLOITED → tin tưởng nếu có evidence cụ thể
            has_admin = self._has_concrete_admin_control(exec_text, json_text)
            has_state_change = self._has_business_logic_state_change(result_json, exec_text)
            has_priv = self._has_privilege_escalation_proof(exec_text, json_text)
            if not has_admin and not has_state_change and not has_priv:
                reason = (
                    f"PROOF_QUALITY_FAIL: {pattern_id} proof requires demonstrating "
                    f"unauthorized action execution or admin access. No concrete evidence found."
                )
                return {"status": "PROOF_QUALITY_FAIL", "reason": reason, "evidence": reason}

        # ── BLF: Business logic — cần before/after state change ──
        if pattern_id.startswith("BLF") or "business logic" in category or "blf" in category:
            if not self._has_business_logic_state_change(result_json, exec_text):
                reason = (
                    "PROOF_QUALITY_FAIL: BLF proof requires before/after state, a non-zero "
                    "delta, or a verified invalid state transition. A successful request "
                    "without measured impact is not accepted."
                )
                return {"status": "PROOF_QUALITY_FAIL", "reason": reason, "evidence": reason}

        return {}

    @staticmethod
    def _metadata_only_exec_proof_reason(exec_result: str, current_bug: dict) -> str:
        """Reject success claims whose proof comes from challenge/metadata text only."""
        text = str(exec_result or "").lower()
        bug_text = " ".join(
            str(current_bug.get(k, "") or "")
            for k in ("endpoint", "title", "hypothesis", "verify_method")
        ).lower()

        metadata_hits = (
            "/api/challenges",
            '"probe": "challenges"',
            "adminsectionchallenge",
            "registeradminchallenge",
            "challenge metadata",
            "challenge list",
            "admin marker found in anonymous probe",
        )
        if not any(hit in text for hit in metadata_hits):
            return ""

        strong_admin_controls = (
            "admin dashboard",
            "user management",
            "manage users",
            "role management",
            "delete user",
            "order management",
            "admin api resource",
            "privileged control",
        )
        if any(marker in text for marker in strong_admin_controls):
            return ""

        admin_candidate = (
            "admin" in bug_text
            or str(current_bug.get("pattern_id", "")).upper() == "BAC-01"
        )
        if not admin_candidate:
            return ""

        return (
            "METADATA_ONLY_PROOF: Exec reported EXPLOITED using /api/Challenges or "
            "challenge metadata markers, but no concrete admin UI/API control was proven "
            "on the claimed endpoint."
        )

    @staticmethod
    def _json_text(data: dict) -> str:
        try:
            return json.dumps(data or {}, ensure_ascii=False, sort_keys=True).lower()
        except Exception:
            return str(data or "").lower()

    @staticmethod
    def _as_list(value) -> list:
        if isinstance(value, list):
            return value
        if value is None:
            return []
        return [value]

    @staticmethod
    def _status_is_2xx(value) -> bool:
        try:
            code = int(value)
        except Exception:
            return False
        return 200 <= code < 300

    @staticmethod
    def _has_owner_marker(item: dict) -> bool:
        owner_keys = {"userid", "user_id", "ownerid", "owner_id", "accountid", "account_id", "customerid", "customer_id"}
        return any(str(key).lower() in owner_keys for key in item)

    @classmethod
    def _iter_dicts(cls, value):
        if isinstance(value, dict):
            yield value
            for child in value.values():
                yield from cls._iter_dicts(child)
        elif isinstance(value, list):
            for child in value:
                yield from cls._iter_dicts(child)

    @classmethod
    def _has_object_ownership_bypass(cls, result_json: dict, exec_text: str) -> bool:
        """True only for concrete direct-object or cross-user access proof."""
        direct_keys = (
            "probe_results", "probes", "direct_object_results",
            "object_probes", "idor_probes", "cross_user_results",
        )
        for key in direct_keys:
            for item in cls._as_list((result_json or {}).get(key)):
                if not isinstance(item, dict):
                    continue
                if item.get("error"):
                    continue
                status = item.get("status_code", item.get("status"))
                if cls._status_is_2xx(status) and any(cls._has_owner_marker(nested) for nested in cls._iter_dicts(item)):
                    return True

        verify = (result_json or {}).get("verify_result")
        if isinstance(verify, dict) and cls._status_is_2xx(verify.get("status_code", verify.get("status"))):
            requested_user = verify.get("userId", verify.get("user_id"))
            rows = verify.get("feedbacks") or verify.get("items") or verify.get("records") or []
            if requested_user is not None and isinstance(rows, list) and rows:
                try:
                    requested = int(requested_user)
                    observed = [
                        int(row.get("UserId", row.get("userId", row.get("user_id"))))
                        for row in rows
                        if isinstance(row, dict)
                        and row.get("UserId", row.get("userId", row.get("user_id"))) is not None
                    ]
                except Exception:
                    observed = []
                if observed and all(user_id == requested for user_id in observed):
                    return True

        for item in cls._iter_dicts(result_json or {}):
            if any(
                bool(item.get(key))
                for key in (
                    "ownership_bypass", "cross_user_access", "other_user_access",
                    "unauthorized_object_access", "accessed_other_user_object",
                )
            ):
                return True

        direct_object_pattern = (
            r"/api/[a-z0-9_/-]+/\d+\s+status=2\d\d"
            r".{0,160}(userid|user_id|ownerid|owner_id|accountid|customerid)\s*="
        )
        if re.search(direct_object_pattern, exec_text, re.IGNORECASE | re.DOTALL):
            return True
        if re.search(r"(cross-user|other user|user a .* user b|not owned by).{0,160}status=2\d\d", exec_text, re.IGNORECASE | re.DOTALL):
            return True
        strong_text_markers = (
            "horizontal idor: confirmed",
            "horizontal idor confirmed",
            "vertical idor: confirmed",
            "vertical idor confirmed",
            "cross-user access",
            "accessed user",
            "accessed admin",
            "attacker (id",
            "attacker id",
            "read other users' pii",
            "read admin account details",
            "server returned exact feedback data of user",
        )
        if any(marker in exec_text for marker in strong_text_markers):
            if any(owner in exec_text for owner in ("userid", "user id", "user_id", "admin id", "role: admin", "email:")):
                return True
        return False

    @classmethod
    def _has_public_info_exposure_signal(cls, result_json: dict, exec_text: str) -> bool:
        baseline = (result_json or {}).get("baseline_summary")
        if isinstance(baseline, dict):
            entries = baseline.get("sample_entries") or baseline.get("entries") or []
            if baseline.get("count", 0) and isinstance(entries, list):
                for item in entries:
                    if isinstance(item, dict) and cls._has_owner_marker(item):
                        return True
        proof = (result_json or {}).get("proof")
        if isinstance(proof, dict):
            for item in cls._as_list(proof.get("baseline")):
                if isinstance(item, dict) and cls._has_owner_marker(item):
                    return True
        public_markers = (
            "baseline leaks userid", "baseline leaks user_id",
            "public exposure", "public get", "feedbacks_found",
            "userid+comment", "user-linked data",
        )
        return any(marker in exec_text for marker in public_markers)

    @staticmethod
    def _has_concrete_admin_control(exec_text: str, json_text: str) -> bool:
        text = f"{exec_text}\n{json_text}"
        control_markers = (
            # Dashboard / panel names
            "admin dashboard", "admin panel", "administration dashboard",
            "admin area", "admin page", "admin section", "admin console",
            "control panel", "system settings", "configuration panel",
            "management console", "admin interface", "admin portal",
            # User/role management actions
            "user management", "manage users", "delete user", "remove user",
            "role management", "change role", "promote user", "demote user",
            "user list", "users list", "list of users",
            # API/endpoint markers
            "privileged control", "admin api resource", "admin-only api",
            "all users", "/api/users status=200", "/rest/admin", "/api/admin",
            "/admin/products", "/admin/users", "/admin/orders",
            # Action evidence
            "victim deleted", "user deleted", "role changed",
            "admin action succeeded", "admin-only action",
        )
        return any(marker in text for marker in control_markers)

    @staticmethod
    def _has_privilege_escalation_proof(exec_text: str, json_text: str) -> bool:
        """Detect privilege escalation evidence: cookie/role tamper → access admin resources."""
        text = f"{exec_text}\n{json_text}"
        # Evidence of cookie/role tampering combined with successful access
        tamper_markers = (
            "cookie tamper", "role=admin", "role=user", "role tampering",
            "cookie role", "modified cookie", "changed cookie",
            "privilege escalation", "vertical escalation",
            "role escalation", "elevated privileges",
        )
        access_markers = (
            "status=200", "status=201", "status=302",
            "success", "accessed", "visible", "returned",
            "admin", "dashboard", "panel", "management",
        )
        has_tamper = any(marker in text for marker in tamper_markers)
        has_access = any(marker in text for marker in access_markers)
        return has_tamper and has_access

    @classmethod
    def _has_business_logic_state_change(cls, result_json: dict, exec_text: str) -> bool:
        positive_bool_markers = (
            "state_changed", "changed", "price_changed", "total_changed",
            "balance_changed", "cart_changed", "quantity_changed",
            "inventory_decremented", "stock_decreased", "discount_applied",
            "order_created", "checkout_succeeded", "invalid_state_accepted",
            "negative_quantity_accepted", "coupon_reused",
        )
        for item in cls._iter_dicts(result_json or {}):
            for key, value in item.items():
                key_lower = str(key).lower()
                if key_lower == "status":
                    continue
                if isinstance(value, bool) and value and any(marker in key_lower for marker in positive_bool_markers):
                    return True
                if isinstance(value, (int, float)) and "delta" in key_lower and value != 0:
                    return True
            if "before" in item and "after" in item:
                before = item.get("before")
                after = item.get("after")
                if before is not None and after is not None and str(before) != str(after):
                    return True

        for match in re.finditer(r"(?:delta|change|difference)\s*[:=]\s*(-?\d+(?:\.\d+)?)", exec_text):
            try:
                if float(match.group(1)) != 0:
                    return True
            except ValueError:
                continue

        before_after = re.search(
            r"before[^0-9-]{0,40}(-?\d+(?:\.\d+)?).*after[^0-9-]{0,40}(-?\d+(?:\.\d+)?)",
            exec_text,
            re.IGNORECASE | re.DOTALL,
        )
        if before_after:
            try:
                return float(before_after.group(1)) != float(before_after.group(2))
            except ValueError:
                return True

        text_state_markers = (
            "state changed", "balance changed", "price changed", "total changed",
            "inventory decreased", "order created", "checkout succeeded",
            "invalid state transition accepted", "negative quantity accepted",
            "coupon reused",
        )
        return any(marker in exec_text for marker in text_state_markers)

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

        log.report_summary(
            exploitable,
            len(self.risk_bugs),
            str(Path(self.run_dir) / "report.md"),
        )
        for b in exploitable:
            log.debug(f"  [{b.get('id', '?')}] {b.get('title', '?')} Status: {b.get('status')}")

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
        log.debug(f"Report saved: {report_path.resolve()}")
        log.debug(f"Raw report saved: {raw_path.resolve()}")
        log.debug(f"Final Vietnamese report saved: {final_path.resolve()}")

    def _write_report_fail(self, reason: str) -> None:
        not_exploitable = self.risk_bugs
        log.report_summary([], len(self.risk_bugs), str(Path(self.run_dir) / "report.md"))
        log.debug(f"REPORT_FAIL Reason: {reason}")

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
        log.debug(f"Report saved: {report_path.resolve()}")
        log.debug(f"Raw report saved: {raw_path.resolve()}")
        log.debug(f"Final Vietnamese report saved: {final_path.resolve()}")

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

            # ── EXPLOITED → immediate success ──
            if status == "EXPLOITED":
                return "NEXT_BUG", f"Exec {bug_label} tự verify EXPLOITED. {reason}"

            # ── Non-EXPLOITED → DIAGNOSIS trước khi quyết định ──
            log.debug(
                f"[MANAGER] 🔍 Phân tích thất bại {bug_label}: "
                f"status={status} retry_count={retry_count}"
            )
            diag_action, diag_note = self._diagnose_failure(
                current_bug, last_exec, status, retry_count,
            )

            # Guardrail: nếu diagnosis nói RETRY_RED nhưng đã quá số lần → force STOP
            red_attempts_count = state_context.get("red_attempts", 0)
            if diag_action == "RETRY_RED" and red_attempts_count >= 2:
                log.info(
                    f"[MANAGER] Diagnosis nói RETRY_RED nhưng red_attempts={red_attempts_count} >= 2 "
                    f"→ force STOP_BUG để tránh loop."
                )
                diag_action = "STOP_BUG"
                diag_note = (
                    f"[PHÂN TÍCH] {bug_label}: Đã thử {red_attempts_count} lần strategy khác nhau. "
                    f"NOT_VULNERABLE — dừng bug."
                )

            log.info(f"[PHÂN TÍCH] {bug_label} → {diag_action}")
            return diag_action, diag_note

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
            log.debug(f"[!] Manager LLM error: {e} — fallback logic")
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
