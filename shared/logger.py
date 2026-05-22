"""
MarlLogger — Hệ thống logging trung tâm cho MARL.

Thiết kế 2 tầng:
  • Terminal: hiển thị trọng tâm — phase, exploit steps, verdicts
  • Log file: ghi đầy đủ chi tiết — strategy text, debug state, LLM calls

Tất cả agent dùng singleton `log` từ module này thay vì print() trực tiếp.
"""

from __future__ import annotations

import os
import re
import sys
from datetime import datetime
from pathlib import Path

# ══════════════════════════════════════════════════════════════
# ANSI COLORS & STYLES
# ══════════════════════════════════════════════════════════════

class _C:
    """ANSI escape codes."""
    RST   = "\033[0m"
    BOLD  = "\033[1m"
    DIM   = "\033[2m"
    ITALIC = "\033[3m"
    ULINE = "\033[4m"

    # Foreground
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    GRAY   = "\033[90m"

    # Background
    BG_RED    = "\033[41m"
    BG_GREEN  = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE   = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN   = "\033[46m"

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


# ══════════════════════════════════════════════════════════════
# MARL LOGGER
# ══════════════════════════════════════════════════════════════

class MarlLogger:
    """Singleton logger cho toàn bộ MARL pipeline.

    - terminal(): in ra console (có ANSI color)
    - file_only(): chỉ ghi vào log file (cho debug/detail)
    - Tất cả output đều ghi vào log file tự động
    """

    _instance: MarlLogger | None = None

    def __init__(self):
        self._log_file = None
        self._log_path: str | None = None
        self._at_line_start = True

    @classmethod
    def get(cls) -> MarlLogger:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def setup(self, log_path: str) -> str:
        """Mở log file và bắt đầu ghi."""
        self._log_path = log_path
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(f"MARL Session Log — {datetime.now().isoformat()}\n")
            f.write(f"{'═' * 60}\n\n")
        self._log_file = open(log_path, "a", encoding="utf-8")
        self._at_line_start = True
        return log_path

    @property
    def log_path(self) -> str | None:
        return self._log_path

    # ── Core output ──────────────────────────────────────────

    def terminal(self, text: str, end: str = "\n"):
        """In ra console + ghi vào log file."""
        sys.__stdout__.write(text + end)
        sys.__stdout__.flush()
        self._write_to_file(text + end)

    def file_only(self, text: str):
        """Chỉ ghi vào log file, KHÔNG hiển thị trên terminal."""
        self._write_to_file(text + "\n")

    def _write_to_file(self, text: str):
        if not self._log_file:
            return
        clean = _strip_ansi(text)
        if not clean:
            return
        lines = clean.split("\n")
        for i, line in enumerate(lines):
            if i > 0:
                self._log_file.write("\n")
                self._at_line_start = True
            if line:
                if self._at_line_start:
                    ts = datetime.now().strftime("%H:%M:%S")
                    self._log_file.write(f"[{ts}] {line}")
                else:
                    self._log_file.write(line)
                self._at_line_start = False
        if clean.endswith("\n"):
            self._at_line_start = True
        self._log_file.flush()
        try:
            os.fsync(self._log_file.fileno())
        except OSError:
            pass

    def close(self):
        if self._log_file:
            self._log_file.close()
            self._log_file = None

    # ══════════════════════════════════════════════════════════
    # HIGH-LEVEL API — Terminal output đẹp
    # ══════════════════════════════════════════════════════════

    def main_banner(self, target_url: str, workspace: str, workspace_mode: str):
        """Banner chính khi khởi động MARL."""
        w = 62
        self.terminal("")
        self.terminal(f"{_C.CYAN}{_C.BOLD}╔{'═' * w}╗{_C.RST}")
        self.terminal(f"{_C.CYAN}{_C.BOLD}║  🤖 MARL — Hệ thống Pentest Đa Agent                       ║{_C.RST}")
        self.terminal(f"{_C.CYAN}{_C.BOLD}║  Tự động khai thác BAC & Business Logic Flaw                ║{_C.RST}")
        self.terminal(f"{_C.CYAN}{_C.BOLD}╠{'═' * w}╣{_C.RST}")
        tgt_line = f"  🎯 Mục tiêu: {target_url}"
        self.terminal(f"{_C.CYAN}║{tgt_line:<{w}}║{_C.RST}")
        ws_line = f"  📂 Workspace: {workspace} [{workspace_mode}]"
        self.terminal(f"{_C.CYAN}║{ws_line:<{w}}║{_C.RST}")
        self.terminal(f"{_C.CYAN}{_C.BOLD}╚{'═' * w}╝{_C.RST}")
        self.terminal("")

    def phase_banner(self, phase_num: int, phase_name: str, subtitle: str = ""):
        """Banner cho mỗi phase chính."""
        header = f" GIAI ĐOẠN {phase_num}: {phase_name} "
        w = max(60, len(header) + 4)
        pad = w - len(header)
        left = pad // 2
        right = pad - left
        self.terminal("")
        self.terminal(f"{_C.YELLOW}{_C.BOLD}{'━' * left}{header}{'━' * right}{_C.RST}")
        if subtitle:
            self.terminal(f"{_C.GRAY}  {subtitle}{_C.RST}")

    def sub_phase(self, title: str):
        """Sub-phase header nhỏ hơn."""
        self.terminal(f"\n{_C.CYAN}{_C.BOLD} ── {title} ──{_C.RST}")

    # ── Bug display ──────────────────────────────────────────

    def bug_table(self, bugs: list[dict]):
        """In bảng tóm tắt các bug candidates."""
        if not bugs:
            self.terminal(f" {_C.YELLOW}⚠ Không tìm thấy bug candidate nào{_C.RST}")
            return

        self.terminal("")
        self.terminal(f" {_C.BOLD}┌─ Danh sách Bug Candidates ──────────────────────────────────────┐{_C.RST}")
        self.terminal(f" {_C.BOLD}│ {'#':>2}  {'ID':<10} {'Mức độ':<10} {'Endpoint':<22} {'Pattern':<8} │{_C.RST}")
        self.terminal(f" {_C.BOLD}├─────────────────────────────────────────────────────────────────┤{_C.RST}")

        risk_colors = {
            "CRITICAL": _C.RED + _C.BOLD,
            "HIGH": _C.RED,
            "MEDIUM": _C.YELLOW,
            "LOW": _C.GREEN,
        }
        for i, bug in enumerate(bugs):
            risk = bug.get("risk_level", "MEDIUM")
            color = risk_colors.get(risk, _C.WHITE)
            endpoint = f"{bug.get('method', '?')} {bug.get('endpoint', '?')}"
            if len(endpoint) > 20:
                endpoint = endpoint[:19] + "…"
            risk_display = _strip_ansi(f"{risk:<8}")
            # Build the colored line for terminal
            line_text = f" │ {i+1:>2}  {bug.get('id', '?'):<10} {color}{risk_display:<10}{_C.RST} {endpoint:<22} {bug.get('pattern_id', '?'):<8} │"
            self.terminal(line_text)

        self.terminal(f" {_C.BOLD}└─────────────────────────────────────────────────────────────────┘{_C.RST}")
        self.terminal("")

    def bug_header(self, bug_index: int, total_bugs: int, bug: dict):
        """Header khi bắt đầu xử lý 1 bug."""
        bid = bug.get("id", "?")
        title = bug.get("title", "?")
        risk = bug.get("risk_level", "?")
        endpoint = f"{bug.get('method', '?')} {bug.get('endpoint', '?')}"
        hypothesis = bug.get("hypothesis", "")

        risk_colors = {"CRITICAL": _C.RED + _C.BOLD, "HIGH": _C.RED, "MEDIUM": _C.YELLOW, "LOW": _C.GREEN}
        rc = risk_colors.get(risk, _C.WHITE)

        self.terminal("")
        self.terminal(f"{_C.MAGENTA}{_C.BOLD}━━━ BUG {bug_index}/{total_bugs}: {bid} — {title} [{rc}{risk}{_C.MAGENTA}{_C.BOLD}] ━━━{_C.RST}")
        self.terminal(f" 📋 Endpoint:   {_C.BOLD}{endpoint}{_C.RST}")

        params = bug.get("request_params") or []
        if params:
            self.terminal(f" 📎 Tham số:    {', '.join(params)}")

        cookies = bug.get("cookie_attack_surface") or []
        if cookies:
            cookie_names = [c.get("name", "?") for c in cookies[:4] if isinstance(c, dict)]
            if cookie_names:
                self.terminal(f" 🍪 Cookies:    {', '.join(cookie_names)}")

        if hypothesis:
            hyp_short = hypothesis[:120] + "…" if len(hypothesis) > 120 else hypothesis
            self.terminal(f" 🎯 Giả thuyết: {_C.ITALIC}{hyp_short}{_C.RST}")

    # ── Agent briefs ─────────────────────────────────────────

    def red_brief(self, response: str, is_valid: bool = False):
        """1-dòng tóm tắt Red Team trên terminal, chi tiết vào log."""
        if response.startswith("[LLM Error:"):
            self.terminal(f" ⚔ {_C.RED}RED TEAM → Lỗi kết nối LLM{_C.RST}")
        elif is_valid:
            char_count = len(response)
            self.terminal(f" ⚔ {_C.RED}RED TEAM → Chiến lược đã đề xuất ({char_count} ký tự){_C.RST}  {_C.DIM}[chi tiết → log]{_C.RST}")
        else:
            self.terminal(f" ⚔ {_C.RED}RED TEAM → Phản hồi không hợp lệ{_C.RST}")
        # Chi tiết ghi vào log file
        self.file_only(f"[RED-TEAM FULL RESPONSE]\n{response}\n[/RED-TEAM FULL RESPONSE]")

    def blue_brief(self, response: str, intent: str):
        """1-dòng tóm tắt Blue Team trên terminal, chi tiết vào log."""
        if response.startswith("[LLM Error:"):
            self.terminal(f" 🛡 {_C.CYAN}BLUE TEAM → Lỗi kết nối LLM{_C.RST}")
        elif intent == "APPROVE":
            self.terminal(f" 🛡 {_C.GREEN}BLUE TEAM → CHẤP THUẬN ✓{_C.RST}")
        elif intent == "REVISE":
            # Extract short reason
            reason = self._extract_blue_reason(response)
            self.terminal(f" 🛡 {_C.YELLOW}BLUE TEAM → TỪ CHỐI ✗ — {reason}{_C.RST}")
        elif intent == "STOP":
            self.terminal(f" 🛡 {_C.RED}BLUE TEAM → DỪNG BUG ■{_C.RST}")
        else:
            self.terminal(f" 🛡 {_C.CYAN}BLUE TEAM → Đang đánh giá…{_C.RST}")
        # Chi tiết ghi vào log file
        self.file_only(f"[BLUE-TEAM FULL RESPONSE]\n{response}\n[/BLUE-TEAM FULL RESPONSE]")

    def _extract_blue_reason(self, response: str) -> str:
        """Trích xuất lý do reject ngắn gọn từ Blue."""
        lower = response.lower()
        # Look for gap= or fix= patterns
        gap_match = re.search(r"gap\s*=\s*(.+?)(?:;|$|\n)", response, re.IGNORECASE)
        if gap_match:
            reason = gap_match.group(1).strip()
            if len(reason) > 80:
                reason = reason[:77] + "…"
            return reason
        # Fallback: first sentence after REJECTED
        rej_match = re.search(r"REJECTED?\s*[-—:]\s*(.+?)(?:\.|;|\n)", response, re.IGNORECASE)
        if rej_match:
            reason = rej_match.group(1).strip()
            if len(reason) > 80:
                reason = reason[:77] + "…"
            return reason
        # Last fallback
        first_line = response.split("\n")[0][:80]
        return first_line

    # ── Execution logging ────────────────────────────────────

    def exec_session(self, method: str, cookie: str = "", status: str = ""):
        """Log session prep (login)."""
        if cookie:
            cookie_short = cookie[:50] + "…" if len(cookie) > 50 else cookie
            self.terminal(f" 🔑 Phiên đăng nhập: {method} → {_C.GREEN}{cookie_short}{_C.RST}")
        else:
            self.terminal(f" 🔑 Phiên đăng nhập: {method} → {_C.YELLOW}{status}{_C.RST}")

    def exec_phase(self, phase_name: str, detail: str = ""):
        """Exec sub-phase header."""
        self.terminal(f"\n {_C.CYAN}{_C.BOLD}─── {phase_name} ───{_C.RST}")
        if detail:
            self.terminal(f"   {_C.GRAY}{detail}{_C.RST}")

    def exploit_step(
        self,
        step_num: int,
        description: str,
        method: str = "",
        path: str = "",
        cookie: str = "",
        params: str = "",
        status: str = "",
        evidence: str = "",
        success: bool | None = None,
    ):
        """In chi tiết 1 bước exploit — trọng tâm output."""
        icon = "📡"
        self.terminal(f"\n {icon} {_C.BOLD}BƯỚC {step_num}: {description}{_C.RST}")

        if method and path:
            self.terminal(f"    Yêu cầu:    {_C.BOLD}{method} {path}{_C.RST}")
        if cookie:
            cookie_short = cookie[:60] + "…" if len(cookie) > 60 else cookie
            self.terminal(f"    Cookie:     {_C.DIM}{cookie_short}{_C.RST}")
        if params:
            self.terminal(f"    Tham số:    {params}")
        if status:
            status_color = _C.GREEN if status.startswith("2") else (_C.YELLOW if status.startswith("3") else _C.RED)
            self.terminal(f"    Trạng thái: {status_color}{status}{_C.RST}")
        if evidence:
            ev_icon = "✓" if success else ("⚠" if success is None else "✗")
            ev_color = _C.GREEN if success else (_C.YELLOW if success is None else _C.RED)
            self.terminal(f"    Bằng chứng: {ev_color}{ev_icon} {evidence}{_C.RST}")

    def exec_script_info(self, shot: int, total: int, script_path: str = ""):
        """Log script shot info."""
        self.terminal(f"\n   {_C.YELLOW}▶ Chạy exploit script (lần {shot}/{total}){_C.RST}", end="")
        if script_path:
            self.terminal(f"  {_C.DIM}[{script_path}]{_C.RST}")
        else:
            self.terminal("")

    # ── Verdict ──────────────────────────────────────────────

    def verdict_box(self, status: str, evidence: str = "", reason: str = ""):
        """In verdict box cho kết quả exploit."""
        w = 62

        if status == "EXPLOITED":
            icon = "✅"
            label = "KHAI THÁC THÀNH CÔNG"
            border_c = _C.GREEN
            text_c = _C.GREEN + _C.BOLD
        elif status == "PARTIAL":
            icon = "⚠️"
            label = "KHAI THÁC MỘT PHẦN"
            border_c = _C.YELLOW
            text_c = _C.YELLOW + _C.BOLD
        elif status == "SCRIPT_ERROR":
            icon = "💥"
            label = "LỖI SCRIPT"
            border_c = _C.RED
            text_c = _C.RED + _C.BOLD
        else:
            icon = "❌"
            label = "KHÔNG KHAI THÁC ĐƯỢC"
            border_c = _C.RED
            text_c = _C.RED + _C.BOLD

        self.terminal("")
        self.terminal(f" {border_c}┌{'─' * w}┐{_C.RST}")
        self.terminal(f" {border_c}│{text_c}  {icon} {label:<{w - 5}}{border_c}│{_C.RST}")
        if evidence:
            ev_lines = self._wrap_text(evidence, w - 6)
            for line in ev_lines[:3]:
                self.terminal(f" {border_c}│{_C.RST}    {line:<{w - 4}}{border_c}│{_C.RST}")
        if reason and status != "EXPLOITED":
            reason_lines = self._wrap_text(f"Lý do: {reason}", w - 6)
            for line in reason_lines[:2]:
                self.terminal(f" {border_c}│{_C.RST}    {_C.DIM}{line:<{w - 4}}{_C.RST}{border_c}│{_C.RST}")
        self.terminal(f" {border_c}└{'─' * w}┘{_C.RST}")

    # ── Manager / Progress ───────────────────────────────────

    def manager_decision(self, tick: int, action: str, bug_id: str = "", note: str = ""):
        """Log manager decision — compact trên terminal."""
        action_icons = {
            "DEBATE_RED": "⚔",
            "DEBATE_BLUE": "🛡",
            "EXECUTE_BUG": "🚀",
            "RETRY_RED": "🔄⚔",
            "RETRY_BLUE": "🔄🛡",
            "RETRY_EXEC": "🔄🚀",
            "STOP_BUG": "⏹",
            "NEXT_BUG": "⏭",
            "REPORT_SUCCESS": "📊✅",
            "REPORT_FAIL": "📊❌",
        }
        icon = action_icons.get(action, "⚙")

        # Map action to Vietnamese
        action_vi = {
            "DEBATE_RED": "Red Team lập chiến lược",
            "DEBATE_BLUE": "Blue Team đánh giá",
            "EXECUTE_BUG": "Thực thi khai thác",
            "RETRY_RED": "Red Team thử lại",
            "RETRY_BLUE": "Blue Team thử lại",
            "RETRY_EXEC": "Thực thi lại",
            "STOP_BUG": "Dừng bug",
            "NEXT_BUG": "Bug tiếp theo",
            "REPORT_SUCCESS": "Báo cáo thành công",
            "REPORT_FAIL": "Báo cáo thất bại",
        }.get(action, action)

        self.file_only(f"[MANAGER tick={tick}] → {action} | bug={bug_id} | note={note}")

        # Terminal: chỉ hiện cho một số action quan trọng
        if action in ("EXECUTE_BUG", "RETRY_EXEC", "STOP_BUG", "NEXT_BUG",
                       "REPORT_SUCCESS", "REPORT_FAIL"):
            self.terminal(f"\n {_C.MAGENTA}{icon} [{action_vi}]{_C.RST}", end="")
            if bug_id:
                self.terminal(f"  {_C.DIM}{bug_id}{_C.RST}", end="")
            self.terminal("")

    def manager_tick_state(self, tick: int, bug_index: int, total_bugs: int,
                           bug_id: str, red_attempts: int, approved: bool):
        """Manager tick state — chỉ ghi log file."""
        self.file_only(
            f"[MANAGER tick={tick}] bug={bug_index + 1}/{total_bugs} "
            f"({bug_id}) red_attempts={red_attempts}/2 "
            f"approved={'✓' if approved else '✗'}"
        )

    def policy_log(self, tick: int, verdict: str, action: str, reason: str = ""):
        """Policy decision — chỉ ghi log file."""
        self.file_only(f"[POLICY tick={tick}] {verdict} '{action}' → {reason}")

    # ── Info / Debug ─────────────────────────────────────────

    def info(self, text: str):
        """Thông tin quan trọng — hiển thị terminal + log file."""
        self.terminal(f" {_C.GREEN}✓{_C.RST} {text}")

    def warn(self, text: str):
        """Cảnh báo — hiển thị terminal."""
        self.terminal(f" {_C.YELLOW}⚠ {text}{_C.RST}")

    def error(self, text: str):
        """Lỗi — hiển thị terminal."""
        self.terminal(f" {_C.RED}✗ {text}{_C.RST}")

    def debug(self, text: str):
        """Debug — chỉ ghi log file."""
        self.file_only(f"[DEBUG] {text}")

    def detail(self, label: str, text: str):
        """Nội dung dài — chỉ ghi log file."""
        self.file_only(f"[DETAIL {label}]\n{text}\n[/DETAIL {label}]")

    # ── Report ───────────────────────────────────────────────

    def report_summary(self, exploited: list[dict], total: int, report_path: str):
        """Tóm tắt kết quả cuối cùng."""
        w = 62
        self.terminal("")
        self.terminal(f"{_C.CYAN}{_C.BOLD}╔{'═' * w}╗{_C.RST}")
        self.terminal(f"{_C.CYAN}{_C.BOLD}║  📊 KẾT QUẢ KIỂM THỬ                                         ║{_C.RST}")
        self.terminal(f"{_C.CYAN}{_C.BOLD}╠{'═' * w}╣{_C.RST}")

        if exploited:
            line = f"  ✅ Khai thác thành công: {len(exploited)}/{total} bugs"
            self.terminal(f"{_C.CYAN}║{_C.GREEN}{line:<{w}}{_C.CYAN}║{_C.RST}")
            for b in exploited:
                bline = f"     • {b.get('id', '?')} — {b.get('title', '?')}"
                if len(bline) > w:
                    bline = bline[:w - 1] + "…"
                self.terminal(f"{_C.CYAN}║{_C.GREEN}{bline:<{w}}{_C.CYAN}║{_C.RST}")
        else:
            line = f"  ❌ Không khai thác được bug nào ({total} bugs đã thử)"
            self.terminal(f"{_C.CYAN}║{_C.RED}{line:<{w}}{_C.CYAN}║{_C.RST}")

        rp_line = f"  📄 Báo cáo: {report_path}"
        if len(rp_line) > w:
            rp_line = rp_line[:w - 1] + "…"
        self.terminal(f"{_C.CYAN}║{rp_line:<{w}}║{_C.RST}")
        self.terminal(f"{_C.CYAN}{_C.BOLD}╚{'═' * w}╝{_C.RST}")
        self.terminal("")

    # ── Parse exec output helpers ────────────────────────────

    def parse_and_display_exec_output(self, exec_output: str):
        """Parse output từ Python exploit script và hiển thị structured."""
        if not exec_output:
            return

        lines = exec_output.splitlines()
        current_step = 0
        step_desc = ""

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue

            # Detect STEP markers
            step_match = re.match(r"===\s*STEP\s+(\d+)\s*:\s*(.+?)\s*===", stripped, re.IGNORECASE)
            if step_match:
                current_step = int(step_match.group(1))
                step_desc = step_match.group(2)
                self.terminal(f"\n {_C.BOLD}📡 BƯỚC {current_step}: {step_desc}{_C.RST}")
                continue

            # REQUEST_SUMMARY lines
            req_match = re.match(
                r"REQUEST_SUMMARY:\s*(GET|POST|PUT|PATCH|DELETE|HEAD)\s+(\S+)\s+status=(\d+)(.*)",
                stripped, re.IGNORECASE,
            )
            if req_match:
                method, path, status, rest = req_match.groups()
                status_color = _C.GREEN if status.startswith("2") else (
                    _C.YELLOW if status.startswith("3") else _C.RED
                )
                self.terminal(f"    Yêu cầu:    {_C.BOLD}{method} {path}{_C.RST}")
                self.terminal(f"    Trạng thái: {status_color}{status}{_C.RST}")
                if rest.strip():
                    self.terminal(f"    Chi tiết:   {rest.strip()}")
                continue

            # SHOT_RESULT
            shot_match = re.match(r"SHOT_RESULT:\s*(\w+)", stripped, re.IGNORECASE)
            if shot_match:
                result = shot_match.group(1).upper()
                color = _C.GREEN if result == "EXPLOITED" else (_C.YELLOW if result == "PARTIAL" else _C.RED)
                self.terminal(f"    Kết quả:    {color}{result}{_C.RST}")
                continue

            # EVIDENCE_SUMMARY
            ev_match = re.match(r"EVIDENCE_SUMMARY:\s*(.+)", stripped, re.IGNORECASE)
            if ev_match:
                self.terminal(f"    Bằng chứng: {ev_match.group(1)}")
                continue

            # FINAL marker
            final_match = re.match(r"===\s*FINAL:\s*(\w+)\s*===", stripped, re.IGNORECASE)
            if final_match:
                # Don't print here — verdict_box handles this
                continue

            # VERIFY_COMPLETED
            verify_match = re.match(r"VERIFY_COMPLETED:\s*(\w+)", stripped, re.IGNORECASE)
            if verify_match:
                val = verify_match.group(1).lower()
                color = _C.GREEN if val == "yes" else _C.YELLOW
                icon = "✓" if val == "yes" else "…"
                self.terminal(f"    Xác minh:   {color}{icon} {val}{_C.RST}")
                continue

            # FINAL_REASON
            reason_match = re.match(r"FINAL_REASON:\s*(.+)", stripped, re.IGNORECASE)
            if reason_match:
                self.terminal(f"    Kết luận:   {_C.ITALIC}{reason_match.group(1)}{_C.RST}")
                continue

            # ERRORS
            err_match = re.match(r"ERRORS:\s*(.+)", stripped, re.IGNORECASE)
            if err_match:
                err_text = err_match.group(1)
                if err_text.lower() != "none":
                    self.terminal(f"    Lỗi:        {_C.RED}{err_text}{_C.RST}")
                continue

            # Generic StepN: SUCCESS/FAIL
            step_result_match = re.match(r"Step\s*\d+\s*:\s*(SUCCESS|FAIL|EXPLOITED|PARTIAL)", stripped, re.IGNORECASE)
            if step_result_match:
                r = step_result_match.group(1).upper()
                color = _C.GREEN if r in ("SUCCESS", "EXPLOITED") else _C.RED
                self.terminal(f"    Kết quả:    {color}{r}{_C.RST}")
                continue

        # Always write full output to log file
        self.file_only(f"[EXEC RAW OUTPUT]\n{exec_output}\n[/EXEC RAW OUTPUT]")

    # ── Utilities ────────────────────────────────────────────

    @staticmethod
    def _wrap_text(text: str, width: int) -> list[str]:
        """Wrap text to fit within width."""
        words = text.split()
        lines = []
        current = ""
        for word in words:
            if not current:
                current = word
            elif len(current) + 1 + len(word) <= width:
                current += " " + word
            else:
                lines.append(current)
                current = word
        if current:
            lines.append(current)
        return lines or [""]


# ══════════════════════════════════════════════════════════════
# STDOUT/STDERR REDIRECTOR — capture agent print() vào log file
# ══════════════════════════════════════════════════════════════

class _LogCapture:
    """Intercept print() calls from agent code and route to log file.

    Terminal output ĐÃ ĐƯỢC kiểm soát bởi MarlLogger.terminal().
    Các print() từ agent code cũ chỉ ghi vào log file, KHÔNG hiện terminal.

    Ngoại lệ: set pass_through=True để vẫn hiện terminal (cho backward compat giai đoạn chuyển đổi).
    """

    def __init__(self, logger: MarlLogger, stream, *, pass_through: bool = False):
        self._logger = logger
        self._stream = stream
        self._pass_through = pass_through

    def write(self, text: str):
        if not text:
            return
        if self._pass_through:
            self._stream.write(text)
            self._stream.flush()
        self._logger._write_to_file(text)

    def flush(self):
        self._stream.flush()

    def fileno(self):
        return self._stream.fileno()

    def isatty(self):
        return self._stream.isatty()

    @property
    def encoding(self):
        return self._stream.encoding


def install_log_capture(*, pass_through: bool = False):
    """Redirect sys.stdout/stderr → MarlLogger file only.

    Gọi SAU khi MarlLogger.setup() đã chạy.
    Tất cả print() từ agents sẽ chỉ ghi vào log file.
    Terminal output phải dùng MarlLogger.terminal() explicitly.
    """
    logger = MarlLogger.get()
    sys.stdout = _LogCapture(logger, sys.__stdout__, pass_through=pass_through)
    sys.stderr = _LogCapture(logger, sys.__stderr__, pass_through=pass_through)


# ══════════════════════════════════════════════════════════════
# MODULE-LEVEL SHORTCUT
# ══════════════════════════════════════════════════════════════

log = MarlLogger.get()
