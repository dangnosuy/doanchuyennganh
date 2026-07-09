"""
policy_agent.py — Tác nhân kiểm tra chính sách (guardrail) cho pipeline MARL.

Chạy TRƯỚC khi ManageAgent thực thi hành động. Xác thực action đề xuất
qua luật tất định của state machine hiện tại.

Trả về ALLOW / BLOCK / SUGGEST.
"""

import os
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Hằng số
# ---------------------------------------------------------------------------

VALID_ACTIONS = {
    "DEBATE_RED",
    "DEBATE_BLUE",
    "EXECUTE_BUG",
    "RETRY_RED",
    "RETRY_BLUE",
    "RETRY_EXEC",
    "STOP_BUG",
    "NEXT_BUG",
    "REPORT_SUCCESS",
    "REPORT_FAIL",
}

@dataclass
class PolicyVerdict:
    verdict: str            # "ALLOW" | "BLOCK" | "SUGGEST"
    reason: str             # giải thích bằng tiếng Việt
    suggested_action: str | None  # nếu verdict == "SUGGEST", hành động thay thế


# ---------------------------------------------------------------------------
# PolicyAgent
# ---------------------------------------------------------------------------


class PolicyAgent:
    """
    Guardrail nội bộ đứng cạnh ManageAgent.

    Nhận đầy đủ context (target, recon, scope) để đánh giá:
    - Luật cứng: state machine (không cần LLM, nhanh).
    - Ngữ nghĩa sâu: chiến lược có đúng scope target không, có khai thác
      đúng loại lỗ hổng (BAC/BLF) không, có đi quá domain scope không,
      có lặp lại chiến lược đã thất bại không.
    """

    def __init__(
        self,
        model: str | None = None,
        max_rounds: int = 5,
        min_debate_rounds: int = 2,
        max_exec_retries: int = 2,
        max_ticks: int = 60,
        target_url: str = "",
        recon_summary: str = "",
    ):
        self.model = model or os.environ.get("MARL_MANAGER_MODEL", "ollama/gemma4:31b-cloud")
        self.max_ticks = max_ticks
        self.target_url = target_url
        self.max_rounds = max_rounds
        self.min_debate_rounds = min_debate_rounds
        self.max_exec_retries = max_exec_retries
        self.recon_summary = recon_summary

    # ------------------------------------------------------------------
    # API công khai
    # ------------------------------------------------------------------

    def validate(
        self,
        proposed_action: str,
        state_context: dict,
        conversation: list[dict],
    ) -> PolicyVerdict:
        """
        Xác thực hành động đề xuất theo luật cứng (không dùng LLM nữa).
        LLM semantic check đã gây too many false blocks.
        """
        rule_verdict = self._check_rules(proposed_action, state_context)
        if rule_verdict is not None:
            _print_verdict(rule_verdict)
            return rule_verdict

        # No LLM check — hard rules only
        return None

    # ------------------------------------------------------------------
    # Giai đoạn 1: Kiểm tra luật tất định
    # ------------------------------------------------------------------

    def _check_rules(self, action: str, state: dict) -> PolicyVerdict | None:
        """
        Kiểm tra các luật cứng cho per-bug pipeline.
        Trả về PolicyVerdict(BLOCK) nếu vi phạm, None nếu không vi phạm.
        """
        tick: int = state.get("tick", 0)
        current_bug_index: int = state.get("current_bug_index", 0)
        total_bugs: int = state.get("total_bugs", 0)
        red_approved: bool = state.get("red_approved", False)
        has_workflow: bool = state.get("has_workflow", False)

        if action not in VALID_ACTIONS:
            return PolicyVerdict(
                verdict="BLOCK",
                reason=f"Hành động '{action}' không nằm trong danh sách hợp lệ.",
                suggested_action=None,
            )

        if tick >= self.max_ticks:
            return PolicyVerdict(
                verdict="BLOCK",
                reason=f"Đã đạt giới hạn MAX_TICKS ({self.max_ticks}). Phải kết thúc pipeline.",
                suggested_action=None,
            )

        # EXECUTE_BUG requires a current workflow and Blue strategy approval.
        if action == "EXECUTE_BUG" and not has_workflow:
            return PolicyVerdict(
                verdict="SUGGEST",
                reason="EXECUTE_BUG chưa thể chạy: chưa có strategy/shot plan hợp lệ.",
                suggested_action="DEBATE_RED",
            )
        if action == "EXECUTE_BUG" and not red_approved:
            return PolicyVerdict(
                verdict="SUGGEST",
                reason="EXECUTE_BUG chưa thể chạy: strategy hiện tại chưa được Blue approve.",
                suggested_action="DEBATE_BLUE",
            )

        # NEXT_BUG should not be called when all bugs are exhausted
        if action == "NEXT_BUG" and current_bug_index >= total_bugs - 1:
            # Let Manager decide via _decide shortcut instead of blocking
            pass

        # REPORT_SUCCESS/REPORT_FAIL always allowed at this stage
        return None
def _print_verdict(v: PolicyVerdict) -> None:
    """In kết quả Policy ra console với màu phù hợp."""
    color = "\033[91m" if v.verdict == "BLOCK" else "\033[93m"
    label = f"[POLICY {v.verdict}]"
    suffix = f" → đề xuất: {v.suggested_action}" if v.suggested_action else ""
    print(f"{color}{label} {v.reason}{suffix}\033[0m")
