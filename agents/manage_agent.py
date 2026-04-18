"""
ManageAgent — "Sếp" LLM điều phối toàn bộ pipeline pentest.

Thay thế toàn bộ retry loop + phase_debate/execute/evaluate/report trong main.py.
ManageAgent là agent LLM thật — mỗi tick gọi LLM để quyết định action tiếp theo,
inject hướng dẫn vào conversation, rồi gọi đúng agent con.

Đội ngũ:
  - RedTeamAgent  (Pentest): viết chiến lược tấn công
  - BlueTeamAgent (SOC):     review, phản biện chiến lược
  - ExecAgent     (Intern):  chạy tool, thực thi workflow, verify

Không có agent nào gọi thẳng agent khác — tất cả đều qua ManageAgent.
"""

import os
import re
from pathlib import Path

from openai import OpenAI

from shared.utils import extract_next_tag, extract_send_block, truncate

# ── Env / Connection ─────────────────────────────────────────
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "gho_token")
SERVER_URL   = os.environ.get("MARL_SERVER_URL", "http://127.0.0.1:5000/v1")
MODEL        = os.environ.get("MARL_MANAGER_MODEL", "gpt-5-mini")

# ── Guardrail constants ──────────────────────────────────────
MAX_DEBATE_STEPS  = 30   # tổng turns trong debate (Red + Blue + Agent)
MAX_ROUNDS        = 5    # số round Red↔Blue tối đa
MIN_DEBATE_ROUNDS = 2    # tối thiểu 2 round trước khi approve
MAX_EXEC_RETRIES  = 2    # số lần thử chiến lược mới sau exec fail
MAX_TICKS         = 80   # tổng số tick tối đa cho toàn pipeline

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
    "DEBATE_RED",      # Yêu cầu Red Team viết / sửa chiến lược
    "DEBATE_BLUE",     # Yêu cầu Blue Team review
    "VERIFY",          # Yêu cầu Exec verify thông tin (read-only)
    "EXECUTE",         # Yêu cầu Exec thực thi workflow đã approved
    "EVALUATE",        # Yêu cầu Red đánh giá kết quả thực thi
    "RETRY_DEBATE",    # Chiến lược thất bại → debate lại từ đầu
    "REPORT_SUCCESS",  # Kết thúc thành công → viết report
    "REPORT_FAIL",     # Kết thúc thất bại → viết report
}

ACTION_PATTERN = re.compile(
    r"\[ACTION:\s*(" + "|".join(VALID_ACTIONS) + r")\]",
    re.IGNORECASE,
)

NOTE_PATTERN = re.compile(r"<note>(.*?)</note>", re.DOTALL | re.IGNORECASE)

# ── Keyword để nhận diện workflow từ Red ─────────────────────
WORKFLOW_KEYWORDS = [
    "chiến lược", "chien luoc", "workflow", "attack plan",
    "bước 1", "buoc 1", "step 1",
]

# ─────────────────────────────────────────────────────────────
MANAGER_PROMPT = """\
Bạn là Manager (Sếp) của nhóm kiểm thử bảo mật (pentest) được ủy quyền.
Nhiệm vụ: dẫn dắt đội ngũ kiểm tra lỗ hổng BAC / BLF tại mục tiêu.

=== MỤC TIÊU ===
{target_url}

=== DỮ LIỆU RECON (tóm tắt) ===
{recon_summary}

=== ĐỘI NGŨ ===
- RED TEAM  (Pentest): Viết chiến lược tấn công từng bước. Sáng tạo, chi tiết.
- BLUE TEAM (SOC):    Review chiến lược, đặt câu hỏi, phản biện, approve khi đủ điều kiện.
- EXEC AGENT (Intern): Chạy tool, verify endpoint, thực thi workflow. Làm theo lệnh chính xác.

=== QUY TRÌNH ===
Giai đoạn DEBATE (bắt buộc ≥ {min_rounds} round, tối đa {max_rounds} round):
  Red viết CHIEN LUOC → Blue review → lặp lại → khi Blue approve đủ round → EXECUTE

Giai đoạn EXECUTE:
  Exec thực thi workflow từng bước, ghi kết quả.

Giai đoạn EVALUATE:
  Red đọc kết quả, đánh giá thành công / thất bại / cần thử lại.

=== HÀNH ĐỘNG BẠN CÓ THỂ RA LỆNH ===
Mỗi lượt chọn ĐÚNG 1 action dưới đây:

[ACTION: DEBATE_RED]     — Yêu cầu Red Team viết / sửa chiến lược tấn công
[ACTION: DEBATE_BLUE]    — Yêu cầu Blue Team review chiến lược Red vừa nộp
[ACTION: VERIFY]         — Yêu cầu Exec verify thông tin cụ thể (chỉ đọc, không exploit)
[ACTION: EXECUTE]        — Yêu cầu Exec thực thi workflow đã được Blue approve
[ACTION: EVALUATE]       — Yêu cầu Red đánh giá kết quả sau khi Exec chạy xong
[ACTION: RETRY_DEBATE]   — Chiến lược thất bại, reset debate, yêu cầu chiến lược mới
[ACTION: REPORT_SUCCESS] — Kết thúc: lỗ hổng được xác nhận, viết báo cáo thành công
[ACTION: REPORT_FAIL]    — Kết thúc: không tìm được lỗ hổng sau hết retry, viết báo cáo

=== NGUYÊN TẮC RA QUYẾT ĐỊNH ===
1. Luôn bắt đầu bằng DEBATE_RED.
2. Sau khi Red nộp chiến lược → DEBATE_BLUE để review.
3. Blue cần verify endpoint → VERIFY rồi quay lại DEBATE_BLUE.
4. Blue approve VÀ đã đủ {min_rounds} round → EXECUTE.
5. Sau EXECUTE → EVALUATE để Red đọc kết quả.
6. Red xác nhận thành công → REPORT_SUCCESS.
7. Red muốn thử lại VÀ còn lượt retry → RETRY_DEBATE.
8. Hết retry hoặc hết round → REPORT_FAIL.
9. KHÔNG bao giờ để Blue approve trước khi đủ round tối thiểu.
10. KHÔNG gọi EXECUTE khi chưa có approval từ Blue.

=== FORMAT TRẢ LỜI ===
Viết 1-2 câu giải thích quyết định bằng tiếng Việt.
Nếu cần hướng dẫn thêm cho agent tiếp theo, ghi trong thẻ <note>...</note>.
Cuối cùng emit action tag.

Ví dụ:
Red vừa nộp chiến lược lần đầu, cần Blue review kỹ trước khi chấp thuận.
<note>Hãy đặt ít nhất 2 câu hỏi kiểm tra, đặc biệt về xác thực phiên đăng nhập.</note>
[ACTION: DEBATE_BLUE]
"""


def _strip_tag_display(text: str) -> str:
    """Xóa các routing tag ở cuối text để hiển thị sạch."""
    return re.sub(
        r"\[(?:REDTEAM|BLUETEAM|AGENT(?::run)?|APPROVED|DONE)\]\s*$",
        "", text, flags=re.IGNORECASE,
    ).rstrip()


def _extract_last_workflow(conversation: list[dict]) -> str:
    """Tìm workflow / chiến lược từ message Red Team gần nhất trong conversation."""
    for msg in reversed(conversation):
        if msg["speaker"] != "REDTEAM":
            continue
        content = msg["content"]
        lower = content.lower()
        if any(kw in lower for kw in WORKFLOW_KEYWORDS):
            clean = content
            if clean.startswith("[REDTEAM]:"):
                clean = clean[len("[REDTEAM]:"):].strip()
            return _strip_tag_display(clean)
    # Fallback: lấy message Red cuối cùng
    for msg in reversed(conversation):
        if msg["speaker"] == "REDTEAM":
            clean = msg["content"]
            if clean.startswith("[REDTEAM]:"):
                clean = clean[len("[REDTEAM]:"):].strip()
            return _strip_tag_display(clean)
    raise RuntimeError("Không tìm thấy workflow từ Red Team.")


def _get_last_red_content(conversation: list[dict]) -> str:
    """Lấy nội dung message Red Team cuối cùng (đã strip tag)."""
    for msg in reversed(conversation):
        if msg["speaker"] == "REDTEAM":
            clean = msg["content"]
            if clean.startswith("[REDTEAM]:"):
                clean = clean[len("[REDTEAM]:"):].strip()
            return _strip_tag_display(clean)
    return ""


class ManageAgent:
    """'Sếp' LLM điều phối toàn bộ pipeline pentest.

    ManageAgent sở hữu và khởi tạo tất cả agent con bên trong.
    main.py chỉ cần gọi manage_agent.run(conversation).

    Mỗi tick:
      1. Gọi LLM → quyết định [ACTION: XXX] + <note> hướng dẫn
      2. In quyết định ra console
      3. Inject note vào conversation (nếu có)
      4. Gọi agent tương ứng
      5. Lặp lại cho đến REPORT_* hoặc hết MAX_TICKS
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

        self.client = OpenAI(api_key=GITHUB_TOKEN, base_url=SERVER_URL)
        self.system_prompt = MANAGER_PROMPT.format(
            target_url    = target_url,
            recon_summary = truncate(recon_content, 4000),
            min_rounds    = min_debate_rounds,
            max_rounds    = max_rounds,
        )

    # ══════════════════════════════════════════════════════════
    # PUBLIC API
    # ══════════════════════════════════════════════════════════

    def run(self, conversation: list[dict]) -> None:
        """Toàn bộ pipeline: debate → execute → evaluate → report.

        Không trả về giá trị — kết quả được ghi vào run_dir/report.md.
        Mọi exception đều được bắt và in ra console.
        """
        from agents.red_team  import RedTeamAgent
        from agents.blue_team import BlueTeamAgent
        from agents.exec_agent import ExecAgent

        print(f"\n{M}{B}{'='*60}")
        print(f"  MANAGE AGENT — Khởi động pipeline")
        print(f"{'='*60}{RST}\n")

        exec_agent = ExecAgent(
            working_dir = self.run_dir,
            target_url  = self.target_url,
            recon_md    = str(Path(self.run_dir) / "recon.md"),
        )
        red = RedTeamAgent(
            target_url    = self.target_url,
            recon_context = self.recon_content,
        )

        try:
            self._run_loop(red, exec_agent, conversation)
        except RuntimeError as e:
            print(f"\n{R}[!] ManageAgent: {e}{RST}")
            self._write_report(
                verdict        = "FAIL",
                workflow       = "",
                exec_report    = str(e),
                red_evaluation = "Pipeline kết thúc do lỗi.",
                debate_rounds  = 0,
            )
        finally:
            try:
                exec_agent.shutdown()
            except Exception:
                pass

    # ══════════════════════════════════════════════════════════
    # INTERNAL — main loop
    # ══════════════════════════════════════════════════════════

    def _run_loop(
        self,
        red,
        exec_agent,
        conversation: list[dict],
    ) -> None:
        """Vòng lặp tick chính. Toàn bộ state là local variable."""
        from agents.blue_team import BlueTeamAgent

        # ── State (tất cả local — ManageAgent an toàn khi reuse) ──
        round_num:    int  = 0
        exec_attempts: int = 0
        red_spoke:    bool = False
        blue_spoke:   bool = False
        workflow:     str  = ""
        exec_report:  str  = ""
        last_action:  str  = ""

        # Blue được tạo mới mỗi lần debate bắt đầu / retry
        blue: BlueTeamAgent | None = None

        for tick in range(MAX_TICKS):

            # ── Hard guardrails (không phụ thuộc LLM) ──────────────
            if round_num >= self.max_rounds and not exec_report:
                print(f"\n{R}[!] Hết {self.max_rounds} rounds — buộc REPORT_FAIL{RST}")
                self._write_report("FAIL", workflow, exec_report,
                                   "Hết số round debate tối đa.", round_num)
                return

            if exec_attempts > self.max_exec_retries and exec_report:
                print(f"\n{R}[!] Hết {self.max_exec_retries} lần retry — buộc REPORT_FAIL{RST}")
                self._write_report("FAIL", workflow, exec_report,
                                   "Hết số lần thử tối đa.", round_num)
                return

            # ── Manager quyết định action tiếp theo ─────────────────
            action, note = self._decide(
                conversation  = conversation,
                state_context = {
                    "tick":          tick,
                    "round_num":     round_num,
                    "exec_attempts": exec_attempts,
                    "red_spoke":     red_spoke,
                    "blue_spoke":    blue_spoke,
                    "last_action":   last_action,
                    "has_workflow":  bool(workflow),
                    "has_exec":      bool(exec_report),
                },
            )

            print(f"\n{M}{B}[MANAGER] → {action}{RST}", end="")
            if note:
                print(f"  |  {note[:80]}" + ("…" if len(note) > 80 else ""))
            else:
                print()

            last_action = action

            # ── Inject Manager note vào conversation nếu có ─────────
            if note:
                conversation.append({
                    "speaker": "SYSTEM",
                    "content": f"[MANAGER]: {note}",
                })

            # ══════════════════════════════════════════════════════════
            # ROUTING — Manager gọi đúng agent theo action
            # ══════════════════════════════════════════════════════════

            # ── DEBATE_RED ──────────────────────────────────────────
            if action == "DEBATE_RED":
                if blue is None:
                    blue = BlueTeamAgent(
                        target_url   = self.target_url,
                        recon_context = self.recon_content,
                    )
                # Tính round khi cả hai đã nói
                if red_spoke and blue_spoke:
                    round_num += 1
                    red_spoke = blue_spoke = False

                if round_num >= self.max_rounds:
                    print(f"{R}[!] Hết rounds trong DEBATE_RED — REPORT_FAIL{RST}")
                    self._write_report("FAIL", workflow, exec_report,
                                       "Hết số round debate.", round_num)
                    return

                print(f"\n{R}{B}══ RED TEAM — Round {round_num + 1}/{self.max_rounds} ══{RST}")
                response = red.respond(conversation)
                conversation.append({
                    "speaker": "REDTEAM",
                    "content": f"[REDTEAM]: {response}",
                })
                print(f"{R}{_strip_tag_display(response)}{RST}")
                red_spoke = True

            # ── DEBATE_BLUE ─────────────────────────────────────────
            elif action == "DEBATE_BLUE":
                if blue is None:
                    blue = BlueTeamAgent(
                        target_url    = self.target_url,
                        recon_context = self.recon_content,
                    )
                print(f"\n{C}{B}══ BLUE TEAM — Review ══{RST}")
                response = blue.respond(conversation)
                conversation.append({
                    "speaker": "BLUETEAM",
                    "content": f"[BLUETEAM]: {response}",
                })
                print(f"{C}{_strip_tag_display(response)}{RST}")
                blue_spoke = True

                # Guardrail: Blue emit [APPROVED] nhưng chưa đủ round
                tag = extract_next_tag(response)
                if tag == "APPROVED" and (round_num + 1) < self.min_debate_rounds:
                    print(f"\n{Y}{B}[GUARDRAIL] Chưa đủ {self.min_debate_rounds} round "
                          f"— ép tiếp tục debate{RST}")
                    conversation.append({
                        "speaker": "SYSTEM",
                        "content": (
                            "[SYSTEM]: Chưa đủ số round tối thiểu. "
                            "Cần đặt thêm câu hỏi verify hoặc yêu cầu Red làm rõ."
                        ),
                    })

            # ── VERIFY ──────────────────────────────────────────────
            elif action == "VERIFY":
                # Xác định caller từ người gửi request gần nhất
                caller = "REDTEAM"
                for msg in reversed(conversation):
                    if msg["speaker"] in ("REDTEAM", "BLUETEAM"):
                        caller = msg["speaker"]
                        break
                caller_name = "Red Team" if caller == "REDTEAM" else "Blue Team"
                print(f"\n{G}{B}[AGENT] Verify cho {caller_name} (read-only)...{RST}")

                raw  = exec_agent.answer(conversation, caller=caller, read_only=False)
                data = extract_send_block(raw) or raw
                conversation.append({
                    "speaker": "AGENT",
                    "content": f"[AGENT]: {data}",
                })
                print(f"{G}{_strip_tag_display(raw)}{RST}")

            # ── EXECUTE ─────────────────────────────────────────────
            elif action == "EXECUTE":
                print(f"\n{C}{B}{'='*60}")
                print(f"  PHASE 3: EXECUTION")
                print(f"{'='*60}{RST}\n")

                workflow = _extract_last_workflow(conversation)
                print(f"{G}{B}[AGENT] Đang thực thi workflow...{RST}\n")

                raw         = exec_agent.run_workflow(workflow, conversation)
                exec_report = extract_send_block(raw) or raw
                exec_attempts += 1

                conversation.append({
                    "speaker": "AGENT",
                    "content": f"[AGENT EXEC]: {exec_report}",
                })
                print(f"{G}{_strip_tag_display(raw)}{RST}")

                # Switch Red sang eval mode
                red.switch_to_eval_mode(exec_report)

                # Inject kết quả vào conversation để Red đọc
                conversation.append({
                    "speaker": "SYSTEM",
                    "content": (
                        "[SYSTEM — KẾT QUẢ THỰC THI]\n"
                        "Đây là kết quả thực thi từ Agent. "
                        "Hãy đọc kỹ và đánh giá dựa trên evidence thực tế.\n\n"
                        f"{exec_report}"
                    ),
                })

            # ── EVALUATE ────────────────────────────────────────────
            elif action == "EVALUATE":
                print(f"\n{C}{B}{'='*60}")
                print(f"  PHASE 4: EVALUATION")
                print(f"{'='*60}{RST}\n")
                print(f"\n{R}{B}══ RED TEAM — Đánh giá kết quả ══{RST}")

                response = red.respond(conversation)
                conversation.append({
                    "speaker": "REDTEAM",
                    "content": f"[REDTEAM]: {response}",
                })
                print(f"{R}{_strip_tag_display(response)}{RST}")

            # ── RETRY_DEBATE ────────────────────────────────────────
            elif action == "RETRY_DEBATE":
                print(f"\n{Y}{B}══ RETRY — Red đề xuất chiến lược mới ══{RST}")
                # Reset Blue (tươi mới cho chiến lược mới)
                blue       = None
                red_spoke  = False
                blue_spoke = False

            # ── REPORT_SUCCESS ──────────────────────────────────────
            elif action == "REPORT_SUCCESS":
                red_evaluation = _get_last_red_content(conversation)
                self._write_report(
                    verdict        = "SUCCESS",
                    workflow       = workflow,
                    exec_report    = exec_report,
                    red_evaluation = red_evaluation,
                    debate_rounds  = round_num + 1,
                )
                return

            # ── REPORT_FAIL ─────────────────────────────────────────
            elif action == "REPORT_FAIL":
                red_evaluation = _get_last_red_content(conversation)
                self._write_report(
                    verdict        = "FAIL",
                    workflow       = workflow,
                    exec_report    = exec_report,
                    red_evaluation = red_evaluation,
                    debate_rounds  = round_num + 1,
                )
                return

            else:
                # Action không hợp lệ — mặc định tiếp tục với DEBATE_RED
                print(f"{Y}[!] Action không hợp lệ '{action}' → fallback DEBATE_RED{RST}")

        # Hết MAX_TICKS — buộc kết thúc
        print(f"\n{R}[!] Hết {MAX_TICKS} ticks — buộc REPORT_FAIL{RST}")
        self._write_report(
            verdict        = "FAIL",
            workflow       = workflow,
            exec_report    = exec_report,
            red_evaluation = "Pipeline kết thúc do vượt giới hạn ticks.",
            debate_rounds  = round_num,
        )

    # ══════════════════════════════════════════════════════════
    # INTERNAL — Manager LLM decision
    # ══════════════════════════════════════════════════════════

    def _decide(
        self,
        conversation: list[dict],
        state_context: dict,
    ) -> tuple[str, str]:
        """Gọi LLM để quyết định action tiếp theo.

        Returns:
            (action, note)
            - action: một trong VALID_ACTIONS
            - note:   hướng dẫn bổ sung cho agent tiếp theo (có thể rỗng)
        """
        # Build context tóm tắt trạng thái hiện tại
        state_summary = (
            f"=== TRẠNG THÁI HIỆN TẠI ===\n"
            f"Tick: {state_context['tick']} / {MAX_TICKS}\n"
            f"Round debate: {state_context['round_num']} / {self.max_rounds} "
            f"(tối thiểu: {self.min_debate_rounds})\n"
            f"Số lần execute: {state_context['exec_attempts']} / {self.max_exec_retries + 1}\n"
            f"Red đã nói turn này: {state_context['red_spoke']}\n"
            f"Blue đã nói turn này: {state_context['blue_spoke']}\n"
            f"Đã có workflow: {state_context['has_workflow']}\n"
            f"Đã có kết quả exec: {state_context['has_exec']}\n"
            f"Action vừa thực hiện: {state_context['last_action'] or '(chưa có)'}\n"
        )

        # Chỉ lấy các message quan trọng gần nhất để tránh context quá dài
        recent_msgs = conversation[-12:] if len(conversation) > 12 else conversation
        conv_text = "\n".join(
            f"[{m['speaker']}]: {truncate(m['content'], 800)}"
            for m in recent_msgs
        )

        user_msg = (
            f"{state_summary}\n"
            f"=== LỊCH SỬ HỘI THOẠI GẦN NHẤT ===\n"
            f"{conv_text}\n\n"
            f"Dựa trên trạng thái và hội thoại trên, bạn sẽ ra quyết định gì tiếp theo?\n"
            f"Nhớ: emit đúng 1 action tag [ACTION: XXX] ở cuối."
        )

        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user",   "content": user_msg},
        ]

        try:
            resp = self.client.chat.completions.create(
                model       = self.model,
                messages    = messages,
                temperature = 0.2,   # thấp để Manager nhất quán, ít sáng tạo
                max_tokens  = 512,
            )
            text = resp.choices[0].message.content or ""
        except Exception as e:
            print(f"{Y}[!] Manager LLM error: {e} — fallback logic{RST}")
            text = ""

        # Extract action
        action = self._extract_action(text, state_context)

        # Extract note
        note_match = NOTE_PATTERN.search(text)
        note = note_match.group(1).strip() if note_match else ""

        return action, note

    def _extract_action(self, text: str, state_context: dict) -> str:
        """Đọc [ACTION: XXX] từ Manager LLM response.

        Nếu LLM không emit action hợp lệ → fallback deterministic
        dựa trên state để tránh bị kẹt.
        """
        match = ACTION_PATTERN.search(text)
        if match:
            return match.group(1).upper()

        # ── Fallback deterministic khi LLM fail ──
        has_workflow = state_context.get("has_workflow", False)
        has_exec     = state_context.get("has_exec", False)
        red_spoke    = state_context.get("red_spoke", False)
        last_action  = state_context.get("last_action", "")

        if has_exec:
            return "EVALUATE"
        if has_workflow and not has_exec:
            return "EXECUTE"
        if red_spoke:
            return "DEBATE_BLUE"
        return "DEBATE_RED"

    # ══════════════════════════════════════════════════════════
    # INTERNAL — Report writer
    # ══════════════════════════════════════════════════════════

    def _write_report(
        self,
        verdict:        str,
        workflow:       str,
        exec_report:    str,
        red_evaluation: str,
        debate_rounds:  int,
    ) -> None:
        """Ghi report.md vào run_dir và in tóm tắt ra console."""
        print(f"\n{C}{B}{'='*60}")
        print(f"  PHASE 5: REPORT")
        print(f"{'='*60}{RST}\n")

        icon = "✅" if verdict == "SUCCESS" else "❌"
        print(f"{B}Target:{RST}       {self.target_url}")
        print(f"{B}Verdict:{RST}      {icon} {verdict}")
        print(f"{B}Debate rounds:{RST} {debate_rounds}")

        if exec_report:
            print(f"\n{B}Execution Output (truncated):{RST}")
            print(exec_report[:3000])

        report_path = Path(self.run_dir) / "report.md"
        report_md = f"""# MARL Penetration Test Report
**Target:** {self.target_url}
**Verdict:** {icon} {verdict}
**Debate rounds:** {debate_rounds}

## Approved Attack Workflow
{workflow or "N/A"}

## Execution Report
```
{exec_report or "N/A"}
```

## Red Team Evaluation
{red_evaluation or "N/A"}
"""
        report_path.write_text(report_md, encoding="utf-8")
        print(f"\n{G}[+] Report saved: {report_path.resolve()}{RST}")
