"""
MARL Orchestrator — Entry point duy nhat cho toan bo pipeline.

Flow:
  Phase 1: RECON — CrawlAgent crawl target → recon.md
  Phase 2: DEBATE — Red ↔ Blue tranh luan, ca hai co the goi Agent
           Red viet chien luoc tan cong → Blue review → reject/approve
  Phase 3: EXECUTION — Agent thuc thi workflow da duoc approve
  Phase 4: EVALUATION — Red danh gia ket qua, co the de xuat chien luoc moi
  Phase 5: REPORT — Luu ket qua cuoi cung

Usage:
    python main.py
    python main.py "Test https://target.com user:admin pass:secret"
"""

import os
import re
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from shared.utils import parse_prompt, extract_next_tag, extract_send_block

WORKSPACE = "./workspace"


def _make_run_dir(target_url: str) -> str:
    """Create workspace/{domain}_{timestamp}/ for this run.

    Returns absolute path to the run directory.
    """
    domain = urlparse(target_url).hostname or "unknown"
    # Strip port-like suffixes and sanitize for filesystem
    domain = re.sub(r"[^a-zA-Z0-9._-]", "_", domain)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = Path(WORKSPACE) / f"{domain}_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return str(run_dir.resolve())


MAX_DEBATE_STEPS = 30          # tong so turn toi da (Red + Blue + Agent)
MAX_ROUNDS = 5                 # so round Red↔Blue reject/revise toi da
MIN_DEBATE_ROUNDS = 2          # buoc phai co it nhat 2 round truoc khi approve
MAX_EXEC_RETRIES = 2           # so lan cho Red de xuat chien luoc moi sau exec fail

# ── ANSI colors ──────────────────────────────────────────────
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
C = "\033[96m"
B = "\033[1m"
RST = "\033[0m"

# Regex strip ANSI escape codes for log file
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


# ═════════════════════════════════════════════════════════════
# TEE LOGGER — mirror stdout/stderr to log file
# ═════════════════════════════════════════════════════════════

class TeeLogger:
    """Write to both original stream and a log file — realtime.

    - Console gets full ANSI colors as normal
    - Log file gets clean text (ANSI codes stripped) + timestamp per line
    - Every write() is flushed IMMEDIATELY to disk (os.fsync)
      so log is never lost even on Ctrl+C or crash
    """

    def __init__(self, log_path: str, stream):
        self._stream = stream          # original sys.stdout or sys.stderr
        # Open unbuffered (buffering=1 is line-buffered, but we flush manually)
        self._log_file = open(log_path, "a", encoding="utf-8")
        self._at_line_start = True     # track for timestamp insertion

    def write(self, text: str):
        # Console: pass through as-is (with colors)
        self._stream.write(text)
        self._stream.flush()

        # Log file: strip ANSI, add timestamps, flush immediately
        clean = _ANSI_RE.sub("", text)
        if clean:
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
            # If text ended with \n, next write starts a new line
            if clean.endswith("\n"):
                self._at_line_start = True

            # REALTIME: flush to disk immediately — survive Ctrl+C / crash
            self._log_file.flush()
            os.fsync(self._log_file.fileno())

    def flush(self):
        self._stream.flush()
        self._log_file.flush()

    def close(self):
        self._log_file.close()

    def fileno(self):
        return self._stream.fileno()

    def isatty(self):
        return self._stream.isatty()

    @property
    def encoding(self):
        return self._stream.encoding


def setup_logging(run_dir: str) -> str:
    """Setup TeeLogger to mirror all output to {run_dir}/marl.log.

    Returns:
        Path to the log file.
    """
    log_path = str(Path(run_dir) / "marl.log")

    # Write header
    with open(log_path, "w", encoding="utf-8") as f:
        f.write(f"MARL Session Log — {datetime.now().isoformat()}\n")
        f.write(f"{'=' * 60}\n\n")

    sys.stdout = TeeLogger(log_path, sys.__stdout__)
    sys.stderr = TeeLogger(log_path, sys.__stderr__)

    return log_path


# ═════════════════════════════════════════════════════════════
# HELPERS
# ═════════════════════════════════════════════════════════════

def banner():
    print(f"""{C}{B}
    ╔══════════════════════════════════════════╗
    ║   MARL — Multi-Agent Red-team LLM        ║
    ║   Penetration Testing via Debate          ║
    ╚══════════════════════════════════════════╝{RST}
    """)


def get_user_prompt() -> str:
    """Lay prompt tu CLI arg hoac stdin."""
    if len(sys.argv) > 1:
        return " ".join(sys.argv[1:])
    print(f"{Y}Nhap prompt (URL + credentials neu co):{RST}")
    prompt = input("> ").strip()
    if not prompt:
        print(f"{R}[!] Prompt khong duoc de trong.{RST}")
        sys.exit(1)
    return prompt


def strip_tag(text: str) -> str:
    """Xoa tag [REDTEAM], [BLUETEAM], [AGENT], [APPROVED], [DONE] o cuoi text."""
    return re.sub(
        r"\[(?:REDTEAM|BLUETEAM|AGENT(?::run)?|APPROVED|DONE)\]\s*$",
        "", text, flags=re.IGNORECASE,
    ).rstrip()


# ═════════════════════════════════════════════════════════════
# PHASE 1: RECON
# ═════════════════════════════════════════════════════════════

def phase_recon(user_prompt: str, run_dir: str) -> tuple[str, str, str]:
    """CrawlAgent crawl target → (target_url, recon_path, recon_content)."""
    print(f"\n{C}{B}{'='*60}")
    print(f"  PHASE 1: RECON")
    print(f"{'='*60}{RST}\n")

    from agents.crawl_agent import CrawlAgent

    target_url, _ = parse_prompt(user_prompt)
    if not target_url:
        raise ValueError("Khong tim thay URL trong prompt.")

    crawl = CrawlAgent(working_dir=run_dir)
    try:
        recon_path = crawl.run(user_prompt)
        if not recon_path or not Path(recon_path).exists():
            raise RuntimeError("CrawlAgent khong tao duoc recon file.")
        recon_content = Path(recon_path).read_text(encoding="utf-8")
    finally:
        crawl.shutdown()

    print(f"\n{G}[+] Recon hoan tat: {recon_path}{RST}")
    return target_url, recon_path, recon_content


# ═════════════════════════════════════════════════════════════
# PHASE 2: DEBATE  (Red ↔ Blue, ca hai co the goi Agent)
# ═════════════════════════════════════════════════════════════

def phase_debate(
    target_url: str,
    recon_content: str,
    exec_agent,
    red,
    conversation: list[dict],
) -> tuple[str, list[dict], int]:
    """Red vs Blue debate loop.

    [GIẢI THÍCH CÁC CƠ CHẾ KIỂM SOÁT DEBATE Ở ĐÂY - THEO ROADMAP]:
    1. Max Steps (MAX_DEBATE_STEPS=30): "Cầu dao" chống AI rơi vào vòng lặp vô tận (infinite loop). 
       Giới hạn số lượt thoại qua lại để không đốt API. Nết vượt quá mức này mà vẫn chưa có sự đồng thuận, 
       hệ thống sẽ raise RuntimeError ép ngừng.
    2. Max Rounds (MAX_ROUNDS=5): 1 Round là khi Red nộp bản thảo và Blue bắt lỗi. Quá 5 lần sửa nháp 
       mà vẫn fail thì vứt chiến lược đó. Cùng lúc, MIN_DEBATE_ROUNDS=2 ép Blue phải review cẩn thận, 
       chống bệnh duyệt bừa của LLM.
    3. Conversation Memory (Quay lui dữ liệu - Backtracking): Đầu vào "conversation" không hề bị xóa đi.
       Lý do: Nếu Phase 3 Execute gặp lỗi (VD. 403 Forbidden), kết quả thất bại được nối vào tail của list
       và quăng ngược lại Phase 2 Retry. Khi đó 2 Agent đọc hiểu ngay "chiến lược 1 thất bại", tự giác 
       chuyển hướng sang chiến lược 2, không lặp lại lỗi ngớ ngẩn (cắn vào ngõ cụt).

    Args:
        target_url: URL target.
        recon_content: Noi dung recon.md.
        exec_agent: ExecAgent instance (shared across phases).
        red: RedTeamAgent instance (shared across retries).
        conversation: Conversation (co the co history/log loi tu retry truoc).

    Returns:
        (approved_workflow, conversation, round_num)

    Raises:
        RuntimeError: neu het rounds ma khong duoc approve.
    """
    print(f"\n{C}{B}{'='*60}")
    print(f"  PHASE 2: RED vs BLUE DEBATE")
    print(f"{'='*60}{RST}\n")

    from agents.blue_team import BlueTeamAgent

    blue = BlueTeamAgent(target_url=target_url, recon_context=recon_content)

    # ── Simple state machine ──
    # Flow: RED → BLUE → (cai nhau cho den khi APPROVED)
    # Ca RED va BLUE deu co the goi [AGENT] bat ky luc nao.
    # Agent tra ket qua ve → quyen noi tra lai cho nguoi da goi Agent.
    # 1 round = RED da noi + BLUE da noi (Agent khong tinh).
    round_num = 0
    red_spoke = False
    blue_spoke = False
    next_turn = "REDTEAM"
    last_caller = "REDTEAM"    # ai goi Agent → Agent tra ve cho nguoi do

    for step in range(MAX_DEBATE_STEPS):

        # ── RED TEAM ──
        if next_turn == "REDTEAM":
            # Neu ca Red va Blue da noi → hoan thanh 1 round
            if red_spoke and blue_spoke:
                round_num += 1
                red_spoke = False
                blue_spoke = False

            if round_num >= MAX_ROUNDS:
                print(f"{R}[!] Het {MAX_ROUNDS} rounds — REJECTED.{RST}")
                raise RuntimeError(
                    f"Debate het {MAX_ROUNDS} rounds ma khong duoc approve."
                )

            print(f"\n{R}{B}══ RED TEAM — Round {round_num + 1}/{MAX_ROUNDS} ══{RST}")

            response = red.respond(conversation)
            tag = extract_next_tag(response)
            conversation.append({
                "speaker": "REDTEAM",
                "content": f"[REDTEAM]: {response}",
            })
            print(f"{R}{strip_tag(response)}{RST}")
            red_spoke = True

            if tag == "AGENT":
                last_caller = "REDTEAM"
                next_turn = "AGENT"
            else:
                next_turn = "BLUETEAM"

        # ── BLUE TEAM ──
        elif next_turn == "BLUETEAM":
            print(f"\n{C}{B}══ BLUE TEAM — Review ══{RST}")

            response = blue.respond(conversation)
            tag = extract_next_tag(response)
            conversation.append({
                "speaker": "BLUETEAM",
                "content": f"[BLUETEAM]: {response}",
            })
            print(f"{C}{strip_tag(response)}{RST}")
            blue_spoke = True

            if tag == "APPROVED":
                if round_num + 1 < MIN_DEBATE_ROUNDS:
                    # Chua du round toi thieu — ep Blue phai review them
                    print(f"\n{Y}{B}[GUARDRAIL] Round {round_num + 1}/{MIN_DEBATE_ROUNDS} "
                          f"— chua du round toi thieu, ep tiep tuc debate.{RST}")
                    conversation.append({
                        "speaker": "SYSTEM",
                        "content": (
                            "[SYSTEM]: Chua du so round toi thieu. "
                            "Ban can dat them cau hoi verify hoac yeu cau "
                            "Red Team lam ro them truoc khi approve. "
                            "Hay tiep tuc review."
                        ),
                    })
                    next_turn = "BLUETEAM"
                else:
                    print(f"\n{G}{B}══ APPROVED ══{RST}")
                    workflow = _extract_last_workflow(conversation)
                    return workflow, conversation, round_num + 1
            elif tag == "AGENT":
                last_caller = "BLUETEAM"
                next_turn = "AGENT"
            else:
                next_turn = "REDTEAM"

        # ── AGENT (culi) — ai goi thi tra ve nguoi do ──
        elif next_turn == "AGENT":
            caller_name = "Red Team" if last_caller == "REDTEAM" else "Blue Team"
            print(f"\n{G}{B}[AGENT] Dang xu ly cho {caller_name}...{RST}")

            raw = exec_agent.answer(conversation, caller=last_caller)
            data = extract_send_block(raw) or raw
            conversation.append({
                "speaker": "AGENT",
                "content": f"[AGENT]: {data}",
            })
            print(f"{G}{strip_tag(raw)}{RST}")

            # Tra quyen noi ve cho nguoi da goi Agent
            next_turn = last_caller

    # Het MAX_DEBATE_STEPS
    raise RuntimeError(
        f"Debate het {MAX_DEBATE_STEPS} steps ma khong duoc approve."
    )


def _extract_last_workflow(conversation: list[dict]) -> str:
    """Tim workflow/chien luoc tu message Red Team gan nhat.

    Scan nguoc conversation, tim message cua REDTEAM co chua:
    - "CHIEN LUOC" / "WORKFLOW" / "ATTACK PLAN" / numbered steps
    - Lay toan bo noi dung cua message do
    """
    for msg in reversed(conversation):
        if msg["speaker"] != "REDTEAM":
            continue
        content = msg["content"]
        # Tim dau hieu co chien luoc
        lower = content.lower()
        if any(kw in lower for kw in [
            "chiến lược", "chien luoc", "workflow", "attack plan",
            "bước 1", "buoc 1", "step 1",
        ]):
            # Xoa prefix [REDTEAM]: va tag cuoi
            clean = content
            if clean.startswith("[REDTEAM]:"):
                clean = clean[len("[REDTEAM]:"):].strip()
            return strip_tag(clean)
    # Fallback: lay message Red cuoi cung
    for msg in reversed(conversation):
        if msg["speaker"] == "REDTEAM":
            clean = msg["content"]
            if clean.startswith("[REDTEAM]:"):
                clean = clean[len("[REDTEAM]:"):].strip()
            return strip_tag(clean)
    raise RuntimeError("Khong tim thay workflow tu Red Team.")


# ═════════════════════════════════════════════════════════════
# PHASE 3: EXECUTION  (Agent thuc thi workflow)
# ═════════════════════════════════════════════════════════════

def phase_execute(
    exec_agent,
    workflow: str,
    conversation: list[dict],
) -> str:
    """Agent thuc thi approved workflow bang MCP tools.

    Returns:
        exec_report: bao cao thuc thi tu Agent.
    """
    print(f"\n{C}{B}{'='*60}")
    print(f"  PHASE 3: EXECUTION")
    print(f"{'='*60}{RST}\n")

    print(f"{G}{B}[AGENT] Dang thuc thi workflow...{RST}\n")

    raw = exec_agent.run_workflow(workflow, conversation)
    exec_report = extract_send_block(raw) or raw

    conversation.append({
        "speaker": "AGENT",
        "content": f"[AGENT EXEC]: {exec_report}",
    })
    print(f"{G}{strip_tag(raw)}{RST}")

    return exec_report


# ═════════════════════════════════════════════════════════════
# PHASE 4: EVALUATION  (Red danh gia ket qua)
# ═════════════════════════════════════════════════════════════

def phase_evaluate(
    red,
    exec_agent,
    exec_report: str,
    conversation: list[dict],
) -> tuple[str, str, str]:
    """Red Team danh gia ket qua thuc thi.

    Red co the:
    - [DONE] → hai long, ket thuc
    - [BLUETEAM] → de xuat chien luoc moi → quay lai debate
    - [AGENT] → hoi Agent verify (read_only mode) → roi danh gia lai

    Returns:
        (verdict, final_analysis, enriched_exec_report)
        - verdict: "SUCCESS" hoac "RETRY"
        - final_analysis: Red's evaluation text
        - enriched_exec_report: exec_report goc + agent verification data (neu co)
    """
    print(f"\n{C}{B}{'='*60}")
    print(f"  PHASE 4: EVALUATION")
    print(f"{'='*60}{RST}\n")

    # ── Switch Red sang eval mode: system prompt moi, buoc doc evidence ──
    red.switch_to_eval_mode(exec_report)

    # Inject exec_report vao conversation de Red THAY ket qua
    conversation.append({
        "speaker": "SYSTEM",
        "content": (
            "[SYSTEM — KET QUA THUC THI]\n"
            "Day la ket qua thuc thi tu Agent. "
            "Hay doc ky va danh gia dua tren evidence thuc te.\n\n"
            f"{exec_report}"
        ),
    })

    # Collect agent verification data de append vao exec_report
    agent_verification_parts: list[str] = []

    max_eval_steps = 5
    for _ in range(max_eval_steps):
        print(f"\n{R}{B}══ RED TEAM — Danh gia ket qua ══{RST}")

        response = red.respond(conversation)
        tag = extract_next_tag(response)

        conversation.append({
            "speaker": "REDTEAM",
            "content": f"[REDTEAM]: {response}",
        })
        print(f"{R}{strip_tag(response)}{RST}")

        if tag == "DONE":
            enriched = _enrich_exec_report(exec_report, agent_verification_parts)
            return "SUCCESS", strip_tag(response), enriched
        elif tag == "AGENT":
            # Red hoi Agent verify — READ_ONLY mode (khong cho exploit lai)
            print(f"\n{G}{B}[AGENT] Dang verify cho Red Team (read-only)...{RST}")
            raw = exec_agent.answer(conversation, caller="REDTEAM",
                                    read_only=True)
            data = extract_send_block(raw) or raw
            agent_verification_parts.append(data)
            conversation.append({
                "speaker": "AGENT",
                "content": f"[AGENT]: {data}",
            })
            print(f"{G}{strip_tag(raw)}{RST}")
            continue
        elif tag == "BLUETEAM":
            # Red muon de xuat chien luoc moi → can debate lai
            enriched = _enrich_exec_report(exec_report, agent_verification_parts)
            return "RETRY", strip_tag(response), enriched
        else:
            # Khong ro → coi nhu DONE
            enriched = _enrich_exec_report(exec_report, agent_verification_parts)
            return "SUCCESS", strip_tag(response), enriched

    enriched = _enrich_exec_report(exec_report, agent_verification_parts)
    return "SUCCESS", strip_tag(response), enriched


def _enrich_exec_report(
    exec_report: str,
    agent_parts: list[str],
) -> str:
    """Noi exec_report goc voi agent verification data."""
    if not agent_parts:
        return exec_report
    separator = "\n\n--- AGENT VERIFICATION (Phase 4) ---\n\n"
    return exec_report + separator + "\n\n".join(agent_parts)


# ═════════════════════════════════════════════════════════════
# PHASE 5: REPORT
# ═════════════════════════════════════════════════════════════

def phase_report(
    target_url: str,
    verdict: str,
    workflow: str,
    exec_report: str,
    red_evaluation: str,
    debate_rounds: int,
    run_dir: str,
):
    """Luu report cuoi cung ra file."""
    print(f"\n{C}{B}{'='*60}")
    print(f"  PHASE 5: REPORT")
    print(f"{'='*60}{RST}\n")

    icon = "✅" if verdict == "SUCCESS" else "❌"
    print(f"{B}Target:{RST}  {target_url}")
    print(f"{B}Verdict:{RST} {icon} {verdict}")
    print(f"{B}Debate rounds:{RST} {debate_rounds}")

    if exec_report:
        print(f"\n{B}Execution Output (truncated):{RST}")
        print(exec_report[:3000])

    # ── Save file ──
    report_path = Path(run_dir) / "report.md"

    report_md = f"""# MARL Penetration Test Report
**Target:** {target_url}
**Verdict:** {icon} {verdict}
**Debate rounds:** {debate_rounds}

## Approved Attack Workflow
{workflow}

## Execution Report
```
{exec_report or "N/A"}
```

## Red Team Evaluation
{red_evaluation}
"""
    report_path.write_text(report_md, encoding="utf-8")
    print(f"\n{G}[+] Report saved: {report_path.resolve()}{RST}")


# ═════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════

def main():
    banner()

    user_prompt = get_user_prompt()

    # ── Parse target URL to create per-target workspace dir ──
    target_url_early, _ = parse_prompt(user_prompt)
    if not target_url_early:
        print(f"{R}[!] Khong tim thay URL trong prompt.{RST}")
        return
    run_dir = _make_run_dir(target_url_early)

    # ── Setup logging — mirror all console output to run_dir/marl.log ──
    log_path = setup_logging(run_dir)
    print(f"{G}[+] Run directory: {run_dir}{RST}")
    print(f"{G}[+] Logging to: {log_path}{RST}\n")

    # ── Phase 1: Recon ──
    try:
        target_url, recon_path, recon_content = phase_recon(user_prompt, run_dir)
    except Exception as e:
        print(f"\n{R}[!] Recon failed: {e}{RST}")
        return

    # ── Phase 2–4: Debate → Execute → Evaluate (loop) ──
    exec_agent = None
    try:
        from agents.exec_agent import ExecAgent
        from agents.red_team import RedTeamAgent

        exec_agent = ExecAgent(
            working_dir=run_dir,
            target_url=target_url,
            recon_md=recon_path,
        )

        red = RedTeamAgent(target_url=target_url, recon_context=recon_content)
        conversation: list[dict] = [
            {"speaker": "USER", "content": f"[USER]: {user_prompt}"},
        ]
        verdict = "REJECTED"
        workflow = ""
        exec_report = ""
        red_evaluation = ""
        total_debate_rounds = 0

        for attempt in range(1, MAX_EXEC_RETRIES + 2):
            if attempt > 1:
                print(f"\n{Y}{B}══ RETRY #{attempt - 1} — Red de xuat chien luoc"
                      f" moi ══{RST}")

            # Phase 2: Debate (conversation duoc giu lai giua retries)
            workflow, conversation, round_num = phase_debate(
                target_url, recon_content,
                exec_agent, red, conversation,
            )
            total_debate_rounds += round_num

            # Phase 3: Execute
            exec_report = phase_execute(exec_agent, workflow, conversation)

            # Phase 4: Evaluate
            verdict, red_evaluation, exec_report = phase_evaluate(
                red, exec_agent, exec_report, conversation,
            )

            if verdict == "SUCCESS":
                break
            elif verdict == "RETRY" and attempt <= MAX_EXEC_RETRIES:
                print(f"\n{Y}[!] Red Team muon thu chien luoc moi.{RST}")
                continue
            else:
                break

        # Phase 5: Report
        phase_report(
            target_url=target_url,
            verdict=verdict,
            workflow=workflow,
            exec_report=exec_report,
            red_evaluation=red_evaluation,
            debate_rounds=total_debate_rounds,
            run_dir=run_dir,
        )

    except RuntimeError as e:
        print(f"\n{R}[!] Pipeline: {e}{RST}")
    except Exception as e:
        print(f"\n{R}[!] Pipeline failed: {e}{RST}")
        import traceback
        traceback.print_exc()
    finally:
        if exec_agent:
            try:
                exec_agent.shutdown()
            except Exception:
                pass
        print(f"\n{G}[+] Full session log: {log_path}{RST}")


if __name__ == "__main__":
    main()
