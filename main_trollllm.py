"""
MARL Orchestrator (TrollLLM Version) — Entry point dung TrollLLM API.

Day la ban main.py su dung TrollLLM API (chat.trollllm.xyz) thay vi Copilot.
Tat ca agents se goi den local proxy server_trollllm.py.

Flow:
  Phase 1: RECON — CrawlAgent crawl target → recon.md
  Phase 2: DEBATE — Red ↔ Blue tranh luan, ca hai co the goi Agent
           Red viet chien luoc tan cong → Blue review → reject/approve
  Phase 3: EXECUTION — Agent thuc thi workflow da duoc approve
  Phase 4: EVALUATION — Red danh gia ket qua, co the de xuat chien luoc moi
  Phase 5: REPORT — Luu ket qua cuoi cung

Usage:
    # Truoc het, chay server:
    export TROLLLLM_API_KEY="sk-trollllm-xxx"
    python server/server_trollllm.py

    # Sau do chay main:
    python main_trollllm.py
    python main_trollllm.py "Test https://target.com user:admin pass:secret"

Environment variables:
    TROLLLLM_API_KEY     - API key cho TrollLLM (bat buoc)
    MARL_SERVER_URL      - URL cua proxy server (default: http://127.0.0.1:5001/v1)
    MARL_CRAWL_MODEL     - Model cho CrawlAgent (default: gpt-5-mini)
    MARL_EXECUTOR_MODEL  - Model cho ExecAgent (default: gpt-5-mini)
    MARL_RED_MODEL       - Model cho RedTeamAgent (default: gpt-5-mini)
    MARL_BLUE_MODEL      - Model cho BlueTeamAgent (default: gpt-5-mini)
"""

import os
import sys
from pathlib import Path

# ═══════════════════════════════════════════════════════════════
# SET DEFAULT ENV VARS FOR TROLLLLM
# ═══════════════════════════════════════════════════════════════
# Phai set TRUOC khi import agents vi chung doc env luc import

# Default server URL cho TrollLLM proxy (port 5001)
if "MARL_SERVER_URL" not in os.environ:
    os.environ["MARL_SERVER_URL"] = "http://127.0.0.1:5001/v1"

# Default models cho TrollLLM
DEFAULT_MODEL = "gpt-5-mini"

if "MARL_CRAWL_MODEL" not in os.environ:
    os.environ["MARL_CRAWL_MODEL"] = DEFAULT_MODEL

if "MARL_EXECUTOR_MODEL" not in os.environ:
    os.environ["MARL_EXECUTOR_MODEL"] = DEFAULT_MODEL

if "MARL_RED_MODEL" not in os.environ:
    os.environ["MARL_RED_MODEL"] = DEFAULT_MODEL

if "MARL_BLUE_MODEL" not in os.environ:
    os.environ["MARL_BLUE_MODEL"] = DEFAULT_MODEL

# ═══════════════════════════════════════════════════════════════
# IMPORTS (sau khi set env vars)
# ═══════════════════════════════════════════════════════════════

from shared.utils import parse_prompt, extract_next_tag, extract_send_block

WORKSPACE = "./workspace"
MAX_DEBATE_STEPS = 30          # tong so turn toi da (Red + Blue + Agent)
MAX_ROUNDS = 5                 # so round Red↔Blue reject/revise toi da
MAX_AGENT_CONSECUTIVE = 3      # so lan lien tiep goi Agent truoc khi ep chuyen
MAX_EXEC_RETRIES = 2           # so lan cho Red de xuat chien luoc moi sau exec fail

# ── ANSI colors ──────────────────────────────────────────────
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
C = "\033[96m"
B = "\033[1m"
RST = "\033[0m"


# ═════════════════════════════════════════════════════════════
# HELPERS
# ═════════════════════════════════════════════════════════════

def banner():
    print(f"""{C}{B}
    ╔══════════════════════════════════════════════════════╗
    ║   MARL — Multi-Agent Red-team LLM (TrollLLM)         ║
    ║   Penetration Testing via Debate                      ║
    ╠══════════════════════════════════════════════════════╣
    ║   API: {os.environ.get('MARL_SERVER_URL', 'http://127.0.0.1:5001/v1'):<40} ║
    ║   Model: {DEFAULT_MODEL:<38} ║
    ╚══════════════════════════════════════════════════════╝{RST}
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
    import re
    return re.sub(
        r"\[(?:REDTEAM|BLUETEAM|AGENT(?::run)?|APPROVED|DONE)\]\s*$",
        "", text, flags=re.IGNORECASE,
    ).rstrip()


# ═════════════════════════════════════════════════════════════
# PHASE 1: RECON
# ═════════════════════════════════════════════════════════════

def phase_recon(user_prompt: str) -> tuple[str, str, str]:
    """CrawlAgent crawl target → (target_url, recon_path, recon_content)."""
    print(f"\n{C}{B}{'='*60}")
    print(f"  PHASE 1: RECON")
    print(f"{'='*60}{RST}\n")

    from agents.crawl_agent import CrawlAgent

    target_url, _ = parse_prompt(user_prompt)
    if not target_url:
        raise ValueError("Khong tim thay URL trong prompt.")

    crawl = CrawlAgent(working_dir=WORKSPACE)
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

    Args:
        target_url: URL target.
        recon_content: Noi dung recon.md.
        exec_agent: ExecAgent instance (shared across phases).
        red: RedTeamAgent instance (shared across retries).
        conversation: Conversation (co the co history tu retry truoc).

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

    step = 0
    round_num = 0
    agent_consecutive = 0   # dem so lan lien tiep goi Agent
    next_turn = "REDTEAM"   # Red luon bat dau

    while step < MAX_DEBATE_STEPS:
        step += 1

        # ── RED TEAM turn ──
        if next_turn == "REDTEAM":
            round_num += 1
            agent_consecutive = 0
            print(f"\n{R}{B}══ RED TEAM — Round {round_num}/{MAX_ROUNDS} ══{RST}")

            if round_num > MAX_ROUNDS:
                print(f"{R}[!] Het {MAX_ROUNDS} rounds — REJECTED.{RST}")
                raise RuntimeError(
                    f"Debate het {MAX_ROUNDS} rounds ma khong duoc approve."
                )

            response = red.respond(conversation)
            tag = extract_next_tag(response)

            conversation.append({
                "speaker": "REDTEAM",
                "content": f"[REDTEAM]: {response}",
            })
            print(f"{R}{strip_tag(response)}{RST}")

            if tag == "AGENT":
                next_turn = "AGENT_FOR_RED"
            elif tag == "BLUETEAM":
                next_turn = "BLUETEAM"
            elif tag == "DONE":
                # Red tu ket thuc (hiem — thuong chi sau exec)
                print(f"\n{G}[+] Red Team ket thuc.{RST}")
                raise RuntimeError(
                    "Red Team ket thuc truoc khi co workflow duoc approve."
                )
            else:
                # Khong co tag ro rang → ep gui Blue
                next_turn = "BLUETEAM"

        # ── BLUE TEAM turn ──
        elif next_turn == "BLUETEAM":
            agent_consecutive = 0
            print(f"\n{C}{B}══ BLUE TEAM — Review ══{RST}")

            response = blue.respond(conversation)
            tag = extract_next_tag(response)

            conversation.append({
                "speaker": "BLUETEAM",
                "content": f"[BLUETEAM]: {response}",
            })
            print(f"{C}{strip_tag(response)}{RST}")

            if tag == "APPROVED":
                print(f"\n{G}{B}══ APPROVED ══{RST}")
                workflow = _extract_last_workflow(conversation)
                return workflow, conversation, round_num
            elif tag == "AGENT":
                next_turn = "AGENT_FOR_BLUE"
            elif tag == "REDTEAM":
                next_turn = "REDTEAM"
            else:
                # Khong ro tag → mac dinh tra ve Red sua
                next_turn = "REDTEAM"

        # ── AGENT turn (goi boi Red) ──
        elif next_turn == "AGENT_FOR_RED":
            agent_consecutive += 1
            print(f"\n{G}{B}[AGENT] Dang xu ly cho Red Team...{RST}")

            raw = exec_agent.answer(conversation, caller="REDTEAM")
            data = extract_send_block(raw) or raw

            conversation.append({
                "speaker": "AGENT",
                "content": f"[AGENT]: {data}",
            })
            print(f"{G}{strip_tag(raw)}{RST}")

            if agent_consecutive >= MAX_AGENT_CONSECUTIVE:
                print(f"{Y}[!] {MAX_AGENT_CONSECUTIVE} Agent calls lien tiep"
                      f" — ep Red viet chien luoc.{RST}")
            next_turn = "REDTEAM"

        # ── AGENT turn (goi boi Blue) ──
        elif next_turn == "AGENT_FOR_BLUE":
            agent_consecutive += 1
            print(f"\n{G}{B}[AGENT] Dang xu ly cho Blue Team...{RST}")

            raw = exec_agent.answer(conversation, caller="BLUETEAM")
            data = extract_send_block(raw) or raw

            conversation.append({
                "speaker": "AGENT",
                "content": f"[AGENT]: {data}",
            })
            print(f"{G}{strip_tag(raw)}{RST}")

            if agent_consecutive >= MAX_AGENT_CONSECUTIVE:
                print(f"{Y}[!] {MAX_AGENT_CONSECUTIVE} Agent calls lien tiep"
                      f" — ep Blue ra quyet dinh.{RST}")
            next_turn = "BLUETEAM"

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
) -> tuple[str, str]:
    """Red Team danh gia ket qua thuc thi.

    Red co the:
    - [DONE] → hai long, ket thuc
    - [BLUETEAM] → de xuat chien luoc moi → quay lai debate
    - [AGENT] → hoi Agent them → roi danh gia lai

    Returns:
        (verdict, final_analysis)
        - verdict: "SUCCESS" hoac "RETRY"
        - final_analysis: Red's evaluation text
    """
    print(f"\n{C}{B}{'='*60}")
    print(f"  PHASE 4: EVALUATION")
    print(f"{'='*60}{RST}\n")

    # Them exec_report vao conversation de Red thay
    # (da append trong phase_execute roi — Red se thay tu conversation)

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
            return "SUCCESS", strip_tag(response)
        elif tag == "AGENT":
            # Red hoi Agent them
            print(f"\n{G}{B}[AGENT] Dang xu ly cho Red Team...{RST}")
            raw = exec_agent.answer(conversation, caller="REDTEAM")
            data = extract_send_block(raw) or raw
            conversation.append({
                "speaker": "AGENT",
                "content": f"[AGENT]: {data}",
            })
            print(f"{G}{strip_tag(raw)}{RST}")
            continue
        elif tag == "BLUETEAM":
            # Red muon de xuat chien luoc moi → can debate lai
            return "RETRY", strip_tag(response)
        else:
            # Khong ro → coi nhu DONE
            return "SUCCESS", strip_tag(response)

    return "SUCCESS", strip_tag(response)


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
    ws = Path(WORKSPACE)
    ws.mkdir(parents=True, exist_ok=True)
    report_path = ws / "report.md"

    report_md = f"""# MARL Penetration Test Report (TrollLLM)
**Target:** {target_url}
**Verdict:** {icon} {verdict}
**Debate rounds:** {debate_rounds}
**Model:** {DEFAULT_MODEL}

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

    # Check API key
    api_key = os.environ.get("TROLLLLM_API_KEY", "")
    if not api_key:
        print(f"""{Y}
╔══════════════════════════════════════════════════════════════╗
║  WARNING: TROLLLLM_API_KEY not set!                          ║
║  Set it via environment variable:                            ║
║    export TROLLLLM_API_KEY="sk-trollllm-xxx"                 ║
╚══════════════════════════════════════════════════════════════╝
{RST}""")

    user_prompt = get_user_prompt()

    # ── Phase 1: Recon ──
    try:
        target_url, recon_path, recon_content = phase_recon(user_prompt)
    except Exception as e:
        print(f"\n{R}[!] Recon failed: {e}{RST}")
        return

    # ── Phase 2–4: Debate → Execute → Evaluate (loop) ──
    exec_agent = None
    try:
        from agents.exec_agent import ExecAgent
        from agents.red_team import RedTeamAgent

        exec_agent = ExecAgent(
            working_dir=WORKSPACE,
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
            verdict, red_evaluation = phase_evaluate(
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


if __name__ == "__main__":
    main()
