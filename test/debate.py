"""
MARL Debate — Red Team vs Blue Team + Executor Agent (Culi).

Luong:
  1. User nhap prompt → Executor crawl (bat het request/response, loc rac) → gui conversation
  2. REDTEAM doc data, co the hoi Agent them → viet exploit → gui BLUETEAM
  3. BLUETEAM review gat gao, reject/approved → neu reject → REDTEAM sua
  4. Sau APPROVED → Agent nhan exploit, ghi file, chay, tra ket qua ve REDTEAM
  5. Chi REDTEAM <-> Agent giao tiep. BLUETEAM khong biet Agent ton tai.

Tag system:
  [REDTEAM]  = chuyen cho Red Team
  [BLUETEAM] = chuyen cho Blue Team
  [AGENT]    = Red Team goi Agent (chi Red duoc goi)
  [APPROVED] = Blue Team chap nhan exploit
"""

import os
from openai import OpenAI
from agent import ExecutorAgent, extract_send_block, extract_next_tag, strip_tag, _truncate

# ── Colors ──
R = "\033[91m"   # red
B = "\033[94m"   # blue
G = "\033[92m"   # green
YELLOW = "\033[93m"
Y = "\033[93m"   # yellow
BOLD = "\033[1m"
DIM = "\033[2m"
RST = "\033[0m"

# ── Config ──
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "gho_token")
SERVER_URL = os.getenv("MARL_SERVER_URL", "http://127.0.0.1:5000/v1")
MODEL_RED  = os.getenv("MARL_RED_MODEL", "gpt-5-mini")
MODEL_BLUE = os.getenv("MARL_BLUE_MODEL", "gpt-5-mini")

# Max chars per message in conversation (prevent token overflow on small models)
MAX_MSG_CHARS = 6000

client = OpenAI(api_key=GITHUB_TOKEN, base_url=SERVER_URL)

MAX_ROUNDS = 5
MAX_STEPS = 30

# ═══════════════════════════════════════════════════════════════
# PROMPTS
# ═══════════════════════════════════════════════════════════════

RED_PROMPT = """Ban la Penetration Tester (Red Team). Phan tich du lieu crawl, tim lo hong BAC/BLF, viet PoC Python chay duoc ngay.

QUY TAC:
- Tap trung 1 kich ban tot nhat moi luot.
- Bi reject → doi huong, KHONG lap lai.
- Can them thong tin → goi Agent bang [AGENT].
- PoC Python PHAI tu dong hoan toan: tu login lay session moi, tu lay CSRF token, roi exploit.
  KHONG BAO GIO hardcode cookie/session/CSRF tu data crawl — chung se het han.
- PoC KHONG duoc dung input()/stdin — Agent chay tu dong, khong the nhap interactive.

TAG CUOI (bat buoc, dong cuoi):
- Gui PoC cho Blue → [BLUETEAM]
- Hoi Agent → [AGENT]
- KHONG BAO GIO ket thuc bang [REDTEAM]"""

BLUE_PROMPT = """Ban la Security Reviewer (Blue Team). Danh gia PoC cua Red Team — cong tam, kho tinh.

TIEU CHI: Logic hop ly? Code chay duoc? Endpoint dung voi data crawl? Lo hong that hay behavior binh thuong?

FLOW: Sau khi ban APPROVED, Agent se TU DONG chay PoC va bao ket qua. Ban KHONG can yeu cau "chay thu truoc" — do la buoc tiep theo sau approve. Nhiem vu cua ban CHI LA review code.

QUY TAC:
- DOC KY TOAN BO code Python truoc khi danh gia — code co the dai, doc het roi moi nhan xet.
- Endpoint/param khong co trong data crawl → REJECT.
- Logic giong lan truoc bi reject → REJECT, yeu cau huong KHAC.
- PoC PHAI tu login (tao session moi), KHONG hardcode cookie/session tu data crawl → REJECT.
- PoC PHAI tu lay CSRF token moi, KHONG hardcode CSRF tu data crawl → REJECT.
- Neu PoC DA tu login va tu lay CSRF dong, KHONG reject vi ly do "hardcode".
- PoC KHONG duoc dung input()/stdin — Agent khong the nhap interactive. Dung constant/hardcode cho lab.
- Ban la BLUE TEAM. KHONG roleplay thanh Agent hay Red Team. Chi review va tra loi.

TAG CUOI (bat buoc, dong cuoi):
- Reject → [REDTEAM]
- Approved → [APPROVED]
- KHONG BAO GIO ket thuc bang [BLUETEAM]"""


# ═══════════════════════════════════════════════════════════════
# LLM CALL
# ═══════════════════════════════════════════════════════════════

def _truncate(text: str, limit: int = MAX_MSG_CHARS) -> str:
    """Truncate text to limit chars, keeping head + tail."""
    if len(text) <= limit:
        return text
    half = limit // 2
    return text[:half] + f"\n\n... [truncated {len(text) - limit} chars] ...\n\n" + text[-half:]


def _estimate_tokens(text: str) -> int:
    """Rough token estimate: ~4 chars per token for English, ~2 for code-heavy."""
    return len(text) // 3


# Token budget per model (leave room for response)
_TOKEN_BUDGETS = {
    "REDTEAM": 25000,   # gpt-4o has 128k context
    "BLUETEAM": 9000,   # gpt-4o-mini has 12288 token limit
}


def build_messages(agent: str, conversation: list[dict]) -> list[dict]:
    """Build messages cho agent. Speaker = agent → assistant, khac → user."""
    prompt = RED_PROMPT if agent == "REDTEAM" else BLUE_PROMPT
    msgs = [{"role": "system", "content": prompt}]

    # Filter conversation for this agent
    filtered = []
    for msg in conversation:
        if agent == "BLUETEAM" and msg["speaker"] == "AGENT":
            continue
        filtered.append(msg)

    # Build raw content list (newest first for priority truncation)
    budget = _TOKEN_BUDGETS.get(agent, 25000)
    used = _estimate_tokens(prompt) + 50  # system prompt + overhead
    entries = []  # (role, content) pairs

    for i, msg in enumerate(filtered):
        role = "assistant" if msg["speaker"] == agent else "user"
        content = msg["content"]
        # Always truncate older messages (all except last 3)
        if i < len(filtered) - 3:
            content = _truncate(content)
        entries.append((role, content))

    # If still over budget, progressively truncate from oldest
    total_est = used + sum(_estimate_tokens(c) for _, c in entries)
    if total_est > budget:
        for i in range(len(entries)):
            role, content = entries[i]
            truncated = _truncate(content, limit=1500)
            saved = _estimate_tokens(content) - _estimate_tokens(truncated)
            entries[i] = (role, truncated)
            total_est -= saved
            if total_est <= budget:
                break

    for role, content in entries:
        msgs.append({"role": role, "content": content})

    # Dam bao message cuoi la "user" (Copilot API requirement)
    if not msgs or msgs[-1]["role"] != "user":
        msgs.append({"role": "user", "content": "Tiep tuc."})

    return msgs


def call_llm(agent: str, conversation: list[dict]) -> str:
    """Goi LLM cho Red/Blue, tra ve raw text."""
    color = R if agent == "REDTEAM" else B
    label = "RED TEAM" if agent == "REDTEAM" else "BLUE TEAM"

    print(f"\n{color}{BOLD}[{label}] Dang suy nghi...{RST}")

    msgs = build_messages(agent, conversation)
    model = MODEL_RED if agent == "REDTEAM" else MODEL_BLUE
    try:
        resp = client.chat.completions.create(
            model=model, messages=msgs, temperature=0.7, max_tokens=8192,
        )
    except Exception as e:
        if "token" in str(e).lower() and "exceed" in str(e).lower():
            # Token limit exceeded — aggressively truncate and retry
            print(f"{YELLOW}[!] Token limit, truncating conversation...{RST}")
            for i in range(len(msgs) - 1, 0, -1):
                msgs[i]["content"] = _truncate(msgs[i]["content"], limit=800)
            resp = client.chat.completions.create(
                model=model, messages=msgs, temperature=0.7, max_tokens=4096,
            )
        else:
            raise
    raw = resp.choices[0].message.content

    # Append vao conversation
    conversation.append({"speaker": agent, "content": f"[{agent}]: {raw}"})

    print(f"{color}{BOLD}[{label}]:{RST}\n{color}{strip_tag(raw)}{RST}")
    return raw


# ═══════════════════════════════════════════════════════════════
# EXECUTOR CALLS (chi REDTEAM duoc goi)
# ═══════════════════════════════════════════════════════════════

def exec_crawl(executor: ExecutorAgent, user_prompt: str) -> str:
    """Phase 1: Crawl target."""
    print(f"\n{G}{BOLD}[AGENT] Dang crawl target...{RST}")
    raw = executor.crawl(user_prompt)
    data = extract_send_block(raw) or raw

    # Preview: show first 50 lines + stats
    lines = data.splitlines()
    total_lines = len(lines)
    preview = "\n".join(lines[:50])
    if total_lines > 50:
        preview += f"\n{DIM}... ({total_lines - 50} dong con lai da luoc bot trong preview){RST}"

    # Count requests in data (lines starting with "REQUEST:")
    request_count = sum(1 for l in lines if l.strip().startswith("REQUEST:"))

    print(f"{G}{BOLD}[AGENT CRAWL] ({total_lines} dong, ~{request_count} requests):{RST}")
    print(f"{G}{preview}{RST}")

    return data


def exec_filter(executor: ExecutorAgent, crawl_data: str) -> str:
    """Filter + rank crawl data using Executor LLM."""
    print(f"\n{G}{BOLD}[AGENT] Dang loc va xep hang traffic...{RST}")
    raw = executor.filter_traffic(crawl_data)
    data = extract_send_block(raw) or raw

    lines = data.splitlines()
    total_lines = len(lines)
    preview = "\n".join(lines[:30])
    if total_lines > 30:
        preview += f"\n{DIM}... ({total_lines - 30} dong con lai da luoc bot trong preview){RST}"

    print(f"{G}{BOLD}[AGENT FILTER] ({total_lines} dong):{RST}")
    print(f"{G}{preview}{RST}")

    return data


def exec_answer(executor: ExecutorAgent, conversation: list[dict]) -> str:
    """Red Team hoi Agent mot cau hoi."""
    print(f"\n{G}{BOLD}[AGENT] Dang tra loi cau hoi cua Red Team...{RST}")
    raw = executor.answer(conversation, caller="REDTEAM")
    data = extract_send_block(raw) or raw
    conversation.append({"speaker": "AGENT", "content": f"[AGENT]: {data}"})
    print(f"{G}{BOLD}[AGENT]:{RST}\n{G}{strip_tag(raw)}{RST}")
    return data


def exec_run(executor: ExecutorAgent, conversation: list[dict]) -> str:
    """Agent chay exploit (sau khi APPROVED)."""
    print(f"\n{G}{BOLD}[AGENT] Dang thuc thi exploit...{RST}")
    raw = executor.process(conversation, caller="REDTEAM")
    data = extract_send_block(raw) or raw
    conversation.append({"speaker": "AGENT", "content": f"[AGENT KET QUA THUC THI]:\n{data}"})
    print(f"{G}{BOLD}[AGENT KET QUA]:{RST}\n{G}{strip_tag(raw)}{RST}")
    return data


# ═══════════════════════════════════════════════════════════════
# MAIN LOOP
# ═══════════════════════════════════════════════════════════════

def run_debate():
    print(f"""{BOLD}{'='*60}
  MARL DEBATE — Red Team vs Blue Team
{'='*60}{RST}
{R}  Red Team:  Attacker (viet PoC, giao tiep voi Agent){RST}
{B}  Blue Team: Reviewer (danh gia kho tinh){RST}
{G}  Agent:     Crawler + Executor (chi Red Team goi duoc){RST}
""")

    executor = ExecutorAgent()
    conversation: list[dict] = []

    # ── PHA 1: CRAWL ──
    print(f"{BOLD}{'='*60}\n  PHA 1: CRAWL & RECONNAISSANCE\n{'='*60}{RST}")
    user_prompt = input(f"{Y}{BOLD}[BAN] Nhap prompt (URL + context): {RST}").strip()
    if not user_prompt:
        executor.shutdown()
        return

    crawl_data = exec_crawl(executor, user_prompt)
    crawl_data = exec_filter(executor, crawl_data)

    # Seed conversation — ca Red va Blue deu thay crawl data
    conversation.append({"speaker": "USER", "content": f"[USER]: {user_prompt}"})
    conversation.append({"speaker": "AGENT", "content": f"[AGENT CRAWL]:\n{crawl_data}"})

    # ── PHA 2: DEBATE ──
    print(f"\n{BOLD}{'='*60}\n  PHA 2: RED vs BLUE DEBATE\n{'='*60}{RST}")

    round_num = 0
    step = 0
    agent_calls = 0          # consecutive Agent calls tracker
    MAX_AGENT_CALLS = 3       # max consecutive Agent calls before forcing PoC
    next_turn = "REDTEAM"  # Red luon bat dau

    while step < MAX_STEPS:
        step += 1

        # ── REDTEAM turn ──
        if next_turn == "REDTEAM":
            round_num += 1
            if round_num > MAX_ROUNDS:
                print(f"\n{BOLD}[!] Da dat gioi han {MAX_ROUNDS} vong. Ket thuc.{RST}")
                break

            print(f"\n{BOLD}{'─'*60}\n  VONG {round_num}/{MAX_ROUNDS}\n{'─'*60}{RST}")

            raw = call_llm("REDTEAM", conversation)
            tag = extract_next_tag(raw)

            if tag == "AGENT":
                agent_calls += 1
                if agent_calls > MAX_AGENT_CALLS:
                    # Force Red to write PoC — inject system nudge
                    print(f"\n{Y}[!] Da goi Agent {MAX_AGENT_CALLS} lan lien tiep. Buoc Red Team viet PoC.{RST}")
                    conversation.append({
                        "speaker": "USER",
                        "content": "[SYSTEM]: Ban da hoi Agent nhieu lan. Hay viet PoC dua tren thong tin da co va gui cho Blue Team. KHONG goi Agent them."
                    })
                    agent_calls = 0
                    next_turn = "REDTEAM"
                    round_num -= 1
                else:
                    # Red hoi Agent → Agent tra loi → quay lai Red (khong tang round)
                    exec_answer(executor, conversation)
                    next_turn = "REDTEAM"
                    round_num -= 1  # bu lai vi dau turn da tang
            else:
                # Red gui PoC cho Blue review
                agent_calls = 0   # reset counter
                next_turn = "BLUETEAM"

        # ── BLUETEAM turn ──
        elif next_turn == "BLUETEAM":
            raw = call_llm("BLUETEAM", conversation)

            if "[APPROVED]" in raw:
                print(f"\n{BOLD}{'='*60}")
                print(f"  BLUE TEAM APPROVED! Chuyen exploit cho Agent thuc thi...")
                print(f"{'='*60}{RST}")

                # Agent chay exploit → ket qua ve REDTEAM
                exec_run(executor, conversation)

                # Red Team danh gia ket qua
                print(f"\n{BOLD}{'─'*60}\n  RED TEAM DANH GIA KET QUA\n{'─'*60}{RST}")
                red_eval = call_llm("REDTEAM", conversation)
                red_tag = extract_next_tag(red_eval)

                if red_tag == "BLUETEAM":
                    # Red gui PoC moi → tiep tuc debate (exec fail, Red muon thu lai)
                    agent_calls = 0   # reset agent counter for new PoC cycle
                    next_turn = "BLUETEAM"
                elif red_tag == "AGENT":
                    # Red can Agent giup debug → reset counter, quay lai Red
                    agent_calls = 0   # fresh quota after exec
                    next_turn = "REDTEAM"
                    round_num -= 1  # bu lai round
                    # Red hai long hoac het y → ket thuc
                    break
            else:
                # Blue reject → Red sua
                next_turn = "REDTEAM"

        # ── Fallback ──
        else:
            next_turn = "REDTEAM"

    # ── KET THUC ──
    print(f"\n{BOLD}{'='*60}\n  DEBATE KET THUC\n{'='*60}{RST}")
    executor.shutdown()


if __name__ == "__main__":
    run_debate()
