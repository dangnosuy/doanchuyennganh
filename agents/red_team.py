"""
RedTeamAgent — Module Red Team cho MARL.

Red = Chien luoc gia: phan tich recon, viet attack workflow cho Agent thuc thi.
Red co the goi Agent de tim them ngu canh (tag [AGENT]).
Red viet chien luoc xong gui Blue review (tag [BLUETEAM]).

Tag system:
  [AGENT]     — Red hoi Agent (navigate, check endpoint, tim them info...)
  [BLUETEAM]  — Red gui chien luoc cho Blue review
  [DONE]      — Red ket thuc (sau khi danh gia ket qua thuc thi)

Khac debate.py cu:
- Tach rieng module, khong phu thuoc main loop
- respond() xu ly 1 turn, main.py goi nhieu lan trong debate loop
- Khong co self-contained run() loop nua

Usage (tu main.py):
    red = RedTeamAgent(target_url="...", recon_context="...")
    text = red.respond(conversation, exec_agent)
    tag  = extract_next_tag(text)  # "AGENT" | "BLUETEAM" | "DONE"
"""

import os
import re
import sys
from pathlib import Path

from openai import OpenAI

# ── Dam bao project root tren sys.path ──
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from shared.utils import extract_next_tag, extract_send_block, truncate
from knowledge.bac_blf_playbook import get_playbook_text

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / ".env")


# ── Import type hints only ──
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from agents.exec_agent import ExecAgent


# ═══════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "gho_token")
SERVER_URL = os.getenv("MARL_SERVER_URL", "http://127.0.0.1:5000/v1")
MODEL = os.getenv("MARL_RED_MODEL", "gpt-5-mini")
PROMPT_PATH = "prompts/red"

# Colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Limits
MAX_TAG_RETRIES = 2     # Nudge LLM neu thieu tag
MAX_MSG_CHARS = 6000    # Truncate message cu


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
# SYSTEM PROMPT — Red = Chien luoc gia
# ═══════════════════════════════════════════════════════════════

RED_PROMPT = load_prompt("red")

# ═══════════════════════════════════════════════════════════════
# EVAL PROMPT — Red dùng ở Phase 4 đánh giá kết quả
# ═══════════════════════════════════════════════════════════════

RED_EVAL_PROMPT = load_prompt("red_eval")

# ═══════════════════════════════════════════════════════════════
# RED TEAM AGENT CLASS
# ═══════════════════════════════════════════════════════════════

class RedTeamAgent:
    """Red Team chiến lược gia — phân tích recon, viết attack workflow,
    gọi Agent tìm thêm info, gửi Blue review."""

    def __init__(
        self,
        target_url: str,
        recon_context: str,
        *,
        model: str | None = None,
    ):
        """
        Args:
            target_url: URL cua target website.
            recon_context: Recon data (recon.md content).
            model: LLM model override. Default: env MARL_RED_MODEL or gpt-5-mini.
        """
        self.target_url = target_url
        self.recon_context = recon_context
        self.model = model or MODEL
        self.client = OpenAI(api_key=GITHUB_TOKEN, base_url=SERVER_URL)

        # System prompt — bake target_url + recon_context + playbook vao
        self.system_prompt = RED_PROMPT.format(
            target_url=self.target_url,
            recon_context=truncate(self.recon_context),
            playbook=get_playbook_text(),
        )

        print(f"\n{RED}{BOLD}[RED-TEAM] Khoi tao — model={self.model}{RESET}")
        print(f"{RED}[RED-TEAM] Target: {self.target_url}{RESET}")
        print(f"{RED}[RED-TEAM] Recon: {len(self.recon_context)} chars{RESET}")

    # ─── Public API ──────────────────────────────────────────────

    def switch_to_eval_mode(self, exec_report: str):
        """Chuyen sang eval mode — dung RED_EVAL_PROMPT thay vi RED_PROMPT.

        Goi truoc khi dung respond() o Phase 4.
        """
        self.system_prompt = RED_EVAL_PROMPT.format(
            target_url=self.target_url,
            exec_report=truncate(exec_report),
        )
        print(f"{RED}{BOLD}[RED-TEAM] Switched to EVAL mode{RESET}")

    def respond(self, conversation: list[dict]) -> str:
        """Xu ly 1 turn cua Red Team.

        Doc conversation (chua history cua debate), goi LLM 1 turn.
        Caller (main.py) se doc tag de route tiep.

        Args:
            conversation: Shared debate conversation
                          (list of {"speaker": ..., "content": ...}).

        Returns:
            Raw Red Team response text. Caller dung extract_next_tag()
            de lay tag: "AGENT" | "BLUETEAM" | "DONE".
        """
        messages = self._build_messages(conversation)

        # Tag retry loop
        for retry in range(MAX_TAG_RETRIES + 1):
            response_text = self._think(messages)

            tag = extract_next_tag(response_text)
            if tag:
                return response_text

            # Khong co tag — nudge
            if retry < MAX_TAG_RETRIES:
                print(f"{YELLOW}[RED-TEAM] Khong co tag — nudge "
                      f"({retry + 1}/{MAX_TAG_RETRIES})...{RESET}")
                messages.append({"role": "assistant", "content": response_text})
                messages.append({
                    "role": "user",
                    "content": (
                        "Ban chua ket thuc bang tag. Hay ket thuc bang:\n"
                        "- [AGENT] neu muon hoi Agent\n"
                        "- [BLUETEAM] neu da viet xong chien luoc\n"
                        "- [DONE] neu da co ket qua exploit"
                    ),
                })
            else:
                # Het retries — force tag
                print(f"{YELLOW}[RED-TEAM] Het tag retries — "
                      f"force [BLUETEAM]{RESET}")
                return response_text + "\n[BLUETEAM]"

        return response_text + "\n[BLUETEAM]"  # safety fallthrough

    # ─── Internal: LLM call ──────────────────────────────────────

    def _think(self, messages: list[dict]) -> str:
        """Goi LLM Red Team 1 turn."""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.4,
                max_tokens=4096,
            )
            text = response.choices[0].message.content or ""
            print(f"{RED}[RED-TEAM] Response ({len(text)} chars){RESET}")
            return text
        except Exception as e:
            print(f"{RED}[RED-TEAM] LLM error: {e}{RESET}")
            return f"[LLM Error: {e}]\n[BLUETEAM]"

    def _build_messages(self, conversation: list[dict]) -> list[dict]:
        """Build messages cho LLM call.

        Pattern tu debate.py build_messages():
        - speaker == "REDTEAM" → role: assistant (Red la chinh)
        - speaker != "REDTEAM" → role: user
        - System prompt dau tien
        - Dam bao message cuoi la role: user
        """
        messages: list[dict] = [{"role": "system", "content": self.system_prompt}]

        for msg in conversation:
            speaker = msg["speaker"]
            content = msg["content"]

            # Truncate message qua dai
            if len(content) > MAX_MSG_CHARS:
                content = truncate(content, MAX_MSG_CHARS)

            if speaker == "REDTEAM":
                messages.append({"role": "assistant", "content": content})
            else:
                # BLUETEAM, AGENT, USER, SYSTEM → user
                messages.append({"role": "user", "content": content})

        # Copilot API yeu cau message cuoi phai la user
        if not messages or messages[-1]["role"] != "user":
            messages.append({
                "role": "user",
                "content": "Hay phan tich va dua ra chien luoc tan cong. "
                           "Ket thuc bang [AGENT], [BLUETEAM] hoac [DONE].",
            })

        return messages
