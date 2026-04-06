"""
BlueTeamAgent — Module Blue Team cho MARL.

Blue = Reviewer nghiem khac: review chien luoc cua Red Team,
co the hoi Agent de verify thong tin, approve hoac reject.

Tag system:
  [AGENT]     — Blue hoi Agent de verify (endpoint co ton tai? param dung khong?)
  [REDTEAM]   — Reject → tra lai cho Red sua
  [APPROVED]  — Duyet chien luoc → Agent se thuc thi

Khac debate.py cu:
- Tach rieng module, khong phu thuoc main loop
- respond() xu ly 1 turn, main.py goi nhieu lan trong debate loop
- Blue CO THE goi Agent de verify (khong chi la text-only reviewer)

Usage (tu main.py):
    blue = BlueTeamAgent(target_url="...", recon_context="...")
    text = blue.respond(conversation, exec_agent)
    tag  = extract_next_tag(text)  # "AGENT" | "REDTEAM" | "APPROVED"
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
MODEL = os.getenv("MARL_BLUE_MODEL", "gpt-5-mini")
PROMPT_PATH = "prompts/blue"

# Colors
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Limits
MAX_TAG_RETRIES = 2
MAX_MSG_CHARS = 6000

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
# SYSTEM PROMPT — Blue = Reviewer nghiem khac
# ═══════════════════════════════════════════════════════════════

BLUE_PROMPT = load_prompt("blue")

# ═══════════════════════════════════════════════════════════════
# BLUE TEAM AGENT CLASS
# ═══════════════════════════════════════════════════════════════

class BlueTeamAgent:
    """Blue Team reviewer — review chiến lược Red Team,
    verify bằng Agent nếu cần, approve/reject."""

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
            model: LLM model override. Default: env MARL_BLUE_MODEL or gpt-5-mini.
        """
        self.target_url = target_url
        self.recon_context = recon_context
        self.model = model or MODEL
        self.client = OpenAI(api_key=GITHUB_TOKEN, base_url=SERVER_URL)

        # System prompt — bake playbook vao
        self.system_prompt = BLUE_PROMPT.format(
            target_url=self.target_url,
            recon_context=truncate(self.recon_context),
            playbook=get_playbook_text(),
        )

        print(f"\n{BLUE}{BOLD}[BLUE-TEAM] Khoi tao — model={self.model}{RESET}")
        print(f"{BLUE}[BLUE-TEAM] Target: {self.target_url}{RESET}")

    # ─── Public API ──────────────────────────────────────────────

    def respond(self, conversation: list[dict]) -> str:
        """Xu ly 1 turn cua Blue Team.

        Doc conversation, goi LLM 1 turn.
        Caller (main.py) se doc tag de route tiep.

        Args:
            conversation: Shared debate conversation.

        Returns:
            Raw Blue Team response text. Caller dung extract_next_tag()
            de lay tag: "AGENT" | "REDTEAM" | "APPROVED".
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
                print(f"{YELLOW}[BLUE-TEAM] Khong co tag — nudge "
                      f"({retry + 1}/{MAX_TAG_RETRIES})...{RESET}")
                messages.append({"role": "assistant", "content": response_text})
                messages.append({
                    "role": "user",
                    "content": (
                        "Ban chua ket thuc bang tag. Hay ket thuc bang:\n"
                        "- [AGENT] neu muon hoi Agent verify\n"
                        "- [REDTEAM] neu REJECT chien luoc\n"
                        "- [APPROVED] neu DUYET chien luoc"
                    ),
                })
            else:
                print(f"{YELLOW}[BLUE-TEAM] Het tag retries — "
                      f"force [REDTEAM]{RESET}")
                return response_text + "\n[REDTEAM]"

        return response_text + "\n[REDTEAM]"  # safety fallthrough

    # ─── Internal: LLM call ──────────────────────────────────────

    def _think(self, messages: list[dict]) -> str:
        """Goi LLM Blue Team 1 turn."""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.3,
                max_tokens=4096,
            )
            text = response.choices[0].message.content or ""
            print(f"{BLUE}[BLUE-TEAM] Response ({len(text)} chars){RESET}")
            return text
        except Exception as e:
            print(f"{BLUE}[BLUE-TEAM] LLM error: {e}{RESET}")
            return f"[LLM Error: {e}]\n[REDTEAM]"

    def _build_messages(self, conversation: list[dict]) -> list[dict]:
        """Build messages cho LLM call.

        Pattern tu debate.py build_messages():
        - speaker == "BLUETEAM" → role: assistant (Blue la chinh)
        - speaker != "BLUETEAM" → role: user
        """
        messages: list[dict] = [{"role": "system", "content": self.system_prompt}]

        for msg in conversation:
            speaker = msg["speaker"]
            content = msg["content"]

            if len(content) > MAX_MSG_CHARS:
                content = truncate(content, MAX_MSG_CHARS)

            if speaker == "BLUETEAM":
                messages.append({"role": "assistant", "content": content})
            else:
                messages.append({"role": "user", "content": content})

        # Dam bao message cuoi la user
        if not messages or messages[-1]["role"] != "user":
            messages.append({
                "role": "user",
                "content": "Hay review chien luoc tan cong cua Red Team. "
                           "Ket thuc bang [AGENT], [REDTEAM] hoac [APPROVED].",
            })

        return messages
