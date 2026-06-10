"""RedAgent — writes and refines exploit strategies."""
from __future__ import annotations

import logging
import re

from ..contracts.enums import Role
from ..contracts.results import DebateMessage, DebateThread
from ..knowledge.provider import get_provider
from ..llm.client import LLMClient
from ..memory.retrieval import ContextBundle
from ..prompts.registry import render

log = logging.getLogger("marl3.debate.red")


class RedAgent:
    def __init__(self, llm: LLMClient) -> None:
        self._llm = llm
        self._playbook = get_provider()

    async def argue(
        self,
        thread: DebateThread,
        dossier,
        context: ContextBundle,
        round_num: int,
        recon=None,
    ) -> DebateMessage:
        """Generate Red's message for this round.

        Round 0: initial strategy (STRATEGY + EXECUTION GUIDE + SUCCESS CONDITION).
        Round ≥1: REBUTTAL addressing each Blue point + updated strategy.
        """
        try:
            card = self._playbook.card_for(dossier.pattern_id)
        except Exception:
            card = {}

        # Get last Blue message for context
        blue_last = ""
        for msg in reversed(thread.messages):
            if msg.role == "blue":
                blue_last = msg.content
                break

        # Collect session cookies from recon auth_profiles so Red can plan cookie-tamper attacks
        # even when http_examples for this specific endpoint are empty.
        auth_cookies_hint = ""
        if recon is not None:
            cookie_lines = []
            for p in getattr(recon, "auth_profiles", []):
                if p.cookie_header:
                    cookie_lines.append(f"  - {p.label}: `{p.cookie_header}`")
            if cookie_lines:
                auth_cookies_hint = "Session cookies captured during login:\n" + "\n".join(cookie_lines)

        system_prompt = render(
            "red_system",
            bug=dossier,
            pattern_card=_format_card(card),
            round=round_num,
            blue_last_message=blue_last,
            auth_cookies_hint=auth_cookies_hint,
        )

        # Assemble messages: system + memory context + thread history
        messages = [{"role": "system", "content": system_prompt}]

        memory_section = context.render(token_budget=1500)
        if memory_section:
            messages.append({"role": "user", "content": f"## Memory Context\n\n{memory_section}"})

        # Append thread history (render_for drops oldest turns as whole units)
        thread_text = thread.render_for("red", token_budget=4000)
        if thread_text:
            messages.append({"role": "user", "content": f"## Debate History\n\n{thread_text}"})

        messages.append({"role": "user", "content": "Write your strategy now."})

        response = await self._llm.chat(
            messages=messages,
            role=Role.RED,
            temperature=0.6,
            max_tokens=4000,
        )

        return DebateMessage(role="red", round=round_num, content=response)


def _format_card(card: dict) -> str:
    if not card:
        return "(no knowledge card available)"
    lines = [
        f"**{card.get('id', '')} — {card.get('name', '')}**",
        f"Severity: {card.get('severity', '')}",
        f"\n{card.get('description', '')}",
        "\nTechnique:",
    ]
    for step in card.get("technique", []):
        lines.append(f"  {step}")
    lines.append(f"\nSuccess condition: {card.get('success_condition', '')}")
    return "\n".join(lines)
