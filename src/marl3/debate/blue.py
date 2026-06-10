"""BlueAgent — reviews Red strategies and returns a structured verdict."""
from __future__ import annotations

import logging
import re

from ..contracts.enums import Role, DebateVerdict
from ..contracts.results import DebateMessage, DebateThread
from ..llm.client import LLMClient
from ..prompts.registry import render

log = logging.getLogger("marl3.debate.blue")

_VERDICT_MAP = {
    "approve": DebateVerdict.APPROVE,
    "revise": DebateVerdict.REVISE,
    "stop": DebateVerdict.STOP,
    "unverifiable": DebateVerdict.UNVERIFIABLE,
}


def _format_recon(dossier, recon_endpoints=None) -> str:
    """Concise, concrete recon facts for Blue: real endpoint examples + full discovered endpoint list."""
    lines = [f"Target endpoint: {dossier.method} {dossier.endpoint}"]
    for ex in getattr(dossier, "http_examples", [])[:4]:
        x = ex.exchange
        bits = [f"{x.method} {x.url} → {x.status}"]
        if x.json_keys:
            bits.append(f"json_keys={x.json_keys[:8]}")
        if getattr(x, "forms", None):
            fields = [f["name"] for form in x.forms for f in form.get("fields", [])]
            if fields:
                bits.append(f"form_fields={fields[:8]}")
        lines.append("- " + " | ".join(bits))

    if recon_endpoints:
        lines.append("\nAll discovered endpoints (use this to verify that proposed endpoints actually exist):")
        for ep in recon_endpoints[:60]:
            disc = getattr(ep, "discovery", "crawled")
            disc_tag = "" if disc == "crawled" else f" [{disc}]"
            lines.append(f"  - {ep.method} {ep.endpoint}{disc_tag}")
    else:
        lines.append("\n(No full endpoint list available — treat unverifiable endpoint references with caution)")
    return "\n".join(lines)


class BlueAgent:
    def __init__(self, llm: LLMClient) -> None:
        self._llm = llm

    async def review(
        self,
        thread: DebateThread,
        dossier,
        round_num: int,
        recon_endpoints=None,
    ) -> DebateMessage:
        """Review Red's latest strategy and return APPROVE/REVISE/STOP/UNVERIFIABLE + rationale."""
        # Get last Red message
        red_last = ""
        for msg in reversed(thread.messages):
            if msg.role == "red":
                red_last = msg.content
                break

        # Give Blue the SAME concrete recon evidence Red has, PLUS the full endpoint list,
        # so it can catch hallucinated fields/endpoints instead of rubber-stamping.
        recon_facts = _format_recon(dossier, recon_endpoints=recon_endpoints)
        system_prompt = render(
            "blue_system",
            bug=dossier,
            round=round_num,
            red_last_message=red_last,
            recon_facts=recon_facts,
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": "Review the strategy above and give your verdict."},
        ]

        response = await self._llm.chat(
            messages=messages,
            role=Role.BLUE,
            temperature=0.3,  # Blue is conservative
            max_tokens=3000,
        )

        verdict_token = _parse_verdict(response)
        return DebateMessage(role="blue", round=round_num, content=response, verdict_token=verdict_token)


def _parse_verdict(text: str) -> DebateVerdict:
    """Extract the verdict token from Blue's response.

    The prompt instructs Blue to start with APPROVE/REVISE/STOP as the FIRST word.
    We therefore look at the leading ~80 chars (enough for "**APPROVE**:" prefixes) and
    require the token NOT to be immediately preceded by a negation word like NOT or DON'T.
    Searching the full 400-char prefix would match "I do NOT APPROVE" as APPROVE — wrong.
    """
    import re
    # Strip common markdown decorators, check the first ~80 characters only
    prefix = re.sub(r'[*_`#\s]', ' ', text.strip()[:80]).upper()
    for token, verdict in [
        ("APPROVE", DebateVerdict.APPROVE),
        ("UNVERIFIABLE", DebateVerdict.UNVERIFIABLE),
        ("STOP", DebateVerdict.STOP),
        ("REVISE", DebateVerdict.REVISE),
    ]:
        m = re.search(rf'\b{token}\b', prefix)
        if m:
            # Reject if preceded by a negation (NOT, DON'T, CANNOT, etc.)
            before = prefix[:m.start()].strip()
            if re.search(r'\b(NOT|NO|DON\'?T|CANNOT|CAN\'?T|NEVER)\s*$', before):
                continue
            return verdict
    # Wider fallback: search full first 400 chars but still exclude negated occurrences
    head = re.sub(r'[*_`#]', ' ', text.strip()[:400]).upper()
    for token, verdict in [
        ("APPROVE", DebateVerdict.APPROVE),
        ("UNVERIFIABLE", DebateVerdict.UNVERIFIABLE),
        ("STOP", DebateVerdict.STOP),
        ("REVISE", DebateVerdict.REVISE),
    ]:
        for m in re.finditer(rf'\b{token}\b', head):
            before = head[:m.start()].strip()
            if not re.search(r'\b(NOT|NO|DON\'?T|CANNOT|CAN\'?T|NEVER)\s*$', before):
                return verdict
    return DebateVerdict.REVISE
