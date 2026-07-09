"""BlueAgent — reviews Red strategies and returns a structured verdict."""
from __future__ import annotations

import logging
import re

from ..contracts.enums import Role, DebateVerdict
from ..contracts.results import DebateMessage, DebateThread
from ..knowledge.provider import get_provider
from ..llm.client import LLMClient
from ..prompts.registry import render

log = logging.getLogger("marl3.debate.blue")

_VERDICT_MAP = {
    "approve": DebateVerdict.APPROVE,
    "revise": DebateVerdict.REVISE,
    "stop": DebateVerdict.STOP,
    "unverifiable": DebateVerdict.UNVERIFIABLE,
}


_INVENTED_MONEY_FIELDS = frozenset({"price", "amount", "unit_price", "total", "cost", "subtotal", "fee"})


def _format_recon(dossier, recon_endpoints=None) -> str:
    """Concise, concrete recon facts for Blue: real endpoint examples + full discovered endpoint list."""
    lines = [f"Target endpoint: {dossier.method} {dossier.endpoint}"]

    # Show form fields for the target endpoint upfront — this is the most important signal
    # for catching Red strategies that reference fields which don't exist in the form contract.
    target_ep = (dossier.endpoint or "").rstrip("/")
    target_fields: list[str] = []
    if recon_endpoints:
        for ep in recon_endpoints:
            if ep.method == dossier.method and (ep.endpoint or "").rstrip("/") == target_ep:
                target_fields = list(getattr(ep, "parameters", None) or [])
                break
    if target_fields:
        lines.append(f"Known form fields for {dossier.method} {target_ep}: {target_fields}")
    else:
        lines.append(f"Known form fields for {dossier.method} {target_ep}: (none discovered)")

    for ex in getattr(dossier, "http_examples", [])[:4]:
        x = ex.exchange
        bits = [f"{x.method} {x.url} → {x.status}"]
        if getattr(x, "html_title", None):
            bits.append(f"title={x.html_title!r}")
        if x.json_keys:
            bits.append(f"json_keys={x.json_keys[:8]}")
        if getattr(x, "forms", None):
            field_info: list[str] = []
            for form in x.forms:
                for f in form.get("fields", []):
                    name = f.get("name", "")
                    if not name:
                        continue
                    ftype = f.get("type", "text")
                    value = f.get("value", "")
                    if ftype == "hidden":
                        field_info.append(f"{name}={value}[hidden]")
                    elif value:
                        field_info.append(f"{name}={value}")
                    else:
                        field_info.append(f"{name}[{ftype}]")
            if field_info:
                bits.append(f"form_fields={field_info[:8]}")
        body_ref = getattr(x, "response_body_ref", None)
        if body_ref and getattr(body_ref, "head_preview", None):
            preview_text = body_ref.head_preview[:300].replace("\n", " ").replace("\r", "")
            bits.append(f"body_preview={preview_text!r}")
        lines.append("- " + " | ".join(bits))

    if recon_endpoints:
        lines.append("\nAll discovered endpoints (use this to verify that proposed endpoints actually exist):")
        for ep in recon_endpoints[:60]:
            disc = getattr(ep, "discovery", "crawled")
            disc_tag = "" if disc == "crawled" else f" [{disc}]"
            params_tag = f" form-fields={ep.parameters}" if getattr(ep, "parameters", None) else ""
            lines.append(f"  - {ep.method} {ep.endpoint}{disc_tag}{params_tag}")
    else:
        lines.append("\n(No full endpoint list available — treat unverifiable endpoint references with caution)")
    return "\n".join(lines)


def _check_field_grounding(red_last: str, dossier, recon_endpoints=None) -> str:
    """Deterministic check: flag money/price fields Red claims that don't exist in recon evidence.

    Returns an injected warning string (or empty string if no issue found).
    This runs before the LLM to catch the common case where Red invents a `price` field
    when the form only has `productId`, `quantity`, `redir`.
    """
    target_ep = (dossier.endpoint or "").rstrip("/")
    known: set[str] = set()

    # Collect known fields from dossier http_examples
    for ex in getattr(dossier, "http_examples", []):
        x = ex.exchange
        for form in getattr(x, "forms", None) or []:
            for fld in form.get("fields", []):
                n = fld.get("name", "")
                if n:
                    known.add(n.lower())
        for k in getattr(x, "json_keys", None) or []:
            known.add(k.lower())

    # Collect from recon endpoint params (populated by Fix 3: cross-page form enrichment)
    if recon_endpoints:
        for ep in recon_endpoints:
            if ep.method == dossier.method and (ep.endpoint or "").rstrip("/") == target_ep:
                for p in getattr(ep, "parameters", None) or []:
                    known.add(p.lower())

    if not known:
        return ""  # No field evidence → cannot make a grounded check

    # Extract field names Red references in concrete HTTP calls
    claimed: set[str] = set()
    for m in re.findall(r'`(\w+)`', red_last):
        claimed.add(m.lower())
    for m in re.findall(r'"(\w+)"\s*:', red_last):
        claimed.add(m.lower())
    for m in re.findall(r"'(\w+)'\s*:", red_last):
        claimed.add(m.lower())
    # field=<numeric value> patterns (catches price=0.01, quantity=-1, etc.)
    for m in re.findall(r'\b(\w+)\s*=\s*[\-\d]', red_last):
        claimed.add(m.lower())

    # Flag money fields that Red claims but are absent from the form contract
    invented = {f for f in claimed if f in _INVENTED_MONEY_FIELDS and f not in known}
    if not invented:
        return ""

    return (
        f"\n\n[AUTOMATED FIELD CHECK — treat as Objection 1 if writing REVISE]\n"
        f"Red references {sorted(invented)} but these fields are NOT present in the "
        f"recon form contract for {dossier.method} {dossier.endpoint}. "
        f"Known form fields: {sorted(known)}. "
        f"Sending a request with invented field names either fails silently (server ignores "
        f"the unknown field) or returns 400 — the exploit will never work."
    )


class BlueAgent:
    def __init__(self, llm: LLMClient) -> None:
        self._llm = llm
        self._playbook = get_provider()

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

        # Deterministic pre-check: detect money fields Red references that don't exist.
        # Injects a warning into recon_facts so the LLM can't miss it.
        field_warning = _check_field_grounding(red_last, dossier, recon_endpoints)
        if field_warning:
            recon_facts = recon_facts + field_warning

        lab_reference = self._playbook.solution_for(dossier.pattern_id)

        system_prompt = render(
            "blue_system",
            bug=dossier,
            round=round_num,
            red_last_message=red_last,
            recon_facts=recon_facts,
            lab_reference=lab_reference,
        )

        messages = [
            {"role": "system", "content": system_prompt},
        ]

        # Round 1+: inject full debate history so Blue can see its own previous objection
        # alongside Red's rebuttal and verify each numbered point was actually addressed.
        # Without this, Blue on round 1 guesses what it objected to from Red's rebuttal text,
        # which lets superficial rebuttals slip through.
        if round_num > 0:
            thread_text = thread.render_for("blue", token_budget=3000)
            if thread_text:
                messages.append({
                    "role": "user",
                    "content": (
                        "## Full Debate History (for context — your previous objections are here)\n\n"
                        + thread_text
                    ),
                })

        messages.append({"role": "user", "content": "Review the strategy above and give your verdict."})

        response = await self._llm.chat(
            messages=messages,
            role=Role.BLUE,
            temperature=0.3,  # Blue is conservative
            max_tokens=3000,
        )

        verdict_token = _parse_verdict(response)

        # Mandatory first-round challenge: Blue must always push back on round 0.
        # Purpose: force Red to prove and sharpen its strategy before execution.
        # Exception: STOP and UNVERIFIABLE are not overridden — if the attack is
        # structurally impossible, there is no point forcing another debate round.
        if round_num == 0 and verdict_token == DebateVerdict.APPROVE:
            log.info(
                f"{dossier.id}: round 0 — APPROVE overridden → REVISE "
                f"(mandatory first-round challenge, prompt instruction not followed)"
            )
            verdict_token = DebateVerdict.REVISE
            # Prepend REVISE so the transcript starts with the correct verdict token,
            # not the LLM's "APPROVE" text (which would confuse anyone reading the debate file).
            response = (
                "REVISE\n\n"
                "*[System: Round 0 mandatory challenge — LLM wrote APPROVE but it was overridden. "
                "Red must treat this as REVISE and address the concern below before execution.]*\n\n"
                "---\n\n"
            ) + response

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
