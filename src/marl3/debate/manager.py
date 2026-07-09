"""DebateManager — orchestrates the real Red↔Blue debate loop.

This is the fix for MARL's "fake debate" problem:
- MARL: each agent called LLM once, Manager hand-relays text
- marl2: DebateManager drives a real N-round loop where:
  1. Red argues (round 0: initial strategy; round≥1: REBUTTAL + updated strategy)
  2. Blue reviews and returns APPROVE/REVISE/STOP
  3. Loop continues until APPROVE, STOP, or max_rounds reached
"""
from __future__ import annotations

import logging

from typing import Optional

from ..config import AppConfig
from ..contracts.enums import DebateVerdict
from ..contracts.results import DebateThread
from ..llm.client import LLMClient
from ..memory.retrieval import ContextBundle
from ..state import BugRun
from .red import RedAgent
from .blue import BlueAgent

log = logging.getLogger("marl3.debate")


class DebateManager:
    def __init__(self, llm: LLMClient, cfg: AppConfig) -> None:
        self._llm = llm
        self._cfg = cfg
        self._red = RedAgent(llm)
        self._blue = BlueAgent(llm)

    async def run(self, bug_run: BugRun, context: ContextBundle, recon=None) -> str:
        """Run the full debate loop for bug_run.

        Returns one of: "APPROVED", "STOP", "MAX_ROUNDS", "INSUFFICIENT_CONTEXT"
        Side-effects: populates bug_run.thread, bug_run.frozen_strategy,
                      bug_run.frozen_success_condition, bug_run.debate_rounds.
        """
        dossier = bug_run.dossier

        # Ablation: skip debate entirely — exec runs directly from the dossier hypothesis.
        if getattr(self._cfg.debate, "skip", False):
            log.info(f"{dossier.id}: debate.skip=True — bypassing Red↔Blue, freezing dossier as strategy")
            bug_run.thread = DebateThread(bug_id=dossier.id)
            bug_run.frozen_strategy = dossier.hypothesis
            bug_run.frozen_execution_guide = dossier.exploit_approach or dossier.hypothesis
            bug_run.frozen_success_condition = dossier.hypothesis
            bug_run.frozen_verification_questions = []
            bug_run.debate_rounds = 0
            return "APPROVED"

        thread = DebateThread(bug_id=dossier.id)
        bug_run.thread = thread

        max_rounds = bug_run.max_debate_rounds
        recon_endpoints = getattr(recon, "endpoints", None)

        for round_num in range(max_rounds):
            # Check cumulative total budget (includes previous debate cycles on this bug)
            if bug_run.debate_budget_exhausted:
                log.warning(f"{dossier.id}: total debate budget exhausted at round {round_num}")
                return "MAX_ROUNDS"
            bug_run.debate_rounds += 1

            red_msg = await self._red.argue(
                thread=thread,
                dossier=dossier,
                context=context,
                round_num=round_num,
                recon=recon,
            )
            thread.append(red_msg)

            # Detect Red's own INSUFFICIENT_EVIDENCE signal (GROUNDING CHECK failed).
            # Check raw content directly — do NOT strip underscores, they're part of
            # the token. Stripping `_` would turn INSUFFICIENT_EVIDENCE → INSUFFICIENT EVIDENCE
            # and the check would always fail.
            _raw_prefix = red_msg.content[:500].upper()
            if "INSUFFICIENT_EVIDENCE" in _raw_prefix:
                from .. import logging_setup as _ls
                _ls.agent_message("red", round_num, red_msg.content, bug_id=dossier.id)
                log.info(f"{dossier.id}: Red declared INSUFFICIENT_EVIDENCE — skipping to SKIPPED_NO_EVIDENCE")
                return "INSUFFICIENT_CONTEXT"

            blue_msg = await self._blue.review(
                thread=thread,
                dossier=dossier,
                round_num=round_num,
                recon_endpoints=recon_endpoints,
            )
            thread.append(blue_msg)
            verdict = blue_msg.verdict_token

            # Display full agent messages — no truncation
            from .. import logging_setup as _ls
            _ls.agent_message("red", round_num, red_msg.content, bug_id=dossier.id)
            _ls.agent_message(
                "blue", round_num, blue_msg.content,
                verdict=verdict.value if verdict else "?",
                bug_id=dossier.id,
            )

            if verdict == DebateVerdict.APPROVE:
                bug_run.frozen_strategy = _extract_section(red_msg.content, "STRATEGY")
                bug_run.frozen_execution_guide = _extract_section(red_msg.content, "EXECUTION GUIDE")
                bug_run.frozen_success_condition = _extract_section(red_msg.content, "SUCCESS CONDITION")
                bug_run.frozen_verification_questions = _extract_verification_questions(red_msg.content)
                # If sections weren't parseable, fall back to the WHOLE message so the exec
                # agent never loses Red's concrete steps (Codex #1).
                if not bug_run.frozen_strategy:
                    bug_run.frozen_strategy = red_msg.content
                if not bug_run.frozen_execution_guide:
                    bug_run.frozen_execution_guide = red_msg.content
                # Issue-003: success condition fallback to hypothesis so exec/verifier always have
                # a non-empty anchor (prevents empty success condition reaching exec_system.md)
                if not bug_run.frozen_success_condition:
                    bug_run.frozen_success_condition = bug_run.dossier.hypothesis or red_msg.content
                log.info(
                    f"{dossier.id}: debate APPROVED (round {round_num + 1}) "
                    f"— {len(bug_run.frozen_verification_questions)} verification question(s) frozen"
                )
                return "APPROVED"

            elif verdict == DebateVerdict.STOP:
                log.info(f"{dossier.id}: debate STOP (round {round_num + 1})")
                return "STOP"

            elif verdict == DebateVerdict.UNVERIFIABLE:
                log.info(f"{dossier.id}: Blue declared UNVERIFIABLE — insufficient context")
                return "INSUFFICIENT_CONTEXT"

        log.info(f"{dossier.id}: debate MAX_ROUNDS ({max_rounds})")
        return "MAX_ROUNDS"


def _extract_section(text: str, section_name: str) -> str:
    """Extract the content of a === SECTION NAME === block from Red's output."""
    import re
    pattern = rf"===\s*{re.escape(section_name)}\s*===(.*?)(?:===|$)"
    match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).strip()
    return ""


def _extract_verification_questions(text: str) -> list[str]:
    """Extract the 3 numbered yes/no questions from the VERIFICATION QUESTIONS section."""
    import re
    section = _extract_section(text, "VERIFICATION QUESTIONS")
    if not section:
        return []
    questions = []
    for line in section.splitlines():
        line = line.strip()
        # Match lines starting with 1. / 2. / 3. (numbered list)
        m = re.match(r'^[1-9]\d*[\.\)]\s+(.+)', line)
        if m:
            questions.append(m.group(1).strip())
    return questions[:3]
