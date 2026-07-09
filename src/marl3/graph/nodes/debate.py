"""Debate node — runs the Red↔Blue debate loop for one bug.

Input keys consumed:  dossier, recon, thread, debate_rounds, max_debate_rounds,
                      frozen_strategy, frozen_execution_guide, frozen_success_condition,
                      llm, cfg, memory, verifier_rationale
Output keys produced: thread, debate_rounds, frozen_*, bug_status
"""
from __future__ import annotations

import logging

log = logging.getLogger("marl3.graph.debate")


async def run_debate(state: dict) -> dict:
    from ...debate.manager import DebateManager
    from ...contracts.results import DebateThread
    from ...state import BugRun

    dossier = state["dossier"]
    recon = state["recon"]
    llm = state["llm"]
    cfg = state["cfg"]
    memory = state["memory"]
    verifier_rationale = state.get("verifier_rationale", "")
    debate_rounds_so_far = state.get("debate_rounds", 0)

    # Build context bundle (includes verifier feedback if this is a retry)
    context_bundle = _build_context(memory, dossier, verifier_rationale)

    # Restore or create thread
    thread: DebateThread = state.get("thread") or DebateThread(bug_id=dossier.id)

    manager = DebateManager(llm=llm, cfg=cfg)

    # Use the real BugRun dataclass — DebateManager was designed around it
    bug_run = BugRun(
        dossier=dossier,
        thread=thread,
        debate_rounds=debate_rounds_so_far,
        max_debate_rounds=state.get("max_debate_rounds", cfg.debate.max_rounds),
        max_exec_retries=state.get("max_exec_retries", 1),
        max_verify_retries=state.get("max_verify_retries", 1),
        verifier_rationale=verifier_rationale,
    )
    # Start from DEBATING (not QUEUED — we skip the transition gate for retry paths)
    from ...contracts.enums import BugState
    bug_run.state = BugState.DEBATING

    outcome = await manager.run(bug_run=bug_run, context=context_bundle, recon=recon)

    updates: dict = {
        "thread": bug_run.thread,
        "debate_rounds": bug_run.debate_rounds,
        "frozen_strategy": bug_run.frozen_strategy,
        "frozen_execution_guide": bug_run.frozen_execution_guide,
        "frozen_success_condition": bug_run.frozen_success_condition,
        "frozen_verification_questions": bug_run.frozen_verification_questions,
    }

    if outcome == "APPROVED":
        updates["bug_status"] = "DEBATE_APPROVED"
        # Persist approved strategy so exec can retrieve it on retry and memory carries context
        if memory is not None:
            try:
                memory.update_strategy(dossier.id, bug_run.frozen_strategy or "")
            except Exception as _e:
                log.debug(f"memory.update_strategy skipped: {_e}")
    elif outcome == "INSUFFICIENT_CONTEXT":
        updates["bug_status"] = "SKIPPED_NO_EVIDENCE"
        if memory is not None:
            try:
                memory.record_attempt(dossier.id, "SKIPPED_NO_EVIDENCE")
            except Exception:
                pass
    else:
        # STOP or MAX_ROUNDS
        updates["bug_status"] = "NOT_EXPLOITED"
        if memory is not None:
            try:
                memory.record_attempt(dossier.id, f"DEBATE_{outcome}")
            except Exception:
                pass

    return updates


def _build_context(memory, dossier, verifier_rationale: str):
    """Build the Red context bundle. On a re-debate, the verifier's rejection rationale
    is carried back so Red can fix exactly what failed (ContextBundle.verifier_feedback)."""
    from ...memory.retrieval import ContextRetriever, ContextBundle
    feedback = verifier_rationale or None
    if memory is None:
        return ContextBundle(role="red", bug_id=dossier.id, verifier_feedback=feedback)
    return ContextRetriever(memory).bundle_for("red", dossier, verifier_feedback=feedback)


