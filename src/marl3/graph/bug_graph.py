"""Per-bug LangGraph sub-graph.

Flow:
  START → debate → [approved] → exec → verify → [confirmed] → END
                → [skip/stop] → END
                                verify → [proof_fail + retry] → debate (loop)
                                        → [give_up] → END

Conditional routing is deterministic — based on bug_status string, never LLM-driven.
This replaces marl2's inner state-machine loop (orchestrator.py lines 90-180).
"""
from __future__ import annotations

import logging

from langgraph.graph import StateGraph, END, START

from .state import BugRunState
from .nodes import debate as _debate_node
from .nodes import execution as _exec_node
from .nodes import verify as _verify_node

log = logging.getLogger("marl3.graph.bug")


# ---------------------------------------------------------------------------
# Routing functions (pure — take state, return edge label)
# ---------------------------------------------------------------------------

def _after_debate(state: BugRunState) -> str:
    status = state.get("bug_status", "NOT_EXPLOITED")
    if status == "DEBATE_APPROVED":
        return "exec"
    # SKIPPED_NO_EVIDENCE, NOT_EXPLOITED, MAX_ROUNDS
    return "end"


def _after_exec(state: BugRunState) -> str:
    status = state.get("bug_status", "EXEC_ERROR")
    if status == "EXEC_DONE":
        return "verify"
    # EXEC_ERROR — check retries
    if state.get("exec_retries", 0) < state.get("max_exec_retries", 1):
        _retry_banner("EXEC", state, state.get("error_message", "exec error"))
        return "retry_exec"
    return "end"


def _after_verify(state: BugRunState) -> str:
    status = state.get("bug_status", "")
    # EXPLOITED (full proof) and INFO_EXPOSURE_ONLY (real but partial, capped by
    # the proof-gate) are both terminal — re-debating a gate-capped finding wastes
    # budget since the data ceiling won't change.
    if status in ("EXPLOITED", "INFO_EXPOSURE_ONLY"):
        return "end"
    # PROOF_QUALITY_FAIL — retry when there's a meaningful signal worth re-strategizing on.
    # Two independent signals, either is sufficient:
    #   1. panel_verdicts confirmed_count >= 1: Panel saw something promising in raw exchanges.
    #   2. has_partial_proof: ProofGate ran and at least one proof_marker was SATISFIED
    #      (e.g., endpoint accessible but data not confirmed sensitive yet). This is the
    #      strongest retry signal — execution was structurally close, strategy needs refinement.
    # Panel runs pre-gate (raw HTTP), so its signal is weaker than ProofGate's markers.
    # Checking both prevents missing retries when ProofGate found partial evidence
    # but Panel voted 0/3 (e.g., Panel couldn't parse non-English response body).
    # Off-by-one note: verify.py increments verify_retries BEFORE this check runs,
    # so the guard must use <= (not <) to allow max_verify_retries=1 to mean 1 retry.
    panel_verdicts = state.get("panel_verdicts", []) or []
    confirmed_count = sum(1 for v in panel_verdicts if getattr(v, "confirmed", False))
    evidence = state.get("evidence")
    has_partial_proof = any(
        getattr(m, "satisfied", False)
        for m in (getattr(evidence, "proof_markers", None) or [])
    ) if evidence else False
    can_retry = (
        (confirmed_count >= 1 or has_partial_proof)
        and state.get("verify_retries", 0) <= state.get("max_verify_retries", 1)
        and state.get("debate_rounds", 0) < state.get("max_debate_rounds", 3) * 2
    )
    if can_retry:
        _retry_banner("DEBATE", state, "proof insufficient — re-strategising with verifier feedback")
        return "retry_debate"
    return "end"


def _retry_banner(kind: str, state: BugRunState, reason: str) -> None:
    try:
        from .. import logging_setup as _ls
        dossier = state.get("dossier")
        bug_id = getattr(dossier, "id", "?")
        _ls.retry(kind, bug_id, reason)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------

def build_bug_graph():
    """Compile and return the per-bug StateGraph."""
    g = StateGraph(BugRunState)

    g.add_node("debate", _debate_node.run_debate)
    g.add_node("exec", _exec_node.run_execution)
    g.add_node("verify", _verify_node.run_verify)

    g.add_edge(START, "debate")

    g.add_conditional_edges(
        "debate",
        _after_debate,
        {
            "exec": "exec",
            "end": END,
        },
    )

    g.add_conditional_edges(
        "exec",
        _after_exec,
        {
            "verify": "verify",
            "retry_exec": "exec",   # retry exec immediately (different strategy)
            "end": END,
        },
    )

    g.add_conditional_edges(
        "verify",
        _after_verify,
        {
            "end": END,
            "retry_debate": "debate",  # loop back with verifier feedback
        },
    )

    return g.compile()


# Singleton — compiled once, reused per bug
_BUG_GRAPH = None


def get_bug_graph():
    global _BUG_GRAPH
    if _BUG_GRAPH is None:
        _BUG_GRAPH = build_bug_graph()
    return _BUG_GRAPH
