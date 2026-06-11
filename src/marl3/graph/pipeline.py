"""Main pipeline LangGraph for marl3.

Phases (linear — each feeds the next):
  START → recon → hunt → coordinate → bugs → report → END

The 'bugs' node is NOT a simple function — it iterates over all dossiers,
invokes the per-bug sub-graph for each, and accumulates findings.
This replaces marl2's Orchestrator._phase_bugs() loop.
"""
from __future__ import annotations

import logging

from langgraph.graph import StateGraph, END, START

from .nodes.recon import run_recon, run_hunt
from .nodes.coordinate import run_coordinate
from .nodes.report import run_report

log = logging.getLogger("marl3.graph.pipeline")


# ---------------------------------------------------------------------------
# Bugs phase node — iterates dossiers using per-bug sub-graph
# ---------------------------------------------------------------------------

async def run_bugs(state: dict) -> dict:
    """Run per-bug sub-graph for every dossier; accumulate findings."""
    from .bug_graph import get_bug_graph
    from .state import make_bug_state
    from ..contracts.results import Finding
    from ..memory.store import MemoryStore
    from ..recon.body_store import BodyStore
    from ..recon.auth import AuthSessionStore

    dossiers = state.get("dossiers", [])
    recon = state["recon"]
    cfg = state["cfg"]
    workspace = state["workspace"]
    llm = state["llm"]

    # Shared infra for all bugs
    memory = MemoryStore(workspace.memory_json)
    body_store = BodyStore(workspace.bodies_dir)
    auth_store = AuthSessionStore(workspace.sessions_json)

    from .. import logging_setup as _ls
    _ls.phase("ATTACK — per bug: debate → exec → verify")

    bug_graph = get_bug_graph()
    findings: list[Finding] = []

    for dossier in dossiers:
        _ls.bug_header(dossier.id, dossier.title, dossier.pattern_id)

        bug_state = make_bug_state(
            dossier=dossier,
            recon=recon,
            cfg=cfg,
            workspace=workspace,
            llm=llm,
            memory=memory,
            body_store=body_store,
            auth_store=auth_store,
            max_debate_rounds=cfg.debate.max_rounds,
            max_exec_retries=getattr(cfg.debate, "max_exec_retries", 1),
            max_verify_retries=getattr(cfg.debate, "max_verify_retries", 1),
        )

        # Invoke per-bug sub-graph (runs to completion)
        final_state = await bug_graph.ainvoke(bug_state)

        # Build Finding from final sub-graph state
        finding = _build_finding(final_state, dossier)
        findings.append(finding)

        # Persist finding to memory for future bugs
        _persist_finding(memory, finding)

        status_label = final_state.get("bug_status", "UNKNOWN")
        log.info(f"[bugs] {dossier.id} → {status_label}")

    # Distill episodic memory into cross-target rules (anti-overfit thresholds from config).
    try:
        from ..memory.longterm import get_longterm
        lt = get_longterm(cfg)
        if lt.enabled:
            mem_cfg = getattr(cfg, "memory", None)
            lt.distill(
                min_successes=getattr(mem_cfg, "promote_min_successes", 3),
                min_targets=getattr(mem_cfg, "promote_min_targets", 2),
            )
    except Exception as e:
        log.debug(f"[bugs] distill skipped: {e}")

    _ls.final_summary(findings)
    return {"findings": findings}


def _build_finding(state: dict, dossier) -> "Finding":
    from ..contracts.results import Finding
    from ..contracts.enums import Severity

    evidence = state.get("evidence")
    verdicts = state.get("panel_verdicts", [])
    bug_status = state.get("bug_status", "NOT_EXPLOITED")
    thread = state.get("thread")

    # Map bug_status → Finding status string
    if bug_status == "EXPLOITED":
        status = "EXPLOITED"
    elif bug_status == "INFO_EXPOSURE_ONLY":
        status = "INFO_EXPOSURE_ONLY"
    elif bug_status == "SKIPPED_NO_EVIDENCE":
        status = "SKIPPED_NO_EVIDENCE"
    elif bug_status in ("NOT_EXPLOITED", "PROOF_QUALITY_FAIL"):
        status = "NOT_EXPLOITED"
    else:
        status = "ERROR"

    debate_summary = ""
    if thread and thread.messages:
        debate_summary = f"{len(thread.messages)} messages, {state.get('debate_rounds', 0)} rounds"

    # verdict field expects Verdict object or None
    verdict_obj = None
    if evidence:
        verdict_obj = getattr(evidence, "_verdict_obj", None)
        if verdict_obj is None:
            # Build minimal Verdict from verdict_status string
            from ..contracts.evidence import Verdict as EvidenceVerdict
            try:
                from ..contracts.enums import VerdictStatus
                vs = getattr(evidence, "verdict_status", "FAILED")
                verdict_obj = EvidenceVerdict(status=vs, reason="")
            except Exception:
                pass

    # poc field expects PocArtifact or None — runner.last_poc is already a PocArtifact
    poc_artifact = state.get("poc_path")  # pipeline.py stores PocArtifact here
    if isinstance(poc_artifact, str):
        poc_artifact = None  # discard plain string paths

    return Finding(
        bug_id=dossier.id,
        title=dossier.title,
        pattern_id=dossier.pattern_id,
        category=dossier.category.value,
        severity=dossier.risk,
        status=status,
        endpoint=dossier.endpoint,
        method=dossier.method,
        hypothesis=dossier.hypothesis,
        summary=_summarise(state),
        debate=debate_summary,
        verdict=verdict_obj,
        evidence=evidence,
        panel=verdicts,
        panel_decision=status,
        poc=poc_artifact,
        remediation="",
        discovered_by="marl3",
    )


def _summarise(state: dict) -> str:
    bug_status = state.get("bug_status", "")
    error = state.get("error_message", "")
    evidence = state.get("evidence")
    exchanges = len(getattr(evidence, "exchanges", [])) if evidence else 0
    if bug_status == "EXPLOITED":
        return f"Exploited — {exchanges} HTTP exchanges captured"
    if bug_status == "SKIPPED_NO_EVIDENCE":
        return "Skipped — Red declared INSUFFICIENT_EVIDENCE"
    if error:
        return f"Not exploited — {error}"
    return f"Not exploited after {state.get('debate_rounds', 0)} debate rounds"


def _persist_finding(memory, finding) -> None:
    try:
        memory.record_finding(finding.bug_id, {
            "status": finding.status,
            "title": finding.title,
            "pattern_id": finding.pattern_id,
        })
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Main pipeline graph
# ---------------------------------------------------------------------------

def build_pipeline():
    """Compile and return the main pipeline StateGraph."""
    from .state import PipelineState
    g = StateGraph(PipelineState)

    g.add_node("recon", run_recon)
    g.add_node("hunt", run_hunt)
    g.add_node("coordinate", run_coordinate)
    g.add_node("bugs", run_bugs)
    g.add_node("report", run_report)

    g.add_edge(START, "recon")
    g.add_edge("recon", "hunt")
    g.add_edge("hunt", "coordinate")
    g.add_edge("coordinate", "bugs")
    g.add_edge("bugs", "report")
    g.add_edge("report", END)

    return g.compile()


# Singleton
_PIPELINE = None


def get_pipeline():
    global _PIPELINE
    if _PIPELINE is None:
        _PIPELINE = build_pipeline()
    return _PIPELINE
