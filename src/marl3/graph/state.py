"""LangGraph state TypedDicts for marl3.

Two graphs:
  PipelineState — top-level pipeline (recon → hunt → bugs → report)
  BugRunState   — per-bug sub-graph (debate → exec → verify, with cycles)

Must use TypedDict (not plain dict) so LangGraph can handle cycles and
update merging correctly. All fields have defaults so partial updates work.
"""
from __future__ import annotations

import time
from typing import Any, Optional
from typing_extensions import TypedDict


class PipelineState(TypedDict, total=False):
    """Top-level pipeline state: recon → hunt → bugs → report."""
    # Inputs (required)
    target_url: str
    credentials: list
    # Infra (passed through all nodes unchanged)
    cfg: Any
    workspace: Any
    llm: Any
    # Phase outputs (set by each node)
    recon: Optional[Any]
    dossiers: list
    findings: list
    error: Optional[str]


class BugRunState(TypedDict, total=False):
    """Per-bug sub-graph state: debate → exec → verify (with retry cycles)."""
    # Inputs
    dossier: Any
    recon: Any
    # Infra
    cfg: Any
    workspace: Any
    llm: Any
    memory: Optional[Any]
    body_store: Optional[Any]
    auth_store: Optional[Any]
    # Debate
    thread: Optional[Any]
    debate_rounds: int
    max_debate_rounds: int
    frozen_strategy: str
    frozen_execution_guide: str
    frozen_success_condition: str
    # Execution
    evidence: Optional[Any]
    exec_retries: int
    max_exec_retries: int
    # Verification
    panel_verdicts: list
    verifier_rationale: str
    verify_retries: int
    max_verify_retries: int
    # Status (drives conditional edges)
    bug_status: str
    finding: Optional[Any]
    poc_path: Optional[str]
    error_message: str
    # Timing (benchmark instrumentation)
    started_at: float


def make_pipeline_state(
    *,
    target_url: str,
    credentials: list,
    cfg: Any,
    workspace: Any,
    llm: Any,
) -> PipelineState:
    return PipelineState(
        target_url=target_url,
        credentials=credentials,
        cfg=cfg,
        workspace=workspace,
        llm=llm,
        recon=None,
        dossiers=[],
        findings=[],
        error=None,
    )


def make_bug_state(
    *,
    dossier: Any,
    recon: Any,
    cfg: Any,
    workspace: Any,
    llm: Any,
    memory: Any = None,
    body_store: Any = None,
    auth_store: Any = None,
    max_debate_rounds: int = 3,
    max_exec_retries: int = 1,
    max_verify_retries: int = 1,
) -> BugRunState:
    return BugRunState(
        dossier=dossier,
        recon=recon,
        cfg=cfg,
        workspace=workspace,
        llm=llm,
        memory=memory,
        body_store=body_store,
        auth_store=auth_store,
        thread=None,
        debate_rounds=0,
        max_debate_rounds=max_debate_rounds,
        frozen_strategy="",
        frozen_execution_guide="",
        frozen_success_condition="",
        evidence=None,
        exec_retries=0,
        max_exec_retries=max_exec_retries,
        panel_verdicts=[],
        verifier_rationale="",
        verify_retries=0,
        max_verify_retries=max_verify_retries,
        bug_status="QUEUED",
        finding=None,
        poc_path=None,
        error_message="",
        started_at=time.monotonic(),
    )
