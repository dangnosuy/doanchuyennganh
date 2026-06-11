"""Execution node — runs the exploit and returns structured Evidence."""
from __future__ import annotations

import logging

log = logging.getLogger("marl3.graph.execution")


async def run_execution(state: dict) -> dict:
    from ...execution.runner import ExecutionRunner

    dossier = state["dossier"]
    recon = state["recon"]
    cfg = state["cfg"]
    workspace = state["workspace"]
    llm = state["llm"]
    memory = state.get("memory")
    strategy = state["frozen_strategy"]
    execution_guide = state.get("frozen_execution_guide", "")
    success_condition = state.get("frozen_success_condition", "")

    log.info(f"[exec] {dossier.id} — running exploit")

    runner = ExecutionRunner(llm=llm, cfg=cfg, workspace=workspace)
    try:
        evidence = await runner.run(
            dossier=dossier,
            recon=recon,
            strategy=strategy,
            success_condition=success_condition,
            execution_guide=execution_guide,
            memory=memory,
        )
        # runner.last_poc is a PocArtifact object — store it directly
        return {
            "evidence": evidence,
            "poc_path": runner.last_poc,  # PocArtifact or None
            "bug_status": "EXEC_DONE",
        }
    except Exception as exc:
        log.error(f"[exec] {dossier.id} failed: {exc}")
        exec_retries = state.get("exec_retries", 0) + 1
        return {
            "exec_retries": exec_retries,
            "error_message": str(exc),
            "bug_status": "EXEC_ERROR",
        }
