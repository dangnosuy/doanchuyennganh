"""Report node — builds final report.md + findings.json from all findings."""
from __future__ import annotations

import logging

log = logging.getLogger("marl3.graph.report")


async def run_report(state: dict) -> dict:
    from ...report.builder import ReportBuilder

    findings = state.get("findings", [])
    workspace = state["workspace"]
    llm = state["llm"]

    from ... import logging_setup as _ls
    _ls.phase("REPORT — writing report.md + findings.json")

    builder = ReportBuilder(llm=llm, workspace=workspace)
    await builder.build(findings)

    _ls.info(f"📄 report.md + findings.json → {workspace.root}")
    return {}
