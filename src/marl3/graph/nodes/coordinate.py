"""Coordinator node — re-ranks dossiers and injects dependency links."""
from __future__ import annotations

import logging

log = logging.getLogger("marl3.graph.coordinate")


async def run_coordinate(state: dict) -> dict:
    from ...recon.coordinator import rank_and_link

    dossiers = state.get("dossiers", [])
    recon = state["recon"]
    cfg = state["cfg"]
    llm = state["llm"]

    if not dossiers:
        return {"dossiers": dossiers}

    from ... import logging_setup as _ls
    _ls.step(f"COORDINATE — ranking {len(dossiers)} candidate(s) + linking dependencies")
    ranked = await rank_and_link(dossiers, recon, llm=llm, cfg=cfg)
    return {"dossiers": ranked}
