"""Recon + Hunt nodes — LangGraph wrappers for the crawl and vulnerability discovery phases."""
from __future__ import annotations

import logging

log = logging.getLogger("marl3.graph.recon")


async def run_recon(state: dict) -> dict:
    """Crawl target → populate state['recon'].

    Handles both single-credential dict and list-of-credentials from CLI.
    """
    from ...recon.crawler import GuidedCrawler
    from ...recon.workflow import run_recon as _workflow_run_recon
    from ... import logging_setup as _ls

    cfg = state["cfg"]
    workspace = state["workspace"]
    llm = state["llm"]
    target_url = state["target_url"]
    credentials = state["credentials"]

    # Pass ALL credentials through (multi-account → cross-user IDOR). The crawler
    # accepts a list or a single dict and logs in each account in its own session.
    creds = credentials if isinstance(credentials, list) else ([credentials] if credentials else [])

    _ls.phase(f"RECON — crawling {target_url} ({len(creds)} credential(s))")

    recon = await _workflow_run_recon(
        url=target_url,
        credentials=creds,
        cfg=cfg,
        workspace=workspace,
        llm=llm,
    )

    # Visual summary: how much attack surface we captured.
    methods: dict[str, int] = {}
    for ex in recon.exchanges:
        methods[ex.method] = methods.get(ex.method, 0) + 1
    _ls.recon_summary(
        n_endpoints=len(recon.endpoints),
        n_exchanges=len(recon.exchanges),
        methods=methods,
        auth_ok=getattr(recon, "auth_succeeded", False),
        profiles=[p.label for p in recon.auth_profiles],
        auth_diffs=len(recon.auth_diffs),
    )
    return {"recon": recon}


async def run_hunt(state: dict) -> dict:
    """HunterAgent → populate state['dossiers']."""
    from ...recon.candidates import VulnCandidateGenerator
    from ... import logging_setup as _ls

    _ls.phase("HUNT — analysing recon for candidate bugs")

    # Pull lessons from long-term memory (past runs) to seed better candidates.
    lessons = ""
    try:
        from ...memory.longterm import (
            get_longterm, target_fingerprint, render_hunt_lessons, render_rules,
        )
        lt = get_longterm(state["cfg"])
        if lt.enabled:
            recon = state["recon"]
            query = " ".join(e.endpoint for e in (recon.endpoints or [])[:25])
            rules_block = render_rules(lt.rules_for_hunt())
            eps = lt.lessons_for_hunt(target_fingerprint(recon), query_text=query)
            episodic_block = render_hunt_lessons(eps)
            lessons = "\n\n".join(b for b in (rules_block, episodic_block) if b)
            if lessons:
                log.info(f"[hunt] injecting long-term memory: {len(eps)} episode(s)"
                         + (" + distilled rules" if rules_block else ""))
    except Exception as e:
        log.debug(f"[hunt] long-term lessons skipped: {e}")

    generator = VulnCandidateGenerator(llm=state["llm"], cfg=state["cfg"])
    dossiers = await generator.generate(recon=state["recon"], lessons=lessons)

    # Enrich with graph_context
    from ...dossier.enrich import enrich_all
    dossiers = enrich_all(dossiers, state["recon"])

    _ls.hunt_summary(dossiers)
    return {"dossiers": dossiers}
