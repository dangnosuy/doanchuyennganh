"""Recon phase workflow — thin entry point called by CLI and Orchestrator."""
from __future__ import annotations

import logging

from ..config import AppConfig
from ..contracts.recon import ReconArtifact
from ..workspace import RunWorkspace

log = logging.getLogger("marl3.recon.workflow")


async def run_recon(
    url: str,
    credentials: dict[str, str],
    cfg: AppConfig,
    workspace: RunWorkspace,
    llm=None,
) -> ReconArtifact:
    from .crawler import GuidedCrawler
    from .flow_mapper import detect_business_flows

    crawler = GuidedCrawler(cfg=cfg, workspace=workspace)
    artifact = await crawler.crawl(target_url=url, credentials=credentials)

    # Replace keyword-detected flows with hybrid AI flow mapper
    try:
        flows = await detect_business_flows(artifact, llm=llm)
        if flows != artifact.business_flows:
            artifact.business_flows = flows
            # Re-write recon.json with improved flows
            workspace.recon_json.write_text(artifact.model_dump_json(indent=2))
            log.info(f"Flow mapper: updated business_flows → {[f.name for f in flows]}")
    except Exception as e:
        log.warning(f"Flow mapper failed (non-fatal, keeping crawler flows): {e}")

    return artifact
