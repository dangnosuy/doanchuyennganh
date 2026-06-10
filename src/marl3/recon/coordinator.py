"""Lightweight post-hunt coordinator.

One LLM call after the hunt phase:
- Input: dossier list + recon summary
- Output: re-ranked order + enables/depends_on links between dossiers
- Effect: bugs are processed in dependency order; Red gets "enabled by" context

Based on PentestGPT's separation of planning from execution: the coordinator
acts as the Reasoning Module, deciding attack order without executing anything.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from ..contracts.dossier import BugDossier
from ..contracts.enums import Role
from ..contracts.recon import ReconArtifact

log = logging.getLogger("marl3.coordinator")


async def rank_and_link(
    dossiers: list[BugDossier],
    recon: ReconArtifact,
    llm=None,
    cfg=None,
) -> list[BugDossier]:
    """Re-rank dossiers by exploitability and inject dependency context.

    Returns the same dossiers in a new order, with graph_context.enables populated
    to tell Red which bugs are "unlocked" after this one is exploited.
    """
    if not dossiers or llm is None:
        return dossiers

    try:
        ranked = await _llm_rank(dossiers, recon, llm)
        return ranked
    except Exception as e:
        log.warning(f"Coordinator LLM call failed (non-fatal): {e}")
        return dossiers


async def _llm_rank(
    dossiers: list[BugDossier],
    recon: ReconArtifact,
    llm,
) -> list[BugDossier]:
    """Single LLM call to re-rank and link dossiers."""
    # Build a compact dossier summary for the prompt
    dossier_summary = []
    for d in dossiers:
        dossier_summary.append({
            "id": d.id,
            "pattern_id": d.pattern_id,
            "title": d.title,
            "endpoint": d.endpoint,
            "method": d.method,
            "confidence": d.confidence,
            "risk": d.risk.value,
            "auth_attacker": d.auth.attacker_role if d.auth else "anon",
            "has_http_examples": len(d.http_examples) > 0,
        })

    # Build a compact recon summary
    recon_summary = {
        "endpoints_count": len(recon.endpoints),
        "auth_profiles": [p.label for p in recon.auth_profiles],
        "auth_diffs_count": len(recon.auth_diffs),
        "business_flows": [f.name for f in recon.business_flows],
        "cookies": [],
    }
    for p in recon.auth_profiles:
        if p.cookie_header:
            cookie_names = [c.split("=")[0].strip() for c in p.cookie_header.split(";")]
            recon_summary["cookies"].extend(cookie_names)

    prompt = f"""You are a senior penetration tester prioritizing attack candidates.

## Bug Candidates to Rank
{json.dumps(dossier_summary, indent=2)}

## Recon Context
{json.dumps(recon_summary, indent=2)}

## Task
Re-rank the bug candidates in the order they should be executed, from highest to lowest priority.

Prioritization criteria:
1. Bugs with real HTTP evidence (has_http_examples=true) before blind guesses
2. Higher confidence before lower confidence
3. Authentication escalation first (BAC-02 with cookie tampering is fast, impactful)
4. IDOR/ownership bugs that need a victim session last (need to know what IDs exist)
5. Identify dependency chains: e.g. if BAC-02 escalates to admin, admin access may "enable" BAC-01

For each bug, also list which OTHER bug IDs it "enables" (i.e. exploiting this first would make the next one easier or unlock new attack surface). Use [] if it enables nothing.

Return a JSON array in priority order:
[{{"id": "BUG-001", "enables": ["BUG-002"]}}, {{"id": "BUG-003", "enables": []}}]

JSON array only, no explanation:"""

    response = await llm.chat(
        messages=[
            {"role": "system", "content": "You are a precise security analyst. Return only valid JSON."},
            {"role": "user", "content": prompt},
        ],
        role=Role.HUNTER,
        temperature=0.1,
        max_tokens=800,
    )

    import re
    response = response.strip()
    m = re.search(r'\[.*\]', response, re.DOTALL)
    if not m:
        log.warning("Coordinator: no JSON array in response, keeping original order")
        return dossiers

    ranked_list = json.loads(m.group(0))
    if not isinstance(ranked_list, list):
        return dossiers

    # Build id → order + enables map
    id_to_order: dict[str, int] = {}
    id_to_enables: dict[str, list[str]] = {}
    for i, item in enumerate(ranked_list):
        if isinstance(item, dict) and "id" in item:
            id_to_order[item["id"]] = i
            id_to_enables[item["id"]] = item.get("enables", [])

    # Re-order dossiers
    def sort_key(d: BugDossier) -> int:
        return id_to_order.get(d.id, 999)

    reranked = sorted(dossiers, key=sort_key)

    # Inject enables links into graph_context (non-destructive: only add if not already set)
    from ..contracts.dossier import GraphContext
    for d in reranked:
        enables = id_to_enables.get(d.id, [])
        if enables:
            if d.graph_context is None:
                d.graph_context = GraphContext(enables=enables)
            else:
                d.graph_context.enables = enables

    return reranked
