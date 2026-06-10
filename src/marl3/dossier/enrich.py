"""Dossier enrichment — attaches graph context and evidence rules to BugDossier."""
from __future__ import annotations

from ..contracts.dossier import BugDossier, EvidenceRule, GraphContext
from ..contracts.recon import ReconArtifact
from ..knowledge.provider import get_provider


def enrich_dossier(dossier: BugDossier, recon: ReconArtifact) -> BugDossier:
    """Attach graph context and evidence rules to a dossier in-place."""
    playbook = get_provider()

    # Attach evidence rules from knowledge card if not already set
    if not dossier.evidence_rules:
        try:
            card = playbook.card_for(dossier.pattern_id)
            dossier.evidence_rules = [
                EvidenceRule(
                    key=mk,
                    required=True,
                    description=card.get("success_condition", ""),
                )
                for mk in card.get("required_proof_markers", [])
            ]
        except Exception:
            pass

    # Attach graph context from workflow graph
    if recon.workflow_graph and not dossier.graph_context:
        related_nodes = [
            n.node_id for n in recon.workflow_graph.nodes
            if dossier.endpoint in n.node_id or n.node_id in dossier.endpoint
        ]
        relevant_chains = [
            chain for chain in recon.workflow_graph.chains
            if any(n in chain for n in related_nodes)
        ]
        state_fields: list[str] = []
        for flow in recon.business_flows:
            if any(step in dossier.endpoint for step in flow.steps):
                state_fields.extend(flow.numeric_fields)
        dossier.graph_context = GraphContext(
            related_nodes=related_nodes,
            chains=relevant_chains,
            state_fields=list(set(state_fields)),
        )

    return dossier


def enrich_all(dossiers: list[BugDossier], recon: ReconArtifact) -> list[BugDossier]:
    return [enrich_dossier(d, recon) for d in dossiers]
