from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field

from .enums import BugCategory, Severity
from .http import HttpExchange


class AuthRequirement(BaseModel):
    attacker_role: str = Field(description="Label of the attacker session, e.g. 'user_a'")
    victim_role: Optional[str] = Field(default=None, description="Label of the victim session if needed (IDOR)")
    admin_role: Optional[str] = None
    notes: str = ""


class EvidenceRule(BaseModel):
    """A declarative proof rule that will be evaluated by ProofGate against real Evidence."""

    key: str = Field(description="ProofKey enum value as string")
    required: bool = True
    description: str = ""


class GraphContext(BaseModel):
    """Relevant slice of the workflow graph for this bug."""

    related_nodes: list[str] = Field(default_factory=list)
    chains: list[list[str]] = Field(default_factory=list)
    state_fields: list[str] = Field(default_factory=list)
    # Coordinator-injected dependency links
    enables: list[str] = Field(default_factory=list, description="Bug IDs that become easier/unlocked after this one is exploited")
    depends_on: list[str] = Field(default_factory=list, description="Bug IDs that should be exploited before this one")


class HttpExample(BaseModel):
    """A real HTTP exchange from recon, attached as concrete evidence to a dossier."""

    exchange: HttpExchange
    annotation: str = ""


class BugDossier(BaseModel):
    """Structured bug candidate produced by the hunter phase → bugs.json entry."""

    id: str = Field(description="e.g. BUG-001")
    category: BugCategory
    pattern_id: str = Field(description="e.g. BAC-03, BLF-02")
    title: str
    risk: Severity
    endpoint: str
    method: str
    hypothesis: str = Field(description="Specific, grounded in observed fields from recon")
    exploit_approach: str = Field(description="Concrete steps derived from recon evidence")
    auth: AuthRequirement
    http_examples: list[HttpExample] = Field(default_factory=list, description="Full exchanges from recon, never truncated")
    graph_context: Optional[GraphContext] = None
    evidence_rules: list[EvidenceRule] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    notes: str = ""
