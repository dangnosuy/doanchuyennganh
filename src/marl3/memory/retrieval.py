"""ContextRetriever — assembles role-specific memory bundles for agent prompts.

Key invariant: drops WHOLE items when over budget, never slices mid-string.
Every agent prompt goes through bundle_for() — memory is never injected ad-hoc.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .store import MemoryStore
from ..contracts.dossier import BugDossier


@dataclass
class ContextBundle:
    """Memory bundle assembled for a specific role + bug.

    Items are full strings. When rendered for a prompt, items that would
    push over token_budget are dropped as whole units — never mid-sliced.
    """
    role: str
    bug_id: str
    prior_attempts: list[str] = field(default_factory=list)
    relevant_notes: list[str] = field(default_factory=list)
    prior_strategy: Optional[str] = None
    verifier_feedback: Optional[str] = None  # set on PROOF_QUALITY_FAIL re-debate

    def render(self, token_budget: int = 2000) -> str:
        """Render bundle as a prompt section string.

        Drops items as whole units if over budget (approx 4 chars/token).
        Never slices in the middle of any item.
        """
        char_budget = token_budget * 4
        sections: list[str] = []

        if self.prior_attempts:
            sections.append(
                "## Prior Attempts on This Bug\n" +
                "\n".join(f"- {a}" for a in self.prior_attempts[-5:])
            )

        if self.verifier_feedback:
            sections.append(
                "## Verifier Panel Feedback (Why Previous Proof Failed)\n" +
                self.verifier_feedback
            )

        if self.prior_strategy:
            sections.append(
                "## Previously Approved Strategy\n" +
                self.prior_strategy
            )

        if self.relevant_notes:
            sections.append(
                "## Relevant Notes\n" +
                "\n".join(f"- {n}" for n in self.relevant_notes[:10])
            )

        # Priority packing (Codex #4): sections are already ordered most-important-first
        # (attempts, verifier feedback, strategy, notes). Skip a too-large section and keep
        # trying smaller later ones, instead of `break`-ing and dropping everything after the
        # first oversized item.
        result_parts: list[str] = []
        total = 0
        for sec in sections:
            if total + len(sec) > char_budget:
                continue
            result_parts.append(sec)
            total += len(sec)

        if not result_parts:
            return ""
        return "\n\n".join(result_parts)


class ContextRetriever:
    """Single chokepoint for assembling memory into agent prompts."""

    def __init__(self, store: MemoryStore) -> None:
        self._store = store

    def bundle_for(self, role: str, dossier: BugDossier, verifier_feedback: Optional[str] = None) -> ContextBundle:
        """Return a ContextBundle tailored for the given role and bug."""
        bug_id = dossier.id
        attempts = self._store.get_attempts(bug_id)
        notes = [n["note"] for n in self._store.get_notes(bug_id=bug_id, role=role)]
        strategy = self._store.get_strategy(bug_id) if role in ("red", "exec") else None

        return ContextBundle(
            role=role,
            bug_id=bug_id,
            prior_attempts=attempts,
            relevant_notes=notes,
            prior_strategy=strategy,
            verifier_feedback=verifier_feedback,
        )
