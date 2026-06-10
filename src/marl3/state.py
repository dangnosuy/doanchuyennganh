from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from .contracts.enums import BugState
from .contracts.dossier import BugDossier
from .contracts.evidence import Evidence
from .contracts.results import DebateThread, Finding, PocArtifact, VerifierVerdict


# Declarative transition table — the ONLY place state transitions are defined.
# Key: (current_state, event) → next_state
TRANSITIONS: dict[tuple[BugState, str], BugState] = {
    (BugState.QUEUED,             "START_DEBATE"):      BugState.DEBATING,
    (BugState.DEBATING,           "APPROVED"):          BugState.DEBATE_APPROVED,
    (BugState.DEBATING,           "STOP"):              BugState.NOT_EXPLOITED,
    (BugState.DEBATING,           "MAX_ROUNDS"):        BugState.NOT_EXPLOITED,
    (BugState.DEBATING,           "INSUFFICIENT_CONTEXT"): BugState.SKIPPED_NO_EVIDENCE,
    (BugState.DEBATING,           "ERROR"):             BugState.ERROR,
    (BugState.DEBATE_APPROVED,    "START_EXEC"):        BugState.EXECUTING,
    (BugState.EXECUTING,          "EXEC_DONE"):         BugState.VERIFYING,
    (BugState.EXECUTING,          "EXEC_FAILED"):       BugState.NOT_EXPLOITED,
    (BugState.EXECUTING,          "ERROR"):             BugState.ERROR,
    (BugState.VERIFYING,          "CONFIRMED"):         BugState.EXPLOITED,
    (BugState.VERIFYING,          "PROOF_FAIL"):        BugState.PROOF_QUALITY_FAIL,
    (BugState.VERIFYING,          "REJECTED"):          BugState.NOT_EXPLOITED,
    (BugState.VERIFYING,          "ERROR"):             BugState.ERROR,
    # Re-debate after proof fail (within budget)
    (BugState.PROOF_QUALITY_FAIL, "RETRY_DEBATE"):      BugState.DEBATING,
    (BugState.PROOF_QUALITY_FAIL, "GIVE_UP"):           BugState.NOT_EXPLOITED,
}


@dataclass
class BugRun:
    """Mutable per-bug runtime state. One instance per bug; create new for next bug."""

    dossier: BugDossier
    state: BugState = BugState.QUEUED
    debate_rounds: int = 0
    exec_retries: int = 0
    verify_retries: int = 0
    frozen_strategy: str = ""
    frozen_execution_guide: str = ""
    frozen_success_condition: str = ""
    thread: Optional[DebateThread] = field(default=None)
    evidence: Optional[Evidence] = field(default=None)
    poc: Optional[PocArtifact] = field(default=None)
    finding: Optional[Finding] = field(default=None)
    panel: list[VerifierVerdict] = field(default_factory=list)
    verifier_rationale: str = ""  # fed back to Red on PROOF_QUALITY_FAIL
    started_at: float = field(default_factory=time.monotonic)
    error_message: str = ""

    # Guardrail limits (injected from config)
    max_debate_rounds: int = 3
    max_exec_retries: int = 1
    max_verify_retries: int = 1
    per_bug_wall_clock_s: int = 600

    def transition(self, event: str) -> BugState:
        """Apply event; raise ValueError if the transition is not in the table."""
        key = (self.state, event)
        if key not in TRANSITIONS:
            raise ValueError(
                f"BugRun({self.dossier.id}): no transition for ({self.state}, {event!r})"
            )
        self.state = TRANSITIONS[key]
        return self.state

    @property
    def wall_clock_exceeded(self) -> bool:
        return (time.monotonic() - self.started_at) > self.per_bug_wall_clock_s

    @property
    def debate_budget_exhausted(self) -> bool:
        return self.debate_rounds >= self.max_debate_rounds

    @property
    def is_terminal(self) -> bool:
        return self.state in (
            BugState.EXPLOITED,
            BugState.NOT_EXPLOITED,
            BugState.SKIPPED,
            BugState.SKIPPED_NO_EVIDENCE,
            BugState.ERROR,
        )
