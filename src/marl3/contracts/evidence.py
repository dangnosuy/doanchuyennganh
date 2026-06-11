from __future__ import annotations

from typing import Optional, Any
from pydantic import BaseModel, Field

from .enums import ProofKey, VerdictStatus
from .http import HttpExchange


class ProofMarker(BaseModel):
    """Result of evaluating one proof rule against real exchange data."""

    key: ProofKey
    satisfied: bool = False
    detail: str = ""
    exchange_seqs: list[int] = Field(default_factory=list, description="Seq numbers of supporting exchanges")
    extracted: dict[str, Any] = Field(default_factory=dict, description="Extracted field values from response bodies")


class Verdict(BaseModel):
    """Structured outcome from ProofGate.evaluate() — derived from data, not text matching."""

    status: VerdictStatus
    satisfied_markers: list[str] = Field(default_factory=list)
    required_markers: list[str] = Field(default_factory=list)
    missing_markers: list[str] = Field(default_factory=list)
    reason: str = ""
    rule_id: str = ""


class StateSnapshot(BaseModel):
    """For BLF bugs: captures the mutable state before/after manipulation."""

    fields: dict[str, Any] = Field(default_factory=dict)
    exchange_seq: int = 0
    label: str = ""


class Evidence(BaseModel):
    """Full structured evidence produced by ExecutionRunner — consumed by ProofGate + VerifierPanel + Report."""

    bug_id: str
    pattern_id: str
    category: str
    endpoint: str
    method: str
    exchanges: list[HttpExchange] = Field(default_factory=list, description="Ordered capture; bodies on disk via BodyRef")
    proof_markers: list[ProofMarker] = Field(default_factory=list)
    # BLF-specific state tracking
    state_before: Optional[StateSnapshot] = None
    state_after: Optional[StateSnapshot] = None
    state_delta: dict[str, Any] = Field(default_factory=dict)
    # Auth context (labels only — no raw secrets)
    session_context: dict[str, str] = Field(
        default_factory=dict,
        description="label→role mapping, e.g. {'user_a': 'customer', 'admin': 'admin'}"
    )
    exploit_mode: str = Field(default="", description="Recorded for audit; NOT used to gate PoC generation")
    verdict_status: str = Field(default="", description="Deterministic proof-gate verdict, e.g. EXPLOITED")
    notes: str = ""
