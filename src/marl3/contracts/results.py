from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field

from .enums import BugCategory, BugState, DebateVerdict, Severity, VerdictStatus
from .evidence import Evidence, Verdict


class DebateMessage(BaseModel):
    role: str = Field(description="'red', 'blue', or 'system'")
    round: int = 0
    content: str = Field(description="Full verbatim content — never truncated")
    verdict_token: Optional[DebateVerdict] = None
    addressed_points: list[str] = Field(default_factory=list, description="Blue rejection points that Red addressed")


class DebateThread(BaseModel):
    """Append-only debate transcript.

    render_for() drops WHOLE oldest turns when over budget — never slices mid-string.
    """

    bug_id: str
    messages: list[DebateMessage] = Field(default_factory=list)

    def append(self, msg: DebateMessage) -> None:
        self.messages.append(msg)

    def render_for(self, viewer: str, token_budget: int = 8000) -> str:
        """Return the thread as a prompt string.

        Drops oldest turns as whole units if over token_budget (approx 4 chars/token).
        Always preserves the most recent opponent message in full.
        """
        char_budget = token_budget * 4
        lines: list[str] = []
        for msg in self.messages:
            prefix = f"[{msg.role.upper()} round={msg.round}]"
            lines.append(f"{prefix}\n{msg.content}\n")

        full = "\n---\n".join(lines)
        if len(full) <= char_budget:
            return full

        # Drop oldest turns as whole units — but NEVER drop the most recent turn (Codex #5):
        # Red must always see Blue's latest critique to rebut it. Keep at least the last turn,
        # truncating it with a clear marker only if it alone exceeds the budget.
        kept = list(lines)
        dropped = 0
        while len(kept) > 1 and len("\n---\n".join(kept)) > char_budget:
            kept.pop(0)
            dropped += 1

        # If the single remaining (newest) turn still overflows, hard-truncate it explicitly.
        # Clamp the min keep to the char_budget itself so we never EXCEED the budget.
        if kept and len(kept[-1]) > char_budget:
            keep_chars = max(min(char_budget - 80, len(kept[-1])), 100)
            kept[-1] = kept[-1][:keep_chars] + "\n…[latest turn truncated to fit budget]"

        header = f"[{dropped} older turns omitted to fit context budget]\n\n" if dropped else ""
        return header + "\n---\n".join(kept)


class VerifierVerdict(BaseModel):
    verifier_id: str
    confirmed: bool = Field(default=False, description="Default False (refute-by-default)")
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    rationale: str = Field(description="Full reasoning — never truncated")
    cited_markers: list[str] = Field(default_factory=list)
    refutation_points: list[str] = Field(default_factory=list, description="Specific reasons why evidence does not confirm the vulnerability")
    question_answers: list[bool] = Field(default_factory=list, description="Yes/no answers to verification questions from Red, in order")


class PocArtifact(BaseModel):
    path: str = Field(description="Relative path to Burp-style PoC file, e.g. pocs/poc_BUG-001.txt")
    runnable: bool = Field(default=True, description="Always True — plain text, no execution needed")
    reproduced: bool = Field(default=False, description="True if proof markers were satisfied")
    reproduce_log_path: str = ""
    exchange_count: int = 0
    sha256: str = ""


class Finding(BaseModel):
    """The complete result for one bug — the unit of the report."""

    bug_id: str
    title: str
    pattern_id: str
    category: BugCategory
    severity: Severity
    status: BugState
    endpoint: str
    method: str
    hypothesis: str
    summary: str = ""
    debate_transcript: Optional[DebateThread] = None
    verdict: Optional[Verdict] = None
    evidence: Optional[Evidence] = None
    panel: list[VerifierVerdict] = Field(default_factory=list)
    panel_decision: str = ""
    poc: Optional[PocArtifact] = None
    remediation: str = ""
    discovered_by: str = "marl3"

    # ── Runtime metrics (benchmark instrumentation) ──────────────────────────
    debate_rounds: int = Field(default=0, description="Total debate rounds for this bug")
    verify_retries: int = Field(default=0, description="Number of verify→re-debate cycles")
    exec_retries: int = Field(default=0, description="Number of exec retries")
    elapsed_s: float = Field(default=0.0, description="Wall-clock seconds spent on this bug")
    failure_mode: str = Field(default="", description="Classified failure reason if not exploited")
