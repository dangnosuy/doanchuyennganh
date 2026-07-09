"""VerifierPanel — 3 independent verifiers run as a PRE-GATE sanity check.

Role in the pipeline:
  verify.py calls adjudicate() BEFORE ProofGate runs. Panel reads raw HTTP exchanges
  (proof_markers is empty at call time) and votes whether execution produced any
  meaningful HTTP evidence worth running the expensive ProofGate classifier on.

  Fast-fail condition: if ALL verifiers reject (0/N confirmed) AND there are no 2xx
  responses in evidence, verify.py skips ProofGate entirely — PROOF_QUALITY_FAIL.

  ProofGate (deterministic code + LLM classifier) is the SOLE AUTHORITY on EXPLOITED.
  Panel vote determines whether ProofGate runs, not whether the bug is confirmed.

Each verifier runs independently:
- Does NOT see debate history or Red strategy
- Only sees Evidence (raw HTTP exchanges, no proof_markers yet)
- Defaults to NOT confirming (refute-by-default, temperature=0)
- Runs in parallel (asyncio.gather)
"""
from __future__ import annotations

import asyncio
import logging

from ..config import AppConfig
from ..contracts.dossier import BugDossier
from ..contracts.evidence import Evidence
from ..contracts.results import VerifierVerdict
from ..llm.client import LLMClient
from ..recon.body_store import BodyStore
from .verifier import VerifierAgent

log = logging.getLogger("marl3.verify.panel")


class VerifierPanel:
    def __init__(self, llm: LLMClient, cfg: AppConfig, body_store: BodyStore | None = None) -> None:
        self._llm = llm
        self._cfg = cfg
        count = cfg.verifier.count
        _lenses = ["technical", "impact", "skeptic"]
        self._verifiers = [
            VerifierAgent(llm, f"verifier_{i+1}", body_store=body_store,
                          lens=_lenses[i] if i < len(_lenses) else "")
            for i in range(count)
        ]

    async def adjudicate(
        self,
        dossier: BugDossier,
        evidence: Evidence,
        verification_questions: list[str] | None = None,
    ) -> tuple[list[VerifierVerdict], int]:
        """Run all verifiers in parallel and return (verdicts, questions_confirmed).

        questions_confirmed = number of verification questions where ≥ majority of verifiers
        answered YES. Used by verify.py as the LLM-question vote path alongside ProofGate.

        Caller (verify.py) uses the results as:
          - questions_confirmed ≥ 2 → LLM_CONFIRMED (OR'd with ProofGate result)
          - 0/N confirmed + no 2xx → skip ProofGate
          - ≥1 confirmed OR has 2xx → run ProofGate (authoritative verdict)
        """
        questions = verification_questions or []
        verdicts = await asyncio.gather(
            *[v.assess(dossier, evidence, verification_questions=questions) for v in self._verifiers],
            return_exceptions=True,
        )

        results: list[VerifierVerdict] = []
        for i, v in enumerate(verdicts):
            if isinstance(v, Exception):
                log.warning(f"Verifier {i+1} failed: {v}")
                results.append(VerifierVerdict(
                    verifier_id=f"verifier_{i+1}",
                    confirmed=False,
                    confidence=0.0,
                    rationale=f"Verifier failed: {v}",
                ))
            else:
                results.append(v)

        for v in results:
            mark = "✅" if v.confirmed else "❌"
            log.info(f"{dossier.id}   {mark} {v.verifier_id} (conf {v.confidence:.2f}): {' '.join(v.rationale.split())[:120]}")
        confirmed = sum(1 for v in results if v.confirmed)
        log.info(f"{dossier.id}: panel pre-check {confirmed}/{len(results)} confirmed (ProofGate is authoritative)")

        # Compute per-question majority vote across all verifiers
        questions_confirmed = 0
        if questions:
            n = len(questions)
            for qi in range(n):
                yes_count = sum(
                    1 for v in results
                    if len(v.question_answers) > qi and v.question_answers[qi]
                )
                threshold = len(results) / 2  # majority = strictly more than half
                if yes_count > threshold:
                    questions_confirmed += 1
            log.info(
                f"{dossier.id}: verification questions {questions_confirmed}/{n} passed "
                f"(≥majority verifiers answered YES per question)"
            )

        return results, questions_confirmed
