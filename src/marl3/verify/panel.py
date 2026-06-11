"""VerifierPanel — 3 independent verifiers, majority vote (≥2/3 → EXPLOITED).

Each verifier runs independently:
- Does NOT see debate history or Red strategy
- Only sees Evidence (structured data from RecordingHttpClient)
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
        self._verifiers = [VerifierAgent(llm, f"verifier_{i+1}", body_store=body_store) for i in range(count)]

    async def adjudicate(
        self,
        dossier: BugDossier,
        evidence: Evidence,
    ) -> list[VerifierVerdict]:
        """Run all verifiers in parallel and return their verdicts.

        Caller checks: confirmed_count >= ceil(count/2) for EXPLOITED.
        """
        verdicts = await asyncio.gather(
            *[v.assess(dossier, evidence) for v in self._verifiers],
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
        threshold = (len(self._verifiers) + 1) // 2
        verdict_str = "EXPLOITED" if confirmed >= threshold else "not confirmed"
        log.info(f"{dossier.id}: verifiers {confirmed}/{len(results)} → {verdict_str}")

        return results
