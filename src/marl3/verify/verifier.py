"""Single independent verifier — refute-by-default at temperature 0."""
from __future__ import annotations

import json
import logging
import re

from ..config import AppConfig
from ..contracts.dossier import BugDossier
from ..contracts.enums import Role
from ..contracts.evidence import Evidence
from ..contracts.results import VerifierVerdict
from ..llm.client import LLMClient
from ..prompts.registry import render
from ..recon.body_store import BodyStore

log = logging.getLogger("marl3.verify")

_RESP_BODY_CAP = 20_000  # max chars of response body fed to verifier prompt


_LENS_TEMPERATURE = {
    "technical": 0.0,
    "impact":    0.1,
    "skeptic":   0.2,
}

_LENS_INSTRUCTIONS = {
    "technical": (
        "You are the **technical verifier**. Focus strictly on raw HTTP evidence: "
        "status codes, field values, proof markers, and request payloads. "
        "Apply the pattern criteria mechanically. Ignore business context — "
        "if the data satisfies the criteria, confirm; if not, reject."
    ),
    "impact": (
        "You are the **impact verifier**. Focus on what was actually exposed or changed: "
        "what sensitive data did the attacker obtain? What unauthorized state change occurred? "
        "If the technical evidence is ambiguous, consider the real-world harm that could result "
        "and whether the evidence is consistent with a genuine exploitation."
    ),
    "skeptic": (
        "You are the **skeptic verifier**. Your primary job is to find reasons to REJECT this finding. "
        "Ask: could this be a public endpoint? Could the data belong to the attacker themselves? "
        "Could this be an intended feature (e.g. order sharing)? Is the state change expected behaviour? "
        "Only confirm if you genuinely cannot find a plausible alternative explanation."
    ),
}


class VerifierAgent:
    """Independent verifier that defaults to NOT confirming.

    Does not see debate history or strategy — only the Evidence.
    Each instance can be assigned a lens (technical / impact / skeptic) to
    create meaningful diversity across the panel even at low temperature.
    """

    def __init__(
        self,
        llm: LLMClient,
        verifier_id: str,
        body_store: BodyStore | None = None,
        lens: str = "",
    ) -> None:
        self._llm = llm
        self._id = verifier_id
        self._bs = body_store
        self._lens = lens

    async def assess(
        self,
        dossier: BugDossier,
        evidence: Evidence,
        verification_questions: list[str] | None = None,
    ) -> VerifierVerdict:
        """Assess evidence and return a verdict, defaulting to confirmed=False."""
        # Build exchange summaries with head_preview for richer context
        exchange_views = []
        for ex in evidence.exchanges[:20]:
            # Surface the REQUEST side — the tampered cookie / form body is the exploit payload
            req_cookie = ""
            for k, v in (ex.request_headers or {}).items():
                if k.lower() == "cookie":
                    req_cookie = v
            req_body = ""
            if ex.request_body_ref:
                req_body = (ex.request_body_ref.head_preview or "")[:1000]
            # Read full response body from disk when BodyStore is available — the verifier
            # needs to see the actual victim data (email, name, etc.) to confirm IDOR,
            # not just a 200-char head_preview that may truncate the critical fields.
            resp_body = ""
            if ex.response_body_ref:
                if self._bs:
                    try:
                        raw = self._bs.get(ex.response_body_ref.blob_id)
                        decoded = raw.decode("utf-8", "replace")
                        try:
                            resp_body = json.dumps(json.loads(decoded), indent=2)[:_RESP_BODY_CAP]
                        except Exception:
                            resp_body = decoded[:_RESP_BODY_CAP]
                    except Exception:
                        resp_body = ex.response_body_ref.head_preview or ""
                else:
                    resp_body = ex.response_body_ref.head_preview or ""
            view = {
                "seq": ex.seq,
                "actor": ex.actor,
                "method": ex.method,
                "url": ex.url,
                "status": ex.status,
                "request_cookie": req_cookie,
                "request_body": req_body,
                "id_fields": ex.id_fields,
                "numeric_fields": {k: v for k, v in ex.numeric_fields.items() if k != "_resp_len"},
                "json_keys": ex.json_keys,
                "html_title": ex.html_title,
                "head_preview": resp_body,
            }
            exchange_views.append(type("ExView", (), view)())

        prompt = render(
            "verifier_system",
            bug=dossier,
            pattern_id=evidence.pattern_id,
            title=dossier.title,
            method=evidence.method,
            endpoint=evidence.endpoint,
            exchanges=exchange_views,
            proof_markers=evidence.proof_markers,
            state_delta=evidence.state_delta if evidence.state_delta else None,
            session_context=evidence.session_context or {},
            verifier_lens=_LENS_INSTRUCTIONS.get(self._lens, ""),
            verification_questions=verification_questions or [],
        )

        temperature = _LENS_TEMPERATURE.get(self._lens, 0.0)

        q_note = ""
        if verification_questions:
            q_note = (
                " Also answer the verification questions in the `question_answers` array "
                f"({len(verification_questions)} question(s), one boolean each)."
            )
        messages = [
            {"role": "system", "content": prompt},
            {"role": "user", "content": f"Assess the evidence above. Default to confirmed=false unless the evidence is unambiguous.{q_note}"},
        ]

        raw = await self._llm.chat(
            messages=messages,
            role=Role.VERIFIER,
            temperature=temperature,
            max_tokens=4096,
        )

        return self._parse_verdict(raw)

    def _parse_verdict(self, raw: str) -> VerifierVerdict:
        # Use raw_decode to find first valid JSON object (handles nested braces correctly)
        decoder = json.JSONDecoder()
        pos = 0
        while pos < len(raw):
            idx = raw.find('{', pos)
            if idx == -1:
                break
            try:
                data, _ = decoder.raw_decode(raw, idx)
                if isinstance(data, dict) and "confirmed" in data:
                    raw_qa = data.get("question_answers", [])
                    qa = [bool(x) for x in raw_qa] if isinstance(raw_qa, list) else []
                    return VerifierVerdict(
                        verifier_id=self._id,
                        confirmed=bool(data.get("confirmed", False)),
                        confidence=float(data.get("confidence", 0.0)),
                        rationale=str(data.get("rationale", raw)),
                        cited_markers=data.get("cited_markers", []),
                        refutation_points=data.get("refutation_points", []),
                        question_answers=qa,
                    )
                pos = idx + 1
            except json.JSONDecodeError:
                pos = idx + 1

        # Fallback: text heuristic
        lower = raw.lower()
        confirmed = '"confirmed": true' in lower or '"confirmed":true' in lower
        return VerifierVerdict(
            verifier_id=self._id,
            confirmed=confirmed,
            confidence=0.5 if confirmed else 0.1,
            rationale=raw,
        )
