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

_RESP_BODY_CAP = 3000  # max chars of response body fed to verifier prompt


class VerifierAgent:
    """Independent verifier that defaults to NOT confirming.

    Does not see debate history or strategy — only the Evidence.
    """

    def __init__(self, llm: LLMClient, verifier_id: str, body_store: BodyStore | None = None) -> None:
        self._llm = llm
        self._id = verifier_id
        self._bs = body_store

    async def assess(self, dossier: BugDossier, evidence: Evidence) -> VerifierVerdict:
        """Assess evidence and return a verdict, defaulting to confirmed=False."""
        # Build exchange summaries with head_preview for richer context
        exchange_views = []
        for ex in evidence.exchanges[:10]:
            # Surface the REQUEST side — the tampered cookie / form body is the exploit payload
            req_cookie = ""
            for k, v in (ex.request_headers or {}).items():
                if k.lower() == "cookie":
                    req_cookie = v
            req_body = ""
            if ex.request_body_ref:
                req_body = (ex.request_body_ref.head_preview or "")[:200]
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
        )

        messages = [
            {"role": "system", "content": prompt},
            {"role": "user", "content": "Assess the evidence above. Default to confirmed=false unless the evidence is unambiguous."},
        ]

        raw = await self._llm.chat(
            messages=messages,
            role=Role.VERIFIER,
            temperature=0.0,
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
                    return VerifierVerdict(
                        verifier_id=self._id,
                        confirmed=bool(data.get("confirmed", False)),
                        confidence=float(data.get("confidence", 0.0)),
                        rationale=str(data.get("rationale", raw)),
                        cited_markers=data.get("cited_markers", []),
                        refutation_points=data.get("refutation_points", []),
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
