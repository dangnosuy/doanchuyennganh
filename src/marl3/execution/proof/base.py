"""ProofGate base — evaluates Evidence objects, not text strings.

MARL anti-pattern fixed:
  Old: _proof_quality_block() did substring matching on lowercased Exec text
  New: evaluate() reads Evidence.exchanges → response body from BodyStore → parses JSON
       Returns a Verdict with structured satisfied/missing markers.
"""
from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod

from ...contracts.evidence import Evidence, ProofMarker, Verdict
from ...contracts.enums import ProofKey, VerdictStatus
from ...recon.body_store import BodyStore

log = logging.getLogger("marl3.proof")


class ProofGate(ABC):
    def __init__(self, body_store: BodyStore) -> None:
        self._bs = body_store

    @abstractmethod
    def evaluate(self, evidence: Evidence, llm_facts: dict | None = None) -> Verdict:
        """Evaluate evidence and return a structured Verdict.

        llm_facts: optional {exchange_seq: {privileged_page, exposes_other_users_pii,
        distinct_user_records}} from the zero-context classifier. Used as extra signal
        feeding the deterministic rule — never as the verdict itself.
        """
        ...

    @staticmethod
    def _family(path: str) -> str:
        """Normalise an endpoint path to its family (numeric/uuid/{x} segments → {id})."""
        path = (path or "").split("?")[0].rstrip("/") or "/"
        parts: list[str] = []
        for seg in path.split("/"):
            if not seg:
                continue
            if seg.isdigit() or re.fullmatch(r"[0-9a-fA-F-]{16,36}", seg) or (seg.startswith("{") and seg.endswith("}")):
                parts.append("{id}")
            else:
                parts.append(seg)
        return "/" + "/".join(parts) if parts else "/"

    def _in_scope(self, ex_endpoint: str, target: str) -> bool:
        """True if an exchange belongs to the dossier's target endpoint family.

        Prevents a finding from being 'proven' by an exchange the exec agent wandered
        into on a DIFFERENT endpoint (e.g. crediting /orders with a /api/v1/users leak).
        Same family, or one is a path-extension of the other (e.g. /users vs /users/{id}).
        """
        if not target:
            return True
        fe, ft = self._family(ex_endpoint), self._family(target)
        fe_p, ft_p = fe.rstrip("/"), ft.rstrip("/")
        return fe == ft or fe_p.startswith(ft_p + "/") or ft_p.startswith(fe_p + "/")

    def _scope(self, evidence) -> list:
        """Exchanges relevant to this dossier's target endpoint only."""
        target = getattr(evidence, "endpoint", "") or ""
        return [ex for ex in evidence.exchanges if self._in_scope(ex.endpoint, target)]

    def _read_json(self, blob_id: str) -> object:
        """Read a body blob and parse as JSON; return None on failure."""
        try:
            return self._bs.get_json(blob_id)
        except Exception:
            return None

    def _response_obj(self, exchange, default=None):
        if exchange.response_body_ref:
            obj = self._read_json(exchange.response_body_ref.blob_id)
            return obj if obj is not None else default
        return default

    def _response_text(self, exchange) -> str:
        """Read a response body as decoded text (HTML or any non-JSON)."""
        if not exchange.response_body_ref:
            return ""
        try:
            return self._bs.get(exchange.response_body_ref.blob_id).decode("utf-8", "replace")
        except Exception:
            return exchange.response_body_ref.head_preview or ""

    def _request_fields(self, exchange) -> dict:
        """Parse the request body into a {field: value} dict (form or JSON)."""
        if not exchange.request_body_ref:
            return {}
        try:
            raw = self._bs.get(exchange.request_body_ref.blob_id).decode("utf-8", "replace")
        except Exception:
            return {}
        raw = raw.strip()
        if raw.startswith("{"):
            import json
            try:
                obj = json.loads(raw)
                return obj if isinstance(obj, dict) else {}
            except Exception:
                return {}
        from urllib.parse import parse_qsl
        return dict(parse_qsl(raw))

    def _make_verdict(
        self,
        markers: list[ProofMarker],
        required_keys: list[ProofKey],
        rule_id: str,
    ) -> Verdict:
        satisfied = [m.key.value for m in markers if m.satisfied]
        required = [k.value for k in required_keys]
        missing = [k for k in required if k not in satisfied]

        if not missing:
            status = VerdictStatus.EXPLOITED
        elif satisfied:
            status = VerdictStatus.INFO_EXPOSURE_ONLY
        else:
            status = VerdictStatus.FAILED

        return Verdict(
            status=status,
            satisfied_markers=satisfied,
            required_markers=required,
            missing_markers=missing,
            reason=_reason(markers, missing),
            rule_id=rule_id,
        )


def _reason(markers: list[ProofMarker], missing: list[str]) -> str:
    parts = []
    for m in markers:
        flag = "✓" if m.satisfied else "✗"
        parts.append(f"{flag} {m.key.value}: {m.detail}")
    if missing:
        parts.append(f"Missing required markers: {missing}")
    return " | ".join(parts)
