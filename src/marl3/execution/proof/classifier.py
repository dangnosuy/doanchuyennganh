"""Zero-context LLM fact extractor for the proof gates.

Principle: the LLM is an EXTRACTOR, not a voter. It looks at a single HTTP response
with NO knowledge of the hypothesis/strategy/pattern and answers closed factual
questions ("is this an admin page?", "does this expose other users' PII?"). The
deterministic gate then applies the access-control rule using those facts. This
reduces the brittleness of pure string matching without letting model opinion
decide the verdict.

Best-effort: if the LLM is unavailable or returns junk, callers get {} and fall
back to the existing string/structured heuristics — no regression.
"""
from __future__ import annotations

import json
import logging
import re

from ...contracts.enums import Role

log = logging.getLogger("marl3.proof.classifier")

_MAX_TEXT = 6000  # chars of response fed to the extractor (bounded, head only)

_PROMPT = """You are a precise fact extractor for a security tool. Look ONLY at the HTTP \
response below and answer factually about WHAT IT CONTAINS. Do not guess intent or \
speculate about vulnerabilities.

Return ONLY a JSON object, no prose:
{{"privileged_page": <bool>, "exposes_other_users_pii": <bool>, "distinct_user_records": <int>}}

Definitions:
- privileged_page: true if this page is an admin/staff/management console or shows \
admin-only controls (user management, all-orders view, site configuration, role editing).
- exposes_other_users_pii: true if the body reveals personal data (email, phone, \
address, balance, points, password/hash, role) belonging to USERS — especially more than one.
- distinct_user_records: count of distinct user records containing such PII (0 if none).

HTTP RESPONSE:
{text}
"""


async def classify_responses(llm, exchanges, body_store, max_calls: int = 3) -> dict[int, dict]:
    """Run the extractor on a few representative 2xx responses.

    Returns {exchange_seq: {"privileged_page": bool, "exposes_other_users_pii": bool,
    "distinct_user_records": int}}. Empty dict if no LLM or nothing to classify.
    """
    if llm is None:
        return {}

    # Pick candidate 2xx exchanges, preferring the most data-rich responses (largest
    # body) — that's where data exposure shows. Dedup by (endpoint, actor) keeping the
    # largest, so a full-list response wins over a single-record one on the same path.
    twoxx = [ex for ex in exchanges if ex.status in range(200, 300)]
    twoxx.sort(key=_resp_size, reverse=True)
    candidates = []
    seen: set[tuple] = set()
    for ex in twoxx:
        key = (ex.endpoint, ex.actor)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(ex)
        if len(candidates) >= max_calls:
            break

    facts: dict[int, dict] = {}
    for ex in candidates:
        text = _read_text(ex, body_store)
        if not text.strip():
            continue
        parsed = await _classify_one(llm, text[:_MAX_TEXT])
        if parsed is not None:
            facts[ex.seq] = parsed
    return facts


async def _classify_one(llm, text: str) -> dict | None:
    # Reasoning models (minimax/deepseek) spend tokens thinking before the JSON and
    # sometimes ramble without ever emitting it. Give ample room AND retry with a small
    # temperature bump so a fresh sample can land the JSON (temp=0 would repeat verbatim).
    msg = [{"role": "user", "content": _PROMPT.format(text=text)}]
    for attempt in range(3):
        try:
            raw = await llm.chat(
                messages=msg,
                role=Role.VERIFIER,
                temperature=0.0 if attempt == 0 else 0.4,
                max_tokens=1200,
            )
        except Exception as e:
            log.debug(f"classifier LLM call failed (attempt {attempt + 1}): {e}")
            continue
        facts = _parse(raw)
        if facts is not None:
            return facts
    return None


def _parse(raw: str) -> dict | None:
    if not raw:
        return None
    # Reasoning models emit prose THEN the JSON. Prefer the last flat {...} object that
    # actually contains our key; fall back to the last balanced object.
    obj = None
    flat = [m.group(0) for m in re.finditer(r"\{[^{}]*\}", raw) if "privileged_page" in m.group(0)]
    for cand in reversed(flat):
        try:
            obj = json.loads(cand)
            break
        except json.JSONDecodeError:
            continue
    if obj is None:
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if not m:
            return None
        try:
            obj = json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
    if not isinstance(obj, dict):
        return None
    return {
        "privileged_page": bool(obj.get("privileged_page", False)),
        "exposes_other_users_pii": bool(obj.get("exposes_other_users_pii", False)),
        "distinct_user_records": int(obj.get("distinct_user_records", 0) or 0),
    }


def _resp_size(exchange) -> float:
    """Approx response body size, used to prefer data-rich responses for classification."""
    nf = getattr(exchange, "numeric_fields", None) or {}
    if "_resp_len" in nf:
        return nf["_resp_len"]
    ref = getattr(exchange, "response_body_ref", None)
    return float(getattr(ref, "size", 0) or 0) if ref else 0.0


def _read_text(exchange, body_store) -> str:
    if not exchange.response_body_ref:
        return ""
    try:
        return body_store.get(exchange.response_body_ref.blob_id).decode("utf-8", "replace")
    except Exception:
        return exchange.response_body_ref.head_preview or ""
