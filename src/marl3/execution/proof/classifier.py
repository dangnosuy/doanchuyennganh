"""Zero-context LLM fact extractor for the proof gates — per-pattern questions.

Principle: the LLM is an EXTRACTOR, not a voter. For each pattern it answers a small
set of closed factual questions about the HTTP response ("what is the owner field
value?", "was the final step confirmed?"). The deterministic gate then applies its
access-control rule using those facts. This lets the gate handle non-standard field
names, non-English responses, and unusual app structures without string-matching
against a fixed vocabulary.

Per-pattern isolation: each pattern gets its own question set so the extractor is
focused and the JSON schema is narrow. A BAC-03 run never sees admin-page questions;
a BLF-05 run never sees owner-field questions. This reduces hallucination and keeps
token cost low.

Best-effort: if the LLM is unavailable or returns junk, callers get {} and gates
fall back to existing structural heuristics — no regression.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

from ...contracts.enums import Role

log = logging.getLogger("marl3.proof.classifier")

_MAX_TEXT = 6000  # chars of response body fed to extractor

# ---------------------------------------------------------------------------
# Per-pattern prompt templates
# ---------------------------------------------------------------------------

_HEADER = (
    "You are a precise fact extractor for a security tool. "
    "Look ONLY at the HTTP response below and answer factually about WHAT IT CONTAINS. "
    "Do not guess intent or speculate about vulnerabilities. "
    "Return ONLY a JSON object, no prose.\n\n"
)

# BAC-01 / BAC-06 — admin / privileged area access
_PROMPT_BAC_ADMIN = _HEADER + """\
Schema:
{"privileged_page": <bool>, "exposes_other_users_pii": <bool>, "distinct_user_records": <int>}

Definitions:
- privileged_page: true if this is an admin/staff/management console or shows admin-only
  controls (user management, all-orders view, site configuration, role editing).
- exposes_other_users_pii: true if the body reveals personal data (email, phone, address,
  balance, password/hash, role) belonging to MULTIPLE users.
- distinct_user_records: count of distinct user records containing such PII (0 if none).

HTTP RESPONSE:
{text}
"""

# BAC-02 — parameter / cookie privilege escalation
_PROMPT_BAC_PARAM = _HEADER + """\
Schema:
{"privileged_page": <bool>, "admin_content_visible": <bool>, "role_in_response": <"admin"|"user"|null>}

Definitions:
- privileged_page: true if this page is an admin/staff/management console.
- admin_content_visible: true if admin-only content (user list, config, role editor) is rendered.
- role_in_response: if the response body contains a role or privilege indicator, return its value
  ("admin", "user", etc.); null if not found.

HTTP RESPONSE:
{text}
"""

# BAC-03 / BAC-05 — IDOR / horizontal privilege escalation
_PROMPT_BAC_IDOR = _HEADER + """\
Schema:
{"owner_field_name": <string|null>, "owner_field_value": <string|number|null>,
 "email_in_response": <string|null>, "username_in_response": <string|null>}

Definitions:
- owner_field_name: name of the field in the response that identifies who OWNS or CREATED
  this resource (e.g. "userId", "user_id", "ownerId", "createdBy", "pemilik", "benutzer",
  "chủ_đơn" — any language). null if no such field exists.
- owner_field_value: the VALUE of that field (ID number or string). null if field not found.
- email_in_response: first email address found in the response body. null if none.
- username_in_response: first username or display name found. null if none.

HTTP RESPONSE:
{text}
"""

# BAC-04 — HTTP method override
_PROMPT_BAC_METHOD = _HEADER + """\
Schema:
{"resource_modified": <bool>, "action_confirmed": <bool>, "error_in_response": <bool>}

Definitions:
- resource_modified: true if the response indicates a resource was deleted, updated, or
  otherwise mutated (success message, empty body with 2xx, confirmation text).
- action_confirmed: true if the response explicitly confirms the intended action succeeded.
- error_in_response: true if the response contains an error or rejection message.

HTTP RESPONSE:
{text}
"""

# BLF-01 — price / amount tampering
_PROMPT_BLF_PRICE = _HEADER + """\
Schema:
{"price_or_total_value": <number|null>, "order_accepted": <bool>,
 "total_is_negative_or_zero": <bool>, "currency": <string|null>}

Definitions:
- price_or_total_value: numeric value of the price, total, amount, or grand_total field in
  the response. null if not present.
- order_accepted: true if the response indicates an order or transaction was successfully
  created or confirmed.
- total_is_negative_or_zero: true if any price/total/amount value in the response is ≤ 0.
- currency: currency code or symbol found in the response (e.g. "USD", "VND", "$"). null if absent.

HTTP RESPONSE:
{text}
"""

# BLF-02 — type confusion / unconventional input
_PROMPT_BLF_TYPE = _HEADER + """\
Schema:
{"invalid_value_accepted": <bool>, "accepted_field_name": <string|null>,
 "accepted_value": <string|null>, "validation_error_present": <bool>}

Definitions:
- invalid_value_accepted: true if the response indicates the server accepted and processed
  a value that should be invalid (null, NaN, decimal in integer field, negative number).
- accepted_field_name: name of the field that contained the invalid value. null if unknown.
- accepted_value: the invalid value that was accepted. null if unknown.
- validation_error_present: true if the response contains any validation error or rejection.

HTTP RESPONSE:
{text}
"""

# BLF-03 / BLF-09 — workflow / state skip
_PROMPT_BLF_STATE = _HEADER + """\
Schema:
{"final_step_confirmed": <bool>, "completion_keywords_found": <bool>,
 "order_or_transaction_id": <string|null>}

Definitions:
- final_step_confirmed: true if the response indicates a final workflow step completed
  successfully (e.g. "order confirmed", "payment successful", "registration complete",
  "đặt hàng thành công", "주문 완료", "订单成功" — any language).
- completion_keywords_found: true if any success/completion language is present in the body.
- order_or_transaction_id: ID of the created order/transaction if visible in the response.

HTTP RESPONSE:
{text}
"""

# BLF-04 — race condition / TOCTOU
_PROMPT_BLF_RACE = _HEADER + """\
Schema:
{"resource_consumed": <bool>, "remaining_count": <number|null>,
 "success_message": <bool>, "already_used_message": <bool>}

Definitions:
- resource_consumed: true if the response indicates a one-time resource (coupon, credit,
  referral bonus) was successfully applied.
- remaining_count: remaining balance or count shown in the response after consumption. null if absent.
- success_message: true if the response contains a success/accepted message.
- already_used_message: true if the response contains a "already used" or "already redeemed"
  rejection message (any language).

HTTP RESPONSE:
{text}
"""

# BLF-05 — coupon / discount abuse
_PROMPT_BLF_COUPON = _HEADER + """\
Schema:
{"coupon_applied": <bool>, "discount_amount": <number|null>,
 "total_after_discount": <number|null>, "total_is_negative": <bool>}

Definitions:
- coupon_applied: true if the response confirms a coupon/promo/discount code was accepted.
- discount_amount: the discount value applied, as a number. null if not shown.
- total_after_discount: the final order total after discount, as a number. null if not shown.
- total_is_negative: true if the final total is a negative number.

HTTP RESPONSE:
{text}
"""

# BLF-06 / BLF-07 — negative quantity / stock abuse
_PROMPT_BLF_QTY = _HEADER + """\
Schema:
{"quantity_in_response": <number|null>, "negative_quantity_accepted": <bool>,
 "stock_count": <number|null>, "order_created": <bool>}

Definitions:
- quantity_in_response: numeric quantity value found in the response body. null if absent.
- negative_quantity_accepted: true if the response indicates a negative or zero quantity
  order was successfully placed.
- stock_count: remaining stock count shown in the response. null if absent.
- order_created: true if the response confirms an order was created.

HTTP RESPONSE:
{text}
"""

# Mapping: pattern_id → (prompt_template, default_facts_on_parse_failure)
_PATTERN_CONFIG: dict[str, tuple[str, dict[str, Any]]] = {
    "BAC-01": (_PROMPT_BAC_ADMIN,  {"privileged_page": False, "exposes_other_users_pii": False, "distinct_user_records": 0}),
    "BAC-06": (_PROMPT_BAC_ADMIN,  {"privileged_page": False, "exposes_other_users_pii": False, "distinct_user_records": 0}),
    "BAC-02": (_PROMPT_BAC_PARAM,  {"privileged_page": False, "admin_content_visible": False, "role_in_response": None}),
    "BAC-03": (_PROMPT_BAC_IDOR,   {"owner_field_name": None, "owner_field_value": None, "email_in_response": None, "username_in_response": None}),
    "BAC-04": (_PROMPT_BAC_METHOD, {"resource_modified": False, "action_confirmed": False, "error_in_response": False}),
    "BAC-05": (_PROMPT_BAC_IDOR,   {"owner_field_name": None, "owner_field_value": None, "email_in_response": None, "username_in_response": None}),
    "BLF-01": (_PROMPT_BLF_PRICE,  {"price_or_total_value": None, "order_accepted": False, "total_is_negative_or_zero": False, "currency": None}),
    "BLF-02": (_PROMPT_BLF_TYPE,   {"invalid_value_accepted": False, "accepted_field_name": None, "accepted_value": None, "validation_error_present": False}),
    "BLF-03": (_PROMPT_BLF_STATE,  {"final_step_confirmed": False, "completion_keywords_found": False, "order_or_transaction_id": None}),
    "BLF-04": (_PROMPT_BLF_RACE,   {"resource_consumed": False, "remaining_count": None, "success_message": False, "already_used_message": False}),
    "BLF-05": (_PROMPT_BLF_COUPON, {"coupon_applied": False, "discount_amount": None, "total_after_discount": None, "total_is_negative": False}),
    "BLF-06": (_PROMPT_BLF_QTY,    {"quantity_in_response": None, "negative_quantity_accepted": False, "stock_count": None, "order_created": False}),
    "BLF-07": (_PROMPT_BLF_QTY,    {"quantity_in_response": None, "negative_quantity_accepted": False, "stock_count": None, "order_created": False}),
    "BLF-09": (_PROMPT_BLF_STATE,  {"final_step_confirmed": False, "completion_keywords_found": False, "order_or_transaction_id": None}),
}

# Fallback for unknown patterns — generic BAC admin prompt
_FALLBACK_PROMPT = _PROMPT_BAC_ADMIN
_FALLBACK_DEFAULTS: dict[str, Any] = {"privileged_page": False, "exposes_other_users_pii": False, "distinct_user_records": 0}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def classify_responses(
    llm,
    exchanges,
    body_store,
    pattern_id: str = "",
    max_calls: int = 3,
) -> dict[int, dict]:
    """Run the per-pattern extractor on representative 2xx responses.

    Returns {exchange_seq: facts_dict}. Empty dict if no LLM or nothing to classify.
    The facts_dict keys depend on the pattern — callers should use .get() with a default.
    """
    if llm is None:
        return {}

    prompt_tmpl, defaults = _PATTERN_CONFIG.get(
        pattern_id.upper(), (_FALLBACK_PROMPT, _FALLBACK_DEFAULTS)
    )

    # Pick candidate 2xx exchanges, preferring the most data-rich responses (largest body).
    # Dedup by (url, actor): use exact URL (not endpoint template) so that /orders/1,
    # /orders/2, /orders/3 — all templated to /orders/{id} — are each classified separately.
    # This is critical for IDOR detection: ProofGate's HTML fallback needs multiple responses
    # from the same endpoint template to compare identities across different path IDs.
    twoxx = [ex for ex in exchanges if ex.status in range(200, 300)]
    twoxx.sort(key=_resp_size, reverse=True)
    candidates = []
    seen: set[tuple] = set()
    for ex in twoxx:
        key = (ex.url, ex.actor)
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
        parsed = await _classify_one(llm, prompt_tmpl, text[:_MAX_TEXT], defaults)
        if parsed is not None:
            facts[ex.seq] = parsed
            log.debug(f"classifier seq={ex.seq} url={ex.url} actor={ex.actor} → {parsed}")

    return facts


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

async def _classify_one(llm, prompt_tmpl: str, text: str, defaults: dict) -> dict | None:
    msg = [{"role": "user", "content": prompt_tmpl.replace("{text}", text)}]
    for attempt in range(3):
        try:
            raw = await llm.chat(
                messages=msg,
                role=Role.VERIFIER,
                temperature=0.0 if attempt == 0 else 0.4,
                max_tokens=800,
            )
        except Exception as e:
            log.debug(f"classifier LLM call failed (attempt {attempt + 1}): {e}")
            continue
        parsed = _parse(raw, defaults)
        if parsed is not None:
            return parsed
    return None


def _parse(raw: str, defaults: dict) -> dict | None:
    if not raw:
        return None
    # Try flat JSON objects first (avoids nested-brace confusion)
    flat = [m.group(0) for m in re.finditer(r"\{[^{}]*\}", raw)]
    for cand in reversed(flat):
        try:
            obj = json.loads(cand)
            if isinstance(obj, dict) and any(k in obj for k in defaults):
                return _merge(obj, defaults)
        except json.JSONDecodeError:
            continue
    # Fallback: first balanced JSON object in response
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
        if isinstance(obj, dict):
            return _merge(obj, defaults)
    except json.JSONDecodeError:
        pass
    return None


def _merge(obj: dict, defaults: dict) -> dict:
    """Return defaults updated with parsed values, coerced to expected types."""
    result = dict(defaults)
    for k, default_val in defaults.items():
        if k not in obj:
            continue
        v = obj[k]
        if isinstance(default_val, bool):
            result[k] = bool(v)
        elif isinstance(default_val, int):
            try:
                result[k] = int(v) if v is not None else 0
            except (ValueError, TypeError):
                pass
        elif isinstance(default_val, float):
            try:
                result[k] = float(v) if v is not None else 0.0
            except (ValueError, TypeError):
                pass
        else:
            # string | None
            result[k] = str(v) if v is not None else None
    # Also carry through any extra keys the LLM returned (non-destructive)
    for k, v in obj.items():
        if k not in result:
            result[k] = v
    return result


def _resp_size(exchange) -> float:
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
