"""BLF proof rules evaluated against structured Evidence + state delta."""
from __future__ import annotations

import logging
import re

from .base import ProofGate
from ...contracts.evidence import Evidence, ProofMarker, Verdict
from ...contracts.enums import ProofKey
from ...recon.body_store import BodyStore

log = logging.getLogger("marl3.proof.blf")

_MONEY_FIELDS = (
    "amount", "price", "total", "cost", "balance", "credit", "point", "sum", "value",
    "fee", "charge", "rate", "subtotal", "grand_total", "net", "gross",
    "unit_price", "line_total", "tariff", "fare", "deposit", "refund",
)
_QTY_FIELDS = (
    "qty", "quantity", "count", "stock", "num", "items",
    "units", "pieces", "seats", "tickets", "licenses",
)
# Value-tamper proof must be tolerant of BLF-01↔BLF-06 mislabeling by the hunter: an
# out-of-range value ACCEPTED on ANY value-bearing field is the win, regardless of whether
# the candidate was tagged price (BLF-01) or quantity (BLF-06). Scanning both prevents a
# real, successfully-exploited tamper from being scored FAILED just because of its label.
_VALUE_FIELDS = _MONEY_FIELDS + _QTY_FIELDS
_ERROR_MARKERS = (
    # English
    "invalid", "error", "must be", "rejected", "failed", "not allowed",
    "forbidden", "denied", "out of range", "cannot be", "must not",
    "validation", "constraint", "exceeds", "insufficient", "negative",
    "required", "minimum", "maximum", "bad request",
    # Vietnamese (lab language — extend for other languages as needed)
    "không hợp lệ", "lỗi", "thất bại", "phải lớn hơn",
)


def _to_number(v) -> float | None:
    try:
        return float(str(v).replace(",", "").strip())
    except (ValueError, TypeError):
        return None


_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_ERROR_LOCATION_HINTS = ("error", "fail", "invalid", "reject", "denied", "blocked")


class _Mixin:
    """Detect a value-bearing POST with an invalid (negative/extreme) field that was accepted."""

    def _accepted_invalid_post(self, evidence: Evidence, field_kw: tuple):
        for ex in evidence.exchanges:
            if ex.method.upper() not in ("POST", "PUT", "PATCH"):
                continue
            # Accept 2xx (direct success) AND 3xx (redirect-after-POST — standard HTML form
            # success pattern on PortSwigger/most web apps where POST /cart → 302 /product
            # is the normal "added to cart" response, not an error).
            is_redirect = ex.status in _REDIRECT_STATUSES
            if ex.status not in range(200, 300) and not is_redirect:
                continue
            # For 3xx: check that the Location header doesn't indicate a rejection redirect.
            if is_redirect:
                location = (ex.response_headers or {}).get("location", "").lower()
                if any(hint in location for hint in _ERROR_LOCATION_HINTS):
                    continue
            fields = self._request_fields(ex)
            for name, val in fields.items():
                if not any(kw in name.lower() for kw in field_kw):
                    continue
                num = _to_number(val)
                if num is None:
                    continue
                # Only negative values are universally invalid. Large positive values
                # are NOT flagged — many currencies (VND, KRW, IDR) have values > 1M.
                if num < 0:
                    # For 2xx: check response body for rejection markers.
                    # For 3xx: body is empty (redirect); skip body check.
                    if not is_redirect:
                        body = self._response_text(ex).lower()
                        title_err = "404" in (ex.html_title or "") or "lỗi" in (ex.html_title or "").lower()
                        rejected = title_err or any(m in body[:2000] for m in _ERROR_MARKERS)
                        if rejected:
                            continue
                    return ex, name, num
        return None


class BLFProofGate(ProofGate, _Mixin):
    """Evaluates BLF (Business Logic Flaw) evidence."""

    def __init__(self, body_store: BodyStore, pattern_id: str) -> None:
        super().__init__(body_store)
        self._pattern_id = pattern_id

    def evaluate(self, evidence: Evidence, llm_facts: dict | None = None) -> Verdict:
        # BLF proof is primarily judged on numeric data (state_delta, field values).
        # Per-pattern LLM facts now supplement structural checks for cases where numeric
        # signals are absent but semantic confirmation is available (e.g. "order confirmed"
        # in a non-English response, or a non-standard total field name).
        self._facts = llm_facts or {}
        _all = evidence.exchanges
        self._full_exchanges = _all  # some rules (coupon reuse) need cross-endpoint context
        evidence.exchanges = self._scope(evidence)
        try:
            if self._pattern_id == "BLF-05":
                return self._eval_coupon_abuse(evidence)
            elif self._pattern_id == "BLF-01":
                return self._eval_price_tamper(evidence)
            elif self._pattern_id in ("BLF-06", "BLF-07", "BLF-08"):
                # BLF-08 (integer overflow) produces the same evidence shape as BLF-06:
                # a quantity-tamper that results in an anomalous (negative/wrapped) cart total.
                return self._eval_quantity_tamper(evidence)
            elif self._pattern_id == "BLF-02":
                return self._eval_type_confusion(evidence)
            elif self._pattern_id == "BLF-04":
                return self._eval_race_condition(evidence)
            elif self._pattern_id in ("BLF-03", "BLF-09"):
                return self._eval_state_skip(evidence)
            elif self._pattern_id in ("BLF-10", "BLF-11", "BLF-12"):
                # These are auth/access-bypass patterns housed in BLF namespace:
                # BLF-10: dual-use endpoint → admin access after param omission
                # BLF-11: email truncation → admin access after registration trick
                # BLF-12: flawed state machine → admin access after dropped request
                return self._eval_auth_escalation_blf(evidence)
            else:
                return self._eval_generic_blf(evidence)
        finally:
            evidence.exchanges = _all

    def _eval_price_tamper(self, evidence: Evidence) -> Verdict:
        """Price manipulation: state_delta shows price discrepancy."""
        markers: list[ProofMarker] = []
        required = [ProofKey.PRICE_MANIPULATION, ProofKey.STATE_DELTA]

        delta = evidence.state_delta
        if delta:
            price_keys = [k for k in delta if "price" in k.lower() or "amount" in k.lower() or "total" in k.lower()]
            if price_keys:
                markers.append(ProofMarker(
                    key=ProofKey.PRICE_MANIPULATION,
                    satisfied=True,
                    detail=f"Price-related fields changed: {price_keys} → delta={delta}",
                    exchange_seqs=[ex.seq for ex in evidence.exchanges],
                    extracted=delta,
                ))
                markers.append(ProofMarker(
                    key=ProofKey.STATE_DELTA,
                    satisfied=True,
                    detail=f"State changed: {delta}",
                    exchange_seqs=[ex.seq for ex in evidence.exchanges],
                    extracted=delta,
                ))

        # Fallback: look at response body for order/price fields
        if not markers:
            for ex in evidence.exchanges:
                if ex.status in range(200, 300):
                    obj = self._response_obj(ex)
                    if isinstance(obj, dict):
                        price_val = obj.get("price") or obj.get("total") or obj.get("amount")
                        if price_val is not None and float(str(price_val).replace(",", "")) <= 0:
                            markers.append(ProofMarker(
                                key=ProofKey.PRICE_MANIPULATION,
                                satisfied=True,
                                detail=f"Price/total value is ≤0: {price_val!r}",
                                exchange_seqs=[ex.seq],
                                extracted={"price_value": price_val},
                            ))
                            markers.append(ProofMarker(
                                key=ProofKey.STATE_DELTA,
                                satisfied=True,
                                detail=f"Order accepted with manipulated value",
                                exchange_seqs=[ex.seq],
                            ))

        # HTML/form fallback: a negative/extreme value POSTed and accepted (2xx, no error).
        # Scan BOTH money and qty fields so a quantity-tamper mislabeled BLF-01 still proves.
        if not markers:
            hit = self._accepted_invalid_post(evidence, _VALUE_FIELDS)
            if hit:
                ex, name, num = hit
                markers.append(ProofMarker(
                    key=ProofKey.PRICE_MANIPULATION,
                    satisfied=True,
                    detail=f"Invalid value {name}={num} accepted by {ex.method} {ex.url} (status {ex.status}, no validation error)",
                    exchange_seqs=[ex.seq],
                    extracted={"field": name, "value": num, "url": ex.url},
                ))
                markers.append(ProofMarker(
                    key=ProofKey.STATE_DELTA,
                    satisfied=True,
                    detail=f"Server accepted out-of-range {name} without rejection",
                    exchange_seqs=[ex.seq],
                ))

        if not markers:
            markers = [
                ProofMarker(key=ProofKey.PRICE_MANIPULATION, satisfied=False,
                            detail="No price manipulation detected in evidence"),
                ProofMarker(key=ProofKey.STATE_DELTA, satisfied=False,
                            detail="No state delta recorded"),
            ]

        evidence.proof_markers = markers
        return self._make_verdict(markers, required, self._pattern_id)

    def _eval_type_confusion(self, evidence: Evidence) -> Verdict:
        """BLF-02: server accepted an unconventional type or out-of-spec value in a numeric
        field — decimal where integer expected, null/NaN/Infinity, or an out-of-range value —
        without returning a validation error (2xx, no error marker in response)."""
        markers: list[ProofMarker] = []
        required = [ProofKey.QUANTITY_TAMPER, ProofKey.STATE_DELTA]

        _SPECIAL = {"null", "none", "undefined", "nan", "infinity", "-infinity"}

        for ex in evidence.exchanges:
            if ex.method.upper() not in ("POST", "PUT", "PATCH") or ex.status not in range(200, 300):
                continue
            fields = self._request_fields(ex)
            resp_text = self._response_text(ex).lower()
            title_err = "404" in (ex.html_title or "") or \
                any(w in (ex.html_title or "").lower() for w in ("error", "lỗi", "invalid"))
            if title_err or any(m in resp_text[:2000] for m in _ERROR_MARKERS):
                continue

            for name, val in fields.items():
                if not any(kw in name.lower() for kw in _VALUE_FIELDS):
                    continue
                str_val = str(val).strip().lower()

                if str_val in _SPECIAL:
                    markers.extend([
                        ProofMarker(
                            key=ProofKey.QUANTITY_TAMPER, satisfied=True,
                            detail=(f"Special value {name}={str_val!r} accepted in numeric field "
                                    f"by {ex.method} {ex.url} (status {ex.status})"),
                            exchange_seqs=[ex.seq],
                            extracted={"field": name, "value": str_val, "type": "special"},
                        ),
                        ProofMarker(
                            key=ProofKey.STATE_DELTA, satisfied=True,
                            detail="Server accepted special/null value without validation error",
                            exchange_seqs=[ex.seq],
                        ),
                    ])
                    break

                try:
                    f = float(str(val).replace(",", "").strip())
                    i = int(f)
                    if f != i and 0 < abs(f) < 1_000_000:
                        markers.extend([
                            ProofMarker(
                                key=ProofKey.QUANTITY_TAMPER, satisfied=True,
                                detail=(f"Decimal value {name}={val!r} accepted in integer-expected "
                                        f"field by {ex.method} {ex.url} — server may truncate silently"),
                                exchange_seqs=[ex.seq],
                                extracted={"field": name, "value": val, "type": "decimal"},
                            ),
                            ProofMarker(
                                key=ProofKey.STATE_DELTA, satisfied=True,
                                detail="Decimal accepted without integer-only validation",
                                exchange_seqs=[ex.seq],
                            ),
                        ])
                        break
                except (ValueError, TypeError):
                    pass
            if markers:
                break

        if not markers:
            hit = self._accepted_invalid_post(evidence, _VALUE_FIELDS)
            if hit:
                ex, name, num = hit
                markers.extend([
                    ProofMarker(
                        key=ProofKey.QUANTITY_TAMPER, satisfied=True,
                        detail=f"Out-of-range value {name}={num} accepted (type/range confusion)",
                        exchange_seqs=[ex.seq], extracted={"field": name, "value": num},
                    ),
                    ProofMarker(
                        key=ProofKey.STATE_DELTA, satisfied=True,
                        detail="Server accepted out-of-range value without rejection",
                        exchange_seqs=[ex.seq],
                    ),
                ])

        if not markers:
            markers = [
                ProofMarker(key=ProofKey.QUANTITY_TAMPER, satisfied=False,
                            detail="No unconventional input accepted (server validated correctly)"),
                ProofMarker(key=ProofKey.STATE_DELTA, satisfied=False,
                            detail="No state delta recorded"),
            ]

        evidence.proof_markers = markers
        return self._make_verdict(markers, required, self._pattern_id)

    def _eval_race_condition(self, evidence: Evidence) -> Verdict:
        """BLF-04: TOCTOU / race condition — same one-use resource consumed multiple times.

        Full race detection requires parallel requests (future tooling). This gate detects
        the observable subset: same endpoint succeeded N≥2 times, indicating the one-use
        guard is absent or bypassable sequentially.
        """
        markers: list[ProofMarker] = []
        required = [ProofKey.STATE_DELTA]

        endpoint_hits: dict[str, list[int]] = {}
        for ex in evidence.exchanges:
            if ex.method.upper() in ("POST", "PUT", "PATCH") and ex.status in range(200, 300):
                endpoint_hits.setdefault(ex.endpoint, []).append(ex.seq)

        multi_hit = {ep: seqs for ep, seqs in endpoint_hits.items() if len(seqs) >= 2}
        if multi_hit:
            ep, seqs = max(multi_hit.items(), key=lambda kv: len(kv[1]))
            markers.append(ProofMarker(
                key=ProofKey.STATE_DELTA,
                satisfied=True,
                detail=(f"Endpoint {ep!r} accepted {len(seqs)} successful POST/PUT/PATCH "
                        f"requests — one-use guard may be absent (race window or missing dedup)"),
                exchange_seqs=seqs,
                extracted={"endpoint": ep, "success_count": len(seqs)},
            ))
        elif evidence.state_delta:
            markers.append(ProofMarker(
                key=ProofKey.STATE_DELTA,
                satisfied=True,
                detail=f"State delta recorded: {evidence.state_delta}",
                extracted=evidence.state_delta,
            ))
        else:
            markers.append(ProofMarker(
                key=ProofKey.STATE_DELTA, satisfied=False,
                detail="No repeated successful calls and no state delta",
            ))

        evidence.proof_markers = markers
        return self._make_verdict(markers, required, self._pattern_id)

    def _eval_coupon_abuse(self, evidence: Evidence) -> Verdict:
        """BLF-05: detect coupon/discount reuse — the SAME one-time code accepted (2xx) two
        or more times (a secure server rejects the second apply with 4xx). Generic: keys off
        repeated successful applies of an identical code, not any app-specific text. Falls back
        to negative-price coupon detection (price-tamper) when no reuse is seen."""
        applies: dict[str, list[int]] = {}
        for ex in evidence.exchanges:
            if ex.method.upper() not in ("POST", "PUT", "PATCH") or ex.status not in range(200, 300):
                continue
            fields = self._request_fields(ex)
            code = ""
            for name, val in fields.items():
                if val and any(h in name.lower() for h in (
                "coupon", "code", "promo", "voucher", "discount",
                "gift_card", "giftcard", "reward", "referral", "promocode",
                "redeem", "token", "offer",
            )):
                    code = str(val).strip().upper()
                    break
            if code:
                applies.setdefault(code, []).append(ex.seq)

        # Consume events (checkout / pay / confirm) anywhere in the run — re-applying a code
        # AFTER it was consumed is the real BLF-05 reuse; re-applying twice before any checkout
        # is just changing the cart coupon and must NOT be flagged.
        full = getattr(self, "_full_exchanges", None) or evidence.exchanges
        consume_seqs = [
            ex.seq for ex in full
            if ex.method.upper() in ("POST", "PUT", "PATCH") and ex.status in range(200, 300)
            and any(k in (ex.endpoint or "").lower() for k in (
                "checkout", "purchase", "confirm", "/pay", "finalize",
                "submit", "complete", "process", "place", "execute",
                "order", "buy", "charge", "settle",
            ))
        ]
        reused: dict[str, list[int]] = {}
        for code, seqs in applies.items():
            seqs = sorted(seqs)
            if len(seqs) >= 2 and any(seqs[0] < cs < later for cs in consume_seqs for later in seqs[1:]):
                reused[code] = seqs
        if reused:
            code, seqs = max(reused.items(), key=lambda kv: len(kv[1]))
            markers = [
                ProofMarker(
                    key=ProofKey.PRICE_MANIPULATION, satisfied=True,
                    detail=(f"One-time coupon {code!r} accepted {len(seqs)} times — repeated discount "
                            f"obtained by reuse (a secure server rejects the second apply)"),
                    exchange_seqs=seqs, extracted={"code": code, "successful_applies": len(seqs)},
                ),
                ProofMarker(
                    key=ProofKey.STATE_DELTA, satisfied=True,
                    detail=f"Discount re-applied via reused coupon {code!r} across {len(seqs)} requests",
                    exchange_seqs=seqs,
                ),
            ]
            evidence.proof_markers = markers
            return self._make_verdict(markers, [ProofKey.PRICE_MANIPULATION, ProofKey.STATE_DELTA], self._pattern_id)

        # Case 2: coupon/promo STACKING — 2+ DIFFERENT codes all accepted in same session
        stacked = {code: seqs for code, seqs in applies.items() if seqs}
        if len(stacked) >= 2:
            all_codes = list(stacked.keys())
            all_seqs = [s for seqs in stacked.values() for s in seqs]
            markers = [
                ProofMarker(
                    key=ProofKey.PRICE_MANIPULATION, satisfied=True,
                    detail=(f"Coupon stacking: {len(stacked)} distinct codes all accepted "
                            f"({all_codes[:4]}) — one-code-per-order rule violated"),
                    exchange_seqs=all_seqs,
                    extracted={"codes": all_codes[:5], "count": len(stacked)},
                ),
                ProofMarker(
                    key=ProofKey.STATE_DELTA, satisfied=True,
                    detail="Multiple distinct discount codes applied in same session",
                    exchange_seqs=all_seqs,
                ),
            ]
            evidence.proof_markers = markers
            return self._make_verdict(
                markers, [ProofKey.PRICE_MANIPULATION, ProofKey.STATE_DELTA], self._pattern_id)

        # Case 3: negative / zero order total in response (discount over-application)
        _TOTAL_KEYS = ("total", "grand_total", "amount", "price", "order_total",
                       "cart_total", "subtotal", "net_total")
        full_exs = getattr(self, "_full_exchanges", None) or evidence.exchanges
        for ex in full_exs:
            if ex.status not in range(200, 300):
                continue
            obj = self._response_obj(ex)
            if not isinstance(obj, dict):
                continue
            candidates = [obj]
            for wrap in ("data", "result", "order", "cart", "checkout"):
                inner = obj.get(wrap)
                if isinstance(inner, dict):
                    candidates.append(inner)
            for item in candidates:
                for k in _TOTAL_KEYS:
                    v = item.get(k)
                    if v is None:
                        continue
                    n = _to_number(v)
                    if n is not None and n <= 0:
                        markers = [
                            ProofMarker(
                                key=ProofKey.PRICE_MANIPULATION, satisfied=True,
                                detail=(f"Order/cart {k}={v!r} ≤ 0 at {ex.url} — "
                                        "discount stacking reduced total to zero or negative"),
                                exchange_seqs=[ex.seq],
                                extracted={"field": k, "value": v, "url": ex.url},
                            ),
                            ProofMarker(
                                key=ProofKey.STATE_DELTA, satisfied=True,
                                detail=f"Final total became non-positive",
                                exchange_seqs=[ex.seq],
                            ),
                        ]
                        evidence.proof_markers = markers
                        return self._make_verdict(
                            markers, [ProofKey.PRICE_MANIPULATION, ProofKey.STATE_DELTA],
                            self._pattern_id)

        # LLM fallback: extractor may have seen a negative total that the code missed
        # (non-standard field name, HTML-embedded value, non-English label).
        for seq, facts in self._facts.items():
            if facts.get("total_is_negative"):
                total = facts.get("total_after_discount")
                markers = [
                    ProofMarker(
                        key=ProofKey.PRICE_MANIPULATION, satisfied=True,
                        detail=(f"LLM extractor found negative order total "
                                + (f"({total})" if total is not None else "") +
                                f" in exchange {seq} — discount over-application likely"),
                        exchange_seqs=[seq],
                        extracted={"total_after_discount": total, "source": "llm_extractor"},
                    ),
                    ProofMarker(
                        key=ProofKey.STATE_DELTA, satisfied=True,
                        detail="Order total reduced to negative by coupon abuse",
                        exchange_seqs=[seq],
                    ),
                ]
                evidence.proof_markers = markers
                return self._make_verdict(
                    markers, [ProofKey.PRICE_MANIPULATION, ProofKey.STATE_DELTA],
                    self._pattern_id)

        # No reuse detected → fall back to negative/zero-price coupon abuse.
        return self._eval_price_tamper(evidence)

    def _eval_quantity_tamper(self, evidence: Evidence) -> Verdict:
        markers: list[ProofMarker] = []
        required = [ProofKey.QUANTITY_TAMPER, ProofKey.STATE_DELTA]

        delta = evidence.state_delta
        if delta:
            qty_keys = [k for k in delta if "qty" in k.lower() or "quantity" in k.lower() or "count" in k.lower() or "stock" in k.lower()]
            if qty_keys:
                markers.extend([
                    ProofMarker(
                        key=ProofKey.QUANTITY_TAMPER,
                        satisfied=True,
                        detail=f"Quantity fields changed: {qty_keys}",
                        exchange_seqs=[ex.seq for ex in evidence.exchanges],
                        extracted=delta,
                    ),
                    ProofMarker(
                        key=ProofKey.STATE_DELTA,
                        satisfied=True,
                        detail=f"State delta: {delta}",
                        extracted=delta,
                    ),
                ])

        if not markers:
            for ex in evidence.exchanges:
                if ex.status in range(200, 300):
                    # Look for negative or extreme numeric responses
                    # Skip internal housekeeping fields (e.g. _resp_len which is body size)
                    for k, v in ex.numeric_fields.items():
                        if k.startswith("_"):
                            continue
                        if v < 0 or v > 9999:
                            markers.extend([
                                ProofMarker(key=ProofKey.QUANTITY_TAMPER, satisfied=True,
                                            detail=f"Anomalous numeric field {k}={v}",
                                            exchange_seqs=[ex.seq]),
                                ProofMarker(key=ProofKey.STATE_DELTA, satisfied=True,
                                            detail=f"Field {k} has anomalous value {v}",
                                            exchange_seqs=[ex.seq]),
                            ])
                            break

        # HTML/form fallback: a negative/extreme value POSTed and accepted. Scan BOTH qty
        # and money fields so a price-tamper mislabeled BLF-06 still proves.
        if not markers:
            hit = self._accepted_invalid_post(evidence, _VALUE_FIELDS)
            if hit:
                ex, name, num = hit
                markers.extend([
                    ProofMarker(key=ProofKey.QUANTITY_TAMPER, satisfied=True,
                                detail=f"Invalid quantity {name}={num} accepted by {ex.method} {ex.url} (status {ex.status})",
                                exchange_seqs=[ex.seq], extracted={"field": name, "value": num}),
                    ProofMarker(key=ProofKey.STATE_DELTA, satisfied=True,
                                detail=f"Server accepted out-of-range {name}", exchange_seqs=[ex.seq]),
                ])

        if not markers:
            markers = [
                ProofMarker(key=ProofKey.QUANTITY_TAMPER, satisfied=False, detail="No quantity tamper detected"),
                ProofMarker(key=ProofKey.STATE_DELTA, satisfied=False, detail="No state delta recorded"),
            ]

        evidence.proof_markers = markers
        return self._make_verdict(markers, required, self._pattern_id)

    def _eval_state_skip(self, evidence: Evidence) -> Verdict:
        """State/workflow skip: reached final step without required intermediate steps.

        Tightened: requires ≥2 distinct state-changing endpoints to confirm a chain was
        executed with a step skipped. Single action + delta → INFO_EXPOSURE_ONLY (STATE_DELTA
        satisfied, STATE_SKIP not) — can't prove bypass without at least two ordered mutations.
        """
        markers: list[ProofMarker] = []
        required = [ProofKey.STATE_SKIP, ProofKey.STATE_DELTA]

        action_exs = [
            ex for ex in evidence.exchanges
            if ex.method.upper() in ("POST", "PUT", "PATCH", "DELETE")
            and ex.status in range(200, 300)
        ]
        distinct_actions = {ex.endpoint for ex in action_exs}
        has_delta = bool(evidence.state_delta)

        if len(distinct_actions) >= 2 and has_delta:
            action_summary = ", ".join(sorted(distinct_actions)[:4])
            markers = [
                ProofMarker(
                    key=ProofKey.STATE_SKIP,
                    satisfied=True,
                    detail=(f"Workflow bypassed: {len(distinct_actions)} distinct state-changing "
                            f"endpoints hit ({action_summary}) — required intermediate step absent"),
                    exchange_seqs=[ex.seq for ex in action_exs],
                ),
                ProofMarker(
                    key=ProofKey.STATE_DELTA,
                    satisfied=True,
                    detail=f"State delta confirms skip was effective: {evidence.state_delta}",
                    extracted=evidence.state_delta,
                ),
            ]
        elif action_exs and has_delta:
            markers = [
                ProofMarker(
                    key=ProofKey.STATE_SKIP,
                    satisfied=False,
                    detail=(f"Only {len(distinct_actions)} action endpoint(s) recorded — "
                            "cannot confirm a step was skipped without a second ordered action"),
                    exchange_seqs=[ex.seq for ex in action_exs],
                ),
                ProofMarker(
                    key=ProofKey.STATE_DELTA,
                    satisfied=True,
                    detail=f"State changed: {evidence.state_delta}",
                    extracted=evidence.state_delta,
                ),
            ]
        else:
            # LLM fallback: extractor may have seen a "final step confirmed" message
            # in the response even when state_delta was not recorded (e.g. the exec
            # agent did not perform a re-read, or the app embeds confirmation in HTML).
            llm_confirmed = any(
                f.get("final_step_confirmed") or f.get("completion_keywords_found")
                for f in self._facts.values()
            )
            txn_id = next(
                (f.get("order_or_transaction_id") for f in self._facts.values()
                 if f.get("order_or_transaction_id")), None
            )
            if action_exs and llm_confirmed:
                markers = [
                    ProofMarker(
                        key=ProofKey.STATE_SKIP,
                        satisfied=True,
                        detail=(f"LLM extractor confirmed workflow completion "
                                f"({len(distinct_actions)} action endpoint(s) recorded"
                                + (f", txn_id={txn_id!r}" if txn_id else "") + ")"),
                        exchange_seqs=[ex.seq for ex in action_exs],
                        extracted={"source": "llm_extractor", "txn_id": txn_id},
                    ),
                    ProofMarker(
                        key=ProofKey.STATE_DELTA,
                        satisfied=True,
                        detail="Workflow completion confirmed by LLM extractor (no numeric delta captured)",
                        exchange_seqs=[ex.seq for ex in action_exs],
                    ),
                ]
            else:
                markers = [
                    ProofMarker(
                        key=ProofKey.STATE_SKIP,
                        satisfied=False,
                        detail="No completed state-changing requests recorded"
                        if not action_exs else "Action requests present but no state delta recorded",
                    ),
                    ProofMarker(key=ProofKey.STATE_DELTA, satisfied=False,
                                detail="No state delta recorded"),
                ]

        evidence.proof_markers = markers
        return self._make_verdict(markers, required, self._pattern_id)

    def _eval_auth_escalation_blf(self, evidence: Evidence) -> Verdict:
        """BLF-10/11/12: auth/privilege escalation via business logic flaw.

        These patterns achieve admin/elevated access through a logic trick rather than
        a direct auth bypass header. Proof shape is the same as BAC-01/02:
        - A low-priv actor reaches an admin/privileged endpoint with 2xx
        - OR an endpoint that previously returned 302/403 now returns 200 after the trick
        - OR a new authenticated session shows elevated role/access
        """
        markers: list[ProofMarker] = []
        required = [ProofKey.AUTH_BYPASS, ProofKey.PRIVILEGED_ACCESS]

        _ADMIN_HINTS = frozenset({
            "admin", "administrator", "manage", "management", "staff",
            "console", "panel", "moderator", "internal", "superuser",
            "delete", "promote", "users", "settings",
        })

        for ex in evidence.exchanges:
            if ex.status not in range(200, 300):
                continue
            url_low = ex.url.lower()
            title_low = (ex.html_title or "").lower()
            preview_low = self._response_text(ex)[:500].lower()
            # Privileged access signal: admin path OR admin-titled page
            if any(h in url_low for h in _ADMIN_HINTS) or any(h in title_low for h in _ADMIN_HINTS):
                markers.append(ProofMarker(
                    key=ProofKey.PRIVILEGED_ACCESS,
                    satisfied=True,
                    detail=f"Privileged resource reached: {ex.method} {ex.url} → {ex.status} (title={ex.html_title!r})",
                    exchange_seqs=[ex.seq],
                ))
                break
            # Fallback: response preview mentions admin-level content
            if any(h in preview_low for h in _ADMIN_HINTS):
                markers.append(ProofMarker(
                    key=ProofKey.PRIVILEGED_ACCESS,
                    satisfied=True,
                    detail=f"Admin content in response body: {ex.method} {ex.url}",
                    exchange_seqs=[ex.seq],
                ))
                break

        # AUTH_BYPASS: look for a before/after pair — a blocked request followed by access
        statuses = [ex.status for ex in evidence.exchanges]
        blocked_then_ok = any(
            statuses[i] in (302, 401, 403) and statuses[j] in range(200, 300)
            for i in range(len(statuses))
            for j in range(i + 1, len(statuses))
        )
        if blocked_then_ok or any(m.key == ProofKey.PRIVILEGED_ACCESS and m.satisfied for m in markers):
            markers.append(ProofMarker(
                key=ProofKey.AUTH_BYPASS,
                satisfied=True,
                detail=f"Auth bypass confirmed via {self._pattern_id} logic trick",
                exchange_seqs=[ex.seq for ex in evidence.exchanges],
            ))

        if not any(m.satisfied for m in markers):
            markers = [
                ProofMarker(key=ProofKey.AUTH_BYPASS, satisfied=False,
                            detail="No privileged access observed"),
                ProofMarker(key=ProofKey.PRIVILEGED_ACCESS, satisfied=False,
                            detail="No admin/privileged endpoint reached with 2xx"),
            ]

        evidence.proof_markers = markers
        return self._make_verdict(markers, required, self._pattern_id)

    def _eval_generic_blf(self, evidence: Evidence) -> Verdict:
        has_success = any(ex.status in range(200, 300) for ex in evidence.exchanges)
        has_delta = bool(evidence.state_delta)
        markers = [
            ProofMarker(key=ProofKey.STATE_DELTA, satisfied=has_success and has_delta,
                        detail="Generic BLF: 2xx received" + (" with state delta" if has_delta else "")),
        ]
        evidence.proof_markers = markers
        return self._make_verdict(markers, [ProofKey.STATE_DELTA], self._pattern_id)
