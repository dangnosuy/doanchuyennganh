"""BLF proof rules evaluated against structured Evidence + state delta."""
from __future__ import annotations

import logging
import re

from .base import ProofGate
from ...contracts.evidence import Evidence, ProofMarker, Verdict
from ...contracts.enums import ProofKey
from ...recon.body_store import BodyStore

log = logging.getLogger("marl3.proof.blf")

_MONEY_FIELDS = ("amount", "price", "total", "cost", "balance", "credit", "point", "sum", "value")
_QTY_FIELDS = ("qty", "quantity", "count", "stock", "num", "items")
# Value-tamper proof must be tolerant of BLF-01↔BLF-06 mislabeling by the hunter: an
# out-of-range value ACCEPTED on ANY value-bearing field is the win, regardless of whether
# the candidate was tagged price (BLF-01) or quantity (BLF-06). Scanning both prevents a
# real, successfully-exploited tamper from being scored FAILED just because of its label.
_VALUE_FIELDS = _MONEY_FIELDS + _QTY_FIELDS
_ERROR_MARKERS = ("invalid", "error", "không hợp lệ", "lỗi", "thất bại", "must be", "phải lớn hơn", "rejected")


def _to_number(v) -> float | None:
    try:
        return float(str(v).replace(",", "").strip())
    except (ValueError, TypeError):
        return None


class _Mixin:
    """Detect a value-bearing POST with an invalid (negative/extreme) field that was accepted."""

    def _accepted_invalid_post(self, evidence: Evidence, field_kw: tuple):
        for ex in evidence.exchanges:
            if ex.method.upper() not in ("POST", "PUT", "PATCH") or ex.status not in range(200, 300):
                continue
            fields = self._request_fields(ex)
            for name, val in fields.items():
                if not any(kw in name.lower() for kw in field_kw):
                    continue
                num = _to_number(val)
                if num is None:
                    continue
                if num < 0 or num > 1_000_000:
                    body = self._response_text(ex).lower()
                    title_err = "404" in (ex.html_title or "") or "lỗi" in (ex.html_title or "").lower()
                    rejected = title_err or any(m in body[:2000] for m in _ERROR_MARKERS)
                    if not rejected:
                        return ex, name, num
        return None


class BLFProofGate(ProofGate, _Mixin):
    """Evaluates BLF (Business Logic Flaw) evidence."""

    def __init__(self, body_store: BodyStore, pattern_id: str) -> None:
        super().__init__(body_store)
        self._pattern_id = pattern_id

    def evaluate(self, evidence: Evidence, llm_facts: dict | None = None) -> Verdict:
        # BLF proof is judged on numeric request/response data, not page semantics,
        # so the LLM fact-extractor is not needed here (accepted for a uniform interface).
        # Scope to the target endpoint so a tamper on a different endpoint can't credit
        # this bug; restore the full list afterwards for report/PoC.
        _all = evidence.exchanges
        self._full_exchanges = _all  # some rules (coupon reuse) need cross-endpoint context
        evidence.exchanges = self._scope(evidence)
        try:
            if self._pattern_id == "BLF-05":
                return self._eval_coupon_abuse(evidence)
            elif self._pattern_id == "BLF-01":
                return self._eval_price_tamper(evidence)
            elif self._pattern_id in ("BLF-02", "BLF-06", "BLF-07"):
                return self._eval_quantity_tamper(evidence)
            elif self._pattern_id == "BLF-03":
                return self._eval_state_skip(evidence)
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
                if val and any(h in name.lower() for h in ("coupon", "code", "promo", "voucher", "discount")):
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
            and any(k in (ex.endpoint or "").lower() for k in ("checkout", "purchase", "confirm", "/pay"))
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
        """State skip: reached final step without completing intermediate steps."""
        markers: list[ProofMarker] = []
        required = [ProofKey.STATE_SKIP, ProofKey.STATE_DELTA]

        # Success if we got a 2xx on the final workflow step directly
        final_2xx = [ex for ex in evidence.exchanges if ex.status in range(200, 300)]
        if final_2xx and evidence.state_delta:
            markers.extend([
                ProofMarker(
                    key=ProofKey.STATE_SKIP,
                    satisfied=True,
                    detail=f"Final workflow endpoint reached with {final_2xx[-1].status}",
                    exchange_seqs=[final_2xx[-1].seq],
                ),
                ProofMarker(
                    key=ProofKey.STATE_DELTA,
                    satisfied=True,
                    detail=f"State delta confirms step was skipped: {evidence.state_delta}",
                    extracted=evidence.state_delta,
                ),
            ])
        else:
            markers = [
                ProofMarker(key=ProofKey.STATE_SKIP, satisfied=False, detail="No evidence of workflow step skipping"),
                ProofMarker(key=ProofKey.STATE_DELTA, satisfied=False, detail="No state delta"),
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
