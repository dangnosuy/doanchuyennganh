"""BAC proof rules evaluated against structured Evidence."""
from __future__ import annotations

import logging
import re

from .base import ProofGate
from ...contracts.evidence import Evidence, ProofMarker, Verdict
from ...contracts.enums import ProofKey, VerdictStatus
from ...recon.body_store import BodyStore

log = logging.getLogger("marl3.proof.bac")

_SENSITIVE_FIELDS = {"email", "password", "token", "secret", "api_key", "ssn", "credit_card",
                     "address", "phone", "dob", "birth", "role", "admin", "salary", "balance"}
_ADMIN_KEYWORDS = {"/admin", "/administrator", "/management", "/console",
                   "/superuser", "/staff", "/internal", "/config"}
_ADMIN_TITLE_KEYWORDS = ("admin panel", "admin dashboard", "administration", "control panel", "superuser", "staff panel", "management console", "admin console")
_ADMIN_TITLE_WEAK = ("admin", "dashboard", "management", "staff")  # only valid WITH admin path
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")


class BACProofGate(ProofGate):
    """Evaluates BAC (Broken Access Control) evidence."""

    def __init__(self, body_store: BodyStore, pattern_id: str) -> None:
        super().__init__(body_store)
        self._pattern_id = pattern_id

    def evaluate(self, evidence: Evidence, llm_facts: dict | None = None) -> Verdict:
        self._facts = llm_facts or {}
        # Scope evidence to the dossier's target endpoint family: a finding must NOT be
        # 'proven' by an exchange the exec wandered into on a different endpoint
        # (e.g. crediting /orders with a /api/v1/users leak). Restore the full list after
        # so report/PoC still see everything.
        _all = evidence.exchanges
        evidence.exchanges = self._scope(evidence)
        try:
            if self._pattern_id == "BAC-03":
                return self._eval_idor(evidence)
            elif self._pattern_id in ("BAC-01", "BAC-06"):
                return self._eval_admin_access(evidence)
            elif self._pattern_id == "BAC-02":
                return self._eval_param_escalation(evidence)
            else:
                return self._eval_generic_bac(evidence)
        finally:
            evidence.exchanges = _all

    def _fact(self, seq: int, key: str, default=False):
        return (self._facts.get(seq) or {}).get(key, default)

    def _eval_idor(self, evidence: Evidence) -> Verdict:
        """IDOR: attacker gets 2xx and response contains victim's data."""
        markers: list[ProofMarker] = []
        required = [ProofKey.OWNERSHIP_BYPASS]

        # Try to establish attacker's own user ID from a whoami/profile exchange
        attacker_user_id: object = None
        for ex in evidence.exchanges:
            if "whoami" in ex.url or "me" in ex.url.split("/"):
                obj = self._response_obj(ex)
                if isinstance(obj, dict):
                    # {"user": {"id": 24, ...}} or {"id": 24, ...}
                    user_obj = obj.get("user") or obj
                    uid = user_obj.get("id") or user_obj.get("userId") or user_obj.get("user_id")
                    if uid is not None:
                        attacker_user_id = uid
                        break

        for ex in evidence.exchanges:
            if ex.status not in range(200, 300):
                continue
            obj = self._response_obj(ex)
            if not isinstance(obj, (dict, list)):
                continue

            # Check for owner-field mismatch — also unwrap common envelope keys
            candidates: list[dict] = []
            if isinstance(obj, dict):
                candidates.append(obj)
                # Unwrap common envelope keys: {data: {...}}, {result: {...}}, {item: {...}}
                for wrap_key in ("data", "result", "item", "resource", "object"):
                    inner = obj.get(wrap_key)
                    if isinstance(inner, dict):
                        candidates.append(inner)
                    elif isinstance(inner, list):
                        candidates.extend(x for x in inner[:5] if isinstance(x, dict))
            else:
                candidates.extend(x for x in obj[:5] if isinstance(x, dict))

            items = candidates
            for item in items:
                if not isinstance(item, dict):
                    continue
                owner_val = _find_owner_field(item)
                if owner_val is None:
                    continue
                # SOUNDNESS: an owner field on its own proves nothing — reading your OWN
                # resource is not IDOR. Only confirm when we KNOW the attacker's identity
                # AND the owner differs from the attacker (genuine cross-user access).
                if attacker_user_id is None or str(owner_val) == str(attacker_user_id):
                    log.debug(f"{ex.url}: owner={owner_val} attacker={attacker_user_id} — not cross-user, skipping")
                    continue
                markers.append(ProofMarker(
                    key=ProofKey.OWNERSHIP_BYPASS,
                    satisfied=True,
                    detail=(f"Actor {ex.actor!r} (user_id={attacker_user_id}) accessed resource owned by "
                            f"{owner_val!r} at {ex.url} — cross-user access confirmed"),
                    exchange_seqs=[ex.seq],
                    extracted={"owner_value": owner_val, "actor": ex.actor,
                               "attacker_user_id": attacker_user_id, "cross_user": True},
                ))
                exposed = [k for k in item if k.lower() in _SENSITIVE_FIELDS]
                if exposed:
                    markers.append(ProofMarker(
                        key=ProofKey.SENSITIVE_FIELD_EXPOSED,
                        satisfied=True,
                        detail=f"Sensitive fields of another user exposed: {exposed}",
                        exchange_seqs=[ex.seq],
                        extracted={"fields": exposed},
                    ))

        # HTML fallback: reflected-identity CHANGE on the SAME endpoint when only the
        # ID (path or cookie) is varied. SOUNDNESS: we must tie the identity to a
        # tampered request on the same resource template — not just "two emails exist
        # somewhere on the site" (footer/contact emails are not IDOR). We compare 2xx
        # responses for the same endpoint template that differ by path_id / user_id cookie
        # and require the reflected identity to differ between them.
        if not markers:
            by_template: dict[str, list] = {}
            for ex in evidence.exchanges:
                if ex.status not in range(200, 300):
                    continue
                by_template.setdefault(ex.endpoint, []).append(ex)
            for template, exs in by_template.items():
                if len(exs) < 2:
                    continue
                identity_by_key: dict = {}
                for ex in exs:
                    rid = ex.id_fields.get("path_id")
                    cookie = ex.request_headers.get("Cookie", "") + ex.request_headers.get("cookie", "")
                    # Key captures both path-based and cookie-based IDOR variations.
                    # rid alone would be None for every cookie-based request, collapsing
                    # distinct tampered cookies into a single set entry and preventing detection.
                    rid_key = f"path={rid}|{cookie}"
                    body = self._response_text(ex)
                    emails = sorted(set(_EMAIL_RE.findall(body)))
                    identity_by_key[rid_key] = (rid_key, emails, ex.seq)
                # need at least two DIFFERENT request signatures whose reflected identities differ
                distinct = {tuple(v[1]) for v in identity_by_key.values() if v[1]}
                varied_keys = set(identity_by_key.keys())
                if len(varied_keys) >= 2 and len(distinct) >= 2:
                    markers.append(ProofMarker(
                        key=ProofKey.OWNERSHIP_BYPASS,
                        satisfied=True,
                        detail=(f"On {template}, varying the resource ID returned DIFFERENT user "
                                f"identities ({[v[1] for v in identity_by_key.values()][:3]}) — cross-user IDOR"),
                        exchange_seqs=[v[2] for v in identity_by_key.values()],
                        extracted={"template": template, "identities": [v[1] for v in identity_by_key.values()][:5]},
                    ))
                    break

        if not markers:
            markers.append(ProofMarker(
                key=ProofKey.OWNERSHIP_BYPASS,
                satisfied=False,
                detail="No owner-field mismatch or cross-user identity exposure detected",
                exchange_seqs=[],
            ))

        evidence.proof_markers = markers
        return self._make_verdict(markers, required, self._pattern_id)

    def _eval_admin_access(self, evidence: Evidence) -> Verdict:
        """Admin bypass: a low-priv/anon actor reaches a privileged page.

        SOUNDNESS (Codex #11): a bare `is_admin_path + 2xx` is NOT enough — a public page
        under /admin, or (historically) a redirect-to-login collapsed into 200, would
        false-positive. Now require ONE of:
          (a) the rendered page is clearly an admin page (admin-ish <title>), OR
          (b) a visible escalation: the SAME/sibling endpoint was blocked (302/401/403)
              for a baseline request but 2xx here (proves access was gated and bypassed).
        """
        markers: list[ProofMarker] = []
        required = [ProofKey.PRIVILEGED_ACCESS]

        # Map endpoint -> set of statuses seen, to detect blocked→allowed escalation
        blocked_endpoints = {ex.endpoint for ex in evidence.exchanges if ex.status in (301, 302, 303, 401, 403)}

        for ex in evidence.exchanges:
            if ex.status not in range(200, 300):
                continue
            is_admin_path = any(kw in ex.url.lower() for kw in _ADMIN_KEYWORDS)
            title_l = (ex.html_title or "").lower()
            # Strong admin titles (e.g. "Admin Panel") count alone.
            # Weak ones ("dashboard", "management") only count when also on an admin path
            # to avoid "User Dashboard" false positives.
            # LLM fact-extractor signals (zero-context): more robust than title strings
            # for novel admin pages, and the primary signal for BAC-01 data exposure.
            llm_priv = bool(self._fact(ex.seq, "privileged_page"))
            llm_pii = bool(self._fact(ex.seq, "exposes_other_users_pii"))
            n_users = int(self._fact(ex.seq, "distinct_user_records", 0) or 0)

            is_admin_title = (
                any(kw in title_l for kw in _ADMIN_TITLE_KEYWORDS) or
                (is_admin_path and any(kw in title_l for kw in _ADMIN_TITLE_WEAK)) or
                llm_priv
            )
            actor_role = (evidence.session_context.get(ex.actor, "") or ("anon" if ex.actor == "anon" else "user")).lower()
            is_unpriv = actor_role not in ("admin", "administrator", "superuser", "root")
            if not is_unpriv:
                continue

            # Reject obvious login/redirect pages masquerading as access
            looks_like_login = any(w in title_l for w in ("login", "log in", "sign in", "đăng nhập", "redirect"))

            escalated = ex.endpoint in blocked_endpoints  # blocked elsewhere, allowed here
            # BAC-01 data exposure: an unprivileged actor received multiple users' PII.
            data_exposure = llm_pii or n_users >= 2
            strong = (
                (is_admin_title and not looks_like_login)
                or (is_admin_path and escalated and not looks_like_login)
                or data_exposure
            )
            if not strong:
                continue

            obj = self._response_obj(ex)
            sensitive = []
            if isinstance(obj, (dict, list)):
                items = [obj] if isinstance(obj, dict) else (obj[:3] if obj else [])
                for item in items:
                    if isinstance(item, dict):
                        sensitive.extend(k for k in item if k.lower() in _SENSITIVE_FIELDS)
            has_real_title = (
                any(kw in title_l for kw in _ADMIN_TITLE_KEYWORDS)
                or (is_admin_path and any(kw in title_l for kw in _ADMIN_TITLE_WEAK))
            )
            why = []
            if data_exposure:
                why.append(f"sensitive data exposure — PII of {n_users or 'multiple'} user(s) "
                           "returned to an unprivileged actor")
            if has_real_title:
                why.append(f"admin page [title: {ex.html_title!r}]")
            elif llm_priv and not data_exposure:
                why.append("response classified as privileged/admin content")
            if escalated:
                why.append("endpoint was blocked (3xx/401/403) for a baseline request")
            markers.append(ProofMarker(
                key=ProofKey.PRIVILEGED_ACCESS,
                satisfied=True,
                detail=f"Unprivileged actor {ex.actor!r} got {ex.status} on {ex.url} — {'; '.join(why)}",
                exchange_seqs=[ex.seq],
                extracted={"url": ex.url, "status": ex.status, "sensitive_fields": sensitive,
                           "escalated": escalated, "admin_title": is_admin_title},
            ))

        if not markers:
            markers.append(ProofMarker(
                key=ProofKey.PRIVILEGED_ACCESS,
                satisfied=False,
                detail="No proven privileged access (no admin-titled page, no blocked→allowed escalation)",
                exchange_seqs=[],
            ))

        evidence.proof_markers = markers
        return self._make_verdict(markers, required, self._pattern_id)

    def _eval_param_escalation(self, evidence: Evidence) -> Verdict:
        """Privilege escalation via parameter/cookie manipulation.

        Requires BOTH signals to call EXPLOITED:
          (a) PRIVILEGED_ACCESS: unprivileged actor rendered an admin-titled page.
          (b) AUTH_BYPASS: same actor + same endpoint had a blocked baseline first.
        Lone admin-page render without a baseline is indistinguishable from BAC-01.
        """
        markers: list[ProofMarker] = []
        required = [ProofKey.PRIVILEGED_ACCESS, ProofKey.AUTH_BYPASS]

        # Primary signal: an unprivileged actor rendered an admin page (path or title).
        # This is the cookie-tamper proof (role=user→admin) — independent of redirect
        # following, since we judge on what was actually rendered.
        for ex in evidence.exchanges:
            if ex.status not in range(200, 300):
                continue
            is_admin_path = any(kw in ex.url.lower() for kw in _ADMIN_KEYWORDS)
            title_l = (ex.html_title or "").lower()
            is_admin_title = (
                any(kw in title_l for kw in _ADMIN_TITLE_KEYWORDS) or
                (is_admin_path and any(kw in title_l for kw in _ADMIN_TITLE_WEAK)) or
                bool(self._fact(ex.seq, "privileged_page"))
            )
            actor_role = (evidence.session_context.get(ex.actor, "") or ("anon" if ex.actor == "anon" else "user")).lower()
            is_unpriv = actor_role not in ("admin", "administrator", "superuser", "root")
            if is_admin_title and is_unpriv:
                markers.append(ProofMarker(
                    key=ProofKey.PRIVILEGED_ACCESS,
                    satisfied=True,
                    detail=f"Unprivileged actor {ex.actor!r} rendered privileged page [title: {ex.html_title!r}] at {ex.url} after tampering — escalation confirmed",
                    exchange_seqs=[ex.seq],
                    extracted={"url": ex.url, "title": ex.html_title, "status": ex.status},
                ))
                break

        # Secondary signal: cookie-tamper escalation on the SAME endpoint. The endpoint
        # returned a BLOCK (3xx/401/403) for one request and a 2xx for another whose
        # request COOKIE DIFFERS — i.e. changing the role/identity cookie flipped access.
        # This is ORDER-INDEPENDENT (the proof is the cookie change, not which request
        # came first), which fixes BAC-02 being capped at INFO when exec tampered before
        # capturing the blocked baseline. Soundness: cookies must differ, so a genuinely
        # flaky endpoint (identical request, different status) does NOT count. (And BAC-02
        # also requires PRIVILEGED_ACCESS above, so a non-admin page never reaches EXPLOITED.)
        def _cookie(ex) -> str:
            h = ex.request_headers or {}
            return (h.get("Cookie") or h.get("cookie") or "").strip()

        by_endpoint: dict[str, list] = {}
        for ex in evidence.exchanges:
            by_endpoint.setdefault(ex.endpoint, []).append(ex)
        for endpoint, exs in by_endpoint.items():
            blocked = [e for e in exs if e.status in (301, 302, 303, 401, 403)]
            allowed = [e for e in exs if e.status in range(200, 300)]
            pair = None
            for a in allowed:
                for b in blocked:
                    if _cookie(a) != _cookie(b):
                        pair = (a, b)
                        break
                if pair:
                    break
            if pair:
                a, b = pair
                markers.append(ProofMarker(
                    key=ProofKey.AUTH_BYPASS,
                    satisfied=True,
                    detail=(f"On {endpoint}: blocked ({b.status}) with one cookie, 2xx with a different "
                            "(tampered) cookie — changing the role/identity cookie flipped access"),
                    exchange_seqs=[b.seq, a.seq],
                    extracted={"escalated": True, "blocked_status": b.status},
                ))
                break

        if not markers:
            markers.append(ProofMarker(
                key=ProofKey.PRIVILEGED_ACCESS,
                satisfied=False,
                detail="No privilege escalation observed (no admin page rendered, no status escalation)",
            ))

        evidence.proof_markers = markers
        return self._make_verdict(markers, required, self._pattern_id)

    def _eval_generic_bac(self, evidence: Evidence) -> Verdict:
        # For unsupported BAC patterns, a bare 2xx is NOT sufficient to call EXPLOITED —
        # we have no domain rule for what constitutes proof. Return FAILED to keep the
        # verifier panel as the sole authority rather than false-positiving.
        markers = [ProofMarker(
            key=ProofKey.PRIVILEGED_ACCESS,
            satisfied=False,
            detail=(f"Unsupported BAC pattern {self._pattern_id}: no rule-based proof available. "
                    "Verifier panel must decide."),
            exchange_seqs=[],
        )]
        evidence.proof_markers = markers
        return self._make_verdict(markers, [ProofKey.PRIVILEGED_ACCESS], self._pattern_id)


def _find_owner_field(obj: dict) -> object:
    """Return value of the first owner-like field found in the object."""
    for key in ("userId", "UserId", "user_id", "ownerId", "owner_id", "OwnerId",
                "createdBy", "created_by", "owner", "author", "authorId",
                "accountId", "account_id", "customerId", "customer_id"):
        if key in obj:
            return obj[key]
    return None
