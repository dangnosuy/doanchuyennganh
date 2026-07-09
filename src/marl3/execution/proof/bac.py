"""BAC proof rules evaluated against structured Evidence."""
from __future__ import annotations

import logging
import re

from .base import ProofGate
from ...contracts.evidence import Evidence, ProofMarker, Verdict
from ...contracts.enums import ProofKey, VerdictStatus
from ...recon.body_store import BodyStore

log = logging.getLogger("marl3.proof.bac")

_SENSITIVE_FIELDS = {
    # Identity / PII
    "email", "phone", "telephone", "mobile", "address", "dob", "birth", "birthday",
    "ssn", "social_security", "national_id", "passport", "tax_id",
    # Auth / secrets
    "password", "passwd", "hash", "token", "secret", "api_key", "apikey",
    "access_token", "refresh_token", "private_key",
    # Financial
    "salary", "balance", "credit", "credit_card", "card_number", "cvv",
    "bank_account", "iban", "routing_number", "income", "revenue",
    # Privilege
    "role", "admin", "is_admin", "permissions", "privilege", "access_level",
    "is_staff", "is_superuser", "group",
}
_ADMIN_KEYWORDS = {
    "/admin", "/administrator", "/management", "/console",
    "/superuser", "/staff", "/internal", "/config",
    "/control", "/moderator", "/backend", "/panel",
    "/sysadmin", "/ops", "/debug", "/manager",
}
_ADMIN_TITLE_KEYWORDS = (
    "admin panel", "admin dashboard", "administration", "control panel",
    "superuser", "staff panel", "management console", "admin console",
    "back office", "backoffice", "system admin", "site admin",
    "user management", "admin area",
)
_ADMIN_TITLE_WEAK = ("admin", "dashboard", "management", "staff", "backoffice", "console")
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

# HTML-rendered identity patterns — catch "Your username is: VALUE" and "Your API Key is: VALUE"
# which appear on PortSwigger profile pages and other templated account pages instead of emails.
_HTML_ID_PATTERNS = [
    re.compile(r'(?:username|user\s+id|your\s+username|your\s+name|logged\s+in\s+as)\s+is:?\s*([^\s<"\']{1,60})', re.IGNORECASE),
    re.compile(r'(?:api.?key|access.?key|secret.?key)\s+is:?\s*([^\s<"\']{6,100})', re.IGNORECASE),
    re.compile(r'(?:signed\s+in|account)\s+as\s*:?\s*([^\s<"\']{1,60})', re.IGNORECASE),
]


def _extract_html_identity(body: str) -> list[str]:
    """Extract per-user identity markers from HTML for cross-user IDOR comparison."""
    found = []
    for pattern in _HTML_ID_PATTERNS:
        for m in pattern.finditer(body):
            val = m.group(1).strip().rstrip(".,:;")
            if val and len(val) >= 3:
                found.append(val)
    return sorted(set(found))


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
            elif self._pattern_id in ("BAC-01", "BAC-06", "BAC-07"):
                # BAC-07 (email domain bypass) achieves admin access — same proof shape as BAC-01.
                verdict = self._eval_admin_access(evidence)
                # Fallback: Hunter may have misclassified IDOR as BAC-01/06 (e.g. seeded /profile as
                # BAC-01 but Exec probed /profile/{id} cross-user). If admin-access eval failed, try
                # IDOR detection — if cross-user evidence is found, promote pattern to BAC-03.
                if verdict.status != VerdictStatus.EXPLOITED:
                    idor_verdict = self._eval_idor(evidence)
                    if idor_verdict.status == VerdictStatus.EXPLOITED:
                        evidence.pattern_id = "BAC-03"
                        return idor_verdict
                return verdict
            elif self._pattern_id == "BAC-02":
                return self._eval_param_escalation(evidence)
            elif self._pattern_id == "BAC-04":
                return self._eval_method_bypass(evidence)
            elif self._pattern_id in ("BAC-05", "BAC-08"):
                # BAC-08 (IDOR + password disclosure) requires ownership bypass + sensitive field.
                return self._eval_idor(evidence, required=[ProofKey.OWNERSHIP_BYPASS, ProofKey.SENSITIVE_FIELD_EXPOSED])
            else:
                return self._eval_generic_bac(evidence)
        finally:
            evidence.exchanges = _all

    def _fact(self, seq: int, key: str, default=False):
        return (self._facts.get(seq) or {}).get(key, default)

    def _eval_idor(self, evidence: Evidence, required: list | None = None) -> Verdict:
        """IDOR: attacker gets 2xx and response contains victim's data."""
        if required is None:
            required = [ProofKey.OWNERSHIP_BYPASS]
        markers: list[ProofMarker] = []

        log.debug(
            f"_eval_idor: {len(evidence.exchanges)} scoped exchanges, "
            f"facts keys={list(self._facts.keys())}"
        )

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
        # Identity = emails extracted from body PLUS username_in_response from LLM facts
        # (handles HTML pages that show names but no emails, e.g. /orders/{id}).
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
                    # Also check query-param IDs (e.g. ?id=carlos, ?username=wiener)
                    query_id = next(
                        (v for k, v in ex.id_fields.items() if k.startswith("query_")),
                        None
                    )
                    cookie = ex.request_headers.get("Cookie", "") + ex.request_headers.get("cookie", "")
                    # Key captures path-based, query-param-based, and cookie-based IDOR variations.
                    rid_key = f"path={rid}|qid={query_id}|{cookie}"
                    body = self._response_text(ex)
                    emails = sorted(set(_EMAIL_RE.findall(body)))
                    # HTML-pattern identity: "Your username is: X", "Your API Key is: X", etc.
                    # Catches profile pages that show user data as text without email addresses.
                    html_ids = _extract_html_identity(body) if not emails else []
                    # LLM augmentation (lowest priority).
                    ex_facts = self._facts.get(ex.seq) or {}
                    llm_username = ex_facts.get("username_in_response") or ex_facts.get("owner_field_value")
                    if emails:
                        identity = emails
                    elif html_ids:
                        identity = html_ids
                    elif llm_username:
                        identity = [str(llm_username)]
                    else:
                        identity = []
                    identity_by_key[rid_key] = (rid_key, identity, ex.seq)
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

        # Redirect-body fallback: some IDOR implementations redirect (302) but leak
        # sensitive data in the redirect response body (e.g. /my-account?id=carlos → 302
        # with API key in body). Scan redirect responses for emails or known sensitive fields.
        if not markers:
            for ex in evidence.exchanges:
                if ex.status not in range(300, 400):
                    continue
                body = self._response_text(ex)
                emails_found = _EMAIL_RE.findall(body)
                body_lower = body.lower()
                has_sensitive = any(f in body_lower for f in (
                    "apikey", "api_key", "api-key", "password", "secret", "token",
                    "private", "credential", "key=", "\"key\"", "'key'",
                ))
                if emails_found or has_sensitive:
                    markers.append(ProofMarker(
                        key=ProofKey.OWNERSHIP_BYPASS,
                        satisfied=True,
                        detail=(
                            f"Sensitive data leaked in {ex.status} redirect response body at {ex.url}"
                            + (f" — emails: {emails_found[:3]}" if emails_found else "")
                            + (" — sensitive field patterns detected" if has_sensitive else "")
                        ),
                        exchange_seqs=[ex.seq],
                        extracted={"url": ex.url, "status": ex.status,
                                   "emails": emails_found[:3], "has_sensitive": has_sensitive},
                    ))
                    break

        # LLM fallback: classifier may have found an owner field the code missed
        # (non-English field name, unusual envelope structure, etc.).
        # NOTE: only use facts that carry identity-ownership semantics (named field or email).
        # username_in_response alone is NOT sufficient — it cannot prove cross-user access
        # without a comparison to the attacker's own identity. That comparison belongs in
        # a better exec strategy (retry), not in the proof gate.
        if not markers:
            for seq, facts in self._facts.items():
                fname = facts.get("owner_field_name")
                fval  = facts.get("owner_field_value")
                email = facts.get("email_in_response")
                if fname and fval is not None:
                    markers.append(ProofMarker(
                        key=ProofKey.OWNERSHIP_BYPASS,
                        satisfied=True,
                        detail=(f"LLM extractor found owner field {fname!r}={fval!r} "
                                f"in exchange {seq} — possible cross-user resource "
                                f"(verify manually; attacker identity unknown to extractor)"),
                        exchange_seqs=[seq],
                        extracted={"owner_field_name": fname, "owner_field_value": fval,
                                   "email": email, "source": "llm_extractor"},
                    ))
                    break
                if email:
                    markers.append(ProofMarker(
                        key=ProofKey.OWNERSHIP_BYPASS,
                        satisfied=True,
                        detail=(f"LLM extractor found email {email!r} in exchange {seq} "
                                "— possible cross-user data exposure"),
                        exchange_seqs=[seq],
                        extracted={"email": email, "source": "llm_extractor"},
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
            # Structural fallback: JSON array of ≥2 objects each containing sensitive fields
            # (e.g. GET /api/v1/users returns [{email, balance, role}, ...]) — detectable
            # without LLM when the response schema is recognisable.
            structural_pii_count = 0
            if not llm_pii and n_users < 2:
                _obj = self._response_obj(ex)
                if isinstance(_obj, list) and len(_obj) >= 2:
                    structural_pii_count = sum(
                        1 for item in _obj[:10]
                        if isinstance(item, dict)
                        and any(k.lower() in _SENSITIVE_FIELDS for k in item)
                    )
            data_exposure = llm_pii or n_users >= 2 or structural_pii_count >= 2
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
                count = n_users or structural_pii_count or "multiple"
                why.append(f"sensitive data exposure — PII of {count} user record(s) "
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

        # Pre-compute which endpoints had a blocked request (for escalation detection in
        # the PRIVILEGED_ACCESS loop below). When a cookie flip unlocks an admin path,
        # the page title may be a generic lab/app name — not "Admin Panel" — so
        # is_admin_path + blocked-then-allowed is the reliable signal.
        blocked_endpoints = {ex.endpoint for ex in evidence.exchanges if ex.status in (301, 302, 303, 401, 403)}

        # Primary signal: an unprivileged actor rendered an admin page (path or title).
        # This is the cookie-tamper proof (role=user→admin) — independent of redirect
        # following, since we judge on what was actually rendered.
        for ex in evidence.exchanges:
            if ex.status not in range(200, 300):
                continue
            is_admin_path = any(kw in ex.url.lower() for kw in _ADMIN_KEYWORDS)
            title_l = (ex.html_title or "").lower()
            # When a cookie change flips an admin-path endpoint from blocked→allowed, treat
            # that as PRIVILEGED_ACCESS even if the page title doesn't contain "Admin Panel"
            # (e.g. PortSwigger labs whose <title> is the lab name, not the panel name).
            escalated_on_admin = is_admin_path and (ex.endpoint in blocked_endpoints)
            is_admin_title = (
                any(kw in title_l for kw in _ADMIN_TITLE_KEYWORDS) or
                (is_admin_path and any(kw in title_l for kw in _ADMIN_TITLE_WEAK)) or
                bool(self._fact(ex.seq, "privileged_page")) or
                escalated_on_admin
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

    def _eval_method_bypass(self, evidence: Evidence) -> Verdict:
        """HTTP method override / method-based bypass.

        Signal 1: request succeeded (2xx) and used an X-HTTP-Method-Override header
                  or ?_method= query parameter — the server honoured the tunnelled verb.
        Signal 2: same endpoint returned blocked (403/405) for one HTTP method but 2xx
                  for a different method — access control is only enforced on one verb.
        """
        _OVERRIDE_HEADERS = {"x-http-method-override", "x-method-override",
                             "x-http-method", "x-tunneled-method"}
        markers: list[ProofMarker] = []
        required = [ProofKey.AUTH_BYPASS]

        for ex in evidence.exchanges:
            if ex.status not in range(200, 300):
                continue
            req_h = {k.lower(): v for k, v in (ex.request_headers or {}).items()}
            override_hdr = next((k for k in req_h if k in _OVERRIDE_HEADERS), None)
            url_lower = (ex.url or "").lower()
            override_param = "_method" if ("?_method=" in url_lower or "&_method=" in url_lower) else None
            if override_hdr or override_param:
                overridden = req_h.get(override_hdr, "") if override_hdr else \
                    url_lower.split("_method=", 1)[-1].split("&")[0]
                markers.append(ProofMarker(
                    key=ProofKey.AUTH_BYPASS,
                    satisfied=True,
                    detail=(f"HTTP method override accepted: {ex.method} + "
                            f"{override_hdr or override_param}={overridden!r} "
                            f"returned {ex.status} on {ex.url}"),
                    exchange_seqs=[ex.seq],
                    extracted={"override": override_hdr or override_param,
                               "overridden_method": overridden, "url": ex.url},
                ))
                break

        if not markers:
            by_endpoint: dict[str, list] = {}
            for ex in evidence.exchanges:
                by_endpoint.setdefault(ex.endpoint, []).append(ex)
            for endpoint, exs in by_endpoint.items():
                blocked = [e for e in exs if e.status in (403, 405)]
                allowed = [e for e in exs if e.status in range(200, 300)]
                for a in allowed:
                    for b in blocked:
                        if a.method.upper() != b.method.upper():
                            markers.append(ProofMarker(
                                key=ProofKey.AUTH_BYPASS,
                                satisfied=True,
                                detail=(f"Method-based bypass on {endpoint}: "
                                        f"{b.method} blocked ({b.status}), "
                                        f"{a.method} returned {a.status} — "
                                        "access control enforced on one method only"),
                                exchange_seqs=[b.seq, a.seq],
                                extracted={"blocked_method": b.method,
                                           "allowed_method": a.method},
                            ))
                            break
                    if markers:
                        break
                if markers:
                    break

        # LLM fallback: if no structural signal found, check if extractor confirmed
        # the action actually succeeded (resource_modified / action_confirmed).
        if not markers:
            for seq, facts in self._facts.items():
                if facts.get("resource_modified") or facts.get("action_confirmed"):
                    markers.append(ProofMarker(
                        key=ProofKey.AUTH_BYPASS,
                        satisfied=True,
                        detail=(f"LLM extractor confirmed resource was modified/action succeeded "
                                f"in exchange {seq} — method override likely effective"),
                        exchange_seqs=[seq],
                        extracted={"resource_modified": facts.get("resource_modified"),
                                   "action_confirmed": facts.get("action_confirmed"),
                                   "source": "llm_extractor"},
                    ))
                    break

        if not markers:
            markers.append(ProofMarker(
                key=ProofKey.AUTH_BYPASS,
                satisfied=False,
                detail="No method override header or method-based access difference detected",
                exchange_seqs=[],
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
    """Return value of the first owner-like field found in the object.

    Checks exact matches first (fast path), then falls back to substring matching
    for non-standard naming conventions (e.g. 'resource_owner', 'uploaded_by').
    """
    # Exact matches — common field names across frameworks
    for key in ("userId", "UserId", "user_id", "ownerId", "owner_id", "OwnerId",
                "createdBy", "created_by", "owner", "author", "authorId", "author_id",
                "accountId", "account_id", "customerId", "customer_id",
                "sellerId", "seller_id", "memberId", "member_id",
                "assignee", "assignee_id", "creator", "creator_id",
                "uploaded_by", "submitted_by", "requested_by", "modified_by",
                "tenant_id", "tenantId", "org_id", "organizationId"):
        if key in obj:
            return obj[key]
    # Substring fallback — catches non-standard names like 'resource_owner_id'
    lower_keys = {k.lower(): k for k in obj}
    for hint in ("owner", "created_by", "author", "creator", "belongs_to",
                 "assigned_to", "uploaded_by", "submitted_by"):
        for lk, real_k in lower_keys.items():
            if hint in lk:
                return obj[real_k]
    return None
