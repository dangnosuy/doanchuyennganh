"""VulnCandidateGenerator — produces structured BugDossier list from ReconArtifact.

Uses LLM (hunter role) to analyse recon data and suggest vulnerability candidates,
then enriches each candidate with real HTTP examples and evidence rules.
"""
from __future__ import annotations

import base64
import json
import logging
import re

from ..config import AppConfig
from ..contracts.dossier import BugDossier, AuthRequirement, EvidenceRule, HttpExample
from ..contracts.enums import BugCategory, Severity
from ..contracts.recon import ReconArtifact
from ..knowledge.provider import get_provider
from ..llm.client import LLMClient
from ..prompts.registry import render

log = logging.getLogger("marl3.hunter")

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


_OWNER_MARKERS = ("owner", "user_id", "userid", "account", "email", "author", "customer", "belongs")
_LIST_MARKERS = ("full list", "all users", "user list", "list of", "every user",
                 "entire list", "enumerate", "all accounts", "list all")


def _family_path(path: str) -> str:
    """Normalise a path to an endpoint family: numeric/uuid segments → {id}.

    /admin, /admin/, /admin?x=1 → /admin ; /user/1 and /user/2 → /user/{id}.
    """
    path = (path or "").split("?")[0].rstrip("/") or "/"
    parts: list[str] = []
    for seg in path.split("/"):
        if not seg:
            continue
        if seg.isdigit() or re.fullmatch(r"[0-9a-fA-F-]{16,36}", seg):
            parts.append("{id}")
        elif seg.startswith("{") and seg.endswith("}"):
            parts.append("{id}")
        else:
            parts.append(seg)
    return "/" + "/".join(parts) if parts else "/"


def _reclassify_pattern(c: dict) -> str:
    """Correct an obviously-mislabeled pattern_id using endpoint + text markers.

    Only fixes the observed failure mode: a collection/list endpoint (no per-object
    id) tagged BAC-03 (IDOR) is really BAC-01 (unauthorized data exposure). IDOR
    requires a per-object identifier whose owner can differ from the attacker.
    """
    pid = str(c.get("pattern_id") or "BAC-03").upper()
    endpoint = c.get("endpoint") or ""
    blob = " ".join(str(c.get(k, "")) for k in ("endpoint", "title", "hypothesis", "notes")).lower()
    has_obj = bool(re.search(r"\{[^}]+\}", endpoint) or re.search(r"/\d+(/|$)", endpoint))
    is_list = any(w in blob for w in _LIST_MARKERS)
    if pid == "BAC-03" and (is_list or not has_obj):
        return "BAC-01"
    # Reverse: BAC-01 tagged on a per-object path (e.g. /profile/{id}) is really IDOR
    if pid == "BAC-01" and has_obj and not is_list:
        return "BAC-03"
    # BAC-06 (forced-browsing probe) on a per-object non-admin path is really IDOR
    is_admin_path = any(kw in endpoint.lower() for kw in _ADMIN_PATH_KW)
    if pid == "BAC-06" and has_obj and not is_list and not is_admin_path:
        return "BAC-03"
    return pid


_SEED_MONEY_KW = ("amount", "price", "total", "cost", "balance", "credit", "point", "qty", "quantity")


def _build_page_observations(recon) -> str:
    """Build rich page content for the hunter — body previews, form field details with type+value.

    Code responsibility: collect everything and forward it. LLM responsibility: reason from it.
    """
    if recon is None:
        return ""
    lines: list[str] = []
    seen: set[tuple] = set()

    for ex in (getattr(recon, "exchanges", None) or []):
        key = (ex.url, ex.actor)
        if key in seen:
            continue
        has_content = bool(
            ex.html_title
            or ex.forms
            or (getattr(ex, "response_body_ref", None) and ex.response_body_ref.head_preview)
        )
        if not has_content:
            continue
        seen.add(key)

        parts: list[str] = [f"\n### {ex.method} {ex.url}  (actor={ex.actor}) → {ex.status}"]
        if ex.html_title:
            parts.append(f"  Title: {ex.html_title}")

        for form in (ex.forms or []):
            action = form.get("action", "") or ""
            method = (form.get("method", "GET") or "GET").upper()
            field_parts: list[str] = []
            for fld in form.get("fields", []):
                name = fld.get("name", "")
                if not name:
                    continue
                ftype = fld.get("type", "text")
                value = fld.get("value", "")
                if ftype == "hidden":
                    field_parts.append(f"{name}={value}[hidden]")
                elif value:
                    field_parts.append(f"{name}={value}[{ftype}]")
                else:
                    field_parts.append(f"{name}[{ftype}]")
            if field_parts:
                parts.append(f"  Form {method} {action}: {', '.join(field_parts)}")

        body_ref = getattr(ex, "response_body_ref", None)
        if body_ref and getattr(body_ref, "head_preview", None):
            preview = body_ref.head_preview[:500]
            parts.append(f"  Body: {preview}")

        lines.append("\n".join(parts))

    return "\n".join(lines)


def _build_auth_sessions_detail(recon) -> str:
    """Return auth session summary including actual cookie values for BAC reasoning.

    Base64-encoded cookie values are decoded inline — the hunter sees the plaintext
    uid:role structure without needing to decode manually (e.g. _identity=MTp1c2Vy → '1:user').
    """
    profiles = getattr(recon, "auth_profiles", None) or []
    if not profiles:
        return "(none — anonymous crawl only)"
    parts: list[str] = []
    for p in profiles:
        raw_cookie = getattr(p, "cookie_header", None) or ""
        if not raw_cookie:
            parts.append(f"- {p.label}: (no cookies)")
            continue
        annotated_pairs: list[str] = []
        for kv in raw_cookie.split(";"):
            kv = kv.strip()
            if "=" not in kv:
                annotated_pairs.append(kv)
                continue
            name, _, val = kv.partition("=")
            annotation = ""
            if len(val) >= 6:
                try:
                    decoded = base64.b64decode(val + "==").decode("utf-8", errors="strict")
                    if any(c.isalpha() for c in decoded) and decoded.isprintable():
                        annotation = f" [base64→ {decoded!r}]"
                except Exception:
                    pass
            annotated_pairs.append(f"{name}={val}{annotation}")
        parts.append(f"- {p.label}: {'; '.join(annotated_pairs)}")
    return "\n".join(parts)
_SEED_QTY_KW = ("qty", "quantity", "count", "stock")
_TAMPERABLE_COOKIE_NAMES = frozenset({
    "role", "is_admin", "admin", "user_id", "userid", "account", "uid",
    "access_level", "privilege", "permissions", "account_type", "tier",
    "is_staff", "is_superuser", "user_role", "auth_level", "usertype",
    "user_type", "group", "isadmin",
})
_ADMIN_PATH_KW = (
    "/admin", "/administrator", "/manage", "/console", "/staff",
    "/internal", "/backend", "/superuser", "/control", "/moderator",
    "/sysadmin", "/panel", "/ops", "/debug", "/manager", "/config",
)


def _seed(pattern_id: str, endpoint: str, method: str, title: str, hypothesis: str,
          confidence: float = 0.45) -> dict:
    return {
        "pattern_id": pattern_id, "endpoint": endpoint, "method": method,
        "title": title, "hypothesis": hypothesis, "exploit_approach": hypothesis,
        "confidence": confidence, "supporting_exchange_ids": [], "notes": "seeded from recon",
    }


def _seed_from_recon(recon) -> list[dict]:
    """Deterministically derive candidates from observed routes (no LLM).

    Guarantees coverage of high-value endpoints the LLM hunter may forget. Seeds carry
    LOW confidence (≤0.5) so a real LLM candidate on the same endpoint wins the dedup;
    seeds only survive to fill gaps.
    """
    if recon is None:
        return []
    endpoints = getattr(recon, "endpoints", []) or []
    seeds: list[dict] = []

    # Endpoints where anon is blocked (302/401/403) — BAC-01 requires anon to actually
    # receive data, so skip seeding BAC-01 for these (they are properly auth-gated).
    auth_gated: set[str] = set()
    for diff in getattr(recon, "auth_diffs", []) or []:
        if diff.anon_status in (301, 302, 303, 401, 403):
            auth_gated.add(f"{diff.method}:{diff.endpoint}")

    # cookie-tamper (BAC-02) signal: plaintext role/uid cookies OR base64-encoded identity cookies
    # (e.g. _identity=MTp1c2Vy → base64 decode → "1:user" — clear uid:role structure)
    cookie_names: set[str] = set()
    encoded_identity_cookies: set[str] = set()

    for p in getattr(recon, "auth_profiles", []) or []:
        if getattr(p, "cookie_header", None):
            for kv in p.cookie_header.split(";"):
                kv = kv.strip()
                if "=" not in kv:
                    continue
                name, _, val = kv.partition("=")
                cname = name.strip().lower()
                cookie_names.add(cname)
                if len(val) >= 6:
                    try:
                        decoded = base64.b64decode(val + "==").decode("utf-8", errors="strict")
                        if re.search(r"\d+:(user|admin|staff|role|operator|member|mod)", decoded, re.I):
                            encoded_identity_cookies.add(cname)
                    except Exception:
                        pass

    plaintext_tamperable = bool(cookie_names & _TAMPERABLE_COOKIE_NAMES)
    tamperable = plaintext_tamperable or bool(encoded_identity_cookies)

    # money/qty fields per endpoint family (from endpoint params + form fields + form actions)
    from urllib.parse import urlparse
    money_family: dict[str, list[str]] = {}

    def _add_money(fam: str, fields: list[str]) -> None:
        money = [f for f in fields if f and any(k in f.lower() for k in _SEED_MONEY_KW)]
        if money:
            money_family.setdefault(fam, [])
            for f in money:
                if f not in money_family[fam]:
                    money_family[fam].append(f)

    for ep in endpoints:
        _add_money(_family_path(ep.endpoint), list(ep.parameters) + list(ep.numeric_fields))
    for ex in getattr(recon, "exchanges", []) or []:
        for form in getattr(ex, "forms", []) or []:
            fields = [f.get("name", "") for f in form.get("fields", [])]
            _add_money(_family_path(ex.endpoint), fields)
            action = form.get("action") or ""
            if action:
                _add_money(_family_path(urlparse(action).path or action), fields)

    for ep in endpoints:
        path, method = ep.endpoint, ep.method
        low = path.lower()
        fam = _family_path(path)
        probed = getattr(ep, "discovery", "") == "probed"
        is_admin = any(k in low for k in _ADMIN_PATH_KW)
        has_pathid = "{id}" in path or "{uuid}" in path or "{id}" in fam

        if method == "GET" and is_admin:
            # Seed BAC-06 for any admin path that is accessible (auth_diffs, probed, or simply crawled).
            # A crawled path is reachable by definition — the crawler visited it successfully.
            accessible_to_auth = f"GET:{path}" in {f"{d.method}:{d.endpoint}"
                                                    for d in (getattr(recon, "auth_diffs", []) or [])
                                                    if getattr(d, "auth_status", 999) < 400}
            crawled = getattr(ep, "discovery", "") == "crawled"
            if accessible_to_auth or probed or crawled:
                seeds.append(_seed("BAC-06", path, "GET",
                    f"Forced browsing to admin area {path}",
                    f"GET {path} is an admin/privileged area{' ([probed], not linked)' if probed else ''}; "
                    f"test access as low-priv and with a tampered role cookie."))
            if plaintext_tamperable:
                plain_names = sorted(cookie_names & _TAMPERABLE_COOKIE_NAMES)
                seeds.append(_seed("BAC-02", path, "GET",
                    f"Privilege escalation via cookie on {path}",
                    f"Plaintext cookies {plain_names} present. FIRST request {path} as normal "
                    f"user (expect 302/403 block), THEN tamper role=admin (expect 200) — capture both in order.",
                    confidence=0.5))
            if encoded_identity_cookies:
                cnames = sorted(encoded_identity_cookies)
                seeds.append(_seed("BAC-02", path, "GET",
                    f"Encoded-cookie privilege escalation on {path}",
                    f"Cookie(s) {cnames} contain base64-encoded uid:role data (e.g. MTp1c2Vy → '1:user'). "
                    f"FIRST request {path} as normal user, THEN forge cookie with admin/staff role: "
                    f"base64-encode '1:admin' or '1:staff' and replace the cookie value. "
                    f"Capture baseline (normal user → 302/403) then forged (elevated → 200) in order.",
                    confidence=0.55))
        elif method == "GET" and probed and not is_admin:
            seeds.append(_seed("BAC-06", path, "GET",
                f"Forced browsing to {path}",
                f"GET {path} is auth-gated/probed; verify it exists and whether a low-priv session reaches it."))

        # BAC-04: HTTP Method Override — seed when an admin/role-action endpoint exists
        # alongside a GET admin area. Typical scenario: GET /admin renders panel, but
        # POST /admin/roles or /admin/upgrade requires admin privilege — try method override.
        if method in ("POST", "PUT", "PATCH", "DELETE") and is_admin:
            seeds.append(_seed("BAC-04", path, method,
                f"HTTP method override on {path}",
                f"{method} {path} is an admin action endpoint. If it returns 401/403, "
                f"try tunnelling via POST with X-HTTP-Method-Override: {method} header, "
                f"or use _method={method} query param. Capture baseline (no override → blocked) "
                f"then override (expects 200/302).", confidence=0.4))

        # BAC-02 mass assignment: POST/PATCH to account/profile/settings endpoints.
        # Server may accept undocumented JSON fields (roleid, role, is_admin) alongside
        # legitimate ones and persist them without whitelist validation.
        _PROFILE_KW = ("account", "profile", "user", "settings", "my-account", "change-email",
                       "change-password", "update", "edit")
        if method in ("POST", "PATCH") and any(k in low for k in _PROFILE_KW) and not is_admin:
            seeds.append(_seed("BAC-02", path, method,
                f"Mass assignment / JSON privilege field injection on {path}",
                f"{method} {path} accepts JSON updates to user account fields. Try adding "
                f"undocumented privilege fields to the JSON body: {{\"roleid\": 1}}, "
                f"{{\"role\": \"administrator\"}}, {{\"is_admin\": true}}, {{\"admin\": true}} "
                f"alongside the normal fields. If the server stores all submitted JSON keys "
                f"(ORM mass assignment), your role will be elevated.", confidence=0.45))

        if method == "GET" and has_pathid and getattr(ep, "auth_required", False):
            seeds.append(_seed("BAC-03", path, "GET",
                f"IDOR on {path}",
                f"GET {path} has a per-object id. Log in as user A, then request user B's id (cross-user) "
                f"and compare the returned identity — different owner = IDOR."))

        if method == "GET" and any(k in low for k in (
            "user", "account", "profile", "order", "client", "clients",
            "internal", "staff", "personnel", "data", "report",
            "employee", "customer", "member",
        )) and not has_pathid:
            # BAC-01 = anon/low-priv actor receives PII. If anon is blocked by a 302/401/403
            # redirect, the endpoint is properly auth-gated and is NOT a BAC-01 candidate.
            if f"{method}:{path}" not in auth_gated:
                seeds.append(_seed("BAC-01", path, "GET",
                    f"Sensitive data exposure on {path}",
                    f"GET {path} returns user/account data; check whether anon or a low-priv actor "
                    f"receives PII of other users.", confidence=0.5))

        if method in ("POST", "PUT", "PATCH") and fam in money_family:
            mfields = money_family[fam]
            is_qty = any(any(k in f.lower() for k in _SEED_QTY_KW) for f in mfields)
            pid = "BLF-06" if is_qty else "BLF-01"
            extra = ""
            if any(k in path.lower() for k in ("cart", "checkout", "order", "purchase")):
                extra = (" Also probe hidden price params not in the form: unit_price, price, "
                         "total — add them to the request body and check if the server accepts them.")
            seeds.append(_seed(pid, path, method,
                f"Value tampering on {path}",
                f"{method} {path} accepts value field(s) {mfields}; submit negative/extreme values "
                f"(e.g. -100 / -1), then re-read state to confirm acceptance.{extra}", confidence=0.5))
        elif method in ("POST", "PUT", "PATCH", "DELETE"):
            # State-changing action with no obvious money/qty field — seed a business-logic
            # candidate regardless of how it was discovered (crawled/js/form all count).
            # Dedup keeps highest confidence, so money seeds (0.5) win over these (0.4).
            pid, title, hyp = _action_seed_spec(method, path)
            seeds.append(_seed(pid, path, method, title, hyp, confidence=0.4))

    # BLF-09: Workflow step bypass — POST directly to checkout/confirm without prior steps.
    # Triggered when: checkout/confirm endpoint exists AND a cart/add endpoint also exists.
    # The server validates the final action but not that prior workflow steps were completed.
    checkout_eps = [ep for ep in endpoints
                    if ep.method in ("POST", "GET")
                    and any(k in ep.endpoint.lower() for k in ("checkout", "confirm", "order/complete",
                                                                "order/confirm", "payment/complete",
                                                                "purchase/confirm"))]
    cart_eps = [ep for ep in endpoints
                if ep.method in ("POST",)
                and any(k in ep.endpoint.lower() for k in ("cart", "basket", "add-to-cart",
                                                            "cart/add", "cart/item"))]
    if checkout_eps and cart_eps:
        for chk_ep in checkout_eps[:1]:  # one candidate is enough
            seeds.append(_seed("BLF-09", chk_ep.endpoint, chk_ep.method,
                f"Workflow step bypass — POST directly to {chk_ep.endpoint}",
                f"The checkout/confirm flow requires prior cart steps, but "
                f"{chk_ep.method} {chk_ep.endpoint} may process the request without "
                f"verifying the prior steps were completed. Try: (1) ensure cart has the "
                f"target item, (2) POST directly to {chk_ep.endpoint} with only CSRF token, "
                f"skipping any intermediate payment/shipping steps. A 200 or redirect to "
                f"order confirmation proves the workflow validation is missing.",
                confidence=0.45))

    # BLF-10: Password-change endpoint with username field but no current-password check.
    # Seed when a POST endpoint is found with 'password' in path AND form fields include
    # 'username' but the forms don't require 'current-password' (field absent = exploitable).
    for ep in endpoints:
        if ep.method != "POST":
            continue
        if "password" not in ep.endpoint.lower() and "change-pass" not in ep.endpoint.lower():
            continue
        form_fields: list[str] = []
        for ex in (getattr(recon, "exchanges", []) or []):
            if ex.endpoint == ep.endpoint:
                for form in (ex.forms or []):
                    form_fields += [f.get("name", "") for f in form.get("fields", [])]
        has_username = any("username" in f.lower() for f in form_fields)
        has_current = any("current" in f.lower() for f in form_fields)
        if has_username and not has_current:
            seeds.append(_seed("BLF-10", ep.endpoint, "POST",
                f"Password change without current-password check on {ep.endpoint}",
                f"POST {ep.endpoint} has a 'username' field but NO 'current-password' "
                f"field — the server may change any account's password without verifying "
                f"the caller knows the existing one. Try: POST with username=administrator "
                f"+ new-password=<anything>, omitting current-password entirely.",
                confidence=0.6))
        elif has_username:
            seeds.append(_seed("BLF-10", ep.endpoint, "POST",
                f"Potential dual-use password-change endpoint {ep.endpoint}",
                f"POST {ep.endpoint} accepts 'username' in the body. Test omitting "
                f"'current-password' — the server may gate the validation on field presence "
                f"rather than enforcing it unconditionally. Set username=administrator.",
                confidence=0.4))

    return seeds


def _action_seed_spec(method: str, path: str) -> tuple[str, str, str]:
    """Map a discovered state-changing action endpoint to a BLF pattern + hypothesis."""
    low = path.lower()
    if any(k in low for k in ("refund", "cancel", "return", "reverse", "chargeback",
                               "void", "rollback", "undo", "revoke")):
        return ("BLF-06", f"Refund/cancel abuse on {path}",
            f"{method} {path} reverses an order/payment. Check whether it credits the caller "
            f"without an ownership check, can be replayed for repeated credit, or re-enables a "
            f"consumed resource (coupon/stock) — refund/cancel abuse.")
    if any(k in low for k in ("coupon", "discount", "promo", "voucher",
                               "gift_card", "giftcard", "reward", "redeem", "offer")):
        return ("BLF-05", f"Coupon/discount abuse on {path}",
            f"{method} {path} applies a coupon/discount. Test re-applying the same code, and "
            f"re-applying after a related action (order cancel/refund) that may reset a 'used' "
            f"flag — stacking or reusing a one-time discount is BLF-05.")
    if any(k in low for k in ("checkout", "cart", "order", "purchase", "pay", "confirm",
                               "buy", "subscribe", "billing", "charge", "settle")):
        return ("BLF-01", f"Price/total trust on {path}",
            f"{method} {path} is a purchase/checkout step. Test submitting client-controlled "
            f"price fields — including hidden params the form may not advertise: unit_price, price, "
            f"total, amount, subtotal, cost. Also try skipping prior steps (e.g. POST /checkout "
            f"without a completed cart); the server may trust client-supplied values or accept "
            f"out-of-order requests.")
    return ("BLF-03", f"Workflow/state manipulation on {path}",
        f"{method} {path} changes state. Probe sequence bypass: invoke it out of the expected "
        f"order or replay it, then re-read state to confirm an invariant was violated.")


class VulnCandidateGenerator:
    def __init__(self, llm: LLMClient, cfg: AppConfig) -> None:
        self._llm = llm
        self._cfg = cfg
        self._playbook = get_provider()

    async def generate(self, recon: ReconArtifact, lessons: str = "") -> list[BugDossier]:
        # Expose session cookie names — the core signal for cookie-tampering BAC
        auth_cookies: list[str] = []
        for p in recon.auth_profiles:
            if p.cookie_header:
                auth_cookies.extend(c.split("=")[0].strip() for c in p.cookie_header.split(";") if "=" in c)
        # Build auth warning to alert hunter when login failed (Issue-006)
        auth_warning = ""
        if getattr(recon, "auth_attempted", False) and not getattr(recon, "auth_succeeded", False):
            auth_warning = (
                getattr(recon, "auth_error", "") or
                "Login was attempted but failed — auth_diffs and session cookies are EMPTY. "
                "The [probed] endpoints exist but access comparison is unavailable. "
                "Assume auth-gated endpoints (302 redirect) are worth testing once credentials are available."
            )

        hunt_signals = self._playbook.hunt_signals_digest()

        prompt = render(
            "hunter_system",
            target_url=recon.target_url,
            endpoints=recon.endpoints,
            auth_diffs=recon.auth_diffs,
            business_flows=recon.business_flows,
            auth_cookies=sorted(set(auth_cookies)),
            auth_warning=auth_warning,
            hunt_signals=hunt_signals,
            page_observations=_build_page_observations(recon),
            auth_sessions_detail=_build_auth_sessions_detail(recon),
        )
        # Long-term memory: prepend lessons from previous runs (hints, not ground truth).
        if lessons:
            prompt = lessons + "\n\n" + prompt
        # Reasoning models spend completion budget on hidden reasoning; give ample room
        # so the JSON array is not truncated mid-object. The hunter is also flaky —
        # it occasionally returns an empty "[]" for data that clearly has candidates,
        # so retry a few times (escalating temperature) before giving up.
        candidates: list[dict] = []
        _insist = (
            "\n\nIMPORTANT: The recon data above DOES contain testable candidates "
            "(probed auth-gated endpoints, plaintext role/user_id cookies, anon-vs-auth "
            "diffs, money/qty flows). Output 2-6 concrete candidates as a JSON array. "
            "Do NOT return an empty array unless there is genuinely no endpoint to test."
        )
        for attempt in range(3):
            content = prompt if attempt == 0 else prompt + _insist
            messages = [{"role": "user", "content": content}]
            temperature = 0.4 if attempt == 0 else 0.7
            raw = await self._llm.chat(messages, role="hunter", temperature=temperature, max_tokens=16000)
            candidates = self._parse_candidates(raw)
            if candidates:
                if attempt:
                    log.info(f"Hunter produced {len(candidates)} candidates on retry #{attempt}")
                break
            log.warning(f"Hunter returned 0 candidates (attempt {attempt + 1}/3) — retrying")

        # Deterministic seeding: add candidates derived from observed routes so high-value
        # endpoints are covered even when the LLM hunter misses them.
        # Ablation flag hunt.seeder_enabled=false disables this for controlled comparison.
        seeder_on = getattr(self._cfg.hunt, "seeder_enabled", True)
        seeds = _seed_from_recon(recon) if seeder_on else []
        if seeds:
            log.info(f"Deterministic seeding added {len(seeds)} candidate(s) from recon routes")
        elif not seeder_on:
            log.info("Deterministic seeding DISABLED (hunt.seeder_enabled=false) — ablation mode")
        candidates = candidates + seeds

        # Fix mislabeled patterns + collapse duplicate endpoints before assigning IDs.
        candidates = self._dedupe_and_reclassify(candidates)

        dossiers: list[BugDossier] = []
        counter = 1

        for c in candidates:
            try:
                d = self._build_dossier(c, recon, counter)
                dossiers.append(d)
                counter += 1
            except Exception as e:
                log.warning(f"Failed to build dossier for candidate: {e}")

        log.info(f"Generated {len(dossiers)} bug dossiers")
        return dossiers

    def _parse_candidates(self, raw: str) -> list[dict]:
        # Strip think/reasoning blocks emitted by chain-of-thought models before the JSON
        raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
        # Strip markdown code fences (```json ... ```)
        raw = re.sub(r"^```[a-zA-Z]*\n?", "", raw).rstrip("`").strip()

        # Try a clean array parse first
        match = re.search(r"\[.*\]", raw, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group(0))
                cands = [c for c in data if isinstance(c, dict)]
                if cands:
                    return cands
            except json.JSONDecodeError:
                pass

        # Tolerant salvage: scan for complete {...} objects via raw_decode.
        # Survives a truncated trailing object (reasoning models hitting token cap).
        decoder = json.JSONDecoder()
        out: list[dict] = []
        pos = 0
        while pos < len(raw):
            idx = raw.find("{", pos)
            if idx == -1:
                break
            try:
                obj, end = decoder.raw_decode(raw, idx)
                if isinstance(obj, dict) and obj.get("pattern_id"):
                    out.append(obj)
                pos = end
            except json.JSONDecodeError:
                pos = idx + 1
        if not out:
            log.warning("Hunter LLM output had no parseable candidates")
        else:
            log.info(f"Salvaged {len(out)} candidates from partial JSON")
        return out

    def _dedupe_and_reclassify(self, candidates: list[dict]) -> list[dict]:
        """Fix mislabeled patterns, then merge candidates on the same endpoint family.

        - Reclassify: a 'full list / no per-object id' endpoint wrongly tagged BAC-03
          (IDOR) is really BAC-01 (missing auth gate / data exposure).
        - Dedup: collapse candidates with the same (method, family_path) — e.g. two
          BUGs both targeting /admin — keeping the highest-confidence one. Prevents the
          same endpoint being reported twice under different pattern labels.
        """
        for c in candidates:
            c["pattern_id"] = _reclassify_pattern(c)

        best: dict[tuple, dict] = {}
        for c in candidates:
            key = (str(c.get("method", "GET")).upper(), _family_path(c.get("endpoint", "")))
            cur = best.get(key)
            if cur is None or float(c.get("confidence", 0.5)) > float(cur.get("confidence", 0.5)):
                best[key] = c
        deduped = list(best.values())
        if len(deduped) < len(candidates):
            log.info(f"Hunt dedup: {len(candidates)} → {len(deduped)} candidates (merged same-endpoint family)")
        return deduped

    def _build_dossier(self, c: dict, recon: ReconArtifact, idx: int) -> BugDossier:
        pattern_id = c.get("pattern_id", "BAC-03")
        category = BugCategory.BAC if pattern_id.startswith("BAC") else BugCategory.BLF
        risk_str = c.get("risk", "medium").lower()
        risk = _SEVERITY_MAP.get(risk_str, Severity.MEDIUM)

        # Get evidence rules from knowledge card
        try:
            card = self._playbook.card_for(pattern_id)
            evidence_rules = [
                EvidenceRule(key=mk, required=True, description=f"Required for {pattern_id}")
                for mk in card.get("required_proof_markers", [])
            ]
            risk_str_card = card.get("severity", risk_str).lower()
            risk = _SEVERITY_MAP.get(risk_str_card, risk)
        except Exception:
            evidence_rules = []

        # Attach real HTTP examples from recon (not truncated)
        endpoint = c.get("endpoint", "")
        method = c.get("method", "GET")
        supporting_ids = c.get("supporting_exchange_ids", [])
        fam = _family_path(endpoint)
        examples: list[HttpExample] = []
        seen_ids: set[str] = set()

        def _add_ex(ex, note: str) -> None:
            if len(examples) >= 3 or ex.exchange_id in seen_ids:
                return
            seen_ids.add(ex.exchange_id)
            examples.append(HttpExample(exchange=ex, annotation=note))

        # 1. Explicit support ids + exact endpoint+method capture.
        for ex in recon.exchanges:
            if ex.exchange_id in supporting_ids or (endpoint and ex.endpoint == endpoint and ex.method == method):
                _add_ex(ex, f"Recon capture: {ex.status}")

        # 2. Same endpoint-family captures that REVEAL field names (forms) or JSON keys —
        #    so Red sees the real fields (e.g. a POST whose own capture is a 302 redirect
        #    still gets the GET form showing 'amount'/'to_username'). Fixes seeded BLF/BAC
        #    dossiers being skipped as INSUFFICIENT_EVIDENCE.
        for ex in recon.exchanges:
            if _family_path(ex.endpoint) != fam:
                continue
            if not (ex.forms or ex.json_keys):
                continue
            fields: list[str] = []
            for form in ex.forms:
                fields += [fl.get("name", "") for fl in form.get("fields", []) if fl.get("name")]
            note = f"Field evidence: {ex.method} {ex.endpoint} → {ex.status}"
            if fields:
                note += f" — form fields: {fields}"
            elif ex.json_keys:
                note += f" — json keys: {ex.json_keys[:12]}"
            _add_ex(ex, note)

        # 3. Cross-family form-referencing exchanges: pages on a DIFFERENT endpoint that have
        #    a <form action=TARGET> posting to our target endpoint family.
        #    e.g. GET /product has <form action=/cart method=POST> with fields [productId, quantity, price].
        #    The BLF dossier for POST /cart needs those fields visible to Red — without this,
        #    Red declares INSUFFICIENT_EVIDENCE because it only sees POST /cart → 302 with no body.
        from urllib.parse import urlparse as _urlparse
        for ex in recon.exchanges:
            if _family_path(ex.endpoint) == fam:
                continue  # already covered by step 2
            if not ex.forms:
                continue
            for form in ex.forms:
                action = form.get("action") or ""
                action_fam = _family_path(_urlparse(action).path or action)
                if action_fam != fam:
                    continue
                fields_x: list[str] = [fl.get("name", "") for fl in form.get("fields", []) if fl.get("name")]
                note = (
                    f"Form reference: {ex.method} {ex.endpoint} → {ex.status} "
                    f"(has form POST {action} with fields: {fields_x})"
                )
                _add_ex(ex, note)
                break

        # Auth requirement
        auth_profiles = recon.auth_profiles
        attacker_label = auth_profiles[0].label if auth_profiles else "anon"
        victim_label = auth_profiles[1].label if len(auth_profiles) > 1 else None
        auth_req = AuthRequirement(
            attacker_role=attacker_label,
            victim_role=victim_label,
        )

        return BugDossier(
            id=f"BUG-{idx:03d}",
            category=category,
            pattern_id=pattern_id,
            title=c.get("title", f"{pattern_id} on {endpoint}"),
            risk=risk,
            endpoint=endpoint,
            method=method,
            hypothesis=c.get("hypothesis", ""),
            exploit_approach=c.get("exploit_approach", ""),
            auth=auth_req,
            http_examples=examples,
            evidence_rules=evidence_rules,
            confidence=float(c.get("confidence", 0.5)),
            notes=c.get("notes", ""),
        )
