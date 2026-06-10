"""VulnCandidateGenerator — produces structured BugDossier list from ReconArtifact.

Uses LLM (hunter role) to analyse recon data and suggest vulnerability candidates,
then enriches each candidate with real HTTP examples and evidence rules.
"""
from __future__ import annotations

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
    return pid


_SEED_MONEY_KW = ("amount", "price", "total", "cost", "balance", "credit", "point", "qty", "quantity")
_SEED_QTY_KW = ("qty", "quantity", "count", "stock")
_ADMIN_PATH_KW = ("/admin", "/administrator", "/manage", "/console", "/staff",
                  "/internal", "/backend", "/superuser")


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

    # cookie-tamper (BAC-02) signal: plaintext role/uid cookies after login
    cookie_names: set[str] = set()
    for p in getattr(recon, "auth_profiles", []) or []:
        if getattr(p, "cookie_header", None):
            cookie_names |= {c.split("=")[0].strip().lower()
                             for c in p.cookie_header.split(";") if "=" in c}
    tamperable = bool(cookie_names & {"role", "is_admin", "admin", "user_id", "userid", "account", "uid"})

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
        has_pathid = "{id}" in path or "{uuid}" in path

        if method == "GET" and is_admin:
            seeds.append(_seed("BAC-06", path, "GET",
                f"Forced browsing to admin area {path}",
                f"GET {path} is an admin/privileged area{' ([probed], not linked)' if probed else ''}; "
                f"test access as low-priv and with a tampered role cookie."))
            if tamperable:
                seeds.append(_seed("BAC-02", path, "GET",
                    f"Privilege escalation via cookie on {path}",
                    f"Plaintext cookies {sorted(cookie_names)} present. FIRST request {path} as normal "
                    f"user (expect 302/403 block), THEN tamper role=admin (expect 200) — capture both in order.",
                    confidence=0.5))
        elif method == "GET" and probed and not is_admin:
            seeds.append(_seed("BAC-06", path, "GET",
                f"Forced browsing to {path}",
                f"GET {path} is auth-gated/probed; verify it exists and whether a low-priv session reaches it."))

        if method == "GET" and has_pathid and getattr(ep, "auth_required", False):
            seeds.append(_seed("BAC-03", path, "GET",
                f"IDOR on {path}",
                f"GET {path} has a per-object id. Log in as user A, then request user B's id (cross-user) "
                f"and compare the returned identity — different owner = IDOR."))

        if method == "GET" and any(k in low for k in ("user", "account", "profile", "order")):
            seeds.append(_seed("BAC-01", path, "GET",
                f"Sensitive data exposure on {path}",
                f"GET {path} returns user/account data; check whether anon or a low-priv actor receives "
                f"PII of other users.", confidence=0.5))

        if method in ("POST", "PUT", "PATCH") and fam in money_family:
            mfields = money_family[fam]
            is_qty = any(any(k in f.lower() for k in _SEED_QTY_KW) for f in mfields)
            pid = "BLF-06" if is_qty else "BLF-01"
            seeds.append(_seed(pid, path, method,
                f"Value tampering on {path}",
                f"{method} {path} accepts value field(s) {mfields}; submit negative/extreme values "
                f"(e.g. -100 / -1), then re-read state to confirm acceptance.", confidence=0.5))
        elif method in ("POST", "PUT", "PATCH", "DELETE") and getattr(ep, "discovery", "") in ("js", "form"):
            # State-changing action discovered in the app surface but with no obvious
            # money/qty field (e.g. /checkout, /coupon/apply, /orders/{id}/cancel). Seed a
            # business-logic candidate keyed to the right BLF pattern so it is attempted —
            # and can serve as a step the hunter stitches into a multi-request chain —
            # instead of being silently dropped for lacking a value field.
            pid, title, hyp = _action_seed_spec(method, path)
            seeds.append(_seed(pid, path, method, title, hyp, confidence=0.4))

    return seeds


def _action_seed_spec(method: str, path: str) -> tuple[str, str, str]:
    """Map a discovered state-changing action endpoint to a BLF pattern + hypothesis."""
    low = path.lower()
    if any(k in low for k in ("refund", "cancel", "return", "reverse", "chargeback")):
        return ("BLF-06", f"Refund/cancel abuse on {path}",
            f"{method} {path} reverses an order/payment. Check whether it credits the caller "
            f"without an ownership check, can be replayed for repeated credit, or re-enables a "
            f"consumed resource (coupon/stock) — refund/cancel abuse.")
    if any(k in low for k in ("coupon", "discount", "promo", "voucher")):
        return ("BLF-05", f"Coupon/discount abuse on {path}",
            f"{method} {path} applies a coupon/discount. Test re-applying the same code, and "
            f"re-applying after a related action (order cancel/refund) that may reset a 'used' "
            f"flag — stacking or reusing a one-time discount is BLF-05.")
    if any(k in low for k in ("checkout", "cart", "order", "purchase", "pay", "confirm")):
        return ("BLF-01", f"Price/total trust on {path}",
            f"{method} {path} is a purchase/checkout step. Test submitting client-controlled "
            f"price/total/unit_price fields, and skipping prior steps; the server may trust the "
            f"client value or accept an out-of-order request.")
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

        prompt = render(
            "hunter_system",
            target_url=recon.target_url,
            endpoints=recon.endpoints,
            auth_diffs=recon.auth_diffs,
            business_flows=recon.business_flows,
            auth_cookies=sorted(set(auth_cookies)),
            auth_warning=auth_warning,
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

        # Deterministic seeding: ALWAYS add candidates derived from observed routes,
        # so high-value endpoints (money POST, auth-gated admin, IDOR path-ids, PII
        # APIs) are covered even when the LLM hunter forgets them. Merged then deduped.
        seeds = _seed_from_recon(recon)
        if seeds:
            log.info(f"Deterministic seeding added {len(seeds)} candidate(s) from recon routes")
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
