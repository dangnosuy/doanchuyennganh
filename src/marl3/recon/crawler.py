"""HTTP-native crawler — httpx + HTML parsing, no browser.

Targets server-rendered HTTP sites (links, forms, cookie sessions).
No SPA/JS assumptions: discovers surface by parsing <a href> and <form>,
submits the login form over plain HTTP, and keeps the full cookie jar.

Produces a single ReconArtifact → recon.json.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urljoin, urldefrag, urlparse

import httpx
from bs4 import BeautifulSoup

from ..config import AppConfig
from ..contracts.body import BodyRef
from ..contracts.http import HttpExchange
from ..contracts.recon import (
    AuthDiff, AuthProfile, BusinessFlow, Endpoint,
    ReconArtifact, WorkflowEdge, WorkflowGraph, WorkflowNode,
)
from ..workspace import RunWorkspace
from .auth import AuthSessionStore
from .body_store import BodyStore

log = logging.getLogger("marl3.crawler")

# Common login form paths to probe, in priority order (HTTP-native, no SPA hashes).
_LOGIN_PATHS = ["/login", "/signin", "/sign-in", "/auth/login",
                "/account/login", "/user/login", "/users/login", "/admin/login"]
_USERNAME_NAMES = {"username", "user", "email", "login", "name", "userid", "user_name", "uname"}

# Paths to probe after passive crawl (soft-404 filtered).
# Ordered by BAC/BLF relevance: admin areas → user resources → commerce → auth-gated.
_PROBE_PATHS = [
    # Admin / privileged areas (BAC-01)
    "/admin", "/admin/", "/admin/dashboard", "/administrator", "/manage",
    "/management", "/staff", "/superadmin", "/backend", "/cp", "/panel",
    # User account pages (BAC-02/03 candidates)
    "/dashboard", "/profile", "/account", "/settings", "/my-account",
    "/user/profile", "/account/settings", "/me",
    # Commerce / BLF flows
    "/cart", "/checkout", "/order", "/orders", "/basket",
    "/payment", "/pay", "/invoice", "/invoices",
    # API endpoints often missed by HTML crawl
    "/api", "/api/v1", "/api/v1/users", "/api/user",
    # REST resource collections (common API patterns)
    "/api/v1/products", "/api/v1/me", "/api/v1/profile",
    "/api/v1/orders", "/api/v1/items", "/api/v1/accounts",
    # IDOR resource instances — probe ID 1 and 2 (real IDs start here on fresh DBs)
    "/api/v1/orders/1", "/api/v1/orders/2",
    "/api/v1/profile/1", "/api/v1/profile/2",
    "/api/v1/users/1", "/api/v1/users/1/promote",
    # Auth-related (NEVER probe logout — it clears the active session)
    "/register", "/signup",
]


class GuidedCrawler:
    def __init__(self, cfg: AppConfig, workspace: RunWorkspace) -> None:
        self._cfg = cfg
        self._ws = workspace
        self._body_store = BodyStore(workspace.bodies_dir)
        self._auth_store = AuthSessionStore(workspace.sessions_json)
        self._seq = 0

    @staticmethod
    def _norm_cred(c: dict) -> dict:
        """Normalize a credential dict to {user, pass, role, label}."""
        return {
            "user": c.get("user") or c.get("username", ""),
            "pass": c.get("pass") or c.get("password", ""),
            "role": c.get("role", "user"),
            "label": c.get("label", ""),
        }

    async def crawl(self, target_url: str, credentials) -> ReconArtifact:
        # Accept a single credential dict OR a list of them (multi-account for
        # cross-user IDOR). Normalize keys: "username"/"password" or "user"/"pass".
        if isinstance(credentials, dict):
            credentials = [credentials]
        creds = [self._norm_cred(c) for c in (credentials or []) if c]
        creds = [c for c in creds if c["user"] and c["pass"]]

        base = _base_url(target_url)
        log.info(f"Starting crawl: {target_url} ({len(creds)} credential(s))")
        timeout = httpx.Timeout(self._cfg.recon.http_timeout_s if hasattr(self._cfg.recon, "http_timeout_s") else 15.0)
        ua = {"User-Agent": "marl3-pentest/0.2"}

        # 1. Anonymous crawl (passive: links + GET forms)
        async with httpx.AsyncClient(follow_redirects=False, timeout=timeout, headers=ua) as anon:
            anon_exchanges = await self._crawl_session(anon, target_url, base, "anon", "anon")
            # 1b. Endpoint probing with soft-404 baseline (discovers admin/dashboard/cart etc.)
            known = {e.endpoint for e in anon_exchanges}
            probed = await self._probe_endpoints(anon, base, "anon", known)
            anon_exchanges.extend(probed)
            # 1c. Submit POST forms with synthetic values (discovers cart/checkout/order flows)
            form_ex = await self._submit_forms(anon, base, anon_exchanges, "anon")
            anon_exchanges.extend(form_ex)
            # 1d. Safe-probe JS-discovered action endpoints to capture real request examples
            anon_exchanges.extend(await self._safe_probe_js(anon, base, anon_exchanges, "anon"))

        # 2. Authenticated crawl — one isolated session per credential. Crawling
        #    multiple accounts gives exec distinct attacker/victim sessions for
        #    cross-user IDOR (BAC-03).
        auth_exchanges: list[HttpExchange] = []
        auth_attempted = bool(creds)
        auth_succeeded = False
        auth_errors: list[str] = []
        for cred in creds:
            async with httpx.AsyncClient(follow_redirects=False, timeout=timeout, headers=ua) as auth:
                profile = await self._login(auth, target_url, base, cred)
                if profile:
                    auth_succeeded = True
                    self._auth_store.add(profile)
                    ex = await self._crawl_session(auth, target_url, base, profile.label, profile.role)
                    known_auth = {e.endpoint for e in ex}
                    ex.extend(await self._probe_endpoints(auth, base, profile.label, known_auth))
                    ex.extend(await self._submit_forms(auth, base, ex, profile.label))
                    # Capture real request examples for JS-discovered action endpoints while
                    # we still hold this authenticated session (they are auth-gated).
                    ex.extend(await self._safe_probe_js(auth, base, ex, profile.label))
                    auth_exchanges.extend(ex)
                    log.info(f"Authenticated crawl done for {profile.label!r}: {len(ex)} exchanges")
                else:
                    msg = f"Login failed for user={cred.get('user')!r}"
                    auth_errors.append(msg)
                    log.warning(f"AUTH FAILURE: {msg}")
        # auth_error is only meaningful when NO credential logged in (Issue-006).
        auth_error = "" if auth_succeeded else (
            "; ".join(auth_errors) + " — auth_diffs and IDOR candidates will be EMPTY."
            if auth_errors else ""
        )

        all_exchanges = anon_exchanges + auth_exchanges
        endpoints = _extract_endpoints(all_exchanges)
        # Recover JS-driven endpoints (fetch/axios/XHR in inline <script>) that the
        # HTML-only parser misses. Modern server-rendered apps fire actions via JSON
        # calls, not <form> POSTs, so /cart/add, /wallet/transfer, /checkout etc. are
        # invisible to <a>/<form> parsing alone. Not SPA support — just reading the
        # static JS source that already arrived in the HTML.
        endpoints = self._merge_js_endpoints(endpoints, all_exchanges, base)
        auth_diffs = _compute_auth_diffs(anon_exchanges, auth_exchanges) if auth_exchanges else []
        graph = _build_workflow_graph(all_exchanges)
        flows = _detect_business_flows(endpoints, all_exchanges)

        artifact = ReconArtifact(
            target_url=target_url,
            crawl_timestamp=datetime.now(timezone.utc).isoformat(),
            endpoints=endpoints,
            exchanges=all_exchanges,
            auth_profiles=self._auth_store.all_profiles(),
            auth_diffs=auth_diffs,
            workflow_graph=graph,
            business_flows=flows,
            api_hints=_detect_api_hints(all_exchanges),
            bodies_dir=str(self._ws.bodies_dir.relative_to(self._ws.root)),
            auth_attempted=auth_attempted,
            auth_succeeded=auth_succeeded,
            auth_error=auth_error,
        )
        self._ws.recon_json.write_text(artifact.model_dump_json(indent=2))
        self._ws.recon_md.write_text(_render_recon_md(artifact))

        log.info(
            f"Crawl complete: {len(endpoints)} endpoints, "
            f"{len(all_exchanges)} exchanges, {len(auth_diffs)} auth diffs"
        )
        return artifact

    # ── Crawl loop ───────────────────────────────────────────────────────────

    async def _crawl_session(
        self, client: httpx.AsyncClient, start_url: str, base: str, actor: str, role: str
    ) -> list[HttpExchange]:
        exchanges: list[HttpExchange] = []
        visited: set[str] = set()
        queue: list[str] = [start_url]
        max_pages = self._cfg.recon.max_pages

        while queue and len(visited) < max_pages:
            url = queue.pop(0)
            url = urldefrag(url)[0]  # drop #fragment (server ignores it)
            if url in visited:
                continue
            visited.add(url)

            # NEVER GET a logout link: it clears the server session + deletes auth cookies,
            # turning every subsequent request in this session anonymous (401/302). This
            # silently de-authenticated probing, form-submit and JS safe-probe steps.
            if _is_logout(url):
                log.debug(f"Skipping logout URL to preserve session: {url}")
                continue

            try:
                resp = await client.get(url)
            except Exception as e:
                log.debug(f"GET {url} failed: {e}")
                continue

            exc = self._make_exchange(resp, actor)
            exchanges.append(exc)

            # Follow same-origin redirects (record the 3xx, then enqueue Location)
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("location", "")
                if loc:
                    nxt = urljoin(url, loc)
                    if nxt.startswith(base) and urldefrag(nxt)[0] not in visited:
                        queue.append(nxt)
                continue

            ctype = resp.headers.get("content-type", "")
            if "html" not in ctype:
                continue

            # Discover links + forms from HTML
            for link in _extract_links(resp.text, url):
                if link.startswith(base) and urldefrag(link)[0] not in visited:
                    queue.append(link)

            # GET-form actions become crawlable URLs too
            for form in exc.forms:
                if form.get("method", "get").lower() == "get" and form.get("action"):
                    action = urljoin(url, form["action"])
                    if action.startswith(base) and urldefrag(action)[0] not in visited:
                        queue.append(action)

        return exchanges

    # ── Endpoint probing (soft-404 filtered) ─────────────────────────────────

    async def _probe_endpoints(
        self,
        client: httpx.AsyncClient,
        base: str,
        actor: str,
        already_known: set[str],
    ) -> list[HttpExchange]:
        """Probe _PROBE_PATHS that were not found by passive crawl.

        Uses soft-404 baseline: probe a guaranteed-bogus path first, then
        exclude responses that closely match the baseline (same content-length
        ± 100 bytes, or same HTML title).
        """
        # 1. Establish soft-404 baseline
        bogus_path = f"/marl2-probe-baseline-{abs(hash(base)) % 99991:05d}"
        baseline_len = -1
        baseline_title = ""
        try:
            r = await client.get(base + bogus_path)
            baseline_len = len(r.content)
            if "html" in r.headers.get("content-type", ""):
                baseline_title, _ = _extract_html_signals(r.content, base + bogus_path)
        except Exception:
            pass

        probed: list[HttpExchange] = []
        for path in _PROBE_PATHS:
            if _is_logout(base + path):  # never probe logout — it clears the session
                continue
            endpoint = _url_to_endpoint(base + path)
            if endpoint in already_known:
                continue
            url = base + path
            try:
                resp = await client.get(url)
            except Exception:
                continue
            status = resp.status_code
            # A 3xx redirect (e.g. → /login) is NOT a soft-404: it means the endpoint
            # EXISTS and is auth-gated — a first-class BAC signal. Werkzeug's tiny redirect
            # body (~199B) otherwise falls inside the soft-404 length window of the 404 page
            # (~207B) and would be wrongly discarded. So record 3xx directly and skip the
            # length/title heuristics, which only make sense for 2xx bodies.
            is_redirect = status in (301, 302, 303, 307, 308)
            if not is_redirect:
                # Skip clear 4xx/5xx responses
                if status >= 400:
                    continue
                # Soft-404 filter: same content-length as baseline → likely 404 page.
                # Exempt JSON responses: a small JSON object (e.g. {"email":"...","id":1})
                # is NOT a soft-404 just because its byte count is close to the 404 HTML
                # page — the content-types differ fundamentally, so size comparison is meaningless.
                ctype = resp.headers.get("content-type", "")
                response_is_json = "json" in ctype
                body_len = len(resp.content)
                if not response_is_json and baseline_len > 0 and abs(body_len - baseline_len) <= 100:
                    continue
                # Soft-404 filter: same HTML title as baseline
                if "html" in ctype and baseline_title:
                    title, _ = _extract_html_signals(resp.content, url)
                    if title and title == baseline_title:
                        continue
            exc = self._make_exchange(resp, actor)
            # Mark as probed so downstream can distinguish from crawled
            exc_endpoint = _url_to_endpoint(url)
            already_known.add(exc_endpoint)
            exc.label = "probed"  # mark for _extract_endpoints
            probed.append(exc)
            loc = resp.headers.get("location", "") if is_redirect else ""
            log.info(f"Probe found: {status} {path}{f' → {loc}' if loc else ''} (actor={actor})")

        return probed

    # ── JS endpoint recovery (fetch/axios/XHR in inline scripts) ──────────────

    def _merge_js_endpoints(
        self, endpoints: list[Endpoint], exchanges: list[HttpExchange], base: str
    ) -> list[Endpoint]:
        """Scan HTML/JS response bodies for fetch()/axios/XHR calls and register the
        (method, path, fields) they reveal as endpoints, without overwriting real
        crawled/probed ones."""
        agg: dict[tuple[str, str], set[str]] = {}
        anon_only: dict[tuple[str, str], bool] = {}
        for ex in exchanges:
            ct = ex.response_headers.get("content-type", "")
            if "html" not in ct and "javascript" not in ct:
                continue
            if not ex.response_body_ref:
                continue
            try:
                text = self._body_store.get(ex.response_body_ref.blob_id).decode("utf-8", "replace")
            except Exception:
                continue
            for (method, path), fields in _extract_js_endpoints(text).items():
                endpoint = _url_to_endpoint(base + path)
                key = (method, endpoint)
                agg.setdefault(key, set()).update(fields)
                # Track whether this was only ever seen on an anonymous page
                seen_anon = ex.actor == "anon"
                anon_only[key] = anon_only.get(key, True) and seen_anon

        existing = {f"{e.method}:{e.endpoint}" for e in endpoints}
        added = 0
        for (method, endpoint), fields in sorted(agg.items()):
            tag = f"{method}:{endpoint}"
            if tag in existing:
                # enrich params on an already-known endpoint
                for e in endpoints:
                    if e.method == method and e.endpoint == endpoint:
                        for f in sorted(fields):
                            if f not in e.parameters:
                                e.parameters.append(f)
                continue
            endpoints.append(Endpoint(
                url=base + endpoint,
                method=method,
                endpoint=endpoint,
                # JS actions live behind the authenticated UI unless seen on an anon page
                auth_required=not anon_only.get((method, endpoint), False),
                content_type="",
                parameters=sorted(fields),
                discovery="js",
            ))
            existing.add(tag)
            added += 1
            log.info(f"JS endpoint: {method} {endpoint} fields={sorted(fields)}")
        if added:
            log.info(f"Recovered {added} JS-driven endpoint(s) from inline scripts")
        return endpoints

    # ── Safe probe of JS-discovered action endpoints ─────────────────────────

    async def _safe_probe_js(
        self, client: httpx.AsyncClient, base: str,
        source_exchanges: list[HttpExchange], actor: str,
    ) -> list[HttpExchange]:
        """Issue ONE safe, minimal request per JS-discovered NON-GET action endpoint so a
        real request/response example is captured for it.

        JS endpoints are only *parsed* from inline scripts — never actually called during the
        passive crawl — so their dossier has zero http_examples. Red then declares
        INSUFFICIENT_EVIDENCE (grounding check) and Exec has no template to copy, so it guesses
        the wrong body format (form vs JSON) and wrong paths. A minimal probe fixes both:

        - Body is an empty JSON object: apps validate required fields BEFORE mutating, so the
          response is a harmless 400/404 ("amount is required", "Product not found") that still
          reveals the real method, JSON content-type and validation shape.
        - {id}/{uuid} path segments use a non-existent id so nothing real is touched.
        """
        agg: dict[tuple[str, str], set[str]] = {}
        for ex in source_exchanges:
            ct = ex.response_headers.get("content-type", "")
            if "html" not in ct and "javascript" not in ct:
                continue
            if not ex.response_body_ref:
                continue
            try:
                text = self._body_store.get(ex.response_body_ref.blob_id).decode("utf-8", "replace")
            except Exception:
                continue
            for (method, path), fields in _extract_js_endpoints(text).items():
                agg.setdefault((method, path), set()).update(fields)

        probed: list[HttpExchange] = []
        seen: set[tuple[str, str]] = set()
        for (method, path), fields in sorted(agg.items()):
            if method == "GET":
                continue  # GET surface is already covered by crawl/_probe_endpoints
            endpoint = _url_to_endpoint(base + path)
            if (method, endpoint) in seen:
                continue
            seen.add((method, endpoint))
            # concrete URL: digits replace {id}/{uuid} so _url_to_endpoint folds it back
            concrete = path.replace("{id}", "999999").replace(
                "{uuid}", "00000000-0000-0000-0000-000000000000")
            try:
                resp = await client.request(method, base + concrete, json={})
            except Exception as e:
                log.debug(f"JS safe-probe {method} {base + concrete} failed: {e}")
                continue
            exc = self._make_exchange(resp, actor)
            exc.label = "js-probe"
            probed.append(exc)
            log.info(f"JS safe-probe: {method} {endpoint} → {resp.status_code} "
                     f"(fields: {sorted(fields) or '∅'})")
        return probed

    # ── POST form submission (discovers state-dependent flows) ────────────────

    async def _submit_forms(
        self,
        client: httpx.AsyncClient,
        base: str,
        exchanges: list[HttpExchange],
        actor: str,
    ) -> list[HttpExchange]:
        """Submit POST forms with synthetic values to discover cart/checkout/order flows.

        Only submits forms that contain commerce-related fields (quantity, add_to_cart,
        product_id, etc.). Avoids re-submitting login forms or destructive operations.
        """
        submitted: list[HttpExchange] = []
        submitted_actions: set[str] = set()

        _SKIP_FIELDS = {"password", "passwd", "pass", "token", "csrf", "_token", "authenticity_token"}
        _COMMERCE_HINTS = {"qty", "quantity", "product", "item", "add", "cart", "amount", "price", "count"}

        for ex in exchanges:
            if not ex.forms:
                continue
            for form in ex.forms:
                method = form.get("method", "get").lower()
                if method != "post":
                    continue
                action = form.get("action", "")
                if not action:
                    action = ex.url
                action_url = urljoin(ex.url, action)
                if not action_url.startswith(base):
                    continue
                if action_url in submitted_actions:
                    continue

                fields = form.get("fields", [])
                field_names = {f["name"].lower() for f in fields if f.get("name")}

                # Skip if this looks like a login/register form
                if field_names & {"password", "passwd", "pass"}:
                    continue
                # Only submit if there's a commerce-related field hint
                if not (field_names & _COMMERCE_HINTS):
                    continue

                # Build synthetic payload
                payload: dict[str, str] = {}
                for field in fields:
                    name = field.get("name", "")
                    if not name:
                        continue
                    if name.lower() in _SKIP_FIELDS:
                        continue
                    ftype = (field.get("type") or "text").lower()
                    if ftype == "hidden":
                        payload[name] = field.get("value", "1")
                    elif any(h in name.lower() for h in ("qty", "quantity", "count", "amount")):
                        payload[name] = "1"
                    elif any(h in name.lower() for h in ("price", "total")):
                        payload[name] = "10.00"
                    elif any(h in name.lower() for h in ("product", "item", "id")):
                        payload[name] = "1"
                    else:
                        payload[name] = "test"

                submitted_actions.add(action_url)
                try:
                    resp = await client.post(action_url, data=payload)
                    exc = self._make_exchange(resp, actor)
                    submitted.append(exc)
                    log.info(f"Form POST: {resp.status_code} {action_url} fields={list(payload.keys())}")
                except Exception as e:
                    log.debug(f"Form POST {action_url} failed: {e}")

        return submitted

    # ── Login (HTTP-native form POST) ──────────────────────────────────────────

    async def _login(
        self, client: httpx.AsyncClient, target_url: str, base: str, credentials: dict[str, str]
    ) -> Optional[AuthProfile]:
        username = credentials.get("user", "")
        password = credentials.get("pass", "")
        role = credentials.get("role", "user")
        label = re.sub(r"[^a-z0-9_]", "_", username.lower())[:32] or "user_a"

        # Find a login page that contains a password form
        login_form = None
        login_url = None
        candidates = [urljoin(base + "/", p.lstrip("/")) for p in _LOGIN_PATHS]
        candidates.insert(0, target_url)  # the target itself might be the login page
        for url in candidates:
            try:
                resp = await client.get(url)
            except Exception:
                continue
            if resp.status_code >= 400 or "html" not in resp.headers.get("content-type", ""):
                continue
            form = _find_password_form(resp.text, url)
            if form:
                login_form, login_url = form, str(resp.url)
                log.info(f"Login form found: {login_url}")
                break

        if not login_form:
            log.warning("Login: no password form found on any candidate path")
            return None

        # Build POST payload: map credentials onto the form's field names + replay hidden fields
        payload = dict(login_form["hidden"])  # CSRF tokens etc.
        pass_field = login_form["password_field"]
        user_field = login_form["username_field"]
        if not user_field or not pass_field:
            log.warning("Login: could not identify username/password fields")
            return None
        payload[user_field] = username
        payload[pass_field] = password

        action = urljoin(login_url, login_form["action"]) if login_form["action"] else login_url
        method = login_form["method"].upper()
        try:
            if method == "GET":
                resp = await client.get(action, params=payload)
            else:
                resp = await client.post(action, data=payload)
        except Exception as e:
            log.warning(f"Login POST failed: {e}")
            return None

        # Reject obvious failure first: an error message in the response body means the
        # credentials were wrong even if the server still set a (guest) cookie.
        body_l = resp.text.lower() if "html" in resp.headers.get("content-type", "") else ""
        _ERR = ("incorrect", "invalid", "wrong password", "login failed", "sai mật khẩu",
                "không đúng", "tài khoản hoặc mật khẩu", "try again", "thất bại", "unauthorized")
        if body_l and any(k in body_l for k in _ERR):
            log.warning(f"Login rejected: error message in response for {username!r}")
            return None

        cookies = dict(client.cookies)
        redirected = resp.status_code in (301, 302, 303, 307, 308)
        form_gone = "html" in resp.headers.get("content-type", "") and not _find_password_form(resp.text, action)

        # Active verification: fetch a protected page with the session and confirm we are
        # really authenticated (an auth marker, not bounced back to the login form). This
        # prevents false positives where a site sets a session cookie for anonymous guests.
        verified = False
        for vp in ("/profile", "/account", "/dashboard", "/my-account", "/orders", "/me"):
            try:
                vr = await client.get(base + vp)
            except Exception:
                continue
            ctype = vr.headers.get("content-type", "")
            if vr.status_code == 200 and "html" in ctype:
                vt = vr.text.lower()
                if any(m in vt for m in ("logout", "sign out", "đăng xuất", "my account", "tài khoản")) \
                   and not _find_password_form(vr.text, base + vp):
                    verified = True
                    break
            elif vr.status_code in (301, 302, 303) and "login" not in vr.headers.get("location", "").lower():
                # redirect to a non-login page (e.g. /profile → /profile/5) implies a session
                verified = True
                break

        ok = verified or (bool(cookies) and (redirected or form_gone))
        if not ok:
            log.warning(f"Login appears failed (status={resp.status_code}, verified={verified}, cookies={bool(cookies)})")
            return None

        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        log.info(f"Login succeeded: label={label} role={role} cookies=[{', '.join(cookies)}]")
        return AuthProfile(
            label=label,
            role=role,
            bearer_token=None,
            cookie_header=cookie_str or None,
        )

    # ── Exchange building ──────────────────────────────────────────────────────

    def _make_exchange(self, resp: httpx.Response, actor: str) -> HttpExchange:
        self._seq += 1
        body = resp.content or b""
        ctype = resp.headers.get("content-type", "")
        url = str(resp.url)

        req = resp.request
        req_body = req.content if req.content else b""
        resp_ref = self._body_store.put(body, ctype)
        req_ref = self._body_store.put(req_body) if req_body else None

        json_keys: list[str] = []
        numeric_fields: dict[str, float] = {}
        id_fields: dict[str, object] = {}
        html_title = ""
        forms: list[dict] = []

        if "json" in ctype:
            json_keys, numeric_fields, id_fields = _extract_json_signals(body)
        elif "html" in ctype:
            html_title, forms = _extract_html_signals(body, url)

        # ID in the URL path is a first-class signal for IDOR (works for HTML sites)
        for seg in urlparse(url).path.split("/"):
            if re.fullmatch(r"\d+", seg):
                id_fields["path_id"] = int(seg)

        return HttpExchange(
            seq=self._seq,
            exchange_id=f"recon-{self._seq:04d}",
            method=req.method,
            url=url,
            endpoint=_url_to_endpoint(url),
            request_headers={k: v for k, v in req.headers.items()
                             if k.lower() not in ("cookie", "authorization")},
            request_body_ref=req_ref,
            status=resp.status_code,
            response_headers=dict(resp.headers),
            response_body_ref=resp_ref,
            actor=actor,
            json_keys=json_keys,
            numeric_fields=numeric_fields,
            id_fields=id_fields,
            html_title=html_title,
            forms=forms,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )


# ── HTML / JSON parsing helpers ──────────────────────────────────────────────

def _extract_links(html: str, page_url: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    out: list[str] = []
    for a in soup.find_all("a", href=True):
        out.append(urljoin(page_url, a["href"]))
    return out


def _extract_html_signals(body: bytes, page_url: str) -> tuple[str, list[dict]]:
    soup = BeautifulSoup(body, "html.parser")
    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    forms: list[dict] = []
    for f in soup.find_all("form"):
        fields = []
        for inp in f.find_all(["input", "select", "textarea"]):
            name = inp.get("name")
            if name:
                # Capture value so hidden CSRF tokens can be replayed correctly (Issue-005)
                fields.append({
                    "name": name,
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                })
        forms.append({
            "action": f.get("action", ""),
            "method": f.get("method", "get"),
            "fields": fields,
        })
    return title, forms


def _find_password_form(html: str, page_url: str) -> Optional[dict]:
    """Return a normalized descriptor of the first form containing a password input."""
    soup = BeautifulSoup(html, "html.parser")
    for f in soup.find_all("form"):
        pwd = f.find("input", attrs={"type": "password"})
        if not pwd or not pwd.get("name"):
            continue
        password_field = pwd.get("name")
        hidden: dict[str, str] = {}
        username_field = None
        for inp in f.find_all("input"):
            name = inp.get("name")
            if not name or name == password_field:
                continue
            itype = (inp.get("type") or "text").lower()
            if itype == "hidden":
                hidden[name] = inp.get("value", "")
            elif username_field is None and (itype in ("text", "email") or name.lower() in _USERNAME_NAMES):
                username_field = name
        return {
            "action": f.get("action", ""),
            "method": f.get("method", "post"),
            "password_field": password_field,
            "username_field": username_field,
            "hidden": hidden,
        }
    return None


# ── Inline-JS endpoint extraction ────────────────────────────────────────────
# Captures the URL expression up to the first comma/close-paren (URLs never contain
# either), so concatenations like '/orders/' + id + '/cancel' come through intact.
_JS_FETCH_RE  = re.compile(r"""fetch\(\s*([^,)]+)""", re.IGNORECASE)
_JS_AXIOS_RE  = re.compile(r"""axios\.(get|post|put|patch|delete)\(\s*([^,)]+)""", re.IGNORECASE)
_JS_XHR_RE    = re.compile(r"""\.open\(\s*['"]([A-Za-z]+)['"]\s*,\s*([^,)]+)""")
_JS_METHOD_RE = re.compile(r"""method\s*:\s*['"]([A-Za-z]+)['"]""", re.IGNORECASE)
_JS_BODY_RE   = re.compile(r"""JSON\.stringify\(\s*\{([^}]*)\}""", re.DOTALL)
# First identifier of each comma-separated property — captures both `key: val` and the
# ES6 shorthand `{code}` / `{to, amount}` (where there is no colon).
_JS_KEY_RE    = re.compile(r"""^\s*['"]?([A-Za-z_]\w*)""")


def _clean_js_path(s: str) -> Optional[str]:
    s = (s or "").split("?")[0].split("#")[0]
    s = re.sub(r"/+", "/", s)  # collapse '/x/' + id → '/x/{id}' style double-slashes
    if not s.startswith("/") or len(s) < 2:
        return None
    return s


def _js_expr_to_path(expr: str) -> Optional[str]:
    """Turn a JS URL expression into a path template.

    "'/checkout'"                       → /checkout
    "'/cart/remove/' + id"              → /cart/remove/{id}
    "'/orders/' + oid + '/cancel'"      → /orders/{id}/cancel
    "`/orders/${oid}/refund`"           → /orders/{id}/refund
    """
    expr = (expr or "").strip()
    if not expr:
        return None
    if expr[0] == "`":  # template literal
        s = re.sub(r"\$\{[^}]*\}", "{id}", expr.strip("`"))
        return _clean_js_path(s)
    if expr[0] in "'\"":  # plain or concatenated string literals
        parts: list[str] = []
        for tok in expr.split("+"):
            m = re.fullmatch(r"""\s*['"](.*)['"]\s*""", tok)
            parts.append(m.group(1) if m else "{id}")
        return _clean_js_path("".join(parts))
    return None


def _extract_js_endpoints(text: str) -> dict[tuple[str, str], set[str]]:
    """Return {(METHOD, path_template): {field names}} from fetch/axios/XHR calls."""
    out: dict[tuple[str, str], set[str]] = {}

    def _window(end: int) -> str:
        w = text[end:end + 240]
        return re.split(r"fetch\(|axios\.|\.open\(", w)[0]  # don't bleed into next call

    def _record(method: str, expr: str, window: str) -> None:
        path = _js_expr_to_path(expr)
        if not path:
            return
        keys: set[str] = set()
        bm = _JS_BODY_RE.search(window)
        if bm:
            for seg in bm.group(1).split(","):
                km = _JS_KEY_RE.match(seg)
                if km:
                    keys.add(km.group(1))
        out.setdefault((method.upper(), path), set()).update(keys)

    for m in _JS_FETCH_RE.finditer(text):
        win = _window(m.end())
        mm = _JS_METHOD_RE.search(win)
        _record(mm.group(1) if mm else "GET", m.group(1), win)
    for m in _JS_AXIOS_RE.finditer(text):
        _record(m.group(1), m.group(2), _window(m.end()))
    for m in _JS_XHR_RE.finditer(text):
        _record(m.group(1), m.group(2), _window(m.end()))
    return out


def _extract_json_signals(body: bytes) -> tuple[list[str], dict[str, float], dict[str, object]]:
    import json
    json_keys: list[str] = []
    numeric_fields: dict[str, float] = {}
    id_fields: dict[str, object] = {}
    try:
        obj = json.loads(body)
    except Exception:
        return json_keys, numeric_fields, id_fields
    target = obj
    if isinstance(obj, dict) and isinstance(obj.get("data"), (dict, list)):
        target = obj["data"]
    if isinstance(target, list) and target and isinstance(target[0], dict):
        target = target[0]
    if isinstance(target, dict):
        json_keys = list(target.keys())[:50]
        for k, v in target.items():
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                numeric_fields[k] = float(v)
            if "id" in k.lower() or k.lower() in ("user", "owner", "account"):
                id_fields[k] = v
    return json_keys, numeric_fields, id_fields


# ── Aggregation helpers ──────────────────────────────────────────────────────

_LOGOUT_HINTS = ("logout", "signout", "sign-out", "log-out", "logoff", "sign_out")


def _is_logout(url: str) -> bool:
    p = urlparse(url).path.lower()
    return any(h in p for h in _LOGOUT_HINTS)


def _base_url(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _url_to_endpoint(url: str) -> str:
    """Normalise URL to parameterised template: /product/123 → /product/{id}"""
    path = urlparse(url).path
    parts = path.split("/")
    out = []
    for part in parts:
        if re.fullmatch(r"\d+", part):
            out.append("{id}")
        elif re.fullmatch(r"[0-9a-f-]{36}", part):
            out.append("{uuid}")
        else:
            out.append(part)
    return "/".join(out) or "/"


def _extract_endpoints(exchanges: list[HttpExchange]) -> list[Endpoint]:
    seen: dict[str, Endpoint] = {}
    for ex in exchanges:
        key = f"{ex.method}:{ex.endpoint}"
        # Determine discovery method: probed/form takes precedence over crawled
        label = getattr(ex, "label", "") or ""
        disc = "probed" if label == "probed" else ("form" if label == "form" else "crawled")
        if key not in seen:
            params: list[str] = []
            for form in ex.forms:
                params.extend(fld["name"] for fld in form.get("fields", []))
            seen[key] = Endpoint(
                url=ex.url,
                method=ex.method,
                endpoint=ex.endpoint,
                auth_required=(ex.actor != "anon"),
                content_type=ex.response_headers.get("content-type", ""),
                parameters=sorted(set(params)),
                json_keys=ex.json_keys,
                numeric_fields=list(ex.numeric_fields.keys()),
                id_fields=list(ex.id_fields.keys()),
                discovery=disc,
            )
        else:
            # Upgrade discovery if we found it via crawl (more authoritative than probed)
            if disc == "crawled" and seen[key].discovery != "crawled":
                seen[key].discovery = "crawled"
            # Accumulate params from later exchanges
            ep = seen[key]
            for form in ex.forms:
                for fld in form.get("fields", []):
                    if fld["name"] not in ep.parameters:
                        ep.parameters.append(fld["name"])
    return list(seen.values())


def _compute_auth_diffs(anon_ex: list[HttpExchange], auth_ex: list[HttpExchange]) -> list[AuthDiff]:
    anon_map = {f"{e.method}:{e.endpoint}": e for e in anon_ex}
    auth_map = {f"{e.method}:{e.endpoint}": e for e in auth_ex}
    diffs: list[AuthDiff] = []
    for key, auth_e in auth_map.items():
        anon_e = anon_map.get(key)
        anon_status = anon_e.status if anon_e else 0
        # Signal: auth can reach it (2xx) but anon is blocked/redirected/absent
        if anon_status != auth_e.status and auth_e.status < 400:
            if anon_status in (0, 301, 302, 303, 401, 403) or anon_status >= 400:
                diffs.append(AuthDiff(
                    endpoint=auth_e.endpoint,
                    method=auth_e.method,
                    anon_status=anon_status,
                    auth_status=auth_e.status,
                    anon_body_ref_id=anon_e.response_body_ref.blob_id if anon_e and anon_e.response_body_ref else None,
                    auth_body_ref_id=auth_e.response_body_ref.blob_id if auth_e.response_body_ref else None,
                ))
    return diffs


def _build_workflow_graph(exchanges: list[HttpExchange]) -> WorkflowGraph:
    nodes: list[WorkflowNode] = []
    edges: list[WorkflowEdge] = []
    seen: set[str] = set()
    for ex in exchanges:
        if ex.endpoint not in seen:
            seen.add(ex.endpoint)
            nodes.append(WorkflowNode(
                node_id=ex.endpoint,
                label=f"{ex.method} {ex.endpoint}",
                url=ex.url,
                method=ex.method,
                auth_required=(ex.actor != "anon"),
            ))
    prev: dict[str, str] = {}
    for ex in sorted(exchanges, key=lambda e: e.seq):
        if ex.actor in prev and prev[ex.actor] != ex.endpoint:
            edge = WorkflowEdge(from_node=prev[ex.actor], to_node=ex.endpoint)
            if edge not in edges:
                edges.append(edge)
        prev[ex.actor] = ex.endpoint
    return WorkflowGraph(nodes=nodes, edges=edges)


def _detect_business_flows(endpoints: list[Endpoint], exchanges: list[HttpExchange]) -> list[BusinessFlow]:
    """Detect multi-step flows from form-bearing endpoints and money/qty fields."""
    flows: list[BusinessFlow] = []
    kw = ("cart", "checkout", "order", "payment", "confirm", "transfer", "pay", "purchase")
    steps = [e.endpoint for e in endpoints if any(k in e.endpoint.lower() for k in kw)]
    if len(steps) >= 2:
        numeric: list[str] = []
        money_params: list[str] = []
        for ex in exchanges:
            if any(k in ex.endpoint.lower() for k in kw):
                numeric.extend(ex.numeric_fields.keys())
                for form in ex.forms:
                    money_params.extend(
                        fld["name"] for fld in form.get("fields", [])
                        if any(m in fld["name"].lower() for m in ("amount", "price", "qty", "quantity", "total", "balance"))
                    )
        flows.append(BusinessFlow(
            flow_id="transaction",
            name="Transaction / Checkout Flow",
            description="Multi-step value-bearing workflow detected from forms and numeric fields",
            steps=sorted(set(steps)),
            numeric_fields=sorted(set(numeric)),
            state_fields=sorted(set(money_params)),
        ))
    return flows


def _detect_api_hints(exchanges: list[HttpExchange]) -> list[str]:
    hints: set[str] = set()
    for ex in exchanges:
        server = ex.response_headers.get("server", "").lower()
        powered = ex.response_headers.get("x-powered-by", "").lower()
        for fw in ("express", "django", "rails", "spring", "laravel", "fastapi", "flask", "werkzeug"):
            if fw in server or fw in powered:
                hints.add(fw)
    return sorted(hints)


def _render_recon_md(artifact: ReconArtifact) -> str:
    lines = [
        f"# Recon: {artifact.target_url}",
        f"\nCrawled: {artifact.crawl_timestamp}",
        f"\n- Endpoints: {len(artifact.endpoints)}",
        f"- Exchanges: {len(artifact.exchanges)}",
        f"- Auth diffs: {len(artifact.auth_diffs)}",
        f"- Business flows: {len(artifact.business_flows)}",
        f"- API hints: {', '.join(artifact.api_hints) or 'none'}",
        "\n## Endpoints\n",
    ]
    for ep in artifact.endpoints:
        lines.append(f"- `{ep.method} {ep.endpoint}`{' [auth]' if ep.auth_required else ''}")
        if ep.parameters:
            lines.append(f"  - params: {ep.parameters}")
        if ep.id_fields:
            lines.append(f"  - id fields: {ep.id_fields}")
    if artifact.auth_diffs:
        lines.append("\n## Auth Access Diffs (BAC signal)\n")
        for d in artifact.auth_diffs:
            lines.append(f"- `{d.method} {d.endpoint}`: anon={d.anon_status} vs auth={d.auth_status}")
    if artifact.business_flows:
        lines.append("\n## Business Flows\n")
        for flow in artifact.business_flows:
            lines.append(f"- **{flow.name}**: {' → '.join(flow.steps)}")
            if flow.state_fields:
                lines.append(f"  - value fields: {flow.state_fields}")
    return "\n".join(lines)
