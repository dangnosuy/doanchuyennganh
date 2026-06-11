"""RecordingHttpClient — the HTTP chokepoint.

Every HTTP request made during execution goes through this client.
All exchanges are automatically captured into Evidence.
No request can "escape" without being recorded.

This fixes MARL's fundamental problem where exec_agent.py used raw httpx
and requests could bypass recording — making evidence incomplete.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx

from ..contracts.body import BodyRef
from ..contracts.evidence import Evidence
from ..contracts.http import HttpExchange
from ..recon.body_store import BodyStore
from ..recon.auth import AuthSessionStore

log = logging.getLogger("marl3.exec.recorder")

# Client-error statuses that usually mean "wrong body wire-format" rather than a dead
# route, so retrying the same request with the alternate encoding is worth one extra hit.
_RETRYABLE_ENCODING_STATUS = {400, 404, 415, 422}


def _encoding_attempts(body, req_headers: dict, explicit_ct: bool) -> list[tuple[bytes, str | None]]:
    """Ordered (body_bytes, content_type) attempts for a request body.

    A dict is encoded both ways and tried in order so a JSON-only API still receives a
    parseable body even when exec sent it as a form (and vice versa). A caller-supplied
    Content-Type is honored FIRST, then the alternate is kept as a fallback. str/bytes
    bodies are sent verbatim (no content-type override, single attempt).
    """
    if isinstance(body, dict):
        from urllib.parse import urlencode
        form = (urlencode(body).encode(), "application/x-www-form-urlencoded")
        js = (json.dumps(body).encode(), "application/json")
        if explicit_ct:
            ct = (req_headers.get("Content-Type") or req_headers.get("content-type") or "").lower()
            return [js, form] if "json" in ct else [form, js]
        return [form, js]  # no explicit CT: form first (back-compat), JSON on retry
    if isinstance(body, str):
        return [(body.encode(), None)]
    if isinstance(body, bytes):
        return [(body, None)]
    return [(b"", None)]


class RecordingHttpClient:
    """Thin httpx wrapper that auto-captures every exchange into Evidence.

    Usage:
        client = RecordingHttpClient(evidence, body_store, auth_store, cfg)
        resp = await client.request("GET", url, actor="user_a")
        # exchange is automatically appended to evidence.exchanges
    """

    def __init__(
        self,
        evidence: Evidence,
        body_store: BodyStore,
        auth_store: AuthSessionStore,
        timeout_s: int = 30,
        user_agent: str = "marl3-pentest/0.1",
    ) -> None:
        self._evidence = evidence
        self._body_store = body_store
        self._auth_store = auth_store
        self._timeout = httpx.Timeout(timeout_s)
        self._user_agent = user_agent
        self._seq = 0
        # follow_redirects=False is a SOUNDNESS requirement: a blocked /admin that
        # 302→/login must be recorded as 302, not collapsed into a 200 login page
        # (which would let BAC-01/06 false-positive on "GET /admin → 200").
        self._client = httpx.AsyncClient(
            timeout=self._timeout,
            follow_redirects=False,
            verify=False,
        )

    async def request(
        self,
        method: str,
        url: str,
        actor: str = "anon",
        headers: Optional[dict[str, str]] = None,
        body: Optional[bytes | str | dict] = None,
        label: str = "",
    ) -> httpx.Response:
        """Send an HTTP request and record the exchange automatically."""
        self._seq += 1
        exchange_id = f"exec-{self._evidence.bug_id}-{self._seq:03d}"

        # Build headers with auth injection
        req_headers = {"User-Agent": self._user_agent}
        if headers:
            req_headers.update(headers)

        try:
            auth_headers = self._auth_store.headers_for(actor)
            # Caller-provided Cookie/Authorization win — this enables cookie/token
            # tampering exploits (e.g. role=admin, user_id=N). Only fill what's absent.
            caller_keys = {k.lower() for k in (headers or {})}
            for k, v in auth_headers.items():
                if k.lower() not in caller_keys:
                    req_headers[k] = v
        except KeyError:
            if actor != "anon":
                log.warning(f"Auth label not found: {actor!r}")

        # Encode the body and AUTO-ADAPT the wire format. A dict is tried as FORM
        # (server-rendered HTML sites) but auto-retried as JSON when the first attempt
        # draws a client error — JSON-only APIs silently misroute/reject a form body
        # (e.g. Flask get_json()→None→404 "not found", or 400 "field is required"),
        # which previously derailed exec into thinking the endpoint was dead. This makes
        # exec robust to both form- and JSON-based endpoints without guessing the format.
        explicit_ct = "content-type" in {k.lower() for k in (headers or {})}
        attempts = _encoding_attempts(body, req_headers, explicit_ct)

        ts_start = datetime.now(timezone.utc)
        req_body_bytes = b""
        resp_body = b""
        status = 0
        resp_headers: dict[str, str] = {}
        error: Optional[str] = None
        response = None

        for i, (enc_body, enc_ct) in enumerate(attempts):
            send_headers = dict(req_headers)
            if enc_ct:
                send_headers["Content-Type"] = enc_ct
            try:
                response = await self._client.request(
                    method=method,
                    url=url,
                    headers=send_headers,
                    content=enc_body if enc_body else None,
                )
                resp_body = await response.aread()
                status = response.status_code
                resp_headers = dict(response.headers)
                error = None
            except Exception as e:
                error = str(e)
                log.warning(f"HTTP error {method} {url}: {e}")
                response = None
                status = 0
            req_body_bytes = enc_body
            if enc_ct:
                req_headers["Content-Type"] = enc_ct  # reflect the KEPT encoding in the PoC
            # Keep this attempt unless it was a retryable client error and another
            # encoding is still available to try.
            if status not in _RETRYABLE_ENCODING_STATUS or i == len(attempts) - 1:
                break
            log.debug(f"{method} {url} → {status} with {enc_ct or 'raw body'}; retrying alternate encoding")

        req_ref = self._body_store.put(req_body_bytes) if req_body_bytes else None

        elapsed_ms = int((datetime.now(timezone.utc) - ts_start).total_seconds() * 1000)
        resp_ref = self._body_store.put(resp_body, resp_headers.get("content-type", ""))

        # Extract metadata without reading the full body back
        json_keys: list[str] = []
        numeric_fields: dict[str, float] = {}
        id_fields: dict[str, object] = {}
        html_title = ""
        ctype = resp_headers.get("content-type", "")
        if resp_body and "json" in ctype:
            try:
                obj = json.loads(resp_body)
                target = obj["data"] if isinstance(obj, dict) and isinstance(obj.get("data"), (dict, list)) else obj
                if isinstance(target, list) and target and isinstance(target[0], dict):
                    target = target[0]
                if isinstance(target, dict):
                    json_keys = list(target.keys())[:50]
                    for k, v in target.items():
                        if isinstance(v, (int, float)) and not isinstance(v, bool):
                            numeric_fields[k] = float(v)
                        if "id" in k.lower() or k.lower() in ("user", "owner", "account"):
                            id_fields[k] = v
            except Exception:
                pass
        elif resp_body and "html" in ctype:
            m = re.search(rb"<title[^>]*>(.*?)</title>", resp_body, re.IGNORECASE | re.DOTALL)
            if m:
                html_title = m.group(1).decode("utf-8", "replace").strip()[:200]
        # ID in URL path — first-class IDOR signal for HTML sites
        for seg in urlparse(url).path.split("/"):
            if re.fullmatch(r"\d+", seg):
                id_fields["path_id"] = int(seg)
        # Record response size for content-diff based IDOR proof
        numeric_fields["_resp_len"] = float(len(resp_body))

        exchange = HttpExchange(
            seq=self._seq,
            exchange_id=exchange_id,
            method=method.upper(),
            url=url,
            endpoint=_url_to_endpoint(url),
            # Keep request headers INCLUDING cookie — the tampered cookie/token IS the
            # exploit payload (PoC + verifier need it). Long session tokens are masked.
            request_headers=_sanitize_req_headers(req_headers),
            request_body_ref=req_ref,
            status=status,
            response_headers=resp_headers,
            response_body_ref=resp_ref,
            actor=actor,
            json_keys=json_keys,
            numeric_fields=numeric_fields,
            id_fields=id_fields,
            html_title=html_title,
            label=label,
            timestamp=ts_start.isoformat(),
            elapsed_ms=elapsed_ms,
            error=error,
        )

        if error:
            # Do NOT add transport-error exchanges to evidence — status=0 would confuse
            # proof rules that check `ex.status in range(200, 300)`. Log and return fake.
            log.warning(f"Transport error {method} {url}: {error} — exchange not recorded")
            return httpx.Response(0, content=b"")

        self._evidence.exchanges.append(exchange)
        log.debug(f"Recorded: {method} {url} → {status} ({elapsed_ms}ms) actor={actor}")

        return response

    async def close(self) -> None:
        await self._client.aclose()


def _sanitize_req_headers(headers: dict[str, str]) -> dict[str, str]:
    """Keep request headers (incl. cookie/auth — the exploit payload) but mask long
    opaque token values so the tampered fields (role=admin, user_id=N) stay visible."""
    out: dict[str, str] = {}
    for k, v in headers.items():
        if k.lower() == "cookie":
            parts = []
            for c in v.split(";"):
                if "=" in c:
                    name, _, val = c.strip().partition("=")
                    parts.append(f"{name}={val if len(val) <= 24 else val[:8] + '…<masked>'}")
            out[k] = "; ".join(parts)
        elif k.lower() == "authorization":
            out[k] = v[:16] + "…<masked>" if len(v) > 24 else v
        else:
            out[k] = v
    return out


def _url_to_endpoint(url: str) -> str:
    import re
    path = urlparse(url).path
    parts = path.split("/")
    normalized = []
    for part in parts:
        if re.match(r"^\d+$", part):
            normalized.append("{id}")
        elif re.match(r"^[0-9a-f-]{36}$", part):
            normalized.append("{uuid}")
        else:
            normalized.append(part)
    return "/".join(normalized)
