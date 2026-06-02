"""
Guided Playwright crawler for MARL recon.

The CLI keeps the old tools/crawler.py contract so CrawlAgent can continue to
call it unchanged. The implementation is intentionally action-aware: it records
same-origin browser traffic, visits a small set of business routes, performs
safe clicks, and emits workflow evidence for BAC/BLF chaining.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse


RESPONSE_BODY_LIMIT = 12000
PROGRESS_WIDTH = 140
STATIC_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".map", ".webp", ".mp4", ".pdf",
)
BLOCKED_ACTION_WORDS = (
    "confirm",
    "delete",
    "logout",
    "pay",
    "payment",
    "purchase",
    "remove",
    "sign out",
    "submit order",
)
READONLY_NAV_BLOCK_WORDS = ("logout", "delete", "remove", "confirm", "pay", "purchase")
STATEFUL_CLICK_ALLOW_WORDS = (
    "add to basket",
    "add to cart",
    "thêm vào giỏ",
    "basket",
    "cart",
    "product",
    "detail",
    "search",
)
AI_ACTION_CANDIDATE_LIMIT = 24
AI_DEFAULT_STEPS = 4
AI_MAX_STEPS = 8
HIGH_VALUE_ACTION_WORDS = (
    "add to basket",
    "add to cart",
    "basket",
    "cart",
    "order",
    "profile",
    "account",
    "admin",
    "product",
)
LOW_VALUE_NAV_WORDS = (
    "login",
    "log in",
    "sign in",
    "signin",
    "register",
    "home",
)
SAFE_HASH_ROUTES = (
    "#/search",
    "#/profile",
    "#/account",
    "#/cart",
    "#/orders",
    "#/checkout",
    "#/contact",
)
BUSINESS_SURFACE_KEYWORDS = {
    "access_control": ("admin", "manage", "dashboard", "role", "permission", "users", "account", "profile"),
    "commerce": ("cart", "basket", "checkout", "order", "payment", "invoice", "refund"),
    "value_logic": ("coupon", "discount", "promo", "quantity", "price", "amount", "balance", "wallet", "transfer"),
    "workflow_state": ("approve", "approval", "status", "cancel", "return", "shipping", "stock", "inventory"),
}
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass
class CrawlMemory:
    """Compact state memory used to avoid crawl loops and expose coverage gaps."""
    visited_endpoints: set[str] = field(default_factory=set)
    tried_actions: set[tuple[str, str, str, str]] = field(default_factory=set)
    no_effect_actions: set[tuple[str, str, str]] = field(default_factory=set)
    emitted_endpoints: set[str] = field(default_factory=set)
    state_changing_endpoints: set[str] = field(default_factory=set)
    covered_surfaces: set[str] = field(default_factory=set)
    repeated_endpoint_hits: dict[str, int] = field(default_factory=dict)


@dataclass
class GuidedState:
    target: str
    max_pages: int
    pages: list[dict[str, Any]] = field(default_factory=list)
    http_traffic: list[dict[str, Any]] = field(default_factory=list)
    observed_actions: list[dict[str, Any]] = field(default_factory=list)
    action_candidates: list[dict[str, Any]] = field(default_factory=list)
    ai_decisions: list[dict[str, Any]] = field(default_factory=list)
    request_chains: list[dict[str, Any]] = field(default_factory=list)
    external_links: set[str] = field(default_factory=set)
    api_hints: list[dict[str, Any]] = field(default_factory=list)
    business_chain: list[dict[str, Any]] = field(default_factory=list)
    auth_bootstrap: dict[str, Any] = field(default_factory=dict)
    memory: CrawlMemory = field(default_factory=CrawlMemory)
    notes: list[str] = field(default_factory=list)


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


def _progress(msg: str) -> None:
    clean = " ".join(str(msg or "").split())
    if len(clean) > PROGRESS_WIDTH:
        clean = clean[: PROGRESS_WIDTH - 3] + "..."
    sys.stderr.write("[CRAWLER-PROGRESS] " + clean.ljust(PROGRESS_WIDTH) + "\r")
    sys.stderr.flush()


def _progress_done() -> None:
    sys.stderr.write("\n")
    sys.stderr.flush()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _same_origin(base_url: str, candidate: str) -> bool:
    base = urlparse(base_url)
    other = urlparse(candidate)
    return (base.scheme, base.netloc) == (other.scheme, other.netloc)


def _safe_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, parsed.fragment))


def _endpoint(url: str) -> str:
    parsed = urlparse(url)
    endpoint = parsed.path or "/"
    if parsed.query:
        endpoint += "?" + parsed.query
    if parsed.fragment:
        endpoint += "#" + parsed.fragment
    return endpoint


def _is_static(url: str) -> bool:
    return url.lower().split("?")[0].endswith(STATIC_EXTENSIONS)


def _trim(value: Any, limit: int = 500) -> str | None:
    if value is None:
        return None
    compact = " ".join(str(value).split())
    return compact if len(compact) <= limit else compact[: limit - 3] + "..."


def _is_blocked_action(text: str) -> bool:
    lower = (text or "").lower()
    return any(word in lower for word in BLOCKED_ACTION_WORDS)


def _is_blocked_navigation(text: str) -> bool:
    lower = (text or "").lower()
    return any(word in lower for word in READONLY_NAV_BLOCK_WORDS)


def _is_allowed_stateful_click(text: str) -> bool:
    lower = (text or "").lower()
    return any(word in lower for word in STATEFUL_CLICK_ALLOW_WORDS)


def _compact_endpoint_list(items: list[dict[str, Any]], limit: int = 10) -> list[str]:
    result: list[str] = []
    for item in items[-limit:]:
        url = str(item.get("url") or item.get("after_url") or "")
        if url:
            result.append(_endpoint(url))
    return result


def _surface_matches(text: str) -> list[str]:
    lower = (text or "").lower()
    return [
        surface
        for surface, keywords in BUSINESS_SURFACE_KEYWORDS.items()
        if any(keyword in lower for keyword in keywords)
    ]


def _remember_endpoint(state: GuidedState, url_or_endpoint: str, method: str = "") -> None:
    if not url_or_endpoint:
        return
    endpoint = _endpoint(url_or_endpoint) if "://" in str(url_or_endpoint) else str(url_or_endpoint)
    state.memory.repeated_endpoint_hits[endpoint] = state.memory.repeated_endpoint_hits.get(endpoint, 0) + 1
    state.memory.visited_endpoints.add(endpoint)
    if method.upper() in STATE_CHANGING_METHODS:
        state.memory.state_changing_endpoints.add(endpoint)
    for surface in _surface_matches(f"{method} {endpoint}"):
        state.memory.covered_surfaces.add(surface)


def _remember_candidate(state: GuidedState, candidate: dict[str, Any], after_url: str, emitted_count: int) -> None:
    identity = _candidate_identity(candidate)
    state.memory.tried_actions.add(identity)
    no_effect_key = (
        str(candidate.get("current_endpoint") or ""),
        str(candidate.get("action_type") or ""),
        str(candidate.get("label") or "").strip().lower(),
    )
    changed_endpoint = str(candidate.get("current_endpoint") or "") != _endpoint(after_url)
    if emitted_count <= 0 and not changed_endpoint:
        state.memory.no_effect_actions.add(no_effect_key)
    for surface in _surface_matches(
        " ".join(str(candidate.get(k, "") or "") for k in ("label", "target_endpoint", "risk"))
    ):
        state.memory.covered_surfaces.add(surface)


def _memory_snapshot(state: GuidedState) -> dict[str, Any]:
    high_repeat = [
        {"endpoint": endpoint, "hits": hits}
        for endpoint, hits in sorted(state.memory.repeated_endpoint_hits.items(), key=lambda item: item[1], reverse=True)
        if hits >= 3
    ][:10]
    gaps = sorted(set(BUSINESS_SURFACE_KEYWORDS) - state.memory.covered_surfaces)
    return {
        "visited_endpoint_count": len(state.memory.visited_endpoints),
        "visited_endpoints": sorted(state.memory.visited_endpoints)[-30:],
        "tried_action_count": len(state.memory.tried_actions),
        "no_effect_action_count": len(state.memory.no_effect_actions),
        "state_changing_endpoint_count": len(state.memory.state_changing_endpoints),
        "state_changing_endpoints": sorted(state.memory.state_changing_endpoints)[:30],
        "covered_surfaces": sorted(state.memory.covered_surfaces),
        "coverage_gaps": gaps,
        "repeated_endpoint_hits": high_repeat,
    }


def _append_unique(items: list[dict[str, Any]], item: dict[str, Any], keys: tuple[str, ...]) -> None:
    marker = tuple(item.get(key) for key in keys)
    for old in items:
        if tuple(old.get(key) for key in keys) == marker:
            return
    items.append(item)


def _parse_cookie_header(cookie_header: str | None, target_url: str) -> list[dict[str, Any]]:
    if not cookie_header:
        return []
    host = urlparse(target_url).hostname or "localhost"
    cookies: list[dict[str, Any]] = []
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        if not name:
            continue
        cookies.append({
            "name": name,
            "value": value.strip(),
            "domain": host,
            "path": "/",
        })
    return cookies


def _headers_from_cli(headers: list[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for header in headers or []:
        if ":" not in header:
            continue
        name, value = header.split(":", 1)
        name = name.strip()
        value = value.strip()
        if name:
            parsed[name] = value
    return parsed


def _load_project_env() -> None:
    try:
        from dotenv import load_dotenv
    except Exception:
        return
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _crawl_ai_config(args: argparse.Namespace) -> dict[str, Any]:
    _load_project_env()
    enabled = getattr(args, "ai_guided", None)
    if enabled is None:
        enabled = _env_bool("MARL_CRAWL_AI_GUIDED", True)
    steps_raw = getattr(args, "ai_steps", None) or os.getenv("MARL_CRAWL_AI_STEPS") or str(AI_DEFAULT_STEPS)
    try:
        steps = max(0, min(AI_MAX_STEPS, int(steps_raw)))
    except Exception:
        steps = AI_DEFAULT_STEPS
    model = (
        os.getenv("MARL_CRAWL_MODEL")
        or os.getenv("MARL_EXECUTOR_MODEL")
        or os.getenv("MARL_MANAGER_MODEL")
        or ""
    )
    base_url = os.getenv("MARL_SERVER_URL", "")
    api_key = os.getenv("GITHUB_TOKEN") or os.getenv("OPENAI_API_KEY") or "unused"
    return {
        "enabled": bool(enabled and steps > 0 and model and base_url),
        "requested": bool(enabled),
        "steps": steps,
        "model": model,
        "base_url": base_url,
        "api_key": api_key,
    }


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _storage_values_from_state(path: str | None, target_url: str) -> dict[str, str]:
    if not path:
        return {}
    state_path = Path(path)
    if not state_path.exists():
        return {}
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    target_origin = _origin(target_url)
    values: dict[str, str] = {}
    for origin_entry in data.get("origins") or []:
        if not isinstance(origin_entry, dict):
            continue
        if origin_entry.get("origin") != target_origin:
            continue
        for item in origin_entry.get("localStorage") or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            value = str(item.get("value") or "")
            if name:
                values[name] = value
    return values


def _auth_bootstrap_script(values: dict[str, str]) -> str:
    payload = json.dumps(values)
    return f"""(() => {{
        const values = {payload};
        try {{
            for (const [key, value] of Object.entries(values)) {{
                localStorage.setItem(key, value);
                sessionStorage.setItem(key, value);
            }}
            if (values.token) {{
                localStorage.setItem('token', values.token);
                sessionStorage.setItem('token', values.token);
            }}
            if (values.email) {{
                sessionStorage.setItem('email', values.email);
                localStorage.setItem('email', values.email);
            }}
        }} catch (e) {{}}
    }})();"""


def _json_summary(body: str | None) -> tuple[list[str], list[str], list[str]]:
    if not body:
        return [], [], []
    try:
        parsed = json.loads(body)
    except Exception:
        return [], [], []
    keys: list[str] = []
    numeric_fields: list[str] = []
    id_fields: list[str] = []

    def walk(value: Any, prefix: str = "") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                if len(keys) < 60 and path not in keys:
                    keys.append(path)
                lower = str(key).lower()
                if isinstance(child, (int, float)) and len(numeric_fields) < 40:
                    numeric_fields.append(path)
                if (
                    lower == "id"
                    or lower.endswith("id")
                    or lower in {"userid", "basketid", "productid", "orderid"}
                ) and len(id_fields) < 40:
                    id_fields.append(path)
                walk(child, path)
        elif isinstance(value, list):
            for child in value[:3]:
                walk(child, prefix + "[]")

    walk(parsed)
    return keys, numeric_fields, id_fields


def _record_action(
    state: GuidedState,
    name: str,
    status: str,
    before_url: str,
    after_url: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    state.observed_actions.append({
        "name": name,
        "status": status,
        "before_url": before_url,
        "after_url": after_url,
        "detail": detail or {},
        "timestamp": _now_iso(),
    })


def _install_network_capture(page: Any, state: GuidedState) -> None:
    request_meta: dict[Any, dict[str, Any]] = {}

    def on_request(request: Any) -> None:
        if not _same_origin(state.target, request.url):
            return
        if request.resource_type in {"image", "stylesheet", "font", "media"}:
            return
        request_meta[request] = {
            "method": request.method,
            "url": request.url,
            "headers": dict(request.headers),
            "postData": _trim(request.post_data, 2000),
            "response_status": None,
            "response_headers": {},
            "resource_type": request.resource_type,
            "response_body": None,
            "parent_url": request.frame.url if request.frame else None,
            "form_fields": None,
            "timestamp": _now_iso(),
        }

    def on_response(response: Any) -> None:
        request = response.request
        entry = request_meta.get(request)
        if entry is None:
            return
        entry["response_status"] = response.status
        entry["response_headers"] = dict(response.headers)
        if request.resource_type not in {"document", "xhr", "fetch", "other"}:
            return
        try:
            content_type = str(response.headers.get("content-type", ""))
            if any(binary in content_type for binary in ("image/", "font/", "audio/", "video/", "octet-stream")):
                return
            body = response.text()
            entry["response_body"] = body[:RESPONSE_BODY_LIMIT] if body else None
            keys, numeric_fields, id_fields = _json_summary(entry["response_body"])
            if keys:
                entry["response_json_keys"] = keys
            if numeric_fields:
                entry["response_numeric_fields"] = numeric_fields
            if id_fields:
                entry["response_id_fields"] = id_fields
        except Exception as exc:
            entry["body_capture_error"] = str(exc)[:240]

    def on_request_finished(request: Any) -> None:
        entry = request_meta.pop(request, None)
        if entry is not None:
            state.http_traffic.append(entry)
            _remember_endpoint(state, str(entry.get("url") or ""), str(entry.get("method") or ""))

    def on_request_failed(request: Any) -> None:
        entry = request_meta.pop(request, None)
        if entry is not None:
            entry["failed"] = True
            state.http_traffic.append(entry)
            _remember_endpoint(state, str(entry.get("url") or ""), str(entry.get("method") or ""))

    page.on("request", on_request)
    page.on("response", on_response)
    page.on("requestfinished", on_request_finished)
    page.on("requestfailed", on_request_failed)


def _capture_page(page: Any, state: GuidedState, label: str, response: Any | None = None) -> None:
    if len(state.pages) >= state.max_pages:
        return
    _remember_endpoint(state, page.url, "GET")
    try:
        links = page.eval_on_selector_all(
            "a[href]",
            """els => els.slice(0, 120).map(a => ({
                text: (a.innerText || a.textContent || '').trim(),
                href: a.href
            }))""",
        )
    except Exception:
        links = []
    try:
        forms = page.eval_on_selector_all(
            "form",
            """forms => forms.slice(0, 40).map(f => ({
                method: (f.method || 'GET').toUpperCase(),
                action: f.action || location.href,
                text: (f.innerText || '').trim().slice(0, 180),
                inputs: Array.from(f.querySelectorAll('input, textarea, select'))
                    .slice(0, 30)
                    .map(i => ({
                        name: i.name || i.id || '',
                        type: i.type || i.tagName.toLowerCase(),
                        value: i.value || ''
                    }))
            }))""",
        )
    except Exception:
        forms = []
    try:
        buttons = page.eval_on_selector_all(
            "button, input[type=submit], input[type=button], [role=button]",
            """els => els.slice(0, 80).map((el, index) => ({
                index,
                text: (el.innerText || el.value || el.getAttribute('aria-label') || '').trim(),
                type: el.type || el.tagName.toLowerCase()
            }))""",
        )
    except Exception:
        buttons = []

    for link in links:
        href = link.get("href")
        if not href:
            continue
        if _same_origin(state.target, href) and not _is_static(href):
            continue
        state.external_links.add(href)

    _append_unique(
        state.pages,
        {
            "label": label,
            "url": page.url,
            "endpoint": _endpoint(page.url),
            "title": page.title(),
            "status": response.status if response else None,
            "links": [
                {"text": _trim(link.get("text")), "href": link.get("href")}
                for link in links
                if link.get("href") and _same_origin(state.target, link.get("href")) and not _is_static(link.get("href"))
            ],
            "forms": forms,
            "buttons": buttons,
            "timestamp": _now_iso(),
        },
        ("url", "label"),
    )

    for form in forms:
        action_url = form.get("action") or page.url
        if not _same_origin(state.target, action_url):
            continue
        state.http_traffic.append({
            "method": form.get("method", "GET"),
            "url": action_url,
            "headers": {},
            "postData": None,
            "response_status": None,
            "response_headers": {},
            "resource_type": "form",
            "response_body": None,
            "parent_url": page.url,
            "form_fields": form.get("inputs") or [],
            "timestamp": _now_iso(),
        })


def _candidate_score(candidate: dict[str, Any]) -> int:
    text = " ".join(str(candidate.get(k, "") or "") for k in ("label", "target_endpoint", "action_type")).lower()
    score = 0
    for token, value in (
        ("cart", 30),
        ("basket", 30),
        ("order", 25),
        ("checkout", 22),
        ("profile", 20),
        ("account", 20),
        ("admin", 18),
        ("product", 16),
        ("search", 10),
        ("login", -18),
        ("sign in", -18),
        ("register", -12),
        ("home", -10),
    ):
        if token in text:
            score += value
    if candidate.get("action_type") == "navigate":
        score += 4
    if candidate.get("action_type") == "click":
        score += 8
    return score


def _candidate_identity(candidate: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(candidate.get("current_endpoint") or ""),
        str(candidate.get("action_type") or ""),
        str(candidate.get("label") or "").strip().lower(),
        str(candidate.get("target_endpoint") or ""),
    )


def _explored_candidate_identities(state: GuidedState) -> set[tuple[str, str, str, str]]:
    identities: set[tuple[str, str, str, str]] = set()
    for chain in state.request_chains:
        if not isinstance(chain, dict):
            continue
        identities.add((
            str(chain.get("before_endpoint") or ""),
            str(chain.get("action_type") or ""),
            str(chain.get("label") or "").strip().lower(),
            str(chain.get("after_endpoint") or chain.get("target_endpoint") or ""),
        ))
    return identities


def _no_effect_candidate_identities(state: GuidedState) -> set[tuple[str, str, str]]:
    identities: set[tuple[str, str, str]] = set()
    for chain in state.request_chains:
        if not isinstance(chain, dict):
            continue
        if chain.get("emitted_requests"):
            continue
        if chain.get("before_endpoint") != chain.get("after_endpoint"):
            continue
        identities.add((
            str(chain.get("before_endpoint") or ""),
            str(chain.get("action_type") or ""),
            str(chain.get("label") or "").strip().lower(),
        ))
    return identities


def _fallback_candidate(candidates: list[dict[str, Any]], state: GuidedState | None = None) -> dict[str, Any] | None:
    explored = _explored_candidate_identities(state) if state else set()
    no_effect = _no_effect_candidate_identities(state) if state else set()
    memory_tried = state.memory.tried_actions if state else set()
    memory_no_effect = state.memory.no_effect_actions if state else set()
    uncovered_surfaces = (set(BUSINESS_SURFACE_KEYWORDS) - state.memory.covered_surfaces) if state else set()

    def utility(candidate: dict[str, Any]) -> int:
        text = " ".join(
            str(candidate.get(k, "") or "")
            for k in ("label", "target_endpoint", "action_type", "risk")
        ).lower()
        value = int(candidate.get("score") or 0)
        identity = _candidate_identity(candidate)
        if identity in explored or identity in memory_tried:
            value -= 120
        no_effect_key = (
            str(candidate.get("current_endpoint") or ""),
            str(candidate.get("action_type") or ""),
            str(candidate.get("label") or "").strip().lower(),
        )
        if no_effect_key in no_effect or no_effect_key in memory_no_effect:
            value -= 150
        candidate_surfaces = set(candidate.get("memory_surfaces") or _surface_matches(text))
        if candidate_surfaces & uncovered_surfaces:
            value += 32
        target_endpoint = str(candidate.get("target_endpoint") or "")
        if state and target_endpoint and target_endpoint not in state.memory.visited_endpoints:
            value += 22
        elif state and target_endpoint:
            value -= min(30, state.memory.repeated_endpoint_hits.get(target_endpoint, 0) * 8)
        if candidate.get("target_endpoint") == candidate.get("current_endpoint"):
            value -= 18
            if candidate.get("action_type") == "navigate":
                value -= 40
            if candidate.get("action_type") == "click" and "add" not in text and "product" not in text:
                value -= 35
        if any(word in text for word in HIGH_VALUE_ACTION_WORDS):
            value += 35
        if "search" in text and candidate.get("action_type") in {"navigate", "form"}:
            value += 20
        if any(word in text for word in LOW_VALUE_NAV_WORDS):
            value -= 45
        if candidate.get("action_type") == "click":
            value += 14
        if candidate.get("risk") == "bounded_state_changing":
            value += 18
        if candidate.get("risk") == "read_only_navigation":
            value += 6
        return value

    ranked = sorted(candidates, key=utility, reverse=True)
    if not ranked:
        return None
    return ranked[0] if utility(ranked[0]) > 0 else None


def _extract_action_candidates(page: Any, state: GuidedState) -> list[dict[str, Any]]:
    """Return bounded same-origin actions that an LLM may choose from."""
    candidates: list[dict[str, Any]] = []
    current_url = page.url
    current_endpoint = _endpoint(current_url)

    def add_candidate(item: dict[str, Any]) -> None:
        item["action_id"] = f"A{len(candidates) + 1:02d}"
        item["current_endpoint"] = current_endpoint
        memory_text = " ".join(str(item.get(k, "") or "") for k in ("label", "target_endpoint", "risk"))
        item["memory_surfaces"] = _surface_matches(memory_text)
        item["memory_seen"] = _candidate_identity(item) in state.memory.tried_actions
        item["score"] = _candidate_score(item)
        candidates.append(item)

    try:
        links = page.eval_on_selector_all(
            "a[href]",
            """els => els.slice(0, 160).map((a, index) => ({
                index,
                text: (a.innerText || a.textContent || '').trim(),
                href: a.href
            }))""",
        )
    except Exception:
        links = []
    seen_targets: set[str] = set()
    for link in links:
        href = str(link.get("href") or "")
        if not href or href in seen_targets:
            continue
        if not _same_origin(state.target, href) or _is_static(href):
            continue
        label = _trim(link.get("text"), 120) or _endpoint(href)
        if _is_blocked_navigation(f"{label} {href}"):
            continue
        seen_targets.add(href)
        add_candidate({
            "action_type": "navigate",
            "label": label,
            "target_url": href,
            "target_endpoint": _endpoint(href),
            "risk": "read_only_navigation",
            "source": "link",
        })

    button_selector = "button, input[type=submit], input[type=button], [role=button]"
    try:
        buttons = page.eval_on_selector_all(
            button_selector,
            """els => els.slice(0, 80).map((el, index) => ({
                index,
                text: (el.innerText || el.value || el.getAttribute('aria-label') || '').trim(),
                type: el.type || el.tagName.toLowerCase()
            }))""",
        )
    except Exception:
        buttons = []
    for button in buttons:
        label = _trim(button.get("text"), 120) or f"button[{button.get('index', 0)}]"
        policy_text = f"{label} {button.get('type', '')}"
        if _is_blocked_action(policy_text) and not _is_allowed_stateful_click(policy_text):
            continue
        if not _is_allowed_stateful_click(policy_text):
            continue
        add_candidate({
            "action_type": "click",
            "label": label,
            "selector": button_selector,
            "index": int(button.get("index") or 0),
            "target_url": current_url,
            "target_endpoint": current_endpoint,
            "risk": "bounded_state_changing" if "add" in policy_text.lower() else "safe_click",
            "source": "button",
        })

    try:
        forms = page.eval_on_selector_all(
            "form",
            """forms => forms.slice(0, 40).map((f, index) => ({
                index,
                method: (f.method || 'GET').toUpperCase(),
                action: f.action || location.href,
                text: (f.innerText || '').trim().slice(0, 180),
                inputs: Array.from(f.querySelectorAll('input, textarea, select'))
                    .slice(0, 30)
                    .map(i => ({name: i.name || i.id || '', type: i.type || i.tagName.toLowerCase(), value: i.value || ''}))
            }))""",
        )
    except Exception:
        forms = []
    for form in forms:
        action_url = str(form.get("action") or current_url)
        method = str(form.get("method") or "GET").upper()
        fields = [
            str(item.get("name") or "")
            for item in (form.get("inputs") or [])
            if isinstance(item, dict) and item.get("name")
        ]
        label = _trim(form.get("text"), 100) or f"{method} {_endpoint(action_url)}"
        policy_text = f"{method} {action_url} {label} {' '.join(fields)}"
        if not _same_origin(state.target, action_url) or _is_blocked_action(policy_text):
            continue
        if method not in {"GET", "POST"}:
            continue
        if method == "POST" and not _is_allowed_stateful_click(policy_text):
            continue
        add_candidate({
            "action_type": "form",
            "label": label,
            "selector": "form",
            "index": int(form.get("index") or 0),
            "method": method,
            "fields": fields[:10],
            "target_url": action_url,
            "target_endpoint": _endpoint(action_url),
            "risk": "bounded_state_changing" if method == "POST" else "read_only_form",
            "source": "form",
        })

    candidates = sorted(candidates, key=lambda item: item.get("score", 0), reverse=True)
    for index, candidate in enumerate(candidates[:AI_ACTION_CANDIDATE_LIMIT], 1):
        candidate["action_id"] = f"A{index:02d}"
    bounded = candidates[:AI_ACTION_CANDIDATE_LIMIT]
    for item in bounded:
        _append_unique(
            state.action_candidates,
            {
                **item,
                "page_url": current_url,
                "page_endpoint": current_endpoint,
                "timestamp": _now_iso(),
            },
            ("page_endpoint", "action_type", "label", "target_endpoint"),
        )
    return bounded


def _goto(page: Any, state: GuidedState, url: str, label: str, timeout_ms: int) -> None:
    before = page.url
    _progress(f"crawling endpoint {_endpoint(url)}")
    try:
        response = page.goto(url, wait_until="networkidle", timeout=timeout_ms)
        _capture_page(page, state, label, response)
        _record_action(state, f"goto:{label}", "ok", before, page.url, {"target": url})
    except Exception as exc:
        _capture_page(page, state, f"{label}:partial")
        _record_action(state, f"goto:{label}", "error", before, page.url, {"target": url, "error": str(exc)})
        state.notes.append(f"Navigation failed for {url}: {exc}")


def _click_first(page: Any, state: GuidedState, name: str, selectors: list[str], timeout_ms: int) -> bool:
    before = page.url
    for selector in selectors:
        try:
            locator = page.locator(selector)
            count = min(locator.count(), 12)
            for index in range(count):
                item = locator.nth(index)
                if not item.is_visible(timeout=800):
                    continue
                label = _trim(item.inner_text(timeout=800), 120) or ""
                if _is_blocked_action(f"{name} {selector} {label}"):
                    continue
                _progress(f"crawling action {name}: {label or selector}")
                item.click(timeout=timeout_ms)
                page.wait_for_load_state("networkidle", timeout=timeout_ms)
                _capture_page(page, state, name)
                _record_action(state, name, "ok", before, page.url, {"selector": selector, "index": index, "text": label})
                return True
        except Exception:
            continue
    _record_action(state, name, "not_found", before, page.url, {"selectors": selectors})
    return False


def _compact_request_for_chain(request: dict[str, Any]) -> dict[str, Any]:
    return {
        "method": request.get("method", ""),
        "endpoint": _endpoint(str(request.get("url") or "")),
        "status": request.get("response_status"),
        "resource_type": request.get("resource_type", ""),
        "postData": _trim(request.get("postData"), 240),
        "json_keys": (request.get("response_json_keys") or [])[:8],
        "numeric_fields": (request.get("response_numeric_fields") or [])[:8],
        "id_fields": (request.get("response_id_fields") or [])[:8],
    }


def _append_request_chain(
    state: GuidedState,
    candidate: dict[str, Any],
    before_url: str,
    after_url: str,
    start_request_index: int,
    status: str,
    reason: str = "",
) -> None:
    emitted = [
        _compact_request_for_chain(req)
        for req in state.http_traffic[start_request_index:start_request_index + 20]
        if isinstance(req, dict) and req.get("url")
    ]
    for req in emitted:
        _remember_endpoint(state, str(req.get("endpoint") or ""), str(req.get("method") or ""))
    changed_endpoint = _endpoint(before_url) != _endpoint(after_url)
    chain = {
        "action_id": candidate.get("action_id", ""),
        "action_type": candidate.get("action_type", ""),
        "label": candidate.get("label", ""),
        "reason": reason or candidate.get("reason", ""),
        "risk": candidate.get("risk", ""),
        "before_url": before_url,
        "after_url": after_url,
        "before_endpoint": _endpoint(before_url),
        "after_endpoint": _endpoint(after_url),
        "status": status,
        "emitted_requests": emitted,
        "emitted_request_count": len(emitted),
        "changed_endpoint": changed_endpoint,
        "effect": "request_or_navigation" if emitted or changed_endpoint else "no_effect",
        "timestamp": _now_iso(),
    }
    state.request_chains.append(chain)

    if emitted:
        for req in emitted[:8]:
            endpoint = req.get("endpoint") or ""
            state.business_chain.append({
                "step": f"ai_guided:{candidate.get('label', candidate.get('action_type', 'action'))}",
                "method": req.get("method", ""),
                "endpoint": endpoint,
                "status": req.get("status", ""),
                "state_before": _endpoint(before_url),
                "state_after": _endpoint(after_url),
                "action_id": candidate.get("action_id", ""),
                "action_type": candidate.get("action_type", ""),
                "reason": reason or candidate.get("reason", ""),
                "json_keys": req.get("json_keys", []),
                "numeric_fields": req.get("numeric_fields", []),
                "id_fields": req.get("id_fields", []),
            })
    elif candidate.get("action_type") == "navigate" and changed_endpoint:
        state.business_chain.append({
            "step": f"ai_guided:navigate:{candidate.get('label', '')}",
            "method": "GET",
            "endpoint": _endpoint(after_url),
            "status": "",
            "state_before": _endpoint(before_url),
            "state_after": _endpoint(after_url),
            "action_id": candidate.get("action_id", ""),
            "action_type": "navigate",
            "reason": reason or candidate.get("reason", ""),
        })
    _remember_candidate(state, candidate, after_url, len(emitted))


def _execute_action_candidate(page: Any, state: GuidedState, candidate: dict[str, Any], timeout_ms: int, reason: str) -> bool:
    before = page.url
    start_request_index = len(state.http_traffic)
    action_type = candidate.get("action_type")
    status = "error"
    try:
        if action_type == "navigate":
            _goto(page, state, str(candidate.get("target_url") or state.target), f"ai:{candidate.get('action_id')}", timeout_ms)
            status = "ok"
        elif action_type == "click":
            locator = page.locator(str(candidate.get("selector") or "button"))
            item = locator.nth(int(candidate.get("index") or 0))
            item.click(timeout=timeout_ms)
            try:
                page.wait_for_load_state("networkidle", timeout=timeout_ms)
            except Exception:
                pass
            _capture_page(page, state, f"ai:{candidate.get('action_id')}")
            _record_action(
                state,
                f"ai_click:{candidate.get('action_id')}",
                "ok",
                before,
                page.url,
                {"label": candidate.get("label", ""), "reason": reason, "risk": candidate.get("risk", "")},
            )
            status = "ok"
        elif action_type == "form":
            form = page.locator("form").nth(int(candidate.get("index") or 0))
            submit = form.locator("input[type=submit], button[type=submit], button, input[type=button]").first
            if submit.count() >= 1:
                submit.click(timeout=timeout_ms)
            else:
                page.evaluate("form => form.requestSubmit ? form.requestSubmit() : form.submit()", form.element_handle())
            try:
                page.wait_for_load_state("networkidle", timeout=timeout_ms)
            except Exception:
                pass
            _capture_page(page, state, f"ai:{candidate.get('action_id')}")
            _record_action(
                state,
                f"ai_form:{candidate.get('action_id')}",
                "ok",
                before,
                page.url,
                {"label": candidate.get("label", ""), "reason": reason, "risk": candidate.get("risk", "")},
            )
            status = "ok"
        else:
            return False
    except Exception as exc:
        state.notes.append(f"AI action failed for {candidate.get('action_id')}: {str(exc)[:180]}")
        _record_action(
            state,
            f"ai:{candidate.get('action_id')}",
            "error",
            before,
            page.url,
            {"label": candidate.get("label", ""), "reason": reason, "error": str(exc)[:240]},
        )
        status = "error"
    finally:
        _append_request_chain(state, candidate, before, page.url, start_request_index, status, reason)
    emitted_count = len(state.http_traffic) - start_request_index
    changed_endpoint = _endpoint(before) != _endpoint(page.url)
    return status == "ok" and (emitted_count > 0 or changed_endpoint)


def _safe_explore(page: Any, state: GuidedState, timeout_ms: int) -> None:
    _click_first(
        page,
        state,
        "dismiss_overlay",
        [
            "button:has-text('Dismiss')",
            "button:has-text('Me want it!')",
            "button:has-text('Accept')",
            "button:has-text('Close')",
            "button[aria-label*='Close']",
        ],
        timeout_ms,
    )
    _click_first(
        page,
        state,
        "open_product",
            [
                "a[href*='/product/']",
                ".product-card a",
                "mat-card button[aria-label*='detail']",
            ],
            timeout_ms,
        )
    _click_first(
        page,
        state,
        "add_to_basket",
        [
            "button:has-text('Add to Basket')",
            "button[aria-label*='Add to Basket']",
            "button:has-text('Thêm vào giỏ')",
            "form[action*='cart/add'] button",
            "input[type=submit][value*='Add']",
        ],
        timeout_ms,
    )


def _planner_json_from_text(text: str) -> dict[str, Any]:
    text = (text or "").strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except Exception:
        pass
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return {}
    try:
        return json.loads(match.group(0))
    except Exception:
        return {}


def _message_text(message: Any) -> str:
    text = getattr(message, "content", None) or ""
    if text:
        return text
    for attr in ("reasoning_content", "reasoning", "response"):
        value = getattr(message, attr, None)
        if isinstance(value, str) and value.strip():
            return value
    extra = getattr(message, "model_extra", None)
    if isinstance(extra, dict):
        for key in ("reasoning_content", "reasoning", "content"):
            value = extra.get(key)
            if isinstance(value, str) and value.strip():
                return value
    return ""


def _build_planner_messages(state: GuidedState, candidates: list[dict[str, Any]], step_index: int, max_steps: int) -> list[dict[str, str]]:
    recent_requests = [
        _compact_request_for_chain(req)
        for req in state.http_traffic[-12:]
        if isinstance(req, dict) and req.get("url")
    ]
    recent_actions = [
        {
            "name": item.get("name"),
            "status": item.get("status"),
            "from": _endpoint(str(item.get("before_url") or "")),
            "to": _endpoint(str(item.get("after_url") or "")),
        }
        for item in state.observed_actions[-10:]
        if isinstance(item, dict)
    ]
    compact_candidates = [
        {
            "action_id": c.get("action_id"),
            "action_type": c.get("action_type"),
            "label": c.get("label"),
            "current_endpoint": c.get("current_endpoint"),
            "target_endpoint": c.get("target_endpoint"),
            "risk": c.get("risk"),
            "method": c.get("method", ""),
            "fields": c.get("fields", []),
            "score": c.get("score", 0),
            "memory_seen": c.get("memory_seen", False),
            "memory_surfaces": c.get("memory_surfaces", []),
        }
        for c in candidates
    ]
    explored = [
        {
            "from": item[0],
            "action_type": item[1],
            "label": item[2],
            "to": item[3],
        }
        for item in sorted(_explored_candidate_identities(state))[-12:]
    ]
    system = (
        "Ban la AI crawl planner cho cong cu authorized security testing. "
        "Muc tieu: chon mot buoc an toan nhat nhung co gia tri cao de map web workflow, "
        "business logic, request chaining, auth/account/order/cart/admin surfaces. "
        "Chi duoc chon action_id trong danh sach candidate. Khong chon checkout/payment/delete/logout/confirm. "
        "Tra ve JSON thuan: {\"action_id\":\"A01\"|\"STOP\", \"reason\":\"ly do ngan\"}."
    )
    user = {
        "step": step_index + 1,
        "max_steps": max_steps,
        "target": state.target,
        "recent_page_endpoints": _compact_endpoint_list(state.pages, 12),
        "recent_actions": recent_actions,
        "recent_requests": recent_requests,
        "known_business_chain_len": len(state.business_chain),
        "crawl_memory": _memory_snapshot(state),
        "already_explored_actions": explored,
        "candidates": compact_candidates,
        "selection_policy": [
            "Prefer actions that reveal account/profile/cart/order/admin/product workflow map.",
            "Prefer actions that cover crawl_memory.coverage_gaps.",
            "Avoid candidates with memory_seen=true unless no other useful candidate remains.",
            "Prefer a new endpoint or action not already present in recent_actions.",
            "Prefer bounded add-to-cart/search/profile/order navigation over generic homepage links.",
            "Avoid login/register/home unless no higher-value workflow candidates remain.",
            "Avoid choosing an action whose target endpoint equals the current endpoint unless it emits a useful request.",
            "Return STOP if all useful candidates were already explored or look destructive.",
        ],
    }
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(user, ensure_ascii=False)},
    ]


def _ai_guided_explore(page: Any, state: GuidedState, ai_config: dict[str, Any], timeout_ms: int) -> None:
    if not ai_config.get("enabled"):
        if ai_config.get("requested"):
            state.notes.append("AI-guided crawl disabled: missing model/base_url or zero steps.")
        return
    try:
        from openai import OpenAI
    except Exception as exc:
        state.notes.append(f"AI-guided crawl disabled: openai import failed: {exc}")
        return

    client = OpenAI(api_key=ai_config.get("api_key") or "unused", base_url=ai_config.get("base_url"))
    max_steps = int(ai_config.get("steps") or AI_DEFAULT_STEPS)
    model = str(ai_config.get("model") or "")
    for step_index in range(max_steps):
        candidates = _extract_action_candidates(page, state)
        if not candidates:
            state.ai_decisions.append({
                "step": step_index + 1,
                "action_id": "STOP",
                "reason": "no candidates",
                "timestamp": _now_iso(),
            })
            return
        messages = _build_planner_messages(state, candidates, step_index, max_steps)
        content = ""
        decision: dict[str, Any] = {}
        try:
            for attempt in range(2):
                _progress(f"AI planner selecting crawl action {step_index + 1}/{max_steps}")
                response = client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=0,
                    max_tokens=450,
                )
                content = _message_text(response.choices[0].message)
                decision = _planner_json_from_text(content)
                if decision:
                    break
                messages = messages + [{
                    "role": "user",
                    "content": (
                        "Previous response was empty or invalid. Return only valid JSON like "
                        "{\"action_id\":\"A01\", \"reason\":\"short reason\"} or "
                        "{\"action_id\":\"STOP\", \"reason\":\"no useful candidates\"}."
                    ),
                }]
        except Exception as exc:
            state.notes.append(f"AI planner failed: {str(exc)[:220]}")
            return

        raw_action_id = (
            decision.get("action_id")
            or decision.get("selected_action_id")
            or decision.get("action")
            or decision.get("id")
            or ""
        )
        action_id = str(raw_action_id).strip()
        reason = (
            _trim(decision.get("reason"), 240)
            or _trim(decision.get("rationale"), 240)
            or _trim(decision.get("why"), 240)
            or "no reason"
        )
        selected = next((item for item in candidates if item.get("action_id") == action_id), None)
        if not decision:
            selected = _fallback_candidate(candidates, state)
            if selected:
                action_id = str(selected.get("action_id") or "STOP")
                reason = "planner_invalid_fallback: selected highest-value safe candidate"
            else:
                action_id = "STOP"
        elif action_id.upper() != "STOP" and not selected:
            selected = _fallback_candidate(candidates, state)
            if selected:
                action_id = str(selected.get("action_id") or "STOP")
                reason = f"planner_unknown_action_fallback: {reason}"
            else:
                action_id = "STOP"
        state.ai_decisions.append({
            "step": step_index + 1,
            "action_id": action_id,
            "reason": reason,
            "model": model,
            "candidate_count": len(candidates),
            "raw_response": _trim(content, 500),
            "timestamp": _now_iso(),
        })
        if not selected or action_id.upper() == "STOP":
            return
        selected["reason"] = reason
        meaningful = _execute_action_candidate(page, state, selected, timeout_ms, reason)
        if not meaningful:
            state.ai_decisions[-1]["effect"] = "no_request_or_url_change"
            return


def _record_api_response(
    state: GuidedState,
    method: str,
    url: str,
    response: Any,
    *,
    request_body: Any = None,
    parent_url: str = "guided_api_probe",
) -> dict[str, Any]:
    try:
        body = response.text()
    except Exception as exc:
        body = ""
        body_error = str(exc)[:240]
    else:
        body_error = ""
    body = body[:RESPONSE_BODY_LIMIT] if body else ""
    keys, numeric_fields, id_fields = _json_summary(body)
    entry = {
        "method": method.upper(),
        "url": url,
        "headers": {},
        "postData": json.dumps(request_body, ensure_ascii=False) if request_body is not None else None,
        "response_status": response.status,
        "response_headers": dict(response.headers),
        "resource_type": "fetch",
        "response_body": body,
        "parent_url": parent_url,
        "form_fields": None,
        "timestamp": _now_iso(),
        "guided_probe": True,
    }
    if keys:
        entry["response_json_keys"] = keys
    if numeric_fields:
        entry["response_numeric_fields"] = numeric_fields
    if id_fields:
        entry["response_id_fields"] = id_fields
    if body_error:
        entry["body_capture_error"] = body_error
    state.http_traffic.append(entry)
    return entry


def _parse_json_body(entry: dict[str, Any]) -> Any:
    try:
        return json.loads(entry.get("response_body") or "")
    except Exception:
        return None


def _verify_auth_bootstrap(context: Any, state: GuidedState, values: dict[str, str]) -> None:
    token = values.get("token", "")
    state.auth_bootstrap = {
        "has_token": bool(token),
        "verified": False,
        "checks": [],
    }
    headers = {"Accept": "application/json,text/html,*/*"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    for path in ("/api/me", "/api/users/me", "/api/user/me", "/me", "/profile", "/account"):
        try:
            verify_url = urljoin(state.target + "/", path.lstrip("/"))
            response = context.request.get(verify_url, headers=headers, timeout=8000)
            entry = _record_api_response(state, "GET", verify_url, response, parent_url="auth_bootstrap")
            state.auth_bootstrap["checks"].append({
                "endpoint": _endpoint(verify_url),
                "status": response.status,
                "json_keys": entry.get("response_json_keys", []),
            })
            if response.status < 400:
                state.auth_bootstrap["verified"] = True
                return
        except Exception as exc:
            state.auth_bootstrap["checks"].append({"endpoint": path, "error": str(exc)[:240]})
    state.auth_bootstrap["reason"] = "no_generic_auth_probe_succeeded"


def _guided_business_api_probe(context: Any, state: GuidedState, values: dict[str, str]) -> None:
    """Run bounded read-only authenticated probes without target-specific mutations."""
    token = values.get("token", "")
    headers = {
        "Accept": "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    for path in ("/api/orders", "/api/cart", "/api/account", "/api/profile", "/orders", "/cart", "/account"):
        try:
            probe_url = urljoin(state.target + "/", path.lstrip("/"))
            _progress(f"crawling read-only api GET {_endpoint(probe_url)}")
            response = context.request.get(probe_url, headers=headers, timeout=8000)
            entry = _record_api_response(state, "GET", probe_url, response, parent_url="read_only_api_probe")
            if response.status < 500:
                state.business_chain.append({
                    "step": "read_only_api_probe",
                    "method": "GET",
                    "endpoint": _endpoint(probe_url),
                    "status": response.status,
                    "json_keys": entry.get("response_json_keys", [])[:8],
                })
        except Exception as exc:
            state.notes.append(f"Read-only API probe failed for {path}: {str(exc)[:160]}")


def _add_api_hint(state: GuidedState, method: str, path: str, source: str, reason: str) -> None:
    if not path.startswith("/"):
        path = "/" + path
    marker = (method.upper(), path)
    for hint in state.api_hints:
        if (hint.get("method"), hint.get("path")) == marker:
            return
    state.api_hints.append({
        "method": method.upper(),
        "path": path,
        "source": source,
        "reason": reason,
    })


def _extract_static_api_hints(page: Any, context: Any, state: GuidedState) -> None:
    try:
        script_urls = page.eval_on_selector_all(
            "script[src]",
            "els => els.map(s => s.src).filter(Boolean)",
        )
    except Exception:
        script_urls = []

    for script_url in script_urls[:10]:
        if not _same_origin(state.target, script_url):
            continue
        try:
            response = context.request.get(script_url, timeout=8000)
            if response.status >= 400:
                continue
            text = response.text()
        except Exception:
            continue
        source = _endpoint(script_url)
        for match in re.finditer(r"['\"`](/(?:api|rest)/[A-Za-z0-9_./${}:?=&-]+)", text):
            raw_path = match.group(1)
            path = re.sub(r"\$\{[^}]+\}", "{id}", raw_path)
            method_window = text[max(0, match.start() - 80):match.start()].lower()
            method = "GET"
            for candidate in ("post", "put", "patch", "delete", "get"):
                if f".{candidate}" in method_window:
                    method = candidate.upper()
                    break
            _add_api_hint(state, method, path, source, "static_js_literal")


def _route_sweep(page: Any, state: GuidedState, timeout_ms: int) -> None:
    for fragment in SAFE_HASH_ROUTES:
        if len(state.pages) >= state.max_pages:
            break
        target = urljoin(state.target + "/", fragment)
        _goto(page, state, target, f"route:{fragment}", timeout_ms)
        if fragment == "#/search":
            _safe_explore(page, state, timeout_ms)


def _build_workflow_graph(state: GuidedState) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    def ensure_node(url: str, kind: str, title: str | None = None) -> str:
        node_id = _endpoint(url)
        node = nodes.setdefault(node_id, {"id": node_id, "kind": kind, "url": _safe_url(url), "methods": []})
        if title and not node.get("title"):
            node["title"] = title
        return node_id

    for page in state.pages:
        ensure_node(page["url"], "page", page.get("title"))
        for link in page.get("links") or []:
            href = link.get("href")
            if href and _same_origin(state.target, href):
                ensure_node(href, "page")
                edges.append({"from": _endpoint(page["url"]), "to": _endpoint(href), "type": "link"})
        for form in page.get("forms") or []:
            action = form.get("action") or page["url"]
            method = form.get("method", "GET")
            node_id = ensure_node(action, "endpoint")
            if method not in nodes[node_id]["methods"]:
                nodes[node_id]["methods"].append(method)
            edges.append({"from": _endpoint(page["url"]), "to": node_id, "type": "form", "method": method})

    for request in state.http_traffic:
        url = request.get("url")
        if not url:
            continue
        node_id = ensure_node(url, "endpoint")
        method = request.get("method")
        if method and method not in nodes[node_id]["methods"]:
            nodes[node_id]["methods"].append(method)
        parent = request.get("parent_url")
        if parent and _same_origin(state.target, parent):
            edges.append({
                "from": _endpoint(parent),
                "to": node_id,
                "type": "request",
                "method": method,
                "status": request.get("response_status"),
            })

    for action in state.observed_actions:
        before = action.get("before_url")
        after = action.get("after_url")
        if before and after and _same_origin(state.target, before) and _same_origin(state.target, after):
            edges.append({"from": _endpoint(before), "to": _endpoint(after), "type": "observed_action", "label": action.get("name")})

    for chain in state.request_chains:
        before_ep = chain.get("before_endpoint") or _endpoint(str(chain.get("before_url") or ""))
        after_ep = chain.get("after_endpoint") or _endpoint(str(chain.get("after_url") or ""))
        if before_ep and after_ep:
            nodes.setdefault(before_ep, {"id": before_ep, "kind": "page", "url": urljoin(state.target + "/", before_ep.lstrip("/")), "methods": []})
            nodes.setdefault(after_ep, {"id": after_ep, "kind": "page", "url": urljoin(state.target + "/", after_ep.lstrip("/")), "methods": []})
            edges.append({
                "from": before_ep,
                "to": after_ep,
                "type": "request_chain",
                "label": chain.get("label"),
                "action_id": chain.get("action_id"),
                "status": chain.get("status"),
            })
        previous_ep = before_ep
        for request in chain.get("emitted_requests") or []:
            endpoint = request.get("endpoint")
            if not endpoint:
                continue
            node = nodes.setdefault(endpoint, {"id": endpoint, "kind": "endpoint", "url": urljoin(state.target + "/", endpoint.lstrip("/")), "methods": []})
            method = request.get("method")
            if method and method not in node["methods"]:
                node["methods"].append(method)
            edges.append({
                "from": previous_ep,
                "to": endpoint,
                "type": "chain_request",
                "method": method,
                "status": request.get("status"),
                "action_id": chain.get("action_id"),
            })
            previous_ep = endpoint

    previous = "/__auth_bootstrap"
    if state.business_chain:
        nodes.setdefault(previous, {"id": previous, "kind": "workflow", "url": previous, "methods": []})
    for step in state.business_chain:
        endpoint = step.get("endpoint")
        if not endpoint:
            continue
        node = nodes.setdefault(endpoint, {"id": endpoint, "kind": "endpoint", "url": urljoin(state.target + "/", endpoint.lstrip("/")), "methods": []})
        method = step.get("method")
        if method and method not in node["methods"]:
            node["methods"].append(method)
        edges.append({
            "from": previous,
            "to": endpoint,
            "type": "business_chain",
            "method": method,
            "status": step.get("status"),
            "label": step.get("step"),
        })
        previous = endpoint

    unique_edges: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for edge in edges:
        marker = (edge.get("from"), edge.get("to"), edge.get("type"), edge.get("method"), edge.get("label"))
        if marker not in seen:
            seen.add(marker)
            unique_edges.append(edge)
    return {
        "nodes": sorted(nodes.values(), key=lambda item: item["id"]),
        "edges": unique_edges,
        "heuristics": [
            "Nodes are observed pages and same-origin endpoints.",
            "Edges are inferred from links, forms, browser requests, and guided actions.",
            "AI-guided request_chain edges preserve action before/after and emitted request order.",
            "Destructive actions are skipped by keyword policy.",
        ],
    }


def _evaluate_graph_coverage(state: GuidedState, graph: dict[str, Any] | None = None) -> dict[str, Any]:
    """Score post-crawl graph coverage for BAC/BLF-oriented follow-up planning."""
    graph = graph or _build_workflow_graph(state)
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    node_ids = [str(node.get("id", "") or "") for node in nodes if isinstance(node, dict)]
    edge_texts = [
        " ".join(str(edge.get(key, "") or "") for key in ("from", "to", "type", "method", "label"))
        for edge in edges
        if isinstance(edge, dict)
    ]
    combined_by_surface = {
        surface: "\n".join(node_ids + edge_texts)
        for surface in BUSINESS_SURFACE_KEYWORDS
    }
    surfaces: dict[str, dict[str, Any]] = {}
    for surface, keywords in BUSINESS_SURFACE_KEYWORDS.items():
        text = combined_by_surface[surface].lower()
        matched = [keyword for keyword in keywords if keyword in text]
        surface_nodes = [
            node_id for node_id in node_ids
            if any(keyword in node_id.lower() for keyword in keywords)
        ][:20]
        surface_edges = [
            edge for edge in edges
            if any(keyword in " ".join(str(edge.get(k, "") or "") for k in ("from", "to", "label")).lower() for keyword in keywords)
        ][:20]
        surfaces[surface] = {
            "covered": bool(matched),
            "matched_keywords": matched,
            "nodes": surface_nodes,
            "edge_count": len(surface_edges),
        }

    state_changing_edges = [
        edge for edge in edges
        if str(edge.get("method", "") or "").upper() in STATE_CHANGING_METHODS
    ]
    request_chain_edges = [edge for edge in edges if edge.get("type") in {"request_chain", "chain_request"}]
    form_edges = [edge for edge in edges if edge.get("type") == "form"]
    dead_end_pages = []
    outgoing: dict[str, int] = {}
    for edge in edges:
        frm = str(edge.get("from", "") or "")
        if frm:
            outgoing[frm] = outgoing.get(frm, 0) + 1
    for node in nodes:
        node_id = str(node.get("id", "") or "")
        if node.get("kind") == "page" and outgoing.get(node_id, 0) == 0:
            dead_end_pages.append(node_id)

    covered_count = sum(1 for surface in surfaces.values() if surface["covered"])
    score = 0
    score += min(40, covered_count * 10)
    score += min(20, len(request_chain_edges) * 4)
    score += min(15, len(state_changing_edges) * 5)
    score += min(15, len(form_edges) * 3)
    score += min(10, len(state.memory.state_changing_endpoints) * 3)
    score = min(100, score)

    recommendations: list[str] = []
    missing = [name for name, item in surfaces.items() if not item["covered"]]
    for surface in missing:
        recommendations.append(f"Explore {surface} routes/actions if in scope.")
    if not state_changing_edges and not state.memory.state_changing_endpoints:
        recommendations.append("No observed state-changing workflow edge; expand safe form/action planning.")
    if not request_chain_edges:
        recommendations.append("No guided request chains; increase AI steps or inspect candidate extraction.")
    if dead_end_pages:
        recommendations.append("Some page nodes have no outgoing edges; review crawler navigation/candidate extraction.")

    return {
        "score": score,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "covered_surface_count": covered_count,
        "surface_count": len(surfaces),
        "surfaces": surfaces,
        "state_changing_edge_count": len(state_changing_edges),
        "request_chain_edge_count": len(request_chain_edges),
        "form_edge_count": len(form_edges),
        "dead_end_pages": dead_end_pages[:20],
        "recommendations": recommendations[:12],
    }


def run_guided_crawl(args: argparse.Namespace) -> dict[str, Any]:
    started = time.monotonic()
    target = args.url.rstrip("/")
    state = GuidedState(target=target, max_pages=args.max_pages)
    ai_config = _crawl_ai_config(args)
    timeout_ms = max(3000, int(args.timeout) * 1000 if args.timeout < 1000 else int(args.timeout))
    timeout_ms = min(timeout_ms, 15000)

    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        return {
            "ok": False,
            "error": "missing_playwright",
            "message": str(exc),
            "http_traffic": [],
            "cookies": [],
            "external_links": [],
            "pages": [],
            "observed_actions": [],
            "action_candidates": [],
            "ai_decisions": [],
            "request_chains": [],
            "workflow_graph": {"nodes": [], "edges": []},
            "crawl_memory": {},
            "graph_coverage": {"score": 0, "node_count": 0, "edge_count": 0, "recommendations": []},
        }

    cookies: list[dict[str, Any]] = []
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=args.headless, args=["--no-sandbox", "--disable-dev-shm-usage"])
            context_kwargs: dict[str, Any] = {"ignore_https_errors": True}
            storage_values: dict[str, str] = {}
            if args.storage_state:
                state_path = Path(args.storage_state)
                if state_path.exists():
                    context_kwargs["storage_state"] = str(state_path)
                    storage_values = _storage_values_from_state(str(state_path), target)
            context = browser.new_context(**context_kwargs)
            extra_headers = _headers_from_cli(args.header)
            bearer = ""
            auth_value = extra_headers.get("Authorization") or extra_headers.get("authorization") or ""
            if auth_value.lower().startswith("bearer "):
                bearer = auth_value.split(" ", 1)[1].strip()
                storage_values.setdefault("token", bearer)
            if extra_headers:
                context.set_extra_http_headers(extra_headers)
            if storage_values:
                context.add_init_script(_auth_bootstrap_script(storage_values))
            header_cookies = _parse_cookie_header(args.cookie_header, target)
            if header_cookies:
                context.add_cookies(header_cookies)
            _verify_auth_bootstrap(context, state, storage_values)
            _guided_business_api_probe(context, state, storage_values)
            page = context.new_page()
            page.set_default_timeout(timeout_ms)
            _install_network_capture(page, state)
            _goto(page, state, target + "/", "home", timeout_ms)
            _extract_static_api_hints(page, context, state)
            _safe_explore(page, state, timeout_ms)
            _ai_guided_explore(page, state, ai_config, timeout_ms)
            _route_sweep(page, state, timeout_ms)
            try:
                cookies = context.cookies()
            except Exception:
                cookies = []
            context.close()
            browser.close()
    except Exception as exc:
        state.notes.append(f"Guided crawler interrupted: {exc}")

    _progress_done()
    workflow_graph = _build_workflow_graph(state)
    graph_coverage = _evaluate_graph_coverage(state, workflow_graph)
    return {
        "ok": True,
        "target": target,
        "generated_at": _now_iso(),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "http_traffic": state.http_traffic,
        "cookies": cookies,
        "external_links": sorted(state.external_links),
        "pages": state.pages,
        "observed_actions": state.observed_actions,
        "action_candidates": state.action_candidates,
        "ai_decisions": state.ai_decisions,
        "request_chains": state.request_chains,
        "workflow_graph": workflow_graph,
        "crawl_memory": _memory_snapshot(state),
        "graph_coverage": graph_coverage,
        "api_hints": state.api_hints,
        "business_chain": state.business_chain,
        "auth_bootstrap": state.auth_bootstrap,
        "ai_guidance": {
            "requested": ai_config.get("requested", False),
            "enabled": ai_config.get("enabled", False),
            "model": ai_config.get("model", ""),
            "steps": ai_config.get("steps", 0),
            "decisions": len(state.ai_decisions),
        },
        "notes": state.notes,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Guided Playwright crawler for MARL recon.")
    parser.add_argument("--url", required=True)
    parser.add_argument("--max-pages", type=int, default=25)
    parser.add_argument("--max-rounds", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--headless", action="store_true")
    parser.add_argument("--storage-state", default="")
    parser.add_argument("--ai-guided", dest="ai_guided", action="store_true", default=None)
    parser.add_argument("--no-ai-guided", dest="ai_guided", action="store_false")
    parser.add_argument("--ai-steps", type=int, default=None)
    parser.add_argument("-H", "--header", action="append", default=[])
    args = parser.parse_args(argv)
    args.cookie_header = ""
    for header in args.header or []:
        if header.lower().startswith("cookie:"):
            args.cookie_header = header.split(":", 1)[1].strip()
    return args


def main(argv: list[str] | None = None) -> int:
    result = run_guided_crawl(parse_args(argv))
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("ok", False) else 1


if __name__ == "__main__":
    raise SystemExit(main())
