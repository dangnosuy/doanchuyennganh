"""
Standalone Playwright benchmark harness for the local TechShop target.

The harness intentionally does not import or modify the main MARL pipeline. It
visits a target, captures browser network traffic, performs a small set of safe
guided actions, and writes a JSON artifact with pages, requests, observed
actions, and a heuristic workflow graph.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse


DEFAULT_TARGET = "http://localhost:3000"
DEFAULT_USERNAME = "test@gmail.com"
DEFAULT_PASSWORD = "xinchao"
DEFAULT_OUTPUT = "workspace/crawl_benchmark.json"
BLOCKED_ACTION_WORDS = (
    "admin",
    "checkout",
    "confirm",
    "delete",
    "logout",
    "remove",
    "transfer",
)


@dataclass
class BenchmarkState:
    target: str
    pages: list[dict[str, Any]] = field(default_factory=list)
    requests: list[dict[str, Any]] = field(default_factory=list)
    observed_actions: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


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
        endpoint = f"{endpoint}?{parsed.query}"
    if parsed.fragment:
        endpoint = f"{endpoint}#{parsed.fragment}"
    return endpoint


def _is_blocked_action(text: str) -> bool:
    lower = (text or "").lower()
    return any(word in lower for word in BLOCKED_ACTION_WORDS)


def _append_unique(items: list[dict[str, Any]], item: dict[str, Any], keys: tuple[str, ...]) -> None:
    marker = tuple(item.get(key) for key in keys)
    for old in items:
        if tuple(old.get(key) for key in keys) == marker:
            return
    items.append(item)


def _trim(value: str | None, limit: int = 240) -> str | None:
    if value is None:
        return None
    compact = " ".join(str(value).split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."


def _record_action(
    state: BenchmarkState,
    name: str,
    status: str,
    before_url: str,
    after_url: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    state.observed_actions.append(
        {
            "name": name,
            "status": status,
            "before_url": before_url,
            "after_url": after_url,
            "detail": detail or {},
            "timestamp": _now_iso(),
        }
    )


def _install_network_capture(page: Any, state: BenchmarkState) -> None:
    request_meta: dict[Any, dict[str, Any]] = {}

    def on_request(request: Any) -> None:
        if not _same_origin(state.target, request.url):
            return
        request_meta[request] = {
            "method": request.method,
            "url": request.url,
            "endpoint": _endpoint(request.url),
            "resource_type": request.resource_type,
            "post_data": _trim(request.post_data, 1000),
            "headers": dict(request.headers),
            "parent_url": request.frame.url if request.frame else None,
            "status": None,
            "response_headers": {},
            "failed": False,
            "failure": None,
            "timestamp": _now_iso(),
        }

    def on_response(response: Any) -> None:
        request = response.request
        entry = request_meta.get(request)
        if entry is None:
            return
        entry["status"] = response.status
        entry["response_headers"] = dict(response.headers)

    def on_request_finished(request: Any) -> None:
        entry = request_meta.pop(request, None)
        if entry is not None:
            state.requests.append(entry)

    def on_request_failed(request: Any) -> None:
        entry = request_meta.pop(request, None)
        if entry is None:
            return
        entry["failed"] = True
        failure = request.failure
        if isinstance(failure, dict):
            entry["failure"] = failure.get("errorText") or str(failure)
        else:
            entry["failure"] = str(failure or "request failed")
        state.requests.append(entry)

    page.on("request", on_request)
    page.on("response", on_response)
    page.on("requestfinished", on_request_finished)
    page.on("requestfailed", on_request_failed)


def _capture_page(page: Any, state: BenchmarkState, label: str, response: Any | None = None) -> None:
    try:
        links = page.eval_on_selector_all(
            "a[href]",
            """els => els.slice(0, 80).map(a => ({
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
                    .slice(0, 20)
                    .map(i => ({name: i.name || '', type: i.type || i.tagName.toLowerCase()}))
            }))""",
        )
    except Exception:
        forms = []
    try:
        buttons = page.eval_on_selector_all(
            "button, input[type=submit], input[type=button], [role=button]",
            """els => els.slice(0, 60).map((el, index) => ({
                index,
                text: (el.innerText || el.value || el.getAttribute('aria-label') || '').trim(),
                type: el.type || el.tagName.toLowerCase()
            }))""",
        )
    except Exception:
        buttons = []

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
                if link.get("href") and _same_origin(state.target, link.get("href"))
            ],
            "forms": forms,
            "buttons": buttons,
            "timestamp": _now_iso(),
        },
        ("url", "label"),
    )


def _goto(page: Any, state: BenchmarkState, url: str, label: str) -> Any | None:
    before = page.url
    try:
        response = page.goto(url, wait_until="networkidle", timeout=15000)
        _capture_page(page, state, label, response)
        _record_action(state, f"goto:{label}", "ok", before, page.url, {"target": url})
        return response
    except Exception as exc:
        _record_action(state, f"goto:{label}", "error", before, page.url, {"target": url, "error": str(exc)})
        state.notes.append(f"Navigation failed for {url}: {exc}")
        return None


def _click_first(page: Any, state: BenchmarkState, name: str, selectors: list[str]) -> bool:
    before = page.url
    for selector in selectors:
        try:
            if selector.startswith("role=button:"):
                locator = page.get_by_role("button", name=re.compile(selector.split(":", 1)[1], re.I))
            else:
                locator = page.locator(selector)
            for index in range(min(locator.count(), 12)):
                item = locator.nth(index)
                if not item.is_visible(timeout=1200):
                    continue
                label = _trim(item.inner_text(timeout=1200))
                if _is_blocked_action(f"{selector} {label}"):
                    continue
                item.click(timeout=4000)
                wait_warning = None
                try:
                    page.wait_for_load_state("networkidle", timeout=2500)
                except Exception as exc:
                    wait_warning = str(exc)
                _capture_page(page, state, name)
                detail = {"selector": selector, "index": index, "text": label}
                if wait_warning:
                    detail["wait_warning"] = _trim(wait_warning)
                _record_action(
                    state,
                    name,
                    "ok",
                    before,
                    page.url,
                    detail,
                )
                return True
        except Exception:
            continue
    _record_action(state, name, "not_found", before, page.url, {"selectors": selectors})
    return False


def _try_login(page: Any, state: BenchmarkState, username: str, password: str) -> None:
    before = page.url
    opened = _click_first(
        page,
        state,
        "open_login",
        [
            "a[href*='login']",
            "button:has-text('Account')",
            "button[aria-label*='Account']",
            "text=/Đăng nhập|Login|Sign in/i",
        ],
    )
    if opened and page.locator("a[href*='login'], button:has-text('Login')").count() > 0:
        _click_first(page, state, "open_login_menu_item", ["a[href*='login']", "button:has-text('Login')"])
    if page.locator("input[name='username'], input[name='email'], input[type='email'], #email").count() < 1:
        _goto(page, state, urljoin(state.target + "/", "#/login"), "login_route")
    login_url = page.url
    action_before = page.url
    try:
        user_field = page.locator(
            "input[name='username'], input[name='email'], input[type='email'], input[autocomplete='username'], #email"
        ).first
        password_field = page.locator("input[name='password'], input[type='password'], #password").first
        if user_field.count() < 1 or password_field.count() < 1:
            _record_action(state, "login", "not_found", before, page.url, {"reason": "login fields not found"})
            return
        user_field.fill(username)
        password_field.fill(password)
        submit = page.locator(
            "#loginButton, form button[type=submit], form input[type=submit], button:has-text('Đăng nhập'), button:has-text('Log in'), button:has-text('Login')"
        ).first
        if submit.count() >= 1:
            submit.click(timeout=5000)
        else:
            password_field.press("Enter")
        page.wait_for_timeout(1000)
        wait_warning = None
        try:
            page.wait_for_load_state("networkidle", timeout=3500)
        except Exception as exc:
            wait_warning = str(exc)
        _capture_page(page, state, "after_login")
        logged_in = page.url != login_url
        if not logged_in:
            logged_in = page.locator("a[href*='logout']").count() > 0
        if not logged_in:
            logged_in = page.get_by_text("Logout").count() > 0 or page.get_by_text("Đăng xuất").count() > 0
        _record_action(
            state,
            "login",
            "ok" if logged_in else "attempted",
            action_before,
            page.url,
            {
                "username": username,
                "login_url": login_url,
                **({"wait_warning": _trim(wait_warning)} if wait_warning else {}),
            },
        )
    except Exception as exc:
        _record_action(state, "login", "error", action_before, page.url, {"error": str(exc)})


def _guided_actions(page: Any, state: BenchmarkState, username: str, password: str) -> None:
    _try_login(page, state, username, password)
    listing_selector = (
        "button:has-text('Add to Basket'), button[aria-label*='Add to Basket'], "
        "form[action*='cart/add'] button, a[href*='/product/']"
    )
    opened_products = _click_first(
        page,
        state,
        "open_products",
        [
            "a[href*='/products']",
            "a[href*='product']",
            "button:has-text('Products')",
            "button:has-text('Sản phẩm')",
        ],
    )
    if not opened_products and page.locator(listing_selector).count() < 1:
        if "OWASP Juice Shop" in page.title():
            _goto(page, state, urljoin(state.target + "/", "#/search"), "products")
        else:
            _goto(page, state, urljoin(state.target + "/", "products"), "products")
    opened_product = _click_first(
        page,
        state,
        "open_product",
        [
            "a[href*='/product/']",
            ".product-card a",
            "mat-card button[aria-label*='detail']",
            "mat-card:has-text('Apple Juice')",
            "[role=button]:has-text('Apple Juice')",
        ],
    )
    if opened_product:
        try:
            page.keyboard.press("Escape")
            page.wait_for_timeout(300)
        except Exception:
            pass
    else:
        state.notes.append("No product detail link found; continuing with add-to-basket from listing page.")
    _click_first(
        page,
        state,
        "add_to_basket",
        [
            "form[action*='cart/add'] button",
            "button:has-text('Thêm vào giỏ')",
            "role=button:Add to Basket",
            "mat-card button:has-text('Add to Basket')",
            ".mat-mdc-card button:has-text('Add to Basket')",
            "button:has-text('Add to Basket')",
            "button[aria-label*='Add to Basket']",
            "button:has-text('Add')",
            "input[type=submit][value*='Add']",
        ],
    )
    if not _click_first(
        page,
        state,
        "open_basket",
        [
            "a[href*='cart']",
            "a[href*='basket']",
            "button:has-text('Your Basket')",
            "button[aria-label*='Basket']",
            "text=/Giỏ hàng|Basket|Cart/i",
        ],
    ):
        _goto(page, state, urljoin(state.target + "/", "#/basket"), "basket_route")


def _build_workflow_graph(state: BenchmarkState) -> dict[str, Any]:
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
        for form in page.get("forms", []):
            action = form.get("action") or page["url"]
            method = form.get("method", "GET")
            node_id = ensure_node(action, "endpoint")
            if method not in nodes[node_id]["methods"]:
                nodes[node_id]["methods"].append(method)
            edges.append(
                {
                    "from": _endpoint(page["url"]),
                    "to": node_id,
                    "type": "form",
                    "method": method,
                    "label": _trim(form.get("text"), 80),
                }
            )

    for request in state.requests:
        node_id = ensure_node(request["url"], "endpoint")
        method = request.get("method")
        if method and method not in nodes[node_id]["methods"]:
            nodes[node_id]["methods"].append(method)
        parent = request.get("parent_url")
        if parent and _same_origin(state.target, parent):
            edges.append(
                {
                    "from": _endpoint(parent),
                    "to": node_id,
                    "type": "request",
                    "method": method,
                    "status": request.get("status"),
                }
            )

    for action in state.observed_actions:
        before = action.get("before_url")
        after = action.get("after_url")
        if before and after and _same_origin(state.target, before) and _same_origin(state.target, after):
            edges.append(
                {
                    "from": _endpoint(before),
                    "to": _endpoint(after),
                    "type": "observed_action",
                    "label": action.get("name"),
                    "status": action.get("status"),
                }
            )

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
            "Nodes are page URLs and same-origin endpoints observed in forms or network traffic.",
            "Edges are inferred from forms, frame-parent request URLs, and guided action before/after URLs.",
            "Destructive-looking actions such as logout, delete, remove, checkout, transfer, and admin are skipped.",
        ],
    }


def run_benchmark(args: argparse.Namespace) -> dict[str, Any]:
    state = BenchmarkState(target=args.target.rstrip("/"))
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        return {
            "ok": False,
            "error": "missing_dependency",
            "message": "Playwright Python is not installed. Install with: pip install playwright && playwright install chromium",
            "detail": str(exc),
            "generated_at": _now_iso(),
        }

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=not args.headful)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            page.set_default_timeout(args.timeout_ms)
            _install_network_capture(page, state)
            _goto(page, state, state.target + "/", "home")
            _guided_actions(page, state, args.username, args.password)
            context.close()
            browser.close()
    except Exception as exc:
        state.notes.append(f"Benchmark interrupted: {exc}")
        if "Executable doesn't exist" in str(exc) or "playwright install" in str(exc):
            state.notes.append("Playwright browser binaries may be missing. Run: playwright install chromium")

    return {
        "ok": True,
        "target": state.target,
        "credentials": {"username": args.username, "password": "***"},
        "generated_at": _now_iso(),
        "duration_hint": "guided safe crawl",
        "pages": state.pages,
        "requests": state.requests,
        "observed_actions": state.observed_actions,
        "workflow_graph": _build_workflow_graph(state),
        "notes": state.notes,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Standalone Playwright crawl benchmark graph harness.")
    parser.add_argument("--target", default=DEFAULT_TARGET, help=f"Target origin. Default: {DEFAULT_TARGET}")
    parser.add_argument("--username", default=DEFAULT_USERNAME, help="Login username/email.")
    parser.add_argument("--password", default=DEFAULT_PASSWORD, help="Login password.")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help=f"JSON output path. Default: {DEFAULT_OUTPUT}")
    parser.add_argument("--timeout-ms", type=int, default=5000, help="Default Playwright action timeout.")
    parser.add_argument("--headful", action="store_true", help="Run browser with a visible window.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    started = time.monotonic()
    result = run_benchmark(args)
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(output_path), "ok": result.get("ok"), "notes": result.get("notes", [])}, ensure_ascii=False))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
