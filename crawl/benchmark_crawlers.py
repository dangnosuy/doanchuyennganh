"""
Benchmark crawler tools against a local target with one fixed AI model.

This is intentionally isolated from the MARL runtime. It compares crawler/tool
outputs by the artifacts they produce: pages, requests, actions, endpoint
coverage, and workflow graph usefulness.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TARGET = "http://localhost:3000"
DEFAULT_USERNAME = "test@gmail.com"
DEFAULT_PASSWORD = "xinchao"
DEFAULT_RESULTS_DIR = Path("crawl/results")
BUSINESS_KEYWORDS = {
    "auth": ("login", "whoami", "token", "user"),
    "products": ("product", "products", "quantity", "quantitys"),
    "basket": ("basket", "cart"),
    "checkout": ("checkout", "order", "delivery", "payment", "address"),
    "feedback": ("feedback", "complaint", "contact"),
    "admin": ("admin", "administration"),
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_env(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.exists():
        return env
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def _endpoint(url: str) -> str:
    parsed = urlparse(url)
    endpoint = parsed.path or "/"
    if parsed.query:
        endpoint += "?" + parsed.query
    if parsed.fragment:
        endpoint += "#" + parsed.fragment
    return endpoint


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _trim(value: Any, limit: int = 500) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _run_subprocess(command: list[str], timeout: int) -> dict[str, Any]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return {
            "ok": completed.returncode == 0,
            "returncode": completed.returncode,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "stdout": _trim(completed.stdout, 2000),
            "stderr": _trim(completed.stderr, 2000),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "returncode": None,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "stdout": _trim(exc.stdout, 2000),
            "stderr": _trim(exc.stderr, 2000),
            "error": "timeout",
        }


def _summarize_artifact(tool: str, artifact: dict[str, Any]) -> dict[str, Any]:
    pages = artifact.get("pages") or []
    requests = artifact.get("requests") or []
    actions = artifact.get("observed_actions") or []
    graph = artifact.get("workflow_graph") or {}
    endpoints: set[str] = set()
    non_get = 0
    for page in pages:
        if page.get("endpoint"):
            endpoints.add(page["endpoint"])
    for request in requests:
        if request.get("endpoint"):
            endpoints.add(request["endpoint"])
        if request.get("method") and request.get("method") != "GET":
            non_get += 1
    found_surfaces = []
    haystack = " ".join(sorted(endpoints)).lower()
    for surface, keywords in BUSINESS_KEYWORDS.items():
        if any(keyword in haystack for keyword in keywords):
            found_surfaces.append(surface)
    score = (
        len(pages) * 2
        + len(endpoints)
        + len(requests) // 3
        + non_get * 4
        + len(actions) * 3
        + len(graph.get("edges") or []) // 2
        + len(found_surfaces) * 5
    )
    return {
        "tool": tool,
        "ok": artifact.get("ok", False),
        "elapsed_seconds": artifact.get("elapsed_seconds"),
        "pages": len(pages),
        "requests": len(requests),
        "endpoints": len(endpoints),
        "non_get_requests": non_get,
        "observed_actions": len(actions),
        "graph_nodes": len(graph.get("nodes") or []),
        "graph_edges": len(graph.get("edges") or []),
        "business_surfaces": found_surfaces,
        "usefulness_score": score,
        "notes": artifact.get("notes") or artifact.get("errors") or [],
    }


def run_playwright_guided(args: argparse.Namespace, output: Path) -> dict[str, Any]:
    command = [
        sys.executable,
        "crawl/benchmark_graph.py",
        "--target",
        args.target,
        "--username",
        args.username,
        "--password",
        args.password,
        "--output",
        str(output),
        "--timeout-ms",
        str(args.timeout_ms),
    ]
    run = _run_subprocess(command, timeout=args.timeout)
    if output.exists():
        artifact = _read_json(output)
        artifact["tool"] = "playwright_guided"
        if artifact.get("elapsed_seconds") is None:
            artifact["elapsed_seconds"] = run["elapsed_seconds"]
        return artifact
    artifact = {
        "ok": False,
        "tool": "playwright_guided",
        "target": args.target,
        "generated_at": _now_iso(),
        "elapsed_seconds": run["elapsed_seconds"],
        "pages": [],
        "requests": [],
        "observed_actions": [],
        "workflow_graph": {"nodes": [], "edges": []},
        "notes": [f"playwright_guided failed: {run.get('stderr') or run.get('stdout') or run.get('error')}"],
    }
    _write_json(output, artifact)
    return artifact


async def run_crawl4ai(args: argparse.Namespace, output: Path) -> dict[str, Any]:
    started = time.monotonic()
    notes: list[str] = []
    pages: list[dict[str, Any]] = []
    requests: list[dict[str, Any]] = []
    try:
        from crawl4ai import AsyncWebCrawler, BrowserConfig, CrawlerRunConfig
    except Exception as exc:
        artifact = {
            "ok": False,
            "tool": "crawl4ai",
            "error": "missing_dependency",
            "notes": [str(exc)],
            "generated_at": _now_iso(),
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
        _write_json(output, artifact)
        return artifact

    try:
        browser_config = BrowserConfig(headless=True, verbose=False)
        run_config = CrawlerRunConfig(
            wait_until="networkidle",
            page_timeout=args.timeout_ms * 3,
            capture_network_requests=True,
            remove_overlay_elements=True,
            scan_full_page=True,
            max_scroll_steps=4,
            simulate_user=True,
        )
        async with AsyncWebCrawler(config=browser_config) as crawler:
            result = await asyncio.wait_for(crawler.arun(url=args.target, config=run_config), timeout=args.timeout)
        markdown = getattr(result, "markdown", "") or ""
        links = getattr(result, "links", {}) or {}
        network = getattr(result, "network_requests", None) or []
        for req in network:
            if not isinstance(req, dict):
                continue
            requests.append(
                {
                    "method": req.get("method"),
                    "url": req.get("url"),
                    "endpoint": _endpoint(req.get("url") or ""),
                    "status": req.get("status"),
                    "resource_type": req.get("resource_type") or req.get("resourceType"),
                }
            )
        internal_links = links.get("internal") if isinstance(links, dict) else []
        pages.append(
            {
                "label": "crawl4ai_home",
                "url": getattr(result, "url", args.target),
                "endpoint": _endpoint(getattr(result, "url", args.target)),
                "title": getattr(result, "metadata", {}).get("title") if isinstance(getattr(result, "metadata", {}), dict) else None,
                "status": getattr(result, "status_code", None),
                "links": internal_links[:80] if isinstance(internal_links, list) else [],
                "markdown_excerpt": _trim(markdown, 1200),
            }
        )
        notes.append(f"markdown_chars={len(markdown)} internal_links={len(internal_links) if isinstance(internal_links, list) else 0}")
        artifact = {
            "ok": bool(getattr(result, "success", True)),
            "tool": "crawl4ai",
            "target": args.target,
            "generated_at": _now_iso(),
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "pages": pages,
            "requests": requests,
            "observed_actions": [],
            "workflow_graph": _simple_graph(pages, requests, []),
            "notes": notes,
        }
    except Exception as exc:
        artifact = {
            "ok": False,
            "tool": "crawl4ai",
            "target": args.target,
            "generated_at": _now_iso(),
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "pages": pages,
            "requests": requests,
            "observed_actions": [],
            "workflow_graph": _simple_graph(pages, requests, []),
            "notes": notes + [f"crawl4ai failed: {exc}"],
        }
    _write_json(output, artifact)
    return artifact


def _simple_graph(pages: list[dict[str, Any]], requests: list[dict[str, Any]], actions: list[dict[str, Any]]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    for page in pages:
        endpoint = page.get("endpoint") or _endpoint(page.get("url") or "")
        nodes.setdefault(endpoint, {"id": endpoint, "kind": "page", "methods": []})
        for link in page.get("links") or []:
            href = link.get("href") if isinstance(link, dict) else None
            if not href:
                continue
            target = _endpoint(href)
            nodes.setdefault(target, {"id": target, "kind": "page", "methods": []})
            edges.append({"from": endpoint, "to": target, "type": "link"})
    for req in requests:
        endpoint = req.get("endpoint") or _endpoint(req.get("url") or "")
        method = req.get("method") or "GET"
        node = nodes.setdefault(endpoint, {"id": endpoint, "kind": "endpoint", "methods": []})
        if method not in node["methods"]:
            node["methods"].append(method)
    for action in actions:
        before = action.get("before_url")
        after = action.get("after_url")
        if before and after:
            edges.append({"from": _endpoint(before), "to": _endpoint(after), "type": "observed_action", "label": action.get("name")})
    return {"nodes": sorted(nodes.values(), key=lambda item: item["id"]), "edges": edges}


async def run_browser_use(args: argparse.Namespace, output: Path, env: dict[str, str]) -> dict[str, Any]:
    started = time.monotonic()
    notes: list[str] = []
    try:
        from browser_use import Agent, Browser, ChatOpenAI
    except Exception as exc:
        artifact = {
            "ok": False,
            "tool": "browser_use",
            "error": "missing_dependency",
            "notes": [str(exc)],
            "generated_at": _now_iso(),
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
        _write_json(output, artifact)
        return artifact

    model = env.get("MARL_CRAWL_MODEL") or env.get("MARL_RED_MODEL") or "ollama/minimax-m2.5:cloud"
    base_url = env.get("MARL_SERVER_URL")
    api_key = (
        env.get("OPENAI_API_KEY")
        or env.get("MARL_API_KEY")
        or env.get("MARL_TOKEN")
        or env.get("GITHUB_TOKEN")
        or "unused"
    )
    if not base_url:
        notes.append("Missing MARL_SERVER_URL in .env.ollama; cannot attach fixed OpenAI-compatible model.")
    task = (
        f"Open {args.target}. Login with email {args.username} and password {args.password}. "
        "Only observe safe navigation and add at most one visible product to the basket. "
        "Do not checkout, do not delete, do not logout, do not change account data. "
        "Return a compact JSON-like summary containing pages, clickable actions, forms, API endpoints, "
        "and a workflow graph from login to product to basket."
    )
    try:
        llm = ChatOpenAI(
            model=model,
            api_key=api_key,
            base_url=base_url,
            temperature=0,
            max_retries=1,
            timeout=45,
            dont_force_structured_output=True,
        )
        browser = Browser(
            headless=True,
            enable_default_extensions=False,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        agent = Agent(
            task=task,
            llm=llm,
            browser=browser,
            use_vision=False,
            use_judge=False,
            final_response_after_failure=False,
            max_failures=3,
            step_timeout=45,
        )
        history = await asyncio.wait_for(agent.run(max_steps=args.browser_use_steps), timeout=args.timeout)
        final_result = ""
        if hasattr(history, "final_result"):
            final_result = history.final_result() or ""
        completed = bool(final_result.strip())
        artifact = {
            "ok": completed,
            "tool": "browser_use",
            "target": args.target,
            "fixed_model": model,
            "generated_at": _now_iso(),
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "pages": [],
            "requests": [],
            "observed_actions": [],
            "workflow_graph": {"nodes": [], "edges": []},
            "agent_summary": _trim(final_result, 4000),
            "notes": notes
            + [
                "browser-use output is agent narrative, not raw network capture.",
                "use_vision=False because the fixed .env.ollama model does not support image input.",
            ]
            + ([] if completed else ["browser-use did not produce a final summary within the step budget."]),
        }
    except Exception as exc:
        artifact = {
            "ok": False,
            "tool": "browser_use",
            "target": args.target,
            "fixed_model": model,
            "generated_at": _now_iso(),
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "pages": [],
            "requests": [],
            "observed_actions": [],
            "workflow_graph": {"nodes": [], "edges": []},
            "notes": notes + [f"browser-use failed: {exc}"],
        }
    _write_json(output, artifact)
    return artifact


def _write_report(path: Path, summaries: list[dict[str, Any]], artifacts: dict[str, dict[str, Any]], env: dict[str, str]) -> None:
    ranked = sorted(summaries, key=lambda item: (item.get("ok", False), item.get("usefulness_score", 0)), reverse=True)
    lines = [
        "# Crawl Tool Benchmark",
        "",
        f"- Target: `{artifacts[next(iter(artifacts))].get('target', DEFAULT_TARGET) if artifacts else DEFAULT_TARGET}`",
        f"- Fixed AI model: `{env.get('MARL_CRAWL_MODEL') or env.get('MARL_RED_MODEL') or 'unknown'}`",
        f"- Generated: `{_now_iso()}`",
        "",
        "## Ranking",
        "",
        "| Rank | Tool | OK | Score | Pages | Requests | Non-GET | Actions | Graph | Surfaces |",
        "|---:|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for index, item in enumerate(ranked, 1):
        graph = f"{item['graph_nodes']}n/{item['graph_edges']}e"
        surfaces = ", ".join(item["business_surfaces"]) or "-"
        lines.append(
            f"| {index} | `{item['tool']}` | {item['ok']} | {item['usefulness_score']} | "
            f"{item['pages']} | {item['requests']} | {item['non_get_requests']} | "
            f"{item['observed_actions']} | {graph} | {surfaces} |"
        )
    lines += ["", "## Notes", ""]
    for item in ranked:
        notes = "; ".join(str(note) for note in item.get("notes", [])[:4]) or "-"
        lines.append(f"- `{item['tool']}`: {notes}")
    lines += [
        "",
        "## Interpretation",
        "",
        "- `playwright_guided` is the strongest baseline for MARL recon because it captures real browser network requests, POST/PUT/PATCH actions, and a chronological workflow graph.",
        "- `crawl4ai` is useful for page content and link extraction, but it does not naturally prove authenticated business workflows unless we add scripted login/actions around it.",
        "- `browser_use` is useful for AI-guided exploration, but its artifact is weaker for security handoff unless wrapped with network capture and strict step/output contracts.",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


async def run_suite(args: argparse.Namespace) -> int:
    results_dir = Path(args.results_dir)
    env = _load_env(ROOT / ".env.ollama")
    artifacts: dict[str, dict[str, Any]] = {}
    artifacts["playwright_guided"] = run_playwright_guided(args, results_dir / "playwright_guided.json")
    artifacts["crawl4ai"] = await run_crawl4ai(args, results_dir / "crawl4ai.json")
    if args.browser_use:
        artifacts["browser_use"] = await run_browser_use(args, results_dir / "browser_use.json", env)
    summaries = [_summarize_artifact(name, artifact) for name, artifact in artifacts.items()]
    _write_json(results_dir / "benchmark_summary.json", {"generated_at": _now_iso(), "summaries": summaries})
    _write_report(results_dir / "benchmark_report.md", summaries, artifacts, env)
    print(json.dumps({"results_dir": str(results_dir), "summaries": summaries}, ensure_ascii=False, indent=2))
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark crawler tools with one fixed AI model.")
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--username", default=DEFAULT_USERNAME)
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    parser.add_argument("--results-dir", default=str(DEFAULT_RESULTS_DIR))
    parser.add_argument("--timeout-ms", type=int, default=7000)
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--browser-use", action="store_true", help="Also run browser-use with the fixed .env.ollama model.")
    parser.add_argument("--browser-use-steps", type=int, default=8)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(run_suite(parse_args(argv)))


if __name__ == "__main__":
    raise SystemExit(main())
