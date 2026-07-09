#!/usr/bin/env python3
"""
Probe whether enriched crawl/risk evidence is actually visible to LLM agents.

This script is intentionally non-exploitative: it calls VulnHunter/Red/Blue/
Manager LLM paths only. Exec is not invoked and no requests are sent to the
target application.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv

load_dotenv(PROJECT_ROOT / ".env")

from agents.blue_team import BlueTeamAgent
from agents.manage_agent import ManageAgent
from agents.red_team import RedTeamAgent
from agents.vuln_hunter_agent import VulnHunterAgent
from shared.bug_dossier import load_and_enrich_risk_bugs
from shared.utils import truncate


DEFAULT_WORKSPACE = PROJECT_ROOT / "workspace" / "localhost_20260530_165408"
SAFE_FILES = (
    "recon.md",
    "crawl_raw.json",
    "crawl_data.txt",
    "risk-bug.json",
    "auth_context.json",
    "auth_state_test.json",
)


def _redact(text: str) -> str:
    text = str(text or "")
    text = re.sub(r"Bearer\s+[A-Za-z0-9_.=-]+", "Bearer <redacted>", text)
    text = re.sub(r"eyJ[A-Za-z0-9_.=-]{40,}", "<jwt-redacted>", text)
    text = re.sub(r"(Cookie:\s*)[^\n]+", r"\1<redacted>", text, flags=re.IGNORECASE)
    text = re.sub(r"(AUTH_BEARER_TOKEN:\s*)[^\n]+", r"\1<redacted>", text)
    text = re.sub(r"(COOKIE_HEADER:\s*)[^\n]+", r"\1<redacted>", text)
    return text


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _copy_workspace(src: Path) -> Path:
    dst = Path(tempfile.mkdtemp(prefix="marl_context_probe_"))
    for name in SAFE_FILES:
        source = src / name
        if source.exists():
            shutil.copy2(source, dst / name)
    return dst


def _workspace_target(run_dir: Path) -> str:
    raw = _read_json(run_dir / "crawl_raw.json")
    target = raw.get("target")
    if isinstance(target, str) and target.strip():
        return target.rstrip("/")
    return "http://localhost:3000"


def _select_bug(run_dir: Path, bug_id: str | None) -> tuple[list[dict], dict]:
    bugs = load_and_enrich_risk_bugs(str(run_dir))
    if not bugs:
        raise RuntimeError("No bugs found after load_and_enrich_risk_bugs().")
    if bug_id:
        for bug in bugs:
            if bug.get("id") == bug_id:
                return bugs, bug
        raise RuntimeError(f"Bug id not found: {bug_id}")
    return bugs, bugs[0]


def _example_paths(bug: dict) -> list[str]:
    paths: list[str] = []
    for ex in bug.get("http_examples") or []:
        path = str(ex.get("path") or "").strip()
        if path and path not in paths:
            paths.append(path)
    return paths


def _score_response(text: str, bug: dict, *, expected_action: str | None = None) -> dict[str, Any]:
    lower = text.lower()
    endpoint = str(bug.get("endpoint") or "").replace("{id}", "").replace("{bid}", "").rstrip("/")
    paths = _example_paths(bug)
    graph_context = bug.get("graph_context") or {}
    business_terms = [
        str(step.get("step") or "")
        for step in graph_context.get("business_chain") or []
        if isinstance(step, dict)
    ]
    business_terms.extend([
        str(edge.get("to") or "")
        for edge in graph_context.get("edges") or []
        if isinstance(edge, dict)
    ])
    checks = {
        "mentions_bug_id": str(bug.get("id") or "").lower() in lower,
        "mentions_endpoint_family": bool(endpoint and endpoint.lower() in lower),
        "mentions_observed_path": any(path.lower() in lower for path in paths),
        "uses_graph_or_business_context": any(term and term.lower() in lower for term in business_terms),
        "mentions_evidence_rule": "evidence" in lower or "proof" in lower or "bằng chứng" in lower,
        "does_not_ask_for_missing_context": "needs_context" not in lower and "không có http_examples" not in lower,
        "approval_or_alignment_signal": (
            "approved" in lower
            or "dossier_alignment" in lower
            or "endpoint/method" in lower
            or "strategy/shot plan hợp lệ" in lower
            or "strategy/shot plan hop le" in lower
        ),
    }
    if expected_action:
        checks["manager_expected_action"] = expected_action.lower() in lower
    evidence_grounded = (
        checks["mentions_endpoint_family"]
        and (checks["mentions_observed_path"] or checks["uses_graph_or_business_context"])
        and checks["does_not_ask_for_missing_context"]
    )
    approval_grounded = (
        checks["approval_or_alignment_signal"]
        and checks["does_not_ask_for_missing_context"]
        and ("manager_expected_action" not in checks or checks["manager_expected_action"])
    )
    passed = evidence_grounded or approval_grounded
    return {"passed": passed, "checks": checks}


def _call_vulnhunter(run_dir: Path, target_url: str) -> dict[str, Any]:
    hunter = VulnHunterAgent(
        run_dir=str(run_dir),
        target_url=target_url,
        recon_md_path=str(run_dir / "recon.md"),
        crawl_data_path=str(run_dir / "crawl_data.txt"),
    )
    recon = hunter._read_recon()
    raw_endpoints = hunter._load_raw_endpoints()
    raw = hunter._call_llm(recon)
    parsed = hunter._parse_bugs(raw, raw_endpoints=raw_endpoints)
    parsed = hunter._add_deterministic_candidates(parsed, raw_endpoints)
    parsed = hunter._filter_challenge_metadata_bugs(parsed)
    return {
        "model": hunter.model if hasattr(hunter, "model") else os.getenv("MARL_VULNHUNTER_MODEL", ""),
        "raw_response": raw,
        "candidate_count": len(parsed),
        "candidates": [
            {
                "id": b.get("id"),
                "method": b.get("method"),
                "endpoint": b.get("endpoint"),
                "candidate_type": b.get("candidate_type"),
                "evidence_status": b.get("evidence_status"),
                "http_examples": len(b.get("http_examples") or []),
            }
            for b in parsed[:10]
        ],
    }


def _call_red(target_url: str, recon: str, bug: dict) -> dict[str, Any]:
    red = RedTeamAgent(target_url=target_url, recon_context=recon, memory_store=None)
    red.set_current_bug(bug)
    conversation = [{
        "speaker": "USER",
        "content": "Hãy viết chiến lược kiểm thử bug hiện tại, chỉ dựa vào dossier được Manager cung cấp.",
    }]
    text = red.respond(conversation)
    return {"text": text, "score": _score_response(text, bug)}


def _call_blue(target_url: str, recon: str, bug: dict, red_text: str) -> dict[str, Any]:
    blue = BlueTeamAgent(target_url=target_url, recon_context=recon, memory_store=None)
    blue.set_current_bug(bug)
    conversation = [
        {"speaker": "USER", "content": "Review chiến lược Red cho bug hiện tại."},
        {"speaker": "REDTEAM", "content": red_text},
    ]
    text = blue.respond(conversation)
    return {"text": text, "score": _score_response(text, bug)}


def _call_manager(run_dir: Path, target_url: str, recon: str, bug: dict, red_text: str) -> dict[str, Any]:
    manager = ManageAgent(target_url=target_url, recon_content=recon, run_dir=str(run_dir))
    managed_bug = next((b for b in manager.risk_bugs if b.get("id") == bug.get("id")), bug)
    conversation = [
        {"speaker": "USER", "content": "Probe Manager context routing."},
        {"speaker": "REDTEAM", "content": red_text},
    ]
    state_context = {
        "tick": 1,
        "current_bug_index": 0,
        "current_bug_id": managed_bug.get("id", "?"),
        "current_bug": managed_bug,
        "total_bugs": len(manager.risk_bugs) or 1,
        "red_approved": False,
        "red_attempts": 0,
        "exec_retry_count": 0,
        "bugs_processed_count": 0,
        "last_action": "DEBATE_RED",
        "blue_approved": False,
        "has_workflow": bool(red_text.strip()),
        "exec_result_status": "",
        "exec_result_reason": "",
    }
    action, note = manager._decide(conversation, state_context)
    text = f"ACTION={action}\nNOTE={note}"
    return {"action": action, "note": note, "score": _score_response(text, managed_bug, expected_action="DEBATE_BLUE")}


def _render_report(
    *,
    source_workspace: Path,
    run_dir: Path,
    bug: dict,
    target_url: str,
    agents: list[str],
    results: dict[str, Any],
) -> str:
    now = datetime.now().isoformat(timespec="seconds")
    graph = bug.get("graph_context") or {}
    example = (bug.get("http_examples") or [{}])[0]
    lines = [
        "# LLM Context Probe Report",
        "",
        f"- Generated: `{now}`",
        f"- Source workspace: `{source_workspace}`",
        f"- Probe workspace copy: `{run_dir}`",
        f"- Target: `{target_url}`",
        f"- Bug: `{bug.get('id')}` `{bug.get('method')} {bug.get('endpoint')}`",
        f"- Agents called: `{', '.join(agents)}`",
        "",
        "## Dossier Snapshot",
        "",
        f"- HTTP example request: `{str(example.get('request', '')).splitlines()[0] if example else '-'}`",
        f"- HTTP example status/session: `{example.get('response_status', '-')}` / `{example.get('session_label', '-')}`",
        f"- Graph summary: `{graph.get('summary', {})}`",
        f"- Evidence rules: `{len(bug.get('evidence_rules') or [])}`",
        "",
    ]

    if "vulnhunter" in results:
        item = results["vulnhunter"]
        lines.extend([
            "## VulnHunter",
            "",
            f"- Candidate count from actual LLM response after parsing/filtering: `{item['candidate_count']}`",
            "",
            "```json",
            json.dumps(item["candidates"], ensure_ascii=False, indent=2),
            "```",
            "",
            "Raw response excerpt:",
            "",
            "```text",
            _redact(truncate(item["raw_response"], 2500)),
            "```",
            "",
        ])

    for name in ("red", "blue"):
        if name not in results:
            continue
        item = results[name]
        lines.extend([
            f"## {name.title()}",
            "",
            "Score:",
            "",
            "```json",
            json.dumps(item["score"], ensure_ascii=False, indent=2),
            "```",
            "",
            "Response excerpt:",
            "",
            "```text",
            _redact(truncate(item["text"], 3500)),
            "```",
            "",
        ])

    if "manager" in results:
        item = results["manager"]
        lines.extend([
            "## Manager",
            "",
            f"- Action: `{item['action']}`",
            f"- Note: `{_redact(item['note'])}`",
            "",
            "Score:",
            "",
            "```json",
            json.dumps(item["score"], ensure_ascii=False, indent=2),
            "```",
            "",
        ])

    lines.extend([
        "## Overall Assessment",
        "",
        "- PASS means the response mentioned the endpoint family, used observed path or graph/business context, and did not ask for missing context.",
        "- This probe does not prove exploitability. It only verifies that enriched evidence is reaching the model-facing prompts.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Call LLM agents with enriched bug dossier and write a context visibility report.")
    parser.add_argument("--workspace", default=str(DEFAULT_WORKSPACE), help="Workspace containing recon.md/crawl_raw.json/risk-bug.json.")
    parser.add_argument("--bug-id", default="BUG-001", help="Bug id to probe. Default: BUG-001.")
    parser.add_argument(
        "--agents",
        default="red,blue,manager",
        help="Comma-separated subset: vulnhunter,red,blue,manager. Use all for every supported call.",
    )
    parser.add_argument("--output", default="", help="Report path. Default: reports/context_llm_probe_<timestamp>.md")
    parser.add_argument("--keep-temp", action="store_true", help="Keep the temporary workspace copy after the run.")
    args = parser.parse_args()

    source_workspace = Path(args.workspace).resolve()
    if not source_workspace.is_dir():
        raise SystemExit(f"Workspace not found: {source_workspace}")

    agents = [a.strip().lower() for a in args.agents.split(",") if a.strip()]
    if "all" in agents:
        agents = ["vulnhunter", "red", "blue", "manager"]
    invalid = sorted(set(agents) - {"vulnhunter", "red", "blue", "manager"})
    if invalid:
        raise SystemExit(f"Unsupported agents: {', '.join(invalid)}")

    run_dir = _copy_workspace(source_workspace)
    try:
        target_url = _workspace_target(run_dir)
        bugs, bug = _select_bug(run_dir, args.bug_id)
        recon = (run_dir / "recon.md").read_text(encoding="utf-8")

        results: dict[str, Any] = {}
        red_text = ""
        if "vulnhunter" in agents:
            print("[probe] calling VulnHunter LLM...")
            results["vulnhunter"] = _call_vulnhunter(run_dir, target_url)

        if "red" in agents or "blue" in agents or "manager" in agents:
            print("[probe] calling Red LLM...")
            red_result = _call_red(target_url, recon, bug)
            red_text = red_result["text"]
            if "red" in agents:
                results["red"] = red_result

        if "blue" in agents:
            print("[probe] calling Blue LLM...")
            results["blue"] = _call_blue(target_url, recon, bug, red_text)

        if "manager" in agents:
            print("[probe] calling Manager LLM...")
            results["manager"] = _call_manager(run_dir, target_url, recon, bug, red_text)

        if args.output:
            output_path = Path(args.output).resolve()
        else:
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = PROJECT_ROOT / "reports" / f"context_llm_probe_{stamp}_{bug.get('id')}.md"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            _render_report(
                source_workspace=source_workspace,
                run_dir=run_dir,
                bug=bug,
                target_url=target_url,
                agents=agents,
                results=results,
            ),
            encoding="utf-8",
        )
        print(f"[probe] report written: {output_path}")
        if args.keep_temp:
            print(f"[probe] kept temp workspace: {run_dir}")
        return 0
    finally:
        if not args.keep_temp:
            shutil.rmtree(run_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
