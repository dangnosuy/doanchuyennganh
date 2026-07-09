"""marl3 CLI — LangGraph-powered multi-agent pentest tool.

Usage:
    marl3 run "http://target.com user:alice pass:secret"
    marl3 crawl "http://target.com user:alice pass:secret"
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Optional

import typer

app = typer.Typer(name="marl3", help="Multi-agent BAC/BLF pentest with LangGraph")

# ── AI prompt parser system prompt ──────────────────────────────────────────
_AI_PARSE_SYSTEM = """\
You are a parameter extractor for a web security testing tool.
Extract: url, username, password. Return ONLY JSON: {"url":"...","username":"...","password":"..."}.

Rules:
- If the user writes "localhost:PORT" without a scheme, add "http://".
- Treat user/username/login/tên đăng nhập/tài khoản as username signals.
- Treat pass/password/mật khẩu as password signals.
- The format "user/password" (slash) means username=user, password=password.
- The format "user:password" (colon, not URL-prefixed) means username=user, password=password.
"""


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base (override wins on scalar conflicts)."""
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def _load_cfg(config: Optional[str]):
    from .config import AppConfig
    import yaml

    defaults = Path(__file__).parent.parent.parent / "config" / "default.yaml"
    raw: dict = {}
    if defaults.exists():
        raw = yaml.safe_load(defaults.read_text()) or {}
    if config:
        extra = yaml.safe_load(Path(config).read_text()) or {}
        raw = _deep_merge(raw, extra)
    return AppConfig(**raw)


def _parse_prompt(prompt: str) -> tuple[str, list[dict]]:
    """Fast-path keyword parser. Supports MULTIPLE accounts for cross-user IDOR:
    'http://... user:alice pass:Alice@123 user:bob pass:Bob@123'.
    user:/pass: tokens are paired in order of appearance.
    """
    url = ""
    users: list[str] = []
    passwords: list[str] = []
    for token in prompt.split():
        if token.startswith(("http://", "https://")):
            url = token
        elif token.startswith("user:"):
            users.append(token[5:])
        elif token.startswith("pass:"):
            passwords.append(token[5:])
    if not url:
        raise typer.BadParameter("No URL found in prompt. Include http://... in the prompt.")
    credentials = []
    for i, u in enumerate(users):
        p = passwords[i] if i < len(passwords) else ""
        label = re.sub(r"[^a-z0-9_]", "_", u.lower())[:32] or f"user{i + 1}"
        credentials.append({"username": u, "password": p, "label": label})
    return url, credentials


async def _ai_parse_prompt(raw: str, cfg) -> tuple[str, list[dict]]:
    import json
    from .llm.client import LLMClient

    llm = LLMClient(cfg.llm)
    resp = await llm.chat(
        messages=[
            {"role": "system", "content": _AI_PARSE_SYSTEM},
            {"role": "user", "content": raw},
        ],
        temperature=0,
        max_tokens=200,
    )
    # Strip markdown fences if present
    text = resp.strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    data = json.loads(text.strip())
    url = data.get("url", "")
    username = data.get("username", "")
    password = data.get("password", "")
    if not url:
        raise ValueError("AI parser returned no URL")
    credentials = [{"username": username, "password": password, "label": "user"}] if username else []
    return url, credentials


async def _smart_parse_prompt(prompt: str, cfg) -> tuple[str, list[dict]]:
    """Try fast-path first; fall back to AI; fall back to regex."""
    has_url = any(p.startswith(("http://", "https://")) for p in prompt.split())
    has_user_key = "user:" in prompt
    has_pass_key = "pass:" in prompt

    if has_url and has_user_key and has_pass_key:
        return _parse_prompt(prompt)

    try:
        return await _ai_parse_prompt(prompt, cfg)
    except Exception as exc:
        typer.echo(f"[AI parser] unavailable ({exc}) — falling back to keyword parse", err=True)

    return _parse_prompt(prompt)


@app.command()
def run(
    prompt: str = typer.Argument(..., help="Target + credentials, e.g. 'http://target user:alice pass:secret'"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config YAML"),
    base_dir: Optional[str] = typer.Option(None, "--workspace", "-w", help="Base workspace directory"),
    show_graph: bool = typer.Option(False, "--show-graph", help="Print graph structure and exit"),
):
    """Run full pentest pipeline: recon → hunt → debate → exec → verify → report."""
    asyncio.run(_run_pipeline(prompt, config, base_dir, show_graph))


@app.command()
def crawl(
    prompt: str = typer.Argument(..., help="Target + credentials"),
    config: Optional[str] = typer.Option(None, "--config", "-c"),
    base_dir: Optional[str] = typer.Option(None, "--workspace", "-w"),
):
    """Run only the recon phase and write recon.json."""
    asyncio.run(_run_crawl(prompt, config, base_dir))


@app.command()
def memory(
    action: str = typer.Argument("stats", help="stats | list | rules | prune | clear"),
    config: Optional[str] = typer.Option(None, "--config", "-c"),
    limit: int = typer.Option(20, "--limit", "-n"),
):
    """Inspect / maintain long-term experiential memory."""
    from .memory.longterm import get_longterm, render_rules
    cfg = _load_cfg(config)
    lt = get_longterm(cfg)
    if not lt.enabled:
        typer.echo("Long-term memory is disabled or unavailable.")
        return

    if action == "stats":
        s = lt.stats()
        typer.echo(f"[memory] total={s.get('total')} (with_embedding={s.get('with_embedding')}, "
                   f"semantic={'on' if s.get('semantic') else 'off'}) rules={s.get('rules')}")
        typer.echo(f"  by outcome: {s.get('by_outcome')}")
        typer.echo(f"  by pattern: {s.get('by_pattern')}")
    elif action == "list":
        for ep in lt.recent(limit):
            typer.echo(f"  [{ep.outcome:9}] {ep.pattern_id:7} {ep.method} {ep.endpoint_family} "
                       f"— {(ep.summary or '')[:80]}")
    elif action == "rules":
        block = render_rules(lt.rules_for_hunt(limit))
        typer.echo(block or "(no distilled rules yet)")
    elif action == "prune":
        removed = lt.prune()
        typer.echo(f"[memory] pruned {removed} stale episode(s)")
    elif action == "clear":
        confirm = typer.confirm("Wipe ALL long-term memory?")
        if confirm:
            lt._conn.executescript("DELETE FROM episodes; DELETE FROM rules;")
            lt._conn.commit()
            typer.echo("[memory] cleared.")
    else:
        typer.echo(f"Unknown action: {action}. Use stats | list | rules | prune | clear.")


async def _run_pipeline(prompt: str, config: Optional[str], base_dir: Optional[str], show_graph: bool):
    import json
    import time
    from .graph.pipeline import get_pipeline
    from .graph.state import make_pipeline_state
    from .workspace import RunWorkspace
    from .llm.client import LLMClient
    from .llm.usage import UsageLedger
    from .logging_setup import setup as _setup_logging, attach_run_log

    cfg = _load_cfg(config)
    _setup_logging()  # console-only setup (file handler added below after workspace is known)

    if show_graph:
        pipeline = get_pipeline()
        typer.echo(pipeline.get_graph().draw_ascii())
        return

    target_url, credentials = await _smart_parse_prompt(prompt, cfg)
    workspace = RunWorkspace.create(base_dir=base_dir or "workspace", target_url=target_url)
    ledger = UsageLedger(output_path=workspace.usage_json)
    llm = LLMClient(cfg.llm, ledger=ledger)

    # Wire up the per-run file log now that we know the workspace directory.
    log_path = attach_run_log(workspace.root)

    typer.echo(f"[marl3] target: {target_url}")
    typer.echo(f"[marl3] workspace: {workspace.root}")
    typer.echo(f"[marl3] log: {log_path}")
    typer.echo("[marl3] pipeline: recon → hunt → bugs (LangGraph) → report")

    pipeline = get_pipeline()
    initial_state = make_pipeline_state(
        target_url=target_url,
        credentials=credentials,
        cfg=cfg,
        workspace=workspace,
        llm=llm,
    )

    run_start = time.monotonic()
    final_state = await pipeline.ainvoke(initial_state)
    run_elapsed = round(time.monotonic() - run_start, 2)

    findings = final_state.get("findings", [])
    exploited = [f for f in findings if getattr(f, "status", "") == "EXPLOITED"]

    # ── Write run_metadata.json for benchmark reproducibility ────────────────
    usage_summary = ledger.summary()
    metadata = {
        "target_url": target_url,
        "config_file": config or "config/default.yaml",
        "model": {
            "crawler": cfg.llm.models.crawler if hasattr(cfg.llm, "models") else "",
            "hunter": cfg.llm.models.hunter if hasattr(cfg.llm, "models") else "",
            "red": cfg.llm.models.red if hasattr(cfg.llm, "models") else "",
            "blue": cfg.llm.models.blue if hasattr(cfg.llm, "models") else "",
            "exec": cfg.llm.models.exec if hasattr(cfg.llm, "models") else "",
            "verifier": cfg.llm.models.verifier if hasattr(cfg.llm, "models") else "",
        },
        "temperature": getattr(cfg.verifier, "temperature", 0.0),
        "debate": {
            "max_rounds": cfg.debate.max_rounds,
            "skip": getattr(cfg.debate, "skip", False),
            "per_bug_wall_clock_s": getattr(cfg.debate, "per_bug_wall_clock_s", 600),
        },
        "seeder_enabled": getattr(cfg.hunt, "seeder_enabled", True) if hasattr(cfg, "hunt") else True,
        "memory_enabled": getattr(cfg.memory, "longterm_enabled", True) if hasattr(cfg, "memory") else True,
        "total_tokens": usage_summary["total_tokens"],
        "total_llm_calls": usage_summary["calls"],
        "tokens_by_role": usage_summary["by_role"],
        "elapsed_s": run_elapsed,
        "findings_total": len(findings),
        "findings_exploited": len(exploited),
        "command": f"marl3 run \"{prompt}\"" + (f" --config {config}" if config else ""),
    }
    meta_path = workspace.root / "run_metadata.json"
    meta_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")

    typer.echo(f"\n[marl3] done — {len(exploited)}/{len(findings)} bugs exploited")
    typer.echo(f"[marl3] report: {workspace.root}/report.md")
    typer.echo(f"[marl3] metadata: {meta_path}")


async def _run_crawl(prompt: str, config: Optional[str], base_dir: Optional[str]):
    from .workspace import RunWorkspace
    from .llm.client import LLMClient
    from .llm.usage import UsageLedger
    from .graph.nodes.recon import run_recon
    from .logging_setup import setup as _setup_logging, attach_run_log

    cfg = _load_cfg(config)
    _setup_logging()

    target_url, credentials = await _smart_parse_prompt(prompt, cfg)
    workspace = RunWorkspace.create(base_dir=base_dir or "workspace", target_url=target_url)
    ledger = UsageLedger(output_path=workspace.usage_json)
    llm = LLMClient(cfg.llm, ledger=ledger)
    attach_run_log(workspace.root)

    typer.echo(f"[marl3] crawling {target_url}")
    state = {
        "target_url": target_url,
        "credentials": credentials,
        "cfg": cfg,
        "workspace": workspace,
        "llm": llm,
    }
    result = await run_recon(state)
    recon = result["recon"]
    typer.echo(f"[marl3] recon done — {len(recon.endpoints)} endpoints, {len(recon.exchanges)} exchanges")
    typer.echo(f"[marl3] recon.json: {workspace.root}/recon.json")


def main():
    app()
