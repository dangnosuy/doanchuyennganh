"""Logging setup — rich terminal output + plain-text file log.

Terminal: rich Panels with color per agent, full content, tool-call boxes.
File:     plain timestamped lines with ALL content (no truncation anywhere).
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich.text import Text
from rich.theme import Theme

# ── Rich console (stderr, no markup leak into file) ──────────────────────────
_THEME = Theme({
    "phase":    "bold white on dark_blue",
    "step":     "bold cyan",
    "red":      "bold red",
    "blue":     "bold blue",
    "verifier": "bold magenta",
    "exec":     "bold yellow",
    "ok":       "bold green",
    "fail":     "bold red",
    "warn":     "bold orange1",
    "dim":      "dim white",
})
_console = Console(stderr=True, theme=_THEME, highlight=False)

_log = logging.getLogger("marl3")
_configured = False


# ── Setup ────────────────────────────────────────────────────────────────────

def setup(run_dir: str | Path | None, level: str = "INFO") -> Path | None:
    """Configure marl3 logger: rich stderr + plain file (file optional if run_dir is None)."""
    global _configured
    if _configured:
        return Path(run_dir) / "run.log" if run_dir else None

    _log.setLevel(getattr(logging, level.upper(), logging.INFO))

    if run_dir is not None:
        log_path = Path(run_dir) / "run.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_fmt = logging.Formatter(
            "%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setFormatter(file_fmt)
        fh.setLevel(logging.DEBUG)
        _log.addHandler(fh)
    else:
        log_path = None

    _log.propagate = False

    # Silence noisy third-party loggers
    for name in ("httpx", "httpcore", "openai", "asyncio", "playwright", "urllib3"):
        logging.getLogger(name).setLevel(logging.WARNING)

    _configured = True
    return log_path


def get() -> logging.Logger:
    return _log


# ── High-level visual helpers ─────────────────────────────────────────────────

def phase(name: str) -> None:
    """Bold phase banner — separates RECON / HUNT / DEBATE→EXEC→VERIFY / REPORT."""
    _console.print()
    _console.print(Rule(f"[phase]  {name}  [/phase]", style="dark_blue"))
    _console.print()
    _log.info("=" * 70)
    _log.info(f"  PHASE: {name}")
    _log.info("=" * 70)


def step(name: str) -> None:
    _console.print(f"[step]── {name}[/step]")
    _log.info(f"── {name}")


def info(msg: str) -> None:
    _console.print(f"  {msg}")
    _log.info(msg)


def warn(msg: str) -> None:
    _console.print(f"[warn]⚠  {msg}[/warn]")
    _log.warning(msg)


def error(msg: str) -> None:
    _console.print(f"[fail]✗  {msg}[/fail]")
    _log.error(msg)


# ── Agent message panels ──────────────────────────────────────────────────────

def agent_message(
    role: str,
    round_num: int,
    content: str,
    verdict: str = "",
    bug_id: str = "",
) -> None:
    """Print a full-content Panel for a Red/Blue/Verifier message.

    Nothing is truncated — the user sees everything the agent wrote.
    The same full content is written to the file log.
    """
    role_l = role.lower()
    # ── terminal panel ──
    if role_l == "red":
        border = "red"
        icon = "🔴"
        label = f"{icon} RED — Round {round_num + 1}"
    elif role_l == "blue":
        border = "blue"
        icon = "🔵"
        verdict_tag = f"  [{verdict}]" if verdict else ""
        label = f"{icon} BLUE — Round {round_num + 1}{verdict_tag}"
    elif role_l == "verifier":
        border = "magenta"
        icon = "🔍"
        label = f"{icon} VERIFIER {verdict}"
    else:
        border = "white"
        icon = "◆"
        label = f"{icon} {role.upper()}"

    if bug_id:
        label = f"{label}  ({bug_id})"

    _console.print(
        Panel(
            content,
            title=f"[bold]{label}[/bold]",
            border_style=border,
            padding=(0, 1),
            expand=True,
        )
    )

    # ── file log (full content, labelled) ──
    _log.info(
        f"[{role.upper()} R{round_num}]{' [' + verdict + ']' if verdict else ''} {bug_id}\n"
        f"{content}\n"
        f"{'─' * 60}"
    )


# ── Tool-call display ─────────────────────────────────────────────────────────

def tool_call(bug_id: str, step_num: int, name: str, args: dict) -> None:
    """Show the tool call + parameters the exec agent is about to make.

    Displayed as a syntax-highlighted JSON box so the user can follow
    exactly what request is being issued.
    """
    header = f"[exec]⚡ EXEC TOOL CALL — step {step_num}[/exec]  [dim]{bug_id}[/dim]"
    payload = {"tool": name, "args": args}
    pretty = json.dumps(payload, indent=2, ensure_ascii=False)
    syntax = Syntax(pretty, "json", theme="monokai", line_numbers=False, word_wrap=True)
    _console.print(header)
    _console.print(
        Panel(syntax, border_style="yellow", padding=(0, 1), expand=False)
    )
    _console.print()

    # file log
    _log.info(f"TOOL_CALL step={step_num} {bug_id}: {name}({json.dumps(args, ensure_ascii=False)})")


def tool_result(bug_id: str, step_num: int, name: str, result: str) -> None:
    """Show the tool result (response status / body preview)."""
    # Only show first 400 chars on terminal to avoid flooding — full content is in file log
    preview = result[:400] + ("…" if len(result) > 400 else "")
    _console.print(f"  [dim]↳ {name} result:[/dim] {preview}")
    _console.print()
    _log.info(f"TOOL_RESULT step={step_num} {bug_id}: {name} → {result}")


# ── Verifier panel summary ────────────────────────────────────────────────────

def verifier_verdict(verifier_id: str, confirmed: bool, confidence: float, rationale: str, bug_id: str = "") -> None:
    """Display one verifier's full verdict."""
    icon = "✅" if confirmed else "❌"
    status = "CONFIRMED" if confirmed else "not confirmed"
    label = f"{icon} {verifier_id.upper()} — {status}  (confidence {confidence:.2f})"
    if bug_id:
        label += f"  ({bug_id})"
    border = "green" if confirmed else "red"
    _console.print(
        Panel(
            rationale,
            title=f"[bold]{label}[/bold]",
            border_style=border,
            padding=(0, 1),
            expand=True,
        )
    )
    _log.info(
        f"[VERIFIER {verifier_id}] confirmed={confirmed} confidence={confidence} {bug_id}\n"
        f"{rationale}\n{'─' * 60}"
    )


def panel_decision(bug_id: str, confirmed_count: int, total: int, decision: str) -> None:
    """Show the final panel vote count."""
    if decision == "EXPLOITED":
        style, icon = "bold green", "🚨"
    else:
        style, icon = "bold red", "🛡 "
    msg = f"{icon} [{style}]{decision}[/{style}] — {confirmed_count}/{total} verifiers confirmed"
    if bug_id:
        msg += f"  ({bug_id})"
    _console.print()
    _console.print(Rule(msg, style=style.split()[-1]))
    _console.print()
    _log.info(f"PANEL_DECISION {bug_id}: {decision} ({confirmed_count}/{total})")


# ── Bug-level header ──────────────────────────────────────────────────────────

def bug_header(bug_id: str, title: str, pattern_id: str) -> None:
    """Announce start of a new bug."""
    _console.print()
    _console.print(Rule(
        f"[bold cyan]{bug_id}[/bold cyan]  {title}  [dim]({pattern_id})[/dim]",
        style="cyan",
    ))
    _console.print()
    _log.info(f"BUG START: {bug_id} — {title} ({pattern_id})")


def bug_result(bug_id: str, status: str) -> None:
    """Announce final result for a bug."""
    if "EXPLOITED" in status and "NOT" not in status and "INFO" not in status:
        style, icon = "bold white on red", "🚨"
    elif status == "INFO_EXPOSURE_ONLY":
        style, icon = "bold black on yellow", "⚠ "
    elif "NOT_EXPLOITED" in status or "GIVE_UP" in status or "PROOF_QUALITY_FAIL" in status:
        style, icon = "bold green", "✔ "
    else:
        style, icon = "bold yellow", "⚠ "
    _console.print(f"  {icon} [{style}] {bug_id}: {status} [/{style}]")
    _console.print()


# ── Phase summaries (high-level "what just happened") ─────────────────────────

def recon_summary(n_endpoints: int, n_exchanges: int, methods: dict,
                  auth_ok: bool, profiles: list, auth_diffs: int) -> None:
    """Compact box shown after the crawl: how much surface was captured."""
    from rich.table import Table
    tbl = Table(show_header=False, box=None, padding=(0, 2))
    tbl.add_column(style="dim")
    tbl.add_column()
    methods_str = ", ".join(f"{m}={c}" for m, c in sorted(methods.items())) or "none"
    tbl.add_row("Endpoints discovered", f"[bold]{n_endpoints}[/bold]")
    tbl.add_row("HTTP requests captured", f"[bold]{n_exchanges}[/bold]  ({methods_str})")
    if auth_ok:
        tbl.add_row("Login", f"[ok]✓ logged in[/ok] as {', '.join(profiles) or '?'}")
    else:
        tbl.add_row("Login", "[fail]✗ not authenticated[/fail]")
    tbl.add_row("Auth access diffs (BAC signal)", f"[bold]{auth_diffs}[/bold]")
    _console.print(Panel(tbl, title="[ok]✅ RECON complete[/ok]", border_style="green", expand=False))
    _console.print()


def hunt_summary(dossiers: list) -> None:
    """Table shown after hunting: which candidate bugs were found."""
    from rich.table import Table
    if not dossiers:
        _console.print("[warn]⚠ HUNT: no candidate bugs found[/warn]\n")
        return
    tbl = Table(title=f"🎯 HUNT — {len(dossiers)} candidate bug(s)", title_style="bold cyan",
                border_style="cyan", expand=True)
    tbl.add_column("ID", style="bold")
    tbl.add_column("Pattern", style="magenta")
    tbl.add_column("Endpoint")
    tbl.add_column("Why it's suspected", overflow="fold")
    for d in dossiers:
        why = (d.hypothesis or d.title or "")[:90]
        tbl.add_row(d.id, d.pattern_id, f"{d.method} {d.endpoint}", why)
    _console.print(tbl)
    _console.print()


def gate_verdict(bug_id: str, verdict: str, markers: list) -> None:
    """Show the deterministic proof-gate decision (the authority) before the panel."""
    color = {"EXPLOITED": "ok", "INFO_EXPOSURE_ONLY": "warn"}.get(verdict, "fail")
    mk = (", ".join(markers) or "none")
    _console.print(f"  🛡  [bold]Proof-gate[/bold]: [{color}]{verdict}[/{color}]  [dim](markers: {mk})[/dim]")


def retry(kind: str, bug_id: str, reason: str = "") -> None:
    """Announce a retry edge firing (re-exec or re-debate) — so loops are visible."""
    r = (reason or "").replace("\n", " ")[:90]
    _console.print(f"  ↻ [warn]RETRY {kind}[/warn] [dim]({bug_id})[/dim]" + (f" — {r}" if r else ""))
    _log.info(f"RETRY {kind} {bug_id}: {reason}")


def verify_result(bug_id: str, gate: str, markers: list, verdicts: list, final_status: str) -> None:
    """One compact block: proof-gate verdict (authority) + each verifier's vote + final."""
    _console.print()
    _console.print(f"[verifier]── VERIFY {bug_id}[/verifier]")
    gate_verdict(bug_id, gate, markers)
    for i, v in enumerate(verdicts):
        mark = "[ok]✓ confirm[/ok]" if v.confirmed else "[fail]✗ reject[/fail]"
        reason = (getattr(v, "rationale", "") or "").replace("\n", " ")[:90]
        _console.print(f"  🔍 verifier {i + 1}: {mark} [dim](conf {v.confidence:.2f})[/dim] — {reason}")
    confirmed = sum(1 for v in verdicts if v.confirmed)
    _console.print(f"  🗳  panel: [bold]{confirmed}/{len(verdicts)}[/bold] confirmed "
                   f"[dim](advisory — gate decides)[/dim]")
    bug_result(bug_id, final_status)


def final_summary(findings: list) -> None:
    """End-of-run scoreboard."""
    from rich.table import Table
    exploited = [f for f in findings if getattr(f.status, "value", f.status) == "EXPLOITED"]
    info = [f for f in findings if getattr(f.status, "value", f.status) == "INFO_EXPOSURE_ONLY"]
    other = [f for f in findings if f not in exploited and f not in info]
    tbl = Table(title="🏁 FINAL RESULTS", title_style="bold white", border_style="blue", expand=True)
    tbl.add_column("Bug", style="bold")
    tbl.add_column("Pattern", style="magenta")
    tbl.add_column("Endpoint")
    tbl.add_column("Result")
    def _res(f):
        s = getattr(f.status, "value", f.status)
        if s == "EXPLOITED":
            return "[bold white on red] EXPLOITED [/]"
        if s == "INFO_EXPOSURE_ONLY":
            return "[bold black on yellow] INFO EXPOSURE [/]"
        return f"[green]{s}[/green]"
    for f in exploited + info + other:
        tbl.add_row(f.bug_id, f.pattern_id, f"{f.method} {f.endpoint}", _res(f))
    _console.print()
    _console.print(tbl)
    _console.print(f"\n  [bold]{len(exploited)} exploited[/bold] · {len(info)} info-exposure · "
                   f"{len(other)} not exploited  (total {len(findings)})\n")
