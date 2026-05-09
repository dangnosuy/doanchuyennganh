"""
MARL Orchestrator — Entry point duy nhat cho toan bo pipeline.

Flow:
  Phase 1: RECON — CrawlAgent crawl target → recon.md
  Phase 2: CANDIDATE_QUEUE — VulnHunter risk-bug.json → ManageAgent chon bug
  Phase 3: STRATEGY — Red viet strategy ngan, Blue review shot plan
  Phase 4: EXECUTION — Exec chay Python exploit self-verify
  Phase 5: REPORT — Manager ghi ket qua cuoi cung tu Exec verdict/artifacts

Usage:
    python main.py
    python main.py "Test https://target.com user:admin pass:secret"
    python main.py --fresh-workspace "Test https://target.com"
    python main.py --reuse-workspace "Test https://target.com"
"""

import argparse
import os
import re
import logging
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv
load_dotenv(Path(__file__).parent / ".env")

from shared.utils import parse_prompt

WORKSPACE = "./workspace"


def _is_placeholder_recon(text: str) -> bool:
    """Return True when recon.md is only a placeholder/non-informative stub."""
    lower = text.lower()
    return (
        "llm analysis skipped" in lower
        or "vulnhunter đọc crawl_data.txt trực tiếp" in lower
        or len(text.strip()) < 200
    )


def _workspace_domain(target_url: str) -> str:
    """Normalize target hostname into a workspace-safe slug."""
    domain = urlparse(target_url).hostname or "unknown"
    return re.sub(r"[^a-zA-Z0-9._-]", "_", domain)


def _find_reusable_run_dir(target_url: str) -> str | None:
    """Return the newest reusable workspace for *target_url*, if any."""
    domain = _workspace_domain(target_url)
    import json as _json
    workspace_path = Path(WORKSPACE)
    if workspace_path.exists():
        for existing in sorted(workspace_path.iterdir(), reverse=True):
            if existing.is_dir() and existing.name.startswith(domain + "_"):
                if not (existing / "crawl_data.txt").exists():
                    continue
                bugs_file = existing / "risk-bug.json"
                bugs_count = 0
                if bugs_file.exists():
                    try:
                        with open(bugs_file) as f:
                            bugs = _json.load(f)
                            bugs_count = len(bugs) if isinstance(bugs, list) else 0
                    except: pass
                if bugs_count > 0:
                    return str(existing.resolve())
    return None


def _create_fresh_run_dir(target_url: str) -> str:
    """Create a new workspace/{domain}_{timestamp}/ directory for this run."""
    domain = _workspace_domain(target_url)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    workspace_path = Path(WORKSPACE)
    run_dir = workspace_path / f"{domain}_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return str(run_dir.resolve())


def _make_run_dir(target_url: str, workspace_mode: str) -> str:
    """Resolve run_dir according to workspace mode: fresh or reuse."""
    if workspace_mode == "reuse":
        existing = _find_reusable_run_dir(target_url)
        if existing:
            print(f"{G}[+] Reusing existing workspace: {existing}{RST}")
            return existing
        print(f"{Y}[!] Reuse requested but no suitable workspace found — creating fresh workspace{RST}")
    return _create_fresh_run_dir(target_url)


# Legacy constants kept for older imports/scripts. Active orchestration limits
# now live in agents/manage_agent.py.
MAX_DEBATE_STEPS = 30
MAX_ROUNDS = 5
MIN_DEBATE_ROUNDS = 0
MAX_EXEC_RETRIES = 1

# ── ANSI colors ──────────────────────────────────────────────
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
C = "\033[96m"
B = "\033[1m"
RST = "\033[0m"

YELLOW = "\033[93m"  # yellow for backward compatibility
RESET = "\033[0m"  # reset for backward compatibility

# Regex strip ANSI escape codes for log file
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


# ═════════════════════════════════════════════════════════════
# TEE LOGGER — mirror stdout/stderr to log file
# ═════════════════════════════════════════════════════════════

class TeeLogger:
    """Write to both original stream and a log file — realtime.

    - Console gets full ANSI colors as normal
    - Log file gets clean text (ANSI codes stripped) + timestamp per line
    - Every write() is flushed IMMEDIATELY to disk (os.fsync)
      so log is never lost even on Ctrl+C or crash
    """

    def __init__(self, log_path: str, stream):
        self._stream = stream          # original sys.stdout or sys.stderr
        # Open unbuffered (buffering=1 is line-buffered, but we flush manually)
        self._log_file = open(log_path, "a", encoding="utf-8")
        self._at_line_start = True     # track for timestamp insertion

    def write(self, text: str):
        # Console: pass through as-is (with colors)
        self._stream.write(text)
        self._stream.flush()

        # Log file: strip ANSI, add timestamps, flush immediately
        clean = _ANSI_RE.sub("", text)
        if clean:
            lines = clean.split("\n")
            for i, line in enumerate(lines):
                if i > 0:
                    self._log_file.write("\n")
                    self._at_line_start = True
                if line:
                    if self._at_line_start:
                        ts = datetime.now().strftime("%H:%M:%S")
                        self._log_file.write(f"[{ts}] {line}")
                    else:
                        self._log_file.write(line)
                    self._at_line_start = False
            # If text ended with \n, next write starts a new line
            if clean.endswith("\n"):
                self._at_line_start = True

            # REALTIME: flush to disk immediately — survive Ctrl+C / crash
            self._log_file.flush()
            os.fsync(self._log_file.fileno())

    def flush(self):
        self._stream.flush()
        self._log_file.flush()

    def close(self):
        self._log_file.close()

    def fileno(self):
        return self._stream.fileno()

    def isatty(self):
        return self._stream.isatty()

    @property
    def encoding(self):
        return self._stream.encoding


def setup_logging(run_dir: str) -> str:
    """Setup TeeLogger to mirror all output to {run_dir}/marl.log.

    Returns:
        Path to the log file.
    """
    log_path = str(Path(run_dir) / "marl.log")

    # Write header
    with open(log_path, "w", encoding="utf-8") as f:
        f.write(f"MARL Session Log — {datetime.now().isoformat()}\n")
        f.write(f"{'=' * 60}\n\n")

    sys.stdout = TeeLogger(log_path, sys.__stdout__)
    sys.stderr = TeeLogger(log_path, sys.__stderr__)

    return log_path


def _quiet_third_party_logging() -> None:
    """Keep runtime logs focused on agent-level orchestration, not library chatter."""
    logging.getLogger().setLevel(logging.WARNING)
    for name in (
        "mcp",
        "mcp.client",
        "mcp.server",
        "mcp.server.lowlevel",
        "mcp.server.lowlevel.server",
        "mcp.server.fastmcp",
        "mcp_server_shell",
        "mcp_server_fetch",
        "mcp_client",
        "httpx",
        "httpcore",
        "asyncio",
        "urllib3",
        "openai",
    ):
        logging.getLogger(name).setLevel(logging.WARNING)


# ═════════════════════════════════════════════════════════════
# HELPERS
# ═════════════════════════════════════════════════════════════

def banner():
    print(f"""{C}{B}
    ╔══════════════════════════════════════════╗
    ║   MARL — Multi-Agent Red-team LLM        ║
    ║   Penetration Testing via Debate          ║
    ╚══════════════════════════════════════════╝{RST}
    """)


def parse_cli_args() -> argparse.Namespace:
    """Parse CLI flags without breaking the old positional prompt style."""
    parser = argparse.ArgumentParser(
        description="MARL multi-agent pentest orchestrator",
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--fresh-workspace",
        action="store_true",
        help="Luon tao workspace moi, khong dung recon/memory/risk-bug cu.",
    )
    mode_group.add_argument(
        "--reuse-workspace",
        action="store_true",
        help="Tai su dung workspace cu cua cung target neu co crawl_data.txt + risk-bug.json.",
    )
    parser.add_argument(
        "prompt",
        nargs="*",
        help='Prompt chua target URL va credentials, vd: "Test https://target.com user:admin pass:secret"',
    )
    return parser.parse_args()


def get_workspace_mode(args: argparse.Namespace) -> str:
    """Resolve workspace mode from CLI flags or env var."""
    if args.fresh_workspace:
        return "fresh"
    if args.reuse_workspace:
        return "reuse"

    env_mode = os.environ.get("MARL_WORKSPACE_MODE", "fresh").strip().lower()
    if env_mode in {"fresh", "reuse"}:
        return env_mode
    return "fresh"


def get_user_prompt(prompt_parts: list[str] | None = None) -> str:
    """Lay prompt tu CLI arg hoac stdin."""
    if prompt_parts:
        return " ".join(prompt_parts).strip()
    # MARL_AUTO_PROMPT: for scripted runs, bypass stdin
    import os as _os
    _auto = _os.environ.get("MARL_AUTO_PROMPT", "")
    if _auto:
        return _auto
    print(f"{Y}Nhap prompt (URL + credentials neu co):{RST}")
    prompt = input("> ").strip()
    if not prompt:
        print(f"{R}[!] Prompt khong duoc de trong.{RST}")
        sys.exit(1)
    return prompt


# ═════════════════════════════════════════════════════════════
# PHASE 1: RECON
# ═════════════════════════════════════════════════════════════

def phase_recon(user_prompt: str, run_dir: str) -> tuple[str, str, str]:
    """CrawlAgent crawl target → (target_url, recon_path, recon_content).

    Skips Phase 1 (CrawlAgent + VulnHunter) entirely if existing workspace
    already has both crawl_data.txt and risk-bug.json with at least 1 bug.
    This avoids expensive re-crawl when a prior run already produced bugs.
    """
    print(f"\n{C}{B}{'='*60}")
    print(f"  PHASE 1: RECON")
    print(f"{'='*60}{RST}\n")

    target_url, _ = parse_prompt(user_prompt)
    if not target_url:
        raise ValueError("Khong tim thay URL trong prompt.")

    # ── Check for existing workspace with bugs ──
    # If both crawl_data.txt + risk-bug.json exist and have content,
    # skip the expensive Phase 1 (crawl + vuln-hunter).
    existing_risk_bugs = Path(run_dir) / "risk-bug.json"
    existing_recon = Path(run_dir) / "recon.md"
    if existing_risk_bugs.exists() and existing_recon.exists():
        try:
            import json
            with open(existing_risk_bugs) as f:
                bugs = json.load(f)
            if bugs and len(bugs) > 0:
                recon_path = str(existing_recon)
                recon_content = existing_recon.read_text(encoding="utf-8")
                if not _is_placeholder_recon(recon_content):
                    print(f"\033[93m[+] Workspace already has {len(bugs)} bugs — skipping Phase 1 (CrawlAgent + VulnHunter)\033[0m")
                    print(f"\033[92m[+] Using existing recon.md: {recon_path}\033[0m")
                    print(f"\033[92m[+] Recon + VulnHunter hoan tat\033[0m")
                    return target_url, recon_path, recon_content

                existing_crawl_data = Path(run_dir) / "crawl_data.txt"
                if existing_crawl_data.exists():
                    print(f"\033[93m[+] Existing recon.md is placeholder — rebuilding from saved crawl artifacts\033[0m")
                    from agents.crawl_agent import CrawlAgent
                    crawl = CrawlAgent(working_dir=run_dir)
                    try:
                        recon_path = crawl.rebuild_recon_from_saved_artifacts(user_prompt)
                        recon_content = Path(recon_path).read_text(encoding="utf-8")
                        print(f"\033[92m[+] Rebuilt recon.md from saved crawl data: {recon_path}\033[0m")
                        print(f"\033[92m[+] Recon + VulnHunter hoan tat\033[0m")
                        return target_url, recon_path, recon_content
                    finally:
                        crawl.shutdown()
        except Exception:
            pass  # proceed with Phase 1 normally

    from agents.crawl_agent import CrawlAgent

    crawl = CrawlAgent(working_dir=run_dir)
    try:
        recon_path = crawl.run(user_prompt)
        if not recon_path or not Path(recon_path).exists():
            raise RuntimeError("CrawlAgent khong tao duoc recon file.")
        recon_content = Path(recon_path).read_text(encoding="utf-8")
    finally:
        crawl.shutdown()

    print(f"\n{G}[+] Recon hoan tat: {recon_path}{RST}"
          f"{C}{B}\n  PHASE 1b: VULN HUNTER — Nhận diện lỗ hổng{RST}\n")

    # Skip VulnHunter if risk-bug.json already exists with bugs
    existing_risk_bugs = Path(run_dir) / "risk-bug.json"
    if existing_risk_bugs.exists():
        try:
            import json
            with open(existing_risk_bugs) as f:
                existing = json.load(f)
            if existing and len(existing) > 0:
                print(f"\033[93m[+] VulnHunter skipped — using existing risk-bug.json ({len(existing)} bugs)\033[0m")
                print(f"\n\033[92m[+] Recon + VulnHunter hoan tat\033[0m")
                return target_url, recon_path, recon_content
        except Exception:
            pass

    from agents.vuln_hunter_agent import VulnHunterAgent
    crawler_data = Path(run_dir) / "crawl_data.txt"

    hunter = VulnHunterAgent(
        run_dir        = run_dir,
        target_url     = target_url,
        recon_md_path  = recon_path,
        crawl_data_path = str(crawler_data) if crawler_data.exists() else "",
    )
    bugs = hunter.run()
    print(f"\n{G}[+] VulnHunter hoan tat: {len(bugs)} bugs identified{RST}")

    print(f"\n{G}[+] Recon + VulnHunter hoan tat{RST}")
    return target_url, recon_path, recon_content


# ═════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════

def main():
    banner()

    args = parse_cli_args()
    workspace_mode = get_workspace_mode(args)
    user_prompt = get_user_prompt(args.prompt)

    # ── Parse target URL to create per-target workspace dir ──
    target_url_early, _ = parse_prompt(user_prompt)
    if not target_url_early:
        print(f"{R}[!] Khong tim thay URL trong prompt.{RST}")
        return
    run_dir = _make_run_dir(target_url_early, workspace_mode)

    # ── Setup logging — mirror all console output to run_dir/marl.log ──
    log_path = setup_logging(run_dir)
    _quiet_third_party_logging()
    print(f"{G}[+] Workspace mode: {workspace_mode}{RST}")
    print(f"{G}[+] Run directory: {run_dir}{RST}")
    print(f"{G}[+] Logging to: {log_path}{RST}\n")

    # ── Phase 1: Recon ──
    try:
        target_url, recon_path, recon_content = phase_recon(user_prompt, run_dir)
    except Exception as e:
        print(f"\n{R}[!] Recon failed: {e}{RST}")
        return

    # ── Phase 2–5: ManageAgent điều phối toàn bộ ──
    try:
        from agents.manage_agent import ManageAgent

        conversation: list[dict] = [
            {"speaker": "USER", "content": f"[USER]: {user_prompt}"},
        ]

        manager = ManageAgent(
            target_url    = target_url,
            recon_content = recon_content,
            run_dir       = run_dir,
        )
        manager.run(conversation)

    except Exception as e:
        print(f"\n{R}[!] Pipeline failed: {e}{RST}")
        import traceback
        traceback.print_exc()
    finally:
        print(f"\n{G}[+] Full session log: {log_path}{RST}")


if __name__ == "__main__":
    main()
