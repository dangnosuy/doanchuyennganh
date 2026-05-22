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
from shared.logger import log, install_log_capture

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
            log.info(f"Tái sử dụng workspace: {existing}")
            return existing
        log.warn("Yêu cầu tái sử dụng nhưng không tìm thấy workspace phù hợp — tạo mới")
    return _create_fresh_run_dir(target_url)


# Legacy constants kept for older imports/scripts. Active orchestration limits
# now live in agents/manage_agent.py.
MAX_DEBATE_STEPS = 30
MAX_ROUNDS = 5
MIN_DEBATE_ROUNDS = 0
MAX_EXEC_RETRIES = 1

# ── ANSI colors (kept for backward compat with any remaining references) ──
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
C = "\033[96m"
B = "\033[1m"
RST = "\033[0m"

YELLOW = "\033[93m"
RESET = "\033[0m"


def setup_logging(run_dir: str) -> str:
    """Setup MarlLogger to write all output to {run_dir}/marl.log.

    Returns:
        Path to the log file.
    """
    log_path = str(Path(run_dir) / "marl.log")
    log.setup(log_path)
    # Redirect all print() from agents to log file only
    # Terminal output is now exclusively via log.terminal()
    install_log_capture(pass_through=False)
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
    # Legacy — replaced by log.main_banner() in main()
    pass


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
    log.terminal("\033[93mNhập prompt (URL + credentials nếu có):\033[0m")
    prompt = input("> ").strip()
    if not prompt:
        log.error("Prompt không được để trống.")
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
    log.phase_banner(1, "TRINH SÁT", "CrawlAgent thu thập thông tin mục tiêu")

    target_url, _ = parse_prompt(user_prompt)
    if not target_url:
        raise ValueError("Không tìm thấy URL trong prompt.")

    # ── Check for existing workspace with bugs ──
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
                    log.info(f"Workspace đã có {len(bugs)} bugs — bỏ qua Giai đoạn 1")
                    log.info(f"Sử dụng recon.md có sẵn: {recon_path}")
                    return target_url, recon_path, recon_content

                existing_crawl_data = Path(run_dir) / "crawl_data.txt"
                if existing_crawl_data.exists():
                    log.warn("recon.md là placeholder — đang xây dựng lại từ crawl data")
                    from agents.crawl_agent import CrawlAgent
                    crawl = CrawlAgent(working_dir=run_dir)
                    try:
                        recon_path = crawl.rebuild_recon_from_saved_artifacts(user_prompt)
                        recon_content = Path(recon_path).read_text(encoding="utf-8")
                        log.info(f"Đã xây dựng lại recon.md: {recon_path}")
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
            raise RuntimeError("CrawlAgent không tạo được recon file.")
        recon_content = Path(recon_path).read_text(encoding="utf-8")
    finally:
        crawl.shutdown()

    log.info(f"Trinh sát hoàn tất: {recon_path}")
    log.sub_phase("VULN HUNTER — Nhận diện lỗ hổng")

    # Skip VulnHunter if risk-bug.json already exists with bugs
    existing_risk_bugs = Path(run_dir) / "risk-bug.json"
    if existing_risk_bugs.exists():
        try:
            import json
            with open(existing_risk_bugs) as f:
                existing = json.load(f)
            if existing and len(existing) > 0:
                log.info(f"VulnHunter bỏ qua — sử dụng risk-bug.json có sẵn ({len(existing)} bugs)")
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
    log.info(f"VulnHunter hoàn tất: {len(bugs)} lỗ hổng tiềm năng")

    return target_url, recon_path, recon_content


# ═════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════

def main():
    args = parse_cli_args()
    workspace_mode = get_workspace_mode(args)
    user_prompt = get_user_prompt(args.prompt)

    # ── Parse target URL to create per-target workspace dir ──
    target_url_early, _ = parse_prompt(user_prompt)
    if not target_url_early:
        log.error("Không tìm thấy URL trong prompt.")
        return
    run_dir = _make_run_dir(target_url_early, workspace_mode)

    # ── Setup logging — MarlLogger handles everything ──
    log_path = setup_logging(run_dir)
    _quiet_third_party_logging()

    # ── Main banner (printed AFTER logging is set up) ──
    log.main_banner(target_url_early, run_dir, workspace_mode)
    log.debug(f"Log file: {log_path}")

    # ── Phase 1: Recon ──
    try:
        target_url, recon_path, recon_content = phase_recon(user_prompt, run_dir)
    except Exception as e:
        log.error(f"Trinh sát thất bại: {e}")
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
        log.error(f"Pipeline thất bại: {e}")
        import traceback
        log.file_only(traceback.format_exc())
    finally:
        log.terminal(f"\n ℹ Log đầy đủ: {log_path}")
        log.close()


if __name__ == "__main__":
    main()
