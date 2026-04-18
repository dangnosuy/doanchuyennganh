"""
MARL Orchestrator — Entry point duy nhat cho toan bo pipeline.

Flow:
  Phase 1: RECON — CrawlAgent crawl target → recon.md
  Phase 2: DEBATE — Red ↔ Blue tranh luan, ca hai co the goi Agent
           Red viet chien luoc tan cong → Blue review → reject/approve
  Phase 3: EXECUTION — Agent thuc thi workflow da duoc approve
  Phase 4: EVALUATION — Red danh gia ket qua, co the de xuat chien luoc moi
  Phase 5: REPORT — Luu ket qua cuoi cung

Usage:
    python main.py
    python main.py "Test https://target.com user:admin pass:secret"
"""

import os
import re
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from shared.utils import parse_prompt, extract_send_block
from agents.manage_agent import ManageAgent

WORKSPACE = "./workspace"


def _make_run_dir(target_url: str) -> str:
    """Create workspace/{domain}_{timestamp}/ for this run.

    Returns absolute path to the run directory.
    """
    domain = urlparse(target_url).hostname or "unknown"
    # Strip port-like suffixes and sanitize for filesystem
    domain = re.sub(r"[^a-zA-Z0-9._-]", "_", domain)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = Path(WORKSPACE) / f"{domain}_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return str(run_dir.resolve())


MAX_DEBATE_STEPS = 30          # tong so turn toi da (Red + Blue + Agent)
MAX_ROUNDS = 5                 # so round Red↔Blue reject/revise toi da
MIN_DEBATE_ROUNDS = 2          # buoc phai co it nhat 2 round truoc khi approve
MAX_EXEC_RETRIES = 2           # so lan cho Red de xuat chien luoc moi sau exec fail

# ── ANSI colors ──────────────────────────────────────────────
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
C = "\033[96m"
B = "\033[1m"
RST = "\033[0m"

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


def get_user_prompt() -> str:
    """Lay prompt tu CLI arg hoac stdin."""
    if len(sys.argv) > 1:
        return " ".join(sys.argv[1:])
    print(f"{Y}Nhap prompt (URL + credentials neu co):{RST}")
    prompt = input("> ").strip()
    if not prompt:
        print(f"{R}[!] Prompt khong duoc de trong.{RST}")
        sys.exit(1)
    return prompt


def strip_tag(text: str) -> str:
    """Xoa tag [REDTEAM], [BLUETEAM], [AGENT], [APPROVED], [DONE] o cuoi text."""
    return re.sub(
        r"\[(?:REDTEAM|BLUETEAM|AGENT(?::run)?|APPROVED|DONE)\]\s*$",
        "", text, flags=re.IGNORECASE,
    ).rstrip()


# ═════════════════════════════════════════════════════════════
# PHASE 1: RECON
# ═════════════════════════════════════════════════════════════

def phase_recon(user_prompt: str, run_dir: str) -> tuple[str, str, str]:
    """CrawlAgent crawl target → (target_url, recon_path, recon_content)."""
    print(f"\n{C}{B}{'='*60}")
    print(f"  PHASE 1: RECON")
    print(f"{'='*60}{RST}\n")

    from agents.crawl_agent import CrawlAgent

    target_url, _ = parse_prompt(user_prompt)
    if not target_url:
        raise ValueError("Khong tim thay URL trong prompt.")

    crawl = CrawlAgent(working_dir=run_dir)
    try:
        recon_path = crawl.run(user_prompt)
        if not recon_path or not Path(recon_path).exists():
            raise RuntimeError("CrawlAgent khong tao duoc recon file.")
        recon_content = Path(recon_path).read_text(encoding="utf-8")
    finally:
        crawl.shutdown()

    print(f"\n{G}[+] Recon hoan tat: {recon_path}{RST}")
    return target_url, recon_path, recon_content


# ═════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════

def main():
    banner()

    user_prompt = get_user_prompt()

    # ── Parse target URL to create per-target workspace dir ──
    target_url_early, _ = parse_prompt(user_prompt)
    if not target_url_early:
        print(f"{R}[!] Khong tim thay URL trong prompt.{RST}")
        return
    run_dir = _make_run_dir(target_url_early)

    # ── Setup logging — mirror all console output to run_dir/marl.log ──
    log_path = setup_logging(run_dir)
    print(f"{G}[+] Run directory: {run_dir}{RST}")
    print(f"{G}[+] Logging to: {log_path}{RST}\n")

    # ── Phase 1: Recon ──
    try:
        target_url, recon_path, recon_content = phase_recon(user_prompt, run_dir)
    except Exception as e:
        print(f"\n{R}[!] Recon failed: {e}{RST}")
        return

    # ── Phase 2–5: ManageAgent lo toàn bộ ──
    try:
        manage_agent = ManageAgent(
            target_url    = target_url,
            recon_content = recon_content,
            run_dir       = run_dir,
        )
        conversation: list[dict] = [
            {"speaker": "USER", "content": f"[USER]: {user_prompt}"},
        ]
        manage_agent.run(conversation)

    except Exception as e:
        print(f"\n{R}[!] Pipeline failed: {e}{RST}")
        import traceback
        traceback.print_exc()
    finally:
        print(f"\n{G}[+] Full session log: {log_path}{RST}")


if __name__ == "__main__":
    main()
