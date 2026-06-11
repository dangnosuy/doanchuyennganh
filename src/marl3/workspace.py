from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


_LABEL_RE = re.compile(r"^[a-z0-9_]{1,32}$")


class RunWorkspace:
    """Owns every path in a run directory.

    All subsystems receive a RunWorkspace instance and call its path methods.
    No subsystem may construct paths independently — this prevents orphan files.
    """

    def __init__(self, run_dir: Path) -> None:
        self._root = run_dir
        self._root.mkdir(parents=True, exist_ok=True)
        self.bodies_dir.mkdir(exist_ok=True)
        self.evidence_dir.mkdir(exist_ok=True)
        self.pocs_dir.mkdir(exist_ok=True)

    # ── Root ──────────────────────────────────────────────────────────────────

    @property
    def root(self) -> Path:
        return self._root

    # ── Recon phase ───────────────────────────────────────────────────────────

    @property
    def recon_json(self) -> Path:
        return self._root / "recon.json"

    @property
    def recon_md(self) -> Path:
        return self._root / "recon.md"

    @property
    def sessions_json(self) -> Path:
        return self._root / "sessions.json"

    @property
    def bodies_dir(self) -> Path:
        return self._root / "bodies"

    def body_path(self, blob_id: str) -> Path:
        return self.bodies_dir / f"{blob_id}.bin"

    # ── Hunt phase ────────────────────────────────────────────────────────────

    @property
    def bugs_json(self) -> Path:
        return self._root / "bugs.json"

    # ── Memory ────────────────────────────────────────────────────────────────

    @property
    def memory_json(self) -> Path:
        return self._root / "memory.json"

    # ── Execution phase ───────────────────────────────────────────────────────

    @property
    def evidence_dir(self) -> Path:
        return self._root / "evidence"

    def evidence_path(self, bug_id: str) -> Path:
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", bug_id)
        d = self.evidence_dir / safe
        d.mkdir(exist_ok=True)
        return d / "evidence.json"

    @property
    def debates_dir(self) -> Path:
        d = self._root / "debates"
        d.mkdir(exist_ok=True)
        return d

    def debate_path(self, bug_id: str) -> Path:
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", bug_id)
        return self.debates_dir / f"{safe}.md"

    @property
    def pocs_dir(self) -> Path:
        return self._root / "pocs"

    def poc_path(self, bug_id: str) -> Path:
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", bug_id)
        return self.pocs_dir / f"poc_{safe}.txt"

    # ── Report phase ──────────────────────────────────────────────────────────

    @property
    def report_md(self) -> Path:
        return self._root / "report.md"

    @property
    def findings_json(self) -> Path:
        return self._root / "findings.json"

    # ── Audit ─────────────────────────────────────────────────────────────────

    @property
    def usage_json(self) -> Path:
        return self._root / "usage.json"

    @property
    def run_log(self) -> Path:
        return self._root / "run.log"

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def create(cls, base_dir: str | Path, target_url: str) -> "RunWorkspace":
        """Create a fresh workspace directory for the given target."""
        base = Path(base_dir)
        base.mkdir(parents=True, exist_ok=True)
        host = _url_slug(target_url)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        run_dir = base / f"{host}_{ts}"
        return cls(run_dir)

    @classmethod
    def open(cls, run_dir: str | Path) -> "RunWorkspace":
        """Open an existing workspace (for reuse mode)."""
        return cls(Path(run_dir))


def validate_auth_label(label: str) -> str:
    """Validate and return label; raises ValueError on invalid."""
    if not _LABEL_RE.match(label):
        raise ValueError(
            f"Auth label '{label}' is invalid; must match ^[a-z0-9_]{{1,32}}$. "
            "Fix the label to prevent garbage file names."
        )
    return label


def _url_slug(url: str) -> str:
    host = urlparse(url).hostname or "unknown"
    return re.sub(r"[^a-zA-Z0-9._-]", "_", host)
