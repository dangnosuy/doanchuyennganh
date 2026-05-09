"""
shared/memory_store.py
----------------------
Persistent memory store for a single MARL pipeline run.

Scoped to a run_dir (e.g. workspace/target_20260423_120000/) and manages:
  - task_registry.json     : task tracking with agent assignments and statuses
  - findings.json          : structured facts discovered during the run
  - conversation_full.jsonl: append-only full conversation log (JSONL)
  - conversation_summary.md: rolling human-readable summary
  - scratchpad/            : per-agent key-value note stores

All file I/O uses a load-modify-save pattern with try/except guards so that
a corrupted or missing file never crashes the pipeline — it is silently
re-initialised.  No external dependencies; stdlib only.
"""

import json
import re
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    """Return current ISO-8601 timestamp."""
    return datetime.now().isoformat()


def _load_json(path: Path, default):
    """Load JSON from *path*, returning *default* if the file is absent or corrupt."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return default


def _save_json(path: Path, data) -> None:
    """Atomically write *data* as JSON to *path* (write-then-rename)."""
    tmp = path.with_suffix(".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        tmp.replace(path)
    except OSError:
        # Best-effort: fall back to direct write if rename fails (e.g. cross-device)
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
        except OSError:
            pass


def _agent_scratchpad_filename(agent: str) -> str:
    """Return the scratchpad filename for *agent* (red/blue/exec)."""
    slug = re.sub(r"[^a-z0-9_]", "", agent.lower())
    return f"{slug}_notes.json"


# ---------------------------------------------------------------------------
# MemoryStore
# ---------------------------------------------------------------------------

class MemoryStore:
    """
    Persistent, file-backed memory store for one MARL pipeline run.

    All state is written to ``{run_dir}/memory/`` so it survives process
    restarts and can be inspected by humans after the run completes.

    Thread-safety: not guaranteed — the pipeline is single-threaded so this
    is acceptable.  Each public method re-loads the backing file before
    modifying it, which is safe enough for sequential calls.
    """

    # Known agent slugs that get pre-created scratchpad files
    _DEFAULT_AGENTS = ("red", "blue", "exec")

    def __init__(self, run_dir: str) -> None:
        self.run_dir = Path(run_dir)
        self.memory_dir = self.run_dir / "memory"
        self.scratchpad_dir = self.memory_dir / "scratchpad"

        # Paths for managed files
        self._task_file = self.memory_dir / "task_registry.json"
        self._findings_file = self.memory_dir / "findings.json"
        self._conv_file = self.memory_dir / "conversation_full.jsonl"
        self._summary_file = self.memory_dir / "conversation_summary.md"

        self._init_dirs()

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def _init_dirs(self) -> None:
        """Create directory tree and seed empty files if they don't exist."""
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        self.scratchpad_dir.mkdir(parents=True, exist_ok=True)

        # Seed empty JSON arrays / files
        for path, default in [
            (self._task_file, []),
            (self._findings_file, []),
        ]:
            if not path.exists():
                _save_json(path, default)

        # Seed empty JSONL log
        if not self._conv_file.exists():
            try:
                self._conv_file.touch()
            except OSError:
                pass

        # Seed empty summary
        if not self._summary_file.exists():
            try:
                self._summary_file.write_text("", encoding="utf-8")
            except OSError:
                pass

        # Seed per-agent scratchpad files
        for agent in self._DEFAULT_AGENTS:
            sp = self.scratchpad_dir / _agent_scratchpad_filename(agent)
            if not sp.exists():
                _save_json(sp, {})

    # ------------------------------------------------------------------
    # Task Registry
    # ------------------------------------------------------------------

    def register_task(
        self,
        task_id: str,
        agent: str,
        phase: str,
        description: str,
    ) -> dict:
        """
        Register a new task and persist it.

        Parameters
        ----------
        task_id:     Unique string identifier (e.g. "phase2_red_001")
        agent:       Owner agent name (e.g. "red", "blue", "exec")
        phase:       Pipeline phase (e.g. "DEBATE", "EXECUTION")
        description: Human-readable description of what the task entails

        Returns
        -------
        The newly created task dict.
        """
        tasks: list[dict] = _load_json(self._task_file, [])
        task = {
            "task_id": task_id,
            "agent": agent,
            "phase": phase,
            "description": description,
            "status": "pending",
            "created_at": _now(),
            "updated_at": _now(),
            "artifacts": [],
        }
        # Replace if task_id already exists, otherwise append
        tasks = [t for t in tasks if t.get("task_id") != task_id]
        tasks.append(task)
        _save_json(self._task_file, tasks)
        return task

    def update_task(
        self,
        task_id: str,
        status: str,
        artifacts: list[str] | None = None,
    ) -> None:
        """
        Update the status (and optionally the artifact list) of a task.

        Valid statuses: pending / in_progress / completed / failed
        """
        tasks: list[dict] = _load_json(self._task_file, [])
        for task in tasks:
            if task.get("task_id") == task_id:
                task["status"] = status
                task["updated_at"] = _now()
                if artifacts is not None:
                    task["artifacts"] = artifacts
                break
        _save_json(self._task_file, tasks)

    def get_task(self, task_id: str) -> dict | None:
        """Return the task dict for *task_id*, or None if not found."""
        tasks: list[dict] = _load_json(self._task_file, [])
        for task in tasks:
            if task.get("task_id") == task_id:
                return task
        return None

    def list_tasks(
        self,
        agent: str | None = None,
        status: str | None = None,
    ) -> list[dict]:
        """
        Return all tasks, optionally filtered by *agent* and/or *status*.
        Both filters are applied with AND logic when both are provided.
        """
        tasks: list[dict] = _load_json(self._task_file, [])
        if agent is not None:
            tasks = [t for t in tasks if t.get("agent") == agent]
        if status is not None:
            tasks = [t for t in tasks if t.get("status") == status]
        return tasks

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def add_finding(
        self,
        category: str,
        key: str,
        value: str,
        agent: str = "",
    ) -> None:
        """
        Record a structured finding.

        Parameters
        ----------
        category: One of endpoint / credential / vulnerability / note
                  (arbitrary strings are accepted but the above are canonical)
        key:      Short label, e.g. "admin_endpoint"
        value:    The actual finding, e.g. "/api/admin/users"
        agent:    Agent that discovered this (for provenance)
        """
        findings: list[dict] = _load_json(self._findings_file, [])
        finding_id = f"{category}_{len(findings):04d}"
        finding = {
            "id": finding_id,
            "category": category,
            "key": key,
            "value": value,
            "agent": agent,
            "timestamp": _now(),
        }
        findings.append(finding)
        _save_json(self._findings_file, findings)

    def get_findings(self, category: str | None = None) -> list[dict]:
        """Return all findings, optionally filtered by *category*."""
        findings: list[dict] = _load_json(self._findings_file, [])
        if category is not None:
            findings = [f for f in findings if f.get("category") == category]
        return findings

    def get_findings_text(self, category: str | None = None) -> str:
        """
        Return findings formatted as human-readable text suitable for
        injecting into an LLM prompt.

        Example output::

            [endpoint]
            - login_page: /login (from crawl)
            - admin_api: /api/admin/users (from exec)

            [vulnerability]
            - idor_found: GET /api/user/2 returns other user's data (from red)
        """
        findings = self.get_findings(category)
        if not findings:
            return "(no findings recorded)"

        # Group by category
        grouped: dict[str, list[dict]] = {}
        for f in findings:
            grouped.setdefault(f["category"], []).append(f)

        lines: list[str] = []
        for cat, items in grouped.items():
            lines.append(f"[{cat}]")
            for item in items:
                src = f" (from {item['agent']})" if item.get("agent") else ""
                lines.append(f"  - {item['key']}: {item['value']}{src}")
            lines.append("")

        return "\n".join(lines).rstrip()

    # ------------------------------------------------------------------
    # Full conversation log (JSONL)
    # ------------------------------------------------------------------

    def append_message(self, msg: dict) -> None:
        """
        Append *msg* to ``conversation_full.jsonl``.

        The message is stored verbatim with an added ``logged_at`` timestamp.
        This file is append-only and never rewritten.
        """
        record = dict(msg)
        record.setdefault("logged_at", _now())
        try:
            with open(self._conv_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def load_full_conversation(self) -> list[dict]:
        """
        Load and return every message from ``conversation_full.jsonl``.
        Malformed lines are silently skipped.
        """
        messages: list[dict] = []
        try:
            with open(self._conv_file, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        messages.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        except (FileNotFoundError, OSError):
            pass
        return messages

    # ------------------------------------------------------------------
    # Rolling summary
    # ------------------------------------------------------------------

    def get_summary(self) -> str:
        """Read and return the current ``conversation_summary.md`` text."""
        try:
            return self._summary_file.read_text(encoding="utf-8")
        except (FileNotFoundError, OSError):
            return ""

    def update_summary(self, summary: str) -> None:
        """Overwrite ``conversation_summary.md`` with *summary*."""
        try:
            self._summary_file.write_text(summary, encoding="utf-8")
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Agent Scratchpad
    # ------------------------------------------------------------------

    def _scratchpad_path(self, agent: str) -> Path:
        return self.scratchpad_dir / _agent_scratchpad_filename(agent)

    def scratchpad_write(self, agent: str, key: str, value: str) -> None:
        """
        Write (or overwrite) *key* → *value* in *agent*'s scratchpad.

        The scratchpad is a simple JSON dict persisted to disk.
        Agent slug is normalised to lowercase alphanumeric.
        """
        path = self._scratchpad_path(agent)
        notes: dict = _load_json(path, {})
        notes[key] = value
        _save_json(path, notes)

    def scratchpad_read(
        self,
        agent: str,
        key: str | None = None,
    ) -> dict | str | None:
        """
        Read from *agent*'s scratchpad.

        - ``key=None``  → return the entire notes dict
        - ``key=<str>`` → return the value for that key, or None if absent
        """
        path = self._scratchpad_path(agent)
        notes: dict = _load_json(path, {})
        if key is None:
            return notes
        return notes.get(key)

    def scratchpad_search(
        self,
        agent: str,
        query: str,
    ) -> list[tuple[str, str]]:
        """
        Keyword search across *agent*'s scratchpad values.

        Case-insensitive substring match.  Returns a list of (key, value)
        tuples whose value contains *query*.
        """
        path = self._scratchpad_path(agent)
        notes: dict = _load_json(path, {})
        query_lower = query.lower()
        results: list[tuple[str, str]] = []
        for k, v in notes.items():
            if query_lower in str(v).lower():
                results.append((k, v))
        return results

    # ------------------------------------------------------------------
    # RAG-style context retrieval
    # ------------------------------------------------------------------

    def get_relevant_context(
        self,
        agent: str,
        keywords: list[str],
        max_chars: int = 2000,
    ) -> str:
        """
        Assemble a concise context block for *agent* by searching:

        1. All findings (text match against key + value)
        2. Agent's own scratchpad (text match against value)
        3. The current summary (returned verbatim if it fits)

        The result is a formatted string ready to prepend to an LLM prompt.
        Empty sections are omitted.

        Parameters
        ----------
        agent:     Requesting agent (e.g. "red", "blue", "exec")
        keywords:  List of search terms (case-insensitive)
        max_chars: Soft limit on total output length (truncated with notice)
        """
        agent_label = agent.upper()
        lowered_kw = [kw.lower() for kw in keywords]

        def _matches(text: str) -> bool:
            t = text.lower()
            return any(kw in t for kw in lowered_kw)

        # ── 1. Relevant findings ──────────────────────────────────────
        findings = self.get_findings()
        matched_findings: list[str] = []
        for f in findings:
            # Include category in haystack so keyword "endpoint" matches category=endpoint
            haystack = f"{f.get('category', '')} {f.get('key', '')} {f.get('value', '')}"
            if not lowered_kw or _matches(haystack):
                src = f" (from {f['agent']})" if f.get("agent") else ""
                matched_findings.append(
                    f"  - {f['category']}: {f['key']}: {f['value']}{src}"
                )

        # ── 2. Agent scratchpad ───────────────────────────────────────
        notes: dict = _load_json(self._scratchpad_path(agent), {})
        matched_notes: list[str] = []
        for k, v in notes.items():
            if not lowered_kw or _matches(f"{k} {v}"):
                matched_notes.append(f"  - {k}: {v}")

        # ── 3. Summary (full, trimmed later if needed) ────────────────
        summary = self.get_summary().strip()

        # ── Assemble ──────────────────────────────────────────────────
        sections: list[str] = []

        if matched_findings:
            sections.append("[Findings]\n" + "\n".join(matched_findings))

        if matched_notes:
            sections.append("[Scratchpad]\n" + "\n".join(matched_notes))

        if summary:
            sections.append(f"[Summary]\n{summary}")

        if not sections:
            return ""

        header = f"=== MEMORY CONTEXT (agent: {agent_label}) ==="
        footer = "=== END MEMORY ==="
        body = "\n\n".join(sections)
        result = f"{header}\n{body}\n{footer}"

        # Soft truncation
        if len(result) > max_chars:
            cutoff = max_chars - len(footer) - 60
            result = (
                result[:cutoff]
                + "\n... [truncated for length] ...\n"
                + footer
            )

        return result
