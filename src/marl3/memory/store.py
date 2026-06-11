"""MemoryStore — every write method has an explicit read method.

MARL anti-pattern fixed: no more write-only files.
Reader-pair map:
  record_attempt()   → get_attempts()
  record_finding()   → get_findings()
  add_note()         → get_notes()
  update_strategy()  → get_strategy()
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("marl3.memory")


class MemoryStore:
    """Persistent memory for a run. Backed by memory.json."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._data: dict[str, Any] = {
            "attempts": {},       # bug_id → list of outcome strings
            "findings": {},       # bug_id → summary dict
            "notes": [],          # list of {bug_id, role, note}
            "strategies": {},     # bug_id → last approved strategy text
        }
        if path.exists():
            try:
                self._data = json.loads(path.read_text(encoding="utf-8"))
            except Exception as e:
                log.warning(f"Failed to load memory.json: {e}")

    # ── Writers ───────────────────────────────────────────────────────────────

    def record_attempt(self, bug_id: str, outcome: str) -> None:
        self._data["attempts"].setdefault(bug_id, []).append(outcome)
        self._flush()

    def record_finding(self, bug_id: str, summary: dict) -> None:
        self._data["findings"][bug_id] = summary
        self._flush()

    def add_note(self, bug_id: str, role: str, note: str) -> None:
        self._data["notes"].append({"bug_id": bug_id, "role": role, "note": note})
        self._flush()

    def update_strategy(self, bug_id: str, strategy: str) -> None:
        self._data["strategies"][bug_id] = strategy
        self._flush()

    # ── Readers (every writer has a paired reader) ────────────────────────────

    def get_attempts(self, bug_id: str) -> list[str]:
        return self._data["attempts"].get(bug_id, [])

    def get_findings(self) -> dict[str, dict]:
        return dict(self._data["findings"])

    def get_notes(self, bug_id: Optional[str] = None, role: Optional[str] = None) -> list[dict]:
        notes = self._data["notes"]
        if bug_id:
            notes = [n for n in notes if n["bug_id"] == bug_id]
        if role:
            notes = [n for n in notes if n["role"] == role]
        return notes

    def get_strategy(self, bug_id: str) -> Optional[str]:
        return self._data["strategies"].get(bug_id)

    def summary(self) -> dict:
        return {
            "total_bugs_attempted": len(self._data["attempts"]),
            "exploited": sum(
                1 for attempts in self._data["attempts"].values()
                if "EXPLOITED" in attempts
            ),
            "not_exploited": sum(
                1 for attempts in self._data["attempts"].values()
                if attempts and attempts[-1] == "NOT_EXPLOITED"
            ),
        }

    def _flush(self) -> None:
        self._path.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
