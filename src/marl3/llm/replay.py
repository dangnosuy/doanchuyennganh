from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from ..contracts.enums import Role
from .usage import UsageLedger


class FixtureLLMClient:
    """Deterministic replay client for offline tests.

    Reads responses from a fixture file; raises AssertionError on unexpected calls.
    Fixture format: list of {"role": str, "response": str} objects.
    """

    def __init__(self, fixture_path: Path, ledger: Optional[UsageLedger] = None) -> None:
        self._ledger = ledger or UsageLedger()
        with open(fixture_path, encoding="utf-8") as f:
            self._queue: list[dict] = json.load(f)
        self._idx = 0

    def model_for(self, role: Role | str) -> str:
        return "fixture"

    async def chat(
        self,
        messages: list[dict],
        role: Role | str,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        call_id: Optional[str] = None,
    ) -> str:
        if self._idx >= len(self._queue):
            raise AssertionError(
                f"FixtureLLMClient: no more queued responses (call #{self._idx})"
            )
        entry = self._queue[self._idx]
        self._idx += 1
        return entry["response"]

    async def close(self) -> None:
        pass
