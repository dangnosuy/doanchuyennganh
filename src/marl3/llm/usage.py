from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class TokenUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    role: str = ""
    model: str = ""
    call_id: str = ""

    @property
    def total(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class UsageLedger:
    """Accumulates token usage across all LLM calls and writes usage.json."""

    def __init__(self, output_path: Optional[Path] = None) -> None:
        self._records: list[TokenUsage] = []
        self._path = output_path

    def record(self, usage: TokenUsage) -> None:
        self._records.append(usage)
        if self._path:
            self._flush()

    def total_tokens(self) -> int:
        return sum(u.total for u in self._records)

    def summary(self) -> dict:
        by_role: dict[str, int] = {}
        for u in self._records:
            by_role[u.role] = by_role.get(u.role, 0) + u.total
        return {
            "total_tokens": self.total_tokens(),
            "calls": len(self._records),
            "by_role": by_role,
        }

    def _flush(self) -> None:
        assert self._path
        data = {
            "summary": self.summary(),
            "records": [
                {
                    "role": u.role,
                    "model": u.model,
                    "prompt_tokens": u.prompt_tokens,
                    "completion_tokens": u.completion_tokens,
                    "call_id": u.call_id,
                }
                for u in self._records
            ],
        }
        self._path.write_text(json.dumps(data, indent=2), encoding="utf-8")
