from __future__ import annotations

from functools import lru_cache
from typing import Optional

from .loader import load_bac_patterns, load_blf_patterns, KnowledgeError


class PlaybookProvider:
    """Cached access to pattern cards.

    card_for() returns only the card for the requested pattern_id (~1-2KB),
    never the full playbook (~19KB). This prevents bloating every LLM prompt.
    """

    def __init__(self) -> None:
        bac = load_bac_patterns()
        blf = load_blf_patterns()
        self._cards: dict[str, dict] = {p["id"]: p for p in bac + blf}

    def card_for(self, pattern_id: str) -> dict:
        """Return the knowledge card for a pattern ID.

        Raises KnowledgeError if the pattern is unknown.
        """
        if pattern_id not in self._cards:
            raise KnowledgeError(
                f"Unknown pattern_id: {pattern_id!r}. "
                f"Available: {sorted(self._cards.keys())}"
            )
        return self._cards[pattern_id]

    def all_ids(self) -> list[str]:
        return sorted(self._cards.keys())

    def bac_ids(self) -> list[str]:
        return [k for k in self._cards if k.startswith("BAC-")]

    def blf_ids(self) -> list[str]:
        return [k for k in self._cards if k.startswith("BLF-")]


@lru_cache(maxsize=1)
def get_provider() -> PlaybookProvider:
    """Module-level singleton — instantiated once per process."""
    return PlaybookProvider()
