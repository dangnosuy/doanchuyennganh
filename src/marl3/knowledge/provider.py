from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from .loader import load_bac_patterns, load_blf_patterns, KnowledgeError

_DATA_DIR = Path(__file__).parent / "data"


def _parse_solutions(path: Path) -> dict[str, str]:
    """Parse a PortSwigger solutions markdown file into a dict keyed by pattern_id.

    Each section is separated by a `---` divider. The pattern_id is read from the
    `**Pattern:** BLF-XX` line inside each section.
    """
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    sections = re.split(r"\n---\n", text)
    out: dict[str, list[str]] = {}
    for section in sections:
        m = re.search(r"\*\*Pattern:\*\*\s*([\w-]+)", section)
        if not m:
            continue
        pid = m.group(1).strip()
        out.setdefault(pid, []).append(section.strip())
    return {pid: "\n\n---\n\n".join(blocks) for pid, blocks in out.items()}


class PlaybookProvider:
    """Cached access to pattern cards.

    card_for() returns only the card for the requested pattern_id (~1-2KB),
    never the full playbook (~19KB). This prevents bloating every LLM prompt.

    solution_for() returns the PortSwigger lab solution document for a pattern,
    or an empty string if no solution is available.
    """

    def __init__(self) -> None:
        bac = load_bac_patterns()
        blf = load_blf_patterns()
        self._cards: dict[str, dict] = {p["id"]: p for p in bac + blf}
        self._solutions: dict[str, str] = {
            **_parse_solutions(_DATA_DIR / "portswigger_blf_solutions.md"),
            **_parse_solutions(_DATA_DIR / "portswigger_bac_solutions.md"),
        }
        self._hunt_digest: dict[str, str] = self._build_hunt_digest()

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

    def _build_hunt_digest(self) -> dict[str, str]:
        """Extract Signals + Key Field Names + condensed Discovery Steps per pattern.

        Includes Discovery Steps (first 3 steps only) — these are the recon-phase
        actions Hunter should mirror, so showing them raises hypothesis quality.
        """
        digest: dict[str, list[str]] = {}
        for path in (
            _DATA_DIR / "portswigger_blf_solutions.md",
            _DATA_DIR / "portswigger_bac_solutions.md",
        ):
            if not path.exists():
                continue
            text = path.read_text(encoding="utf-8")
            for section in re.split(r"\n---\n", text):
                m = re.search(r"\*\*Pattern:\*\*\s*([\w-]+)", section)
                if not m:
                    continue
                pid = m.group(1).strip()
                parts: list[str] = []
                sig = re.search(r"### Signals.*?\n(.*?)(?=\n###|\Z)", section, re.DOTALL)
                if sig:
                    parts.append("Signals:\n" + sig.group(1).strip())
                kf = re.search(r"### Key Field Names\n(.*?)(?=\n###|\Z)", section, re.DOTALL)
                if kf:
                    parts.append("Key Field Names:\n" + kf.group(1).strip())
                # Include first 3 Discovery Steps — these are the recon checks Hunter
                # should perform to decide if this pattern applies to the current target.
                ds = re.search(r"### Discovery Steps.*?\n(.*?)(?=\n###|\Z)", section, re.DOTALL)
                if ds:
                    raw_steps = ds.group(1).strip()
                    # Keep numbered steps 1-3 only (trim the rest)
                    step_lines: list[str] = []
                    count = 0
                    for line in raw_steps.splitlines():
                        stripped = line.strip()
                        if re.match(r"^\d+\.", stripped):
                            count += 1
                            if count > 3:
                                break
                        if count >= 1:
                            step_lines.append(line)
                    if step_lines:
                        parts.append("Discovery Steps (first 3):\n" + "\n".join(step_lines))
                if parts:
                    digest.setdefault(pid, []).append("\n".join(parts))
        # Merge duplicate sections for the same pattern_id (e.g. BLF-05 appears twice)
        merged = {pid: "\n\n".join(blocks) for pid, blocks in digest.items()}

        # Synthesize minimal signal entries for patterns with no solutions doc coverage
        # so Hunt_signals is never empty for any known pattern.
        for pid, card in self._cards.items():
            if pid in merged:
                continue
            signal_lines: list[str] = []
            for sig in (card.get("signals") or []):
                if isinstance(sig, str):
                    signal_lines.append(f"- {sig}")
            if signal_lines:
                merged[pid] = "Signals (from pattern card):\n" + "\n".join(signal_lines[:5])
        return merged

    def hunt_signals_digest(self) -> dict[str, str]:
        """Return per-pattern Signals + Key Field Names for the Hunter prompt."""
        return self._hunt_digest

    def solution_for(self, pattern_id: str) -> str:
        """Return the PortSwigger lab solution document for a pattern.

        Returns an empty string if no solution is indexed for this pattern.
        """
        return self._solutions.get(pattern_id, "")

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
