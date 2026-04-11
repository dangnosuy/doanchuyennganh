"""
Shared utility functions for MARL — regex patterns, text extraction, prompt parsing.

Extracted from agent.py to avoid duplication across modules.
Only uses stdlib (re) — no external dependencies.
"""

import re


# ═══════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════

TRUNCATE_LIMIT = 15000

SEND_BLOCK_PATTERN = re.compile(
    r"={5,}SEND={5,}\s*\n(.+?)\n\s*={5,}END-SEND={5,}",
    re.DOTALL,
)
TAG_PATTERN = re.compile(r"\[(REDTEAM|BLUETEAM|USER|AGENT|APPROVED|DONE)\]\s*$", re.MULTILINE)


# ═══════════════════════════════════════════════════════════════
# TEXT EXTRACTION
# ═══════════════════════════════════════════════════════════════

def extract_send_block(text: str) -> str | None:
    """Extract content inside =========SEND========= ... =========END-SEND=========."""
    m = SEND_BLOCK_PATTERN.search(text)
    return m.group(1).strip() if m else None


def extract_next_tag(text: str) -> str | None:
    """Find the routing tag in text.

    Priority: AGENT > DONE > APPROVED > REDTEAM/BLUETEAM/USER.
    If multiple tags exist, the highest-priority one wins —
    e.g. [APPROVED] + [AGENT] in the same message → returns "AGENT"
    (so the Agent runs first, caller re-evaluates after).
    """
    matches = [m.group(1) for m in TAG_PATTERN.finditer(text)]
    if not matches:
        return None

    PRIORITY = ["AGENT", "DONE", "APPROVED", "REDTEAM", "BLUETEAM", "USER"]
    for tag in PRIORITY:
        if tag in matches:
            return tag
    return matches[-1]


def strip_tag(text: str) -> str:
    """Remove tags from text for display."""
    return TAG_PATTERN.sub("", text).rstrip()


def truncate(text: str, limit: int = TRUNCATE_LIMIT) -> str:
    """Truncate long output: 70% head + 25% tail."""
    if len(text) <= limit:
        return text
    h = int(limit * 0.70)
    t = int(limit * 0.25)
    return text[:h] + f"\n\n... [{len(text) - h - t} chars truncated] ...\n\n" + text[-t:]


# ═══════════════════════════════════════════════════════════════
# PROMPT PARSING — extract URL + credentials
# ═══════════════════════════════════════════════════════════════

_URL_PATTERN = re.compile(r"https?://[^\s<>\"']+")
_CRED_PATTERNS = [
    # username: X password: Y  (or user/pass variants)
    re.compile(
        r"(?:user(?:name)?|tai\s*khoan|account)\s*[:=]\s*(\S+)\s+"
        r"(?:pass(?:word)?|mat\s*khau)\s*[:=]\s*(\S+)",
        re.IGNORECASE,
    ),
    # credentials: user/pass  (slash separator)
    re.compile(
        r"(?:credential|login)\s*[:=]\s*(\S+)\s*/\s*(\S+)",
        re.IGNORECASE,
    ),
    # credentials: user:pass  (colon separator)
    re.compile(
        r"(?:credentials?|login)\s*[:=]\s*(\S+?)\s*:\s*(\S+)",
        re.IGNORECASE,
    ),
]


def parse_prompt(user_prompt: str) -> tuple[str | None, dict | None]:
    """Extract target URL and credentials from user prompt.

    Returns:
        (url, credentials) where credentials is {"username": ..., "password": ...} or None.
    """
    # URL
    url_match = _URL_PATTERN.search(user_prompt)
    url = url_match.group(0).rstrip(".,;)") if url_match else None

    # Credentials
    credentials = None
    for pat in _CRED_PATTERNS:
        m = pat.search(user_prompt)
        if m:
            credentials = {"username": m.group(1), "password": m.group(2)}
            break

    return url, credentials
