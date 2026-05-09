"""
Shared utility functions for MARL — regex patterns, text extraction, prompt parsing.

Extracted from agent.py to avoid duplication across modules.
Only uses stdlib (re) — no external dependencies.
Ngoại lệ: parse_prompt_llm() nhận OpenAI client từ caller, không import trực tiếp.
"""

import json
import re
from typing import TypedDict


# ═══════════════════════════════════════════════════════════════
# TYPES — multi-account credential support
# ═══════════════════════════════════════════════════════════════

class CredentialEntry(TypedDict):
    """Một cặp credentials cho 1 tài khoản cụ thể."""
    label: str       # nhãn ngắn gọn: "admin", "user1", "account2"...
    username: str
    password: str


class ParsedTarget(TypedDict):
    """Kết quả parse từ user prompt — URL + danh sách accounts + focus."""
    url: str
    credentials: list[CredentialEntry]  # rỗng nếu không có credentials
    focus: str                           # "IDOR", "BLF", "" nếu không đề cập


# ═══════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════

TRUNCATE_LIMIT = 15000
VERIFY_READ_ONLY_HINTS = (
    "read-only",
    "read only",
    "chỉ đọc",
    "chi doc",
    "không exploit",
    "khong exploit",
    "không post",
    "khong post",
    "không sửa",
    "khong sua",
    "không thay đổi",
    "khong thay doi",
    "không ghi",
    "khong ghi",
)

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


def has_verify_read_only_wording(text: str) -> bool:
    """Return True when text explicitly frames verify as read-only/non-mutating."""
    lower = text.lower()
    return any(hint in lower for hint in VERIFY_READ_ONLY_HINTS)


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
    # bare user:pass at end of string (no prefix) — e.g. "test:test" or "admin:secret"
    re.compile(r"\b(\w+)\s*:\s*(\w+)\s*$"),
]


def parse_prompt(user_prompt: str) -> tuple[str | None, dict | None]:
    """Extract target URL and credentials from user prompt.

    Returns:
        (url, credentials) where credentials is {"username": ..., "password": ...} or None.

    Giữ nguyên để backward-compat với main.py (extract URL sớm trước khi LLM start).
    Với multi-account, dùng parse_prompt_llm() thay thế.
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


# ═══════════════════════════════════════════════════════════════
# LLM-BASED PROMPT PARSING — multi-account support
# ═══════════════════════════════════════════════════════════════

_PARSE_SYSTEM_PROMPT = """\
Bạn là parser. Nhận user prompt bằng bất kỳ ngôn ngữ nào, trả về JSON thuần.

Schema bắt buộc:
{
  "url": "<URL đầy đủ bắt đầu bằng http:// hoặc https://>",
  "credentials": [
    {"label": "<tên ngắn>", "username": "<tên đăng nhập>", "password": "<mật khẩu>"}
  ],
  "focus": "<từ khóa mục tiêu nếu có, ví dụ IDOR hoặc BLF, rỗng nếu không có>"
}

Ví dụ input: "Test https://x.com tài khoản 1: admin/abc123, tài khoản 2: user/xyz, focus IDOR"
Ví dụ output: {"url": "https://x.com", "credentials": [{"label": "admin", "username": "admin", "password": "abc123"}, {"label": "user", "username": "user", "password": "xyz"}], "focus": "IDOR"}

Ví dụ input: "https://target.com credentials: wiener:peter"
Ví dụ output: {"url": "https://target.com", "credentials": [{"label": "wiener", "username": "wiener", "password": "peter"}], "focus": ""}

Chỉ trả JSON thuần, KHÔNG có markdown, KHÔNG có giải thích.\
"""


def parse_prompt_llm(user_prompt: str, client) -> ParsedTarget:
    """Dùng LLM để extract URL + list credentials + focus từ prompt tự do.

    Hỗ trợ nhiều tài khoản trong cùng 1 prompt: "tài khoản 1: a/b, tài khoản 2: c/d".

    Args:
        user_prompt: Raw user input (bất kỳ ngôn ngữ, format tự do).
        client:      OpenAI client instance (đã config sẵn base_url + api_key).

    Returns:
        ParsedTarget với credentials là list (có thể rỗng).
        Fallback về parse_prompt() cũ nếu LLM fail hoặc JSON không hợp lệ.
    """
    import os
    model = os.environ.get(
        "MARL_PARSER_MODEL",
        os.environ.get("MARL_RED_MODEL", "gpt-5-mini"),
    )

    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": _PARSE_SYSTEM_PROMPT},
                {"role": "user",   "content": user_prompt},
            ],
            temperature=0,
            max_tokens=512,
        )
        raw = (resp.choices[0].message.content or "").strip()

        # Strip markdown code fences nếu LLM vẫn wrap
        if raw.startswith("```"):
            raw = re.sub(r"^```[a-z]*\n?", "", raw)
            raw = re.sub(r"\n?```$", "", raw)

        data = json.loads(raw)

        # Validate + normalize
        url = str(data.get("url", "") or "").strip()
        if not url:
            raise ValueError("LLM trả về url rỗng")

        creds_raw = data.get("credentials", []) or []
        credentials: list[CredentialEntry] = []
        for i, c in enumerate(creds_raw):
            username = str(c.get("username", "")).strip()
            password = str(c.get("password", "")).strip()
            label    = str(c.get("label", "") or username or f"account{i+1}").strip()
            if username and password:
                credentials.append({"label": label, "username": username, "password": password})

        focus = str(data.get("focus", "") or "").strip()

        return ParsedTarget(url=url, credentials=credentials, focus=focus)

    except Exception:
        # ── Fallback về regex cũ ──────────────────────────────────
        fallback_url, fallback_cred = parse_prompt(user_prompt)
        credentials_fb: list[CredentialEntry] = []
        if fallback_cred:
            uname = fallback_cred["username"]
            credentials_fb = [CredentialEntry(
                label=uname,
                username=uname,
                password=fallback_cred["password"],
            )]
        return ParsedTarget(
            url=fallback_url or "",
            credentials=credentials_fb,
            focus="",
        )
