"""
BAC & BLF Attack Pattern Playbook — Knowledge Base cho Red/Blue Team.

Mỗi pattern gồm:
  - id:          Mã ngắn dùng trong chiến lược (VD: BAC-01)
  - name:        Tên kỹ thuật
  - indicators:  Dấu hiệu trong recon data → match pattern này
  - technique:   Các bước tấn công cụ thể
  - variations:  Biến thể / bypass khi cách chính thất bại
  - success:     Tiêu chí xác nhận exploit thành công
  - severity:    Mức độ (Critical / High / Medium)

Export:
  get_playbook_text(category=None) → str  — render toàn bộ hoặc 1 category
  BAC_PATTERNS  — list[dict]
  BLF_PATTERNS  — list[dict]
"""

from typing import Optional
import json

# ═══════════════════════════════════════════════════════════════════════
# BAC — Broken Access Control Patterns
# ═══════════════════════════════════════════════════════════════════════

try:
    with open("knowledge/bac_knowledge.json", "r") as f:
        BAC_PATTERNS = json.load(f)
        if not isinstance(BAC_PATTERNS, list):
            raise Exception
except:
    print("bac_knowledge.json not found or empty/invalid. Script will now halt.")
    exit(0)


# ═══════════════════════════════════════════════════════════════════════
# BLF — Business Logic Flaw Patterns
# ═══════════════════════════════════════════════════════════════════════

try:
    with open("knowledge/blf_knowledge.json", "r") as f:
        BLF_PATTERNS = json.load(f)
        if not isinstance(BLF_PATTERNS, list):
            raise Exception
except:
    print("blf_knowledge.json not found or empty/invalid. Script will now halt.")
    exit(0)

# TODO: Kiểm tra p["indicators"], p["technique"], p["variations"]

# ═══════════════════════════════════════════════════════════════════════
# Helper: render patterns → text cho system prompt
# ═══════════════════════════════════════════════════════════════════════

def _render_pattern(p: dict) -> str:
    """Render một pattern thành chuỗi human-readable."""
    lines = [
        f"### {p['id']}: {p['name']}  [Severity: {p['severity']}]",
        "",
        "**Dấu hiệu nhận biết (indicators):**",
    ]
    for ind in p["indicators"]:
        lines.append(f"  • {ind}")

    lines.append("")
    lines.append("**Kỹ thuật tấn công:**")
    for step in p["technique"]:
        lines.append(f"  {step}")

    lines.append("")
    lines.append("**Biến thể / Bypass:**")
    for var in p["variations"]:
        lines.append(f"  - {var}")

    lines.append("")
    lines.append(f"**Tiêu chí thành công:** {p['success']}")
    lines.append("")
    return "\n".join(lines)


def get_playbook_text(category: Optional[str] = None) -> str:
    """
    Render playbook thành text cho system prompt.

    Args:
        category: "BAC", "BLF", hoặc None (cả hai)

    Returns:
        Formatted string chứa tất cả patterns.
    """
    sections = []

    if category is None or category.upper() == "BAC":
        sections.append("=" * 60)
        sections.append("BAC — BROKEN ACCESS CONTROL PATTERNS")
        sections.append("=" * 60)
        sections.append("")
        for p in BAC_PATTERNS:
            sections.append(_render_pattern(p))

    if category is None or category.upper() == "BLF":
        sections.append("=" * 60)
        sections.append("BLF — BUSINESS LOGIC FLAW PATTERNS")
        sections.append("=" * 60)
        sections.append("")
        for p in BLF_PATTERNS:
            sections.append(_render_pattern(p))

    return "\n".join(sections)


# ═══════════════════════════════════════════════════════════════════════
# Quick pattern lookup cho agents
# ═══════════════════════════════════════════════════════════════════════

ALL_PATTERNS = BAC_PATTERNS + BLF_PATTERNS

def get_pattern_by_id(pattern_id: str) -> Optional[dict]:
    """Lấy pattern theo ID (VD: 'BAC-01', 'BLF-03')."""
    for p in ALL_PATTERNS:
        if p["id"] == pattern_id:
            return p
    return None


def get_pattern_ids() -> list[str]:
    """Trả về danh sách tất cả pattern IDs."""
    return [p["id"] for p in ALL_PATTERNS]


if __name__ == "__main__":
    # Quick test
    print(get_playbook_text())
    print("\n--- Pattern IDs ---")
    print(get_pattern_ids())
