"""Knowledge base package for MARL — attack pattern registry."""

from .bac_blf_playbook import get_playbook_text, BAC_PATTERNS, BLF_PATTERNS

__all__ = ["get_playbook_text", "BAC_PATTERNS", "BLF_PATTERNS"]
