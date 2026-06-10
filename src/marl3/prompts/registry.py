"""Prompt template registry — the only place templates are loaded.

All prompts are English-only .md files in templates/.
Tests enforce that no template file is orphaned (unused) and no code constructs
prompts outside this module.
"""
from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, StrictUndefined, TemplateNotFound


class PromptError(Exception):
    """Raised when a template cannot be found or rendered."""


def _templates_dir() -> Path:
    # Direct path — works for both editable installs and installed packages
    return Path(__file__).parent / "templates"


class PromptRegistry:
    """Load and render Jinja2 prompt templates from prompts/templates/*.md."""

    def __init__(self) -> None:
        tdir = _templates_dir()
        self._env = Environment(
            loader=FileSystemLoader(str(tdir)),
            undefined=StrictUndefined,
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def render(self, name: str, **ctx) -> str:
        """Render template `name` (without .md extension) with the given context."""
        try:
            tmpl = self._env.get_template(f"{name}.md")
        except TemplateNotFound:
            raise PromptError(f"Prompt template not found: {name}.md")
        try:
            return tmpl.render(**ctx)
        except Exception as e:
            raise PromptError(f"Failed to render template {name}: {e}") from e

    def list_templates(self) -> list[str]:
        return [t.removesuffix(".md") for t in self._env.list_templates() if t.endswith(".md")]


_registry: Optional[PromptRegistry] = None


def get_registry() -> PromptRegistry:
    global _registry
    if _registry is None:
        _registry = PromptRegistry()
    return _registry


def render(name: str, **ctx) -> str:
    return get_registry().render(name, **ctx)
