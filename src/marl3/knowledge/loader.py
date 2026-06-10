from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any


class KnowledgeError(Exception):
    """Raised when knowledge data cannot be loaded — never calls sys.exit()."""


def _load_json(filename: str) -> Any:
    """Load a JSON file from the knowledge/data package using importlib.resources.

    This works regardless of the current working directory (fixes the MARL exit(0) bug).
    """
    try:
        ref = resources.files("marl3.knowledge.data").joinpath(filename)
        with resources.as_file(ref) as p:
            with open(p, encoding="utf-8") as f:
                return json.load(f)
    except FileNotFoundError as e:
        raise KnowledgeError(f"Knowledge file not found: {filename}") from e
    except json.JSONDecodeError as e:
        raise KnowledgeError(f"Knowledge file is malformed JSON: {filename}: {e}") from e


def load_bac_patterns() -> list[dict]:
    return _load_json("bac_patterns.json")


def load_blf_patterns() -> list[dict]:
    return _load_json("blf_patterns.json")
