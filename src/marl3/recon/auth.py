"""Single auth session store — the one source of truth for all session data.

Replaces MARL's 4 parallel auth files:
  auth_state_*.json + crawl_raw.json auth slice + auth_context.json + base_cookies_*.txt
→ one sessions.json file.
"""
from __future__ import annotations

import json
import re
import logging
from pathlib import Path
from typing import Optional

from ..contracts.recon import AuthProfile
from ..workspace import validate_auth_label

log = logging.getLogger("marl3.auth")

_LABEL_RE = re.compile(r"^[a-z0-9_]{1,32}$")


class AuthSessionStore:
    """Manages auth profiles for a run.

    All auth is accessed by label (validated against regex).
    Writing an invalid label raises ValueError immediately — preventing garbage files.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._profiles: dict[str, AuthProfile] = {}
        if path.exists():
            self._load()

    def add(self, profile: AuthProfile) -> None:
        validate_auth_label(profile.label)
        self._profiles[profile.label] = profile
        self._save()

    def get(self, label: str) -> AuthProfile:
        if label not in self._profiles:
            raise KeyError(f"Auth profile not found: {label!r}. Known: {list(self._profiles)}")
        return self._profiles[label]

    def all_profiles(self) -> list[AuthProfile]:
        return list(self._profiles.values())

    def label_role_map(self) -> dict[str, str]:
        return {p.label: p.role for p in self._profiles.values()}

    def headers_for(self, label: str) -> dict[str, str]:
        """Return the Authorization/Cookie headers dict for the given label."""
        p = self.get(label)
        headers: dict[str, str] = {}
        if p.bearer_token:
            headers["Authorization"] = f"Bearer {p.bearer_token}"
        if p.cookie_header:
            headers["Cookie"] = p.cookie_header
        return headers

    def storage_state_for(self, label: str) -> Optional[dict]:
        """Return Playwright storage state dict for the given label, if any."""
        p = self.get(label)
        if p.storage_state_path and Path(p.storage_state_path).exists():
            with open(p.storage_state_path) as f:
                return json.load(f)
        return None

    def _save(self) -> None:
        data = [p.model_dump() for p in self._profiles.values()]
        self._path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _load(self) -> None:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            for item in data:
                p = AuthProfile.model_validate(item)
                self._profiles[p.label] = p
        except Exception as e:
            log.warning(f"Failed to load sessions.json: {e}")
