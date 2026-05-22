"""Shared authenticated-session helpers for Crawl, Manager, and Exec agents."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from urllib.parse import urlparse


AUTH_CONTEXT_FILENAME = "auth_context.json"


def safe_label(label: str | None) -> str:
    raw = str(label or "authenticated").strip()
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", raw).strip("._-")
    return safe or "authenticated"


def auth_context_path(workdir: str | Path) -> Path:
    return Path(workdir) / AUTH_CONTEXT_FILENAME


def storage_state_path(workdir: str | Path, label: str | None) -> Path:
    return Path(workdir) / f"auth_state_{safe_label(label)}.json"


def load_auth_context(workdir: str | Path) -> dict:
    path = auth_context_path(workdir)
    if not path.is_file():
        return {"version": 1, "target": "", "sessions": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"version": 1, "target": "", "sessions": []}
    if not isinstance(data, dict):
        return {"version": 1, "target": "", "sessions": []}
    sessions = data.get("sessions")
    if not isinstance(sessions, list):
        data["sessions"] = []
    data.setdefault("version", 1)
    data.setdefault("target", "")
    return data


def save_auth_context(workdir: str | Path, context: dict) -> Path:
    path = auth_context_path(workdir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(context or {})
    payload.setdefault("version", 1)
    payload.setdefault("sessions", [])
    payload["updated_at"] = int(time.time())
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def upsert_auth_session(workdir: str | Path, target: str, session: dict) -> Path:
    context = load_auth_context(workdir)
    context["target"] = target or context.get("target", "")
    label = str(session.get("label") or "authenticated")
    sessions = [
        item for item in context.get("sessions", [])
        if not isinstance(item, dict) or str(item.get("label") or "") != label
    ]
    merged = dict(session)
    merged.setdefault("label", label)
    merged.setdefault("created_at", int(time.time()))
    sessions.append(merged)
    context["sessions"] = sessions
    return save_auth_context(workdir, context)


def cookie_header_from_cookie_objects(cookies: list[dict] | None) -> str:
    pairs: list[str] = []
    for cookie in cookies or []:
        if not isinstance(cookie, dict):
            continue
        name = str(cookie.get("name") or "").strip()
        value = str(cookie.get("value") or "").strip()
        if name and value and "<value>" not in value.lower():
            pairs.append(f"{name}={value}")
    return "; ".join(pairs)


def normalize_cookie_objects(cookies: list[dict] | None, target_url: str = "") -> list[dict]:
    parsed = urlparse(target_url or "")
    fallback_domain = (parsed.hostname or parsed.netloc.split(":", 1)[0] or "").lstrip(".")
    is_https = parsed.scheme == "https"
    normalized: list[dict] = []
    for cookie in cookies or []:
        if not isinstance(cookie, dict):
            continue
        name = str(cookie.get("name") or "").strip()
        value = str(cookie.get("value") or "").strip()
        if not name or not value:
            continue
        domain = str(cookie.get("domain") or fallback_domain).strip().lstrip(".")
        if "://" in domain:
            domain = (urlparse(domain).hostname or fallback_domain).lstrip(".")
        normalized.append({
            "name": name,
            "value": value,
            "domain": domain or fallback_domain,
            "path": str(cookie.get("path") or "/"),
            "httpOnly": bool(cookie.get("httpOnly", False)),
            "secure": bool(cookie.get("secure", is_https)),
            "sameSite": cookie.get("sameSite"),
        })
    return normalized


def storage_state_has_material(storage_state: dict | None) -> bool:
    if not isinstance(storage_state, dict):
        return False
    if cookie_header_from_cookie_objects(storage_state.get("cookies") or []):
        return True
    for origin in storage_state.get("origins") or []:
        if not isinstance(origin, dict):
            continue
        for item in origin.get("localStorage") or []:
            if isinstance(item, dict) and item.get("name") and item.get("value"):
                return True
    return False


def cookies_from_storage_state_file(path: str | Path | None, target_url: str = "") -> list[dict]:
    if not path:
        return []
    state_path = Path(path)
    if not state_path.is_file():
        return []
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except Exception:
        return []
    return normalize_cookie_objects(state.get("cookies") or [], target_url)


def bearer_token_from_session(session: dict | None) -> str:
    """Extract a reusable bearer/JWT token from an auth-context session."""
    if not isinstance(session, dict):
        return ""
    explicit = str(session.get("bearer_token") or session.get("auth_token") or "").strip()
    if explicit:
        return explicit

    state = session.get("storage_state")
    if not isinstance(state, dict):
        path = session.get("storage_state_path")
        if path and Path(str(path)).is_file():
            try:
                state = json.loads(Path(str(path)).read_text(encoding="utf-8"))
            except Exception:
                state = {}

    token_names = (
        "token", "jwt", "access_token", "auth_token", "authentication",
        "id_token", "bearer", "authorization",
    )
    for origin in (state or {}).get("origins") or []:
        if not isinstance(origin, dict):
            continue
        for item in origin.get("localStorage") or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").lower()
            value = str(item.get("value") or "").strip()
            if value and any(token_name in name for token_name in token_names):
                return value
    return ""


def session_has_auth_material(session: dict | None) -> bool:
    if not isinstance(session, dict):
        return False
    if cookie_header_from_cookie_objects(session.get("cookies") or []):
        return True
    if bearer_token_from_session(session):
        return True
    state = session.get("storage_state")
    if storage_state_has_material(state if isinstance(state, dict) else None):
        return True
    path = session.get("storage_state_path")
    if path and Path(str(path)).is_file():
        try:
            state_payload = json.loads(Path(str(path)).read_text(encoding="utf-8"))
        except Exception:
            return False
        return storage_state_has_material(state_payload)
    return False


def choose_auth_session(workdir: str | Path, preferred_label: str | None = "") -> dict | None:
    context = load_auth_context(workdir)
    sessions = [s for s in context.get("sessions", []) if isinstance(s, dict)]
    if not sessions:
        return None
    preferred = str(preferred_label or "").strip().lower()
    if preferred:
        for session in sessions:
            if str(session.get("label") or "").strip().lower() == preferred and session_has_auth_material(session):
                return session
    for session in sessions:
        if session.get("auth_verified") and session_has_auth_material(session):
            return session
    for session in sessions:
        if session_has_auth_material(session):
            return session
    return None


def write_netscape_cookie_file(
    cookies: list[dict],
    path: str | Path,
    target_url: str = "",
) -> str:
    normalized = normalize_cookie_objects(cookies, target_url)
    target_path = Path(path)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    parsed = urlparse(target_url or "")
    fallback_domain = (parsed.hostname or parsed.netloc.split(":", 1)[0] or "localhost").lstrip(".")
    lines = ["# Netscape HTTP Cookie File"]
    for cookie in normalized:
        domain = str(cookie.get("domain") or fallback_domain).lstrip(".")
        include_subdomains = "TRUE" if domain.startswith(".") else "FALSE"
        secure = "TRUE" if cookie.get("secure") else "FALSE"
        lines.append(
            "\t".join([
                domain,
                include_subdomains,
                str(cookie.get("path") or "/"),
                secure,
                "0",
                str(cookie.get("name") or ""),
                str(cookie.get("value") or ""),
            ])
        )
    target_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return cookie_header_from_cookie_objects(normalized)
