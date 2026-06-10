from __future__ import annotations

import fnmatch
import json
from pathlib import Path


class WorkspaceFilesystem:
    def __init__(self, root: Path) -> None:
        self._root = Path(root).resolve()

    def _resolve(self, raw_path: str) -> Path:
        path = Path(raw_path or ".")
        candidate = path if path.is_absolute() else self._root / path
        resolved = candidate.resolve()
        if self._root not in resolved.parents and resolved != self._root:
            raise ValueError(f"Path escapes workspace root: {raw_path!r}")
        return resolved

    def read_text_file(self, path: str, max_chars: int = 20000) -> str:
        try:
            target = self._resolve(path)
            text = target.read_text(encoding="utf-8", errors="replace")
            if len(text) > max_chars:
                return json.dumps({
                    "path": str(target),
                    "truncated": True,
                    "content": text[:max_chars],
                })
            return json.dumps({
                "path": str(target),
                "truncated": False,
                "content": text,
            })
        except Exception as exc:
            return json.dumps({"error": str(exc), "path": path})

    def write_file(self, path: str, content: str) -> str:
        try:
            target = self._resolve(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            return json.dumps({"path": str(target), "bytes": len(content.encode("utf-8"))})
        except Exception as exc:
            return json.dumps({"error": str(exc), "path": path})

    def edit_file(self, path: str, old_text: str, new_text: str, replace_all: bool = False) -> str:
        try:
            target = self._resolve(path)
            text = target.read_text(encoding="utf-8")
            if old_text not in text:
                return json.dumps({"path": str(target), "updated": False, "reason": "old_text not found"})
            updated = text.replace(old_text, new_text) if replace_all else text.replace(old_text, new_text, 1)
            target.write_text(updated, encoding="utf-8")
            return json.dumps({"path": str(target), "updated": True, "bytes": len(updated.encode("utf-8"))})
        except Exception as exc:
            return json.dumps({"error": str(exc), "path": path})

    def list_directory(self, path: str = ".") -> str:
        try:
            target = self._resolve(path)
            if not target.exists():
                return json.dumps({"path": str(target), "entries": [], "error": "path not found"})
            entries = []
            for child in sorted(target.iterdir()):
                entries.append({
                    "name": child.name,
                    "type": "dir" if child.is_dir() else "file",
                    "size": child.stat().st_size if child.exists() and child.is_file() else 0,
                })
            return json.dumps({"path": str(target), "entries": entries})
        except Exception as exc:
            return json.dumps({"error": str(exc), "path": path})

    def search_files(self, pattern: str, path: str = ".", limit: int = 50) -> str:
        try:
            target = self._resolve(path)
            matches: list[str] = []
            for child in target.rglob("*"):
                if len(matches) >= limit:
                    break
                if child.is_file() and fnmatch.fnmatch(child.name, pattern):
                    matches.append(str(child))
            return json.dumps({"path": str(target), "pattern": pattern, "matches": matches, "truncated": len(matches) >= limit})
        except Exception as exc:
            return json.dumps({"error": str(exc), "path": path, "pattern": pattern})
