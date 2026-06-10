"""Content-addressed lossless body store.

Every HTTP request/response body is stored as bodies/<sha256>.bin.
Bodies are NEVER truncated. Deduplication is automatic (same content → same file).
"""
from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Optional

from ..contracts.body import BodyRef

log = logging.getLogger("marl3.body_store")


class BodyStore:
    """Writes bytes to bodies/<sha256>.bin; returns a BodyRef pointer.

    Thread/async safe for concurrent writes (each write is atomic via tmp+rename).
    """

    def __init__(self, directory: Path) -> None:
        self._dir = directory
        self._dir.mkdir(parents=True, exist_ok=True)

    def put(self, data: bytes, content_type: str = "application/octet-stream") -> BodyRef:
        """Store data losslessly; return BodyRef. Deduplicated by content hash."""
        ref = BodyRef.from_bytes(data, content_type)
        path = self._dir / f"{ref.blob_id}.bin"
        if not path.exists():
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(data)
            tmp.rename(path)
        return ref

    def get(self, blob_id: str) -> bytes:
        """Retrieve full body bytes by blob_id (sha256 hex)."""
        path = self._dir / f"{blob_id}.bin"
        if not path.exists():
            raise FileNotFoundError(f"Body blob not found: {blob_id}")
        return path.read_bytes()

    def get_text(self, blob_id: str, encoding: str = "utf-8") -> str:
        return self.get(blob_id).decode(encoding, errors="replace")

    def get_json(self, blob_id: str) -> object:
        import json
        return json.loads(self.get(blob_id))

    def exists(self, blob_id: str) -> bool:
        return (self._dir / f"{blob_id}.bin").exists()

    def total_bytes(self) -> int:
        return sum(f.stat().st_size for f in self._dir.glob("*.bin"))

    def prune_oldest(self, max_bytes: int) -> int:
        """Remove oldest blobs until total size is under max_bytes. Returns count removed."""
        blobs = sorted(self._dir.glob("*.bin"), key=lambda p: p.stat().st_mtime)
        removed = 0
        for blob in blobs:
            if self.total_bytes() <= max_bytes:
                break
            blob.unlink(missing_ok=True)
            removed += 1
        return removed
