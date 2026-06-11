from __future__ import annotations

from pydantic import BaseModel, Field


class BodyRef(BaseModel):
    """Pointer to an HTTP body stored losslessly on disk as bodies/<sha256>.bin.

    Never store the raw body inline — always use BodyRef + BodyStore.get().
    The preview fields are informational only; they never substitute for the real body.
    """

    blob_id: str = Field(description="SHA-256 hex of the body bytes")
    size: int = Field(description="Byte length of the full body")
    content_type: str = Field(default="application/octet-stream")
    sha256: str = Field(description="Same as blob_id; explicit for clarity")
    # Informational preview — NEVER used for proof evaluation
    head_preview: str = Field(default="", description="First 200 bytes decoded as utf-8, errors replaced")
    tail_preview: str = Field(default="", description="Last 200 bytes decoded as utf-8, errors replaced")
    truncated: bool = Field(default=False, description="Always False — body is never truncated on disk")

    @classmethod
    def from_bytes(cls, data: bytes, content_type: str = "application/octet-stream") -> "BodyRef":
        import hashlib
        sha = hashlib.sha256(data).hexdigest()
        head = data[:200].decode("utf-8", errors="replace")
        tail = data[-200:].decode("utf-8", errors="replace") if len(data) > 200 else ""
        return cls(
            blob_id=sha,
            size=len(data),
            content_type=content_type,
            sha256=sha,
            head_preview=head,
            tail_preview=tail,
        )
