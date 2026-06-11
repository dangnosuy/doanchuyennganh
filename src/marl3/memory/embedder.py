"""Lazy text embedder (fastembed) for long-term memory semantic retrieval.

Graceful by design: if fastembed is not installed, embed() returns None and callers
fall back to structured-only retrieval — no crash, no hard dependency. The ONNX model
downloads once on first use and is cached by fastembed.
"""
from __future__ import annotations

import logging

log = logging.getLogger("marl3.memory.embedder")

_MODEL = None
_TRIED = False


def _load(model_name: str):
    global _MODEL, _TRIED
    if _MODEL is not None:
        return _MODEL
    if _TRIED:
        return None
    _TRIED = True
    try:
        from fastembed import TextEmbedding
        _MODEL = TextEmbedding(model_name=model_name)
        log.info(f"Embedder loaded: {model_name}")
    except Exception as e:
        log.warning(f"Embedder unavailable ({e}) — semantic retrieval disabled, structured-only")
        _MODEL = None
    return _MODEL


def embed(text: str, model_name: str = "BAAI/bge-small-en-v1.5") -> list[float] | None:
    m = _load(model_name)
    if m is None or not text:
        return None
    try:
        vecs = list(m.embed([text]))
        return [float(x) for x in vecs[0]]
    except Exception as e:
        log.debug(f"embed failed: {e}")
        return None


def available(model_name: str = "BAAI/bge-small-en-v1.5") -> bool:
    return _load(model_name) is not None
