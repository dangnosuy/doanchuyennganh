"""Long-term experiential memory — persists ACROSS runs.

The agent gets smarter the more it is used (verbal / in-context RL, NOT fine-tuning):
verified episodes are stored, and relevant lessons are retrieved into prompts on the
next run. This is separate from the per-run short-term MemoryStore (memory/store.py).

B1 = episodic tier, SQLite + STRUCTURED retrieval (no embeddings yet; B2 adds semantic).

Principles carried from the research:
- Provenance: only episodes that passed the deterministic proof-gate are written
  (self-executed + data-verified) → no memory poisoning from model opinion or target text.
- Graceful: any storage failure disables it silently — the pipeline keeps running.
- Retrieval is 2-step by design (structured filter now; semantic rank in B2).
"""
from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

log = logging.getLogger("marl3.memory.longterm")


@dataclass
class Episode:
    target_fingerprint: str
    target_url: str
    pattern_id: str
    endpoint_family: str
    method: str
    outcome: str             # exploited | info | failed
    verdict_status: str = ""
    payload: str = ""        # JSON: the actionable bit that worked (e.g. {"field":"amount","value":-100})
    proof_markers: str = ""  # JSON: satisfied markers [{key, detail, extracted}]
    summary: str = ""
    run_id: str = ""
    created_at: str = ""
    id: Optional[int] = None


_SCHEMA = """
CREATE TABLE IF NOT EXISTS episodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_fingerprint TEXT, target_url TEXT, pattern_id TEXT,
    endpoint_family TEXT, method TEXT, outcome TEXT, verdict_status TEXT,
    payload TEXT, proof_markers TEXT, summary TEXT, run_id TEXT, created_at TEXT,
    embedding BLOB
);
CREATE INDEX IF NOT EXISTS idx_ep_pattern ON episodes(pattern_id);
CREATE INDEX IF NOT EXISTS idx_ep_fp ON episodes(target_fingerprint);
CREATE INDEX IF NOT EXISTS idx_ep_outcome ON episodes(outcome);
CREATE TABLE IF NOT EXISTS rules (
    pattern_id TEXT PRIMARY KEY,
    successes INTEGER, distinct_targets INTEGER,
    confidence TEXT, payload_example TEXT, strategy TEXT, updated_at TEXT
);
"""

_COLS = ("target_fingerprint", "target_url", "pattern_id", "endpoint_family", "method",
         "outcome", "verdict_status", "payload", "proof_markers", "summary", "run_id", "created_at")
_SELECT_COLS = "id," + ",".join(_COLS) + ",embedding"


class LongTermMemory:
    def __init__(self, db_path: str, enabled: bool = True,
                 embedding_enabled: bool = False,
                 embedding_model: str = "BAAI/bge-small-en-v1.5") -> None:
        self._ok = False
        self._conn: Optional[sqlite3.Connection] = None
        self._emb_enabled = bool(embedding_enabled)
        self._emb_model = embedding_model
        if not enabled:
            log.info("Long-term memory disabled by config")
            return
        try:
            p = Path(db_path).expanduser()
            p.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(p))
            self._conn.row_factory = sqlite3.Row
            self._conn.executescript(_SCHEMA)
            # Migrate older DBs that predate the embedding column.
            try:
                self._conn.execute("ALTER TABLE episodes ADD COLUMN embedding BLOB")
            except Exception:
                pass
            self._conn.commit()
            self._ok = True
            log.info(f"Long-term memory ready: {p} ({self.count()} episodes, "
                     f"semantic={'on' if self._emb_enabled else 'off'})")
        except Exception as e:
            log.warning(f"Long-term memory disabled (cannot open {db_path}): {e}")

    @property
    def enabled(self) -> bool:
        return self._ok

    def count(self) -> int:
        if not self._ok:
            return 0
        try:
            return self._conn.execute("SELECT COUNT(*) FROM episodes").fetchone()[0]
        except Exception:
            return 0

    def record_episode(self, ep: Episode) -> None:
        if not self._ok:
            return
        if not ep.created_at:
            ep.created_at = datetime.now(timezone.utc).isoformat()
        blob = self._embed(_canonical(ep)) if self._emb_enabled else None
        try:
            cols = _COLS + ("embedding",)
            self._conn.execute(
                f"INSERT INTO episodes ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                tuple(getattr(ep, c) for c in _COLS) + (blob,),
            )
            self._conn.commit()
        except Exception as e:
            log.debug(f"record_episode failed: {e}")

    def _embed(self, text: str) -> Optional[bytes]:
        try:
            from .embedder import embed
            import numpy as np
            v = embed(text, self._emb_model)
            if v is None:
                return None
            return np.asarray(v, dtype="float32").tobytes()
        except Exception as e:
            log.debug(f"embed failed: {e}")
            return None

    def _select(self, where: str, params: tuple, limit: int) -> list[tuple[Episode, Optional[bytes]]]:
        """Fetch (Episode, embedding_blob) candidates, newest first."""
        if not self._ok:
            return []
        try:
            rows = self._conn.execute(
                f"SELECT {_SELECT_COLS} FROM episodes WHERE {where} ORDER BY id DESC LIMIT ?",
                params + (limit,),
            ).fetchall()
        except Exception as e:
            log.debug(f"query failed: {e}")
            return []
        out: list[tuple[Episode, Optional[bytes]]] = []
        for r in rows:
            ep = Episode(id=r["id"], **{c: r[c] for c in _COLS})
            out.append((ep, r["embedding"]))
        return out

    def _semantic_rank(self, pool, query_text: str):
        """Rerank (Episode, blob) pairs by cosine similarity to query_text.

        Falls back to the given (recency) order if embeddings are unavailable. Rows
        without an embedding sink to the bottom.
        """
        try:
            from .embedder import embed
            import numpy as np
        except Exception:
            return pool
        qv = embed(query_text, self._emb_model)
        if qv is None:
            return pool
        q = np.asarray(qv, dtype="float32")
        q = q / (float(np.linalg.norm(q)) + 1e-9)
        scored = []
        for ep, blob in pool:
            if not blob:
                scored.append((-1.0, ep, blob))
                continue
            v = np.frombuffer(blob, dtype="float32")
            v = v / (float(np.linalg.norm(v)) + 1e-9)
            scored.append((float(q @ v), ep, blob))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [(ep, blob) for _, ep, blob in scored]

    def lessons_for_hunt(self, fingerprint: str, query_text: str = "", limit: int = 25) -> list[Episode]:
        """Tier A (concrete) lessons for the hunter — ONLY from the SAME target.

        Anti-overfit: concrete past results (exact endpoints/values) are reused only when we
        are looking at the same target again. Cross-target generalisation is delivered
        separately by `rules_for_hunt` (which carry the ≥2-target validation gate), so a
        target's specifics never leak into a different target's hunt.
        """
        pool = self._select(
            "outcome IN ('exploited','info') AND target_fingerprint = ?", (fingerprint,), 200)
        if query_text and self._emb_enabled:
            ranked = self._semantic_rank(pool, query_text)
        else:
            ranked = sorted(pool, key=lambda t: (t[0].outcome == "exploited", t[0].id or 0), reverse=True)
        return [ep for ep, _ in ranked[:limit]]

    def skills_for_exec(self, pattern_id: str, fingerprint: str = "",
                        query_text: str = "", limit: int = 5) -> dict:
        """Exec skills, split into two anti-overfit tiers:

          same  = exploited episodes on THIS target → reuse the concrete payload directly.
          cross = techniques from OTHER targets → injected ONLY as ABSTRACTED technique
                  (no URL/host/title) AND ONLY if validated on ≥2 distinct targets,
                  deduped by technique. This is what stops TechShop URLs leaking into a
                  VulnShop run while still transferring the generalisable 'how'.
        """
        pool = self._select("pattern_id = ? AND outcome = 'exploited' AND payload != ''",
                            (pattern_id,), 200)
        if query_text and self._emb_enabled:
            ranked = [ep for ep, _ in self._semantic_rank(pool, query_text)]
        else:
            ranked = [ep for ep, _ in sorted(pool, key=lambda t: t[0].id or 0, reverse=True)]

        same = [e for e in ranked if e.target_fingerprint == fingerprint and fingerprint]
        cross = [e for e in ranked if not (e.target_fingerprint == fingerprint and fingerprint)]

        # how many DISTINCT targets each cross-target technique worked on
        from collections import defaultdict
        tgt_count: dict = defaultdict(set)
        for e in cross:
            tgt_count[_technique_key(e)].add(e.target_fingerprint)

        same_out, seen = [], set()
        for e in same:
            k = _technique_key(e)
            if k in seen:
                continue
            seen.add(k); same_out.append(e)
            if len(same_out) >= limit:
                break

        cross_out, cseen = [], set()
        for e in cross:
            k = _technique_key(e)
            if k in cseen or len(tgt_count[k]) < 2:   # ≥2-target trust gate
                continue
            cseen.add(k); cross_out.append(e)
            if len(cross_out) >= limit:
                break

        return {"same": same_out, "cross": cross_out}

    # ── distillation: episodic → cross-target rules ─────────────────────────

    def distill(self, min_successes: int = 3, min_targets: int = 2) -> int:
        """Promote repeated exploited episodes into cross-target rules.

        A pattern that succeeded >= min_successes times becomes a rule. Confidence is
        'validated' only if it worked across >= min_targets DISTINCT targets (anti-overfit);
        otherwise 'emerging' (proven on one target, promising elsewhere). Returns #rules.
        """
        if not self._ok:
            return 0
        try:
            rows = self._conn.execute(
                "SELECT pattern_id, COUNT(*) AS succ, COUNT(DISTINCT target_fingerprint) AS tgts "
                "FROM episodes WHERE outcome='exploited' GROUP BY pattern_id"
            ).fetchall()
        except Exception as e:
            log.debug(f"distill query failed: {e}")
            return 0
        n = 0
        now = datetime.now(timezone.utc).isoformat()
        for r in rows:
            pid, succ, tgts = r["pattern_id"], r["succ"], r["tgts"]
            if succ < min_successes:
                continue
            confidence = "validated" if tgts >= min_targets else "emerging"
            ex = self._conn.execute(
                "SELECT payload, summary FROM episodes WHERE pattern_id=? AND outcome='exploited' "
                "AND payload!='' ORDER BY id DESC LIMIT 1", (pid,)
            ).fetchone()
            payload = ex["payload"] if ex else ""
            strategy = ex["summary"] if ex else ""
            try:
                self._conn.execute(
                    "INSERT INTO rules (pattern_id,successes,distinct_targets,confidence,payload_example,strategy,updated_at) "
                    "VALUES (?,?,?,?,?,?,?) ON CONFLICT(pattern_id) DO UPDATE SET "
                    "successes=excluded.successes, distinct_targets=excluded.distinct_targets, "
                    "confidence=excluded.confidence, payload_example=excluded.payload_example, "
                    "strategy=excluded.strategy, updated_at=excluded.updated_at",
                    (pid, succ, tgts, confidence, payload, strategy, now),
                )
                n += 1
            except Exception as e:
                log.debug(f"distill upsert failed for {pid}: {e}")
        self._conn.commit()
        if n:
            log.info(f"Distilled {n} cross-target rule(s) from episodic memory")
        return n

    def rules_for_hunt(self, limit: int = 15) -> list[dict]:
        if not self._ok:
            return []
        try:
            rows = self._conn.execute(
                "SELECT * FROM rules ORDER BY (confidence='validated') DESC, successes DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    # ── inspection & anti-stale maintenance ─────────────────────────────────

    def stats(self) -> dict:
        if not self._ok:
            return {"enabled": False}
        try:
            by_outcome = dict(self._conn.execute(
                "SELECT outcome, COUNT(*) FROM episodes GROUP BY outcome").fetchall())
            by_pattern = dict(self._conn.execute(
                "SELECT pattern_id, COUNT(*) FROM episodes GROUP BY pattern_id "
                "ORDER BY COUNT(*) DESC").fetchall())
            n_rules = self._conn.execute("SELECT COUNT(*) FROM rules").fetchone()[0]
            n_emb = self._conn.execute("SELECT COUNT(*) FROM episodes WHERE embedding IS NOT NULL").fetchone()[0]
            return {
                "enabled": True, "total": self.count(), "with_embedding": n_emb,
                "by_outcome": by_outcome, "by_pattern": by_pattern, "rules": n_rules,
                "semantic": self._emb_enabled,
            }
        except Exception as e:
            log.debug(f"stats failed: {e}")
            return {"enabled": True, "error": str(e)}

    def recent(self, limit: int = 20) -> list[Episode]:
        return [ep for ep, _ in self._select("1=1", (), limit)]

    def prune(self, max_age_days: int = 90, drop_failed_age_days: int = 14) -> int:
        """Anti-stale: drop episodes older than max_age_days, and failed attempts older
        than drop_failed_age_days (stale negatives age out faster). Also delete rules not
        refreshed within max_age_days (a pattern that stopped working). Returns rows removed.
        """
        if not self._ok:
            return 0
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(days=max_age_days)).isoformat()
        cutoff_fail = (now - timedelta(days=drop_failed_age_days)).isoformat()
        removed = 0
        try:
            cur = self._conn.execute("DELETE FROM episodes WHERE created_at < ?", (cutoff,))
            removed += cur.rowcount or 0
            cur = self._conn.execute(
                "DELETE FROM episodes WHERE outcome='failed' AND created_at < ?", (cutoff_fail,))
            removed += cur.rowcount or 0
            self._conn.execute("DELETE FROM rules WHERE updated_at < ?", (cutoff,))
            self._conn.commit()
        except Exception as e:
            log.debug(f"prune failed: {e}")
        return removed

    def close(self) -> None:
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass


def _canonical(ep: Episode) -> str:
    """Canonical string embedded for semantic retrieval (compact, signal-rich)."""
    return f"{ep.pattern_id} {ep.method} {ep.endpoint_family} outcome={ep.outcome} {ep.summary}".strip()


# ── Learning layer: turn a concrete episode into a TARGET-AGNOSTIC technique ──
# This is the anti-overfit core: cross-target injection must carry the *technique*
# (the "HOW"), never a target's concrete URL/host/title (the "WHAT").

_PATH_NOISE = {"api", "v1", "v2", "v3", "{id}", "{uuid}", ""}


def _endpoint_role(endpoint_family: str) -> str:
    """Last meaningful path segment as a transferable 'role'.
    /wallet/transfer → 'transfer', /api/v1/users → 'users', /coupon/apply → 'apply'.
    Merges e.g. /transfer (one target) and /wallet/transfer (another) to the same role,
    so a technique can be COUNTED across targets for the ≥2-target trust gate."""
    segs = [s for s in (endpoint_family or "").split("/") if s.lower() not in _PATH_NOISE]
    return segs[-1].lower() if segs else (endpoint_family or "endpoint").lower()


def _value_category(v) -> str:
    """The transferable lesson is the CATEGORY of value, not the exact number."""
    try:
        n = float(v)
    except (TypeError, ValueError):
        return "another user's / out-of-policy value"
    if n < 0:
        return "a negative value"
    if n == 0:
        return "zero"
    if n > 1_000_000:
        return "an extreme value"
    return "an out-of-range value"


def _payload_obj(ep: "Episode") -> dict:
    try:
        o = json.loads(ep.payload) if ep.payload else {}
        return o if isinstance(o, dict) else {}
    except Exception:
        return {}


def _technique_key(ep: "Episode") -> tuple:
    """Target-agnostic identity of a technique — used for dedup AND for counting how
    many DISTINCT targets a technique worked on (the ≥2-target anti-overfit gate)."""
    obj = _payload_obj(ep)
    field = (obj.get("field") or "").lower()
    return (ep.pattern_id, _endpoint_role(ep.endpoint_family), field)


def _abstract_technique(ep: "Episode") -> str:
    """One-line transferable technique with ALL target-specifics (host/url/title) stripped."""
    pid, role = ep.pattern_id, _endpoint_role(ep.endpoint_family)
    obj = _payload_obj(ep)
    seq = obj.get("sequence")
    if seq:  # chain recipe — the step ORDER is the transferable knowledge
        return f"{pid}: multi-step chain — {' → '.join(seq)} (map endpoints to THIS target)"
    field, val = obj.get("field"), obj.get("value")
    if pid in ("BLF-01", "BLF-05") and field is not None:
        return (f"{pid}: POST {_value_category(val)} to a money field (seen named '{field}') "
                f"on a '{role}' action; JSON body; success = 2xx accepted with no validation error.")
    if pid in ("BLF-02", "BLF-06", "BLF-07") and field is not None:
        return (f"{pid}: POST {_value_category(val)} to a quantity field (seen named '{field}') "
                f"on a '{role}' action.")
    if pid == "BAC-02":
        return (f"{pid}: send a tampered cookie (role=admin / is_admin=1 / user_id=other) to a "
                f"privileged '{role}' endpoint; success = 200 + privileged content.")
    if pid == "BAC-03":
        return (f"{pid}: change a path id or user_id cookie to ANOTHER user's on a '{role}' "
                f"resource; success = a different owner's data returned.")
    if pid == "BAC-01":
        return (f"{pid}: request the '{role}' endpoint as anon / low-priv; "
                f"success = other users' data or PII returned.")
    if pid == "BAC-06":
        return f"{pid}: force-browse the unlinked privileged '{role}' endpoint."
    base = f"{pid}: technique on a '{role}' action"
    if field is not None:
        base += f" (field '{field}', {_value_category(val)})"
    return base


# ── target fingerprint (per-target memory key) ───────────────────────────────

def target_fingerprint(recon) -> str:
    """Compact, stable fingerprint of a target for per-target memory keying."""
    hints = "+".join(sorted(getattr(recon, "api_hints", []) or [])) or "unknown"
    host = ""
    try:
        host = urlparse(recon.target_url).netloc
    except Exception:
        pass
    endpoints = getattr(recon, "endpoints", []) or []
    has_uuid = any("{uuid}" in getattr(e, "endpoint", "") for e in endpoints)
    has_int = any("{id}" in getattr(e, "endpoint", "") for e in endpoints)
    idfmt = "uuid" if has_uuid else ("int" if has_int else "none")
    return f"{host}|stack={hints}|ids={idfmt}"


# ── retrieval → prompt text helpers ──────────────────────────────────────────

def render_hunt_lessons(episodes: list[Episode], max_items: int = 12) -> str:
    """Render past lessons as a compact prompt block for the hunter."""
    if not episodes:
        return ""
    lines = ["## Prior results ON THIS TARGET (previous runs — still verify):"]
    seen: set[tuple] = set()
    for ep in episodes:
        key = (ep.pattern_id, ep.endpoint_family, ep.outcome)
        if key in seen:
            continue
        seen.add(key)
        tag = "WORKED" if ep.outcome == "exploited" else "partial"
        lines.append(f"- {tag}: {ep.pattern_id} on {ep.method} {ep.endpoint_family}"
                     + (f" — {ep.summary}" if ep.summary else ""))
        if len(lines) > max_items:
            break
    return "\n".join(lines)


def render_rules(rules: list[dict], max_items: int = 12) -> str:
    """Render distilled cross-target rules — these carry higher trust than raw episodes."""
    if not rules:
        return ""
    lines = ["## Distilled rules (learned across runs — prioritise these):"]
    for r in rules[:max_items]:
        tag = str(r.get("confidence", "")).upper()
        line = (f"- [{tag}] {r.get('pattern_id')}: worked {r.get('successes')}x "
                f"on {r.get('distinct_targets')} target(s)")
        if r.get("payload_example"):
            line += f" — payload {r['payload_example']}"
        if r.get("strategy"):
            line += f"; {r['strategy']}"
        lines.append(line)
    return "\n".join(lines)


def render_exec_skills(skills, max_items: int = 4) -> str:
    """Render exec skills: SAME-target concrete payloads + CROSS-target abstracted techniques.

    Accepts the dict from skills_for_exec ({"same":[...], "cross":[...]}); also tolerates a
    bare list (treated as same-target) for backward compatibility.
    """
    if isinstance(skills, list):
        skills = {"same": skills, "cross": []}
    same = (skills or {}).get("same", [])
    cross = (skills or {}).get("cross", [])
    lines: list[str] = []
    if same:
        lines.append("Proven on THIS target in a previous run (reuse the payload directly):")
        for ep in same[:max_items]:
            if ep.payload:
                lines.append(f"- {ep.method} {ep.endpoint_family}: {ep.payload}")
    if cross:
        lines.append("General techniques that worked on OTHER targets — adapt to THIS target's "
                     "real endpoints/values; do NOT copy old URLs:")
        seen = set()
        for ep in cross[:max_items]:
            t = _abstract_technique(ep)
            if t in seen:
                continue
            seen.add(t)
            lines.append(f"- {t}")
    return "\n".join(lines) if len(lines) > 1 else ""


# ── singleton (one connection per db_path per process) ───────────────────────

_INSTANCES: dict[str, LongTermMemory] = {}


def get_longterm(cfg) -> LongTermMemory:
    mem = getattr(cfg, "memory", None)
    enabled = bool(getattr(mem, "longterm_enabled", True)) if mem else True
    db_path = getattr(mem, "db_path", "~/.local/share/marl3/memory.db") if mem else "~/.local/share/marl3/memory.db"
    emb_enabled = bool(getattr(mem, "embedding_enabled", False)) if mem else False
    emb_model = getattr(mem, "embedding_model", "BAAI/bge-small-en-v1.5") if mem else "BAAI/bge-small-en-v1.5"
    key = db_path if enabled else "__disabled__"
    if key not in _INSTANCES:
        _INSTANCES[key] = LongTermMemory(db_path, enabled=enabled,
                                         embedding_enabled=emb_enabled, embedding_model=emb_model)
    return _INSTANCES[key]
