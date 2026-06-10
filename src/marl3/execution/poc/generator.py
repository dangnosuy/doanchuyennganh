"""PocFormatter — writes a Burp-style HTTP request/response PoC.

No Python script, no py_compile, no re-run.
Just the raw exchanges that proved exploitation, formatted for humans.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from ...contracts.evidence import Evidence
from ...contracts.results import PocArtifact
from ...recon.body_store import BodyStore

log = logging.getLogger("marl3.poc")


class PocGenerator:
    def __init__(self, body_store: BodyStore, workspace_root: Path) -> None:
        self._bs = body_store
        self._root = workspace_root

    def generate(
        self,
        evidence: Evidence,
        target_url: str,
        poc_path: Path,
        proof_runtime_path: Path | None = None,
        required_markers: list[str] | None = None,
    ) -> PocArtifact:
        """Write a Burp-style HTTP PoC file from evidence exchanges."""
        # Pick the proof-relevant exchanges (satisfied markers), fallback to all
        proof_seqs = set()
        for m in evidence.proof_markers:
            if m.satisfied:
                proof_seqs.update(m.exchange_seqs)
        proof_exchanges = [e for e in evidence.exchanges if e.seq in proof_seqs] or evidence.exchanges[:6]

        lines: list[str] = []
        lines.append(f"# Proof of Concept: {evidence.bug_id} — {evidence.pattern_id}")
        lines.append(f"# Target: {target_url}")
        lines.append("")

        # Proof summary
        satisfied = [m for m in evidence.proof_markers if m.satisfied]
        if satisfied:
            lines.append("## Proof Markers")
            for m in satisfied:
                lines.append(f"  [+] {m.key.value}: {m.detail}")
            lines.append("")

        lines.append("## HTTP Evidence")
        lines.append("")

        for i, ex in enumerate(proof_exchanges, 1):
            lines.append(f"### Step {i} — {ex.label or ex.url}")
            lines.append("")

            # Request — show ALL recorded headers, including the (sanitized) Cookie/Authorization.
            # The recorder already masks long session tokens but keeps tampered fields like
            # role=admin / user_id=N visible, which IS the exploit payload (Codex #15).
            # Do NOT invent a fake bearer token.
            lines.append(f"{ex.method} {ex.url} HTTP/1.1")
            lines.append(f"# actor: {ex.actor}")
            for k, v in (ex.request_headers or {}).items():
                lines.append(f"{k}: {v}")
            req_body = self._read_body(ex.request_body_ref)
            if req_body:
                lines.append("")
                lines.append(req_body[:500])
            lines.append("")

            # Response
            lines.append(f"HTTP/1.1 {ex.status}")
            resp_body = self._read_body(ex.response_body_ref)
            if resp_body:
                lines.append("")
                lines.append(resp_body[:800])
            lines.append("")
            lines.append("---")
            lines.append("")

        # Notes from exec agent
        if evidence.notes:
            lines.append("## Exec Agent Findings")
            lines.append(evidence.notes[:1000])
            lines.append("")

        # Change extension to .txt
        poc_txt = poc_path.with_suffix(".txt")
        poc_txt.write_text("\n".join(lines), encoding="utf-8")

        artifact = PocArtifact(
            path=str(poc_txt.relative_to(self._root)),
            runnable=True,
            reproduced=bool(satisfied),
            exchange_count=len(proof_exchanges),
            sha256="",
        )
        log.info(f"{evidence.bug_id}: PoC → {poc_txt.name} ({len(proof_exchanges)} exchanges, reproduced={artifact.reproduced})")
        return artifact

    def _read_body(self, ref) -> str:
        if not ref:
            return ""
        try:
            raw = self._bs.get(ref.blob_id)
            try:
                return json.dumps(json.loads(raw), indent=2)
            except Exception:
                return raw.decode("utf-8", errors="replace")
        except Exception:
            return ref.head_preview or ""
