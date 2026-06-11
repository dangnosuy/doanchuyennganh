"""Verify node — runs the 3-verifier panel and determines EXPLOITED / PROOF_QUALITY_FAIL."""
from __future__ import annotations

import logging

log = logging.getLogger("marl3.graph.verify")


async def run_verify(state: dict) -> dict:
    from ...verify.panel import VerifierPanel
    from ...recon.body_store import BodyStore

    dossier = state["dossier"]
    evidence = state["evidence"]
    cfg = state["cfg"]
    workspace = state["workspace"]
    llm = state["llm"]
    memory = state.get("memory")

    if evidence is None:
        return {"bug_status": "NOT_EXPLOITED", "error_message": "No evidence to verify"}

    body_store = BodyStore(workspace.bodies_dir)
    panel = VerifierPanel(llm=llm, cfg=cfg, body_store=body_store)

    log.info(f"[verify] {dossier.id} — panel adjudicating")
    verdicts = await panel.adjudicate(dossier=dossier, evidence=evidence)

    confirmed = sum(1 for v in verdicts if v.confirmed)

    # ── Proof-gate is the SOLE AUTHORITY for the verdict (data is source-of-truth) ──
    # The deterministic per-pattern gate reads real structured evidence and decides.
    # The LLM panel is ADVISORY only: its votes are recorded and shown in the report
    # as a confidence signal, but they NEVER change the verdict. This deliberately
    # removes both failure modes of letting the panel decide:
    #   - panel PROMOTING a finding over a FAILED gate (fake EXPLOITED), and
    #   - over-skeptical panel KILLING a data-proven finding (lost real bug).
    # If a gate produces a false positive/negative, fix the gate rule — don't override
    # data with model opinion.
    #   gate=EXPLOITED            → EXPLOITED
    #   gate=INFO_EXPOSURE_ONLY   → real but partial → terminal
    #   gate=FAILED/INCONCLUSIVE/"" → no data proof → re-debate
    gate = getattr(evidence, "verdict_status", "") or "FAILED"

    if gate == "EXPLOITED":
        bug_status = "EXPLOITED"
    elif gate == "INFO_EXPOSURE_ONLY":
        bug_status = "INFO_EXPOSURE_ONLY"
    else:
        bug_status = "PROOF_QUALITY_FAIL"

    exploited = bug_status == "EXPLOITED"

    rationale_parts = [
        f"Verifier {i+1}: {'CONFIRMED' if v.confirmed else 'REJECTED'} — {v.rationale}"
        for i, v in enumerate(verdicts)
    ]
    verifier_rationale = "\n".join(rationale_parts)

    log.info(
        f"[verify] {dossier.id} → gate={gate} panel={confirmed}/{len(verdicts)} → {bug_status}"
    )
    # Visual: show the proof-gate verdict (authority) + each verifier vote + final status.
    try:
        from ... import logging_setup as _ls
        markers_satisfied = [getattr(m.key, "value", str(m.key))
                             for m in getattr(evidence, "proof_markers", []) if getattr(m, "satisfied", False)]
        _ls.verify_result(dossier.id, gate, markers_satisfied, verdicts, bug_status)
    except Exception:
        pass
    _save_memory(memory, dossier, evidence, verdicts, exploited=exploited)
    _record_longterm(state, dossier, evidence, bug_status)

    return {
        "panel_verdicts": verdicts,
        "verifier_rationale": verifier_rationale,
        "verify_retries": state.get("verify_retries", 0) + 1,
        "bug_status": bug_status,
    }


def _record_longterm(state: dict, dossier, evidence, bug_status: str) -> None:
    """Write a verified episode to long-term memory (persists across runs).

    Provenance: this fires only after the deterministic proof-gate has run on real
    self-executed evidence — so we never learn from model opinion or target-controlled text.
    """
    import json as _json
    try:
        from ...memory.longterm import get_longterm, target_fingerprint, Episode
        cfg = state["cfg"]
        lt = get_longterm(cfg)
        if not lt.enabled:
            return
        recon = state.get("recon")
        workspace = state.get("workspace")
        outcome = {"EXPLOITED": "exploited", "INFO_EXPOSURE_ONLY": "info"}.get(bug_status, "failed")

        # Extract the actionable payload + satisfied markers from structured evidence.
        markers = []
        payload = ""
        for m in getattr(evidence, "proof_markers", []) or []:
            if not getattr(m, "satisfied", False):
                continue
            ex = dict(getattr(m, "extracted", {}) or {})
            markers.append({"key": getattr(m.key, "value", str(m.key)), "detail": m.detail, "extracted": ex})
            if not payload and any(k in ex for k in ("field", "value", "payload", "url")):
                payload = _json.dumps(ex)

        # Chain patterns (sequence/coupon) rarely carry a single value-payload — the transferable
        # knowledge is the ORDER of state-changing requests. Record that sequence so the chain
        # also becomes a reusable skill (fixes "0 skill for BLF-05"). Endpoints are already
        # path-templated ({id}) and host-free → target-agnostic by construction.
        if dossier.pattern_id in ("BLF-03", "BLF-05") and outcome == "exploited":
            seq: list[str] = []
            for ex in getattr(evidence, "exchanges", []) or []:
                if (ex.method or "").upper() in ("POST", "PUT", "PATCH", "DELETE") and 200 <= ex.status < 300:
                    step = f"{ex.method.upper()} {ex.endpoint}"
                    if not seq or seq[-1] != step:
                        seq.append(step)
            if seq:
                payload = _json.dumps({"sequence": seq})

        # Concise, structured summary from the proof marker (not the noisy exec notes).
        summary = markers[0]["detail"][:200] if markers else (getattr(evidence, "notes", "") or "")[:160]

        ep = Episode(
            target_fingerprint=target_fingerprint(recon) if recon else "unknown",
            target_url=getattr(recon, "target_url", "") if recon else "",
            pattern_id=dossier.pattern_id,
            endpoint_family=dossier.endpoint,
            method=dossier.method,
            outcome=outcome,
            verdict_status=getattr(evidence, "verdict_status", ""),
            payload=payload,
            proof_markers=_json.dumps(markers) if markers else "",
            summary=summary,
            run_id=(workspace.root.name if workspace else ""),
        )
        lt.record_episode(ep)
    except Exception as e:
        log.debug(f"long-term record skipped: {e}")


def _save_memory(memory, dossier, evidence, verdicts, exploited: bool) -> None:
    if memory is None:
        return
    try:
        confirmed = sum(1 for v in verdicts if v.confirmed)
        status = "EXPLOITED" if exploited else "NOT_EXPLOITED"
        memory.add_note(
            bug_id=dossier.id,
            role="verify",
            note=f"Panel: {confirmed}/{len(verdicts)} confirmed. Status: {status}. "
                 f"Exchanges: {len(getattr(evidence, 'exchanges', []))}",
        )
    except Exception:
        pass
