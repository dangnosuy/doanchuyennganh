"""Verify node — VerifierPanel as pre-gate sanity check, ProofGate as authoritative verdict.

Flow:
  1. VerifierPanel runs on raw evidence (no proof_markers yet) — 3 independent LLM agents.
  2. Gate decision:
     - 0/N confirmed AND no 2xx response → PROOF_QUALITY_FAIL immediately.
       Execution clearly yielded nothing; ProofGate/classifier would also fail.
     - 0/N confirmed BUT has 2xx → safety-net: still run ProofGate.
       Panel may misread non-English or complex response bodies; ProofGate's
       deterministic classifier catches these cases.
     - ≥1 confirmed → run ProofGate (normal path).
  3. ProofGate verdict is authoritative: EXPLOITED / INFO_EXPOSURE_ONLY / PROOF_QUALITY_FAIL.

Rationale: Panel is cheap (broad exchange-level read) and catches obvious failures early
(all 4xx responses, execution errors) before spending classifier tokens — but never
overrides ProofGate when execution actually produced a successful HTTP response.
"""
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
    verification_questions: list[str] = state.get("frozen_verification_questions") or []

    # ── STEP 1: Panel pre-check on raw evidence ──────────────────────────────
    # Panel reads exchanges + answers verification questions from the debate.
    # proof_markers are empty at this point (ProofGate hasn't run yet).
    log.info(f"[verify] {dossier.id} — panel pre-check (before ProofGate)")
    verdicts, questions_confirmed = await panel.adjudicate(
        dossier=dossier,
        evidence=evidence,
        verification_questions=verification_questions,
    )
    pre_confirmed = sum(1 for v in verdicts if v.confirmed)
    # LLM question vote: ≥2/3 questions confirmed by majority of verifiers.
    n_questions = len(verification_questions)
    llm_questions_pass = n_questions >= 2 and questions_confirmed >= 2

    # ── ABLATION: skip ProofGate, panel majority vote is final authority ──────
    if getattr(cfg.verifier, "skip_proofgate", False):
        majority = len(verdicts) / 2
        if pre_confirmed > majority or llm_questions_pass:
            bug_status = "EXPLOITED"
        elif pre_confirmed >= 1:
            bug_status = "INFO_EXPOSURE_ONLY"
        else:
            bug_status = "PROOF_QUALITY_FAIL"
        evidence.verdict_status = bug_status
        log.info(
            f"[verify] {dossier.id} — skip_proofgate=True, panel {pre_confirmed}/{len(verdicts)} "
            f"→ {bug_status} (panel-only ablation)"
        )
        verifier_rationale = "\n".join(
            f"Verifier {i+1}: {'CONFIRMED' if v.confirmed else 'REJECTED'} — {v.rationale}"
            for i, v in enumerate(verdicts)
        )
        exploited = bug_status == "EXPLOITED"
        _save_memory(memory, dossier, evidence, verdicts, exploited=exploited)
        _record_longterm(state, dossier, evidence, bug_status)
        return {
            "panel_verdicts": verdicts,
            "verifier_rationale": verifier_rationale,
            "verify_retries": state.get("verify_retries", 0) + 1,
            "bug_status": bug_status,
        }
    # ── (end ablation) ────────────────────────────────────────────────────────

    # ── STEP 2: Gate decision based on panel pre-check ───────────────────────
    # Safety net: even when Panel is unanimous (0/3), run ProofGate if execution
    # produced any 2xx response. ProofGate's deterministic classifier handles
    # non-English / complex responses that Panel may misread from raw exchanges.
    # Only skip ProofGate when execution clearly failed: no 2xx at all.
    has_2xx = any(200 <= ex.status < 300 for ex in (evidence.exchanges or []))

    if pre_confirmed == 0 and not has_2xx:
        # Unanimous rejection + no successful HTTP response → execution failed entirely.
        # ProofGate would also return FAILED, so skip it to save classifier tokens.
        log.info(
            f"[verify] {dossier.id} — panel 0/{len(verdicts)}, no 2xx "
            f"→ skip ProofGate → PROOF_QUALITY_FAIL"
        )
        evidence.verdict_status = "FAILED"
        gate = "FAILED"
    else:
        # Run authoritative ProofGate.
        # Paths: (a) ≥1 confirmed → clear signal; (b) 0/3 confirmed but has 2xx
        # → safety net to avoid missing real exploits ProofGate can detect structurally.
        if pre_confirmed == 0:
            log.info(
                f"[verify] {dossier.id} — panel 0/{len(verdicts)} but has 2xx "
                f"→ ProofGate safety-net"
            )
        else:
            log.info(
                f"[verify] {dossier.id} — panel {pre_confirmed}/{len(verdicts)} "
                f"→ running ProofGate"
            )
        await _run_proof_gate(llm, evidence, body_store)
        gate = getattr(evidence, "verdict_status", "") or "FAILED"

    # ── STEP 3: Map gate result to bug_status ─────────────────────────────────
    # ProofGate is authoritative. LLM verification questions are an OR path:
    # if ≥2/3 questions passed by majority vote, treat as EXPLOITED even when
    # ProofGate lacks a specific rule for this app's response shape.
    if gate == "EXPLOITED":
        bug_status = "EXPLOITED"
    elif llm_questions_pass:
        bug_status = "EXPLOITED"
        log.info(
            f"[verify] {dossier.id} — LLM verification questions passed "
            f"({questions_confirmed}/{n_questions}) → EXPLOITED (question-vote path)"
        )
    elif gate == "INFO_EXPOSURE_ONLY":
        bug_status = "INFO_EXPOSURE_ONLY"
    else:
        bug_status = "PROOF_QUALITY_FAIL"

    exploited = bug_status == "EXPLOITED"

    rationale_parts = [
        f"Verifier {i+1}: {'CONFIRMED' if v.confirmed else 'REJECTED'} — {v.rationale}"
        for i, v in enumerate(verdicts)
    ]

    # Append ProofGate marker results so Red gets actionable failure details on retry.
    # Panel ran on raw HTTP (pre-gate) — its rationale is broad but lacks the specific
    # "which proof condition failed and what was extracted" that makes re-strategizing useful.
    proof_markers = getattr(evidence, "proof_markers", None) or []
    if proof_markers:
        marker_lines = []
        for m in proof_markers:
            key_str = getattr(m.key, "value", str(m.key))
            status_str = "SATISFIED" if getattr(m, "satisfied", False) else "NOT SATISFIED"
            detail = getattr(m, "detail", "")
            extracted = getattr(m, "extracted", None)
            line = f"  [{status_str}] {key_str} — {detail}"
            if extracted:
                line += f" (extracted: {extracted})"
            marker_lines.append(line)
        rationale_parts.append("ProofGate marker results:\n" + "\n".join(marker_lines))

    verifier_rationale = "\n".join(rationale_parts)

    log.info(
        f"[verify] {dossier.id} → gate={gate} panel={pre_confirmed}/{len(verdicts)} → {bug_status}"
    )
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


async def _run_proof_gate(llm, evidence, body_store) -> None:
    """Run per-pattern LLM fact extraction + deterministic ProofGate.

    Sets evidence.verdict_status in place. Mirrors the logic that was previously
    in ExecutionRunner._evaluate_proof — extracted here so the verify phase owns
    the authoritative verdict decision.
    """
    from ...execution.proof.bac import BACProofGate
    from ...execution.proof.blf import BLFProofGate
    from ...execution.proof.classifier import classify_responses

    llm_facts: dict = {}
    try:
        llm_facts = await classify_responses(
            llm, evidence.exchanges, body_store,
            pattern_id=evidence.pattern_id,
        )
    except Exception as e:
        log.warning(f"{evidence.bug_id}: classifier failed (non-fatal): {e}")

    if evidence.category == "BAC":
        gate = BACProofGate(body_store, evidence.pattern_id)
    else:
        gate = BLFProofGate(body_store, evidence.pattern_id)

    verdict = gate.evaluate(evidence, llm_facts)
    evidence.verdict_status = verdict.status.value


def _record_longterm(state: dict, dossier, evidence, bug_status: str) -> None:
    """Write a verified episode to long-term memory (persists across runs)."""
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

        markers = []
        payload = ""
        for m in getattr(evidence, "proof_markers", []) or []:
            if not getattr(m, "satisfied", False):
                continue
            ex = dict(getattr(m, "extracted", {}) or {})
            markers.append({"key": getattr(m.key, "value", str(m.key)), "detail": m.detail, "extracted": ex})
            if not payload and any(k in ex for k in ("field", "value", "payload", "url")):
                payload = _json.dumps(ex)

        if dossier.pattern_id in ("BLF-03", "BLF-05") and outcome == "exploited":
            seq: list[str] = []
            for ex in getattr(evidence, "exchanges", []) or []:
                if (ex.method or "").upper() in ("POST", "PUT", "PATCH", "DELETE") and 200 <= ex.status < 300:
                    step = f"{ex.method.upper()} {ex.endpoint}"
                    if not seq or seq[-1] != step:
                        seq.append(step)
            if seq:
                payload = _json.dumps({"sequence": seq})

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
        memory.record_attempt(dossier.id, status)

        note_parts = [
            f"Panel: {confirmed}/{len(verdicts)} confirmed. Status: {status}. "
            f"Exchanges: {len(getattr(evidence, 'exchanges', []))}."
        ]

        # Key exchange results — actionable context for the next exec retry
        key_exs = (getattr(evidence, "exchanges", None) or [])[:6]
        if key_exs:
            step_strs = [f"{ex.method} {ex.endpoint} → {ex.status} (actor={ex.actor})"
                         for ex in key_exs]
            note_parts.append("Steps: " + "; ".join(step_strs))

        # Proof marker results — tells Red exactly which condition failed
        markers = getattr(evidence, "proof_markers", None) or []
        if markers:
            m_strs = []
            for m in markers:
                key_str = getattr(m.key, "value", str(m.key))
                sat = "SATISFIED" if getattr(m, "satisfied", False) else "NOT SATISFIED"
                detail = (getattr(m, "detail", "") or "")[:100]
                m_strs.append(f"{sat} {key_str}: {detail}")
            note_parts.append("Markers: " + "; ".join(m_strs))

        memory.add_note(
            bug_id=dossier.id,
            role="verify",
            note="\n".join(note_parts),
        )
    except Exception:
        pass
