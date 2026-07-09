# AGENTS.md

## Developer & Benchmark Commands

```bash
pip install -e .                                                          # install package in editable mode
marl3 run "http://target user:alice pass:secret"                          # single-user run
marl3 run "http://target user:alice pass:Alice@123 user:bob pass:Bob@123"  # multi-user (IDOR candidate)
marl3 run "http://target user:alice pass:secret" --show-graph             # print graph structure + exit
marl3 crawl "http://target user:alice pass:secret"                        # recon phase only (generates recon.json)
marl3 memory stats|list|rules|prune|clear                                 # inspect and maintain long-term memory
pytest tests/ -v                                                          # run test suite (currently empty)
ruff check src/                                                           # lint source code

# Benchmark & Statistical Analysis
python3 run_benchmark.py --repeats 5 --target vulnshop                    # run benchmark repeats across configs
python3 analyze_benchmark.py --input benchmark_results --latex            # analyze benchmark data and generate LaTeX tables
```

## Architecture & Graph Routing

Multi-agent automated pentester for BAC and BLF vulns, built on LangGraph. Core principle: **AI reasons, code controls flow, data is truth**.

- **Main Graph (`graph/pipeline.py`):** `START → recon → hunt → coordinate → bugs → report → END`
- **Sub-graph (`graph/bug_graph.py`):** Runs per-bug loops (`debate → exec → verify → loop/END`) where routing is deterministic (code reads `bug_status` string, LLM output never directly decides edges).

### Verify Node & Safety Nets (2-Step Sequence)
1. **Verifier Panel × 3 (pre-gate):** Reads raw HTTP exchanges (no `proof_markers` populated yet) to see if execution produced anything promising.
   - `0/3 confirmed + no 2xx response` → skip ProofGate → `PROOF_QUALITY_FAIL` immediately.
   - `0/3 confirmed + has 2xx response` → run ProofGate as safety net (Panel may miss non-English/complex pages).
   - `≥1/3 confirmed` → run ProofGate normally.
2. **ProofGate (authoritative):** Deterministic code rules evaluating HTTP evidence and LLM facts. Returns `EXPLOITED` / `INFO_EXPOSURE_ONLY` / `PROOF_QUALITY_FAIL`.
3. **LLM Question-Vote Safety Net:** In `verify.py`, if `verifier_rationale` has $\geq 2$ verification questions confirmed as `True` by the majority of panel verifiers, the final status is set to `EXPLOITED` even if ProofGate failed (acts as a backup path for custom endpoints).

### Verify Loop Retries & Off-by-One Guard
- `can_retry` condition: `(panel_confirmed ≥ 1 OR has_partial_proof) AND verify_retries <= max_verify_retries AND debate_rounds < max_debate_rounds * 2`
- `has_partial_proof` is `True` if any ProofGate marker is `SATISFIED` (worth refining).
- **Off-by-one note:** `verify.py` increments `verify_retries` before checks, so routing guards must use `<=` instead of `<`.

### Frozen Strategy Invariant
After debate, strategy fields (`frozen_strategy`, `frozen_execution_guide`, `frozen_success_condition`, `frozen_verification_questions`) are frozen in `BugRun`. The `Exec` agent receives these as read-only context and cannot deviate. If execution fails to prove them → `PROOF_QUALITY_FAIL` → back to debate for another round.

## Crawler & Recon Constraints

### Logout Prevention
- The crawler has a strict `_is_logout(url)` check. It **never** enqueues or requests logout links during passive, probed, or form-submission phases. Fetching a logout link clears active cookies and silently de-authenticates all subsequent requests in that session.

### JS Endpoint Discovery & Probing
- GET endpoints are passively crawled. Non-GET JS-discovered endpoints are **safely probed** once with an empty JSON body (`{}`) to capture a real HTTP request/response exchange without mutating state. This is required for `Red` to pass its grounding check and construct proper HTTP headers.

## Memory System & Anti-Overfitting

Memory is split into two systems to prevent target-specific data leakage (overfitting):
- **Short-Term Memory (`memory/store.py`):** Ephemeral run-specific notes (approved strategies, attempts, verify notes).
- **Long-Term Memory (`memory/longterm.py`):** Persists across runs in SQLite.
  - **SAME target retrieval:** Retrieves concrete payloads and exact endpoints.
  - **CROSS target retrieval:** Abstracted techniques only (all URLs, hosts, fields stripped) AND only if verified on $\geq 2$ targets.

## Ablation Flags

Ablation YAML files reside in `config/ablations/`. They utilize specific configurations:
- `debate.skip = true` (bypasses debate entirely; runs execution directly from dossier).
- `hunt.seeder_enabled = false` (disables deterministic seed candidates from recon routes).
- `verifier.skip_proofgate = true` (disables ProofGate; panel majority vote is final).
- `memory.longterm_enabled = false` (disables long-term memory).

## Non-obvious Gotchas

- **State Machine Location:** The `TRANSITIONS` table is in `src/marl3/state.py` (package root), NOT `contracts/state.py`.
- **Config Env Var Prefix:** Override env variables prefix is legacy `MARL2_` (e.g., `MARL2_LLM__BASE_URL`), not `MARL3_`.
- **Model Defaults:** `config.py` hardcodes `gpt-4.1` as fallback, but `config/default.yaml` sets `minimax-m2.5:cloud`. The YAML config takes precedence at runtime.
- **Verifier Count:** Must be an odd number (1, 3, 5...) or `VerifierConfig` will raise a `ValueError`.
- **Config Resolution Path:**
  - `config.load_config()` (library path): resolves `${ENV_VAR}` and overlays `MARL2_*` env overrides.
  - `cli._load_cfg()` (CLI path): shallow merges defaults and `--config` overlay, but **does not** resolve env variables or apply `MARL2_*` overrides.
- **Jinja2 Prompt Templates:** All prompt templates in `src/marl3/prompts/templates/` are Jinja2 templates loaded using `StrictUndefined`. Any undefined variables will throw errors.
- **RunWorkspace Authority:** `src/marl3/workspace.py`'s `RunWorkspace` is the sole authority for run directory paths. Never construct paths manually.
- **Lossless BodyStore:** Response bodies are stored losslessly as SHA-256 content-addressed files. RAM holds only a `BodyRef` preview. Do not truncate bodies mid-stream as it breaks ProofGate checks.
