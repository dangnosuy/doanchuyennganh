# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install (editable)
pip install -e .
# or
uv pip install -e .

# Run full pentest pipeline
marl3 run "http://target user:alice pass:secret"

# Multi-user run (required for IDOR — provides attacker and victim sessions)
marl3 run "http://target user:alice pass:secret user:bob pass:secret2"

# Recon only
marl3 crawl "http://target user:alice pass:secret"

# Memory management
marl3 memory stats
marl3 memory list
marl3 memory rules
marl3 memory prune
marl3 memory clear

# Tests (all async — tests/ is currently empty, no tests written yet)
pytest tests/ -v
pytest tests/path/to/test.py::test_name -v

# Lint
ruff check src/
```

## LLM Setup

The tool requires an OpenAI-compatible API endpoint. The default config points to a local proxy at `http://localhost:20128/v1`. To use a different provider, override in `config/default.yaml` or pass `--config path/to/config.yaml`:

```yaml
llm:
  base_url: https://api.openai.com/v1
  api_key: sk-...
  models:
    hunter: gpt-4o
    red: gpt-4o
    blue: gpt-4o
    exec: gpt-4o
    verifier: gpt-4o
```

## Architecture

**marl3** is a multi-agent automated penetration tester for web apps, built on LangGraph. Core design: **AI reasons, code controls flow, data is truth**.

### Main Pipeline (`graph/pipeline.py`)

```
START → recon → hunt → coordinate → bugs → report → END
```

Each bug runs through a **sub-graph** (`graph/bug_graph.py`):
```
debate → [APPROVED] → exec → verify → [EXPLOITED/INFO_ONLY] → END
                                    ↘ [PROOF_QUALITY_FAIL + retry budget] → debate
```

Retry condition: `(panel_confirmed ≥ 1 OR has_partial_proof) AND verify_retries < max AND debate_rounds < max×2`.
`has_partial_proof` = any ProofGate marker is SATISFIED (partial evidence worth a strategy revision).

Routing is **purely deterministic** — decided by `BugState` enum values, never by LLM output.

### Three-Tier Architecture

| Tier | Role |
|------|------|
| **Code (Tier 1)** | Crawler extracts `ReconArtifact`: endpoints, auth diffs, response bodies |
| **LLM (Tier 2)** | Hunter, Red, Blue, Exec, Verifier agents reason and strategize |
| **Code (Tier 3)** | `ProofGate` gives the final verdict from raw HTTP evidence — AI cannot override this |

### Phase-by-Phase Data Flow

1. **RECON** — HTTP + Playwright crawl → `ReconArtifact` (endpoints, sessions, body blobs in SHA-256 content-addressed `BodyStore`)
2. **HUNT** — LLM hypothesis generation → `list[BugDossier]` (pattern codes: BAC-01, BLF-05, etc.)
3. **COORDINATE** — Sort dossiers (severity, BAC before BLF, simple before chains)
4. **DEBATE** — Red (attacker) ↔ Blue (skeptic) loop → immutable `StrategyDocument`; Exec cannot deviate from this
5. **EXEC** — Tool-calling loop; `RecordingHttpClient` (`execution/recorder.py`) intercepts every HTTP call and stores it as an `HttpExchange` → `Evidence`
6. **VERIFY** — Two-step sequence:
   - `VerifierPanel` (3 AI agents) runs **first** as a pre-gate on raw exchanges (no proof_markers yet).
     Fast-fail: `0/3 + no 2xx` → skip ProofGate → `PROOF_QUALITY_FAIL`.
     Safety net: `0/3 + has 2xx` → ProofGate still runs.
   - `ProofGate` (deterministic code) checks structured evidence → sets `verdict_status`. **Sole authority on EXPLOITED.**
   - `BACProofGate` has IDOR fallback: `BAC-01` eval fail → try `_eval_idor()` → if pass, promote `evidence.pattern_id = "BAC-03"`.
7. **REPORT** — `workspace/<target>_<timestamp>/` with `report.md`, `findings.json`, `pocs/`.
   PoC is regenerated **after** ProofGate runs (proof_markers now populated) so only attack-critical exchanges appear.

### LangGraph State

Two TypedDicts (both `total=False` — all fields optional to support partial updates):
- **`PipelineState`** (`graph/state.py`) — top-level pipeline; holds `ReconArtifact`, `list[BugDossier]`, `list[Finding]`
- **`BugRunState`** (`graph/state.py`) — per-bug sub-graph; flat TypedDict holding all debate/exec/verify fields directly (debate_rounds, frozen_strategy, evidence, panel_verdicts, bug_status, etc.)

`BugRun` (`state.py`) is a separate `@dataclass` — the mutable runtime object created per-bug by `graph/nodes/debate.py`. It owns the state machine via `transition(event)`, retry counters, frozen strategy fields, and accumulated `Evidence`. `BugRunState` mirrors these fields for LangGraph but is not a wrapper — the node implementations keep a `BugRun` instance in the state under the `dossier`/flat-field convention.

### Vulnerability Pattern Codes

Patterns are defined in `knowledge/data/bac_patterns.json` and `blf_patterns.json`. ProofGate subclasses in `execution/proof/bac.py` and `blf.py` implement the check logic; `execution/proof/classifier.py` is the LLM-based fact extractor that turns raw HTTP exchanges into structured facts the gates consume.

| Code | Category | What it proves |
|------|----------|---------------|
| BAC-01 | BAC | Unauthenticated access to sensitive data (anon → 200 with PII/protected content) |
| BAC-02 | BAC | Privilege escalation via tampered cookie/param (user → admin endpoint) |
| BAC-03 | BAC | IDOR — cross-user object access (actor A reads/modifies actor B's resource) |
| BLF-01 | BLF | Price manipulation (negative or zero prices accepted) |
| BLF-05 | BLF | Coupon/voucher reuse (same code consumed more than once) |
| BLF-06 | BLF | Quantity tampering (negative quantities accepted with state change) |

`ProofKey` enum (`contracts/enums.py`) names individual proof checks: `OWNERSHIP_BYPASS`, `PRIVILEGED_ACCESS`, `STATE_DELTA`, `AUTH_BYPASS`, `PRICE_MANIPULATION`, `QUANTITY_TAMPER`, `STATE_SKIP`, `SENSITIVE_FIELD_EXPOSED`.

### Key Invariant: Frozen Strategy

After `debate` produces a `StrategyDocument`, four fields are frozen into `BugRun`:
- `frozen_strategy` — overall approach
- `frozen_execution_guide` — step-by-step instructions for Exec
- `frozen_success_condition` — what constitutes proof
- `frozen_verification_questions` — checklist questions fed to the VerifierPanel

**Exec agent receives these as read-only context and cannot change the strategy.** If the strategy is wrong, execution fails → `PROOF_QUALITY_FAIL` → new debate round.

### State Machine

`src/marl3/state.py` holds `TRANSITIONS` (the declarative transition table) and the `BugRun` class. `BugState` enum is in `contracts/enums.py`. When adding new phases or routing logic, update `BugState` + `TRANSITIONS` in `state.py` first, then wire the graph edges in `bug_graph.py`.

### Key Data Contracts (`contracts/`)

| File | Key types |
|------|-----------|
| `enums.py` | `BugState`, `BugCategory`, `Severity`, `VerdictStatus`, `DebateVerdict`, `ProofKey`, `Role` |
| `dossier.py` | `BugDossier`, `StrategyDocument` |
| `evidence.py` | `Evidence`, `ProofMarker`, `Verdict` |
| `http.py` | `HttpExchange` (one request + response pair, recorded by `RecordingHttpClient`) |
| `body.py` | `BodyRef` (SHA-256 blob_id + preview; bodies stored in `BodyStore`, never inlined) |
| `recon.py` | `ReconArtifact` |
| `results.py` | `Finding`, `VerifierVerdict`, `PocArtifact` |

### Workspace Output

Each run creates `workspace/<target>_<timestamp>/`:

```
recon.json          # ReconArtifact (endpoints, sessions, auth diffs)
bugs.json           # All BugDossier hypotheses
findings.json       # Final Finding objects per confirmed bug
report.md           # Human-readable findings
sessions.json       # Auth session store
bodies/             # SHA-256 content-addressed HTTP body store
pocs/               # curl-reproducible PoC per confirmed bug
evidence/           # evidence.json per bug
debates/            # Red↔Blue transcript per bug
```

### Key Directories

| Path | Purpose |
|------|---------|
| `src/marl3/cli.py` | CLI entry (`marl3 run`, `crawl`, `memory`) |
| `src/marl3/state.py` | `BugRun` dataclass + `TRANSITIONS` table |
| `src/marl3/workspace.py` | `RunWorkspace` — sole authority on run-dir paths; all subsystems use this, never construct paths directly |
| `src/marl3/interfaces.py` | `Protocol` interfaces (`ReconPort`, `HunterPort`, etc.) for mock/test decoupling |
| `src/marl3/graph/pipeline.py` | Main LangGraph pipeline |
| `src/marl3/graph/bug_graph.py` | Per-bug sub-graph with cycle |
| `src/marl3/graph/state.py` | `PipelineState` and `BugRunState` TypedDicts + factory functions |
| `src/marl3/graph/nodes/` | Phase nodes: `recon.py`, `coordinate.py`, `debate.py`, `execution.py`, `verify.py`, `report.py` |
| `src/marl3/contracts/` | Pydantic data models (`BugDossier`, `ReconArtifact`, `Evidence`, `Finding`) |
| `src/marl3/dossier/enrich.py` | `enrich_dossier()` — attaches evidence rules + graph context to a `BugDossier` from the knowledge playbook |
| `src/marl3/recon/` | `crawler.py`, `candidates.py`, `flow_mapper.py`, `auth.py` (`AuthSessionStore`), `body_store.py`, `workflow.py` |
| `src/marl3/debate/` | `red.py`, `blue.py`, `manager.py` |
| `src/marl3/execution/runner.py` | Tool-calling LLM agent loop |
| `src/marl3/execution/recorder.py` | `RecordingHttpClient` — wraps httpx, records all exchanges |
| `src/marl3/execution/tool_profiles.py` | `ToolProfile` definitions — exec uses different tool sets per phase (prepare vs. attack) |
| `src/marl3/execution/browser.py` | Playwright `BrowserTool` for JS-heavy targets |
| `src/marl3/execution/shell.py` | `ShellRunner` — sandboxed shell/curl execution |
| `src/marl3/execution/proof/` | `ProofGate` rules: `bac.py`, `blf.py`, `base.py`; LLM fact extractor: `classifier.py` |
| `src/marl3/execution/poc/generator.py` | PoC generator — rebuilds curl-reproducible PoC after ProofGate populates proof_markers |
| `src/marl3/verify/` | `verifier.py` (refute-by-default), `panel.py` (3-agent vote) |
| `src/marl3/memory/` | `longterm.py` (SQLite), `store.py`, `retrieval.py` |
| `src/marl3/llm/client.py` | OpenAI-compatible LLM client (wraps `openai`) |
| `src/marl3/llm/replay.py` | `FixtureLLMClient` — deterministic offline replay for tests |
| `src/marl3/llm/usage.py` | `UsageLedger` — token usage tracking |
| `src/marl3/report/builder.py` | `ReportBuilder` — produces `report.md` + `findings.json` from structured `Finding` objects; LLM only writes the human summary paragraph |
| `src/marl3/prompts/templates/` | Jinja2 prompt templates per agent role |
| `src/marl3/knowledge/data/` | `bac_patterns.json`, `blf_patterns.json` — pattern definitions |
| `config/default.yaml` | Config schema with all tuneable knobs |

### Prompt Templates

Agent system prompts live in `src/marl3/prompts/templates/` and are Jinja2 templates:

| File | Agent |
|------|-------|
| `hunter_system.md` | Hypothesis generator (HUNT phase) |
| `red_system.md` | Attacker strategist (DEBATE) |
| `blue_system.md` | Skeptic/devil's advocate (DEBATE) |
| `exec_system.md` | Tool-calling exploit agent (EXEC) |
| `verifier_system.md` | Advisory verifier (VERIFY) |

### Memory System

Two-tier memory gated by promotion thresholds:
- **Episodic** (`longterm.py`) — by-target; specific payload + endpoint; no promotion gate
- **Semantic** (`longterm.py`) — cross-target; requires `promote_min_successes=3` confirmed successes across `promote_min_targets=2` distinct targets before promotion

Semantic promotion prevents overfitting to a single app's quirks.

### LLM Client

`src/marl3/llm/client.py` wraps `openai.AsyncOpenAI` pointing at `llm.base_url` (default: local proxy at `http://localhost:20128/v1`). Each agent role gets its own model key (`llm.models.<role>`). To swap models, change `config/default.yaml` or pass `--config`.

### Configuration

Override via `--config path/to/config.yaml` or `.env`:

| Key | Default |
|-----|---------|
| `llm.base_url` | `http://localhost:20128/v1` |
| `llm.models.*` | `minimax-m2.5:cloud` (per-role: hunter, red, blue, exec, verifier) |
| `debate.max_rounds` | 3 |
| `debate.max_exec_retries` | 1 |
| `debate.max_verify_retries` | 1 |
| `debate.per_bug_wall_clock_s` | 600 |
| `recon.max_pages` | 60 |
| `verifier.count` | 3 (must be odd — majority vote) |
| `memory.longterm_enabled` | `true` |

### Extending: Adding a New Vulnerability Pattern

1. Add pattern JSON entry to `knowledge/data/bac_patterns.json` or `blf_patterns.json`
2. Add `ProofKey` values to `contracts/enums.py` if new proof checks are needed
3. Implement a new `ProofGate` subclass in `execution/proof/bac.py` or `blf.py`
4. Register the pattern → gate mapping in `execution/proof/classifier.py`
5. Add the new `BugCategory` or pattern code to relevant agent prompts in `prompts/templates/`

### Test Setup

```ini
asyncio_mode = auto
pythonpath = ["src"]
```

Tests are async by default. `ruff` uses `line-length=100`, `target-version="py311"`.

## Known Open Issues

### HIGH — directly limits coverage

**T2a: Multi-actor session (IDOR blocker)**
Exec only has one session. IDOR requires two actors (attacker reads victim's resource).
- `execution/tool_bridge.py`: add `create_session(url, username, password) → actor_label`
- `execution/recorder.py`: `RecordingHttpClient` manages multiple parallel sessions
- `prompts/templates/exec_system.md`: add IDOR multi-actor pattern example

**T1: Client-side price injection**
`POST /cart/add` has a hidden `unit_price` field not visible in JS. Needs parameter fuzzing.
- `recon/candidates.py`: add BLF variant — inject `unit_price`, `price`, `override_price` into every POST with a numeric field

**T3: BAC-06 gate doesn't cover API endpoints**
Current `BAC-06` gate requires an "admin title" check, which fails on JSON API endpoints like `/api/v1/users/{id}/promote`.
- `execution/proof/bac.py`: add rule — "endpoint blocked with role X, 2xx with role Y → BAC-06 proven"

### MEDIUM

| ID | Description | File |
|----|-------------|------|
| T6 | Hunter noise: DELETE on owned resource incorrectly labelled IDOR | `recon/candidates.py` |
| T7 | IDOR gate needs `/api/v1/me` to resolve `attacker_user_id` | `execution/proof/bac.py` |
| T4 | Discover refund endpoint (`/api/v1/orders/{id}/refund`) | `recon/crawler.py` probe paths |
