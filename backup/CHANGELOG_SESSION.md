# CHANGELOG_SESSION

## 2026-05-09 - Simple proof pipeline and anti-overfitting guardrails

- Removed the post-Exec verification hot path from `ManageAgent`: Exec results are no longer sent through `EvidenceGuard`, `Exec verify mode`, `manager_exec_review`, or `[BUG-SUMMARY]` logging before routing.
- Removed the unused `shared/evidence_guard.py` module and legacy `ExecAgent.verify_result()` API so the runtime architecture is not split between old and new verification paths.
- `ManageAgent` now records Exec's self-verified Python result directly via `exec_result_status`: `EXPLOITED`, `PARTIAL`, `FAILED`, or `SCRIPT_ERROR`.
- `SUCCESS: YES`, `FINAL: EXPLOITED`, `result.json.status=EXPLOITED`, or a generic proof signal such as `2xx + privileged/object marker` can now move the bug to `EXPLOITED -> NEXT_BUG`.
- Exec retry is capped to one retry with one generated Python script per call, avoiding long shot chains and repeated Red/Exec loops.
- Added anti-overfitting and minimum-sufficient-proof rules to Red, Blue, Exec, and Manager prompts:
  - no hardcoded lab endpoint/marker/account;
  - derive proof from the current dossier/recon/approved strategy;
  - do not require extra endpoints or side effects beyond the bug hypothesis;
  - BAC/IDOR read-only proof can be a low-privileged user seeing privileged/object content;
  - BLF/stateful proof should use before/after state or a clear invalid state transition.

Validation:

- `python -m py_compile main.py agents/manage_agent.py agents/exec_agent.py agents/red_team.py agents/blue_team.py agents/policy_agent.py agents/crawl_agent.py agents/vuln_hunter_agent.py shared/bug_dossier.py shared/context_manager.py shared/memory_store.py mcp_client.py`
- Smoke-tested the previous `BUG-001` output: `/admin status=200 marker=True` is now classified as `EXPLOITED` and Manager routes to `NEXT_BUG` instead of `RETRY_EXEC`.

## 2026-05-09 - Blue strategy gate only, Exec read-only verify cleanup

- Removed the deprecated Blue post-Exec evidence-review prompt and `BlueTeamAgent.review_exec_evidence()` API. Blue remains in the hot path only for Red strategy / shot-plan review before Exec runs.
- Removed the unused Manager `_post_exec_review()` path and Blue evidence-review verdict parser, so post-Exec validation now flows through deterministic `EvidenceGuard`, Exec read-only verify, and Manager routing.
- Clarified `ExecAgent` verify prompt: verify mode may use tools only for local artifact reading, GET/HEAD requests, and passive browser snapshots; it must not generate new exploits or mutate target state.
- Updated Manager and entrypoint wording so the documented hot path is `Red -> Blue review -> Exec exploit -> Exec verify`.

Validation:

- `python -m py_compile agents/manage_agent.py agents/blue_team.py agents/exec_agent.py shared/evidence_guard.py main.py`

## 2026-05-06 - Clean manager-led workflow

- `ManageAgent` is now the only runtime router for Red/Blue/Exec worker turns.
- `PolicyAgent` remains internal to `ManageAgent`; Red/Blue/Exec do not call or verify against Policy directly.
- Removed legacy worker routing-tag inference from `ManageAgent`; Red/Blue intent is inferred from response content and Manager policy action.
- Conversation history stored by `ManageAgent` now keeps raw worker content instead of injecting `[REDTEAM]`, `[BLUETEAM]`, `[AGENT EXEC]`, `[MANAGER]`, or `[SYSTEM]` prefixes.
- Raised minimum debate rounds to 2 so Red and Blue get a real first-pass review before execution.
- `ExecAgent` no longer uses `[REDTEAM]` / `[BLUETEAM]` as completion signals.
- `ExecAgent` now treats a complete `=========SEND========= ... =========END-SEND=========` block as the only final-answer signal.
- `ExecAgent` fallback/error/max-round outputs are wrapped in complete SEND blocks so `ManageAgent` can always parse them.
- `ExecAgent` prompts now explicitly say not to add routing tags, while keeping a wider tool budget for evidence gathering and execution.
- `ManageAgent` now extracts all Exec SEND blocks from a workflow result, preserving both login evidence and exploit evidence instead of only the first block.
- `VulnHunterAgent` prompt now requires JSON-only output, and its parser can extract the first balanced JSON array from mixed LLM output with prose before/after the JSON.
- `CrawlAgent` now appends a deterministic structured recon appendix to `recon.md` with route families, endpoint dossiers, and BAC/BLF candidate signals derived from crawl artifacts.
- `VulnHunterAgent` now reads enriched `recon.md` as its sole runtime input and generates higher-recall BAC/BLF bug candidates from the recon dossier instead of reading `crawl_data.txt` directly.
- Candidate bug parsing now normalizes `form_fields` into dict records, and bug dossier enrichment now replaces placeholder credentials with observed session labels when available.
- `ExecAgent` keeps script execution as the primary exploit path, and exploit retries are now modeled as bounded script shots instead of immediate tool-loop fallback.
- `ExecAgent` can still run iterative tool-loop execution, but only when explicitly allowed by the caller rather than auto-escalating after the first weak script result.
- Failed or invalid script generations now feed structured retry context into the next script shot instead of jumping straight into unconstrained tool use.
- `ExecAgent` session prep is now baseline-first: reuse per-account `base_cookies_<label>.txt` when present, otherwise import authenticated cookies from `crawl_raw.json`, then try deterministic HTTP login, and only then fall back to browser/LLM login.
- Each auth-required bug now resets `cookies.txt` from a clean baseline session before exploitation, so Exec no longer logs in again for every bug and does not carry mutated cookies from one bug into the next.
- Anonymous workflows now clear `cookies.txt` instead of accidentally inheriting an authenticated session from a previous bug.
- Cookie files written from crawl/imported sessions now normalize domains to host-only form, so `curl -b cookies.txt` can actually replay the authenticated session instead of silently missing cookies because of `host:port` domains.
- `ExecAgent` exploit execution is now script-shot-first: Manager drives a bounded `2-shot` first pass and a bounded `3-shot` retry pass, each shot regenerating a full bash exploit script with feedback from the previous shot.
- Invalid or failed script generations now return structured retry feedback to the next shot instead of auto-falling into tool-loop execution.
- `ManageAgent` now distinguishes explicit exploit failure from real runtime/infrastructure failure, so `FINAL: FAILED` no longer gets misrouted as a script/runtime error.
- `ManageAgent` retry semantics for Exec are now aligned to script-shot budgets: first exec pass = 2 shots, retry exec pass = 3 shots, then hand back to Red if still unclear.

Validation:

- `python -m py_compile agents/manage_agent.py agents/red_team.py agents/blue_team.py agents/exec_agent.py agents/vuln_hunter_agent.py agents/crawl_agent.py`

## 2026-05-07 - Exploit artifacts and guarded reporting

- `ExecAgent` now saves every generated exploit script shot as a stable artifact under `exploits/`, using names like `bug-001-exploit1.sh`, `bug-001-exploit2.sh`, instead of relying only on the overwritten `exploit.sh`.
- `exploit.sh` is kept only as a backward-compatible alias to the latest shot; named files are the report source of truth.
- Exec SEND blocks now include `SCRIPT_PATH`, `SCRIPT_SHA256`, and syntax-check status so Manager can persist PoC artifacts in `risk-bug.json` and the final report.
- Exec now runs `bash -n` before executing a generated script and returns `SUCCESS: PARTIAL` with artifact metadata when syntax is invalid.
- Exec script prompts now require `curl -sS -L` for state/HTML verification and discourage fragile `grep -P` lookbehind parsing.
- Exec evidence guard now downgrades suspicious stateful claims from `YES` to `PARTIAL` when before/after markers are empty, parse failed, redirect-only evidence is used, or a balance/transfer delta is zero.
- `ManageAgent` now trusts the guarded `=== SUCCESS: YES ===` verdict first and will not mark a bug exploited when Exec returns `SUCCESS: PARTIAL` even if raw script output contains `FINAL: EXPLOITED`.
- `ManageAgent` records approved Red procedures, Blue reviews, latest Exec evidence, failure reasons, and all script artifact paths per bug.
- Final `report.md` now includes exploited findings and not-exploited/false-positive candidates with procedure, saved exploit scripts, and execution evidence for each bug.

Validation:

- `python -m py_compile agents/exec_agent.py agents/manage_agent.py`

## 2026-05-08 - Exec artifact contract and per-bug summaries

- `ExecAgent` now checks the lightweight artifact contract after each exploit script run:
  - `exploit_state/<BUG>/result.json`
  - `baseline/probe/verify` request-response artifacts when present
- Exec SEND blocks now include `STATE_DIR`, `RESULT_JSON_PATH`, `RESULT_JSON_STATUS`, `EVIDENCE_FILES_SAVED`, and `ARTIFACT_CONTRACT`.
- `ManageAgent` now stores those artifact fields in `risk-bug.json` and includes result JSON / contract status in the final report artifact list.
- `ManageAgent` prints a compact `[BUG-SUMMARY]` after Exec verify and when a bug is stopped/marked exploited, showing status, validation, verify status, artifact contract, reason, script, output, and result JSON.
- `ExecAgent` shot count is now capped by the Manager-provided budget: first execution stays at 1 shot, retry stays at 2 shots, even if Red accidentally writes a larger shot plan.
- `ManageAgent` now stops `BLOCKED` / `NEEDS_MANUAL` Exec verify outcomes instead of retrying them as generic inconclusive results.

Validation:

- `python -m py_compile agents/exec_agent.py agents/manage_agent.py main.py`
- Smoke-tested artifact parsing, artifact contract validation, Manager bug summary logging, Red-to-Exec routing, Policy gating, and `NEEDS_MANUAL` stop routing.

## 2026-05-09 - Manager workflow scoping and Exec prompt cleanup

- Fixed a critical Manager routing issue where a new bug could reuse the last valid Red strategy from a previous bug through global conversation fallback.
- `has_workflow` is now scoped to the current in-memory `current_approach`, and `EXECUTE_BUG` / `RETRY_EXEC` no longer pull stale Red content from the whole conversation.
- After `NEXT_BUG`, Manager now deterministically routes to `DEBATE_RED` when the new bug has no current workflow.
- Restored Blue to the hot path: valid Red strategies now route to `DEBATE_BLUE`, and Exec can run only after the current workflow has Blue approval.
- `PolicyAgent` now suggests `DEBATE_BLUE` if Manager tries `EXECUTE_BUG` before Blue approval.
- Syntax/invalid-script markers such as `SYNTAX_CHECK: FAIL`, `script validation failed`, and `bash -n failed` are now classified as script errors so Manager retries Exec instead of sending the issue back to Red.
- `ExecAgent` now normalizes the common generated bash typo `set -eo` to `set -e`, preventing shell option tables from polluting exploit output.
- Exec script prompt now explicitly tells the model to use `curl -H "Cookie: $COOKIES"` for composed cookie headers and to avoid `curl -b <(echo "$COOKIES")`.
- Artifact contract accepts common result keys such as `shot_result`, `exploit_status`, `final_reason`, and `verify_completed`, reducing false `WARN` on valid result files.

Validation:

- `python -m py_compile main.py agents/manage_agent.py agents/exec_agent.py agents/red_team.py agents/policy_agent.py shared/evidence_guard.py mcp_client.py`
- Smoke-tested stale-strategy isolation after `NEXT_BUG`, Policy fallback to `DEBATE_RED`, bash normalizer, result artifact validation, and GitHub proxy prompt responses for Red and Exec verify.

## 2026-05-07 - Simplified agent handoff logging

- `Manager` logs now focus on orchestration state only: which bug is handed to `ExecAgent`, what the input context is, and a concise summary of the returned exploit evidence.
- `ExecAgent` runtime logs now drop shell command previews and keep only verdict, exit state, and compact output summaries from the exploit run.
- Third-party INFO chatter from MCP-related loggers is suppressed so the session log stays readable for humans following the pipeline.

Validation:

- `python -m py_compile agents/exec_agent.py agents/manage_agent.py main.py`
- Smoke-tested artifact naming (`bug-001-exploit1.sh`, `bug-001-exploit2.sh`) and guarded false-positive handling for empty before/after transfer evidence.

## 2026-05-07 - Live shot logging and Blue intent fix

- `ExecAgent` now prints a live summary right after each script shot finishes: verdict, return code, final marker, saved script path, saved output path, and a condensed step-by-step summary extracted from the script output.
- Each script artifact now stores two sidecar logs next to the `.sh` file:
  - `<script>.syntax.txt` for `bash -n`
  - `<script>.output.txt` for decoded stdout/stderr from the script run
- Exec SEND blocks now include `SYNTAX_LOG_PATH` and `EXEC_OUTPUT_PATH`, and `ManageAgent` carries those paths into `risk-bug.json` / `report.md`.
- Fixed `ManageAgent` Blue intent parsing so replies that start with `APPROVED` are always treated as approve, even if the explanation later contains words like `bổ sung`, preventing false `Blue REJECTED` transitions.

Validation:

- `python -m py_compile agents/exec_agent.py agents/manage_agent.py`
- Smoke-tested `_infer_dialog_intent()` with `APPROVED ... bổ sung ...` and live shot logging output formatting.

## 2026-05-07 - Verbose Exec runtime logging

- `ExecAgent` now prints the prepared script path, working directory, line count, SHA prefix, and a short script preview before any shell execution.
- Live shot logging now includes the exact `bash -n` command, the runtime `cd ... && bash ...` command, the decoded command output path, and the number of output lines observed.
- Step summaries now surface more runtime clues from the script output, including login/result lines, response sizes, redirects, syntax errors, `404/403/405` style failures, and other shell-level errors.

Validation:

- `python -m py_compile agents/exec_agent.py agents/manage_agent.py`

## 2026-05-07 - Post-Exec evidence validation and final report split

- Added deterministic `EvidenceGuard` to inspect Exec outputs before a bug can be marked exploited.
- `EvidenceGuard` flags obvious contradictions such as `405 Method Not Allowed` plus success, admin-role cookies used for BAC/IDOR proof, missing stateful before/after markers, request-sent-only proof, and multi-shot workflows that stop before the verify shot.
- Added Blue Team evidence-review mode. After Exec returns a candidate result, Blue now reviews the bug dossier, approved strategy/shot plan, Exec result, and guard summary, then returns `VALIDATED`, `REJECTED_EXEC`, `REJECTED_STRATEGY`, or `INCONCLUSIVE`.
- `ManageAgent` no longer treats `Exec SUCCESS: YES` as confirmed. A bug is marked `EXPLOITED` only when `validation_status=VALIDATED`.
- `ManageAgent` routes failed post-exec validation back to Exec or Red depending on whether Blue rejected implementation evidence or the strategy itself.
- `risk-bug.json` now records `evidence_guard`, `post_exec_review`, `validation_status`, `validation_reason`, and `validated_evidence_summary`.
- Final reports are split:
  - `report_raw.md` keeps full technical artifacts and raw evidence for audit.
  - `report_final_vi.md` and `report.md` contain the clean Vietnamese report with `FINDING`, `MÔ TẢ`, `TÁC ĐỘNG`, `POC`, and `KHUYẾN NGHỊ KHẮC PHỤC`.
- `ExecAgent` script prompt now requires structured summaries (`SHOT_RESULT`, `REQUEST_SUMMARY`, `EVIDENCE_SUMMARY`, `ERRORS`, `FINAL_REASON`) and explicitly forbids marking 4xx/5xx/error-page responses as success.
- `RedTeamAgent` now has explicit instructions to fix strategies based on post-exec evidence review feedback, especially admin-cookie misuse, 405/error responses, and request-sent-only proof.

Validation:

- `python -m py_compile shared/evidence_guard.py agents/blue_team.py agents/manage_agent.py agents/red_team.py agents/exec_agent.py`
- Smoke-tested `EvidenceGuard` against the previous bad `BUG-004` and `BUG-005` outputs; both are downgraded to `REJECTED_EXEC`, while the stronger profile IDOR output passes.

## 2026-05-07 - Read-only BAC early-stop evidence fix

- `EvidenceGuard` now distinguishes simple read-only BAC/IDOR probes from stateful BLF/chaining workflows.
- Read-only GET/HEAD access-control bugs can pass even if Exec stops before every planned shot, but only when output has concrete evidence: successful status, correct role/session context, and response markers tied to the dossier.
- Stateful/business-logic workflows such as cart, transfer, checkout, coupon, profile edit, and other mutations still require baseline/action/verify evidence and are rejected if they stop before verify.
- `RedTeamAgent` now tells Red to prefer a single-shot plan for simple read-only BAC/IDOR instead of forcing Guest/User/Verify into three mandatory shots.
- `BlueTeamAgent` evidence review now knows this exception and should not reject a proven read-only BAC solely because `executed_shots < planned_shots`.
- `ExecAgent` script prompt now asks for `VERIFY_COMPLETED`, `EARLY_STOP_ALLOWED`, and `EARLY_STOP_REASON` markers when a read-only proof is complete inside one shot.
- `ExecAgent` no longer stops at the first candidate success for BLF/stateful workflows unless the output explicitly says verify is complete; it continues to the next shot within the approved shot budget.

Validation:

- `python -m py_compile shared/evidence_guard.py agents/blue_team.py agents/red_team.py agents/exec_agent.py`

## 2026-05-07 - Recon cookie surface and Manager attempt ledger

- `CrawlAgent` now appends a deterministic `Client-Controlled State / Cookie Attack Surface` section to `recon.md`, highlighting generic BAC/BLF signals such as client-visible `role`, `user_id`, `is_admin`, and account-like cookies.
- `shared/bug_dossier.py` now enriches BAC-style bug dossiers with `cookie_attack_surface` and `attack_variants`, so Red/Manager can see CTF-style variants like direct access, sibling admin endpoints, ID tampering, and cookie tampering when the crawl evidence supports them.
- `RedTeamAgent` now includes those enriched cookie/client-state surfaces and suggested variants in the current bug context.
- `ManageAgent` now records an `attempt_ledger` per bug, classifying Exec attempts as `PROOF_CANDIDATE`, `NEW_LEAD`, `NO_SIGNAL`, `CONTRADICTION`, `RUNTIME_ERROR`, `PARTIAL`, or `UNCLEAR`.
- `ManageAgent` uses the ledger to avoid retrying the same dead path repeatedly: repeated `NO_SIGNAL`/`UNCLEAR` attempts stop the bug, while `NEW_LEAD` routes back to Red for a focused pivot.
- Post-exec `RETRY_RED` now consumes a Red revision budget, so Manager cannot loop Red pivots indefinitely after Exec/Blue evidence rejection.

Validation:

- `python -m py_compile agents/crawl_agent.py shared/bug_dossier.py agents/red_team.py agents/manage_agent.py`
