"""ReportBuilder — produces report.md + findings.json from structured Finding objects.

MARL anti-pattern fixed:
  Old: report built from attack_notes.md (timeline) + truncated evidence
  New: report built directly from Finding objects (structured Evidence + PoC + panel)
       LLM only writes the human-readable summary paragraph — data comes from objects.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from ..config import AppConfig
from ..contracts.enums import BugState, Severity
from ..contracts.results import Finding
from ..llm.client import LLMClient
from ..prompts.registry import render
from ..workspace import RunWorkspace

log = logging.getLogger("marl3.report")

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class ReportBuilder:
    def __init__(self, llm: LLMClient, workspace: RunWorkspace) -> None:
        self._llm = llm
        self._ws = workspace

    async def build(self, findings: list[Finding]) -> None:
        """Build report.md and findings.json from Finding objects."""
        # Sort: exploited first, then by severity
        sorted_findings = sorted(
            findings,
            key=lambda f: (
                0 if f.status == BugState.EXPLOITED else 1,
                _SEVERITY_ORDER.get(f.severity, 99),
            ),
        )

        # Enrich summaries via LLM
        for finding in sorted_findings:
            if finding.status in (BugState.EXPLOITED, BugState.INFO_EXPOSURE_ONLY) and not finding.summary:
                finding.summary = await self._generate_summary(finding)

        # Write findings.json (structured, for tooling/benchmarking)
        self._ws.findings_json.write_text(
            json.dumps([f.model_dump(mode="json") for f in sorted_findings], indent=2, default=str),
            encoding="utf-8",
        )

        # Write report.md (human-readable)
        self._ws.report_md.write_text(
            self._render_md(sorted_findings),
            encoding="utf-8",
        )

        log.info(
            f"Report complete: {self._ws.report_md} "
            f"({sum(1 for f in findings if f.status == BugState.EXPLOITED)} exploited)"
        )

    async def _generate_summary(self, finding: Finding) -> str:
        key_exchanges = []
        if finding.evidence:
            key_exchanges = finding.evidence.exchanges[:5]
        proof_markers = []
        if finding.evidence:
            proof_markers = [m for m in finding.evidence.proof_markers if m.satisfied]
        panel_decision = finding.panel_decision

        prompt = render(
            "report_summary",
            bug_id=finding.bug_id,
            title=finding.title,
            pattern_id=finding.pattern_id,
            status=finding.status.value,
            severity=finding.severity.value,
            method=finding.method,
            endpoint=finding.endpoint,
            key_exchanges=key_exchanges,
            proof_markers=proof_markers,
            panel_decision=panel_decision,
        )
        messages = [{"role": "user", "content": prompt}]
        try:
            return await self._llm.chat(messages, role="reporter", temperature=0.3, max_tokens=800)
        except Exception as e:
            log.warning(f"Summary generation failed for {finding.bug_id}: {e}")
            return ""

    def _render_md(self, findings: list[Finding]) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        exploited = [f for f in findings if f.status == BugState.EXPLOITED]
        info_exposure = [f for f in findings if f.status == BugState.INFO_EXPOSURE_ONLY]
        not_exploited = [
            f for f in findings
            if f.status not in (BugState.EXPLOITED, BugState.INFO_EXPOSURE_ONLY)
        ]

        lines = [
            f"# Security Assessment Report",
            f"\nGenerated: {ts}",
            f"Tool: marl3 v1.0.0",
            f"\n## Summary\n",
            f"| Status | Count |",
            f"|--------|-------|",
            f"| EXPLOITED | {len(exploited)} |",
            f"| INFO EXPOSURE (partial) | {len(info_exposure)} |",
            f"| NOT EXPLOITED | {len(not_exploited)} |",
            f"| Total | {len(findings)} |",
        ]

        if exploited:
            lines += ["\n## Exploited Vulnerabilities\n"]
            for f in exploited:
                lines += self._render_finding(f)

        if info_exposure:
            lines += ["\n## Information Exposure (partial — proof-gate capped)\n"]
            for f in info_exposure:
                lines += self._render_finding(f)

        if not_exploited:
            lines += ["\n## Not Exploited\n"]
            for f in not_exploited:
                lines += [
                    f"### {f.bug_id}: {f.title}",
                    f"- Pattern: {f.pattern_id}",
                    f"- Endpoint: `{f.method} {f.endpoint}`",
                    f"- Status: {f.status.value}",
                    "",
                ]

        return "\n".join(lines)

    def _render_finding(self, f: Finding) -> list[str]:
        lines = [
            f"---",
            f"### {f.bug_id}: {f.title}",
            f"",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Pattern | {f.pattern_id} |",
            f"| Severity | **{f.severity.value}** |",
            f"| Endpoint | `{f.method} {f.endpoint}` |",
            f"| Status | {f.status.value} |",
            f"",
        ]

        if f.summary:
            lines += [f"**Summary:** {f.summary}", ""]

        if f.evidence and f.evidence.exchanges:
            lines += ["**Evidence:**", ""]
            for ex in f.evidence.exchanges[:5]:
                lines.append(f"- `{ex.method} {ex.url}` → `{ex.status}` (actor=`{ex.actor}`)")
            lines.append("")

        if f.evidence and f.evidence.proof_markers:
            satisfied = [m for m in f.evidence.proof_markers if m.satisfied]
            if satisfied:
                lines += ["**Proof Markers:**", ""]
                for m in satisfied:
                    lines.append(f"- ✓ `{m.key.value}`: {m.detail}")
                lines.append("")

        if f.panel:
            confirmed_count = sum(1 for v in f.panel if v.confirmed)
            lines += [
                f"**Verifier Panel:** {confirmed_count}/{len(f.panel)} confirmed",
                "",
            ]

        # Inline Burp-style PoC
        poc_content = self._read_poc(f)
        if poc_content:
            lines += ["**Proof of Concept (HTTP):**", "", "```"]
            lines += poc_content.splitlines()
            lines += ["```", ""]
        elif f.poc:
            lines += [f"**PoC:** `{f.poc.path}`", ""]

        if f.remediation:
            lines += [f"**Remediation:** {f.remediation}", ""]

        return lines


    def _read_poc(self, f: Finding) -> str:
        if not f.poc:
            return ""
        try:
            poc_path = self._ws.root / f.poc.path
            return poc_path.read_text(encoding="utf-8")
        except Exception:
            return ""


def _map_severity(risk) -> Severity:
    """Map BugDossier risk (Severity) to Finding severity."""
    if isinstance(risk, Severity):
        return risk
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
    }
    return mapping.get(str(risk).lower(), Severity.MEDIUM)
