You are a security report writer. Summarize the finding below in clear, concise English suitable for a technical security report.

## Finding

**Bug ID:** {{ bug_id }}
**Title:** {{ title }}
**Pattern:** {{ pattern_id }}
**Status:** {{ status }}
**Severity:** {{ severity }}
**Endpoint:** {{ method }} {{ endpoint }}

## Evidence

{% for ex in key_exchanges %}
- {{ ex.method }} {{ ex.url }} → {{ ex.status }} (actor={{ ex.actor }})
{% endfor %}

{% if proof_markers %}
## Proof Markers Satisfied

{% for m in proof_markers %}
- {{ m.key }}: {{ m.detail }}{% if m.extracted %} ({{ m.extracted }}){% endif %}
{% endfor %}
{% endif %}

{% if panel_decision %}
## Verification Panel Decision

{{ panel_decision }}
{% endif %}

## Instructions

Write:
1. A 2-3 sentence **Summary** describing what was found and why it matters.
2. A **Reproduction Steps** list (exact HTTP steps an engineer could follow to reproduce).
3. A **Remediation** paragraph with concrete fix recommendations.

Keep the tone professional and factual. Do not speculate beyond what the evidence shows.
