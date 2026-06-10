"""Hybrid AI flow mapper.

Two-stage approach:
1. Deterministic prepass: collect endpoints + forms + money/qty fields + graph edges
   → structured summary (no LLM, fast, always runs)
2. One LLM call with the summary → semantic ordering + naming → BusinessFlow objects
   Fallback: keyword detector (existing logic) when LLM call fails.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from ..contracts.enums import Role
from ..contracts.recon import BusinessFlow, ReconArtifact

log = logging.getLogger("marl3.flow_mapper")

# Keywords that indicate a commerce/workflow step
_FLOW_KW = ("cart", "checkout", "order", "payment", "confirm", "transfer",
            "pay", "purchase", "basket", "invoice", "shipping", "billing")
_MONEY_KW = ("amount", "price", "qty", "quantity", "total", "balance", "cost",
             "fee", "subtotal", "discount")


async def detect_business_flows(artifact: ReconArtifact, llm=None) -> list[BusinessFlow]:
    """Detect business flows using hybrid approach: deterministic prepass + optional LLM call."""
    prepass = _deterministic_prepass(artifact)

    if not prepass["flow_endpoints"] and not prepass["money_forms"]:
        log.info("Flow mapper: no commerce signals found — returning empty flows")
        return []

    # If no LLM available, fall back to keyword detector
    if llm is None:
        return _keyword_fallback(artifact)

    try:
        flows = await _llm_flow_detection(prepass, llm)
        if flows:
            log.info(f"Flow mapper (LLM): detected {len(flows)} flows")
            return flows
    except Exception as e:
        log.warning(f"Flow mapper LLM call failed, using keyword fallback: {e}")

    return _keyword_fallback(artifact)


def _deterministic_prepass(artifact: ReconArtifact) -> dict:
    """Collect all structured signals without any LLM call."""
    flow_endpoints: list[dict] = []
    money_forms: list[dict] = []
    auth_required: list[str] = []

    for ep in artifact.endpoints:
        ep_lower = ep.endpoint.lower()
        is_flow = any(k in ep_lower for k in _FLOW_KW)
        is_auth = ep.auth_required

        if is_flow:
            flow_endpoints.append({
                "endpoint": ep.endpoint,
                "method": ep.method,
                "auth_required": is_auth,
                "parameters": ep.parameters,
                "numeric_fields": ep.numeric_fields,
            })
        if is_auth:
            auth_required.append(ep.endpoint)

    # Find forms with money/quantity fields
    for ex in artifact.exchanges:
        for form in ex.forms:
            money_fields = [
                f["name"] for f in form.get("fields", [])
                if any(m in f["name"].lower() for m in _MONEY_KW)
            ]
            if money_fields:
                money_forms.append({
                    "endpoint": ex.endpoint,
                    "action": form.get("action", ""),
                    "method": form.get("method", "post"),
                    "money_fields": money_fields,
                    "all_fields": [f["name"] for f in form.get("fields", [])],
                })

    # Get workflow graph edges for the flow endpoints
    graph_edges: list[dict] = []
    if artifact.workflow_graph:
        flow_ep_set = {e["endpoint"] for e in flow_endpoints}
        for edge in artifact.workflow_graph.edges:
            if edge.from_node in flow_ep_set or edge.to_node in flow_ep_set:
                graph_edges.append({"from": edge.from_node, "to": edge.to_node})

    # Extract cookies that look like session/state carriers
    session_cookies: list[str] = []
    for profile in artifact.auth_profiles:
        if profile.cookie_header:
            for part in profile.cookie_header.split(";"):
                name = part.strip().split("=")[0].lower()
                if any(k in name for k in ("session", "cart", "token", "order")):
                    session_cookies.append(name)

    return {
        "target_url": artifact.target_url,
        "flow_endpoints": flow_endpoints,
        "money_forms": money_forms,
        "graph_edges": graph_edges,
        "auth_required_endpoints": auth_required,
        "session_cookies": list(set(session_cookies)),
        "all_endpoints": [
            {"endpoint": ep.endpoint, "method": ep.method, "auth_required": ep.auth_required}
            for ep in artifact.endpoints
        ],
    }


async def _llm_flow_detection(prepass: dict, llm) -> list[BusinessFlow]:
    """One LLM call to sequence and name the flows from structured prepass data."""
    prompt = f"""You are analyzing HTTP recon data to detect multi-step business flows.

Target: {prepass["target_url"]}

## Commerce-related endpoints discovered:
{json.dumps(prepass["flow_endpoints"], indent=2)}

## Forms with money/quantity fields:
{json.dumps(prepass["money_forms"], indent=2)}

## Workflow graph edges (temporal sequence):
{json.dumps(prepass["graph_edges"], indent=2)}

## All discovered endpoints (for reference):
{json.dumps(prepass["all_endpoints"], indent=2)}

Based on this data, identify distinct multi-step business flows (e.g. "add to cart → checkout → payment → confirmation").

Return a JSON array. Each flow must:
- Only reference endpoints that appear in the "all_endpoints" list above
- Have ordered steps (from first to last in the flow)
- Include any state_fields (cookies/params that carry value across steps)
- Include any numeric_fields (price, qty, amount fields)

Return [] if no clear multi-step flow exists.

Example output:
[{{
  "flow_id": "checkout",
  "name": "Shopping Checkout Flow",
  "description": "Add item to cart, proceed through checkout, confirm payment",
  "steps": ["/cart", "/checkout", "/order/confirm"],
  "state_fields": ["session_id", "cart_token"],
  "numeric_fields": ["price", "quantity", "total"]
}}]

JSON array only, no markdown:"""

    response = await llm.chat(
        messages=[
            {"role": "system", "content": "You are a precise security analyst. Return only valid JSON."},
            {"role": "user", "content": prompt},
        ],
        role=Role.HUNTER,
        temperature=0.1,
        max_tokens=1500,
    )

    # Extract JSON from response
    import re
    response = response.strip()
    # Try to find JSON array
    m = re.search(r'\[.*\]', response, re.DOTALL)
    if not m:
        if response.strip() == "[]" or "no" in response.lower():
            return []
        raise ValueError(f"No JSON array in LLM response: {response[:200]}")

    raw = json.loads(m.group(0))
    # Build valid endpoint set for Issue-007 validation
    valid_endpoints = {e["endpoint"] for e in prepass["all_endpoints"]}

    flows: list[BusinessFlow] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        try:
            # Only keep steps that were actually discovered — filter hallucinated paths
            raw_steps = item.get("steps", [])
            valid_steps = [s for s in raw_steps if s in valid_endpoints]
            if len(valid_steps) < 2:
                log.debug(f"Flow mapper: dropped flow '{item.get('name')}' — "
                          f"only {len(valid_steps)}/{len(raw_steps)} steps are real endpoints")
                continue
            flows.append(BusinessFlow(
                flow_id=item.get("flow_id", "flow"),
                name=item.get("name", "Detected Flow"),
                description=item.get("description", ""),
                steps=valid_steps,
                state_fields=item.get("state_fields", []),
                numeric_fields=item.get("numeric_fields", []),
            ))
        except Exception:
            continue
    return flows


def _keyword_fallback(artifact: ReconArtifact) -> list[BusinessFlow]:
    """Simple keyword-based flow detection — fallback when LLM is unavailable."""
    steps = [e.endpoint for e in artifact.endpoints
             if any(k in e.endpoint.lower() for k in _FLOW_KW)]
    if len(steps) < 2:
        return []

    numeric: list[str] = []
    money_params: list[str] = []
    for ex in artifact.exchanges:
        if any(k in ex.endpoint.lower() for k in _FLOW_KW):
            numeric.extend(ex.numeric_fields.keys())
            for form in ex.forms:
                money_params.extend(
                    fld["name"] for fld in form.get("fields", [])
                    if any(m in fld["name"].lower() for m in _MONEY_KW)
                )
    return [BusinessFlow(
        flow_id="transaction",
        name="Transaction / Checkout Flow",
        description="Multi-step value-bearing workflow (keyword detection fallback)",
        steps=sorted(set(steps)),
        numeric_fields=sorted(set(numeric)),
        state_fields=sorted(set(money_params)),
    )]
