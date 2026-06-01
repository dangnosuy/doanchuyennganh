"""
BusinessFlowMapper — maps crawl_raw.json to structured business_flows.json.

Runs between CrawlAgent and VulnHunterAgent. Uses LLM to identify multi-step
workflows, state-changing actions, and BLF/BAC vulnerable steps from observed
crawl data.

Usage:
    from shared.business_flow_mapper import BusinessFlowMapper, run
    flows = run(workspace_path, crawl_raw, target_url)
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from openai import OpenAI

# ── Ensure project root is on sys.path ──
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

# ── Config ───────────────────────────────────────────────────
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "gho_token")
SERVER_URL = os.getenv("MARL_SERVER_URL", "http://127.0.0.1:5000/v1")
MODEL = os.getenv("MARL_FLOW_MAPPER_MODEL", "gpt-4.1")

# Colors
YELLOW = "\033[93m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Limits
MAX_TRAFFIC_PER_SESSION = 80
MAX_PAGES = 20
MAX_NODES = 30
MAX_EDGES = 40
MAX_LLM_RETRIES = 3

# ── LLM Prompt ───────────────────────────────────────────────

_BUSINESS_FLOW_SYSTEM_PROMPT = """\
Ban la chuyen gia phan tich business flow — bac si phan tich quy trinh nghiep vu web.

Cho nay la output cua mot he thong crawl tu dong: crawl_raw.json chua HTTP traffic,
observed actions, AI-guided request chains, workflow graph, pages, va business chain da thu thap.

Nhiem vu cua ban: Phan tich tat ca du lieu nay va MAP ra cac business flows
theo cau truc chuan.

=== YEU CAU PHAN TICH ===
1. Doc toan bo HTTP traffic, observed_actions, request_chains, workflow_graph, pages
2. Tim cac chuoi hanh dong co tinh thu tu (multi-step workflows)
3. Dinh danh moi buoc: step_name, endpoint, method, form_fields_observed,
   state_before, state_after, redirect, response_status
4. Xac dinh buoc nao la state-changing (POST/PUT/PATCH/DELETE)
5. Doi voi buoc state-changing, xac dinh:
   - object_created: loai object tao ra (order, cart_item, coupon...)
   - state_change_verified: co the verify duoc khong
   - ownership_verified: co kiem tra ownership khong
6. Xac dinh vulnerable_steps: cac buoc co the co BLF/BAC
7. Tinh confidence: OBSERVED (thay truc tiep trong traffic) /
   CONFIRMED (co state change verified) / PARTIAL (suy luan tu schema/link)
8. Phan loai flow: purchase | account | admin | transfer | custom

=== FLOW STRUCTURE (output JSON) ===
{{
  "flow_count": N,
  "flows": [
    {{
      "id": "FLOW-001",
      "name": "Ten flow (VD: Dat hang, Dang nhap...)",
      "type": "purchase|account|admin|transfer|custom",
      "confidence": "OBSERVED|CONFIRMED|PARTIAL",
      "steps": [
        {{
          "order": 1,
          "step_name": "browse_products",
          "endpoint": "/products",
          "method": "GET",
          "params_observed": [],
          "state_before": null,
          "state_after": "user_browsing",
          "forms": [],
          "redirects_to": null,
          "response_status": 200,
          "state_change_verified": false
        }},
        {{
          "order": 2,
          "step_name": "add_to_cart",
          "endpoint": "/cart/add",
          "method": "POST",
          "form_fields_observed": ["product_id", "qty"],
          "sample_values": {{"product_id": "1", "qty": "1"}},
          "state_before": "cart_empty",
          "state_after": "cart_has_items",
          "response_status": 302,
          "response_redirect": "/cart",
          "state_change_verified": true,
          "object_created": null
        }}
      ],
      "vulnerable_steps": [
        {{
          "step_order": 2,
          "pattern": "BLF-07",
          "reason": "qty parameter co the nhan gia tri am — khong co server-side validation",
          "test_payload": {{"qty": "-1"}},
          "expected_behavior": "cart count giam xuong duoi 0"
        }}
      ],
      "evidence_endpoints": ["/products", "/cart/add", "/cart"],
      "provenance": "crawl_observed"
    }}
  ]
}}

=== RULES ===
- Chi tao flow neu co it nhat 2 buoc lien tiep
- Buoc state-changing phai co method POST/PUT/PATCH/DELETE
- endpoint phai xuat hien trong http_traffic hoac api_hints
- sample_values lay tu actual traffic, khong biet thi de null
- vulnerable_steps la list rong neu khong co nghi ngo
- DO NOT hallucinate. Chi map nhung gi thay trong du lieu.
- Tra ve JSON thuan, bat dau bang {{"flow_count": va ket thuc bang }}
"""


# ═══════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════

def _endpoint_path(url: str) -> str:
    """Extract path (with query) from a full URL."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return path


def _trim(value, limit: int = 80) -> str:
    if value is None:
        return ""
    s = " ".join(str(value).split())
    return s if len(s) <= limit else s[:limit - 3] + "..."


# ═══════════════════════════════════════════════════════════════════════
# BUSINESS FLOW MAPPER CLASS
# ═══════════════════════════════════════════════════════════════════════

class BusinessFlowMapper:
    """Map crawl data to structured business flows using LLM."""

    def __init__(self, run_dir: str, target_url: str, model: str | None = None):
        self.run_dir = os.path.abspath(run_dir)
        self.target_url = target_url
        self.model = model or MODEL
        self.client = OpenAI(api_key=GITHUB_TOKEN, base_url=SERVER_URL)

    # ── Public API ──────────────────────────────────────────────

    def run(self) -> dict:
        """Full pipeline: load crawl_raw → compact → LLM → parse → write → return flows."""
        print(f"\n{YELLOW}{BOLD}[FLOW-MAPPER] Bat dau phan tich business flows...{RESET}")
        print(f"{YELLOW}[FLOW-MAPPER] Target: {self.target_url}{RESET}")
        print(f"{YELLOW}[FLOW-MAPPER] Model: {self.model}{RESET}")

        crawl_raw = self._load_crawl_raw()
        if not crawl_raw:
            print(f"{RED}[FLOW-MAPPER] Khong the load crawl_raw.json — tra ve empty flows{RESET}")
            return self._empty_flows()

        # Compact payload for LLM context
        payload = self._compact_payload(crawl_raw)

        # Build messages
        messages = self._build_llm_messages(payload)

        # Call LLM with retries
        raw_response = self._call_llm(messages)
        if not raw_response:
            print(f"{RED}[FLOW-MAPPER] LLM call failed sau {MAX_LLM_RETRIES} lan thu{RESET}")
            return self._empty_flows()

        # Parse response
        flows = self._parse_llm_response(raw_response)
        flows["model_used"] = self.model

        # Write output
        output_path = self._write_flows(flows)
        flow_count = flows.get("flow_count", 0)
        print(f"{GREEN}[FLOW-MAPPER] Da ghi business_flows.json: {output_path} ({flow_count} flows){RESET}")

        # Print summary per flow
        for f in flows.get("flows", []):
            vuln_count = len(f.get("vulnerable_steps", []))
            print(
                f"  {CYAN}{f.get('id', '?')}: {f.get('name', '?')} "
                f"[{f.get('type', '?')}/{f.get('confidence', '?')}] — "
                f"{len(f.get('steps', []))} steps, {vuln_count} vuln{RESET}"
            )

        return flows

    # ── Internal ────────────────────────────────────────────────

    def _load_crawl_raw(self) -> dict:
        path = Path(self.run_dir) / "crawl_raw.json"
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"{RED}[FLOW-MAPPER] Error loading crawl_raw.json: {e}{RESET}")
            return {}

    def _compact_payload(self, raw: dict) -> dict:
        """Trim http_traffic/pages to manageable size while preserving signal."""
        payload = {
            "target": raw.get("target", self.target_url),
        }

        for key in ("anonymous", "authenticated"):
            session = raw.get(key)
            if key == "authenticated" and isinstance(session, list):
                # authenticated is a list of sessions
                compact_list = []
                for entry in session[:2]:  # max 2 authenticated sessions
                    if isinstance(entry, dict):
                        compact_list.append(self._compact_session(entry.get("data", entry)))
                payload[key] = compact_list
            elif isinstance(session, dict):
                payload[key] = self._compact_session(session)

        return payload

    def _compact_session(self, session: dict) -> dict:
        """Trim a single session's data."""
        compact = {}

        # HTTP traffic — keep most relevant entries
        ht = session.get("http_traffic", [])
        if isinstance(ht, list):
            # Prefer state-changing requests and those with form data
            scored = []
            for rec in ht:
                score = 0
                method = str(rec.get("method", "")).upper()
                if method in ("POST", "PUT", "PATCH", "DELETE"):
                    score += 10
                if rec.get("postData"):
                    score += 5
                if rec.get("form_fields"):
                    score += 5
                status = rec.get("response_status")
                if status and 200 <= status < 400:
                    score += 2
                if rec.get("response_json_keys"):
                    score += 3
                scored.append((score, rec))
            scored.sort(key=lambda x: x[0], reverse=True)
            compact["http_traffic"] = [r for _, r in scored[:MAX_TRAFFIC_PER_SESSION]]

        # Pages
        pages = session.get("pages", [])
        if isinstance(pages, list):
            compact["pages"] = pages[:MAX_PAGES]

        # Observed actions — keep all (usually small)
        compact["observed_actions"] = session.get("observed_actions", [])
        compact["ai_decisions"] = session.get("ai_decisions", [])
        compact["request_chains"] = session.get("request_chains", [])

        # Workflow graph — keep all nodes/edges but trim
        wg = session.get("workflow_graph", {})
        if isinstance(wg, dict):
            compact["workflow_graph"] = {
                "nodes": (wg.get("nodes") or [])[:MAX_NODES],
                "edges": (wg.get("edges") or [])[:MAX_EDGES],
            }

        # API hints
        compact["api_hints"] = session.get("api_hints", [])

        # Business chain
        compact["business_chain"] = session.get("business_chain", [])

        return compact

    def _build_llm_messages(self, payload: dict) -> list[dict]:
        """Build LLM messages with compact crawl data."""
        lines: list[str] = []
        lines.append("=== CRAWL DATA FOR BUSINESS FLOW ANALYSIS ===\n")
        lines.append(f"Target: {payload.get('target', self.target_url)}\n")

        # Helper to iterate sessions
        def _iter_sessions(label):
            session = payload.get(label)
            if isinstance(session, dict):
                yield session
            elif isinstance(session, list):
                for s in session:
                    if isinstance(s, dict):
                        yield s

        # ── HTTP Traffic ──
        for label in ("anonymous", "authenticated"):
            has_traffic = False
            for session in _iter_sessions(label):
                ht = session.get("http_traffic", [])
                if not ht:
                    continue
                if not has_traffic:
                    lines.append(f"\n## {label.upper()} HTTP TRAFFIC")
                    has_traffic = True
                for rec in ht:
                    url = rec.get("url", "")
                    method = rec.get("method", "GET")
                    status = rec.get("response_status", "?")
                    path = _endpoint_path(url)
                    post_data = rec.get("postData")
                    form_fields = rec.get("form_fields")
                    resp_keys = rec.get("response_json_keys", [])

                    line = f"  [{status}] {method} {path}"
                    extras = []
                    if post_data:
                        extras.append(f"body={_trim(post_data)}")
                    if form_fields and isinstance(form_fields, list):
                        field_names = [
                            ff.get("name", "") for ff in form_fields
                            if isinstance(ff, dict) and ff.get("name")
                        ]
                        if field_names:
                            extras.append(f"fields={','.join(field_names[:8])}")
                    if resp_keys and isinstance(resp_keys, list):
                        extras.append(f"json_keys={','.join(str(k) for k in resp_keys[:8])}")
                    if extras:
                        line += " | " + " | ".join(extras)
                    lines.append(line)

        # ── Observed Actions ──
        for label in ("anonymous", "authenticated"):
            has_actions = False
            for session in _iter_sessions(label):
                oa = session.get("observed_actions", [])
                if not oa:
                    continue
                if not has_actions:
                    lines.append(f"\n## {label.upper()} OBSERVED ACTIONS")
                    has_actions = True
                for action in oa:
                    name = action.get("name", "?")
                    status = action.get("status", "?")
                    before = _endpoint_path(action.get("before_url", ""))
                    after = _endpoint_path(action.get("after_url", ""))
                    detail = action.get("detail", {})
                    target = ""
                    if isinstance(detail, dict):
                        target = detail.get("target", "") or detail.get("selector", "")
                    lines.append(f"  {name} | {status} | {before} -> {after} | {_trim(target)}")

        # ── AI-guided request chains ──
        for label in ("anonymous", "authenticated"):
            has_chains = False
            for session in _iter_sessions(label):
                chains = session.get("request_chains", [])
                if not chains:
                    continue
                if not has_chains:
                    lines.append(f"\n## {label.upper()} AI REQUEST CHAINS")
                    has_chains = True
                for chain in chains:
                    lines.append(
                        "  ACTION "
                        f"{chain.get('action_id', '?')} {chain.get('label', '')} | "
                        f"{_endpoint_path(chain.get('before_url', ''))} -> {_endpoint_path(chain.get('after_url', ''))} | "
                        f"status={chain.get('status', '?')} | reason={_trim(chain.get('reason', ''), 120)}"
                    )
                    for req in (chain.get("emitted_requests") or [])[:8]:
                        lines.append(
                            f"    REQ: {req.get('method', '?')} {req.get('endpoint', '?')} "
                            f"status={req.get('status', '?')} json={req.get('json_keys', [])}"
                        )

        # ── Pages (forms + buttons) ──
        for label in ("anonymous", "authenticated"):
            has_pages = False
            for session in _iter_sessions(label):
                pages = session.get("pages", [])
                if not pages:
                    continue
                if not has_pages:
                    lines.append(f"\n## {label.upper()} PAGES")
                    has_pages = True
                for page in pages:
                    page_label = page.get("label", "?")
                    url = page.get("url", "")
                    path = _endpoint_path(url)
                    forms = page.get("forms", [])
                    buttons = page.get("buttons", [])
                    lines.append(f"  PAGE: {page_label} | {path} | forms={len(forms)} | buttons={len(buttons)}")
                    if isinstance(forms, list):
                        for form in forms:
                            action = _endpoint_path(form.get("action", ""))
                            method = form.get("method", "GET")
                            inputs = form.get("inputs", [])
                            field_names = [
                                i.get("name", "") for i in inputs
                                if isinstance(i, dict) and i.get("name")
                            ]
                            lines.append(f"    FORM: {method} {action} fields={field_names[:8]}")

        # ── Workflow Graph ──
        for label in ("anonymous", "authenticated"):
            has_graph = False
            for session in _iter_sessions(label):
                wg = session.get("workflow_graph", {})
                if not isinstance(wg, dict):
                    continue
                nodes = wg.get("nodes", [])
                edges = wg.get("edges", [])
                if not nodes and not edges:
                    continue
                if not has_graph:
                    lines.append(f"\n## {label.upper()} WORKFLOW GRAPH")
                    has_graph = True
                lines.append(f"  Nodes ({len(nodes)}):")
                for node in nodes[:MAX_NODES]:
                    nid = node.get("id", node.get("url", ""))
                    kind = node.get("kind", "")
                    methods = node.get("methods", [])
                    title = _trim(node.get("title", ""), 50)
                    lines.append(f"    [{kind}] {nid} methods={methods} title={title}")
                lines.append(f"  Edges ({len(edges)}):")
                for edge in edges[:MAX_EDGES]:
                    frm = edge.get("from", "")
                    to = edge.get("to", "")
                    etype = edge.get("type", "")
                    emethod = edge.get("method", "")
                    lines.append(f"    {frm} --[{etype}/{emethod}]--> {to}")

        # ── API Hints ──
        for label in ("anonymous", "authenticated"):
            has_hints = False
            for session in _iter_sessions(label):
                hints = session.get("api_hints", [])
                if not hints:
                    continue
                if not has_hints:
                    lines.append(f"\n## {label.upper()} API HINTS")
                    has_hints = True
                for h in hints:
                    method = h.get("method", "GET")
                    path = h.get("path", "")
                    source = h.get("source", "")
                    lines.append(f"  {method} {path} | source={source}")

        # ── Existing Business Chain ──
        for label in ("anonymous", "authenticated"):
            has_chain = False
            for session in _iter_sessions(label):
                bc = session.get("business_chain", [])
                if not bc:
                    continue
                if not has_chain:
                    lines.append(f"\n## {label.upper()} BUSINESS CHAIN (existing)")
                    has_chain = True
                for step in bc:
                    step_name = step.get("step", "")
                    method = step.get("method", "")
                    endpoint = step.get("endpoint", "")
                    status = step.get("status", "")
                    lines.append(f"  {step_name} | {method} {endpoint} | status={status}")

        data_text = "\n".join(lines)

        return [
            {"role": "system", "content": _BUSINESS_FLOW_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    "Phan tich du lieu crawl ben duoi va tra ve business_flows.json "
                    "theo cau truc da yeu cau.\n\n"
                    "Dieu kien:\n"
                    "- Chi dinh danh flow tu HTTP traffic thuc te (khong suy ra tu JS/schema don)\n"
                    "- Neu mot endpoint co nhieu action (view, add, update), tach thanh nhieu steps\n"
                    "- Neu khong co du lieu du cho 1 flow, bo qua flow do\n"
                    "- Chi tao vulnerable_steps neu co dau hieu cu the\n"
                    "- Uu tien flows co state-changing actions (POST/PUT/PATCH/DELETE)\n"
                    "- Goi y vulnerable_steps cho: IDOR (object ID trong URL), "
                    "quantity/price manipulation, race condition (repeated POST), "
                    "missing ownership check\n\n"
                    f"=== CRAWL DATA ===\n{data_text}"
                ),
            },
        ]

    def _call_llm(self, messages: list[dict]) -> str:
        """Call LLM with retries."""
        for attempt in range(1, MAX_LLM_RETRIES + 1):
            try:
                print(f"{YELLOW}[FLOW-MAPPER] LLM call attempt {attempt}/{MAX_LLM_RETRIES}...{RESET}")
                resp = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    temperature=0.2,
                    max_tokens=16384,
                )
                text = resp.choices[0].message.content or ""
                if text.strip():
                    return text.strip()
                print(f"{YELLOW}[FLOW-MAPPER] LLM tra ve rong (attempt {attempt}){RESET}")
            except Exception as e:
                print(f"{RED}[FLOW-MAPPER] LLM failed (attempt {attempt}): {e}{RESET}")
        return ""

    def _parse_llm_response(self, raw: str) -> dict:
        """Parse LLM response into structured flows dict."""
        text = raw.strip()

        # Remove markdown fences
        if text.startswith("```"):
            lines = text.split("\n")
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            text = "\n".join(lines).strip()

        # Find JSON start
        json_start = -1
        for marker in ('{"flow_count":', '{"flows":', '{'):
            idx = text.find(marker)
            if idx != -1:
                json_start = idx
                break

        if json_start > 0:
            text = text[json_start:]

        # Walk depth to find JSON end
        depth = 0
        in_string = False
        escape = False
        json_end = -1
        for i, c in enumerate(text):
            if escape:
                escape = False
                continue
            if c == "\\" and in_string:
                escape = True
                continue
            if c == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    json_end = i + 1
                    break

        if json_end > 0:
            text = text[:json_end]

        try:
            flows = json.loads(text)
        except json.JSONDecodeError as e:
            print(f"{RED}[FLOW-MAPPER] JSON parse failed: {e}{RESET}")
            print(f"{RED}[FLOW-MAPPER] Raw (first 500 chars): {text[:500]}{RESET}")
            return self._empty_flows()

        # Validate structure
        if not isinstance(flows, dict):
            return self._empty_flows()
        if "flows" not in flows:
            flows["flows"] = []
        if "flow_count" not in flows:
            flows["flow_count"] = len(flows.get("flows", []))

        # Validate each flow
        valid_flows = []
        for f in flows.get("flows", []):
            if not isinstance(f, dict):
                continue
            if not f.get("steps"):
                continue
            # Ensure required fields
            f.setdefault("id", f"FLOW-{len(valid_flows) + 1:03d}")
            f.setdefault("name", "Unknown Flow")
            f.setdefault("type", "custom")
            f.setdefault("confidence", "PARTIAL")
            f.setdefault("vulnerable_steps", [])
            f.setdefault("evidence_endpoints", [])
            f.setdefault("provenance", "crawl_observed")
            valid_flows.append(f)

        flows["flows"] = valid_flows
        flows["flow_count"] = len(valid_flows)

        return flows

    def _write_flows(self, flows: dict) -> str:
        """Write flows to business_flows.json in workspace."""
        output_path = Path(self.run_dir) / "business_flows.json"
        flows["generated_at"] = datetime.now(timezone.utc).isoformat()
        output_path.write_text(
            json.dumps(flows, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return str(output_path)

    def _empty_flows(self) -> dict:
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "model_used": self.model,
            "flow_count": 0,
            "flows": [],
        }


# ═══════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════════

def run(workspace_path: str, crawl_raw: dict, target_url: str) -> dict:
    """Main entry point. Returns flows dict. Writes {workspace}/business_flows.json.

    If crawl_raw is empty/invalid, returns empty flows dict (never crashes).
    """
    mapper = BusinessFlowMapper(workspace_path, target_url)
    if not crawl_raw or not isinstance(crawl_raw, dict):
        flows = mapper._empty_flows()
        mapper._write_flows(flows)
        return flows
    return mapper.run()


# ═══════════════════════════════════════════════════════════════════════
# STANDALONE CLI
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: python {sys.argv[0]} <run_dir> <target_url>")
        sys.exit(1)

    run_dir = sys.argv[1]
    target_url = sys.argv[2]

    mapper = BusinessFlowMapper(run_dir, target_url)
    flows = mapper.run()
    print(f"\n{GREEN}=== BusinessFlowMapper Complete: {flows.get('flow_count', 0)} flows ==={RESET}")
