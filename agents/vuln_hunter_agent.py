"""
VulnHunterAgent — Vulnerability hypothesis generator for MARL.

Runs AFTER CrawlAgent produces recon.md and BEFORE the per-bug debate.
Reads recon.md (LLM analysis) and crawl_data.txt (raw HTTP traffic),
uses an LLM to identify structured vulnerability hypotheses,
writes output to risk-bug.json.

Usage:
    from agents.vuln_hunter_agent import VulnHunterAgent
    agent = VulnHunterAgent(run_dir="./workspace/...", target_url="https://target.com/")
    bugs = agent.run()
"""

import json
import os
import re
import sys
from pathlib import Path

from openai import OpenAI

# ── Ensure project root is on sys.path ──
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from knowledge.bac_blf_playbook import get_playbook_text
from shared.bug_dossier import normalize_http_example


# ═══════════════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════════════

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "gho_token")
SERVER_URL = os.getenv("MARL_SERVER_URL", "http://127.0.0.1:5000/v1")
MODEL = os.getenv("MARL_VULNHUNTER_MODEL", "ollama/gemma4:31b-cloud")

# Colors (match other agents)
YELLOW = "\033[93m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Limits
MAX_RECON_CHARS = 0  # 0 = doc toan bo recon.md enriched
MAX_BUGS = 15
MAX_RAW_BUGS_TO_PARSE = MAX_BUGS * 3
MAX_ACTION_DISCOVERY_BUGS = 3
MAX_HTTP_EXAMPLES_PER_BUG = 2
MAX_RESPONSE_SNIPPET_CHARS = 200
MAX_LLM_RETRIES = 3
INVALID_ENDPOINT_MARKERS = ("/nan", "/undefined", "/null", "{nan}", "{undefined}", "{null}")
ACTION_DISCOVERY_ALLOWED_PATH_MARKERS = (
    "cart", "basket", "checkout", "order", "payment", "transfer",
    "wallet", "balance", "coupon", "discount", "promo", "invoice",
    "booking", "reservation", "stock", "inventory", "subscription",
)
ACTION_DISCOVERY_BLOCKED_PATH_MARKERS = (
    "/api/users", "/users", "whoami", "/me", "history", "challenge",
    "configuration", "version", "captcha", "language",
)
ACTION_DISCOVERY_SCHEMA_MARKERS = (
    "quantity", "qty", "limit", "quota", "price", "amount", "balance",
    "total", "stock", "inventory", "coupon", "discount", "payment",
    "wallet", "credit", "debit", "ownerid", "userid", "accountid",
    "orderid", "invoiceid", "cartid", "basketid", "productid",
)
BUSINESS_ROUTE_MARKERS = (
    "cart", "basket", "checkout", "order", "payment", "transfer",
    "wallet", "balance", "coupon", "discount", "invoice", "booking",
    "reservation", "subscription", "shipment", "stock", "inventory",
)
SENSITIVE_READ_MARKERS = (
    "user", "users", "account", "accounts", "profile", "admin",
    "role", "roles", "permission", "permissions", "order", "orders",
    "invoice", "invoices", "transaction", "transactions", "payment",
    "payments", "wallet", "wallets", "document", "documents", "file",
    "files", "project", "projects", "tenant", "tenants",
)

# Risk level mapping: pattern_id → risk_level
RISK_LEVEL_MAP = {
    "BAC-01": "CRITICAL",
    "BAC-04": "CRITICAL",
    "BLF-08": "CRITICAL",
    "BAC-02": "HIGH",
    "BAC-03": "HIGH",
    "BLF-01": "HIGH",
    "BLF-03": "HIGH",
    "BLF-05": "HIGH",
    "BLF-07": "HIGH",
    # everything else defaults to MEDIUM
}


# ═══════════════════════════════════════════════════════════════════════
# SYSTEM PROMPT
# ═══════════════════════════════════════════════════════════════════════

VULNHUNTER_SYSTEM_PROMPT = """Ban la chuyen gia Vulnerability Analysis — doc ENRICHED RECON DOSSIER
de dua ra cac bug candidate ve BAC (Broken Access Control) va BLF (Business Logic Flaw).

MUC TIEU:
- Uu tien evidence-backed candidates hon viec tao nhieu bug.
- Chi dua route/endpoint vao output neu no xuat hien trong Observed Endpoint Inventory,
  Structured Route Families, Endpoint Dossiers, Active Discovery Probes voi route_exists=true,
  Guided Auth And API Hints,
  HOAC la action endpoint suy ra truc tiep tu route/schema da observed cho cung route family.
- Khong bien HTML/CSS/JS keyword thanh endpoint that neu recon chi ghi la signal.
- Red/Blue/Exec se la cac thanh phan xac minh sau. Ban KHONG can confirm 100%.
- TOI DA {max_bugs} bug candidates. Neu evidence it thi tra ve it bug, khong tu bia cho du so luong.

=== KIEN THUC VE CAC PATTERN ===
{playbook}

=== ENRICHED RECON DOSSIER ===
{recon_summary}

=== CACH LAM VIEC BAT BUOC ===
1. Doc toan bo recon.md enriched, dac biet cac phan:
   - Observed Endpoint Inventory
   - Guided Workflow Graph
   - Guided Auth And API Hints
   - Active Discovery Probes
   - Structured Route Families
   - Endpoint Dossiers
   - Candidate BAC/BLF Signals
1b. Neu narrative o phan tren mau thuan voi Structured Route Families / Endpoint Dossiers,
    LUON uu tien section cau truc o phia duoi. Endpoint trong output phai dung dung route family
    da xuat hien trong Structured Route Families, Endpoint Dossiers, Guided Workflow Graph,
    hoac Static JS API Hints voi candidate_type=ACTION_DISCOVERY.
2. Tim CAC DIEM CO THE CO BUG dua tren:
   - route dung direct object identifiers
   - admin/management endpoints
   - mutable numeric fields: qty, amount, price, stock, balance
   - profile/order/cart/checkout/transfer workflow
   - role/user_id/client-controlled identity hints
   - Cookie-based role/auth: role, user_id, session — cookie tampering candidates
   - Multi-step workflows co state transition hoac gia tri business thay doi
   - HTTP method variations: GET vs POST vs PUT vs DELETE on same endpoint
   - Guided workflow edges co state-changing request that (POST/PUT/PATCH/DELETE)
3. Khi nghi ngo nhung route chua co evidence/probe route_exists=true, chi duoc dua thanh bug neu
   candidate_type=`ACTION_DISCOVERY` va phai noi ro route/schema observed nao lam can cu.
4. Moi bug candidate phai noi ro vi sao route do dang nghi va can verify nhu the nao.
5. Khong bat buoc moi route family phai co bug. Chi route co BAC/BLF signal ro moi tao candidate.
6. Moi bug nen co `candidate_type`: `EVIDENCE_BACKED` hoac `ACTION_DISCOVERY`.
   thi nen co bug candidate cho TUNG nhom route.

=== YEU CAU QUAN TRONG ===
Moi bug candidate nen co:
- endpoint / route family bi nghi ngo
- method neu suy ra duoc
- hypothesis: tai sao co the co bug
- exploit_approach: cach thu nghiem
- verify_method: dau hieu can kiem tra boi cac agent sau
- request_params / form_fields / response_clues neu recon co nhac toi
- confidence: LOW / MEDIUM / HIGH
- Neu endpoint co trong Guided Workflow Graph voi request method POST/PUT/PATCH/DELETE thi uu tien
  candidate_type=`EVIDENCE_BACKED` va method phai la method da observed, khong doi sang GET.
- Neu chi co GET schema gan do nhung muon de xuat state-changing method moi thi moi dung
  candidate_type=`ACTION_DISCOVERY`, confidence LOW, requires_probe se duoc pipeline gan sau.
- Khong tao bug cho endpoint loi do crawl/auth-state nhu `/NaN`, `/undefined`, `/null`.
- Static JS API Hints chi la co so ACTION_DISCOVERY neu co route family ro va co schema/traffic gan do lam can cu.

=== OUTPUT FORMAT ===
CHI TRA VE JSON array hop le, TOI DA {max_bugs} phan tu. Neu evidence it thi tra ve it bug.
Khong viet markdown, khong viet giai thich, khong viet attack surface summary ngoai JSON.
Ky tu dau tien phai la `[` va ky tu cuoi cung phai la `]`.
Moi phan tu co cau truc:
{{
  "id": "BUG-001",
  "category": "BAC",
  "pattern_id": "BAC-03",
  "title": "IDOR on /product/<id> — horizontal privilege escalation",
  "risk_level": "HIGH",
  "endpoint": "/product/{{id}}",
  "method": "GET",
  "hypothesis": "Backend khong verify ownership khi user truy cap product cua user B.",
  "exploit_approach": "Login as user A → GET /product/N (N la product cua user B) → neu tra data → IDOR",
  "verify_method": "GET /product/{{other_user_id}} as user A → neu co data → CONFIRMED",
  "request_params": ["id"],
  "form_fields": [],
  "response_clues": ["route uses direct object identifiers in the path", "order/account data page"],
  "auth_required": true,
  "auth_credentials_needed": ["user_a"],
  "confidence": "MEDIUM"
}}

Dong y voi cac quy tac:
- "auth_required": true neu loi hong can authenticated session (login), false neu anonymous
- "auth_credentials_needed": list username can thiet de khai thac (bo trong [] neu khong can)
- "hypothesis": viet 1-2 cau tieng Viet, ro rang, giai thich tai sao day la loi
- "exploit_approach": viet 2-3 cau, mo ta buoc khai thac cu the
- "verify_method": viet 1-2 cau, mo ta cach xac nhan loi
- "request_params" va "form_fields" dua tren recon neu co
- "response_clues" la cac clue ngan gon tu recon, khong can exact raw dump
- "confidence": LOW neu chi la nghi ngo yeu, MEDIUM neu co nhieu dau hieu, HIGH neu recon cho thay dau hieu rat manh

Khong can chac chan 100%. Neu thay dang nghi thi cu dua vao output.
Neu khong co bug hop le → tra ve [].
NHAN MANH: Hay gen TOI DA cac candidate. 5 bug la QUA IT cho mot ung dung web co nhieu endpoints.
"""


# ═══════════════════════════════════════════════════════════════════════
# USER PROMPT BUILDER
# ═══════════════════════════════════════════════════════════════════════

def _build_user_prompt(
    recon_content: str, playbook: str, business_flows: list[dict] | None = None
) -> str:
    base = VULNHUNTER_SYSTEM_PROMPT.format(
        playbook=playbook,
        recon_summary=recon_content,
        max_bugs=MAX_BUGS,
    )

    if not business_flows:
        return base

    # Build flows section
    lines = ["\n=== OBSERVED BUSINESS FLOWS (from crawl analysis) ==="]
    for f in business_flows[:8]:  # limit to 8 flows
        if not isinstance(f, dict):
            continue
        name = f.get("name", "Unknown")
        flow_type = f.get("type", "custom")
        confidence = f.get("confidence", "PARTIAL")
        vuln_count = len(f.get("vulnerable_steps", []))
        vuln_str = f" | {vuln_count} suspect step(s)" if vuln_count else ""
        lines.append(f"\n- {f.get('id', '?')}: {name} [{flow_type}/{confidence}]{vuln_str}")

        # Steps
        for step in f.get("steps", [])[:6]:
            if not isinstance(step, dict):
                continue
            state = " (state_change_verified)" if step.get("state_change_verified") else ""
            fields = step.get("form_fields_observed", [])
            field_str = f" fields={fields}" if fields else ""
            lines.append(
                f"  step {step.get('order', '?')}: {step.get('step_name', '?')} = "
                f"{step.get('method', '?')} {step.get('endpoint', '?')}{state}{field_str}"
            )
            # Show sample values if available
            sample = step.get("sample_values")
            if sample and isinstance(sample, dict):
                lines.append(f"    sample: {sample}")

        # Vulnerable steps
        for vs in f.get("vulnerable_steps", []):
            if not isinstance(vs, dict):
                continue
            lines.append(
                f"  VULN step {vs.get('step_order', '?')}: {vs.get('pattern', '?')} — "
                f"{str(vs.get('reason', ''))[:120]}"
            )

    flows_section = "\n".join(lines)

    # Inject flows section into the prompt
    return base + "\n" + flows_section


# ═══════════════════════════════════════════════════════════════════════
# VULNHUNTER AGENT CLASS
# ═══════════════════════════════════════════════════════════════════════

class VulnHunterAgent:
    """Identify vulnerability hypotheses from CrawlAgent output."""

    def __init__(
        self,
        run_dir: str,
        target_url: str,
        recon_md_path: str,
        crawl_data_path: str,
    ):
        self.run_dir = os.path.abspath(run_dir)
        self.target_url = target_url
        self.recon_md_path = recon_md_path
        self.crawl_data_path = crawl_data_path

        self.client = OpenAI(api_key=GITHUB_TOKEN, base_url=SERVER_URL)
        self.playbook = get_playbook_text()
        self._raw_payload: dict = {}
        self.business_flows: list[dict] = []

        os.makedirs(self.run_dir, exist_ok=True)

    # ─── Public API ──────────────────────────────────────────────────────

    def run(self) -> list[dict]:
        """
        Main entry point. Reads enriched recon.md, calls LLM,
        writes risk-bug.json to run_dir, returns list of bug entries.
        """
        print(f"\n{YELLOW}{BOLD}[VULN-HUNTER] Bat dau phan tich vulnerability hypotheses...{RESET}")
        print(f"{YELLOW}[VULN-HUNTER] Target: {self.target_url}{RESET}")

        # ── 1. Read enriched recon dossier only ──
        recon_content = self._read_recon()

        if not recon_content:
            print(f"{RED}[VULN-HUNTER] Khong co recon.md de phan tich.{RESET}")
            self._write_bugs([])
            return []

        print(f"{GREEN}[VULN-HUNTER] Da doc {len(recon_content)} chars recon dossier{RESET}")

        # ── 1b. Load raw endpoints from crawl_raw.json ──
        raw_endpoints = self._load_raw_endpoints()
        if raw_endpoints:
            print(f"{GREEN}[VULN-HUNTER] Loaded {len(raw_endpoints)} raw endpoints from crawl_raw.json{RESET}")

        # ── 1c. Load business flows from business_flows.json ──
        self.business_flows = self._load_business_flows()
        if self.business_flows:
            print(f"{GREEN}[VULN-HUNTER] Loaded {len(self.business_flows)} business flows{RESET}")

        # ── 2. Call LLM ──
        print(f"{YELLOW}[VULN-HUNTER] Goi LLM phan tich... (model={MODEL}, max_tokens=16384){RESET}")
        raw_json = self._call_llm(recon_content)
        if not raw_json.strip():
            print(f"{YELLOW}[VULN-HUNTER] Khong nhan duoc output hop le tu LLM sau {MAX_LLM_RETRIES} lan thu{RESET}")
            self._write_bugs([])
            return []

        # ── 3. Parse + validate + enrich ──
        bugs = self._parse_bugs(raw_json, raw_endpoints=raw_endpoints)
        bugs = self._dedupe_and_rank_candidates(bugs, max_bugs=MAX_BUGS)
        bugs = self._add_deterministic_candidates(bugs, raw_endpoints)
        bugs = self._dedupe_and_rank_candidates(bugs, max_bugs=MAX_BUGS)
        print(f"{GREEN}[VULN-HUNTER] Tim thay {len(bugs)} vulnerability hypotheses{RESET}")

        # ── 3b. Filter metadata-only candidates ──
        bugs = self._filter_challenge_metadata_bugs(bugs)
        print(f"{GREEN}[VULN-HUNTER] Sau filter metadata-only: {len(bugs)} bugs{RESET}")

        # ── 4. Write output ──
        self._write_bugs(bugs)

        return bugs

    # ─── Internal ─────────────────────────────────────────────────────────

    def _try_truncate_to_complete_json(self, json_text: str) -> str | None:
        """Try to truncate JSON at a safe point after the last complete object."""
        # Find the last },{ or }] that could be a complete boundary
        # Walk backwards from the end to find a }, or }] that closes a complete object
        depth = 0
        in_string = False
        escape = False
        for i in range(len(json_text) - 1, -1, -1):
            c = json_text[i]
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
            if c in ("}", "]"):
                depth += 1
            elif c in ("{", "["):
                depth -= 1
            # If we just closed an object (depth back to 0) and next char is , or ] or }
            if depth == 0 and i < len(json_text) - 1:
                next_c = json_text[i + 1]
                if next_c in (",", "]", "}"):
                    return json_text[:i + 1] + "]"
        return None

    @staticmethod
    def _extract_balanced_json_array(text: str) -> str | None:
        """Extract the first balanced JSON array from mixed LLM output."""
        start = text.find("[")
        while start != -1:
            depth = 0
            in_string = False
            escape = False
            for i in range(start, len(text)):
                c = text[i]
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
                if c == "[":
                    depth += 1
                elif c == "]":
                    depth -= 1
                    if depth == 0:
                        candidate = text[start:i + 1].strip()
                        try:
                            parsed = json.loads(candidate)
                            if isinstance(parsed, list):
                                return candidate
                        except json.JSONDecodeError:
                            break
            start = text.find("[", start + 1)
        return None

    def _read_recon(self) -> str:
        """Read the full enriched recon.md as VulnHunter's only runtime input."""
        try:
            with open(self.recon_md_path, "r", encoding="utf-8") as f:
                content = f.read() if MAX_RECON_CHARS == 0 else f.read(MAX_RECON_CHARS)
            if MAX_RECON_CHARS == 0:
                print(f"{CYAN}[VULN-HUNTER] Da doc recon.md: {len(content)} chars (full file){RESET}")
            else:
                print(f"{CYAN}[VULN-HUNTER] Da doc recon.md: {len(content)} chars "
                      f"(gioi han {MAX_RECON_CHARS}){RESET}")
            return content
        except FileNotFoundError:
            print(f"{YELLOW}[VULN-HUNTER] recon.md not found: {self.recon_md_path}{RESET}")
            return ""
        except Exception as e:
            print(f"{YELLOW}[VULN-HUNTER] Error reading recon.md: {e}{RESET}")
            return ""

    def _call_llm(self, recon_content: str) -> str:
        """Send enriched recon.md to LLM and return raw text response."""
        messages = [
            {"role": "system", "content": _build_user_prompt(recon_content, self.playbook, self.business_flows)},
            {"role": "user", "content": (
                "Doc TOAN BO recon.md enriched va tra ve CAC BUG CANDIDATE co evidence-backed BAC/BLF. "
                "Khong tao bug cho endpoint chi la keyword/signal/chua duoc probe, tru khi la ACTION_DISCOVERY "
                "suy ra truc tiep tu route/schema da observed. "
                "Khong viet markdown, khong giai thich ngoai JSON. "
                "Output phai bat dau bang '[' va ket thuc bang ']'. "
                "Chi dung Observed Endpoint Inventory, Guided Workflow Graph, Guided Auth And API Hints, "
                "Endpoint Dossiers, hoac Active Discovery Probes route_exists=true. "
                "Khong tao candidate cho endpoint co NaN/undefined/null vi do la loi crawl state. "
                "Voi BLF/BAC state-changing, chi de xuat method chua observed neu co route family/schema gan do lam can cu. "
                "Neu evidence it thi tra ve it bug, khong can du 8 candidates."
            )},
        ]

        for attempt in range(1, MAX_LLM_RETRIES + 1):
            try:
                response = self.client.chat.completions.create(
                    model=MODEL,
                    messages=messages,
                    temperature=0.3,
                    max_tokens=16384,
                )
                text = response.choices[0].message.content or ""
                if text.strip():
                    return text
                print(
                    f"{YELLOW}[VULN-HUNTER] LLM tra ve output rong "
                    f"(attempt {attempt}/{MAX_LLM_RETRIES}){RESET}"
                )
            except Exception as e:
                print(
                    f"{RED}[VULN-HUNTER] LLM call failed "
                    f"(attempt {attempt}/{MAX_LLM_RETRIES}): {e}{RESET}"
                )
        return ""

    def _parse_bugs(self, raw_text: str, *, raw_endpoints: list[dict] | None = None) -> list[dict]:
        """
        Parse raw LLM output into bug entries.
        Tries to extract a JSON array from the response.
        Each bug is enriched with id, status, attempt_count, debate_rounds,
        request params, form fields, response clues, and auth hints.
        """
        if not raw_text or not raw_text.strip():
            return []

        text = raw_text.strip()

        # Remove markdown code fences if present
        if text.startswith("```"):
            lines = text.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            text = "\n".join(lines).strip()

        # Strip markdown bold/italic markers that corrupt JSON parsing
        text = re.sub(r"\*+", "", text)

        # Extract the first complete JSON array. The local/Ollama model can
        # prepend attack-surface prose or append notes even when asked for JSON.
        json_text = self._extract_balanced_json_array(text)
        if json_text is None:
            arr_start = text.find("[")
            json_text = text[arr_start:] if arr_start != -1 else text

        try:
            bugs = json.loads(json_text)
        except json.JSONDecodeError as e:
            print(f"{RED}[VULN-HUNTER] JSON parse failed: {e}{RESET}")
            print(f"{DIM}Raw response (first 500 chars): {raw_text[:500]}{RESET}")
            # Try cleanup of trailing commas + unclosed strings
            try:
                cleaned = re.sub(r",\s*([\]}])", r"\1", json_text)
                bugs = json.loads(cleaned)
            except json.JSONDecodeError:
                # Try to find a safe truncation point — after last complete object
                truncated = self._try_truncate_to_complete_json(json_text)
                if truncated:
                    try:
                        bugs = json.loads(truncated)
                        print(f"{GREEN}[VULN-HUNTER] JSON repaired via truncation{RESET}")
                    except Exception:
                        return []
                else:
                    return []

        if not isinstance(bugs, list):
            print(f"{YELLOW}[VULN-HUNTER] Expected list, got {type(bugs).__name__}{RESET}")
            return []

        # Enrich and validate each bug
        enriched = []
        for i, bug in enumerate(bugs[:MAX_RAW_BUGS_TO_PARSE]):
            if not isinstance(bug, dict):
                continue

            bug_id = bug.get("id") or f"BUG-{i + 1:03d}"

            # Resolve risk_level
            pattern_id = bug.get("pattern_id", "")
            risk_level = bug.get("risk_level", "")
            if not risk_level:
                risk_level = RISK_LEVEL_MAP.get(pattern_id, "MEDIUM")

            # Normalize optional evidence fields. The richer recon is the primary
            # source now, so http_examples may legitimately be empty here.
            http_examples = bug.get("http_examples", [])
            if not isinstance(http_examples, list):
                http_examples = []

            # Truncate response_snippet per example
            for ex in http_examples:
                if isinstance(ex, dict) and "response_snippet" in ex:
                    snippet = ex["response_snippet"]
                    if len(snippet) > MAX_RESPONSE_SNIPPET_CHARS:
                        ex["response_snippet"] = snippet[:MAX_RESPONSE_SNIPPET_CHARS] + "..."

            # Cap at MAX_HTTP_EXAMPLES_PER_BUG
            http_examples = http_examples[:MAX_HTTP_EXAMPLES_PER_BUG]

            # Infer auth_required
            auth_required = bug.get("auth_required")
            if auth_required is None:
                # Infer: if credentials listed or login in endpoint/method → true
                creds = bug.get("auth_credentials_needed", [])
                endpoint = bug.get("endpoint", "").lower()
                method = bug.get("method", "").upper()
                auth_required = (
                    bool(creds)
                    or "login" in endpoint
                    or "auth" in endpoint
                    or ("POST" in method and ("login" in endpoint or "signin" in endpoint))
                )

            # Normalize auth_credentials_needed
            auth_credentials_needed = bug.get("auth_credentials_needed", [])
            if not isinstance(auth_credentials_needed, list):
                auth_credentials_needed = []

            request_params = bug.get("request_params", [])
            if not isinstance(request_params, list):
                request_params = []

            raw_form_fields = bug.get("form_fields", [])
            form_fields = []
            if isinstance(raw_form_fields, list):
                for field in raw_form_fields:
                    if isinstance(field, dict):
                        name = str(field.get("name", "")).strip()
                        if not name:
                            continue
                        form_fields.append({
                            "name": name,
                            "type": str(field.get("type", "?") or "?"),
                            "value": str(field.get("value", "") or "")[:80],
                        })
                    elif isinstance(field, str):
                        name = field.strip()
                        if name:
                            form_fields.append({"name": name, "type": "?", "value": ""})

            response_clues = bug.get("response_clues", [])
            if not isinstance(response_clues, list):
                response_clues = []

            enriched_bug = {
                "id": bug_id,
                "category": bug.get("category", "BAC"),
                "pattern_id": pattern_id,
                "candidate_type": str(bug.get("candidate_type") or "").upper() or "",
                "title": bug.get("title", f"Vulnerability #{i + 1}"),
                "risk_level": risk_level,
                "endpoint": bug.get("endpoint", ""),
                "method": bug.get("method", "GET"),
                "hypothesis": bug.get("hypothesis", ""),
                "exploit_approach": bug.get("exploit_approach", ""),
                "verify_method": bug.get("verify_method", ""),
                "http_examples": http_examples,
                "auth_required": bool(auth_required),
                "auth_credentials_needed": auth_credentials_needed,
                "request_params": request_params,
                "form_fields": form_fields,
                "response_clues": response_clues,
                "confidence": bug.get("confidence", "MEDIUM"),
                "status": "PENDING",
                "PoC": "",
                "attempt_count": 0,
                "debate_rounds": 0,
            }

            if self._is_invalid_endpoint(enriched_bug["endpoint"]):
                print(
                    f"  {DIM}[VULN-HUNTER] Filtered invalid crawl-state endpoint: "
                    f"{enriched_bug['id']} {enriched_bug['method']} {enriched_bug['endpoint']}{RESET}"
                )
                continue

            enriched_bug["http_examples"] = [
                normalize_http_example(
                    ex,
                    endpoint=enriched_bug["endpoint"],
                    method=enriched_bug["method"],
                )
                for ex in enriched_bug.get("http_examples", [])
                if isinstance(ex, dict)
            ][:MAX_HTTP_EXAMPLES_PER_BUG]

            # ── Inject http_examples from raw_endpoints if LLM didn't provide ──
            if not enriched_bug["http_examples"] and raw_endpoints:
                endpoint_path = enriched_bug["endpoint"]
                bug_method = enriched_bug["method"].upper()
                matched_examples = self._match_raw_endpoints(
                    endpoint_path, bug_method, raw_endpoints,
                )
                if matched_examples:
                    enriched_bug["http_examples"] = matched_examples[:MAX_HTTP_EXAMPLES_PER_BUG]

            action_methods = {"POST", "PUT", "PATCH", "DELETE"}
            bug_method_upper = str(enriched_bug.get("method", "GET") or "GET").upper()
            if enriched_bug["http_examples"] and bug_method_upper in action_methods:
                exact_method_examples = [
                    ex for ex in enriched_bug["http_examples"]
                    if isinstance(ex, dict)
                    and str(ex.get("method", "") or "").upper() == bug_method_upper
                ]
                if not exact_method_examples:
                    action_example = self._build_action_discovery_example(enriched_bug, raw_endpoints)
                    if action_example:
                        enriched_bug["candidate_type"] = "ACTION_DISCOVERY"
                        enriched_bug["http_examples"] = [action_example]
                        enriched_bug["requires_probe"] = True
                        enriched_bug["confidence"] = "LOW"
                    else:
                        enriched_bug["http_examples"] = []

            if not enriched_bug["http_examples"]:
                action_example = self._build_action_discovery_example(enriched_bug, raw_endpoints)
                if action_example:
                    enriched_bug["candidate_type"] = "ACTION_DISCOVERY"
                    enriched_bug["http_examples"] = [action_example]
                    enriched_bug["requires_probe"] = True
                    enriched_bug["confidence"] = "LOW"
                    if not enriched_bug.get("confidence"):
                        enriched_bug["confidence"] = "LOW"
                else:
                    print(
                        f"  {DIM}[VULN-HUNTER] Filtered no-evidence candidate: "
                        f"{enriched_bug['id']} {enriched_bug['method']} {enriched_bug['endpoint']}{RESET}"
                    )
                    continue

            provenances = {
                str(ex.get("provenance", "crawl"))
                for ex in enriched_bug.get("http_examples", [])
                if isinstance(ex, dict)
            }
            if "action_discovery" in provenances:
                enriched_bug["evidence_status"] = "ACTION_DISCOVERY"
                enriched_bug["candidate_type"] = "ACTION_DISCOVERY"
                enriched_bug["requires_probe"] = True
                enriched_bug["confidence"] = "LOW"
            elif "active_discovery" in provenances:
                enriched_bug["evidence_status"] = "ACTIVE_DISCOVERY"
                enriched_bug["candidate_type"] = enriched_bug.get("candidate_type") or "EVIDENCE_BACKED"
            else:
                enriched_bug["evidence_status"] = "CRAWL_OBSERVED"
                enriched_bug["candidate_type"] = enriched_bug.get("candidate_type") or "EVIDENCE_BACKED"

            enriched.append(enriched_bug)

        return self._dedupe_and_rank_candidates(enriched, max_bugs=MAX_BUGS)

    @staticmethod
    def _is_invalid_endpoint(endpoint: str) -> bool:
        lower = str(endpoint or "").lower()
        return any(marker in lower for marker in INVALID_ENDPOINT_MARKERS)

    @staticmethod
    def _family_path(path: str) -> str:
        path = str(path or "").split("?", 1)[0].rstrip("/") or "/"
        parts = []
        for segment in path.split("/"):
            if not segment:
                continue
            if re.fullmatch(r"\d+", segment):
                parts.append("{id}")
            else:
                parts.append(segment)
        return "/" + "/".join(parts) if parts else "/"

    @classmethod
    def _candidate_key(cls, bug: dict) -> tuple[str, str]:
        method = str(bug.get("method", "GET") or "GET").upper()
        family = cls._family_path(str(bug.get("endpoint", "") or "")).lower()
        return method, family

    @classmethod
    def _find_candidate(cls, bugs: list[dict], method: str, endpoint: str) -> dict | None:
        key = (str(method or "GET").upper(), cls._family_path(endpoint).lower())
        for bug in bugs:
            if cls._candidate_key(bug) == key:
                return bug
        return None

    @staticmethod
    def _path_tokens(path: str) -> set[str]:
        return {
            token
            for token in re.split(r"[^a-z0-9]+", str(path or "").lower())
            if token and token not in {"api", "rest", "v1", "v2", "id"}
        }

    @staticmethod
    def _response_field_tokens(response: dict) -> set[str]:
        tokens: set[str] = set()
        for key in ("json_keys", "numeric_fields", "id_fields"):
            for field in response.get(key) or []:
                for token in re.split(r"[^a-z0-9]+", str(field).lower()):
                    if token:
                        tokens.add(token)
        snippet = str(response.get("body_snippet", "") or "").lower()
        for token in re.split(r"[^a-z0-9]+", snippet[:1000]):
            if token:
                tokens.add(token)
        return tokens

    @classmethod
    def _route_has_object_reference(cls, family: str, response: dict) -> bool:
        if re.search(r"\{[^}]+\}", cls._family_path(family).lower()):
            return True
        id_fields = response.get("id_fields") or []
        return bool(id_fields)

    @classmethod
    def _route_has_business_signal(cls, path: str, response: dict, request_body: object = None) -> bool:
        tokens = cls._path_tokens(path) | cls._response_field_tokens(response)
        if request_body is not None:
            for token in re.split(r"[^a-z0-9]+", str(request_body).lower()):
                if token:
                    tokens.add(token)
        return bool(tokens & set(BUSINESS_ROUTE_MARKERS)) or bool(tokens & set(ACTION_DISCOVERY_SCHEMA_MARKERS))

    @classmethod
    def _route_has_sensitive_read_signal(cls, path: str, response: dict) -> bool:
        tokens = cls._path_tokens(path) | cls._response_field_tokens(response)
        return bool(tokens & set(SENSITIVE_READ_MARKERS))

    @staticmethod
    def _auth_required_from_endpoint(ep: dict) -> bool:
        session = str(ep.get("auth_session", "") or "").lower()
        if session and session not in {"anonymous", "anon", "guest", "public", "unknown"}:
            return True
        headers = (ep.get("request") or {}).get("headers") or {}
        if isinstance(headers, dict):
            return any(str(name).lower() in {"authorization", "cookie"} for name in headers)
        return False

    @classmethod
    def _request_params_for_route(cls, endpoint: str, response: dict, request_body: object = None) -> list[str]:
        params: list[str] = []
        for match in re.finditer(r"\{([^}]+)\}", endpoint):
            value = match.group(1).strip() or "id"
            if value not in params:
                params.append(value)
        if "{id}" in cls._family_path(endpoint) and "id" not in params:
            params.append("id")
        for field in (response.get("id_fields") or [])[:4]:
            name = str(field).split(".")[-1].strip("[]") or str(field)
            if name and name not in params:
                params.append(name)
        if request_body is not None:
            for token in re.split(r"[^A-Za-z0-9_]+", str(request_body)):
                lower = token.lower()
                if lower in ACTION_DISCOVERY_SCHEMA_MARKERS and token not in params:
                    params.append(token)
        return params[:8]

    @staticmethod
    def _unique_extend(current: list, incoming: list, limit: int | None = None) -> list:
        output = list(current or [])
        seen = {json.dumps(item, ensure_ascii=False, sort_keys=True, default=str) for item in output}
        for item in incoming or []:
            marker = json.dumps(item, ensure_ascii=False, sort_keys=True, default=str)
            if marker in seen:
                continue
            output.append(item)
            seen.add(marker)
            if limit is not None and len(output) >= limit:
                break
        return output

    @classmethod
    def _merge_candidate_details(cls, kept: dict, incoming: dict) -> dict:
        for key, limit in (
            ("request_params", 12),
            ("form_fields", 12),
            ("response_clues", 12),
            ("auth_credentials_needed", 6),
            ("evidence_rules", 8),
        ):
            kept[key] = cls._unique_extend(kept.get(key, []), incoming.get(key, []), limit)

        kept["http_examples"] = cls._unique_extend(
            kept.get("http_examples", []),
            incoming.get("http_examples", []),
            MAX_HTTP_EXAMPLES_PER_BUG,
        )

        for key in ("hypothesis", "exploit_approach", "verify_method", "title"):
            if not kept.get(key) and incoming.get(key):
                kept[key] = incoming[key]

        if incoming.get("auth_required"):
            kept["auth_required"] = True
        return kept

    @classmethod
    def _candidate_quality_tuple(cls, bug: dict) -> tuple[int, int, int, int, int, int]:
        evidence_status = str(bug.get("evidence_status", "") or "").upper()
        candidate_type = str(bug.get("candidate_type", "") or "").upper()
        provenances = {
            str(ex.get("provenance", "") or "").lower()
            for ex in bug.get("http_examples", []) or []
            if isinstance(ex, dict)
        }
        if evidence_status == "CRAWL_OBSERVED" or "crawl" in provenances:
            evidence_score = 5
        elif evidence_status == "ACTIVE_DISCOVERY" or "active_discovery" in provenances:
            evidence_score = 4
        elif candidate_type == "EVIDENCE_BACKED":
            evidence_score = 3
        elif evidence_status == "ACTION_DISCOVERY" or "action_discovery" in provenances:
            evidence_score = 1
        else:
            evidence_score = 0

        method = str(bug.get("method", "GET") or "GET").upper()
        exact_method_examples = sum(
            1
            for ex in bug.get("http_examples", []) or []
            if isinstance(ex, dict) and str(ex.get("method", "") or "").upper() == method
        )
        risk_score = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(
            str(bug.get("risk_level", "") or "").upper(), 0,
        )
        confidence_score = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(
            str(bug.get("confidence", "") or "").upper(), 0,
        )
        example_score = min(len(bug.get("http_examples", []) or []), MAX_HTTP_EXAMPLES_PER_BUG)
        detail_score = sum(bool(bug.get(key)) for key in ("request_params", "form_fields", "response_clues"))
        return evidence_score, exact_method_examples, risk_score, confidence_score, example_score, detail_score

    @classmethod
    def _is_action_discovery_candidate(cls, bug: dict) -> bool:
        candidate_type = str(bug.get("candidate_type", "") or "").upper()
        evidence_status = str(bug.get("evidence_status", "") or "").upper()
        provenances = {
            str(ex.get("provenance", "") or "").lower()
            for ex in bug.get("http_examples", []) or []
            if isinstance(ex, dict)
        }
        return (
            candidate_type == "ACTION_DISCOVERY"
            or evidence_status == "ACTION_DISCOVERY"
            or "action_discovery" in provenances
        )

    @classmethod
    def _dedupe_and_rank_candidates(cls, bugs: list[dict], *, max_bugs: int = MAX_BUGS) -> list[dict]:
        deduped: dict[tuple[str, str], dict] = {}
        for bug in bugs or []:
            if not isinstance(bug, dict):
                continue
            endpoint = str(bug.get("endpoint", "") or "")
            if cls._is_invalid_endpoint(endpoint):
                continue
            key = cls._candidate_key(bug)
            if key not in deduped:
                deduped[key] = bug
                continue
            current = deduped[key]
            if cls._candidate_quality_tuple(bug) > cls._candidate_quality_tuple(current):
                deduped[key] = cls._merge_candidate_details(bug, current)
            else:
                cls._merge_candidate_details(current, bug)

        ranked = sorted(
            deduped.values(),
            key=lambda item: cls._candidate_quality_tuple(item),
            reverse=True,
        )
        output: list[dict] = []
        action_count = 0
        for bug in ranked:
            if cls._is_action_discovery_candidate(bug):
                if action_count >= MAX_ACTION_DISCOVERY_BUGS:
                    print(
                        f"  {DIM}[VULN-HUNTER] Filtered extra ACTION_DISCOVERY candidate: "
                        f"{bug.get('id', '?')} {bug.get('method', 'GET')} {bug.get('endpoint', '')}{RESET}"
                    )
                    continue
                action_count += 1
            output.append(bug)
            if len(output) >= max_bugs:
                break
        return output

    @classmethod
    def _candidate_exists(cls, bugs: list[dict], method: str, endpoint: str) -> bool:
        return cls._find_candidate(bugs, method, endpoint) is not None

    def _collect_api_hints(self) -> list[dict]:
        payload = self._raw_payload or {}
        hints: list[dict] = []
        anonymous = payload.get("anonymous") or {}
        for hint in anonymous.get("api_hints") or []:
            if isinstance(hint, dict):
                hints.append({**hint, "context": "anonymous"})
        for session in payload.get("authenticated", []) or []:
            if not isinstance(session, dict):
                continue
            data = session.get("data") or {}
            for hint in data.get("api_hints") or []:
                if isinstance(hint, dict):
                    hints.append({**hint, "context": f"auth:{session.get('label', 'auth')}"})
        return hints

    @staticmethod
    def _example_from_hint(hint: dict, raw_endpoints: list[dict]) -> dict:
        path = str(hint.get("path", "") or "")
        method = str(hint.get("method", "GET") or "GET").upper()
        best = None
        best_score = -1
        hint_tokens = {t for t in re.split(r"[^a-z0-9]+", path.lower()) if t and t not in {"id", "bid"}}
        for ep in raw_endpoints or []:
            ep_path = str(ep.get("path", "") or "")
            ep_tokens = {t for t in re.split(r"[^a-z0-9]+", ep_path.lower()) if t}
            score = len(hint_tokens & ep_tokens)
            if ep.get("auth_session") != "anonymous":
                score += 1
            if score > best_score:
                best = ep
                best_score = score
        return {
            **normalize_http_example({
                "method": best.get("method", "GET") if isinstance(best, dict) else "GET",
                "path": best.get("path", "") if isinstance(best, dict) else "",
                "status": best.get("status", 0) if isinstance(best, dict) else 0,
                "request_body": (best.get("request") or {}).get("body") if isinstance(best, dict) else None,
                "response_snippet": (best.get("response") or {}).get("body_snippet", "") if isinstance(best, dict) else "",
                "content_type": (best.get("response") or {}).get("headers", {}).get("content-type", "") if isinstance(best, dict) else "",
                "auth_session": best.get("auth_session", "anonymous") if isinstance(best, dict) else "unknown",
                "provenance": "action_discovery",
                "discovery": {
                "candidate_endpoint": path,
                "candidate_method": method,
                "basis": "static_js_api_hint",
                "source": hint.get("source", ""),
                "reason": hint.get("reason", ""),
                "basis_path": best.get("path", "") if isinstance(best, dict) else "",
                },
            }, endpoint=path, method=method),
        }

    @staticmethod
    def _next_bug_id(bugs: list[dict]) -> str:
        max_id = 0
        for bug in bugs:
            match = re.search(r"BUG-(\d+)", str(bug.get("id", "")))
            if match:
                max_id = max(max_id, int(match.group(1)))
        return f"BUG-{max_id + 1:03d}"

    def _append_seed(
        self,
        bugs: list[dict],
        *,
        category: str,
        pattern_id: str,
        title: str,
        endpoint: str,
        method: str,
        hypothesis: str,
        exploit_approach: str,
        verify_method: str,
        request_params: list[str] | None,
        response_clues: list[str] | None,
        auth_required: bool,
        confidence: str,
        candidate_type: str,
        evidence_status: str,
        http_examples: list[dict],
    ) -> None:
        method = method.upper()
        if self._is_invalid_endpoint(endpoint):
            return
        seed = {
            "id": self._next_bug_id(bugs),
            "category": category,
            "pattern_id": pattern_id,
            "candidate_type": candidate_type,
            "evidence_status": evidence_status,
            "title": title,
            "risk_level": RISK_LEVEL_MAP.get(pattern_id, "MEDIUM"),
            "endpoint": endpoint,
            "method": method,
            "hypothesis": hypothesis,
            "exploit_approach": exploit_approach,
            "verify_method": verify_method,
            "http_examples": http_examples[:MAX_HTTP_EXAMPLES_PER_BUG],
            "auth_required": auth_required,
            "auth_credentials_needed": ["authenticated_user"] if auth_required else [],
            "request_params": request_params or [],
            "form_fields": [],
            "response_clues": response_clues or [],
            "confidence": confidence,
            "requires_probe": candidate_type == "ACTION_DISCOVERY",
            "status": "PENDING",
            "PoC": "",
            "attempt_count": 0,
            "debate_rounds": 0,
        }
        existing = self._find_candidate(bugs, method, endpoint)
        if existing:
            seed_better = self._candidate_quality_tuple(seed) > self._candidate_quality_tuple(existing)
            if seed_better:
                kept_id = existing.get("id")
                merged = self._merge_candidate_details(seed, existing)
                existing.update({k: v for k, v in merged.items() if k != "id"})
                existing["id"] = kept_id or merged["id"]
            else:
                self._merge_candidate_details(existing, seed)
            return
        bugs.append(seed)

    def _add_deterministic_candidates(self, bugs: list[dict], raw_endpoints: list[dict]) -> list[dict]:
        """Add generic BAC/BLF seeds from observed route semantics.

        Keep this layer deliberately target-agnostic. It should promote signals
        such as object identifiers, authenticated sensitive reads, mutable
        business fields, and observed state-changing methods without naming a
        training lab's exact endpoints.
        """
        if not raw_endpoints:
            return bugs

        for ep in raw_endpoints:
            method = str(ep.get("method", "GET") or "GET").upper()
            path = str(ep.get("path", "") or "")
            try:
                status = int(ep.get("status") or 0)
            except (TypeError, ValueError):
                status = 0
            if self._is_invalid_endpoint(path) or status >= 500:
                continue
            family = self._family_path(path)
            response = ep.get("response") or {}
            json_keys = response.get("json_keys") or []
            numeric_fields = response.get("numeric_fields") or []
            id_fields = response.get("id_fields") or []
            request_body = (ep.get("request") or {}).get("body")
            auth_required = self._auth_required_from_endpoint(ep)
            route_has_object_ref = self._route_has_object_reference(family, response)
            route_has_business_signal = self._route_has_business_signal(path, response, request_body)
            route_has_sensitive_signal = self._route_has_sensitive_read_signal(path, response)
            request_params = self._request_params_for_route(family, response, request_body)
            example = normalize_http_example({
                "method": method,
                "path": path,
                "status": status,
                "request_body": request_body,
                "response_snippet": response.get("body_snippet", ""),
                "content_type": response.get("headers", {}).get("content-type", ""),
                "auth_session": ep.get("auth_session", "anonymous"),
                "provenance": ep.get("provenance", "crawl"),
                "discovery": ep.get("discovery", {}),
            }, endpoint=path, method=method)

            if method == "GET" and 200 <= status < 300 and route_has_object_ref and auth_required:
                self._append_seed(
                    bugs,
                    category="BAC",
                    pattern_id="BAC-03",
                    title="Direct object access surface observed",
                    endpoint=family,
                    method="GET",
                    hypothesis="Route co object identifier va duoc quan sat trong authenticated traffic. Can verify server co rang buoc object ownership theo session hien tai hay khong.",
                    exploit_approach="Dung authenticated session hien co goi baseline cho object hop le, sau do thu object id khac cung route family va so sanh status/body.",
                    verify_method="Neu session hien tai doc duoc object khong thuoc minh hoac response chua owner/user/account khac thi BAC/IDOR.",
                    request_params=request_params,
                    response_clues=list(json_keys[:8]) + list(id_fields[:6]),
                    auth_required=auth_required,
                    confidence="HIGH" if id_fields else "MEDIUM",
                    candidate_type="EVIDENCE_BACKED",
                    evidence_status=ep.get("provenance", "crawl").upper(),
                    http_examples=[example],
                )

            if method == "GET" and 200 <= status < 300 and route_has_sensitive_signal and auth_required:
                self._append_seed(
                    bugs,
                    category="BAC",
                    pattern_id="BAC-04",
                    title="Authenticated sensitive read surface observed",
                    endpoint=family,
                    method="GET",
                    hypothesis="Authenticated route tra ve du lieu nhay cam nhu user/account/order/role/object metadata. Can verify role/ownership filtering.",
                    exploit_approach="So sanh response giua anonymous va authenticated user thuong; neu co object id thi thu bien doi id/filter theo route family.",
                    verify_method="Neu user thuong doc duoc privileged data, cross-user data, role/permission metadata khong nen thay thi BAC.",
                    request_params=request_params,
                    response_clues=list(json_keys[:8]) + list(id_fields[:6]),
                    auth_required=auth_required,
                    confidence="MEDIUM",
                    candidate_type="EVIDENCE_BACKED",
                    evidence_status=ep.get("provenance", "crawl").upper(),
                    http_examples=[example],
                )

            if method in {"POST", "PUT", "PATCH", "DELETE"} and 200 <= status < 400 and route_has_business_signal:
                has_numeric_or_mutable = bool(numeric_fields) or any(
                    marker in str(request_body or "").lower()
                    for marker in ACTION_DISCOVERY_SCHEMA_MARKERS
                )
                self._append_seed(
                    bugs,
                    category="BLF",
                    pattern_id="BLF-07" if has_numeric_or_mutable else "BLF-03",
                    title="Observed state-changing business route",
                    endpoint=family,
                    method=method,
                    hypothesis="Route state-changing nam tren workflow/value surface. Can verify server-side rule enforcement, ownership, va before/after state.",
                    exploit_approach="Dung request observed lam baseline, bien doi id hoac mutable fields mot cach nho va co rollback/verify, sau do so sanh response/state.",
                    verify_method="Neu server chap nhan state transition trai rule, gia tri bat thuong, hoac object khong thuoc session thi BLF/BAC.",
                    request_params=request_params,
                    response_clues=list(json_keys[:8]) + list(numeric_fields[:6]) + list(id_fields[:4]),
                    auth_required=auth_required,
                    confidence="HIGH" if method in {"PUT", "PATCH", "DELETE"} else "MEDIUM",
                    candidate_type="EVIDENCE_BACKED",
                    evidence_status=ep.get("provenance", "crawl").upper(),
                    http_examples=[example],
                )

        for hint in self._collect_api_hints():
            method = str(hint.get("method", "GET") or "GET").upper()
            path = str(hint.get("path", "") or "")
            if self._is_invalid_endpoint(path):
                continue
            if method not in {"POST", "PUT", "PATCH", "DELETE"}:
                continue
            if not self._is_allowed_action_discovery_endpoint(path):
                continue
            hint_example = self._example_from_hint(hint, raw_endpoints)
            if not hint_example:
                continue
            self._append_seed(
                bugs,
                category="BLF",
                pattern_id="BLF-03",
                title="State-changing workflow route discovered from static/API hints",
                endpoint=self._family_path(path),
                method=method,
                hypothesis="Static/API hint cho thay route state-changing gan workflow business. Can probe nhe truoc khi coi la bug.",
                exploit_approach="Xac minh route ton tai voi authenticated context neu co, dung body/schema observed gan do, sau do so sanh before/after state.",
                verify_method="Chi xac nhan khi probe cho thay state transition trai rule, ownership bypass, hoac mutable value khong duoc enforce.",
                request_params=self._request_params_for_route(path, {}, None),
                response_clues=["static_or_guided_api_hint", hint.get("reason", "")],
                auth_required=True,
                confidence="LOW",
                candidate_type="ACTION_DISCOVERY",
                evidence_status="ACTION_DISCOVERY",
                http_examples=[hint_example],
            )

        return self._dedupe_and_rank_candidates(bugs, max_bugs=MAX_BUGS)

    def _write_bugs(self, bugs: list[dict]) -> str:
        """Write bugs list to risk-bug.json in run_dir and print summary."""
        output_path = os.path.join(self.run_dir, "risk-bug.json")
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(bugs, f, ensure_ascii=False, indent=2)
            print(f"{GREEN}[VULN-HUNTER] Da ghi risk-bug.json: {output_path} "
                  f"({len(bugs)} bugs){RESET}")
        except Exception as e:
            print(f"{RED}[VULN-HUNTER] Failed to write risk-bug.json: {e}{RESET}")

        # Print summary per bug
        for bug in bugs:
            n_examples = len(bug.get("http_examples", []))
            auth = "auth" if bug.get("auth_required") else "anon"
            creds = bug.get("auth_credentials_needed", [])
            cred_str = f" creds={', '.join(creds)}" if creds else ""
            print(f"  {DIM}[{bug['risk_level']:8s}] {bug['id']} | {bug['endpoint']} | "
                  f"{bug['method']} | {auth}{cred_str} | {n_examples} http_examples{RESET}")

        return output_path

    def _load_raw_endpoints(self) -> list[dict]:
        """Load raw_endpoints from crawl_raw.json if available."""
        raw_path = os.path.join(self.run_dir, "crawl_raw.json")
        try:
            if not os.path.isfile(raw_path):
                return []
            with open(raw_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._raw_payload = data
            endpoints = data.get("raw_endpoints", [])
            if isinstance(endpoints, list):
                return endpoints
        except Exception as e:
            print(f"{YELLOW}[VULN-HUNTER] Could not load crawl_raw.json: {e}{RESET}")
        return []

    def _load_business_flows(self) -> list[dict]:
        """Load business flows from business_flows.json for flow-aware BLF generation."""
        flows_path = os.path.join(self.run_dir, "business_flows.json")
        try:
            if not os.path.isfile(flows_path):
                return []
            with open(flows_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            flows = data.get("flows", [])
            if isinstance(flows, list):
                return [f for f in flows if isinstance(f, dict)]
        except Exception as e:
            print(f"{YELLOW}[VULN-HUNTER] Could not load business_flows.json: {e}{RESET}")
        return []

    @staticmethod
    def _match_raw_endpoints(
        endpoint_path: str,
        bug_method: str,
        raw_endpoints: list[dict],
    ) -> list[dict]:
        """Find raw endpoint examples that match a bug's endpoint path.

        Matching strategy:
        1. Exact path match
        2. Template match (e.g. /api/Users/{id} matches /api/Users/1)
        3. Prefix match (e.g. /api/Products matches /api/Products/search)

        Returns list of http_example dicts suitable for risk-bug.json.
        """
        if not endpoint_path or not raw_endpoints:
            return []

        # Normalize endpoint: remove template vars like {id}, {{id}}
        clean_endpoint = re.sub(r'\{+\w+\}+', '', endpoint_path).rstrip('/')
        if not clean_endpoint:
            clean_endpoint = endpoint_path.split('/')[1] if '/' in endpoint_path else endpoint_path

        matched = []
        for ep in raw_endpoints:
            ep_path = ep.get("path", "")
            if VulnHunterAgent._is_invalid_endpoint(ep_path):
                continue
            ep_method = ep.get("method", "GET")
            ep_status = ep.get("status", 0)
            bug_method_upper = str(bug_method or "GET").upper()
            ep_method_upper = str(ep_method or "GET").upper()

            # Skip non-live endpoints
            if ep_status >= 404:
                continue
            if ep_method_upper != bug_method_upper:
                continue

            # Match logic
            is_match = False
            # 1. Exact match
            if ep_path.rstrip('/') == endpoint_path.rstrip('/'):
                is_match = True
            # 2. Path starts with the clean endpoint (prefix)
            elif ep_path.startswith(clean_endpoint):
                is_match = True
            # 3. Bug endpoint is a template and raw path matches the base
            elif clean_endpoint and ep_path.startswith(clean_endpoint.rstrip('/')):
                is_match = True

            if is_match:
                example = normalize_http_example({
                    "method": ep_method,
                    "path": ep_path,
                    "status": ep_status,
                    "request_body": ep.get("request", {}).get("body"),
                    "response_snippet": ep.get("response", {}).get("body_snippet", ""),
                    "content_type": ep.get("response", {}).get("headers", {}).get("content-type", ""),
                    "auth_session": ep.get("auth_session", "anonymous"),
                    "provenance": ep.get("provenance", "crawl"),
                    "discovery": ep.get("discovery", {}),
                }, endpoint=endpoint_path, method=bug_method)
                matched.append(example)

        return matched

    @staticmethod
    def _is_allowed_action_discovery_endpoint(endpoint: str) -> bool:
        endpoint_lower = str(endpoint or "").lower().split("?", 1)[0]
        if any(marker in endpoint_lower for marker in ACTION_DISCOVERY_BLOCKED_PATH_MARKERS):
            return False
        return any(marker in endpoint_lower for marker in ACTION_DISCOVERY_ALLOWED_PATH_MARKERS)

    @staticmethod
    def _build_action_discovery_example(bug: dict, raw_endpoints: list[dict]) -> dict | None:
        """Keep state-changing BAC/BLF candidates when grounded in nearby observed schema."""
        method = str(bug.get("method", "GET") or "GET").upper()
        if method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return None
        endpoint = str(bug.get("endpoint", "") or "").strip()
        if not endpoint or not raw_endpoints:
            return None

        endpoint_base = endpoint.rstrip("/")
        endpoint_lower = endpoint_base.lower()
        if not VulnHunterAgent._is_allowed_action_discovery_endpoint(endpoint_lower):
            return None

        best: dict | None = None
        best_score = -1
        for ep in raw_endpoints:
            ep_path = str(ep.get("path", "") or "")
            ep_lower = ep_path.lower().rstrip("/")
            if not ep_lower:
                continue
            try:
                status = int(ep.get("status") or 0)
            except (TypeError, ValueError):
                status = 0
            if status >= 404 or VulnHunterAgent._is_invalid_endpoint(ep_lower):
                continue
            score = 0
            ep_family = VulnHunterAgent._family_path(ep_lower)
            endpoint_family = VulnHunterAgent._family_path(endpoint_lower)
            family_match = ep_family == endpoint_family
            if ep_lower == endpoint_lower:
                score += 6
            elif family_match:
                score += 5
            elif endpoint_lower.startswith(ep_lower) or ep_lower.startswith(endpoint_lower):
                score += 4
            else:
                ep_tokens = {t for t in re.split(r"[^a-z0-9]+", ep_lower) if t}
                bug_tokens = {t for t in re.split(r"[^a-z0-9]+", endpoint_lower) if t}
                score += len(ep_tokens & bug_tokens)

            response = ep.get("response") or {}
            schema_blob = " ".join([
                str(response.get("body_snippet", "") or ""),
                " ".join(str(k) for k in response.get("json_keys", []) or []),
                " ".join(str(k) for k in response.get("numeric_fields", []) or []),
                " ".join(str(k) for k in response.get("id_fields", []) or []),
                str((ep.get("request") or {}).get("body") or ""),
            ]).lower()
            has_schema_signal = any(k in schema_blob for k in ACTION_DISCOVERY_SCHEMA_MARKERS)
            if has_schema_signal:
                score += 3
            elif not family_match:
                continue
            if ep.get("provenance") == "active_discovery":
                score -= 1
            if score > best_score:
                best = ep
                best_score = score

        if not best or best_score < 6:
            return None

        return normalize_http_example({
            "method": best.get("method", "GET"),
            "path": best.get("path", ""),
            "status": best.get("status", 0),
            "request_body": best.get("request", {}).get("body"),
            "response_snippet": best.get("response", {}).get("body_snippet", ""),
            "content_type": best.get("response", {}).get("headers", {}).get("content-type", ""),
            "auth_session": best.get("auth_session", "anonymous"),
            "provenance": "action_discovery",
            "discovery": {
                "candidate_endpoint": endpoint,
                "candidate_method": method,
                "basis": "state-changing candidate grounded in nearby observed endpoint/schema",
                "basis_path": best.get("path", ""),
            },
        }, endpoint=endpoint, method=method)

    @staticmethod
    def _filter_challenge_metadata_bugs(bugs: list[dict]) -> list[dict]:
        """Filter out bugs that are purely based on metadata/catalog endpoints."""
        METADATA_ENDPOINTS = {
            "/api/challenges", "/rest/challenges", "/challenges",
            "/api/schema", "/schema", "/openapi.json", "/swagger.json",
            "/api/version", "/version", "/health", "/status",
            "/api/configuration", "/configuration",
        }

        METADATA_KEYWORDS = (
            "metadata", "catalog", "schema", "version", "configuration",
            "health check", "status page", "challenge name", "challenge text",
            "challenge list",
        )

        filtered = []
        removed_count = 0
        for bug in bugs:
            endpoint = bug.get("endpoint", "").strip()
            hypothesis = str(bug.get("hypothesis", "")).lower()
            title = str(bug.get("title", "")).lower()

            # Check if this is a pure metadata bug
            is_metadata = False

            # 1. Endpoint is a known metadata-only endpoint
            if endpoint.lower() in {item.lower() for item in METADATA_ENDPOINTS}:
                # Check if the hypothesis ALSO mentions metadata
                if any(kw in hypothesis or kw in title for kw in METADATA_KEYWORDS):
                    is_metadata = True

            # 2. Hypothesis is purely about metadata text, not a real app control
            if not is_metadata and "metadata" in hypothesis and not any(
                kw in hypothesis
                for kw in ("ownership", "permission", "role", "state", "amount", "price", "balance", "user data")
            ):
                is_metadata = True

            if is_metadata:
                removed_count += 1
                print(f"  {DIM}[VULN-HUNTER] Filtered: {bug.get('id', '?')} — "
                      f"{bug.get('title', '?')} (metadata-only){RESET}")
            else:
                filtered.append(bug)

        if removed_count > 0:
            print(f"{YELLOW}[VULN-HUNTER] Removed {removed_count} metadata-only bug(s){RESET}")

        return filtered


# ═══════════════════════════════════════════════════════════════════════
# STANDALONE CLI
# ═══════════════════════════════════════════════════════════════════════

def main():
    """Quick standalone test: python agents/vuln_hunter_agent.py <run_dir> <target_url>"""
    if len(sys.argv) < 3:
        print(f"Usage: python {sys.argv[0]} <run_dir> <target_url>")
        print(f"Example: python {sys.argv[0]} ./workspace/target_com_20250101_120000 https://target.com/")
        sys.exit(1)

    run_dir = sys.argv[1]
    target_url = sys.argv[2]

    recon_md = os.path.join(run_dir, "recon.md")
    crawl_data = os.path.join(run_dir, "crawl_data.txt")

    agent = VulnHunterAgent(
        run_dir=run_dir,
        target_url=target_url,
        recon_md_path=recon_md,
        crawl_data_path=crawl_data,
    )

    bugs = agent.run()
    print(f"\n{GREEN}=== VulnHunter Complete: {len(bugs)} bugs identified ==={RESET}")
    for bug in bugs:
        print(f"  [{bug['risk_level']}] {bug['id']} — {bug['title']}")


if __name__ == "__main__":
    main()
