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
MAX_BUGS = 5
MAX_HTTP_EXAMPLES_PER_BUG = 2
MAX_RESPONSE_SNIPPET_CHARS = 200
MAX_LLM_RETRIES = 3

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
- Uu tien RECALL cao hon PRECISION.
- Neu mot route/endpoint co dau hieu dang nghi thi CU DUA VAO OUTPUT.
- False positive duoc CHAP NHAN.
- Red/Blue/Exec se la cac thanh phan xac minh sau. Ban KHONG can confirm 100%.

=== KIEN THUC VE CAC PATTERN ===
{playbook}

=== ENRICHED RECON DOSSIER ===
{recon_summary}

=== CACH LAM VIEC BAT BUOC ===
1. Doc toan bo recon.md enriched, dac biet cac phan:
   - Endpoint Inventory
   - Endpoint Details
   - Structured Route Families
   - Endpoint Dossiers
   - Candidate BAC/BLF Signals
1b. Neu narrative o phan tren mau thuan voi Structured Route Families / Endpoint Dossiers,
    LUON uu tien section cau truc o phia duoi. Endpoint trong output phai dung dung route family
    da xuat hien trong Structured Route Families hoac Endpoint Dossiers.
2. Tim CAC DIEM CO THE CO BUG dua tren:
   - route dung direct object identifiers
   - admin/management endpoints
   - mutable numeric fields: qty, amount, price, stock, balance
   - profile/order/cart/checkout/transfer workflow
   - role/user_id/client-controlled identity hints
3. Khi nghi ngo, cu dua bug candidate vao output. Khong can raw HTML/JSON exact dump.
4. Moi bug candidate phai noi ro vi sao route do dang nghi va can verify nhu the nao.

=== YEU CAU QUAN TRONG ===
Moi bug candidate nen co:
- endpoint / route family bi nghi ngo
- method neu suy ra duoc
- hypothesis: tai sao co the co bug
- exploit_approach: cach thu nghiem
- verify_method: dau hieu can kiem tra boi cac agent sau
- request_params / form_fields / response_clues neu recon co nhac toi
- confidence: LOW / MEDIUM / HIGH

=== OUTPUT FORMAT ===
CHI TRA VE JSON array hop le, toi da {max_bugs} phan tu. Khong viet markdown,
khong viet giai thich, khong viet attack surface summary ngoai JSON.
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
"""


# ═══════════════════════════════════════════════════════════════════════
# USER PROMPT BUILDER
# ═══════════════════════════════════════════════════════════════════════

def _build_user_prompt(recon_content: str, playbook: str) -> str:
    return VULNHUNTER_SYSTEM_PROMPT.format(
        playbook=playbook,
        recon_summary=recon_content,
        max_bugs=MAX_BUGS,
    )


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

        # ── 2. Call LLM ──
        print(f"{YELLOW}[VULN-HUNTER] Goi LLM phan tich... (model={MODEL}, max_tokens=16384){RESET}")
        raw_json = self._call_llm(recon_content)
        if not raw_json.strip():
            print(f"{YELLOW}[VULN-HUNTER] Khong nhan duoc output hop le tu LLM sau {MAX_LLM_RETRIES} lan thu{RESET}")
            self._write_bugs([])
            return []

        # ── 3. Parse + validate ──
        bugs = self._parse_bugs(raw_json)
        print(f"{GREEN}[VULN-HUNTER] Tim thay {len(bugs)} vulnerability hypotheses{RESET}")

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
            {"role": "system", "content": _build_user_prompt(recon_content, self.playbook)},
            {"role": "user", "content": (
                "Doc TOAN BO recon.md enriched va tra ve CAC BUG CANDIDATE co the co BAC/BLF. "
                "Uu tien recall, false positive chap nhan duoc. "
                "Khong viet markdown, khong giai thich ngoai JSON. "
                "Output phai bat dau bang '[' va ket thuc bang ']'. "
                "Dung cac route dossiers va candidate signals trong recon de suy ra bug."
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

    def _parse_bugs(self, raw_text: str) -> list[dict]:
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
        for i, bug in enumerate(bugs[:MAX_BUGS]):
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
            enriched.append(enriched_bug)

        # Sort by risk_level severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        enriched.sort(key=lambda b: severity_order.get(b["risk_level"], 3))

        return enriched

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
