"""
RedTeamAgent — Module Red Team cho MARL.

Red = Chien luoc gia: phan tich recon, viet attack workflow, gui Blue review.
Routing do ManageAgent quyet dinh dua tren noi dung response (khong can tag).

Usage (tu manage_agent.py):
    red = RedTeamAgent(target_url="...", recon_context="...")
    text = red.respond(conversation)
"""

import os
import re
import sys
from pathlib import Path

from openai import OpenAI

# ── Dam bao project root tren sys.path ──
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from shared.utils import truncate
from knowledge.bac_blf_playbook import get_playbook_text

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / ".env")




# ═══════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "gho_token")
SERVER_URL = os.getenv("MARL_SERVER_URL", "http://127.0.0.1:5000/v1")
MODEL = os.getenv("MARL_RED_MODEL", "ollama/gemma4:31b-cloud")

# Colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Limits
MAX_MSG_CHARS = 6000    # Truncate message cu


# ═══════════════════════════════════════════════════════════════
# SYSTEM PROMPT — Red = Chien luoc gia
# ═══════════════════════════════════════════════════════════════

RED_PROMPT = """\
Ban la Senior Attack Strategist cho BAC/BLF.
Nhiem vu duy nhat: doc BUG DOSSIER hien tai va viet mot strategy ngan, co the dua thang cho Exec chay.
Ban KHONG dung tool, KHONG viet curl/code, KHONG viet review dai.

=== TARGET ===
{target_url}

=== RECON DATA ===
{recon_context}

=== ATTACK PATTERN KNOWLEDGE BASE ===
{playbook}

=== NGUYEN TAC ===
- BUG DOSSIER la source of truth. Chi tap trung 1 bug hien tai.
- Neu co `AUTHORIZED USER CREDENTIALS` trong context, CHI duoc dung dung cac credential do.
- Khong duoc tu them credential noi tieng cua lab/demo nhu wiener/carlos/admin/administrator neu khong xuat hien trong dossier hoac user prompt.
- Auth evidence co the la cookie, Playwright storage_state, hoac localStorage/JWT token. Neu co `AUTH_CONTEXT_AVAILABLE`,
  viet strategy dung session/token da co, khong bat buoc login lai va khong hardcode login path cua lab.
- Neu bug can auth nhung `Auth evidence` noi khong co authenticated recon/session verified, ghi `NEEDS_CONTEXT` thay vi viet strategy khai thac.
- Don gian truoc: baseline -> probe -> verify. Khong them CSRF/state-changing/concurrency neu khong phuc vu core bug.
- BAC/IDOR read-only: phai chung minh object ownership/cross-user access. Public collection leak UserId/comment
  ma khong chung minh ownership bypass chi la PARTIAL/INFO_EXPOSURE_ONLY.
- BLF/input validation: test tung bien the it nhat, sau moi action phai doc lai state/message de verify.
- Neu endpoint/param/context thieu that su, ghi `NEEDS_CONTEXT` va noi dung thieu, khong phong dai plan.
- Strategy toi da 500 tu. Phai co EXECUTION GUIDE voi cac buoc cu the de Exec (tool-loop) co the thuc hien adaptive.
- ANTI-OVERFITTING: khong hardcode endpoint/marker cua mot lab. Endpoint, marker, account, payload phai den tu dossier/recon/current conversation.
- MINIMUM SUFFICIENT PROOF: chi dat dieu kien thanh cong toi thieu de chung minh hypothesis, khong bat endpoint/tac dong phu.
- BAC vertical/admin: user thuong/guest phai thay control/admin API quyen cao that. Status 200, generic Admin,
  hoac metadata/catalog marker khong du.
- IDOR/BAC horizontal: user A/guest doc duoc object/data cu the cua user B la EXPLOITED.
- BLF/stateful: thao tung duoc state/gia/balance/cart/order theo huong trai logic la EXPLOITED, phai co
  before/after hoac non-zero delta.

=== FORMAT BAT BUOC ===
=== CHIEN LUOC ===
Loai: <BAC|BLF>
Pattern: <pattern_id neu co>
Muc tieu: <1 cau>
Can cu dossier:
- <endpoint/param/auth/marker 1>
- <endpoint/param/auth/marker 2>

Buoc 1: <baseline/discovery ngan>
  Method: <GET/POST/...> URL: <endpoint that>
  Params: <param/value hoac none>
  Expect: <raw evidence mong doi>
Buoc 2: <probe/action ngan>
  Method: <...> URL: <...>
  Params: <...>
  Expect: <...>
Buoc 3 (VERIFY): <doc lai state/response de xac minh>
  Expect: <minimum sufficient proof: marker/status/delta cu the; neu khong co thi FAILED/PARTIAL>
=== KET THUC CHIEN LUOC ===

=== EXECUTION GUIDE ===
Approach: <api_first | browser_first | mixed>
  (api_first: endpoint tra JSON/REST, Exec dung curl/fetch.
   browser_first: SPA/JS-heavy, Exec can browser render.
   mixed: login qua API, verify qua browser hoac nguoc lai.)

Auth setup: <da co session/token | can login truoc | anonymous>
  Login endpoint: <path neu can login>
  Auth mechanism: <jwt_bearer | cookie_session | unknown>

Steps:
  1. <Baseline>: <method> <endpoint> -> expect <marker/status>
  2. <Probe/Action>: <method> <endpoint> params=<...> -> expect <change/marker>
  3. <Verify>: <method> <endpoint> -> expect <minimum proof: specific marker/delta/status>

Fallback neu step chinh fail:
  - Neu endpoint tra 404: thu <alternative endpoint>
  - Neu endpoint tra 403: thu <different auth approach>
  - Neu response khac expect: <cach xac nhan alternative>

Evidence files can luu: baseline.resp.txt, probe.resp.txt, result.json

Success condition: <minimum sufficient proof — 1 cau ro rang>
Partial condition: <khi nao la PARTIAL — 1 cau>
=== END EXECUTION GUIDE ===

=== KHONG DUOC ===
- Khong viet script/curl/code trong strategy. Exec se tu chon tools.
- Khong them endpoint/response/status tu tuong tuong.
- Khong yeu cau verify phu lam success condition nang hon hypothesis.
- Khong lap lai strategy cu neu conversation da cho thay fail; sua dung loi fail.
- Khong mo rong sang bug khac, chaining, brute force, DDoS, SQLi/XSS/SSRF.
Viet xong strategy thi dung."""


# ═══════════════════════════════════════════════════════════════
# RED TEAM AGENT CLASS
# ═══════════════════════════════════════════════════════════════

class RedTeamAgent:
    """Red Team chiến lược gia — phân tích recon, viết attack workflow."""

    def __init__(
        self,
        target_url: str,
        recon_context: str,
        *,
        model: str | None = None,
        memory_store=None,
    ):
        """
        Args:
            target_url: URL cua target website.
            recon_context: Recon data (recon.md content).
            model: LLM model override. Default: env MARL_RED_MODEL or gpt-5-mini.
            memory_store: Optional MemoryStore instance for scratchpad + RAG.
        """
        self.target_url = target_url
        self.recon_context = recon_context
        self.model = model or MODEL
        self.client = OpenAI(api_key=GITHUB_TOKEN, base_url=SERVER_URL)
        self.memory_store = memory_store

        # System prompt — bake target_url + recon_context + playbook vao
        self.base_system_prompt = RED_PROMPT.format(
            target_url=self.target_url,
            recon_context=truncate(self.recon_context),
            playbook=get_playbook_text(),
        )
        self.system_prompt = self.base_system_prompt

        # Register task in memory if available
        if self.memory_store:
            self.memory_store.register_task(
                "red_init", "red", "INIT",
                f"Red Team khởi tạo cho {target_url}",
            )

        print(f"\n{RED}{BOLD}[RED-TEAM] Khoi tao — model={self.model}{RESET}")
        print(f"{RED}[RED-TEAM] Target: {self.target_url}{RESET}")
        print(f"{RED}[RED-TEAM] Recon: {len(self.recon_context)} chars{RESET}")

    # ─── Public API ──────────────────────────────────────────────

    def respond(self, conversation: list[dict]) -> str:
        """Xu ly 1 turn cua Red Team.

        Doc conversation, goi LLM 1 turn.
        Manager se doc noi dung va quyet dinh routing (khong can tag).

        Args:
            conversation: Shared debate conversation
                          (list of {"speaker": ..., "content": ...}).

        Returns:
            Raw Red Team response text.
        """
        messages = self._build_messages(conversation)
        response_text = self._think(messages)
        if self.memory_store:
            self._save_to_scratchpad(response_text)
        return response_text

    # ─── Internal: LLM call ──────────────────────────────────────

    def _save_to_scratchpad(self, response_text: str) -> None:
        """Extract key info from Red's response and persist to scratchpad."""
        if not self.memory_store:
            return

        self.memory_store.scratchpad_write("red", "last_strategy", response_text[:800])

        endpoints = re.findall(
            r'(?:https?://[^\s<>"]+|/[a-zA-Z0-9/_\-?=&%]+)', response_text
        )
        if endpoints:
            self.memory_store.scratchpad_write(
                "red", "mentioned_endpoints", ", ".join(endpoints[:10])
            )

        lower = response_text.lower()
        if any(kw in lower for kw in ("=== verdict ===", "ket qua: success", "ket qua: fail")):
            self.memory_store.scratchpad_write("red", "final_verdict", response_text[:500])
            self.memory_store.add_finding(
                "note", "red_verdict", response_text[:300], agent="red"
            )

        for pattern in ["bac-", "blf-", "idor", "horizontal", "vertical", "price", "quantity"]:
            if pattern in lower:
                self.memory_store.scratchpad_write("red", "attack_pattern", pattern.upper())
                break

    def _think(self, messages: list[dict]) -> str:
        """Goi LLM Red Team 1 turn."""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.4,
                max_tokens=1800,
            )
            text = response.choices[0].message.content or ""
            print(f"{RED}[RED-TEAM] Response ({len(text)} chars){RESET}")
            if not text.strip():
                return "[LLM Error: Empty response from RedTeamAgent]"
            return text
        except Exception as e:
            print(f"{RED}[RED-TEAM] LLM error: {e}{RESET}")
            return f"[LLM Error: {e}]"

    def _build_messages(self, conversation: list[dict]) -> list[dict]:
        """Build messages cho LLM call.

        Pattern tu debate.py build_messages():
        - speaker == "REDTEAM" → role: assistant (Red la chinh)
        - speaker != "REDTEAM" → role: user
        - System prompt dau tien
        - Dam bao message cuoi la role: user
        """
        messages: list[dict] = [{"role": "system", "content": self.system_prompt}]

        # Inject RAG memory context — replaces full history when memory is available
        if self.memory_store:
            mem_ctx = self.memory_store.get_relevant_context(
                agent="red",
                keywords=["endpoint", "workflow", "chiến lược", "lỗ hổng", "credential", "verify"],
                max_chars=2000,
            )
            if mem_ctx:
                messages.append({
                    "role": "user",
                    "content": f"[MEMORY — tóm tắt từ các lượt trước]\n{mem_ctx}",
                })
            # Memory available: giữ 8 messages gần nhất để thấy failure summary + verify results
            recent_conv = conversation[-8:]
        else:
            recent_conv = conversation[-10:]  # Không có memory → giữ 10 để không mất context

        for msg in recent_conv:
            speaker = msg["speaker"]
            content = msg["content"]

            # Truncate message qua dai
            if len(content) > MAX_MSG_CHARS:
                content = truncate(content, MAX_MSG_CHARS)

            if speaker == "REDTEAM":
                messages.append({"role": "assistant", "content": content})
            else:
                # BLUETEAM, AGENT, USER, SYSTEM → user
                messages.append({"role": "user", "content": content})

        if recent_conv and recent_conv[-1]["speaker"] == "AGENT":
            messages.append({
                "role": "user",
                "content": (
                    "Co thong tin bo sung vua duoc cung cap. "
                    "Tong hop thong tin da co va viet CHIEN LUOC hoan chinh."
                ),
            })

        # Copilot API yeu cau message cuoi phai la user
        if not messages or messages[-1]["role"] != "user":
            messages.append({
                "role": "user",
                "content": "Hay phan tich recon data va viet chien luoc tan cong chi tiet.",
            })

        return messages


    def set_current_bug(self, bug: dict):
        """Inject current bug + HTTP examples into system prompt for per-bug focus.

        Red only sees the current bug and its HTTP traffic from crawl data,
        NOT the full recon_context. This is the isolation model.
        """
        http_examples = bug.get("http_examples", [])
        examples_text = ""
        if http_examples:
            lines = []
            for ex in http_examples[:2]:
                req = ex.get("request", "")
                resp_status = ex.get("response_status", "?")
                snippet = ex.get("response_snippet", "")[:200]
                why = ex.get("why_relevant", "")
                lines.append(
                    f"  Request:\n    {req}\n"
                    f"  Response Status: {resp_status}\n"
                    f"  Response Snippet: {snippet}\n"
                    f"  Why Relevant: {why}"
                )
            examples_text = "\n\nHTTP Examples from crawl data:\n" + "\n---\n".join(lines)
        else:
            examples_text = "\n(Không có http_examples trong risk-bug.json cho bug này)"

        auth_evidence = bug.get("auth_evidence") or ""
        if not auth_evidence:
            if bug.get("auth_required") and not http_examples:
                auth_evidence = (
                    "NO_VERIFIED_AUTH_CONTEXT: bug yêu cầu auth nhưng không có http_examples "
                    "hoặc authenticated crawl evidence trong dossier."
                )
            elif bug.get("auth_required"):
                auth_evidence = "AUTH_REQUIRED_WITH_LIMITED_EVIDENCE"
            else:
                auth_evidence = "ANONYMOUS_OR_MIXED"

        bug_text = (
            f"BUG HIEN TAI (tu risk-bug.json):\n"
            f"  ID: {bug.get('id','?')} [{bug.get('pattern_id','?')}]\n"
            f"  Title: {bug.get('title','?')}\n"
            f"  Risk: {bug.get('risk_level','?')} | {bug.get('method','?')} {bug.get('endpoint','?')}\n"
            f"  Chuc nang endpoint: {bug.get('endpoint_function','?')}\n"
            f"  Auth: {'required' if bug.get('auth_required') else 'anonymous/mixed'}\n"
            f"  Auth observation: {bug.get('auth_observation','?')}\n"
            f"  Auth evidence: {auth_evidence}\n"
            f"  Auth credentials needed labels: {', '.join(bug.get('auth_credentials_needed', []) or ['(none)'])}\n"
            f"  Hypothesis: {bug.get('hypothesis','?')}\n"
            f"  Exploit Approach: {bug.get('exploit_approach','?')}\n"
            f"  Verify Method: {bug.get('verify_method','?')}\n"
            f"  Request Params: {', '.join(bug.get('request_params', []) or ['(khong ro)'])}\n"
        )
        form_fields = bug.get("form_fields", []) or []
        if form_fields:
            field_lines = []
            for field in form_fields[:10]:
                field_lines.append(
                    f"    - {field.get('name', '?')} "
                    f"(type={field.get('type', '?')}, value={field.get('value', '')})"
                )
            bug_text += "  Form Fields:\n" + "\n".join(field_lines) + "\n"

        response_clues = bug.get("response_clues", []) or []
        if response_clues:
            bug_text += "  Response Clues:\n"
            for clue in response_clues[:8]:
                bug_text += f"    - {clue}\n"

        cookie_surface = bug.get("cookie_attack_surface", []) or []
        if cookie_surface:
            bug_text += "  Cookie / Client-State Attack Surface:\n"
            for item in cookie_surface[:8]:
                if not isinstance(item, dict):
                    continue
                bug_text += (
                    f"    - {item.get('name', '?')}={item.get('value_sample', '?')} "
                    f"(session={item.get('session', '?')}, httpOnly={item.get('httpOnly', '?')}, "
                    f"signal={item.get('signal', '?')}) -> {item.get('probe', '?')}\n"
                )

        attack_variants = bug.get("attack_variants", []) or []
        if attack_variants:
            bug_text += "  Suggested Generic Attack Variants:\n"
            for variant in attack_variants[:8]:
                bug_text += f"    - {variant}\n"

        evidence_rules = bug.get("evidence_rules", []) or []
        if evidence_rules:
            bug_text += "  Evidence Rules For This Bug:\n"
            for rule in evidence_rules[:6]:
                bug_text += f"    - {rule}\n"

        graph_context = bug.get("graph_context") or {}
        if graph_context:
            summary = graph_context.get("summary") or {}
            bug_text += (
                "  Guided Workflow / Graph Context:\n"
                f"    - summary: nodes={summary.get('nodes', 0)}, "
                f"edges={summary.get('edges', 0)}, "
                f"business_chain={summary.get('business_chain', 0)}, "
                f"api_hints={summary.get('api_hints', 0)}\n"
            )
            for step in (graph_context.get("business_chain") or [])[:5]:
                bug_text += (
                    f"    - business_chain[{step.get('context', '?')}]: "
                    f"{step.get('step', '?')} -> {step.get('method', '?')} "
                    f"{step.get('endpoint', '?')} status={step.get('status', '?')}\n"
                )
            for edge in (graph_context.get("edges") or [])[:5]:
                bug_text += (
                    f"    - edge[{edge.get('context', '?')}]: "
                    f"{edge.get('from', '?')} -> {edge.get('to', '?')} "
                    f"type={edge.get('type', '?')} method={edge.get('method', '-')}"
                    f" status={edge.get('status', '-')}\n"
                )

        bug_text += (
            f"{examples_text}\n\n"
            "AUTHORIZED USER CREDENTIALS:\n"
            "- Nếu user prompt trong conversation có credentials, chỉ dùng đúng cặp đó.\n"
            "- Nếu không có credential cụ thể trong conversation/dossier, không tự bịa credential.\n\n"
            f"HAY TAP TRUNG VIEC KHAI THAC BUG NAY. Khong de y den cac bug khac."
        )
        # Replace system prompt — Red sees ONLY bug info + http_examples, no recon_context
        self.system_prompt = bug_text + "\n\n" + RED_PROMPT.format(
            target_url=self.target_url,
            recon_context="(khong co du lieu recon — chi dua vao http_examples ben duoi)",
            playbook=get_playbook_text(),
        )
        if self.memory_store:
            self.memory_store.scratchpad_write("red", "current_bug", bug.get("id","?"))
        print(f"{RED}{BOLD}[RED-TEAM] Bug focused: {bug.get('id','?')} with {len(http_examples)} http_examples{RESET}")
