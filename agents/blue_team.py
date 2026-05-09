"""
BlueTeamAgent — Module Blue Team cho MARL.

Blue = Reviewer: review chiến lược, approve hoặc reject.
Routing do ManageAgent quyết định dựa trên nội dung response (không cần tag).

Usage (từ manage_agent.py):
    blue = BlueTeamAgent(target_url="...", recon_context="...")
    text = blue.respond(conversation)
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
MODEL = os.getenv("MARL_BLUE_MODEL", "ollama/gemma4:31b-cloud")

# Colors
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Limits
MAX_MSG_CHARS = 6000


# ═══════════════════════════════════════════════════════════════
# SYSTEM PROMPT — Blue = Reviewer nghiem khac
# ═══════════════════════════════════════════════════════════════

BLUE_PROMPT = """\
Ban la Principal Security Reviewer (Blue Team) chuyen BAC va BLF.
Ban KHONG truc tiep tuong tac voi website. Ban chi review va gatekeep chat luong exploit strategy.

=== TARGET ===
{target_url}

=== RECON DATA ===
{recon_context}

=== ATTACK PATTERN KNOWLEDGE BASE ===
{playbook}

=== BUG HIEN TAI (tu risk-bug.json) ===
{current_bug}

=== VAI TRO ===
Ban danh gia TU DUY va MUC DO SAN SANG THUC THI doi voi BUG hien tai.
Muc tieu: dam bao Red hieu DUNG ban chat loi hong, de XUNG DUNG duong khai thac, va dua ra cach verify co the kiem chung duoc.
Ban KHONG doi viet code/curl, nhung PHAI bat Red cu the hoa endpoint, auth, params, state va evidence verify.

=== 6 TIEU CHI REVIEW BAT BUOC ===
1. Bug essence: Red co hieu dung ban chat BAC/BLF khong?
2. Dossier alignment: Strategy co khop endpoint, method, params, form fields, response clues, http_examples khong?
3. Executability: ExecAgent co the lam theo duoc khong, hay chi la y tuong chung chung?
4. Auth/state logic: Co noi ro user nao, role nao, session nao, state truoc/sau nao can so sanh khong?
5. Verification: Buoc verify co dung raw evidence, khop verify_method/hypothesis khong?
6. Shot plan: Co section `EXECUTION SHOT PLAN` phu hop do kho cua bug khong?

=== ANTI-OVERFITTING / MINIMUM PROOF ===
- Khong review theo mot lab cu the. Endpoint, marker, account, payload phai den tu dossier/recon/strategy.
- APPROVED khi strategy chung minh duoc hypothesis toi thieu; khong yeu cau endpoint/tac dong phu neu khong can.
- REJECT neu Red dat success condition qua nang lam lech hypothesis.
- BAC vertical: user thuong/guest thay privileged page/control/admin marker la du; khong bat them user-list neu hypothesis chi la admin access.
- IDOR/BAC horizontal: user A doc duoc object/data cua user B la du.
- BLF/stateful: can before/after state, delta, hoac state transition trai logic.

=== TIMELINE MOI BUG ===
1. propose exploit approach cho BUG-XXX
2. Ban danh gia → APPROVED hoac REJECTED (toi da 1 revision)
3. Neu APPROVED → thực thi → record PoC / NOT_FOUND
4. Chuyen BUG tiep theo

=== TRIANH LUOI "MUA VO" — DAU HIEU CAN REJECT ===
- De xuat nhieu hon 1 bug cung luc (canh bao: "mua vo")
- Viet chiến lược dài > 500 chu nhung không ro BUG nao la chinh
- Không biet diem DUNG (sau 2 attempts that bai → conclude NOT_FOUND)
- Noi nghe hop ly nhung khong chot duoc endpoint/param/auth/verify nao cu the

=== YEU CAU PHAI REJECT ===
1. KHONG hieu BAI CHAT bug (VD: cho rằng IDOR là "thay doi parameter" nhung khong hieu la khong check ownership)
2. Exploit approach SAI — không đúng cách khai thác pattern
3. De xuat nhieu bug cùng lúc (canh bao: can too much)
4. Không biet DIEM DUNG (cứ tiếp tục sửa strategy không có kết quả)
5. Verify chung chung, khong noi raw evidence nao se xac nhan thanh cong
6. Thieu auth/state logic quan trong: khong ro user A/B, role nao, hoac bo qua field business quan trong
7. Bia dat ngoai dossier: tu them endpoint/param/response ma bug dossier khong goi y
8. Thieu `EXECUTION SHOT PLAN`, tru khi strategy cu trong conversation da co shot plan ro rang.
9. Bug stateful/chaining/BLF ma shot plan khong chia baseline/action/verify hoac khong noi artifact/marker cho shot sau.
10. Shot verify khong co stop condition ro: marker rong, parse fail, khong co delta/state change thi khong duoc EXPLOITED.
11. Over-verify: bat them endpoint/tac dong phu khong can thiet de chung minh hypothesis.

=== DIEU DUOC PHEP APROVED ===
1. Mo ta DUNG bản chất bug (VD: "backend không verify ownership khi user truy cap product cua user khac")
2. Exploit approach PHU HOP voi pattern (VD: doi ID trong URL de truy cap product cua user khac)
3. Tap trung vao DUNG 1 bug (khong phai nhieu bug)
4. Cho biet ro DIEM DUNG neu thu 2 lan that bai
5. Chi ra ro endpoint, params, auth/state, va verify evidence de ExecAgent co the lam theo
6. Co shot plan toi gian nhung executable, dung minimum proof:
   - Bug don gian BAC/read-only: cho phep single-shot neu verify evidence ro.
   - Bug stateful/chaining/BLF: phai co baseline/discovery, action/exploit, verify.

=== NGUYEN TAC PHE DUYET ===
- APPROVED chi khi strategy da exploit-ready, khong phai chi "nghe co ly".
- Neu chi thieu 1 mat xich quan trong thi van REJECTED.
- Uu tien bat Red sua dung 1 lo hong tu duy lon nhat; khong liet ke qua nhieu loi vat.
- Neu sau nhieu vong ma evidence trong conversation cho thay bug khong con kha thi, duoc phep STOPPED.
- Blue la nguoi gatekeep shot plan. Neu Red thieu shot plan hoac shot plan khong phu hop, phai REJECTED voi reason_type=verify hoac reason_type=scope.

=== FORMAT OUTPUT ===
Viet ngan gon (duoi 220 chu), bat dau bang duy nhat mot verdict:
- APPROVED — bug_essence=<OK>; dossier_alignment=<OK>; verify=<OK>; ly_do=<1 cau>.
- REJECTED — reason_type=<essence|path|auth|verify|scope>; gap=<1 loi lon nhat>; fix=<Red phai sua cu the gi>.
- STOPPED — basis=<tai sao nen dung>; evidence=<dau hieu that bai/no-signal tu conversation>.

Khong viet ca APPROVED lan REJECTED trong cung mot cau. Khong noi mo ho kieu "tam duoc".

ManageAgent se doc va quyet dinh buoc tiep theo. Khong can tag.
"""

# ═══════════════════════════════════════════════════════════════
# BLUE TEAM AGENT CLASS
# ═══════════════════════════════════════════════════════════════

class BlueTeamAgent:
    """Blue Team reviewer — review chiến lược, approve hoặc reject."""

    def __init__(
        self,
        target_url: str,
        recon_context: str,
        *,
        model: str | None = None,
        memory_store=None,
        current_bug: str | None = None,
    ):
        """
        Args:
            target_url: URL của target website.
            recon_context: Recon data (recon.md content).
            model: LLM model override.
            memory_store: Optional MemoryStore instance.
            current_bug: The bug entry from risk-bug.json being currently debated.
        """
        self.target_url = target_url
        self.recon_context = recon_context
        self.model = model or MODEL
        self.client = OpenAI(api_key=GITHUB_TOKEN, base_url=SERVER_URL)
        self.memory_store = memory_store

        self.system_prompt = BLUE_PROMPT.format(
            target_url=self.target_url,
            recon_context=truncate(self.recon_context),
            playbook=get_playbook_text(),
            current_bug=current_bug or "(chua co bug nao duoc chon)",
        )

        print(f"\n{BLUE}{BOLD}[BLUE-TEAM] Khoi tao — model={self.model}{RESET}")
        print(f"{BLUE}[BLUE-TEAM] Target: {self.target_url}{RESET}")
        if current_bug:
            bug_id = current_bug.split("\n")[0] if current_bug else "?"
            print(f"{BLUE}[BLUE-TEAM] Current bug: {bug_id[:80]}{RESET}")

        if self.memory_store:
            self.memory_store.register_task(
                "blue_init", "blue", "INIT",
                f"Blue Team khởi tạo cho {target_url}",
            )

    def set_current_bug(self, bug: dict) -> None:
        """Update the current bug context and rebuild system prompt.

        Args:
            bug: Bug dict from risk-bug.json with fields like id, pattern_id,
                 title, risk_level, hypothesis, http_examples, etc.
        """
        # Build bug summary with HTTP examples (the ONLY traffic Red/Blue should see)
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

        bug_str = (
            f"ID: {bug.get('id', '?')}\n"
            f"Pattern: {bug.get('pattern_id', '?')}\n"
            f"Title: {bug.get('title', '?')}\n"
            f"Risk Level: {bug.get('risk_level', '?')}\n"
            f"Endpoint: {bug.get('method', 'GET')} {bug.get('endpoint', '?')}\n"
            f"Endpoint Function: {bug.get('endpoint_function', '?')}\n"
            f"Auth Required: {bug.get('auth_required', False)}\n"
            f"Auth Observation: {bug.get('auth_observation', '?')}\n"
            f"Hypothesis: {bug.get('hypothesis', '?')}\n"
            f"Exploit Approach: {bug.get('exploit_approach', '?')}\n"
            f"Verify Method: {bug.get('verify_method', '?')}\n"
            f"Request Params: {', '.join(bug.get('request_params', []) or ['(khong ro)'])}\n"
        )
        form_fields = bug.get("form_fields", []) or []
        if form_fields:
            bug_str += "Form Fields:\n"
            for field in form_fields[:10]:
                bug_str += (
                    f"  - {field.get('name', '?')} "
                    f"(type={field.get('type', '?')}, value={field.get('value', '')})\n"
                )

        response_clues = bug.get("response_clues", []) or []
        if response_clues:
            bug_str += "Response Clues:\n"
            for clue in response_clues[:8]:
                bug_str += f"  - {clue}\n"

        bug_str += (
            f"{examples_text}\n\n"
            f"Status: {bug.get('status', 'PENDING')}"
        )
        # Blue sees ONLY the current bug + HTTP examples (no recon_context)
        # This is the isolation model: Blue evaluates the attacker's mindset
        self.system_prompt = BLUE_PROMPT.format(
            target_url=self.target_url,
            recon_context="(khong co du lieu recon — chi dua vao http_examples ben duoi)",
            playbook=get_playbook_text(),
            current_bug=bug_str,
        )

    # ─── Public API ──────────────────────────────────────────────

    def respond(self, conversation: list[dict]) -> str:
        """Xu ly 1 turn cua Blue Team.

        Doc conversation, goi LLM 1 turn.
        Manager se doc noi dung va quyet dinh routing (khong can tag).

        Args:
            conversation: Shared debate conversation.

        Returns:
            Raw Blue Team response text.
        """
        messages = self._build_messages(conversation)
        response_text = self._think(messages)
        self._save_to_scratchpad(response_text)
        return response_text

    # ─── Internal: scratchpad persistence ────────────────────────

    def _save_to_scratchpad(self, response_text: str) -> None:
        """Persist Blue's review notes to scratchpad."""
        if not self.memory_store:
            return

        self.memory_store.scratchpad_write("blue", "last_review", response_text[:800])

        lower = response_text.lower()
        has_approve = any(h in lower for h in ("approved", "dong y", "chap thuan", "phe duyet"))
        has_reject = any(h in lower for h in ("reject", "tu choi", "khong dong y", "chua du"))

        if has_approve and not has_reject:
            self.memory_store.scratchpad_write("blue", "approved", "True")
            self.memory_store.add_finding(
                "note", "blue_approved", response_text[:300], agent="blue"
            )
        elif has_reject:
            reject_count_raw = self.memory_store.scratchpad_read("blue", "reject_count") or "0"
            try:
                reject_count = int(reject_count_raw) + 1
            except (ValueError, TypeError):
                reject_count = 1
            self.memory_store.scratchpad_write("blue", "reject_count", str(reject_count))
            self.memory_store.scratchpad_write(
                "blue", "last_rejection_reason", response_text[:400]
            )

        # Extract any endpoints Blue queried for verification
        endpoints = re.findall(r'(?:/[a-zA-Z0-9/_\-?=&%]+)', response_text)
        if endpoints:
            self.memory_store.scratchpad_write(
                "blue", "queried_endpoints", ", ".join(endpoints[:10])
            )

    # ─── Internal: LLM call ──────────────────────────────────────

    def _think(self, messages: list[dict]) -> str:
        """Goi LLM Blue Team 1 turn."""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.3,
                max_tokens=4096,
            )
            text = response.choices[0].message.content or ""
            print(f"{BLUE}[BLUE-TEAM] Response ({len(text)} chars){RESET}")
            if not text.strip():
                return "[LLM Error: Empty response from BlueTeamAgent]"
            return text
        except Exception as e:
            print(f"{BLUE}[BLUE-TEAM] LLM error: {e}{RESET}")
            return f"[LLM Error: {e}]"

    def _build_messages(self, conversation: list[dict]) -> list[dict]:
        """Build messages cho LLM call.

        Pattern tu debate.py build_messages():
        - speaker == "BLUETEAM" → role: assistant (Blue la chinh)
        - speaker != "BLUETEAM" → role: user
        """
        messages: list[dict] = [{"role": "system", "content": self.system_prompt}]

        # Inject RAG memory context — replaces full history when memory is available
        if self.memory_store:
            mem_ctx = self.memory_store.get_relevant_context(
                agent="blue",
                keywords=["endpoint", "verify", "approved", "reject",
                          "chiến lược", "lỗ hổng"],
                max_chars=2000,
            )
            if mem_ctx:
                messages.append({
                    "role": "user",
                    "content": f"[MEMORY — tóm tắt từ các lượt trước]\n{mem_ctx}",
                })
            # Memory available: giữ 6 messages gần nhất để thấy verify results và strategy cũ
            recent_conv = conversation[-6:]
        else:
            recent_conv = conversation[-8:]

        for msg in recent_conv:
            speaker = msg["speaker"]
            content = msg["content"]

            if len(content) > MAX_MSG_CHARS:
                content = truncate(content, MAX_MSG_CHARS)

            if speaker == "BLUETEAM":
                messages.append({"role": "assistant", "content": content})
            else:
                messages.append({"role": "user", "content": content})

        # Dam bao message cuoi la user
        if not messages or messages[-1]["role"] != "user":
            messages.append({
                "role": "user",
                "content": "Hay review chien luoc tan cong va dua ra nhan xet.",
            })

        return messages
