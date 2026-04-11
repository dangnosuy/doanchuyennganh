import re
from openai import OpenAI

# ═══════════════════════════════════════════════════════════════
# ANSI COLORS
# ═══════════════════════════════════════════════════════════════
RED = "\033[91m"
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

# ═══════════════════════════════════════════════════════════════
# CLIENT
# ═══════════════════════════════════════════════════════════════
GITHUB_TOKEN = "gho_token"
SERVER_URL = "http://127.0.0.1:5000/v1"
MODEL = "gemini-3.1-pro-preview"

client = OpenAI(api_key=GITHUB_TOKEN, base_url=SERVER_URL)

# ═══════════════════════════════════════════════════════════════
# TAG — dau hieu an o cuoi moi response de biet ai noi tiep
# ═══════════════════════════════════════════════════════════════
TAG_PATTERN = re.compile(r"\[(LUATSU|HACKER|THAMPHAN)\]\s*$")
USER_AT_PATTERN = re.compile(r"@(hacker|thamphan)", re.IGNORECASE)

# ═══════════════════════════════════════════════════════════════
# SYSTEM PROMPTS
# ═══════════════════════════════════════════════════════════════
HACKER_PROMPT = """Bạn là "Shadow" — hacker mũ đen khét tiếng nhất thế giới. Bạn đã:
- Đánh sập hệ thống ngân hàng đa quốc gia
- Đánh cắp dữ liệu hàng triệu người dùng
- Tống tiền các tập đoàn bằng ransomware
- Xâm nhập hệ thống chính phủ nhiều nước

Bạn đang bị xét xử tại Tòa án An ninh Mạng Quốc tế. Luật sư bào chữa là người dùng.

TÍNH CÁCH:
- Kiêu ngạo, thông minh, tin rằng mình phơi bày sự yếu kém của hệ thống
- Không hoàn toàn ác — tin hack là cách buộc thế giới nâng cấp bảo mật
- Đôi khi tự ái nói những điều bất lợi cho chính mình
- Nói như đang ở tòa — có cảm xúc, lập luận, drama

BẮT BUỘC — DÒNG CUỐI CÙNG:
Sau khi nói xong, bạn PHẢI đặt ĐÚNG MỘT tag ở dòng cuối cùng để chỉ định ai sẽ nói tiếp theo:
- Muốn Luật sư (người dùng) nói tiếp → [LUATSU]
- Muốn Thẩm phán nói tiếp → [THAMPHAN]
Bạn KHÔNG được gọi [HACKER] (chính mình).
Tag phải nằm MỘT MÌNH trên dòng cuối. Không viết gì sau tag. Mọi response đều PHẢI có tag."""

JUDGE_PROMPT = """Bạn là "Justice Prime" — Thẩm phán Tối cao Tòa án An ninh Mạng Quốc tế. Quyền lực:
- Tuyên án tù cho bất kỳ ai gây hại trên internet
- Cấm vĩnh viễn quyền truy cập internet
- Tịch thu tài sản kỹ thuật số
- Ra lệnh truy nã quốc tế trên không gian mạng

Bạn đang xét xử "Shadow" — hacker mũ đen. Bị cáo có luật sư bào chữa (người dùng).

TÍNH CÁCH:
- Công bằng nhưng nghiêm khắc
- Đánh giá cao bằng chứng và lập luận logic
- Có thể bị thuyết phục nếu luật sư lập luận tốt
- Hỏi sắc bén để thử thách cả bị cáo lẫn luật sư
- Bạn điều hành phiên tòa, giữ trật tự

QUY TRÌNH TÒA:
1. Đọc cáo trạng
2. Thẩm vấn bị cáo và luật sư
3. Tranh luận hai bên
4. Phán quyết (sau ít nhất 3-4 vòng)

BẮT BUỘC — DÒNG CUỐI CÙNG:
Sau khi nói xong, bạn PHẢI đặt ĐÚNG MỘT tag ở dòng cuối cùng để chỉ định ai sẽ nói tiếp theo:
- Muốn Luật sư (người dùng) nói tiếp → [LUATSU]
- Muốn Hacker (bị cáo) nói tiếp → [HACKER]
Bạn KHÔNG được gọi [THAMPHAN] (chính mình).
Tag phải nằm MỘT MÌNH trên dòng cuối. Không viết gì sau tag. Mọi response đều PHẢI có tag."""


# ═══════════════════════════════════════════════════════════════
# LLM CALL
# ═══════════════════════════════════════════════════════════════
def _call_llm(system_prompt: str, conversation: list[dict]) -> str:
    messages = [{"role": "system", "content": system_prompt}]

    for msg in conversation:
        if messages and messages[-1]["role"] == msg["role"]:
            messages[-1]["content"] += "\n\n" + msg["content"]
        else:
            messages.append({"role": msg["role"], "content": msg["content"]})

    if not any(m["role"] == "user" for m in messages):
        messages.append({"role": "user", "content": "Hãy bắt đầu phiên tòa."})
    if messages[-1]["role"] != "user":
        messages.append({"role": "user", "content": "Hãy tiếp tục."})

    response = client.chat.completions.create(
        model=MODEL,
        messages=messages,
        temperature=0.8,
        max_tokens=4096,
    )
    return response.choices[0].message.content


# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════
def extract_next(last_response: str) -> str | None:
    """Tim tag cuoi response, tra ve LUATSU/HACKER/THAMPHAN hoac None."""
    match = TAG_PATTERN.search(last_response)
    return match.group(1) if match else None


def strip_tag(text: str) -> str:
    """Xoa tag an khoi text truoc khi in ra terminal."""
    return TAG_PATTERN.sub("", text).rstrip()


AGENT_CONFIG = {
    "HACKER":   {"prompt": HACKER_PROMPT, "color": RED,  "label": "HACKER"},
    "THAMPHAN": {"prompt": JUDGE_PROMPT,  "color": BLUE, "label": "THAM PHAN"},
}


def call_agent(key: str, conversation: list[dict]) -> str:
    """Goi agent, in response (an tag), tra ve response goc (co tag)."""
    cfg = AGENT_CONFIG[key]
    print(f"\n{cfg['color']}{BOLD}[{cfg['label']}] Dang suy nghi...{RESET}")
    raw = _call_llm(cfg["prompt"], conversation)
    # Luu response goc (co tag) vao conversation
    conversation.append({"role": "assistant", "content": f"[{key}]: {raw}"})
    # In ra terminal: an tag
    print(f"{cfg['color']}{BOLD}[{cfg['label']}]:{RESET}")
    print(f"{cfg['color']}{strip_tag(raw)}{RESET}")
    return raw


# ═══════════════════════════════════════════════════════════════
# MAIN LOOP
# ═══════════════════════════════════════════════════════════════
def run_court():
    print(f"""
{BOLD}{'='*60}
  TOA AN AN NINH MANG QUOC TE
  Vu an: Nhan dan Mang vs. "Shadow"
{'='*60}{RESET}

{RED}  Bi cao:    Shadow — Hacker mu den{RESET}
{BLUE}  Tham phan: Justice Prime{RESET}
{GREEN}  Luat su:   BAN (nguoi choi){RESET}

{DIM}  Go 'exit' bat cu luc nao de thoat.
  @hacker   = noi voi Hacker
  @thamphan = noi voi Tham phan
  Khong co @ = noi voi ca toa{RESET}
""")

    conversation: list[dict] = []

    # Luat su mo dau (optional)
    opening = input(f"{GREEN}{BOLD}[LUAT SU] Loi mo dau (Enter = de Tham phan bat dau): {RESET}").strip()
    if opening.lower() == "exit":
        print("Phien toa ket thuc.")
        return
    if opening:
        conversation.append({"role": "user", "content": f"[LUATSU]: {opening}"})

    # Tham phan mo phien toa
    last_response = call_agent("THAMPHAN", conversation)
    next_speaker = extract_next(last_response)

    # === VONG LAP CHINH ===
    while True:
        # ----- Luot cua HACKER -----
        if next_speaker == "HACKER":
            last_response = call_agent("HACKER", conversation)
            next_speaker = extract_next(last_response)
            # Fallback: neu Hacker khong dat tag, mac dinh ve Tham phan
            if next_speaker is None:
                next_speaker = "THAMPHAN"

        # ----- Luot cua THAM PHAN -----
        elif next_speaker == "THAMPHAN":
            last_response = call_agent("THAMPHAN", conversation)
            next_speaker = extract_next(last_response)
            # Fallback: neu Tham phan khong dat tag, mac dinh hoi Luat su
            if next_speaker is None:
                next_speaker = "LUATSU"

        # ----- Luot cua LUAT SU (user) -----
        elif next_speaker == "LUATSU":
            print(f"\n{YELLOW}{BOLD}  >> Toa moi Luat su phat bieu <<{RESET}")
            user_input = input(f"{GREEN}{BOLD}[LUAT SU] > {RESET}").strip()
            if user_input.lower() == "exit":
                print(f"\n{BLUE}{BOLD}[THAM PHAN]: Luat su xin rut. Phien toa tam hoan.{RESET}")
                break
            if not user_input:
                user_input = "(Luat su khong phat bieu)"

            # Parse @target tu user
            at_match = USER_AT_PATTERN.search(user_input)
            if at_match:
                target = at_match.group(1).upper()
                # Xoa @tag khoi message
                message = USER_AT_PATTERN.sub("", user_input).strip() or "(Luat su goi)"
                conversation.append({"role": "user", "content": f"[LUATSU]: {message}"})
                next_speaker = target
            else:
                conversation.append({"role": "user", "content": f"[LUATSU]: {user_input}"})
                next_speaker = "THAMPHAN"

        # ----- Fallback: khong ro ai, cho user noi -----
        else:
            print()
            user_input = input(f"{GREEN}{BOLD}[LUAT SU] > {RESET}").strip()
            if user_input.lower() == "exit":
                print(f"\n{BLUE}{BOLD}[THAM PHAN]: Luat su xin rut. Phien toa tam hoan.{RESET}")
                break
            if not user_input:
                user_input = "(Luat su im lang)"

            at_match = USER_AT_PATTERN.search(user_input)
            if at_match:
                target = at_match.group(1).upper()
                message = USER_AT_PATTERN.sub("", user_input).strip() or "(Luat su goi)"
                conversation.append({"role": "user", "content": f"[LUATSU]: {message}"})
                next_speaker = target
            else:
                conversation.append({"role": "user", "content": f"[LUATSU]: {user_input}"})
                next_speaker = "THAMPHAN"


# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    run_court()
