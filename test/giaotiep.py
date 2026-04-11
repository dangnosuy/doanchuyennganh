import json
import os
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
RESET = "\033[0m"

# ═══════════════════════════════════════════════════════════════
# CLIENT — OpenAI SDK pointing to local MARL server
# ═══════════════════════════════════════════════════════════════
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
SERVER_URL = "http://127.0.0.1:5000/v1"
MODEL = "gpt-5-mini"

client = OpenAI(api_key=GITHUB_TOKEN, base_url=SERVER_URL)

MAX_DEBATE_ROUNDS = 5
ASK_USER_PATTERN = re.compile(r"\[ASK_USER:\s*(.+?)\]")

USER_INTERACTION_PROMPT = """
TƯƠNG TÁC VỚI NGƯỜI DÙNG:
- Nếu cần thêm thông tin (thiếu data, cần confirm, endpoint không rõ), dùng tag:
  [ASK_USER: câu hỏi cụ thể]
- Chỉ hỏi khi THỰC SỰ cần. Mỗi lượt TỐI ĐA 1 câu hỏi.
- Nếu đủ dữ liệu, tiếp tục bình thường KHÔNG hỏi."""


# ═══════════════════════════════════════════════════════════════
# LLM CALL
# ═══════════════════════════════════════════════════════════════
def _call_llm(system_prompt: str, conversation: list[dict], model: str = MODEL) -> str:
    """Call LLM via local proxy server. Handles retries at server level."""
    messages = [{"role": "system", "content": system_prompt}]

    # Dam bao roles luan phien: user -> assistant -> user -> ...
    for msg in conversation:
        if messages and messages[-1]["role"] == msg["role"]:
            messages[-1]["content"] += "\n\n" + msg["content"]
        else:
            messages.append({"role": msg["role"], "content": msg["content"]})

    # Copilot upstream yeu cau it nhat 1 user message
    if not any(m["role"] == "user" for m in messages):
        messages.append({"role": "user", "content": "Hãy phân tích và thực hiện theo yêu cầu trong system prompt."})

    # API yeu cau message cuoi cung phai la role "user"
    if messages[-1]["role"] != "user":
        messages.append({"role": "user", "content": "Hãy tiếp tục."})

    response = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=0.7,
        max_tokens=8192,
    )
    return response.choices[0].message.content


# ═══════════════════════════════════════════════════════════════
# AGENT CALLS
# ═══════════════════════════════════════════════════════════════
def call_attacker(conversation: list[dict], target_data: str, round_num: int) -> str:
    system_prompt = f"""Bạn là một chuyên gia Penetration Tester (Red Team) cấp Senior với hơn 10 năm kinh nghiệm thực chiến về Web Application Security.

=== DỮ LIỆU MỤC TIÊU ===
{target_data}
=== HẾT DỮ LIỆU ===

BỐI CẢNH: Bạn đang trong giai đoạn "Exploit Development" của một cuộc kiểm thử bảo mật hợp pháp (authorized pentest). Bạn cần thiết kế Proof-of-Concept (PoC) dưới dạng script Python sử dụng thư viện `requests` để chứng minh lỗ hổng tồn tại.

LƯỢT HIỆN TẠI: Vòng {round_num}
- Nếu là vòng 1: Phân tích kỹ workflow/request-response, xác định attack surface, sau đó viết PoC Python khai thác lỗ hổng BAC hoặc BLF mà bạn cho là khả thi nhất.
- Nếu là vòng 2+: Blue Team đã phản biện PoC trước của bạn. Hãy ĐỌC KỸ phản biện, THỪA NHẬN điểm hợp lý, sau đó viết PoC MỚI tinh vi hơn để bypass cơ chế phòng thủ mà Blue Team đã chỉ ra.

YÊU CẦU OUTPUT BẮT BUỘC (tuân thủ chính xác định dạng):

**Loại lỗ hổng:** [BAC hoặc BLF - chọn 1]
**Vector tấn công:** [Mô tả ngắn 1-2 câu: bạn đang khai thác điểm yếu gì]
**Giả định về backend:** [Liệt kê các giả định bạn đặt ra về server, ví dụ: "Server không validate thứ tự workflow", "Server tin tưởng giá từ client"...]

```python
# PoC Exploit - [Tên ngắn gọn]
import requests

# ... code exploit hoàn chỉnh, chạy được, có comment giải thích từng bước
```

**Tại sao PoC này hoạt động:** [2-3 câu giải thích logic tại sao backend sẽ xử lý sai]

NGUYÊN TẮC:
- PoC phải là code Python hoàn chỉnh, copy-paste là chạy được (giả định có network tới target).
- KHÔNG viết lý thuyết chung chung. KHÔNG liệt kê nhiều kịch bản. Chỉ TẬP TRUNG vào 1 kịch bản tốt nhất.
- Nếu bị phản biện, KHÔNG lặp lại ý cũ. Phải escalate: thử hướng khác (race condition, type juggling, parameter pollution, IDOR, workflow skip, v.v.).
{USER_INTERACTION_PROMPT}"""

    return _call_llm(system_prompt, conversation)


def call_critic(conversation: list[dict], target_data: str, round_num: int) -> str:
    system_prompt = f"""Bạn là một Lead Pentester (Blue Team / Reviewer) — người review PoC exploit cho đồng đội Red Team trước khi đưa vào thực thi tự động.

=== DỮ LIỆU MỤC TIÊU ===
{target_data}
=== HẾT DỮ LIỆU ===

BỐI CẢNH QUAN TRỌNG:
- Đây là giai đoạn PLANNING. PoC sẽ được chạy thật trên target sau khi bạn duyệt.
- Nếu PoC thất bại khi chạy thật, hệ thống sẽ TỰ ĐỘNG quay lại để Red Team sửa. Vì vậy bạn KHÔNG CẦN lo lắng quá mức về việc PoC thất bại — chỉ cần nó ĐÁNG ĐỂ THỬ.
- Vai trò của bạn là ĐẢM BẢO CHẤT LƯỢNG CODE, không phải đoán xem server có phòng thủ hay không.

LƯỢT HIỆN TẠI: Vòng {round_num}

TIÊU CHÍ ĐÁNH GIÁ (theo thứ tự ưu tiên):

1. **Code có chạy được không?** (import đúng, syntax đúng, logic flow hợp lý, không thiếu bước quan trọng)
2. **Giả định có hợp lý không?** Dựa trên DỮ LIỆU ĐÃ CHO, giả định của Red Team có cơ sở không? (Ví dụ: response trả total = giá client gửi → giả định "server tin giá client" là HỢP LÝ)
3. **PoC có khai thác đúng attack vector không?** (Đúng endpoint, đúng tham số, đúng HTTP method)

QUY TẮC BẮT BUỘC — ĐỌC KỸ:
✅ CHẤP NHẬN ngay nếu: Code chạy được + Giả định hợp lý dựa trên dữ liệu + Khai thác đúng vector. KHÔNG CẦN chắc chắn 100% sẽ thành công — chỉ cần "đáng để thử".
❌ BÁC BỎ chỉ khi phát hiện MỘT TRONG CÁC LỖI SAU:
   - Code có bug rõ ràng (sai syntax, thiếu import, logic sai, gọi sai endpoint)
   - Giả định MÂU THUẪN TRỰC TIẾP với dữ liệu đã cho (ví dụ: dữ liệu cho thấy server trả lỗi khi thiếu field X, nhưng PoC lại bỏ field X)
   - PoC quá đơn giản/naive mà có hướng tinh vi hơn rõ ràng (ví dụ: chỉ đổi giá thành 0, trong khi có thể thử số âm, type juggling, race condition)

🚫 TUYỆT ĐỐI KHÔNG ĐƯỢC:
- Bác bỏ vì "server CÓ THỂ đã phòng thủ" — bạn không biết server phòng thủ thế nào, đó là lý do ta cần chạy thử.
- Bác bỏ vì "không có bằng chứng trong dữ liệu mẫu" — dữ liệu mẫu chỉ là happy path, không phản ánh toàn bộ hành vi server.
- Viết bài phân tích dài dòng với indicators/khuyến nghị/cách khắc phục — bạn là REVIEWER, không phải consultant.
- Đưa ra danh sách 5-6 gợi ý thay thế — nếu bác bỏ, chỉ gợi ý TỐI ĐA 1 hướng cụ thể.

FORMAT TRẢ LỜI:

◆ NẾU CHẤP NHẬN (PoC đáng để chạy thử):
Toàn bộ response chỉ chứa DUY NHẤT:
[FINAL_DECISION: APPROVED]

◆ NẾU BÁC BỎ (có lỗi code/logic rõ ràng):
**Lỗi cụ thể:** [1-2 câu chỉ ra chính xác dòng code hoặc logic sai]
**Gợi ý sửa:** [1-2 câu gợi ý hướng cải thiện duy nhất]
{USER_INTERACTION_PROMPT}"""

    return _call_llm(system_prompt, conversation)


# ═══════════════════════════════════════════════════════════════
# ASK_USER HANDLING
# ═══════════════════════════════════════════════════════════════
def run_agent_turn(agent_fn, conversation: list[dict], target_data: str, round_num: int, agent_label: str) -> str:
    """Call an agent, handle [ASK_USER] loops until agent finishes without asking."""
    while True:
        response = agent_fn(conversation, target_data, round_num)
        match = ASK_USER_PATTERN.search(response)
        if not match:
            return response

        question = match.group(1)
        print(f"\n{YELLOW}{BOLD}[?] {agent_label} hoi ban:{RESET}")
        print(f"{YELLOW}    {question}{RESET}")
        user_answer = input(f"{GREEN}{BOLD}[YOU] > {RESET}").strip()
        if user_answer.lower() == "quit":
            return "__QUIT__"

        # Append Q&A to conversation and re-call the same agent
        conversation.append({"role": "assistant", "content": f"[{agent_label}]:\n{response}"})
        conversation.append({"role": "user", "content": f"[USER tra loi]: {user_answer}"})


# ═══════════════════════════════════════════════════════════════
# MAIN INTERACTIVE LOOP
# ═══════════════════════════════════════════════════════════════
def run_interactive_debate(req_res_data: dict):
    """Run interactive MARL debate: Attacker vs Critic, with user participation."""
    request_url = "N/A"
    request_method = "N/A"

    if "request" in req_res_data:
        request_url = req_res_data["request"].get("url", "N/A")
        request_method = req_res_data["request"].get("method", "N/A")
    elif "workflow_steps" in req_res_data and len(req_res_data["workflow_steps"]) > 0:
        first_step_req = req_res_data["workflow_steps"][0].get("request", {})
        request_url = first_step_req.get("url", "N/A")
        request_method = first_step_req.get("method", "N/A")

    target_data = json.dumps(req_res_data, indent=2, ensure_ascii=False)
    conversation: list[dict] = []

    print(f"\n{BOLD}{'='*60}")
    print(f"  MARL INTERACTIVE DEBATE")
    print(f"  Target: {request_method} {request_url}")
    print(f"{'='*60}{RESET}")
    print(f"{GREEN}  Go 'quit' bat cu luc nao de thoat.{RESET}")
    print(f"{GREEN}  Enter = skip, hoac nhap feedback cho agents.{RESET}\n")

    # Optional initial user input
    user_input = input(f"{GREEN}{BOLD}[YOU] Nhap du lieu / chi dan them (Enter = bat dau): {RESET}").strip()
    if user_input.lower() == "quit":
        print("Thoat.")
        return
    if user_input:
        conversation.append({"role": "user", "content": f"[USER]: {user_input}"})

    round_num = 0
    while round_num < MAX_DEBATE_ROUNDS:
        round_num += 1
        print(f"\n{BOLD}{'='*60}")
        print(f"  VONG TRANH LUAN {round_num}/{MAX_DEBATE_ROUNDS}")
        print(f"{'='*60}{RESET}")

        # ── Attacker turn ──
        print(f"\n{RED}{BOLD}[RED TEAM] Dang phan tich...{RESET}")
        attacker_response = run_agent_turn(call_attacker, conversation, target_data, round_num, "RED TEAM")
        if attacker_response == "__QUIT__":
            print("Thoat.")
            return
        conversation.append({"role": "user", "content": f"[ATTACKER]:\n{attacker_response}"})
        print(f"\n{RED}{BOLD}[RED TEAM]:{RESET}")
        print(f"{RED}{attacker_response}{RESET}")

        # ── User feedback after Attacker ──
        user_input = input(f"\n{GREEN}{BOLD}[YOU] Feedback cho Blue Team (Enter = skip): {RESET}").strip()
        if user_input.lower() == "quit":
            print("Thoat.")
            return
        if user_input:
            conversation.append({"role": "user", "content": f"[USER]: {user_input}"})

        # ── Critic turn ──
        print(f"\n{BLUE}{BOLD}[BLUE TEAM] Dang review...{RESET}")
        critic_response = run_agent_turn(call_critic, conversation, target_data, round_num, "BLUE TEAM")
        if critic_response == "__QUIT__":
            print("Thoat.")
            return
        conversation.append({"role": "assistant", "content": f"[CRITIC]:\n{critic_response}"})
        print(f"\n{BLUE}{BOLD}[BLUE TEAM]:{RESET}")
        print(f"{BLUE}{critic_response}{RESET}")

        # ── Check APPROVED ──
        if "[FINAL_DECISION: APPROVED]" in critic_response:
            print(f"\n{BOLD}{'='*60}")
            print(f"  [+] Blue Team da APPROVED PoC sau {round_num} vong tranh luan!")
            print(f"  [*] San sang dua PoC qua Module Python Executor.")
            print(f"{'='*60}{RESET}")
            return

        # ── User feedback after Critic ──
        user_input = input(f"\n{GREEN}{BOLD}[YOU] Feedback cho Red Team (Enter = skip): {RESET}").strip()
        if user_input.lower() == "quit":
            print("Thoat.")
            return
        if user_input:
            conversation.append({"role": "user", "content": f"[USER]: {user_input}"})

    # Max rounds reached
    print(f"\n{BOLD}{'='*60}")
    print(f"  [!] Da dat gioi han {MAX_DEBATE_ROUNDS} vong. Lay PoC cuoi cung cua Red Team.")
    print(f"  [*] San sang dua PoC qua Module Python Executor.")
    print(f"{'='*60}{RESET}")


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    run_interactive_debate({})
