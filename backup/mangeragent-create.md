 Kế hoạch: Thêm ManageAgent vào MARL                                                                          
                                                                                                              
 Context                                                                                                      
                                                                                                              
 Hiện tại, main.py đóng vai trò orchestrator trực tiếp — gọi thẳng từng agent (red.respond(), blue.respond(), 
  exec_agent.answer()) trong state machine phase_debate(). Điều này khiến luồng điều hướng nằm rải rác trong  
 main và không có "trung gian" chịu trách nhiệm kiểm soát giao tiếp giữa các agent.                           

 Mục tiêu: Tạo ManageAgent — một lớp trung gian đứng giữa main.py và các agent con, điều phối toàn bộ Phase 2 
  (Debate). Red/Blue chỉ "nói chuyện" qua ManageAgent, không được gọi thẳng lẫn nhau.                         
                                                                                                              
 Thiết kế theo deterministic state machine (không dùng LLM để routing) — bởi vì routing đã hoàn toàn xác định 
  qua tag ([AGENT], [BLUETEAM], [APPROVED], ...). Thêm LLM routing sẽ gây tốn API call không cần thiết.

 ---
 Files cần thay đổi

 ┌────────────────────────┬───────────────────────────────────────────────────────────────────────────────┐
 │          File          │                                   Thay đổi                                    │
 ├────────────────────────┼───────────────────────────────────────────────────────────────────────────────┤
 │ agents/manage_agent.py │ TẠO MỚI — toàn bộ logic Phase 2                                               │
 ├────────────────────────┼───────────────────────────────────────────────────────────────────────────────┤
 │ main.py                │ Thay phase_debate() bằng manage_agent.run_debate(), xóa hàm phase_debate() và │
 │                        │  _extract_last_workflow()                                                     │
 └────────────────────────┴───────────────────────────────────────────────────────────────────────────────┘

 Tất cả các file khác (red_team.py, blue_team.py, exec_agent.py, shared/utils.py) KHÔNG thay đổi.

 ---
 Thiết kế agents/manage_agent.py

 Class interface

 class ManageAgent:
     def __init__(
         self,
         target_url: str,
         recon_content: str,
         *,
         max_debate_steps: int = MAX_DEBATE_STEPS,   # 30
         max_rounds: int = MAX_ROUNDS,               # 5
         min_debate_rounds: int = MIN_DEBATE_ROUNDS, # 2
     ):
         self.target_url = target_url
         self.recon_content = recon_content
         self.max_debate_steps = max_debate_steps
         self.max_rounds = max_rounds
         self.min_debate_rounds = min_debate_rounds

     def run_debate(
         self,
         red: RedTeamAgent,
         exec_agent: ExecAgent,
         conversation: list[dict],
     ) -> tuple[str, list[dict], int]:
         """Drop-in replacement cho phase_debate() trong main.py.
  
         Tạo BlueTeamAgent nội bộ, điều phối toàn bộ vòng lặp debate.
         Trả về (approved_workflow, conversation, round_num).
         """

 Ownership model

 ┌───────────────────────────────────────────────────────────────┬───────────────────────────────────────┐
 │                      ManageAgent sở hữu                       │          main.py truyền vào           │
 ├───────────────────────────────────────────────────────────────┼───────────────────────────────────────┤
 │ BlueTeamAgent (tạo mới mỗi run_debate())                      │ RedTeamAgent (dùng lại qua retries)   │
 ├───────────────────────────────────────────────────────────────┼───────────────────────────────────────┤
 │ Debate state: round_num, red_spoke, blue_spoke, next_turn,    │ ExecAgent (dùng chung tất cả phases)  │
 │ last_caller                                                   │                                       │
 ├───────────────────────────────────────────────────────────────┼───────────────────────────────────────┤
 │ Constants: max_debate_steps, max_rounds, min_debate_rounds    │ conversation list (lifetime thuộc     │
 │                                                               │ main.py)                              │
 ├───────────────────────────────────────────────────────────────┼───────────────────────────────────────┤
 │ Routing logic từ tags                                         │ Retry loop, Phase 3/4/5               │
 └───────────────────────────────────────────────────────────────┴───────────────────────────────────────┘

 ▎ ⚠️  Quan trọng: Tất cả state (round_num, next_turn, ...) phải là local variable trong run_debate(), KHÔNG
 ▎ phải self.*. ManageAgent được reuse qua retries — nếu state là instance attribute, attempt 2 sẽ bị ô nhiễm
 ▎  bởi attempt 1.

 Logic nội bộ run_debate()

 Di chuyển nguyên vẹn body của phase_debate() hiện tại trong main.py vào run_debate():
 - BlueTeamAgent được tạo ở đầu hàm
 - State machine for step in range(self.max_debate_steps) với các nhánh REDTEAM / BLUETEAM / AGENT
 - Tất cả guardrails giữ nguyên (MIN_DEBATE_ROUNDS check, MAX_ROUNDS check, system message inject)
 - Gọi _extract_last_workflow() khi APPROVED

 Hàm helper

 _extract_last_workflow(conversation) — di chuyển từ main.py sang module-level private trong manage_agent.py.

 ---
 Thay đổi main.py

 1. Import và khởi tạo ManageAgent (cùng chỗ với ExecAgent)

 from agents.manage_agent import ManageAgent

 manage_agent = ManageAgent(
     target_url=target_url,
     recon_content=recon_content,
 )

 2. Thay thế phase_debate() call trong retry loop

 # CŨ:
 workflow, conversation, round_num = phase_debate(
     target_url, recon_content, exec_agent, red, conversation,
 )

 # MỚI:
 workflow, conversation, round_num = manage_agent.run_debate(
     red, exec_agent, conversation,
 )

 3. Xóa khỏi main.py

 - Hàm phase_debate() (toàn bộ body)
 - Hàm _extract_last_workflow() (đã chuyển sang manage_agent.py)

 ---
 Backward compatibility đầy đủ

 ┌─────────────────────────────────────────────────────────────────────┬───────────────┐
 │                              Component                              │  Trạng thái   │
 ├─────────────────────────────────────────────────────────────────────┼───────────────┤
 │ Conversation format (speaker/content dicts)                         │ ✅ Giữ nguyên │
 ├─────────────────────────────────────────────────────────────────────┼───────────────┤
 │ Tất cả guardrails                                                   │ ✅ Giữ nguyên │
 ├─────────────────────────────────────────────────────────────────────┼───────────────┤
 │ Tag routing priority (AGENT > DONE > APPROVED > REDTEAM > BLUETEAM) │ ✅ Giữ nguyên │
 ├─────────────────────────────────────────────────────────────────────┼───────────────┤
 │ Backtracking memory (conversation tích lũy qua retries)             │ ✅ Giữ nguyên │
 ├─────────────────────────────────────────────────────────────────────┼───────────────┤
 │ Retry loop trong main.py                                            │ ✅ Giữ nguyên │
 ├─────────────────────────────────────────────────────────────────────┼───────────────┤
 │ Phase 3, 4, 5 functions                                             │ ✅ Giữ nguyên │
 ├─────────────────────────────────────────────────────────────────────┼───────────────┤
 │ Vietnamese print statements                                         │ ✅ Giữ nguyên │
 ├─────────────────────────────────────────────────────────────────────┼───────────────┤
 │ Tất cả agent files khác                                             │ ✅ Không đổi  │
 └─────────────────────────────────────────────────────────────────────┴───────────────┘

 ---
 Constants trong manage_agent.py

 MAX_DEBATE_STEPS = 30
     │ Tất cả agent files khác                                             │ ✅ Không đổi  │
     └─────────────────────────────────────────────────────────────────────┴───────────────┘

     ---                                                                                  
     Constants trong manage_agent.py
    
     MAX_DEBATE_STEPS = 30
     MAX_ROUNDS = 5
     MIN_DEBATE_ROUNDS = 2                                                                            
                                                                       
     Các giá trị default này mirror với main.py, nhưng injectable qua constructor (tiện test).         
                
     ---                                                                                               
     Verification
                                                                                                              
     1. Chạy python main.py "Test http://target.com" — pipeline đầy đủ 5 phases phải hoạt động bình thường
     2. Kiểm tra log workspace/.../marl.log — output format giống hệt trước      
     3. Kiểm tra retry logic: nếu Phase 4 trả RETRY, Phase 2 được gọi lại qua manage_agent.run_debate() với
     conversation cũ             
     4. Unit test nhỏ: tạo mock red/blue/exec, kiểm tra run_debate() với mock response trả [APPROVED] sau 2
     rounds 