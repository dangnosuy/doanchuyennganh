# MARL — Tổng quan Hệ thống

> **MARL** = Multi-Agent Red-team LLM  
> Công cụ kiểm thử xâm nhập tự động, sử dụng nhiều LLM-agent tranh luận Red/Blue Team để tìm lỗ hổng **BAC** (Broken Access Control) và **BLF** (Business Logic Flaw) trên web app.

---

## Mục lục

1. [Tổng quan kiến trúc](#1-tổng-quan-kiến-trúc)
2. [Cấu trúc thư mục](#2-cấu-trúc-thư-mục)
3. [Chi tiết từng thành phần](#3-chi-tiết-từng-thành-phần)
4. [Luồng chạy từ đầu đến cuối](#4-luồng-chạy-từ-đầu-đến-cuối)
5. [Hệ thống Tag Routing](#5-hệ-thống-tag-routing)
6. [Kết quả đầu ra](#6-kết-quả-đầu-ra)
7. [Biến môi trường](#7-biến-môi-trường)
8. [Cách chạy](#8-cách-chạy)

---

## 1. Tổng quan kiến trúc

```
                        ┌─────────────────────────────────────────┐
                        │              server/server.py            │
                        │       (GitHub Copilot Proxy — :5000)     │
                        └───────────────────┬─────────────────────┘
                                            │ OpenAI-compatible API
                    ┌───────────────────────▼───────────────────────┐
                    │                   main.py                      │
                    │           (5-Phase Orchestrator)               │
                    └──┬──────────┬──────────┬───────────┬──────────┘
                       │          │          │           │
               Phase 1 │  Phase 2 │  Phase 3 │  Phase 4  │ Phase 5
                       │          │          │           │
              ┌────────▼──┐  ┌────▼────┐  ┌─▼────────┐  │   Report
              │CrawlAgent │  │Red/Blue │  │ExecAgent │  │   .md
              │(recon.md) │  │ Debate  │  │(workflow)│  │
              └────────┬──┘  └────┬────┘  └─────┬────┘  │
                       │          │              │       │
              ┌────────▼──────────▼──────────────▼───────▼─────────┐
              │                  MCPManager                          │
              │  filesystem │ shell │ fetch │ playwright │ web_search│
              └─────────────────────────────────────────────────────┘
                       │          │          │
              ┌────────▼──┐  ┌────▼───┐  ┌──▼──────────────────┐
              │tools/     │  │BFS     │  │   Target Website     │
              │crawler.py │  │Playwright│ │  (Pentest Target)    │
              └───────────┘  └────────┘  └──────────────────────┘
```

**Luồng chính:** User nhập URL → Crawl → Red đề xuất chiến lược → Blue review → Agent thực thi → Red đánh giá → Report
- Gặp URL khác thì có quay lại crawl hay không?
- Sự tương tương tác của các phase. 
- Thiếu tool... => Chuyển qua dạng Dynacmic tool (sau này). 
- Đổi tên -> Để viết báo cáo. 
- ManageAgent (main.py => Quản lý task => Tổng hợp lại Một con điều phối) -> Thêm mới. https://github.com/crewAIInc/crewAI -> Kiến trúc task. 
- Red/Blue => Nên là Claude cho Red, Codex là Blue. 
- Portswigger, Dựng Lab, Bug Bounty. 
- Tổng hợp lên google drive. 
---

## 2. Cấu trúc thư mục

```
MARL/
├── main.py                   # Orchestrator: điều phối 5 phase
├── main_trollllm.py          # Bản thay thế dùng TrollLLM backend
├── mcp_client.py             # Quản lý kết nối 5 MCP servers
│
├── agents/
│   ├── crawl_agent.py        # Phase 1: Thu thập thông tin target
│   ├── red_team.py           # Phase 2: LLM chiến lược gia (viết attack plan)
│   ├── blue_team.py          # Phase 2: LLM reviewer (approve/reject plan)
│   └── exec_agent.py         # Phase 3+4: LLM thực thi + xác minh
│
├── knowledge/
│   └── bac_blf_playbook.py   # 17 attack pattern (8 BAC + 9 BLF)
│
├── server/
│   ├── server.py             # FastAPI proxy: OpenAI SDK → GitHub Copilot
│   └── server_trollllm.py    # Bản thay thế dùng TrollLLM
│
├── shared/
│   └── utils.py              # Regex, text extraction, prompt parsing
│
├── tools/
│   └── crawler.py            # BFS web crawler dùng Playwright
│
├── test/                     # Module legacy (không tự động chạy)
│   ├── debate.py             # Debate cũ (tag format không tương thích)
│   ├── giaotiep.py           # Debate round-based có human-in-the-loop
│   └── toaan.py              # Roleplay tòa án (không liên quan pentest)
│
└── workspace/                # Output mỗi lần chạy (gitignored)
    └── {domain}_{timestamp}/
        ├── recon.md          # Báo cáo trinh sát
        ├── report.md         # Báo cáo cuối cùng
        ├── marl.log          # Log toàn bộ session
        └── *.py              # PoC scripts do Agent tạo ra
```

---

## 3. Chi tiết từng thành phần

### `main.py` — Orchestrator

Điểm vào duy nhất của pipeline. Điều phối 5 phase, quản lý conversation chia sẻ giữa các agent, xử lý retry loop (tối đa `MAX_EXEC_RETRIES=2` lần).

**Constants quan trọng:**

| Hằng số | Giá trị | Ý nghĩa |
|---------|---------|---------|
| `MAX_DEBATE_STEPS` | 30 | Tổng số turn tối đa trong debate (Red + Blue + Agent) |
| `MAX_ROUNDS` | 5 | Số vòng Red↔Blue reject/revise tối đa |
| `MIN_DEBATE_ROUNDS` | 2 | Bắt buộc phải có ít nhất 2 round trước khi approve |
| `MAX_EXEC_RETRIES` | 2 | Số lần Red đề xuất chiến lược mới sau exec fail |

**`TeeLogger`:** Ghi tất cả stdout/stderr đồng thời ra console (có màu ANSI) và file `marl.log` (plain text + timestamp mỗi dòng). Flush ngay lập tức sau mỗi write — sống sót qua Ctrl+C.

---

### `agents/crawl_agent.py` — CrawlAgent

Nhiệm vụ: Thu thập HTTP traffic của target → phân tích bằng LLM → viết `recon.md`.

**Flow nội bộ:**
1. Parse URL + credentials từ user prompt
2. **Anonymous crawl** — chạy `tools/crawler.py` subprocess (BFS, headless Playwright)
3. **Login** (nếu có credentials) — httpx POST tới login page, lấy session cookies
   - Tự phát hiện login URL từ homepage links trước
   - Fallback: thử `/login`, `/my-account`, `/account/login`, `/signin`
   - Tự extract CSRF token từ form HTML
4. **Authenticated crawl** — crawl lại với session cookies inject vào header
5. **LLM analysis** — gửi traffic data tới LLM, LLM dùng `write_file` tool viết `recon.md`

**MCP tools dùng:** `shell`, `fetch`, `filesystem` (3 tools)

**System prompt:** Tập trung hoàn toàn BAC + BLF, format cố định cho `recon.md`.

---

### `tools/crawler.py` — BFS Web Crawler

Playwright BFS crawler, chạy như CLI subprocess (JSON ra stdout, logs ra stderr).

**Cơ chế:**
- `BrowserAgent` class: BFS queue với 3 loại action: `visit`, `click`, `form`
- Intercept **tất cả** HTTP request/response trong domain (bỏ image/css/font/media)
- Extract links từ `<a href>` + regex scan HTML + JS
- Submit forms với dummy data (test, test@example.com, Test123!)
- Blacklist: logout, delete, signout, exit, destroy, remove
- Response body cap 2000 chars mỗi request
- Chạy trong thread riêng để tránh asyncio conflict với MCPManager

**Params:** `max_pages=50`, `max_rounds=2`, `timeout=300s`

---

### `agents/red_team.py` — RedTeamAgent

LLM đóng vai chiến lược gia tấn công. Không có MCP tools — chỉ suy nghĩ và viết chiến lược.

**Chế độ hoạt động:**
- **Debate mode** (Phase 2): Phân tích recon, viết attack workflow theo format chuẩn, gửi Blue review
- **Eval mode** (Phase 4): Đọc execution report, ra verdict SUCCESS/FAIL/RETRY

**Format chiến lược bắt buộc:**
```
=== CHIEN LUOC ===
Loai: <BAC hoặc BLF>
Pattern: <VD: BAC-01>
Mục tiêu: <1 câu>

Buoc 1: <mô tả hành động>
  Method: GET/POST  URL: <url>
  Params: <tên param=giá trị>
  Expect: <kết quả mong đợi>
...
Buoc N (VERIFY): <cách xác nhận thành công>
=== KET THUC CHIEN LUOC ===
```

**Model:** `MARL_RED_MODEL` (default: `gpt-5-mini`)

---

### `agents/blue_team.py` — BlueTeamAgent

LLM đóng vai security reviewer. Không có MCP tools — chỉ review và hỏi Agent.

**Quy tắc bắt buộc:**
- Round 1: **LUÔN REJECT** — đặt ít nhất 2 câu hỏi/yêu cầu cụ thể
- Round 2+: Approve nếu đủ điều kiện, reject nếu vẫn thiếu
- Chỉ 1 tag duy nhất mỗi message: `[AGENT]`, `[REDTEAM]`, hoặc `[APPROVED]`

**Model:** `MARL_BLUE_MODEL` (default: `gpt-5-mini`)

---

### `agents/exec_agent.py` — ExecAgent

LLM thực thi — có đầy đủ 5 MCP tools. Nhận lệnh từ Red/Blue, dùng tools để làm việc.

**4 chế độ hoạt động:**

| Method | Dùng khi | System prompt |
|--------|----------|---------------|
| `answer()` | Red/Blue hỏi câu hỏi về target | `ANSWER_SYSTEM_PROMPT` |
| `answer(read_only=True)` | Red verify kết quả (Phase 4) | `VERIFY_SYSTEM_PROMPT` |
| `execute()` | Chạy PoC Python script | `EXECUTE_SYSTEM_PROMPT` |
| `run_workflow()` | Thực thi attack workflow | `WORKFLOW_SYSTEM_PROMPT` |

**MCP tools dùng:** `shell`, `fetch`, `filesystem`, `playwright`, `web_search` (5 tools)

**Output format:** Kết quả trong `=========SEND=========...=========END-SEND=========` block + routing tag cuối.

**Model:** `MARL_EXECUTOR_MODEL` (default: `gpt-4.1`)

---

### `mcp_client.py` — MCPManager

Quản lý kết nối tới 5 MCP servers, convert tools sang OpenAI function calling format.

| Server | Tools expose | Dùng để |
|--------|-------------|---------|
| `filesystem` | `read_text_file`, `write_file`, `edit_file`, `list_directory`, `search_files` | Đọc/ghi file trong workspace |
| `shell` | `execute_command` | Chạy lệnh terminal (curl, python3, nmap...) |
| `fetch` | `fetch` | GET URL stateless (không cookie) |
| `playwright` | tất cả (navigate, click, fill, screenshot...) | Tương tác trình duyệt có session |
| `web_search` | `web_search` | Tìm kiếm DuckDuckGo (built-in, không MCP session) |

**Cơ chế:** Chạy background asyncio event loop trong thread riêng. Mỗi tool call là `asyncio.run_coroutine_threadsafe` → `.result(timeout)`.

---

### `knowledge/bac_blf_playbook.py` — Attack Playbook

17 attack pattern được bake vào system prompt của cả Red và Blue Team.

| Category | Số pattern | Ví dụ |
|----------|-----------|-------|
| BAC (Broken Access Control) | 8 | BAC-01: IDOR, BAC-02: Privilege Escalation, BAC-03: Horizontal Access... |
| BLF (Business Logic Flaw) | 9 | BLF-01: Price Manipulation, BLF-02: Coupon Abuse, BLF-03: Workflow Skip... |

Mỗi pattern có: `id`, `name`, `indicators` (dấu hiệu trong recon), `technique` (các bước tấn công), `variations` (biến thể khi cách chính thất bại).

---

### `server/server.py` — Copilot Proxy

FastAPI server proxy: chuyển OpenAI SDK calls → GitHub Copilot API.

- Endpoint: `POST /v1/chat/completions`
- Tự động chọn model Copilot phù hợp từ model name (gpt-4.1 → `gpt-4o-2024-11-20`, v.v.)
- Support streaming (`stream=True`)
- Dùng `GITHUB_TOKEN` từ `.env`
- Phải khởi động **trước** khi chạy `main.py`

---

### `shared/utils.py` — Utilities

Chỉ dùng stdlib (không external deps).

| Function | Mô tả |
|----------|-------|
| `extract_send_block(text)` | Lấy nội dung trong `=========SEND=========...=========END-SEND=========` |
| `extract_next_tag(text)` | Tìm routing tag với priority: AGENT > DONE > APPROVED > REDTEAM > BLUETEAM > USER |
| `strip_tag(text)` | Xóa tag khỏi text để hiển thị |
| `truncate(text, limit=15000)` | Cắt text dài: 70% đầu + 25% đuôi |
| `parse_prompt(prompt)` | Extract URL + credentials từ user input |

---

## 4. Luồng chạy từ đầu đến cuối

### Khởi động

```
User chạy: python main.py "https://target.com credentials: admin:password"
                    │
                    ▼
main.py khởi động
├── Parse URL → tạo workspace/target_20240410_123456/
├── Setup TeeLogger → mirror stdout+stderr ra marl.log
└── In banner + thông tin
```

---

### Phase 1: RECON (~5–15 phút)

```
Phase 1: RECON
├── CrawlAgent.__init__()
│   └── Khởi động MCPManager (3 servers: shell, fetch, filesystem)
│
├── CrawlAgent.run(user_prompt)
│   │
│   ├── [Anonymous Crawl]
│   │   └── subprocess: python tools/crawler.py --url TARGET --headless
│   │       ├── BrowserAgent BFS: visit pages, click buttons, submit forms
│   │       ├── Intercept tất cả HTTP request/response trong domain
│   │       └── Output JSON: {http_traffic, cookies, external_links}
│   │
│   ├── [Login] (nếu có credentials)
│   │   ├── httpx GET homepage → tìm login links
│   │   ├── Thử /login, /my-account, /account/login, /signin
│   │   ├── Extract CSRF token từ form
│   │   └── httpx POST credentials → lấy session cookies
│   │
│   ├── [Authenticated Crawl] (nếu login thành công)
│   │   └── Crawl lại với cookies inject vào header
│   │
│   └── [LLM Analysis]
│       ├── Format traffic data thành text (pages, API calls, forms)
│       ├── Gửi tới LLM với RECON_SYSTEM_PROMPT (focus BAC/BLF)
│       ├── LLM dùng write_file tool viết recon.md
│       └── Output: workspace/recon.md
│
└── Phase 1 xong → trả về (target_url, recon_path, recon_content)
```

**Nội dung `recon.md` gồm:**
- Target Overview (auth mechanism, session, roles)
- Access Control Map (bảng so sánh anon vs auth access)
- High-Priority Endpoints (request + response đầy đủ)
- Forms & State-Changing Actions
- Observations & Attack Hypotheses (actionable, cụ thể)

---

### Phase 2: DEBATE — Red vs Blue (~10–30 phút)

**Cơ chế xử lý Steps, Rounds và Quay lui dữ liệu (Backtracking):**

Đây là một trong những cơ chế xương sống nhất của hệ thống MARL để giữ cho 2 LLMs "có não" và "có kỷ luật":

1. **Kiểm soát vòng lặp Vô hạn (30 Steps):** 
   - Một `step` tương đương với 1 lượt phát ngôn của một agent trong phòng chat (ví dụ như Red gửi tin, Blue nhận xét, hay Agent báo cáo kết quả quét thử).
   - *Logic phía sau:* AI rất dễ sinh ra ảo giác dẫn đến việc cãi nhau vô bổ mà không chịu đi đến chốt hạ. Giới hạn `MAX_DEBATE_STEPS = 30` đóng vai trò là "cầu dao". Nếu quá 30 bước mà hai bên Red, Blue vẫn kì kèo không chịu ra lệnh `[APPROVED]`, hệ thống sẽ ném ra cờ `RuntimeError`, ép hủy cả phiên chạy đó để **cắt lỗ token API**, ngăn chặn việc thâm hụt tiền oan.

2. **Ép buộc chất lượng Chiến lược (5 Rounds):**
   - Một `round` chỉ được tính khi Red đệ trình bản thảo kế hoạch và Blue duyệt rồi phản hồi.
   - *Logic phía sau:* Red Team được quyền lên kế hoạch và **sửa nháp tối đa 5 lần**. Nếu sau 5 lần bị Blue Team nhận xét bắt chẹt và trả nợ (`[REDTEAM]`), chiến lược đó bị mặc định coi là thất bại, tránh lãng phí thời gian hệ thống.
   - *Trick trị bệnh AI lười biếng:* Thông thường Blue (LLM) khá dễ dãi khi thấy một kế hoạch hơi xuôi mắt là gật đầu luôn. Đoạn lệnh gài `MIN_DEBATE_ROUNDS = 2` ép hệ thống sẽ đập đi kịch bản `[APPROVED]` của Blue nếu nó xuất hiện ngay ở Vòng 1. Điều này bắt AI Blue phải ngồi lại rặn ra thêm ít nhất vài lỗi hoặc hỏi xoáy thêm Agent, từ đó đảm bảo tính thực tiễn khi đi đánh nhau thật.

3. **Cơ chế Quay lui Dữ liệu (State/Data Backtracking):**
   - *Cách hoạt động:* Hệ thống MARL lưu toàn bộ cuộc giao tiếp thành một mảng dữ liệu JSON duy nhất tên là `conversation`. 
   - Khi chiến lược được chốt ở Phase 2, ExecAgent sẽ xách lệnh chạy đi ném vào web thật (Phase 3). Nếu lệnh báo lỗi (ví dụ HTTP 403 Forbidden chặn mồm), thông tin thất bại này lọt qua Phase 4 đánh giá → Red Team sẽ bật flag đòi `RETRY`.
   - Ngay lập tức, luồng mã chạy ngược về Phase 2. Toàn bộ chuỗi JSON `conversation` bao gồm **(Các log cãi nhau cũ) + (Báo cáo lỗi thực thi vừa xong)** được ném nguyên vẹn vào miệng cả Red và Blue. 
   - *Hiệu quả:* Thay vì tạo trí nhớ mới, AI sẽ tự đọc lại đoạn hội thoại quá khứ. Cụ thể: *"Á à, cách 1 đi qua cổng API `/v1/user` ông lính vừa báo về lại báo lỗi 403, do WAF của nó đổi quy trình rồi. Vậy giờ tôi và ông (Blue) sẽ bàn lại cách 2 đi đường `/my-account` nhé"*. 
   Làm như vậy, hệ thống tự động sinh ra khả năng **thích nghi chống lặp sai lầm**, tránh "căn bệnh" phổ biến của những bộ auto-pentest đời cũ là luôn đâm đầu mãi vào một bức tường đã chặn mình.

```
Phase 2: DEBATE
├── Khởi tạo ExecAgent (5 MCP servers: +playwright, +web_search)
├── Khởi tạo RedTeamAgent (no tools, LLM only)
├── Khởi tạo BlueTeamAgent (no tools, LLM only)
│
└── Debate Loop (tối đa 30 steps, 5 rounds)
    │
    ├── [Turn: RED TEAM]
    │   ├── Red đọc conversation + recon + playbook
    │   ├── Phân tích, đề xuất attack workflow
    │   └── Kết thúc bằng:
    │       ├── [AGENT] → hỏi Agent thêm info → Agent trả về → Red lại nói tiếp
    │       └── [BLUETEAM] → gửi chiến lược cho Blue review
    │
    ├── [Turn: BLUE TEAM]
    │   ├── Blue đọc chiến lược của Red
    │   ├── Review dựa trên recon data + playbook
    │   └── Kết thúc bằng:
    │       ├── [AGENT] → verify endpoint → Agent trả về → Blue tiếp tục
    │       ├── [REDTEAM] → REJECT, yêu cầu Red sửa
    │       └── [APPROVED] → chấp nhận chiến lược
    │
    ├── [Turn: AGENT] (khi Red hoặc Blue gọi [AGENT])
    │   ├── ExecAgent.answer(conversation, caller=last_caller)
    │   ├── Dùng tools (playwright/curl/fetch) tìm thông tin
    │   ├── Kết quả trong SEND block
    │   └── Trả về [REDTEAM] hoặc [BLUETEAM] → tiếp tục lượt của người đã gọi
    │
    ├── [Guardrail: MIN_DEBATE_ROUNDS]
    │   └── Nếu Blue approve trước round 2 → hệ thống inject SYSTEM message
    │       ép Blue tiếp tục debate thêm
    │
    └── Kết thúc khi [APPROVED] và đã đủ MIN_DEBATE_ROUNDS
        └── Trích xuất approved workflow từ message Red Team cuối cùng
```

**Conversation format chia sẻ giữa tất cả agents:**
```python
[
  {"speaker": "USER",    "content": "[USER]: https://target.com credentials: admin:pass"},
  {"speaker": "REDTEAM", "content": "[REDTEAM]: Tôi đề xuất tấn công IDOR tại /api/user/..."},
  {"speaker": "BLUETEAM","content": "[BLUETEAM]: Endpoint /api/user có tồn tại không? [AGENT]"},
  {"speaker": "AGENT",   "content": "[AGENT]: GET /api/user/123 → 200 OK, body: {...}"},
  {"speaker": "BLUETEAM","content": "[BLUETEAM]: Chiến lược hợp lệ. [APPROVED]"},
  ...
]
```

---

### Phase 3: EXECUTION (~5–20 phút)

```
Phase 3: EXECUTION
├── ExecAgent.run_workflow(approved_workflow, conversation)
│   ├── System prompt: WORKFLOW_SYSTEM_PROMPT (step-by-step executor)
│   ├── Agent đọc workflow → thực thi từng bước bằng MCP tools:
│   │   ├── browser_navigate → đến trang login
│   │   ├── browser_fill_form + browser_click → đăng nhập
│   │   ├── browser_evaluate("() => document.cookie") → lấy session cookie
│   │   ├── execute_command("curl -s -b 'session=...' POST data ...") → tấn công
│   │   └── Ghi raw HTTP status + response body mỗi bước
│   │
│   └── Output trong SEND block: execution report (từng bước + evidence)
│
└── exec_report lưu vào conversation + Phase 4
```

**Agent không được:**
- Dùng `fetch()` cho authenticated requests (stateless, không có cookie)
- Thay đổi hay viết lại PoC script
- Diễn giải kết quả — chỉ ghi raw facts

---

### Phase 4: EVALUATION (~2–5 phút)

```
Phase 4: EVALUATION
├── Red Team switch sang eval mode (RED_EVAL_PROMPT)
├── Inject exec_report vào conversation
│
└── Evaluation Loop (tối đa 5 steps)
    ├── [RED TEAM] đọc execution report → ra verdict
    │   ├── [DONE] + SUCCESS: exploit thành công, có evidence rõ ràng
    │   ├── [DONE] + FAIL: đã thử hết cách, không khai thác được
    │   ├── [AGENT] → verify read-only (chỉ GET, không POST/exploit mới)
    │   └── [BLUETEAM] → muốn retry với chiến lược mới
    │
    ├── Nếu [AGENT]: ExecAgent.answer(read_only=True)
    │   ├── System prompt: VERIFY_SYSTEM_PROMPT
    │   ├── Chỉ được: GET requests, browser_navigate, browser_snapshot
    │   └── KHÔNG được: POST, form submit, login, exploit
    │
    └── Kết thúc:
        ├── verdict = "SUCCESS" hoặc "FAIL" → Phase 5
        └── verdict = "RETRY" → quay lại Phase 2 (tối đa MAX_EXEC_RETRIES lần)
```

**Mục tiêu tối cao của Phase 4:**
Giải quyết bài toán "Ai là người kiểm chứng việc hack có thực sự thành công hay không?" (Tránh tình trạng AI bị ảo giác, thấy HTTP 200 OK là vội kết luận đã hack được dù CSDL chưa hề thay đổi).
- **RED TEAM (Giám khảo):** Lúc này Red Team bị tước quyền "Lên chiến lược", bị ép chuyển sang Eval Mode (`RED_EVAL_PROMPT`). Nhiệm vụ duy nhất của nó là **đọc chuỗi Log (mã HTML, JSON trả về...)** từ Phase 3 và phân tích xem tấn công có thực sự thành công không.
- **EXEC AGENT (Người xác minh):** Nếu Red Team thấy Log báo thành công nhưng chưa tin (ví dụ: Log báo đổi giá giỏ hàng thành công, nhưng chưa biết giá thật sự đã đổi chưa), Red sẽ gọi Agent đi xác minh. Lúc này Agent bị khóa tay bằng **Read-Only Mode** (chỉ được GET, xem trang, tuyệt đối không được POST/Click tấn công thêm). Agent lăng xăng đi load lại trang, đọc giá tiền mang về cho Red.
- **XUẤT REPORT:** Cuối cùng, toàn bộ phán quyết (Verdict: SUCCESS/FAIL/RETRY) ở bước này hoàn toàn do mớ logic phân tích "bằng chứng thép" của LLM Red Team quyết định. Report cuối cùng (Phase 5) sẽ trích xuất thẳng những nhận xét này.

---

### Phase 5: REPORT

```
Phase 5: REPORT
├── In tóm tắt ra console: target, verdict, debate rounds
├── Tạo workspace/report.md gồm:
│   ├── Target URL + Verdict (✅ SUCCESS / ❌ FAIL)
│   ├── Số debate rounds
│   ├── Approved Attack Workflow (chiến lược đã được Blue duyệt)
│   ├── Execution Report (output từ Agent thực thi)
│   └── Red Team Evaluation (nhận xét cuối cùng)
└── In đường dẫn log file ra console
```

---

### Retry Loop (nếu RETRY)

```
Nếu verdict = "RETRY" và còn lần retry:
├── Red Team được giữ nguyên (conversation history không xóa)
├── Blue Team tạo mới (instance mới)
├── Quay lại Phase 2 với conversation cũ (Red nhớ lịch sử)
└── Tối đa MAX_EXEC_RETRIES = 2 lần retry (tổng 3 lần thử)
```

---

## 5. Hệ thống Tag Routing

Đây là cơ chế điều phối trung tâm của toàn bộ hệ thống:

```
Tag          │ Ai dùng           │ Ý nghĩa
─────────────┼───────────────────┼────────────────────────────────────
[AGENT]      │ Red, Blue         │ Gọi ExecAgent tìm thêm info
[BLUETEAM]   │ Red, Agent        │ Gửi về cho Blue xử lý tiếp
[REDTEAM]    │ Blue, Agent       │ Gửi về cho Red xử lý tiếp (REJECT)
[APPROVED]   │ Blue              │ Chấp nhận chiến lược → Phase 3
[DONE]       │ Red (Phase 4)     │ Kết thúc evaluation
[USER]       │ (reserved)        │ Không dùng trong pipeline hiện tại
```

**Priority** khi nhiều tag xuất hiện: `AGENT > DONE > APPROVED > REDTEAM > BLUETEAM > USER`

**Tag retry:** Nếu LLM không kết thúc bằng tag → nudge tối đa 2 lần → force append tag mặc định.

---

## 6. Kết quả đầu ra

Mỗi lần chạy tạo thư mục `workspace/{domain}_{timestamp}/`:

```
workspace/target.com_20240410_123456/
├── recon.md          # Báo cáo trinh sát (viết bởi CrawlAgent + LLM)
│                     # Nội dung: access control map, high-priority endpoints,
│                     # forms, attack hypotheses
│
├── report.md         # Báo cáo pentest cuối cùng
│                     # Nội dung: verdict, workflow, exec output, evaluation
│
├── marl.log          # Log toàn bộ session (text thuần, có timestamp)
│                     # Mọi thứ in ra console đều vào đây
│
└── *.py, *.txt ...   # PoC scripts và evidence files do Agent tạo ra
```

**Verdict có thể là:**
- `✅ SUCCESS` — Exploit thành công, có evidence rõ ràng từ server response
- `❌ FAIL` — Không khai thác được sau tất cả các lần thử
- `❌ REJECTED` — Debate không đi đến thống nhất (hết rounds)

---

## 7. Biến môi trường

File `.env` ở project root (không commit):

```bash
GITHUB_TOKEN=gho_...          # GitHub token dùng cho Copilot API (bắt buộc)
MARL_SERVER_URL=http://127.0.0.1:5000/v1  # URL proxy server
MARL_EXECUTOR_MODEL=gpt-4.1   # Model cho ExecAgent + CrawlAgent
MARL_CRAWL_MODEL=gpt-4.1      # Override model riêng cho CrawlAgent (fallback về EXECUTOR)
MARL_RED_MODEL=gpt-5-mini     # Model cho Red Team
MARL_BLUE_MODEL=gpt-5-mini    # Model cho Blue Team
MARL_DEBUG=1                  # Bật verbose logging cho CrawlAgent (tùy chọn)
PORT=5000                     # Port cho proxy server (tùy chọn)
```

---

## 8. Cách chạy

### Bước 1: Khởi động proxy server (terminal riêng, để chạy nền)

```bash
python server/server.py
# Server lắng nghe tại http://127.0.0.1:5000
```

### Bước 2: Chạy pipeline

```bash
# Không có credentials (anonymous only)
python main.py "https://target.com"

# Có credentials (crawl anonymous + authenticated)
python main.py "https://target.com credentials: admin:password"

# Hoặc chạy rồi nhập URL khi được hỏi
python main.py
```

### Chạy standalone từng agent

```bash
# Chỉ crawl và viết recon.md
python agents/crawl_agent.py "https://target.com/"
python agents/crawl_agent.py "https://target.com/ credentials: admin:password"

# Chỉ crawl BFS (JSON output)
python tools/crawler.py --url https://target.com --max-pages 50 --max-rounds 2
```

### Debug mode

```bash
MARL_DEBUG=1 python agents/crawl_agent.py "https://target.com/"
# In thêm: traffic breakdown, cookie changes, login form analysis, URL discovery
```

---

## Ghi chú kỹ thuật quan trọng

### Session/Cookie trong ExecAgent

- `fetch()` tool là **stateless GET** — không mang cookie, không có session
- Sau khi login bằng browser, phải lấy cookie qua `browser_evaluate("() => document.cookie")`
- **Tất cả** request sau đó dùng `curl -b 'session=COOKIE_VALUE' URL` qua `execute_command`
- Không bao giờ dùng `fetch()` cho authenticated requests

### Anti-Hallucination

Tất cả system prompts đều có section **CHỐNG AO TƯỞNG** bắt buộc agent:
- Chỉ báo cáo data **thật** từ tool output
- Trích dẫn **nguyên văn** HTML/response snippet
- Ghi "KHÔNG XÁC ĐỊNH" nếu không chắc
- Không tuyên bố có lỗ hổng nếu không có evidence cụ thể

### Tool Loop Safety Mechanisms

`_tool_loop()` trong cả CrawlAgent và ExecAgent có các cơ chế bảo vệ:
- `tool_choice="required"` ở round 0: buộc dùng tool, tránh LLM "lên kế hoạch" thay vì làm
- Detect repeated tool call (3x cùng args → force summary)
- Consecutive errors (3 lần fail → force tổng kết)
- Nudge counter (3 lần text không có tag → force append tag)
- Approaching limit (round >= 47/47 → nudge "tổng kết ngay")

### Known Issues

- `strip_tag()` bị duplicate ở `shared/utils.py` và `main.py` với regex khác nhau
- `mcp_client.py` có unreachable code sau `return` trong `_ddg_search_html_fallback()`
- CrawlAgent login chỉ thử 4 hardcoded paths — URL login không chuẩn sẽ fail
- `fetch()` tool stateless — LLM hay nhầm dùng cho authenticated requests
- Không có token counting — `recon.md` lớn có thể fill context window LLM silently
- Không có `requirements.txt` — dependencies không được khai báo chính thức

---

---

# 📋 Lịch sử thay đổi kiến trúc

---

## [v2] Thêm ManageAgent — Bộ điều phối thông minh thay thế hard-coded orchestration

> **Ngày:** 2026-04-18  
> **Trạng thái:** Đã tích hợp vào `main.py`

---

### Vấn đề của kiến trúc cũ (v1)

Trong phiên bản đầu, `main.py` đóng vai orchestrator bằng cách hard-code toàn bộ luồng chạy:

```python
# main.py cũ — logic cứng nhắc
for attempt in range(MAX_EXEC_RETRIES + 1):
    approved_workflow = phase_debate(...)     # Red ↔ Blue theo vòng cố định
    exec_report       = phase_execute(...)   # luôn chạy sau approve
    verdict           = phase_evaluate(...)  # Red đọc, ra verdict
    if verdict != "RETRY":
        break
phase_report(...)
```

**Hạn chế:**
- Thứ tự phase là **cố định** — không thể linh hoạt (ví dụ: VERIFY xen giữa EXECUTE → EVALUATE)
- Không có ai "hiểu ngữ cảnh" để hướng dẫn agent con trước mỗi bước
- Retry loop đơn giản: đếm số lần thử, không xét lý do thất bại
- `main.py` gánh cả orchestration + logging + CLI → quá nhiều trách nhiệm

---

### Giải pháp: ManageAgent (v2)

Thêm một LLM agent mới đóng vai **"Sếp"** — thay thế toàn bộ `phase_debate / phase_execute / phase_evaluate / phase_report` trong `main.py`.

Mỗi **tick**, Manager:
1. Nhận snapshot trạng thái hiện tại (round, attempts, có workflow chưa, có exec report chưa...)
2. Đọc 12 message gần nhất trong conversation
3. Gọi LLM → quyết định `[ACTION: XXX]` + viết `<note>` hướng dẫn cụ thể cho agent tiếp theo
4. Inject `<note>` vào conversation
5. Gọi đúng agent con theo action

---

### Sơ đồ kiến trúc mới (v2)

```
python main.py "https://target.com credentials: admin:password"
│
├─ [Phase 1: RECON]  ← không đổi
│   └── CrawlAgent → recon.md
│
└─ [Phase 2–5: ManageAgent.run(conversation)]
     │
     │   ┌──────────────────────────────────────────────────────┐
     │   │                MANAGE AGENT (LLM)                    │
     │   │                                                      │
     │   │  state: round_num, exec_attempts, red_spoke,         │
     │   │         blue_spoke, has_workflow, has_exec           │
     │   │                                                      │
     │   │  mỗi tick:                                           │
     │   │  conversation[-12:] + state → LLM → [ACTION: X]     │
     │   │  + <note> inject vào conversation                    │
     │   └──────────────┬───────────────────────────────────────┘
     │                  │
     │      ┌───────────▼──────────────────────────────────┐
     │      │         ROUTING theo ACTION tag               │
     │      └──┬──────┬──────┬────────┬────────┬───────────┘
     │         │      │      │        │        │
     │   DEBATE_RED  DEBATE  VERIFY  EXECUTE  EVALUATE
     │         │    _BLUE    │        │        │
     │    RedTeam   BlueTeam  Exec    Exec    RedTeam
     │    .respond  .respond  .answer .run_   (eval
     │                       (r-o)   workflow  mode)
     │         │      │
     │         └──────┘
     │      (round_num tăng khi cả hai đã nói)
     │
     ├─ RETRY_DEBATE → reset Blue (instance mới), reset round state
     ├─ REPORT_SUCCESS → _write_report(verdict="SUCCESS") → return
     └─ REPORT_FAIL    → _write_report(verdict="FAIL")    → return
```

---

### Bảng ACTION tags của ManageAgent

| Action | Agent được gọi | Khi nào Manager dùng |
|--------|---------------|----------------------|
| `DEBATE_RED` | `RedTeamAgent.respond()` | Bắt đầu debate, hoặc Blue vừa reject |
| `DEBATE_BLUE` | `BlueTeamAgent.respond()` | Red vừa nộp chiến lược |
| `VERIFY` | `ExecAgent.answer(read_only=False)` | Cần kiểm tra endpoint trước khi execute |
| `EXECUTE` | `ExecAgent.run_workflow()` | Blue đã approve + đủ min rounds |
| `EVALUATE` | `RedTeamAgent.respond()` (eval mode) | Exec vừa chạy xong |
| `RETRY_DEBATE` | *(reset state)* | Red muốn thử chiến lược mới + còn retry |
| `REPORT_SUCCESS` | `_write_report()` | Red confirm thành công |
| `REPORT_FAIL` | `_write_report()` | Hết retry hoặc hết rounds |

---

### So sánh v1 vs v2

| Tiêu chí | v1 (main.py hard-coded) | v2 (ManageAgent) |
|----------|------------------------|-----------------|
| **Ai quyết định bước tiếp theo?** | `if/elif` cứng trong Python | LLM đọc context, lý luận |
| **Hướng dẫn agent con** | Không có | Manager inject `<note>` mỗi tick |
| **Retry logic** | Đếm số lần, không xét lý do | Manager xét toàn bộ context trước khi retry |
| **Thứ tự phase** | Cố định: 2→3→4→5 | Linh hoạt: VERIFY có thể xen giữa bất kỳ đâu |
| **Khi LLM fail** | Crash hoặc fallback không kiểm soát | Deterministic fallback trong `_extract_action()` |
| **main.py** | ~400 dòng, ôm toàn bộ logic | ~80 dòng, chỉ Phase 1 + khởi động ManageAgent |
| **Guardrail** | Hard-coded rounds/retries | Hard guardrail (Python) + Soft guardrail (LLM-aware) |
| **Chi phí LLM** | Không thêm | +1 LLM call/tick (gpt-5-mini, 512 tokens) |

---

### Guardrail kép trong v2

ManageAgent có **2 lớp** bảo vệ:

**Lớp 1 — Hard guardrail (Python, không qua LLM):**
```python
if round_num >= self.max_rounds and not exec_report:
    → buộc REPORT_FAIL
if exec_attempts > self.max_exec_retries and exec_report:
    → buộc REPORT_FAIL
if tick >= MAX_TICKS (80):
    → buộc REPORT_FAIL
```

**Lớp 2 — Soft guardrail (nhúng trong system prompt của Manager):**
- "Không approve trước khi đủ `min_rounds`"
- "Không EXECUTE khi chưa có approval từ Blue"
- "RETRY_DEBATE chỉ khi còn lần retry"

**Lớp 3 — Guardrail con trong DEBATE_BLUE:**
```python
# Blue emit [APPROVED] quá sớm → inject SYSTEM message ép tiếp tục
if tag == "APPROVED" and (round_num + 1) < self.min_debate_rounds:
    → inject "[SYSTEM]: Chưa đủ số round tối thiểu..."
```

---

### Fallback khi Manager LLM fail

Nếu LLM không emit action hợp lệ, `_extract_action()` fallback deterministic:

```
has_exec=True          → EVALUATE
has_workflow, no exec  → EXECUTE
red_spoke=True         → DEBATE_BLUE
default                → DEBATE_RED
```

Pipeline không bao giờ bị kẹt dù Manager LLM crash hoàn toàn.

---

### Các file thay đổi và thêm mới

#### 🆕 File mới

| File | Mô tả |
|------|-------|
| `agents/manage_agent.py` | ManageAgent — LLM orchestrator mới. Chứa toàn bộ `_run_loop`, `_decide`, `_extract_action`, `_write_report`. Tự khởi tạo Red/Blue/ExecAgent bên trong. |

#### ✏️ File sửa đổi

| File | Thay đổi |
|------|---------|
| `main.py` | **Xóa hoàn toàn** các hàm `phase_debate()`, `phase_execute()`, `phase_evaluate()`, `phase_report()` và retry loop. **Thêm** `from agents.manage_agent import ManageAgent`. Phase 2–5 giờ chỉ còn 5 dòng: khởi tạo `ManageAgent` → gọi `manage_agent.run(conversation)`. Phase 1 (Recon) giữ nguyên. |

#### 📦 Biến môi trường mới

| Biến | Default | Dùng trong |
|------|---------|-----------|
| `MARL_MANAGER_MODEL` | `gpt-5-mini` | `agents/manage_agent.py` — model cho Manager LLM |

#### ⚙️ Hằng số mới trong ManageAgent

| Hằng số | Giá trị | Ý nghĩa |
|---------|---------|---------|
| `MAX_TICKS` | 80 | Tổng số tick tối đa cho toàn pipeline (hard limit tuyệt đối) |
| `MAX_DEBATE_STEPS` | 30 | Giữ nguyên từ v1 |
| `MAX_ROUNDS` | 5 | Giữ nguyên từ v1 |
| `MIN_DEBATE_ROUNDS` | 2 | Giữ nguyên từ v1 |
| `MAX_EXEC_RETRIES` | 2 | Giữ nguyên từ v1 |

> **Lưu ý:** Các constants này được định nghĩa lại trong `manage_agent.py` thay vì đọc từ `main.py`. `main.py` vẫn giữ bản sao nhưng không còn được dùng trực tiếp trong pipeline.

---

### Ghi chú cho đồ án

- ManageAgent áp dụng pattern **"LLM-as-orchestrator"** — thay vì code cứng logic điều phối, dùng LLM để đưa ra quyết định runtime dựa trên context thực tế.
- Kiến trúc này tương đồng với hướng tiếp cận của **CrewAI** (manager agent điều phối crew) và **LangGraph** (state machine với LLM-driven transitions), nhưng được implement thủ công hoàn toàn không phụ thuộc framework.
- Điểm khác biệt so với CrewAI: Manager của MARL nhận **toàn bộ conversation history** thay vì chỉ nhận task output — cho phép ra quyết định dựa trên chất lượng tranh luận chứ không chỉ kết quả công việc.
- Chi phí: thêm ~1 LLM call nhỏ (gpt-5-mini, ≤512 tokens) mỗi tick. Với pipeline 20–30 tick, tổng overhead không đáng kể so với các lượt gọi ExecAgent/CrawlAgent.



- Cho nó một share memory -> Cho việc quản lý task để định danh từng con rồi từng con có thể tham khảo resource thì nó sẽ lấy phần đó về
- Single gì gì đó nên là sai. Rồi context có thể bị cắt rồi sai => Rồi bỏ sót?
- Hiện thì con Manage Agent là con quyết định hết các luồng chạy, luồng thực thi.
+ Tách ra thêm 1 con AI để policy -> Action nào ở state nào? Khi nào được execute -> Khi nào làm việc gì, ... để giảm phụ thuộc vào con manage agent sai vặt sai là có 1 con AI Policy để kiểm tra lại.
+ Định nghĩa context, persistence 
+ Thu thập dữ liệu để khai thác BAC/BLF (Portswigger, CVE, NIST, Mitre ...) CTI?
+ Tự thu thập playbook -> Framework chung để crawll về và parse định dạng 
- Kết quả khi chạy ra cuối cùng thì thông số nào? Con số nào được tính => Khóa luận mới cần kết quả (Relative Network). Với ngữ cảnh của tôi thì có thể làm thế nào? Rồi sửa ra sao?...
- Nếu có 1 số nhược điểm thì có phương pháp nào đó tức là giải quyết research gap nó như thế nào.
- Sau này chạy được, thực nghiệm được dựa trên số liệu cụ thể.


