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
- Phân tích bug dossier + recon, viết strategy ngắn và execution shot plan để Blue review.
- Strategy phải kèm điều kiện verify tối thiểu để Exec tự kiểm chứng trong exploit script.

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
=== EXECUTION SHOT PLAN ===
Shot 1: <baseline/probe/verify tối thiểu>
=== END EXECUTION SHOT PLAN ===
=== KET THUC CHIEN LUOC ===
```

**Model:** `MARL_RED_MODEL` (default: `gpt-5-mini`)

---

### `agents/blue_team.py` — BlueTeamAgent

LLM đóng vai security reviewer. Không có MCP tools — chỉ review strategy/shot plan của Red trước khi Exec chạy.

**Quy tắc bắt buộc:**
- Approve nếu strategy đủ rõ, khả thi và có verify condition tối thiểu.
- Reject nếu strategy thiếu endpoint/payload/session/điều kiện thành công.
- Không review evidence sau Exec; Manager sẽ đọc Exec verdict/artifact để quyết định.

**Model:** `MARL_BLUE_MODEL` (default: `gpt-5-mini`)

---

### `agents/exec_agent.py` — ExecAgent

LLM thực thi — có đầy đủ MCP tools. Nhận strategy đã được Blue approve từ Manager và sinh Python exploit.

**Chế độ hoạt động chính:**

| Method | Dùng khi | System prompt |
|--------|----------|---------------|
| `run_workflow()` | Thực thi strategy đã approve | `WORKFLOW_SCRIPT_PROMPT` |
| `answer()` | Hỏi raw fact về target khi cần debug/manual | `ANSWER_SYSTEM_PROMPT` |
| `execute()` | Legacy: chạy PoC Python script có sẵn | `EXECUTE_SYSTEM_PROMPT` |

**MCP tools dùng:** `shell`, `fetch`, `filesystem`, `playwright`, `web_search` (5 tools)

**Output format:** Kết quả trong `=========SEND=========...=========END-SEND=========` block. Script exploit tự in `SHOT_RESULT`, `EVIDENCE_SUMMARY`, `VERIFY_COMPLETED`, `FINAL`.

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
│   ├── Chuẩn bị session/cookie từ crawl artifact hoặc login deterministic
│   ├── Sinh 1 Python exploit theo strategy đã được Blue approve
│   ├── Script tự chạy baseline/probe/verify cần thiết
│   ├── Script in SHOT_RESULT / EVIDENCE_SUMMARY / FINAL
│   └── Lưu raw request/response/result.json vào exploit_state/<BUG>/
│   │
│   └── Output trong SEND block: script path + execution output + evidence
│
└── exec_report lưu vào conversation + Manager decision
```

**Agent cần làm:**
- Dùng cookie/session đã có nếu workflow cần auth
- Ghi evidence tối thiểu gắn với hypothesis của bug
- Không hardcode endpoint/marker của riêng một lab; phải lấy từ recon, dossier và strategy hiện tại
- Nếu evidence đã đủ chứng minh BAC/BLF thì in `FINAL: EXPLOITED`

---

### Phase 4: MANAGER DECISION (~1–2 phút)

```
Phase 4: MANAGER DECISION
├── Manager đọc Exec SEND block
├── Manager đọc result.json / FINAL / SUCCESS / evidence summary
│
└── Quyết định:
    ├── EXPLOITED  → NEXT_BUG
    ├── SCRIPT_ERROR/PARTIAL → RETRY_EXEC tối đa 1 lần
    └── FAILED/NO_SIGNAL → STOP_BUG
```

**Mục tiêu tối cao của Phase 4:**
Giữ pipeline đơn giản và đúng trọng tâm đồ án: Red/Blue debate tạo chiến lược, Exec tự khai thác/tự verify trong exploit, Manager quyết định điều phối. Hệ thống ưu tiên proof tối thiểu đủ cho hypothesis để tránh overfitting vào một lab cụ thể. Vì vậy có thể chấp nhận false positive cao hơn, nhưng đổi lại agent không bị kẹt vì đòi thêm endpoint/tác động phụ không cần thiết.

---

### Phase 5: REPORT

```
Phase 5: REPORT
├── In tóm tắt ra console: target, số bug, trạng thái từng bug
├── Tạo workspace/report.md gồm:
│   ├── Finding exploited nếu có
│   ├── Strategy đã được Blue duyệt
│   ├── PoC Python script / artifact paths
│   ├── Execution evidence từ Exec
│   └── Bug chưa khai thác được / false positive
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

## [v3] Multi-account Crawl + LLM Prompt Parsing

> **Ngày:** 2026-04-18  
> **Trạng thái:** Đã tích hợp

---

### Vấn đề của v2

`parse_prompt()` dùng regex cứng chỉ lấy được **1 cặp credentials**. CrawlAgent chỉ login 1 account, authenticated crawl 1 lần. Hệ quả:
- Không thể phát hiện **Horizontal Privilege Escalation** (User A xem data của User B)
- Không thể kiểm tra **IDOR chéo tài khoản** (cần session của 2 user khác nhau)
- Tỷ lệ phát hiện BAC cross-account gần 0% trên các bài Lab yêu cầu 2 accounts

---

### Giải pháp v3

Thay regex parse bằng **LLM parse** → nhận prompt tự do với bất kỳ số lượng accounts → loop crawl từng account → `recon.md` có section **Session Comparison**.

---

### Luồng mới trong Phase 1 (RECON)

```
CrawlAgent.run(user_prompt)
│
├─ [LLM Parse Prompt]  ← MỚI
│   └── parse_prompt_llm(prompt, client)
│       ├── Gọi gpt-5-mini (512 tokens, temperature=0)
│       ├── Trả về JSON: {url, credentials: [...], focus}
│       └── Fallback: parse_prompt() regex cũ nếu LLM fail
│
├─ [Phase 1: Anonymous crawl]  ← không đổi
│   └── tools/crawler.py subprocess
│
├─ [Phase 2+3: Loop qua từng account]  ← MỚI
│   ├── for cred in credentials_list:
│   │   ├── _login(url, cred)  → cookies
│   │   └── _run_crawler(url, cookie_header)  → auth_data
│   └── auth_sessions = [{"label", "cookies", "data"}, ...]
│
└─ [Phase 4: LLM analysis]
    ├── Format: ANONYMOUS + mỗi AUTHENTICATED session có label riêng
    └── RECON_SYSTEM_PROMPT: thêm section Session Comparison
```

---

### Input format mới (tự do)

LLM hiểu bất kỳ cách diễn đạt nào:

```bash
# 1 account — format cũ vẫn hoạt động
python main.py "https://target.com credentials: admin:password"

# 2 accounts — format mới
python main.py "Test https://target.com tài khoản 1: wiener/peter tài khoản 2: carlos/montoya"

# Có focus
python main.py "https://target.com account1: admin/abc account2: user/xyz, focus IDOR"

# Tiếng Anh tự do
python main.py "https://target.com user admin pass secret, also user carlos pass hunter2"
```

---

### Output mới trong recon.md

**Trước (v2):** 2 section — ANONYMOUS + AUTHENTICATED

**Sau (v3):** N+1 section — ANONYMOUS + mỗi account có header riêng:
```
==============================
AUTHENTICATED CRAWL — account: wiener
==============================
[traffic data của wiener...]

==============================
AUTHENTICATED CRAWL — account: carlos
==============================
[traffic data của carlos...]
```

**Thêm section Session Comparison** (chỉ khi ≥2 accounts):
```markdown
## Session Comparison
| Endpoint | Method | wiener | carlos | Nhận xét BAC |
|----------|--------|--------|--------|--------------|
| /api/user/profile | GET | 200 → {id:1} | 200 → {id:2} | Thử wiener xem profile của carlos |
```

---

### Files thay đổi

#### ✏️ File sửa đổi

| File | Thay đổi |
|------|---------|
| `shared/utils.py` | Thêm `TypedDict`: `CredentialEntry`, `ParsedTarget`. Thêm hàm `parse_prompt_llm()` + `_PARSE_SYSTEM_PROMPT`. `parse_prompt()` cũ **giữ nguyên** để backward-compat. |
| `agents/crawl_agent.py` | `run()` gọi `parse_prompt_llm()` thay parse_prompt(), loop qua `credentials_list`. `_login()` nhận `CredentialEntry` (thêm field `label` cho log). `_analyze()` nhận `auth_sessions: list[dict]` thay vì `auth_data: dict`. `RECON_SYSTEM_PROMPT` thêm Session Comparison section và hướng dẫn multi-account. |

#### 📦 Biến môi trường mới (tuỳ chọn)

| Biến | Default | Ý nghĩa |
|------|---------|---------|
| `MARL_PARSER_MODEL` | fallback về `MARL_RED_MODEL` → `gpt-5-mini` | Model dùng cho LLM parse prompt |

---

### Backward compatibility

| Trường hợp | Hành vi |
|---|---|
| Prompt 1 account format cũ `"credentials: admin:pass"` | LLM parse → `credentials_list` có 1 phần tử → hoạt động y hệt v2 |
| Prompt không có credentials | `credentials_list = []` → skip login/auth crawl → chỉ anonymous |
| LLM parse fail (API down) | Fallback `parse_prompt()` regex → tối đa 1 account, không crash |
| `main.py` | Không thay đổi gì — vẫn gọi `CrawlAgent.run()` như cũ |

---

### Ghi chú cho đồ án

- Đây là ví dụ **"LLM thay thế regex cứng"** — dùng ngôn ngữ tự nhiên làm interface thay vì bắt user học format.
- Thay đổi nhỏ về code (2 file) nhưng mở ra toàn bộ khả năng kiểm thử BAC cross-account — một lớp lỗ hổng quan trọng trong PortSwigger Web Security Academy.
- Chi phí: +1 LLM call nhỏ (512 tokens) ở đầu mỗi pipeline. Không đáng kể so với tổng.
- `CredentialEntry` và `ParsedTarget` là `TypedDict` → type-safe, dễ mở rộng sau này (ví dụ thêm `role`, `2fa_secret`...).

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
- Thứ tự phase là **cố định** — không thể linh hoạt khi cần retry Red/Blue/Exec theo lý do lỗi cụ thể
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
     │   DEBATE_RED  DEBATE_BLUE  EXECUTE_BUG  NEXT_BUG
     │         │          │             │          │
     │    RedTeam     BlueTeam       Exec      Manager
     │    .respond    .respond       .run_     decision
     │                              workflow
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
| `EXECUTE_BUG` | `ExecAgent.run_workflow()` | Blue đã approve strategy hiện tại |
| `RETRY_EXEC` | `ExecAgent.run_workflow()` | Script/runtime lỗi hoặc partial, còn retry budget |
| `RETRY_RED` | `RedTeamAgent.respond()` | Strategy sai hướng hoặc Blue reject |
| `STOP_BUG` | *(Manager state)* | Candidate không có tín hiệu hoặc hết retry |
| `NEXT_BUG` | *(Manager state)* | Bug đã exploited hoặc đã stop |
| `REPORT_SUCCESS` | `_write_report_success()` | Có ít nhất một bug `status=EXPLOITED` |
| `REPORT_FAIL` | `_write_report_fail()` | Không có bug exploited |

---

### So sánh v1 vs v2

| Tiêu chí | v1 (main.py hard-coded) | v2 (ManageAgent) |
|----------|------------------------|-----------------|
| **Ai quyết định bước tiếp theo?** | `if/elif` cứng trong Python | LLM đọc context, lý luận |
| **Hướng dẫn agent con** | Không có | Manager inject `<note>` mỗi tick |
| **Retry logic** | Đếm số lần, không xét lý do | Manager xét toàn bộ context trước khi retry |
| **Thứ tự phase** | Cố định: 2→3→4→5 | Manager điều phối per-bug theo state Red/Blue/Exec |
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
exec_result=EXPLOITED  → NEXT_BUG
exec_result=PARTIAL    → RETRY_EXEC hoặc STOP_BUG
has_workflow, no exec  → EXECUTE_BUG
red_strategy=True      → DEBATE_BLUE
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



Thành phần 1: Shared Memory Store (Context & Persistence)                                                   
                                                                                                              
  Ý tưởng: Thay vì 1 flat list conversation, tạo một MemoryStore có cấu trúc, mỗi agent chỉ đọc phần liên quan
   đến mình.                                                                                                  
                                                                  
  workspace/{run_dir}/                                                                                        
    memory/                                                       
      task_registry.json       ← Đăng ký task, agent, trạng thái                                              
      recon.md                 ← Giữ nguyên (Phase 1 output)                                                  
      findings.json            ← Các phát hiện có cấu trúc (structured facts)                                 
      conversation_full.jsonl  ← Full log (append-only, không bao giờ đọc toàn bộ)                            
      conversation_summary.md  ← Summary được cập nhật rolling                                                
      agent_scratchpad/                                                                                       
        red_notes.md           ← Red tự ghi notes riêng                                                       
        blue_notes.md                                                                                         
        exec_notes.md                                             
                                                                                                              
  Task Registry — Định danh từng task:                                                                        
  {
    "task_id": "T001",                                                                                        
    "agent": "REDTEAM",                                           
    "phase": "DEBATE", 
    "status": "in_progress",
    "assigned_at": "2026-04-23T10:00:00",
    "context_snapshot": "Round 2, chiến lược BAC-IDOR",                                                       
    "artifacts": ["workflow_v2.md"]                    
  }                                                                                                           
                                                                  
  Cơ chế RAG đơn giản (không cần vector DB):                                                                  
  - Mỗi agent trước khi nhận task → query MemoryStore.get_relevant(agent_id, keywords)                        
  - Store tìm trong findings.json + conversation_summary.md theo keywords                                     
  - Trả về "memory chunk" nhỏ thay vì toàn bộ history                   

 Thành phần 2: Policy Agent (AI Guardrail)                                                                   
                                                                                                              
  Ý tưởng: Policy là một LLM call nhỏ (cheap model) chạy trước khi ManageAgent execute action. Nó trả về ALLOW
   / BLOCK / SUGGEST.                                                                                         
   
  ManageAgent._decide() → action = "EXECUTE_BUG"                                                                  
      ↓                                                           
  PolicyAgent.validate(action, state, conversation_summary)
      ↓
  {
    "verdict": "BLOCK",
    "reason": "Blue chưa approve workflow",
    "suggest": "DEBATE_BLUE"                                                                                       
  }
      ↓                                                                                                       
  ManageAgent nhận → override action = "DEBATE_BLUE"                   

  Luật Policy (baked vào system prompt):
  STATE: workflow exists = True, exec_attempts = 0, blue_approved = False
  ACTION: EXECUTE_BUG                                                        
  → BLOCK: Phải có [APPROVED] từ Blue trước khi EXECUTE                                                       
                                                       
  STATE: exec_attempts >= 2, no DONE                                                                          
  ACTION: EXECUTE                                                                                             
  → BLOCK: Đã thử 2 lần, phải REPORT với verdict FAIL
                                                                                                              
  STATE: round_num < min_debate_rounds                            
  ACTION: EXECUTE                     
  → BLOCK: Chưa đủ vòng debate tối thiểu
                                        
  STATE: red_mode = EVAL (sau switch_to_eval_mode)
  ACTION: DEBATE_RED (với mục đích viết chiến lược mới)                                                       
  → BLOCK: Red đã chuyển sang eval mode, không thể debate mới
                                                                                                              
  Policy không quyết định logic — chỉ kiểm tra điều kiện hợp lệ để ManageAgent không đi lạc.    

Thành phần 3: Context & Persistence Layer                                                                   
                                                                  
  Vấn đề cần giải quyết: Context bị cắt ở nhiều nơi, mỗi agent nhìn thấy thế giới khác nhau.
                                                                                                              
  Giải pháp: Conversation Summarizer (chạy rolling):                                                          
                                                                                                              
  class ContextManager:                                                                                       
      def __init__(self, memory_store: MemoryStore):                                                          
          ...
                                                                                                              
      def compress(self, conversation: list[dict], trigger_len: int = 20):                                    
          """Khi conversation > 20 messages, summarize messages[:-6] thành 1 block"""
          if len(conversation) <= trigger_len:                                                                
              return conversation                                                                             
                                                                                                              
          to_compress = conversation[:-6]  # giữ 6 messages gần nhất nguyên vẹn                               
          summary = self._llm_summarize(to_compress)              
                                                                                                              
          compressed = [{"speaker": "SYSTEM", "content": f"[CONTEXT SUMMARY]\n{summary}"}]                    
          compressed += conversation[-6:]
                                                                                                              
          # Persist full history riêng                            
          self.memory_store.append_full_log(to_compress)                                                      
                                                                                                              
          return compressed
                                                                                                              
  Persistence cho từng agent:                                     

  class AgentScratchpad:
      """Mỗi agent có 1 file notes riêng, persist qua các round"""
                                                                                                              
      def note(self, agent_id: str, key: str, value: str):                                                    
          """Red ghi: 'found_endpoint': '/api/admin/users'"""                                                 
          ...                                                                                                 
                                                                  
      def recall(self, agent_id: str, query: str) -> str:                                                     
          """Red hỏi: 'những endpoint nào đã verify?'"""          
          # Simple keyword search trong notes của agent đó                                                    
          ...                                               
    
đây để tôi mô tả kỹ hơn nhé. Ở đây sẽ là mô hình như một doanh nghiệp về mảng tấn công BLF/BAC. với Manage  
  sẽ là ông Sếp mục tiêu sẽ là người nắm giữ các luồng giao tiếp của các nhân viên (red, blue, exec). Đi cạnh 
   ông Manage sẽ là cô thư ký Policy. Chỉ có Policy sẽ là người duyệt xem ông Manage có đi đúng hướng hay     
  không thôi? Còn lại các thằng nhân viên khác không có Verify hay làm gì với cô thưu ký hết. Rồi ở Manage sẽ 
   là người nắm luồng thực thi và đưa cái chiến lược, rồi việc làm, ... cho từng nhân viên cụ thể như kiểu    
  con Red cho chiến lược xong thì con Manage sẽ nhận về nó sẽ đọc đọc qua cái chiến lược đó nếu đó là chiến   
  lược thì gửi cho con Blue nếu mà nó là việc cần check thì nó sẽ gửi cho con Exec, ... tương tự như thế con  
  Exec chạy xong thì con Manage sẽ đưa nhiệm vụ tiếp theo về con tương ứng đã gọi nó, ... Xong sau cùng nếu   
  con Manage Agent nó thấy là chiến lược sau vài lần debate và thực thi mà không có kết quả thì nó sẽ là      
  người chốt lại cho FAIL và SUCCESS tùy ý để kết thúc thực thi luôn chứ không có làm bừa làm bãi. Đấy kiến   
  trúc nó sẽ cơ bản như thế đó. Bạn check xem có ổn chưa?


- Nhận xét của bản thân khi chạy: 
- Phase đầu khi red đưa ra rất ổn và hợp lý. Và Manage được xử lý dúng cho chiến lược đi qua Blue. Và ở đây có vẻ Blue chưa đọc recon.md hay gì đó nên lại cần xác nhận lại thông tin => Thừa thải cần phải loại bỏ dể tránh gọi lại Agent.
- Exec xác nhận và Manage nó truy ngược lại Blue => Ổn và đúng luôn. 
- Và sau đó con Blue nó xác nhận lại và nó từ chối chiến lược => Hơi gắt gao nhỉ? Liệu có thể nào bóp ở đây lại được không? 
- Sau khi bị từ chối thì con Manage nó gửi lại Red nhưng mà không nhìn thấy gửi gì => Cần thêm log để hiển thị rõ hơn.
- Nó lại đưa ra chiến lược và lần này có gọi con Agent để xác nhận 1 số thông tin để tìm ra đúng sản phẩm trước khi nó thực thi. 
- Exec đi duyệt và thực thi nhưng mà lại lung tung quá gọi tool lại rất nhiều và mệt. Khả năng ta sẽ cần bắt nó truy ngược lại file recon.md để mà đọc lại toàn bộ request? Hoặc là ban đầu file request của ta có đầy đủ chưa? Nó cần phải có đầy đủ để mà AI có thể truy vấn nó ngược lại trước khi nó đi thực thi để mà nó bị tốn token?? 
- Nó cứ kẹt qua lại ở một số bước dù cái sản phẩm đã được leak ra sau quá trình crawl. Vậy thì khả năng ta sẽ cần nộp hết toàn bộ thông tin crawl lại vào 1 file rồi còn cả file recon.md nữa để sau này nó có thể kiểm tra lại cái file nào cần thiết hoặc là nó có thông tin hơn thì nó ổn hơn. Và có thể nó truy vấn nhiều hơn là gọi tool quá nhiều.
- Cũng cần cho con LLM Red và Blue hoặc là con Manage Agent để nó có thể giúp truy vấn hay gì đó để cung cấp đủ ngữ cảnh hơn cho 2 con Red và Blue để nó làm việc hiệu quả hơn chứ giờ có vẻ đang hơi cụt. 
- Blue nó đang siết quá nhiều. Bởi vì là thường phải cho phép "thử" chứ không có ép như thế pentest là quá trình thử đi thử lại chứ không phải là 1 kết quả chạy hết nên cần nhả Blue ra một chút để nó hoạt động tốt hơn.
- Con Blue sẽ là người tôi nghĩ nó cần xác nhận "tư duy logic" chiến lược chứ không phải là bắt bẻ kỹ vào các điểm như tham số, header, url, path, ... mà đánh giá vào độ tư duy nó hoạt động và khả năng thực thi của chiến lược. 
27/4
- Sau khi sửa thì thấy log rõ ràng hơn rồi. Nhưng tôi còn câu hỏi là liệu con Red và Blue có đọc được cái recon.md tức là hiểu được ngữ cảnh trước khi tấn công hay chưa? Hay là lúc gửi yêu cầu thì chỉ có phần request của Manage Agent thôi? 
- Rồi tại sao con Blue Team lại nói trước? Phải là con Red đi trước nói trước đưa chiến lược trước? Chứ con Blue nói trước là sai quy trình?
- Cần note thêm mẫy cái log rõ ra ví dụ như là khi con Manage Agent cho con nào nói thì nó con đó sẽ được nói nhưng gì? Gộp những thứ gì? Mà viết dưới dạng tóm tắt lại để người ta nhìn vào hiểu là à con này đang có ngữ cảnh của cái này cái này thì nó sẽ dễ nhìn hơn dễ hiểu hơn. 

28/4
- Nhận xét bản thân:
+ BLUE Approve rồi nhưng con Manage lại đưa con kia theo dạng là trả lời câu hỏi cho con BLUE? Đang bị sai quy trình? Đáng ra Approve thì nó phải cần phải chạy kịch bản đã đưa ra chứ? Đang bị ngáo ở system prompt làm sai điều khoản rồi.
- Rồi sau đó APPROVED 2 lần mà con Exec không thực thi mà con Manage Agent nó kém thông minh nó điều hướng chương trình đi lung tung hết.
- Quy trình ở con Red team chủ yếu là đưa ra chiến lược thì sẽ không đưa ra yêu cầu Exec làm gì? Mà trong dây nó vừa đưa chiến lược nó vừa yêu cầu Exec có thể sẽ là nó kêu con Exec đi thực thi chiến lược ngay cho Red mà chưa qua Blue có thể con Red đang bị thối não ở đoạn đó như vậy
- Vậy tòm lại cần phải cập nhật tất cả system prompt để quy trình hoạt động trơn tru hơn rõ ràn hơn và chuẩn hơn.

****
- Nhận xét tiếp: 
+ Sao nó vẫn còn Exec ở bên trong quá trình chạy? Red vẫn biết sự có mặt kìa? Cái đấy vẫn còn sai cần "cách ly" tất cả các con LLM ra bên ngoài không có con nào có thể biết nhiệm vụ của con nào hoặc sự tồn tại của nhau. Vì thế nếu Red đưa chiến lược thì nộp lên Manage, rồi có muốn yêu cầu xác minh hoặc làm trước việc gì đó thì cũng gọi lại Manage luôn nhưng ở đây nó lại xuất hiện sự tồn tại của con Exec.
+ Tương tự như thế các con khác như Blue thì nó cũng chỉ là review và xác minh chiến lược hoặc nếu cần xác minh thì mọi yêu cầu đều gửi lên Manage.
+ Con Exec như là "chân sai vặt chạy bàn" con Manage sẽ lấy các yêu cầu từ con Red hoặc Blue (nếu có) gửi cho và bắt con này đi làm và thực hiện. Có thể làm xác minh hoặc là thực hiện chiến lược được đề ra. 
+ Ngoài ra tôi không cần mô hình ép Debate quá nhiều lần. NẾu lần đầu được duyệt là cho thực thi chiến lược luôn hiểu không?
+ Mô hình nó đang bị lặp ở trong log như này nữa bạn có thể check lại toàn bộ cho tôi đi

/home/dangnosuy/Documents/UIT/doanchuyennganh/MARL/workspace/0a2000f803700f138025bc350036009a.web-security-academy.net_20260428_124144/marl.log

- Con exec tool đang bị kẹt ở tầm tool thứ 30 và không chạy tiếp được? => Không có lý do.
- Ngoài ra nếu mà thay vì sử dụng Playwright? Thì sử dụng cái curl ưu tiên hơn thì có hay hơn không? Vẫn ghép theo được token vẫn chạy tốt mà nhỉ? CÒn đỡ hao token hơn nhiều vì gọi playwright? 
- Sau đó thì nó cũng có tự gọi thêm request dẫn đến hết token? Một điểm đang lưu ý 
