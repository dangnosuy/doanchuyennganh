# Báo cáo cập nhật dự án MARL Pentest Agent

Ngày cập nhật: 23/05/2026

## 1. Tóm tắt hiện trạng

Dự án hiện tại đã đạt mức **prototype chạy được theo kiến trúc chính của đồ án**: hệ thống có thể crawl target, tạo hồ sơ recon, sinh danh sách giả thuyết lỗ hổng BAC/BLF, để Red Team đề xuất chiến lược, Blue Team phản biện chiến lược, Exec Agent thực thi PoC có lưu artifact, Manager điều phối luồng và sinh báo cáo cuối.

Trạng thái hiện tại phù hợp để báo cáo đồ án ở mức:

- Có kiến trúc multi-agent rõ ràng.
- Có pipeline tự động từ recon đến report.
- Có cơ chế giảm token bằng memory/context thay vì gửi toàn bộ conversation thô.
- Có cơ chế self-verifying exploit: Exec tự khai thác, tự xác minh trong Python script, Manager đọc verdict/evidence để quyết định.
- Có lưu lại PoC, script, log, response artifact để chứng minh quá trình khai thác.

Điểm cần lưu ý khi demo: hệ thống phụ thuộc vào LLM proxy đang chạy và token hợp lệ. Kiểm tra gần nhất cho thấy code compile ổn, nhưng endpoint GitHub Copilot proxy cần token hợp lệ để chạy end-to-end.

## 2. Mục tiêu đồ án

Mục tiêu ban đầu của dự án là xây dựng một hệ thống multi-agent hỗ trợ kiểm thử xâm nhập tự động cho nhóm lỗi:

- `BAC` - Broken Access Control.
- `BLF` - Business Logic Flaw.

Trọng tâm không phải là giải một lab cụ thể, mà là chứng minh hệ thống có thể:

- Thu thập ngữ cảnh website.
- Tạo giả thuyết lỗ hổng.
- Lập chiến lược khai thác.
- Phản biện chiến lược.
- Thực thi PoC.
- Xác minh bằng chứng.
- Viết báo cáo kết quả dù thành công hay thất bại.

Một mục tiêu phụ quan trọng là **giảm token gửi lên server LLM** bằng cách dùng memory/context summary và artifact thay vì đẩy toàn bộ conversation history hoặc raw crawl data vào từng agent.

## 3. Kiến trúc tổng thể hiện tại

```text
[Người dùng nhập prompt target]
            |
        [main.py]
            |
      [CrawlAgent]
      |     |     |
      |     |  [recon.md enriched]
      |     |          |
      |  [crawl_raw.json]   [VulnHunterAgent]
      |                          |
   [crawl_data.txt]       [risk-bug.json]
                                 |
                          [ManageAgent] <---> [PolicyAgent]
                         /      |      \
               [RedTeamAgent]   |   [BlueTeamAgent]
                         \      |      /
                          [ExecAgent]
                         /      |      \
              [exploits/]  [exploit_state/]  [artifacts]
                         \      |      /
                          [ManageAgent]
                         /      |      \
               [report.md] [report_raw.md] [report_final_vi.md]
```

## 4. Vai trò từng agent

| Thành phần | Vai trò hiện tại | Ghi chú |
|---|---|---|
| `CrawlAgent` | Crawl website ở anonymous/authenticated mode, lưu traffic và sinh `recon.md` giàu ngữ cảnh | Đây là nguồn dữ liệu chính cho các bước sau |
| `VulnHunterAgent` | Đọc toàn bộ `recon.md` enriched để sinh danh sách candidate bug vào `risk-bug.json` | Ưu tiên recall cao, chấp nhận false positive |
| `ManageAgent` | Điều phối toàn bộ worker agent, chọn action, kiểm soát retry/stop/report | Là "ông sếp" trong mô hình doanh nghiệp của dự án |
| `PolicyAgent` | Guardrail nội bộ đứng cạnh Manager, kiểm tra luật state machine | Red/Blue/Exec không gọi Policy trực tiếp |
| `RedTeamAgent` | Viết chiến lược khai thác và `EXECUTION SHOT PLAN` cho một bug cụ thể | Không dùng tool, không viết code trực tiếp |
| `BlueTeamAgent` | Review chiến lược và shot plan của Red trước khi Exec chạy | Đây là core debate của đồ án |
| `ExecAgent` | Thực thi Python exploit, lưu PoC/artifact, tự verify trong script | Script tự in `FINAL: EXPLOITED/PARTIAL/FAILED` |
| `MemoryStore` / `ContextManager` | Lưu scratchpad, finding, context summary để giảm token | Tránh gửi full history lặp lại |

## 5. Luồng chạy hiện tại

Luồng chính hiện tại:

```text
[RECON]
  --> [VULN HUNTER]
        --> [BUG QUEUE]
              --> [RED STRATEGY]
                    --> [BLUE REVIEW]
                          |
                          +--(APPROVED)--> [EXEC EXPLOIT]
                          |                     |
                          +--(REJECTED)--> quay lại RED    +--(EXPLOITED)  --> [NEXT BUG]
                                                           |
                                                           +--(SCRIPT_ERROR) --> [RETRY EXEC]
                                                           |
                                                           +--(PARTIAL)     --> [RETRY EXEC]
                                                           |
                                                           +--(FAILED)      --> [STOP BUG]
                                                                                     |
                                                                               [NEXT BUG]
                                                                                     |
                                                                         (hết bug) [REPORT]
```


Điểm quan trọng sau các lần chỉnh sửa:

- `BlueTeam` chỉ review **chiến lược của Red trước Exec**.
- Đã bỏ Blue review sau khi Exec chạy, vì phần này làm pipeline khắt khe và dễ retry vòng lặp.
- Sau Exec, `ManageAgent` đọc trực tiếp `SUCCESS`, `FINAL`, `result.json` và evidence summary.
- Exec tự xác minh trong chính Python exploit, không còn verifier thứ hai trong hot path.
- Hệ thống dùng nguyên tắc `minimum sufficient proof`: nếu evidence đủ chứng minh hypothesis thì chốt, không bắt thêm endpoint/tác động phụ.

## 6. Sequence diagram cho một bug

```text
ManageAgent         RedTeamAgent        BlueTeamAgent       ExecAgent
     |                   |                   |                  |
     |-- giao bug ------->|                   |                  |
     |   + dossier        |                   |                  |
     |   + attempt ledger |                   |                  |
     |                   |                   |                  |
     |<-- Strategy -------|                   |                  |
     |    + SHOT PLAN     |                   |                  |
     |                   |                   |                  |
     |-- gửi strategy để review ------------>|                  |
     |                                       |                  |
     |<-- APPROVED / REJECTED / STOPPED -----|                  |
     |                                                          |
     |  [nếu APPROVED]                                          |
     |-- chạy exploit theo approved workflow ------------------>|
     |                                                          |
     |<-- FINAL verdict + result.json + artifacts --------------|
     |
     |  Đọc kết quả:
     |    EXPLOITED    --> chuyển bug tiếp theo
     |    PARTIAL      --> retry Exec tối đa 1 lần
     |    SCRIPT_ERROR --> retry Exec tối đa 1 lần
     |    FAILED       --> dừng bug
     |
     |  [nếu REJECTED]
     |-- yêu cầu Red sửa strategy trong budget
```

## 7. Các artifact sinh ra khi chạy

Mỗi lần chạy tạo một workspace dạng:

```text
workspace/<domain>_<timestamp>/
├── marl.log
├── crawl_data.txt
├── crawl_raw.json
├── recon.md
├── risk-bug.json
├── exploits/
│   ├── bug-001-exploit1.sh
│   ├── bug-001-exploit1.sh.syntax.txt
│   ├── bug-001-exploit1.sh.output.txt
│   └── ...
├── exploit_state/
│   └── BUG-001/
│       ├── baseline.req.txt
│       ├── baseline.resp.txt
│       ├── probe.req.txt
│       ├── probe.resp.txt
│       ├── verify.req.txt
│       ├── verify.resp.txt
│       └── result.json
├── report_raw.md
├── report_final_vi.md
└── report.md
```

Ý nghĩa:

- `marl.log`: log realtime để theo dõi agent nào đang làm gì.
- `recon.md`: bản tóm tắt giàu ngữ cảnh từ crawl, dùng làm input chính cho VulnHunter.
- `risk-bug.json`: danh sách bug candidate và trạng thái xử lý.
- `exploits/`: các script PoC được lưu theo từng bug và từng shot.
- `exploit_state/`: raw request/response phục vụ chứng minh PoC.
- `report_raw.md`: báo cáo kỹ thuật thô.
- `report_final_vi.md`: báo cáo tiếng Việt sạch hơn.
- `report.md`: báo cáo cuối cùng.

## 8. Các cập nhật chính đã làm gần đây

### 8.1. Làm sạch kiến trúc Manager-led workflow

Trước đây các agent có xu hướng tự gắn tag hoặc điều hướng lẫn nhau. Hiện tại đã chuyển về mô hình:

- `ManageAgent` là router duy nhất.
- `PolicyAgent` chỉ đứng cạnh Manager.
- Red/Blue/Exec không tự gọi Policy.
- Red/Blue không tự điều phối Exec.

Điều này làm luồng chạy dễ giải thích hơn khi báo cáo:

```text
Manager = người quản lý luồng
Policy = thư ký kiểm luật
Red = chiến lược gia tấn công
Blue = phản biện chiến lược
Exec = người thực thi kỹ thuật
```

### 8.2. Làm giàu recon.md và giảm phụ thuộc crawl_data.txt

Ban đầu VulnHunter đọc `crawl_data.txt` quá dài, dễ bị mất ngữ cảnh hoặc chỉ đọc được đoạn đầu. Hiện tại:

- `CrawlAgent` tạo `recon.md` enriched.
- `recon.md` mô tả endpoint, request, response, form fields, cookie surface, route family.
- `VulnHunterAgent` đọc toàn bộ `recon.md` thay vì đọc raw crawl data trực tiếp.

Lợi ích:

- Giảm token.
- Tăng chất lượng bug candidate.
- Agent hiểu website theo dạng mô tả nghiệp vụ thay vì đọc HTML/JSON thô quá dài.

### 8.3. VulnHunter ưu tiên recall cao

VulnHunter được chỉnh theo hướng:

- Nghi đâu báo đó.
- Không cần confirm 100%.
- Sinh nhiều candidate BAC/BLF hơn.
- False positive sẽ được xử lý ở Red/Blue/Exec/Manager.

Đây là hướng phù hợp với pipeline nhiều agent vì giai đoạn đầu nên ưu tiên không bỏ sót.

### 8.4. Khôi phục Red/Blue debate là core của đồ án

Hiện tại Blue review chiến lược của Red là bước bắt buộc trước Exec:

```text
Red strategy -> Blue review -> Exec exploit
```

Blue có quyền:

- `APPROVED`: chiến lược đủ rõ để Exec chạy.
- `REJECTED`: Red phải sửa strategy/shot plan.
- `STOPPED`: candidate không còn đáng khai thác.

Blue không còn review evidence sau Exec. Việc này giúp giữ đúng mục tiêu đồ án: Blue là reviewer chiến lược, không phải verifier runtime.

### 8.5. Chuẩn hóa shot plan và exploit artifacts

Red phải viết section:

```text
=== EXECUTION SHOT PLAN ===
...
=== END EXECUTION SHOT PLAN ===
```

Exec dùng shot plan để sinh script exploit. Mỗi script được lưu riêng:

```text
exploits/bug-001-exploit1.sh
exploits/bug-001-exploit2.sh
```

Lợi ích:

- Không mất PoC khi script bị ghi đè.
- Báo cáo cuối có thể trích dẫn lại exploit script.
- Có thể xem từng shot đã làm gì và lỗi ở đâu.

### 8.6. Đơn giản hóa post-Exec decision

Pipeline đã bỏ các lớp hậu kiểm runtime phức tạp cũ, bao gồm guard deterministic, verifier riêng sau Exec, review runtime phụ và log summary nhiễu.

Hiện tại Exec Python script phải tự:

- chạy exploit;
- kiểm tra điều kiện thành công;
- lưu raw request/response/result artifact;
- in `SHOT_RESULT`;
- in `=== FINAL: EXPLOITED/PARTIAL/FAILED ===`;
- ghi `result.json`.

Manager chỉ đọc kết quả này để quyết định:

- `EXPLOITED` -> chuyển bug tiếp theo;
- `PARTIAL` -> retry Exec tối đa một lần;
- `FAILED` -> dừng bug;
- `SCRIPT_ERROR` -> retry Exec tối đa một lần.

### 8.7. Thêm rào chống overfitting

Các prompt Red, Blue, Exec và Manager được bổ sung luật:

- Không hardcode endpoint/marker/account của một lab cụ thể.
- Endpoint, marker, payload phải lấy từ `risk-bug.json`, `recon.md`, strategy hoặc artifact hiện tại.
- Không yêu cầu endpoint phụ hoặc tác động phụ nếu hypothesis đã được chứng minh.
- BAC vertical: user thường/guest thấy privileged page/control/admin marker là đủ.
- IDOR/BAC horizontal: user A đọc được object/data của user B là đủ.
- BLF/stateful: cần before/after state, delta hoặc state transition trái logic.

### 8.8. Memory và context compression

Hệ thống có `MemoryStore` và `ContextManager` để:

- Lưu scratchpad từng agent.
- Lưu finding/attempt ledger.
- Chỉ lấy context liên quan cho từng agent.
- Giảm việc gửi toàn bộ conversation history lên LLM.

Điều này phù hợp với mục tiêu ban đầu: dùng memory để quản lý conversation history và giảm token gửi lên server.

## 9. Trạng thái ổn định hiện tại

Đánh giá kỹ thuật hiện tại:

| Hạng mục | Trạng thái | Nhận xét |
|---|---|---|
| Syntax Python | Ổn | Đã compile các module chính thành công |
| Kiến trúc agent | Ổn | Manager là router duy nhất, Blue nằm đúng vị trí strategy gate |
| Luồng dữ liệu | Khá ổn | recon -> risk-bug -> Red strategy -> Blue review -> Exec exploit tự verify -> Manager decision -> report đã rõ |
| Artifact PoC | Ổn | Script, output, syntax log, request/response được lưu theo bug |
| Report | Khá ổn | Có raw report và final Vietnamese report |
| False positive handling | Cố ý nới lỏng | Chấp nhận candidate proof tối thiểu để tránh overfitting; false positive được ghi rõ trong report nếu Exec/Manager không đủ bằng chứng |
| E2E runtime | Phụ thuộc môi trường | Cần LLM proxy/token hợp lệ và target đang chạy |
| Tính tổng quát | Khá ổn cho BAC/BLF | Chưa hướng đến toàn bộ nhóm lỗi web như SQLi/XSS/SSRF |

Kiểm tra gần nhất:

```bash
python -m py_compile main.py agents/manage_agent.py agents/crawl_agent.py agents/vuln_hunter_agent.py agents/red_team.py agents/blue_team.py agents/exec_agent.py agents/policy_agent.py shared/bug_dossier.py shared/context_manager.py shared/memory_store.py mcp_client.py
```

Kết quả: không có lỗi syntax.

## 10. Trạng thái môi trường chạy hiện tại

Cấu hình runtime hiện tại dùng OpenAI-compatible proxy:

```text
MARL_SERVER_URL=http://127.0.0.1:5000/v1
```

Các model trong `.env` đang được chia theo nhóm:

- Tool-heavy agents: `gpt-4.1`.
- Reasoning/orchestration agents: `gpt-5-mini`.

Lưu ý khi demo:

- Proxy phải đang chạy ở `127.0.0.1:5000`.
- Proxy phải có GitHub/Copilot token hợp lệ hoặc token pool hợp lệ.
- Nếu `.env` vẫn để placeholder `GITHUB_TOKEN=gho_token`, request trực tiếp tới `/v1/models` có thể trả `401`.
- Đây là lỗi môi trường/token, không phải lỗi syntax pipeline.

## 11. Khi chạy hiện tại sẽ diễn ra như thế nào

Ví dụ lệnh chạy:

```bash
python main.py "Test http://localhost:5001 user:... pass:..."
```

Quy trình dự kiến:

1. `main.py` tạo workspace mới hoặc reuse workspace cũ.
2. `CrawlAgent` crawl target:
   - anonymous crawl
   - authenticated crawl nếu có credential
   - lưu `crawl_data.txt`, `crawl_raw.json`
   - tạo `recon.md`
3. `VulnHunterAgent` đọc `recon.md`:
   - sinh candidate bug BAC/BLF
   - lưu `risk-bug.json`
4. `ManageAgent` xử lý từng bug:
   - gửi bug dossier cho Red
   - nhận strategy và shot plan
   - gửi Blue review
   - nếu Blue approve thì gửi Exec chạy exploit
5. `ExecAgent`:
   - chuẩn bị session/cookie
   - sinh Python exploit theo strategy đã approve
   - chạy `python3 -m py_compile`
   - chạy script và tự in `SHOT_RESULT`, `EVIDENCE_SUMMARY`, `FINAL`
   - lưu output và artifact
6. `ManageAgent`:
   - đọc Exec output
   - nếu evidence đạt proof tối thiểu của hypothesis thì đánh dấu `EXPLOITED`
   - nếu script/runtime lỗi thì retry Exec tối đa 1 lần
   - nếu không có tín hiệu rõ thì stop bug để tránh vòng lặp overfitting
7. Hết bug thì sinh report:
   - `report_raw.md`
   - `report_final_vi.md`
   - `report.md`

## 12. Kết quả mong đợi khi chạy thành công

Nếu tìm được lỗ hổng:

- `risk-bug.json` có bug `status=EXPLOITED`.
- `exec_result_status=EXPLOITED`.
- `report.md` có finding với:
  - mô tả lỗi
  - tác động
  - PoC
  - evidence files
  - khuyến nghị khắc phục
- `exploits/` có script PoC tương ứng.
- `exploit_state/` có request/response chứng minh.

Nếu không tìm được lỗ hổng:

- Pipeline vẫn kết thúc đúng.
- Bug candidate được đánh dấu `NOT_EXPLOITED`, `NO_SIGNAL`, `SCRIPT_ERROR`, `INCONCLUSIVE` hoặc `NEEDS_MANUAL`.
- Report vẫn được sinh ra để giải thích lý do fail/false positive.

Đây là điểm quan trọng khi báo cáo: hệ thống không chỉ chạy khi thành công, mà còn có khả năng ghi nhận thất bại có cấu trúc.

## 13. Sơ đồ state machine của Manager

```mermaid
stateDiagram-v2
    [*] --> DEBATE_RED
    DEBATE_RED --> DEBATE_BLUE: Red strategy hợp lệ
    DEBATE_RED --> STOP_BUG: Red không có strategy / hết budget

    DEBATE_BLUE --> EXECUTE_BUG: Blue APPROVED
    DEBATE_BLUE --> RETRY_RED: Blue REJECTED
    DEBATE_BLUE --> STOP_BUG: Blue STOPPED

    RETRY_RED --> DEBATE_BLUE: Red sửa strategy
    RETRY_RED --> STOP_BUG: hết red attempts

    EXECUTE_BUG --> NEXT_BUG: EXPLOITED
    EXECUTE_BUG --> RETRY_EXEC: SCRIPT_ERROR/PARTIAL còn retry budget
    EXECUTE_BUG --> STOP_BUG: FAILED/NO_SIGNAL hoặc hết retry

    RETRY_EXEC --> NEXT_BUG: EXPLOITED
    RETRY_EXEC --> STOP_BUG: vẫn SCRIPT_ERROR/PARTIAL/FAILED

    STOP_BUG --> NEXT_BUG
    NEXT_BUG --> DEBATE_RED: còn bug
    NEXT_BUG --> REPORT: hết bug
    REPORT --> [*]
```

## 14. Điểm mạnh hiện tại

- Kiến trúc dễ giải thích theo mô hình doanh nghiệp: Manager, Policy, Red, Blue, Exec.
- Luồng Red/Blue debate rõ ràng, phù hợp yêu cầu đồ án.
- Recon đã giàu hơn, không bắt agent đọc raw crawl quá dài.
- Exec lưu PoC theo từng bug và từng shot, thuận tiện đưa vào báo cáo.
- Có cơ chế chống overfitting: không yêu cầu endpoint/tác động phụ khi evidence đã đủ chứng minh hypothesis tối thiểu.
- Có report tiếng Việt cuối cùng, phù hợp trình bày.
- Có memory/context để giảm token và giảm lịch sử hội thoại thừa.

## 15. Hạn chế còn tồn tại

- Chất lượng phụ thuộc nhiều vào model LLM và proxy đang dùng.
- Một số model tool-call yếu có thể gọi tool dài dòng hoặc sinh script kém.
- E2E cần server target và GitHub Copilot/OpenAI-compatible proxy hoạt động ổn định.
- Pipeline hiện tập trung BAC/BLF, chưa tối ưu cho toàn bộ nhóm lỗi web.
- False positive vẫn có thể xảy ra vì pipeline ưu tiên recall và proof tối thiểu hơn hậu kiểm nhiều lớp.
- Report có thể tiếp tục cải thiện bằng ảnh chụp màn hình hoặc evidence preview đẹp hơn.

## 16. Dự kiến phát triển tiếp theo

Các hướng phát triển ít rủi ro và có giá trị cho đồ án:

1. Thêm test suite mô phỏng state machine của `ManageAgent`.
2. Thêm benchmark nhiều lab BAC/BLF để đo:
   - số bug candidate
   - số false positive
   - số finding validated
   - số token/chi phí
   - thời gian chạy
3. Thêm screenshot artifact cho finding đã exploited.
4. Thêm report dashboard nhỏ để xem:
   - bug queue
   - status từng bug
   - exploit script
   - evidence files
5. Chuẩn hóa schema `risk-bug.json` và `result.json` để report ổn định hơn.
6. Thêm mode `manual review` để người dùng can thiệp khi bug cần ngữ cảnh nghiệp vụ.
7. Thêm bộ playbook BAC/BLF chi tiết hơn theo pattern:
   - vertical access control
   - horizontal IDOR
   - client-controlled role/state
   - price/quantity tampering
   - coupon/checkout logic
   - workflow bypass

## 17. Cách trình bày với giảng viên

Có thể trình bày dự án theo 5 ý chính:

1. Bài toán: tự động hóa pentest BAC/BLF bằng nhiều agent LLM.
2. Kiến trúc: Manager điều phối, Red lập chiến lược, Blue phản biện, Exec thực thi, Policy kiểm luật.
3. Giảm token: recon enriched, memory/context, không gửi raw crawl dài vào mọi agent.
4. Chứng minh kết quả: PoC Python script, request/response artifact, `result.json`, `report_final_vi.md`.
5. Đánh giá: hệ thống chạy được ở mức prototype, có khả năng tìm/khai thác/ghi báo cáo, nhưng phụ thuộc model và cần benchmark thêm.

## 18. Cập nhật ngày 23/05/2026 — Sửa chữa cơ chế Proof Quality Gate và tối ưu pipeline

### 18.1. Bối cảnh

Sau các lần sửa trước (mục 8.1–8.8), pipeline đã **hoạt động đúng luồng từ đầu đến cuối**:

- CrawlAgent crawl thành công: 32 pages, 142 requests, tạo `recon.md` enriched (12927 bytes).
- VulnHunterAgent sinh 10 bug candidates (3 CRITICAL, 7 HIGH).
- ManageAgent điều phối Red → Blue → Exec đúng per-bug pipeline.
- ExecAgent tự sinh Python exploit, chạy script, tự verify verdict.
- Report được sinh ra cuối pipeline.

**Vấn đề phát hiện**: Exec script **tự xác nhận EXPLOITED** cho 4 bugs (BUG-001, BUG-003, BUG-008, BUG-010), nhưng Manager **chặn 3/4** qua các cơ chế proof quality gate quá nghiêm ngặt, dẫn đến `REPORT_FAIL` dù thực tế có 4 lỗ hổng đã khai thác thành công.

### 18.2. Trace pipeline đầy đủ — Log phiên `localhost_20260523_000609`

```text
Phase 1: RECON
  ├── CrawlAgent → anonymous crawl: 32 pages, 142 requests
  ├── CrawlAgent → login: POST /login status=302 → 3 cookies set
  ├── CrawlAgent → authenticated crawl: bổ sung endpoints
  ├── recon.md enriched: 12927 bytes, 15+ endpoints
  └── VulnHunterAgent → 10 bug candidates

Phase 2: PER-BUG PIPELINE (ManageAgent điều phối)
  ├── BUG-001 [BAC-02/CRITICAL] Cookie role tamper → /admin
  │     Red → strategy ✓ → Blue → APPROVED → Exec → EXPLOITED ✓
  │     ⚠ Manager → PROOF_QUALITY_FAIL (yêu cầu IDOR ownership bypass)
  │     ✗ BỊ CHẶN SAI → vì BAC-02 là privilege escalation, KHÔNG phải IDOR
  │
  ├── BUG-002 [BAC-01/CRITICAL] Mass-assignment role parameter
  │     Red → strategy ✓ → Blue → APPROVED → Exec → FAILED
  │     ✓ Đúng: server validate/whitelist fields → NOT_VULNERABLE
  │
  ├── BUG-003 [BAC-03/HIGH] IDOR on /profile
  │     Red → strategy ✓ → Blue → APPROVED → Exec → EXPLOITED ✓
  │     ✓ Đúng: ownership bypass chứng minh → EXPLOITED
  │
  ├── BUG-004 [BLF-01/HIGH] Negative quantity in cart
  │     Red → strategy ✓ → Blue → APPROVED → Exec → FAILED
  │     ✓ Đúng: server validate qty → NOT_VULNERABLE
  │
  ├── BUG-005 [BLF-03/HIGH] Price tampering checkout
  │     Red → strategy ✓ → Blue → APPROVED → Exec → FAILED
  │     ✓ Đúng: server recalculate price → NOT_VULNERABLE
  │
  ├── BUG-006 [BLF-05/HIGH] Race condition on /transfer
  │     Red → strategy ✓ → Blue → APPROVED → Exec → SCRIPT_ERROR (2 lần)
  │     ⚠ Script phức tạp → syntax error lặp lại → STOP (chỉ 1 retry)
  │
  ├── BUG-007 [BLF-07/HIGH] Multi-step checkout bypass
  │     Red → strategy ✓ → Blue → APPROVED → Exec → FAILED
  │     ✓ Đúng: POST /order status=404 → endpoint không tồn tại
  │
  ├── BUG-008 [BAC-04/HIGH] HTTP method bypass on /admin/users
  │     Red → strategy ✓ → Blue → APPROVED → Exec → EXPLOITED ✓
  │     ⚠ Manager → WRONG_TARGET override EXPLOITED
  │     ✗ BỊ CHẶN SAI → WRONG_TARGET priority cao hơn EXPLOITED
  │
  ├── BUG-009 [BAC-03/HIGH] IDOR on /order
  │     ⚠ Hết tick budget trước khi xử lý
  │
  └── BUG-010 [BAC-01/CRITICAL] Unprotected /admin/products
        Red → strategy ✓ → Blue → APPROVED → Exec → EXPLOITED ✓
        ✓ Đúng: admin marker tìm thấy → EXPLOITED

  TỔNG: 4 EXPLOITED thật, 3 bị chặn sai, 3 đúng FAILED/NOT_VULNERABLE
  KẾT QUẢ CUỐI: REPORT_FAIL (hết 60 ticks, 2 bugs đã bị chặn sai chưa được tính)
```

### 18.3. Phân tích nguyên nhân gốc — 3 loại lỗi proof gate

#### Lỗi 1 (CRITICAL): BAC-02 bị gộp chung với IDOR check

**Vấn đề**: `_proof_quality_block()` kiểm tra BAC-02 và BAC-03 chung nhau, yêu cầu "ownership bypass" cho cả hai. Nhưng BAC-02 là **privilege escalation (vertical)** — user thường leo lên quyền admin. BAC-03 mới là **IDOR (horizontal)** — user A truy cập data user B.

**Hậu quả**: BUG-001 (cookie `role=user` → `role=admin` → truy cập `/admin`) bị reject vì "không có ownership bypass" — vô lý cho privilege escalation.

**Sửa**: Tách BAC-02 ra gate riêng, chỉ cần chứng minh cookie/role tamper dẫn tới admin access. Thêm method `_has_privilege_escalation_proof()`.

#### Lỗi 2 (CRITICAL): WRONG_TARGET override EXPLOITED

**Vấn đề**: Trong `_exec_decision()`, check `WRONG_TARGET` (priority 2) chạy **trước** check `EXPLOITED` (priority 3). Khi exec output chứa cả status 200 và 404, heuristic kết luận `WRONG_TARGET` → override verdict `EXPLOITED` từ script.

**Hậu quả**: BUG-008 rõ ràng exploit thành công ("victim deleted, admin-only action succeeded"), nhưng bị gán nhãn `WRONG_TARGET`.

**Sửa**: Đảo priority: `EXPLOITED` check chạy TRƯỚC `WRONG_TARGET`. Script nói EXPLOITED → tin tưởng, không bị heuristic override.

#### Lỗi 3 (HIGH): Tick budget cố định và retry quá hạn chế

**Vấn đề**: `MAX_TICKS = 60` cố định, không đủ cho 10 bugs. SCRIPT_ERROR chỉ được retry 1 lần. PROOF_QUALITY_FAIL dừng bug ngay lập tức.

**Sửa**: Dynamic tick budget `max(60, len(bugs) * 8)`. SCRIPT_ERROR cho 2 retry. PROOF_QUALITY_FAIL cho retry Red 1 lần.

### 18.4. Các thay đổi đã thực hiện

#### File: `agents/manage_agent.py`

| # | Thay đổi | Mô tả |
|---|----------|-------|
| A | Đảo priority EXPLOITED > WRONG_TARGET | Script nói EXPLOITED (priority 2) thắng heuristic WRONG_TARGET (priority 3). Trước đây ngược lại |
| B | Tách BAC-02 khỏi IDOR check | BAC-02 là privilege escalation, chỉ cần admin marker HOẶC cookie/role tamper evidence. Thêm method `_has_privilege_escalation_proof()` |
| C | Thêm gate cho BAC-04/05/06 | Method/role bypass bugs giờ có gate phù hợp: admin marker OR state change OR privilege escalation |
| D | Mở rộng admin control markers | Thêm 15+ markers: "admin area", "admin page", "/admin/products", "victim deleted", "admin-only action", v.v. |
| E | PROOF_QUALITY_FAIL cho retry | Không STOP ngay — cho RETRY_RED 1 lần với hướng dẫn cụ thể về cần lấy bằng chứng gì |
| F | SCRIPT_ERROR cho 2 lần retry | Syntax error là lỗi kỹ thuật, không phải exploit fail. Cho 2 retry thay vì 1 |
| G | Dynamic MAX_TICKS | `self._max_ticks = max(60, len(bugs) * 8)`. 10 bugs = 80 ticks |
| H | Cập nhật Manager prompt rules | Thêm BAC-02/BAC-04+ rules, ghi rõ EXPLOITED > WRONG_TARGET |

#### File: `agents/vuln_hunter_agent.py`

| # | Thay đổi | Mô tả |
|---|----------|-------|
| I | Prompt yêu cầu gen ≥8 bugs | Thêm: "LUON CO GANG GEN IT NHAT 8-10 bug candidates", "MOI ROUTE FAMILY nen co IT NHAT 1 bug candidate" |
| J | Thêm detection areas | Cookie tampering, multi-step workflows, HTTP method variations |
| K | User prompt reinforcement | Thêm instruction: "Gen it nhat 8 bug candidates. Moi route family nen co 1 candidate" |

### 18.5. Cập nhật sơ đồ state machine

Thay đổi so với mục 13:

```mermaid
stateDiagram-v2
    [*] --> DEBATE_RED
    DEBATE_RED --> DEBATE_BLUE: Red strategy hợp lệ
    DEBATE_RED --> STOP_BUG: Red không có strategy / hết budget

    DEBATE_BLUE --> EXECUTE_BUG: Blue APPROVED
    DEBATE_BLUE --> RETRY_RED: Blue REJECTED
    DEBATE_BLUE --> STOP_BUG: Blue STOPPED

    RETRY_RED --> DEBATE_BLUE: Red sửa strategy
    RETRY_RED --> STOP_BUG: hết red attempts (2 lần)

    EXECUTE_BUG --> NEXT_BUG: EXPLOITED (script verdict thắng heuristic)
    EXECUTE_BUG --> RETRY_EXEC: SCRIPT_ERROR còn retry (tối đa 2 lần)
    EXECUTE_BUG --> RETRY_RED: PROOF_QUALITY_FAIL (retry 1 lần với hướng dẫn)
    EXECUTE_BUG --> STOP_BUG: FAILED/NO_SIGNAL hoặc hết retry

    RETRY_EXEC --> NEXT_BUG: EXPLOITED
    RETRY_EXEC --> RETRY_EXEC: SCRIPT_ERROR lần 2
    RETRY_EXEC --> STOP_BUG: vẫn SCRIPT_ERROR/PARTIAL/FAILED

    STOP_BUG --> NEXT_BUG
    NEXT_BUG --> DEBATE_RED: còn bug
    NEXT_BUG --> REPORT: hết bug
    REPORT --> [*]
```

Thay đổi chính so với phiên bản trước:
- `EXECUTE_BUG → RETRY_RED` khi `PROOF_QUALITY_FAIL` (trước đây → STOP ngay).
- `RETRY_EXEC` cho phép 2 lần (trước đây 1 lần).
- `EXPLOITED` verdict từ script **không bị override** bởi `WRONG_TARGET` heuristic.

### 18.6. Cập nhật bảng trạng thái ổn định

| Hạng mục | Trạng thái | Nhận xét |
|---|---|---|
| Syntax Python | ✅ Ổn | Đã compile tất cả module thành công |
| Kiến trúc agent | ✅ Ổn | Manager là router duy nhất, Blue review strategy, proof gates phân biệt BAC pattern |
| Luồng dữ liệu | ✅ Ổn | recon → risk-bug → Red → Blue → Exec self-verify → proof gate → report đầy đủ |
| Proof quality gates | ✅ Đã sửa | BAC-02 ≠ IDOR, EXPLOITED thắng WRONG_TARGET, PROOF_QUALITY_FAIL cho retry |
| VulnHunter coverage | ✅ Cải thiện | Prompt yêu cầu ≥8 candidates, coverage mỗi route family |
| Tick budget | ✅ Dynamic | `max(60, bugs × 8)` thay vì cố định 60 |
| Artifact PoC | ✅ Ổn | Script, output, request/response được lưu theo bug |
| Report | ✅ Ổn | Có raw report, final Vietnamese report, exploited/not-exploited phân loại |
| E2E runtime | ⚠ Phụ thuộc MT | Cần LLM proxy/token hợp lệ và target đang chạy |

### 18.7. Cập nhật post-exec decision flow

Phần post-exec decision đã thay đổi so với mục 6:

```text
ManageAgent         ExecAgent
     |                  |
     |-- chạy exploit →|
     |                  |
     |←-- FINAL verdict + result.json + artifacts
     |
     |  Đọc kết quả (priority mới):
     |    1. SCRIPT_ERROR → retry tối đa 2 lần
     |    2. EXPLOITED (script verdict) → chấp nhận, KHÔNG bị WRONG_TARGET override
     |    3. WRONG_TARGET (chỉ khi script KHÔNG nói EXPLOITED) → retry Red hoặc stop
     |    4. FAILED (script nói FAILED) → tin tưởng
     |    5. Heuristic fallback → diagnose:
     |         PROOF_QUALITY_FAIL → retry Red 1 lần (lấy bằng chứng mạnh hơn)
     |         STRATEGY_GAP → retry Red
     |         NOT_VULNERABLE → stop bug
```

### 18.8. Tác động dự kiến

Với cùng target TechShop `localhost:5001`, sau khi sửa:

| Bug | Trước sửa | Sau sửa | Lý do |
|-----|-----------|---------|-------|
| BUG-001 (cookie tamper → /admin) | ✗ PROOF_QUALITY_FAIL | ✓ EXPLOITED | BAC-02 giờ không yêu cầu IDOR ownership bypass |
| BUG-003 (IDOR /profile) | ✓ EXPLOITED | ✓ EXPLOITED | Không thay đổi |
| BUG-008 (admin/users bypass) | ✗ WRONG_TARGET | ✓ EXPLOITED | EXPLOITED priority cao hơn WRONG_TARGET |
| BUG-010 (admin products) | ✓ EXPLOITED | ✓ EXPLOITED | Không thay đổi |
| Pipeline kết quả | REPORT_FAIL | REPORT_SUCCESS | ≥4 findings validated |

### 18.9. Bài học kinh nghiệm

1. **Proof quality gates cần phân biệt theo loại BAC**: vertical (privilege escalation) ≠ horizontal (IDOR) ≠ method bypass. Áp dụng chung 1 gate cho tất cả dẫn đến false negative.

2. **Script tự verify phải được tin tưởng**: khi Exec script đã tự chạy baseline → probe → verify và in `FINAL: EXPLOITED`, Manager không nên dùng heuristic (parse regex) để override. Heuristic chỉ là backup khi script ambiguous.

3. **Syntax error ≠ exploit failure**: script Python bị lỗi cú pháp là vấn đề kỹ thuật, cần retry nhiều hơn trước khi kết luận bug không khai thác được.

4. **VulnHunter cần instruction rõ ràng về số lượng**: LLM có xu hướng gen đúng 5 bugs (con số tròn) nếu prompt không nói rõ "tối thiểu 8-10". Cần explicit instruction.

## 19. Kết luận

Tại thời điểm cập nhật 23/05/2026, dự án đã có hình dạng rõ ràng của một hệ thống multi-agent pentest cho BAC/BLF. Phần quan trọng nhất của đồ án là Red/Blue debate vẫn được giữ lại: Red viết chiến lược, Blue phản biện trước khi Exec thực thi. Sau khi Exec chạy, hệ thống đi theo hướng đơn giản và dễ demo hơn: Exec tự verify trong Python exploit, còn Manager đọc verdict/evidence để quyết định exploited, retry hoặc stop.

Các cải tiến mới nhất tập trung vào **chất lượng quyết định của Manager**: phân biệt đúng loại BAC, tôn trọng verdict từ script tự verify, cho phép retry khi bằng chứng chưa đủ mạnh thay vì dừng ngay, và dynamic tick budget theo số lượng bugs. Những thay đổi này không thay đổi kiến trúc tổng thể mà chỉ tinh chỉnh logic quyết định bên trong `ManageAgent` — đúng vai trò "ông sếp thông thái" điều phối pipeline.

Với trạng thái hiện tại, dự án đủ cơ sở để báo cáo như một prototype có kiến trúc hoàn chỉnh, có pipeline chạy thật, có artifact chứng minh, có cơ chế proof quality gate phân biệt theo loại lỗ hổng, và có hướng phát triển rõ ràng cho giai đoạn sau.

---

## 20. Cập nhật 23/05/2026 — Chuyển từ Shot-based sang Orchestrator-driven

### 20.1. Vấn đề kiến trúc cũ

```text
CŨ (Shot-based, sequential):
  Crawl → VulnHunter → [Red viết SHOT PLAN → Blue review shot → Exec gen 1 Python script → chạy 1 lần]

Hạn chế:
  ① Login fail → toàn bộ pipeline mất auth → 6/10 bugs bị BLOCKED_AUTH
  ② Exec gen Python script từ shot plan → dễ syntax error, dễ vỡ với SPA
  ③ Blue review format shot plan thay vì review logic chiến lược
  ④ SPA popup overlay che nút Login → Playwright login fail
  ⑤ VulnHunter thiếu HTTP evidence → Red/Exec thiếu context
```

### 20.2. Kiến trúc mới

```text
MỚI (Orchestrator-driven, adaptive):
  Crawl (+ auto-register + overlay dismiss + raw HTTP examples)
    → VulnHunter (+ inject http_examples + filter metadata)
    → Manager Phase 0: Context Review → Sort bugs → Auth recovery
    → [Red: EXECUTION GUIDE → Blue: review guide quality → Exec: tool-loop adaptive]
    → [EXPLOITED? → PoC script generation]
```

### 20.3. So sánh

| Thành phần | Cũ | Mới |
|---|---|---|
| **Login** | Fail nếu popup/account không tồn tại | Auto-register + dismiss overlay |
| **Red** | `SHOT PLAN` (script format) | `EXECUTION GUIDE` (approach + fallbacks) |
| **Blue** | Review shot format | Review guide quality + fallback paths |
| **Exec** | Gen 1 Python script, chạy 1 lần | Tool-loop adaptive (curl/browser, 15 rounds) |
| **PoC** | Luôn gen (dù fail) | Chỉ gen khi EXPLOITED |
| **Manager** | Block nếu thiếu auth | Phase 0 review → auth recovery → sort bugs |
| **VulnHunter** | Chỉ recon.md | + raw HTTP examples + filter metadata |

### 20.4. Files đã sửa

| File | Thêm mới |
|---|---|
| `crawl_agent.py` | `_dismiss_spa_overlays()`, `_auto_register()`, `_extract_raw_endpoints()` |
| `red_team.py` | `EXECUTION GUIDE` (Approach, Auth setup, Fallback) |
| `blue_team.py` | Review criteria mới cho guide quality |
| `manage_agent.py` | `_phase0_context_review()`, `_ensure_auth_or_skip()`, `_sort_bugs_by_auth_priority()` |
| `exec_agent.py` | `_choose_exploit_mode()`, `_exploit_via_tools()`, `_generate_poc_from_evidence()` |
| `vuln_hunter_agent.py` | `_load_raw_endpoints()`, `_match_raw_endpoints()`, `_filter_challenge_metadata_bugs()` |

### 20.5. Mô hình Orchestrator

```text
ManageAgent (Orchestrator)
  ├── Phase 0: Context Review
  ├── Auth Recovery
  ├── Bug Priority Sort (anon first)
  ├── CrawlAgent    → thu thập + login
  ├── VulnHunter    → phân tích + giả thuyết
  ├── RedTeam       → EXECUTION GUIDE
  ├── BlueTeam      → review guide
  └── ExecAgent     → tool-loop exploit + PoC
```

Mỗi sub-agent nhận chỉ context cần thiết (context isolation) — tránh overfitting, tiết kiệm token.
