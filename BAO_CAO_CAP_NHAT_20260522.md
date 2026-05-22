# Báo Cáo Cập Nhật Dự Án MARL - 2026-05-22

## 1. Mục Đích

File này ghi lại trạng thái mới nhất của dự án MARL sau các thay đổi gần đây, dựa trên:

- Code hiện tại trong repo `/home/dangnosuy/Documents/UIT/doanchuyennganh/MARL`.
- Log chạy gần nhất:
  `/home/dangnosuy/Documents/UIT/doanchuyennganh/MARL/workspace/localhost_20260521_235212/marl.log`
- Report runtime tương ứng:
  `/home/dangnosuy/Documents/UIT/doanchuyennganh/MARL/workspace/localhost_20260521_235212/report.md`

Mục tiêu báo cáo cho giảng viên: chứng minh hệ thống đã có pipeline multi-agent chạy được end-to-end cho nhóm lỗi BAC/BLF, có Red/Blue debate, có Exec sinh PoC, có artifact và có report cuối.

## 2. Tóm Tắt Trạng Thái Hiện Tại

Phiên bản hiện tại đã đi theo hướng đơn giản hơn so với các bản trước:

- Manager là trung tâm điều phối duy nhất.
- Red viết chiến lược khai thác và execution shot plan.
- Blue chỉ review chiến lược trước khi chạy, không review evidence sau Exec.
- Exec sinh Python exploit, chạy script, tự verify trong script và ghi artifact.
- Manager đọc kết quả Exec để quyết định `EXPLOITED`, retry hoặc stop.
- Report cuối tách finding khai thác được và candidate chưa đủ bằng chứng.

Trạng thái kỹ thuật:

```text
Syntax chính          : OK
Pipeline end-to-end   : Chạy được
Latest run result     : 1 / 5 candidates được ghi EXPLOITED
Điểm nghẽn lớn nhất   : login/auth context cho SPA chưa ổn
Rủi ro hiện tại       : vẫn có khả năng overclaim nếu Exec tự kết luận quá rộng
```

## 3. Kiến Trúc Hiện Tại

Sơ đồ tổng quan:

```text
User Prompt
    |
    v
+------------------+
| main.py          |
| tạo workspace    |
+--------+---------+
         |
         v
+------------------+       +-------------------+
| CrawlAgent       | ----> | recon.md          |
| anonymous crawl  |       | crawl_raw.json    |
| auth crawl/fb    |       | crawl_data.txt    |
+--------+---------+       +-------------------+
         |
         v
+------------------+
| VulnHunterAgent  |
| sinh risk-bug    |
+--------+---------+
         |
         v
+--------------------------------------------------+
| ManageAgent                                      |
| - chọn bug                                       |
| - preflight SKIPPED/BLOCKED                      |
| - route Red -> Blue -> Exec                      |
| - đọc Exec verdict và ghi report                 |
+-----+------------------+--------------------+----+
      |                  |                    |
      v                  v                    v
+-----------+     +-------------+      +--------------+
| RedTeam   | --> | BlueTeam    | ---> | ExecAgent    |
| strategy  |     | review gate |      | Python PoC   |
+-----------+     +-------------+      +------+-------+
                                             |
                                             v
                                +------------------------+
                                | exploits/bug-*.py     |
                                | exploit_state/<bug>/  |
                                | result.json           |
                                +-----------+------------+
                                            |
                                            v
                                +------------------------+
                                | report.md              |
                                | report_raw.md          |
                                | report_final_vi.md     |
                                +------------------------+
```

Sơ đồ state machine rút gọn:

```text
PENDING BUG
    |
    v
[PREFLIGHT]
    |-- metadata-only ----------> SKIPPED_METADATA -> NEXT_BUG
    |-- auth required/no ctx ---> BLOCKED_AUTH     -> NEXT_BUG
    |
    v
DEBATE_RED
    |
    v
DEBATE_BLUE
    |-- rejected ---------------> RETRY_RED
    |-- approved ---------------+
                                |
                                v
                           EXECUTE_BUG
                                |
                  +-------------+--------------+
                  |                            |
                  v                            v
             EXPLOITED                    FAILED/PARTIAL
                  |                            |
                  v                            v
              NEXT_BUG                 diagnosis -> RETRY_RED /
                                       RETRY_EXEC / STOP_BUG
```

## 4. Các Thành Phần Chính

### 4.1. `main.py`

Vai trò hiện tại:

- Parse prompt, target, credential.
- Tạo hoặc tái sử dụng workspace.
- Gọi `CrawlAgent`.
- Gọi `VulnHunterAgent`.
- Khởi động `ManageAgent`.
- Dùng `shared/logger.py` để ghi log tập trung vào `marl.log`.

### 4.2. `CrawlAgent`

Điểm mới/đáng chú ý:

- Có nhận diện SPA, ví dụ latest run phát hiện Angular và giảm `max_pages=15`.
- Nếu Playwright crawl bị timeout hoặc rỗng thì chạy API discovery fallback.
- Fallback probe 138 endpoint và tìm được 19 live endpoint trong latest run.
- Tạo `recon.md` giàu hơn, latest run tạo file khoảng 11.3 KB.

Điểm đang yếu:

- Login qua httpx không tìm thấy trang login trong target SPA `localhost:3000`.
- Authenticated crawl không chạy được nên nhiều bug auth bị preflight block.

### 4.3. `VulnHunterAgent`

Vai trò:

- Đọc toàn bộ `recon.md`.
- Sinh danh sách candidate BAC/BLF vào `risk-bug.json`.

Latest run:

```text
Input recon.md : 11610 chars
Candidates    : 5
Critical      : 2
High          : 3
```

### 4.4. `ManageAgent`

Vai trò hiện tại:

- Là "sếp" điều phối toàn bộ worker agent.
- Có preflight để không đốt token vào candidate thiếu điều kiện.
- Bắt buộc Red -> Blue trước khi Exec.
- Đọc Exec output/result.json để route `NEXT_BUG`, `RETRY_*` hoặc `STOP_BUG`.
- Có khung phân tích thất bại:
  `RECON_GAP`, `STRATEGY_GAP`, `TARGETING_GAP`, `NOT_VULNERABLE`.

Điểm mới đáng chú ý:

- Có `SKIPPED_METADATA` cho candidate chỉ dựa vào metadata/challenge.
- Có `BLOCKED_AUTH` cho candidate cần auth nhưng crawl chưa có authenticated context.
- Có proof-quality gate trong code hiện tại cho admin/BAC/IDOR/BLF, để giảm overclaim.

### 4.5. RedTeamAgent và BlueTeamAgent

Red:

- Viết strategy theo bug dossier.
- Phải có `EXECUTION SHOT PLAN`.
- Có rule chống overfitting, không hardcode lab marker.
- Nếu thiếu auth context thì nên ghi `NEEDS_CONTEXT`.

Blue:

- Review strategy trước Exec.
- Gatekeep shot plan.
- Không tương tác trực tiếp với website.
- Có rule chặn các strategy quá yếu, ví dụ IDOR chỉ chứng minh public collection leak nhưng không chứng minh ownership bypass.

### 4.6. ExecAgent

Vai trò:

- Chuẩn bị session/cookie.
- Sinh Python exploit theo strategy đã được approve.
- Chạy `python3 -m py_compile`.
- Chạy script và lưu:
  - `exploits/bug-*.py`
  - `*.output.txt`
  - `*.syntax.txt`
  - `exploit_state/<bug>/result.json`
  - request/response artifacts.

Output mong đợi từ script:

```text
SHOT_RESULT: EXPLOITED/PARTIAL/FAILED
REQUEST_SUMMARY: ...
EVIDENCE_SUMMARY: ...
VERIFY_COMPLETED: yes/no
FINAL_REASON: ...
=== FINAL: EXPLOITED/PARTIAL/FAILED ===
```

## 5. Phân Tích Log Gần Nhất

Workspace:

```text
workspace/localhost_20260521_235212
```

Timeline chính:

```text
23:52:12  Start run, target http://localhost:3000/
23:52:20  CrawlAgent bắt đầu anonymous crawl
23:57:50  Playwright crawler timeout sau 330s
23:57:50  API discovery fallback chạy
23:57:52  Fallback tìm được 19 live endpoints / 138 probes
23:57:52  Login test@gmail.com thất bại: không tìm thấy trang login
23:59:34  recon.md được tạo: 11610 chars
00:00:05  VulnHunter sinh 5 vulnerability hypotheses
00:00:13  BUG-002 bị SKIPPED_METADATA
00:00:13  BUG-005 bị BLOCKED_AUTH
00:00:13  BUG-001 được đưa vào Red/Blue/Exec
00:00:45  Blue approve BUG-001
00:03:09  Exec chạy PoC BUG-001 và tự ghi EXPLOITED
00:03:10  BUG-003, BUG-004 bị BLOCKED_AUTH
00:03:10  Report: 1/5 bugs exploited
```

Kết quả candidate:

```text
+---------+------------+---------------------+-------------------------------+
| Bug     | Status     | Endpoint            | Ghi chú                       |
+---------+------------+---------------------+-------------------------------+
| BUG-002 | SKIPPED    | GET /admin          | metadata/challenge-only       |
| BUG-005 | BLOCKED    | POST /api/Orders    | cần auth, thiếu auth context  |
| BUG-001 | EXPLOITED  | GET /api/Feedbacks  | public feedback leak          |
| BUG-003 | BLOCKED    | GET /api/Orders     | cần auth, thiếu auth context  |
| BUG-004 | BLOCKED    | POST /api/Basket... | cần auth, thiếu auth context  |
+---------+------------+---------------------+-------------------------------+
```

Evidence chính của BUG-001:

```text
GET /api/Feedbacks
  status=200
  feedbacks_found=8
  response chứa UserId + comment

GET /api/Feedbacks/{id}
  id 1..5 đều status=401

GET /api/Feedbacks?userId=2
  status=200
  feedbacks_found=3
```

Artifact đã sinh:

```text
exploits/
  bug-001-exploit1.py
  bug-001-exploit1.py.output.txt
  bug-001-exploit1.py.syntax.txt

exploit_state/bug-001/
  baseline.req.txt
  baseline.resp.txt
  probe_1.req.txt ... probe_5.req.txt
  probe_1.resp.txt ... probe_5.resp.txt
  verify.req.txt
  verify.resp.txt
  result.json
```

Nhận xét quan trọng:

- Run đã chứng minh hệ thống chạy end-to-end: crawl -> recon -> candidate -> debate -> exploit -> report.
- Nhưng finding BUG-001 hiện cần diễn đạt cẩn thận. Direct object access `/api/Feedbacks/{id}` trả `401`, nên bằng chứng mạnh nhất là public information exposure qua collection endpoint và query endpoint, chưa phải ownership bypass rõ ràng.
- Code hiện tại đã có proof-quality gate chặt hơn cho BAC/IDOR. Nếu chạy lại với code hiện tại, case kiểu public collection leak có thể bị hạ từ `EXPLOITED` xuống dạng `INFO_EXPOSURE_ONLY` nếu không chứng minh được cross-user/object ownership bypass.

## 6. Điểm Khác So Với Bản Báo Cáo Trước

```text
Bản trước:
  - Tập trung mô tả kiến trúc sau khi bỏ post-Exec verifier.
  - Nhấn mạnh Exec tự verify và Manager quyết định.
  - Chưa có log mới chứng minh API fallback + preflight auth/metadata rõ ràng.

Bản hiện tại:
  - Đã có run thực tế trên target SPA localhost:3000.
  - Crawl có API-discovery fallback sau timeout.
  - ManageAgent có preflight SKIPPED_METADATA/BLOCKED_AUTH.
  - Report runtime có 1 finding và 4 candidate chưa đủ điều kiện.
  - Lộ rõ điểm nghẽn lớn: authentication context cho SPA.
```

## 7. Đánh Giá Chất Lượng Hiện Tại

Điểm mạnh:

- Pipeline đã chạy được từ đầu đến cuối.
- Log dễ đọc hơn trước, có phase, bug header, verdict, artifact.
- Red/Blue debate vẫn giữ đúng trọng tâm đồ án.
- Exec sinh PoC Python và lưu artifact tốt hơn bản shell cũ.
- Preflight giúp tránh đốt token vào candidate thiếu dữ liệu.

Điểm còn yếu:

- Authenticated crawl chưa ổn với SPA.
- Exec vẫn cố login ở cả case public/anonymous, làm chậm và nhiễu log.
- Candidate auth bị block hàng loạt vì thiếu session verified.
- Report có thể overclaim nếu `result.json` do Exec ghi quá lạc quan.
- Crawler timeout 330s làm run tốn thời gian trước khi fallback API hoạt động.

## 8. Dưới 5 Điểm Cải Thiện Có Tác Động Lớn

### 1. Làm lại login/session cho SPA

Vấn đề từ log:

```text
[LOGIN] Khong tim thay trang login
HTTP login failed -> browser login -> LLM login
CDP cookies raw: [Tool Error] TypeError: __fn__ is not a function
BLOCKED_AUTH cho 3 candidate auth
```

Tác động:

- Đây là nguyên nhân lớn nhất khiến hệ thống bị "ngu" với các bug cần auth.
- Nếu login ổn, BUG-003/BUG-004/BUG-005 sẽ được khai thác thay vì bị block.

Hướng sửa:

- Thêm login profile cho SPA/Juice Shop style: `/#/login`, `/#/register`, localStorage/JWT.
- Không chỉ tìm `<form>` server-rendered bằng httpx.
- Fix cách gọi `browser_run_code_unsafe` để lấy cookie/localStorage đúng format tool đang yêu cầu.
- Lưu `auth_context.json` gồm cookie, localStorage token, account label, verified endpoint.

### 2. Cho crawler API fallback chạy sớm hơn với SPA

Vấn đề từ log:

```text
SPA detected (Angular) — max_pages=15
Crawler timed out after 330s
Sau đó API fallback mới tìm được 19 live endpoints
```

Tác động:

- Mất hơn 5 phút trước khi có dữ liệu hữu ích.
- Với SPA/API app, endpoint API thường quan trọng hơn DOM BFS.

Hướng sửa:

- Nếu phát hiện Angular/React/Vue, chạy API fallback song song hoặc sau 60-90s thay vì đợi 330s.
- Parse JS bundle để lấy route/API path trước khi BFS sâu.
- Đặt timeout theo target type: server-rendered dùng BFS lâu hơn, SPA dùng API-first.

### 3. Nâng cấp preflight để không block auth bug quá sớm

Vấn đề từ log:

```text
BUG-003, BUG-004, BUG-005 đều BLOCKED_AUTH
Lý do: crawl không có authenticated session verified và không có http_examples
```

Tác động:

- Preflight tiết kiệm token nhưng có thể bỏ qua bug quan trọng.
- Với đồ án BAC/BLF, nhiều bug quan trọng cần auth, nên block quá sớm sẽ giảm khả năng demo.

Hướng sửa:

- Thay vì block ngay, tạo trạng thái `NEEDS_AUTH_SETUP`.
- Cho phép một bước "Auth Recovery" có bounded budget:
  - thử login SPA profile
  - thử register account mới
  - thử lấy token/localStorage
  - nếu vẫn fail mới `BLOCKED_AUTH`
- Với candidate có endpoint API rõ, vẫn cho Exec chạy unauth baseline để thu `401/403/schema` làm context.

### 4. Tách taxonomy evidence: INFO_EXPOSURE khác BAC/IDOR confirmed

Vấn đề từ latest run:

```text
BUG-001 report ghi EXPLOITED
Nhưng /api/Feedbacks/{id} đều 401
Evidence mạnh nhất là public collection leak UserId/comment
```

Tác động:

- Nếu báo cáo là "BAC/IDOR confirmed" có thể bị hỏi lại: đã chứng minh ownership bypass chưa?
- Đây là vấn đề chất lượng report, không chỉ vấn đề code.

Hướng sửa:

- Report nên có trạng thái:
  - `EXPLOITED_BAC`
  - `INFO_EXPOSURE_ONLY`
  - `PARTIAL_SIGNAL`
  - `NOT_EXPLOITED`
- Với BAC-03/IDOR, chỉ gọi confirmed khi có cross-user/object ownership bypass rõ.
- Nếu chỉ public collection leak thì vẫn ghi finding, nhưng đổi wording thành "Information Exposure / Weak Access Control Signal".

## 9. Kết Luận Ngắn Để Báo Cáo

Phiên bản hiện tại đã đủ tốt để trình bày như một prototype multi-agent pentest BAC/BLF:

- Có pipeline tự động chạy thật.
- Có Red/Blue debate đúng mục tiêu đồ án.
- Có Exec tự sinh PoC và lưu artifact.
- Có report cuối và log theo workspace.
- Có preflight để tránh chạy bừa.

Điểm cần nhấn mạnh trung thực với giảng viên:

- Hệ thống đã chạy end-to-end, nhưng khả năng khai thác auth-based BAC/BLF còn phụ thuộc mạnh vào login/session handling.
- Latest run thành công 1/5 candidate, nhưng 3/5 candidate bị chặn do thiếu authenticated context.
- Cải thiện login SPA và auth recovery sẽ tăng đáng kể độ "thông minh" thực tế của hệ thống hơn bất kỳ tinh chỉnh prompt nhỏ nào.

