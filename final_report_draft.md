# BẢN NHÁP BÁO CÁO ĐỒ ÁN CHUYÊN NGÀNH

# Đề tài: Xây dựng hệ thống đa tác tử sử dụng mô hình ngôn ngữ lớn để hỗ trợ phát hiện lỗ hổng Broken Access Control và Business Logic Flaw trên ứng dụng web

## 1. Tổng quan đề tài

### 1.1. Lý do chọn đề tài

Ứng dụng web hiện đại ngày càng phức tạp do có nhiều vai trò người dùng, nhiều trạng thái phiên, nhiều bước nghiệp vụ và nhiều API nội bộ. Các lỗ hổng như Broken Access Control và Business Logic Flaw thường không chỉ nằm ở một endpoint riêng lẻ mà xuất hiện trong mối quan hệ giữa người dùng, quyền truy cập, dữ liệu sở hữu, trạng thái giao dịch và chuỗi hành động nghiệp vụ. Vì vậy, việc kiểm thử thủ công nhóm lỗi này đòi hỏi người kiểm thử phải hiểu rõ chức năng của hệ thống, theo dõi nhiều request/response, so sánh hành vi giữa các phiên người dùng và kiểm chứng kết quả bằng bằng chứng cụ thể.

Trong bối cảnh đó, mô hình ngôn ngữ lớn có khả năng hỗ trợ phân tích ngữ cảnh, lập kế hoạch, phản biện và viết mã kiểm thử. Tuy nhiên, nếu chỉ dùng một agent duy nhất thì hệ thống dễ gặp các vấn đề như suy luận thiếu kiểm chứng, bỏ sót ngữ cảnh, lập kế hoạch quá rộng hoặc thực thi thiếu bằng chứng. Do đó, đề tài lựa chọn hướng tiếp cận đa tác tử, trong đó mỗi agent đảm nhận một vai trò chuyên biệt: trinh sát, sinh giả thuyết lỗ hổng, lập chiến lược tấn công, phản biện chiến lược, thực thi khai thác và tổng hợp báo cáo.

Dự án MARL được xây dựng nhằm mô phỏng một quy trình kiểm thử xâm nhập tự động có kiểm soát, tập trung vào hai nhóm lỗi chính: Broken Access Control và Business Logic Flaw. Hệ thống không hướng đến việc thay thế hoàn toàn chuyên gia bảo mật, mà đóng vai trò như một trợ lý tự động giúp thu thập bằng chứng, tạo giả thuyết, thử nghiệm có kiểm soát và lưu lại artifact phục vụ phân tích.

### 1.2. Mục tiêu, đối tượng và phạm vi nghiên cứu

#### 1.2.1. Mục tiêu nghiên cứu

Mục tiêu tổng quát của đề tài là xây dựng một hệ thống đa tác tử sử dụng mô hình ngôn ngữ lớn để hỗ trợ kiểm thử bảo mật ứng dụng web, tập trung vào phát hiện và kiểm chứng các lỗ hổng BAC và BLF.

Các mục tiêu cụ thể gồm:

- Xây dựng pipeline tự động từ đầu đến cuối: nhận target, crawl, phân tích recon, sinh bug candidate, tranh luận chiến lược, thực thi PoC và tạo báo cáo.
- Thiết kế kiến trúc đa tác tử có phân vai rõ ràng, gồm CrawlAgent, VulnHunterAgent, ManageAgent, RedTeamAgent, BlueTeamAgent, ExecAgent và PolicyAgent.
- Xây dựng cơ chế trinh sát ứng dụng web bằng Playwright, thu thập HTTP traffic, forms, links, buttons, API hints, workflow graph và business chain.
- Tích hợp AI-guided crawler để chọn hành động có giá trị từ danh sách candidate đã được kiểm soát an toàn.
- Xây dựng cơ chế sinh giả thuyết lỗ hổng dựa trên recon, raw crawl, workflow graph, business flows và playbook BAC/BLF.
- Xây dựng cơ chế Red/Blue debate để chiến lược tấn công được phản biện trước khi thực thi.
- Xây dựng cơ chế ExecAgent sinh script khai thác, tự xác minh kết quả và lưu lại artifact request/response.
- Xây dựng memory, context compression và graph coverage evaluator nhằm giảm lặp, giảm token và tăng chất lượng ngữ cảnh cho các agent sau.

#### 1.2.2. Đối tượng nghiên cứu

Đối tượng nghiên cứu của đề tài gồm:

- Ứng dụng web có route, form, API, cookie, token và session.
- Hai nhóm lỗ hổng bảo mật:
  - Broken Access Control: IDOR, vượt quyền, truy cập ngang hàng, truy cập route quản trị, sửa đổi cookie/role, thiếu kiểm tra sở hữu tài nguyên.
  - Business Logic Flaw: thao túng giá, số lượng, coupon, workflow skip, trạng thái đơn hàng, refund, transfer, approval hoặc các bước nghiệp vụ nhiều trạng thái.
- Mô hình đa tác tử sử dụng LLM trong quy trình kiểm thử bảo mật.
- Artifact kỹ thuật phục vụ kiểm chứng: crawl_raw.json, recon.md, risk-bug.json, business_flows.json, exploit_state, PoC script và report.md.

#### 1.2.3. Phạm vi nghiên cứu

Phạm vi triển khai tập trung vào kiểm thử ứng dụng web trong môi trường được phép, ví dụ lab nội bộ, target local hoặc môi trường thực nghiệm được cấu hình sẵn. Hệ thống ưu tiên các phương pháp kiểm thử có kiểm soát, có giới hạn và có bằng chứng.

Đề tài không tập trung vào các nhóm lỗi như SQL Injection, XSS, SSRF, XXE, lỗi cấu hình header hoặc khai thác hệ thống ngoài phạm vi web workflow. Các hành động phá hoại như xóa dữ liệu, thanh toán thật, xóa tài khoản, logout cưỡng bức hoặc thao tác phá hủy đều được crawler hạn chế bằng keyword policy.

### 1.3. Phương pháp nghiên cứu

#### 1.3.1. Nghiên cứu lý thuyết

Đề tài nghiên cứu các khái niệm nền tảng sau:

- Kiểm thử xâm nhập ứng dụng web.
- Broken Access Control và Business Logic Flaw.
- Reconnaissance, endpoint discovery, workflow mapping.
- Multi-agent system và vai trò của agent trong quy trình tự động hóa.
- Red Team/Blue Team debate trong việc kiểm soát chất lượng chiến lược.
- Prompt engineering và tool-calling cho LLM.
- Cơ chế quản lý context, memory và artifact trong hệ thống LLM.
- Cơ chế xác minh khai thác bằng script tự kiểm chứng.

#### 1.3.2. Mô phỏng thực nghiệm

Hệ thống được triển khai thành một prototype có thể chạy bằng dòng lệnh. Người dùng truyền prompt chứa URL và tùy chọn credentials. Pipeline thực hiện các bước:

```text
User Prompt
  -> CrawlAgent
  -> BusinessFlowMapper
  -> VulnHunterAgent
  -> ManageAgent
  -> RedTeamAgent
  -> BlueTeamAgent
  -> ExecAgent
  -> Report
```

Các thử nghiệm được thực hiện với ứng dụng web local hoặc target được cấp quyền. Hệ thống tạo workspace riêng cho mỗi lần chạy để lưu log, dữ liệu crawl, recon, danh sách bug, script khai thác, bằng chứng request/response và báo cáo cuối.

#### 1.3.3. Thu thập, phân tích và tổng hợp

Dữ liệu được thu thập từ Playwright browser crawl, HTTP request/response, HTML forms, API JSON keys, static JavaScript hints, auth context và workflow graph. Sau đó, dữ liệu được chuyển thành nhiều lớp artifact:

- `crawl_raw.json`: dữ liệu raw có cấu trúc.
- `crawl_data.txt`: dữ liệu crawl dạng text để đọc nhanh.
- `recon.md`: báo cáo trinh sát có cấu trúc.
- `business_flows.json`: các luồng nghiệp vụ được ánh xạ từ evidence.
- `risk-bug.json`: danh sách giả thuyết lỗ hổng.
- `report.md`: báo cáo cuối sau khi thực thi.

Các artifact này giúp hệ thống vừa có ngữ cảnh cho LLM, vừa có bằng chứng để người dùng kiểm tra lại.

### 1.4. Các nghiên cứu liên quan

Các hướng nghiên cứu liên quan gồm:

- Công cụ kiểm thử web tự động như crawler, spider, proxy scanner và dynamic application security testing.
- Các nền tảng lab bảo mật như PortSwigger Web Security Academy, OWASP Juice Shop hoặc các ứng dụng web cố tình có lỗi.
- Kỹ thuật Red Team/Blue Team trong kiểm thử bảo mật.
- Multi-agent framework như CrewAI hoặc các mô hình task orchestration.
- Ứng dụng LLM trong pentest, gồm lập kế hoạch khai thác, sinh payload, đọc log, viết script và tổng hợp báo cáo.

Điểm khác biệt của MARL là kết hợp nhiều lớp: crawler có graph, VulnHunter sinh candidate, Red/Blue tranh luận chiến lược, Exec tự xác minh bằng script và Manager điều phối state machine. Hệ thống tập trung vào BAC/BLF, tức nhóm lỗi cần hiểu ngữ cảnh nghiệp vụ thay vì chỉ dò payload kỹ thuật đơn lẻ.

### 1.5. Cấu trúc Đồ án Chuyên ngành

Cấu trúc của báo cáo được chia thành 5 chương như sau:

- Chương 1: Tổng quan đề tài. Trình bày lý do chọn đề tài, mục tiêu, đối tượng, phạm vi, phương pháp nghiên cứu và các nghiên cứu liên quan.
- Chương 2: Cơ sở lý thuyết. Trình bày các khái niệm nền tảng về kiểm thử ứng dụng web, BAC, BLF, LLM, multi-agent, Red/Blue debate, workflow graph và artifact-based verification.
- Chương 3: Phân tích và thiết kế hệ thống. Trình bày kiến trúc MARL, vai trò từng agent, pipeline 5 giai đoạn, dữ liệu vào/ra và máy trạng thái xử lý bug.
- Chương 4: Cài đặt và thực nghiệm. Trình bày môi trường, cấu trúc mã nguồn, các module chính, cơ chế crawl, sinh bug, tranh luận, thực thi và kết quả kiểm thử.
- Chương 5: Kết luận và hướng phát triển. Tổng kết kết quả đạt được, hạn chế hiện tại và các hướng cải tiến.

## 2. Cơ sở lý thuyết

### 2.1. Kiểm thử xâm nhập ứng dụng web

Kiểm thử xâm nhập ứng dụng web là quá trình đánh giá bảo mật của một website hoặc API bằng cách mô phỏng hành vi của kẻ tấn công trong phạm vi được phép. Quy trình thường gồm trinh sát, xác định bề mặt tấn công, xây dựng giả thuyết, khai thác thử, xác minh tác động và viết báo cáo.

Trong đề tài này, kiểm thử không chỉ dựa vào một request riêng lẻ mà còn dựa vào chuỗi tương tác:

```text
Page/Route -> User Action -> HTTP Request -> State Change -> Business Flow
```

Cách tiếp cận này phù hợp với BAC và BLF vì nhiều lỗi chỉ xuất hiện khi hiểu quan hệ giữa tài khoản, vai trò, tài nguyên và trạng thái nghiệp vụ.

### 2.2. Broken Access Control

Broken Access Control là nhóm lỗi xảy ra khi ứng dụng không kiểm soát đúng quyền truy cập của người dùng. Một số dạng phổ biến:

- IDOR: người dùng thay đổi ID trong URL hoặc body để truy cập tài nguyên không thuộc sở hữu.
- Horizontal access control: người dùng cùng cấp truy cập dữ liệu của nhau.
- Vertical access control: người dùng thường truy cập chức năng quản trị.
- Forced browsing: truy cập trực tiếp route/API không được hiển thị trên giao diện.
- Role/cookie tampering: chỉnh sửa cookie hoặc token chứa role/privilege.
- Missing ownership check: server chỉ kiểm tra đăng nhập nhưng không kiểm tra chủ sở hữu đối tượng.

Trong MARL, BAC được phát hiện thông qua route admin, user/profile/account endpoint, object ID fields, role/cookie hints, response chứa dữ liệu định danh và so sánh anonymous/authenticated/tampered contexts.

### 2.3. Business Logic Flaw

Business Logic Flaw là lỗi xảy ra khi ứng dụng cho phép người dùng thực hiện chuỗi hành động trái với quy tắc nghiệp vụ. Ví dụ:

- Thay đổi số lượng sản phẩm vượt giới hạn.
- Áp dụng coupon nhiều lần.
- Bỏ qua bước checkout/payment.
- Thao túng price, amount, balance.
- Chuyển trạng thái order/refund/approval trái phép.
- Race condition trong thao tác mua hàng hoặc chuyển tiền.

BLF khó phát hiện bằng scanner truyền thống vì cần hiểu luồng nghiệp vụ và trạng thái trước/sau. Do đó, MARL xây dựng workflow graph, request chains và business_chain để liên kết hành động người dùng với request thật và state transition.

### 2.4. Mô hình ngôn ngữ lớn và tool-calling

Mô hình ngôn ngữ lớn có khả năng đọc ngữ cảnh, tổng hợp thông tin, lập kế hoạch và viết mã. Tuy nhiên, LLM không nên được xem là nguồn sự thật tuyệt đối. Trong MARL, LLM được ràng buộc bởi artifact và tool:

- CrawlAgent thu thập bằng chứng thật.
- VulnHunter chỉ sinh candidate từ evidence.
- RedTeam lập chiến lược dựa trên bug dossier.
- BlueTeam phản biện chiến lược.
- ExecAgent chạy script và tự xác minh.
- Manager đọc verdict và evidence để quyết định.

Như vậy, LLM được dùng để suy luận và điều phối, còn bằng chứng kỹ thuật nằm trong request/response, graph và artifact.

### 2.5. Hệ thống đa tác tử

Hệ thống đa tác tử là kiến trúc trong đó nhiều agent độc lập đảm nhận các vai trò khác nhau. Trong MARL, các agent không tự điều phối lẫn nhau mà giao tiếp thông qua ManageAgent. Điều này giúp giảm coupling, dễ kiểm soát state machine và dễ thay thế từng agent.

Vai trò chính:

- CrawlAgent: thu thập dữ liệu target.
- VulnHunterAgent: sinh danh sách bug candidate.
- ManageAgent: điều phối toàn bộ pipeline.
- RedTeamAgent: lập chiến lược khai thác.
- BlueTeamAgent: phản biện chiến lược.
- ExecAgent: thực thi và xác minh PoC.
- PolicyAgent: kiểm soát luật nội bộ.
- MemoryStore và ContextManager: lưu ngữ cảnh, nén hội thoại, giảm token.

### 2.6. Red/Blue debate

Red/Blue debate là cơ chế trong đó RedTeam đề xuất chiến lược tấn công, còn BlueTeam đánh giá tính rõ ràng, khả thi và điều kiện xác minh. Nếu chiến lược thiếu endpoint, payload, session, verify condition hoặc bằng chứng liên quan, BlueTeam có thể reject và yêu cầu RedTeam sửa.

Mục tiêu của debate không phải kéo dài cuộc hội thoại, mà là tạo một cổng kiểm chất lượng trước khi ExecAgent chạy PoC. Điều này giúp giảm khả năng Exec thực thi một kế hoạch mơ hồ hoặc không có tiêu chí thành công.

### 2.7. Workflow graph và graph coverage

Workflow graph biểu diễn các node và edge của ứng dụng:

- Node: page, route, endpoint, workflow step.
- Edge: link, form, request, observed action, request chain, business chain.

Graph coverage evaluator đánh giá mức độ bao phủ của crawl theo các surface:

- `access_control`: admin, role, permission, users, account, profile.
- `commerce`: cart, basket, checkout, order, payment, invoice, refund.
- `value_logic`: coupon, discount, quantity, price, amount, balance, wallet, transfer.
- `workflow_state`: approval, status, cancel, return, shipping, stock.

Evaluator giúp hệ thống biết phần nào của ứng dụng đã được khảo sát và phần nào còn thiếu.

## 3. Phân tích và thiết kế hệ thống

### 3.1. Tổng quan hệ thống MARL

MARL là hệ thống kiểm thử bảo mật ứng dụng web theo mô hình multi-agent. Luồng chính:

```text
Người dùng nhập prompt + URL
  -> main.py tạo workspace và gọi CrawlAgent
  -> CrawlAgent crawl anonymous/authenticated và tạo recon
  -> BusinessFlowMapper ánh xạ business flows
  -> VulnHunterAgent sinh risk-bug.json
  -> ManageAgent lấy từng bug trong queue
  -> RedTeamAgent viết chiến lược
  -> BlueTeamAgent review chiến lược
  -> ExecAgent thực thi PoC
  -> ManageAgent tổng hợp report
```

Hệ thống dùng server OpenAI-compatible để gọi model. Trong repo có `server/server.py` đóng vai trò proxy FastAPI, nhận request theo chuẩn OpenAI Chat Completions và chuyển tiếp đến backend tương ứng.

### 3.2. Kiến trúc 5 giai đoạn

#### 3.2.1. Giai đoạn 1: Recon

Giai đoạn Recon có nhiệm vụ thu thập thông tin target. CrawlAgent parse prompt để lấy URL, credentials và focus. Sau đó agent thực hiện:

- Anonymous crawl.
- Login nếu có credentials.
- Authenticated crawl cho từng account.
- Bounded BAC/BLF discovery probes bằng GET/OPTIONS.
- Lưu crawl_raw.json, crawl_data.txt, recon.md.
- Chạy BusinessFlowMapper và VulnHunterAgent để sinh business_flows.json và risk-bug.json.

Guided crawler trong `tools/crawler.py` sử dụng Playwright để mở trình duyệt, capture network traffic, trích links/forms/buttons và thực hiện một số hành động an toàn. LLM planner chỉ được chọn từ danh sách candidate đã được crawler trích xuất và lọc policy.

#### 3.2.2. Giai đoạn 2: Candidate queue

ManageAgent đọc `risk-bug.json`, enrich từng candidate bằng context từ `crawl_raw.json`, graph context, evidence rules và auth context. Các bug được sắp xếp thành hàng đợi xử lý. Candidate có thể thuộc hai nhóm:

- Evidence-backed: có request/endpoint quan sát trực tiếp.
- Action-discovery: có cơ sở từ API hints hoặc route graph nhưng cần kiểm chứng thêm.

#### 3.2.3. Giai đoạn 3: Red/Blue debate

Với mỗi bug, ManageAgent giao bug dossier cho RedTeamAgent. RedTeamAgent viết chiến lược khai thác và execution shot plan. Sau đó ManageAgent gửi chiến lược cho BlueTeamAgent.

BlueTeamAgent có thể:

- APPROVED: chiến lược đủ rõ để Exec chạy.
- REJECTED: chiến lược thiếu thông tin, Red cần sửa.
- STOPPED: candidate không còn đáng khai thác.

#### 3.2.4. Giai đoạn 4: Execution

ExecAgent nhận chiến lược đã được approve và tạo script khai thác. Script có nhiệm vụ:

- Chuẩn bị session nếu cần.
- Gửi baseline/probe/verify request.
- Lưu request/response vào `exploit_state/<BUG_ID>/`.
- In kết quả `FINAL: EXPLOITED`, `FINAL: PARTIAL` hoặc `FINAL: FAILED`.
- Ghi `result.json`.

Manager đọc kết quả để quyết định chuyển bug tiếp theo, retry hoặc dừng bug.

#### 3.2.5. Giai đoạn 5: Report

Sau khi xử lý hàng đợi bug, ManageAgent tổng hợp báo cáo cuối. Báo cáo gồm trạng thái từng bug, strategy, evidence, PoC artifact, verdict và khuyến nghị.

### 3.3. Thành phần chính trong mã nguồn

#### 3.3.1. `main.py`

`main.py` là điểm vào của hệ thống. File này nhận prompt từ dòng lệnh, tạo workspace, thiết lập logging và điều phối các phase. Workspace thường có dạng:

```text
workspace/<domain>_<timestamp>/
```

#### 3.3.2. `agents/crawl_agent.py`

CrawlAgent chịu trách nhiệm thu thập và chuẩn hóa thông tin target. Agent này gọi `tools/crawler.py`, xử lý auth context, chạy discovery probes, ghi artifact và render recon.

Các output quan trọng:

- `crawl_raw.json`
- `crawl_data.txt`
- `recon.md`
- `auth_context.json`

#### 3.3.3. `tools/crawler.py`

Guided crawler là một trong các thành phần quan trọng nhất. Các chức năng chính:

- Capture same-origin document/xhr/fetch/form traffic.
- Extract links, forms, buttons.
- Safe deterministic exploration.
- AI-guided action planner.
- Request chain projection.
- Workflow graph builder.
- Static API hints extraction.
- Auth bootstrap.
- Crawl memory.
- Graph coverage evaluator.

Crawler output hiện có các trường:

```text
pages
http_traffic
observed_actions
action_candidates
ai_decisions
request_chains
workflow_graph
business_chain
api_hints
auth_bootstrap
crawl_memory
graph_coverage
```

#### 3.3.4. `shared/business_flow_mapper.py`

BusinessFlowMapper đọc `crawl_raw.json` và ánh xạ dữ liệu thành các luồng nghiệp vụ. Mapper ưu tiên state-changing requests, request chains, workflow graph, forms và graph coverage. Output là `business_flows.json`.

#### 3.3.5. `agents/vuln_hunter_agent.py`

VulnHunterAgent đọc recon, raw endpoints, business flows và playbook để sinh bug candidate. Agent này ưu tiên recall cao, chấp nhận false positive ở giai đoạn đầu vì các bước Red/Blue/Exec sẽ kiểm chứng sau.

#### 3.3.6. `agents/manage_agent.py`

ManageAgent là bộ điều phối trung tâm. Agent này quản lý queue bug, trạng thái từng bug, retry budget, routing tới Red/Blue/Exec và tổng hợp báo cáo.

#### 3.3.7. `agents/red_team.py`

RedTeamAgent là chiến lược gia tấn công. Agent không dùng tool trực tiếp mà đọc bug dossier và viết chiến lược khai thác rõ ràng, có shot plan và verify condition.

#### 3.3.8. `agents/blue_team.py`

BlueTeamAgent review chiến lược của Red. Agent kiểm tra chiến lược có đủ endpoint, payload, auth/session, baseline/probe/verify và điều kiện thành công hay không.

#### 3.3.9. `agents/exec_agent.py`

ExecAgent thực thi strategy đã approve. Agent dùng tools như shell, fetch, filesystem, playwright để tạo và chạy PoC. Exec tự xác minh kết quả trong script thay vì phụ thuộc hoàn toàn vào LLM.

#### 3.3.10. `shared/memory_store.py` và `shared/context_manager.py`

Hai thành phần này lưu scratchpad, finding, task registry, conversation summary và context liên quan. Mục tiêu là giảm token gửi lên LLM và tránh lặp toàn bộ lịch sử hội thoại.

### 3.4. Playbook BAC/BLF

Hệ thống có playbook trong `knowledge/bac_blf_playbook.py`, gồm nhiều pattern cho BAC và BLF. Ví dụ:

- BAC-01: IDOR.
- BAC-02: Privilege escalation.
- BAC-03: Horizontal access.
- BAC-04: Forced browsing.
- BLF-01: Price manipulation.
- BLF-02: Coupon abuse.
- BLF-03: Workflow skip.
- BLF-04: Quantity manipulation.
- BLF-05: State manipulation.

Playbook được dùng để định hướng VulnHunter, RedTeam và BlueTeam.

### 3.5. Dữ liệu và artifact

Mỗi lần chạy sinh ra nhiều artifact:

```text
workspace/<domain>_<timestamp>/
├── marl.log
├── crawl_data.txt
├── crawl_raw.json
├── recon.md
├── business_flows.json
├── risk-bug.json
├── auth_context.json
├── exploits/
├── exploit_state/
├── report_raw.md
├── report_final_vi.md
└── report.md
```

Ý nghĩa:

- `marl.log`: log toàn bộ pipeline.
- `crawl_raw.json`: nguồn dữ liệu giàu nhất.
- `recon.md`: mô tả target đã cấu trúc hóa.
- `business_flows.json`: các flow nghiệp vụ.
- `risk-bug.json`: queue bug.
- `auth_context.json`: thông tin session/token/cookie.
- `exploits/`: script PoC.
- `exploit_state/`: raw request/response evidence.
- `report.md`: báo cáo cuối.

### 3.6. Máy trạng thái xử lý bug

Mỗi bug đi qua các trạng thái:

```text
PENDING
  -> DEBATE_RED
  -> DEBATE_BLUE
  -> EXECUTING
  -> EXPLOITED | PARTIAL | FAILED | STOPPED
```

Nếu Blue reject, bug quay lại Red trong giới hạn retry. Nếu Exec trả `PARTIAL` hoặc `SCRIPT_ERROR`, Manager có thể retry Exec theo budget. Nếu `EXPLOITED`, hệ thống lưu bằng chứng và chuyển bug tiếp theo.

## 4. Cài đặt và thực nghiệm

### 4.1. Cấu trúc thư mục dự án

Cấu trúc chính:

```text
MARL/
├── main.py
├── agents/
│   ├── manage_agent.py
│   ├── crawl_agent.py
│   ├── vuln_hunter_agent.py
│   ├── red_team.py
│   ├── blue_team.py
│   ├── exec_agent.py
│   └── policy_agent.py
├── shared/
│   ├── context_manager.py
│   ├── memory_store.py
│   ├── business_flow_mapper.py
│   ├── bug_dossier.py
│   └── utils.py
├── tools/
│   └── crawler.py
├── knowledge/
│   ├── bac_blf_playbook.py
│   ├── bac_knowledge.json
│   └── blf_knowledge.json
├── server/
│   └── server.py
├── test/
├── vuln-target/
└── workspace/
```

### 4.2. Môi trường và cách chạy

Cài dependencies:

```bash
pip install -r requirements.txt
```

Chạy server API:

```bash
uvicorn server.server:app --reload
```

Chạy full pipeline:

```bash
python main.py "Test http://localhost:3000"
```

Chạy với credentials:

```bash
python main.py "Test http://localhost:3000 user:admin pass:secret"
```

Chạy crawler trực tiếp:

```bash
python tools/crawler.py --url http://localhost:3000 --max-pages 8 --max-rounds 1 --timeout 45 --headless --ai-steps 4
```

Tắt AI-guided crawl để so sánh baseline:

```bash
python tools/crawler.py --url http://localhost:3000 --max-pages 8 --max-rounds 1 --timeout 45 --headless --no-ai-guided
```

### 4.3. Biến môi trường

Một số biến quan trọng:

```env
MARL_SERVER_URL=http://127.0.0.1:5000/v1
MARL_CRAWL_MODEL=...
MARL_EXECUTOR_MODEL=...
MARL_MANAGER_MODEL=...
MARL_CRAWL_AI_GUIDED=true
MARL_CRAWL_AI_STEPS=4
GITHUB_TOKEN=...
OPENAI_API_KEY=...
```

`MARL_CRAWL_MODEL` được dùng riêng cho AI-guided crawler. Nếu không có, crawler fallback sang `MARL_EXECUTOR_MODEL` hoặc `MARL_MANAGER_MODEL`.

### 4.4. Cài đặt Guided Crawler

Guided crawler được nâng cấp từ crawler BFS/traffic capture đơn thuần thành hybrid crawler:

- Vẫn giữ crawl deterministic bằng Playwright.
- Bổ sung action inventory.
- Bổ sung AI planner chọn action.
- Bổ sung request chains.
- Bổ sung workflow graph.
- Bổ sung business_chain.
- Bổ sung crawl state memory.
- Bổ sung graph coverage evaluator.

AI planner không được click tùy ý. Planner chỉ được chọn trong candidate đã được trích xuất và kiểm soát:

- navigation an toàn;
- form GET hoặc POST được policy cho phép;
- click bounded state-changing như add-to-cart;
- loại bỏ delete, logout, payment, confirm, purchase và các hành động nguy hiểm.

### 4.5. Crawl memory và graph coverage

Crawl memory giải quyết hạn chế crawler bị lặp route/action. Memory lưu:

- endpoint đã ghé;
- action đã thử;
- action không có hiệu quả;
- surface đã cover;
- endpoint state-changing;
- endpoint bị lặp nhiều.

Fallback scoring dùng memory để:

- trừ điểm action đã thử;
- trừ điểm action no-effect;
- cộng điểm endpoint mới;
- cộng điểm action cover surface còn thiếu;
- giảm ưu tiên endpoint bị lặp.

Graph coverage evaluator chấm điểm sau crawl. Output có:

- score 0-100;
- node_count, edge_count;
- surfaces covered/gaps;
- state_changing_edge_count;
- request_chain_edge_count;
- form_edge_count;
- recommendations.

Thông tin này được đưa vào `crawl_raw.json`, `crawl_data.txt`, `recon.md` và BusinessFlowMapper.

### 4.6. Cơ chế sinh bug candidate

VulnHunterAgent tạo bug candidate từ:

- observed endpoint inventory;
- guided workflow graph;
- guided auth/API hints;
- active discovery probes;
- endpoint dossiers;
- business flows;
- BAC/BLF playbook.

Sau khi LLM sinh candidate, hệ thống post-process:

- normalize endpoint/method;
- gắn http_examples;
- lọc endpoint invalid như NaN/undefined/null;
- dedupe theo route family;
- phân biệt CRAWL_OBSERVED, ACTIVE_DISCOVERY và ACTION_DISCOVERY;
- ưu tiên state-changing endpoint đã observe.

### 4.7. Cơ chế thực thi PoC

ExecAgent tạo script PoC cho từng bug. Script nên có ba pha:

```text
baseline -> probe -> verify
```

Ví dụ:

- Baseline: request hợp lệ với session/user ban đầu.
- Probe: thay ID, role, quantity, coupon hoặc workflow state.
- Verify: so sánh response, state change hoặc dữ liệu trả về.

Kết quả được lưu trong `exploit_state/<BUG_ID>/` gồm request, response, result.json và summary.

### 4.8. Kiểm thử

Các test hiện có kiểm tra nhiều contract quan trọng:

- Cookie header chuyển thành Playwright cookies.
- Header CLI parse đúng Authorization.
- Storage state replay token/localStorage/sessionStorage.
- Workflow graph có request và action edges.
- Planner JSON parse được object từ model text.
- Fallback ưu tiên business action hơn login generic.
- Fallback tránh no-effect click.
- Request chain project thành business chain và graph.
- Graph coverage evaluator báo gap surface.
- Recon render workflow graph, API hints và graph coverage.
- VulnHunter lọc endpoint invalid và dedupe candidate.
- BusinessFlowMapper parse và ghi business_flows.

Kết quả kiểm thử gần nhất:

```bash
python -m unittest test.test_guided_crawl_contract
```

```text
Ran 23 tests
OK (skipped=1)
```

Kiểm thử toàn bộ thư mục test:

```bash
python -m unittest discover -s test
```

```text
Ran 51 tests
OK (skipped=1)
```

### 4.9. Kết quả đạt được

Hệ thống hiện đạt mức prototype chạy được theo kiến trúc chính:

- Có pipeline từ recon đến report.
- Có crawler Playwright có network capture.
- Có AI-guided action planner.
- Có workflow graph và request chains.
- Có business flow mapper.
- Có VulnHunter sinh bug candidate.
- Có Red/Blue debate trước khi thực thi.
- Có ExecAgent sinh và chạy PoC.
- Có artifact request/response để audit.
- Có memory/context compression.
- Có graph coverage evaluator.
- Có test contract cho các phần quan trọng.

## 5. Đánh giá, hạn chế và hướng phát triển

### 5.1. Đánh giá hệ thống

MARL cho thấy hướng tiếp cận multi-agent phù hợp với bài toán BAC/BLF vì nhóm lỗi này cần nhiều bước: hiểu target, lập giả thuyết, phản biện, thử nghiệm và xác minh. Thay vì để một LLM làm tất cả, hệ thống chia trách nhiệm cho nhiều agent và dùng Manager làm bộ điều phối.

Điểm mạnh chính:

- Artifact-based: mọi quyết định quan trọng dựa trên file và evidence.
- Role separation: Red lập kế hoạch, Blue phản biện, Exec thực thi.
- Recon giàu ngữ cảnh: có endpoint, forms, auth, graph, request chains, business chain.
- Có kiểm soát an toàn ở crawler.
- Có cơ chế giảm token bằng memory/context.
- Có test contract cho schema quan trọng.

### 5.2. Hạn chế hiện tại

Một số hạn chế còn tồn tại:

- Model planner đôi khi trả JSON rỗng hoặc malformed, nên crawler vẫn cần fallback/controller.
- Tốc độ crawl phụ thuộc vào model planner nếu bật AI-guided.
- Planner hiện mới chọn trong candidate click/navigation/form đã trích xuất; chưa có semantic form filling sâu.
- Business logic nhiều bước như checkout, transfer, approval, coupon, refund vẫn cần baseline và state verification tốt hơn.
- Active discovery có thể tạo signal rộng, cần phân biệt rõ hơn giữa route-like response và proof.
- BLF cần before/after state mạnh hơn để tránh suy luận quá mức.
- Hệ thống phụ thuộc vào LLM proxy, token và target đang chạy.
- Chưa có benchmark lớn trên nhiều loại web app khác nhau.

### 5.3. Hướng phát triển

Các hướng phát triển tiếp theo:

- Ép model output bằng structured output nếu backend hỗ trợ.
- Thêm planner timeout/rate telemetry.
- Mở rộng semantic form filling bằng dữ liệu an toàn theo loại field.
- Mở rộng graph coverage theo từng loại nghiệp vụ cụ thể.
- Thêm workflow memory dài hạn giữa nhiều lần crawl.
- Thêm evaluator riêng cho proof quality sau Exec.
- Benchmark trên nhiều lab BAC/BLF như PortSwigger, OWASP Juice Shop và target tự dựng.
- Tách dashboard quan sát pipeline, graph và bug queue.
- Tăng khả năng replay session/auth context cho Exec.
- Chuẩn hóa báo cáo cuối theo template học thuật và pentest report.

### 5.4. Kết luận

Đề tài đã xây dựng được một hệ thống prototype đa tác tử cho kiểm thử ứng dụng web, tập trung vào Broken Access Control và Business Logic Flaw. Hệ thống có pipeline tương đối đầy đủ từ thu thập thông tin, phân tích, sinh giả thuyết, tranh luận chiến lược, thực thi PoC đến báo cáo.

Kết quả quan trọng nhất của đề tài là chuyển hướng recon từ danh sách endpoint đơn thuần sang bản đồ workflow có ngữ cảnh:

```text
Page/Route -> User Action -> HTTP Requests -> State Change -> Business Flow
```

Nhờ đó, các agent sau có thể làm việc trên evidence cụ thể hơn. Dù vẫn còn hạn chế về semantic form filling, độ sâu của BLF nhiều bước và phụ thuộc vào LLM backend, hệ thống đã tạo nền tảng rõ ràng để tiếp tục phát triển thành công cụ hỗ trợ kiểm thử bảo mật tự động có kiểm soát.
