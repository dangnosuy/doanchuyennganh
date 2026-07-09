# BẢN NHÁP BÁO CÁO ĐỒ ÁN CHUYÊN NGÀNH

# Đề tài: Xây dựng hệ thống đa tác tử dùng LangGraph và mô hình ngôn ngữ lớn để phát hiện, khai thác và chứng minh lỗ hổng Broken Access Control và Business Logic Flaw trên ứng dụng web

## Phần mở đầu

### Trang bìa

Tên đề tài đề xuất: **Xây dựng hệ thống đa tác tử dùng LangGraph và mô hình ngôn ngữ lớn để phát hiện, khai thác và chứng minh lỗ hổng Broken Access Control và Business Logic Flaw trên ứng dụng web**.

Thông tin cần hoàn thiện khi nộp bản chính thức:

- Trường/Khoa/Bộ môn.
- Tên học phần hoặc đồ án chuyên ngành.
- Họ tên sinh viên thực hiện.
- Mã số sinh viên.
- Giảng viên hướng dẫn.
- Niên khóa và thời gian thực hiện.

### Trang bìa phụ

Trang bìa phụ có thể giữ cùng nội dung với trang bìa chính nhưng trình bày theo mẫu của khoa. Nếu cần, phần này có thể bổ sung lời cam kết về phạm vi sử dụng hệ thống: công cụ chỉ được dùng trong môi trường được cấp quyền, phục vụ học tập, nghiên cứu và kiểm thử bảo mật hợp pháp.

### Lời cảm ơn

Em xin gửi lời cảm ơn đến giảng viên hướng dẫn đã hỗ trợ định hướng đề tài, góp ý về kiến trúc hệ thống và giúp em hoàn thiện nội dung đồ án. Em cũng xin cảm ơn các tài liệu, công cụ mã nguồn mở và môi trường lab bảo mật đã cung cấp nền tảng để nghiên cứu các lỗ hổng kiểm soát truy cập và logic nghiệp vụ trong ứng dụng web.

Trong quá trình thực hiện, đề tài có tham khảo các khái niệm về kiểm thử xâm nhập, hệ thống đa tác tử, LangGraph, mô hình ngôn ngữ lớn, DAST, Red Team/Blue Team, cũng như các mô hình lưu trữ bằng chứng HTTP phục vụ xác minh. Những kiến thức này giúp em xây dựng được một prototype có khả năng điều phối nhiều bước từ trinh sát đến báo cáo.

### Nội dung

Báo cáo tập trung trình bày hệ thống \verb|marl3|, một công cụ kiểm thử bảo mật ứng dụng web theo kiến trúc đa tác tử, sử dụng LangGraph để điều phối pipeline và LLM để hỗ trợ các tác vụ cần suy luận ngữ cảnh. Hệ thống nhắm vào hai nhóm lỗ hổng chính: Broken Access Control và Business Logic Flaw.

Nội dung chính gồm:

- Lý do chọn đề tài và vấn đề của kiểm thử BAC/BLF.
- Cơ sở lý thuyết về BAC, BLF, LLM, LangGraph, evidence-based verification và long-term memory.
- Thiết kế hệ thống \verb|marl3|: pipeline chính, per-bug graph, contracts, recon, hunt, debate, exec, verify, report.
- Cài đặt và triển khai trong repo hiện tại.
- Kết quả đạt được, hạn chế và hướng phát triển.

### Danh sách hình ảnh

Các hình nên đưa vào báo cáo chính thức:

- Hình 1.1. Tổng quan bài toán phát hiện BAC/BLF trên ứng dụng web.
- Hình 3.1. Kiến trúc tổng thể hệ thống \verb|marl3|.
- Hình 3.2. Pipeline LangGraph chính: \verb|recon -> hunt -> coordinate -> bugs -> report|.
- Hình 3.3. Per-bug subgraph: \verb|debate -> exec -> verify|.
- Hình 3.4. Luồng dữ liệu giữa các object: \verb|ReconArtifact -> BugDossier -> Evidence -> Finding|.
- Hình 3.5. Hai tầng xác minh: ProofGate và VerifierPanel.
- Hình 3.6. Mô hình BodyStore lưu HTTP body theo SHA-256.
- Hình 3.7. Long-term memory chống overfit: same-target tier và cross-target tier.

### Danh sách bảng biểu

Các bảng nên đưa vào báo cáo chính thức:

- Bảng 1.1. So sánh các hướng nghiên cứu/công cụ liên quan.
- Bảng 2.1. Các dạng lỗi BAC tiêu biểu.
- Bảng 2.2. Các dạng lỗi BLF tiêu biểu.
- Bảng 3.1. Vai trò các node/agent trong hệ thống.
- Bảng 3.2. Các contracts dữ liệu chính trong \verb|marl3|.
- Bảng 3.3. Artifact sinh ra trong workspace.
- Bảng 3.4. Các trạng thái xử lý bug.
- Bảng 4.1. Môi trường và công cụ triển khai.
- Bảng 4.2. Tiêu chí đánh giá hệ thống.
- Bảng 5.1. Ưu điểm, hạn chế và hướng phát triển.

### Danh mục từ viết tắt

| Từ viết tắt | Ý nghĩa |
|---|---|
| BAC | Broken Access Control |
| BLF | Business Logic Flaw |
| LLM | Large Language Model |
| DAST | Dynamic Application Security Testing |
| PoC | Proof of Concept |
| API | Application Programming Interface |
| HTTP | HyperText Transfer Protocol |
| IDOR | Insecure Direct Object Reference |
| SPA | Single Page Application |
| CLI | Command Line Interface |
| JSON | JavaScript Object Notation |
| PII | Personally Identifiable Information |

### Danh mục từ tạm dịch

| Thuật ngữ | Cách dùng trong báo cáo |
|---|---|
| Recon | Trinh sát/thu thập bằng chứng |
| Hunt | Sinh giả thuyết lỗ hổng |
| Coordinate | Xếp hàng và liên kết phụ thuộc |
| Debate | Tranh luận/kiểm duyệt chiến lược |
| Execution | Thực thi khai thác |
| Verify | Xác minh bằng chứng |
| Report | Báo cáo |
| Evidence | Bằng chứng thực thi |
| ProofGate | Cổng kiểm chứng tất định |
| BodyStore | Kho lưu nội dung HTTP body |
| BugDossier | Phiếu nghi vấn lỗ hổng |
| Finding | Kết quả đánh giá cuối cho một bug |

## Tóm tắt đồ án

Đề tài xây dựng \verb|marl3|, một prototype công cụ kiểm thử bảo mật ứng dụng web tập trung vào hai nhóm lỗ hổng Broken Access Control và Business Logic Flaw. Đây là hai nhóm lỗi khó phát hiện tự động vì cần hiểu ngữ cảnh quyền truy cập, vai trò người dùng, dữ liệu sở hữu, chuỗi hành động nghiệp vụ và trạng thái trước/sau. Không giống các lỗi injection có thể kiểm tra bằng payload cố định, BAC và BLF yêu cầu hệ thống phải thu thập dữ liệu thật, lập giả thuyết có căn cứ, thực thi thử nghiệm và chứng minh bằng request/response.

Kiến trúc hiện tại của dự án theo README là package \verb|marl3|, đặt trong \verb|src/marl3|, dùng LangGraph làm xương sống điều phối. Pipeline chính gồm các node \verb|recon|, \verb|hunt|, \verb|coordinate|, \verb|bugs|, \verb|report|. Trong node \verb|bugs|, hệ thống chạy per-bug subgraph gồm \verb|debate|, \verb|exec|, \verb|verify|. Điểm quan trọng là quyết định chuyển node do code routing function xử lý, không phải do LLM tự quyết định. LLM chỉ hoạt động trong từng nhiệm vụ hẹp: Hunter sinh BugDossier, Red lập chiến lược, Blue phản biện, Exec dùng tools gửi request, VerifierPanel đưa nhận xét tư vấn.

Hệ thống sử dụng các contracts Pydantic để chuẩn hóa dữ liệu: \verb|ReconArtifact|, \verb|Endpoint|, \verb|HttpExchange|, \verb|AuthDiff|, \verb|BusinessFlow|, \verb|BugDossier|, \verb|Evidence|, \verb|ProofMarker|, \verb|Verdict|, \verb|Finding|. HTTP body được lưu lossless trong \verb|BodyStore| theo SHA-256, giúp không mất bằng chứng khi response dài. Exec ghi mọi request/response vào \verb|Evidence| thông qua \verb|RecordingHttpClient|. Verdict cuối cùng được quyết định bởi ProofGate tất định đọc structured evidence, còn VerifierPanel LLM chỉ đóng vai trò tư vấn và được ghi vào report.

Kết quả của đề tài là một kiến trúc có thể chạy end-to-end trong môi trường được phép: crawl target, sinh recon, tạo bug candidates, tranh luận Red/Blue, thực thi exploit, xác minh bằng ProofGate và tạo \verb|report.md|, \verb|findings.json|, PoC HTTP. Hệ thống vẫn còn hạn chế như test mới cho \verb|src/marl3| chưa đầy đủ, crawler hiện thiên về HTTP-native server-rendered app, cần benchmark ground truth và cần mở rộng ProofGate cho nhiều pattern BAC/BLF hơn. Tuy vậy, kiến trúc hiện tại đã tạo nền tảng rõ ràng cho một công cụ pentest tự động có kiểm soát, dựa trên evidence thật và giảm phụ thuộc vào phán đoán chủ quan của LLM.

## Chương 1. Tổng quan đề tài

### 1.1. Lý do chọn đề tài

Các ứng dụng web hiện đại có cấu trúc phức tạp hơn nhiều so với các website tĩnh truyền thống. Một chức năng đơn giản như mua hàng có thể liên quan đến nhiều bước: xem sản phẩm, thêm vào giỏ, cập nhật số lượng, áp mã giảm giá, checkout, thanh toán, tạo đơn hàng, hủy đơn hoặc hoàn tiền. Tương tự, một hệ thống tài khoản có thể có nhiều loại người dùng như anonymous, user thường, user khác, nhân viên và admin. Điều này làm cho lỗ hổng bảo mật không còn chỉ nằm ở một tham số đầu vào mà nằm trong quan hệ giữa người dùng, object, quyền, trạng thái và thứ tự hành động.

Broken Access Control xảy ra khi ứng dụng không kiểm soát đúng ai được phép làm gì. Ví dụ user thường truy cập được trang admin, user A đọc được đơn hàng của user B, hoặc cookie role có thể sửa thành admin. Business Logic Flaw xảy ra khi ứng dụng xử lý đúng về mặt kỹ thuật nhưng sai quy tắc nghiệp vụ. Ví dụ server chấp nhận số lượng âm, cho dùng lại coupon một lần, cho checkout khi chưa thanh toán, hoặc cho hoàn tiền nhiều lần.

Các scanner tự động truyền thống thường gửi payload cố định vào từng field. Cách này phù hợp với injection nhưng không đủ cho BAC/BLF vì hai nhóm lỗi này cần ngữ cảnh. Một request \verb|GET /orders/1| chỉ có ý nghĩa nếu biết order 1 thuộc ai và actor hiện tại là ai. Một request \verb|POST /coupon/apply| chỉ có ý nghĩa nếu biết coupon đã dùng chưa, order đã checkout chưa và trạng thái sau request thay đổi như thế nào.

Mô hình ngôn ngữ lớn có khả năng đọc ngữ cảnh và lập kế hoạch, nhưng không nên được tin tuyệt đối. LLM có thể bịa endpoint, hiểu sai response hoặc tự tin kết luận khi chưa đủ bằng chứng. Vì vậy, đề tài chọn hướng kết hợp LLM với code tất định: LLM hỗ trợ suy luận trong từng node, còn code điều phối pipeline và ProofGate quyết định verdict dựa trên dữ liệu thật.

### 1.2. Các nghiên cứu liên quan

Các hướng liên quan đến đề tài gồm:

- Công cụ DAST như OWASP ZAP, Burp Scanner, Nikto.
- Web crawler và HTTP proxy dùng trong kiểm thử ứng dụng web.
- Các lab bảo mật như OWASP Juice Shop, PortSwigger Web Security Academy.
- Red Team/Blue Team trong kiểm thử bảo mật.
- Multi-agent framework như LangGraph, CrewAI.
- LLM tool-calling trong tự động hóa pentest.
- Proof-of-concept generation và evidence-based reporting.

Điểm khác biệt của \verb|marl3| là hệ thống không để một agent LLM quản lý toàn bộ quy trình. LangGraph định nghĩa state machine bằng code; LLM chỉ xử lý từng phần nhỏ. Hệ thống cũng không để LLM quyết định exploit thành công hay thất bại. ProofGate đọc structured Evidence và đưa ra verdict.

#### Bảng: So sánh các hướng nghiên cứu liên quan

| Hướng tiếp cận | Điểm mạnh | Hạn chế với BAC/BLF | Cách \verb|marl3| xử lý |
|---|---|---|---|
| Scanner payload truyền thống | Nhanh, tự động, tốt với injection | Thiếu ngữ cảnh role/workflow | Thu thập ReconArtifact, AuthDiff, WorkflowGraph |
| Manual pentest | Chính xác, hiểu nghiệp vụ | Tốn thời gian, khó lặp lại | Tự động hóa recon, hunt, exec, report |
| Một LLM agent duy nhất | Linh hoạt, dễ prototype | Dễ ảo giác, khó kiểm soát trạng thái | Chia node/agent, routing bằng LangGraph |
| Agent manager bằng LLM | Có thể tự điều phối | Rủi ro chuyển trạng thái sai | Code routing function quyết định node tiếp theo |
| LLM verifier | Có khả năng đọc ngữ nghĩa | Có thể phán sai, không ổn định | ProofGate là authority, VerifierPanel advisory |
| Memory transcript | Dễ lưu lịch sử | Dài, nhiễu, overfit target | Long-term memory lưu episode đã qua ProofGate |

### 1.3. Mục tiêu, đối tượng và phạm vi nghiên cứu

#### 1.3.1. Mục tiêu nghiên cứu

Mục tiêu tổng quát là xây dựng một hệ thống multi-agent dùng LangGraph và LLM để hỗ trợ phát hiện, khai thác và chứng minh BAC/BLF trên ứng dụng web.

Các mục tiêu cụ thể:

- Xây dựng CLI \verb|marl3| với các lệnh \verb|run|, \verb|crawl|, \verb|memory|.
- Xây dựng pipeline chính bằng LangGraph: \verb|recon -> hunt -> coordinate -> bugs -> report|.
- Xây dựng per-bug subgraph: \verb|debate -> exec -> verify|, có loop quay lại debate khi proof fail.
- Xây dựng HTTP-native recon crawler thu thập endpoint, forms, auth sessions, auth diffs, workflow graph, business flows.
- Lưu mọi HTTP body lossless bằng BodyStore và BodyRef.
- Sinh BugDossier từ ReconArtifact bằng kết hợp deterministic seeds và LLM Hunter.
- Dùng Red/Blue debate để tạo chiến lược đã được phản biện trước execution.
- Dùng ExecutionRunner và RecordingHttpClient để gửi request thật, ghi Evidence, sinh PoC.
- Dùng ProofGate tất định để quyết định kết quả, VerifierPanel để bổ sung nhận xét độc lập.
- Sinh report có thể audit gồm \verb|report.md|, \verb|findings.json|, PoC HTTP.
- Thiết kế long-term memory chống overfit giữa các target.

#### 1.3.2. Đối tượng nghiên cứu

Đối tượng nghiên cứu gồm:

- Ứng dụng web có route, form, cookie, session, API endpoint và nhiều vai trò.
- Các nhóm lỗi BAC: sensitive data exposure, privilege escalation, IDOR, forced browsing, ownership bypass.
- Các nhóm lỗi BLF: value tampering, quantity tampering, coupon reuse, workflow skip, refund/cancel abuse.
- Pipeline multi-agent dùng LangGraph.
- Các dữ liệu trung gian: ReconArtifact, BugDossier, Evidence, Verdict, Finding.

#### 1.3.3. Phạm vi nghiên cứu

Phạm vi hệ thống là kiểm thử ứng dụng web trong môi trường được cấp quyền, ví dụ lab local hoặc target demo. Hệ thống không hướng đến brute force, phá hoại dữ liệu, DDoS hoặc khai thác ngoài phạm vi BAC/BLF. Các request state-changing cần được giới hạn trong target được phép.

Về codebase, báo cáo lấy package \verb|src/marl3| làm kiến trúc chính vì README hiện tại mô tả \verb|marl3| là hệ thống LangGraph-powered. Repo vẫn còn lớp legacy như \verb|main.py|, \verb|agents/|, \verb|tools/crawler.py|, \verb|shared/| từ giai đoạn trước. Những file này có giá trị lịch sử và một số test contract, nhưng không phải trọng tâm kiến trúc mới.

### 1.4. Phương pháp nghiên cứu

Phương pháp nghiên cứu gồm:

- Nghiên cứu lý thuyết về BAC, BLF, DAST, multi-agent, LangGraph, LLM tool-calling và proof gate.
- Phân tích yêu cầu từ bài toán BAC/BLF: cần nhiều actor, nhiều request, state trước/sau và evidence thật.
- Thiết kế pipeline dạng state graph để tránh để LLM tự điều phối.
- Thiết kế contracts Pydantic để dữ liệu truyền giữa node rõ ràng.
- Cài đặt prototype trong package \verb|src/marl3|.
- Thực nghiệm trên target local/demo và lưu artifact.
- Đánh giá qua khả năng thu thập recon, sinh candidate, thực thi, xác minh và báo cáo.

### 1.5. Những điểm mới của đề tài

Các điểm mới/chính của đề tài:

- Dùng LangGraph để điều phối multi-agent pipeline bằng code, không để LLM quyết định routing.
- Tách rõ các phase: recon, hunt, coordinate, debate, exec, verify, report.
- Dùng per-bug subgraph có retry theo \verb|PROOF_QUALITY_FAIL|.
- Dùng BodyStore lossless cho HTTP body, tránh cắt mất bằng chứng.
- Dùng ProofGate tất định là authority cho verdict.
- VerifierPanel chỉ tư vấn, không override gate.
- Dùng long-term memory chỉ học từ episode đã qua ProofGate.
- Chia memory thành same-target và cross-target để chống overfit.
- Report được xây từ Finding objects có cấu trúc, không phải từ timeline text.

### 1.6. Cấu trúc đồ án chuyên ngành

Báo cáo gồm 5 chương:

- Chương 1 trình bày tổng quan đề tài.
- Chương 2 trình bày cơ sở lý thuyết.
- Chương 3 trình bày phương pháp và thiết kế hệ thống.
- Chương 4 trình bày thực nghiệm và triển khai.
- Chương 5 trình bày đánh giá, hạn chế và hướng phát triển.

## Chương 2. Cơ sở lý thuyết

### 2.1. Tổng quan về kiểm thử bảo mật ứng dụng web

Kiểm thử bảo mật ứng dụng web là quá trình đánh giá khả năng chống chịu của ứng dụng trước các hành vi truy cập trái phép, thao túng dữ liệu hoặc lạm dụng logic nghiệp vụ. Một quy trình kiểm thử thường gồm trinh sát, xác định bề mặt tấn công, tạo giả thuyết, thực thi thử nghiệm, xác minh và báo cáo.

Với BAC/BLF, việc kiểm thử cần chú trọng context. Một response 200 không đủ để nói có lỗi; cần biết actor là ai, endpoint gì, object thuộc ai, trạng thái trước/sau ra sao và điều kiện nghiệp vụ nào bị vi phạm.

### 2.2. Broken Access Control

Broken Access Control là lỗi khi ứng dụng không áp dụng đúng chính sách phân quyền.

#### 2.2.1. Các dạng BAC tiêu biểu

| Mã | Dạng lỗi | Mô tả | Bằng chứng cần có |
|---|---|---|---|
| BAC-01 | Sensitive data exposure | Actor không đủ quyền nhận dữ liệu nhạy cảm | 2xx response chứa PII/sensitive fields |
| BAC-02 | Privilege escalation | Tamper cookie/param để có quyền cao hơn | Blocked -> allowed sau tamper |
| BAC-03 | IDOR | Truy cập object của người khác qua ID | Owner field khác attacker identity |
| BAC-06 | Forced browsing | Vào route/admin endpoint bị ẩn | Low-priv actor truy cập được privileged content |

#### 2.2.2. Yêu cầu xác minh BAC

Để xác minh BAC cần:

- Ghi rõ actor/session.
- Ghi rõ endpoint và method.
- Có baseline hoặc thông tin quyền dự kiến.
- Có response body thật.
- Có proof marker như \verb|OWNERSHIP_BYPASS|, \verb|PRIVILEGED_ACCESS|, \verb|AUTH_BYPASS|, \verb|SENSITIVE_FIELD_EXPOSED|.

### 2.3. Business Logic Flaw

Business Logic Flaw xảy ra khi server cho phép một thao tác trái với quy tắc nghiệp vụ.

| Mã | Dạng lỗi | Ví dụ | Bằng chứng cần có |
|---|---|---|---|
| BLF-01 | Price/amount tamper | Gửi amount âm | 2xx + state delta hoặc accepted invalid value |
| BLF-05 | Coupon reuse | Dùng lại coupon sau checkout/cancel | Cùng code accepted nhiều lần với consume event |
| BLF-06 | Quantity tamper | Quantity âm hoặc cực lớn | 2xx + quantity/state thay đổi |
| BLF-03 | State skip | Bỏ qua bước bắt buộc | State transition không hợp lệ |

BLF cần ordered exchanges và state snapshot. Vì vậy Evidence trong \verb|marl3| hỗ trợ \verb|state_before|, \verb|state_after|, \verb|state_delta|.

### 2.4. LangGraph và mô hình điều phối bằng StateGraph

LangGraph cho phép xây dựng pipeline dưới dạng đồ thị có trạng thái. Trong \verb|marl3|, pipeline chính gồm:

\begin{verbatim}
START -> recon -> hunt -> coordinate -> bugs -> report -> END
\end{verbatim}

Node \verb|bugs| chạy subgraph cho từng BugDossier:

\begin{verbatim}
START -> debate -> exec -> verify -> END
\end{verbatim}

Routing là các hàm Python đọc state, ví dụ \verb|_after_debate|, \verb|_after_exec|, \verb|_after_verify|. Điều này giúp hệ thống ổn định hơn so với việc hỏi LLM “nên làm gì tiếp”.

### 2.5. LLM trong hệ thống bảo mật

LLM được dùng trong các vai trò cần suy luận:

- Hunter đọc recon và sinh BugDossier.
- Red viết strategy.
- Blue phản biện strategy.
- Exec chọn tool/request theo response.
- VerifierPanel đánh giá evidence ở mức tư vấn.
- Reporter tạo summary dễ đọc.

Tuy nhiên, LLM không phải nguồn sự thật cuối cùng. Output của LLM cần được parse, validate, enrich hoặc kiểm chứng bằng code.

### 2.6. Evidence, ProofMarker và ProofGate

Evidence là object ghi lại toàn bộ quá trình thực thi một bug. Evidence gồm:

- bug_id, pattern_id, category, endpoint, method.
- ordered exchanges.
- proof_markers.
- state_before, state_after, state_delta.
- session_context.
- verdict_status.

ProofGate đọc Evidence và sinh Verdict. Nếu đủ required markers thì \verb|EXPLOITED|; nếu có marker nhưng thiếu marker bắt buộc thì có thể \verb|INFO_EXPOSURE_ONLY|; nếu không có marker thỏa thì \verb|FAILED| hoặc \verb|PROOF_QUALITY_FAIL| ở node verify.

### 2.7. BodyStore và lưu bằng chứng lossless

BodyStore lưu mọi HTTP body dưới dạng file nhị phân theo hash SHA-256. BodyRef là con trỏ đến body đó. Cách này có các lợi ích:

- Không cắt body giữa chừng.
- Dễ deduplicate.
- Giảm RAM trong object.
- Cho phép ProofGate và report đọc lại full response.
- Dễ audit vì body thật nằm trên đĩa.

### 2.8. Long-term memory chống overfit

Long-term memory không lưu transcript tùy tiện. Nó lưu Episode sau khi ProofGate đã xác minh. Một Episode gồm target fingerprint, pattern_id, endpoint_family, method, outcome, payload, proof_markers, summary, run_id.

Memory có hai tầng:

- Same-target: reuse payload cụ thể chỉ trên cùng target fingerprint.
- Cross-target: chỉ inject technique trừu tượng nếu kỹ thuật đã thành công trên đủ số target khác nhau.

Điều này giúp hệ thống học từ kinh nghiệm mà không hardcode endpoint/payload của target cũ vào target mới.

### 2.9. Các nghiên cứu liên quan

Các nghiên cứu/công cụ liên quan gồm DAST, Burp Suite, OWASP ZAP, web crawler, lab bảo mật, LLM agents và multi-agent orchestration. \verb|marl3| kế thừa ý tưởng từ các hệ thống này nhưng nhấn mạnh ba nguyên tắc: artifact lossless, code routing, data-driven verdict.

## Chương 3. Phương pháp và thiết kế hệ thống

#### Hình: Kiến trúc hệ thống

Sơ đồ kiến trúc đề xuất đưa vào báo cáo:

\begin{verbatim}
User CLI
  |
  v
marl3.cli
  |
  v
LangGraph Main Pipeline
  |-- recon
  |-- hunt
  |-- coordinate
  |-- bugs
  |     |-- debate
  |     |-- exec
  |     |-- verify
  |-- report
  |
  v
Workspace artifacts
\end{verbatim}

### 3.1. Tổng quan

Package chính của hệ thống nằm trong \verb|src/marl3|. Các nhóm module chính:

\begin{verbatim}
src/marl3/
├── cli.py
├── config.py
├── workspace.py
├── state.py
├── graph/
├── contracts/
├── recon/
├── dossier/
├── debate/
├── execution/
├── verify/
├── report/
├── memory/
├── llm/
├── prompts/
└── knowledge/
\end{verbatim}

CLI tạo config, workspace, LLM client rồi gọi LangGraph pipeline. Các node đọc/ghi state và artifact vào workspace.

### 3.2. CLI, config và workspace

#### Hình: Luồng khởi tạo pipeline

\begin{verbatim}
marl3 run prompt
  -> parse URL/credentials
  -> load config/default.yaml
  -> create RunWorkspace
  -> create LLMClient
  -> make PipelineState
  -> pipeline.ainvoke(state)
\end{verbatim}

\verb|config/default.yaml| cấu hình model theo role:

- crawler
- hunter
- red
- blue
- exec
- verifier
- reporter

Ngoài ra còn có debate budget, verifier count, execution timeout, recon max pages, body store size, workspace base dir và long-term memory settings.

\verb|RunWorkspace| quản lý mọi file:

| Artifact | Mục đích |
|---|---|
| \verb|recon.json| | ReconArtifact machine-readable |
| \verb|recon.md| | Recon human-readable |
| \verb|sessions.json| | Auth profiles/session data |
| \verb|bodies/| | HTTP bodies lossless |
| \verb|bugs.json| | BugDossier list |
| \verb|memory.json| | Per-run memory |
| \verb|evidence/<BUG_ID>/evidence.json| | Evidence từng bug |
| \verb|debates/<BUG_ID>.md| | Debate transcript/summary |
| \verb|pocs/poc_<BUG_ID>.txt| | PoC HTTP |
| \verb|findings.json| | Finding objects |
| \verb|report.md| | Báo cáo cuối |
| \verb|run.log| | Log |
| \verb|usage.json| | Thống kê usage |

### 3.3. RECON phase

Recon phase dùng \verb|GuidedCrawler| trong \verb|src/marl3/recon/crawler.py|. Crawler hiện tại là HTTP-native crawler dùng \verb|httpx| và HTML parsing. Nó phù hợp với ứng dụng server-rendered hoặc các endpoint có thể phát hiện qua HTML/script.

Các bước chính:

1. Chuẩn hóa credentials.
2. Anonymous crawl bằng link/form parsing.
3. Probe các path có giá trị cho BAC/BLF như \verb|/admin|, \verb|/profile|, \verb|/cart|, \verb|/checkout|, \verb|/api/v1/users|, \verb|/api/v1/orders/1|.
4. Soft-404 filtering.
5. Submit forms với synthetic values.
6. Safe-probe JS-discovered endpoints.
7. Login từng credential trong session riêng.
8. Authenticated crawl và probe.
9. Tính endpoints, auth_diffs, workflow_graph, business_flows, api_hints.
10. Ghi \verb|recon.json| và \verb|recon.md|.

#### Hình: Recon data flow

\begin{verbatim}
HTTP responses
  -> HttpExchange
  -> BodyStore
  -> Endpoint extraction
  -> AuthDiff
  -> WorkflowGraph
  -> BusinessFlow
  -> ReconArtifact
\end{verbatim}

### 3.4. HUNT phase

Hunt phase dùng \verb|VulnCandidateGenerator|. Input là ReconArtifact và optional lessons từ long-term memory. Candidate được tạo từ hai nguồn:

- Deterministic seeds: admin path, ID path, auth-gated path, numeric field, state-changing JS/form action.
- LLM Hunter: đọc recon và playbook để sinh candidate có hypothesis và exploit approach.

Sau khi LLM sinh output, hệ thống parse JSON, normalize pattern, dedupe và attach HttpExample/EvidenceRule. Dossier sau đó được enrich thêm graph context ở node hunt.

#### Bảng: BugDossier fields

| Field | Ý nghĩa |
|---|---|
| \verb|id| | Mã bug, ví dụ BUG-001 |
| \verb|category| | BAC hoặc BLF |
| \verb|pattern_id| | BAC-03, BLF-05... |
| \verb|endpoint| | Endpoint family |
| \verb|method| | HTTP method |
| \verb|hypothesis| | Giả thuyết cụ thể |
| \verb|exploit_approach| | Cách thử khai thác |
| \verb|auth| | Yêu cầu attacker/victim/admin role |
| \verb|http_examples| | Exchange thật từ recon |
| \verb|graph_context| | Node/chain/state fields liên quan |
| \verb|evidence_rules| | Marker cần thỏa |
| \verb|confidence| | Độ tin cậy candidate |

### 3.5. COORDINATE phase

Coordinate phase gọi \verb|rank_and_link|. Mục tiêu là xếp candidate theo ưu tiên và gắn phụ thuộc. Ví dụ:

- Candidate có severity cao xử lý trước.
- Candidate có evidence rõ hơn xử lý trước.
- Candidate BLF chain cần endpoint/cart/order liên quan thì được liên kết với context phù hợp.
- Candidate có dependency có thể được gắn vào \verb|graph_context.depends_on| hoặc \verb|enables|.

### 3.6. DEBATE phase

Debate phase có Red và Blue. Red viết strategy, execution guide và success condition. Blue kiểm tra kế hoạch.

Red cần dựa trên recon và dossier, không được bịa endpoint. Blue có thể:

- APPROVE: chiến lược đủ rõ.
- REVISE: cần sửa.
- STOP hoặc INSUFFICIENT_CONTEXT: không đủ evidence để thử.

Khi verify fail và quay lại debate, verifier rationale được đưa vào context để Red sửa đúng vấn đề proof gate đã chỉ ra.

### 3.7. EXEC phase

Exec phase dùng \verb|ExecutionRunner|. Runner tạo Evidence, RecordingHttpClient, ToolBridge, BodyStore và AuthSessionStore.

Các cơ chế bảo vệ Exec:

- Inject endpoint schema từ recon.
- Inject known values từ body store.
- Inject exec memory từ MemoryStore.
- Inject long-term skills từ LongTermMemory.
- Chain steering cho BLF nhiều bước.
- Không cho BLF dừng nếu chưa có tampering POST hoặc chưa đủ state-changing chain.
- Deterministic fallback cho BLF nếu LLM không thực hiện tamper.
- Deterministic fallback cho BAC-02 nếu cookie tamper bị LLM tạo sai.
- Sinh PoC sau mỗi run từ Evidence.

### 3.8. VERIFY phase

Verify phase có hai tầng:

\begin{verbatim}
Evidence
  -> ProofGate  -> authority verdict
  -> VerifierPanel -> advisory rationale
\end{verbatim}

ProofGate hiện có các nhóm rule chính:

- \verb|BACProofGate|: IDOR, admin/forced browsing, param/cookie escalation, generic BAC.
- \verb|BLFProofGate|: price tamper, coupon abuse, quantity tamper, state skip, generic BLF.

VerifierPanel gồm nhiều VerifierAgent chạy song song. Panel không quyết định cuối cùng, nhưng giúp report có góc nhìn định tính.

### 3.9. REPORT phase

ReportBuilder đọc list Finding, sort exploited trước, ghi \verb|findings.json| và \verb|report.md|. Với mỗi finding exploited hoặc info exposure, report hiển thị:

- Pattern.
- Severity.
- Endpoint.
- Status.
- Summary.
- Evidence exchanges.
- Proof markers.
- Verifier panel.
- PoC HTTP.

### 3.10. Long-term memory

LongTermMemory dùng SQLite ở \verb|~/.local/share/marl3/memory.db| theo config. Nó lưu Episode sau verify. Có hai nhóm retrieval:

- Lessons cho Hunt: same-target lessons và distilled rules.
- Skills cho Exec: same-target concrete payload và cross-target abstract technique.

Distillation promote repeated exploited episodes thành rule nếu đạt ngưỡng số lần thành công và số target khác nhau.

### 3.11. Quan hệ với lớp legacy

Repo vẫn còn lớp legacy từ phiên bản MARL trước:

- \verb|main.py|
- \verb|agents/|
- \verb|tools/crawler.py|
- \verb|shared/|
- \verb|test/|

Lớp này có guided Playwright crawler, request chain, graph coverage và ManageAgent LLM. Tuy nhiên README hiện tại và package metadata chỉ rõ \verb|marl3| là package chính, mô tả “LangGraph-powered multi-agent BAC/BLF web pentest tool”. Vì vậy báo cáo nên tập trung vào \verb|src/marl3|; lớp legacy nên được ghi nhận là nền tảng trước đó hoặc module tham khảo.

## Chương 4. Thực nghiệm và triển khai

### 4.1. Môi trường và công cụ

#### Bảng: Môi trường triển khai

| Thành phần | Công nghệ |
|---|---|
| Ngôn ngữ | Python >= 3.11 |
| Orchestration | LangGraph |
| CLI | Typer |
| Data contracts | Pydantic |
| HTTP client | httpx |
| HTML parsing | BeautifulSoup |
| LLM client | OpenAI-compatible client |
| Config | YAML + pydantic settings |
| Memory DB | SQLite |
| Report | Markdown + JSON |

Cài đặt:

\begin{verbatim}
pip install -e .
\end{verbatim}

Cài thêm dev/proxy:

\begin{verbatim}
pip install -e '.[dev,proxy]'
\end{verbatim}

Chạy pipeline:

\begin{verbatim}
marl3 run "http://localhost:5000 user:alice pass:alice123 user:bob pass:bob123"
\end{verbatim}

Chạy crawl-only:

\begin{verbatim}
marl3 crawl "http://localhost:5000 user:alice pass:alice123"
\end{verbatim}

### 4.2. Các phương pháp đánh giá

#### 4.2.1. Đánh giá khả năng recon

Các chỉ số đề xuất:

- Số endpoint phát hiện.
- Số HttpExchange ghi lại.
- Số auth profiles đăng nhập thành công.
- Số AuthDiff.
- Số workflow nodes/edges.
- Số business flows.
- Tỉ lệ endpoint expected được phát hiện nếu có ground truth.

#### 4.2.2. Đánh giá khả năng sinh candidate

Các chỉ số:

- Số BugDossier sinh ra.
- Tỉ lệ candidate có HttpExample.
- Tỉ lệ candidate có evidence_rules.
- Candidate recall so với ground truth.
- False positive rate sau verify.

#### 4.2.3. Đánh giá thực thi và xác minh

Các chỉ số:

- Số candidate được debate approve.
- Số candidate thực thi thành công về mặt request.
- Số Evidence có đủ exchanges.
- Số bug \verb|EXPLOITED| theo ProofGate.
- Số \verb|INFO_EXPOSURE_ONLY|.
- Số \verb|PROOF_QUALITY_FAIL| quay lại debate.
- Số PoC sinh ra.

### 4.3. Kết quả

Dựa trên scan project hiện tại, hệ thống đã có các thành phần cốt lõi:

- CLI \verb|marl3|.
- Config mặc định.
- LangGraph main pipeline.
- Per-bug graph.
- Recon crawler HTTP-native.
- BodyStore lossless.
- Candidate generator.
- Coordinator.
- Debate Red/Blue.
- ExecutionRunner.
- ProofGate BAC/BLF.
- VerifierPanel.
- Long-term memory.
- ReportBuilder.
- Workspace artifact management.

Repo cũng có \verb|vuln-target/| làm target demo với các route login, register, profile, products, cart, checkout, orders, transfer và admin. Đây là nền tảng tốt để xây benchmark chính thức.

### 4.4. Đánh giá

Hệ thống đã đạt mức prototype kiến trúc rõ. Điểm mạnh nhất là thiết kế tách rời decision by code và reasoning by LLM. Những object như ReconArtifact, BugDossier, Evidence và Finding giúp pipeline dễ kiểm tra hơn so với transcript-only agent. BodyStore và ProofGate làm cho bằng chứng có tính audit cao.

Tuy nhiên, phần test hiện có trong repo chủ yếu kiểm tra lớp legacy ở thư mục \verb|test/|. Trong khi đó \verb|pyproject.toml| cấu hình pytest cho thư mục \verb|tests|, nhưng repo hiện không thấy thư mục \verb|tests/|. Vì vậy cần bổ sung test cho package \verb|src/marl3| để đánh giá đúng kiến trúc hiện tại.

## Chương 5. Đánh giá và thảo luận

### 5.1. Ưu điểm của hệ thống

- Kiến trúc LangGraph rõ ràng, có node và routing deterministic.
- LLM không tự quyết định chuyển phase.
- Dữ liệu truyền giữa phase được chuẩn hóa bằng Pydantic contracts.
- HTTP body được lưu lossless.
- ProofGate là authority, giảm rủi ro LLM phán sai.
- VerifierPanel vẫn cung cấp nhận xét định tính cho report.
- ExecutionRunner ghi evidence và sinh PoC.
- Long-term memory chỉ học từ episode đã xác minh.
- Workspace quản lý artifact tập trung.
- Có target demo \verb|vuln-target/| để phát triển benchmark.

### 5.2. Hạn chế

- Crawler chính hiện là HTTP-native, có thể chưa đủ với SPA/JS-heavy app.
- Test cho \verb|src/marl3| chưa đầy đủ; test hiện có thiên về legacy.
- Ground truth benchmark cho \verb|vuln-target| chưa hoàn thiện.
- ProofGate cần nhiều rule hơn cho các biến thể BAC/BLF.
- Hunt và Debate vẫn phụ thuộc LLM, cần structured output chặt hơn.
- Long-term memory cần đánh giá thực nghiệm để chứng minh chống overfit.
- Tài liệu trong repo còn nhiều bản cũ như \verb|OVERVIEW.md|, \verb|ARCHITECTURE.md|, \verb|CHANGED.md|, \verb|CHANGED2.md|, dễ gây nhầm với README mới.
- Lớp legacy và lớp \verb|marl3| cùng tồn tại nên báo cáo/demo cần xác định rõ kiến trúc nào là chính.

### 5.3. Hướng phát triển tương lai

Các hướng phát triển nên ưu tiên:

1. Bổ sung test cho \verb|src/marl3|:
   - pipeline graph;
   - bug graph routing;
   - ReconArtifact serialization;
   - BodyStore;
   - CandidateGenerator;
   - ExecutionRunner;
   - ProofGate BAC/BLF;
   - ReportBuilder;
   - LongTermMemory.

2. Xây ground truth benchmark cho \verb|vuln-target|:
   - expected routes;
   - expected endpoints;
   - business objects;
   - workflows;
   - vulnerabilities;
   - negative cases.

3. Thêm browser recon mode bằng Playwright cho SPA/JS-heavy app, song song với HTTP-native crawler.

4. Thiết kế \verb|TargetState| machine-readable:
   - route_state;
   - endpoint_state;
   - action_state;
   - business_object_state;
   - coverage_state.

5. Thêm coverage-guided recrawl dựa trên gap của target state.

6. Chuẩn hóa structured output cho LLM roles.

7. Mở rộng ProofGate:
   - approval bypass;
   - refund abuse;
   - order state transition;
   - transfer amount/balance;
   - coupon stacking;
   - cross-user write access.

8. Tách tài liệu legacy khỏi tài liệu \verb|marl3| để người đọc không nhầm kiến trúc.

9. Tích hợp CI:

\begin{verbatim}
pytest
python -m unittest discover -s test
python -m py_compile src/marl3/**/*.py
\end{verbatim}

10. Chuẩn hóa final report template theo tiêu chuẩn pentest: confirmed findings, partial findings, not exploited, coverage gaps, limitations.

## Tài liệu tham khảo

Danh sách tài liệu tham khảo nên hoàn thiện trong bản chính thức:

1. OWASP Top 10: Broken Access Control.
2. OWASP Web Security Testing Guide.
3. PortSwigger Web Security Academy: Access Control vulnerabilities.
4. PortSwigger Web Security Academy: Business logic vulnerabilities.
5. OWASP Juice Shop documentation.
6. LangGraph documentation.
7. OpenAI API / OpenAI-compatible Chat Completions documentation.
8. Pydantic documentation.
9. httpx documentation.
10. Typer documentation.
11. Các tài liệu về Red Team/Blue Team methodology.
12. Các nghiên cứu liên quan đến LLM agents trong kiểm thử bảo mật.
