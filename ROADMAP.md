# ROADMAP — Các tính năng nâng cao dự kiến

> File này ghi lại các hướng cải tiến có thể bổ sung cho hệ thống MARL sau khi hoàn thành
> phiên bản cơ bản (đồ án chuyên ngành). Ưu tiên những cải tiến có thể đo lường bằng số liệu
> cụ thể để phục vụ báo cáo và nghiên cứu.

---

## 1. Feedback Loop — Cho phép thử lại khi exploit thất bại [UU TIEN CAO]

**Hiện tại**: Pipeline chạy tuyến tính `recon → debate → execute → evaluate → report`. Nếu
execute thất bại thì đánh giá thất bại và dừng. Code hiện tại đã có `MAX_EXEC_RETRIES = 2`
nhưng cơ chế retry chỉ là Red đề xuất chiến lược mới → chưa thực sự inject kết quả thất bại
vào debate để 2 bên phân tích nguyên nhân.

**Cải tiến**: Khi evaluate trả verdict RETRY:
1. Inject exec_report (lý do thất bại, HTTP response, error log) vào conversation
2. Red Team phân tích nguyên nhân, đề xuất chiến lược khác dựa trên dữ liệu mới
3. Blue Team review chiến lược mới với context rằng chiến lược trước đã fail
4. Lặp lại execute → evaluate

**Đo lường**: So sánh tỷ lệ phát hiện lỗ hổng (detection rate) giữa có và không có feedback
loop trên cùng bộ target. Metric: số lỗ hổng tìm được / tổng số lỗ hổng biết trước.

**Độ khó**: Trung bình — sửa `main.py` phase_evaluate + main loop.

---

## 2. Scoring System — Chấm điểm chiến lược tấn công [UU TIEN CAO]

**Hiện tại**: Blue Team approve bằng cảm tính LLM, không có tiêu chí rõ ràng. Đôi khi
approve chiến lược yếu hoặc reject chiến lược tốt.

**Cải tiến**: Thêm rubric chấm điểm vào prompt Blue Team:

| Tiêu chí | Thang điểm | Mô tả |
|-----------|-----------|-------|
| Feasibility | 0-10 | Chiến lược có khả thi với thông tin từ recon không? |
| Specificity | 0-10 | Các bước có cụ thể (URL, param, method) hay mơ hồ? |
| Coverage | 0-10 | Có cover đúng pattern BAC/BLF được nhắm tới không? |

Approve khi trung bình >= 7/10. Reject kèm điểm cụ thể và lý do từng tiêu chí.

**Đo lường**: So sánh chất lượng chiến lược (tỷ lệ execute thành công) giữa có và không
có scoring. Metric: approved strategies that lead to successful exploit / total approved.

**Độ khó**: Thấp — chỉ sửa `BLUE_PROMPT` trong `blue_team.py` + thêm regex parse score.

---

## 3. Judge Agent — Trọng tài độc lập cho debate [TRUNG BINH]

**Hiện tại**: Blue Team vừa phản biện vừa quyết định approve — vừa là đối thủ vừa là
trọng tài, dễ bị bias.

**Cải tiến**: Thêm agent thứ 3:
- **Red Team**: Chỉ đề xuất chiến lược tấn công
- **Blue Team**: Chỉ phản biện, chỉ ra điểm yếu
- **Judge Agent**: Đọc cả hai bên, ra quyết định approve/reject dựa trên rubric

Luồng mới: Red → Blue → Judge → (approve hoặc gửi lại Red)

**Đo lường**: So sánh chất lượng quyết định (precision/recall của approve) giữa 2-agent
vs 3-agent. Metric: false approve rate (approve chiến lược dẫn đến fail).

**Độ khó**: Trung bình — tạo `agents/judge_agent.py` mới, sửa debate loop trong `main.py`.

---

## 4. Benchmark & Thống kê tự động [UU TIEN CAO]

**Hiện tại**: Không có cơ chế đo lường hiệu quả. Chạy xong chỉ có report text.

**Cải tiến**: Tạo benchmark suite:
1. Chọn 5-10 target có lỗ hổng biết trước (PortSwigger labs, DVWA, Juice Shop, bWAPP)
2. Mỗi target ghi rõ: lỗ hổng gì, pattern nào (BAC-01, BLF-03, v.v.)
3. Script tự động chạy MARL trên từng target, ghi log
4. Tổng hợp: detection rate, false positive, thời gian trung bình, số debate rounds

**Kết quả**: Bảng thống kê cụ thể cho báo cáo đồ án:

| Target | Lỗ hổng | Pattern | Phát hiện? | Exploit? | Thời gian | Rounds |
|--------|---------|---------|-----------|----------|-----------|--------|
| Lab 1  | IDOR    | BAC-03  | Co        | Co       | 3m20s     | 3      |
| Lab 2  | Price   | BLF-01  | Co        | Khong    | 5m10s     | 4      |

**Độ khó**: Trung bình — viết script wrapper, chọn target, chạy batch.

---

## 5. Dynamic Playbook / RAG [NANG CAO]

**Hiện tại**: 17 pattern cố định trong `bac_blf_playbook.py`. Red Team luôn nhận toàn bộ
playbook bất kể target là gì → tốn token, thiếu tập trung.

**Cải tiến**:
- Dùng embedding + vector DB (ChromaDB hoặc FAISS) lưu attack pattern
- Sau khi recon xong, query playbook dựa trên recon context (loại app, endpoints, forms)
- Chỉ inject top-5 relevant patterns vào Red Team prompt
- Cho phép thêm pattern mới sau mỗi lần pentest thành công

**Đo lường**: Token usage giảm bao nhiêu %, detection rate thay đổi thế nào.

**Độ khó**: Cao — cần thêm dependency (chromadb/faiss), embedding model, refactor knowledge/.

---

## 6. Session Memory — Ghi nhớ kinh nghiệm [NANG CAO]

**Hiện tại**: Mỗi lần chạy là session độc lập. Không nhớ target đã test, chiến lược nào
đã thử, kết quả ra sao.

**Cải tiến**:
- Sau mỗi lần chạy, lưu structured data: target, pattern, strategy, result, lessons learned
- Lần chạy sau trên cùng target hoặc target tương tự → load context cũ
- Red Team tham khảo "đã thử X → thất bại vì Y → lần này thử Z"

**Đo lường**: Detection rate cải thiện trên lần chạy thứ 2+ so với lần 1.

**Độ khó**: Trung bình — JSON file storage đơn giản là đủ, không cần DB.

---

## 7. Song song hóa Execution [NANG CAO]

**Hiện tại**: Nếu debate approve chiến lược có 5 bước, ExecAgent chạy tuần tự từng bước.
Nếu các bước độc lập thì lãng phí thời gian.

**Cải tiến**: Phân tích dependency giữa các bước, chạy song song các bước độc lập.
Ví dụ: Test IDOR trên `/users/1`, `/users/2`, `/users/3` → 3 request song song.

**Đo lường**: Thời gian execute giảm bao nhiêu %.

**Độ khó**: Cao — cần refactor ExecAgent, xử lý concurrent MCP sessions.

---

## 8. Nâng cấp Cơ chế Truyền Credentials và Crawl đa luồng (Multi-account) [CẦN SỬA / THAY ĐỔI KIẾN TRÚC]

**Hiện tại**: Cơ chế truyền thông tin đăng nhập hoàn toàn tĩnh. Hàm `parse_prompt` dùng Regex chỉ cắt được 1 cặp tên đăng nhập/mật khẩu. Trình thu thập dữ liệu cũng sử dụng logic hardcode để tìm form login, dẫn tới việc hệ thống chỉ có thể nhận diện và thao tác duy nhất 1 tài khoản. Điều này làm cản trở việc tìm các lỗi BAC chéo tài khoản (Horizontal Privilege Escalation, IDOR giữa 2 người dùng) do không có phiên của User thứ 2 để đối chiếu.

**Cải tiến**:
1. **Dùng LLM phân tích Prompt đầu vào**: Thay vì Regex tĩnh, đưa thẳng user prompt (ví dụ: *"Mục tiêu web X, tài khoản 1: a/b, tài khoản 2: c/d, focus test IDOR"*) cho LLM phân tích. LLM sẽ xuất ra JSON chứa cấu trúc: danh sách URL, mảng các cặp credentials, và mục tiêu cụ thể.
2. **Multi-account Crawling**: Crawler tiếp nhận JSON này, sau đó chạy:
   - Crawl Unauthenticated (không đăng nhập)
   - Crawl Authenticated Account 1
   - Crawl Authenticated Account 2 ...
   - Gộp chung toàn bộ requests/responses vào cùng một tập dữ liệu.
3. **Mở rộng Context Recon**: `recon.md` báo cáo sự khác biệt requests giữa các session, cung cấp góc nhìn đa chiều cho Red Team thiết kế luồng khai thác.

**Đo lường**: Khả năng phát hiện lỗi Horizontal Privilege Escalation/IDOR trên các bài Lab yêu cầu 2 accounts (so với tỷ lệ gần 0% của thiết kế 1 tài khoản hiện tại).

**Độ khó**: Khá cao — Cần viết lại `parse_prompt` (thay bằng thao tác gọi API AI), sửa `CrawlAgent` và state management trong `crawler.py` để xử lý mảng cookies/sessions đa luồng.

---

## Thứ tự ưu tiên đề xuất

| # | Tính năng | Vì sao ưu tiên |
|---|-----------|----------------|
| 1 | Benchmark & Thống kê | Cần số liệu cho báo cáo đồ án, chạy trên PortSwigger labs |
| 2 | Scoring System | Thay đổi nhỏ, cải thiện chất lượng debate, dễ so sánh before/after |
| 3 | Feedback Loop | Tăng detection rate rõ rệt, có metric đo được |
| 4 | Judge Agent | Hay về mặt nghiên cứu (so sánh 2-agent vs 3-agent debate) |
| 5 | Nâng cấp Truyền Credentials/Multi-account Crawll | Thay đổi cốt lõi để test BAC, quan trọng vì hiện tại không test được IDOR đa tài khoản |
| 6 | Session Memory | Thú vị nhưng cần nhiều lần chạy để thấy hiệu quả |
| 7 | Dynamic Playbook | Tối ưu token nhưng phức tạp, ROI chưa rõ |
| 8 | Song song hóa | Nice-to-have, không ảnh hưởng detection rate |
