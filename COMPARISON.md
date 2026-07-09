# MARL (cũ) vs marl3 — So sánh điểm yếu & cải tiến

---

## Bảng so sánh

| # | Điểm yếu của MARL cũ | marl3 giải quyết thế nào |
|---|---|---|
| 1 | **Debate giả** — Red và Blue mỗi bên chỉ nói **đúng 1 lần**, không có vòng lặp thật. Một "Manager" là AI đứng giữa chép chuỗi qua lại và keyword-match để giả vờ tranh luận. | Red↔Blue tranh luận **thật nhiều vòng**. Vòng 2 trở đi Red **buộc phải phản bác từng điểm** Blue đã chê. Manager là **máy trạng thái code** — tất định, không phải AI. |
| 2 | **Memory chết** — Red và Blue **không bao giờ** được nạp memory vào prompt. "RAG" thực chất chỉ là grep keyword. Nhiều file ghi ra nhưng **không có reader** nào đọc lại. | Mọi prompt agent đi qua một chokepoint duy nhất (`ContextRetriever`) — đảm bảo **mỗi file ghi ra có đúng 1 reader**. Memory được nạp đúng vai: short-term → Debate+Exec, long-term → Hunt+Exec. |
| 3 | **Cắt chuỗi mất ngữ cảnh** — Hàm `truncate()` cắt **5% ở giữa** chuỗi. Body bị cắt tầng 12KB→8KB→200 ký tự. Feedback Blue→Red bị cắt còn 400 ký tự — đúng chỗ chứa price/qty/id quan trọng của BLF. | Body lưu **nguyên vẹn trên đĩa** (content-addressed). RAM chỉ giữ con trỏ + preview. Khi quá ngân sách: **bỏ nguyên item**, không bao giờ cắt giữa thân. |
| 4 | **PoC gần như không bao giờ được lưu** — Hàm sinh PoC bị chặn sau điều kiện `exploit_mode != "tool_loop"`, trong khi `tool_loop` là mode mặc định → **mọi bug EXPLOITED in "Không có artifact"**. | PoC **luôn** được tái dựng từ Evidence sau mỗi lần Exec, độc lập với exploit mode. Chạy `py_compile` + replay để xác nhận PoC thật sự tái lập được. |
| 5 | **Proof-gate dò substring trên text đã bị cắt** — Kết quả phụ thuộc vào việc LLM có "nói đúng từ" trong log không, không đọc dữ liệu thật. Dễ báo lỗ giả hoặc bỏ sót lỗ thật. | ProofGate đọc **object có cấu trúc** (HTTP exchange thật). Quyết định dựa trên số liệu: status code, giá trị field, state delta — không dò chuỗi, không phụ thuộc ngôn ngữ response. ProofGate cũng có **fallback nội bộ**: BAC-01 thất bại → tự thử IDOR rule → nếu pass thì promote pattern sang BAC-03. |
| 6 | **Verifier là trọng tài cuối cùng** — MARL cũ dùng AI vote để quyết định EXPLOITED, không có cơ chế xác minh dữ liệu thật. Panel AI dễ đồng ý với nhau (group-think) hoặc quá thận trọng (bỏ lỗ thật). | Panel chạy **trước** ProofGate (pre-gate): lọc nhanh các execution thất bại rõ ràng (tất cả 4xx, không có 2xx). ProofGate là **trọng tài duy nhất** — Panel không thể thay thế. Khi Panel nghi ngờ nhưng có 2xx → ProofGate vẫn chạy làm safety net. |
| 6 | **File thừa/trùng** — Cùng traffic mã hoá 2 kiểu (`crawl_raw.json` 4MB + `crawl_data.txt` 667KB). Session auth lưu 3 nơi. Exec đẻ file cookie rác từ label không kiểm soát. | `RunWorkspace` sở hữu mọi đường dẫn. 1 `bodies/` content-addressed (tự dedup). 1 `sessions.json`. Label auth validate bằng regex — không đẻ file ngoài workspace. |

---

## Một câu tóm gọn sự khác biệt

> MARL cũ: AI điều phối, AI phán kết quả, dữ liệu bị cắt xén.
> marl3: **code điều phối tất định, AI chỉ lý luận trong từng ô, dữ liệu thật là chân lý.**

---

## Benchmark

### PortSwigger Web Security Academy (2026-06-17) — **12/19 = 63.2%**

| Run | Kết quả | Ghi chú |
|-----|---------|---------|
| MARL cũ | — | Không đánh giá trên PortSwigger |
| marl3 v3 (trước fix) | 3/19 = 15.8% | Trước khi vá 3 bug ProofGate |
| **marl3 v3 (sau fix)** | **12/19 = 63.2%** | BAC 5/10 (50%), BLF 7/9 (78%) |

Các lỗ hổng khai thác được: IDOR (4 lab), forced browsing, BLF-01 price tamper, BLF-06 negative qty, BLF-05 coupon reuse, BLF-08 integer overflow, BLF-03 workflow skip, BLF-12 flawed state machine, BLF-05 infinite money loop.

Không khai thác được (7 lab): method override, static file IDOR, Referer header bypass, param omission bypass, padding oracle crypto attack.

Xem chi tiết: `../BENCHMARK_PORTSWIGGER_REPORT.md`

### VulnShop (2026-06-17) — **5/10 = 50%**

| Run | Kết quả | Ghi chú |
|-----|---------|---------|
| MARL cũ | ~1–2/10 | Báo EXPLOITED nhiều lỗ giả do Panel là trọng tài |
| marl3 v3 | **5/10** | Zero false positive, ProofGate làm trọng tài |

Khai thác được: BAC-01 (`/api/v1/users`), BAC-02 (`/admin` cookie tamper), BLF-01 (`/wallet/transfer` negative amount), BLF-02 (`/cart/add` negative qty), BLF-09 (`/checkout` workflow skip).
Điểm yếu còn lại: IDOR `/profile/{id}` và `/orders/{id}` (hunter bỏ sót lần này), BLF-05 coupon reuse, BAC-06 forced browsing API.
