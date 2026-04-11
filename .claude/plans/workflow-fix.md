# Phân tích Log & Kế hoạch Sửa Workflow MARL

## I. PHÂN TÍCH LOG — Chuyện gì đã xảy ra?

### Timeline (19:42 → 20:01 = ~20 phút)

```
Phase 1 RECON   [19:42–19:52] ~10 phút  ← Crawl anonymous + auth → recon.md OK
Phase 2 DEBATE  [19:52–19:53] ~1 phút   ← Red viết chiến lược → Blue APPROVED ngay
Phase 3 EXEC    [19:53–19:57] ~4 phút   ← Agent thực thi → THÀNH CÔNG (price=1, checkout $0.02)
Phase 4 EVAL    [19:57–20:01] ~4 phút   ← Red "đánh giá" → NHƯNG LẠI LÀM LẠI TỪ ĐẦU → FAIL login
Phase 5 REPORT  [20:01]                  ← Lưu report với kết quả... lẫn lộn
```

### Kết quả thực tế

**Phase 3 ĐÃ THÀNH CÔNG** — Agent exploit price tampering:
- POST /cart với `price=1` → server chấp nhận
- Checkout thành công, Total: $0.02 cho sản phẩm giá $99.53
- Evidence đầy đủ: `step5_cart_price1.html`, `step6_order_confirmation.html`

**NHƯNG Phase 4 PHÁ NGANG** — Red Team "đánh giá" nhưng thực chất:
- Red không đọc kết quả Phase 3, mà **tự bịa workflow mới** (login lại từ đầu)
- Agent trong Phase 4 dùng curl (không có cookie) → login fail vì CSRF mismatch
- Lặp lại 3 lần verify, mỗi lần đều fail login
- Report cuối cùng lẫn lộn: có evidence thành công từ Phase 3 + evidence fail từ Phase 4

---

## II. 5 NGUYÊN NHÂN GỐC RỄ

### Nguyên nhân 1: Blue Team APPROVED quá sớm — debate thành 1 lượt
**Vấn đề:** Blue nhận chiến lược của Red → nói vài ý kiến → APPROVED ngay + gọi [AGENT] cùng lúc.
Kết quả: không có "cãi nhau" thực sự, debate = 1 round duy nhất.

**Nguyên nhân code:** Blue system prompt quá mềm. Nó nói "review" nhưng không buộc phải reject ít nhất 1 lần. Thêm nữa, Blue được phép vừa APPROVED vừa gọi [AGENT] cùng message — main.py thấy [APPROVED] là nhảy sang Phase 3, bỏ qua yêu cầu Agent verify của Blue.

**Bằng chứng trong log:**
```
[19:53:04] Kết luận: [APPROVED] để thực hiện, nhưng trước khi chạy full exploit
           hãy thực hiện các kiểm tra nhanh bằng Agent...
[19:53:04] [AGENT] — vui lòng kiểm tra nhanh...
[19:53:04] ══ APPROVED ══           ← main.py thấy APPROVED, bỏ qua Agent request
[19:53:04] PHASE 3: EXECUTION      ← nhảy thẳng vào execution
```

### Nguyên nhân 2: Red Team trong Phase 4 không đọc exec_report — tự bịa workflow mới
**Vấn đề:** Phase 4 đưa exec_report vào conversation cho Red đánh giá, nhưng Red hoàn toàn bỏ qua evidence thành công, bắt đầu ra lệnh Agent login lại từ đầu.

**Nguyên nhân code:** Red system prompt chỉ nói "đánh giá kết quả" nhưng KHÔNG buộc Red format theo template cụ thể (VD: "SUCCESS/FAIL + evidence"). Red cũng không được nhắc "nếu thành công → [DONE]". Kết quả: Red "suy nghĩ" quá tự do, tự đề xuất verify thêm, rồi gọi [AGENT] liên tục.

**Bằng chứng:**
```
[19:57:31] Kết luận tạm thời: Thành công — server bị khai thác...
[19:58:28] ==> Không lấy được session cookie    ← Agent thử login lại = FAIL
[19:58:44] [RED-TEAM] Response (3544 chars)
[19:58:44] [RED-TEAM] Khong co tag — nudge      ← Red không biết phải kết thúc
```

### Nguyên nhân 3: Agent trong Phase 4 dùng curl mới (mất session)
**Vấn đề:** Phase 3 Agent đã login thành công bằng browser (Playwright). Nhưng Phase 4 Agent chạy curl → session cookie khác → CSRF token hết hạn → login fail.

**Nguyên nhân code:** `exec_agent.answer()` (Phase 4 verify mode) tạo conversation MỚI, không kế thừa cookie/session từ Phase 3. Mỗi lần Agent gọi curl, nó bắt đầu clean — không có cookies.txt từ run trước.

### Nguyên nhân 4: Tag priority logic bị sai khi có nhiều tag
**Vấn đề:** Blue gửi cả [APPROVED] và [AGENT] trong cùng message. main.py dùng `extract_next_tag()` — trả về tag đầu tiên tìm thấy. [APPROVED] xuất hiện trước → Phase 3 bắt đầu, yêu cầu Agent verify bị bỏ qua.

**Nguyên nhân code (main.py line ~270-280):**
```python
tag = extract_next_tag(raw)
if tag == "APPROVED":
    # nhảy thẳng vào Phase 3
```
Không check xem có [AGENT] đi kèm không.

### Nguyên nhân 5: Red viết chiến lược quá dài, quá chi tiết (9713 chars)
**Vấn đề:** Red viết luôn cả curl commands, biến thể payload, full execution plan. Đây KHÔNG phải vai trò Red — Red là chiến lược gia, Agent mới là người thực thi.

**Nguyên nhân:** System prompt không giới hạn format output. Red được cho playbook 17 patterns → nó trộn kiến thức + lệnh cụ thể thành 1 khối.

---

## III. WORKFLOW LÝ TƯỞNG — "2 con AI cãi nhau ở tầm Junior Pentest"

```
RED: "Em thấy product page có hidden price field, POST /cart chấp nhận price
     từ client. Em muốn thử BLF-01: sửa price=1 rồi checkout xem server
     có validate không."

BLUE: "Ý tưởng hợp lý. Nhưng trước khi chạy full exploit, em cần verify:
      1) form add-to-cart có CSRF không?
      2) cart page hiển thị price client-sent hay server-recalculated?
      → [AGENT] kiểm tra 2 điểm này"

AGENT: "1) Không có CSRF cho add-to-cart. 2) Cart hiển thị price=1 khi POST price=1"

BLUE: "OK confirmed, server trust client price. Nhưng checkout mới là điểm
      quyết định. Cho thêm test: price=0 và price=-1 nữa.
      → [REDTEAM] bổ sung payload variants"

RED: "Đồng ý. Workflow update:
     Step 1: Login → Step 2: POST /cart price=1 → Step 3: Checkout
     Nếu fail thử price=0, price=-1
     → [BLUETEAM]"

BLUE: "Workflow gọn, hợp lý. [APPROVED]"

--- Phase 3: Agent chạy → thành công ---

RED (Phase 4): "Evidence rõ ràng: checkout total $0.02 cho sản phẩm $99.53.
               BLF-01 confirmed. Severity: HIGH. [DONE]"
```

Đặc điểm:
- **2-3 rounds debate** (không phải 1, không phải 10)
- Red nói **ý tưởng + lý do**, KHÔNG nói curl commands
- Blue **reject ít nhất 1 lần** để buộc verify trước
- Agent chỉ làm khi được gọi, trả kết quả ngắn
- Phase 4: Red đọc evidence → đưa verdict ngay, không tự chạy lại

---

## IV. KẾ HOẠCH SỬA — 6 thay đổi cụ thể

### Thay đổi 1: Sửa Red Team system prompt — "khắt khe workflow, mềm kiến thức"

**File:** `agents/red_team.py` — `RED_PROMPT`

Nguyên tắc:
- **Khắt khe format:** Buộc Red theo template CHIẾN_LƯỢC ngắn (mục tiêu, pattern, steps dạng mô tả, criteria thành công). KHÔNG viết curl/code.
- **Mềm kiến thức:** Cho Red tự do suy nghĩ pattern nào phù hợp, tự do đề xuất, nhưng PHẢI tuân thủ format.
- **Phase 4 prompt riêng:** Khi đánh giá, buộc Red đọc evidence → verdict (SUCCESS/FAIL) → [DONE] hoặc đề xuất 1 chiến lược mới.

### Thay đổi 2: Sửa Blue Team system prompt — buộc reject round 1

**File:** `agents/blue_team.py` — `BLUE_PROMPT`

Nguyên tắc:
- Round 1: Blue PHẢI đặt ít nhất 2 câu hỏi verify TRƯỚC KHI approve.
- Blue KHÔNG được gửi [APPROVED] + [AGENT] cùng lúc. Nếu muốn Agent verify → gửi [AGENT] trước, đợi kết quả, rồi mới quyết định.
- Blue chỉ APPROVED khi chiến lược ngắn gọn, steps rõ ràng, evidence criteria cụ thể.

### Thay đổi 3: Sửa tag priority trong main.py — xử lý multi-tag

**File:** `main.py` — hàm `phase_debate()`

Logic mới:
- Nếu message chứa cả [APPROVED] và [AGENT]: ưu tiên [AGENT] trước. Sau khi Agent trả về, quay lại người gọi, KHÔNG tự động approve.
- Tách logic: `[APPROVED]` chỉ được chấp nhận khi nó là tag DUY NHẤT (hoặc tag cuối cùng sau khi xử lý hết Agent calls).

### Thay đổi 4: Phase 4 eval — giới hạn scope của Red + Agent

**File:** `main.py` — hàm `phase_eval()`

Thay đổi:
- Truyền exec_report vào Red prompt rõ ràng hơn: "Đây là kết quả execution. Đọc evidence và trả verdict."
- Red PHẢI trả lời theo format: `VERDICT: SUCCESS|FAIL` + lý do + `[DONE]` hoặc `[RETRY]`
- Agent trong Phase 4 chỉ được READ (curl GET, browser navigate) — không được thay đổi state (POST, submit form).
- Giới hạn Phase 4 Agent = max 3 tool calls (chỉ verify, không exploit lại).

### Thay đổi 5: Session persistence giữa Phase 3 → Phase 4

**File:** `agents/exec_agent.py`

Thay đổi:
- Giữ cookies.txt / session state từ Phase 3 cho Phase 4 verify.
- Hoặc đơn giản hơn: Phase 4 Agent KHÔNG cần login lại — dùng evidence files đã lưu từ Phase 3 (read_file thay vì curl mới).

### Thay đổi 6: Giới hạn Red output length trong debate

**File:** `agents/red_team.py`

Thay đổi:
- System prompt nói rõ: "Chiến lược tối đa 10 bước. Mỗi bước 1-2 dòng mô tả (KHÔNG viết curl/code). Tổng chiến lược < 2000 ký tự."
- Nếu Red viết quá dài, truncate trước khi gửi cho Blue (đã có TRUNCATE_LIMIT nhưng = 15000, quá cao cho debate context).

---

## V. THỨ TỰ TRIỂN KHAI (ưu tiên impact)

1. **Thay đổi 3** — Fix tag priority (nhanh, fix bug rõ ràng)
2. **Thay đổi 1** — Sửa Red prompt (impact lớn nhất lên chất lượng debate)
3. **Thay đổi 2** — Sửa Blue prompt (buộc debate thực sự)
4. **Thay đổi 4** — Fix Phase 4 eval scope
5. **Thay đổi 5** — Session persistence
6. **Thay đổi 6** — Output length limit

Thay đổi 1-4 là bắt buộc. Thay đổi 5-6 là nice-to-have.
