# marl3 — Luồng hoạt động từ đầu đến cuối

> Công cụ tự động tìm & chứng minh lỗ hổng **phân quyền (BAC)** và **logic nghiệp vụ (BLF)** trên web.
> Điểm cốt lõi: **việc điều phối các agent là CODE tất định, không phải do AI tự quyết.**

---

## 0. Từ vựng (đọc 1 lần là hiểu hết file)

| Thuật ngữ trong code | Nói cho dễ hiểu |
|---|---|
| **Recon** | Đi **do thám**: crawl web, thu thập trang/endpoint/cookie |
| **Phiếu nghi vấn** (code gọi là *dossier*) | 1 thẻ mô tả: "endpoint X có thể dính lỗ Y, đây là bằng chứng do thám" |
| **Exec** | Agent **thực thi khai thác** (gửi request thật) |
| **Red / Blue** | Hai agent **tranh luận**: Red lập kế hoạch tấn công, Blue phản biện |
| **Verifier panel** | 3 agent **giám định** độc lập, mặc định nghi ngờ |
| **Proof-gate** | **Trọng tài bằng code** (không phải AI) — đọc dữ liệu thật, phán đúng/sai |
| **Bằng chứng** (*evidence*) | Toàn bộ request/response đã ghi lại trong lúc khai thác |

---

## 1. Bức tranh tổng thể (4 giai đoạn)

```
        ┌─────────┐     ┌────────┐     ┌──────────────────────┐     ┌─────────┐
  URL → │  RECON  │ →   │  HUNT  │ →   │  BUGS (vòng lặp/bug)  │ →   │ REPORT  │
        │ do thám │     │ tìm    │     │  debate→exec→verify  │     │ báo cáo │
        └─────────┘     │ nghi   │     └──────────────────────┘     └─────────┘
                        │ vấn    │
                        └────────┘
   crawl + login     LLM + luật ra      với MỖI phiếu nghi vấn,      report.md
   → danh sách        danh sách          chạy 1 "dây chuyền" 3       + findings.json
     endpoint         phiếu nghi vấn     agent (xem mục 3)
```

- **RECON**: crawl web (kể cả đọc JS để lấy endpoint AJAX), đăng nhập, ghi lại mọi request.
- **HUNT**: agent **Hunter** + luật tất định đọc kết quả do thám → đẻ ra danh sách **phiếu nghi vấn**.
- **BUGS**: phần chính — mỗi phiếu chạy qua dây chuyền `debate → exec → verify` (mục 3).
- **REPORT**: gom kết quả ra file.

---

## 2. Cái gì ĐIỀU PHỐI? (câu hỏi quan trọng nhất)

**KHÔNG có "agent quản lý" nào ra lệnh.** Cái xoay vòng các agent là **một máy trạng thái viết bằng code** (LangGraph). Nó chỉ đọc 1 biến chuỗi `trạng_thái` rồi quyết định đi đâu tiếp:

```
                 (đọc biến trạng_thái, RẼ NHÁNH tất định — KHÔNG hỏi AI)

   [debate] ──"ĐÃ DUYỆT"──────────────→ [exec] ──"XONG"──→ [verify]
       │                                                       │
       └──"thiếu bằng chứng / dừng"──→ KẾT THÚC               │
                                                               ├─"CHỨNG MINH ĐƯỢC"─→ KẾT THÚC
                  ┌────"proof yếu, còn lượt retry"─────────────┘
                  ▼
              quay lại [debate]  (mang theo lời chê của giám định)
```

> Mọi mũi tên trên = một dòng `if trạng_thái == "..."` trong code. AI **chỉ nói nội dung trong lượt của nó**, KHÔNG quyết định ai đi tiếp.

---

## 3. Dây chuyền cho MỖI phiếu nghi vấn (chi tiết các agent)

```
 ╔══════════════════════════════════════════════════════════════════════════╗
 ║  BƯỚC 1 — DEBATE (tranh luận Red ↔ Blue, lặp tối đa N vòng)               ║
 ╠══════════════════════════════════════════════════════════════════════════╣
 ║                                                                            ║
 ║   ┌─────────────┐   chiến lược tấn công   ┌─────────────┐                 ║
 ║   │   RED 🔴    │ ─────────────────────→  │   BLUE 🔵   │                 ║
 ║   │ lập kế hoạch│                          │ phản biện   │                 ║
 ║   └─────────────┘  ←── chê/duyệt ───────   └─────────────┘                 ║
 ║                                                                            ║
 ║   Blue trả 1 trong 3 phán quyết:                                          ║
 ║     • DUYỆT   → đóng băng chiến lược, sang BƯỚC 2                          ║
 ║     • SỬA LẠI → quay lại Red (vòng kế, Red phải cãi từng điểm Blue chê)    ║
 ║     • DỪNG    → bỏ phiếu này                                               ║
 ╚══════════════════════════════════════════════════════════════════════════╝
                                   │ chiến lược ĐÃ DUYỆT
                                   ▼
 ╔══════════════════════════════════════════════════════════════════════════╗
 ║  BƯỚC 2 — EXEC (thực thi khai thác thật)                                  ║
 ╠══════════════════════════════════════════════════════════════════════════╣
 ║   ┌─────────────┐  gửi request thật   ┌──────────────┐                    ║
 ║   │  EXEC ⚡    │ ──────────────────→ │  WEB MỤC TIÊU │                    ║
 ║   │ làm theo    │ ←── response ─────  └──────────────┘                    ║
 ║   │ chiến lược  │                                                          ║
 ║   └─────────────┘   MỌI request/response tự động được GHI LẠI            ║
 ║          │          → "Bằng chứng" (có cấu trúc)                          ║
 ║          ▼                                                                 ║
 ║   vòng lặp tối đa 12–20 bước; có "steering" nhắc nếu chưa làm đủ           ║
 ╚══════════════════════════════════════════════════════════════════════════╝
                                   │ Bằng chứng
                                   ▼
 ╔══════════════════════════════════════════════════════════════════════════╗
 ║  BƯỚC 3 — VERIFY (giám định)                                              ║
 ╠══════════════════════════════════════════════════════════════════════════╣
 ║   ┌────────────────────┐        ┌──────────────────────────────┐         ║
 ║   │ PROOF-GATE ⚖ (code)│  ←──── │ 3 VERIFIER 🔍 (AI, cố bác bỏ) │        ║
 ║   │ = TRỌNG TÀI chính  │        │  = chỉ tư vấn, KHÔNG quyết     │         ║
 ║   └────────────────────┘        └──────────────────────────────┘         ║
 ║   Gate đọc Bằng chứng (số liệu thật) → phán:                              ║
 ║     • CHỨNG MINH ĐƯỢC      → xong, ghi nhận lỗ thật                        ║
 ║     • PROOF YẾU            → quay lại DEBATE (kèm lời chê) nếu còn lượt    ║
 ╚══════════════════════════════════════════════════════════════════════════╝
```

> **Vì sao Proof-gate (code) phán chứ không phải AI vote?** Để tránh 2 lỗi: AI "khen" 1 thứ chưa chứng minh (báo lỗ giả), hoặc AI "chê" 1 lỗ đã có số liệu thật (bỏ sót lỗ). **Dữ liệu là chân lý, không phải ý kiến model.**

---

## 4. "Cục gì" được đưa vào NGỮ CẢNH mỗi agent?

Quan trọng: **mỗi lượt gọi AI là tách biệt** — ngữ cảnh được **dựng lại từ dữ liệu**, không phải nhớ từ hội thoại cũ.

```
┌──────────┬──────────────────────────────────────────────────────────────────┐
│ AGENT    │ NHẬN VÀO NGỮ CẢNH (mỗi lượt)                                       │
├──────────┼──────────────────────────────────────────────────────────────────┤
│ RED 🔴   │ • Phiếu nghi vấn (endpoint, giả thuyết lỗ, bằng chứng do thám)     │
│          │ • Thẻ kiến thức của loại lỗ (cách tấn công mẫu)                     │
│          │ • Tin nhắn GẦN NHẤT của Blue (để cãi lại)                          │
│          │ • Toàn bộ lịch sử tranh luận + cookie phiên đăng nhập              │
├──────────┼──────────────────────────────────────────────────────────────────┤
│ BLUE 🔵  │ • Chiến lược MỚI NHẤT của Red                                      │
│          │ • CÙNG danh sách endpoint thật như Red (để bắt Red "bịa")          │
├──────────┼──────────────────────────────────────────────────────────────────┤
│ EXEC ⚡  │ • Chiến lược ĐÃ DUYỆT (các bước cụ thể Red viết)                   │
│          │ • Tên field thật + "giá trị hợp lệ" (product id, mã coupon, user)  │
│          │ • Cookie để giả mạo (đổi role=admin…) + danh sách công cụ          │
│          │ • Mỗi bước: kết quả request vừa rồi + nhắc nhở nếu làm chưa đủ     │
├──────────┼──────────────────────────────────────────────────────────────────┤
│ VERIFIER │ • CHỈ "Bằng chứng" có cấu trúc (request/response đã ghi)           │
│ 🔍       │   → KHÔNG thấy tranh luận → phán độc lập, mặc định nghi ngờ         │
└──────────┴──────────────────────────────────────────────────────────────────┘
```

- **Cái dựng ngữ cảnh đó là gì?** → **System prompt** (file mẫu `.md`), được "điền" các dữ liệu trên vào mỗi lượt.
- **System prompt KHÔNG điều phối luồng** — nó chỉ định hình *agent nói gì*. Việc *ai đi tiếp* là do máy trạng thái (mục 2).

---

## 5. Dữ liệu được CHUYỀN TAY giữa các bước

```
 do thám ──┐
           ▼
   [HUNT]  Phiếu nghi vấn ──────────────────────────────────────┐
                                                                 ▼
   [RED]   viết chiến lược ── DUYỆT ──→ "chiến lược đóng băng" ──→ [EXEC]
                                                                     │
   [EXEC]  chạy khai thác ───────────────────→ "Bằng chứng" ───────→ [VERIFY]
                                                                       │
   [VERIFY] proof yếu ──→ "lời chê của giám định" ──┐                  │
                                                    ▼                  ▼
                                            quay lại [RED]      CHỨNG MINH ĐƯỢC
                                       (sửa đúng chỗ đã fail)   → vào REPORT
```

- **Red → Exec:** trích 3 phần `CHIẾN LƯỢC / CÁC BƯỚC / ĐIỀU KIỆN THÀNH CÔNG` từ tin Red đã duyệt.
- **Exec → Verify:** toàn bộ Bằng chứng (request/response thật).
- **Verify → Red (retry):** lời chê của verifier để Red sửa đúng điểm yếu, không làm lại từ đầu.

---

## 6. Một câu chốt cho slide

> **Pipeline = máy trạng thái bằng code điều phối; AI chỉ làm việc trong từng ô (lập kế hoạch / phản biện / khai thác / giám định); và TRỌNG TÀI cuối cùng là code đọc dữ liệu thật, không phải AI bỏ phiếu.**
> Nhờ vậy luồng chạy ổn định, không "lạc", và không báo lỗ giả.
```
   CODE điều phối  ┃  AI làm nội dung từng ô  ┃  CODE (proof-gate) phán kết quả
```

---

## 7. Hỏi–Đáp phản biện (chuẩn bị cho câu hỏi giảng viên)

### Q1. Sao không dùng 1 "Manager chung" điều phối như bản cũ, mà lại dùng LangGraph?

Bản cũ có 1 Manager là **chính LLM** đứng giữa, gọi từng agent 1 lần rồi **chép tay** chuỗi qua lại → 3 nhược điểm:
- **"Tranh luận giả":** mỗi bên nói đúng 1 lần, không có vòng lặp thật, không cãi nhau.
- **Không tất định:** Manager là AI nên cùng input có thể rẽ luồng khác nhau → khó tái lập, khó gỡ lỗi.
- **Tốn token & dễ lạc:** thêm 1 LLM chỉ để "điều phối".

LangGraph thay Manager-AI bằng **máy trạng thái viết bằng code**:

```
   Manager-AI (cũ)                 LangGraph (mới)
   ─────────────                   ───────────────
   AI tự quyết ai đi tiếp     →    if trạng_thái == "X": đi node Y   (tất định)
   chép tay chuỗi             →    state (TypedDict) tự truyền       (không mất mát)
   gọi 1 lần/agent            →    vòng lặp THẬT có chu trình         (debate N vòng,
                                                                      verify→debate)
```
→ **Cùng input ⇒ cùng luồng**, dễ tái lập/giải thích, và AI chỉ tốn cho phần "suy nghĩ", không tốn cho phần "điều phối".

---

### Q2. Khi Blue từ chối thì sao? Luồng nào đẩy sang phiếu mới?

Phải phân biệt **2 kiểu "từ chối" của Blue**:

```
 Blue trả "SỬA LẠI" (REVISE)  → quay lại Red, VÒNG KẾ (vẫn cùng phiếu)
 Blue trả "DỪNG"   (STOP)     → kết thúc phiếu này  → SANG PHIẾU MỚI
```

- **REVISE** → DebateManager lặp tiếp (Red cãi lại từng điểm Blue chê). Cùng phiếu.
- **STOP** → debate trả `NOT_EXPLOITED` → hàm `_after_debate` trả `"end"` → **đồ thị của phiếu này kết thúc**.

Cái đẩy sang **phiếu mới** KHÔNG nằm trong đồ thị 1 phiếu, mà là **vòng for ở tầng trên**:
```python
for phiếu in danh_sách_phiếu:        # ← chỗ này chuyển phiếu
    final = bug_graph.ainvoke(phiếu)  # chạy trọn 1 phiếu tới khi END
    findings.append(build(final))     # ghi kết quả rồi sang phiếu kế
```
→ Mỗi phiếu chạy **trọn vẹn** (đến END) rồi vòng for mới lấy phiếu tiếp theo.

> Lưu ý: nếu Blue trả lời **mơ hồ/không rõ token**, code mặc định coi là **REVISE** (an toàn — không bao giờ tự "DUYỆT" nhầm).

---

### Q3. 3 con Verifier để làm gì? Có ảnh hưởng kết quả không?

3 Verifier là **AI giám định độc lập**, mỗi con chỉ nhìn "Bằng chứng" thô, **mặc định nghi ngờ** (cố bác bỏ).

**Chúng KHÔNG quyết định EXPLOITED hay không.** Trọng tài là **Proof-gate (code)**:
```
   gate (code, đọc số liệu) == EXPLOITED   →   EXPLOITED   ✅ (dù panel chê)
   gate == FAILED                          →   proof yếu   (dù panel khen)
```
(Đúng như BUG coupon trong lab: panel 2/3, 1 con phản đối, nhưng gate đọc dữ liệu thật → vẫn EXPLOITED.)

**Vậy chúng có tác dụng gì?** Hai việc — **gián tiếp**:
1. **Làm tín hiệu tin cậy** hiển thị trong báo cáo (3/3 vs 1/3 cho người đọc biết độ chắc).
2. **Khi proof yếu và phải retry:** lý do mỗi verifier bác bỏ được **gói lại làm "lời chê"** đưa ngược cho Red ở vòng debate sau → Red sửa đúng chỗ.

> Tóm lại: **không đổi phán quyết, nhưng định hướng lần thử lại + thể hiện độ tin cậy.** Lý do tách "vote AI" khỏi "phán quyết": tránh AI khen lố (lỗ giả) hoặc chê oan (mất lỗ thật) — *dữ liệu là chân lý, không phải ý kiến model*.

---

### Q4. Khai thác KHÔNG thành công thì sao? Khi nào retry lại DEBATE?

Có **2 kiểu "không thành công"**, xử lý KHÁC nhau:

```
 (a) Exec BỊ LỖI kỹ thuật (vd: rớt mạng, ngoại lệ)
        → retry EXEC (tối đa max_exec_retries=1), KHÔNG đụng debate

 (b) Exec chạy xong nhưng GATE phán "proof yếu" (PROOF_QUALITY_FAIL)
        → retry DEBATE  ── nếu còn ngân sách:
              verify_retries < max_verify_retries (=1)
              VÀ debate_rounds < max_rounds × 2
        → nếu hết ngân sách → kết thúc phiếu (NOT_EXPLOITED)
```
→ **Chỉ trường hợp (b) mới quay lại debate** — tức gate thấy chưa đủ bằng chứng thì cho Red nghĩ lại chiến lược, không phải lỗi vặt của exec.

---

### Q5. Khi retry DEBATE, ngữ cảnh đưa vào là gì? Chỉ 1 câu của Blue/Red có thiếu không?

Làm rõ 2 mức:

**Trong CÙNG một vòng tranh luận** — Red KHÔNG chỉ nhận 1 câu, mà nhận:
- toàn bộ **lịch sử tranh luận của vòng đó** (`render_for`),
- **tin nhắn Blue gần nhất** (tách riêng để cãi),
- bộ nhớ phiếu (các lần thử trước + ghi chú).

**Khi RETRY (mở lại debate sau khi proof yếu)** — luồng tranh luận **bắt đầu thread MỚI** (bỏ hội thoại cũ), tính liên tục được giữ bằng **"lời chê của Verifier"** đưa vào ngữ cảnh Red:
```
   Verifier nói "thiếu X" ──→ đóng gói thành verifier_feedback ──→ Red đọc → sửa đúng X
```
> Có "thiếu" không? Đây là **đánh đổi có chủ đích**: thay vì nhồi lại toàn bộ hội thoại cũ (tốn token, nhiễu), chỉ đưa **bản chắt lọc "cần sửa gì"**. Rủi ro: nếu lời chê của verifier mơ hồ thì Red có thể sửa chưa trúng — đây là điểm có thể cải tiến.

---

### Q6. Dữ liệu khai thác của Exec có được nạp vào DEBATE khi retry không?

**KHÔNG nạp dữ liệu thô** (toàn bộ request/response của Exec không đổ thẳng vào Red).
Exec ảnh hưởng tới Red **gián tiếp, đã chắt lọc**:
```
  Exec → Bằng chứng → 3 Verifier ĐỌC bằng chứng → "lời chê" → Red
  Exec → ghi chú ngắn vào bộ nhớ ("panel 1/3, N request") → Red đọc
```
**Tại sao thiết kế vậy?**
- Việc của Red là **chiến lược**, không phải đọc lại từng gói HTTP (đó là việc của gate/verifier).
- Nhồi toàn bộ HTTP thô vào Red sẽ **tốn token + gây nhiễu**, dễ làm Red lạc.
- Verifier đã đọc bằng chứng và **nói đúng chỗ thiếu** rồi → Red chỉ cần cái đó.

> Trade-off rõ ràng: gọn & tập trung, đổi lại phụ thuộc chất lượng "lời chê". (Nếu sau này muốn, có thể đính kèm vài request quan trọng nhất của Exec cho Red.)

---

### Q7. Có khi nào model "chạy lệch" (trả lời lung tung / không trả lời / sai) không? Cơ chế gì chặn?

Có — và mỗi kiểu đều có lưới đỡ **bằng code**:

```
┌────────────────────────────┬──────────────────────────────────────────────────┐
│ Sự cố model                 │ Cơ chế xử lý (tất định, ở code)                    │
├────────────────────────────┼──────────────────────────────────────────────────┤
│ Trả lời RỖNG               │ Không trả "" ra ngoài; tự GỌI LẠI với ngân sách    │
│                            │ lớn hơn; vẫn rỗng → báo lỗi to (không nuốt thầm)   │
│ Bị CẮT giữa chừng (length) │ Gọi lại với max_tokens lớn hơn                      │
│ Proxy chập (lỗi 400 tạm)   │ Tự retry vài lần                                   │
│ Gọi tool SAI cú pháp       │ Bộ đọc hiểu 6 định dạng; JSON hỏng → bỏ qua;       │
│                            │ tham số thiếu → trả lỗi cho model tự sửa bước sau  │
│ Blue trả verdict mơ hồ     │ Mặc định = REVISE (không bao giờ tự DUYỆT nhầm)    │
│ Red BỊA endpoint/field     │ Red tự "GROUNDING CHECK" (thiếu bằng chứng→dừng);  │
│                            │ Blue thấy cùng danh sách thật → bắt được bịa       │
│ Exec gõ nhầm sang endpoint │ Gate CHỈ tính bằng chứng đúng endpoint của phiếu   │
│ khác                       │ (endpoint-scoped) → không báo lỗ giả               │
│ Exec quên làm bước tấn công│ Bị "nhắc" (steering); riêng BLF có cơ chế CODE tự  │
│                            │ gửi request tấn công thay nếu LLM không làm        │
│ Gate phán SAI (FP/FN)      │ Sửa LUẬT GATE (code), không "đè" dữ liệu bằng vote │
└────────────────────────────┴──────────────────────────────────────────────────┘
```

> Triết lý chung: **AI được phép sai trong lượt của nó, nhưng code bao quanh không cho cái sai đó lọt ra thành kết quả** — hoặc retry, hoặc chặn, hoặc để trọng tài-code phán trên dữ liệu thật.
