# marl3 — Kiến trúc & Luồng hoạt động

> Hệ thống tự động kiểm thử lỗ hổng **phân quyền (BAC)** và **logic nghiệp vụ (BLF)** trên ứng dụng web.
> Nguyên tắc cốt lõi: **AI lý luận — code điều phối — dữ liệu thật là chân lý.**

---

## 1. Toàn cảnh pipeline

```
                              ┌──────────────────────────────────────────────────┐
                              │                   marl3 pipeline                  │
                              └──────────────────────────────────────────────────┘

    URL mục tiêu
         │
         ▼
  ┌─────────────┐
  │    RECON    │  Crawl tự động: duyệt web, đăng nhập, ghi lại toàn bộ
  │  (do thám)  │  endpoint, cookie, sự khác biệt quyền truy cập
  └──────┬──────┘
         │  ReconArtifact
         │  (danh sách endpoint + session + body đã lưu trữ)
         ▼
  ┌─────────────┐
  │    HUNT     │  LLM đọc kết quả do thám + luật tất định
  │ (lập nghi   │  → sinh danh sách BugDossier
  │  vấn)       │  mỗi dossier gắn nhãn: pattern_id, endpoint, giả thuyết
  └──────┬──────┘
         │  [BUG-001, BUG-002, BUG-003, ...]
         ▼
  ┌─────────────┐
  │  COORDINATE │  Sắp xếp thứ tự ưu tiên:
  │  (xếp hàng) │  BAC trước BLF · nghiêm trọng trước · đơn giản trước chain
  └──────┬──────┘
         │
         │  Mỗi bug chạy một sub-graph riêng biệt, độc lập
         ▼
  ╔═════════════════════════════════════════╗
  ║         BUG SUB-GRAPH (xem mục 2)       ║
  ╚═════════════════════════════════════════╝
         │
         ▼
  ┌─────────────┐
  │   REPORT    │  Gom toàn bộ kết quả → report.md + findings.json + PoC scripts
  └─────────────┘
```

---

## 2. Sub-graph cho mỗi bug

> Đây là phần cốt lõi. Mỗi BugDossier chạy qua vòng lặp này cho đến khi đạt kết quả cuối cùng.

```
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                          BUG SUB-GRAPH                                  │
  │                                                                         │
  │                  ┌───────────────────────────────┐                      │
  │                  │           DEBATE              │                      │
  │                  │                               │                      │
  │                  │  Red 🔴  ──────────→  Blue 🔵  │                      │
  │                  │  (tấn công)  ←──────  (phản   │                      │
  │                  │               chiến  biện)    │                      │
  │                  │               lược            │                      │
  │      ┌───────────┤                               ├─────────────┐        │
  │      │  STOP /   │   tối đa max_debate_rounds    │   APPROVED  │        │
  │      │  hết vòng └───────────────────────────────┘             │        │
  │      ▼                                                         ▼        │
  │    [END]                                               ┌──────────────┐  │
  │  (bỏ bug)                                              │     EXEC     │  │
  │                                                        │   (khai      │  │
  │                                                        │   thác thật) │  │
  │                                                        └──────┬───────┘  │
  │                                                               │          │
  │                                                    EXEC_DONE  │          │
  │                                                               ▼          │
  │                                                      ┌──────────────┐   │
  │                                                      │    VERIFY    │   │
  │                                                      │              │   │
  │                                                      │ ①Panel 🔍×3 │   │
  │                                                      │  (pre-gate)  │   │
  │                                                      │ ②ProofGate⚖ │   │
  │                                                      │  (authority) │   │
  │                                                      └──────┬───────┘   │
  │                                                             │           │
  │              ┌──────────────────────────────────────────────┤           │
  │              │                                              │           │
  │   PROOF_QUALITY_FAIL                          EXPLOITED /  │           │
  │   (còn budget retry)                          INFO_ONLY /  │           │
  │              │                                FAILED       │           │
  │              ▼                                             ▼           │
  │    quay lại DEBATE                                       [END]         │
  │    (kèm Panel vote +                                 (ghi kết quả)    │
  │     ProofGate markers)                                                 │
  │                                                                         │
  └─────────────────────────────────────────────────────────────────────────┘
```


---

## 3. Các giá trị chuyển luồng

```
  ┌────────────────────┬───────────────────────────────────────────────────────┐
  │ Giá trị            │ Ý nghĩa & luồng tiếp theo                              │
  ├────────────────────┼───────────────────────────────────────────────────────┤
  │ APPROVED           │ Blue đồng ý chiến lược → chuyển sang EXEC              │
  │ REVISE             │ Blue chê, cần sửa → quay lại Red (vòng tranh luận kế)  │
  │ STOP               │ Blue phán bug không thể khai thác → kết thúc bug này   │
  ├────────────────────┼───────────────────────────────────────────────────────┤
  │ EXEC_DONE          │ Exec hoàn thành, có bằng chứng → chuyển sang VERIFY    │
  │ EXEC_ERROR         │ Lỗi kỹ thuật → retry Exec (tối đa 1 lần), không lên   │
  │                    │ Verify; nếu hết lần → kết thúc                         │
  ├────────────────────┼───────────────────────────────────────────────────────┤
  │ EXPLOITED          │ ProofGate xác nhận khai thác thành công → vào report   │
  │ INFO_EXPOSURE_ONLY │ Có lộ thông tin nhưng không đủ để gọi là khai thác     │
  │                    │ → vào report với mức độ thấp hơn, không retry           │
  │ PROOF_QUALITY_FAIL │ Exec đã chạy nhưng bằng chứng chưa đủ cứng             │
  │                    │ → quay lại DEBATE nếu còn budget, ngược lại kết thúc   │
  │ FAILED             │ Khai thác rõ ràng không thành công → kết thúc          │
  └────────────────────┴───────────────────────────────────────────────────────┘
```

---

## 4. Giới hạn số vòng lặp

```
  Debate:
    max_debate_rounds = 3   (mặc định)
    → tối đa 3 vòng Red↔Blue trong một lần debate

  Verify → Debate retry:
    max_verify_retries = 1  (mặc định)
    → chỉ được quay lại debate 1 lần sau khi proof yếu

  Tổng vòng debate cho 1 bug:
    max_debate_rounds × 2 = 6 vòng (gộp cả 2 lần debate)

  Exec retry:
    max_exec_retries = 1
    → chỉ retry khi lỗi kỹ thuật, không retry vì proof yếu

  Thời gian tối đa / bug:
    per_bug_wall_clock_s = 600 giây (10 phút)
```

---

## 5. Vai trò từng thành phần

```
  ┌──────────────┬────────────────────────────────────────────────────────────┐
  │ Thành phần   │ Vai trò                                                    │
  ├──────────────┼────────────────────────────────────────────────────────────┤
  │ Crawler      │ Thu thập thực tế: endpoint, session, sự khác biệt quyền.   │
  │              │ Không có AI — hoàn toàn tự động bằng code.                  │
  ├──────────────┼────────────────────────────────────────────────────────────┤
  │ Hunter       │ Đọc kết quả crawler → đề xuất giả thuyết bug.               │
  │ (LLM)        │ Gắn nhãn pattern_id cho mỗi bug ngay tại đây — nhãn này    │
  │              │ không thay đổi suốt pipeline.                               │
  ├──────────────┼────────────────────────────────────────────────────────────┤
  │ Red 🔴       │ Lập chiến lược tấn công cụ thể: làm gì, endpoint nào,       │
  │ (LLM)        │ payload gì, điều kiện thành công là gì.                     │
  │              │ Vòng 2+: buộc phải phản bác từng điểm Blue đã nêu.          │
  ├──────────────┼────────────────────────────────────────────────────────────┤
  │ Blue 🔵      │ Phản biện chiến lược của Red dựa trên dữ liệu thật từ recon. │
  │ (LLM)        │ Mặc định nghi ngờ. Phán APPROVED / REVISE / STOP.           │
  │              │ Không thể "chê vơ vẩn" vì phải trích dẫn bằng chứng thật.  │
  ├──────────────┼────────────────────────────────────────────────────────────┤
  │ Exec ⚡      │ Thực thi khai thác theo đúng chiến lược đã duyệt.            │
  │ (LLM +       │ Không được tự ý thay đổi chiến lược.                        │
  │  tool calls) │ Mọi request/response tự động ghi lại thành bằng chứng.     │
  ├──────────────┼────────────────────────────────────────────────────────────┤
  │ ProofGate ⚖  │ Trọng tài duy nhất — code thuần túy, không phải AI.         │
  │ (code)       │ Đọc bằng chứng thô → áp rule cứng theo pattern_id.          │
  │              │ EXPLOITED chỉ khi đủ marker bắt buộc của pattern đó.        │
  │              │ AI không thể ghi đè quyết định này.                         │
  ├──────────────┼────────────────────────────────────────────────────────────┤
  │ Verifier 🔍  │ 3 AI độc lập, chạy TRƯỚC ProofGate (pre-gate sanity check).  │
  │ × 3 (LLM)   │ Chỉ đọc raw exchanges — không biết chiến lược Red/Blue,     │
  │              │ cũng không có proof_markers (chưa chạy ProofGate).           │
  │              │ Ba trường hợp sau vote:                                      │
  │              │  · 0/3 + no 2xx → skip ProofGate → PROOF_QUALITY_FAIL       │
  │              │  · 0/3 + has 2xx → ProofGate vẫn chạy (safety net)          │
  │              │  · ≥1/3 confirmed → chạy ProofGate bình thường              │
  │              │ KHÔNG có quyền quyết định EXPLOITED (đó là ProofGate).       │
  │              │ Tác dụng: (1) tín hiệu tin cậy trong báo cáo;               │
  │              │           (2) vote + ProofGate marker detail → gửi Red       │
  │              │               để retry với chiến lược sửa đúng điểm.        │
  └──────────────┴────────────────────────────────────────────────────────────┘
```

---

## 6. Khi nào quay lại Debate?

```
  Verify kết thúc
       │
       ├── ProofGate = EXPLOITED          → KẾT THÚC (bug xác nhận)
       │
       ├── ProofGate = INFO_EXPOSURE_ONLY → KẾT THÚC (ghi nhận, không retry)
       │
       ├── ProofGate = FAILED             → KẾT THÚC (bug không tồn tại)
       │
       └── ProofGate = PROOF_QUALITY_FAIL
                │
                ├── còn budget retry? ─── CÓ ──→ DEBATE lại
                │                                (kèm feedback 2 lớp — xem dưới)
                │   Điều kiện can_retry:
                │     (panel_confirmed ≥ 1 OR has_partial_proof)
                │     AND verify_retries < max_verify_retries (mặc định 1)
                │     AND debate_rounds < max_debate_rounds × 2 (mặc định 6)
                │
                │   has_partial_proof = bất kỳ ProofGate marker nào SATISFIED
                │   → ngay cả khi Panel 0/3, nếu ProofGate thấy tín hiệu
                │     một phần thì vẫn đáng retry
                │
                └──────────────────── HẾT ──→ KẾT THÚC (chấp nhận thua)


  Feedback gửi Red khi retry gồm 2 lớp:
    Lớp 1 — Panel vote:
      "Verifier 1: REJECTED — lý do rộng từ exchanges"
      "Verifier 2: CONFIRMED — ..."
    Lớp 2 — ProofGate markers (cụ thể hơn):
      "[NOT SATISFIED] OWNERSHIP_BYPASS — No owner-field mismatch detected"
      "[SATISFIED] PRIVILEGED_ACCESS — ..."
    → Red biết chính xác điều kiện nào thất bại, không cần đoán mò.

  Lưu ý quan trọng:
    · Quay về DEBATE, không phải thẳng sang Exec
      → vì Exec chỉ làm theo chiến lược, phải sửa chiến lược trước
    · Red nhận feedback 2 lớp → sửa đúng điểm yếu, không viết lại từ đầu
    · Thread debate bắt đầu mới nhưng Red biết lý do fail cụ thể
```

---

## 7. Hệ thống bộ nhớ (Memory)

```
  ┌────────────────────────────────────────────────────────────────────────┐
  │                         MEMORY SYSTEM                                  │
  │                                                                         │
  │  SHORT-TERM (per run)                  LONG-TERM (cross run, SQLite)   │
  │  memory.json                           longterm.db                     │
  │                                                                         │
  │  · Chiến lược đã duyệt (strategies)  · Episodes: những khai thác       │
  │  · Ghi chú verify sau mỗi bug:          thành công trên target thật    │
  │    - Panel vote (N/3)               · Rules: kỹ thuật trừu tượng       │
  │    - Steps: METHOD /path → STATUS     đã được đúc kết (≥3 success,     │
  │      (actor=...)                       ≥2 target khác nhau)            │
  │    - Markers: [SAT/NOT] KEY: detail │                                   │
  │  · Lịch sử attempt (EXPLOITED /     │                                   │
  │    NOT_EXPLOITED) per bug           │                                   │
  │        ▼                                       ▼                        │
  │   Nạp vào: Debate + Exec              Nạp vào: Hunt + Exec              │
  │   (context của run hiện tại)          (kinh nghiệm từ run trước)        │
  │                                                                         │
  │  Nguyên tắc chống overfitting:                                          │
  │    Same target → giữ nguyên payload cụ thể                             │
  │    Cross target → chỉ giữ kỹ thuật trừu tượng (bỏ host/URL/tên field) │
  └────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Luồng dữ liệu xuyên suốt

```
  Hunter
    └─ gắn pattern_id vào BugDossier ───────────────────────────────────┐
                                                                         │
  Red/Blue                                                               │ pattern_id
    └─ chiến lược đóng băng (StrategyDocument) ───────────────┐         │ từ dossier
                                                               │         │
  Exec                                                         ▼         ▼
    └─ ghi mọi request/response → Evidence  ──→  Panel × 3 đọc Evidence (pre-gate)
                                                        │
                                                        ├─ 0/3 + no 2xx → PROOF_QUALITY_FAIL
                                                        │
                                                        └─ has 2xx OR ≥1/3 →
                                                              ProofGate đọc Evidence
                                                              (dùng rule theo pattern_id)
                                                                    │
                                                                    ├─ [fallback] BAC-01 fail
                                                                    │   → thử IDOR rule
                                                                    │   → nếu pass: promote
                                                                    │     evidence.pattern_id
                                                                    │     = "BAC-03"
                                                                    │
                                                                    ▼
                                                              verdict_status + proof_markers
                                                              (đóng dấu vào Evidence)
                                                                    │
  Verify node                                                        │
    └─ đọc verdict_status ◀─────────────────────────────────────────┘
       → bug_status: EXPLOITED / INFO_EXPOSURE_ONLY / PROOF_QUALITY_FAIL

  Report node
    └─ PocGenerator tái tạo PoC từ proof_markers.exchange_seqs
       (chỉ giữ exchanges liên quan tới proof — loại bỏ navigation noise)
```

> **Ghi chú:** Hunter gắn pattern_id lúc đầu. ProofGate CÓ THỂ promote pattern_id khi phát hiện
> pattern thực tế khác (ví dụ: Hunter gắn BAC-01 cho `/profile`, Exec khai thác IDOR `/profile/{id}`,
> ProofGate fallback xác nhận cross-user → promote sang BAC-03).

---

## 9. Một câu chốt

```
  ┌──────────────────────────────────────────────────────────────────────┐
  │                                                                      │
  │   CODE điều phối   ┃   AI lý luận trong từng ô   ┃   CODE phán kết  │
  │   (tất định)       ┃   (sáng tạo, có thể sai)    ┃   quả (dữ liệu  │
  │                    ┃                              ┃   thật)          │
  │                                                                      │
  │   → Luồng ổn định, tái lập được, không báo lỗ giả.                  │
  │                                                                      │
  └──────────────────────────────────────────────────────────────────────┘
```
