# marl3 — A multi-agent system for detecting and exploiting business logic flaws and broken access control vulnerabilities.

> Công cụ pentest tự động phát hiện và **chứng minh** lỗ hổng phân quyền (BAC) và logic nghiệp vụ (BLF) trên ứng dụng web, sử dụng kiến trúc đa agent điều phối bằng LangGraph.

---

## Mục lục

1. [Đặt vấn đề — tại sao xây cái này?](#1-đặt-vấn-đề--tại-sao-xây-cái-này)
2. [Triết lý thiết kế cốt lõi](#2-triết-lý-thiết-kế-cốt-lõi)
3. [Bức tranh tổng thể](#3-bức-tranh-tổng-thể)
4. [LangGraph — Xương sống điều phối](#4-langgraph--xương-sống-điều-phối)
5. [Từng giai đoạn — Mindset & Cơ chế](#5-từng-giai-đoạn--mindset--cơ-chế)
   - [5.1 RECON — Thu thập bằng chứng](#51-recon--thu-thập-bằng-chứng)
   - [5.2 HUNT — Đặt giả thuyết](#52-hunt--đặt-giả-thuyết)
   - [5.3 COORDINATE — Xếp hàng](#53-coordinate--xếp-hàng)
   - [5.4 DEBATE — Lập kế hoạch qua phản biện](#54-debate--lập-kế-hoạch-qua-phản-biện)
   - [5.5 EXEC — Khai thác thật](#55-exec--khai-thác-thật)
   - [5.6 VERIFY — Phán xét bằng dữ liệu](#56-verify--phán-xét-bằng-dữ-liệu)
   - [5.7 REPORT — Báo cáo](#57-report--báo-cáo)
6. [Dữ liệu chuyền tay giữa các node](#6-dữ-liệu-chuyền-tay-giữa-các-node)
7. [Long-term Memory — Học mà không overfit](#7-long-term-memory--học-mà-không-overfit)
8. [Từ điển thuật ngữ](#8-từ-điển-thuật-ngữ)
9. [Kết quả thực nghiệm](#9-kết-quả-thực-nghiệm)
10. [Cài đặt & Chạy](#10-cài-đặt--chạy)
11. [Điểm tồn đọng & TODO](#11-điểm-tồn-đọng--todo)

---

## 1. Đặt vấn đề — tại sao xây cái này?

### Hai lớp lỗ hổng mục tiêu

| Lớp | Tên đầy đủ | Ý nghĩa |
|-----|-----------|---------|
| **BAC** | Broken Access Control | Ứng dụng không kiểm soát đúng ai được phép làm gì — user thường leo thang thành admin, đọc dữ liệu của người khác (IDOR), truy cập endpoint bị khóa |
| **BLF** | Business Logic Flaw | Ứng dụng xử lý đúng kỹ thuật nhưng sai logic nghiệp vụ — giá âm được chấp nhận, mã giảm giá dùng lại nhiều lần, bỏ qua bước thanh toán |

**Điểm khó:** Cả hai loại này không có pattern cú pháp rõ ràng như SQL injection hay XSS. Để phát hiện BAC, bạn phải *thực sự đăng nhập như hai người dùng khác nhau và so sánh kết quả*. Để phát hiện BLF-05 (coupon reuse), bạn phải *chạy đúng chuỗi 4 bước*: thêm hàng → áp mã → thanh toán → hủy → áp lại. Không có regex nào tìm được.

### Vấn đề với các tool tự động hiện có

Hầu hết scanner tự động (Nikto, OWASP ZAP, Burp Scanner) tìm lỗi bằng cách gửi payload cố định vào từng trường. Cách này hiệu quả với injection nhưng **hoàn toàn bỏ qua** BAC và BLF vì:

- Không hiểu ngữ cảnh phân quyền (endpoint nào cần role gì)
- Không biết chuỗi nghiệp vụ (bước nào phải đến trước)
- Không phân biệt "đây là dữ liệu hợp lệ cần kiểm thử" với "đây là dữ liệu thật của người dùng khác"

**marl3 giải quyết bằng cách:** dùng LLM để *hiểu ngữ cảnh*, dùng *code tất định* để *phán xét* và *điều phối*, và dùng *evidence thật* (HTTP request/response thực tế) để *chứng minh*.

---

## 2. Triết lý thiết kế cốt lõi

Trước khi đọc bất kỳ chi tiết nào, cần nắm 5 nguyên tắc này. Mỗi quyết định thiết kế đều bắt nguồn từ đây.

### D1: Dữ liệu là sự thật — không phải lời của LLM

```
ProofGate (code) đọc Evidence (HTTP data thật) → phán EXPLOITED / FAILED
LLM Verifier panel → chỉ tư vấn, KHÔNG override gate
```

LLM có thể bịa, ảo giác, tự tin sai. Nhưng một HTTP response với `status=200` và body chứa email của 1000 người dùng là bằng chứng không thể tranh cãi. **Quyết định cuối cùng luôn phải đến từ dữ liệu thật, không từ đánh giá chủ quan của AI.**

Hệ quả: nếu gate báo sai → sửa **rule trong gate** (code), không cần sửa prompt.

### D2: Code điều phối — LLM chỉ suy nghĩ trong từng ô

```
Ai quyết định node nào đi tiếp?  → CODE (if/else trên trạng thái)
Ai lập kế hoạch tấn công?        → LLM (Red agent)
Ai gửi HTTP request?              → LLM (Exec agent, dùng tool)
Ai phán EXPLOITED?               → CODE (ProofGate)
```

LLM không bao giờ được quyền nói "bây giờ hãy chuyển sang node verify" hay "bug này không cần exec". Đây là lý do dùng LangGraph — máy trạng thái viết bằng code, không phải "agent manager" là LLM.

### D3: Lossless-on-disk — không bao giờ cắt bỏ dữ liệu HTTP

Mọi HTTP response body được lưu nguyên vẹn trên đĩa, đánh địa chỉ bằng hash SHA-256 (`bodies/<sha256>.bin`). Object trong RAM chỉ giữ con trỏ (`BodyRef`) + đoạn preview. **Cấm tuyệt đối cắt giữa chuỗi response** — nếu quá giới hạn thì bỏ item đó hoàn toàn và ghi chú, không giữ nửa vời.

Lý do: một response bị cắt có thể làm Gate đọc nhầm (ví dụ: email bị cắt trở thành chuỗi bình thường), dẫn đến false negative hoặc false positive.

### D4: Memory chống overfit — học cách, không học mục tiêu

```
Same-target tier:   payload cụ thể (URL, field, value của target đó)
                    → chỉ inject vào đúng target fingerprint đó
Cross-target tier:  kỹ thuật trừu tượng (pattern + vai trò endpoint + category field)
                    → gated: phải xác nhận trên ≥ 2 target KHÁC NHAU mới được inject
```

Mục tiêu: khi gặp target mới, hệ thống nhớ *cách* khai thác (negative price tamper trên endpoint transfer), không nhớ *cụ thể* (gửi `-100` vào `localhost:5001/wallet/transfer`). Hai target đều có negative price bug nhưng endpoint khác nhau → technique được trừu tượng hóa → áp dụng được.

### D5: Không hardcode per-target

Mọi giá trị cụ thể (coupon code, product id, endpoint path) phải được **harvest từ recon** của target đó, không được viết cứng trong logic pipeline. Đây là ranh giới giữa tool pentest general và script khai thác 1 target cụ thể.

---

## 3. Bức tranh tổng thể

```
  URL + credentials
        │
        ▼
  ┌─────────────┐
  │    RECON    │  ← Thu thập bằng chứng: crawl web, đăng nhập, ghi lại HTTP
  └──────┬──────┘
         │ ReconArtifact (danh sách endpoint + request/response mẫu)
         ▼
  ┌─────────────┐
  │    HUNT     │  ← Đặt giả thuyết: "endpoint X có thể dính lỗ Y vì lý do Z"
  └──────┬──────┘
         │ Danh sách BugDossier (phiếu nghi vấn)
         ▼
  ┌──────────────┐
  │  COORDINATE  │  ← Xếp ưu tiên, xác định phụ thuộc
  └──────┬───────┘
         │
         ▼ (vòng lặp per bug)
  ┌──────────────────────────────────────────────────────┐
  │                    VÒNG LẶP PER BUG                   │
  │                                                       │
  │   ┌─────────┐   APPROVE    ┌──────┐    Evidence    ┌─────────┐  │
  │   │  DEBATE │ ──────────→  │ EXEC │ ─────────────→ │ VERIFY  │  │
  │   │ Red↔Blue│              └──────┘                └────┬────┘  │
  │   └────┬────┘                                           │        │
  │        │ ← ── ── ── ── ── PROOF_QUALITY_FAIL ── ── ── ─┘        │
  │        │ (kèm lý do gate từ chối — Red sửa đúng điểm đó)        │
  └──────────────────────────────────────────────────────────────────┘
         │ Finding (EXPLOITED / NOT_EXPLOITED)
         ▼
  ┌─────────────┐
  │   REPORT    │  ← report.md + findings.json + PoC per bug
  └─────────────┘
```

**Điểm then chốt:** Tất cả mũi tên trong sơ đồ trên là quyết định của **code** (LangGraph routing function), không phải của LLM. LLM chỉ làm việc *bên trong* từng ô.

---

## 4. LangGraph — Xương sống điều phối

### Tại sao cần LangGraph?

Vấn đề cần giải: hệ thống có **nhiều agent**, **nhiều vòng lặp** (debate có thể quay lại nhiều lần, verify fail thì quay về debate), và **trạng thái phải nhất quán** xuyên suốt. Nếu tự viết bằng if/else thủ công sẽ nhanh chóng thành mớ hỗn độn.

LangGraph cung cấp `StateGraph` — một đồ thị có hướng, trong đó:
- **Node** = một bước xử lý (một hàm Python nhận state, trả state mới)
- **Edge** = điều kiện chuyển tiếp (một hàm Python thuần túy đọc state, trả tên node tiếp theo)
- **State** = một `TypedDict` duy nhất truyền xuyên suốt toàn bộ pipeline

### Sơ đồ node và routing

```
  [recon] ──→ [hunt] ──→ [coordinate] ──→ [debate_red]
                                                │
                              ┌─── STOP ────────┤
                              │                 ▼
                              │          [debate_blue]
                              │                │
                              │    REVISE ──────┤
                              │    (còn lượt)   │ APPROVE
                              │                 ▼
                              │           [execution]
                              │                │
                              │                ▼
                              │           [verify]
                              │                │
                              ├── PROOF_QUALITY_FAIL (còn retry) ──→ [debate_red]
                              │                │
                              └── DONE ─────────┘
                                   (next bug hoặc [report])
```

**Routing function** (code, không phải LLM) đọc các biến:
- `bug_state` (PENDING → IN_DEBATE → APPROVED → EXECUTED → VERIFIED → DONE/FAILED)
- `debate_retries` còn bao nhiêu
- `verify_retries` còn bao nhiêu
- `blue_decision` (APPROVE / REVISE / STOP)

→ quyết định node tiếp theo trong ~5 dòng if/else.

### State — "xương sống" truyền dữ liệu

```python
# State là TypedDict duy nhất, tất cả node đọc/ghi vào đây
{
  "target_url": str,
  "recon": ReconArtifact,        # kết quả do thám
  "dossiers": list[BugDossier],  # danh sách phiếu nghi vấn
  "current_bug_idx": int,        # đang xử lý phiếu nào
  "bug_runs": list[BugRun],      # trạng thái từng phiếu
  "findings": list[Finding],     # kết quả cuối cùng
}
```

Không có agent nào "nhớ" context từ lượt trước bằng conversation history dài. Thay vào đó, **mỗi lượt gọi LLM được dựng ngữ cảnh từ State** — sạch, có thể kiểm soát, không bị nhiễu từ các bug khác.

---

## 5. Từng giai đoạn — Mindset & Cơ chế

---

### 5.1 RECON — Thu thập bằng chứng

#### Mindset

> *"Không tin vào bất kỳ giả định nào về cấu trúc app. Đi thu thập dữ liệu thô: endpoint nào tồn tại, endpoint nào cần auth, endpoint nào trả gì cho anon vs auth user."*

Recon không được phép phán xét hay đặt giả thuyết — nó chỉ thu thập và ghi lại. Output của Recon là **bằng chứng thô** mà các giai đoạn sau sẽ phân tích.

#### Vấn đề cần giải

Ứng dụng web hiện đại không chỉ có HTML `<form>` nữa. Rất nhiều action được trigger qua `fetch()` JavaScript (SPA, AJAX). Nếu chỉ parse HTML, sẽ bỏ qua toàn bộ tầng API của ứng dụng.

Thêm vào đó, endpoint "nhạy cảm" như `/admin` không link trực tiếp từ nav bar của user thường — phải probe chủ động.

#### Cách xử lý — 4 tầng thu thập song song

```
Tầng 1 — Passive crawl
  Follow <a href>, submit <form>
  → endpoint được link công khai

Tầng 2 — JS extraction
  Regex scan <script>: fetch('/endpoint') / axios.post('/endpoint') / XHR.open()
  Reconstruct path template: '/orders/' + id → /orders/{id}
  Extract field names từ JSON.stringify({field1, field2})
  → endpoint AJAX không có trong HTML

Tầng 3 — Active probe
  Gửi request đến danh sách path đã biết: /admin, /api/v1/users, /api/v1/orders/1, ...
  → endpoint không được link từ đâu cả

Tầng 4 — Auth-diff
  So sánh response của cùng endpoint: anon vs auth user
  → signal BAC: nếu anon trả 302/403 nhưng auth trả 200 → endpoint cần xác thực
```

**Điểm tinh tế — Soft-404 filter:**
Nhiều app trả body dài cho mọi response (kể cả 404) vì có nav bar, footer. Filter kiểm tra: nếu body length của response ≈ body length của `/404` probe (trong khoảng ±100 byte), coi là "không tồn tại". Nhưng **JSON response được miễn** — vì JSON compact (143 byte) không thể so với HTML 404 page (207 byte), dù cả hai đều nhỏ.

**Guard quan trọng:** Không bao giờ probe `/logout` (sẽ kill session đang có). Cũng không interpret 302 redirect là "không tồn tại" — 302 là signal "endpoint tồn tại, cần auth", rất có giá trị.

**Safe-probe JS endpoint:** Với endpoint tìm được qua JS (chưa từng được gọi thật), gửi một request `{}` để capture response thật. App sẽ trả lỗi validation (400) trước khi làm gì → không có side effect, nhưng ta có method + content-type + field names thật.

#### Output

`ReconArtifact` — một object chứa:
- Danh sách `Endpoint` (path, method, parameters, auth_required, discovery method, http_examples)
- `AuthDiff` list — cặp (anon_response, auth_response) cho mỗi endpoint
- `BodyStore` — content-addressed store cho tất cả response body (SHA-256 → file trên disk)

---

### 5.2 HUNT — Đặt giả thuyết

#### Mindset

> *"LLM đọc danh sách endpoint thật (từ recon) và đặt giả thuyết: cái này có thể bị khai thác theo pattern nào? Bằng cách nào? Tại sao? LLM không phán 'đây là lỗ hổng' — nó chỉ nói 'đây là nghi vấn đáng thử'."*

Hunt là bước duy nhất LLM được "sáng tạo". Nó nhìn vào bức tranh tổng thể của app (tất cả endpoint, auth diff, workflow) và đưa ra danh sách **phiếu nghi vấn** (`BugDossier`).

#### Hai bước trong Hunt

**Bước 1 — Rule-based prefilter (code):**
Trước khi gọi LLM, lọc sơ bằng rule cứng:
- Endpoint có auth_diff (anon=403, auth=200) → ứng viên BAC
- Endpoint nhận numeric field (amount, quantity, price) → ứng viên BLF
- Endpoint có `{id}` trong path → ứng viên IDOR

**Bước 2 — LLM Hunter (suy luận):**
Hunter nhận toàn bộ ReconArtifact và list prefiltered candidates. Với mỗi candidate, Hunter viết ra `BugDossier` gồm:
- `pattern_id`: BAC-01 / BAC-02 / BAC-03 / BLF-01 / BLF-05 / BLF-06 / ...
- `hypothesis`: giả thuyết cụ thể (ví dụ: "cookie `role` là plaintext, có thể tamper thành admin")
- `exploit_approach`: các bước khai thác theo thứ tự (chain reasoning)
- `evidence_rules`: điều kiện nào thì coi là EXPLOITED

Hunter **không được phép nói "đây chắc chắn là lỗ hổng"**. Nó chỉ mô tả nghi vấn. Verdict là việc của ProofGate sau này.

#### Tại sao cần LLM ở đây?

Vì BAC và BLF đòi hỏi hiểu *ngữ cảnh*. Ví dụ: để nhận ra `/api/v1/users` là BAC-01 (lộ PII), LLM phải hiểu rằng: endpoint không cần auth + response chứa email/balance/phone của nhiều user = bất kỳ ai cũng đọc được dữ liệu nhạy cảm. Không có rule regex nào bắt được tổ hợp ngữ cảnh này.

---

### 5.3 COORDINATE — Xếp hàng

#### Mindset

> *"Không phải mọi bug đều độc lập. Bug IDOR cần session của victim trước. Bug coupon reuse cần có item trong cart trước. Coordinate xếp hàng theo ưu tiên và đánh dấu phụ thuộc."*

Đây là node đơn giản nhất — chủ yếu sắp xếp `BugDossier` theo:
1. Severity (CRITICAL trước)
2. Pattern (BAC trước BLF, simple trước chain)
3. Dependencies (bug A cần output của bug B thì B đi trước)

Output: queue có thứ tự để vòng lặp per-bug chạy theo.

---

### 5.4 DEBATE — Lập kế hoạch qua phản biện

#### Mindset

> *"Trước khi thực sự gửi HTTP request, hãy kiểm tra lại chiến lược. Một agent lập kế hoạch, một agent cố tìm lỗ hổng trong kế hoạch đó. Chỉ khi kế hoạch vượt qua phản biện mới được thực thi."*

#### Tại sao cần Debate?

Vấn đề với Exec agent chạy trực tiếp từ dossier: dossier có thể thiếu bước, sai field name, hoặc dựa vào giả định sai về app. Nếu exec ngay, sẽ fail ở step đầu tiên và không hiểu tại sao.

Debate tạo ra **chiến lược cụ thể và đã được kiểm tra** trước khi exec bắt đầu.

#### Red agent — Người lập kế hoạch

**Vòng đầu (strategy):** Red nhận phiếu nghi vấn + kiến thức về loại lỗ → viết ra:
- Phần `STRATEGY`: tổng quan cách khai thác
- Phần `EXECUTION GUIDE`: các bước cụ thể theo thứ tự
- Phần `SUCCESS CONDITIONS`: khi nào thì coi là đã exploit thành công

Red **không được bịa endpoint hay field không có trong recon**. Nó chỉ được sử dụng những gì đã quan sát được.

**Vòng sau (rebuttal):** Nếu Blue phản biện, Red phải respond đúng từng điểm Blue đã chỉ ra — không viết lại từ đầu.

#### Blue agent — Người phản biện

Blue nhận chiến lược của Red và cố tìm lý do nó sẽ fail:
- "Endpoint này không thật trong recon"
- "Bước 2 thiếu authentication"
- "Điều kiện thành công quá mơ hồ"

Blue trả về một trong ba phán quyết:
- `APPROVE` → chiến lược đủ chắc → sang Exec
- `REVISE` → có vấn đề cụ thể → Red phải sửa (còn lượt thì quay lại)
- `STOP` → không có cơ sở thử → bỏ phiếu này

**Điều quan trọng:** Blue và Red nhìn vào **cùng một danh sách endpoint thật** từ recon — Blue không thể approve nếu Red đề xuất tấn công vào endpoint không tồn tại.

#### Sản phẩm của Debate

Một `StrategyDocument` đã được approve, gồm 3 phần rõ ràng: strategy / steps / success_conditions. Exec sẽ dùng đúng cái này, không tự sáng tạo thêm.

---

### 5.5 EXEC — Khai thác thật

#### Mindset

> *"Tool-calling agent: nhận chiến lược đã duyệt, có trong tay các công cụ HTTP, và tự quyết định từng bước gửi request nào. Mọi request đều được ghi lại. Mọi thất bại đều được phân tích để tự điều chỉnh."*

#### Exec không phải script — nó tự quyết định từng bước

Không có vòng lặp cứng "bước 1 → bước 2 → bước 3". Exec nhận chiến lược dưới dạng ngôn ngữ tự nhiên, có danh sách tool, và tự quyết định dùng tool nào với tham số gì dựa trên response vừa nhận.

```
System prompt (chiến lược + known values + hướng dẫn) 
→ LLM quyết định: "gọi http_request(GET /cart)" 
→ nhận response 
→ LLM quyết định: "gọi http_request(POST /cart/add, {product_id: 2})"
→ ...
```

#### Các "guardrail" giúp Exec không đi lạc

**Guardrail 1 — Known values (Tier 2):**
Thay vì để Exec đoán giá trị (thường đoán sai), harvest từ recon bodies và inject vào prompt:
```
Known-Good Values (USE THESE — do not guess):
- Valid resource IDs: [1, 2, 3, 4, 5]
- Real usernames: ['alice', 'bob', 'charlie']
- Valid coupon codes: ['SAVE10']
- Product prices: id=1→$19.99, id=2→$29.99
```

**Guardrail 2 — Body encoding auto-retry (Tier 1):**
Exec không cần biết endpoint dùng form-urlencoded hay JSON. `RecordingHttpClient` tự thử form trước, nếu nhận `{400, 404, 415, 422}` thì retry với JSON. Exec chỉ thấy "request thành công" hay "thất bại", không thấy encoding issue.

**Guardrail 3 — Chain steering (Tier 3):**
Với multi-step chain (BLF-05 coupon reuse), inject thêm:
```
MULTI-STEP CHAIN — pattern BLF-05. Execute EVERY step below in ORDER:
[dossier exploit_approach được paste vào đây]
Do NOT stop until you have attempted the FINAL step.
```

`_needs_more()` kiểm tra: nếu chain chưa đủ 2 state-changing request thì không cho dừng. Anti-waste: nếu ≥7 bước mà chưa có action nào → break sớm (exec đang đi lạc).

#### RecordingHttpClient — Ghi lại mọi thứ

Mọi HTTP call từ Exec đều đi qua `RecordingHttpClient`, wrapper này:
1. Ghi lại request (method, URL, headers, body) vào `Exchange` object
2. Ghi lại response (status, headers, body) — body lưu vào BodyStore
3. Gán số thứ tự (seq) để trace sau này
4. Trả response cho Exec như bình thường

Exec không biết gì về việc ghi lại này — nó chỉ thấy tool hoạt động bình thường.

#### Output của Exec

`Evidence` object chứa:
- Danh sách `HttpExchange` theo thứ tự
- `state_before` / `state_after` — snapshot state trước và sau
- `state_delta` — thay đổi numeric field (balance tăng bao nhiêu, quantity thay đổi ra sao)

---

### 5.6 VERIFY — Phán xét bằng dữ liệu

#### Mindset

> *"Đây là giai đoạn quan trọng nhất. Exec đã gửi request — nhưng đó là exploit thật hay chỉ là noise? Câu trả lời phải đến từ dữ liệu, không từ AI đánh giá."*

#### Hai tầng verify độc lập

```
        Evidence (HTTP data thật)
               │
        ┌──────┴──────┐
        │             │
   ┌────▼────┐   ┌────▼────────────┐
   │  PROOF  │   │  VERIFIER PANEL │
   │  GATE   │   │  (3 agent LLM)  │
   │  (code) │   │  refute-default │
   └────┬────┘   └────────┬────────┘
    AUTHORITY         ADVISORY
        │                 │
        │    xuất hiện trong report
        │    nhưng KHÔNG override gate
        ▼
   EXPLOITED / FAILED
```

#### ProofGate — Trọng tài code

Gate đọc `Evidence` và kiểm tra các `ProofMarker` cụ thể:

| Pattern | ProofMarker cần thỏa | Điều kiện |
|---------|---------------------|-----------|
| BAC-02 (cookie tamper) | PRIVILEGED_ACCESS + AUTH_BYPASS | Có page admin render (title check) VÀ cùng endpoint: blocked→200 sau khi flip cookie |
| BAC-01 (info exposure) | PRIVILEGED_ACCESS | Anon actor nhận 200 với JSON chứa sensitive fields (email, balance, phone của nhiều user) |
| BAC-03 (IDOR) | CROSS_USER_ACCESS | Response chứa owner field ≠ attacker's user_id |
| BLF-01 (price tamper) | PRICE_MANIPULATION + STATE_DELTA | Numeric ≤0 được accept (2xx, không có error text) |
| BLF-05 (coupon reuse) | PRICE_MANIPULATION + STATE_DELTA | Cùng code 2xx ≥2 lần VỚI consume event (checkout) ở giữa |
| BLF-06 (qty tamper) | QUANTITY_TAMPER + STATE_DELTA | Negative quantity accepted |

**Rule cứng:** Nếu không đủ marker → `FAILED`. Không có trường hợp ngoại lệ. Không có "tuy nhiên nếu...". Điều này đảm bảo **zero false positive** từ phía gate.

#### Verifier Panel — Tư vấn độc lập

3 Verifier agent chạy song song, mỗi agent:
- **Không thấy** transcript debate (tránh bị ảnh hưởng bởi kế hoạch của Red)
- **Mặc định nghi ngờ** — phải bị thuyết phục bởi evidence, không phải bởi lời khai
- Trả ra: `confirmed` (bool), `confidence` (0.0–1.0), `rationale`, `cited_markers`, `refutation_points`

Panel decision hiển thị trong report (cho context phân tích) nhưng **không override gate**. Nếu gate nói EXPLOITED và panel 2/3 nói không → vẫn EXPLOITED (và report sẽ note "2/3 panel skeptical").

**Tại sao giữ panel nếu không override?**
Vì panel cung cấp context định tính — tại sao exploit hoạt động theo góc nhìn security — giúp người đọc report hiểu, không phải để quyết định verdict.

#### PROOF_QUALITY_FAIL → quay về Debate

Nếu gate trả `FAILED` và còn `verify_retries`, hệ thống không bỏ phiếu luôn. Nó gửi lý do fail về Debate để Red sửa đúng điểm đó:
```
"Gate từ chối: PRICE_MANIPULATION không thỏa — response có error text 'invalid amount'. 
Thử endpoint khác hoặc field khác."
```
Red vòng tiếp theo sửa đúng điểm này, không viết lại từ đầu.

---

### 5.7 REPORT — Báo cáo

#### Mindset

> *"Mọi claim trong report phải traceable về HTTP evidence thật. Không có câu 'có thể bị khai thác' — chỉ có 'đã khai thác, đây là bước reproduce'."*

Report builder đọc tất cả `Finding` đã EXPLOITED và tạo:

**`report.md`** — Human-readable:
- Summary table (EXPLOITED / NOT_EXPLOITED / tổng)
- Với mỗi EXPLOITED bug: severity, endpoint, proof markers thỏa, verifier panel decision
- Embedded PoC (HTTP request/response thật, đủ để reproduce)

**`findings.json`** — Machine-readable:
- Full `Finding` object per bug (tất cả evidence, exchanges, markers, panel rationale)
- Dùng cho post-processing hoặc tích hợp vào reporting system khác

**`pocs/poc_<BUG>.txt`** — Proof of Concept độc lập:
- Chỉ những exchange cần thiết để reproduce (state-changing request)
- Đủ để copy-paste vào Burp Suite / curl

---

## 6. Dữ liệu chuyền tay giữa các node

Đây là "huyết mạch" của hệ thống — hiểu được cái này là hiểu được tại sao các agent phối hợp được mà không cần "manager" AI.

```
  RECON
  └─→ ReconArtifact {
        endpoints: [Endpoint(path, method, params, auth_required, examples)],
        auth_diffs: [AuthDiff(endpoint, anon_resp, auth_resp)],
        body_store: BodyStore (SHA-256 → bytes trên disk)
      }

  HUNT (đọc ReconArtifact) 
  └─→ [BugDossier] {
        pattern_id: "BLF-05",
        endpoint: "/coupon/apply",
        hypothesis: "coupon code có thể áp dụng lại sau khi cancel order",
        exploit_approach: "1. Add item\n2. Apply SAVE10\n3. Checkout\n4. Cancel\n5. Apply SAVE10 again",
        evidence_rules: "second apply must return 200 with discount"
      }

  DEBATE (đọc BugDossier + ReconArtifact)
  └─→ StrategyDocument {
        strategy: "...",
        steps: "1. GET /cart\n2. POST /cart/add {...}\n...",
        success_conditions: "coupon applied twice, both 200"
      }

  EXEC (đọc StrategyDocument + known_values từ ReconArtifact)
  └─→ Evidence {
        exchanges: [HttpExchange × N],
        state_before: {balance: 100},
        state_after: {balance: 100},
        state_delta: {},
        proof_markers: [] (để trống, Gate sẽ điền)
      }

  VERIFY (đọc Evidence)
  └─→ Verdict {
        status: "EXPLOITED",
        satisfied_markers: [PRICE_MANIPULATION, STATE_DELTA],
        reason: "coupon SAVE10 accepted 5 times with consume events between"
      }

  REPORT (đọc [Finding])
  └─→ report.md + findings.json + pocs/
```

**Điểm quan trọng:** Mỗi object trên là **pure data** — không có method nào phụ thuộc vào LLM. Agent đọc object, làm việc của mình, trả object mới. Không có "ngầm hiểu" giữa các agent.

---

## 7. Long-term Memory — Học mà không overfit

### Vấn đề

Sau khi chạy nhiều target, hệ thống tích lũy kinh nghiệm. Nhưng nếu lưu và inject naively ("lần trước dùng `/wallet/transfer` với `amount=-100` thành công"), thì khi sang target mới (không có `/wallet/transfer`), thông tin đó là noise, thậm chí hại.

### Giải pháp — 2-tier memory

```
          EPISODE THẬT
          (từ run đã EXPLOITED)
                │
        ┌───────┴────────┐
        │                │
   SAME TARGET      CROSS TARGET
   tier                 tier
   ────────────    ─────────────────────────────
   Lưu payload    _abstract_technique() trước khi lưu:
   cụ thể:          • Xóa host/URL/title
   URL, field,      • Giữ: pattern + endpoint_role + field + sequence
   value,           Gated: chỉ lưu nếu xác nhận trên ≥2 target khác nhau
   sequence
        │                │
        ▼                ▼
   Inject vào      Inject vào target mới (nếu có ≥2 xác nhận)
   đúng target     dưới dạng kỹ thuật trừu tượng:
   đó              "negative amount on transfer endpoint → try here"
```

**`_endpoint_role()`:** Chuẩn hóa path về "vai trò" — `/wallet/transfer` và `/account/send` đều có role là "transfer". Nhờ vậy kỹ thuật từ một target được nhận ra là applicable cho target khác dù path khác nhau.

**`_abstract_technique()`:** Strip tất cả thông tin target-specific trước khi lưu cross-target. Kết quả: "negative value on money field of transfer endpoint" — không phải "send `-100` to `localhost:5001/wallet/transfer`".

### Memory commands

```bash
marl3 memory stats   # xem DB stats
marl3 memory list    # xem episodes
marl3 memory rules   # xem validated techniques (≥2 target)
marl3 memory prune   # xóa stale entries
marl3 memory clear   # xóa toàn bộ (cold-start)
```

---

## 8. Từ điển thuật ngữ

| Thuật ngữ | Định nghĩa trong hệ thống |
|-----------|--------------------------|
| **BAC** | Broken Access Control — lớp lỗ về phân quyền (ai được làm gì) |
| **BLF** | Business Logic Flaw — lớp lỗ về logic nghiệp vụ (làm gì thì được phép) |
| **BAC-01** | Anonymous access to sensitive data — truy cập không cần đăng nhập mà vẫn lấy được dữ liệu nhạy cảm |
| **BAC-02** | Cookie/param escalation — tamper cookie hoặc param để leo thang từ user lên admin |
| **BAC-03** | IDOR — Insecure Direct Object Reference — truy cập resource của người khác qua path param |
| **BAC-06** | Forced browsing — truy cập endpoint bị khóa bằng cách duyệt thẳng URL |
| **BLF-01** | Price tamper — giá trị tiền âm hoặc ngoài phạm vi được server chấp nhận |
| **BLF-05** | Coupon reuse — mã giảm giá "một lần" được dùng lại nhiều lần |
| **BLF-06** | Quantity tamper — số lượng âm được server chấp nhận |
| **BLF-03** | State skip — bỏ qua một bước bắt buộc trong luồng (ví dụ: thanh toán → nhận hàng không qua verify) |
| **ReconArtifact** | Object chứa toàn bộ kết quả do thám: endpoints, auth diffs, body store |
| **BugDossier** | "Phiếu nghi vấn" — mô tả một lỗ tiềm năng: endpoint, pattern, giả thuyết, exploit approach |
| **Evidence** | Tập hợp HTTP exchange thật được ghi lại trong quá trình exec một bug |
| **ProofMarker** | Một điều kiện cụ thể trong Evidence đã được thỏa (ví dụ: PRIVILEGED_ACCESS, STATE_DELTA) |
| **ProofGate** | Code tất định đọc Evidence và ProofMarker → quyết định EXPLOITED hay FAILED |
| **Verifier Panel** | 3 LLM agent giám định độc lập, mặc định nghi ngờ, advisory |
| **BodyStore** | Content-addressed store: SHA-256 → bytes trên disk, lossless |
| **BodyRef** | Con trỏ tới body trong BodyStore (không copy bytes vào RAM) |
| **HttpExchange** | Một cặp request/response đầy đủ, có seq number và actor label |
| **StateGraph** | LangGraph construct: đồ thị node có hướng, state truyền qua TypedDict |
| **AuthDiff** | Cặp (anon_response, auth_response) cùng endpoint — signal BAC |
| **family_path** | Chuẩn hóa path về dạng tổng quát: `/orders/1` → `/orders/{id}` — dùng để dedup |
| **fingerprint** | Định danh target: host + hash(title + endpoint set) — dùng để same-target LTM |
| **technique_key** | (pattern_id, endpoint_role, field_name) — dùng để cross-target LTM dedup |

---

## 9. Kết quả thực nghiệm

### Lab benchmark: VulnShop (Flask + SQLite, port 5002)

10 planted bugs — xem `vulnshop/VULNS.md` để biết chi tiết từng bug.

### Tiến trình coverage

| Milestone | Score | Bottleneck vừa giải |
|-----------|-------|---------------------|
| Baseline (cold-start) | 2/9 | Crawler chỉ thấy HTML form, bỏ qua JS endpoints |
| Crawler fix (302 signal + JS extraction) | 4/16 endpoints → 4/7 | Tìm thêm /wallet/transfer, /cart/add |
| Tier 1 — body encoding | 4/7 | JSON API không còn trả 404 vì wrong content-type |
| Tier 1+2+3 + gate fixes | 5/7 | Coupon chain chạy đúng end-to-end |
| LTM redesign | Cold-start xác nhận memory có giá trị | Memory leak cross-target đã fix |
| Probe paths + product_prices | 5/11 | Coupon reuse EXPLOITED với giá đúng |
| Soft-404 JSON exemption | **5/10 planted (5/12 candidates)** | IDOR endpoints được discover |

### Run 3 — chi tiết (2026-06-10, workspace `localhost_20260610_131330`)

Recon tìm được 20 endpoints.

```
marl3 ID  │ Pattern  │ Endpoint                      │ Planted bug          │ Kết quả
──────────┼──────────┼───────────────────────────────┼──────────────────────┼──────────────
BUG-002   │ BAC-02   │ GET /admin                    │ Cookie tamper        │ EXPLOITED ✓
BUG-001   │ BAC-01   │ GET /api/v1/users             │ PII dump anonymous   │ EXPLOITED ✓
BUG-004   │ BLF-01   │ POST /wallet/transfer         │ Negative amount      │ EXPLOITED ✓
BUG-003   │ BLF-05   │ POST /coupon/apply            │ Coupon reuse chain   │ EXPLOITED ✓
BUG-005   │ BLF-06   │ POST /cart/add                │ Negative qty         │ EXPLOITED ✓
BUG-006   │ BAC-03   │ GET /api/v1/orders/{id}       │ IDOR orders          │ NOT_EXPLOITED ✗
BUG-012   │ BAC-01   │ GET /api/v1/profile/{id}      │ IDOR profile         │ NOT_EXPLOITED ✗
──────────┴──────────┴───────────────────────────────┴──────────────────────┴──────────────
False candidates (hunter sai hypothesis — NOT_EXPLOITED là đúng):
  /api/v1/products, /api/v1/me, /profile, /orders, /api/v1/orders
```

**Zero false positives** qua tất cả các run — gate không bao giờ promote bug không có evidence thật.

### Root cause của IDOR fail (bottleneck còn lại)

Exec chỉ có một session (`dangnosuy`). IDOR cần **multi-actor**: đăng nhập như `alice`, dùng session `alice` để truy cập order của `dangnosuy`. Cần primitive `create_session(url, user, pass) → session_label` để Exec có thể quản lý nhiều identity cùng lúc — chưa implement.

---

## 10. Cài đặt & Chạy

### Yêu cầu

- Python ≥ 3.11
- LLM endpoint OpenAI-compatible (mặc định `http://localhost:20128/v1`)
- Docker (để chạy VulnShop lab)

### Cài đặt

```bash
cd marl3/
pip install -e .
# hoặc: uv pip install -e .
```

### Chạy scan

```bash
marl3 run "http://TARGET user:USERNAME pass:PASSWORD"

# Ví dụ với VulnShop:
marl3 run "http://localhost:5002 user:dangnosuy pass:Dang@123"

# Output tại:
# workspace/localhost_YYYYMMDD_HHMMSS/report.md       ← human-readable
# workspace/localhost_YYYYMMDD_HHMMSS/findings.json   ← machine-readable
# workspace/localhost_YYYYMMDD_HHMMSS/pocs/           ← PoC per bug
```

### Dựng VulnShop lab

```bash
cd ../vulnshop/
docker compose down -v && docker compose up -d
# Đăng ký tài khoản test qua form tại http://localhost:5002/register
# Có sẵn: alice/Alice@123, bob/Bob@123, admin/Admin@123
```

### Cấu hình

File: `config/default.yaml`

| Key | Default | Ý nghĩa |
|-----|---------|---------|
| `llm.base_url` | `http://localhost:20128/v1` | LLM proxy endpoint |
| `llm.models.hunter` | `minimax-m2.5:cloud` | Model cho Hunter |
| `llm.models.exec` | `minimax-m2.5:cloud` | Model cho Exec |
| `debate.max_rounds` | `3` | Vòng Red↔Blue tối đa |
| `debate.max_verify_retries` | `1` | Retry sau PROOF_QUALITY_FAIL |
| `debate.per_bug_wall_clock_s` | `600` | Timeout 10 phút per bug |
| `recon.max_pages` | `60` | Số trang crawl tối đa |
| `memory.longterm_enabled` | `true` | Bật/tắt long-term memory |

---

## 11. Điểm tồn đọng & TODO

### HIGH — ảnh hưởng coverage trực tiếp

#### T2a: Multi-actor session (BLOCKER cho IDOR)

**Vấn đề:** Exec chỉ có 1 session. IDOR cần chạy với 2 actor khác nhau đồng thời.

**Fix cần thiết:**
- `tool_bridge.py`: thêm tool `create_session(url, username, password) → actor_label`
- `recorder.py`: `RecordingHttpClient` quản lý nhiều session song song
- `exec_system.md`: thêm pattern "IDOR Testing: (1) create_session(alice) → (2) http_request GET /api/v1/orders/{victim_order_id} actor=alice → 200 with victim data = IDOR proven"

#### T1: Client-side price injection

**Vấn đề:** `POST /cart/add` có hidden field `unit_price` không xuất hiện trong JS. Cần parameter fuzzing.

**Fix:** Thêm BLF variant trong `candidates.py` — thử inject `unit_price`, `price`, `override_price` vào mọi POST có numeric field.

#### T3: Promote privilege (BAC-06 gate)

**Vấn đề:** Gate BAC-06 hiện cần "admin title" — nhưng `/api/v1/users/{id}/promote` không có title.

**Fix:** Thêm rule "endpoint bị block với role X, 2xx với role Y → BAC-06 proven" vào `proof/bac.py`.

### MEDIUM

| ID | Mô tả | File |
|----|-------|------|
| T6 | Hunter noise: DELETE trên owned resource bị label IDOR sai | `recon/candidates.py` |
| T7 | IDOR gate cần `/api/v1/me` để lấy `attacker_user_id` | `execution/proof/bac.py` |
| T4 | Discover refund endpoint (`/api/v1/orders/{id}/refund`) | `recon/crawler.py` probe paths |

### LOW (deferred)

| ID | Mô tả |
|----|-------|
| T8 | Tier 4: Hunter pattern classification tighter |
| T9 | Tier 5: Happy-path capture — chạy primary flow để auto-seed known values |
| T10 | REST sibling inference: từ `/api/v1/users` tự infer `/api/v1/products`, etc. |

---

## Câu chốt cho slide

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│   CODE điều phối luồng        →  ổn định, tái lập được             │
│   LLM hiểu ngữ cảnh từng ô   →  xử lý được BAC + BLF              │
│   CODE phán kết quả cuối      →  không false positive từ gate      │
│                                                                     │
│   Pipeline = máy trạng thái (LangGraph) điều phối                  │
│   AI = fact-extractor và planner, không phải arbitrator             │
│   Gate = code đọc HTTP data thật, không phải AI bỏ phiếu           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```
