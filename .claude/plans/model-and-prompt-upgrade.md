# Plan: Đổi model + Tổng quát hóa prompt cho MARL

## Tóm tắt vấn đề

1. **ExecAgent (gemini-2.5-pro)** và **CrawlAgent (gemini-2.5-pro)** quá "thông minh" — tự suy diễn, bịa kết quả ("Congratulations") thay vì report raw data
2. **Prompt hiện tại** gán cứng BAC/BLF — không cover được pentest thực tế rộng hơn
3. **Checklist** `business_logic_advanced.md` có test cases cực kỳ chi tiết (P-01→P-15, N-01→N-15, race condition, workflow skip) mà playbook hiện tại thiếu

## Chiến lược: 2 mảng thay đổi

### MẢNG A: Đổi model — "culi nên ngu vừa phải"

**File: `.env`**
```
MARL_EXECUTOR_MODEL=gpt-4o-2024-11-20    # Exec: culi, không thinking
MARL_CRAWL_MODEL=gpt-4o-2024-11-20       # Crawl: culi, không thinking
MARL_RED_MODEL=gpt-5-mini                # Giữ nguyên — Red cần suy luận
MARL_BLUE_MODEL=gpt-5-mini               # Giữ nguyên — Blue cần phản biện
```

**Lý do:**
- `gpt-4o-2024-11-20`: tool calling tốt, nhanh, không có extended thinking → ít hallucinate
- Red/Blue giữ `gpt-5-mini` vì vai trò chiến lược cần suy luận sâu hơn
- Chỉ đổi .env, không cần sửa code (đã dùng os.getenv)

### MẢNG B: Tổng quát hóa prompt — từ "BAC/BLF only" → "Business Logic + Access Control rộng"

#### B1. Nâng cấp Knowledge Base (`knowledge/bac_blf_playbook.py`)

**Hiện tại có:** BAC-01→07, BLF-01→06 (13 patterns, khái quát)

**Bổ sung từ checklist của bạn:**
- **BLF-07: Numeric Manipulation** — Bảng test N-01→N-15 (integer overflow, float precision, negative, zero, MAX_INT, scientific notation, unicode digits...)
- **BLF-08: Race Condition / TOCTOU** — Parallel requests, double-spend, coupon reuse. Kèm kỹ thuật: batch 20 request đồng thời
- **BLF-09: Workflow State Bypass** — Skip step (jump từ step 1 → step 4), replay step, out-of-order, direct state mutation (`PATCH /user {"status":"active"}`)

Mỗi pattern mới sẽ giữ đúng format hiện tại (`id`, `name`, `indicators`, `technique`, `variations`, `success`, `severity`) để Red/Blue không cần sửa cách đọc.

#### B2. Tổng quát hóa system prompts

**Nguyên tắc:** Prompt không nói "chỉ BAC/BLF" mà nói "Business Logic & Access Control vulnerabilities" — vẫn là cùng scope nhưng ngôn ngữ mở hơn, không giới hạn model chỉ nghĩ đến 6 pattern cũ.

**Các file cần sửa prompt:**

1. **`agents/exec_agent.py`** — WORKFLOW_SYSTEM_PROMPT:
   - Thêm quy tắc chống hallucination cứng: `"KHONG BAO GIO tu ket luan 'thanh cong' hoac 'Congratulations'. Chi report NGUYEN VAN noi dung response."`
   - Thêm: `"Neu response KHONG chua CHINH XAC chuoi text duoc expect → Status: FAIL"`
   - Bỏ mention "BAC/BLF" cứng → thay bằng "security testing"

2. **`agents/exec_agent.py`** — ANSWER_SYSTEM_PROMPT:
   - Tương tự: mở rộng scope description
   - Giữ nguyên rule "report RAW facts"

3. **`agents/exec_agent.py`** — VERIFY_SYSTEM_PROMPT:
   - Thêm: `"Copy-paste CHINH XAC text tu page. KHONG tom tat. KHONG suy dien."`

4. **`agents/crawl_agent.py`** — RECON_SYSTEM_PROMPT:
   - Mở rộng BLF scope: thêm numeric manipulation, race condition, workflow state
   - Mở rộng BAC scope: thêm multi-step auth bypass, referer-based, method override
   - Giữ OUT OF SCOPE (XSS, SQLi, SSRF, headers)

5. **`agents/red_team.py`** — RED_PROMPT:
   - Thay "chuyen BAC va BLF" → "chuyen Business Logic & Access Control"
   - Giữ nguyên structure (quy trình phân tích, format chiến lược)

6. **`agents/blue_team.py`** — Sửa prompt tương ứng

#### B3. Anti-hallucination layer cho ExecAgent

Thêm vào WORKFLOW_SYSTEM_PROMPT:
```
=== CHONG AO TUONG (CRITICAL) ===
- KHONG BAO GIO viet "Congratulations", "lab solved", "exploit thanh cong"
  TRU KHI chinh xac chuoi do XUAT HIEN trong HTTP response body.
- Khi report Result: PHAI copy NGUYEN VAN tu response (cat -n, hoac page text).
  Gioi han 200 ky tu dau cua response body.
- Neu khong chac chan → Status: INCONCLUSIVE (khong phai SUCCESS).
- TIEU CHI SUCCESS: response body CHUA CHINH XAC expect string.
  302 redirect KHONG PHAI la success — phai follow redirect va doc final page.
```

## Danh sách file thay đổi

| # | File | Thay đổi |
|---|------|----------|
| 1 | `.env` | Đổi EXECUTOR + CRAWL model → `gpt-4o-2024-11-20` |
| 2 | `knowledge/bac_blf_playbook.py` | Thêm BLF-07, BLF-08, BLF-09 từ checklist |
| 3 | `agents/exec_agent.py` | Sửa 4 system prompts (tổng quát + anti-hallucination) |
| 4 | `agents/crawl_agent.py` | Sửa RECON_SYSTEM_PROMPT (mở rộng scope) |
| 5 | `agents/red_team.py` | Sửa RED_PROMPT (tổng quát hóa language) |
| 6 | `agents/blue_team.py` | Sửa prompt tương ứng |

## Không thay đổi

- `main.py` — flow/pipeline giữ nguyên
- `server/server.py` — proxy không đổi
- `tools/crawler.py` — crawler tool không đổi
- `shared/utils.py` — tag system không đổi
- Cấu trúc thư mục — không đổi

## Thứ tự thực hiện

1. `.env` (đổi model — 30 giây)
2. `knowledge/bac_blf_playbook.py` (thêm 3 patterns — cần cẩn thận giữ format)
3. `agents/exec_agent.py` (sửa prompt — quan trọng nhất, anti-hallucination)
4. `agents/crawl_agent.py` (mở rộng recon prompt)
5. `agents/red_team.py` (tổng quát hóa)
6. `agents/blue_team.py` (tổng quát hóa tương ứng)
