# LLM Context Probe Guide

Mục tiêu của bước này là kiểm chứng bằng model thật rằng evidence từ crawl/graph/risk-bug đã đi vào prompt của các agent, trước khi chạy pipeline exploit đầy đủ.

Probe này không gọi Exec exploit và không gửi request khai thác tới target. Nó chỉ gọi các đường LLM:

- VulnHunter: đọc `recon.md` + `crawl_raw.json` và sinh candidate trong bộ nhớ.
- Red: nhận bug dossier đã enrich và viết strategy.
- Blue: nhận cùng bug dossier + strategy của Red để review.
- Manager: nhận bug dossier + Red strategy và quyết định routing tiếp theo.

## Chuẩn bị

1. Đảm bảo `.env` hiện tại trỏ đúng model/server:

```bash
rtk python - <<'PY'
import os
from dotenv import load_dotenv
load_dotenv('.env')
for key in ('MARL_SERVER_URL', 'MARL_VULNHUNTER_MODEL', 'MARL_RED_MODEL', 'MARL_BLUE_MODEL', 'MARL_MANAGER_MODEL'):
    print(f'{key}={os.getenv(key, "")}')
PY
```

Không in API key hoặc token ra terminal.

2. Chọn workspace đã có đủ artifact:

```text
workspace/<run>/
  recon.md
  crawl_raw.json
  crawl_data.txt
  risk-bug.json
  auth_context.json
```

Ví dụ hiện tại:

```text
workspace/localhost_20260530_165408
```

## Chạy probe nhanh

Chỉ kiểm tra Red/Blue/Manager cho một bug cụ thể:

```bash
rtk python tools/context_llm_probe.py \
  --workspace workspace/localhost_20260530_165408 \
  --bug-id BUG-001 \
  --agents red,blue,manager
```

Script sẽ copy workspace sang temp, enrich `risk-bug.json` trong bản copy, gọi model, rồi ghi report vào:

```text
reports/context_llm_probe_<timestamp>_BUG-001.md
```

## Chạy probe đầy đủ gồm VulnHunter

```bash
rtk python tools/context_llm_probe.py \
  --workspace workspace/localhost_20260530_165408 \
  --bug-id BUG-001 \
  --agents all
```

`--agents all` tương đương:

```text
vulnhunter,red,blue,manager
```

Lưu ý: VulnHunter gọi model với full `recon.md`, nên chậm hơn Red/Blue/Manager.

## Giữ workspace temp để debug

```bash
rtk python tools/context_llm_probe.py \
  --workspace workspace/localhost_20260530_165408 \
  --bug-id BUG-001 \
  --agents red,blue,manager \
  --keep-temp
```

Report sẽ ghi đường dẫn temp copy. Dùng nó để xem `risk-bug.json` sau enrichment mà không làm bẩn workspace gốc.

## Đọc kết quả

Trong report, mỗi agent có phần `Score`:

```json
{
  "passed": true,
  "checks": {
    "mentions_bug_id": true,
    "mentions_endpoint_family": true,
    "mentions_observed_path": true,
    "uses_graph_or_business_context": true,
    "mentions_evidence_rule": true,
    "does_not_ask_for_missing_context": true
  }
}
```

Diễn giải:

- `mentions_endpoint_family`: model nhắc đúng endpoint family, ví dụ `/api/BasketItems`.
- `mentions_observed_path`: model dùng path quan sát được, ví dụ `/api/BasketItems/11`.
- `uses_graph_or_business_context`: model có dùng graph/business-chain, ví dụ `basket_update_quantity`.
- `does_not_ask_for_missing_context`: model không còn nói thiếu `http_examples`/`NEEDS_CONTEXT`.

PASS ở bước này chỉ chứng minh evidence đã vào prompt và model có dùng nó. Nó không chứng minh bug khai thác được.

## Kỳ vọng sau các sửa đổi context

Với `BUG-001`, report tốt nên thể hiện:

- Red viết strategy dựa trên `PUT /api/BasketItems/11`, `BasketId`, `quantity`.
- Blue review strategy dựa trên logic ownership/cross-basket, không reject vì thiếu request shape.
- Manager action thường nên là `DEBATE_BLUE` sau khi Red đưa strategy hợp lệ.
- VulnHunter nếu được gọi nên sinh candidate có `http_examples > 0`, `candidate_type`/`evidence_status` rõ ràng.

## Khi report fail

Nếu `mentions_observed_path=false`, kiểm tra:

- `risk-bug.json` sau enrichment có `http_examples[].request` không.
- `http_examples[].path` có đúng path thực tế không.
- `shared/bug_dossier.py` có attach `graph_context` cho endpoint đó không.

Nếu `uses_graph_or_business_context=false`, kiểm tra:

- `crawl_raw.json` có `workflow_graph`, `business_chain`, `api_hints` không.
- Endpoint trong bug có match với node/edge trong graph không.

Nếu Blue vẫn reject vì thiếu dữ liệu:

- Mở phần Blue response trong report.
- Nếu Blue đòi thứ Exec mới cần chứng minh, chỉnh prompt Blue để chỉ review logic strategy, không đòi proof hậu khai thác.

