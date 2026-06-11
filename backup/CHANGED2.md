# CHANGED2.md

## 1. Muc tieu thay doi

Doc phan `Gioi han hien tai` trong `CHANGED.md` va implement cac huong cai tien co the lam ngay trong codebase hien tai.

Trong cac gioi han duoc neu, dot nay tap trung vao:

- Them state memory de crawler tranh lap route/action.
- Them evaluator rieng de cham diem coverage cua workflow graph sau crawl.
- Dua thong tin coverage/memory vao recon va business-flow analysis de downstream agents co context ro hon.

## 2. Cac thay doi chinh

### 2.1. Them crawl state memory

File: `tools/crawler.py`

Da them `CrawlMemory` vao `GuidedState`, gom cac thong tin:

- `visited_endpoints`: endpoint da thay.
- `tried_actions`: action identity da thu.
- `no_effect_actions`: action da thu nhung khong tao request va khong doi URL.
- `state_changing_endpoints`: endpoint co method `POST`, `PUT`, `PATCH`, `DELETE`.
- `covered_surfaces`: nhom surface da cover theo BAC/BLF.
- `repeated_endpoint_hits`: endpoint bi lap lai nhieu lan.

Memory duoc cap nhat khi:

- Capture page.
- Capture network request.
- Append request chain sau AI-guided action.
- Action duoc danh dau la no-effect.

### 2.2. Planner va fallback selection co memory-awareness

File: `tools/crawler.py`

Da cap nhat AI planner prompt de nhan them:

- `crawl_memory`
- `coverage_gaps`
- `memory_seen`
- `memory_surfaces`

Fallback candidate scoring bay gio:

- Tru diem action da thu.
- Tru diem action no-effect.
- Tru diem endpoint bi lap lai nhieu.
- Cong diem endpoint moi.
- Cong diem action cover surface con thieu.

Muc tieu la crawler it bi vong lap hon va uu tien cac route/action co gia tri cho BAC/BLF nhu admin, profile/account, cart/order/checkout, coupon/discount, transfer/balance.

### 2.3. Them graph coverage evaluator

File: `tools/crawler.py`

Da them `_evaluate_graph_coverage(...)` de cham diem workflow graph sau crawl.

Evaluator tinh:

- `score`: diem coverage 0-100.
- `node_count`, `edge_count`.
- `covered_surface_count`.
- Coverage theo nhom:
  - `access_control`
  - `commerce`
  - `value_logic`
  - `workflow_state`
- So edge state-changing.
- So request-chain edge.
- So form edge.
- Dead-end pages.
- Recommendations cho lan crawl/analysis tiep theo.

Crawler output bay gio co them:

- `crawl_memory`
- `graph_coverage`

Neu Playwright bi thieu, output fallback cung giu contract voi hai field nay.

### 2.4. Render coverage vao recon

File: `agents/crawl_agent.py`

Da them section:

```markdown
## Crawl Graph Coverage Evaluation
```

Section nay hien thi:

- Context anonymous/authenticated.
- Coverage score.
- Nodes/edges.
- Surfaces covered.
- State-changing edge count.
- Request-chain count.
- Coverage gaps.
- Follow-up recommendations.
- Endpoint bi lap lai can de-prioritize.

Ngoai ra `_format_crawl_data(...)` cung them `## Crawl Graph Coverage` de LLM recon co evidence truc tiep trong `crawl_data.txt`.

### 2.5. Dua coverage vao BusinessFlowMapper

File: `shared/business_flow_mapper.py`

Da them `graph_coverage` va `crawl_memory` vao compact payload.

Prompt text cho flow mapper bay gio co them block:

```text
GRAPH COVERAGE
```

Muc dich:

- Flow mapper biet phan nao cua graph manh/yeu.
- Giam suy luan qua muc khi graph coverage thap.
- Giu recommendations lam context cho viec lap flow va vulnerable steps.

## 3. Tests da them

File: `test/test_guided_crawl_contract.py`

Da them cac test:

- `test_memory_aware_fallback_prefers_uncovered_surface`
  - Dam bao fallback uu tien surface chua cover thay vi action da thu/lap lai.

- `test_graph_coverage_evaluator_reports_business_gaps`
  - Dam bao evaluator detect commerce coverage va bao gap access_control.

- `test_recon_renders_graph_coverage`
  - Dam bao recon render duoc section coverage va repeated endpoint hints.

## 4. Verification

Da chay:

```bash
python -m unittest test.test_guided_crawl_contract
```

Ket qua:

```text
Ran 23 tests
OK (skipped=1)
```

Da chay:

```bash
python -m unittest discover -s test
```

Ket qua:

```text
Ran 51 tests
OK (skipped=1)
```

## 5. Files da thay doi

- `tools/crawler.py`
  - Them `CrawlMemory`.
  - Them memory update helpers.
  - Them memory-aware fallback/planner context.
  - Them graph coverage evaluator.
  - Them `crawl_memory` va `graph_coverage` vao crawl output.

- `agents/crawl_agent.py`
  - Render `Crawl Graph Coverage Evaluation` vao recon.
  - Them graph coverage vao formatted crawl data.

- `shared/business_flow_mapper.py`
  - Dua `graph_coverage` va `crawl_memory` vao compact payload.
  - Them graph coverage context vao LLM prompt text.

- `test/test_guided_crawl_contract.py`
  - Them contract tests cho memory, evaluator, recon rendering.

## 6. Tac dong ky thuat

Sau thay doi nay crawler co kha nang:

- Nho cac route/action da di qua trong mot crawl session.
- Giam viec chon lai action da khong co effect.
- Uu tien surface con thieu thay vi lap lai route quen thuoc.
- Tu danh gia workflow graph sau crawl.
- Bao cho downstream agents biet graph coverage con yeu o dau.

Day la buoc nen lam truoc khi mo rong semantic form filling hoac structured output backend, vi no tao nen nen tang deterministic de do chat luong crawl.
