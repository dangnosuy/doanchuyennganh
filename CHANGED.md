# CHANGED.md

Cap nhat ngay 2026-06-02 cho MARL recon/crawl pipeline.

## 1. Tom tat thay doi

Dot chinh sua nay chuyen crawler tu huong BFS/traffic capture don thuan sang **hybrid guided crawler**:

- Van giu Playwright crawl co kiem soat de lay pages, links, forms va HTTP traffic.
- Bo sung AI-guided action planner dung model trong `.env` de chon hanh dong dang crawl sau.
- Sinh them graph theo ngu canh business: `workflow_graph`, `action_candidates`, `ai_decisions`, `request_chains`, `business_chain`.
- Ket noi hanh dong nguoi dung voi request that: `action -> before_url -> emitted_requests -> after_url`.
- Tich hop du lieu `request_chains` vao `BusinessFlowMapper` de LLM suy luan business flow tu evidence da quan sat.
- Cap nhat `CrawlAgent` de render cac muc AI decisions/request chains/business chain vao recon output.
- Them contract tests cho crawler, request-chain projection, fallback policy va business flow mapping.

Muc tieu moi cua RECON khong con chi la "co danh sach endpoint", ma la co ban do:

```text
Page/Route -> User Action -> HTTP Requests -> State Change -> Business Flow
```

## 2. Kien truc hien tai

Pipeline chinh hien tai:

```text
main.py
  |
  |-- Phase 1: RECON
  |     |
  |     |-- CrawlAgent
  |     |     |-- tools/crawler.py
  |     |     |     |-- Playwright browser crawl
  |     |     |     |-- Safe deterministic exploration
  |     |     |     |-- AI-guided action planner
  |     |     |     |-- Network capture
  |     |     |     |-- Workflow graph builder
  |     |     |
  |     |     |-- writes crawl_raw.json / crawl_data.txt / recon.md
  |     |
  |     |-- BusinessFlowMapper
  |     |     |-- reads crawl_raw.json
  |     |     |-- uses request_chains + workflow_graph + traffic
  |     |     |-- writes business_flows.json
  |     |
  |     |-- VulnHunterAgent
  |           |-- reads recon + crawl data + business flows
  |           |-- writes risk-bug.json
  |
  |-- Phase 2: MANAGER / QUEUE
  |     |-- ManageAgent enriches bug candidates with graph_context/evidence_rules
  |
  |-- Phase 3: STRATEGY
  |     |-- RedTeamAgent proposes strategy
  |     |-- BlueTeamAgent reviews strategy
  |
  |-- Phase 4: EXECUTION
  |     |-- ExecAgent generates and verifies PoC
  |
  |-- Phase 5: REPORT
        |-- report.md / report_final_vi.md
```

## 3. Guided crawler moi

File chinh: `tools/crawler.py`.

Crawler moi tao `GuidedState` gom:

- `pages`: cac page/route da thay.
- `http_traffic`: request/response cung origin, gom method, status, body snippet, JSON keys.
- `observed_actions`: hanh dong deterministic da thuc hien.
- `action_candidates`: cac hanh dong ma AI duoc phep chon.
- `ai_decisions`: quyet dinh cua model trong tung step.
- `request_chains`: chuoi hanh dong -> request -> state sau hanh dong.
- `workflow_graph`: nodes/edges cho page, endpoint, request, action va request chain.
- `business_chain`: cac buoc business co evidence tu request/route.
- `api_hints`: endpoint hint trich tu static JS.
- `auth_bootstrap`: thong tin replay auth/session neu co.

AI planner khong duoc click tuy y. No chi duoc chon trong danh sach candidate da duoc crawler tao san va da loc policy.

Vi du request chain:

```json
{
  "action_id": "A02",
  "action_type": "click",
  "label": "Add to Basket",
  "before_endpoint": "/#/",
  "after_endpoint": "/#/",
  "effect": "request_or_navigation",
  "emitted_requests": [
    {
      "method": "GET",
      "endpoint": "/api/Products/1?d=Tue%20Jun%2002%202026",
      "status": 200
    }
  ]
}
```

## 4. Cau hinh `.env`

Crawler doc model tu `.env`:

```env
MARL_SERVER_URL=http://127.0.0.1:5000/v1
MARL_CRAWL_MODEL=ollama/minimax-m2.5:cloud

# Neu khong set MARL_CRAWL_MODEL, crawler fallback theo thu tu:
# MARL_EXECUTOR_MODEL -> MARL_MANAGER_MODEL

GITHUB_TOKEN=...
# hoac OPENAI_API_KEY=...

MARL_CRAWL_AI_GUIDED=true
MARL_CRAWL_AI_STEPS=4
```

Bien quan trong:

| Bien | Y nghia |
|---|---|
| `MARL_SERVER_URL` | OpenAI-compatible server endpoint |
| `MARL_CRAWL_MODEL` | Model dung rieng cho AI-guided crawler |
| `MARL_CRAWL_AI_GUIDED` | Bat/tat AI-guided crawl |
| `MARL_CRAWL_AI_STEPS` | So step toi da model duoc chon action |
| `GITHUB_TOKEN` / `OPENAI_API_KEY` | API key cho OpenAI-compatible client |

## 5. Cach su dung moi

Chay crawler truc tiep:

```bash
python tools/crawler.py \
  --url http://localhost:3000 \
  --max-pages 8 \
  --max-rounds 1 \
  --timeout 45 \
  --headless \
  --ai-steps 4
```

Tat AI-guided de so baseline:

```bash
python tools/crawler.py \
  --url http://localhost:3000 \
  --max-pages 8 \
  --max-rounds 1 \
  --timeout 45 \
  --headless \
  --no-ai-guided
```

Chay CrawlAgent:

```bash
python agents/crawl_agent.py "http://localhost:3000"
```

Chay full pipeline:

```bash
python main.py "Test http://localhost:3000"
```

Neu target can auth, truyen credential theo prompt hien co cua project:

```bash
python main.py "Test http://localhost:3000 user:admin pass:secret"
```

## 6. Output moi can xem

Trong `workspace/<target>_<timestamp>/`:

| File | Noi dung |
|---|---|
| `crawl_raw.json` | Du lieu raw cua guided crawl, graph, AI decisions, request chains |
| `crawl_data.txt` | Traffic text da flatten cho agent/doc cu |
| `recon.md` | Recon report co them guided workflow graph va AI-guided sections |
| `business_flows.json` | Business flows suy luan tu crawl evidence |
| `risk-bug.json` | Hang doi bug candidates cho ManageAgent |
| `report.md` / `report_final_vi.md` | Bao cao cuoi |

Cac truong moi trong `crawl_raw.json` nen uu tien kiem tra:

```text
ai_guidance
ai_decisions
action_candidates
request_chains
business_chain
workflow_graph.nodes
workflow_graph.edges
api_hints
auth_bootstrap
```

## 7. Ket qua test da chay

Da chay contract suite lien quan:

```bash
python -m unittest \
  test.test_guided_crawl_contract \
  test.test_business_flow_mapper \
  test.test_context_dossier
```

Ket qua:

```text
Ran 48 tests in 2.147s
OK
```

Da smoke test tren `http://localhost:3000`:

```text
Baseline khong AI:
- pages: 8
- traffic: 50
- workflow graph: 51 nodes / 80 edges
- request_chains: 0

AI-guided:
- pages: 8
- traffic: 51
- workflow graph: 51 nodes / 80 edges
- ai_decisions: 3
- request_chains: 3
- business_chain: 5
```

Ket luan smoke test:

- BFS/khong AI co map page/API nhung khong co `request_chains`.
- AI-guided da noi duoc hanh dong nhu `Add to Basket` va `Basket` voi request that.
- Controller da danh dau/noi chan no-op action bang `effect=no_effect` va dung AI loop som hon.

## 8. Gioi han hien tai

Phan moi da dung huong nhung chua phai crawler business-intelligence hoan chinh.

Cac gioi han con lai:

- Model co luc tra JSON rong hoac malformed, nen crawler co fallback/controller.
- Toc do crawl phu thuoc nhieu vao model planner.
- Planner hien moi chon trong candidate click/navigation/form da trich xuat; chua co form-filling semantic sau.
- Chua co memory workflow dai han de lap ke hoach nhieu nhanh phuc tap.
- Chua verify het moi loai web app co business logic nhieu buoc nhu checkout, transfer, approval, coupon, refund.

Huong tiep theo nen lam:

- Ep model output bang structured output neu backend ho tro.
- Them planner timeout/rate telemetry.
- Them state memory de tranh lap route/action.
- Mo rong form planning co data an toan.
- Them evaluator rieng cham diem coverage cua graph sau crawl.

## 9. Files chinh da thay doi

- `tools/crawler.py`: hybrid guided crawler, AI planner, request chains, workflow graph.
- `agents/crawl_agent.py`: render AI decisions/request chains/business chain vao recon text.
- `shared/business_flow_mapper.py`: doc them `request_chains` va guided graph context.
- `test/test_guided_crawl_contract.py`: contract tests cho crawler moi.
- `ARCHITECTURE.md`: kien truc tong quan moi.
- `CRAWL_RECON_UPGRADE_REPORT.md`: muc tieu AI-guided system map.
- `CLAUDE.md`: cap nhat developer guide.
- `description.md`: cap nhat huong crawl/graph/business flow.

