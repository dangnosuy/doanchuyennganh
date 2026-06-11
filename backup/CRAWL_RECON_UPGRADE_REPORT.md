# Crawl Recon Upgrade Report

## Summary

Đã backup crawl cũ và thay `tools/crawler.py` bằng guided Playwright crawler có network capture, safe action exploration, và workflow graph. Flow chính của MARL vẫn giữ nguyên: `CrawlAgent` gọi crawler CLI, ghi `crawl_raw.json`, `crawl_data.txt`, render `recon.md`, rồi `VulnHunter` đọc recon để sinh `risk-bug.json`.

## Current Target: AI-Guided System Map

Mục tiêu tiếp theo của crawl stage không chỉ là endpoint discovery. Sau crawl, workspace phải có một bản đồ hệ thống web đủ dùng cho BAC/BLF:

- page/link graph và request graph;
- action inventory ở từng state/page;
- AI-selected actions có reason, selector, before/after state;
- request chains phát sinh sau từng action;
- `business_chain` có thứ tự thực tế, không chỉ link graph;
- `business_flows.json` map nhiều quy trình khác nhau từ crawl evidence.

Crawler hiện tại mới có guided deterministic actions và workflow graph; AI chưa trực tiếp điều hướng browser. Phần đang nâng cấp là thêm LLM action planner dùng model từ `.env` (`MARL_CRAWL_MODEL`, fallback `MARL_EXECUTOR_MODEL`) để chọn một số click/navigation đáng thử theo JSON contract và policy an toàn.

## Backup

- `backup/crawl_legacy_20260530/crawl_agent.py`
- `backup/crawl_legacy_20260530/crawler.py`

## Changes

- `tools/crawler.py`
  - Giữ tương thích CLI cũ: `--url`, `--max-pages`, `--timeout`, `--headless`, `--storage-state`, `-H Cookie: ...`.
  - Capture same-origin `document/xhr/fetch/form` traffic.
  - Bổ sung hướng nâng cấp: hybrid BFS/action inventory + LLM-guided planner, không thay thế network capture deterministic.
  - Bootstrap auth trước khi crawl bằng bearer/localStorage/sessionStorage, gồm `token`, `bid`, `email`.
  - Verify auth bằng `/rest/user/whoami` và `/rest/basket/{bid}` trước guided crawl.
  - Thêm guided safe routes: search, basket, profile, order-history, contact.
  - Thêm safe actions: dismiss overlay, open product, add-to-basket.
  - Thêm guided business API probe cho basket/order flow và capture JSON response keys/numeric/id fields.
  - Trích static JS API hints để làm cơ sở `ACTION_DISCOVERY`.
  - Sinh `observed_actions` và `workflow_graph` để hỗ trợ BAC/BLF chaining.

- `agents/crawl_agent.py`
  - `recon.md` giờ có section `Guided Workflow Graph`.
  - `recon.md` giờ có section `Guided Auth And API Hints`.
  - Recon phân biệt rõ endpoint inventory, workflow evidence, discovery probe, route family.

- `agents/vuln_hunter_agent.py`
  - Prompt được chỉnh để đọc `Guided Workflow Graph` như nguồn evidence hợp lệ.
  - Lọc endpoint lỗi crawl/auth-state như `/NaN`, `/undefined`, `/null`.
  - Bổ sung deterministic BAC/BLF seeds từ business chain, raw endpoints, và static API hints.
  - Ưu tiên method thật đã observe từ workflow graph, nhất là `POST/PUT/PATCH/DELETE`.
  - Candidate state-changing chưa observe trực tiếp vẫn phải đi theo `ACTION_DISCOVERY`.

## Testcases

- `test/test_guided_crawl_contract.py`
  - Test cookie injection contract.
  - Test workflow graph có request/action edges.
  - Test crawler CLI artifact contract.
  - Test recon render section `Guided Workflow Graph`.
  - Test VulnHunter match state-changing endpoint observed method.
  - Test VulnHunter action discovery grounding.
  - Test auth storage bootstrap có `sessionStorage.bid`.
  - Test VulnHunter filter endpoint `/NaN` và deterministic BasketItems seed.

Run:

```bash
rtk python -m unittest test.test_guided_crawl_contract
```

Verified: `11 tests OK`.
