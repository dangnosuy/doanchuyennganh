# MARL — Hướng dẫn chạy pipeline mới (Per-Bug Flow)

## Chạy nhanh

```bash
# Không có credentials (anon crawl + VulnHunter → risk-bug.json → per-bug debate)
python main.py "http://localhost:5001/"

# Với credentials (authenticated crawl)
python main.py "http://localhost:5001/ credentials: admin:password"

# Với credentials nhiều tài khoản
python main.py "http://target.com credentials: user1:pass1 credentials: user2:pass2"

# Target từ xa
python main.py "https://example.com/ credentials: admin:secret123"
```

## Pipeline mới (Per-Bug Flow)

```
Phase 1a: CrawlAgent    → crawl toàn bộ site (anonymous + authenticated)
Phase 1b: VulnHunterAgent → phân tích crawl data → risk-bug.json (vulnerability hypotheses)
Phase 2:  Per-bug debate  → Red → Blue → ExecAgent → ghi kết quả vào risk-bug.json
Phase 3:  Report          → đọc risk-bug.json → report.md
```

## Đầu ra

Sau khi chạy xong, trong `workspace/{domain}_{timestamp}/`:

| File | Nội dung |
|------|----------|
| `recon.md` | LLM phân tích crawl data |
| `risk-bug.json` | Danh sách bugs + trạng thái + PoC |
| `report.md` | Báo cáo cuối cùng |
| `marl.log` | Log đầy đủ của phiên |
| `crawl_data.txt` | Raw HTTP traffic |

## So sánh pipeline cũ vs mới

| | Pipeline cũ | Pipeline mới |
|---|---|---|
| Red strategy | Tất cả bugs 1 lần | Từng bug 1 lần |
| Blue review | CSRF, session, endpoint | Tư duy khai thác |
| Stop rule | Không có | 2 attempts → NOT_FOUND |
| Credential | Red tự tạo | Không tự tạo (OOS_SCOPE) |
| PoC | Tất cả execute cùng lúc | Từng bug ghi riêng |
| risk-bug.json | Không có | Core state file |

## Các file chính sửa cho pipeline mới

- `main.py` — thêm VulnHunter phase
- `agents/vuln_hunter_agent.py` — module nhận diện bug từ crawl data
- `agents/manage_agent.py` — per-bug flow, ghi kết quả vào risk-bug.json
- `agents/blue_team.py` — đánh giá tư duy Red (không phải methodology)
- `agents/red_team.py` — `set_current_bug()` để tập trung vào 1 bug
- `shared/utils.py` — `load_risk_bugs()`, `save_risk_bugs()`, `get_current_bug_text()`