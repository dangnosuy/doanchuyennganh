# Recon Discovery Strategy

Mục tiêu của recon là tóm tắt lại đúng những gì crawler đã quan sát hoặc đã probe, không tự suy diễn endpoint.

## 1. Normal Crawl

Normal crawl thu thập fact:

- pages/documents đã visit;
- XHR/fetch requests;
- forms, action, method, fields;
- cookies/client state;
- response status, headers, snippets;
- authenticated vs anonymous differences.

Endpoint chỉ được xem là observed nếu có request/response thật trong crawl traffic.

## 2. Bounded BAC/BLF Discovery

Sau normal crawl, chạy thêm một lớp discovery read-only:

- Methods allowed: `GET`, `OPTIONS`.
- Không gửi `POST`, `PUT`, `PATCH`, `DELETE`.
- Không thực hiện action thay đổi state.
- Candidate limit mặc định: 70 paths.
- Contexts:
  - anonymous;
  - authenticated user thường;
  - same authenticated session với identity cookie tamper nếu có `role`, `is_admin`, `user_id`, `account_id`.

Discovery output phải ghi provenance rõ:

- `bac_seed`
- `blf_seed`
- `observed_link_or_script`
- `html_or_js_bac_signal`
- `html_or_js_blf_signal`
- `focus_bac`
- `focus_blf`

Candidate chưa probe không phải endpoint evidence.

## 3. BAC Coverage

Probe các bề mặt:

- admin/management/dashboard/console/settings;
- users/accounts/roles;
- API variants như `/api/users`, `/api/v1/users`, `/api/admin/users`;
- internal/admin variants;
- client-visible identity cookies như `role=user`, `is_admin=false`, `user_id=5`.

Một BAC signal chỉ đáng dispatch khi có một trong các điều kiện:

- route tồn tại và bị protected/redirect có ý nghĩa;
- anonymous hoặc user thường đọc được admin/user/role data;
- tampered identity cookie tạo response khác baseline;
- JSON/HTML chứa identity/role/user-list/admin-only marker cụ thể.

Status 200 hoặc keyword `admin` đơn lẻ không đủ.

## 4. BLF Coverage

Probe các bề mặt:

- cart/basket;
- checkout/order/invoice;
- payment/transfer/wallet/balance;
- coupon/discount/promo;
- price/quantity/stock/status/refund/shipping.

Một BLF signal chỉ là candidate cho bước sau. Kết luận exploit cần before/after state hoặc response chứng minh workflow/value bị thao túng.

## 5. Recon.md Contract

`recon.md` chỉ được render từ artifacts:

- `crawl_raw.json["raw_endpoints"]`;
- `crawl_raw.json["discovery_probes"]`;
- auth context/fingerprint;
- structured route summaries từ traffic.

Không để LLM tự viết endpoint inventory.

Endpoint inventory chỉ chứa:

- `provenance=crawl`;
- hoặc `provenance=active_discovery` với `route_exists=true`.

HTML/CSS/JS marker chỉ được ghi là signal, không được nâng thành endpoint.
