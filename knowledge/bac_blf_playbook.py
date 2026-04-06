"""
BAC & BLF Attack Pattern Playbook — Knowledge Base cho Red/Blue Team.

Mỗi pattern gồm:
  - id:          Mã ngắn dùng trong chiến lược (VD: BAC-01)
  - name:        Tên kỹ thuật
  - indicators:  Dấu hiệu trong recon data → match pattern này
  - technique:   Các bước tấn công cụ thể
  - variations:  Biến thể / bypass khi cách chính thất bại
  - success:     Tiêu chí xác nhận exploit thành công
  - severity:    Mức độ (Critical / High / Medium)

Export:
  get_playbook_text(category=None) → str  — render toàn bộ hoặc 1 category
  BAC_PATTERNS  — list[dict]
  BLF_PATTERNS  — list[dict]
"""

from typing import Optional

# ═══════════════════════════════════════════════════════════════════════
# BAC — Broken Access Control Patterns
# ═══════════════════════════════════════════════════════════════════════

BAC_PATTERNS = [
    # ── BAC-01: Vertical Privilege Escalation — Unprotected Functionality ──
    {
        "id": "BAC-01",
        "name": "Unprotected Admin/Sensitive Functionality",
        "severity": "Critical",
        "indicators": [
            "robots.txt chứa đường dẫn admin/management",
            "JavaScript source tiết lộ URL ẩn (VD: adminPanelTag, isAdmin check)",
            "Sitemap.xml liệt kê endpoint không public",
            "Có endpoint /admin, /administrator, /management, /console, /dashboard "
            "nhưng không yêu cầu auth",
            "Response header tiết lộ framework có admin panel mặc định",
        ],
        "technique": [
            "1. Recon: kiểm tra robots.txt, sitemap.xml, JS bundles tìm hidden paths",
            "2. Thử truy cập trực tiếp các admin paths bằng tài khoản thường "
            "(hoặc không login)",
            "3. Nếu bị redirect → kiểm tra response body trước redirect "
            "(có thể leak nội dung)",
            "4. Thử path variations: /Admin, /ADMIN, /admin/, /admin/dashboard",
            "5. Kiểm tra JS source cho biến/hàm liên quan: "
            "isAdmin, adminPanel, role, privilege",
        ],
        "variations": [
            "Path case-sensitivity bypass: /Admin vs /admin (một số server phân biệt hoa thường)",
            "Trailing slash / double slash: /admin// hoặc /admin/./",
            "URL encoding: /%61dmin",
            "Thử thêm path prefix: /static/../admin, /api/../admin",
        ],
        "success": "Truy cập được giao diện/chức năng admin mà không cần role admin",
    },

    # ── BAC-02: Vertical Privilege Escalation — Parameter-Based ──
    {
        "id": "BAC-02",
        "name": "Parameter-Based Access Control",
        "severity": "Critical",
        "indicators": [
            "URL có tham số role/admin/access: ?role=user, ?admin=false, ?access=1",
            "Cookie chứa role indicator: isAdmin=false, role=user, access_level=1",
            "Hidden form field liên quan đến role/permission",
            "Request body JSON có trường role/privilege/admin",
            "Response trả về thông tin role trong body/cookie",
        ],
        "technique": [
            "1. Đăng nhập tài khoản thường, capture request/response đầy đủ",
            "2. Tìm tham số role trong: URL params, cookies, request body, "
            "hidden fields",
            "3. Thay đổi giá trị: role=admin, isAdmin=true, access_level=99, "
            "admin=1",
            "4. Gửi lại request với tham số đã sửa",
            "5. Kiểm tra response có thay đổi quyền / hiện thêm chức năng không",
        ],
        "variations": [
            "Thay đổi cookie: isAdmin=false → isAdmin=true",
            "Thêm tham số mới vào request: &admin=true, &role=administrator",
            "Đổi content-type và gửi JSON body thay vì form data",
            "Sửa JWT payload nếu không verify signature (alg:none attack)",
        ],
        "success": "Có quyền admin/elevated sau khi sửa tham số, "
        "có thể thực hiện hành động chỉ admin mới có",
    },

    # ── BAC-03: Horizontal Privilege Escalation — IDOR ──
    {
        "id": "BAC-03",
        "name": "IDOR — Insecure Direct Object Reference",
        "severity": "High",
        "indicators": [
            "URL chứa ID/username dùng để lấy data: /user?id=123, "
            "/profile/john, /account/456",
            "API endpoint dùng user ID trong path: /api/users/123/orders",
            "Request body chứa userId, accountId, customerId",
            "Response chứa data cá nhân của user hiện tại (gợi ý thử user khác)",
            "Predictable ID format: số nguyên tăng dần, username rõ ràng",
        ],
        "technique": [
            "1. Đăng nhập tài khoản A, capture request lấy data cá nhân",
            "2. Xác định tham số identify user: id, username, email, accountId",
            "3. Thay giá trị sang user B (VD: id=123 → id=124, "
            "username=wiener → username=carlos)",
            "4. So sánh response: có trả về data của user B không?",
            "5. Thử cả đọc (GET) và ghi (POST/PUT/DELETE)",
        ],
        "variations": [
            "Nếu ID là GUID → tìm cách leak GUID (qua comment, review, social feature)",
            "Horizontal → Vertical: xem data của admin user có thể leak password/token",
            "Mass assignment: gửi thêm field userId trong update profile request",
            "Thử ID = 0, 1, admin, root cho edge cases",
        ],
        "success": "Đọc/sửa/xóa được data của user khác mà không có quyền",
    },

    # ── BAC-04: Method-Based Access Control Bypass ──
    {
        "id": "BAC-04",
        "name": "HTTP Method-Based Access Control Bypass",
        "severity": "High",
        "indicators": [
            "Endpoint bị 403 với POST nhưng chưa test GET/PUT/PATCH/DELETE",
            "API framework dùng annotation-based routing (Spring, Django REST)",
            "Admin action chỉ chặn trên 1 method cụ thể",
            "Server hỗ trợ nhiều HTTP methods (kiểm tra OPTIONS response)",
        ],
        "technique": [
            "1. Gửi request admin action bằng POST → bị 403",
            "2. Thử lại bằng GET với params tương đương: "
            "GET /admin/delete?username=target",
            "3. Thử PUT, PATCH, DELETE",
            "4. Thử method override: X-HTTP-Method-Override: DELETE, "
            "X-HTTP-Method: PUT, _method=PUT trong body",
            "5. Thử POSTX, GETS (invalid method — một số WAF/framework bypass)",
        ],
        "variations": [
            "Header override: X-HTTP-Method-Override, X-Method-Override",
            "Query param override: ?_method=PUT",
            "Content-Type thay đổi: application/json vs application/x-www-form-urlencoded",
            "TRACE method có thể reflect sensitive headers",
        ],
        "success": "Thực hiện được admin action bằng HTTP method khác (không phải method bị chặn)",
    },

    # ── BAC-05: URL/Path-Based Access Control Bypass ──
    {
        "id": "BAC-05",
        "name": "URL Rewrite / Path Traversal Bypass",
        "severity": "High",
        "indicators": [
            "Server dùng reverse proxy (Nginx/Apache trước backend)",
            "Response header có X-Original-URL, X-Rewrite-URL",
            "Front-end access control dựa trên URL path",
            "Có sự khác biệt giữa proxy routing và backend routing",
        ],
        "technique": [
            "1. Truy cập /admin → bị 403",
            "2. Thử header bypass: X-Original-URL: /admin, "
            "X-Rewrite-URL: /admin/delete",
            "3. Request path /? với header X-Original-URL: /admin",
            "4. Thử path confusion: /admin%00, /admin%0d%0a, /./admin, "
            "//admin, /admin;",
            "5. Nếu API gateway: thử /api/v1/../admin, path traversal qua proxy",
        ],
        "variations": [
            "Header: X-Forwarded-For, X-Custom-IP-Authorization: 127.0.0.1",
            "Path normalization: /admin/. , /admin..;/ (Tomcat), "
            "/admin%252f (double encoding)",
            "Host header manipulation: Host: localhost",
            "Thêm port: Host: target.com:8443",
        ],
        "success": "Bypass access control trên proxy/front-end, "
        "truy cập endpoint admin qua backend",
    },

    # ── BAC-06: Multi-Step Process Missing Check ──
    {
        "id": "BAC-06",
        "name": "Multi-Step Process — Missing Access Control on Later Steps",
        "severity": "High",
        "indicators": [
            "Workflow nhiều bước: step1 (chọn action) → step2 (xác nhận) → step3 (thực thi)",
            "Step đầu check quyền nhưng step sau không re-check",
            "URL pattern có step/phase: ?step=2, /confirm, /execute",
            "Hidden form field chứa action đã chọn ở step trước",
        ],
        "technique": [
            "1. Dùng tài khoản admin thực hiện full workflow, capture tất cả requests",
            "2. Xác định request ở mỗi step (đặc biệt step cuối — thực thi action)",
            "3. Dùng tài khoản thường, skip các step đầu, "
            "gửi thẳng request step cuối",
            "4. Hoặc: làm step 1-2 bình thường, ở step cuối đổi "
            "target user/action",
            "5. Kiểm tra action có được thực thi với quyền thường không",
        ],
        "variations": [
            "Thay đổi Referer header (một số app check Referer thay vì session)",
            "Bỏ CSRF token ở step cuối (nếu app skip check khi không có token)",
            "Đổi thứ tự params / thêm params từ step khác",
        ],
        "success": "Thực hiện được privileged action bằng cách skip hoặc "
        "thao túng multi-step workflow",
    },

    # ── BAC-07: Referer-Based Access Control ──
    {
        "id": "BAC-07",
        "name": "Referer-Based Access Control",
        "severity": "Medium",
        "indicators": [
            "Endpoint admin trả 403 khi truy cập trực tiếp nhưng "
            "cho phép nếu có Referer từ trang admin khác",
            "Server check Referer header để xác thực source of navigation",
            "Admin sub-page accessible nếu Referer = admin main page",
        ],
        "technique": [
            "1. Truy cập /admin/delete-user → 403",
            "2. Thêm header Referer: https://target.com/admin và gửi lại",
            "3. Thử variations: Referer: /admin, "
            "Referer: https://target.com/admin/dashboard",
            "4. Kết hợp với method bypass nếu cần",
        ],
        "variations": [
            "Referer chứa keyword admin ở bất kỳ vị trí nào: "
            "?ref=admin, /page?from=admin",
            "Bỏ hoàn toàn Referer header (Referer: )",
            "Sửa Origin header thay vì Referer",
        ],
        "success": "Bypass access control bằng cách giả mạo Referer header",
    },

    # ── BAC-08: API Endpoint Mismatch ──
    {
        "id": "BAC-08",
        "name": "API Endpoint Discoverability & Version Mismatch",
        "severity": "High",
        "indicators": [
            "API có versioning: /api/v1/, /api/v2/ — version cũ có thể thiếu auth",
            "JS source tiết lộ API endpoint không document",
            "Có endpoint PATCH/PUT ngoài GET đã biết",
            "Mobile app dùng API khác web app (kiểm tra traffic mobile)",
            "Swagger/OpenAPI spec public",
        ],
        "technique": [
            "1. Enumerate API versions: /api/v1/users, /api/v2/users, /api/v3/users",
            "2. Tìm undocumented endpoints trong JS bundles / Swagger",
            "3. Thử PATCH /api/users/me với body thêm field: "
            '{\"role\":\"admin\", \"isAdmin\":true}',
            "4. Kiểm tra API endpoint không có auth header vẫn trả data",
            "5. So sánh auth requirements giữa các API versions",
        ],
        "variations": [
            "Mass assignment: gửi thêm fields không document trong update request",
            "Thay đổi response format: .json, .xml, .csv",
            "GraphQL introspection nếu có GraphQL endpoint",
            "Kiểm tra /internal/, /debug/, /test/ paths",
        ],
        "success": "Truy cập API endpoint không có auth / bypass auth "
        "qua version cũ hoặc undocumented path",
    },
]


# ═══════════════════════════════════════════════════════════════════════
# BLF — Business Logic Flaw Patterns
# ═══════════════════════════════════════════════════════════════════════

BLF_PATTERNS = [
    # ── BLF-01: Excessive Trust in Client-Side Controls ──
    {
        "id": "BLF-01",
        "name": "Client-Side Validation Bypass",
        "severity": "High",
        "indicators": [
            "Giá sản phẩm / số lượng / discount nằm trong hidden field hoặc request body",
            "JavaScript validate input trước khi gửi (client-side only)",
            "Form có hidden input với value quan trọng (price, role, discount_code)",
            "Request chứa tham số tính toán (total, subtotal, tax)",
            "Dropdown/select chỉ cho chọn giá trị nhất định nhưng "
            "backend không validate lại",
        ],
        "technique": [
            "1. Capture request khi thực hiện transaction (mua hàng, nạp tiền, etc.)",
            "2. Tìm tham số price/quantity/amount trong request body",
            "3. Sửa giá trị: price=0, price=-100, quantity=0, "
            "discount=100%",
            "4. Gửi request đã sửa, kiểm tra server có validate lại không",
            "5. Kiểm tra response + trạng thái đơn hàng / tài khoản",
        ],
        "variations": [
            "Giá âm để tăng credit: price=-1000",
            "Quantity cực lớn gây integer overflow: quantity=99999999",
            "Sửa currency: USD → VND (tỷ giá khác)",
            "Bỏ tham số validation (CSRF token, nonce) xem có skip check không",
        ],
        "success": "Server chấp nhận giá trị không hợp lệ từ client, "
        "thực hiện transaction sai logic",
    },

    # ── BLF-02: Failing to Handle Unconventional Input ──
    {
        "id": "BLF-02",
        "name": "Unconventional Input Handling",
        "severity": "High",
        "indicators": [
            "Input field có max length / min length trên client nhưng "
            "không rõ server-side",
            "Số lượng / giá có thể nhập số thập phân, số âm",
            "Form field có regex validation chỉ ở client",
            "Application xử lý chuỗi dài (truncation issues)",
            "Tham số numeric không rõ ràng về range",
        ],
        "technique": [
            "1. Thử input quá dài: email dài 300 ký tự, name dài 10000 ký tự",
            "2. Thử số âm: quantity=-1, amount=-500",
            "3. Thử số thập phân: quantity=1.5, amount=0.001",
            "4. Thử zero: quantity=0, price=0",
            "5. Thử giá trị đặc biệt: null, undefined, NaN, Infinity, "
            "empty string",
            "6. Thử data type mismatch: gửi string thay vì number, "
            "array thay vì string",
        ],
        "variations": [
            "Integer overflow: 2147483647 + 1, MAX_INT",
            "Precision issues: 0.1 + 0.2 ≠ 0.3",
            "Encoding tricks: Unicode equivalents, fullwidth numbers",
            "Null byte injection: param%00value",
        ],
        "success": "Server xử lý input bất thường → sai logic, "
        "gây lỗi business hoặc bypass validation",
    },

    # ── BLF-03: Making Flawed Assumptions About User Behavior ──
    {
        "id": "BLF-03",
        "name": "Workflow Sequence Manipulation",
        "severity": "High",
        "indicators": [
            "Multi-step process: checkout, registration, password reset",
            "Mỗi step có URL riêng: /checkout/step1, /checkout/step2",
            "Server assume user đi theo thứ tự",
            "Có thể skip step bằng truy cập URL trực tiếp",
        ],
        "technique": [
            "1. Thực hiện workflow bình thường, capture tất cả requests",
            "2. Bỏ qua bước validation: skip step 2, đến thẳng step 3",
            "3. Lặp lại step nhất định: apply coupon 2 lần, "
            "verify email nhiều lần",
            "4. Đảo thứ tự steps",
            "5. Thay đổi data giữa các steps (VD: đổi sản phẩm sau khi "
            "nhập coupon)",
        ],
        "variations": [
            "Race condition: gửi 2 request apply coupon đồng thời",
            "State manipulation: sửa session state giữa các step",
            "Remove required step: skip payment verification",
            "Repeat step: apply discount code nhiều lần",
        ],
        "success": "Bypass bước quan trọng hoặc lặp lại bước có lợi, "
        "vi phạm business logic flow",
    },

    # ── BLF-04: Domain-Specific Flaw ──
    {
        "id": "BLF-04",
        "name": "Domain-Specific Business Logic Flaw",
        "severity": "High",
        "indicators": [
            "Chức năng đặc thù: coupon/discount, loyalty points, transfer tiền",
            "Quy tắc business phức tạp (VD: free shipping trên $X, "
            "discount khi mua Y sản phẩm)",
            "Chức năng có điều kiện: giới hạn lần dùng, thời gian hiệu lực",
            "Transfer/exchange giữa các account",
        ],
        "technique": [
            "1. Hiểu rõ business rules: đọc Terms, FAQ, UI hints",
            "2. Tìm edge cases trong rules: "
            "free shipping + return = profit? coupon + gift card stack?",
            "3. Thử vượt quota/limit: apply coupon quá số lần cho phép",
            "4. Manipulate conditions: đạt điều kiện discount rồi "
            "bỏ item → giữ discount",
            "5. Self-transfer hoặc circular transactions",
        ],
        "variations": [
            "Gift card + coupon stacking",
            "Price rounding exploitation (mua 1.5 items, trả 1 item giá)",
            "Referral self-loop: tự refer chính mình",
            "Time-based: sửa timezone/date trong request",
        ],
        "success": "Lợi dụng logic business để đạt lợi thế không mong muốn "
        "(tiền, quyền, bypass quota)",
    },

    # ── BLF-05: Email/Verification Logic Flaws ──
    {
        "id": "BLF-05",
        "name": "Email & Verification Logic Bypass",
        "severity": "High",
        "indicators": [
            "Email verification flow: register → verify email → access",
            "Password reset qua email",
            "2FA implementation",
            "Email-based authentication (magic link)",
            "Domain-based access control (chỉ @company.com mới được)",
        ],
        "technique": [
            "1. Đăng ký → verify → đổi email sau verify (bypass domain check)",
            "2. Password reset: tạo link reset cho user A, "
            "dùng cho user B (đổi username/email trong request)",
            "3. 2FA bypass: skip step 2FA, truy cập thẳng authenticated page",
            "4. Rate limit brute force: thử tất cả OTP (4 digit = 10000 combos)",
            "5. Token reuse: dùng lại verification/reset token",
        ],
        "variations": [
            "Đổi Host header trong password reset → link reset trỏ tới attacker",
            "Email parameter pollution: email=victim@mail.com&email=attacker@mail.com",
            "Subdomain bypass: user@evil.company.com vs user@company.com",
            "Case manipulation: Admin@company.com vs admin@company.com",
        ],
        "success": "Bypass verification flow, chiếm quyền tài khoản khác, "
        "hoặc bypass email-based restrictions",
    },

    # ── BLF-06: Insufficient Workflow Validation ──
    {
        "id": "BLF-06",
        "name": "Insufficient Workflow Validation (State Tampering)",
        "severity": "Medium",
        "indicators": [
            "Form có nhiều submit button (approve/reject, buy/cancel)",
            "Request gửi action type trong body: action=approve, status=confirmed",
            "Workflow status lưu client-side hoặc trong URL",
            "Có thể thay đổi trạng thái object trực tiếp",
        ],
        "technique": [
            "1. Capture request khi thực hiện action hợp lệ",
            "2. Thay đổi action/status param: "
            "action=reject → action=approve, status=pending → status=approved",
            "3. Gửi request với role/permission thấp hơn yêu cầu",
            "4. Thay đổi object ID để approve/reject object khác",
            "5. Kiểm tra có audit trail ghi nhận thay đổi trái phép không",
        ],
        "variations": [
            "Bulk action: thay đổi nhiều object cùng lúc",
            "Race condition: approve + reject cùng lúc → xem xử lý nào thắng",
            "Partial update: chỉ gửi 1 field thay vì full object",
        ],
        "success": "Thay đổi trạng thái workflow mà không có quyền, "
        "skip approval process",
    },

    # ── BLF-07: Numeric / Parameter Manipulation ──
    {
        "id": "BLF-07",
        "name": "Numeric & Parameter Manipulation",
        "severity": "High",
        "indicators": [
            "Form có field số: quantity, amount, price, discount, points",
            "Giá trị số truyền qua hidden field hoặc POST body",
            "Trang có chức năng tính toán: tổng tiền, balance, transfer",
            "API nhận JSON với numeric fields",
        ],
        "technique": [
            "1. Capture request bình thường, ghi nhận tất cả numeric params",
            "2. Test từng param với bảng payload:",
            "   - Số âm: quantity=-1, amount=-100 (đảo chiều logic?)",
            "   - Zero: quantity=0, price=0 (bypass payment?)",
            "   - Overflow 32-bit: 2147483647, 2147483648 (wrap thành âm?)",
            "   - Overflow 64-bit: 9223372036854775807",
            "   - Float precision: 0.1+0.2, 99999999999999.99",
            "   - String thay number: quantity=\"abc\" (error leak?)",
            "   - Leading zeros: 000100 (octal interpretation?)",
            "   - Rất lớn: 99999999 (exceed stock/limit?)",
            "3. Với mỗi payload: so sánh response vs baseline bình thường",
            "4. Check server có validate không: total có recalculate từ server-side price?",
            "5. Nếu có discount/coupon: thử áp dụng nhiều lần, discount > 100%",
        ],
        "variations": [
            "JSON type confusion: {\"qty\": \"1\"} vs {\"qty\": 1} vs {\"qty\": [1]}",
            "Unicode digits: １００ (fullwidth) thay vì 100",
            "Scientific notation: 1e5 thay vì 100000",
            "Negative discount stacking: 2 coupon cùng lúc → price < 0 → credit?",
        ],
        "success": "Server chấp nhận giá trị bất thường, dẫn đến thanh toán sai, "
        "balance manipulation, hoặc bypass business rules",
    },

    # ── BLF-08: Race Condition / TOCTOU ──
    {
        "id": "BLF-08",
        "name": "Race Condition / Time-of-Check-Time-of-Use",
        "severity": "Critical",
        "indicators": [
            "Chức năng transfer tiền, redeem coupon, apply discount, vote",
            "Limit-based actions: 'use once', 'max 1 per user', quota",
            "Balance check rồi mới trừ (2 bước riêng, không atomic)",
            "Coupon/gift card chỉ dùng 1 lần",
        ],
        "technique": [
            "1. Xác định endpoint target (VD: POST /transfer, POST /redeem)",
            "2. Ghi nhận state trước: balance, coupon status, usage count",
            "3. Gửi 20-50 request đồng thời (parallel) cùng 1 action:",
            "   curl parallel hoặc Turbo Intruder style — tất cả cùng session",
            "4. Check state sau: balance bị trừ bao nhiêu lần? Coupon used count?",
            "5. So sánh: nếu balance trước=$100, transfer=$100, gửi 20 lần →",
            "   balance sau = -$1900? = Race condition confirmed",
            "6. Test cả limit bypass: action giới hạn 1 lần → gửi đồng thời → dùng >1?",
        ],
        "variations": [
            "File upload race: upload file → process → delete (TOCTOU window)",
            "Signup bonus: tạo nhiều account song song → bonus multiplied?",
            "Inventory race: add to cart đồng thời khi stock=1 → cả 2 đều add được?",
            "Session race: login đồng thời trên nhiều session → state inconsistency?",
        ],
        "success": "Action thực hiện nhiều hơn giới hạn cho phép, balance bị trừ sai, "
        "hoặc coupon/resource dùng nhiều lần",
    },

    # ── BLF-09: Multi-Step Workflow Skip / Process Bypass ──
    {
        "id": "BLF-09",
        "name": "Multi-Step Process Bypass",
        "severity": "High",
        "indicators": [
            "Quy trình nhiều bước: đăng ký, checkout, approval, KYC",
            "URL/param chứa step number: step=1, phase=2, /checkout/step3",
            "Redirect chain: page1 → page2 → page3 → confirm",
            "Có bước xác minh giữa chừng: email verify, OTP, admin approval",
        ],
        "technique": [
            "1. Đi qua flow bình thường (Burp/proxy ON), ghi lại TẤT CẢ request theo thứ tự",
            "2. Thử skip bước: gửi thẳng request bước 3 mà không qua bước 1-2",
            "3. Thử đảo thứ tự: bước 3 trước, bước 1 sau → server check thứ tự không?",
            "4. Thử replay: hoàn thành flow → gửi lại request bước cuối → action lặp?",
            "5. Thử thay đổi state trực tiếp: PATCH /user {\"status\":\"active\"} skip verify",
            "6. Tìm API endpoint khác (mobile API, v2) có thể bypass step check",
        ],
        "variations": [
            "Parameter pollution: gửi step=1&step=3 → server dùng giá trị nào?",
            "Referer bypass: server check Referer từ bước trước → forge Referer header",
            "Direct object access: biết URL bước cuối → truy cập trực tiếp",
            "Parallel flow: bắt đầu 2 flow cùng lúc, hoàn thành flow A bước 1, "
            "dùng state cho flow B bước 2",
        ],
        "success": "Bypass bước xác minh/phê duyệt, hoàn thành flow mà không "
        "qua đủ các bước bắt buộc",
    },
]


# ═══════════════════════════════════════════════════════════════════════
# Helper: render patterns → text cho system prompt
# ═══════════════════════════════════════════════════════════════════════

def _render_pattern(p: dict) -> str:
    """Render một pattern thành chuỗi human-readable."""
    lines = [
        f"### {p['id']}: {p['name']}  [Severity: {p['severity']}]",
        "",
        "**Dấu hiệu nhận biết (indicators):**",
    ]
    for ind in p["indicators"]:
        lines.append(f"  • {ind}")

    lines.append("")
    lines.append("**Kỹ thuật tấn công:**")
    for step in p["technique"]:
        lines.append(f"  {step}")

    lines.append("")
    lines.append("**Biến thể / Bypass:**")
    for var in p["variations"]:
        lines.append(f"  - {var}")

    lines.append("")
    lines.append(f"**Tiêu chí thành công:** {p['success']}")
    lines.append("")
    return "\n".join(lines)


def get_playbook_text(category: Optional[str] = None) -> str:
    """
    Render playbook thành text cho system prompt.

    Args:
        category: "BAC", "BLF", hoặc None (cả hai)

    Returns:
        Formatted string chứa tất cả patterns.
    """
    sections = []

    if category is None or category.upper() == "BAC":
        sections.append("=" * 60)
        sections.append("BAC — BROKEN ACCESS CONTROL PATTERNS")
        sections.append("=" * 60)
        sections.append("")
        for p in BAC_PATTERNS:
            sections.append(_render_pattern(p))

    if category is None or category.upper() == "BLF":
        sections.append("=" * 60)
        sections.append("BLF — BUSINESS LOGIC FLAW PATTERNS")
        sections.append("=" * 60)
        sections.append("")
        for p in BLF_PATTERNS:
            sections.append(_render_pattern(p))

    return "\n".join(sections)


# ═══════════════════════════════════════════════════════════════════════
# Quick pattern lookup cho agents
# ═══════════════════════════════════════════════════════════════════════

ALL_PATTERNS = BAC_PATTERNS + BLF_PATTERNS

def get_pattern_by_id(pattern_id: str) -> Optional[dict]:
    """Lấy pattern theo ID (VD: 'BAC-01', 'BLF-03')."""
    for p in ALL_PATTERNS:
        if p["id"] == pattern_id:
            return p
    return None


def get_pattern_ids() -> list[str]:
    """Trả về danh sách tất cả pattern IDs."""
    return [p["id"] for p in ALL_PATTERNS]


if __name__ == "__main__":
    # Quick test
    print(get_playbook_text())
    print("\n--- Pattern IDs ---")
    print(get_pattern_ids())
