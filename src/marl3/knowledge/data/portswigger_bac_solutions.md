# Access Control (BAC) — Web Security Attack Reference

Coverage: 13 BAC vulnerability patterns

## Unprotected Admin Functionality via robots.txt Disclosure (BAC-01)
**Pattern:** BAC-01

### Vulnerability
The application exposes an admin panel at /administrator-panel with zero server-side access control. Any unauthenticated HTTP client that knows the URL receives HTTP 200 with full admin UI. The path is disclosed in the publicly readable /robots.txt file under a Disallow directive. The application relies entirely on security-through-obscurity (URL not linked from normal UI) rather than authentication or authorization middleware. Because robots.txt is a standard, publicly indexed file, the obscurity is trivially defeated by a single unauthenticated GET request. No session cookie, role token, or credential is required at any step.

### Signals (detectable from recon)
- robots.txt contains a Disallow directive pointing to a path with 'admin', 'administrator', 'panel', 'manage', or 'backend' in the name
- Unauthenticated GET to the Disallow path returns HTTP 200 (not 401/403/302)
- Response body at the admin path contains user management keywords: 'Delete', 'delete user', 'manage users', username list, or account administration forms
- No Set-Cookie challenge, no WWW-Authenticate header, and no redirect to a login page is returned when accessing the admin path without credentials
- Delete/edit actions on the admin panel are accessible via simple GET parameters (e.g., ?username=<VICTIM_USER>) or unguarded POST forms with no CSRF token and no role verification

### Discovery Steps (before attacking)
1. GET /robots.txt (unauthenticated). Parse every Disallow: line. Each value is a candidate sensitive path. Store them as a list.
2. GET /sitemap.xml (unauthenticated). Parse all <loc> entries as additional candidate paths.
3. Grep all crawled HTML and inline JS for path strings matching: /admin, /administrator, /administrator-panel, /admin-panel, /manage, /management, /dashboard, /control, /panel, /backend, /staff, /internal, /superuser, /cpanel, /wp-admin, /phpmyadmin.
4. Issue an unauthenticated GET to each candidate path collected above. Send NO Cookie header and NO Authorization header — the test must simulate a zero-session client.
5. For each response, check: HTTP status == 200 AND response body contains at least one of: 'delete user', 'Delete', 'manage users', 'admin', input/form fields referencing usernames, or a visible user list table.
6. A 401, 403, or 3xx redirect to a login page means the endpoint is protected — skip it. Only HTTP 200 with admin-indicative body content is a positive signal.
7. Confirm the admin panel path discovered (e.g., /administrator-panel) by verifying the response body renders user management controls without any prior authentication step.

### Exploit Steps
1. Step 1 — Fetch robots.txt: GET https://<TARGET_HOST>/robots.txt with no cookies. Extract the value of the Disallow directive. Expected response body example: 'User-agent: *\nDisallow: /administrator-panel'. The extracted path is /administrator-panel.
2. Step 2 — Access admin panel unauthenticated: GET https://<TARGET_HOST>/administrator-panel with no cookies and no Authorization header. Assert HTTP 200. Assert response body contains user management controls (e.g., a 'Delete' link or button next to listed usernames).
3. Step 3 — Identify the delete action URL for target user '<VICTIM_USER>': Inspect the response body of /administrator-panel for a hyperlink or form whose action targets a delete endpoint and whose parameter references the username '<VICTIM_USER>'. The typical pattern is: href='/administrator-panel/delete?username=<VICTIM_USER>' or a POST form with input name='username' value='<VICTIM_USER>'.
4. Step 4 — Execute deletion: If the delete action is a GET link, issue GET https://<TARGET_HOST>/administrator-panel/delete?username=<VICTIM_USER> with no cookies. If it is a POST form, issue POST to the form action URL with body: username=<VICTIM_USER> and Content-Type: application/x-www-form-urlencoded. Send no session cookie in either case.
5. Step 5 — Verify deletion: After the delete request, re-fetch /administrator-panel. Confirm that '<VICTIM_USER>' no longer appears in the user list. Additionally, confirm the application or page title indicates exploitation is confirmed.

### Key Field Names
- `Disallow (robots.txt directive — value is the admin path to probe)`
- `username (query parameter on the delete endpoint, e.g., /administrator-panel/delete?username=<VICTIM_USER>)`
- `Cookie (must be absent / empty in exploit requests — absence of a valid session is the precondition that proves the vulnerability)`
- `Authorization (must be absent — confirms no auth header is needed)`
- `HTTP response status code (must be 200, not 401/403/302, to confirm unprotected access)`

### Proof of Exploitation
Exploitation is proven by two observable conditions: (1) GET /administrator-panel returns HTTP 200 with full admin UI while the request carries zero authentication (no Cookie header, no Authorization header) — this alone proves missing access control; (2) after issuing the delete request for <VICTIM_USER>, a subsequent GET /administrator-panel returns HTTP 200 and the response body no longer contains '<VICTIM_USER>' in the user list, confirming the privileged destructive action succeeded without credentials. The application may render a success confirmation banner on the page, which can be matched as a string in the final response body to programmatically confirm full exploitation.

### Exec Notes
The exec agent requires no prior login step. The full exploit is three unauthenticated HTTP requests. Request 1: GET /robots.txt — extract Disallow path. Request 2: GET /{disallow-path} — confirm HTTP 200 and locate the delete link for target username '<VICTIM_USER>' in the response body using a regex or DOM parse for href patterns matching /delete?username= or form action + input[name=username]. Request 3: GET or POST to the delete endpoint with username=<VICTIM_USER> — no cookie, no token. The agent should assert HTTP 200 or HTTP 302-to-admin (post-delete redirect) on request 3, then re-fetch the admin panel and assert '<VICTIM_USER>' is absent from the body. If the Disallow path differs from /administrator-panel, the agent must dynamically substitute the actual extracted value — do not hardcode the path.

---

## Unprotected Admin Panel with URL Disclosed in Client-Side JavaScript
**Pattern:** BAC-01

### Vulnerability
The admin panel is served at a high-entropy, non-guessable URL path (e.g., /administrator-panel-yb556) that is never linked in the rendered DOM for non-admin users. However, the full URL string is embedded verbatim inside a role-gated conditional block in JavaScript that is delivered to every client regardless of role. Because the check is purely client-side (e.g., `if (isAdmin) { ... href = '/administrator-panel-yb556' ... }`), the URL is visible to any user who reads the raw page source or JS payload. Once the URL is known, the endpoint performs no server-side authentication or authorization check — a 200 response is returned to any unauthenticated request, and all admin actions (user deletion, role changes) execute without further verification. This is a security-through-obscurity failure layered on top of a missing authorization gate.

### Signals (detectable from recon)
- Inline or external JavaScript on the home page contains a conditional block (if (isAdmin), if (role === 'admin'), if (user.isAdmin)) that assigns or constructs a URL string — the URL is present in the JS source even when the condition evaluates to false at runtime.
- The assigned URL path has a high-entropy suffix: matches regex /\/[a-z]+-[a-z0-9]{4,8}/ (e.g., /administrator-panel-yb556, /admin-a3f9c2).
- The link is absent from the rendered DOM (not found via document.querySelectorAll('a')) but present in raw page source — this is the key discrepancy that separates JS-disclosed URLs from normally linked ones.
- Unauthenticated GET to the discovered path returns HTTP 200 with full HTML (not 401, 403, or redirect to /login).
- The admin panel response contains user management actions — keywords 'Delete', 'Users', form fields named 'username', or links containing '/delete?username='.
- No Set-Cookie or Authorization challenge is issued by the server when accessing the admin path — confirms zero server-side auth gate.

### Discovery Steps (before attacking)
1. GET / — fetch the home page raw HTTP response body (not the rendered DOM). Store the full response body including all inline script blocks.
2. Extract all inline <script> tag contents from the HTML response. Also extract the src= URLs of any external .js files.
3. For each JS payload (inline and external), run a regex scan for URL-like strings inside conditional blocks. Target pattern: any string matching /['\"](\/[a-z0-9\-]{8,})['\"]/ that appears within 5 lines of a token matching /isAdmin|role|admin|is_admin|userRole/i.
4. Specifically look for setAttribute('href', ...), location.href =, window.location =, or href = assignments inside if-blocks that check an admin/role variable.
5. Flag any path-like string with a high-entropy suffix: regex /\/[a-z]+-[a-z0-9]{4,}/i (e.g., /administrator-panel-yb556). Paths with random-looking suffixes are candidate disclosures.
6. For every extracted candidate URL, issue an unauthenticated GET request. A 200 response with HTML content (especially containing user management UI elements like 'Delete', 'Users', 'Admin') confirms an unprotected admin panel.
7. If the 200 response contains a form or links with action URLs referencing ?username= or /delete, record those as the delete endpoints.

### Exploit Steps
1. GET / — fetch raw page source.
2. Parse all inline <script> blocks. Apply regex: /href[\s]*=[\s]*['\"](\/[a-zA-Z0-9\-\_]+)['\"]/ and /setAttribute\(['\"]href['\"],\s*['\"](\/[a-zA-Z0-9\-\_]+)['\"]\)/ — collect all matched URL strings.
3. Filter collected URLs: discard common paths (/login, /logout, /home, /static, /css, /js, /img). Retain any path whose final segment contains a hyphen followed by 4+ alphanumeric characters (high-entropy suffix pattern).
4. Issue GET <discovered_admin_path> with no session cookie or with a low-privilege user session. Assert HTTP 200 and that response body contains admin UI indicators (keywords: 'Delete', 'Admin panel', 'Users', '<VICTIM_USER>').
5. Parse the admin panel response to find the delete action. Look for: <a href='/administrator-panel-<suffix>/delete?username=<VICTIM_USER>'> or a form with action containing 'delete' and a hidden input named 'username'.
6. Issue GET <admin_path>/delete?username=<VICTIM_USER> (or POST with body username=<VICTIM_USER> if the form uses POST). No auth headers required.
7. Assert the response is HTTP 200 or a redirect (302) back to the admin panel. Confirm <VICTIM_USER> no longer appears in the user list by issuing GET <admin_path> again and checking that '<VICTIM_USER>' is absent from the response body.

### Key Field Names
- `username — query parameter in the delete action URL (GET /administrator-panel-<suffix>/delete?username=<VICTIM_USER>). This is the only parameter needed to trigger user deletion.`
- `href attribute value inside the JS conditional block — this is the field in the source that discloses the admin path. Exact attribute name: href inside setAttribute('href', '...') or direct assignment adminPanelTag.href = '...'.`
- `isAdmin / role — the JS variable name used in the conditional gate. Common variants: isAdmin, is_admin, userRole, role, admin, isAdministrator. The variable name itself is not tampered with — it is used only to locate the URL string nearby in the source.`

### Proof of Exploitation
["Primary proof: GET <admin_path>/delete?username=<VICTIM_USER> returns HTTP 200 or 302 with no 401/403 error. A success confirmation ('the action/order was completed successfully') appears in the response body or on subsequent page load.", "Secondary proof: GET <admin_path> after deletion — the user list in the response body no longer contains the string '<VICTIM_USER>'. If the panel lists users in a table, <VICTIM_USER>'s row is absent.", "Negative control: Before exploitation, GET <admin_path> returns 200 and <VICTIM_USER> IS present. After the delete request, <VICTIM_USER> is absent. This state change confirms the server-side delete executed without authorization."]

### Exec Notes
["Step 1 — fetch raw source: HTTP GET / with no session or with low-priv session. Do not use a headless browser rendered DOM — use raw HTTP response body. The URL is in the source, not in the rendered DOM.", "Step 2 — JS extraction: parse <script> tags from raw HTML. Also check for <script src='...'> and fetch those external files. Apply regex on combined JS text: /[\\'\\\"](\\\/[a-zA-Z0-9\\-\\_\\/]+)[\\'\\\"]/g — collect all string literals that look like URL paths.", "Step 3 — entropy filter: from collected paths, filter to those matching /\\/[a-z][a-z\\-]*-[a-z0-9]{4,}/i OR any path containing 'admin', 'administrator', 'panel', 'management', 'dashboard' as a substring.", "Step 4 — confirm unprotected: GET each candidate path unauthenticated. Accept as vulnerable if status == 200 AND ('Delete' in body OR 'Admin' in body OR 'username' in body).", "Step 5 — execute delete: GET <admin_path>/delete?username=<VICTIM_USER>. If the admin page contained a form with method=POST, use POST with body: username=<VICTIM_USER> and Content-Type: application/x-www-form-urlencoded.", "Step 6 — verify: GET <admin_path> again. Assert the deleted user no longer appears in the response body.", "Edge case: some target applications use a slightly different path prefix. If /administrator-panel-<suffix> returns 404, try /admin-<suffix> — the JS extraction in step 2 will have captured the exact string; trust that over guessing."]

---

## User Role Controlled by Request Parameter (BAC-02)
**Pattern:** BAC-02

### Vulnerability
The application delegates the authorization decision for privileged access to a client-controlled cookie. On successful login, the server sets a plaintext cookie (e.g., Admin=false) in the response. Every subsequent request to a restricted endpoint (e.g., /admin) is gated solely by reading this cookie value — no server-side session role store, HMAC signature, or opaque token is consulted. Because the cookie is entirely user-modifiable, an attacker intercepts the login response and flips the cookie value (Admin=false → Admin=true) before it reaches the browser, immediately gaining administrative access without possessing a privileged account.

### Signals (detectable from recon)
- Set-Cookie header in login response contains a name that semantically encodes privilege: Admin, role, isAdmin, userRole, accountType, access, privilege, level.
- Cookie value is a plain boolean string (true/false, True/False, 0/1) or a role name (user/admin/moderator) — not an opaque hex token, JWT, or HMAC-signed value.
- Restricted path /admin (or equivalent) returns 403 or redirect for a normal session but is referenced in JS, robots.txt, or sitemap — indicating it exists and is merely gated.
- No server-side session role validation: flipping the cookie value in a replay request immediately changes the HTTP response code from 403 to 200.
- Cookie lacks a cryptographic signature: value can be rewritten arbitrarily without triggering a server-side integrity check.
- Admin panel exposes destructive user management actions (delete, role change) accessible directly via GET parameters (e.g., /admin/delete?username=<VICTIM_USER>), confirming no secondary authorization layer.

### Discovery Steps (before attacking)
1. Grep all Set-Cookie headers from every auth/login response (POST /login, POST /signin, POST /authenticate) for cookie names matching case-insensitive patterns: /admin/i, /role/i, /isadmin/i, /access/i, /privilege/i, /level/i, /userrole/i, /accounttype/i.
2. Flag any matched cookie whose value is a plain boolean string (true, false, True, False) or a low-cardinality role string (user, admin, moderator, 0, 1). These are not opaque tokens and are therefore forgeable.
3. Scan JS source files, robots.txt, and sitemap.xml for path segments matching /admin, /administrator, /manage, /dashboard, /panel, /backoffice. Record all discovered privileged paths as targets for probe requests.
4. After login with a low-privilege account, replay GET requests to each discovered privileged path. Any path returning 403 or a redirect when accessed with the normal session is a candidate for the forged-cookie test.
5. Check whether Set-Cookie response headers include the HttpOnly and Secure flags. Absence of these flags on a role-semantic cookie is an additional risk signal (though irrelevant to Burp-based interception).
6. Verify the cookie is not HMAC-signed or JWT-encoded: a plain Admin=false string with no dot-separated structure and no Base64 encoding is forgeable directly. A JWT or signed value would require a different attack path.
7. If no role cookie is found on the initial login response, also inspect redirect responses (HTTP 302) and any subsequent authenticated page loads — some apps set the role cookie lazily after the first authenticated request.

### Exploit Steps
1. Step 1 — Probe the restricted endpoint: Send GET /admin with a normal (non-admin) session cookie. Confirm the response is 403 or a redirect to /login. This establishes the target endpoint and confirms it is gated.
2. Step 2 — Fetch the login page: Send GET /login to retrieve the login form (capture any CSRF token if present in the form).
3. Step 3 — Submit login credentials: Send POST /login with body username=<ATTACKER_USER>&password=<ATTACKER_PASS> (URL-encoded). Include any CSRF token extracted in Step 2.
4. Step 4 — Intercept the login response: Before forwarding the server response to the browser, inspect all Set-Cookie headers in the response. Identify the cookie whose name matches a role/privilege pattern (e.g., Admin) and whose value is a plain boolean or role string (exact value: false).
5. Step 5 — Forge the cookie: In the login response, rewrite the Set-Cookie header value from Admin=false to Admin=true. Forward the modified response so the browser stores Admin=true.
6. Step 6 — Access the restricted endpoint with the forged cookie: Send GET /admin with the cookie Admin=true. Confirm the response is HTTP 200 and contains admin panel content (user management UI, delete links, etc.).
7. Step 7 — Execute the privileged action: Locate the delete endpoint for user <VICTIM_USER> within the admin panel response (typically a link such as /admin/delete?username=<VICTIM_USER> or a POST form). Send GET /admin/delete?username=<VICTIM_USER> (or the equivalent POST) with the cookie Admin=true.
8. Step 8 — Confirm deletion: The response should confirm the user <VICTIM_USER> has been deleted (HTTP 200 or redirect back to /admin with <VICTIM_USER> absent from the user list). This constitutes proof of exploitation.

### Key Field Names
- `Cookie name: Admin`
- `Cookie value (malicious): true`
- `Cookie value (original): false`
- `Login POST body field: username`
- `Login POST body field: password`
- `Delete action query parameter: username (value: <VICTIM_USER>)`
- `Restricted endpoint path: /admin`
- `Delete endpoint path: /admin/delete`

### Proof of Exploitation
HTTP 200 response from GET /admin/delete?username=<VICTIM_USER> (or equivalent POST) with cookie Admin=true, followed by GET /admin returning a user list that no longer contains the entry for <VICTIM_USER>.

### Exec Notes
The exec agent must intercept the login response (not the request) — response interception must be explicitly enabled in Burp Proxy or replicated programmatically by capturing the Set-Cookie header before it is stored. The agent should: (1) perform the POST /login, (2) capture the raw Set-Cookie header from the response, (3) rewrite the role-semantic cookie value in its local cookie jar to the privileged value (Admin=true), and (4) issue all subsequent requests using the modified cookie jar. No browser automation is required — raw HTTP replay with a modified Cookie header on steps 6-8 is sufficient. The target username to delete (<VICTIM_USER>) is known from recon; the agent should enumerate users from the admin panel response before issuing the delete request.

---

## User role can be modified in user profile
**Pattern:** BAC-02

### Vulnerability
The profile update endpoint accepts a JSON body and reflects security-sensitive fields (specifically `roleid`) back in its response. The server applies any client-supplied value for `roleid` without stripping, validating, or rejecting it. Injecting `"roleid": 2` into the update request body causes the server to overwrite the authenticated user's role to admin. This is a mass assignment vulnerability leading to vertical privilege escalation: the server trusts client input for a privilege attribute because the update handler lacks an allowlist of permitted writable fields.

### Signals (detectable from recon)
- JSON response to a profile/account update request contains a `roleid` field (integer) not present in the submitted request body — server is reflecting the full user model object.
- The update endpoint accepts Content-Type: application/json (not form-encoded), making arbitrary field injection trivial without encoding concerns.
- The role value is a plain integer (`roleid: 1`, `roleid: 2`), not a cryptographic token or opaque string — it is enumerable by incrementing.
- No HTTP 400 or error is returned when extra/unexpected fields are appended to the JSON body — confirms absence of input allowlisting.
- The /admin endpoint returns different HTTP status codes (200 vs 403) depending on session role, confirming role-based gating is enforced via session state which was overwritten by mass assignment.
- OpenAPI/Swagger spec (if present) exposes a User schema with a `roleid` field — check if the field is marked writable or lacks a readOnly annotation.

### Discovery Steps (before attacking)
1. Log in with credentials <ATTACKER_USER> / <ATTACKER_PASS> via POST /login with body username=<ATTACKER_USER>&password=<ATTACKER_PASS>.
2. Navigate to GET /my-account to locate the account/profile page.
3. Submit any valid email address via the 'Update Email' form to trigger a POST /my-account/change-email request with Content-Type: application/json and body {"email": "probe@example.com"}.
4. Inspect the JSON response body for fields beyond what was submitted. A `roleid` field (integer, value 1) present in the response is the primary detection signal — the server is reflecting a privilege attribute as part of the same model object being updated.
5. Confirm the field is writable: the presence of `roleid` in a non-admin context with an integer value (not a hash/token) means it is enumerable and likely accepted on write.

### Exploit Steps
1. Authenticate: POST /login with body username=<ATTACKER_USER>&password=<ATTACKER_PASS>. Confirm session cookie is set.
2. Capture the email update request: POST /my-account/change-email with Content-Type: application/json and body {"email": "attacker@evil.com"}. Note the response includes {"username": "<ATTACKER_USER>", "email": "attacker@evil.com", "roleid": 1}.
3. Inject the privilege field: resend POST /my-account/change-email with the same session cookie but with body {"email": "attacker@evil.com", "roleid": 2}.
4. Verify role escalation: the response body should now show {"username": "<ATTACKER_USER>", "email": "attacker@evil.com", "roleid": 2}. If `roleid` in the response equals 2, the server accepted and applied the injected value.
5. Access the admin panel: GET /admin. Expect HTTP 200 and admin UI content (not a 401/403).
6. Delete the target user: GET /admin/delete?username=<VICTIM_USER>. Expect HTTP 200 or a redirect confirming deletion.

### Key Field Names
- `roleid`
- `email`
- `username`
- `role`
- `is_admin`
- `admin`
- `group`
- `permissions`

### Proof of Exploitation
Three-part proof required: (1) The POST /my-account/change-email response with injected `roleid` body shows `\"roleid\": 2` in the JSON response, confirming server-side role overwrite. (2) GET /admin returns HTTP 200 with admin panel content (not 401/403), confirming the session now has admin privileges. (3) GET /admin/delete?username=<VICTIM_USER> returns HTTP 200 or 302 and <VICTIM_USER> no longer appears in the user list, confirming full exploitation.

### Exec Notes
No product IDs or coupon codes are required. The full exploit is: (1) login, (2) POST to /my-account/change-email with appended `"roleid": 2` in the JSON body, (3) GET /admin, (4) GET /admin/delete?username=<VICTIM_USER>. The automated agent must: preserve the session cookie across all requests; detect the `roleid` field in the email-update response before attempting injection (do not hardcode the endpoint path — confirm it from the form action attribute on the account page); try `roleid` values 2, 99, and 9999 in sequence if 2 does not grant admin access. For broader mass assignment probing on any JSON update endpoint, append each of these keys in turn: `roleid`, `role`, `is_admin`, `admin`, `group`, `permissions`, `authority` — check both the response body (does the value reflect?) and subsequent access to /admin (does gating change?).

---

## URL-Based Access Control Bypass via X-Original-URL Header
**Pattern:** BAC-04

### Vulnerability
The front-end proxy enforces access control by inspecting the request-line URL path (e.g., blocking any request where path == /admin). The back-end application framework (Symfony, certain Spring Cloud Gateway or Express configs) is configured to honor the X-Original-URL header as a routing override, replacing the request-line path for internal dispatch. An attacker sets the request-line URL to / (which passes the front-end ACL check) and sets X-Original-URL: /admin (which the back-end routes to the admin handler). This is a split-brain / confused-deputy access control failure. Query parameters must remain on the request-line URL because the framework only uses the header for path routing, not for query string parsing.

### Signals (detectable from recon)
- GET /admin returns 403/401 with response characteristics indicating proxy/CDN origin: no application session cookies in response, no CSRF token in body, error page HTML is generic (not app-templated), Server or Via headers show Nginx/Varnish/CDN rather than application framework.
- GET / with X-Original-URL: /nonexistent returns a response that differs from the baseline GET / — specifically an application-layer 404 (app-styled error page, possibly with app session cookie or CSRF token), NOT the proxy block page. This body/status divergence from baseline is the primary detection signal.
- Technology stack indicators: PHPSESSID cookie, X-Powered-By: PHP, Symfony debug toolbar fragment in HTML, Spring Boot Whitelabel Error Page, all raise probability that X-Original-URL is processed.
- Admin panel at /admin has no authentication form of its own — it relies entirely on the front-end URL block, meaning no login redirect or session check is observed when the bypass succeeds (200 response with admin HTML directly).

### Discovery Steps (before attacking)
1. Enumerate paths with a fuzzer targeting common admin/privileged paths (e.g., /admin, /admin/users, /administrator, /manage, /dashboard). Flag any response where: HTTP status is 403/401 AND the response body/headers show proxy/CDN origin characteristics (no app cookies, no CSRF token, generic block page, Server header shows Nginx/CDN rather than app framework, no Set-Cookie from app session).
2. For every flagged front-end-blocked path, run a differential header probe: baseline = GET / HTTP/1.1 (record status, body length, Content-Type); probe = GET / HTTP/1.1 + X-Original-URL: /nonexistent (if status or body length differs from baseline, the header is being processed by back-end); confirm = GET / HTTP/1.1 + X-Original-URL: /admin (if response returns 200 with different content than baseline, bypass confirmed).
3. Technology fingerprinting to raise prior probability: look for PHPSESSID cookies (Symfony/PHP), X-Powered-By: PHP, Symfony debug toolbar artifacts in HTML comments, or Spring Boot actuator endpoints. These frameworks are documented to process X-Original-URL by default or with common configurations.
4. Check for X-Rewrite-URL as an alternative header exhibiting the same behavior. Send GET / HTTP/1.1 with X-Rewrite-URL: /admin as a parallel probe if X-Original-URL does not produce a differential response.

### Exploit Steps
1. Step 1 — Confirm front-end blocking: Send GET /admin HTTP/1.1 with Host header set to the target. Expect a 403 or 'Access denied' response that originates from the proxy layer (different error page styling, no app session cookies, no CSRF token in body, response headers show Nginx/CDN origin rather than app framework).
2. Step 2 — Probe back-end header processing: Send GET / HTTP/1.1 with header X-Original-URL: /invalid. If the back-end processes the header, the response will change from the normal homepage to an application-layer 404 (different body/size/styling from both the homepage and the proxy 403). This response difference confirms the back-end is routing on X-Original-URL.
3. Step 3 — Bypass to admin panel: Send GET / HTTP/1.1 with header X-Original-URL: /admin. Expect a 200 response containing the admin panel HTML. Parse the response to extract the username parameter value for the target user (<VICTIM_USER>).
4. Step 4 — Execute privileged action (delete user): Send GET /?username=<VICTIM_USER> HTTP/1.1 with header X-Original-URL: /admin/delete. The query string (?username=<VICTIM_USER>) MUST be placed on the request-line URL, NOT inside the X-Original-URL header value. The back-end uses X-Original-URL only for path routing; query string is read from the raw request line. Expect a 302 redirect or 200 confirming deletion.

### Key Field Names
- `X-Original-URL`
- `X-Rewrite-URL`
- `X-Forwarded-URL`
- `username (query parameter on request-line URL for admin actions, e.g., ?username=<VICTIM_USER>)`

### Proof of Exploitation
["Bypass confirmed: GET / HTTP/1.1 with X-Original-URL: /admin returns HTTP 200 with admin panel HTML body (contains user management table or delete links for users such as <VICTIM_USER>).", "Exploitation confirmed: GET /?username=<VICTIM_USER> HTTP/1.1 with X-Original-URL: /admin/delete returns HTTP 302 redirect or HTTP 200 with confirmation message. Subsequent GET / with X-Original-URL: /admin no longer lists <VICTIM_USER> in the user table, or the application displays a success confirmation banner."]

### Exec Notes
Query parameters for back-end admin actions (e.g., ?username=<VICTIM_USER> for /admin/delete) MUST be appended to the request-line URL, not to the X-Original-URL header value. Sending X-Original-URL: /admin/delete?username=<VICTIM_USER> will fail because the framework only uses the header for path dispatch and reads query strings from the raw request line. Correct form: GET /?username=<VICTIM_USER> HTTP/1.1 + X-Original-URL: /admin/delete. The target username (<VICTIM_USER>) is obtained by parsing the admin panel HTML returned in the bypass step; do not hardcode without first reading it from the response.

---

## Method-Based Access Control Bypass (BAC-04)
**Pattern:** BAC-04

### Vulnerability
The application enforces access control only on specific HTTP methods (typically POST) for privileged endpoints. The ACL rule is written as a method-specific DENY (e.g., DENY POST /admin/* for non-admin roles). When the same endpoint receives a GET request or a non-standard method (POSTX, XPOST, FOOBAR), the authorization middleware does not match the rule and skips the check entirely. The underlying handler is method-agnostic and processes the privileged action regardless, completing the operation. This is a platform-layer misconfiguration: access control lives in routing/middleware with a method filter, but the controller has no independent authorization check.

### Signals (detectable from recon)
- Response error class changes from 401/403 to 400/500/'missing parameter' when method is changed to POSTX — this means the ACL rule matched on method and is now absent, but the handler is partially reached.
- The endpoint accepts GET at all: many frameworks (Spring MVC, Rails, Django generic views, Express without explicit method binding) register the same handler for all methods unless restricted. A 200 or 302 on GET (rather than 405 Method Not Allowed) confirms the route is unguarded.
- No CSRF token required on GET: GET requests are typically excluded from CSRF middleware, further removing friction from the exploit.
- 302 redirect on the GET exploit request (not 403) — state-changing redirect confirms the action executed.
- In crawled JS or HTML: if the same URL path appears in both a form action (POST) and an anchor href or fetch() GET call, the handler is method-agnostic and is a high-priority BAC-04 candidate.
- Framework fingerprints that raise prior probability: Spring Security with @PreAuthorize only on @PostMapping; Apache httpd Limit/LimitExcept directives; Express app.post('/admin', authMiddleware) without a matching app.get guard; Rails resources routing without explicit method constraints on before_action filters.

### Discovery Steps (before attacking)
1. Authenticate as a low-privilege user (the attacker account credentials) and capture the session cookie. Label it LOW_SESSION.
2. Authenticate as an admin user (administrator:admin), navigate to the admin panel, and trigger a privileged state-change action (e.g., promote user <VICTIM_USER>). Intercept the request in Burp Suite — record the exact endpoint path, parameter names, and parameter values. Label this Request A.
3. Confirm the endpoint is access-controlled: replay Request A with LOW_SESSION replacing the admin session cookie (keep method POST, keep all other fields identical). Expect a 401 or 403 response with body containing 'Unauthorized'. This confirms the gate exists on POST.
4. Probe method-bypass with a non-standard method: change the HTTP method from POST to POSTX (leave all headers and body identical, still using LOW_SESSION). If the response changes from 401/403 to any other error class (400, 'missing parameter', 500, or 200), the ACL is method-bound and the gate is skipped for unknown methods. This is the primary bypass signal.
5. Enumerate whether a GET route exists: use Burp Repeater 'Change request method' to convert the POSTX request to GET (Burp automatically moves body parameters to the query string). Send with LOW_SESSION. A 200 or 302 response confirms the GET route is live and unprotected.

### Exploit Steps
1. Obtain LOW_SESSION: POST /login with actual target credentials from Known-Good Values, extract the Set-Cookie session value from the 302 response.
2. Identify the privileged endpoint: from the admin session baseline, the endpoint is /admin-roles (exact path varies per application; confirm from Request A interception). The HTTP method is POST. The body parameters are username=<VICTIM_USER>&action=upgrade.
3. Verify the gate: send POST /admin-roles with body username=<ATTACKER_USER>&action=upgrade and header Cookie: session=LOW_SESSION. Assert response status is 401 or 403 and body contains 'Unauthorized'. If not, re-check the session cookie.
4. Send the bypass request: change HTTP method to GET, move parameters to query string. Full request: GET /admin-roles?username=<ATTACKER_USER>&action=upgrade HTTP/1.1 with header Cookie: session=LOW_SESSION. Send this request.
5. Assert exploit success: expect HTTP 302 redirect response. The redirect location should point back to /admin or /. Follow the redirect with LOW_SESSION and confirm the account page or admin panel shows <ATTACKER_USER> has administrator role.

### Key Field Names
- `username`
- `action`
- `session (Cookie header)`
- `HTTP method (POST -> GET conversion)`
- `query string (parameter migration from body to ?username=&action= on GET)`

### Proof of Exploitation
The exploit is confirmed when the alternative-method request with LOW_SESSION returns HTTP 302 (or 200). Post-exploit verification: send GET /my-account (or equivalent profile endpoint) with Cookie: session=LOW_SESSION and confirm the response body contains 'admin': true, role='administrator', or an 'Admin panel' link — whichever indicator the application uses. Privilege escalation is confirmed when the attacker's low-priv account gains admin-level access.

### Exec Notes
Automated agent execution order: (1) POST /login [admin creds] -> extract ADMIN_SESSION. (2) POST /admin-roles body=username=<VICTIM_USER>&action=upgrade cookie=ADMIN_SESSION -> record exact endpoint and params. (3) POST /login [low creds] -> extract LOW_SESSION. (4) POST /admin-roles body=username=<ATTACKER_USER>&action=upgrade cookie=LOW_SESSION -> assert 401/403 (gate confirmed). (5) POSTX /admin-roles body=username=<ATTACKER_USER>&action=upgrade cookie=LOW_SESSION -> assert response NOT 401/403 (bypass signal confirmed). (6) GET /admin-roles?username=<ATTACKER_USER>&action=upgrade cookie=LOW_SESSION -> assert 302 (exploit confirmed). (7) GET /my-account cookie=LOW_SESSION -> assert body contains admin indicator. The critical branching condition is step 5: if POSTX still returns 401/403, the server may be using a catch-all method deny; in that case try HEAD, PUT, and OPTIONS before declaring not exploitable. If step 6 returns 405, the GET route is not registered; try PATCH and PUT as alternate method bypasses before falling back.

---

## IDOR via user ID in request parameter (BAC-03)
**Pattern:** BAC-03

### Vulnerability
The application exposes a user-controlled query parameter (id) on account/profile endpoints to identify which user record to return. The server performs no authorization check comparing the authenticated session's user to the requested id value. Any authenticated user can substitute a different username or user identifier to retrieve another user's account data, including sensitive fields such as API keys, email addresses, and PII. This is a horizontal privilege escalation via Insecure Direct Object Reference (IDOR): the object reference (username string) is client-supplied, human-readable, and unprotected by any ownership verification on the server side.

### Signals (detectable from recon)
- Query parameter named 'id' (or similar identity parameter) on an account/profile endpoint whose value equals the authenticated user's own username or integer ID
- Parameter value is a plain, human-readable, guessable string (username, integer sequence, non-signed UUID) rather than a cryptographic token or session-derived reference
- Endpoint path matches account/profile patterns: /my-account, /account, /profile, /user/profile, /dashboard
- HTTP GET method with the identity value in the query string (easiest substitution case; also check POST body parameters)
- Response to the baseline request (id=own_user) is HTTP 200 and contains sensitive fields: API key, email, PII, balance, order history
- Response to the probe request (id=other_user, same session) is also HTTP 200 with a different response body containing the other user's data
- No secondary authorization token, CSRF token, or ownership secret is required to complete the lookup — session cookie alone is accepted

### Discovery Steps (before attacking)
1. Crawl the application after authenticating as a known user (the attacker account credentials). Collect all GET and POST requests that contain parameters named: id, user_id, uid, account, username, profile, userId, user, or similar identity-shaped parameters.
2. Flag any endpoint where the parameter value equals the currently authenticated username or user ID (e.g., /my-account?id=<ATTACKER_USER>). This reflection of the session identity into a query parameter is the primary signal.
3. Check whether the id parameter value is a human-readable, guessable, or sequential identifier (plain username string, integer, UUID) rather than a signed/HMAC token or opaque session-derived reference. Non-opaque values are substitutable.
4. Identify a second known username to use as the target. In this lab the target is '<VICTIM_USER>'. In real applications, enumerate usernames from profile pages, comments, order history, error messages, or registration flows.
5. Issue a baseline request: GET /my-account?id=<ATTACKER_USER> with the attacker session cookie. Record the HTTP status code and response body hash/length.
6. Issue the probe request: GET /my-account?id=<VICTIM_USER> with the attacker session cookie (no other change). Compare HTTP status code and response body to the baseline.
7. IDOR is confirmed if: probe returns HTTP 200 AND response body differs from baseline AND response body contains data attributable to <VICTIM_USER> (different email, different API key, different name). A 401 or 403 response falsifies this pattern for this endpoint.

### Exploit Steps
1. Authenticate: POST /login with body username=<ATTACKER_USER>&password=<ATTACKER_PASS>. Capture the session cookie from the Set-Cookie response header.
2. Access own account page: GET /my-account?id=<ATTACKER_USER>, sending the captured session cookie. Confirm HTTP 200 and that the response contains the attacker's account data. Record the API key or other sensitive field values shown for the attacker account as the baseline.
3. Tamper the id parameter: construct the attack request GET /my-account?id=<VICTIM_USER>, sending the same attacker session cookie. Do not change any other header or cookie.
4. Send the attack request. Expect HTTP 200. Parse the response body for the API key field (look for text patterns such as 'API Key', 'apikey', 'api_key', or a labeled alphanumeric string distinct from the attacker's API key).
5. Extract the API key value from the response body. It will appear in the HTML of the victim's account page.
6. Submit the extracted API key value as exploitation proof or use it to confirm unauthorized cross-account data access.

### Key Field Names
- `id`
- `user_id`
- `uid`
- `username`
- `account`
- `profile`
- `userId`
- `user`

### Proof of Exploitation
The exploit is proven when the response to GET /my-account?id=<VICTIM_USER> (sent with the attacker session cookie) returns HTTP 200 and the response body contains an API key value that is different from the API key shown on the attacker's own account page. Concrete confirmation criteria: (1) HTTP status is 200, not 401 or 403; (2) response body contains a field labeled 'API Key' or equivalent; (3) the API key value differs from the baseline value retrieved for id=<ATTACKER_USER>; (4) the extracted API key belongs to a different user, confirming unauthorized cross-account access.

### Exec Notes
The automated exploit agent requires two valid accounts to confirm this vulnerability. Discovery phase: after login, scan all collected requests for the pattern {account_endpoint}?{id_param}={own_username}. Substitution phase: replace the id_param value with each known username in the target set (at minimum: '<VICTIM_USER>', 'admin', 'user2', and any usernames extracted during crawl). Send each substituted request with the original session cookie unchanged. Oracle evaluation: if response is HTTP 200 AND body length differs from baseline by more than a noise threshold (e.g., 50 bytes) AND body contains a field matching the pattern /api.?key|apikey|api_key/i with a value distinct from the baseline value, classify as IDOR confirmed. Extract and return the sensitive field value. No brute-force of integer IDs is needed for username-based IDOR; for integer-based variants, try baseline_id +/- 1 and baseline_id - 1 as the minimal probe set before broader enumeration.

---

## IDOR with unpredictable GUIDs exposed in blog posts
**Pattern:** BAC-03: IDOR via UUID id parameter — server fails to bind the authenticated session to the id parameter, allowing horizontal privilege escalation by substituting a target user's GUID harvested from public-facing author/profile links.

### Vulnerability
Horizontal privilege escalation via Insecure Direct Object Reference (IDOR). The application uses GUIDs as user identifiers to avoid sequential enumeration, but performs no server-side authorization check to verify the authenticated session's user matches the id parameter in the request. Any authenticated user can retrieve any other user's account data by substituting a known GUID. The GUID is not secret — it is leaked on public blog post author links, forum posts, or profile pages, making the "unpredictability" defense ineffective. This is a false sense of security: unpredictability is not a substitute for ownership enforcement.

### Signals (detectable from recon)
- URL parameter named 'id', 'userId', or 'accountId' in authenticated account/profile endpoint contains a UUID-format value (8-4-4-4-12 hex pattern).
- Public pages (blog posts, forums, comment sections) contain author/user links where the href includes a UUID in an id-type parameter — the same parameter name used on the authenticated account endpoint.
- Authenticated account endpoint returns HTTP 200 with full account data (including sensitive fields like API key, email, personal info) for any valid UUID regardless of session ownership.
- No 401 or 403 response when substituting a different user's UUID while authenticated as a different user.
- No CSRF token, ownership token, or session-bound nonce present in the account page URL or request.
- Response body when fetching another user's GUID is structurally identical to own account response (same HTML template, same fields populated) — confirming the server renders any account for any authenticated request.

### Discovery Steps (before attacking)
1. Crawl all public/unauthenticated pages: blog posts, comment threads, forum posts, author profile links. Collect every URL containing a user-identifying parameter.
2. For each discovered user-facing link, check if the URL contains a UUID-format id parameter matching regex: [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}. Example target URL: /blogs?userId=3b2c1f4a-89de-4012-b3c7-1234567890ab.
3. Record all harvested GUIDs and associate them with usernames (e.g., author name '<VICTIM_USER>' maps to GUID X seen in blog author link href).
4. Log in as the test user (the attacker account credentials via POST /login with body username=<ATTACKER_USER>&password=<ATTACKER_PASS>). Record the session cookie.
5. Navigate to the authenticated account endpoint (GET /my-account?id=<<ATTACKER_GUID>>). Record the exact parameter name (id) and the GUID format used for the authenticated user.
6. Confirm the endpoint is IDOR-candidate: the id parameter is user-controlled via URL, the value is a UUID, and the same endpoint is used for all users.

### Exploit Steps
1. Obtain the victim's GUID from a public blog post author link. Click the author name '<VICTIM_USER>' on any blog post. Extract the UUID from the resulting URL — the parameter name is 'id' or 'userId'. Example: GET /blogs?userId=3b2c1f4a-89de-4012-b3c7-1234567890ab — record value 3b2c1f4a-89de-4012-b3c7-1234567890ab.
2. Authenticate as the attacker account: POST /login with body username=<ATTACKER_USER>&password=<ATTACKER_PASS>. Store the session cookie returned in the Set-Cookie header.
3. Issue the IDOR request using the attacker's session but the victim's GUID: GET /my-account?id=<<VICTIM_GUID>> with the attacker's session cookie. No other headers, tokens, or body required.
4. Parse the response body for the API key field. The page will render the victim's account data including his API key (typically labeled 'API Key' in the HTML).
5. Use the extracted API key as exploitation proof of unauthorized cross-account data access.

### Key Field Names
- `id`
- `userId`
- `accountId`
- `user_id`
- `uid`

### Proof of Exploitation
HTTP 200 response to GET /my-account?id=<<VICTIM_GUID>> (using the attacker's session cookie) that contains the victim's account data — specifically the API key value displayed on the account page. Proof is confirmed when: (1) the response body contains a field labeled 'API Key' with a non-empty value, AND (2) that value differs from the attacker's own API key (obtained by first fetching /my-account?id=<<ATTACKER_GUID>>). Successfully accessing the victim's API key from a different authenticated session is the final proof.

### Exec Notes
Discovery phase must crawl unauthenticated pages first to harvest target GUIDs before authentication. The GUID is the only required artifact from recon — no product IDs, coupon codes, or sequential enumeration needed. The exploit is a single substitution: replace the authenticated user's UUID in the id parameter with the target's UUID on the same endpoint (/my-account or equivalent). No request body manipulation, no special headers, no token forgery required. The only session cookie used is the attacker's own valid session — the attack does not require stealing <VICTIM_USER>'s session. Regex for UUID detection in crawl output: [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}. BAC-03 rule trigger condition: UUID-format id parameter visible on authenticated endpoint AND same UUID format discoverable from unauthenticated public pages = high-confidence exploit candidate, proceed directly to cross-account substitution test.

---

## IDOR with Data Leakage in Redirect Body
**Pattern:** BAC-03

### Vulnerability
The server generates the full account page response body — including sensitive user data such as API keys — before performing the authorization check. When the check fails for a cross-user request, the server issues a 302 redirect to the home page but does NOT discard the already-rendered response body. The attacker receives a 302 response whose body contains the victim's sensitive data. Standard browsers silently follow the redirect and discard the body, so the leakage is invisible in a normal browser session but fully visible in an intercepting proxy or any HTTP client that does not auto-follow redirects. The root cause is a render-then-gate ordering flaw combined with failure to clear the response buffer before issuing the redirect.

### Signals (detectable from recon)
- Account or profile endpoint URL contains a user-controlled identity parameter (e.g. ?id=<ATTACKER_USER>) rather than deriving identity solely from the session.
- Substituting a foreign id value triggers a redirect (3xx) instead of a 403 or 401 — this indicates the server processes the request before the access check.
- The 3xx redirect response has a non-empty body (Content-Length greater than 0). Redirect responses should normally have an empty or minimal body.
- The non-empty redirect body contains sensitive data: API keys, tokens, PII, email addresses, or session identifiers.
- No cryptographic binding between the id parameter and the session token — the server trusts the parameter value directly to select which user record to render.

### Discovery Steps (before attacking)
1. Crawl all authenticated endpoints and record every URL that contains a user-identity parameter in the query string or POST body. Target parameter names: id, user, username, user_id, account_id, uid, profile_id, email. Example pattern to match: /my-account?id=<ATTACKER_USER>, /profile?username=<ATTACKER_USER>, /account?user_id=42.
2. For every endpoint matched in the previous step, record the baseline response: status code, Content-Length, and whether a redirect is issued when the correct (own) id value is submitted with a valid session.
3. Enumerate at least one additional valid username or numeric ID. For black-box testing, common valid values are: <VICTIM_USER>, admin, administrator, test, user2, or integer IDs adjacent to your own (e.g. if your id=5, try id=4 and id=6).
4. Issue a modified request substituting the foreign id value while preserving the authenticated session cookie. Do NOT follow any redirect that is returned — capture the raw HTTP response.
5. Inspect the raw response body of any 3xx response. Flag as BAC-03 candidate if: (a) status code is 301, 302, 303, 307, or 308, AND (b) Content-Length is greater than 0 or the body is non-empty, AND (c) the body contains tokens matching patterns such as [A-Za-z0-9]{32,} or field names api_key, apiKey, token, secret, key, password, email.

### Exploit Steps
1. Authenticate as the attacker-controlled user (credentials: the attacker account credentials) and obtain a valid session cookie.
2. Send GET /my-account?id=<ATTACKER_USER> with the session cookie. Confirm a 200 response containing your own account data. Record the exact endpoint path and parameter name used.
3. Open Burp Repeater (or equivalent non-redirect-following HTTP client). Duplicate the request.
4. In the duplicated request, change the value of the id parameter from <ATTACKER_USER> to <VICTIM_USER>. Keep all other headers and the session cookie unchanged. Exact modified request line: GET /my-account?id=<VICTIM_USER> HTTP/1.1
5. Send the request. Do NOT follow any redirect. Inspect the raw response.
6. Locate the API key in the response body. It will appear in a field named api_key, apiKey, or similar, or as a standalone alphanumeric string of 32 or more characters.
7. Copy the API key value verbatim as proof of unauthorized cross-account data exposure.

### Key Field Names
- `id`
- `user`
- `username`
- `user_id`
- `account_id`
- `uid`
- `profile_id`
- `api_key`
- `apiKey`
- `token`
- `secret`
- `key`

### Proof of Exploitation
The exploit is confirmed when the HTTP response to GET /my-account?id=<victim_username> returns status code 302 (or any 3xx) AND the response body contains a non-empty api_key (or equivalent sensitive field) that differs from the api_key returned for the attacker's own id. In automated testing, proof is: (1) response.status_code in [301,302,303,307,308], (2) len(response.body) > 0, (3) a regex match for api_key\s*[:=]\s*[A-Za-z0-9]+ in the body, and (4) the extracted value does not match the attacker's own api_key from the baseline request.

### Exec Notes
The exec agent must disable automatic redirect following in its HTTP client (e.g. allow_redirects=False in Python requests, or --max-redirs 0 in curl). Without this, the redirect will be followed and the leaking body will be silently discarded, making the vulnerability undetectable. All 3xx responses from identity-parameterized endpoints must be captured raw and their bodies scanned before any redirect is followed. The parameter substitution is purely horizontal (attacker-tier to same-tier victim user), so no privilege escalation is required — only a valid session for any account is needed. The target username <VICTIM_USER> is known from recon context; in a real engagement, valid usernames must be enumerated first (registration error messages, user search endpoints, or numeric ID walking).

---

## IDOR with password in masked input (BAC-08)
**Pattern:** BAC-08

### Vulnerability
Insecure Direct Object Reference (IDOR) on an account page endpoint where a user-supplied query parameter (e.g. ?id=<ATTACKER_USER>) determines which account record is rendered, with no server-side check that the session user matches the requested id. The compounding critical factor is that the account page embeds the account's plaintext password in an HTML input field as value="&lt;password&gt;" with type="password". The browser masks this visually, but the raw HTTP response body exposes the credential in clear text. A low-privilege authenticated user can change id=<ATTACKER_USER> to id=administrator to receive the administrator's full account page including their plaintext password, converting a horizontal IDOR into a vertical privilege escalation. CWEs: CWE-639 (Authorization Bypass Through User-Controlled Key), CWE-522 (Insufficiently Protected Credentials), CWE-200 (Exposure of Sensitive Information). CVSS estimate: 9.1 Critical.

### Signals (detectable from recon)
- URL query parameter named id, user, uid, account, profile, or username whose value matches the authenticated session username — indicates server uses a client-controlled key for object lookup
- HTTP 200 response on ?id=administrator using a non-admin session cookie — confirms missing server-side authorization check
- Response body contains <input type="password" value="..."> with a non-empty value attribute — confirms plaintext credential embedded in HTML
- Parameter value is a predictable string (administrator, admin, <VICTIM_USER>) or a sequential integer (id=1, id=2) — confirms enumerability
- No 401, 403, or redirect-to-login response when the id parameter is changed to a different user — confirms the session is used only for authentication, not authorization

### Discovery Steps (before attacking)
1. Crawl all authenticated GET endpoints and collect every URL containing query parameters whose names match the pattern: id, user, uid, account, profile, username, userId. Flag any where the parameter value equals the authenticated session username or a small integer.
2. For each flagged endpoint, record the baseline response: HTTP status, body hash, and rendered username/email fields. The canonical baseline is GET /my-account?id=<ATTACKER_USER> with a valid attacker session cookie returning HTTP 200.
3. Probe the flagged endpoint by replaying the exact same request (same session cookie, same headers) but substituting the id parameter value with high-value targets in order: administrator, admin, 1, 0, 2. A response that returns HTTP 200 with account-specific content (username, email, or password field) for the target user rather than the authenticated user confirms IDOR.
4. In every IDOR-confirmed response body, apply the regex <input[^>]+type=["']?password["']?[^>]+value=["']([^"']+)["'] (and its attribute-order variant <input[^>]+value=["']([^"']+)["'][^>]+type=["']?password["']?>) to detect a non-empty password value embedded in the HTML. A non-empty capture group is a confirmed credential disclosure.
5. If the IDOR target resolves to an administrator-class account (username field contains 'admin' or 'administrator' in the response body) AND the password regex yields a non-empty value, classify the finding as vertical privilege escalation, Critical severity, and proceed immediately to exploitation.

### Exploit Steps
1. Authenticate as the low-privilege user: POST /login with body username=<ATTACKER_USER>&password=<ATTACKER_PASS>. Capture the session cookie from the Set-Cookie response header.
2. Send GET /my-account?id=<ATTACKER_USER> with the attacker session cookie. Confirm HTTP 200 and note the response body structure (baseline).
3. Send GET /my-account?id=administrator with the same attacker session cookie unchanged. Confirm the response is HTTP 200 and that the body contains the administrator's account page (look for the string 'administrator' in the username field).
4. Extract the administrator password from the response body using the regex: <input[^>]+type=["']?password["']?[^>]+value=["']([^"']+)["']. The first capture group is the plaintext password (e.g. value="s3cr3tP@ss"). Also try the reversed attribute order variant in case value= precedes type=.
5. Log out of the attacker session (GET /logout or equivalent, or simply discard the session cookie).
6. Authenticate as administrator: POST /login with body username=administrator&password=<extracted_value>. Capture the new administrator session cookie.
7. Navigate to the admin panel: GET /admin with the administrator session cookie. Confirm the panel is accessible (HTTP 200, admin interface rendered).
8. Delete user <VICTIM_USER>: GET or POST /admin/delete?username=<VICTIM_USER> with the administrator session cookie. Confirm HTTP 200 or redirect response indicating successful deletion.

### Key Field Names
- `id (query parameter on /my-account — the object reference that must be tampered)`
- `value (HTML attribute on input[type=password] — contains the plaintext credential in the response body)`
- `type (HTML attribute on input — must equal 'password' to identify the masked credential field)`
- `username (POST /login body parameter)`
- `password (POST /login body parameter)`
- `session (cookie name carrying the authenticated session — must be kept as the attacker account's cookie during the IDOR probe)`

### Proof of Exploitation
Exploitation is proven by a chain of three observable states: (1) GET /my-account?id=<admin_username> with a non-admin session cookie returns HTTP 200 and the response body contains a non-empty value attribute inside an input[type=password] element — this proves IDOR and credential disclosure; (2) POST /login with the admin username and the extracted password returns HTTP 200 or a redirect with a new administrator session cookie — this proves the credential is valid; (3) GET or POST /admin/delete?username=<victim_username> returns HTTP 200 or 302 and the subsequent GET /admin no longer lists the victim as a user — this proves vertical escalation to admin.

### Exec Notes
The exec agent requires no prior enumeration of unknown identifiers — the target id values (administrator, admin, 1, 0) are a sensible priority list to try first. The single pivotal HTTP request is GET /my-account?id=<admin_id_candidate> with the low-privilege session cookie; everything else is setup or cleanup. Password extraction must handle both attribute orderings of the input tag (type before value, or value before type) since HTML attribute order is not guaranteed. The agent must treat a non-empty regex capture from the password input as an immediate stop condition and pivot to login — do not continue probing other id values once a credential is extracted. The admin panel path and delete endpoint must be discovered from recon (check /admin, /admin/users, /admin/delete, etc.).

---

## IDOR via Predictable Incrementing Filename in Download Endpoint (Chat Transcript)
**Pattern:** BAC-03

### Vulnerability
The application stores user chat transcripts as static text files on the server filesystem, named with a simple auto-incrementing integer (1.txt, 2.txt, 3.txt, ...). The download endpoint exposes the filename directly in the URL path and performs no server-side authorization check — it does not verify that the requesting user owns or is permitted to access the requested file. Any user (including unauthenticated users) can enumerate sequential integers to retrieve any other user's transcript. This is a textbook IDOR: the internal object reference (the integer filename) is exposed directly in the client-visible URL with no access control mediating it. The transcript of an earlier user (user #1) contains plaintext credentials exposed within the chat message body.

### Signals (detectable from recon)
- URL path contains a bare integer followed by a file extension: /\d+\.(txt|pdf|csv|xml|json|log) — no UUID, no hash, no session token in the filename.
- HTTP 200 response with Content-Type: text/plain (or application/octet-stream) served directly from disk — no template rendering, no auth wrapper.
- Response body is a raw plaintext user-generated document (chat log, invoice, order confirmation) — not a JSON API response.
- The integer in the path is sequential and was assigned to the current session at a value > 1, implying prior records exist.
- No Authorization header, no cookie re-validation, and no CSRF token present in the download GET request.
- Decrementing the integer by 1 (or setting to 1) returns HTTP 200 with different plaintext content — cross-user access confirmed.
- The alternate transcript body contains a line with a plaintext password or credential string belonging to another user.
- POST /login with the extracted credentials returns HTTP 302 redirect — account takeover confirmed.

### Discovery Steps (before attacking)
1. Crawl signal: Spider discovers a URL matching path pattern /[segment]/<integer>.<ext> where ext is txt, pdf, csv, xml, log, or json — any numeric-only filename in a download or file-serving endpoint. Flag this endpoint class immediately as a BAC-03 candidate.
2. Crawl signal: The endpoint appears in response HTML as an href or button action referencing a path with an integer segment. The content category is user-generated (chat logs, invoices, receipts, exports, orders, reports, messages).
3. Crawl signal: The 'View transcript' / 'Download' link rendered in the page HTML contains the integer assigned to the current session. If the integer is 2, 3, or higher, prior transcripts (1, 2, ...) exist and are unguarded.
4. Dynamic detection — step 1: Authenticate as test user. Trigger the flow that generates the file (send a chat message, place an order, etc.). Capture the assigned object integer N from the response link.
5. Dynamic detection — step 2: GET /endpoint/N.txt — expect HTTP 200. Then GET /endpoint/1.txt (or N-1). If the server returns HTTP 200 with a different response body, IDOR is confirmed. A 403/401/404 response means access control is present.
6. Dynamic detection — gating rule: IF path_regex matches /\d+\.(txt|pdf|csv|xml|json|log)/ AND status(N) == 200 AND status(1) == 200 AND body(1) != body(N) THEN classify as BAC-03 IDOR.
7. Dynamic detection — no auth redirect: Response to /endpoint/1.txt must NOT contain Set-Cookie with a new session or a Location header pointing to /login. Absence of auth redirect confirms no ownership gate.
8. Credential harvesting signal: Response body at /endpoint/1.txt contains any of the strings: 'password', 'passwd', 'pass:', 'pwd', 'credentials', or a sequence matching pattern [word]=[value] adjacent to a username indicator. Extract with regex: (?i)(password|pass|pwd)[\s:=]+([\S]+).

### Exploit Steps
1. DISCOVERY STEP 1 — Trigger transcript generation: Send any POST request to the live chat submission endpoint (e.g., POST /chat with body message=hello or equivalent field name surfaced by recon). This causes the server to create a transcript file on disk.
2. DISCOVERY STEP 2 — Fetch your own transcript: Issue GET /download-transcript/2.txt (or whatever integer the server assigned you — inspect the href in the 'View transcript' link in the response HTML or intercept via proxy). The exact path segment varies; common patterns are /download-transcript/<n>.txt, /chat/transcript/<n>.txt, /transcripts/<n>.txt. The integer N is the one assigned to your session.
3. DISCOVERY STEP 3 — Confirm IDOR signal: The URL contains a path segment matching regex /\d+\.txt (or similar extension). The response is HTTP 200, Content-Type: text/plain, body is a raw plaintext chat log. No session cookie re-validation or ownership check occurs.
4. EXPLOIT STEP 1 — Tamper the path integer: Change the integer in the path from your assigned N to N-1 (e.g., if your transcript is /download-transcript/2.txt, request /download-transcript/1.txt). The field to tamper is the numeric path segment embedded directly in the URL — there is no query parameter; the reference is in the path itself.
5. EXPLOIT STEP 2 — If N-1 returns 404, try N=1 directly (/download-transcript/1.txt). The first transcript created is typically the victim's. Also try N+1 if N-1 is empty.
6. EXPLOIT STEP 3 — Read the response body of the tampered request. Scan for credential patterns: lines containing 'password', 'pass', 'pwd', credentials exposed in the chat message body (e.g., 'My password is ...', 'user: <VICTIM_USER> pass: <value>'). The password will appear as plaintext within the transcript text.
7. EXPLOIT STEP 4 — Extract the username and password from the transcript body. The username is typically '<VICTIM_USER>' in this context. Issue POST /login with body username=<VICTIM_USER>&password=<extracted_value> (form-urlencoded). Accept a 302 redirect to the account page as confirmation of successful login.
8. VERIFICATION — Confirm the login response is a 302 redirect (or 200 with authenticated session content) and that the resulting session shows the victim user's account (different username/email than the attacker's session).

### Key Field Names
- `Path segment: the integer component of the URL path (e.g., the '2' in /download-transcript/2.txt) — this is the IDOR reference to tamper. It is embedded in the path, not a query parameter.`
- `File extension: .txt (primary), also .pdf, .csv, .xml, .log, .json in analogous patterns.`
- `Chat submission body field: 'message' (most common), also 'msg', 'text', 'content' — used to trigger transcript creation in the POST to the chat endpoint.`
- `Login form fields: 'username' (or 'user', 'email') and 'password' — used in the final POST /login step with extracted credentials.`
- `The integer N assigned to the attacker's session: visible in the href of the 'View transcript' button rendered in the page HTML after submitting a chat message.`

### Proof of Exploitation
Proof requires two observable conditions: (1) GET /download-transcript/1.txt (or the tampered integer path) returns HTTP 200 with a response body containing plaintext credentials belonging to a different user than the currently authenticated session — specifically a line in the transcript revealing a password value. (2) POST /login with the extracted credentials returns HTTP 302 (redirect to authenticated area) and the resulting session cookie grants access to a different user's account (<VICTIM_USER>). The combination of cross-user 200 response on the integer-decremented path AND successful login with extracted credentials constitutes full exploitation. A single 200 response to the tampered path alone (without successful credential use) constitutes INFO_EXPOSURE_ONLY. The server must NOT return 401/403/404 on the tampered path for the IDOR gate to fire.

### Exec Notes
The exec agent MUST follow a strict ordered chain for this pattern. Step 1: POST to the chat/message endpoint to create a transcript (field name 'message', value any string). Step 2: GET the transcript link from the response HTML — parse the href containing the integer filename to learn N. Step 3: GET /download-transcript/1.txt (hardcode 1 as the victim transcript, not N-1, since N may be 2 if only one prior user exists). Step 4: Parse the response body for password — use regex (?i)(password|pass|pwd)[\\s:=]+([\\S]+) or scan for lines containing 'password'. Step 5: POST /login with username=<VICTIM_USER> (or whatever name appears in the transcript header/body) and the extracted password. Step 6: Verify the login response is 302 or contains authenticated session markers. CRITICAL: Do NOT skip step 1 (transcript generation) — the 'View transcript' link only appears after submitting a message. Do NOT guess the integer; always read N from the rendered link. The body encoding for the chat POST is form-urlencoded (not JSON) in this lab. If GET /download-transcript/1.txt returns 404, try /chat/transcript/1.txt and /transcripts/1.txt as fallbacks.

---

## Multi-Step Process with No Access Control on Confirmation Step
**Pattern:** BAC-05

### Vulnerability
The application implements a multi-step workflow for privileged administrative actions (e.g., role promotion). Access control is enforced on the first step (only admins can initiate the action), but the confirmation step (the final POST with confirmed=true) is not re-checked for authorization. The server assumes that reaching the confirmation step implies prior authorization from step one. An attacker can skip step one entirely and directly POST the confirmation request with a low-privilege session cookie, bypassing all access control. This is a step-skipping / confused deputy broken access control flaw.

### Signals (detectable from recon)
- Same POST endpoint appears twice in proxy history with different parameter sets (one subset for step 1, one superset with confirmed=true for step 2)
- Hidden form field <input type='hidden' name='confirmed' value='true'> in the confirmation page HTML
- JavaScript that auto-submits a second form on user confirmation of a privileged action
- Multi-step wizard UI pattern (e.g., 'Are you sure?' confirmation screen) for any admin action
- Step 1 returns 401/403 with a low-privilege session (ACL exists), Step 2 returns 200 with a low-privilege session (ACL missing) — the response contrast is the definitive signal
- No step-scoped CSRF token on the confirmation request (a per-step token would prevent replay of the confirmation out of order)
- No re-authentication or privilege re-check challenge presented at the confirmation step

### Discovery Steps (before attacking)
1. Authenticate as an admin user and fully walk through any multi-step privileged workflows (role changes, user deletions, account promotions) while proxying traffic through Burp Suite.
2. In Burp Proxy history, identify POST requests to the same endpoint that appear in two variants: one without a confirmation parameter (step 1: e.g., username=<VICTIM_USER>&action=upgrade) and one with a confirmation parameter (step 2: e.g., username=<VICTIM_USER>&action=upgrade&confirmed=true).
3. Note the exact endpoint (e.g., POST /admin-roles), the full parameter set of the confirmation step, and the admin session cookie value.
4. Open a second browser in incognito/private mode, log in as a low-privilege user (e.g., <ATTACKER_USER> / <ATTACKER_PASS>), and capture that session cookie from Burp Proxy history.
5. In Burp Repeater, load the confirmation-step request (step 2). Replace the Cookie header with the low-privilege session cookie and change the username parameter to the low-privilege username. Send the request.
6. If the server returns HTTP 200 or a success redirect instead of 401/403, the confirmation step lacks access control — BAC-05 is confirmed.
7. Automated crawl signal: scan all POST endpoints for parameter-set variants at the same URL. Flag any endpoint where a subset of parameters appears in one request and a superset (adding confirmed=, confirm=, step=, proceed=, or action= variants) appears in another — these are candidate multi-step workflows.

### Exploit Steps
1. Log in as administrator / admin and navigate to the admin panel at /admin.
2. Initiate a role upgrade on any target user (e.g., <VICTIM_USER>) and capture both HTTP requests in Burp Suite.
3. Identify the confirmation request: POST /admin-roles with body username=<VICTIM_USER>&action=upgrade&confirmed=true and the admin session cookie.
4. Send this confirmation request to Burp Repeater.
5. In a separate incognito browser, log in as the attacker account / peter. In Burp Proxy history, locate and copy the session cookie value for the attacker session.
6. In Burp Repeater, modify the confirmation request: (a) replace Cookie: session=<admin_session> with Cookie: session=<attacker_session>, (b) change username=<VICTIM_USER> to username=<ATTACKER_USER>.
7. Send the modified request. The exact exploit HTTP request is: POST /admin-roles HTTP/1.1 | Host: <TARGET_HOST> | Cookie: session=<attacker_session_token> | Content-Type: application/x-www-form-urlencoded | Body: username=<ATTACKER_USER>&action=upgrade&confirmed=true
8. Verify that the response is HTTP 200 or a success redirect (not 401/403). Navigate to /my-account as the attacker account to confirm the role has changed to administrator.

### Key Field Names
- `username`
- `action`
- `confirmed`
- `session (Cookie header)`
- `confirm`
- `step`
- `stage`
- `proceed`

### Proof of Exploitation
The server returns HTTP 200 (or a success redirect) when the confirmation POST is sent with the low-privilege attacker session. Navigating to /my-account as the attacker account shows the account now has administrator role. The application may display a success confirmation banner. A 401 or 403 on the same request would indicate the control is present — only a 2xx/success response on the non-admin session proves the BAC-05 gap exists.

### Exec Notes
Discovery: Crawl all POST endpoints as an admin. For each unique URL, collect all observed parameter sets. Flag URLs where multiple parameter sets exist and one is a strict superset of another (the superset is the confirmation step). No productId or coupon discovery needed — the only required inputs are: (1) the target endpoint (POST /admin-roles), (2) the low-privilege session cookie, (3) the low-privilege username. Replay logic: take the full-parameter-set request (confirmed=true variant), swap the session cookie, swap the username, send. Check response status: 2xx = vulnerable, 4xx = not vulnerable. No brute force or enumeration required — the endpoint and parameters are revealed by the admin workflow crawl alone.

---

## Referer-Based Access Control Bypass
**Pattern:** BAC-02

### Vulnerability
The application gates a privileged action endpoint (/admin-roles) solely on the presence and value of the HTTP Referer header rather than verifying the session owner's role. When a request arrives with Referer pointing to the admin panel (/admin), the server permits the action regardless of whether the session cookie belongs to a low-privilege user. Because the Referer header is entirely client-controlled and can be freely set by any HTTP client or proxy tool, this is not a valid security boundary. The authentication check (session cookie) and the authorization check (Referer header) are fully decoupled — only the weaker one is applied to the sensitive action endpoint. CWE-807: Reliance on Untrusted Inputs in a Security Decision. OWASP A01:2021.

### Signals (detectable from recon)
- Admin sub-action reachable via GET with query parameters: /admin-roles?username=X&action=upgrade — no POST body, no CSRF token.
- Differential response: same endpoint returns 200 with Referer: .../admin present and 401/403 with Referer absent, regardless of session privilege level.
- The /admin panel itself correctly enforces access control (non-admin session denied), but /admin-roles does not — inconsistency between panel gate and action gate.
- No CSRF token on the state-changing action request, making header-only replay trivial.
- Action URL parameters are human-readable and predictable: username=<target>&action=upgrade|downgrade.

### Discovery Steps (before attacking)
1. Spider the application under an authenticated admin session. Record every HTTP request including full headers (especially Referer). Flag all endpoints that appear under /admin* paths.
2. Identify GET-based state-change endpoints: URLs that trigger privilege changes via query parameters (e.g., /admin-roles?username=X&action=upgrade) with no POST body and no CSRF token are the primary target class.
3. For each flagged admin-action endpoint, run a 2x2 differential response test across four request variants: (a) admin session + Referer: .../admin, (b) admin session + no Referer header, (c) non-admin session + Referer: .../admin, (d) non-admin session + no Referer header. If variant (c) returns 200/success and variant (b) returns 401/403/redirect, Referer is the sole gate and the session is not checked.
4. Confirm the /admin panel itself enforces real access control (non-admin session redirects or 403s) — this rules out a completely unprotected admin panel and isolates the vulnerability to the sub-action endpoint.
5. Check whether any CSRF token is required on the action request. Absence of a CSRF token on a state-changing action compounds the Referer-gating vulnerability and makes replay trivially straightforward.

### Exploit Steps
1. Log in as administrator:admin. Navigate to the admin panel. Trigger the 'Upgrade user' action for any user (e.g., <VICTIM_USER>). Intercept this GET request in Burp Suite and send it to Repeater. Confirm the captured request contains: GET /admin-roles?username=<VICTIM_USER>&action=upgrade, a valid admin session cookie, and Referer: https://<TARGET_HOST>/admin.
2. Open a private/incognito browser window. Log in as the attacker account credentials. Copy the session cookie value assigned to this non-admin session.
3. In the non-admin browser, directly navigate to /admin-roles?username=<ATTACKER_USER>&action=upgrade (no Referer header will be sent on direct address-bar navigation). Confirm the server returns 401/403/redirect — this establishes that Referer absence blocks access.
4. In Burp Repeater, modify the captured admin request: replace the Cookie header value with the attacker session cookie; change the username parameter value from <VICTIM_USER> to <ATTACKER_USER>; leave the Referer header unchanged as Referer: https://<TARGET_HOST>/admin.
5. Send the modified request. The server evaluates only the Referer header (points to /admin → allowed) and ignores that the session cookie belongs to a non-admin user. The action succeeds — <ATTACKER_USER> is promoted to administrator.

### Key Field Names
- `Referer`
- `Cookie`
- `username`
- `action`

### Proof of Exploitation
The server returns HTTP 200 (or a redirect to /admin confirming success) on the replayed request. Post-exploitation confirmation: log in as the attacker account credentials in a normal browser session and navigate to /admin — the admin panel is now accessible, proving role elevation succeeded. Alternatively, observe that the server response body or redirect destination for the replayed request matches the success path seen in the original admin-session capture.

### Exec Notes
Discovery phase: spider admin session, collect all requests to /admin* endpoints with headers. Filter for GET requests with action= or role-change parameters. Run differential probe: replay each candidate four times varying session cookie (admin vs non-admin) and Referer header (present vs absent). Flag any endpoint where (non-admin session + Referer present) returns the same 200 as (admin session + Referer present). Exploit phase: no credential brute-force needed. The exploit requires only two valid session cookies (admin and target user) plus the captured action URL. Swap session cookie in the captured admin request, set username to the target account, preserve Referer header, send. Proof check: follow the redirect or re-request the admin panel with the promoted user's session and assert HTTP 200 on /admin.

---

## Forced Browsing / Missing Function-Level Access Control (BAC-06)
**Pattern:** BAC-06

### Vulnerability
The application exposes an admin interface that requires no server-side role check beyond authentication. A regular authenticated user (non-admin) can access admin paths directly — the server checks that a session exists but not that the session has admin privilege. Also covers: authentication bypass via flawed state machine, where the login flow has an intermediate step (role-selector, MFA) that, if dropped, causes the server to default the session to a privileged role.

### Signals (detectable from recon)
- An admin/management/staff path (`/admin`, `/admin/panel`, `/admin/roles`, `/admin/users`) is present in the discovered endpoints.
- auth_diffs shows the admin path returns 200 or 302 for at least one authenticated session (even a low-privilege one), not just for admins.
- The login flow has a redirect to an intermediate step: `/role-selector`, `/choose-account`, `/select-role`, `/account-type`. Dropping that step may grant the caller default admin role.
- Cookies contain a session token (opaque), and no client-side role field — the role is entirely server-side; bypass requires skipping a server flow step rather than tampering a cookie.

### Discovery Steps (before attacking)
1. GET /admin (or /admin/panel, /admin/users, /manage) with the wiener session cookie (normal user). If status is 200 with admin content → BAC-06 confirmed.
2. If 401/403: check if the login flow has an intermediate redirect. In the HUNT phase, look for `/role-selector`, `/select-role`, `/choose-account` in the crawled endpoints. If present, propose BLF-12 (drop that redirect after login).
3. Check whether any admin action endpoint (upgrade, delete, role change) can be reached by a low-priv user — e.g., GET /admin/roles or POST /admin/upgrade with wiener session.

### Key Field Names
- `session (opaque token — carry as-is from the low-priv login)`
- `csrf (from any form on the page — required for POST actions)`
- `/admin, /admin/roles, /admin/panel, /admin/users, /admin/upgrade (typical admin path suffixes)`
- `/role-selector, /choose-account (intermediate login steps — drop to trigger BLF-12)`

### Exec Notes
The exec agent needs only one step if the admin path is directly accessible: GET /admin with the wiener session cookie. If 200 → done. If 401/403 → try BLF-12 path (login again and drop the /role-selector redirect). Never try cookie tamper for this pattern — the session is opaque. The ProofGate requires PRIVILEGED_ACCESS: the wiener session must receive a 200 on an admin-only path.

---

## JSON Mass Assignment / Undocumented Privilege Field Injection (BAC-02)
**Pattern:** BAC-02

### Vulnerability
A POST or PATCH endpoint for account/profile management accepts JSON and stores all submitted fields without a whitelist. The server's ORM layer (ActiveRecord, Mongoose, SQLAlchemy bulk-update, etc.) maps every JSON key to a model attribute — including privileged attributes like `roleid`, `role`, `is_admin`, `admin` that the HTML form does not expose. An attacker who submits the normal email-change body plus `"roleid": 1` elevates their account to admin without going through any authorization step.

### Signals (detectable from recon)
- POST or PATCH to `/my-account/change-email`, `/api/user`, `/profile/update`, or similar with JSON body.
- The HTML form only shows `email`/`username`/`bio` fields — no role field — but the backend accepts arbitrary JSON keys.
- After submitting with the extra field, accessing `/admin` returns 200 (role was elevated server-side).
- No CSRF or HMAC protection on the JSON body (or CSRF token is in a separate header and the body is freely modifiable).

### Discovery Steps (before attacking)
1. Find the account-update endpoint: look for POST/PATCH to paths containing `account`, `profile`, `user`, `settings`, `my-account`, `change-email`.
2. Inspect the existing form to identify the required fields (e.g., `email`, `csrf`).
3. Send the normal request first to confirm it works, then resend with extra fields added to the JSON body: `{"email": "...", "csrf": "...", "roleid": 1}`.
4. After the request, navigate to `/admin` — if 200, mass assignment succeeded.

### Key Field Names
- `roleid` (integer — 1 = admin in many frameworks)`
- `role` (string — try "administrator", "admin")`
- `is_admin` (boolean — try true)`
- `admin` (boolean — try true)`
- `email, csrf (required legitimate fields — include these alongside the injected ones)`

### Exec Notes
Include both the legitimate fields AND the injected privilege field in one request. Do not send just the injected field alone — the server may reject a malformed body. After the POST returns 200, immediately GET /admin to check access. If /admin returns 200 with admin content, EXPLOITED. The ProofGate checks AUTH_BYPASS + PRIVILEGED_ACCESS — both are satisfied when: (1) the POST with roleid changed the role (AUTH_BYPASS evidence: the tampered-field request was accepted), and (2) GET /admin returns 200 (PRIVILEGED_ACCESS). ProofGate may map this to BAC-02 or BAC-06 depending on which path fires first.

---
