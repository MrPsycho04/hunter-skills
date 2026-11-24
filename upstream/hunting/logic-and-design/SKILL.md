---
name: logic-and-design
description: >-
  Hunting skill for business logic vulnerabilities. Built from 12 public bug bounty reports. Covers coupon-
  race-stacking (Instacart, Stripe, Reverb), negative-quantity-in-cart price tampering (Upserve,
  Eternal/Zomato), decimal/fraction price-field overflow (Shipt), client-side checkout amount trust on
  PayPal redirect (WordPress.org), price-per-unit mass-assignment (Krisp), and archived-price swap / cart-
  TOCTOU (Stripe). Use when hunting business logic — heavy emphasis on financial-impact-demonstrated cases.
  Combined with the HackerOne field guide (real disclosed-report data: where it pays, quick wins, payload
  banks). Hunt business logic abuse and secure-design violations. Use when testing payments, coupons,
  refunds, quotas, workflows, approvals, or state machines. Backed by 931 disclosed HackerOne reports.
---

# Logic And Design — Combined Field Guide

**Merged skill.** This fuses two complementary sources into one reference:

- **Part 1 — HackerOne field guide:** statistics from disclosed reports, "where it pays," quick wins, and curated payload banks.
- **Part 2 — Bug hunter methodology:** autonomous testing priority, canary discipline, crown-jewel targeting, OOB/validation gates, and reporting guidance.

**How to use:** Open with Part 2 for execution discipline (set your canary, know your success/failure gate). Use Part 1 to prioritize targets and pull payloads. Before reporting, run the validation gates in both parts.

---

<!-- ============ PART 1: HACKERONE FIELD GUIDE (data + payloads) ============ -->

# Business Logic & Design Flaws — HackerOne field guide

Built from **931** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Signal

- Reports: **931** · paid: **134**
- Median bounty **$500** · p90 **$2,400** · max **$12,000** · total **$134,498**
- Median upvotes **10**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| HackerOne | 101 | $17,000 | 4218 |
| GitLab | 9 | $15,320 | 508 |
| Internet Bug Bounty | 12 | $12,960 | 136 |
| Coinbase | 11 | $11,100 | 851 |
| Valve | 3 | $10,000 | 615 |
| Mail.ru | 18 | $7,507 | 628 |
| Augur | 2 | $7,000 | 54 |
| Reddit | 5 | $5,500 | 357 |

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`quantity` `price` `amount` `coupon` `discount` `plan` `trial` `refund` `withdraw` `balance` `limit` `seat`

## Tools

`Burp` · `Turbo Intruder` · `custom scripts` · `mitmproxy`

## Escalation chains

- Logic flaw -> free goods/credit.
- Limit bypass -> resource abuse.
- Refund abuse -> financial loss.

## Related

- `race-condition` (97 reports)
- `authz-bypass` (1,386 reports)
- `dos` (66 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

## Crown Jewel Targets

Business logic vulnerabilities pay highest in platforms where financial transactions, identity verification, and access controls intersect with real-world consequences. The richest targets are:

- **E-commerce & payment platforms** (Valve/Steam, Shopify) — payment flow manipulation, free goods, price tampering
- **Marketplace & gig economy apps** (Airbnb, Uber) — identity/verification bypass enabling fraud or unsafe interactions
- **SaaS with tiered access** (Mozilla Monitor) — bypassing verification to unlock monitoring features without entitlement
- **High-traffic consumer apps** (Snapchat, Yelp) — rate-limit bypass enabling spam, enumeration, or abuse at scale

Asset types that pay: checkout flows, subscription endpoints, callback/verification systems, webhook handlers, employee/internal portals exposed to the internet, and any endpoint that trusts client-supplied data to make authorization decisions.

---

## Attack Surface Signals

**URL patterns to watch:**
- `/checkout`, `/order`, `/subscribe`, `/payment`, `/verify`, `/confirm`, `/callback`
- `/internal`, `/employee`, `/summit`, `/staff`, `/admin` — internal pages accidentally public
- `/api/v*/payment`, `/api/v*/notify`, `/webhook` — payment provider callbacks
- Endpoints accepting `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP` headers

**Response/header signals:**
- `Set-Cookie` with unvalidated session state tied to cart or order data
- Payment provider names in responses: `Smart2Pay`, `Stripe`, `PayPal`, `Braintree`
- Redirect chains through third-party payment pages (in-flight data opportunity)
- `200 OK` on subscription/verification endpoints with no CAPTCHA or token

**JS patterns:**
- Hardcoded internal URLs in frontend bundles (`/employee/`, `/staff/`, `/internal/`)
- Client-side price calculation before server submission
- Verification logic that only checks on the frontend (`if (verified) { ... }`)
- `fetch('/api/subscribe', { method: 'POST', body: ... })` with no anti-CSRF token or rate-limit token

**Tech stack signals:**
- Shopify storefronts with draft/unpublished channel pages
- Apps using IP-based rate limiting without session/account binding
- Payment webhooks with no HMAC signature validation
- SMS/phone callback flows that don't verify ownership before enabling features

---

## Step-by-Step Hunting Methodology

1. **Map all authentication boundaries.** Spider the target. Identify pages/endpoints that serve authenticated content (employee portals, premium features, order pages) and test each unauthenticated. Look for internal pages indexed in JS bundles or linked from robots.txt/sitemap.xml.

2. **Identify every verification flow.** Enumerate: email verification, phone/SMS verification, payment verification, CAPTCHA, age gates. For each, test: what happens if you skip the verification step entirely? What happens if you replay a valid token on a different account?

3. **Test rate-limiting controls on every form.** For every POST endpoint (subscribe, login, OTP, search), send 50+ rapid requests. Vary: remove cookies, rotate `X-Forwarded-For` / `X-Real-IP` headers, change `User-Agent`. Check if the server uses IP from headers rather than connection IP.

4. **Intercept and tamper with payment flows.** Use Burp Suite to intercept every request between your browser, the application, and the payment provider. Identify where price, currency, order ID, or status fields are set. Attempt to modify amounts to $0.01 or currency to a low-value currency. Look for POST-back/webhook endpoints that accept payment confirmation — test if they validate HMAC/signature.

5. **Test phone/callback number verification.** Whenever a platform accepts a callback number, test: can you set it to a number you don't own? Does the platform call/text that number and grant trust based solely on submission? Try setting it to a victim's number.

6. **Check for unprotected employee/internal surfaces.** Search Shodan, GitHub, JS bundles, and Wayback Machine for internal subdomain/path references. Test access without authentication. Check if these surfaces allow order placement, data access, or privilege escalation.

7. **Validate business impact.** For each finding, determine: does this result in financial loss, unauthorized access, or data exposure? Document the end-to-end chain.

---

## Common Root Causes

1. **Server trusts client-supplied data for financial decisions.** Developers offload price calculation to the frontend or pass amount fields through forms/URLs without re-validating on the server against a canonical source (the product database).

2. **Verification is enforced only in the UI, not the API.** Frontend hides features behind a verification gate, but the backend API endpoints are fully functional without a verified status — any authenticated request succeeds.

3. **IP-based rate limiting reads from spoofable headers.** Developers implement rate limits using `request.headers['X-Forwarded-For']` instead of the actual connection IP, allowing trivial bypass by header manipulation.

4. **Payment webhooks lack signature validation.** Developers implement "success" webhooks without verifying the HMAC signature provided by the payment provider, allowing anyone to POST a fake success notification.

5. **Internal/employee pages aren't access-controlled.** Internal tools are deployed to production domains without authentication middleware, either because developers assume obscurity (unlisted URL) or forgot to apply auth to a new route.

6. **Phone/callback verification is advisory, not enforced.** Systems accept a phone number and grant trust to whoever submitted it, without confirming the submitter owns or controls that number.

7. **Draft/channel-specific storefronts inherit full order functionality.** Platforms like Shopify allow creating storefronts for specific channels (employee events) that are unlisted but still fully functional for order placement if the URL is known.

---

## Gate 0 Validation

Before writing any report, answer all three:

1. **What can the attacker DO right now?**
   Be specific: "An unauthenticated user can place an order for physical goods at $0 cost" or "An attacker can bypass email verification and monitor any email address without owning it" or "An attacker can send unlimited subscription emails to any address." Vague impact = reject.

2. **What does the victim LOSE?**
   Identify a concrete, attributable loss: financial loss (free goods, fraudulent payments), privacy loss (phone number spoofed, unauthorized monitoring), service abuse (spam campaigns via rate-limit bypass), or security degradation (unverified identity trusted for sensitive actions). If the loss is purely theoretical, re-evaluate severity.

3. **Can it be reproduced in 10 minutes from scratch?**
   Create a fresh account (or use no account). Follow your documented steps. Achieve the impact. If you can't reliably reproduce it end-to-end in under 10 minutes with the steps you've written, your methodology is incomplete — refine before submitting.

---

## Real Impact Examples

**Scenario 1 — Free Physical Goods via Exposed Internal Storefront (Shopify-style)**
An employee summit page was deployed to a public Shopify storefront as a private channel for distributing free books to staff. The URL was discoverable via JS bundle analysis or link sharing. An anonymous user who navigated to the URL could browse and complete a checkout with no authentication required, receiving physical merchandise shipped at the company's expense. Impact: direct financial loss per order, potential for bulk ordering if not caught quickly.

**Scenario 2 — Payment Manipulation via In-Flight Tampering (Valve/Steam-style)**
A payment flow passed order amount and currency through client-controlled parameters before redirecting to a third-party payment provider (Smart2Pay). By intercepting the redirect with Burp Suite and modifying the amount field, an attacker could complete a real payment for $0.01 while the application's webhook — lacking HMAC validation — accepted the provider's confirmation and credited the full item/service to the account. Impact: critical financial loss; attacker receives full value goods/services for near-zero cost, infinitely repeatable.

**Scenario 3 — Email Verification Bypass for Unauthorized Monitoring (Mozilla-style)**
A breach-monitoring service required email verification before enabling monitoring alerts for an address. The verification check was enforced in the UI flow but the underlying API accepted monitoring setup requests for any address using a valid session — skipping the verification step entirely. An attacker could set up monitoring for email addresses they don't own, receiving breach notification data (potentially including credential exposure status) for victim accounts. Impact: privacy violation; attacker gains intelligence on whether a target's email was in a breach without the target's knowledge or consent.

---

## Disclosed Report Citations (Backfill +5 — 2016-2023)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill. All five share a measurable financial-impact angle (actual $ loss demonstrated or quantifiable platform-wide exposure).

8. **Stripe — Fee discount race redemption** ([H1 #1849626](https://hackerone.com/reports/1849626))
    - Subclass: coupon/discount race-multi-redemption + financial primitive
    - Payload: Stripe Support applied a one-time $20,000 fee-credit. Researcher captured the "accept-discount" POST and replayed it 30× in parallel via Burp Turbo Intruder, each acceptance crediting the account anew
    - Root cause: idempotency missing on discount-acceptance endpoint; no unique constraint on (account_id, discount_id)
    - Year: 2023 — **$5,000**, $600,000 of fee-free transactions accrued before fix (~$18,000 real Stripe loss at 3% take rate)

9. **Reverb.com — Gift-card race multi-redemption** ([H1 #759247](https://hackerone.com/reports/759247))
    - Subclass: gift-card / store-credit race-redemption
    - Payload: single valid gift card, parallel-POST to `/redeem` from 10 sockets via Turbo Intruder. Balance credits N× the face value
    - Root cause: no row-level lock on gift_card table; balance debit and credit live in separate transactions
    - Year: 2019 — **$1,500**

10. **Upserve / OLO — Negative-quantity price manipulation** ([H1 #364843](https://hackerone.com/reports/364843))
    - Subclass: negative-quantity-in-cart price tampering
    - Payload: `POST /api/order {"items":[{"id":1,"qty":1,"price":50},{"id":2,"qty":-3,"price":50}]}` — order total computes to `-$100`, floors to ~$0 at payment capture, food still fulfills
    - Root cause: server multiplies `qty * price` with no `qty >= 1` guard
    - Year: 2018 — textbook citation for the subclass (acknowledged-only program)

11. **Krisp — Pay-less-per-seat via PUT tampering** ([H1 #1446090](https://hackerone.com/reports/1446090))
    - Subclass: price-per-unit mass-assignment / quantity-discount manipulation
    - Payload: `PUT /v2/seats` body includes a server-trusted `price` field. Set `price=1` instead of $60. Subscription updates, billing engine charges $1/seat for 100 seats
    - Root cause: server reads price from request body instead of looking it up by plan_id; classic mass-assignment
    - Year: 2021 — Stripe-billed SaaS pricing exposure

12. **Stripe — Pay using archived price via mid-flow swap** ([H1 #1328278](https://hackerone.com/reports/1328278))
    - Subclass: cart-state TOCTOU / cancel-then-deliver (price-version race at checkout)
    - Payload: merchant archives an old price (e.g., $5 instead of new $50). Buyer starts checkout via the new payment-link, then mid-flow swaps `price_id` back to the archived one. Stripe charges $5; subscription provisions at the new tier
    - Root cause: payment-link validates "is active", price object validates "exists" — but the join "price.active AND price ∈ link.allowed_prices" is missing
    - Year: 2021 — Stripe Medium (per-subscription recurring loss)

---

## Related Skills & Chains

- **`race-condition`** — Every uniqueness/quota check in a logic flow is a race candidate. Chain primitive: Business logic (coupon/credit/promotion) + race condition → coupon redeemed N times in a single TCP packet via Turbo Intruder.
- **`idor`** — Logic flows that trust a client-supplied identifier (order_id, tenant_id, beneficiary_id) overlap directly with IDOR. Chain primitive: business-logic step-skip + IDOR on beneficiary_id → transfer funds from victim account.
- **`api-misconfig`** — Step-skip and verification-bypass often live next to mass-assignment fields. Chain primitive: business-logic email-verify skip + API mass assignment (`verified:true, role:admin`) → ATO without email control.
- **`account-takeover`** — Logic bugs in password reset, email change, and recovery flows are core ATO paths. Chain primitive: business logic (email change accepts without re-auth) + `account-takeover` Path 2 → silent victim email swap → password reset to attacker mailbox.
- **`security-arsenal`** — Load the Business-Logic Probe Checklist (negative quantity, decimal overflow, currency swap, step-skip via direct URL nav, state-machine reverse) and the Always-Rejected list to avoid filing self-inflicted bugs.
- **`triage-validation`** — Apply the 7-Question Gate (especially Q4 "Is this exploitable by an outside attacker without unrealistic preconditions?"): logic bugs need a concrete dollar/PII/state impact, not just "the flow looks weird".

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete places, params, headers, flows to look

- Adopt the **OWASP Top 10 for Business Logic Abuse (2025)** as a coverage checklist when enumerating features:
  - BLA1 Action Limit Overrun (TOCTOU single-use), BLA2 Concurrent Workflow Order Bypass, BLA3 Object State Manipulation (mass assignment of protected properties), BLA4 Malicious Logic Loop (hidden routines/recursion), BLA5 Artifact Lifetime Exploitation (stale tokens/sessions/temp files), BLA6 Missing Transition Validation, BLA7 Resource Quota Violation, BLA8 Internal State Disclosure (differential errors/timing), BLA9 Broken Access Control in workflows, BLA10 Shadow Function Abuse (forgotten test/internal endpoints).
- For every feature that **dispenses value** — signup bonus, referral, promo, free trial, points, voucher, password-reset, email/SMS sender — run the "dishonest user" exercise: assume the user follows the letter of the rules but optimizes for maximum extraction. Ask which assumptions the developer made about user intent and how breaking each one benefits the user.
- **Write down the invariants** in plain English and find the code that enforces each: "a coupon is redeemable once per user", "a balance can never go negative", "a user cannot approve their own request", "state `approved` requires reviewer A **and** B", "a transfer leaves source ≥ 0". If the answer is "the UI" or "the user won't try that", the invariant is unenforced.
- **Re-derive every security-relevant value server-side** (OWASP Business Logic Security Cheat Sheet, added 2026). Treat all client state as input: `price`, `subtotal`, `discountAmount`, `tax`, `shippingCost`, `total`, `visibility`, `sourceBalance`, `userId`, `tenantId`, `role`, `verified`, `taxExempt`. Accept identifiers/quantities only; look up prices/permissions in the DB.
- **Workflow/state-machine probes**: for any multi-step flow (signup, checkout, KYC, approval, password reset), call the final endpoint directly, skip steps, repeat completed steps, reorder steps, and replay a completed step. Check for state held in hidden form fields or client-readable cookies — that is not enforcement. Check that partial states expire (long-lived half-completed workflows are a frequent inconsistency source).
- **Semantic input validation**: a value can be perfectly formatted and still business-invalid. Probe negative quantity, zero/negative price, quantity above stock, checkout date before check-in, amount above account/regulatory limit, currency switched mid-transaction (USD → weaker unit with amount unchanged), amount kept while currency changes.
- **Coupon/promo logic**: test stacking two codes that were meant to be mutually exclusive (PortSwigger lab alternates `NEWCUST5` and `SIGNUP30` to drive price to zero), reusing one code, applying to excluded products, and applying after the price was computed.
- **Integer/float overflow**: push quantity until the total wraps (PortSwigger low-level lab: 32-bit signed wrap at 2,147,483,647 → negative total, then add a cheap item to land between $0 and store credit). Also test decimal precision/rounding on fractional prices.
- **Abuse-friendly feature signals**: self-referral (referrer == referee different accounts), multi-accounting with one payment method/device, free-trial reset by cancel/re-signup, unbounded email/SMS/webhook triggers, and behavior-based enumeration (different reset messages for valid/invalid emails).
- **Differential-oracle ("internal state disclosure") endpoints**: compare responses for valid vs invalid input — message text, status code, timing, visual change, cache headers. BLA8 covers these as groundwork-for-fraud findings when the difference reveals sensitive state.
- **Shadow functions (BLA10)**: internal/test/debug endpoints, unauthenticated admin utilities, old API versions with weaker rules, GraphQL mutations never called by the UI, `/actuator`, `/debug`, `/swagger`. These are gold for step-skip chains.
- **Quota layers to enumerate**: per-action cap, per-account lifetime cap, and per-source (device/payment method/phone) cap. A single cap with no cross-layer enforcement is usually bypassable via multi-accounting — test the same identity signal across three fresh accounts.
- **Audit trail as an oracle**: if the app logs value-dispensing operations, request your own logs (or an export) after abuse tests. Missing entries for a granted bonus/credit prove the invariant is unenforced even when the UI looks consistent.
- **Decimal and rounding boundaries**: amounts `0.001`, `0.01`, `0.1`, `1.005`, `-0.01`, and values at currency minor-unit precision; check whether rounding happens before or after discount/tax. Repeat a small rounding gain at scale to establish material impact.
- **Free-trial eligibility key**: check whether trial status is tied to a cheap identifier (email) rather than a stable one (payment method/device/KYC). Cancel-and-re-signup with a new email is the canonical reset test.
- For any "atomic" claim, look for **multi-store operations** — a DB row plus a session value, a cache plus a DB, a queue plus a ledger. OWASP explicitly warns against using one storage layer to secure another (e.g., sessions cannot enforce a database limit-overrun rule).

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Client-side price tampering**: `POST /cart` with `price=1` (cents) → cart shows the changed price (PortSwigger excessive-trust lab). Escalate from "UI shows wrong price" to an actual placed order at that price.
- **Negative quantity**: `POST /cart {"productId":2,"quantity":-N}` subtracts more than the item's cost; combine a jacket with a negative quantity of a cheap item so the total is positive but below store credit. If the app rejects an all-negative total, top up with a cheap item.
- **Alternating-coupon stacking**: `NEWCUST5` → `SIGNUP30` → `NEWCUST5` … until the balance hits zero; the app rejects immediate reuse of the *same* code but not crossing codes.
- **Workflow step-skip** (PortSwigger insufficient workflow validation): complete a cheap purchase, capture the confirmation `GET /order-confirmation?order-confirmed=true`, add the expensive jacket, then replay that confirmation URL directly. Alternatively intercept the *response* and rewrite the `Location` header to skip validation. State must be server-side and transition-checked; URL obfuscation is not a control.
- **MFA workflow bypass variants**: (a) direct navigate to `/my-account?id=carlos` after password-stage login before entering the code ("2FA simple bypass"); (b) change the `verify` cookie from `wiener` to `carlos`, request `GET /login2` to send *Carlos* a code, then brute the 4-digit `mfa-code` against `POST /login2` and swap in the 302's session cookie. The 2025 paid writeup pattern earned $2,500 on a live program.
- **2FA/OTP race + logic**: aliases in GraphQL or single-packet bursts can process multiple OTP attempts before a failure counter persists — combine with `race-condition`.
- **Artifact lifetime (BLA5)**: replay password-reset links, email-verification links, invite tokens, and temporary file URLs after use or after expiry. Test "consume once" by reusing the same token from a second browser/IP.
- **Distributed workflow order bypass (BLA2)**: run the final step concurrently with its prerequisites (shipping + payment validation, approval + KYC completion) — often the same primitive as a race but framed as a broken state machine.
- **Malicious logic loop (BLA4)**: find endpoints that call an internal routine with no loop-exit/recursion limit or gating — e.g. repeatedly invoking a chain of internal redirects/webhooks that each trigger the next, amplifying one request into many (respect authorization; DoS-class).
- **Resource quota (BLA7)**: per-feature abuse rather than global rate limits — hammer an endpoint that sends email, renders PDFs, or consumes AI tokens until one user degrades others.
- **Object state manipulation (BLA3)** is the bridge to `api-misconfig`: bind `role`, `verified`, `blocked`, `price`, `owner_id` into an update request. Combine a workflow step-skip with `verified:true, role:admin` for full ATO.
- **Ownership re-check omission**: check ownership *on every request*, not just when the resource is loaded. A URL/reference ID that was authorized once is not proof the next request is authorized.

### C. Validation / proof bar — how to confirm and avoid false positives

- A scanner-clean app can still be logically broken: always ground the report in a **business invariant that was violated** ("a $1,337 jacket was obtained for $0.01", "user A approved user B's request") and show the monetary/state/PII consequence. "The flow looks weird" is not enough (OWASP's writing is developer-oriented; your report must be impact-oriented).
- Demonstrate the **full chain end to end**: tampered request → observable intermediate state (cart total) → completed privileged/financial outcome (order placed, role granted, other user's data returned). Stopping at "the UI shows a negative price" is often closed as client-side-only.
- Use **two accounts** for workflow/ownership bugs: attacker A must reach B's data or perform a privileged action on B's object. For self-referral/multi-account abuse, show the same device/payment method behind "distinct" users.
- For 2FA bypass, prove access to a sensitive authenticated page — not just a redirect. Capture the exact session cookie state at the bypass moment.
- For coupon stacking/crypto-overflow, record the arithmetic (before/after totals, coupon application order) and confirm the order actually completed at the manipulated price, not merely that the cart displayed it.
- For differential-oracle/BLA8 findings, show that the difference reveals *sensitive state* (account existence with PII, internal step status). A generic error string difference with no sensitive disclosure is usually informational.
- For BLA4/BLA7 resource findings, stay inside authorization: bounded amplification measurement, no real outage, and document the per-request multiplier. Many programs reject pure DoS claims without demonstrated business impact.
- Avoid self-inflicted bugs: if you had to modify client-side state that the server correctly ignores, or the "bypass" only affects data you already own with no privilege change, do not report. Apply the 7-Question Gate, especially exploitability by an outside attacker with realistic preconditions.
- Mention the OWASP BLA category name and the exact invariant in the title/first paragraph — it gives triagers a familiar taxonomy anchor for an otherwise hard-to-classify bug.

### D. Sources — numbered list of URLs you actually fetched

1. https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html
2. https://owasp.org/projects/top-10-for-business-logic-abuse?tab=top10
3. https://github.com/OWASP/www-project-top-10-for-business-logic-abuse/blob/master/docs/the-top-10/missing-transition-validation.md
4. https://wstg.owasp.org/latest/14-Business_Logic/06-Circumvention_of_Work_Flows/
5. https://portswigger.net/web-security/logic-flaws
6. https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-high-level
7. https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-low-level
8. https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-excessive-trust-in-client-side-controls
9. https://yashfren.net/blogs/businesslogicvulnerabilities-portswiggerlabs-walkthrough/
