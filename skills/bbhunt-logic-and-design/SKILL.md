---
name: bbhunt-logic-and-design
description: "Use for workflow abuse, price/quantity math, limits and quotas, multi-step trust, enumeration through behavior, and violations of secure design principles. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Business Logic and Secure-Design Flaws — unified methodology

> **Unified skill.** Built from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus-backed method (this class)

1. Model the state machine on paper: states, transitions, who may trigger each, and what is trusted between steps.
2. Identify check-then-act boundaries and decide where a value is validated vs used. Missing validation at the second use is the bug.
3. Test numeric abuse: negative, zero, fractional, overflow, currency mismatch, and precision rounding.
4. Skip, reorder and replay steps; submit later-step requests without completing earlier ones.
5. Test idempotency and replay: same coupon, invite, withdrawal, or refund used twice.
6. Compare responses for valid/invalid identities to find enumeration that feeds a larger attack.
7. Prove business harm: money moved, quota exceeded, approval bypassed, or another user affected.

### Signals

- Money, credits, coupons, quotas, limits, approvals, or status transitions
- Multi-step flows where a step can be skipped or replayed
- Client-supplied totals, prices, roles, or state
- A workflow that behaves differently when steps arrive out of order

### Kill criteria

- Documented/intended behaviour, even if it feels odd.
- No real consequence — only an unusual internal state.
- Requires privileged operator actions unavailable to an attacker.

### Escalation chains

- Price manipulation -> financial loss.
- Missing rate limit -> OTP/reset brute force -> ATO.
- Workflow skip -> approval bypass -> privileged state change.

### Veteran tip

Scanners cannot reason about business state. This is the class where understanding the app as a user pays the most.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Model the intended state machine, then skip/reorder/replay steps.
- Test negative values, zero, decimals, rounding, and currency confusion in money flows.
- Replay one-time actions: coupons, invites, refunds, withdrawals, votes, trials.
- Check seat/limit counting and plan changes for proration and cancellation abuse.
- Look for trust in client-supplied price, role, plan, timestamp, or status.

### Deeper checklist

- Model the intended workflow and state machine; look for steps that can be skipped, replayed, or reordered.
- Test quantity/price/tax manipulation, negative values, rounding, and currency confusion.
- Replay one-time actions: coupons, invites, refunds, withdrawals, votes, trials.
- Race critical actions and check idempotency (see race-condition skill).
- Test boundary values and overflow in balances, limits, and counters.
- Abuse trial/plan changes: downgrade/upgrade, proration, seat counting, cancellation.
- Look for trust in client-supplied state (price, role, plan, feature flags, timestamps).
- Show concrete financial or access impact, not just unexpected behavior.

### Step-by-Step Hunting Methodology

1. **Map all authentication boundaries.** Spider the target. Identify pages/endpoints that serve authenticated content (employee portals, premium features, order pages) and test each unauthenticated. Look for internal pages indexed in JS bundles or linked from robots.txt/sitemap.xml.

2. **Identify every verification flow.** Enumerate: email verification, phone/SMS verification, payment verification, CAPTCHA, age gates. For each, test: what happens if you skip the verification step entirely? What happens if you replay a valid token on a different account?

3. **Test rate-limiting controls on every form.** For every POST endpoint (subscribe, login, OTP, search), send 50+ rapid requests. Vary: remove cookies, rotate `X-Forwarded-For` / `X-Real-IP` headers, change `User-Agent`. Check if the server uses IP from headers rather than connection IP.

4. **Intercept and tamper with payment flows.** Use Burp Suite to intercept every request between your browser, the application, and the payment provider. Identify where price, currency, order ID, or status fields are set. Attempt to modify amounts to $0.01 or currency to a low-value currency. Look for POST-back/webhook endpoints that accept payment confirmation — test if they validate HMAC/signature.

5. **Test phone/callback number verification.** Whenever a platform accepts a callback number, test: can you set it to a number you don't own? Does the platform call/text that number and grant trust based solely on submission? Try setting it to a victim's number.

6. **Check for unprotected employee/

### A. Discovery checklist — concrete places, params, headers, flows to look

- Adopt the **OWASP Top 10 for Business Logic Abuse (2025)** as a coverage checklist when enumerating features:
  - BLA1 Action Limit Overrun (TOCTOU single-use), BLA2 Concurrent Workflow Order Bypass, BLA3 Object State Manipulation (mass assignment of protected properties), BLA4 Malicious Logic Loop (hidden routines/recursion), BLA5 Artifact Lifetime Exploitation (stale tokens/sessions/temp files), BLA6 Missing Transition Validation, BLA7 Resource Quota Violation, BLA8 Internal State Disclosure (differential errors/timing), BLA9 Broken Access Control in workflows, BLA10 Shadow Function Abuse (forgotten test/internal endpoints).
- For every feature that **dispenses value** — signup bonus, referral, promo, free trial, points, voucher, password-reset, email/SMS sender — run the "dishonest user" exercise: assume the user follows the letter of the rules but optimizes for maximum extraction. Ask which assumptions the developer made about user intent and how breaking each one benefits the user.
- **Write down the invariants** in plain English and find the code that enforces each: "a coupon is redeemable once per user", "a balance can never go negative", "a user cannot approve their own request", "state `approved` requires reviewer A **and** B", "a transfer leaves source ≥ 0". If the answer is "the UI" or "the user won't try that", the invariant is unenforced.
- **Re-derive every security-relevant value server-side** (OWASP Business Logic Security Cheat Sheet, added 2026). Treat all client state as input

### Signals and surfaces

### Signal

- Reports: **931** · paid: **134**
- Median bounty **$500** · p90 **$2,400** · max **$12,000** · total **$134,498**
- Median upvotes **10**

### Where it pays

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

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`quantity` `price` `amount` `coupon` `discount` `plan` `trial` `refund` `withdraw` `balance` `limit` `seat`

### Crown Jewel Targets

Business logic vulnerabilities pay highest in platforms where financial transactions, identity verification, and access controls intersect with real-world consequences. The richest targets are:

- **E-commerce & payment platforms** (Valve/Steam, Shopify) — payment flow manipulation, free goods, price tampering
- **Marketplace & gig economy apps** (Airbnb, Uber) — identity/verification bypass enabling fraud or unsafe interactions
- **SaaS with tiered access** (Mozilla Monitor) — bypassing verification to unlock monitoring features without entitlement
- **High-traffic consumer apps** (Snapchat, Yelp) — rate-limit bypass enabling spam, enumeration, or abuse at scale

Asset types that pay: checkout flows, subscription endpoints, callback/verification systems, webhook handlers, employee/internal portals exposed to the internet, and any endpoint that trusts client-supplied data to make authorization decisions.

---

### Attack Surface Signals

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

### Techniques, payloads and bypasses

### Payloads & probes

- Quantity -> `-1`, `0`, `0.001`, `1e9`, `NaN`, very long decimals
- Price -> change `price=100` to `price=1`, remove the field, send array
- State -> `status=approved`, `paid=true`, `step=3` out of order
- Race -> parallel redeem of the same coupon/withdrawal

### Bypass tricks

- Skip payment by calling the fulfillment endpoint directly.
- Abuse currency/rounding with fractional quantities.
- Reuse idempotency keys or omit them.
- Exploit trial reset via email aliases, domains, or deleted accounts.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Modify in-flight data to payment provider Smart2Pay** — `#1295844` · Valve · $7,500 · ▲443
  > For example, we can change original `Amount=2000` to `Amount2=000` and after contacting it still will be `Amount2000`
- **H1514 Ability to MiTM Shopify PoS Session to Takeover Communications** — `#423467` · Shopify · $0 · ▲372
  > The code actually specifically listens on all local interfaces (`0.0.0.0`) and the wifi network address is specifically used in the QR code connection string, as shown here in…
- **Hackerone is not properly deleting user id** — `#1133118` · HackerOne · $0 · ▲356
  > Optional: Supporting Material/References (Screenshots)
- **Getting New Invitations without Leaving Programs** — `#999789` · HackerOne · $0 · ▲322
  > Yesterday, I sent about 25-30 request with different private programs and I asked `how much pending invitations do I have?` to `support@hackerone.com` and they said `It looks like you currently have 19 pending invitations at this time.`.
- **Race Condition allows to redeem multiple times gift cards which leads to free "money"** — `#759247` · Reverb.com · $0 · ▲308
  > - Now set the external HTTP header `x-request: %s` - This is needed by the turbo intruder
- **An attacker can run pipeline jobs as arbitrary user** — `#894569` · GitLab · $12,000 · ▲307
  > - Go to `Project settings` = `Repository` = `Mirroring repositories`
- **Ethereum account balance manipulation** — `#300748` · Coinbase · $0 · 

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 7× | `Curl_httpsrr_applicable()` |
| 6× | `security@` |
| 6× | `(all)` |
| 5× | `wallet2::sign_tx(unsigned_tx_set &...)` |
| 5× | `gtsatsis@staff.ratelimited.me` |
| 5× | `hostmatch()` |
| 4× | `conn->ssl_config` |
| 4× | `$.extend` |
| 3× | `data:` |
| 3× | `__proto__` |
| 3× | `get_peer_type()` |
| 3× | `ossl_verifyhost()` |
| 3× | `conn_config->CRLfile` |
| 3× | `cr_init_backend()` |
| 2× | `x-request: %s` |
| 2× | `javascript:` |
| 2× | `%00` |
| 2× | `master @ 3ad4a5ee8` |
| 2× | `tester@test.com` |
| 2× | `h1test@example.com` |

### Common Root Causes

1. **Server trusts client-supplied data for financial decisions.** Developers offload price calculation to the frontend or pass amount fields through forms/URLs without re-validating on the server against a canonical source (the product database).

2. **Verification is enforced only in the UI, not the API.** Frontend hides features behind a verification gate, but the backend API endpoints are fully functional without a verified status — any authenticated request succeeds.

3. **IP-based rate limiting reads from spoofable headers.** Developers implement rate limits using `request.headers['X-Forwarded-For']` instead of the actual connection IP, allowing trivial bypass by header manipulation.

4. **Payment webhooks lack signature validation.** Developers implement "success" webhooks without verifying the HMAC signature provided by the payment provider, allowing anyone to POST a fake success notification.

5. **Internal/employee pages aren't access-controlled.** Internal tools are deployed to production domains without authentication middleware, either because developers assume obscurity (unlisted URL) or forgot to apply auth to a new route.

6. **Phone/callback verification is advisory, not enforced.** Systems accept a phone number and grant trust to whoever submitted it, without confirming the submitter owns or controls that number.

7. **Draft/channel-specific storefronts inherit full order functionality.** Platforms like Shopify allow creating storefronts for specific channels (employee events) that are unlisted but still fully functional for order p

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Client-side price tampering**: `POST /cart` with `price=1` (cents) → cart shows the changed price (PortSwigger excessive-trust lab). Escalate from "UI shows wrong price" to an actual placed order at that price.
- **Negative quantity**: `POST /cart {"productId":2,"quantity":-N}` subtracts more than the item's cost; combine a jacket with a negative quantity of a cheap item so the total is positive but below store credit. If the app rejects an all-negative total, top up with a cheap item.
- **Alternating-coupon stacking**: `NEWCUST5` → `SIGNUP30` → `NEWCUST5` … until the balance hits zero; the app rejects immediate reuse of the *same* code but not crossing codes.
- **Workflow step-skip** (PortSwigger insufficient workflow validation): complete a cheap purchase, capture the confirmation `GET /order-confirmation?order-confirmed=true`, add the expensive jacket, then replay that confirmation URL directly. Alternatively intercept the *response* and rewrite the `Location` header to skip validation. State must be server-side and transition-checked; URL obfuscation is not a control.
- **MFA workflow bypass variants**: (a) direct navigate to `/my-account?id=carlos` after password-stage login before entering the code ("2FA simple bypass"); (b) change the `verify` cookie from `wiener` to `carlos`, request `GET /login2` to send *Carlos* a code, then brute the 4-digit `mfa-code` against `POST /login2` and swap in the 302's session cookie. The 2025 paid writeup pattern earned $2,500 on a live program.
- **2FA/

_...and 2 more sections in `references/unified-method.md`._

### Validation and proof

### Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

### Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

### Gate 0 Validation

Before writing any report, answer all three:

1. **What can the attacker DO right now?**
   Be specific: "An unauthenticated user can place an order for physical goods at $0 cost" or "An attacker can bypass email verification and monitor any email address without owning it" or "An attacker can send unlimited subscription emails to any address." Vague impact = reject.

2. **What does the victim LOSE?**
   Identify a concrete, attributable loss: financial loss (free goods, fraudulent payments), privacy loss (phone number spoofed, unauthorized monitoring), service abuse (spam campaigns via rate-limit bypass), or security degradation (unverified identity trusted for sensitive actions). If the loss is purely theoretical, re-evaluate severity.

3. **Can it be reproduced in 10 minutes from scratch?**
   Create a fresh account (or use no account). Follow your documented steps. Achieve the impact. If you can't reliably reproduce it end-to-end in under 10 minutes with the steps you've written, your methodology is incomplete — refine before submitting.

---

### C. Validation / proof bar — how to confirm and avoid false positives

- A scanner-clean app can still be logically broken: always ground the report in a **business invariant that was violated** ("a $1,337 jacket was obtained for $0.01", "user A approved user B's request") and show the monetary/state/PII consequence. "The flow looks weird" is not enough (OWASP's writing is developer-oriented; your report must be impact-oriented).
- Demonstrate the **full chain end to end**: tampered request → observable intermediate state (cart total) → completed privileged/financial outcome (order placed, role granted, other user's data returned). Stopping at "the UI shows a negative price" is often closed as client-side-only.
- Use **two accounts** for workflow/ownership bugs: attacker A must reach B's data or perform a privileged action on B's object. For self-referral/multi-account abuse, show the same device/payment method behind "distinct" users.
- For 2FA bypass, prove access to a sensitive authenticated page — not just a redirect. Capture the exact session cookie state at the bypass moment.
- For coupon stacking/crypto-overflow, record the arithmetic (before/after totals, coupon application order) and confirm the order actually completed at the manipulated price, not merely that the cart displayed it.
- For differential-oracle/BLA8 findings, show that the difference reveals *sensitive state* (account existence with PII, internal step status). A generic error string difference with no sensitive disclosure is usually informational.
- For BLA4/BLA7 resource findings, stay inside aut

### Escalation and related chains

### Escalation chains

- Logic flaw -> free goods/credit.
- Limit bypass -> resource abuse.
- Refund abuse -> financial loss.

### Related Skills & Chains

- **`race-condition`** — Every uniqueness/quota check in a logic flow is a race candidate. Chain primitive: Business logic (coupon/credit/promotion) + race condition → coupon redeemed N times in a single TCP packet via Turbo Intruder.
- **`idor`** — Logic flows that trust a client-supplied identifier (order_id, tenant_id, beneficiary_id) overlap directly with IDOR. Chain primitive: business-logic step-skip + IDOR on beneficiary_id → transfer funds from victim account.
- **`api-misconfig`** — Step-skip and verification-bypass often live next to mass-assignment fields. Chain primitive: business-logic email-verify skip + API mass assignment (`verified:true, role:admin`) → ATO without email control.
- **`account-takeover`** — Logic bugs in password reset, email change, and recovery flows are core ATO paths. Chain primitive: business logic (email change accepts without re-auth) + `account-takeover` Path 2 → silent victim email swap → password reset to attacker mailbox.
- **`security-arsenal`** — Load the Business-Logic Probe Checklist (negative quantity, decimal overflow, currency swap, step-skip via direct URL nav, state-machine reverse) and the Always-Rejected list to avoid filing self-inflicted bugs.
- **`triage-validation`** — Apply the 7-Question Gate (especially Q4 "Is this exploitable by an outside attacker without unrealistic preconditions?"): logic bugs need a concrete dollar/PII/state impact, not just "the flow looks weird".

### Related Skills & Chains

- **`hunt-race-condition`** — Every uniqueness/quota check in a logic flow is a race candidate. Chain primitive: Business logic (coupon/credit/promotion) + race condition → coupon redeemed N times in a single TCP packet via Turbo Intruder.
- **`hunt-idor`** — Logic flows that trust a client-supplied identifier (order_id, tenant_id, beneficiary_id) overlap directly with IDOR. Chain primitive: business-logic step-skip + IDOR on beneficiary_id → transfer funds from victim account.
- **`hunt-api-misconfig`** — Step-skip and verification-bypass often live next to mass-assignment fields. Chain primitive: business-logic email-verify skip + API mass assignment (`verified:true, role:admin`) → ATO without email control.
- **`hunt-ato`** — Logic bugs in password reset, email change, and recovery flows are core ATO paths. Chain primitive: business logic (email change accepts without re-auth) + `hunt-ato` Path 2 → silent victim email swap → password reset to attacker mailbox.
- **`security-arsenal`** — Load the Business-Logic Probe Checklist (negative quantity, decimal overflow, currency swap, step-skip via direct URL nav, state-machine reverse) and the Always-Rejected list to avoid filing self-inflicted bugs.
- **`triage-validation`** — Apply the 7-Question Gate (especially Q4 "Is this exploitable by an outside attacker without unrealistic preconditions?"): logic bugs need a concrete dollar/PII/state impact, not just "the flow looks weird".

### Tools and wordlists

### Tools

`Burp` · `Turbo Intruder` · `custom scripts` · `mitmproxy`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_logic-and-design.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_logic-and-design.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_logic-and-design.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_logic-and-design.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

### Nuclei

No scanner finds business-logic flaws. Use Nuclei for recon, then model the workflow manually.

```sh
nuclei -u https://target -tags vuln,exposure \
       -severity low,medium,high,critical -rl 40 -o nuclei_logic-and-design.txt
nuclei -u https://target -t ~/nuclei-templates/http/exposures \
       -rl 40 -o nuclei_logic-and-design_exposures.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Source skills merged into this topic

- `h1skills` — `hackerone-logic-and-design`
- `hunting` — `logic-and-design`
- `cbh` — `hunt-business-logic`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 2 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `../../upstream/` — complete unmodified archives of all five source repositories
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
