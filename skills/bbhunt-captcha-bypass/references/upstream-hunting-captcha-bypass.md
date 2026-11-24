# Upstream source: captcha-bypass (hunting)

Original path: `/tmp/h1res_MrPsycho04_Hunting-Agent/captcha-bypass/SKILL.md`

---

---
name: captcha-bypass
description: "Hunt CAPTCHA Bypass — 6 distinct patterns: (1) CAPTCHA field simply omitted from the request (server-side validation absent), (2) CAPTCHA token replayed from a solved challenge (no single-use enforcement), (3) CAPTCHA response accepted on a different endpoint than it was solved on (no binding to action/session), (4) static or predictable CAPTCHA values accepted (e.g. '0', 'null', empty string), (5) audio/accessibility CAPTCHA trivially solvable programmatically, (6) CAPTCHA only enforced after N failures (first N requests bypass it). Detection: intercept a successful form submission, remove the CAPTCHA field entirely, replay — if it still succeeds, server-side validation is absent. Medium severity standalone; High when it removes the only rate-limit gate protecting a login, registration, or payment endpoint."
---

## Autonomous Testing Priority

**The fastest test: just omit the CAPTCHA field entirely. Most CAPTCHA bypass bugs are client-side-only validation.**

**Pattern 1 — Omit the CAPTCHA field (most common, most automatable):**
1. GET the form/endpoint that shows a CAPTCHA to understand its field name (usually `g-recaptcha-response`, `captcha`, `captcha_token`, `captcha_answer`, `h-captcha-response`)
2. POST the form with ALL fields EXCEPT the CAPTCHA field
3. If the action succeeds (200, redirect, or "success" message) → no server-side CAPTCHA validation
4. Proof: the state-changing action completes without a valid CAPTCHA field (compare against a baseline request that includes it)

**Pattern 2 — Empty or null CAPTCHA value:**
Instead of omitting the field entirely, include it with an empty string, `null`, `0`, or `undefined`:
```
captcha=&email=test@example.com&password=test123
```
Some apps validate field presence but not content.

**Pattern 3 — Replay a previously solved CAPTCHA token:**
1. Complete one legitimate CAPTCHA challenge and capture the `g-recaptcha-response` token
2. Submit a second request immediately with the SAME token value
3. If the second submission also succeeds → token is not single-use (replay attack)
4. A replayed token can be shared across automated requests

**Pattern 4 — Test without CAPTCHA on similar endpoints:**
Some apps add CAPTCHA to the registration form but forget the password reset, API endpoint, or mobile API path (`/api/register` vs `/register`). Try the same action via the API path without any CAPTCHA field.

**Pattern 5 — Rate/throughput-gated "prove you're automated" challenges:**
Some apps define CAPTCHA "bypass" as simply exceeding the rate a human could plausibly sustain —
e.g. "N submissions within T seconds" — checked by a middleware that counts REQUESTS REACHING the
route, not successful outcomes. Garbage/placeholder payloads satisfy this exactly as well as valid
ones, since the counter increments regardless of whether the request's own validation passes.

**Timing note (sliding-window counters):** don't solve this one request at a time — a sequential
pace (seconds between each request) structurally cannot land N requests inside a short sliding
window, and issuing more requests serially does not fix it. A typical failing pattern is 12
requests spread across ~250 seconds when the check requires ~10 requests within 20 seconds.
Instead fire the requests **concurrently** (e.g. `"concurrency": N` on a single request call, or
any parallel-request primitive your tooling offers, with N >= the required count) so they arrive
simultaneously and satisfy the sliding window trivially. Check the endpoint's own
required-field validation first (e.g. a `rating` field that can't be null) so the concurrent
payload is at least well-formed enough to reach the counting middleware, even if other fields
(like the CAPTCHA answer itself) are wrong or reused.

**What to skip in automated testing:** Solving real reCAPTCHA/hCaptcha programmatically (OCR, audio bypass) requires external services. Only attempt if patterns 1-4 fail and the test budget allows.

**Proof:** Any successful state-changing action (account created, login succeeded, form submitted) that completed without a valid CAPTCHA token confirms the bypass.

---

## Vulnerability Classes in This Skill

### 1. Client-Side-Only CAPTCHA Validation
JavaScript hides/disables the submit button until CAPTCHA is solved, but the server never checks the CAPTCHA token. Direct API calls bypass the UI gate entirely.

### 2. CAPTCHA Not Tied to Session or Action
A token solved for login is accepted on the registration endpoint (or any other). The server validates "is this a real CAPTCHA solution?" but not "is this the right solution for THIS action?".

### 3. Single-Use Not Enforced
CAPTCHA tokens (especially reCAPTCHA v2) are meant to be consumed after one use. If the server doesn't revoke them after verification, a single human-solved token becomes reusable for many requests.

### 4. CAPTCHA Added Reactively (Only After N Failures)
Some apps only show CAPTCHA after 3-5 failed login attempts. Before that threshold, no CAPTCHA is required → an attacker can make N-1 attempts per account indefinitely by resetting state between attempts.

### 5. Static or Predictable CAPTCHA
Math CAPTCHAs (`3 + 4 = ?`), simple image CAPTCHAs, or text CAPTCHAs with a finite answer set can be automated. These are custom CAPTCHA implementations, not Google/hCaptcha.

---

## Impact Chain

CAPTCHA bypass alone: **Medium** (enables automation of rate-limited actions)

CAPTCHA bypass + login endpoint = **brute force gate removed** → chain with `brute-force` → High/Critical

CAPTCHA bypass + registration endpoint = **account farming** → abuse, spam, resource exhaustion

CAPTCHA bypass + password reset = **token flooding** → chain with `forgot-password`

---

## Related Skills

- **`brute-force`** — CAPTCHA is often the only rate-limit gate; bypass unlocks brute force
- **`forgot-password`** — reset endpoints sometimes protected by CAPTCHA only
- **`race-condition`** — race the CAPTCHA validation window (submit before the token is revoked)

## Web-Research Methodology Additions (2026)

Research basis: HackTricks "Captcha Bypass" and PortSwigger Research "Cracking reCAPTCHA, Turbo Intruder style" (James Kettle's single-use-token race). Common framing from both: a CAPTCHA is a **rate-abuse control, not a replacement for authorization, throttling, or account lockout** — test whether the server binds the solution to the intended action, session, challenge and expiry.

### A. Discovery checklist — concrete places, params, headers, flows to look

- **Field names:** `g-recaptcha-response`, `h-captcha-response`, `cf-turnstile-response`, `captcha`, `captcha_token`, `captcha_answer`, `captcha_response`, `captcha_id`, `challenge`, `solve`, `otp`, plus any hidden field toggled by the widget's JS.
- **The four bindings to test:** is the solution tied to (1) a specific action/endpoint, (2) a specific session/cookie, (3) a specific challenge ID, (4) an expiry window? Missing any one is a finding.
- **Where the value comes from:** page source/HTML comments, cookies, JS globals, a hidden input, an API response. HackTricks explicitly recommends inspecting source and cookies for a reusable value.
- **Sibling endpoints missing the gate:** the mobile/API path (`/api/register` vs `/register`), password reset, feedback/contact, coupon redemption, review/vote endpoints. A CAPTCHA on one form says nothing about the others.
- **Method/format surface:** POST→GET or other verbs; `application/x-www-form-urlencoded` → JSON → multipart. A validator written for one parser often silently skips the others.
- **Counter mechanics:** does a normal application flow (reloading the form, changing a cookie, logging in) reset the attempt counter? Is the counter keyed to IP, session, or a device id?
- **Custom-captcha families:** math captchas, finite image sets (count unique images and fingerprint by MD5), text captchas with a small answer space; also the audio/accessibility option.
- **Tooling signals:** Tesseract for character challenges, speech-to-text for audio, OWASP WSTG "Testing for Weak Lock Out Mechanism" for the canonical CAPTCHA test cases.

- **Baseline capture:** save one full successful request with a valid token — status, body, headers, resulting state — as the comparison point for every manipulation.
- **Token lifecycle:** note issue time, expiry, endpoint(s) accepted on, and whether the response sets/consumes a cookie; these define the four bindings.
- **Widget-specific fields:** Turnstile (`cf-turnstile-response`), hCaptcha (`h-captcha-response`), reCAPTCHA v3 (`g-recaptcha-response` + `action`/`score`) — v3 score thresholds can be gamed by replaying a high-score token.
- **Where the challenge is enforced:** CDN/WAF layer vs application layer. A WAF-level challenge may be bypassable by reaching origin directly; an app-level check needs a token the app trusts.
- **Downgrade paths:** switch from the hardened client (browser SDK) to a plain HTTP client; many integrations only verify the widget's JS gating.
- **Second-order surface:** any endpoint consuming the same token type (contact form and newsletter signup, e.g.) — cross-endpoint reuse is a distinct finding.
- **Rate-limit interaction:** determine whether the CAPTCHA is the *only* gate. If removing it exposes an uncapped login/OTP endpoint, the impact is that chain, not "CAPTCHA bypass."
- **Counter increments:** send a valid-but-wrong captcha value and confirm whether the failure counter still advances — this is the sliding-window condition in this skill.
- **Audio path:** enumerate the audio challenge endpoint; it often has a far smaller answer set than the image variant.
- **Cookie-bound challenges:** check whether the solution is stored in a cookie and merely echoed back — if so, forge the cookie.
- **Multi-tenant reuse:** a token solved in tenant A accepted in tenant B.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Omit / empty / null the parameter** entirely (the fastest test), then try `""`, `null`, `0`, `undefined`, and an entirely bogus token. Compare against a baseline that includes a real token.
- **Switch verb and content-type** on the same action — a server-side check applied to form POSTs is frequently absent on GET or JSON bodies.
- **Reuse a solved token:** replay the same `g-recaptcha-response` immediately; reuse it across a different session ID; reuse it on a different endpoint (no action binding). Tokens need not expire to be exploitable.
- **Source/cookie extraction:** if the answer is present in the DOM or a cookie, read it programmatically and submit it with every request.
- **Finite-set automation:** for image captchas, hash the image set and map to answers; for math captchas, evaluate the expression; OCR/STT where needed.
- **Rotate the limiter key:** test-owned session IDs and source IPs, User-Agent/header rotation, and normal flows that reset the counter. Stay within the authorized scope.
- **reCAPTCHA single-use race (second-order TOCTOU).** reCAPTCHA validation happens at the *target website → Google* hop, so the target can be made to race on your behalf. With Turbo Intruder last-byte synchronisation (gate + `openGate`), one solved token can be accepted several times — PortSwigger tripled Reddit registration rate with three concurrent uses. Impact: N× spam accounts and the ability to win races in thread-unsafe code that CAPTCHA was protecting. Defensive fix is to lock/synchronise on the `g-recaptcha-response` token.
- **Sliding-window concurrency:** if the gate is "N requests in T seconds," fire N concurrently (see the existing timing note) — garbage placeholder values count because the counter increments regardless of the request's own validation result.
- **Third-party solvers** (e.g. CapSolver-style APIs) are a last resort and must be treated as data processors: only in-scope challenges, no sensitive screenshots or production tokens.

### C. Validation / proof bar — how to confirm and avoid false positives

- **Proof = the state-changing action completes without a valid CAPTCHA**, verified against a baseline request that includes one. Account created, login succeeded, form submitted, vote recorded — a rendered widget is not proof.
- **Single-use / binding:** show the same token succeeding twice, succeeding cross-session, or succeeding on a different action. A token that fails on replay is correctly single-use — don't report it.
- **Race proof:** demonstrate multiple accounts/rows created from *one* solved token under concurrency, and show the count. A noisy timing log is not proof.
- **Solver caveat:** programmatically solving a real CAPTCHA with OCR/STT is an automation capability, not by itself a server vulnerability. The finding is the missing/weak server-side enforcement that the solver then exposes.
- **Scope:** don't send third-party challenges, tokens, or screenshots to an external solving service without approval; rotating IPs/accounts must stay inside the engagement scope.

- **Baseline diff:** every "bypass" must be compared against a request with a valid token AND one with a deliberately invalid token — a three-way diff removes ambiguity.
- **Server-side proof:** remove the token in Burp Repeater (not by disabling JS in the browser) — if it still succeeds, the check is truly absent server-side.
- **Reuse proof:** show the *same* token string accepted twice with two different payloads; log only a token prefix in the report, not the full secret.
- **Action-binding proof:** a token solved on `/register` succeeding on `/reset` is the finding — capture both requests.
- **Hard-lock case:** if the server rejects token reuse, report only the omitted/empty-field variant if that succeeds; do not claim replay.
- **Effect on other users:** a bypass that only lets you spam yourself is informational; show it reaches another account or a shared resource.
- **Response-time check:** a server that always returns 200 but silently drops the action is the CAPTCHA analogue of shadow-throttling; verify the state actually changed.
- **No solved token needed:** if omitting the field works, say so explicitly — it strengthens the finding.
- **Scope hygiene:** note in the report that external solver services were not used (or only on in-scope challenges), so evidence stays reproducible.

### D. Sources — numbered list of URLs you actually fetched

1. https://hacktricks.wiki/en/pentesting-web/captcha-bypass.html
2. https://portswigger.net/research/cracking-recaptcha-turbo-intruder-style
