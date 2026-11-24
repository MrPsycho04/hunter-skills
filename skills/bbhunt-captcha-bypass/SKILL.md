---
name: bbhunt-captcha-bypass
description: "Hunt omitted fields, replayed tokens, predictable solutions and client-only enforcement. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# CAPTCHA bypass hunting — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Autonomous Testing Priority

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

**Pattern 5 — Rate/throughpu

### Web-Research Methodology Additions (2026)

Research basis: HackTricks "Captcha Bypass" and PortSwigger Research "Cracking reCAPTCHA, Turbo Intruder style" (James Kettle's single-use-token race). Common framing from both: a CAPTCHA is a **rate-abuse control, not a replacement for authorization, throttling, or account lockout** — test whether the server binds the solution to the intended action, session, challenge and expiry.

### A. Discovery checklist — concrete places, params, headers, flows to look

- **Field names:** `g-recaptcha-response`, `h-captcha-response`, `cf-turnstile-response`, `captcha`, `captcha_token`, `captcha_answer`, `captcha_response`, `captcha_id`, `challenge`, `solve`, `otp`, plus any hidden field toggled by the widget's JS.
- **The four bindings to test:** is the solution tied to (1) a specific action/endpoint, (2) a specific session/cookie, (3) a specific challenge ID, (4) an expiry window? Missing any one is a finding.
- **Where the value comes from:** page source/HTML comments, cookies, JS globals, a hidden input, an API response. HackTricks explicitly recommends inspecting source and cookies for a reusable value.
- **Sibling endpoints missing the gate:** the mobile/API path (`/api/register` vs `/register`), password reset, feedback/contact, coupon redemption, review/vote endpoints. A CAPTCHA on one form says nothing about the others.
- **Method/format surface:** POST→GET or other verbs; `application/x-www-form-urlencoded` → JSON → multipart. A validator written for one parser often silently skips the others.
- **Counter mechanics:** does a normal application flow (reloading the form, changing a cookie, logging in) reset the attempt counter? Is the counter keyed to IP, session, or a device id?
- **Custom-captcha families:** math captchas, finite image sets (count unique images and fingerprint by MD5), text captchas with a small answer space; also the audio/accessibility option.
- **Tooling signals:** Tesseract for character challenges, speech-to-text for audio, OWASP WS

### Techniques, payloads and bypasses

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Omit / empty / null the parameter** entirely (the fastest test), then try `""`, `null`, `0`, `undefined`, and an entirely bogus token. Compare against a baseline that includes a real token.
- **Switch verb and content-type** on the same action — a server-side check applied to form POSTs is frequently absent on GET or JSON bodies.
- **Reuse a solved token:** replay the same `g-recaptcha-response` immediately; reuse it across a different session ID; reuse it on a different endpoint (no action binding). Tokens need not expire to be exploitable.
- **Source/cookie extraction:** if the answer is present in the DOM or a cookie, read it programmatically and submit it with every request.
- **Finite-set automation:** for image captchas, hash the image set and map to answers; for math captchas, evaluate the expression; OCR/STT where needed.
- **Rotate the limiter key:** test-owned session IDs and source IPs, User-Agent/header rotation, and normal flows that reset the counter. Stay within the authorized scope.
- **reCAPTCHA single-use race (second-order TOCTOU).** reCAPTCHA validation happens at the *target website → Google* hop, so the target can be made to race on your behalf. With Turbo Intruder last-byte synchronisation (gate + `openGate`), one solved token can be accepted several times — PortSwigger tripled Reddit registration rate with three concurrent uses. Impact: N× spam accounts and the ability to win races in thread-unsafe code that CAPTCHA was protecting. Defensive fix is to lock/synchronise o

### Validation and proof

### 1. Client-Side-Only CAPTCHA Validation

JavaScript hides/disables the submit button until CAPTCHA is solved, but the server never checks the CAPTCHA token. Direct API calls bypass the UI gate entirely.

### C. Validation / proof bar — how to confirm and avoid false positives

- **Proof = the state-changing action completes without a valid CAPTCHA**, verified against a baseline request that includes one. Account created, login succeeded, form submitted, vote recorded — a rendered widget is not proof.
- **Single-use / binding:** show the same token succeeding twice, succeeding cross-session, or succeeding on a different action. A token that fails on replay is correctly single-use — don't report it.
- **Race proof:** demonstrate multiple accounts/rows created from *one* solved token under concurrency, and show the count. A noisy timing log is not proof.
- **Solver caveat:** programmatically solving a real CAPTCHA with OCR/STT is an automation capability, not by itself a server vulnerability. The finding is the missing/weak server-side enforcement that the solver then exposes.
- **Scope:** don't send third-party challenges, tokens, or screenshots to an external solving service without approval; rotating IPs/accounts must stay inside the engagement scope.

- **Baseline diff:** every "bypass" must be compared against a request with a valid token AND one with a deliberately invalid token — a three-way diff removes ambiguity.
- **Server-side proof:** remove the token in Burp Repeater (not by disabling JS in the browser) — if it still succeeds, the check is truly absent server-side.
- **Reuse proof:** show the *same* token string accepted twice with two different payloads; log only a token prefix in the report, not the full secret.
- **Action-binding proof:** a token solved on `/re

### Escalation and related chains

### Impact Chain

CAPTCHA bypass alone: **Medium** (enables automation of rate-limited actions)

CAPTCHA bypass + login endpoint = **brute force gate removed** → chain with `brute-force` → High/Critical

CAPTCHA bypass + registration endpoint = **account farming** → abuse, spam, resource exhaustion

CAPTCHA bypass + password reset = **token flooding** → chain with `forgot-password`

---

### Related Skills

- **`brute-force`** — CAPTCHA is often the only rate-limit gate; bypass unlocks brute force
- **`forgot-password`** — reset endpoints sometimes protected by CAPTCHA only
- **`race-condition`** — race the CAPTCHA validation window (submit before the token is revoked)

### Impact Chain

CAPTCHA bypass alone: **Medium** (enables automation of rate-limited actions)

CAPTCHA bypass + login endpoint = **brute force gate removed** → chain with `hunt-brute-force` → High/Critical

CAPTCHA bypass + registration endpoint = **account farming** → abuse, spam, resource exhaustion

CAPTCHA bypass + password reset = **token flooding** → chain with `hunt-forgot-password`

---

### Related Skills

- **`hunt-brute-force`** — CAPTCHA is often the only rate-limit gate; bypass unlocks brute force
- **`hunt-forgot-password`** — reset endpoints sometimes protected by CAPTCHA only
- **`hunt-race-condition`** — race the CAPTCHA validation window (submit before the token is revoked)

## Source skills merged into this topic

- `hunting` — `captcha-bypass`
- `cbh` — `hunt-captcha-bypass`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
