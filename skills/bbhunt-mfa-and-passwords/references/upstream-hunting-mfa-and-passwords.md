# Upstream source: mfa-and-passwords (hunting)

Original path: `/tmp/h1res_MrPsycho04_Hunting-Agent/mfa-and-passwords/SKILL.md`

---

---
name: mfa-and-passwords
description: >-
  Hunt MFA / 2FA bypass — 7 distinct patterns. (1) MFA not enforced on sensitive endpoints (password change,
  email change accept without MFA challenge), (2) MFA-step skip via direct navigation to post-login URL, (3)
  MFA-token replay (same code accepted twice), (4) brute-force the 6-digit OTP without rate limit (10^6
  attempts at server speed), (5) race condition on OTP validation, (6) recovery-code dump via /api/me, (7)
  backup factor downgrade (SMS factor with no rate limit). Plus the chain: cookie theft + password oracle +
  no step-up = ATO without MFA challenge. Detection: trace auth flow in Burp, find every state transition,
  check if MFA is middleware-gated vs per-endpoint, check OTP entropy and rate limit on OTP-validate.
  Validate: attacker session reaching post-MFA state. Use when hunting auth bypass, MFA flows, chaining
  primitives toward ATO. Combined with the HackerOne field guide (real disclosed-report data: where it pays,
  quick wins, payload banks). Hunt MFA bypass, OTP flaws, and password policy issues. Use when testing 2FA,
  recovery codes, and login throttling. Backed by 285 disclosed HackerOne reports.
---

# MFA And Passwords — Combined Field Guide

**Merged skill.** This fuses two complementary sources into one reference:

- **Part 1 — HackerOne field guide:** statistics from disclosed reports, "where it pays," quick wins, and curated payload banks.
- **Part 2 — Bug hunter methodology:** autonomous testing priority, canary discipline, crown-jewel targeting, OOB/validation gates, and reporting guidance.

**How to use:** Open with Part 2 for execution discipline (set your canary, know your success/failure gate). Use Part 1 to prioritize targets and pull payloads. Before reporting, run the validation gates in both parts.

---

<!-- ============ PART 1: HACKERONE FIELD GUIDE (data + payloads) ============ -->

# MFA, OTP & Password Attacks — HackerOne field guide

Built from **285** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Signal

- Reports: **285** · paid: **60**
- Median bounty **$500** · p90 **$3,000** · max **$10,000** · total **$64,056**
- Median upvotes **16**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| HackerOne | 20 | $11,000 | 1156 |
| Mail.ru | 31 | $10,307 | 1731 |
| Uber | 7 | $8,000 | 115 |
| Shopify | 5 | $5,500 | 194 |
| Nextcloud | 31 | $4,000 | 586 |
| VK.com | 5 | $3,850 | 73 |
| Eternal | 5 | $3,250 | 153 |
| Superhuman (formerly Grammarly) | 3 | $2,500 | 273 |

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`otp` `mfa` `2fa` `password` `reset` `recovery` `backup`

## Tools

`Burp` · `Turbo Intruder` · `ffuf`

## Escalation chains

- MFA bypass -> ATO.
- OTP brute -> ATO.

## Related

- `auth-bypass` (989 reports)
- `account-takeover` (262 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

## Autonomous Testing Priority

**Try workflow bypasses before brute force — they're faster and more likely to succeed.**

**Pattern 1 — Skip the MFA step entirely (most automatable):**
1. Login with valid credentials → receive a "pre-MFA" session state
2. Without completing MFA, directly access a protected resource (`/dashboard`, `/api/me`, `/account/profile`)
3. If the response returns user data → MFA is enforced only in the UI, not server-side = Critical

**Pattern 2 — OTP replay (reuse a consumed code):**
1. Complete a valid MFA flow to get a working OTP
2. Log out, log in again with the same credentials
3. Submit the same OTP again
4. If accepted → OTP is not invalidated after use

**Pattern 3 — Submit obviously wrong OTP, observe response:**
Try submitting `000000` or `123456`. If the response is 200 or returns a session token, OTP validation is broken or client-side only.

**Pattern 4 — Partial / incremental validation (prefix oracle):**
If a guessed full code is rejected, test whether the server validates the OTP **prefix-by-prefix** instead of all-or-nothing. Submit a short partial code and compare responses:
1. Submit a 1–3 digit value (e.g. `otp=1`, then `otp=12`, …) — for a POST verify endpoint the code goes in the **request body**, not the URL query string, or the server reads an empty value.
2. If a *correct* prefix gives a DIFFERENT response than a wrong one (a success/flag, a distinct message, or a different length/timing), the validator leaks correctness one chunk at a time.
3. Walk the code digit-by-digit: keep the prefix that "responds correct," append 0–9, repeat. This collapses 10^6 brute force to ~10×N guesses (≤60 for a 6-digit code) — very feasible in a bounded test.
This is the go-to when there is no leaked code and no skip/replay path. Some apps award success on *any* correct prefix outright (so a single correct first digit can win — sweep `otp=0,1,…,9` before giving up).
**CRITICAL — stay in ONE session:** re-authenticating (POST /…/login again) regenerates the OTP, throwing away your prefix progress. Do the entire sweep against a single established MFA session; never re-login between guesses.

**On full brute force:** brute-forcing all 10^6 codes is infeasible in a bounded test — but the prefix oracle above (Pattern 4) usually makes it unnecessary. Only attempt full brute force with evidence of no rate limit AND a small key space.

**Proof:** A session token or protected resource data in the response without completing MFA confirms the bypass.

---

## Related Skills & Chains

- **`account-takeover`** — MFA bypass is a primitive; ATO is the destination. Chain primitive: cookie theft (via XSS or session-fixation) + password oracle (login response timing/length diff reveals valid passwords without lockout) + no MFA step-up on password-change endpoint = persistent ATO without ever facing the OTP challenge → password rotated, attacker locks victim out.
- **`race-condition`** — Pattern 5 (OTP race) lives in race-condition territory; load both skills together. Chain primitive: same 6-digit OTP submitted via 20 parallel HTTP/2 streams (single-packet Turbo Intruder attack) before the server marks it used → 1 success + 19 "already-used" → race window confirmed → attacker doesn't need to brute, just guesses once and parallelizes → ATO.
- **`auth-bypass`** — MFA-step-skip is auth-flow bypass at the workflow layer. Chain primitive: pre-MFA cookie issued after password step + direct navigation to `/dashboard` skipping `/mfa` route + server only middleware-gates `/mfa` not `/dashboard` = full post-auth access from password-only state → MFA never enforced because the route gate was misplaced.
- **`misc`** — Recovery-code dump via `/api/me` is a misc-class info disclosure that becomes Critical when chained. Chain primitive: `/api/me` returns full user object including `backup_codes` array (plaintext, never rotated) → attacker with any read-IDOR or XSS exfils backup codes → uses one backup code → MFA satisfied → ATO without OTP knowledge.
- **`security-arsenal`** — Pull the OTP-brute-force payload section (000000-999999 wordlist generator, ffuf rate-limit-evasion patterns with `-t 5 -p 0.5-2`, distributed-IP rotation via proxychains) and the JWT-token-replay table when "MFA satisfied" claim lives in a JWT claim that can be forged.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an MFA bypass that only works when the attacker already has the password. Standalone MFA bypass is High; chained-with-password-oracle is Critical; chained-with-cookie-theft-only is Critical. The chain question separates the two.

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete places, params, headers, flows to look

- Trace every step of the auth flow in Burp: `POST /login` → `GET/POST /login2` or `/login-steps/second` → `POST /otp-verify` → `/mfa/backup-codes` → `/dashboard`. Record which cookie identifies the account during the MFA step (`verify=`, `account=`), which parameter carries the code (`mfa-code`, `verification-code`, `otp`, `code`), and every identity/role field in responses.
- Check whether a valid session exists before the OTP is verified: after the password step, try direct navigation to `/my-account`, `/profile`, `/admin` (PortSwigger "2FA simple bypass").
- Inspect response bodies and status codes of OTP verification for client-side gating signals: `{"success":false}`, `{"requires_2fa":true}`, `actionResult`, HTTP 403 vs 200. Inspect JS bundles for OTP generation logic or a cached plaintext OTP.
- Look for missing integrity: does the verifier check the code is valid *for this user*, and is the code single-use/short-lived? Replay a used OTP and an OTP from your own account against the victim's session.
- Map rate-limit behavior precisely: attempts per time window, whether requesting a new OTP resets the counter, whether the counter is per IP/account/session, and whether `X-Forwarded-For`/VPN rotation resets it.
- Check recovery paths: backup/recovery codes (`/api/me` dumps), stale reset links issued before 2FA was enabled, MFA-disabling endpoints (CSRF/clickjacking targets), OAuth "Continue with Facebook" landing directly on the dashboard, and SMS/email fallback factors.
- Note timing windows: single-request flows that set `session['userid']` then set `enforce_mfa` create a hidden sub-state where a valid logged-in session exists without MFA (PortSwigger race-condition methodology).

- Check whether password-policy issues exist alongside MFA: weak password requirements, no breach check, and unchanged default passwords turn an MFA bypass into a trivially reachable ATO (Cobalt/CVE-2026 context).
- Note whether MFA is optional and can be disabled without re-authentication — the disable endpoint is a CSRF/clickjacking target and a direct "downgrade" primitive.
- Record the OTP transport: SMS is susceptible to SIM swap and interception; email-based "2FA" is really the same knowledge factor verified twice (PortSwigger) — this affects severity framing but is not itself a bypass.
- Check for OTP exposed in accessible HTML/JS, logs, or plaintext in the response when the code is requested (HackerOne MFA guidance).
- Identify whether recovery questions or backup codes are the weakest factor — backup codes are often numeric, never rotated, and dumped by `/api/me`-style endpoints.
- Look for OTP validation on a different endpoint than issuance — a code minted on `/api/otp/request` may be accepted at `/api/mfa/verify` with no session binding.
- Test whether the OTP endpoint accepts a code for any user by parameter (`user_id`, `email`, `phone`) — this is the "missing integrity" class seen in Snapchat's upvoted report.
- Check how many wrong attempts trigger logout/lockout, and whether the counter resets on a *successful* re-login (macro-driven brute force depends on this).
- For passkey/WebAuthn/passwordless flows, check whether a fallback (SMS/email) bypasses the phishing-resistant factor entirely — the fallback is the attack surface.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- Step-skip / forceful browsing: log in with password, then manually request `/my-account` while on the OTP prompt — no second factor needed if middleware only guards `/login2`.
- Account-cookie swap + brute: change `Cookie: verify=wiener` → `verify=carlos` on `GET /login2` to *issue* a code for carlos, then brute `mfa-code` 0000-9999 on `POST /login2` with a Burp macro that re-logs in after each logout (or Turbo Intruder). A `302` is success, not 200.
- Response tampering: intercept `200 {"success":false}` and change to `{"success":true}`; change a 403 to 200, or flip `requires_2fa`/`actionResult`. Synack documented real cases where copying the full success response pasted over the failed one bypassed MFA.
- Missing integrity: request a valid OTP on account A, submit it on account B (same code, different identity cookie). Test backup codes the same way.
- OTP reuse / code leakage: after using a code, submit it again; scrape the initial `/otp-verify` response and dynamic JS (`/a4.13238.app.js`) for the code or its generation logic; content-type switching (JSON→XML) on "Resend Code" to leak the victim's phone number.
- Rate-limit bypass: spam wrong codes until IP block, rotate via VPN/proxy or spoof `X-Forwarded-For`; request a fresh OTP to reset the counter (meet-in-the-middle: parallel OTP requests + brute until one matches).
- CSRF/clickjacking to disable MFA on endpoints that don't re-ask for the password; GET/verb tampering on OTP endpoints (Liferay-style).
- Race the MFA flag: send a login request and a sensitive authenticated request in parallel with HTTP/2 single-packet (Turbo Intruder `engine=Engine.BURP2`, `concurrentConnections=1`, `gate`/`openGate`) during the sub-state where MFA is not yet enforced; also race OTP validation with 20 parallel streams so one succeeds before the code is marked used.
- State-transition tricks: stale reset link issued pre-2FA; lockout-then-login skip; SPA race using a session partially initiated before 2FA was enabled across two browser instances; AiTM proxy (EvilGinx/Tycoon) capturing both password and OTP to replay the session cookie.

- HTTP method bypass: convert `POST /otp-verify` to GET/PUT with the code in the query string — some frameworks route the OTP check only for the expected verb (Liferay-style CVEs).
- Backup-code abuse: apply every OTP test (replay, brute, cross-user, response tampering) to `/mfa/backup-codes` and recovery-code validation as well.
- Content-type confusion: switch the "Resend Code" request from JSON to XML to elicit a response containing the victim's phone number or the code itself.
- Stale pre-2FA reset link: request a password reset before enabling 2FA, enable 2FA, then replay the link — a direct dashboard login without a code is a bypass.
- Lockout skip: enter wrong passwords 10× to trigger a 1–2 hour lockout, wait, then log in with the correct password — some flows skip MFA after the lockout expires.
- Social-login bypass: enable 2FA, log out, then use "Continue with Facebook/Google" — if the IdP flow lands straight on the dashboard, MFA is not enforced on that path.
- SPA race across browser instances: a session partially initiated before 2FA was enabled can be completed afterwards in a second browser to skip the new factor.
- AiTM/session replay: with an authorized phishing simulation, capture both password and OTP through a reverse proxy and replay the resulting session cookie — this proves the *session* is the real bearer of MFA state.
- Push-fatigue / OTP spam: repeated push requests or hundreds of SMS OTPs can be an availability/harassment issue; treat as a separate finding, not a bypass unless access is gained.

### C. Validation / proof bar — how to confirm and avoid false positives

- Prove an attacker session actually reaches the post-MFA state (a protected page or state-changing action), not just that a code was accepted or a response flipped.
- State the precondition honestly: a bypass that requires the password is High standalone; with a password oracle or cookie-theft it is Critical. Do not inflate severity by omitting the chain.
- For brute force, benchmark normal behavior first and show the rate limit is genuinely absent (or reliably bypassed via spoofed IP / OTP-regeneration reset) — a slow-but-present throttle is not "no rate limit".
- Replay the same OTP twice and check the response: a 302 on second use means non-invalidated codes. Re-test after logout and password change to prove persistence.
- Do not count theoretical "AiTM could capture the code" as an app finding — that is a phishing/threat-model note, not a demonstrable server flaw. Preserve evidence of the exact request/response pair that was tampered with and redact session cookies.

- Benchmark the normal flow first: if a wrong OTP returns 403 and a correct one 302, a response-tampering bypass must produce the same 302 and a usable session — not just a 200 with a different body.
- For brute force, repeat attempts with a re-login macro and confirm the OTP actually changes per request; PortSwigger notes a code may reset mid-attack, so a single failed run is not proof of protection.
- A code accepted twice is a clear single-use failure; verify with the *same* session and the *same* code, and re-check after a short delay to rule out a long validity window.
- For cookie-swap brute, remember to first trigger code generation for the victim cookie target (`GET /login2` with `Cookie: account=victim`) — brute-forcing a code that was never issued is a false negative, not a secure MFA.
- Prove the final state with a protected action (e.g. changing the victim's email or reading their data), not just reaching `/my-account` with a 200.
- Distinguish "MFA not enforced" from "MFA satisfied by a different factor": document which factor was actually bypassed and which preconditions (password, session, cookie) the attacker held.
- Push fatigue, SIM swap, and phishing-proxied OTPs are real-world threats but are not server-side app bugs — label them as threat-model notes, not reportable findings, unless the app has a specific control that fails.
- Backup/recovery-code findings need a clean proof that the code was not issued to the attacker legitimately for that account — use two controlled accounts.
- Redact OTP values, session cookies, and other-user PII in screenshots; keep the request/response pair that demonstrates the tampering.

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/web-security/authentication/multi-factor
2. https://www.cobalt.io/blog/bypassing-the-protections-mfa-bypass-techniques-for-the-win
3. https://portswigger.net/web-security/race-conditions
