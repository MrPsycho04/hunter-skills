---
name: bbhunt-mfa-and-passwords
description: "Use for 2FA bypass, OTP brute force/replay, factor-disabling logic, password policy issues, and recovery-flow abuse. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# MFA, OTP and Password-Recovery Flaws — unified methodology

> **Unified skill.** Built from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus-backed method (this class)

1. Map the factor lifecycle: enrol, challenge, verify, disable, reset, remembered device.
2. Test whether a later step can be reached without completing verification (direct request, parameter toggle, response manipulation).
3. Test OTP replay, reuse across accounts, acceptance of old codes, and codes issued to a different identity.
4. Assess brute-force feasibility against the actual lockout rule, including rate-limit resets via session/IP/parameter changes.
5. Check backup-code and recovery paths for single-use enforcement and ownership binding.
6. Prove an authentication-state change to an account you do not legitimately control.

### Signals

- OTP/2FA enrollment, verification, backup codes, remember-device
- No rate limit or rate limit that resets on a new session/IP/parameter
- OTP accepted out of order, replayed, or from a prior step
- Password reset or change flow that skips current-password verification

### Kill criteria

- Requires the victim's second factor or an already authenticated session.
- Rate limit is effective across all reset vectors.
- Self-only configuration weakness.

### Escalation chains

- Missing rate limit -> OTP brute force -> ATO.
- MFA disable CSRF -> persistent access.

### Veteran tip

Treat the recovery path as part of MFA — most real bypasses are in reset/disable, not in the OTP check itself.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Test OTP brute force limits, reuse, expiry, and response leakage.
- Try MFA bypass via direct navigation, API calls, and remember-me tokens.
- Check backup-code generation and storage.
- Test password reset/change for missing current-password checks.

### Deeper checklist

- Test OTP brute force limits, reuse, expiry, and response leakage.
- Try MFA bypass by direct navigation, API calls, and remember-me tokens.
- Check backup-code generation and storage.
- Test password reset and change flows for missing current-password checks.
- Look for user enumeration via timing and error messages.
- Prove bypass into a protected account or area.

### Autonomous Testing Priority

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
3. Walk the code digit-by-digit: keep the prefix that "responds correct," append 0

### A. Discovery checklist — concrete places, params, headers, flows to look

- Trace every step of the auth flow in Burp: `POST /login` → `GET/POST /login2` or `/login-steps/second` → `POST /otp-verify` → `/mfa/backup-codes` → `/dashboard`. Record which cookie identifies the account during the MFA step (`verify=`, `account=`), which parameter carries the code (`mfa-code`, `verification-code`, `otp`, `code`), and every identity/role field in responses.
- Check whether a valid session exists before the OTP is verified: after the password step, try direct navigation to `/my-account`, `/profile`, `/admin` (PortSwigger "2FA simple bypass").
- Inspect response bodies and status codes of OTP verification for client-side gating signals: `{"success":false}`, `{"requires_2fa":true}`, `actionResult`, HTTP 403 vs 200. Inspect JS bundles for OTP generation logic or a cached plaintext OTP.
- Look for missing integrity: does the verifier check the code is valid *for this user*, and is the code single-use/short-lived? Replay a used OTP and an OTP from your own account against the victim's session.
- Map rate-limit behavior precisely: attempts per time window, whether requesting a new OTP resets the counter, whether the counter is per IP/account/session, and whether `X-Forwarded-For`/VPN rotation resets it.
- Check recovery paths: backup/recovery codes (`/api/me` dumps), stale reset links issued before 2FA was enabled, MFA-disabling endpoints (CSRF/clickjacking targets), OAuth "Continue with Facebook" landing directly on the dashboard, and SMS/email fallback factors.
- Note timing windows:

### Signals and surfaces

### Signal

- Reports: **285** · paid: **60**
- Median bounty **$500** · p90 **$3,000** · max **$10,000** · total **$64,056**
- Median upvotes **16**

### Where it pays

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

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`otp` `mfa` `2fa` `password` `reset` `recovery` `backup`

### Techniques, payloads and bypasses

### Payloads & probes

- OTP -> `000000`, reuse old code, race multiple codes
- MFA -> call the post-MFA endpoint directly
- Password -> `password[]=x`, type juggling
- Enumeration -> response length/timing variants

### Bypass tricks

- Bypass step-up auth by replaying a privileged session.
- Use unicode/whitespace variants of the password.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Improper Authentication - any user can login as other user with otp/logout & otp/login** — `#921780` · Snapchat · $0 · ▲972
  > - Attacker performs `/scauth/otp/login` request with username equal victim's username, and the token obtained on previous step.
- **Change phone number OTP flaw leads to any phone number takeover** — `#2588329` · inDrive · $2,000 · ▲241
  > When an user requests a phone number change inside the app, it will send a 4 digit code but if you place 0000, it will accept any number and update it into the app!!
- **Hacker can bypass 2FA requirement and reporter blacklist through embedded submission form** — `#418767` · HackerOne · $10,000 · ▲208
  > BYPASS: Get the `Embedded Submission` URL on their [policy page](https://hackerone.com/parrot sec): i get this - https://hackerone.com/0a1e1f11-257e-4b46-b949-c7151212ffbb/embedded submissions/new
- **2FA Bypass leads to  impersonation of legimate users** — `#2885636` · Drugs.com · $0 · ▲207
  > Go to https://www.drugs.com/account/register/ and create an account using an email you own.
- **TikTok 2FA Bypass** — `#1247108` · TikTok · $1,564 · ▲194
  > A vulnerability was found where a user would be able to bypass 2FA if logging in and redirecting back on a UK TikTok Seller URL.
- **Previously created sessions continue being valid after MFA activation** — `#667739` · Superhuman (formerly Grammarly) · $0 · ▲176
  > I found one issue related to your 2FA system on h

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 2× | `> POST /users/sign_in HTTP/1.1 / > Host: 159.xxx.xxx.xxx / > ... / > ----------1881604860 / > Content-Disposition: form-data; name="user[otp` |
| 2× | `{{temaplte:38dhs_admins_only_header.html}}` |
| 1× | `{email: \"█████ \", password: \"███\" }` |
| 1× | `POST /login/confirm HTTP/1.1 / Host: cs.money / Content-Length: 28 / Connection: close / Cookie: steamid=<victim_steam_id>; / {"token":"foo` |
| 1× | `HTTP/1.1 400 Bad Request / Content-Encoding: gzip / Content-Type: application/json; charset=utf-8 / Date: Tue, 31 Jan 2017 17:45:43 GMT / X-` |
| 1× | `Throttler\sleepDelay` |
| 1× | `{"username":"admin"}` |
| 1× | `/api/system/verification-codes/[0-9]{6}` |
| 1× | `{"password":"<NEW PASSWORD>","code":"<BRUTEFORCED SMS TOKEN>","securityCode":"<RETRIEVED SECURITY CODE>"}` |
| 1× | `<methodName> system.listMethods </methodName>` |
| 1× | `curl -u "RANDOM1:RANDOM2" -X PROPFIND https://server/public.php/webdav` |
| 1× | `[...]OCA\\\\DAV\\\\Connector\\\\Sabre\\\\Auth->validateUserPass('matthes', '***THE_PASSWORD***')[...]` |
| 1× | `/php/restaurantSmsHandler.php?type=app-download-sms&mobile_no=<NUMBER>&csrf_token=<TOKEN>` |
| 1× | `/php/restaurantSmsHandler.php?type=order-app-download-sms&mobile_no=<NUMBER>&csrf_token=<TOKEN>` |
| 1× | `/php/restaurantSmsHandler.php?type=app-download-sms&mobile_no=[8127410000,8317030000,...]&csrf_token=<TOKEN>` |
| 1× | `$ curl --globoff 'http://localhost:3000/api/v1/gems?api_key[]=key1&api_key[]=key2

### Hacker can bypass 2FA requirement and reporter blacklist through embedded submission form

`#418767` · HackerOne · $10,000 · medium · 2018-10-31 · ▲208
> A program owner can enforce the hackers to setup the two-factor authentication before submitting new reports to their program here: https://hackerone.com/parrot sec/submission requirements (see below image) {F355169} The Parrot Sec program has this feature enabled to enforce the hackers to setup 2FA before submitting reports. I removed my 2FA to test and it is good that i was block from submitting new reports (see below image) {F355168} ---

### 2FA Bypass leads to  impersonation of legimate users

`#2885636` · Drugs.com · $0 · high · 2025-03-14 · ▲207
> Hello team, I have discovered a logic flaw in the authentication system that allows an attacker (User A) to impersonate a legitimate user (User B) who has not yet registered. By abusing the email change functionality and bypassing 2FA, the attacker can retain access to the account until the legitimate user resets their password.

_...and 3 more sections in `references/unified-method.md`._

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

### C. Validation / proof bar — how to confirm and avoid false positives

- Prove an attacker session actually reaches the post-MFA state (a protected page or state-changing action), not just that a code was accepted or a response flipped.
- State the precondition honestly: a bypass that requires the password is High standalone; with a password oracle or cookie-theft it is Critical. Do not inflate severity by omitting the chain.
- For brute force, benchmark normal behavior first and show the rate limit is genuinely absent (or reliably bypassed via spoofed IP / OTP-regeneration reset) — a slow-but-present throttle is not "no rate limit".
- Replay the same OTP twice and check the response: a 302 on second use means non-invalidated codes. Re-test after logout and password change to prove persistence.
- Do not count theoretical "AiTM could capture the code" as an app finding — that is a phishing/threat-model note, not a demonstrable server flaw. Preserve evidence of the exact request/response pair that was tampered with and redact session cookies.

- Benchmark the normal flow first: if a wrong OTP returns 403 and a correct one 302, a response-tampering bypass must produce the same 302 and a usable session — not just a 200 with a different body.
- For brute force, repeat attempts with a re-login macro and confirm the OTP actually changes per request; PortSwigger notes a code may reset mid-attack, so a single failed run is not proof of protection.
- A code accepted twice is a clear single-use failure; verify with the *same* session and the *same* code, and re-check after a short 

### Escalation and related chains

### Escalation chains

- MFA bypass -> ATO.
- OTP brute -> ATO.

### Related Skills & Chains

- **`account-takeover`** — MFA bypass is a primitive; ATO is the destination. Chain primitive: cookie theft (via XSS or session-fixation) + password oracle (login response timing/length diff reveals valid passwords without lockout) + no MFA step-up on password-change endpoint = persistent ATO without ever facing the OTP challenge → password rotated, attacker locks victim out.
- **`race-condition`** — Pattern 5 (OTP race) lives in race-condition territory; load both skills together. Chain primitive: same 6-digit OTP submitted via 20 parallel HTTP/2 streams (single-packet Turbo Intruder attack) before the server marks it used → 1 success + 19 "already-used" → race window confirmed → attacker doesn't need to brute, just guesses once and parallelizes → ATO.
- **`auth-bypass`** — MFA-step-skip is auth-flow bypass at the workflow layer. Chain primitive: pre-MFA cookie issued after password step + direct navigation to `/dashboard` skipping `/mfa` route + server only middleware-gates `/mfa` not `/dashboard` = full post-auth access from password-only state → MFA never enforced because the route gate was misplaced.
- **`misc`** — Recovery-code dump via `/api/me` is a misc-class info disclosure that becomes Critical when chained. Chain primitive: `/api/me` returns full user object including `backup_codes` array (plaintext, never rotated) → attacker with any read-IDOR or XSS exfils backup codes → uses one backup code → MFA satisfied → ATO without OTP knowledge.
- **`security-arsenal`** — Pull the OTP-brute-force payload section (000000-999999 wordlist gener

### Pattern 7: "Remember This Device" Trust Escalation

```
1. Complete MFA once on Device A (attacker's browser)
2. Capture the "remember device" cookie
3. Present that cookie from a new IP/browser
4. If MFA skipped = device trust not bound to IP/UA = ATO from any location
```

### MFA Chain Escalation

```
Rate limit bypass + no lockout = ATO (Critical)
Response manipulation = client-side only check = Critical
Skip MFA step = auth flow bypass = Critical
OTP reuse = persistent session hijack = High
```

---

### Related Skills & Chains

- **`hunt-ato`** — MFA bypass is a primitive; ATO is the destination. Chain primitive: cookie theft (via XSS or session-fixation) + password oracle (login response timing/length diff reveals valid passwords without lockout) + no MFA step-up on password-change endpoint = persistent ATO without ever facing the OTP challenge → password rotated, attacker locks victim out.
- **`hunt-race-condition`** — Pattern 5 (OTP race) lives in race-condition territory; load both skills together. Chain primitive: same 6-digit OTP submitted via 20 parallel HTTP/2 streams (single-packet Turbo Intruder attack) before the server marks it used → 1 success + 19 "already-used" → race window confirmed → attacker doesn't need to brute, just guesses once and parallelizes → ATO.
- **`hunt-auth-bypass`** — MFA-step-skip is auth-flow bypass at the workflow layer. Chain primitive: pre-MFA cookie issued after password step + direct navigation to `/dashboard` skipping `/mfa` route + server only middleware-gates `/mfa` not `/dashboard` = full post-auth access from password-only state → MFA never enforced because the route gate was misplaced.
- **`hunt-misc`** — Recovery-code dump via `/api/me` is a misc-class info disclosure that becomes Critical when chained. Chain primitive: `/api/me` returns full user object including `backup_codes` array (plaintext, never rotated) → attacker with any read-IDOR or XSS exfils backup codes → uses one backup code → MFA satisfied → ATO without OTP knowledge.
- **`security-arsenal`** — Pull the OTP-brute-force payload section (000000-999999 wordlis

### Tools and wordlists

### Tools

`Burp` · `Turbo Intruder` · `ffuf`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_mfa-and-passwords.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_mfa-and-passwords.txt` | 75 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_mfa-and-passwords.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_mfa-and-passwords.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

### Nuclei

Test OTP brute-force limits, reuse, and direct post-MFA endpoint access manually.

```sh
nuclei -u https://target -tags auth-bypass,default-login,token-spray,login \
       -severity low,medium,high,critical -rl 40 -o nuclei_mfa-and-passwords.txt
nuclei -u https://target -t ~/nuclei-templates/http/default-logins \
       -rl 40 -o nuclei_mfa-and-passwords_default-logins.txt
nuclei -u https://target -t ~/nuclei-templates/http/token-spray \
       -rl 40 -o nuclei_mfa-and-passwords_token-spray.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Source skills merged into this topic

- `h1skills` — `hackerone-mfa-and-passwords`
- `hunting` — `mfa-and-passwords`
- `cbh` — `hunt-mfa-bypass`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 2 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `../../upstream/` — complete unmodified archives of all five source repositories
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
