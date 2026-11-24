# Unified upstream methodology

Collected from every contributing repository skill. Deduplicated by content hash; full originals are preserved in `references/upstream-*.md`.

## Discovery and hunting method

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
3. Walk the code digit-by-digit: keep the prefix that "responds correct," append 0–9, repeat. This collapses 10^6 brute force to ~10×N guesses (≤60 for a 6-digit code) — very feasible in a bounded test.
This is the go-to when there is no leaked code and no skip/replay path. Some apps award success on *any* correct prefix outright (so a single correct first digit can win — sweep `otp=0,1,…,9` before giving up).
**CRITICAL — stay in ONE session:** re-authenticating (POST /…/login again) regenerates the OTP, throwing away your prefix progress. Do the entire sweep against a single established MFA session; never re-login between guesses.

**On full brute force:** brute-forcing all 10^6 codes is infeasible in a bounded test — but the prefix oracle above (Pattern 4) usually makes it unnecessary. Only attempt full brute force with evidence of no rate limit AND a small key space.

**Proof:** A session token or protected resource data in the response without completing MFA confirms the bypass.

---

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

## Signals and surfaces

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

## Techniques, payloads and bypasses

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
  > I found one issue related to your 2FA system on https://account.grammarly.com/security
- **Web Authentication Endpoint Credentials Brute-Force Vulnerability** — `#127844` · HackerOne · $0 · ▲161
  > The following successful brute-force attack of 10.001 passwords (https://github.com/danielmiessler/SecLists/blob/master/Passwords/10k most common.txt appended with the real password) against test account ██████:Geniaal2!!
- **Enable 2FA without verifying the email** — `#649533` · Moneybird · $0 · ▲149
  > Attacker sign up with victim email (Email verification will be sent to victim email).
- **Bypassing HackerOne 2FA due to race condition** — `#2598548` · HackerOne · $0 · ▲139
  > When a user canceled one reset request, the remaining requests would stay active, potentially leading to unauthorized 2FA removal after 24 hours.
- **Business Logic Error – Bypass of OTP Verification During Signup on hover.com** — `#3255473` · Tucows (VDP) · $0 · ▲135
  > By omitting the code parameter entirely from the signup request, the backend completes the registration and returns a valid session.
- **Yet Another OTP code Leaked in the API Response** — `#2635315` · MTN Group · $0 · ▲135
  > This is much similar to my report here(https://hackerone.com/reports/2633888) , except it affects a different domain.
- **Adding phone number to profile By OTP brute forcing** — `#3265780` · CoinMate.io · $100 · ▲114
  > Step2: So enter any OTP in the OTP filed and intercept the request in the burp-suite, Then send the intercepted request to burp intruder.
- **Claiming the listing of a non-delivery restaurant through OTP manipulation** — `#1330529` · Eternal · $3,250 · ▲108
  > Here by changing the `verificationCode` - (Otp received on Attacker Mobile in response of Request :1 )& `requestId` (Response of request:1) and `resId` to Victim Restaurant.
- **2FA requirement bypass when inviting team members** — `#3356149` · Omise · $0 · ▲105
  > Use a Burp extension ( Match and Replace) to change the client-side flag `false → true`.
- **Bypass a fix for report #708013** — `#1363672` · Shopify · $3,500 · ▲102
  > Observe that you have bypassed the limit though the email is still valid (to prove it try `{email: \"█████ \", password: \"███\" }` and get the token)
- **Email OTP/2FA Bypass** — `#2315420` · Drugs.com · $0 · ▲100
  > The application has a functionality of 2FA by email OTP so i can bypass that 2FA and got the access of application without having any access of victim account.
- **2FA bypass possible on https://authsvc.singlestore.com** — `#3329361` · SingleStore · $0 · ▲96
  > CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N/CR:H/IR:H/AR:H
- **Password not checked when disabling 2FA on HackerOne** — `#587910` · HackerOne · $0 · ▲95
  > when I was submitted a report to a program that request `2FA` ON, I notice that if you try to disable this option will ask for `backup code - password` and if you enter a random password in the request filed and a correct `backup code` it will be successfully…
- **Improper Authentication Throttling Allows Attacker-Controlled Account Lockouts** — `#3160210` · Lichess · $0 · ▲92
  > Because the system does not verify the request origin or impose intelligent rate-limiting tied to session/IP/fingerprint, an attacker can intentionally lock out legitimate users — impacting their access to the application.
- **Account takeover w/o interaction for a user that doesn't have 2fa enabled via 2fa linking and improper auth at /api/2fa/verify** — `#810880` · Helium · $0 · ▲92
  > Register an account `user2`, register at https://console.helium.com, perform a 2FA request but with ID from `user1`.
- **Session Doesn't expire after 2fa and also other session can change passsword** — `#2234736` · SideFX · $300 · ▲90
  > I found one issue related to your 2FA system on https://sidefx.com
- **“email” MFA mode allows bypassing MFA from victim’s device when the device trust is not expired** — `#665722` · Superhuman (formerly Grammarly) · $2,500 · ▲82
  > When we turn on the MFA and we have the user and password of the user, it is possible bypass the MFA only changing some values the endpoint POST `auth.grammarly.com//v3/api/login`
- **OTP code Leaked in API Response** — `#2633888` · MTN Group · $0 · ▲81
  > The application https://corporate.admyntec.co.za allows users to sign up for device insurance.
- **Information disclosure -> 2fa bypass -> POST exploitation** — `#1276373` · Algolia · $0 · ▲76
  > - There will be 2 buttons : "Revoke" and "Renew", click on "Renew" and intercept that request using proxy like burp suite
- **Weak Rate Limiting Controls in the (LOGIN) page Expose System to Brute Force and DoS Attacks** — `#3085889` · Lichess · $0 · ▲74
  > =================================================================================
- **Able to blocking users with 2fa from login into their accounts by just knowing the SteamID** — `#1179232` · CS Money · $300 · ▲70
  > By changing the steamID cookie on confirm 2fa code request, I am able to block the login of an account with 2fa for 5 minutes (300 seconds).
- **Enable 2FA without verifying the email** — `#3016540` · XVIDEOS · $0 · ▲70
  > After that, Navigate to: https://www.xvideos.com/account/security
- **Bypassing the victim's phone number OTP in the account recovery process on the https://hackerone.com/settings/auth/setup_account_recovery** — `#2501984` · HackerOne · $0 · ▲67
  > First, create an account recovery request using your own phone number and successfully enable account recovery with that same number.
- **Two-factor authentication enforcement bypass** — `#1050244` · Nextcloud · $750 · ▲64
  > https://github.com/nextcloud/server/blob/1762a409f954fd9a66e7572704ea9ba7813601b4/core/templates/twofactorselectchallenge.php
- **Brute Force of fabric-ca server admin account** — `#411364` · Linux Foundation Decentralized Trust · $0 · ▲61
  > - Listening 0.0.0.0:7054(easily discoved and can be reached)

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
| 1× | `$ curl --globoff 'http://localhost:3000/api/v1/gems?api_key[]=key1&api_key[]=key2' / > Access Denied. Please sign up for an account at https` |
| 1× | `SecureRandom.hex (32)` |
| 1× | `$response->throttle()` |
| 1× | `using the way ''{{temaplte:38dhs_admins_only_header.html}}'' in 'create new' via 'preview feature', nothing. The other variable name, which` |
| 1× | `{id:"2"}` |

### Hacker can bypass 2FA requirement and reporter blacklist through embedded submission form

`#418767` · HackerOne · $10,000 · medium · 2018-10-31 · ▲208
> A program owner can enforce the hackers to setup the two-factor authentication before submitting new reports to their program here: https://hackerone.com/parrot sec/submission requirements (see below image) {F355169} The Parrot Sec program has this feature enabled to enforce the hackers to setup 2FA before submitting reports. I removed my 2FA to test and it is good that i was block from submitting new reports (see below image) {F355168} ---

### 2FA Bypass leads to  impersonation of legimate users

`#2885636` · Drugs.com · $0 · high · 2025-03-14 · ▲207
> Hello team, I have discovered a logic flaw in the authentication system that allows an attacker (User A) to impersonate a legitimate user (User B) who has not yet registered. By abusing the email change functionality and bypassing 2FA, the attacker can retain access to the account until the legitimate user resets their password.

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

### 19. MFA / 2FA BYPASS

> Growing bug class — 7 distinct patterns. Pays High/Critical when it enables ATO without prior session.

### Pattern 4: Skip MFA Step (Workflow Bypass)

```bash
# After entering password, app sets a "pre-mfa" cookie → redirects to /mfa
# Test: skip /mfa entirely, access /dashboard directly with pre-mfa cookie
# If app grants access without MFA = auth flow bypass = Critical
curl -s -b "session=PRE_MFA_SESSION" https://target.com/dashboard
```

## Validation and proof

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
- A code accepted twice is a clear single-use failure; verify with the *same* session and the *same* code, and re-check after a short delay to rule out a long validity window.
- For cookie-swap brute, remember to first trigger code generation for the victim cookie target (`GET /login2` with `Cookie: account=victim`) — brute-forcing a code that was never issued is a false negative, not a secure MFA.
- Prove the final state with a protected action (e.g. changing the victim's email or reading their data), not just reaching `/my-account` with a 200.
- Distinguish "MFA not enforced" from "MFA satisfied by a different factor": document which factor was actually bypassed and which preconditions (password, session, cookie) the attacker held.
- Push fatigue, SIM swap, and phishing-proxied OTPs are real-world threats but are not server-side app bugs — label them as threat-model notes, not reportable findings, unless the app has a specific control that fails.
- Backup/recovery-code findings need a clean proof that the code was not issued to the attacker legitimately for that account — use two controlled accounts.
- Redact OTP values, session cookies, and other-user PII in screenshots; keep the request/response pair that demonstrates the tampering.

## Escalation and related chains

### Escalation chains

- MFA bypass -> ATO.
- OTP brute -> ATO.

### Related Skills & Chains

- **`account-takeover`** — MFA bypass is a primitive; ATO is the destination. Chain primitive: cookie theft (via XSS or session-fixation) + password oracle (login response timing/length diff reveals valid passwords without lockout) + no MFA step-up on password-change endpoint = persistent ATO without ever facing the OTP challenge → password rotated, attacker locks victim out.
- **`race-condition`** — Pattern 5 (OTP race) lives in race-condition territory; load both skills together. Chain primitive: same 6-digit OTP submitted via 20 parallel HTTP/2 streams (single-packet Turbo Intruder attack) before the server marks it used → 1 success + 19 "already-used" → race window confirmed → attacker doesn't need to brute, just guesses once and parallelizes → ATO.
- **`auth-bypass`** — MFA-step-skip is auth-flow bypass at the workflow layer. Chain primitive: pre-MFA cookie issued after password step + direct navigation to `/dashboard` skipping `/mfa` route + server only middleware-gates `/mfa` not `/dashboard` = full post-auth access from password-only state → MFA never enforced because the route gate was misplaced.
- **`misc`** — Recovery-code dump via `/api/me` is a misc-class info disclosure that becomes Critical when chained. Chain primitive: `/api/me` returns full user object including `backup_codes` array (plaintext, never rotated) → attacker with any read-IDOR or XSS exfils backup codes → uses one backup code → MFA satisfied → ATO without OTP knowledge.
- **`security-arsenal`** — Pull the OTP-brute-force payload section (000000-999999 wordlist generator, ffuf rate-limit-evasion patterns with `-t 5 -p 0.5-2`, distributed-IP rotation via proxychains) and the JWT-token-replay table when "MFA satisfied" claim lives in a JWT claim that can be forged.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an MFA bypass that only works when the attacker already has the password. Standalone MFA bypass is High; chained-with-password-oracle is Critical; chained-with-cookie-theft-only is Critical. The chain question separates the two.

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
- **`security-arsenal`** — Pull the OTP-brute-force payload section (000000-999999 wordlist generator, ffuf rate-limit-evasion patterns with `-t 5 -p 0.5-2`, distributed-IP rotation via proxychains) and the JWT-token-replay table when "MFA satisfied" claim lives in a JWT claim that can be forged.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an MFA bypass that only works when the attacker already has the password. Standalone MFA bypass is High; chained-with-password-oracle is Critical; chained-with-cookie-theft-only is Critical. The chain question separates the two.

## Tools and wordlists

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

## Sources and related reading

### Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class mfa-and-passwords --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class mfa-and-passwords
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class mfa-and-passwords
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class mfa-and-passwords --min-bounty 1000
```

### Related

- `hackerone-auth-bypass` (989 reports)
- `hackerone-account-takeover` (262 reports)

### Related

- `auth-bypass` (989 reports)
- `account-takeover` (262 reports)

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/web-security/authentication/multi-factor
2. https://www.cobalt.io/blog/bypassing-the-protections-mfa-bypass-techniques-for-the-win
3. https://portswigger.net/web-security/race-conditions

## Additional notes

### Parameters observed

`password` · `username` · `template` · `authenticity_token` · `invite_code` · `commit` · `hash` · `phone` · `token` · `api_key[]` · `id` · `next` · `_method` · `type` · `mobile_no` · `csrf_token` · `data` · `uuid` · `redirect` · `product`

### Improper Authentication - any user can login as other user with otp/logout & otp/login

`#921780` · Snapchat · $0 · critical · 2021-09-03 · ▲972
> '/scauth/otp/droid/logout' request contains user id parameter. Usually it is equal to current user user id, but if an attacker passes user id of victim account he can login as victim. I will demonstrate the problem on two accounts. Victim: ███ Attacker: ██████████ - Attacker perform a usuall login to attacker's personal account.

### Bruteforce password recovery code

`#743545` · Bumble · $0 · n/a · 2020-01-18 · ▲258
> It's possible to bruteforce recovery code from SMS as iOS application doesn't have limits for incorrect inputs. I have tried 50+ different combinations until I reached code from SMS.

### Change phone number OTP flaw leads to any phone number takeover

`#2588329` · inDrive · $2,000 · critical · 2024-10-09 · ▲241
> Dear Indrive, Ive found another valid report, the app allows any user to change the app phone number, but a flaw within the otp allows any number to be added into the account! When an user requests a phone number change inside the app, it will send a 4 digit code but if you place 0000, it will accept any number and update it into the app!!

### Pattern 1: No Rate Limit on OTP

```bash
# Test with ffuf — all 1M 6-digit codes
ffuf -u "https://target.com/api/verify-otp" \
  -X POST -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"otp":"FUZZ"}' \
  -w <(seq -w 000000 999999) \
  -fc 400,429 -t 5
# -t 5 (slow down) — aggressive rates get 429 or ban
```

### Pattern 2: OTP Not Invalidated After Use

```
1. Login → receive OTP "123456" → enter it → success
2. Logout → login again with same credentials
3. Try OTP "123456" again
4. If accepted → OTP never invalidated = ATO (attacker sniffs OTP once, reuses forever)
```

### Pattern 3: Response Manipulation

```
1. Enter wrong OTP → capture response in Burp
2. Change {"success":false} → {"success":true} (or 401 → 200)
3. Forward → if app proceeds → client-side only MFA check
```

### Pattern 5: Race on MFA Verification

```python
import asyncio, aiohttp

async def verify(session, otp):
    async with session.post("https://target.com/api/mfa/verify",
                            json={"otp": otp}) as r:
        return r.status, await r.text()

async def race():
    cookies = {"session": "YOUR_SESSION"}
    async with aiohttp.ClientSession(cookies=cookies) as s:
        # Fire ~30 concurrent submissions of the SAME OTP to hit the TOCTOU
        # window before the server marks it used. Two requests are NOT enough —
        # they almost always resolve sequentially as "already-used" (false negative).
        # Best done as a single-packet / 20+ HTTP-2-stream attack (Turbo Intruder).
        results = await asyncio.gather(*[verify(s, "123456") for _ in range(30)])
        # Race confirmed if >1 success (or 1 success among many "already-used").
        for status, body in results:
            print(status, body)
asyncio.run(race())
```

### Pattern 6: Backup Code Brute Force

```
Backup codes: typically 8 alphanumeric = 36^8 = ~2.8T (too large)
BUT: check if backup codes are only 6-8 digits = 1-10M range = feasible with no rate limit
Also test: can backup codes be reused after exhaustion? Some apps regenerate predictably.
```

## Companion methodology (merged, deduplicated)

Full text of every non-SKILL.md methodology file from the contributing skills — payload banks, technique references, reconnaissance and attack-class guides.

### Companion: hunting / references/payloads.md

# MFA And Passwords — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- OTP -> `000000`, reuse old code, race multiple codes

- MFA -> call the post-MFA endpoint directly

- Password -> `password[]=x`, type juggling

- Enumeration -> response length/timing variants



## Payload fragments observed



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

| 1× | `$ curl --globoff 'http://localhost:3000/api/v1/gems?api_key[]=key1&api_key[]=key2' / > Access Denied. Please sign up for an account at https` |

| 1× | `SecureRandom.hex (32)` |

| 1× | `$response->throttle()` |

| 1× | `using the way ''{{temaplte:38dhs_admins_only_header.html}}'' in 'create new' via 'preview feature', nothing. The other variable name, which` |

| 1× | `{id:"2"}` |



## Parameters observed



`password` · `username` · `template` · `authenticity_token` · `invite_code` · `commit` · `hash` · `phone` · `token` · `api_key[]` · `id` · `next` · `_method` · `type` · `mobile_no` · `csrf_token` · `data` · `uuid` · `redirect` · `product`



## Wordlists



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



## Nuclei



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

### Companion: hunting / references/techniques.md

# MFA And Passwords — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Test OTP brute force limits, reuse, expiry, and response leakage.

- Try MFA bypass via direct navigation, API calls, and remember-me tokens.

- Check backup-code generation and storage.

- Test password reset/change for missing current-password checks.



## Bypass tricks



- Bypass step-up auth by replaying a privileged session.

- Use unicode/whitespace variants of the password.



## Deeper checklist



- Test OTP brute force limits, reuse, expiry, and response leakage.

- Try MFA bypass by direct navigation, API calls, and remember-me tokens.

- Check backup-code generation and storage.

- Test password reset and change flows for missing current-password checks.

- Look for user enumeration via timing and error messages.

- Prove bypass into a protected account or area.



## Techniques from real reports



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

  > I found one issue related to your 2FA system on https://account.grammarly.com/security

- **Web Authentication Endpoint Credentials Brute-Force Vulnerability** — `#127844` · HackerOne · $0 · ▲161

  > The following successful brute-force attack of 10.001 passwords (https://github.com/danielmiessler/SecLists/blob/master/Passwords/10k most common.txt appended with the real password) against test account ██████:Geniaal2!!

- **Enable 2FA without verifying the email** — `#649533` · Moneybird · $0 · ▲149

  > Attacker sign up with victim email (Email verification will be sent to victim email).

- **Bypassing HackerOne 2FA due to race condition** — `#2598548` · HackerOne · $0 · ▲139

  > When a user canceled one reset request, the remaining requests would stay active, potentially leading to unauthorized 2FA removal after 24 hours.

- **Business Logic Error – Bypass of OTP Verification During Signup on hover.com** — `#3255473` · Tucows (VDP) · $0 · ▲135

  > By omitting the code parameter entirely from the signup request, the backend completes the registration and returns a valid session.

- **Yet Another OTP code Leaked in the API Response** — `#2635315` · MTN Group · $0 · ▲135

  > This is much similar to my report here(https://hackerone.com/reports/2633888) , except it affects a different domain.

- **Adding phone number to profile By OTP brute forcing** — `#3265780` · CoinMate.io · $100 · ▲114

  > Step2: So enter any OTP in the OTP filed and intercept the request in the burp-suite, Then send the intercepted request to burp intruder.

- **Claiming the listing of a non-delivery restaurant through OTP manipulation** — `#1330529` · Eternal · $3,250 · ▲108

  > Here by changing the `verificationCode` - (Otp received on Attacker Mobile in response of Request :1 )& `requestId` (Response of request:1) and `resId` to Victim Restaurant.

- **2FA requirement bypass when inviting team members** — `#3356149` · Omise · $0 · ▲105

  > Use a Burp extension ( Match and Replace) to change the client-side flag `false → true`.

- **Bypass a fix for report #708013** — `#1363672` · Shopify · $3,500 · ▲102

  > Observe that you have bypassed the limit though the email is still valid (to prove it try `{email: \"█████ \", password: \"███\" }` and get the token)

- **Email OTP/2FA Bypass** — `#2315420` · Drugs.com · $0 · ▲100

  > The application has a functionality of 2FA by email OTP so i can bypass that 2FA and got the access of application without having any access of victim account.

- **2FA bypass possible on https://authsvc.singlestore.com** — `#3329361` · SingleStore · $0 · ▲96

  > CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N/CR:H/IR:H/AR:H

- **Password not checked when disabling 2FA on HackerOne** — `#587910` · HackerOne · $0 · ▲95

  > when I was submitted a report to a program that request `2FA` ON, I notice that if you try to disable this option will ask for `backup code - password` and if you enter a random password in the request filed and a correct `backup code` it will be successfully…

- **Improper Authentication Throttling Allows Attacker-Controlled Account Lockouts** — `#3160210` · Lichess · $0 · ▲92

  > Because the system does not verify the request origin or impose intelligent rate-limiting tied to session/IP/fingerprint, an attacker can intentionally lock out legitimate users — impacting their access to the application.

- **Account takeover w/o interaction for a user that doesn't have 2fa enabled via 2fa linking and improper auth at /api/2fa/verify** — `#810880` · Helium · $0 · ▲92

  > Register an account `user2`, register at https://console.helium.com, perform a 2FA request but with ID from `user1`.

- **Session Doesn't expire after 2fa and also other session can change passsword** — `#2234736` · SideFX · $300 · ▲90

  > I found one issue related to your 2FA system on https://sidefx.com

- **“email” MFA mode allows bypassing MFA from victim’s device when the device trust is not expired** — `#665722` · Superhuman (formerly Grammarly) · $2,500 · ▲82

  > When we turn on the MFA and we have the user and password of the user, it is possible bypass the MFA only changing some values the endpoint POST `auth.grammarly.com//v3/api/login`

- **OTP code Leaked in API Response** — `#2633888` · MTN Group · $0 · ▲81

  > The application https://corporate.admyntec.co.za allows users to sign up for device insurance.

- **Information disclosure -> 2fa bypass -> POST exploitation** — `#1276373` · Algolia · $0 · ▲76

  > - There will be 2 buttons : "Revoke" and "Renew", click on "Renew" and intercept that request using proxy like burp suite

- **Weak Rate Limiting Controls in the (LOGIN) page Expose System to Brute Force and DoS Attacks** — `#3085889` · Lichess · $0 · ▲74

  > =================================================================================

- **Able to blocking users with 2fa from login into their accounts by just knowing the SteamID** — `#1179232` · CS Money · $300 · ▲70

  > By changing the steamID cookie on confirm 2fa code request, I am able to block the login of an account with 2fa for 5 minutes (300 seconds).

- **Enable 2FA without verifying the email** — `#3016540` · XVIDEOS · $0 · ▲70

  > After that, Navigate to: https://www.xvideos.com/account/security

- **Bypassing the victim's phone number OTP in the account recovery process on the https://hackerone.com/settings/auth/setup_account_recovery** — `#2501984` · HackerOne · $0 · ▲67

  > First, create an account recovery request using your own phone number and successfully enable account recovery with that same number.

- **Two-factor authentication enforcement bypass** — `#1050244` · Nextcloud · $750 · ▲64

  > https://github.com/nextcloud/server/blob/1762a409f954fd9a66e7572704ea9ba7813601b4/core/templates/twofactorselectchallenge.php

- **Brute Force of fabric-ca server admin account** — `#411364` · Linux Foundation Decentralized Trust · $0 · ▲61

  > - Listening 0.0.0.0:7054(easily discoved and can be reached)



## Case studies



### Improper Authentication - any user can login as other user with otp/logout & otp/login

`#921780` · Snapchat · $0 · critical · 2021-09-03 · ▲972

> '/scauth/otp/droid/logout' request contains user id parameter. Usually it is equal to current user user id, but if an attacker passes user id of victim account he can login as victim. I will demonstrate the problem on two accounts. Victim: ███ Attacker: ██████████ - Attacker perform a usuall login to attacker's personal account.



### Bruteforce password recovery code

`#743545` · Bumble · $0 · n/a · 2020-01-18 · ▲258

> It's possible to bruteforce recovery code from SMS as iOS application doesn't have limits for incorrect inputs. I have tried 50+ different combinations until I reached code from SMS.



### Change phone number OTP flaw leads to any phone number takeover

`#2588329` · inDrive · $2,000 · critical · 2024-10-09 · ▲241

> Dear Indrive, Ive found another valid report, the app allows any user to change the app phone number, but a flaw within the otp allows any number to be added into the account! When an user requests a phone number change inside the app, it will send a 4 digit code but if you place 0000, it will accept any number and update it into the app!!



### Hacker can bypass 2FA requirement and reporter blacklist through embedded submission form

`#418767` · HackerOne · $10,000 · medium · 2018-10-31 · ▲208

> A program owner can enforce the hackers to setup the two-factor authentication before submitting new reports to their program here: https://hackerone.com/parrot sec/submission requirements (see below image) {F355169} The Parrot Sec program has this feature enabled to enforce the hackers to setup 2FA before submitting reports. I removed my 2FA to test and it is good that i was block from submitting new reports (see below image) {F355168} ---



### 2FA Bypass leads to  impersonation of legimate users

`#2885636` · Drugs.com · $0 · high · 2025-03-14 · ▲207

> Hello team, I have discovered a logic flaw in the authentication system that allows an attacker (User A) to impersonate a legitimate user (User B) who has not yet registered. By abusing the email change functionality and bypassing 2FA, the attacker can retain access to the account until the legitimate user resets their password.



## Query the corpus



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class mfa-and-passwords --limit 20

python3 ~/.local/share/hackerone-reports/h1.py stats --class mfa-and-passwords

python3 ~/.local/share/hackerone-reports/h1.py show <id> --full

```



Search by technology, endpoint, parameter, or program. Examples:



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class mfa-and-passwords

python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class mfa-and-passwords --min-bounty 1000

```



## 19. MFA / 2FA BYPASS

> Growing bug class — 7 distinct patterns. Pays High/Critical when it enables ATO without prior session.



### Pattern 1: No Rate Limit on OTP

```bash

# Test with ffuf — all 1M 6-digit codes

ffuf -u "https://target.com/api/verify-otp" \

  -X POST -H "Content-Type: application/json" \

  -H "Cookie: session=YOUR_SESSION" \

  -d '{"otp":"FUZZ"}' \

  -w <(seq -w 000000 999999) \

  -fc 400,429 -t 5

# -t 5 (slow down) — aggressive rates get 429 or ban

```



### Pattern 2: OTP Not Invalidated After Use

```

1. Login → receive OTP "123456" → enter it → success

2. Logout → login again with same credentials

3. Try OTP "123456" again

4. If accepted → OTP never invalidated = ATO (attacker sniffs OTP once, reuses forever)

```



### Pattern 3: Response Manipulation

```

1. Enter wrong OTP → capture response in Burp

2. Change {"success":false} → {"success":true} (or 401 → 200)

3. Forward → if app proceeds → client-side only MFA check

```



### Pattern 4: Skip MFA Step (Workflow Bypass)

```bash

# After entering password, app sets a "pre-mfa" cookie → redirects to /mfa

# Test: skip /mfa entirely, access /dashboard directly with pre-mfa cookie

# If app grants access without MFA = auth flow bypass = Critical

curl -s -b "session=PRE_MFA_SESSION" https://target.com/dashboard

```



### Pattern 5: Race on MFA Verification

```python

import asyncio, aiohttp



async def verify(session, otp):

    async with session.post("https://target.com/api/mfa/verify",

                            json={"otp": otp}) as r:

        return r.status, await r.text()



async def race():

    cookies = {"session": "YOUR_SESSION"}

    async with aiohttp.ClientSession(cookies=cookies) as s:

        # Fire ~30 concurrent submissions of the SAME OTP to hit the TOCTOU

        # window before the server marks it used. Two requests are NOT enough —

        # they almost always resolve sequentially as "already-used" (false negative).

        # Best done as a single-packet / 20+ HTTP-2-stream attack (Turbo Intruder).

        results = await asyncio.gather(*[verify(s, "123456") for _ in range(30)])

        # Race confirmed if >1 success (or 1 success among many "already-used").

        for status, body in results:

            print(status, body)

asyncio.run(race())

```



### Pattern 6: Backup Code Brute Force

```

Backup codes: typically 8 alphanumeric = 36^8 = ~2.8T (too large)

BUT: check if backup codes are only 6-8 digits = 1-10M range = feasible with no rate limit

Also test: can backup codes be reused after exhaustion? Some apps regenerate predictably.

```



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
