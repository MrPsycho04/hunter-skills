---
name: bbhunt-session
description: "Use for session fixation, non-invalidation on logout/password/email change, weak session IDs, and session lifetime/revocation issues. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Session Management Flaws — unified methodology

> **Unified skill.** Built from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus evidence (112 valid reports, 18 paid / 16%)

Payment is not validity — zero-bounty disclosures are mined as evidence too.

### Techniques ranked across ALL valid writeups

| Technique | Reports |
|---|---:|
| unauthenticated / removed-cookie test | 14 |
| admin / privileged-role context | 14 |
|  HosT/absolute-URL reset poisoning | 13 |
| cache / CDN / unkeyed header | 11 |
| encoding / double-encode / null byte | 10 |
| second-order / stored / blind delivery | 9 |
| header injection (Host / X-Forwarded / etc.) | 9 |
| HTTP method / verb tampering | 9 |
| race / concurrency / timing | 9 |
| public source-code / repo review | 8 |

### Parameters observed

`valid_until`, `charset`, `in_header`, `max-age`, `rel`, `curlopt_ssl_verifypeer`, `rtp_len`, `size`, `download_done`, `state`, `jsessionid`, `xsrf-token`, `src`, `steps`, `summary`

### Case studies (real reports, paid and unpaid)

- [1547684](https://hackerone.com/reports/1547684) Shopify — Disconnecting an external login provider does not revoke session ($1600, medium)
- [347748](https://hackerone.com/reports/347748) X / xAI — Improper session handling on web browsers ($560, medium)
- [1162443](https://hackerone.com/reports/1162443) Shopify — No Session Expiry after log-out, attacker can reuse the old cookies ($500, low)

Full payload bank, bypass frequencies, approach patterns and case-study excerpts: `references/evidence.md`.

## Corpus-backed method (this class)

1. Capture session identifiers at pre-login, post-login, after privilege change, and after logout; check for regeneration and revocation.
2. Test whether a session can be fixed by planting a known identifier before authentication.
3. Attempt reuse after each lifecycle event (logout, password change, email change, admin reset, MFA disable).
4. Inspect identifier entropy/structure and server-side session storage assumptions.
5. Prove that an attacker with a stolen/old session retains access they should have lost.

### Signals

- Session cookie not regenerated at login
- Old session still works after logout or password change
- Predictable or unsigned session identifiers
- Account/email change does not terminate other sessions

### Kill criteria

- Session correctly regenerated and invalidated at every boundary.
- Old token reuse needs credentials an attacker does not have.

### Escalation chains

- Session fixation -> authenticated session -> account access.
- Stale session -> access after password reset -> persistence.

### Veteran tip

The most useful evidence is a timeline of which token worked at which lifecycle event.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Check cookie flags: Secure, HttpOnly, SameSite, scope, lifetime.
- Test fixation and rotation on login/logout/privilege change.
- Test revocation after password change or logout.
- Look for predictable tokens and JWT weaknesses.

### Deeper checklist

- Check cookie flags: Secure, HttpOnly, SameSite, scope, and lifetime.
- Test session fixation and rotation on login/logout/privilege change.
- Test token revocation and reuse after password change or logout.
- Look for predictable tokens and JWT weaknesses.
- Check cross-subdomain cookie leakage.
- Demonstrate session hijack or persistence.

### Autonomous Testing Priority

**Missing HttpOnly on cookies is auto-detected — focus your active testing on lifecycle invalidation (higher impact).**

**Pattern 1 — Session survives logout (most common high-value finding):**
1. Login and note the session token/cookie value
2. Call the logout endpoint (`/logout`, `POST /api/logout`, etc.)
3. Try to use the OLD session token to access a protected resource (`/api/me`, `/dashboard`, `/account`)
4. If 200 with user data → session not invalidated on logout = ATO persistence

**Pattern 2 — Session not regenerated on login (session fixation):**
1. GET any page to receive a pre-authentication session token/cookie
2. POST valid credentials to the login endpoint
3. Compare the session token BEFORE and AFTER login
4. If the token is unchanged → session fixation vulnerability

**Pattern 3 — Session survives password change:**
1. Login → record session A value
2. Change the password via the account settings endpoint
3. Replay session A on a protected endpoint
4. If 200 → token not rotated on credential change = persistent ATO (critical chain when combined with XSS/cookie theft)

**Content-type:** Login and session endpoints vary — use `application/json` for REST APIs, `application/x-www-form-urlencoded` for traditional web forms. Try both if the first returns an unexpected response.

**Proof:** A protected-resource 200 response (with user data) using a session token that should have been invalidated confirms the finding.

---

# HUNT-SESSION — Session Management

### Step-by-Step Hunting Methodology

> **Two-session rule.** Every invalidation/fixation claim is proven with TWO concrete sessions captured by a real flow — attacker **A** and victim **B** — never with hardcoded placeholder strings. Helpers below capture real cookies from `curl`'s Netscape jar.

```bash
TARGET=target.com
JAR_A=$(mktemp); JAR_B=$(mktemp)

# Robust session-cookie extractor: handles #HttpOnly_ prefix lines and any
# cookie name (sid/JSESSIONID/connect.sid/PHPSESSID/...). Prints name=value.
get_cookie () {  # $1=jar  $2=name-regex (default: common session names)
  local jar="$1" re="${2:-session|sid|sess|JSESSIONID|connect\.sid|PHPSESSID|laravel_session}"
  awk -v re="$re" '
    /^#HttpOnly_/ { sub(/^#HttpOnly_/,""); }   # strip jar HttpOnly marker
    /^#/ { next }                              # skip remaining comments
    NF>=7 && $6 ~ re { print $6"="$7 }         # field6=name field7=value
  ' "$jar" | tail -1
}
```

### A. Discovery checklist — concrete places, params, headers, flows to look

- Inventory every session-bearing artifact: auth cookie(s), `remember-me`/persistent cookie, refresh token, JWT access token, SSO session cookie, password-reset token, CSRF token, and any opaque session ID in a URL (`?sid=`, `?session=`, path segments). PortSwigger classifies session-in-URL as CWE-598/CWE-384 and notes leakage via browser history, logs, and `Referer`.
- Record cookie attributes for each: `Secure`, `HttpOnly`, `SameSite`, `Domain`, `Path`, `Expires`/`Max-Age`, `__Host-`/`__Secure-` prefixes. Multiple cookies with the same name but different `Path` (Snyk 2026 OAuth case) create a path-scope confusion primitive.
- Determine regeneration points: compare the session token before login, after login, after privilege change, after password change, and after email change. Logout must invalidate server-side state, not just clear the browser cookie.
- Test refresh-token flows from SPAs/mobile apps: collect the full `POST /oauth/token` with `grant_type=refresh_token` and watch whether each exchange returns a *new* refresh token (rotation) and whether old ones are revoked.
- Use Burp Sequencer on a large sample of session tokens (PortSwigger/Burp testing workflow: "Analyzing session token generation") to check entropy; decode opaque tokens (Base64/JSON) for timestamp+username construction.
- Look for session-handling rules that auto-re-login during fuzzing (Burp "Maintaining an authenticated session") — a token that stays valid after the app tries to log you out is a signal.
- Enumerate siblin

### Signals and surfaces

### Signal

- Reports: **150** · paid: **22**
- Median bounty **$100** · p90 **$540** · max **$1,600** · total **$6,140**
- Median upvotes **11**

### Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| Shopify | 8 | $2,100 | 553 |
| HackerOne | 13 | $1,000 | 293 |
| WePay | 2 | $600 | 6 |
| X / xAI | 1 | $560 | 19 |
| Internet Bug Bounty | 4 | $540 | 123 |
| Open-Xchange | 1 | $300 | 11 |
| VK.com | 1 | $300 | 10 |
| Visma Public | 2 | $200 | 23 |

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`cookie` `session` `token` `jwt` `remember` `logout`

### Crown Jewel Targets

Session fixation leading to admin hijack = Critical. Session surviving a password change = High-to-Critical (persistent ATO from a stolen cookie that the victim believes they revoked by resetting their password).

**Highest-value chains:**
- **Session fixation** — server accepts a session ID set by the client and does NOT regenerate it on login → attacker pre-plants an ID, victim authenticates, attacker rides the now-authenticated session → persistent ATO.
- **No invalidation on logout** — old token still works after `/logout` → theft window never closes.
- **No invalidation on password / email change** — a stolen session survives the victim's "I think I was hacked, let me reset" → persistent ATO. This is the single highest-paid session bug class.
- **Refresh-token reuse without rotation-detection** — a leaked refresh token mints fresh access tokens forever; no reuse-detection means the legitimate user's later refresh does NOT revoke the attacker's branch.
- **Predictable / low-entropy session ID** — sequential, timestamp- or userId-derived IDs → brute-force or compute other users' sessions.
- **JWT-as-session with no `exp` / no revocation list** — stolen JWT = permanent access; logout is cosmetic.

---

### Attack Surface Signals

```
Set-Cookie: session=...            # name varies: sid, JSESSIONID, connect.sid,
                                   # PHPSESSID, ASP.NET_SessionId, laravel_session, _csrf
/login /logout /api/login /oauth/token
/auth/refresh /api/token/refresh   # refresh-token rotation surface
/account/change-password /settings/email
?sid= ?session= in URL             # session-in-URL → leaks via Referer/logs (finding)
```
```
# Header signals worth flagging immediately:
Set-Cookie: session=abc; Path=/                 # no HttpOnly/Secure/SameSite
Set-Cookie: session=abc; SameSite=None          # None without Secure = rejected by modern browsers, but flag
Set-Cookie: __Host-sess=...; Secure; Path=/     # GOOD — hard to fixate
Sec-Session-Registration: ...                   # DBSC in play → test downgrade
```

---

### Techniques, payloads and bypasses

### Payloads & probes

- Set-Cookie -> `; SameSite=None` without Secure
- Fixate -> `PHPSESSID=attacker` before login
- Reuse -> old token after logout/password change

### Bypass tricks

- Cross-subdomain cookie leakage.
- Token in URL/Referer.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Session works after logout from Shopify account and password of online store is displayed** — `#837729` · Shopify · $0 · ▲157
  > When a logout request has been made and response has been received/displayed that logout is successful, session still works when
- **H1514 Session Fixation on multiple shopify-built apps on *.shopifycloud.com and *.shopifyapps.com** — `#423136` · Shopify · $0 · ▲144
  > Attacker uses XSS on .shopifycloud.com and writes the cookie scoped to all subdomain to victim `document.cookie=' flow session=EVIL;domain=.shopifycloud.com;path=/';`
- **Session Cookie Leakage via Static Header Field in WebViewerFragment** — `#3475626` · LinkedIn · $0 · ▲131
  > A static field (`CUSTOM HEADERS`) in `WebViewerFragment` persists cookies across different URL loads, allowing an attacker to chain multiple weaknesses to exfiltrate a victim's LinkedIn session cookies to an attacker-controlled server.
- **No Session Expiry after log-out, attacker can reuse the old cookies** — `#1162443` · Shopify · $500 · ▲87
  > Now open another browser and import those cookies - you can able to login an account by using cookies
- **Insufficient session expiration in the **com.shopify.ping** android app** — `#1172205` · Shopify · $0 · ▲63
  > More specifically, after the user provides the required credentials, an access token will be fetched from the server at accounts.shopify.com/oauth/token.
- **Session Persistence Designed to Keep Us

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 5× | `rtsp_connect()` |
| 5× | `$\x00\x00\x10` |
| 3× | `Curl_ws_accept()` |
| 3× | `Curl_ssl_scache_take()` |
| 3× | `rtsp_filter_rtp()` |
| 3× | `rtsp_done()` |
| 2× | `(valid_until > 0) && (valid_until < now)` |
| 2× | `(-1 > 0) = FALSE` |
| 2× | `curl_easy_ssls_export()` |
| 2× | `valid_until < 0` |
| 2× | `match_ssl_primary_config()` |
| 2× | `SSL_connect()` |
| 2× | `rtspc->in_header = FALSE` |
| 2× | `rtspc->buf` |
| 2× | `curl -c cookies.txt -b cookies.txt https://somesite.tld:9999/` |
| 2× | `ssl_peer_key_build()` |
| 2× | `peer->origin->scheme->family` |
| 1× | `document.cookie='_flow_session=EVIL;domain=.shopifycloud.com;path=/';` |
| 1× | `javascript://www.linkedin.com/%0aalert(1)` |
| 1× | `javascript://www.linkedin.com/%0aalert(1)?renderContext=trustVerificationDeeplink` |

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- Session fixation: set a known `PHPSESSID`/`JSESSIONID` in the victim (via URL param, hidden form field, or subdomain cookie injection), let them authenticate, then reuse the pre-set ID. Failure to regenerate on login = CWE-384.
- No invalidation: replay the old cookie after logout, after password change, and after email change; a persistent ATO results if the server accepts it. HackerOne reports #3101207 (auto sign-in without credentials after logout) and #3120790 (captured login response replay) are public precedents.
- Predictable token: decode your own cookie, deduce the formula (e.g. `base64(user|timestamp)` or unsalted `md5(password)`), then brute-force another user's cookie offline — bypassing login rate limits because cookie guesses hit a different endpoint.
- Refresh-token abuse (HackTricks + Auth0 2025 detection catalog): redeem RT1 → get RT2; redeem RT1 again (must fail); redeem RT2 (with proper reuse detection it must also fail because the whole token family is revoked). If RT2 still works, there is no rotation-based replay detection. Also check unused RTs after logout/password change/app revocation.
- Sender-constrained token downgrade: take a DPoP-bound token and send `Authorization: Bearer <TOKEN>` with no `DPoP` header, replay an old `iat` proof, reuse a proof with the wrong `htm`/`htu`, or sign with a key not matching `cnf.jkt`. For mTLS tokens, call the API with no client certificate.
- Path-scope cookie confusion: if the app sets `_access_cookie` for `/` and for sensitive subpa

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

### Phase 2 — Invalidation on Logout

```bash
# A logs in for real (fresh jar), capture A's live session.
curl -s -L -c "$JAR_A" -X POST "https://$TARGET/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"attacker@example.com","password":"CorrectHorse1"}' -o /dev/null
A=$(get_cookie "$JAR_A"); echo "A=$A"

# Baseline: what does an authenticated /api/me look like for A? (capture body, not just code)
BEFORE=$(curl -s -L -b "$JAR_A" "https://$TARGET/api/me")

# Logout A.
curl -s -L -b "$JAR_A" -X POST "https://$TARGET/api/logout" -o /dev/null

# Replay A's OLD cookie value explicitly (do NOT reuse the jar — logout may have
# overwritten it). Compare body + code against the authenticated baseline.
AFTER=$(curl -s -L -H "Cookie: $A" "https://$TARGET/api/me" -w '\n[%{http_code}]')
echo "AFTER: $AFTER"
```
**FP discipline (mandatory):**
- Don't trust the status code. A cached/edge 200 or a generic SPA shell returns 200 for everyone. **Body-diff** `AFTER` against `BEFORE` — the finding is only real if `AFTER` still contains A's *unique identity marker* (email, user-id, CSRF token, account name).
- Confirm with a **negative control**: a random/garbage cookie value must NOT return the same authenticated body. If garbage also yields 200 with user data, the endpoint isn't session-gated and there's no finding here.
- Re-test after a **short delay** and from a **different IP** — some servers lazily expire on next access or pin sessions to IP.

### Phase 3 — Invalidation on Password / Email Change (persistent-ATO core)

```bash
# This is the real two-session flow. A = attacker holding a stolen/old session.
# B = the victim who changes their password believing it revokes access.
# (In a real engagement A is a session you legitimately captured for a TEST account
#  that you also control as B — never use a real third party.)

# 1) Log the TEST account in as session A, capture it.
curl -s -L -c "$JAR_A" -X POST "https://$TARGET/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@example.com","password":"OldPass!1"}' -o /dev/null
SESSION_A=$(get_cookie "$JAR_A"); echo "SESSION_A=$SESSION_A"
BEFORE=$(curl -s -L -H "Cookie: $SESSION_A" "https://$TARGET/api/profile")

# 2) Log the SAME account in as session B (separate jar = "the victim's browser").
curl -s -L -c "$JAR_B" -X POST "https://$TARGET/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@example.com","password":"OldPass!1"}' -o /dev/null

# 3) Victim (session B) changes the password.
curl -s -L -b "$JAR_B" -X POST "https://$TARGET/api/change-password" \
  -H 'Content-Type: application/json' \
  -d '{"old_password":"OldPass!1","new_password":"BrandNew!2"}' -o /dev/null

# 4) THE TEST: replay the OLD SESSION_A captured in step 1.
AFTER=$(curl -s -L -H "Cookie: $SESSION_A" "https://$TARGET/api/profile" -w '\n[%{http_code}]')
echo "AFTER pw-change: $AFTER"
```
**Decision + FP discipline:**
- Finding is confirmed only if `AFTER` returns 200 **and** the body still carries the account's unique data (body-diff vs `BEFORE`)

### Validation (house FP discipline)

Before claiming ANY session finding:
- **Two real sessions, not placeholders** — every fixation/invalidation claim uses A and B captured by the `curl` flows above.
- **Body-diff, never status-only** — a 200 means nothing without the account's unique identity marker present in the body, diffed against the authenticated baseline.
- **Negative control** — a garbage/random cookie must FAIL where your "surviving" cookie succeeds; otherwise the endpoint isn't session-gated and it's a non-finding.
- **Cache/edge check** — re-request with a cache-buster and from a second IP; rule out an edge-cached or IP-pinned 200.
- **OOB for theft chains** — when the impact depends on exfiltrating a cookie/token (XSS, SSRF, log leak), confirm receipt out-of-band (Collaborator) rather than asserting it.
- **Static-vs-state** — `HttpOnly`/`Secure`/`SameSite` absence is a *policy* observation; only report as High once paired with a real exploit primitive (XSS, network-MITM, CSRF). Standalone attribute gaps are Low/Informational.

**Severity:**
- Session fixation → admin/SSO takeover: **Critical**
- No invalidation on password/email change, or refresh-token reuse without detection: **High → Critical** (escalate if MFA/step-up also absent)
- Predictable/duplicate session ID: **High**
- No invalidation on logout: **Medium → High** (depends on theft vector)
- Missing `HttpOnly`/`SameSite` standalone: **Low/Informational** until chained

### C. Validation / proof bar — how to confirm and avoid false positives

- Use TWO real sessions (attacker A + victim B). Body-diff every 200 response; show a live authenticated action as B from A's starting position, not merely an accepted cookie.
- For theft chains, require out-of-band confirmation (Collaborator hit with the token) or a demonstrated login as the victim; a leaked cookie that is HttpOnly/secure-scoped and never delivered anywhere is not a finding.
- Rotation/reuse: honor documented grace periods — an overlap window is legitimate (Auth0 false-positive note). Only claim missing reuse detection after RT2 works *outside* any grace window; confirm family revocation by testing both tokens.
- Fixation requires showing the victim actually authenticates on the attacker-chosen ID; a cookie you set but the server ignores is not fixation.
- Cookie-attribute-only findings (missing `HttpOnly`/`SameSite` with no theft vector) are Low/Informational until chained.
- Redact session cookies and other-user PII in the PoC; preserve raw Set-Cookie headers in evidence but mask values.

- Prove fixation with a full walkthrough: seed the token, have the victim log in, then use the token from a browser that never saw their credentials. Showing that the token is merely accepted post-login is not enough.
- For "no invalidation" findings, replay at three points — logout, password change, and email change — and note each result; a control that works at only one point is still a finding but the impact differs.
- Verify the stale token still accesses *sensitive* data, not just a static p

_...and 1 more sections in `references/unified-method.md`._

### Escalation and related chains

### Escalation chains

- Session fixation -> ATO.
- Token leak -> session hijack.

### Chain Table

| Session finding | Chain to | Impact |
|----------------|----------|--------|
| Session fixation (forced `__Host-`-less cookie) | Trick admin/SSO user into authenticating on planted ID | Admin session takeover (Critical) |
| No logout/password-change invalidation | `xss`/`dom` cookie theft → replay surviving session | Persistent ATO past victim's reset |
| Refresh token, no reuse-detection | Leaked RT (SSRF/log/bundle) → infinite access-token minting | Persistent ATO, survives password change |
| `SameSite=Lax` only | Sibling-subdomain top-level nav (CVE-2024-22424 class) → CSRF | State change / login-CSRF → fixation |
| JWT no `exp`/`jti` | Stolen token, no server revocation | Permanent access |
| DBSC downgrade accepted | Steal plain cookie despite device-binding | Defeats the only theft mitigation |
| Predictable ID | Compute/brute another user's session | Cross-user ATO |

---

### Chain Table

| Session finding | Chain to | Impact |
|----------------|----------|--------|
| Session fixation (forced `__Host-`-less cookie) | Trick admin/SSO user into authenticating on planted ID | Admin session takeover (Critical) |
| No logout/password-change invalidation | `hunt-xss`/`hunt-dom` cookie theft → replay surviving session | Persistent ATO past victim's reset |
| Refresh token, no reuse-detection | Leaked RT (SSRF/log/bundle) → infinite access-token minting | Persistent ATO, survives password change |
| `SameSite=Lax` only | Sibling-subdomain top-level nav (CVE-2024-22424 class) → CSRF | State change / login-CSRF → fixation |
| JWT no `exp`/`jti` | Stolen token, no server revocation | Permanent access |
| DBSC downgrade accepted | Steal plain cookie despite device-binding | Defeats the only theft mitigation |
| Predictable ID | Compute/brute another user's session | Cross-user ATO |

---

### Tools and wordlists

### Tools

`Burp` · `jwt_tool` · `browser devtools`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_session.txt` | 70 |
| `~/.local/share/hackerone-reports/wordlists/params_session.txt` | 57 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_session.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_session.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

### Nuclei

Check cookie flags and token lifecycle by hand; scanner coverage is thin.

```sh
nuclei -u https://target -tags cookie,session,jwt,token \
       -severity low,medium,high,critical -rl 40 -o nuclei_session.txt
nuclei -u https://target -t ~/nuclei-templates/http/misconfiguration \
       -rl 40 -o nuclei_session_misconfiguration.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Source skills merged into this topic

- `h1skills` — `hackerone-session`
- `hunting` — `session`
- `cbh` — `hunt-session`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 2 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `references/unified-method.md` — includes 2 merged companion methodology documents
- `references/corpus-wordlists/` — 2 mined paths/params/payload lists from the HackerOne corpus
- `../../upstream/` — complete unmodified archives of all five source repositories
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
