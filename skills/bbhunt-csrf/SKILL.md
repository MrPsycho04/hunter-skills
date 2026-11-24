---
name: bbhunt-csrf
description: "Use for tokenless or weakly validated state-changing requests, cross-origin form/JS PoCs, login/link CSRF, and SameSite/Origin checking gaps. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Cross-Site Request Forgery — unified methodology

> **Unified skill.** Built from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus-backed method (this class)

1. Inventory state-changing endpoints: create, update, delete, invite, email/role change, and unsubscribe.
2. For each, check token presence, token binding to session, and server-side validation on all accepted methods/content types.
3. Inspect cookie attributes (SameSite, Secure) and Origin/Referer validation; determine whether a cross-origin request can carry credentials.
4. Build a real cross-origin PoC (form, image, fetch with credentials where allowed) — do not report on scanner output alone.
5. Test method and content-type overrides; a token enforced on JSON may be ignored on form/multipart.
6. Evaluate impact by action sensitivity: email change and account linking are high value; unauthenticated/no-sensitive-action forms are not.

### Signals

- State-changing GET or POST without a token
- Token present but not bound to the session, or accepted from a different parameter
- Origin/Referer checks that can be removed or spoofed
- Cookie without SameSite on a mutating endpoint

### Kill criteria

- No sensitive state change for an authenticated victim.
- Token correctly validated and bound; SameSite blocks credentialed cross-origin request.
- Requires the victim to enter credentials or take unusual actions.

### Escalation chains

- CSRF email change -> reset flow -> ATO.
- CSRF account linking -> third-party identity takeover.
- CSRF admin action -> privilege or configuration change.

### Veteran tip

Only a minority of valid CSRF reports paid — but the technique is real; always price the *action*, not the presence of a token.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Find state-changing requests and check for anti-CSRF tokens and SameSite cookies.
- Remove the token, blank it, reuse another session's token, and try a fixed token.
- Try GET, form POST, text/plain JSON, multipart, and method override.
- Check email/password change, OAuth consent, and login CSRF.
- Look for subdomain XSS or cookie scope that enables CSRF.

### Deeper checklist

- Identify state-changing requests and check for anti-CSRF tokens and SameSite cookies.
- Test token validation: missing token, empty token, token from another session, fixed token.
- Try method/content-type tricks: GET, POST forms, text/plain JSON, multipart, method override.
- Check CORS misconfigurations that allow credentialed cross-origin reads/writes.
- Test login CSRF, logout CSRF, OAuth state CSRF, and email-change CSRF.
- Look at subdomain/XSS-assisted CSRF where cookies are scoped to the parent domain.
- Build a minimal PoC page and confirm the state change on a victim account.

### Autonomous Testing Priority

**CSRF only matters on state-changing actions that a browser could be tricked into making cross-site.**

**Testing flow:**
1. **GET the form endpoint** to establish a baseline and check what fields exist (look for hidden `csrf_token`, `authenticity_token`, `_token`, `csrfmiddlewaretoken` fields).
2. **POST the state-changing action without any CSRF token field.** Send only the functional parameters (email, amount, etc.).
3. **Use a "simple-request" Content-Type** — `application/x-www-form-urlencoded`, `multipart/form-data`, OR `text/plain` are the three CORS "simple" content-types a cross-origin form can send with no preflight. A JSON endpoint is CSRF-resistant **only if the server rejects those** — if it also accepts a `text/plain` body (common), craft a `text/plain` payload that parses as valid JSON (see the JSON-CSRF-via-text/plain section). Don't skip a JSON endpoint on the assumption that `application/json` alone is protective.
4. **If the action succeeds (2xx, no "invalid token" error) → CSRF is confirmed.**

**High-value targets (in order of impact):**
- Email/password change → account takeover
- Money transfer or payment → financial fraud
- Admin actions (role assignment, user deletion)
- OAuth social-account linking → persistent ATO

**Token bypass techniques when a token IS present:**
- Omit the token field entirely — some frameworks only validate if the field exists, not if it's absent
- Send an empty value (`_token=`) — some validate format, not presence
- Copy a token from another session — some tokens aren't tied to the session

### Step-by-Step Hunting Methodology

1. **Map all state-changing endpoints** — Spider authenticated session, filter for POST/PUT/DELETE/PATCH. Note every form and AJAX call.

2. **Check cookie SameSite attributes** — In DevTools → Application → Cookies. Flag any session cookie without `SameSite=Strict` or `Lax`.

3. **Test token staticness** — Log in twice (different sessions or incognito). Compare `authenticity_token` / `csrfmiddlewaretoken` / `csrf-token` values across:
   - Same session, different page loads (should be different)
   - Different sessions for same user
   - Different users entirely

4. **Test token omission** — Remove the CSRF token field entirely from a POST request. If the server returns 200, you have CSRF.

5. **Test token substitution** — Replace the token with one from a different session. Server accepting it = broken validation.

6. **Test JSON endpoints for form-POST CSRF** — Check if Content-Type is enforced:
   - Send `application/x-www-form-urlencoded` to a JSON endpoint
   - Send `text/plain` with a JSON body
   - If accepted, HTML form can trigger it cross-origin

7. **Hunt OAuth/SSO RelayState** — Intercept SAML/OIDC flows. Test if `RelayState` is validated for same-origin. Inject external URLs.

8. **Check social linking flows** — Every "connect your X account" feature. These often use redirect-based OAuth where CSRF on the callback can associate an attacker's social account.

9. **Test third-party dashboards on subdomains** — Grafana, Kibana, Prometheus. Check version, apply known CVEs, test default CSRF posture.

10. **Build PoC HTML page*

### Web-Research Methodology Additions (2026)

Research basis: PortSwigger Web Security Academy "Bypassing SameSite cookie restrictions" and the OWASP CSRF Prevention Cheat Sheet (Fetch Metadata, client-side CSRF, signed double-submit cookies, origin verification). OWASP's leading reminder still governs triage: **XSS defeats every CSRF mitigation** — so if you have XSS, chain it rather than double-reporting.

### A. Discovery checklist — concrete places, params, headers, flows to look

- **Fetch Metadata headers on protected requests:** `Sec-Fetch-Site` (same-origin / same-site / cross-site / none), `Sec-Fetch-Mode`, `Sec-Fetch-Dest`, `Sec-Fetch-User`, plus a `Vary: Sec-Fetch-Site, Origin` response. A missing/ignored `Sec-Fetch-Site` is the newest common gap.
- **Origin verification logic:** `Origin` / `Referer` checks, and whether a literal `null` is allow-listed. OWASP warns null origins arise from cross-origin redirects and sandboxed iframes without `allow-same-origin` — both attacker-creatable.
- **Custom CSRF header names:** `X-CSRF-Token` (Rails/Laravel/Django), `X-XSRF-Token` (AngularJS), `CSRF-Token` (Express csurf), `X-CSRFToken`. Their presence implies a preflight-based defense — test whether the server actually rejects requests lacking them.
- **Cookie shape:** `__Host-` prefix vs a bare `Domain=` cookie; `SameSite=Strict|Lax|None`, `Secure`. A domain-scoped session cookie shared with sibling subdomains is the classic site-based bypass.
- **Double-submit implementation:** is the token merely duplicated in a cookie (naive, forgeable via a sibling subdomain or plaintext-HTTP cookie injection) or HMAC-bound to the session (signed)?
- **Client-side CSRF gadgets:** JS that builds `fetch()` from `location.hash` / `location.search` (e.g. `#post;/api/profile`), DOM-based open redirects used as on-site gadgets, `postMessage`-driven requests.
- **Sites vs origins:** enumerate every sibling subdomain of the registrable domain — a cross-origin, same-site XSS/subdomain-takeover de

### Signals and surfaces

### Signal

- Reports: **541** · paid: **93**
- Median bounty **$300** · p90 **$2,450** · max **$10,000** · total **$69,328**
- Median upvotes **9**

### Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| GitHub | 2 | $10,000 | 152 |
| HackerOne | 20 | $8,850 | 735 |
| GitLab | 6 | $6,570 | 287 |
| X / xAI | 16 | $5,320 | 598 |
| TikTok | 12 | $4,847 | 847 |
| Internet Bug Bounty | 2 | $4,660 | 58 |
| Uber | 9 | $4,000 | 256 |
| PayPal | 1 | $3,500 | 81 |

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`email` `password` `change` `delete` `transfer` `invite` `settings` `oauth` `consent`

### Crown Jewel Targets

CSRF becomes high-value when it touches **state-changing actions with account-level or financial consequences**. The highest-paying targets are:

- **Account takeover vectors**: OAuth/SSO flows (RelayState manipulation), social account linking/unlinking (Oculus-Facebook, SocialClub), import-friends features that expose OAuth tokens
- **Authentication infrastructure**: Login CSRF, session fixation via CSRF, forced account association
- **API endpoints accepting cross-origin POST**: JSON APIs, heartbeat/activity APIs, anything that skips Content-Type enforcement
- **Third-party integrations**: Grafana, monitoring dashboards, embedded analytics — often lag on CSRF protections
- **Social platforms**: Twitter/X collections, friend imports, social graph mutations — high-volume, authenticated actions with real user impact

**Asset types that pay most:** Core product auth flows > API gateways > third-party integrations running on subdomains > admin panels.

---

### Response Header Signals

```
# Missing or weak SameSite cookie attributes
Set-Cookie: session=abc123; HttpOnly        # no SameSite = vulnerable
Set-Cookie: session=abc123; SameSite=None   # explicitly allows cross-site

# Missing CSRF headers
# No X-Frame-Options or permissive CORS
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true      # dangerous combo
```

### Tech Stack Signals

- **Rails apps**: Look for `authenticity_token` — test if it's static per session
- **Django apps**: Check `csrfmiddlewaretoken` — test cross-user/session reuse
- **Grafana instances**: CVE-2022-21703 — check version via `/api/health`
- **SAMLv2/OIDC flows**: `RelayState` parameter rarely validated
- **Express/Node APIs**: Often skip CSRF middleware on `/api/*` routes

---

_...and 1 more sections in `references/unified-method.md`._

### Techniques, payloads and bypasses

### Payloads & probes

- Form -> `<form action=https://target/email method=POST><input name=email value=attacker@x>`
- JSON -> `<form enctype=text/plain><input name='{"email":"attacker@x","x":"' value='"}'>`
- GET -> `<img src=https://target/settings?email=attacker@x>`
- Method override -> `_method=POST` in a GET/form request

### Bypass tricks

- Token not bound to session; token from another account accepted.
- SameSite=Lax bypass via top-level GET or 2-minute window.
- CORS misconfig allowing credentialed cross-origin requests.
- Bypass token check by changing content-type or removing the parameter.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **[CSRF] TikTok Careers Portal Account Takeover** — `#1010522` · TikTok · $0 · ▲366
  > If you have any feedback, feel free to ping me at [Twitter](https://twitter.com/ lauritz ).
- **CSRF on connecting Paypal as Payment Provider** — `#807924` · Shopify · $0 · ▲304
  > `https://h60ngalog.myshopify.com/admin/payments/complete paypal incontext oauth/41?merchantId=MTU4MzAzMDUwNDowMTBmMDZkYjg1NzM0YjQ4NWVkMDk1YzQ1YWYxY2ZlNw%3D%3D&merchantIdInPayPal=5NS8DHQCFGT84&permissionsGranted=true&accountStatus=BUSINESS…
- **Periscope android app deeplink leads to CSRF in follow action** — `#583987` · X / xAI · $1,540 · ▲224
  > + It means we can use ` pscp://user/<user-id or pscpd://user/<user-id `
- **Take over of accounts created using Google or Facebook** — `#442901` · Khan Academy · $0 · ▲184
  > Since the account is created using a social media account, no existing password check is needed and the CSRF check on the endpoint is broken.
- **Improper CSRF token validation allows attackers to access victim's accounts linked to Hackerone** — `#1727221` · HackerOne · $0 · ▲168
  > Then it redirects us to the callback endpoint which sends a postmessage to the embedded iframe to validate the integration on the client side.
- **CSRF protection bypass in GitHub Enterprise management console** — `#1497169` · GitHub · $10,000 · ▲152
  > [CVE-2022-23732](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23732)
- **Slack integration setup lacks

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 3× | `new.cs.money{.withgoogle.com` |
| 2× | `www.pscp.tv/<user-id>/follow` |
| 2× | `new.cs.money{.attacker.com` |
| 2× | `http://localhost$something.io` |
| 2× | `<html> / <!-- CSRF PoC - generated by Burp Suite Professional --> / <body> / <script>history.pushState('', '', '/')</script> / <form action=` |
| 1× | `MTU4MzAzMDUwNDowMTBmMDZkYjg1NzM0YjQ4NWVkMDk1YzQ1YWYxY2ZlNw%3D%3D` |
| 1× | `pscp://user/<user-id> or pscpd://user/<user-id>` |
| 1× | `{F1976253} / 3. Following the redirection takes us to the authorization page of the service provider / {F1976255} / If we choose to Authoriz` |
| 1× | `This endpoint validates the code received from Github, the backend relies on the ***state*** parameter to determine to which user should the` |
| 1× | `Location: https://slack.com/oauth/authorize / ?client_id=2174110321.11522100978 / &redirect_uri=https%3A%2F%2Fhackerone.com%2Fauth%2Fslack%2` |
| 1× | `<meta name="referrer" content="origin" />` |
| 1× | `$this->request->getHeader("Authorization")` |
| 1× | `GET /2.0/repositories/%7B766210f9-9bec-4010-9f4d-917b06661c0c%7D HTTP/2 / Host: api.bitbucket.org / User-Agent: curl/7.79.1 / Accept: */* /` |
| 1× | `gitlab@gitlab.com` |
| 1× | `https://academy.acronis.com/#/account/edit/account_id/<your_id>` |
| 1× | `<img>` |
| 1× | `__utmz=123456.123456789.11.2.utmcsr=[HOST]\\|utmccn=(referral)\\|utmcmd=referral\\|utmcct=[PATH]` |
| 1× | `__utmz=123456.123456789.11.2.utmcsr=blackfan.ru\\|utmccn=(referr

### Common Root Causes

1. **Static CSRF tokens per session** — Developers generate one token at login and reuse it. Airbnb bug: `authenticity_token` was the same across all page loads for a session, making it trivially leakable.

2. **Token not tied to user identity** — Token is valid server-wide or rotates on a schedule, not per-user/session. Mozilla bug: `csrftoken` reusable across users.

3. **Missing token on "secondary" endpoints** — Developers protect login/signup but forget API endpoints, import flows, or webhook handlers.

4. **JSON API assumption of safety** — Belief that `Content-Type: application/json` prevents CSRF. It does via CORS preflight — unless the server also accepts `text/plain` or `application/x-www-form-urlencoded`.

5. **SameSite=None for cross-site embeds** — Developers set `SameSite=None` to support iframe embeds or third-party integrations, inadvertently re-enabling CSRF.

6. **OAuth RelayState not validated** — Developers implement SAML/OIDC but treat `RelayState` as a redirect hint, not a CSRF state parameter requiring cryptographic binding.

7. **Framework misconfiguration** — CSRF middleware excluded for `/api/*` routes in Django/Rails because "API clients don't need it," but browser-based JS clients do.

8. **Third-party software defaults** — Grafana, Kibana, Jenkins shipped with weak or no CSRF protection in older versions; teams don't patch or check.

---

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Lax + GET bypass:** if the server accepts GET for a state-changing route, a top-level navigation sends the Lax cookie: `<script>document.location='https://target/account/transfer?to=hacker&amt=100'</script>`. Method-override parameters (Symfony `_method=POST`) turn a GET into a routed POST.
- **Strict bypass via on-site gadget:** a client-side redirect whose target comes from a URL parameter produces an ordinary **same-site** request (browsers don't treat client-side redirects as cross-site), so all cookies ride along. Server-side 302s do NOT work this way.
- **Vulnerable sibling domain:** any XSS or takeover on `*.example.com` can issue same-site requests, defeating site-based defenses and fetching custom headers if CORS is regex-permissive.
- **Null-origin bypass:** serve the PoC from a sandboxed iframe (`<iframe sandbox>` without `allow-same-origin`) so `e.origin` is `null`; if the app allowlists `null` (or compares against `window.origin`, which sandboxing also makes `null`), the check passes. PortSwigger also notes `Origin`-omission cases.
- **Naive double-submit forge:** from a controlled sibling or via plaintext HTTP cookie injection, plant a matching cookie; the server compares cookie==parameter and accepts. Only the signed, session-bound HMAC pattern resists this.
- **Referer string checks:** permissive prefix/format validation is bypassable the same way as weak postMessage/CORS checks (e.g. a look-alike host).
- **Client-side CSRF:** manipulate the hash fragment that the JS feeds to 

_...and 1 more sections in `references/unified-method.md`._

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

### Gate 0 Validation

1. **What can the attacker DO right now?** — The attacker must be able to trigger a specific state-changing action (account linking, email change, data deletion, social association) on behalf of the victim without any interaction beyond visiting a URL or page.

2. **What does the victim LOSE?** — Identify the concrete harm: account access (ATO), data exposure, financial loss, reputation damage. "A CSRF token is missing" is not impact — "attacker can link their Oculus account to victim's Facebook account, gaining full profile access" is impact.

3. **Can it be reproduced in 10 minutes from scratch?** — You must be able to: (a) create attacker and victim accounts, (b) host a static HTML PoC, (c) have victim visit PoC, (d) confirm the action executed in victim's account — all within 10 minutes with no additional prerequisites.

---

### C. Validation / proof bar — how to confirm and avoid false positives

- **Gate 0 (keep the skill's existing test):** attacker and victim accounts, a static PoC, victim visits, confirm the action executed in the victim's account — reproducible in 10 minutes. State what the victim *loses*, not that "a request fired."
- **Real browser for real defenses:** a spoofed `Origin`/`Referer` header proves only a naive string check (the raw-client shortcut in this skill). Genuine SameSite/fetch-based enforcement needs an actual cross-origin page and a browser to observe cookie attachment in DevTools.
- **Null-origin must be real:** produce it with a sandboxed iframe and show the request carrying the victim's cookie — don't claim it from a forged header.
- **Fetch-Metadata finding:** show the request's `Sec-Fetch-Site` value and that the server accepted it despite the policy.
- **Avoid false positives:** logout and login-only CSRF, read-only GETs, and "token missing on an endpoint that changes nothing" are N/A. XSS on the origin is not a separate CSRF finding — chain it.
- **Chain to severity:** prove ATO (email/account link), money movement, or admin state change; otherwise report at the base severity.

- **Method/Content-Type matrix:** repeat with form, `text/plain` JSON, and a custom header. A single accepted variant is the finding; document exactly which.
- **Origin variations:** no header, trusted value, look-alike value, and `null` — record which the server accepts.
- **Cookie attachment:** in the victim browser, confirm the session cookie is present on the cross-origin reques

### Escalation and related chains

### Escalation chains

- CSRF -> email change -> ATO.
- CSRF -> OAuth link -> ATO.
- CSRF + XSS -> worm.

### Related Skills & Chains

- **`xss`** — Any XSS on a trusted origin neutralizes CSRF defenses (token, SameSite, Origin check) instantly. Chain primitive: XSS reads the `meta[name=csrf-token]` value and same-origin-fetches `/accounts/email` with attacker payload → one-click ATO via attacker-page postMessage triggering the stored XSS to perform the state change.
- **`auth-bypass`** — CSRF combined with an auth-bypass primitive lets attacker-side scripts perform state changes that should have required step-up auth. Chain primitive: CSRF on `/settings/password` reaches an endpoint that skips the re-auth check → password change executes without the victim ever entering their current password → ATO.
- **`oauth-oidc`** — OAuth/SAML `state`/`RelayState` is structurally a CSRF token; missing validation here is account-linking CSRF. Chain primitive: attacker initiates OAuth on their account, sends victim the `/callback?code=X&state=` URL → victim's logged-in browser completes the link → attacker's social identity now controls victim's account.
- **`security-arsenal`** — Reach for the CSRF PoC templates (form POST, `enctype=text/plain` JSON, sandboxed-iframe null-origin, base64 multipart bypass) before writing one from scratch; also the WAF-bypass header variants for Origin/Referer checks.
- **`triage-validation`** — Run the Pre-Severity Gate before submitting CSRF on a logout endpoint or any action without state-change consequence — those are the canonical N/A traps. Confirm victim LOSES something concrete (account access, money, data), not just "a request executed."

### Related Skills & Chains

- **`hunt-xss`** — Any XSS on a trusted origin neutralizes CSRF defenses (token, SameSite, Origin check) instantly. Chain primitive: XSS reads the `meta[name=csrf-token]` value and same-origin-fetches `/accounts/email` with attacker payload → one-click ATO via attacker-page postMessage triggering the stored XSS to perform the state change.
- **`hunt-auth-bypass`** — CSRF combined with an auth-bypass primitive lets attacker-side scripts perform state changes that should have required step-up auth. Chain primitive: CSRF on `/settings/password` reaches an endpoint that skips the re-auth check → password change executes without the victim ever entering their current password → ATO.
- **`hunt-oauth`** — OAuth/SAML `state`/`RelayState` is structurally a CSRF token; missing validation here is account-linking CSRF. Chain primitive: attacker initiates OAuth on their account, sends victim the `/callback?code=X&state=` URL → victim's logged-in browser completes the link → attacker's social identity now controls victim's account.
- **`security-arsenal`** — Reach for the CSRF PoC templates (form POST, `enctype=text/plain` JSON, sandboxed-iframe null-origin, base64 multipart bypass) before writing one from scratch; also the WAF-bypass header variants for Origin/Referer checks.
- **`triage-validation`** — Run the Pre-Severity Gate before submitting CSRF on a logout endpoint or any action without state-change consequence — those are the canonical N/A traps. Confirm victim LOSES something concrete (account access, money, data), not just "a request executed."

### Tools and wordlists

### Tools

`Burp CSRF PoC generator` · `browser devtools` · `mitmproxy`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_csrf.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_csrf.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_csrf.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_csrf.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

### Nuclei

Confirm with a real cross-origin PoC; scanner hits need a browser check.

```sh
nuclei -u https://target -tags csrf \
       -severity low,medium,high,critical -rl 40 -o nuclei_csrf.txt
nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/generic \
       -rl 40 -o nuclei_csrf_generic.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Grep patterns for recon

```bash
# Find CSRF token fields in HTML responses
grep -Eo 'name="(csrf|_token|authenticity_token|csrfmiddlewaretoken)"[^>]*value="[^"]+"'

# Find forms without CSRF tokens
grep -B5 -A20 '<form method="[Pp][Oo][Ss][Tt]"' response.html | grep -L "csrf\|token\|nonce"

# Check SameSite in response headers
curl -sI https://target.com/login | grep -i "set-cookie"

# Find RelayState parameters
grep -r "RelayState" --include="*.js" .
```

## Source skills merged into this topic

- `h1skills` — `hackerone-csrf`
- `hunting` — `csrf`
- `cbh` — `hunt-csrf`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
