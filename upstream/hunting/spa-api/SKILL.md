---
name: spa-api
description: Discover a single-page-app's hidden backend API from its public JS bundle, then test that API for broken access control / missing authentication. One of the highest-yield web plays in modern recon — SPAs ship their entire backend route map to the browser, and the API behind them is frequently missing the auth middleware the login page implies. Built from an authorized engagement where this play found an unauthenticated financial API that an ASM scan reporting hundreds of "Criticals" completely missed. Use whenever a target serves a JS-heavy SPA (React/Vue/Angular/Next), an "app"/"console"/"dashboard"/"portal" subdomain, or any `*api*` host shows up in recon. Leaked build artifacts (source maps / .env / .git / asset-manifest) are owned by info-disclosure; API version-inventory and behavioral diffing by shadow-api; this skill owns mapping a live SPA's backend routes from its JS bundle and testing them for broken access control / missing auth.
---

## When to use this skill

Trigger when:
- A target host returns a tiny HTML shell + big `/static/js/*.js` or `/_next/static/*` bundles (React/Vue/Angular/Next/Svelte SPA)
- You see a subdomain named `console`, `app`, `dashboard`, `portal`, `admin`, `panel`, `manage`, `internal`
- Recon surfaces any `*api*`, `*-api*`, `api.*` host
- A login page is OAuth/SSO-gated (the *frontend* auth tells you nothing about whether the *API* enforces auth)

The core insight: **a SPA is a client to a backend API, and it ships the full map of that API — hosts, routes, sometimes keys — to anyone who views source.** The login page being protected says nothing about whether the API behind it checks tokens. Auth is frequently enforced on the *gateway/login* and missing on a *route group* of the API.

DO NOT skip this because "the app needs login" — that's exactly when this pays off.

---

## The play (5 steps)

### 1. Pull the shell + enumerate the bundles
```bash
curl -s https://console.target.com/ -o index.html
# React/CRA:
grep -oE '/static/js/[^"]+\.js' index.html
# Next.js:
grep -oE '/_next/static/[^"]+\.js' index.html
# generic:
grep -oiE 'src="[^"]+\.js[^"]*"' index.html
```
Download every bundle (they can be multi-MB — that's fine, it's all route data):
```bash
mkdir bundles
for j in $(grep -oE '/static/js/[^"]+\.js' index.html | sort -u); do
  curl -s "https://console.target.com$j" -o "bundles/$(echo "$j"|tr '/' '_')"
done
```

### 2. Harvest API hosts, routes, and secrets from the bundles
```bash
B=bundles/*.js
# Backend API hosts (incl. dev/beta/staging variants — often weaker auth)
grep -ohiE 'https://[a-z0-9.-]*(api|console|backend|service)[a-z0-9.-]*\.target\.com[a-z0-9/_-]*' $B | sort -u
# Versioned API base paths
grep -ohiE '/api/v[0-9]+/?' $B | sort -u
# Route literals — minified bundles store routes as STRING segments, not full URLs.
# Grep for quoted "resource/action" strings:
grep -ohiE '"[a-z0-9_-]+/[a-z0-9_/-]+"' $B | tr -d '"' \
  | grep -iE '(login|user|account|order|billing|invoice|payment|deal|report|token|otp|password|reset|admin|profile|auth|upload|export|role|permission|dashboard|wallet|finance|sales)' | sort -u
# Secrets (validate before trusting — most AIza keys are Maps/analytics, not Auth)
grep -ohiE '(AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|sk_live_[0-9A-Za-z]+|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|apiKey["'"'"']?\s*[:=]\s*["'"'"'][^"'"'"']+)' $B | sort -u
```
**Note:** minifiers store routes as concatenated string segments (e.g. `"account/payment/list"`), NOT full `/api/v2/...` URLs — so a naive `/api/v*` grep returns nothing. Grep for the **resource-word route strings** and prepend the base yourself.

**Lazy-loaded (async) chunks — don't stop at HTML-referenced bundles.** CRA/webpack SPAs reference only runtime+main+vendor in index.html; numbered async route chunks are named inside main.js's chunk map and loaded at runtime, so grepping only `/static/js/*.js` from the shell truncates route coverage to eager chunks.
```bash
grep -oE '[0-9]+:"[a-f0-9]+"' bundles/*main*.js        # {chunkId:"hash"} pairs
# reconstruct /static/js/<id>.<hash>.chunk.js, download each, re-run route/host/secret harvest
# asset-manifest.json (if present) lists them all -> info-disclosure
```

### 3. Establish a CONTROL — find an endpoint that IS gated
Before declaring anything vulnerable, send an unauthenticated request to an endpoint you expect to be protected, and capture what *correct* rejection looks like:
```bash
curl -s -X POST https://api.target.com/api/users -H 'Content-Type: application/json' -d '{}'
# secure → {"error":"Missing or invalid authorization header"} or HTTP 401
```
This is your differential. A sibling API (e.g. a second API host, or a different route group on the same host) is the ideal control — same stack, so a different response = real authz gap, not a quirk.

### 4. Test each route family UNAUTHENTICATED, both methods
For every discovered route, send it with **no `Authorization` header** and compare to the control:
```bash
for r in <routes>; do
  curl -s -o /tmp/r -w "[%{http_code}] $r\n" -X POST -H 'Content-Type: application/json' -d '{}' "https://api.target.com/api/v2/$r"
done
```
Interpret:
- **`401`/`"Missing authorization"`** → gated (correct). Move on.
- **`200` with data** → unauthenticated data exposure. **Finding.**
- **`400 "field X is mandatory"`** → the route processed your request and reached *business-logic validation* without an auth check → **auth bypass; supply the field minimally to confirm.**
- **`200` + verbose DB/stack error** (e.g. `PROCEDURE db_x.sp_y does not exist`) → reached the data layer unauthenticated; also a SQLi-surface signal.
- **Mandatory fields named like `is_admin` / `is_internal` / `requested_by` / `role_id` / `account_type`** → **authorization derived from client-supplied parameters** — set the privilege flag and you self-elevate. Critical-class.

### 5. Pivot & prove (minimally)
- IDs returned by one endpoint (`account_id`, `order_id`, `deal_id`) are the keys the *other* endpoints consume — they prove the whole router is reachable, not just one route.
- Test `dev-`/`beta-`/`staging-` API variants — they frequently have weaker/disabled auth.
- Check the response headers: `Access-Control-Allow-Origin: *` compounds the issue (any web origin reads it from a victim's browser).
- **STOP at minimum-necessary proof.** A handful of records (or a `totalCount`) confirms the missing check. Do NOT enumerate the table — see `redteam-mindset` data-minimization boundary. The finding is the absent auth, not the data volume.

---

## What "the API behind the SSO login" really means

A common, dangerous architecture:
- `console.target.com` (the SPA) → login is **Entra/Okta/Google OAuth** (looks airtight).
- `api.target.com` (the backend) → some route groups enforce the bearer token, **some route groups forgot the middleware.**

The frontend login is theatre if the API doesn't independently validate the token on every route. Always test the API directly, bare, regardless of how locked-down the login UI is.

---

## Anti-patterns

- **"The app requires login, so the API must be protected."** No — test the API directly, unauthenticated. The whole point.
- **"Minified bundle, can't read it."** You don't need to read it — grep it for hosts/routes/secrets. 5 minutes.
- **"`/api/v1/foo` returned 404, so no API here."** Wrong base or wrong method. Try `/api/`, `/api/v2/`, POST not GET, and the exact route strings from the bundle (Express's 404 echoes the path — use it to calibrate).
- **"AIza key found → critical secret."** Validate first — most are Maps/analytics keys (`CONFIGURATION_NOT_FOUND` on identitytoolkit = not Auth-enabled). Don't over-claim.
- **Dumping the whole dataset once you get a 200.** Stop at PoC. (`redteam-mindset`.)
- **Account-creation / write endpoints as "proof".** Read endpoints prove the auth gap without creating state. Never POST a `create`/`signup`/`upload` to "demonstrate" — that's a destructive write needing explicit per-action authorization.

---

## Related Skills & Chains

- **`api-misconfig`** — once the API is mapped, run the broader misconfig matrix (method tampering, mass assignment, JWT alg confusion) per route.
- **`idor`** — the `account_id`/`order_id` pivots feed straight into IDOR testing across discovered routes.
- **`info-disclosure`** — sourcemaps (`*.js.map`) reconstruct original source for deeper route/secret extraction; same harvesting muscle.
- **`nextjs`** — for Next.js targets, layer the middleware-bypass (`x-middleware-subrequest`) and `/_next/data` route tests on top of this.
- **`redteam-mindset`** — the data-minimization boundary governs step 5: prove the missing check, don't exfiltrate the table.
- **`recon-scope-triage`** — verify the API host actually belongs to the target before testing (don't pop a same-named third party's API).

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete artifacts, endpoints, patterns, tools to look for

- **Why this play works (Breach Authority 2026):** a SPA ships the browser a map of its entire API surface — routes, base URLs, versioned paths, parameter names, and auth logic. An unauthenticated visitor loading the login page can receive as much API information as an authenticated user exploring every feature; hiding a feature in the UI does not hide its address in the code.
- **Collect bundles across application states:** anonymous, standard user, and admin; include pre-redirect scripts, lazy-loaded modules, and historical URLs. Compare staging-to-production where in scope — admin paths, legacy versions, internal tooling, mobile-only routes, and feature-flagged previews commonly hide there.
- **Bundle inventory:** hashed chunks (`main.<hash>.js`, `[n].<hash>.js`), framework manifests (`_buildManifest.js`, `__NEXT_DATA__`, `asset-manifest.json`), `createServerReference(...)` for Next.js Server Actions, and public env prefixes `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_`.
- **Extraction commands:** `curl -s target.com | grep -oE 'src="[^"]+\.js"'` to list scripts; then `curl -s <bundle> | grep -oE '"(/api/|/v[0-9]+/)[a-zA-Z0-9_/{}.-]+"' | sort -u`. Look for `/admin/`, `/internal/`, `/v2/`, `/payments/refund`, `/feature-flags` in the output.
- **Source maps:** always check `<bundle>.map` and `//# sourceMappingURL=` — original source, comments, and internal folder paths make route/role discovery far easier.
- **Auth/role logic markers:** `role === "admin"`, `isAdmin`, `hasFeature(`, `permission`, `getItem('token')`, `sessionStorage`, `localStorage`, `Authorization: Bearer`. Mandiant (Google Cloud, 2025) identifies routing manipulation, hidden elements, and JavaScript debugging as the three systemic SPA access-control issues.
- **Tools:** Burp (Site Map, JS Miner "API Endpoints Finder", DOM Invader for canary→request flow), BChecks ("Swagger endpoint found"), `LinkFinder`/`xnLinkFinder`, `jsluice`, `katana -jc`, Param Miner/ffuf for hidden parameters, `feroxbuster --burp`.
- **OWASP anchors:** A01:2025 Broken Access Control Scenario #3 (all access control in front-end → `curl example.com/app/admin_getappInfo` directly); WSTG client-side testing; OWASP API5:2023 Broken Function Level Authorization for hidden-route testing.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **The core test — two accounts, three replays:** for each discovered endpoint: (1) baseline as admin/capture the admin's real request, (2) replay with the low-privilege user's session, (3) replay with no session. Compare *bodies* — an error page with HTTP 200 is not success. Server-side enforcement is the only valid control (OWASP A01:2025).
- **BOLA/IDOR on discovered routes:** `/api/v2/org/{id}/billing` — change `{id}` to another organization's ID. This is the highest-severity outcome of SPA route discovery.
- **Mass assignment from bundle-only params:** hidden JSON fields (`role`, `isAdmin`, `verified`, `accountStatus`) surfaced in request-building code → inject into JSON bodies and observe privileged attribute binding.
- **Unauthenticated/internal endpoint probe:** internal-tooling routes relying on "security by invisibility" — call directly with no auth, a low-privilege session, and malformed/missing tokens. A hidden admin export like `fetch("/api/admin/export?type=csv")` returning admin data to a normal user is Broken Access Control.
- **Version/environment drift:** bundles often reference `/api/v1/`, `/legacy/`, or staging-pattern hosts pointed at production; hand these to `shadow-api` for behavioral diffing.
- **Feature-flag forcing:** flip client-side flags in DevTools to reveal hidden UI, then call the endpoint directly with the original token — a `role === "admin"` check that only hides a button is cosmetic.
- **SSTI/token tampering adjacency:** SPA JWTs in `localStorage`/`sessionStorage` sent as `Authorization: Bearer` — test signature/claims handling per `crypto-and-secrets` after identifying the token flow.
- **DOM Invader canary tracing:** inject canaries to identify the exact code path and variable names that build an API request, then set breakpoints/hooks to reveal dynamically constructed hidden paths.
- **SSR as mitigation signal:** where the SPA uses server-side rendering for page/data access, client-side tampering yields less — adjust impact accordingly rather than assuming the client route is exploitable.

### C. Validation / proof bar — how to confirm and avoid false positives

- **A path found in a bundle is a lead, not a vulnerability.** The finding exists only when the backend trusts the client or fails authorization. Prove it with the two-account differential and a concrete unauthorized read/action.
- Do not assume an endpoint is admin-only because of its path — OWASP API5 explicitly warns against this; test with a real low-privilege token.
- Read endpoints prove the auth gap without creating state. Never POST `create`/`signup`/`upload` merely to "demonstrate" — destructive writes need explicit per-action authorization (`redteam-mindset` data-minimization rule).
- **Validate leaked keys:** most `AIza...` values are Maps/analytics keys (`CONFIGURATION_NOT_FOUND` on identitytoolkit means Auth is not enabled); do not call them critical secrets without proving capability.
- Compare bodies and status; stop at a minimal PoC — do not dump the whole table once a 200 is obtained.
- Scope-check the API host before testing — an `api.` subdomain may belong to a same-named third party (`recon-scope-triage`).
- Log and monitor evidence: unauthorized-but-successful access should be reported with the exact request, session identity, and response that proves missing server-side authorization.

- **Mandiant's three SPA issue classes:** routing manipulation, hidden element exposure, and JavaScript debugging — test each explicitly: force unknown routes, force hidden UI states, and read/instrument the minified client.
- **An unauthenticated visitor can learn the whole surface:** do not skip bundle collection just because the interesting features require login — the login page bundle often contains every admin and internal route string.
- **Use SSR as a scoping signal, not a blanket excuse:** Mandiant notes SSR can prevent unauthorized viewing/modification; verify which routes actually render server-side before downgrading impact.
- **Endpoint shortlist triage:** prioritize `/admin`, `/internal`, `/export`, `/billing`, `/payments/refund`, and any path the UI never calls; deprioritize static asset and health-check calls.
- **Token storage review:** localStorage/sessionStorage tokens are readable by any XSS and persist across tabs; test token replay and privilege changes per `session`/`crypto-and-secrets` after mapping the SPA's auth flow.
- **Logging/monitoring angle (Mandiant recommendation):** confirm whether unauthorized API calls are logged and alerted — a missing detection control can be part of the finding's impact statement.
- **Combine with server-side parameter pollution:** undocumented parameters discovered in the bundle may reach an internal API behind the frontend — test `#`/`&` injection into JSON/query parameters per PortSwigger's API testing topic.
- **CORS re-check on discovered routes:** an admin route that returns data to any origin with credentials is an independent finding — verify `Access-Control-Allow-Origin`/`Allow-Credentials` per `cors`.
- **Keep the PoC reversible:** use a read endpoint with a low-privilege session and record the single request/response that proves the missing check; avoid creating users, orders, or uploads.

- **Chain-out checklist for each confirmed endpoint:** admin-only route → BFLA (no role check); object ID → BOLA/IDOR; hidden body field → mass assignment; internal base URL → SSRF; stale version → `shadow-api`; prefilled token in Swagger UI → `info-disclosure`.
- **Scope note for "same-named third party" hosts:** many SPAs call a vendor's API on a different domain — verify ownership before testing, and treat vendor-side findings as out of scope unless the program explicitly includes them.

### D. Sources — numbered list of URLs you actually fetched

1. https://www.guidepointsecurity.com/blog/the-secret-life-of-apis-uncovering-hidden-endpoints-and-more (highest-privilege SPA crawl, JS Miner, BCheck Swagger discovery, real-world hidden-admin example)
2. https://cloud.google.com/blog/topics/threat-intelligence/single-page-applications-vulnerable (Mandiant: routing manipulation, hidden elements, API access controls)
3. https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control (Scenario #3: front-end-only access control bypassed by direct curl)
4. https://breachauthority.com/posts/api-endpoint-discovery-through-javascript-bundle-analysis (unauthenticated login page exposes full API map; need for multi-state bundle extraction)
5. https://blogs.jsmon.sh/how-to-find-hidden-api-endpoints-in-webpack-bundles (DOM Invader tracing; BOLA/mass-assignment/drift test categories)
6. https://dev.to/krishna_kumar_75bdf350b26/hidden-api-endpoints-in-javascript-bundles-find-and-prove-them-251h (two-account baseline/test/compare method)
7. https://safeguard.sh/resources/blog/security-testing-single-page-applications (client-side API exposure methodology for React/Vue/Angular)
8. https://safeguard.sh/resources/blog/hidden-risks-of-single-page-applications (bundle routes/flags/keys; server-side authorization requirement)
9. https://blog.nashtechglobal.com/%F0%9F%94%93-hacking-single-page-apps-spas-with-burp-suite (hidden admin export endpoint example, JWT tampering)
10. https://portswigger.net/web-security/api-testing (API recon, docs paths, Intruder hidden-endpoint/parameter discovery)

