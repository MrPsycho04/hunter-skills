---
name: bbhunt-spa-api
description: "Recover a single-page app's backend API from its public JS bundles and test it for broken access control. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# SPA hidden API discovery — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### A. Discovery checklist — concrete artifacts, endpoints, patterns, tools to look for

- **Why this play works (Breach Authority 2026):** a SPA ships the browser a map of its entire API surface — routes, base URLs, versioned paths, parameter names, and auth logic. An unauthenticated visitor loading the login page can receive as much API information as an authenticated user exploring every feature; hiding a feature in the UI does not hide its address in the code.
- **Collect bundles across application states:** anonymous, standard user, and admin; include pre-redirect scripts, lazy-loaded modules, and historical URLs. Compare staging-to-production where in scope — admin paths, legacy versions, internal tooling, mobile-only routes, and feature-flagged previews commonly hide there.
- **Bundle inventory:** hashed chunks (`main.<hash>.js`, `[n].<hash>.js`), framework manifests (`_buildManifest.js`, `__NEXT_DATA__`, `asset-manifest.json`), `createServerReference(...)` for Next.js Server Actions, and public env prefixes `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_`.
- **Extraction commands:** `curl -s target.com | grep -oE 'src="[^"]+\.js"'` to list scripts; then `curl -s <bundle> | grep -oE '"(/api/|/v[0-9]+/)[a-zA-Z0-9_/{}.-]+"' | sort -u`. Look for `/admin/`, `/internal/`, `/v2/`, `/payments/refund`, `/feature-flags` in the output.
- **Source maps:** always check `<bundle>.map` and `//# sourceMappingURL=` — original source, comments, and internal folder paths make route/role discovery far easier.
- **Auth/role logic markers:** `role === "admin"`, `isAdmin`, `hasFeature(`, `permission`,

### Techniques, payloads and bypasses

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **The core test — two accounts, three replays:** for each discovered endpoint: (1) baseline as admin/capture the admin's real request, (2) replay with the low-privilege user's session, (3) replay with no session. Compare *bodies* — an error page with HTTP 200 is not success. Server-side enforcement is the only valid control (OWASP A01:2025).
- **BOLA/IDOR on discovered routes:** `/api/v2/org/{id}/billing` — change `{id}` to another organization's ID. This is the highest-severity outcome of SPA route discovery.
- **Mass assignment from bundle-only params:** hidden JSON fields (`role`, `isAdmin`, `verified`, `accountStatus`) surfaced in request-building code → inject into JSON bodies and observe privileged attribute binding.
- **Unauthenticated/internal endpoint probe:** internal-tooling routes relying on "security by invisibility" — call directly with no auth, a low-privilege session, and malformed/missing tokens. A hidden admin export like `fetch("/api/admin/export?type=csv")` returning admin data to a normal user is Broken Access Control.
- **Version/environment drift:** bundles often reference `/api/v1/`, `/legacy/`, or staging-pattern hosts pointed at production; hand these to `shadow-api` for behavioral diffing.
- **Feature-flag forcing:** flip client-side flags in DevTools to reveal hidden UI, then call the endpoint directly with the original token — a `role === "admin"` check that only hides a button is cosmetic.
- **SSTI/token tampering adjacency:** SPA JWTs in `localStorage`/`sessionStor

### Validation and proof

### C. Validation / proof bar — how to confirm and avoid false positives

- **A path found in a bundle is a lead, not a vulnerability.** The finding exists only when the backend trusts the client or fails authorization. Prove it with the two-account differential and a concrete unauthorized read/action.
- Do not assume an endpoint is admin-only because of its path — OWASP API5 explicitly warns against this; test with a real low-privilege token.
- Read endpoints prove the auth gap without creating state. Never POST `create`/`signup`/`upload` merely to "demonstrate" — destructive writes need explicit per-action authorization (`redteam-mindset` data-minimization rule).
- **Validate leaked keys:** most `AIza...` values are Maps/analytics keys (`CONFIGURATION_NOT_FOUND` on identitytoolkit means Auth is not enabled); do not call them critical secrets without proving capability.
- Compare bodies and status; stop at a minimal PoC — do not dump the whole table once a 200 is obtained.
- Scope-check the API host before testing — an `api.` subdomain may belong to a same-named third party (`recon-scope-triage`).
- Log and monitor evidence: unauthorized-but-successful access should be reported with the exact request, session identity, and response that proves missing server-side authorization.

- **Mandiant's three SPA issue classes:** routing manipulation, hidden element exposure, and JavaScript debugging — test each explicitly: force unknown routes, force hidden UI states, and read/instrument the minified client.
- **An unauthenticated visitor can learn the whole surface:** do not skip 

### Escalation and related chains

### Related Skills & Chains

- **`api-misconfig`** — once the API is mapped, run the broader misconfig matrix (method tampering, mass assignment, JWT alg confusion) per route.
- **`idor`** — the `account_id`/`order_id` pivots feed straight into IDOR testing across discovered routes.
- **`info-disclosure`** — sourcemaps (`*.js.map`) reconstruct original source for deeper route/secret extraction; same harvesting muscle.
- **`nextjs`** — for Next.js targets, layer the middleware-bypass (`x-middleware-subrequest`) and `/_next/data` route tests on top of this.
- **`redteam-mindset`** — the data-minimization boundary governs step 5: prove the missing check, don't exfiltrate the table.
- **`recon-scope-triage`** — verify the API host actually belongs to the target before testing (don't pop a same-named third party's API).

### Related Skills & Chains

- **`hunt-api-misconfig`** — once the API is mapped, run the broader misconfig matrix (method tampering, mass assignment, JWT alg confusion) per route.
- **`hunt-idor`** — the `account_id`/`order_id` pivots feed straight into IDOR testing across discovered routes.
- **`hunt-source-leak`** — sourcemaps (`*.js.map`) reconstruct original source for deeper route/secret extraction; same harvesting muscle.
- **`hunt-nextjs`** — for Next.js targets, layer the middleware-bypass (`x-middleware-subrequest`) and `/_next/data` route tests on top of this.
- **`redteam-mindset`** — the data-minimization boundary governs step 5: prove the missing check, don't exfiltrate the table.
- **`recon-scope-triage`** — verify the API host actually belongs to the target before testing (don't pop a same-named third party's API).

## Source skills merged into this topic

- `hunting` — `spa-api`
- `cbh` — `hunt-spa-api`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
