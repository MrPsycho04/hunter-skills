---
name: bbhunt-js-collect
description: "Collect bundles, chunks and source maps from a live target. Unified from 3 upstream skills (h1skills, hunting, research). For authorized security testing only."
agent_created: true
---

# JavaScript bundle collection — unified methodology

> **Unified skill.** Built from 3 upstream skills across h1skills, hunting, research. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Quick wins

Ordered by yield — do these first.

1. **Seed from the live HTML.** Fetch every in-scope URL and extract `src=` from `<script>` tags. Modern apps hide 80%+ of their code in hashed bundles you can only discover from the page that loads them.
2. **Enumerate subdomains first.** JS often lives on `assets.`, `static.`, `cdn.`, `s3.`, `*.cloudfront.net`, `*.azureedge.net`, or a separate `*.dev`/`*.staging` host. Subdomains you miss are JS you never collect.
3. **Query historical URLs** (Wayback/Common Crawl via `gau`, `waybackurls`) and filter for `.js`, `.js.map`, `.mjs`, `.json` config files. Old, forgotten bundles are gold: they often still contain the secrets the current build removed.
4. **Crawl with JS rendering** (`katana -jc`, `gospider`) — client-side routers (React/Vue/Angular/Next) only emit script URLs after JavaScript executes.
5. **Hunt source maps.** A public `.js.map` turns minified spaghetti into original TypeScript with comments, `process.env` references, and internal filenames. Report #638635 (Trint, ▲102) was found this way.
6. **Check the asset host's directory and path patterns** — `/assets/webpack/`, `/static/js/`, `/_next/static/chunks/`, `/packs/js/`. Next.js/Nuxt/Webpack apps leak their whole build manifest.
7. **Collect with status/size metadata**, not just URLs. A `200` that returns an HTML error page is not a JS file; dedupe by content hash.

### A. Discovery checklist — concrete artifacts, endpoints, patterns, tools to look for

- **Crawl every application state, not just the landing page:** browse as anonymous, low-privilege, and highest-privilege test accounts with Burp/ZAP/Caido recording. Code splitting means lazy-loaded chunks only appear when their route is visited; admin/beta chunks exist on the server even if your role never renders them.
- **Harvest script URLs from three sources:** (1) live HTML `<script src>` extraction (`grep -oE 'src="[^"]+\.js"'`); (2) Burp Site Map filtered to MIME type `script` / extension `.js`, plus "Engagement tools → Find scripts"; (3) historical URLs from `waybackurls`, `gau`, and the Archive.org CDX API (`curl -G "https://web.archive.org/cdx/search/cdx" --data-urlencode "url=*.example.com/*" --data-urlencode "fl=original"`).
- **Chunk-name mining:** the main bundle must contain the filenames of chunks it can lazy-load; grepping chunk names leads to code for pages your account never saw. Framework manifests are gold: `_buildManifest.js` (`sortedPages`), `__NEXT_DATA__` `buildId`, `asset-manifest.json`, webpack runtime chunk maps.
- **Source maps:** for every `<file>.js` check `<file>.js.map` (append `.map`), and read the `//# sourceMappingURL=` trailer. OWASP WSTG-INFO-05 explicitly lists this as a black-box test. Prefer maps with `sourcesContent` — those contain original source, comments, and absolute filesystem paths.
- **Public env prefixes:** `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_` are inlined at build time; collect their literal values — API bases, staging hosts, feature

### Signals and surfaces

### Signal

- JS-adjacent reports: **1,330** mentioning javascript · **208** paid · **$392,415** disclosed bounties
- Browser-side sinks: **68** `postMessage` · **56** DOM XSS · **30** "DOM Based XSS"
- Secret exposure: **141** "api key" · **40** "hardcoded" · **34** "secret key"
- Top programs in the JS slice: Node.js third-party modules (137), U.S. DoD (132), Shopify (63), HackerOne (53), GitLab (48), X/xAI (36), Automattic (35), Uber (33), Rocket.Chat (29)

### Techniques, payloads and bypasses

### Techniques from real reports

| Report | Program | Bounty | Lesson for collection |
|---|---|---:|---|
| [#638635](https://hackerone.com/reports/638635) | Trint Ltd | — (▲102) | Source maps sat **next to** minified files at `/static/js/app.<hash>.js.map`; always request the `.map` sibling. |
| [#1481207](https://hackerone.com/reports/1481207) | GitLab | — (▲161) | Failed asset loads revealed exact webpack chunk names (`/assets/webpack/top_nav.<hash>.chunk.js`) via DevTools after a `<base>` injection — a reminder to record chunk paths from the browser, not only from HTML. |
| [#1717210](https://hackerone.com/reports/1717210) | Semrush | — (▲56) | Build-time env vars were baked into a webpack bundle — collect **build artifacts**, not just API responses. |
| [#1160407](https://hackerone.com/reports/1160407) | GitLab | — (▲83) | `assets.gitlab-static.net` cache poisoning — asset hosts are in scope when they serve the app's JS. |
| [#90367](https://hackerone.com/reports/90367) | HackerOne | — | Public uncompiled CSS + source maps; "dev artifacts on prod" is a recurring, low-effort find. |
| [#1444682](https://hackerone.com/reports/1444682) | Shopify | $9,400 | XSS on a `*.shopifycloud.com` asset host — never stop at the main domain. |
| [#3085742](https://hackerone.com/reports/3085742) | Bykea | — (▲128) | "Hardcoded zombie endpoint" found in-app — old JS can expose forgotten APIs. |

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Validate archived URLs before mining:** `cat js-cdx.txt | httpx -mc 200 -o js-live.txt` — dead Wayback hits waste analysis time but can still reveal *old* endpoint names for version drift (feed to `shadow-api`).
- **Complete the inventory loop:** after browsing, re-check the Site Map; Burp passively extracts some endpoints, but "Find scripts" + a heavier `LinkFinder`/`jsluice` pass is needed for full coverage.
- **Burp automation:** a BCheck "Swagger endpoint found" iterates known documentation paths; `JS Miner`'s "API Endpoints Finder" passive scan surfaces endpoints directly in the proxy. Run an active scan — it often triggers source-map retrieval.
- **Minified/obfuscated/encrypted distinction:** minified → `js-beautify`/`prettier` (readability only); obfuscated → `webcrack` (handles `javascript-obfuscator` string arrays and control-flow flattening) or `jsnice`; "encrypted" strings → the decryption key travels in the same bundle, so decode with `atob()` or a Python `print("\x2f...")`.
- **Decode without execution:** evaluate only isolated string expressions, never the whole bundle under `node` (third-party code has filesystem/network access); the target's browser console is already sandboxed.
- **Beautify pipeline:** `curl -s <url> -o main.js && npx --yes js-beautify main.js > main.pretty.js`; then `grep -oE '"/(api|admin|internal|v[0-9]+)[^"]*"' main.pretty.js | sort -u`.
- **Hidden-path fuzzing from a seed:** with `PUT /api/user/update` discovered, Intruder/ffuf the `{update}` position wit

### Validation and proof

### C. Validation / proof bar — how to confirm and avoid false positives

- A collected script is not a finding. Scope-check the host; discard same-named third-party assets (`recon-scope-triage`).
- Confirm a source map is genuinely served (HTTP 200 + JSON-shaped content) rather than trusting the `sourceMappingURL` comment alone; some servers return a SPA HTML fallback with 200.
- Deduplicate by hash before analysis so the same hashed bundle from multiple paths is not counted twice; note its first-seen URL and which account state revealed it.
- Lazy-loaded chunks: absence from the initial crawl is not evidence of absence — revisit with the privileged account and with forced route navigation before concluding a feature is not in the bundle.
- Record which account/state unlocked each artifact; this is required later to demonstrate that hidden admin routes were reachable from the client even if the UI hid them.
- Avoid destructive collection: do not trigger state-changing endpoints just to make them appear in the Site Map; use read requests and existing documentation.

- **Pre-redirect scripts matter:** capture the response body of an unauthenticated landing page before the app redirects to SSO — those bundles often carry the public API base URLs and login/register endpoints.
- **Historical bundle versions:** a stale hashed bundle from Wayback can still reference endpoints removed from the current build; these are prime shadow/zombie candidates (hand to `shadow-api`).
- **Archive CDX filtering:** add `--data-urlencode "filter=mimetype:application/javascript"` and `filter=statu

## Source skills merged into this topic

- `h1skills` — `hackerone-js-collect`
- `hunting` — `js-collect`
- `research` — `js-collect`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
