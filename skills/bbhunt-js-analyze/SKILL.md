---
name: bbhunt-js-analyze
description: "Analyze collected JS for secrets, endpoints, DOM sinks and client-side auth flaws. Unified from 4 upstream skills (h1skills, hunting, research). For authorized security testing only."
agent_created: true
---

# JavaScript bundle analysis — unified methodology

> **Unified skill.** Built from 4 upstream skills across h1skills, hunting, research. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Quick wins

Ordered by yield.

1. **Get the source map first.** `curl https://target/app.<hash>.js.map | jq -r '.sourcesContent[]'`. Original source with `process.env` / `REACT_APP_*` references is worth 100× the minified bundle. Report #638635 is the canonical example.
2. **Grep for secret names and prefixes** across all collected JS (patterns below). Triage hits: real key vs placeholder vs docs example.
3. **Extract endpoints** with LinkFinder or a string sweep. Feed unique paths to your HTTP client (`httpx`) and check for unauthenticated / undocumented endpoints.
4. **Find hidden parameters and GraphQL queries** in request-building code (`axios`, `fetch`, `ky`, GraphQL `.graphql` strings). Try them on live endpoints — hidden params are a classic IDOR/mass-assignment entry point.
5. **Trace DOM sinks** — `innerHTML`, `eval`, `Function`, `location`, `document.write`, `dangerouslySetInnerHTML`, `.html()`, `postMessage` listeners. This is where bundled JS pays as XSS.
6. **Decode every JWT-looking string** at jwt.io. Check whether the signing secret is also in the JS — if so, you can mint arbitrary tokens.
7. **Check for vulnerable libraries** (`retire.js`, npm advisory lookup) — a bundled old jQuery/React/Angular can be a known CVE with a ready PoC.

### A. Discovery checklist — concrete artifacts, endpoints, patterns, tools to look for

- **Source-map trail (OWASP WSTG-INFO-05):** tail every bundle for `//# sourceMappingURL=...`; request the sibling `<file>.js.map`. A 200 with JSON `{"version":3,"sources":[...],"sourcesContent":[...]}` is the whole codebase. Absolute `sources` entries such as `/home/sysadmin/cashsystem/src/actions/cashoutAction.js` or `webpack:///./src/...` leak internal repo layout and route names.
- **Framework/bundler fingerprints:** `webpackChunk`, `__NEXT_DATA__`, `/_next/static/<buildId>/_buildManifest.js` (`sortedPages` enumerates every prerendered page), `self.__next_f.push` Flight chunks, Angular build hashes, and public env prefixes `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_` (deliberately shipped; occasionally a secret lands there by mistake).
- **Next.js Server Actions (HackTricks 2025/2026):** grep chunks for `createServerReference(...)` and build a `Next-Action` 40-hex-hash → function-name dictionary. Regex: `createServerReference\)"([a-f0-9]{40,})",\w+\.callServer,void 0,\w+\.findSourceMapURL,"([^"]+)"\)`. Tooling: `NextjsServerActionAnalyzer` Burp extension (Adversis). Responses with `Content-Type: text/x-component` are Flight endpoints.
- **Secret regex catalog:** `AKIA[0-9A-Z]{16}`, `ghp_[a-zA-Z0-9]{36}`, `sk_live_[a-zA-Z0-9]{24,}`, `eyJ[A-Za-z0-9_-]*\.eyJ...` (JWT), `-----BEGIN (RSA |EC )?PRIVATE KEY-----`, plus generic `api[_-]?key|apikey|secret|password|token|auth|2fa|sign`. Use `jsluice secrets`, `jsleak -s -l -k`, `SecretFinder`, `trufflehog filesystem`, `gitleaks dir`, `gf` patterns, 

### Signals and surfaces

### Signal

- Secret exposure: **141** "api key" · **40** "hardcoded" · **34** "secret key" · **14** "access key"
- Client-side auth: **66** JWT · **109** "client-side" · **57** `postMessage` · **20** `localStorage`
- Top classes to mine: `info-disclosure` (1,827 reports), `crypto-and-secrets` (562), `xss` (2,569), `auth-bypass` (989), `authz-bypass` (1,386)
- Median payoff for a *valid* hardcoded secret or source-map disclosure is usually low severity on its own — the money is in the **escalation** (forge a token, access another tenant, reach an internal API).

### Techniques, payloads and bypasses

### 4. Webpack chunk names as a CSP-bypass oracle (GitLab, #1481207)

After injecting a `<base href=https://attacker>` via Markdown, DevTools showed failed requests for `/assets/webpack/hello.<hash>.chunk.js`. Hosting files at those exact paths on the attacker domain made them load with the page's nonces → stored XSS. **Takeaway: the JS inventory from collection is itself an exploitation asset.**

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **AST beats regex on minified bundles:** regex misses split/reconstructed strings; `jsluice` parses the AST for URLs, paths, and secrets. Burp passive tools `JSMiner`, `JSpector`, and `Uproot` save and scan scripts automatically; run an active scan too.
- **Rebuild from source maps:** parse the `.map` JSON and write each `sources[i]` with `sourcesContent[i]` to a tree (`unwebpack_sourcemap.py`, `source-map-extract`, a small `rebuild.py`). Then grep routing/service/config files rather than the minified blob.
- **Deobfuscate without a map:** find the terminal `return`, rewrite it to `console.log()`, paste into `jsconsole.com`, then beautify in `prettier`; repeat if recursively packed. Never `node bundle.js` — evaluate only isolated expressions or use the target's own browser console.
- **Next.js action pivot:** capture a valid POST with `Next-Action: <hash>`, swap in a discovered hash, replay in Repeater, then test authz/input validation/business logic of an otherwise unreachable action. Function-name disclosure alone is *not* a vuln — it is a targeting aid.
- **React2Shell (CVE-2025-55182) Flight deserialization:** set `"then":"$1:__proto__:then"`, point `_response._formData.get` at `"$1:constructor:constructor"`, and place JS in `_response._prefix` (`require('child_process').exec('id')`). Remote oracle: crafted multipart Flight request → `HTTP/500` with `E{"digest"` in body; patched returns `400/200` (`assetnote/react2shell-scanner --safe-check`).
- **Middleware/route bypass recon:** `x-middlewa

### Validation and proof

### C. Validation / proof bar — how to confirm and avoid false positives

- Record exact JS URL, source-map URL, and line/variable; validate each secret as live and in-scope and demonstrate the concrete attacker action (OWASP Web Frontend cheat sheet: nothing sent to the client is secret; ASVS V13.4 forbids secrets in build artifacts).
- Do not report a key until its privilege is proven: `200` + readable data or a documented service permission check. Publishable keys with no capability = Informational/false positive.
- A recovered endpoint path is a *lead*, not a finding. Confirm reachability (not 404) and prove the authz gap with two controlled accounts: baseline admin request vs same request with low-privilege session and with no session; compare bodies, not status codes.
- Source-map or function-name disclosure is not itself a vulnerability; it must unlock a demonstrable secret, endpoint, or action.
- DOM XSS: browsers URL-encode `location.search`/`location.hash` (Chrome/Firefox/Safari), so encoded reflections rarely execute; confirm with an actual `alert(document.domain)` in the sink context rather than inferring from source text.
- Track third-party scripts separately; a secret in a vendor SDK is out of scope unless the target controls it.
- Avoid tunnel vision — sensitive data surfaces in comments, error pages, and embedded JSON config (`runtimeConfig`, `BASE_BACKOFFICE_API`, `ADMIN_PAGE`) as often as in bundles.

- **Framework-specific extensions:** Next.js `productionBrowserSourceMaps` also exposes RSC Flight attack surface (CVE-2025-55183 source disclosure, CVE-202

### 5. Dynamic confirmation

Only for in-scope targets, only with benign markers.
- Put a breakpoint on the suspected sink or gadget getter.
- Replay the input in the running app using a harmless marker (a unique string logged to the console), not a payload that reads data or changes state.
- Capture the file and line from the stack trace.
- Confirm on your own account and test data only.

Only a flow you reproduced gets `confidence: high`.

### Escalation and related chains

### Escalation chains

A secret in JS is rarely the final finding. Chain it:

| Primitive | Escalation | Corpus example |
|---|---|---|
| Hardcoded SSO/JWT secret | Mint token for another user → account takeover | #638635 Trint ($0, ▲102) |
| Exposed cloud API key | Access storage/console → data disclosure or RCE | #716292 Starbucks JumpCloud key (▲777); #2401648 Mozilla AWS keys (▲71) |
| Hardcoded API secret | Access third-party service (Cloudinary, SendGrid, DB) | #351555 Reverb Cloudinary secret (▲96); #1580567 Glovo exposed AWS/MySQL/SendGrid |
| Hidden internal endpoint | IDOR / missing authz on an unlisted API | #3085742 Bykea (▲128) |
| postMessage sink | XSS → cookie/token theft → ATO | #398054 HackerOne; #534450 Superhuman |
| Webpack chunk path + HTML injection | CSP bypass via `<base href>` → stored XSS | #1481207 GitLab (▲161) |
| Source map | Recover full source → find auth flaw → escalate | #638635 Trint |

### Tools and wordlists

### Entropy / tooling

```sh
trufflehog filesystem ./js-files --no-verification
gitleaks detect --source ./js-files --no-git -v
# jsfinder / SecretFinder for pattern-based JS sweeps
python3 SecretFinder.py -i app.js -o cli
```

## Source skills merged into this topic

- `h1skills` — `hackerone-js-analyze`
- `hunting` — `js-analyze`
- `research` — `js-sinks`
- `research` — `js-analyze`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 1 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `references/unified-method.md` — includes 1 merged companion methodology documents
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
