# Unified upstream methodology

Collected from every contributing repository skill. Deduplicated by content hash; full originals are preserved in `references/upstream-*.md`.

## Discovery and hunting method

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
- **Secret regex catalog:** `AKIA[0-9A-Z]{16}`, `ghp_[a-zA-Z0-9]{36}`, `sk_live_[a-zA-Z0-9]{24,}`, `eyJ[A-Za-z0-9_-]*\.eyJ...` (JWT), `-----BEGIN (RSA |EC )?PRIVATE KEY-----`, plus generic `api[_-]?key|apikey|secret|password|token|auth|2fa|sign`. Use `jsluice secrets`, `jsleak -s -l -k`, `SecretFinder`, `trufflehog filesystem`, `gitleaks dir`, `gf` patterns, and `keyhacks` for usage syntax once a key is found.
- **Endpoint extraction:** `LinkFinder`/`xnLinkFinder`, `jsluice urls`, `katana -jc`, and path-shaped regex `"/(api|admin|internal|v[0-9]+)[^"]*"`. Search for *constructions* not just literals: `join('/')`, `+` concatenation, and template literals like ``${BASE}/admin/${id}``.
- **Role/flag mining:** `isAdmin`, `hasFeature(`, `role ===`, `betaFlags`, `permission`, `can[A-Z]\w+\(` — each is a forced-enablement candidate.
- **Canonical DOM source/sink inventory (PortSwigger DOM Invader):** sources `location*`, `document.URL/baseURI/referrer/cookie`, `window.name`, `history.pushState`, `localStorage`/`sessionStorage`, web messages. High-rank sinks: `eval`, `Function`, `setTimeout`, `script.src`, `document.write`, `jQuery.html/append/attr`, `element.innerHTML/outerHTML`, `iframe.srcdoc`, `window.open`, `location.href`, `fetch`, `JSON.parse`, `localStorage.setItem`, `document.evaluate`.
- **Obfuscation transforms:** hex `"\x2f\x61\x70\x69"`, unicode `"\u002f..."`, string-array decoder `_0x1b2c(0x1a4)`, `atob("L2FwaS9hZG1pbg==")`, dead code, control-flow-flattening `switch` loops. Deobfuscate with `webcrack`, `jsnice`, `prettier`/`js-beautify`.
- **Client storage audit:** DevTools → Application → LocalStorage/sessionStorage for `token`, `jwt`, `role`, `user_info`.
- **Third-party JS surface (OWASP Third Party JS cheat sheet):** SRI tags, script mirroring, "JavaScript Drift", outdated libs flagged by `retire.js`; OWASP Top 10:2025 A03 Software Supply Chain Failures.

## Signals and surfaces

### Signal

- Secret exposure: **141** "api key" · **40** "hardcoded" · **34** "secret key" · **14** "access key"
- Client-side auth: **66** JWT · **109** "client-side" · **57** `postMessage` · **20** `localStorage`
- Top classes to mine: `info-disclosure` (1,827 reports), `crypto-and-secrets` (562), `xss` (2,569), `auth-bypass` (989), `authz-bypass` (1,386)
- Median payoff for a *valid* hardcoded secret or source-map disclosure is usually low severity on its own — the money is in the **escalation** (forge a token, access another tenant, reach an internal API).

## Techniques, payloads and bypasses

### 4. Webpack chunk names as a CSP-bypass oracle (GitLab, #1481207)

After injecting a `<base href=https://attacker>` via Markdown, DevTools showed failed requests for `/assets/webpack/hello.<hash>.chunk.js`. Hosting files at those exact paths on the attacker domain made them load with the page's nonces → stored XSS. **Takeaway: the JS inventory from collection is itself an exploitation asset.**

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **AST beats regex on minified bundles:** regex misses split/reconstructed strings; `jsluice` parses the AST for URLs, paths, and secrets. Burp passive tools `JSMiner`, `JSpector`, and `Uproot` save and scan scripts automatically; run an active scan too.
- **Rebuild from source maps:** parse the `.map` JSON and write each `sources[i]` with `sourcesContent[i]` to a tree (`unwebpack_sourcemap.py`, `source-map-extract`, a small `rebuild.py`). Then grep routing/service/config files rather than the minified blob.
- **Deobfuscate without a map:** find the terminal `return`, rewrite it to `console.log()`, paste into `jsconsole.com`, then beautify in `prettier`; repeat if recursively packed. Never `node bundle.js` — evaluate only isolated expressions or use the target's own browser console.
- **Next.js action pivot:** capture a valid POST with `Next-Action: <hash>`, swap in a discovered hash, replay in Repeater, then test authz/input validation/business logic of an otherwise unreachable action. Function-name disclosure alone is *not* a vuln — it is a targeting aid.
- **React2Shell (CVE-2025-55182) Flight deserialization:** set `"then":"$1:__proto__:then"`, point `_response._formData.get` at `"$1:constructor:constructor"`, and place JS in `_response._prefix` (`require('child_process').exec('id')`). Remote oracle: crafted multipart Flight request → `HTTP/500` with `E{"digest"` in body; patched returns `400/200` (`assetnote/react2shell-scanner --safe-check`).
- **Middleware/route bypass recon:** `x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware` (CVE-2025-29927); compare normal URL vs `/_next/data/<buildId>/account.json` (no locale prefix) and `.rsc`/`segment.rsc` prefetch URLs without cookies.
- **CSP/selector-constrained DOM XSS (PayPal research):** probe `"` and escaped `\"` in a canary, observe sink context; valid-CSS-selector payload such as `input[value='"><iframe srcdoc=<script>alert(1)</script>>"']`; bypass allow-list CSP with unintended script gadgets.
- **postMessage origin-check bypass:** `if (e.origin.endsWith('normal-website.com'))` accepts `https://evilnormal-website.com`; DOM Invader can spoof origin and auto-build the PoC iframe.
- **Secret triage:** Stripe `pk_live_` publishable, Firebase web config, and Supabase `anon` keys are public-by-design; the finding is the *scope of what the service allows* (check rules minimally). `sk_live_`, `service_role`, and cloud provider credentials are real findings.
- **Feature-flag escalation:** flip `isAdmin`/`beta` in devtools to reveal hidden UI, then call the endpoint directly with the original low-privilege token — UI-only gating is cosmetic (OWASP A01:2025).

## Validation and proof

### C. Validation / proof bar — how to confirm and avoid false positives

- Record exact JS URL, source-map URL, and line/variable; validate each secret as live and in-scope and demonstrate the concrete attacker action (OWASP Web Frontend cheat sheet: nothing sent to the client is secret; ASVS V13.4 forbids secrets in build artifacts).
- Do not report a key until its privilege is proven: `200` + readable data or a documented service permission check. Publishable keys with no capability = Informational/false positive.
- A recovered endpoint path is a *lead*, not a finding. Confirm reachability (not 404) and prove the authz gap with two controlled accounts: baseline admin request vs same request with low-privilege session and with no session; compare bodies, not status codes.
- Source-map or function-name disclosure is not itself a vulnerability; it must unlock a demonstrable secret, endpoint, or action.
- DOM XSS: browsers URL-encode `location.search`/`location.hash` (Chrome/Firefox/Safari), so encoded reflections rarely execute; confirm with an actual `alert(document.domain)` in the sink context rather than inferring from source text.
- Track third-party scripts separately; a secret in a vendor SDK is out of scope unless the target controls it.
- Avoid tunnel vision — sensitive data surfaces in comments, error pages, and embedded JSON config (`runtimeConfig`, `BASE_BACKOFFICE_API`, `ADMIN_PAGE`) as often as in bundles.

- **Framework-specific extensions:** Next.js `productionBrowserSourceMaps` also exposes RSC Flight attack surface (CVE-2025-55183 source disclosure, CVE-2025-55184/67779 pre-auth DoS via malformed Flight payloads) — see the `nextjs` skill before writing the report.
- Run all three `jsluice` modes (`urls`, `paths`, `secrets`), not only secrets; combine with `gf` pattern packs and `RegHex` for obfuscated/encoded secret strings.
- **JS drift detection (OWASP Top 10 Client-Side Risks #6):** diff bundles across builds or Wayback snapshots; newly added route strings or role checks reveal unreleased admin surface and are strong leads even when the current bundle looks clean.
- **Runtime capture beats static grep for constructed paths:** set DevTools breakpoints/XHR breakpoints on `fetch`/`XMLHttpRequest`, or Chrome Overrides, to record URLs the app actually builds at runtime.
- With source maps that have only `sources` (no `sourcesContent`), the absolute paths and folder names still identify the framework and internal route names; don't discard partial maps.
- Inspect webpack module IDs and `__webpack_require__.u` (chunk filename function) to map lazy-loaded routes to chunk files your account never loaded.
- Sentry DSNs, analytics IDs, and Maps keys in SDK init are commonly intentional; the reportable impact is what the SDK can do with them, not their mere presence.
- **DOM XSS requires live-browser confirmation:** use DevTools Control+F on the rendered DOM (not "View Source", which ignores JS mutations); stack traces from DOM Invader give the exact assignment to cite.
- Cross-check every extracted secret against the scope boundary and a live validation before including it; record the validation request/response (redacted per `evidence-hygiene`).

### 5. Dynamic confirmation

Only for in-scope targets, only with benign markers.
- Put a breakpoint on the suspected sink or gadget getter.
- Replay the input in the running app using a harmless marker (a unique string logged to the console), not a payload that reads data or changes state.
- Capture the file and line from the stack trace.
- Confirm on your own account and test data only.

Only a flow you reproduced gets `confidence: high`.

## Escalation and related chains

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

## Tools and wordlists

### Entropy / tooling

```sh
trufflehog filesystem ./js-files --no-verification
gitleaks detect --source ./js-files --no-git -v
# jsfinder / SecretFinder for pattern-based JS sweeps
python3 SecretFinder.py -i app.js -o cli
```

## Sources and related reading

### 1. Source map → client-side JWT secret → arbitrary impersonation (Trint, #638635)

The reporter fetched `/static/js/app.e984c9df.js.map` next to the minified bundle. Its `sourcesContent` contained `ZendeskLoadingPage.js` with:

```js
const { REACT_APP_ZENDESK_SECRET } = process.env;
const zendeskToken = jwt.sign(payload, REACT_APP_ZENDESK_SECRET);
window.location = `${ZENDESK_DOMAIN}/access/jwt?jwt=${zendeskToken}`;
```

Grepping the map for `REACT_APP_ZENDESK_SECRET` yielded the literal secret. Anyone could mint a Zendesk SSO JWT for any email. **Takeaway: bundle inlining turns `process.env` into a public constant, and source maps hand you the variable name.**

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/blog/introducing-dom-invader (canonical source/sink ranking, canary workflow, postMessage spoofing)
2. https://hacktricks.wiki/en/network-services-pentesting/pentesting-web/nextjs.html (Server Action hash↔name mapping, React2Shell payload, middleware bypass)
3. https://portswigger.net/web-security/dom-based (taint-flow source/sink taxonomy)
4. https://portswigger.net/blog/finding-client-side-prototype-pollution-with-dom-invader
5. https://cheatsheetseries.owasp.org/cheatsheets/Web_Frontend_Security_Cheat_Sheet.html ("Never transmit secrets to the client")
6. https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/01-API_Reconnaissance/ (regex vs AST tools: JSLuice, JSMiner, JSpector, LinkFinder, Uproot)
7. https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html
8. https://www.rootsec.in/cheatsheets/web-security/js-analysis (grep patterns, SecretFinder, LinkFinder, jsluice, source-map extraction)
9. https://pwnversity.online/en/recon/recon-js/ (bundle/chunk/manifest anatomy, obfuscation reversal table)
10. https://my-hack-tricks.gitbook.io/my-hacktricks/network-services-pentesting/pentesting-web/code-review-tools (JSnice/jsconsole deobfuscation workflow)

## Additional notes

### Prepare the files

```sh
# Beautify so patterns are readable
for f in *.js; do js-beautify "$f" > "pretty-$f"; done
# or: npx prettier --write '*.js'

# Expand source maps to original sources
curl -s https://target/static/js/app.abc.js.map \
  | jq -r '.sourcesContent[]?' > app-original.js
curl -s https://target/static/js/app.abc.js.map \
  | jq -r '.sources[]' > app-sources.txt   # internal file paths = app structure leak
```

### High-confidence prefixes

```regex
AKIA[0-9A-Z]{16}                         # AWS access key ID
ASIA[0-9A-Z]{16}                         # AWS temporary key
AIza[0-9A-Za-z\\-_]{35}                  # Google / Firebase API key
sk_live_[0-9a-zA-Z]{24,}                 # Stripe live secret
rk_live_[0-9a-zA-Z]{24,}
xox[baprs]-[0-9A-Za-z-]{10,}             # Slack token
gh[pousr]_[A-Za-z0-9]{36,}               # GitHub token
glpat-[A-Za-z0-9_-]{20,}                 # GitLab PAT
-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----
eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}   # JWT
https://hooks\.slack\.com/services/[...]
```

### Variable/name sweep

```sh
grep -REino '(api[_-]?key|apikey|secret|passwd|password|token|auth|access[_-]?key|client[_-]?secret|private[_-]?key|bearer|credential|salt|encryption[_-]?key)' *.js \
  | sort -u > secret-hits.txt
```

Framework env var names are especially productive because bundlers inline them at build time:

```text
REACT_APP_*        NEXT_PUBLIC_*       VUE_APP_*        VITE_*
process.env.*      import.meta.env.*   ENV['*']         __ENV__
ZENDESK_SECRET     STRIPE_SECRET       FIREBASE_*       COGNITO_*
```

Search `REACT_APP` specifically — in corpus report #638635 a `REACT_APP_ZENDESK_SECRET` constant was inlined into a source map and used to sign arbitrary Zendesk SSO JWTs.

### Validate before reporting

- Keys must look live: correct length/charset, not a placeholder (`YOUR_KEY_HERE`, `xxxx`, `example`, `null`)
- Confirm the key actually works *within scope* (e.g., a Google API key may be restricted by HTTP referrer — still report it, but describe the restriction accurately)
- If the secret is for an out-of-scope service (Zendesk, a SaaS), check whether the program accepts client-side secret exposure on their app — several H1 programs do

### Extract endpoints and parameters

```sh
# LinkFinder: relative + absolute URLs from JS
python3 linkfinder.py -i app.js -o cli
python3 linkfinder.py -i app.js -o html -o report.html

# Quick relative-URL sweep
grep -REo '"/[A-Za-z0-9_./?=&%{}$:-]{3,}"' *.js | sort -u > endpoints.txt
grep -REo "'/[A-Za-z0-9_./?=&%{}$:-]{3,}'" *.js | sort -u >> endpoints.txt
```

Look for:

```text
/api/v1/...        /graphql           /internal/...      /admin/...
/_.json            /config            /debug             /.well-known/
fetch(...)         axios.get/post     $.ajax({url:...})  XMLHttpRequest.open()
new URL(...)       request(...)
```

Then probe the discovered endpoints:

```sh
cat endpoints.txt | httpx -path / -silent -status-code -title -o endpoint-status.txt
```

Feed interesting parameter names into `arjun` / `paramspider` and test for IDOR, mass assignment, and authz bypass. Corpus report #3085742 (Bykea, ▲128) was an IDOR on a "hardcoded zombie endpoint" recovered from client code.

### DOM and client-side sinks

```sh
grep -REin 'innerHTML|outerHTML|document\.write|eval\(|new Function|setTimeout\(|setInterval\(|location\.|href\s*=|dangerouslySetInnerHTML|\.html\(|\.append\(|postMessage|addEventListener\(.message|\.attr\(|window\.open|jascript:' *.js
```

Key observations from the corpus:

- **postMessage listeners** — **68** reports. Check `event.origin` validation. #398054 (HackerOne, $500) : a Marketo `message` handler took `followUpUrl` from the message and assigned it to `location.href = u`, allowing `javascript:` (CSP blocked it, but the sink is the lesson). #231053 (Shopify, $3,000) abused the HTML5 structured clone algorithm in a postMessage listener.
- **`javascript:` / `data:` URLs** — **220** reports mention `javascript:`. #1962645 (Reddit, $5,000) redirect param → XSS; #526325 (GitLab, ▲633) stored XSS in Wiki.
- **DOM XSS** — #868934 (DuckDuckGo, ▲326), #2371019 (Automattic, ▲92), #646505 (Shopify, ▲76).
- **Client-side race** — #381356 (HackerOne, ▲154) client-side race via Marketo sending a user to a `data:` URL.
- **CSP interaction matters** — #1481207 (GitLab, ▲161) injected a `<base href>` tag so nonced webpack chunks loaded from the attacker's domain; the chunks were the payload delivery mechanism.

### Client-side auth and JWT

```sh
grep -REin 'jwt\.sign|jwt\.decode|localStorage|sessionStorage|document\.cookie|Authorization|Bearer|access_token|id_token|refresh_token|oauth|redirect_uri|response_type' *.js
```

Test what you find:

- **JWT with inlined secret** → forge tokens for arbitrary users (report #638635)
- **Token in `localStorage`** → check XSS → token theft chains (#534450 Superhuman, ▲292: cookie manipulation + XSS → ATO)
- **Client-side SSO generation** → any secret in JS is public. #638635 again; also #401326-style patterns
- **OAuth params built in JS** → tamper `redirect_uri`, `response_type`, `state`; see `hackerone-oauth-oidc`
- **Cognito / Firebase config** → often includes identity pool IDs that grant unauthenticated access; see #1342088 (Flickr ATO via AWS Cognito, ▲440)

Decode and inspect JWTs:

```sh
# header/payload only — never paste a live production token into a public website
python3 - <<'PY'
import base64, json, sys
t = sys.argv[1].split('.')
for part in t[:2]:
    print(json.dumps(json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4))), indent=2))
PY
```

### 2. postMessage followUpUrl → javascript: sink (HackerOne, #398054)

A `message` listener parsed JSON, dispatched `mktoResponse`, and the success callback set `location.href = findCorrectFollowUpUrl(data)`. An attacker-controlled `followUpUrl` of `javascript:alert(document.domain);//` reached the sink. CSP blocked execution in modern browsers, but the underlying DOM flaw was valid. **Takeaway: enumerate every `message` listener and follow `event.data` to its sink; check origin validation and URL schemes.**

### 3. Build-time env vars baked into webpack (Semrush, #1717210)

"During the build phase, not essential for the application's functionality environment variables were accidentally included in the webpack configuration" and exposed in the final bundle. **Takeaway: you don't need a source map to find this — grep the minified bundle for token-shaped strings and env-style names.**

### Corpus cheat sheet

```sh
H1=~/.local/share/hackerone-reports/h1.py

python3 "$H1" search "hardcoded secret javascript" --limit 10
python3 "$H1" search "api key" --class crypto-and-secrets --limit 10
python3 "$H1" search "postMessage" --class xss --limit 10
python3 "$H1" search "source map" --limit 10
python3 "$H1" show 638635 --full
python3 "$H1" show 398054 --full
python3 "$H1" show 1717210 --full
```

Mined parameter/path wordlists live at `~/.local/share/hackerone-reports/wordlists/` — `params_crypto-and-secrets.txt`, `paths_info-disclosure.txt`, `params_xss.txt`, `payloads_xss.txt`, and the global `params.txt`/`paths.txt`.

### Reporting checklist

- [ ] Exact JS URL + (if applicable) source-map URL recorded
- [ ] Exact line/variable where the secret or sink appears
- [ ] Secret validated as live and in-scope, or impact otherwise demonstrated
- [ ] Concrete exploit chain (what an attacker can read/do), not just "a key was found"
- [ ] Note any mitigating controls (referrer restrictions, CSP, short token TTL)
- [ ] Suggested fix: move secrets server-side, remove `.map` from production, remove unused env vars from build config

### See also

- `hackerone-js-collect` — gather the files this skill analyzes
- `hackerone-crypto-and-secrets` — key handling and exposed credentials
- `hackerone-info-disclosure` — config/debug data in client assets
- `hackerone-xss` — DOM/XSS payloads for the sinks you find
- `hackerone-oauth-oidc`, `hackerone-session` — token and redirect flaws
- `hackerone-graphql` — GraphQL queries recovered from bundles

### Client-side auth and JWT

```sh
grep -REin 'jwt\.sign|jwt\.decode|localStorage|sessionStorage|document\.cookie|Authorization|Bearer|access_token|id_token|refresh_token|oauth|redirect_uri|response_type' *.js
```

Test what you find:

- **JWT with inlined secret** → forge tokens for arbitrary users (report #638635)
- **Token in `localStorage`** → check XSS → token theft chains (#534450 Superhuman, ▲292: cookie manipulation + XSS → ATO)
- **Client-side SSO generation** → any secret in JS is public. #638635 again; also #401326-style patterns
- **OAuth params built in JS** → tamper `redirect_uri`, `response_type`, `state`; see `oauth-oidc`
- **Cognito / Firebase config** → often includes identity pool IDs that grant unauthenticated access; see #1342088 (Flickr ATO via AWS Cognito, ▲440)

Decode and inspect JWTs:

```sh
# header/payload only — never paste a live production token into a public website
python3 - <<'PY'
import base64, json, sys
t = sys.argv[1].split('.')
for part in t[:2]:
    print(json.dumps(json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4))), indent=2))
PY
```

### See also

- `js-collect` — gather the files this skill analyzes
- `crypto-and-secrets` — key handling and exposed credentials
- `info-disclosure` — config/debug data in client assets
- `xss` — DOM/XSS payloads for the sinks you find
- `oauth-oidc`, `session` — token and redirect flaws
- `graphql` — GraphQL queries recovered from bundles

### Input

`js-collect-output/<target>/processed/` (and recovered sources in `sourcemaps/`). Work on unpacked, beautified code. Minified one-liners make results unreadable.

### 1. Quick triage

A fast first pass to see what's there. Plain search is fine here, as long as you treat hits as leads and not conclusions.

**Sources** (attacker-influenced data): `location.search`, `location.hash`, `location.pathname`, `document.referrer`, `window.name`, `document.cookie`, `localStorage`/`sessionStorage`, `postMessage` payloads, URL parameters parsed into objects, server responses rendered into the DOM.

**Sinks:**
- Code execution: `eval`, `new Function`, `setTimeout`/`setInterval` with a string, `import()` with a variable path, dynamic `<script>` creation, JSONP callbacks
- HTML injection: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `dangerouslySetInnerHTML`, `v-html`, jQuery `.html()`/`.append()` with variables
- Navigation: assignments to `location` / `location.href`, `window.open`, `postMessage` target origins
- Other: `fetch`/`XMLHttpRequest`/`WebSocket` to user-controlled URLs, hardcoded crypto keys, `Math.random` used for tokens

**Message handlers:** every `addEventListener('message', ...)`. Does it check `event.origin`? Is the check exact or a loose `indexOf`/`endsWith`?

### 2. Prototype pollution candidates

Look for code that writes to objects using attacker-influenced keys:
- Recursive merge/extend/clone/deep-set functions (`merge`, `extend`, `defaultsDeep`, `set`, `$.extend(true, ...)`) with no guard against `__proto__`, `constructor`, and `prototype`
- `for...in` copies without a `hasOwnProperty` check
- Bracket assignment `obj[a][b] = c` where `a`/`b` come from input (query string, JSON, hash)
- Query-string or hash parsers that build nested objects

Then look for **gadgets**: places that read a property that might be missing and fall through to the prototype (script `src`, template options, config flags, `innerHTML`-bound fields). A pollution source with no reachable gadget has low impact.

### 3. Taint analysis

Use a static taint tool instead of reading flows by eye.
- **Semgrep** (JavaScript taint-mode rules): define sources and sinks from step 1, run against `processed/`.
- **CodeQL** (JavaScript/TypeScript): build a database from the recovered sources and run the standard DOM-XSS, prototype-pollution, and open-redirect queries.
- Keep the rules and queries you used in the output folder so the run is repeatable.

Bundled and transpiled code can break flow tracking. Prefer recovered original sources when a sourcemap gave them.

### 4. Cross-reference known gadgets

Before assigning confidence, compare each candidate against public references: published client-side prototype-pollution gadget lists, PortSwigger research on DOM XSS and prototype pollution, and advisories for the specific library versions in use. A match gets a reference link and a confidence bump. Anything unmatched stays a candidate.

### Output: `gadgets.md`

| File | Line | Sink / gadget | Source | Reachable from (route/feature) | Confidence | Known reference | Notes |
|------|------|---------------|--------|--------------------------------|------------|-----------------|-------|

Confidence:
- **high**: reproduced in the running app
- **medium**: static taint flow found, not yet reproduced
- **low**: sink present, no source reaching it found
- **candidate**: pattern match only

End the file with the five highest-value leads and the manual test you'd run for each. Hand the table to `js-analyse` to join with routes and the feature map.

### Input

A `js-collect-output/<target>/` folder (or any set of JS files). Prefer `processed/` and recovered sourcemap sources. Also use `flows_endpoints.txt` and `summary.md` from `js-collect` as a starting point, and join `gadgets.md` from `js-sinks` to the routes and features you find.

### 1. Params and route analysis

Extract every client-side route and parameter name:
- Router definitions (React Router, Vue Router, Angular routes, Next.js pages, Express-style path strings)
- Query parameters and form field names the code reads or sends
- **Admin and privileged routes:** paths containing `admin`, `internal`, `debug`, `staff`, `manage`, `superuser`, role checks such as `isAdmin`, `role ===`, `hasPermission`
- **Feature flags:** flag names, default values, how they are loaded (config endpoint, inline object, third-party flag service), and whether flags are enforced client-side only
- **Interesting comments:** TODO/FIXME/HACK, developer names, internal hostnames, ticket IDs, commented-out code, disabled endpoints

For each route, note whether it needs authentication and which role the code expects.

### 2. API analysis

- Extract every `fetch`, `axios`, `XMLHttpRequest`, GraphQL operation, and WebSocket message.
- Record: method, URL or path template, parameters, headers, auth mechanism, request/response shape.
- **Old versions:** look for `/v1/`, `/v2/`, `/legacy/`, `/beta/` and compare with the version the app currently uses. Older versions often lack newer authorization checks.
- **Group all calls by functionality** (auth, profile, payments, uploads, admin, search, messaging, etc.), so related endpoints can be tested together for authorization and logic issues.
- Note base URLs, third-party APIs, and any internal or staging hosts.

### 3. Library analysis

- Identify every library and version (from banners, `package.json` fragments in sourcemaps, version constants, known file signatures).
- **Outdated:** compare against the latest release.
- **Security:** check each version against known-vulnerability sources (OSV, GitHub advisories, retire.js database, npm audit). Record the CVE/advisory ID and whether the vulnerable code path is actually reachable in this app.
- An old version is a lead, not a finding. Confirm exploitability before reporting.

### 4. Framework and tech analysis

Identify and record:
- Framework and version (React, Angular, Vue, Next.js, Nuxt, Svelte, jQuery, etc.)
- Bundler and build tooling (webpack, Vite, Rollup), and whether dev builds or sourcemaps are exposed in production
- State management, auth libraries (OAuth/OIDC clients, JWT handling), analytics, error-tracking, and payment SDKs
- Framework-specific risks: SSR data leaks (`__NEXT_DATA__`, `window.__INITIAL_STATE__`), exposed server actions, client-trusted authorization

### 5. Feature map

Combine the above into one map of what the app can do:

| Feature | Routes | API endpoints | Roles | Flags | Notes / test ideas |
|---------|--------|---------------|-------|-------|--------------------|

Highlight features that exist in code but aren't reachable from the UI. These are often the most valuable targets.

### 6. Secrets

Scan for exposed credentials and sensitive values using two methods, then compare:
- **Known-pattern regex:** cloud provider keys, API tokens (Stripe, Slack, GitHub, Google, Twilio, etc.), JWTs, private key blocks, database URLs, OAuth client secrets
- **High-entropy strings:** compute Shannon entropy on string literals and flag long, random-looking values the regexes missed

Triage each hit:
- Is it a secret or a public identifier? (Public client IDs, publishable keys, and analytics IDs are usually not findings.)
- What would it grant, according to the provider's documentation?
- Is it in current code or only in an old/historical version?

Verify validity only through methods the program allows (for example, a provider's documented non-destructive key-check endpoint), and stop there. Redact secrets in notes and reports.

### Output

Produce `analysis.md` with these sections:

1. **Summary**: target, files analyzed, tech stack, top 5 leads
2. **Routes and parameters**
3. **API inventory** (grouped by functionality, old versions flagged)
4. **Libraries** (name, version, latest, known issues)
5. **Feature map**
6. **Secrets** (redacted, with triage notes)
7. **Next steps**: ordered list of what to test manually, most promising first

For each lead, include the source file and line so you can find it again.
