---
name: hackerone-js-analyze
description: >-
  Analyze collected JavaScript files for bugs: hardcoded secrets and API keys, hidden endpoints and parameters, DOM XSS sinks, client-side JWT/auth flaws, source maps, and exposed config. Use when reviewing bundles, minified JS, or .map files from a target. Backed by 1,330 disclosed HackerOne reports mentioning JavaScript.
---

# JavaScript Analysis — HackerOne field guide

Turn collected JS into findings. Pair with `hackerone-js-collect` for gathering the files. Built from your local corpus of **~15,000 disclosed HackerOne reports** at `~/.local/share/hackerone-reports/` — **1,330** reports mention JavaScript, **141** "api key", **40** "hardcoded", **34** "secret key", **68** `postMessage`, **56** DOM XSS.

> For authorized testing only. Validate every leaked credential against program scope and report impact, don't abuse it.

## Signal

- Secret exposure: **141** "api key" · **40** "hardcoded" · **34** "secret key" · **14** "access key"
- Client-side auth: **66** JWT · **109** "client-side" · **57** `postMessage` · **20** `localStorage`
- Top classes to mine: `info-disclosure` (1,827 reports), `crypto-and-secrets` (562), `xss` (2,569), `auth-bypass` (989), `authz-bypass` (1,386)
- Median payoff for a *valid* hardcoded secret or source-map disclosure is usually low severity on its own — the money is in the **escalation** (forge a token, access another tenant, reach an internal API).

## Quick wins

Ordered by yield.

1. **Get the source map first.** `curl https://target/app.<hash>.js.map | jq -r '.sourcesContent[]'`. Original source with `process.env` / `REACT_APP_*` references is worth 100× the minified bundle. Report #638635 is the canonical example.
2. **Grep for secret names and prefixes** across all collected JS (patterns below). Triage hits: real key vs placeholder vs docs example.
3. **Extract endpoints** with LinkFinder or a string sweep. Feed unique paths to your HTTP client (`httpx`) and check for unauthenticated / undocumented endpoints.
4. **Find hidden parameters and GraphQL queries** in request-building code (`axios`, `fetch`, `ky`, GraphQL `.graphql` strings). Try them on live endpoints — hidden params are a classic IDOR/mass-assignment entry point.
5. **Trace DOM sinks** — `innerHTML`, `eval`, `Function`, `location`, `document.write`, `dangerouslySetInnerHTML`, `.html()`, `postMessage` listeners. This is where bundled JS pays as XSS.
6. **Decode every JWT-looking string** at jwt.io. Check whether the signing secret is also in the JS — if so, you can mint arbitrary tokens.
7. **Check for vulnerable libraries** (`retire.js`, npm advisory lookup) — a bundled old jQuery/React/Angular can be a known CVE with a ready PoC.

## Prepare the files

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

## Secret and key patterns

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

### Entropy / tooling

```sh
trufflehog filesystem ./js-files --no-verification
gitleaks detect --source ./js-files --no-git -v
# jsfinder / SecretFinder for pattern-based JS sweeps
python3 SecretFinder.py -i app.js -o cli
```

## Extract endpoints and parameters

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

## DOM and client-side sinks

```sh
grep -REin 'innerHTML|outerHTML|document\.write|eval\(|new Function|setTimeout\(|setInterval\(|location\.|href\s*=|dangerouslySetInnerHTML|\.html\(|\.append\(|postMessage|addEventListener\(.message|\.attr\(|window\.open|jascript:' *.js
```

Key observations from the corpus:

- **postMessage listeners** — **68** reports. Check `event.origin` validation. #398054 (HackerOne, $500) : a Marketo `message` handler took `followUpUrl` from the message and assigned it to `location.href = u`, allowing `javascript:` (CSP blocked it, but the sink is the lesson). #231053 (Shopify, $3,000) abused the HTML5 structured clone algorithm in a postMessage listener.
- **`javascript:` / `data:` URLs** — **220** reports mention `javascript:`. #1962645 (Reddit, $5,000) redirect param → XSS; #526325 (GitLab, ▲633) stored XSS in Wiki.
- **DOM XSS** — #868934 (DuckDuckGo, ▲326), #2371019 (Automattic, ▲92), #646505 (Shopify, ▲76).
- **Client-side race** — #381356 (HackerOne, ▲154) client-side race via Marketo sending a user to a `data:` URL.
- **CSP interaction matters** — #1481207 (GitLab, ▲161) injected a `<base href>` tag so nonced webpack chunks loaded from the attacker's domain; the chunks were the payload delivery mechanism.

## Client-side auth and JWT

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

## Escalation chains

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

## Case studies

### 1. Source map → client-side JWT secret → arbitrary impersonation (Trint, #638635)

The reporter fetched `/static/js/app.e984c9df.js.map` next to the minified bundle. Its `sourcesContent` contained `ZendeskLoadingPage.js` with:

```js
const { REACT_APP_ZENDESK_SECRET } = process.env;
const zendeskToken = jwt.sign(payload, REACT_APP_ZENDESK_SECRET);
window.location = `${ZENDESK_DOMAIN}/access/jwt?jwt=${zendeskToken}`;
```

Grepping the map for `REACT_APP_ZENDESK_SECRET` yielded the literal secret. Anyone could mint a Zendesk SSO JWT for any email. **Takeaway: bundle inlining turns `process.env` into a public constant, and source maps hand you the variable name.**

### 2. postMessage followUpUrl → javascript: sink (HackerOne, #398054)

A `message` listener parsed JSON, dispatched `mktoResponse`, and the success callback set `location.href = findCorrectFollowUpUrl(data)`. An attacker-controlled `followUpUrl` of `javascript:alert(document.domain);//` reached the sink. CSP blocked execution in modern browsers, but the underlying DOM flaw was valid. **Takeaway: enumerate every `message` listener and follow `event.data` to its sink; check origin validation and URL schemes.**

### 3. Build-time env vars baked into webpack (Semrush, #1717210)

"During the build phase, not essential for the application's functionality environment variables were accidentally included in the webpack configuration" and exposed in the final bundle. **Takeaway: you don't need a source map to find this — grep the minified bundle for token-shaped strings and env-style names.**

### 4. Webpack chunk names as a CSP-bypass oracle (GitLab, #1481207)

After injecting a `<base href=https://attacker>` via Markdown, DevTools showed failed requests for `/assets/webpack/hello.<hash>.chunk.js`. Hosting files at those exact paths on the attacker domain made them load with the page's nonces → stored XSS. **Takeaway: the JS inventory from collection is itself an exploitation asset.**

## Corpus cheat sheet

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

## Reporting checklist

- [ ] Exact JS URL + (if applicable) source-map URL recorded
- [ ] Exact line/variable where the secret or sink appears
- [ ] Secret validated as live and in-scope, or impact otherwise demonstrated
- [ ] Concrete exploit chain (what an attacker can read/do), not just "a key was found"
- [ ] Note any mitigating controls (referrer restrictions, CSP, short token TTL)
- [ ] Suggested fix: move secrets server-side, remove `.map` from production, remove unused env vars from build config

## See also

- `hackerone-js-collect` — gather the files this skill analyzes
- `hackerone-crypto-and-secrets` — key handling and exposed credentials
- `hackerone-info-disclosure` — config/debug data in client assets
- `hackerone-xss` — DOM/XSS payloads for the sinks you find
- `hackerone-oauth-oidc`, `hackerone-session` — token and redirect flaws
- `hackerone-graphql` — GraphQL queries recovered from bundles
