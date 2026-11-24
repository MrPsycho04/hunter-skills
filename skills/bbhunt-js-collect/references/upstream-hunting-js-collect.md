# Upstream source: js-collect (hunting)

Original path: `/tmp/h1res_MrPsycho04_Hunting-Agent/js-collect/SKILL.md`

---

---
name: js-collect
description: >-
  Collect JavaScript files from a live target during recon: map the JS attack surface, find bundles, chunks, source maps, and script URLs before analysis. Use when enumerating scripts, gathering JS from a scope, or building a target's JS inventory. Backed by 1,330 disclosed HackerOne reports mentioning JavaScript.
---

# JavaScript Collection — HackerOne field guide

Recon playbook for gathering every reachable JavaScript file for an in-scope target. Analysis of what's inside the files lives in `js-analyze`. Built from your local corpus of **~15,000 disclosed HackerOne reports** at `~/.local/share/hackerone-reports/` — **1,330** reports mention JavaScript, **68** mention `postMessage`, **141** mention API keys, and **40** hardcoded values.

> For authorized testing only. Stay inside the program's scope; never test systems you are not permitted to touch.

**Reference files (load on demand):**

- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Signal

- JS-adjacent reports: **1,330** mentioning javascript · **208** paid · **$392,415** disclosed bounties
- Browser-side sinks: **68** `postMessage` · **56** DOM XSS · **30** "DOM Based XSS"
- Secret exposure: **141** "api key" · **40** "hardcoded" · **34** "secret key"
- Top programs in the JS slice: Node.js third-party modules (137), U.S. DoD (132), Shopify (63), HackerOne (53), GitLab (48), X/xAI (36), Automattic (35), Uber (33), Rocket.Chat (29)

## Where JS hides

- `<script src>` in initial HTML, and lazy-loaded chunks referenced inside the downloaded bundles
- Inline `<script>` blocks and `import(...)` / dynamic `import()` expressions
- `link[rel=modulepreload]`, `link[as=script]`, service-worker registrations (`navigator.serviceWorker.register('/sw.js')`)
- Next.js: `/_next/static/chunks/pages/*.js`, `build-manifest.json`, `_buildManifest.js`
- Webpack: `/assets/webpack/*.chunk.js`, `*.bundle.js`, named chunks seen in DevTools network tab
- Vue/Nuxt: `/_nuxt/*.js`, `/static/js/`, `chunk-vendors.<hash>.js`
- Rails: `/packs/js/*.js` (Webpacker), `/assets/*.js`
- Django: `/static/js/`, `/static/bundles/`
- Angular: `main.<hash>.js`, `runtime.<hash>.js`, `polyfills.<hash>.js`
- Electron/desktop: `app.asar`, packaged `*.js` inside the app bundle
- Mobile: JS bridged in WebViews, `file:///android_asset/www/`, Cordova `www/` directories
- Third-party hosts: analytics, tag managers, chat widgets, payment SDKs, CDN-hosted themes — check scope before testing
- `.json` siblings: `manifest.json`, `config.json`, `env.json`, `version.json`, `*.map`

## Collection workflow

### 1. Scope → hosts

```sh
# Subdomains and live hosts
subfinder -dL domains.txt -silent | sort -u > subs.txt
httpx -l subs.txt -silent -o alive.txt

# Add the root domains, www, and any explicit in-scope hosts
printf '%s\n' example.com www.example.com >> alive.txt
sort -u alive.txt -o alive.txt
```

### 2. Seed URLs → JS references

```sh
# Passive historical URLs (gau pulls Wayback + Common Crawl + URLScan)
gau --subs example.com | sort -u > urls.txt
# or: waybackurls example.com >> urls.txt

# Active crawl with JS rendering
katana -list alive.txt -jc -kf -d 4 -silent -o katana.txt
# gospider alternative (good for deep link discovery)
gospider -S alive.txt -d 3 -c 10 -t 20 -o gospider-out
```

### 3. Extract script URLs

```sh
# Direct JS URLs from the URL corpus
grep -Eio 'https?://[^"'"'"' <>]+(\.js|\.mjs)(\?[^"'"'"' <>]*)?' urls.txt katana.txt \
  | sed 's/[),;]*$//' | sort -u > js-urls.txt

# Script tags from live pages
while read -r u; do
  curl -sL --max-time 10 "$u" \
    | grep -Eio '<script[^>]+src=["'"'"'][^"'"'"']+' \
    | sed -E 's/.*src=["'"'"']//'
done < alive.txt >> js-urls.txt
sort -u js-urls.txt -o js-urls.txt
```

Resolve relative paths against their page URL (use Python/`urllib.parse.urljoin` or `arjun`/`urless`), then dedupe:

```sh
python3 - <<'PY'
from urllib.parse import urljoin
import sys
page = sys.argv[1]
for line in sys.stdin:
    u = line.strip()
    if u:
        print(urljoin(page, u))
PY
```

### 4. Find source maps

```sh
# Method A: inspect the bundle's trailing comment
curl -s https://target/static/js/app.abc123.js | tail -c 500 | grep -i 'sourceMappingURL'

# Method B: just request the conventional sibling
while read -r u; do printf '%s.map\n' "$u"; done < js-urls.txt > map-urls.txt
ffuf -u FUZZ -w map-urls.txt -mc 200 -of csv -o maps-found.csv
```

A `.map` is a JSON object: `sources`, `sourcesContent`, `names`, `mappings`. `sourcesContent` frequently contains unminified source — pass it straight to the analyze skill.

### 5. Brute-force common JS paths (when the app is a SPA with few discoverable scripts)

```sh
ffuf -u https://TARGET/FUZZ -w ~/.local/share/hackerone-reports/wordlists/paths.txt \
     -mc 200 -fc 404 -recursion -recursion-depth 2 -o js-paths.json
```

Handy JS path seeds:

```text
/static/js/app.js
/static/js/main.js
/static/js/bundle.js
/static/js/chunk-vendors.js
/assets/webpack/main.js
/assets/index.js
/js/app.js
/bundle.js
/main.js
/app.js
/dist/main.js
/build/bundle.js
/_next/static/chunks/main.js
/_nuxt/app.js
/packs/js/application.js
/static/bundles/app.js
/sw.js
/service-worker.js
/manifest.json
/config.json
/env.json
```

### 6. Download and dedupe

```sh
mkdir -p js-files && cd js-files
while read -r u; do
  name="$(printf '%s' "$u" | md5 -q 2>/dev/null || printf '%s' "$u" | md5sum | cut -d' ' -f1)"
  curl -sL --max-time 15 "$u" -o "$name.js"
  printf '%s\t%s\n' "$name.js" "$u" >> manifest.tsv
done < ../js-urls.txt

# Keep only real JS (reject HTML 200s)
for f in *.js; do
  head -c 200 "$f" | grep -qE '<!doctype|<html|error|not found' && rm -f "$f"
done
```

Save every file with its source URL in a manifest — you need that mapping when a secret turns out to be real and you're writing the report.

## Filtering noise

Libraries dominate the results. You still download them (a bundled vendor copy can carry a config the CDN copy doesn't), but triage them last. Skip/ deprioritize by signature:

```text
jquery, react.production, angular.js, vue.runtime, bootstrap,
lodash, moment, chart.js, d3, hammer, polyfill, swiper,
webpack runtime (short "webpackJsonp" bootstrap)
```

Use [jslib](https://github.com/NoahSaso/jslib) if you have it locally to auto-classify library vs first-party code. First-party chunks are where the bugs are.

Also watch for:
- **Same content, many hashes** — cache-busted copies; dedupe by hash to save time
- **Dev bundles on prod** — `*.dev.js`, unminified, with `webpack://` paths and source maps
- **Backups** — `app.js.bak`, `app.js.old`, `app.js~`, `app.js.1`, `app.min.js.map`
- **Wrong content-type** — a JS endpoint served as `text/plain` is still useful

## Corpus cheat sheet (your downloaded reports)

The skills are generated from `~/.local/share/hackerone-reports/`. Use the companion CLI to pull report examples that inform your recon choices:

```sh
H1=~/.local/share/hackerone-reports/h1.py

python3 "$H1" search "source map" --limit 10
python3 "$H1" search "webpack bundle token" --limit 10
python3 "$H1" search "javascript asset cdn" --limit 10
python3 "$H1" search "postMessage" --class xss --limit 10
python3 "$H1" show 638635 --full       # source map -> hardcoded JWT secret
python3 "$H1" show 1481207 --full      # webpack chunk names as CSP-bypass oracle
python3 "$H1" stats --class info-disclosure
```

## Handoff to analysis

When collection is done you should have:

- `js-urls.txt` — every unique script URL
- `js-files/manifest.tsv` — filename → source URL
- `map-urls.txt` / downloaded `.map` files — source maps with `sourcesContent`
- A note of any script host outside the main domain

Then invoke **`js-analyze`** to mine these files for secrets, endpoints, sinks, and client-side auth flaws.

## See also

- `info-disclosure` — exposed config, tokens, and debug data
- `crypto-and-secrets` — hardcoded keys and credential handling
- `xss` — DOM XSS sinks found in the collected JS
- `subdomain-takeover` — dead asset hosts discovered during JS recon
- `graphql` — queries and endpoints embedded in bundles

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete artifacts, endpoints, patterns, tools to look for

- **Crawl every application state, not just the landing page:** browse as anonymous, low-privilege, and highest-privilege test accounts with Burp/ZAP/Caido recording. Code splitting means lazy-loaded chunks only appear when their route is visited; admin/beta chunks exist on the server even if your role never renders them.
- **Harvest script URLs from three sources:** (1) live HTML `<script src>` extraction (`grep -oE 'src="[^"]+\.js"'`); (2) Burp Site Map filtered to MIME type `script` / extension `.js`, plus "Engagement tools → Find scripts"; (3) historical URLs from `waybackurls`, `gau`, and the Archive.org CDX API (`curl -G "https://web.archive.org/cdx/search/cdx" --data-urlencode "url=*.example.com/*" --data-urlencode "fl=original"`).
- **Chunk-name mining:** the main bundle must contain the filenames of chunks it can lazy-load; grepping chunk names leads to code for pages your account never saw. Framework manifests are gold: `_buildManifest.js` (`sortedPages`), `__NEXT_DATA__` `buildId`, `asset-manifest.json`, webpack runtime chunk maps.
- **Source maps:** for every `<file>.js` check `<file>.js.map` (append `.map`), and read the `//# sourceMappingURL=` trailer. OWASP WSTG-INFO-05 explicitly lists this as a black-box test. Prefer maps with `sourcesContent` — those contain original source, comments, and absolute filesystem paths.
- **Public env prefixes:** `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_` are inlined at build time; collect their literal values — API bases, staging hosts, feature-flag endpoints.
- **Third-party vs first-party triage:** de-prioritize `react-dom`, `lodash`, analytics/ads SDKs; prioritize the application's own hashed bundles (`main.<hash>.js`, `app.<hash>.js`, `[n].<hash>.js`). Still record third-party script hosts for supply-chain review (OWASP Third Party JS cheat sheet, SRI, JS Drift).
- **Host-level spread:** note any script host outside the main domain (`cdn.`, `static.`, `assets.`), and cross-check those hosts against the scope list before testing.
- **Tool inventory:** `waybackurls`, `gau`, `katana -jc` (extracts paths from JS it finds), `ffuf`/`feroxbuster --burp` for API-path discovery, `Uproot` (Burp plugin that saves every encountered JS to disk), `jsluice`, `LinkFinder`/`xnLinkFinder`, `JS Miner`, `JSpector`, `jsleak`.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Validate archived URLs before mining:** `cat js-cdx.txt | httpx -mc 200 -o js-live.txt` — dead Wayback hits waste analysis time but can still reveal *old* endpoint names for version drift (feed to `shadow-api`).
- **Complete the inventory loop:** after browsing, re-check the Site Map; Burp passively extracts some endpoints, but "Find scripts" + a heavier `LinkFinder`/`jsluice` pass is needed for full coverage.
- **Burp automation:** a BCheck "Swagger endpoint found" iterates known documentation paths; `JS Miner`'s "API Endpoints Finder" passive scan surfaces endpoints directly in the proxy. Run an active scan — it often triggers source-map retrieval.
- **Minified/obfuscated/encrypted distinction:** minified → `js-beautify`/`prettier` (readability only); obfuscated → `webcrack` (handles `javascript-obfuscator` string arrays and control-flow flattening) or `jsnice`; "encrypted" strings → the decryption key travels in the same bundle, so decode with `atob()` or a Python `print("\x2f...")`.
- **Decode without execution:** evaluate only isolated string expressions, never the whole bundle under `node` (third-party code has filesystem/network access); the target's browser console is already sandboxed.
- **Beautify pipeline:** `curl -s <url> -o main.js && npx --yes js-beautify main.js > main.pretty.js`; then `grep -oE '"/(api|admin|internal|v[0-9]+)[^"]*"' main.pretty.js | sort -u`.
- **Hidden-path fuzzing from a seed:** with `PUT /api/user/update` discovered, Intruder/ffuf the `{update}` position with `delete`, `add`, `list`, etc.; use SecLists `Discovery/Web-Content/api/api-endpoints-res.txt` and target-specific terms from initial recon.
- **Hidden-parameter discovery:** mark `id` in `/api/author?id=1` and fuzz parameter names while keeping `=1` — a 500/error often reveals a real parameter; Param Miner or Caido equivalents automate this.
- **Preserve provenance:** maintain `js-urls.txt`, `js-files/manifest.tsv` (filename → source URL), `map-urls.txt`, and a note of off-domain script hosts so analysis can cite exact artifacts.

### C. Validation / proof bar — how to confirm and avoid false positives

- A collected script is not a finding. Scope-check the host; discard same-named third-party assets (`recon-scope-triage`).
- Confirm a source map is genuinely served (HTTP 200 + JSON-shaped content) rather than trusting the `sourceMappingURL` comment alone; some servers return a SPA HTML fallback with 200.
- Deduplicate by hash before analysis so the same hashed bundle from multiple paths is not counted twice; note its first-seen URL and which account state revealed it.
- Lazy-loaded chunks: absence from the initial crawl is not evidence of absence — revisit with the privileged account and with forced route navigation before concluding a feature is not in the bundle.
- Record which account/state unlocked each artifact; this is required later to demonstrate that hidden admin routes were reachable from the client even if the UI hid them.
- Avoid destructive collection: do not trigger state-changing endpoints just to make them appear in the Site Map; use read requests and existing documentation.

- **Pre-redirect scripts matter:** capture the response body of an unauthenticated landing page before the app redirects to SSO — those bundles often carry the public API base URLs and login/register endpoints.
- **Historical bundle versions:** a stale hashed bundle from Wayback can still reference endpoints removed from the current build; these are prime shadow/zombie candidates (hand to `shadow-api`).
- **Archive CDX filtering:** add `--data-urlencode "filter=mimetype:application/javascript"` and `filter=statuscode:200` to reduce the archive result set before downloading.
- **Crawl the mobile surface too:** if the target ships an app, its hardcoded endpoints (from `apk-redteam-pipeline`/`ios-redteam-pipeline`) should be added to the collection target list — mobile builds frequently expose an older API version.
- **Deduplicate by SHA-256 of the response body**, not by URL: hashed bundles are served from many paths, and duplicate analysis wastes time; keep the first-seen URL as provenance.
- **Record HTTP metadata for each artifact:** status code, content type, cache headers, and timestamp — a 200 HTML fallback at a `.js.map` path is not a source map.
- **Chunk naming conventions** (`<number>.<hash>.js`, `static/chunks/...`, `_next/static/chunks/app/...`) identify which build tool produced the app and therefore which manifest and source-map conventions to expect.
- **Scope discipline:** collect from in-scope hosts only; a third-party CDN or same-named unrelated domain in a script `src` is out of scope and must not be tested (`recon-scope-triage`).
- **Preserve chain-of-custody:** keep raw responses (redacted of any live cookies/tokens per `evidence-hygiene`) so the analysis phase can cite exact line numbers and reproduce findings.

- **Output manifest discipline:** finish with `js-urls.txt`, `js-files/manifest.tsv`, `map-urls.txt`, and a one-line note per off-domain script host — `js-analyze` consumes these directly.
- **OSINT corroboration:** cross-check discovered API/internal hostnames against certificate-transparency records and DNS before spending analysis time; this also confirms the asset belongs to the target.
- **Don't stop at one page:** single-page apps load new chunks on route change, role change, and feature-flag activation — repeat the collection pass after each state transition.

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/web-security/api-testing (API recon, docs paths, JS Link Finder BApp, hidden endpoint/parameter fuzzing)
2. https://www.guidepointsecurity.com/blog/the-secret-life-of-apis-uncovering-hidden-endpoints-and-more (highest-privilege crawl, JS Miner, BCheck Swagger discovery)
3. https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage (source-map `.map` black-box test)
4. https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html (first/third-party triage, SRI, JS drift)
5. https://amrelsagaei.com/javascript-analysis-masterclass-pt-1 (Burp mime filter, Wayback/CDX harvesting, LinkFinder, jsleak, LocalStorage audit)
6. https://pwnversity.online/en/recon/recon-js/ (chunk/manifest/environment-variable inventory, bundle collection workflow)
7. https://www.rootsec.in/cheatsheets/web-security/js-analysis (LinkFinder/jsluice commands, source-map extraction)
8. https://my-hack-tricks.gitbook.io/my-hacktricks/network-services-pentesting/pentesting-web/code-review-tools (Burp "Find scripts", waybackurls grep, JSnice workflow)
9. https://bugbounty.info/Recon/API-Discovery (combined Swagger/GraphQL/JS/mobile-traffic discovery graph)

