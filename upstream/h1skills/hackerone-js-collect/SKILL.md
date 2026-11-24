---
name: hackerone-js-collect
description: >-
  Collect JavaScript files from a live target during recon: map the JS attack surface, find bundles, chunks, source maps, and script URLs before analysis. Use when enumerating scripts, gathering JS from a scope, or building a target's JS inventory. Backed by 1,330 disclosed HackerOne reports mentioning JavaScript.
---

# JavaScript Collection — HackerOne field guide

Recon playbook for gathering every reachable JavaScript file for an in-scope target. Analysis of what's inside the files lives in `hackerone-js-analyze`. Built from your local corpus of **~15,000 disclosed HackerOne reports** at `~/.local/share/hackerone-reports/` — **1,330** reports mention JavaScript, **68** mention `postMessage`, **141** mention API keys, and **40** hardcoded values.

> For authorized testing only. Stay inside the program's scope; never test systems you are not permitted to touch.

## Signal

- JS-adjacent reports: **1,330** mentioning javascript · **208** paid · **$392,415** disclosed bounties
- Browser-side sinks: **68** `postMessage` · **56** DOM XSS · **30** "DOM Based XSS"
- Secret exposure: **141** "api key" · **40** "hardcoded" · **34** "secret key"
- Top programs in the JS slice: Node.js third-party modules (137), U.S. DoD (132), Shopify (63), HackerOne (53), GitLab (48), X/xAI (36), Automattic (35), Uber (33), Rocket.Chat (29)

## Quick wins

Ordered by yield — do these first.

1. **Seed from the live HTML.** Fetch every in-scope URL and extract `src=` from `<script>` tags. Modern apps hide 80%+ of their code in hashed bundles you can only discover from the page that loads them.
2. **Enumerate subdomains first.** JS often lives on `assets.`, `static.`, `cdn.`, `s3.`, `*.cloudfront.net`, `*.azureedge.net`, or a separate `*.dev`/`*.staging` host. Subdomains you miss are JS you never collect.
3. **Query historical URLs** (Wayback/Common Crawl via `gau`, `waybackurls`) and filter for `.js`, `.js.map`, `.mjs`, `.json` config files. Old, forgotten bundles are gold: they often still contain the secrets the current build removed.
4. **Crawl with JS rendering** (`katana -jc`, `gospider`) — client-side routers (React/Vue/Angular/Next) only emit script URLs after JavaScript executes.
5. **Hunt source maps.** A public `.js.map` turns minified spaghetti into original TypeScript with comments, `process.env` references, and internal filenames. Report #638635 (Trint, ▲102) was found this way.
6. **Check the asset host's directory and path patterns** — `/assets/webpack/`, `/static/js/`, `/_next/static/chunks/`, `/packs/js/`. Next.js/Nuxt/Webpack apps leak their whole build manifest.
7. **Collect with status/size metadata**, not just URLs. A `200` that returns an HTML error page is not a JS file; dedupe by content hash.

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

## Techniques from real reports

| Report | Program | Bounty | Lesson for collection |
|---|---|---:|---|
| [#638635](https://hackerone.com/reports/638635) | Trint Ltd | — (▲102) | Source maps sat **next to** minified files at `/static/js/app.<hash>.js.map`; always request the `.map` sibling. |
| [#1481207](https://hackerone.com/reports/1481207) | GitLab | — (▲161) | Failed asset loads revealed exact webpack chunk names (`/assets/webpack/top_nav.<hash>.chunk.js`) via DevTools after a `<base>` injection — a reminder to record chunk paths from the browser, not only from HTML. |
| [#1717210](https://hackerone.com/reports/1717210) | Semrush | — (▲56) | Build-time env vars were baked into a webpack bundle — collect **build artifacts**, not just API responses. |
| [#1160407](https://hackerone.com/reports/1160407) | GitLab | — (▲83) | `assets.gitlab-static.net` cache poisoning — asset hosts are in scope when they serve the app's JS. |
| [#90367](https://hackerone.com/reports/90367) | HackerOne | — | Public uncompiled CSS + source maps; "dev artifacts on prod" is a recurring, low-effort find. |
| [#1444682](https://hackerone.com/reports/1444682) | Shopify | $9,400 | XSS on a `*.shopifycloud.com` asset host — never stop at the main domain. |
| [#3085742](https://hackerone.com/reports/3085742) | Bykea | — (▲128) | "Hardcoded zombie endpoint" found in-app — old JS can expose forgotten APIs. |

## Handoff to analysis

When collection is done you should have:

- `js-urls.txt` — every unique script URL
- `js-files/manifest.tsv` — filename → source URL
- `map-urls.txt` / downloaded `.map` files — source maps with `sourcesContent`
- A note of any script host outside the main domain

Then invoke **`hackerone-js-analyze`** to mine these files for secrets, endpoints, sinks, and client-side auth flaws.

## See also

- `hackerone-info-disclosure` — exposed config, tokens, and debug data
- `hackerone-crypto-and-secrets` — hardcoded keys and credential handling
- `hackerone-xss` — DOM XSS sinks found in the collected JS
- `hackerone-subdomain-takeover` — dead asset hosts discovered during JS recon
- `hackerone-graphql` — queries and endpoints embedded in bundles
