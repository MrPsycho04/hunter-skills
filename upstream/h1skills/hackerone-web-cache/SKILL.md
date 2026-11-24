---
name: hackerone-web-cache
description: >-
  Hunt cache poisoning and deception. Use when testing CDNs, reverse proxies, and unkeyed input handling. Backed by 68 disclosed HackerOne reports.
---

# Web Cache Poisoning / Deception — HackerOne field guide

Built from **68** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

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

## Quick wins

Start here. These are the highest-yield tests for this class.

- Identify cache layers, keys, and TTLs from headers and behavior.
- Find unkeyed inputs: X-Forwarded-Host, X-Host, X-Original-URL, cookies, headers reflected in responses.
- Test cache deception with static extensions on authenticated routes.
- Check normalization mismatches between cache and origin.

## Payloads & probes

- `X-Forwarded-Host: evil.com` `X-Host: evil.com` `X-Forwarded-Scheme: http`
- `/account/profile.css` `/account/profile%2ecss` `/account/profile;.css`
- Cache buster -> `?cb=123` then poison the canonical URL

## Bypass tricks

- Use unkeyed headers that the origin reflects into redirects or HTML.
- Exploit path normalization: `/x/..%2faccount`.
- Poison only your own cache key, then request the victim URL.

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`any CDN/proxy path` `static extensions` `X-Forwarded-*` `Host` `cookies`

## Tools

`Burp` · `Web Cache Vulnerability Scanner` · `Param Miner`

## Escalation chains

- Cache poisoning -> stored XSS.
- Cache deception -> PII theft.

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

## Payload fragments observed

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

## Parameters observed

`for[]` · `for` · `dontpoisoneveryone` · `cachebuster` · `cb` · `cachebust` · `yeettest` · `token` · `qwKzzSR` · `xyzxyz` · `hackerone` · `petIncluded` · `filterByTotalPrice` · `ssr` · `email` · `authenticity_token` · `letme` · `enable_registration` · `redirectTo` · `referrer_page_location`

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

## Wordlists

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

## Nuclei

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

## Related

- `hackerone-request-smuggling` (101 reports)
- `hackerone-xss` (2,569 reports)
- `hackerone-info-disclosure` (1,827 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.
