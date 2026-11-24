# Evidence appendix — HTTP Request Smuggling and Desync

Mined from all **97 valid disclosed reports** for this class (30 paid, 31% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
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

## Tools mentioned

| Item | Count |
|---|---:|
| curl | 19 |
| browser | 14 |
| source-code-review | 14 |
| burp | 12 |
| burp-intruder | 10 |
| devtools | 9 |
| javascript-debugging | 8 |
| python | 7 |
| burp-collaborator | 5 |
| collaborator/oast | 5 |
| burp-repeater | 4 |
| git | 3 |

## Bypass primitives

| Item | Count |
|---|---:|
| chunked | 163 |
| transfer-encoding | 151 |
| desync | 57 |
| content-type | 42 |
| bypass | 31 |
| crlf | 24 |
| host header | 15 |
| %0d%0a | 14 |
| bypassing | 11 |
| header injection | 8 |
| transfer encoding | 3 |
| bypassed | 3 |
| trailing space | 2 |
| bypasses | 2 |
| http method | 1 |
| open redirect | 1 |
| html-encoding | 1 |
| html encoding | 1 |
| empty value | 1 |
| backslash | 1 |
| normalizing | 1 |

## Impact language

| Item | Count |
|---|---:|
| localhost | 64 |
| token | 52 |
| credential | 19 |
| admin | 19 |
| password | 9 |
| sensitive data | 7 |
| unauthorized | 6 |
| payment | 3 |
| privilege escalation | 3 |
| exfiltration | 3 |
| pii | 2 |
| exfiltrated | 2 |
| account takeover | 1 |
| rce | 1 |
| internal service | 1 |
| arbitrary command | 1 |

## Parameters observed

| Item | Count |
|---|---:|
| result | 11 |
| target | 6 |
| daemon | 6 |
| path | 3 |
| session | 3 |
| capture_output | 3 |
| body | 3 |
| args | 3 |
| domain | 2 |
| max-age | 2 |
| injected | 2 |
| qop | 2 |
| port | 2 |
| payload | 2 |
| nextnonce | 2 |
| jar | 2 |
| suffix | 2 |
| ci_session | 2 |
| text | 2 |
| size | 2 |
| buf | 2 |
| verify_token | 1 |
| expires | 1 |
| gerbenjavado | 1 |
| mode | 1 |
| charset | 1 |
| header-field | 1 |
| field-name | 1 |
| aerg | 1 |
| ubvhq | 1 |

## Recurring approach patterns

- **2×** in this poc i was able to massive redirect users to a domain under my control but other scenarios are also possible like the ones described here
  - e.g. In this PoC I was able to massive redirect users to a domain under my control but other scenarios are also possible like the ones described here
- **1×** so i found a http response splitting issue in your website
  - e.g. So i found a http response splitting issue in your website.
- **1×** poc firefox after sending the request through firefox this query is saved in cache and using a small trick can be made to work it in another browser
  - e.g. **PoC (FireFox)** After sending the request through FireFox this query is saved in cache and using a small trick can be made to work it in another browser.
- **1×** these defects represent a security concern when httpd is participating in any chain of proxies or interacting with back end application servers either through mod proxy or using conventional cgi mechanisms
  - e.g. These defects represent a security concern when httpd is participating in any chain of proxies or interacting with back-end application servers, either through mod_proxy or using conventional CGI mechanisms.
- **1×** after adding to cart step there is no checking step
  - e.g. After adding to cart step there is no checking step.
- **1×** in starting from these past studies i studied apache nginx varnish source code i discovered that a lot of smuggling problems were still present found new ones based on overflows for the size attributes previous works were mostly based on doubling length information and expanded my works on golang nodejs pound haproxy jetty tomcat apache traffic server
  - e.g. In 2015, Starting from these past studies, I studied **Apache**, **Nginx**, **Varnish** source code, I discovered that a lot of smuggling problems were still present, found new ones based on overflows for the size attributes (previous works were mostly based on doubling length information) and expan
- **1×** if you ask my opinion this is one of the most problematic issue i found on these years
  - e.g. If you ask my opinion this is one of the most problematic issue I found on these 5 years.
- **1×** cve httpd apache http request parsing whitespace defects problems with cr ff vtab and others strange characeters in parsing http messages especially the space before colon problem
  - e.g. * **CVE-2016-8743** : httpd: Apache HTTP Request Parsing Whitespace Defects : problems with CR, FF, VTAB and others strange characeters in parsing HTTP messages especially the space before colon problem.
- **1×** during testing there was one such case of this happening and the burp collaborator manages to posion someone from los angeles california f622459 f622460 in order to prevent affecting more innocent users i stopped further testing after coming with the above proof of concept which should be sufficent to proof the existence of the vulnerability
  - e.g. During testing, there was one such case of this happening and the Burp Collaborator manages to posion someone from Los Angeles, California: {F622459} {F622460} In order to prevent affecting more innocent users, I stopped further testing after coming with the above proof of concept which should be su
- **1×** in addition i noticed there was a wordpress login page but seems like it requires a specially configured browser to access the sso
  - e.g. In addition, I noticed there was a Wordpress login page but seems like it requires a specially-configured browser to access the SSO.
- **1×** my name is evan and i m a first time bug hunter to your platform because you guys were running a month long bounty promotion i decided to take a little of my time and gently perform recon on your platform
  - e.g. My name is Evan and I'm a first time bug hunter to your platform :) Because you guys were running a month long bounty promotion I decided to take a little of my time and gently perform recon on your platform.
- **1×** in my research i stumbled across a finding that i consider extremely critical not only for slack but for all customers and organizations which share their privatedata channels conversations on slack
  - e.g. In my research I stumbled across a finding that I consider extremely critical not only for Slack but for all customers and organizations which share their privatedata/channels/conversations on Slack.
- **1×** i was running smuggler u running my array of exhaustive tests when i stumbled upon a failure with test space1 see below f633736 the space1 tests checks for http desync with the following payload f633737 this testcase failed on testing a clte and not a tecl
  - e.g. I was running `smuggler -u running my array of exhaustive tests when I stumbled upon a failure with test: `space1` (see below) {F633736} The `space1` tests checks for HTTP desync with the following payload: {F633737} This testcase failed on testing a CLTE and not a TECL.
- **1×** i am really happy i found this for you guys so that it can be dealt with asap
  - e.g. I am really happy I found this for you guys so that it can be dealt with ASAP.
- **1×** the reporter identified a request smuggling issue on admin official line me te cl type the reporter clearly illustrated the impact without putting our users at risk or affecting the stability of our service
  - e.g. The reporter identified a request smuggling issue on admin-official.line.me [(TE.CL-type).]( The reporter clearly illustrated the impact without putting our users at risk or affecting the stability of our service.
- **1×** http smuggling dashboard fortmatic png we will notice i was able to cause the next valid request to error out returning valuable details
  - e.g. [http-smuggling-dashboard-fortmatic.png] we will notice i was able to cause the next valid request to error out returning valuable details.
- **1×** squid increases the upgrade to rfc7230 specification with implementation of the majority of message parsing updates
  - e.g. > > Squid-4 increases the upgrade to RFC7230 specification with > implementation of the majority of message parsing updates.
- **1×** i m pretty sure this issue will soon be discovered by other bounty hunters
  - e.g. I'm pretty sure this issue will soon be discovered by other bounty hunters.
- **1×** when evaluating your platform i ve found one asset that falls victim to http smuggling attacks that result in pii information leakage session takeover victim request hijacking forging and forced victim redirection to attacker endpoint
  - e.g. When evaluating your platform I've found one asset that falls victim to HTTP Smuggling Attacks that result in: PII/Information Leakage, Session Takeover, Victim Request Hijacking/Forging and Forced Victim Redirection to Attacker Endpoint.
- **1×** summary http request smuggling vulnerabilities arise when websites route http requests through webservers with inconsistent http parsing
  - e.g. ## Summary: HTTP request smuggling vulnerabilities arise when websites route HTTP requests through webservers with inconsistent HTTP parsing.
- **1×** description by sending an ambiguous request on the rails application on launchpad 37signals com an attacker can desynchronise frontend and backend servers leaving the socket to the backend server poisoned with a harmful response
  - e.g. ## Description By sending an ambiguous request on the rails application on `launchpad.37signals.com`, an attacker can desynchronise frontend and backend servers, leaving the socket to the backend server poisoned with a harmful response.
- **1×** the desync occurs when sending a request with a content length header and a valid transfer encoding header followed by an invalid transfer encoding header
  - e.g. The desync occurs when sending a request with a `Content-Length` header and a valid `Transfer-Encoding` header followed by an invalid `Transfer-Encoding` header.
- **1×** summary add summary of the vulnerability apparently node js converts cr in http request headers to hyphen before parsing
  - e.g. **Summary:** [add summary of the vulnerability] Apparently, node.js converts CR in HTTP request headers to hyphen before parsing.
- **1×** f1124380 doing the redirect mentioned above using my own pqp mx domain i was able to receive some connections
  - e.g. {F1124380} Doing the redirect mentioned above using my own pqp.mx domain I was able to receive some connections.

## Case studies (full excerpts)

### 510152 — Bypass for #488147 enables stored XSS on https://paypal.com/signin again
PayPal · $20000 · high · https://hackerone.com/reports/510152

Due to a configuration in frontend, caching servers, it was possible for a researcher to use request smuggling to convert a page request into a cached redirect. If the cached redirect were accessed by a legitimate user, an attacker's content would be rendered instead of the requested page. While this would not impact any back-end data, this could interfere with the integrity of certain pages, including potential interference with the sign-in page. PayPal worked with the researcher and our technical teams to remediate the issue and confirm there was no evidence of real-world attacks. I've posted a full writeup over at

### 488147 — Stored XSS on https://paypal.com/signin via cache poisoning
PayPal · $18900 · high · https://hackerone.com/reports/488147

Due to a configuration in frontend, caching servers, it was possible for a researcher to use request smuggling to convert a page request into a cached redirect. If the cached redirect were accessed by a legitimate user, an attacker's content would be rendered instead of the requested page. While this would not impact any back-end data, this could interfere with the integrity of certain pages, including potential interference with the sign-in page. PayPal worked with the researcher and our technical teams to remediate the issue and confirm there was no evidence of real-world attacks. I've posted a full writeup over at

### 1478633 — HTTP Request Smuggling in Transform Rules using hexadecimal escape sequences in the concat() function
Cloudflare Public Bug Bounty · $6000 · critical · https://hackerone.com/reports/1478633

The Edge Rules engine used by Cloudflare Transform Rules features string modifying functions like lower() and concat(), which accepted hexadecimal-encoded characters such as ”\x0a\x0d“. This allowed for manipulation of request headers (e.g. injecting an additional header) and, as a consequence, made HTTP smuggling attack (TE.CL) possible. This vulnerability enabled an attacker to bypass security products such as Cloudflare Access and view the content of internal origin servers. This bug in hexadecimal parsing was fixed by the relevant engineering team. We rewarded this finding as critical as well as a bonus for a high quality, detailed report. Internal investigation confirmed that no other CF customer was affected by this attack. As a recommendation, we advise Cloudflare Access customers to always verify the Authorization JWT token before processing requests from the Cloudflare edge. Cloudflare's Ruleset Engine allows the use of hexadecimal escape sequences in string manipulation functions such as `concat()`. Due to a lack of output sanitation, this enabled an attacker to inject newlines into the header value. By creating a dynamic header rewrite rule with the value `concat("-", "\x0d\x0aTransfer-Encoding: chunked")`, it was possible to change the transfer encoding of the request. When combined with a POST body such as `0\r\n\r\nGET / HTTP/1.1\r\nHost: internal.example.com\r\n\

### 2280391 — Possibility of Request smuggling attack
Internet Bug Bounty · $4660 · high · https://hackerone.com/reports/2280391

Request smuggling was possible by throwing an IOException with the upper size limit of the trailer header. Confirmed with tomcat version 9.0.82. * example ~~~~~~~~~~~~~~~~~~ POST /examples/test.jsp HTTP/1.1 Host: www.example.co.jp Content-Type: application/x-www-form-urlencoded Transfer-Encoding: chunked Connection: KeepAlive 5 foo=b 2 ar 0 testtrailer: aaaaa...(large size) a: GET /examples/?this_is_attack HTTP/1.1 Host: attack ~~~~~~~~~~~~~~~~~~ * Reproduce with the following steps: The result of curl is two HTTP responses("/examples/test.jsp" and "/examples/?this_is_attack"). Two requests are recorded in the Tomcat access log. ## Impact A trailer header that exceeded the header size limit could cause Tomcat to treat a single request as multiple requests leading to the possibility of request smuggling when behind a reverse proxy.

### 2327341 — CVE-2024-21733 Apache Tomcat HTTP Request Smuggling (Client- Side Desync) (CWE: 444)
Internet Bug Bounty · $4660 · high · https://hackerone.com/reports/2327341

Apache Tomcat from 8.5.7 through 8.5.63, from 9.0.0-M11 through 9.0.43 are vulnerable to client-side de-sync attacks. Client-side de-sync (CSD) vulnerabilities occur when a web server fails to correctly process the Content-Length of POST requests. By exploiting this behavior, an attacker can force a victim's browser to de-synchronize its connection with the website, causing sensitive data to be smuggled from the server and/or client connections. Users are recommended to upgrade to version 8.5.64 onwards or 9.0.44 onwards, which contain a fix for the issue. PoC: ~~~~~~~~~~~~~~~~~~ POST / HTTP/1.1 Host: hostname Sec-Ch-Ua: "Chromium";v="119", "Not?A_Brand";v="24" Sec-Ch-Ua-Mobile: ?0 Sec-Ch-Ua-Platform: "Linux" Upgrade-Insecure-Requests: 1 User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.159 Safari/537.36 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7 Sec-Fetch-Site: none Sec-Fetch-Mode: navigate Sec-Fetch-User: ?1 Sec-Fetch-Dest: document Accept-Encoding: gzip, deflate, br Accept-Language: en-US,en;q=0.9 Priority: u=0, i Connection: keep-alive Content-Length: 6 Content-Type: application/x-www-form-urlencoded X ~~~~~~~~~~~~~~~~~~ In some cases, this can leak sensitive data such as clear-text credentials (see attached screen

### 737140 — Mass account takeovers using HTTP Request Smuggling on https://slackb.com/ to steal session cookies
Slack · no bounty (valid finding) · critical · https://hackerone.com/reports/737140

Hi Slack Security Team! My name is Evan and I'm a first time bug hunter to your platform :) Because you guys were running a month long bounty promotion I decided to take a little of my time and gently perform recon on your platform. Specifically the area of interest I focus in is HTTP Request Smuggling. I developed tooling to actively target some advanced HTTP Smuggling exploits and ran it on your in-scope assets. In my research I stumbled across a finding that I consider extremely critical not only for Slack but for all customers and organizations which share their privatedata/channels/conversations on Slack. The bug chain is as follows: 1) HTTP Request Smuggling CTLE to Arbitrary Request Hijacking (Poisoned Socket) on `slackb.com` 2) Request Hijack forces victim HTTP requests to instead use `GET HTTP/1.1` on `slackb.com` 3) A request of `GET HTTP/1.1` on the backend server socket results in a 301 redirect to ` with slack cookies (most importantly the `d` cookie) 4) Me with my Burp Collaborator steals victims cookies by using a collaborator server as the defined <URL> in the attack 5) Me (if I were evil) collects massive amounts of `d` session cookies and steals any/all possble Slack user/organization data from victim sessions So let's start from the beginning. I was running `smuggler -u running my array of exhaustive tests when I stumbled upon a failure with test: `space1` (s

### 740037 — Request smuggling on admin-official.line.me could lead to account takeover
LY Corporation · no bounty (valid finding) · high · https://hackerone.com/reports/740037

The reporter identified a request smuggling issue on admin-official.line.me [(TE.CL-type).]( The reporter clearly illustrated the impact without putting our users at risk or affecting the stability of our service. For this we would like to thank @shaolin_tw! This issue was the result of how our load balancers were forwarding requests to the backend services. It had widespread influence and the report allowed us to resolve the issue internally, as well as make the vendor of the load balancers aware of this possible issue when using their product. The contents of the report allowed us to identify and prevent similar issues elsewhere in our infrastructure

## Field playbook (unedited)

### quick

- Identify proxy/CDN + origin stack and HTTP version handling.
- Test CL.TE, TE.CL, TE.TE obfuscation, and HTTP/2 downgrade desync.
- Use timing-based and differential probes before exploitation.
- Check connection reuse, pipelining, and hop-by-hop headers.

### payloads

- CL.TE -> `Content-Length: 13` + `Transfer-Encoding: chunked`
- TE.CL -> chunked body with a smaller Content-Length
- TE.TE -> `Transfer-Encoding: xchunked`, `Transfer-Encoding : chunked`
- HTTP/2 -> `Transfer-Encoding: chunked` injected as a header

### bypass

- Obfuscate TE with case, spaces, tabs, and duplicate headers.
- Exploit front-end/back-end parser differences in header folding.
- Use cache deception/poisoning to prove impact.

### surface

- any endpoint behind CDN/proxy
- login
- API gateway
- static assets

### tools

- Burp HTTP Request Smuggler
- smuggler.py
- h2cSmuggler

### chain

- Smuggling -> cache poisoning -> XSS.
- Smuggling -> auth bypass.
- Smuggling -> request capture.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class request-smuggling
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class request-smuggling --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
