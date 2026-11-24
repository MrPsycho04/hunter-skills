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
