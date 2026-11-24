---
name: bbhunt-oauth-oidc
description: "Use for redirect_uri manipulation, state/PKCE issues, code/token leakage, scope escalation, JWT/OIDC problems, and account-linking abuse. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# OAuth and OIDC Flaws — unified methodology

> **Unified skill.** Built from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus-backed method (this class)

1. Reconstruct the flow end to end: authorize, consent, code, token exchange, API call, and logout.
2. Read discovery metadata and JWKS where exposed; note supported grants and redirect registrations.
3. Enumerate redirect_uri validation behaviour across the full spectrum (arbitrary host, subdomain, suffix, path, parameter addition, regex quirks).
4. Test state and PKCE: absence, predictability, replay, and binding to the user session.
5. Test code/token leakage and replay: Referer, browser history, error responses, and token exchange without the original redirect_uri.
6. Probe scope escalation and account linking — dynamic registration and weak subject binding are high-value paths.
7. Prove code/token capture or an identity-state change for a victim account.

### Signals

- client_id, redirect_uri, response_type, state, code, nonce parameters
- Authorization code or token in URLs, Referers, logs, or responses
- Dynamic client registration or metadata endpoints

### Kill criteria

- redirect_uri strictly allowlisted and no redirect chain can escape it.
- State/PKCE correctly bound and single-use; token exchange validates all parameters.
- No victim-actionable consequence — self-only configuration issue.

### Escalation chains

- Open redirect -> redirect_uri bypass -> auth code -> token -> ATO.
- Weak state -> login CSRF -> account linking -> ATO.
- Dynamic registration SSRF -> internal metadata -> key material.

### Veteran tip

The operator's field notes include the full OAuth step map — follow the parameters, not the UI.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Test redirect_uri: suffix, path traversal, open redirect, localhost, custom schemes.
- Test state for CSRF and missing binding to the session.
- Try code reuse, code swapping between clients, and PKCE downgrade.
- Check account linking for takeover via unverified email or provider mixups.

### Deeper checklist

- Test redirect_uri validation: suffix, path traversal, open redirect, localhost, custom schemes.
- Test `state` for CSRF and missing binding to the user session.
- Try code reuse, code swapping between clients, and PKCE downgrade.
- Check account linking for takeover via unverified email or provider mixups.
- Test token audience/issuer validation in implicit and hybrid flows.
- Look for token leakage via Referer, logs, and postMessage.
- Show account takeover or cross-account access.

### Step-by-Step Hunting Methodology

1. **Enumerate all OAuth entry points**
   - Spider the app for `/oauth`, `/connect`, `/auth`, `/login` paths
   - Check `.well-known/openid-configuration` and `.well-known/oauth-authorization-server`
   - Decompile mobile APKs: `apktool d app.apk` and grep for `redirect_uri`, `intent://`, deep link schemes

2. **Map the full OAuth flow**
   - Capture the authorization request: note `client_id`, `redirect_uri`, `state`, `nonce`, `response_type`
   - Capture the callback: note where tokens/codes land, what validates state/nonce

3. **Test `redirect_uri` validation (highest yield)**
   - Try exact host bypass: `redirect_uri=https://legit.com.evil.com`
   - Try path traversal: `redirect_uri=https://legit.com/callback/../../../evil`
   - Try open redirects on the legitimate domain first, then chain into OAuth
   - Try parameter pollution: `redirect_uri=https://legit.com&redirect_uri=https://evil.com`
   - Try encoded characters: `%2F`, `%40`, `%23` to confuse parsers

4. **Test `state` parameter (CSRF)**
   - Remove `state` entirely — does the flow complete?
   - Reuse a fixed `state` value across sessions
   - Check if `state` is validated server-side or only client-side

5. **Test `nonce` parameter (replay/bypass)**
   - Capture a nonce from one flow, attempt to replay it in another
   - Check if nonce is validated after token exchange
   - Test if nonce can be extracted via referrer leak (step 9)

6. **Test authentication step completeness**
   - For multi-step auth (e.g., email verification + OAuth): can you skip to `/oauth/token` direc

### A. Discovery checklist — concrete places, params, headers, flows to look

- Pull the server metadata first: `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server` (PortSwigger: even in black-box tests this reveals `registration_endpoint`, `request_uri_parameter_supported`, `require_request_uri_registration`, grant types, `token_endpoint_auth_methods_supported`). Also try `/.well-known/webfinger`.
- Enumerate hidden endpoints never referenced by client HTML: `/authorize`, `/oauth/confirm_access`, `/connect/register`, `/register`, `/token`, `/userinfo`, `/revoke`, `/introspect`, `/api/clients/{id}/logo`. Dynamic Client Registration is a standardized request format — test it even when only reachable from an admin panel.
- At `/authorize`, inventory every parameter and its validation: `client_id`, `redirect_uri`, `response_type` (`code`, `token`, `id_token`, `code id_token`), `scope`, `state`, `nonce`, `code_challenge`/`code_challenge_method`, `request_uri`, `prompt` (`none`, `consent`), `response_mode` (`query`, `fragment`, `form_post`, `web_message`), and issuer hints.
- Test both success and failure callbacks and capture full URLs and rendered HTML. High-value reflected params on first-party callback pages: `error`, `error_description`, `message`, `description`, `state` (Base64-decode `state` for PII/workflow state).
- For multi-provider clients, compare cookies, callback paths, `state`, `nonce`, PKCE data and transaction IDs between flows A and B; reset with `nonce` in OIDC and `iss` in authorization responses (RFC 9207).
- Grep JS bundles/sou

### Signals and surfaces

### Signal

- Reports: **177** · paid: **45**
- Median bounty **$900** · p90 **$4,000** · max **$10,500** · total **$78,222**
- Median upvotes **21**

### Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| GitLab | 4 | $12,580 | 701 |
| Superhuman (formerly Grammarly) | 1 | $10,500 | 260 |
| GitHub Security Lab | 3 | $8,500 | 12 |
| Snapchat | 1 | $7,500 | 244 |
| X / xAI | 10 | $6,300 | 875 |
| Uber | 5 | $6,000 | 621 |
| Mapbox | 2 | $4,000 | 152 |
| Nextcloud | 18 | $3,850 | 550 |

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`redirect_uri` `state` `nonce` `code` `client_id` `scope` `response_type`

### Crown Jewel Targets

OAuth vulnerabilities are among the highest-value bug classes in web security because they directly enable **account takeover, session theft, and authentication bypass** — the trifecta that programs pay most for.

**Highest-value targets:**
- **Consumer identity providers** (Google, Facebook, PayPal, Apple SSO integrations) — any compromise cascades across all relying parties
- **Mobile apps with custom deep link OAuth handlers** — Android/iOS intent handling is notoriously loose
- **Multi-tenant SaaS platforms** (GitLab, Reddit-scale apps) where one OAuth flaw hits millions of accounts
- **Gaming/entertainment platforms** with federated login (Rockstar, Oculus) — often security-immature teams
- **Enterprise SSO connectors** — critical infrastructure, high severity payouts

**Asset types that pay most:**
- OAuth authorization endpoints (`/oauth/authorize`, `/connect/authorize`)
- Token exchange endpoints (`/oauth/token`)
- Mobile deep link handlers (`push_notification_webview`, custom scheme URIs)
- Social login callback handlers (`/auth/callback`, `/oauth/callback`)

**Typical payouts:** $500–$20,000+ depending on program; account takeover findings often hit max bounty.

---

### Response Headers That Signal OAuth

```
Location: https://accounts.example.com/oauth/...
Set-Cookie: oauth_state=
WWW-Authenticate: Bearer
Content-Type: application/json (with access_token in body)
```

### Tech Stack Signals

- Android apps with `intent-filter` in `AndroidManifest.xml` handling `http://` or custom scheme URIs
- Apps using Doorkeeper, OmniAuth, Devise (Ruby), Passport.js (Node), Spring Security OAuth
- Social login buttons (Google, Facebook, Apple) = OAuth surface guaranteed
- `.well-known/openid-configuration` present = full OIDC surface available

---

### Techniques, payloads and bypasses

### Payloads & probes

- `redirect_uri=https://target.com.evil.com` `redirect_uri=https://target.com%2f@evil.com`
- `redirect_uri=https://target.com/callback/../../evil`
- `response_type=token` `scope=openid profile email`
- `state=` empty/reused; `nonce=` missing

### Bypass tricks

- Open redirect on an allowlisted callback domain.
- Exploit parser differences in redirect_uri validation.
- Reuse authorization codes across clients or after use.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Email Confirmation Bypass in myshop.myshopify.com that Leads to Full Privilege Escalation to Any Shop Owner by Taking Advantage of the Shopify SSO** — `#791775` · Shopify · $0 · ▲1922
  > If you check https://h31ngalog.myshopify.com/ and see the email address of the owner, it is ngalog@hackerone.com, which I obviously would never be able to validate otherwise
- **Shopify Stocky App OAuth Misconfiguration** — `#740989` · Shopify · $0 · ▲527
  > This resulted in a full authentication bypass.
- **Chained Bugs to Leak Victim's Uber's FB Oauth Token** — `#202781` · Uber · $0 · ▲427
  > Next, @ngalog found that the `https://login.uber.com/logout` endpoint would redirect based on the Referer header, making it possible to chain together another redirect.
- **[Urgent] Invalidating OAuth2 Bearer token makes TweetDeck unavailable** — `#210779` · X / xAI · $0 · ▲323
  > According to the documentation, with a valid consumer key and consumer secret pair, one can generate or invalidate existing bearer token: https://dev.twitter.com/oauth/reference/post/oauth2/invalidate/token
- **Able to Takeover Merchants Accounts Even They Have Already Setup SSO, After Bypassing the Email Confirmation** — `#796956` · Shopify · $0 · ▲310
  > Here's the magic step, note that the url path is `/login` now at stage3, change the path to `/accounts merge/new-password` while keeping the query part the same
- **Insufficient OAuth callback validation which leads 

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 5× | `Curl_auth_allowed_to_host()` |
| 4× | `wp_redirect()` |
| 4× | `Curl_auth_allowed_to_origin()` |
| 4× | `data->state.creds` |
| 3× | `$count = 1` |
| 3× | `conn->bits.netrc` |
| 3× | `support+1@trint.com` |
| 3× | `@rpath` |
| 3× | `url_set_data_creds_netrc()` |
| 2× | `ngalog+1@wearehackerone.com` |
| 2× | `https://snappublisher.snapchat.com/sso_continue?ticket=<stolen token>` |
| 2× | `GET → 404 {"status":404,"error":"Not Found"}` |
| 2× | `https://github.com/login?client_id=5f45cc999f7812d0b6d2&return_to=%2Flogin%2Foauth%2Fauthorize%3Fclient_id%3D5f45cc999f7812d0b6d2%26redirect` |
| 2× | `str_replace( OPENVERSE_SUBPATH, '', $path, $count )` |
| 2× | `str_replace()` |
| 2× | `wp_safe_redirect()` |
| 2× | `get_target_url()` |
| 2× | `wp_sanitize_redirect()` |
| 2× | `wp_validate_redirect()` |
| 2× | `GET / HTTP/1.1 / Host: hostname.tld:9999 / User-Agent: curl/7.83.0-DEV / Accept: */* / Authorization: secrettoken / Cookie: secretcookie` |

### Email Confirmation Bypass in myshop.myshopify.com that Leads to Full Privilege Escalation to Any Shop Owner by Taking Advantage of the Shopify SSO

`#791775` · Shopify · $0 · critical · 2020-04-01 · ▲1922
> It's possible to take over any store account through bypassing the email confirmation step in .myshopify.com. I found a way to confirm arbitrary emails, and after confirming arbitrary email in .myshopify.com, user is able to integrate with other Shopify store that shares the same email address by setting a master password for all of the stores(if the owner hasn't integrated before), effectively taking over every Shopify stores by knowing just the owner's…

### Common Root Causes

1. **Weak `redirect_uri` validation** — developers whitelist by prefix (`startsWith`) rather than exact match, or whitelist an entire domain instead of specific paths. A sub-path open redirect on the same domain then becomes a full token theft primitive.

2. **Missing or unvalidated `state` parameter** — developers implement OAuth by following basic tutorials that omit CSRF protection, or validate state client-side only in JavaScript (easily bypassed).

3. **Nonce not validated post-exchange** — nonce is generated and sent in the request but never verified against the ID token after the code exchange, making replay attacks possible.

4. **Authentication step ordering not enforced server-side** — teams implement multi-step auth (signup → email verify → OAuth grant) but don't enforce the sequence server-side. The token endpoint doesn't check completion of prerequisite steps.

5. **Token/code in URL with outbound requests on callback page** — developers land users on a callback page with tokens in the query string, then that page fires analytics, social share, or CDN requests that leak the full URL via `Referer` header.

6. **Mobile deep link handlers trust all input URLs** — Android/iOS developers build webview wrappers for push notification flows without validating that the loaded URL belongs to their own domain.

7. **Misconfigured OAuth application registration** — developers register wildcard redirect URIs (`https://*.example.com/*`) or don't restrict them at all during development and forget to lock down for production.

8. **Client secrets embedd

_...and 5 more sections in `references/unified-method.md`._

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

### Gate 0 Validation

Before writing the report, answer all three:

**1. What can the attacker DO right now?**
Be specific: "I can send victim a crafted URL → victim clicks → their OAuth code redirects to my server → I exchange code for access token → I am now logged in as victim." If you can't complete this full chain, it may be informational only.

**2. What does the victim LOSE?**
Minimum bar: victim loses authenticated session (account access). Higher bars: victim loses linked accounts, payment methods, private data. If the attacker only learns the victim's identity without gaining access, severity drops significantly.

**3. Can it be reproduced in 10 minutes from scratch?**
Open a fresh browser/device with no prior state. If you can walk from "unauthenticated" to "authenticated as victim" in 10 minutes using only your written steps, the bug is real and reportable. If it requires lucky timing, specific victim behavior beyond "click a link," or network position, document those dependencies explicitly.

---

### C. Validation / proof bar — how to confirm and avoid false positives

- A redirect alone is not ATO. Capture the victim's `code`/token, complete the server-side exchange, and demonstrate access to a victim-only resource or a state change on the victim account. State-only leakage is Low.
- Bind the transaction to issuer/client/redirect/state/nonce/PKCE and validate the authorization-response `iss` against the value stored at flow start; do not claim mix-up from a single mismatched URL alone.
- On refresh rotation, respect grace windows; claim missing reuse detection only after the active token family survives an explicit replay outside that window. DPoP: a duplicate proof within the allowed `jti` window is not itself a standards violation.
- Confirm blind SSRF (logo/jwks/sector_identifier/request_uri) with an out-of-band hit and note the trigger step — these are often second-order, fetched only at consent/token exchange.
- Do not report a leaked `client_secret` as ATO unless you also show a stolen code or a token minted for the victim; public clients cannot keep secrets, so check whether PKCE is actually enforced.
- For `error_description` reflection, show executed JS (browser-specific events like Safari `onpagereveal`) or a coherent phishing page, not just HTML presence. Redact tokens/codes in evidence.

- For the code-exchange step, use the client's real `/token` call (with its `client_secret` or PKCE verifier) and show a victim-API response, not merely that a code landed on your domain.
- When testing `error_description` reflection, prove either script execution or a 

### Defender: Host validation on mobile deep links

**Bypass:** Try URL encoding (`https%3A//evil.com`), double encoding, Unicode normalization, or null bytes to confuse the validator while the underlying webview still navigates correctly.

### Defender: Nonce validation

**Bypass:** Check if nonce is validated client-side in JavaScript only. Intercept and modify the ID token's nonce claim if the signature isn't verified (rare but seen in misconfigured implementations). Also test if nonce is validated on *initial* request but not on token refresh.

---

### Escalation and related chains

### Escalation chains

- OAuth redirect -> token theft -> ATO.
- Account linking -> ATO.

### Chained Bugs to Leak Victim's Uber's FB Oauth Token

`#202781` · Uber · $0 · high · 2019-01-25 · ▲427
> The Facebook OAuth application was misconfigured to allow any URL that followed the https://auth.uber.com/login? format to be provided as a redirect uri. By taking advantage of this, @ngalog was able to discover that the next url parameter could be added to the redirect uri allowing it to be chained further.

### Related Skills & Chains

- **`subdomain-takeover`** — The single highest-impact OAuth chain. Chain primitive: OAuth `redirect_uri` validator accepts any `*.target.com` subdomain + recon reveals `dev-staging.target.com` CNAMEs to a deprovisioned Heroku/S3/Azure app → claim the dangling subdomain → host an OAuth callback receiver there → craft `/oauth/authorize?redirect_uri=https://dev-staging.target.com/cb` → victim clicks → auth code lands on attacker-claimed subdomain → exchange for token → ATO. The redirect_uri whitelist passed because the subdomain is "legitimately" under target.com control.
- **`account-takeover`** — OAuth state-CSRF is the textbook ATO-via-account-linking primitive. Chain primitive: `state` parameter absent or not session-bound + victim is already logged into target.com + attacker initiates OAuth flow from their own account, captures `code` before exchange + crafts callback URL with attacker's code → forces victim to visit → victim's target.com session is now linked to attacker's Google/Facebook identity → attacker logs in via Google → owns victim's account.
- **`llm-ai`** — Modern OAuth flows for AI agents (ChatGPT plugins, Claude MCP servers, agentic copilots) reuse OAuth 2.1 + PKCE. Chain primitive: agentic AI accepts `redirect_uri` from indirect prompt-injection in a document → model crafts OAuth authorize URL with attacker callback → user clicks "approve" thinking it's the agent's own flow → tokens exfiltrated via tool-use to attacker domain.
- **`saml`** — When OAuth is layered atop a SAML IdP, the IdP-level XSW becomes the OAuth ATO path. Ch

### Related Skills & Chains

- **`hunt-subdomain`** — The single highest-impact OAuth chain. Chain primitive: OAuth `redirect_uri` validator accepts any `*.target.com` subdomain + recon reveals `dev-staging.target.com` CNAMEs to a deprovisioned Heroku/S3/Azure app → claim the dangling subdomain → host an OAuth callback receiver there → craft `/oauth/authorize?redirect_uri=https://dev-staging.target.com/cb` → victim clicks → auth code lands on attacker-claimed subdomain → exchange for token → ATO. The redirect_uri whitelist passed because the subdomain is "legitimately" under target.com control.
- **`hunt-ato`** — OAuth state-CSRF is the textbook ATO-via-account-linking primitive. Chain primitive: `state` parameter absent or not session-bound + victim is already logged into target.com + attacker initiates OAuth flow from their own account, captures `code` before exchange + crafts callback URL with attacker's code → forces victim to visit → victim's target.com session is now linked to attacker's Google/Facebook identity → attacker logs in via Google → owns victim's account.
- **`hunt-llm-ai`** — Modern OAuth flows for AI agents (ChatGPT plugins, Claude MCP servers, agentic copilots) reuse OAuth 2.1 + PKCE. Chain primitive: agentic AI accepts `redirect_uri` from indirect prompt-injection in a document → model crafts OAuth authorize URL with attacker callback → user clicks "approve" thinking it's the agent's own flow → tokens exfiltrated via tool-use to attacker domain.
- **`hunt-saml`** — When OAuth is layered atop a SAML IdP, the IdP-level XSW becomes the OAuth ATO path. Chai

### Tools and wordlists

### Tools

`Burp` · `oauth-misconfig` · `jwt_tool`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_oauth-oidc.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_oauth-oidc.txt` | 78 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_oauth-oidc.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_oauth-oidc.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

### Nuclei

Focus on redirect_uri validation, state/nonce, code reuse, and account linking — scanner coverage is shallow.

```sh
nuclei -u https://target -tags oauth,oidc \
       -severity low,medium,high,critical -rl 40 -o nuclei_oauth-oidc.txt
nuclei -u https://target -t ~/nuclei-templates/http/technologies/oauth2-detect.yaml \
       -rl 40 -o nuclei_oauth-oidc_oauth2-detect.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Grep Patterns for Recon

```bash
# In APK/JS files
grep -r "redirect_uri\|client_secret\|oauth_token\|access_token\|push_notification" .
grep -r "intent://\|deeplink\|scheme://" .

# In Burp history
# Filter: URL contains "oauth" OR "token" OR "callback"
# Filter: Response contains "access_token" OR "code=" in Location header

# Check .well-known
curl https://target.com/.well-known/openid-configuration | python3 -m json.tool
```

## Source skills merged into this topic

- `h1skills` — `hackerone-oauth-oidc`
- `hunting` — `oauth-oidc`
- `cbh` — `hunt-oauth`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
