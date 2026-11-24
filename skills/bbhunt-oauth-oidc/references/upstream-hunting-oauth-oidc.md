# Upstream source: oauth-oidc (hunting)

Original path: `/tmp/h1res_MrPsycho04_Hunting-Agent/oauth-oidc/SKILL.md`

---

---
name: oauth-oidc
description: >-
  Hunting skill for oauth vulnerabilities. Built from 19 public bug bounty reports. Use when hunting oauth
  on any target. Combined with the HackerOne field guide (real disclosed-report data: where it pays, quick
  wins, payload banks). Hunt OAuth and OIDC flaws. Use when testing social login, SSO, account linking,
  redirect_uri validation, and token handling. Backed by 177 disclosed HackerOne reports.
---

# OAuth OIDC — Combined Field Guide

**Merged skill.** This fuses two complementary sources into one reference:

- **Part 1 — HackerOne field guide:** statistics from disclosed reports, "where it pays," quick wins, and curated payload banks.
- **Part 2 — Bug hunter methodology:** autonomous testing priority, canary discipline, crown-jewel targeting, OOB/validation gates, and reporting guidance.

**How to use:** Open with Part 2 for execution discipline (set your canary, know your success/failure gate). Use Part 1 to prioritize targets and pull payloads. Before reporting, run the validation gates in both parts.

---

<!-- ============ PART 1: HACKERONE FIELD GUIDE (data + payloads) ============ -->

# OAuth / OIDC / SSO — HackerOne field guide

Built from **177** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Signal

- Reports: **177** · paid: **45**
- Median bounty **$900** · p90 **$4,000** · max **$10,500** · total **$78,222**
- Median upvotes **21**

## Where it pays

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

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`redirect_uri` `state` `nonce` `code` `client_id` `scope` `response_type`

## Tools

`Burp` · `oauth-misconfig` · `jwt_tool`

## Escalation chains

- OAuth redirect -> token theft -> ATO.
- Account linking -> ATO.

## Related

- `auth-bypass` (989 reports)
- `open-redirect` (385 reports)
- `account-takeover` (262 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

## Crown Jewel Targets

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

## Attack Surface Signals

### URL Patterns to Hunt
```
/oauth/authorize
/oauth/token
/connect/authorize
/auth/callback
/oauth/callback
/login?redirect_uri=
/signin?next=
/auth?return_to=
/oauth/redirect
/push_notification_webview
```

### Response Headers That Signal OAuth
```
Location: https://accounts.example.com/oauth/...
Set-Cookie: oauth_state=
WWW-Authenticate: Bearer
Content-Type: application/json (with access_token in body)
```

### JavaScript Patterns (grep in JS bundles)
```javascript
redirect_uri
client_id
response_type=code
response_type=token
state=
nonce=
oauth_token
access_token
push_notification_webview
deeplink
intent://
```

### Tech Stack Signals
- Android apps with `intent-filter` in `AndroidManifest.xml` handling `http://` or custom scheme URIs
- Apps using Doorkeeper, OmniAuth, Devise (Ruby), Passport.js (Node), Spring Security OAuth
- Social login buttons (Google, Facebook, Apple) = OAuth surface guaranteed
- `.well-known/openid-configuration` present = full OIDC surface available

---

## Step-by-Step Hunting Methodology

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
   - For multi-step auth (e.g., email verification + OAuth): can you skip to `/oauth/token` directly?
   - Check if partial auth state (unverified email) is accepted by the token endpoint

7. **Hunt referrer leakage**
   - After OAuth callback with tokens in URL fragment or query, check if any on-page resources (images, scripts, iframes) receive the full `Referer` header
   - Look specifically at language switchers, analytics calls, social share buttons triggered post-auth

8. **Test mobile deep links**
   - For Android: craft malicious intent URIs that redirect the OAuth webview to attacker-controlled URLs
   - Check if deep link handlers validate the origin/host before loading
   - Test `push_notification_webview` patterns that accept arbitrary URLs

9. **Test misconfigured client credentials**
   - Check if `client_secret` appears in JS bundles or APK resources
   - Test if token endpoint accepts arbitrary `redirect_uri` values when combined with leaked `client_id`/`client_secret`

10. **Verify and document**
    - Confirm state is not validated → CSRF to account link
    - Confirm token lands on attacker domain → session theft
    - Confirm email verification skippable → auth bypass
    - Run Gate 0 check before reporting

---

## Common Root Causes

1. **Weak `redirect_uri` validation** — developers whitelist by prefix (`startsWith`) rather than exact match, or whitelist an entire domain instead of specific paths. A sub-path open redirect on the same domain then becomes a full token theft primitive.

2. **Missing or unvalidated `state` parameter** — developers implement OAuth by following basic tutorials that omit CSRF protection, or validate state client-side only in JavaScript (easily bypassed).

3. **Nonce not validated post-exchange** — nonce is generated and sent in the request but never verified against the ID token after the code exchange, making replay attacks possible.

4. **Authentication step ordering not enforced server-side** — teams implement multi-step auth (signup → email verify → OAuth grant) but don't enforce the sequence server-side. The token endpoint doesn't check completion of prerequisite steps.

5. **Token/code in URL with outbound requests on callback page** — developers land users on a callback page with tokens in the query string, then that page fires analytics, social share, or CDN requests that leak the full URL via `Referer` header.

6. **Mobile deep link handlers trust all input URLs** — Android/iOS developers build webview wrappers for push notification flows without validating that the loaded URL belongs to their own domain.

7. **Misconfigured OAuth application registration** — developers register wildcard redirect URIs (`https://*.example.com/*`) or don't restrict them at all during development and forget to lock down for production.

8. **Client secrets embedded in mobile apps** — treating confidential client credentials as public, enabling an attacker with the secret to perform token requests with arbitrary redirect URIs.

9. **OIDC `sub` claim ambiguity across identity providers** — apps accepting login from multiple IdPs (Google, Microsoft, Apple) may key accounts on `sub` alone without IdP isolation. If two IdPs emit the same `sub` for different users, one IdP's attacker hijacks accounts linked to the other IdP.

---

## Gate 0 Validation

Before writing the report, answer all three:

**1. What can the attacker DO right now?**
Be specific: "I can send victim a crafted URL → victim clicks → their OAuth code redirects to my server → I exchange code for access token → I am now logged in as victim." If you can't complete this full chain, it may be informational only.

**2. What does the victim LOSE?**
Minimum bar: victim loses authenticated session (account access). Higher bars: victim loses linked accounts, payment methods, private data. If the attacker only learns the victim's identity without gaining access, severity drops significantly.

**3. Can it be reproduced in 10 minutes from scratch?**
Open a fresh browser/device with no prior state. If you can walk from "unauthenticated" to "authenticated as victim" in 10 minutes using only your written steps, the bug is real and reportable. If it requires lucky timing, specific victim behavior beyond "click a link," or network position, document those dependencies explicitly.

---

## Real Impact Examples

### Scenario 1: Mobile Session Theft via Push Notification Deep Link (PayPal/Venmo pattern)
An attacker discovers that the Android app's push notification handler accepts an arbitrary `url` parameter in its deep link scheme without validating the host. The attacker crafts a malicious URL using the app's custom scheme pointing to their own server. When sent to a victim (via social engineering or a compromised push notification channel), the app opens a WebView navigating to the attacker's server — which then initiates an OAuth flow and captures the OAuth token as it's returned to the "callback" now under attacker control. Result: full account takeover on a payments platform affecting millions of users. Business impact: unauthorized fund transfers, exposure of linked payment methods and transaction history.

### Scenario 2: Email Verification Bypass via Direct Token Endpoint Access (GitLab pattern)
A developer creates an account with an unverified email address. Normally the platform blocks full access until email is verified. However, the `/oauth/token` endpoint performs no verification status check — it only validates credentials. The attacker calls `/oauth/token` directly with valid (unverified) credentials and receives a fully-scoped OAuth token. This token passes all downstream authorization checks. Result: complete authentication bypass, allowing unverified/disposable email accounts to gain full platform access, undermining the email verification security control entirely. At scale on a platform like GitLab, this affects CI/CD pipeline access, repository access, and API usage.

### Scenario 3: OAuth Token Theft via Referrer Header on Language Change (Rockstar Games pattern)
The OAuth callback page for Facebook login lands users at a URL containing the `access_token` in the query string. The page includes a language-switcher widget that makes a GET request to change locale preferences. This GET request includes the full page URL as a `Referer` header — containing the Facebook access token. An attacker who can read server logs (or who compromises the language-change endpoint, or who is a malicious advertiser with pixel access) harvests Facebook OAuth tokens from Referer logs. Result: the attacker can authenticate to the victim's Facebook account and any other service accepting that Facebook token, constituting a cross-platform account takeover. Business impact: GDPR/privacy violation, cross-service account compromise, potential regulatory liability.

---

## Disclosed Report Citations (Backfill +9 — 2020-2024)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill beyond the original 10 internal references. Each is a distinct OAuth subclass with a working PoC documented in the cited writeup.

11. **Semrush — IDN-homograph redirect_uri bypass** ([H1 #861940](https://hackerone.com/reports/861940))
    - Subclass: `redirect_uri` bypass via Unicode-confusable host (homograph)
    - Payload: `redirect_uri=https://oauth.šemrush.com/cb` (punycode `xn--emrush-9jb.com`) — passed Latin-only string check on validator
    - Root cause: server validates `redirect_uri` host as ASCII-string equality but does not normalize Unicode → confusables → punycode before compare
    - Disclosure: 2020, public bounty (amount not disclosed); discoverer Yassine Aboukir

12. **Bohemia Interactive — redirect_uri filter bypass (BiStudio)** ([H1 #405100](https://hackerone.com/reports/405100))
    - Subclass: `redirect_uri` validation bypass → OAuth token exfiltration
    - Payload: redirect_uri crafted to defeat the regex/prefix filter and land tokens on attacker host; reporter chained the bypass to a full token-leak PoC
    - Root cause: weak redirect_uri filter that accepted attacker-controlled host while still matching the intended pattern
    - Year: 2018-disclosed; remains a canonical example of regex-redirect_uri-bypass cited in subsequent reports

13. **pixiv — path-traversal in OAuth `redirect_uri`** ([H1 #1861974](https://hackerone.com/reports/1861974))
    - Subclass: path-traversal `redirect_uri` bypass → authorization-code leakage
    - Payload: `redirect_uri=https://legit.pixiv.host/legit/../../attacker/cb` — server normalized after validation
    - Root cause: validator inspected raw string; downstream HTTP/browser handled `../` traversal and emitted code to attacker path
    - Disclosure: 2023, **$2,000 bounty**, 244 upvotes — confirmed paid

14. **Slack — OAuth2 redirect_uri bypass (domain-suffix)** ([H1 #2575](https://hackerone.com/reports/2575))
    - Subclass: `redirect_uri` validation bypass via domain-suffix / subdomain confusion
    - Payload: redirect_uri using a domain that suffix-matched the registered host (e.g., `slack.com.attacker.com`) defeated the suffix-only check
    - Root cause: `endsWith()` / suffix-match instead of strict host equality
    - Disclosure: 2013 (foundational case still cited in modern OAuth training material) — Slack public bounty

15. **Booking.com (Facebook social-login)** ([Salt Labs writeup](https://salt.security/blog/traveling-with-oauth-account-takeover-on-booking-com))
    - Subclass: three-step chain — open-redirect on whitelisted domain + redirect_uri bypass + `response_type` swap → Facebook OAuth code/token theft → ATO
    - Payload: authorize URL with `redirect_uri=https://account.booking.com/<open-redirect>?next=https://attacker.tld/cb` and `response_type` toggled to leak tokens via fragment
    - Root cause: validator trusted any path under `account.booking.com`; open redirect on that host bounced the auth code to attacker
    - Disclosure: March 2023 — coordinated disclosure, no public bounty figure (~500M MAU exposure)

16. **Expo.io (`expo-auth-session`) — CVE-2023-28131** ([Salt Labs writeup](https://salt.security/blog/a-new-oauth-vulnerability-that-may-impact-hundreds-of-online-services))
    - Subclass: scope-creep / unvalidated `returnUrl` parameter → cross-app OAuth-code theft (impacts every consumer of expo-auth-session social login)
    - Payload: attacker passes `returnUrl=https://attacker.tld` to the OAuth proxy → Expo blindly forwards Facebook/Google/Apple/Twitter code to attacker
    - Root cause: framework-level OAuth proxy did not validate `returnUrl` host before forwarding the social-IdP callback
    - Disclosure: May 2023; CVSS 9.6; fixed Feb 2023 hotfix + deprecated by Feb 26 2023

17. **Microsoft Azure AD multi-tenant — "nOAuth"** ([Descope writeup](https://www.descope.com/blog/post/noauth))
    - Subclass: cross-IdP account-takeover via unverified, mutable `email` claim ("Pass-The-Token" equivalent)
    - Payload: attacker sets Azure AD admin profile `mail` attribute to victim's address → clicks "Log in with Microsoft" on relying party that keys users by email claim → instant ATO
    - Root cause: Microsoft `email` claim is mutable + unverified; RPs treated it as primary identifier
    - Disclosure: April 11 2023 reported, fixed June 20 2023 (mitigations + new `xms_edov` claim)

18. **Grammarly / Vidio / Bukalapak — "Pass-The-Token" social-login** ([Salt Labs writeup](https://salt.security/blog/oh-auth-abusing-oauth-to-take-over-millions-of-accounts))
    - Subclass: missing audience / `aud` validation on Facebook access_token → cross-client token replay → ATO
    - Payload: attacker obtains Facebook token issued for `attacker.app` → replays the token to Grammarly/Vidio/Bukalapak login API → server fetches FB user via `/me`, finds victim's email, issues victim session
    - Root cause: relying party calls Facebook `/me` with attacker-issued token but never validates the token's `app_id` belongs to the RP
    - Disclosure: October 2023 — coordinated, ~1B account exposure across the three sites

19. **Zoom — OAuth "dirty dancing" chained ATO** ([Harel Security writeup](https://nokline.github.io/bugbounty/2024/06/07/Zoom-ATO.html))
    - Subclass: `response_type=token` swap + lax `postMessage` origin check + cookie-tossing → authorization-code leak via web_message response mode → ATO + cam/mic hijack
    - Payload: attacker page opens Zoom OAuth with `response_type=code&response_mode=web_message`, intercepts the resulting `postMessage` because window listener accepts any `*.zoom.us` origin → exchanges code for session
    - Root cause: combination of weak postMessage origin check, missing CSRF binding on `state`, and `response_mode=web_message` returning code to a parent window without exact-origin enforcement
    - Disclosure: reported Oct 2023, fixed Jan 2024, **$15,000 bounty** (Sudi / BrunoZero / H4R3L)

20. **Detectify Labs — "Dirty Dancing" multi-vendor OAuth token leakage** ([Detectify writeup, F. Rosén](https://labs.detectify.com/writeups/account-hijacking-using-dirty-dancing-in-sign-in-oauth-flows/))
    - Subclass: response-type switching + invalid-state quirks + 3rd-party JS gadget chains → OAuth code/token leakage with NO XSS required
    - Payload: attacker forces `response_type=token` on an endpoint that only validated `code`; combines with promiscuous postMessage listeners and URL-storage gadgets on the callback page to siphon tokens via cross-origin reads
    - Root cause: OAuth server tolerates response_type downgrade/swap; callback page leaks `window.location` via permissive postMessage receivers
    - Disclosure: July 2022 — multi-vendor (Apple, Microsoft, Slack et al.); PortSwigger Top 10 Web Hacks 2022 #1

---

## Related Skills & Chains

- **`subdomain-takeover`** — The single highest-impact OAuth chain. Chain primitive: OAuth `redirect_uri` validator accepts any `*.target.com` subdomain + recon reveals `dev-staging.target.com` CNAMEs to a deprovisioned Heroku/S3/Azure app → claim the dangling subdomain → host an OAuth callback receiver there → craft `/oauth/authorize?redirect_uri=https://dev-staging.target.com/cb` → victim clicks → auth code lands on attacker-claimed subdomain → exchange for token → ATO. The redirect_uri whitelist passed because the subdomain is "legitimately" under target.com control.
- **`account-takeover`** — OAuth state-CSRF is the textbook ATO-via-account-linking primitive. Chain primitive: `state` parameter absent or not session-bound + victim is already logged into target.com + attacker initiates OAuth flow from their own account, captures `code` before exchange + crafts callback URL with attacker's code → forces victim to visit → victim's target.com session is now linked to attacker's Google/Facebook identity → attacker logs in via Google → owns victim's account.
- **`llm-ai`** — Modern OAuth flows for AI agents (ChatGPT plugins, Claude MCP servers, agentic copilots) reuse OAuth 2.1 + PKCE. Chain primitive: agentic AI accepts `redirect_uri` from indirect prompt-injection in a document → model crafts OAuth authorize URL with attacker callback → user clicks "approve" thinking it's the agent's own flow → tokens exfiltrated via tool-use to attacker domain.
- **`saml`** — When OAuth is layered atop a SAML IdP, the IdP-level XSW becomes the OAuth ATO path. Chain primitive: SAML SP that issues OAuth tokens after assertion-validation + XSW attack on the assertion alters `NameID` to admin user → SP issues OAuth token bearing admin identity → OAuth-scoped APIs grant admin access.
- **`security-arsenal`** — Pull the OAuth `redirect_uri` Bypass Table (host-confusion `legit.com@evil.com`, `legit.com.evil.com`, path-traversal, parameter pollution, encoded-slash `%2F`, fragment-injection `#legit.com`) and the open-redirect chain catalog when exact-match validation forces you to find an open-redirect on the whitelisted domain first.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an OAuth "open redirect" that doesn't actually leak a token (only the `state` param, or the callback page doesn't include credentials in URL). State-only leakage is Low; token/code leakage with successful exchange demonstration is Critical. The exchange-the-code step is non-negotiable.

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete places, params, headers, flows to look

- Pull the server metadata first: `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server` (PortSwigger: even in black-box tests this reveals `registration_endpoint`, `request_uri_parameter_supported`, `require_request_uri_registration`, grant types, `token_endpoint_auth_methods_supported`). Also try `/.well-known/webfinger`.
- Enumerate hidden endpoints never referenced by client HTML: `/authorize`, `/oauth/confirm_access`, `/connect/register`, `/register`, `/token`, `/userinfo`, `/revoke`, `/introspect`, `/api/clients/{id}/logo`. Dynamic Client Registration is a standardized request format — test it even when only reachable from an admin panel.
- At `/authorize`, inventory every parameter and its validation: `client_id`, `redirect_uri`, `response_type` (`code`, `token`, `id_token`, `code id_token`), `scope`, `state`, `nonce`, `code_challenge`/`code_challenge_method`, `request_uri`, `prompt` (`none`, `consent`), `response_mode` (`query`, `fragment`, `form_post`, `web_message`), and issuer hints.
- Test both success and failure callbacks and capture full URLs and rendered HTML. High-value reflected params on first-party callback pages: `error`, `error_description`, `message`, `description`, `state` (Base64-decode `state` for PII/workflow state).
- For multi-provider clients, compare cookies, callback paths, `state`, `nonce`, PKCE data and transaction IDs between flows A and B; reset with `nonce` in OIDC and `iss` in authorization responses (RFC 9207).
- Grep JS bundles/source maps/mobile APKs for `client_secret`, `client_id`, hard-coded OAuth endpoints, and `redirect_url` reflection sinks. Inspect `@ModelAttribute`-style parameters that can carry `redirectUri` during internal forwards.

- Inspect the IdP's consent page behavior: `prompt=consent` forces re-approval (useful for session-poisoning chains) while `prompt=none` can silently complete a flow when a session already exists.
- Check whether `redirect_uri` is validated at BOTH `/authorize` and `/token` — PortSwigger explicitly recommends sending it to the token endpoint; many implementations only check the first hop, enabling an attacker to swap the URI at exchange time.
- Test URI parsing differentials between the IdP's validator and its redirector: encoded slashes `%2F`, backslashes, `@`, `?`, `#`, double encoding, trailing dot, userinfo tricks, and IDN homographs.
- Look for open redirects on any allowlisted callback host (user namespaces, CMS uploads, legacy apps) — a strict exact-match policy is defeated if the allowed host itself exposes an open redirect that forwards the code.
- Note token delivery mode: query, fragment, `form_post`, or `web_message`. Fragments survive redirects and can be forwarded via the client-as-open-redirector pattern even with narrow URI patterns (IETF OAuth security topics).
- Check OIDC `id_token` claims: `nonce` (replay protection), `aud` (must equal your client_id), `iss`, `exp`, `iat`, and `azp` for multiple audiences.
- Look for `/.well-known/webfinger` user enumeration and LDAP injection as a side-channel for identifying valid accounts to target in an OAuth account-linking attack.
- Check whether the client stores identity in `localStorage` (MSAL `getAllAccounts()`) rather than validating the bearer token server-side — patching the JS guard is then enough to expose protected routes.
- For desktop AI/agent clients, test whether discovery metadata (`authorization_endpoint`, `token_endpoint`) is passed to an OS URL handler — CVE-2025-6514 (`mcp-remote` ≤0.1.15) turned this into local code execution.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- redirect_uri validation bypasses (HackTricks): no validation; weak regex (`evilmatch.com`, `match.com.evil.com`, `match.com.mx`, `matchAmatch.com`, `evil.com#match.com`, `match.com@evil.com`); IDN punycode vs Unicode mismatch; allowlisted host with an open redirect or attacker-controlled subpath (`/openredirect?next=...`, user namespaces, CMS uploads); directory pattern `/oauth/*` bypassed via `/oauth/../anything`; wildcard subdomains; `http://` callbacks.
- Steal the code on an *allowlisted* domain: set `redirect_uri` to a trusted host/path with attacker-controlled content so `token`/`blob`/`code` land in `window.location` and JS exfiltrates them — FB Accounts Center `blob=<BLOB>&token=<TOKEN>` pattern.
- `state` attacks: remove it entirely; use a static/predictable/state-fixated value; tamper with returned `state`; replay the attacker's own final `?code=&state=` URL against a victim via link/iframe/form. Missing or unbound `state` = login CSRF/account linking.
- PKCE downgrade: remove `code_challenge` and `code_challenge_method` from an attacker-initiated flow, obtain a non-PKCE code, inject it into the victim's pending callback; the client sends its own `code_verifier` but the token endpoint ignores it. Also try omitting `code_verifier`, flipping `S256` → `plain`, one-character verifier changes.
- Code lifetime/replay: redeem a captured code after 5–10 minutes (RFC 6749 wants minutes), send the same code twice, race two parallel redemptions; a replay should also revoke already-minted tokens. Cross-client swap: redeem app A's code at app B's token endpoint.
- Session poisoning from PortSwigger research: `GET /authorize?client_id=<trusted>&...&prompt=consent` + hidden `GET /oauth/confirm_access?client_id=<trusted>&...&redirectUri=<evil>` — `redirectUri` binds to the model attribute via mass assignment while the trusted client id wins approval.
- Dynamic Client Registration SSRF: `POST /connect/register {"redirect_uris":["..."],"logo_uri":"http://collaborator/","jwks_uri":"...","sector_identifier_uri":"...","request_uris":["..."]}`; trigger with `/api/clients/{id}/logo` or `/authorize?...&request_uri=<collaborator>/request.jwt`.
- Open Dynamic Client Registration + PKCE: register an attacker client with `redirect_uris:["https://attacker/callback"]`, send the victim through `/authorize` with your `client_id`, and redeem with your own verifier — PKCE does not stop a malicious registered client.
- Multi-provider mix-up: keep flows A and B pending, complete in reverse; replay B's response at A's callback; point an attacker-controlled issuer's `authorization_endpoint` at the honest issuer while keeping an attacker `token_endpoint`.
- Verb/extras: `prompt=none` silent approval; `response_mode=fragment`/`web_message` code delivery; two-link `RU` cookie redirect trick; Referer/telemetry leaks of `code`/`state`; Cognito `update-user-attributes` email change; OIDC discovery metadata forwarded to OS URL handlers (CVE-2025-6514 `mcp-remote` RCE).

- Dynamic Client Registration SSRF detail: `logo_uri` is fetched when the approval page or `/api/clients/{id}/logo` is hit; `jwks_uri` is fetched at `/token` when `client_assertion` is a `jwt-bearer`; `sector_identifier_uri` may be fetched at registration or at authorization time. Each needs its own trigger test.
- Pre-ATO account linking: create an account at the target using the victim's email *before* they sign up with a social provider; when they later use OAuth, the IdP identity can be linked to the attacker's pre-created account.
- `@ModelAttribute` poisoning variant: the confirmed `client_id` can be trusted while `redirectUri` (camel-case model attribute name, not `redirect_uri`) is attacker-supplied on `/oauth/confirm_access` — the parameter-name difference is intentional.
- Login CSRF via `state` replay: attacker completes their own flow, suppresses the final callback, then induces the victim to load `callback?code=<attacker-code>&state=<attacker-state>` so the victim is logged into the attacker's account.
- Cross-provider transaction confusion: keep flows for provider A and B pending, then complete B at A's callback. If global cookies hold `state`/`nonce`/verifier, one provider's value satisfies the other's callback and an attacker's social identity can be attached to a victim account.
- `response_mode=web_message` exfiltration: the code is posted via `window.opener.postMessage(...)` — check whether the receiving origin check is missing so any opener can read it.
- Two-link `RU` cookie trick: set the redirect cookie in one tab via a visible `returnUrl`, close before the warning, then open a second flow without the visible parameter — the consent prompt omits the attacker host while the cookie still redirects the token there.
- Wildcard CORS on OAuth endpoints is usually an amplifier, not the root ATO cause — note it but keep the proof focused on code/token leakage and exchange.
- AWS Cognito primitive: `cognito-idp get-user` then `update-user-attributes --user-attributes Name=email,Value=<attacker>` with a victim access token can enable account takeover if the app trusts an unverified email change.

### C. Validation / proof bar — how to confirm and avoid false positives

- A redirect alone is not ATO. Capture the victim's `code`/token, complete the server-side exchange, and demonstrate access to a victim-only resource or a state change on the victim account. State-only leakage is Low.
- Bind the transaction to issuer/client/redirect/state/nonce/PKCE and validate the authorization-response `iss` against the value stored at flow start; do not claim mix-up from a single mismatched URL alone.
- On refresh rotation, respect grace windows; claim missing reuse detection only after the active token family survives an explicit replay outside that window. DPoP: a duplicate proof within the allowed `jti` window is not itself a standards violation.
- Confirm blind SSRF (logo/jwks/sector_identifier/request_uri) with an out-of-band hit and note the trigger step — these are often second-order, fetched only at consent/token exchange.
- Do not report a leaked `client_secret` as ATO unless you also show a stolen code or a token minted for the victim; public clients cannot keep secrets, so check whether PKCE is actually enforced.
- For `error_description` reflection, show executed JS (browser-specific events like Safari `onpagereveal`) or a coherent phishing page, not just HTML presence. Redact tokens/codes in evidence.

- For the code-exchange step, use the client's real `/token` call (with its `client_secret` or PKCE verifier) and show a victim-API response, not merely that a code landed on your domain.
- When testing `error_description` reflection, prove either script execution or a convincing credential-phishing page on the trusted origin — HTML presence alone is a low-severity XSS/HTML-injection issue.
- For DPoP/mTLS downgrade, test each API host and version independently: one resource server enforcing the binding does not prove the rest do.
- A stolen authorization code that cannot be redeemed (wrong client, redirect, or PKCE verifier) is not ATO — state exactly which checks were bypassed.
- Open dynamic client registration is only impactful if you can get a victim to approve your client; document the approval step and whether `prompt=consent` was needed.
- Confirm blind SSRF from registration with an out-of-band callback and note the exact fetch trigger; many servers save URL parameters and resolve them only later during the flow.
- For multi-provider mix-up, verify the authorization-response `iss` — accepting a value different from the stored issuer is the crux; a mere callback path difference is not enough.
- Check whether the victim's token/session actually changes privileges — login CSRF into an attacker's *low-privilege* account is not equivalent to account takeover of the victim.
- Redact codes, tokens, `state`, and victim PII in PoCs; callback URLs often contain all four and are easy to over-share in screenshots.

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/research/hidden-oauth-attack-vectors
2. https://hacktricks.wiki/en/pentesting-web/oauth-to-account-takeover.html
