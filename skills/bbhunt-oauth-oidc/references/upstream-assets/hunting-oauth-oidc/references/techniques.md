# OAuth OIDC — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Test redirect_uri: suffix, path traversal, open redirect, localhost, custom schemes.

- Test state for CSRF and missing binding to the session.

- Try code reuse, code swapping between clients, and PKCE downgrade.

- Check account linking for takeover via unverified email or provider mixups.



## Bypass tricks



- Open redirect on an allowlisted callback domain.

- Exploit parser differences in redirect_uri validation.

- Reuse authorization codes across clients or after use.



## Deeper checklist



- Test redirect_uri validation: suffix, path traversal, open redirect, localhost, custom schemes.

- Test `state` for CSRF and missing binding to the user session.

- Try code reuse, code swapping between clients, and PKCE downgrade.

- Check account linking for takeover via unverified email or provider mixups.

- Test token audience/issuer validation in implicit and hybrid flows.

- Look for token leakage via Referer, logs, and postMessage.

- Show account takeover or cross-account access.



## Techniques from real reports



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



## Case studies



### Email Confirmation Bypass in myshop.myshopify.com that Leads to Full Privilege Escalation to Any Shop Owner by Taking Advantage of the Shopify SSO

`#791775` · Shopify · $0 · critical · 2020-04-01 · ▲1922

> It's possible to take over any store account through bypassing the email confirmation step in .myshopify.com. I found a way to confirm arbitrary emails, and after confirming arbitrary email in .myshopify.com, user is able to integrate with other Shopify store that shares the same email address by setting a master password for all of the stores(if the owner hasn't integrated before), effectively taking over every Shopify stores by knowing just the owner's…



### Shopify Stocky App OAuth Misconfiguration

`#740989` · Shopify · $0 · medium · 2019-12-11 · ▲527

> @vulnh0lic noticed that a staff member without Apps permission was able to access the Stocky app. We determined that this was because of a bug in Stocky's OAuth authentication code, which allowed the user to be granted access to Stocky at the start of the OAuth process rather than the end. This resulted in a full authentication bypass. Within an hour of validating the report, we deployed a fix for this vulnerability.



### Reflected XSS in OAUTH2 login flow

`#697099` · LY Corporation · $1,990 · medium · 2020-04-21 · ▲489

> The reporter found a reflected XSS in the OAUTH2 login flow which could have allowed potential attackers to steal credentials or hijack accounts by sending a message to the victim containing a malicious URL.



### Chained Bugs to Leak Victim's Uber's FB Oauth Token

`#202781` · Uber · $0 · high · 2019-01-25 · ▲427

> The Facebook OAuth application was misconfigured to allow any URL that followed the https://auth.uber.com/login? format to be provided as a redirect uri. By taking advantage of this, @ngalog was able to discover that the next url parameter could be added to the redirect uri allowing it to be chained further.



### [Urgent] Invalidating OAuth2 Bearer token makes TweetDeck unavailable

`#210779` · X / xAI · $0 · n/a · 2019-04-25 · ▲323

> I've noticed that TweetDeck is using OAuth2 to issue requests (Authorization Bearer token): According to the documentation, with a valid consumer key and consumer secret pair, one can generate or invalidate existing bearer token: https://dev.twitter.com/oauth/reference/post/oauth2/invalidate/token Now, it can be guessed that the hardcoded bearer token used in TweetDeck belongs to the TweetDeck client.



## Query the corpus



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



## Bypass Techniques



### Defender: Exact-match `redirect_uri` whitelist

**Bypass:** Find an open redirect on the whitelisted domain itself, then use that URL as the redirect_uri. The OAuth server validates the registered domain ✓, but the open redirect bounces the code/token to attacker.

```

redirect_uri=https://legit.com/logout?next=https://evil.com

```



### Defender: `state` parameter required

**Bypass:** Check if state is validated for *length/format* but not *binding to session*. Use a fixed predictable state value. Also check if PKCE is enforced — if not, the state check alone is insufficient for code injection.



### Defender: Fragment-only token delivery (`response_type=token`)

**Bypass:** Fragment isn't sent in `Referer` by browsers, but JavaScript on the callback page may read `window.location.hash` and pass it to analytics or postMessage to a parent frame. Intercept postMessage handlers.



### Defender: Host validation on mobile deep links

**Bypass:** Try URL encoding (`https%3A//evil.com`), double encoding, Unicode normalization, or null bytes to confuse the validator while the underlying webview still navigates correctly.



### Defender: Short-lived authorization codes

**Bypass:** Referrer leakage and open redirects work even with short-lived codes if the attacker has a fast receiver. For CSRF, the victim completes the flow so timing is less critical.



### Defender: PKCE enforcement

**Bypass:** Check if PKCE is required for *all* clients or only specific ones. Legacy clients or mobile apps may be exempt. Test with `code_challenge` omitted — if the server still issues tokens, PKCE isn't enforced.



### Defender: Nonce validation

**Bypass:** Check if nonce is validated client-side in JavaScript only. Intercept and modify the ID token's nonce claim if the signature isn't verified (rare but seen in misconfigured implementations). Also test if nonce is validated on *initial* request but not on token refresh.



---



## Browser-parse vs server-parse — redirect_uri prefix-match bypass shapes



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
