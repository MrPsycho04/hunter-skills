---
name: bbhunt-auth-bypass
description: "Use for login logic flaws, password reset and recovery, session issuance, JWT/session trust, account enumeration, and identity verification failures. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Authentication Bypass — unified methodology

> **Unified skill.** Built from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus evidence (989 valid reports, 197 paid / 20%)

Payment is not validity — zero-bounty disclosures are mined as evidence too.

### Techniques ranked across ALL valid writeups

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

### Parameters observed

`name`, `charset`, `class`, `path`, `type`, `_ga`, `max-age`, `email`, `__utma`, `__utmz`, `utmcsr`, `utmccn`, `utmcmd`, `href`, `__utmb`

### Case studies (real reports, paid and unpaid)

- [739737](https://hackerone.com/reports/739737) PayPal — Token leak in security challenge flow allows retrieving victim's PayPal email and plain text password ($15300, high)
- [2443228](https://hackerone.com/reports/2443228) TikTok — Account Takeover via Authentication Bypass in TikTok Account Recovery ($12000, critical)
- [976603](https://hackerone.com/reports/976603) Superhuman (formerly Grammarly) — Ability to DOS any organization's SSO and open up the door to account takeovers ($10500, high)

Full payload bank, bypass frequencies, approach patterns and case-study excerpts: `references/evidence.md`.

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

### Veteran tip

A real corpus case turned a Content-Type conversion into a dual-recipient reset email — parameter shape is a first-class auth test.

## Unified upstream methodology (deduplicated)

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
   - Does removing `state` from OAu

### A. Discovery checklist — concrete places, params, headers, flows to look

- Inventory every auth endpoint beyond `/login`: `/login2`, `/login-steps/first` and `/second`, `/otp-verify`, `/api/*/login`, `/sso`, `/api/home/ssoAuthentication`, legacy `/v1/*`, XMLRPC `/xmlrpc.php`, SharePoint `/_vti_bin/Authentication.asmx`. Top HackerOne auth-bypass patterns repeatedly hit legacy endpoints that skip the branded UI's controls.
- Trace the multi-step login in Burp and note any identity-bearing cookie set at step 1 (`verify=`, `account=`, `Set-Cookie: ...=<username>`) and every parameter that selects the identity (`username`, `user_id`, `userId`, `email`, hidden fields).
- Test whether the second factor actually gates a session: after password-only login, manually browse to `/my-account`, `/profile`, `/dashboard`, `/admin` before submitting any code.
- Probe parameter pollution (duplicate `username`/`password`), HTTP verb tampering (GET on a POST-only login), `X-HTTP-Method-Override`, and path-override headers (`X-Original-URL`, `X-Rewrite-URL`).
- Username-enumeration channels: distinct messages ("Invalid username" vs "Incorrect password"), a missing full stop, status-code differences, response timing that grows with password length, account-lockout differences, and `/.well-known/webfinger` (200 vs 404; also LDAP injection there — PortSwigger "Hidden OAuth attack vectors").
- Check whether IP-based brute-force protection trusts `X-Forwarded-For` (PortSwigger timing lab), and whether "remember me" tokens are predictable concatenations of username + timestamp.
- Look for token-

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
  > Words such as `http://example.co

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
- For response-tampering 

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

## Source skills merged into this topic

- `h1skills` — `hackerone-auth-bypass`
- `hunting` — `auth-bypass`
- `cbh` — `hunt-auth-bypass`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 2 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `references/unified-method.md` — includes 2 merged companion methodology documents
- `references/corpus-wordlists/` — 2 mined paths/params/payload lists from the HackerOne corpus
- `../../upstream/` — complete unmodified archives of all five source repositories
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
