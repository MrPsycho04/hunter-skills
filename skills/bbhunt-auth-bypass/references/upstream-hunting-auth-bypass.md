# Upstream source: auth-bypass (hunting)

Original path: `/tmp/h1res_MrPsycho04_Hunting-Agent/auth-bypass/SKILL.md`

---

---
name: auth-bypass
description: >-
  Hunting skill for auth bypass vulnerabilities. Built from 12 public bug bounty reports across SAML XSW /
  parser-differential (GitHub Enterprise CVE-2025-25291/25292), SAML signature stripping (Uber, Rocket.Chat,
  samlify CVE-2025-47949), SAML domain enforcement bypass via control characters (HackerOne 2024), partner-
  portal cross-IdP assertion reuse (Slack), WordPress XMLRPC bypassing SSO (Uber), JWT alg-confusion
  HS256/RS256 (Jitsi), JWT signature-validation skip (Linktree, Newspack), and token-audience confusion
  (Argo CD CVE-2023-22482). For standalone JWT signature/crypto forging (alg:none, key confusion, kid/jku)
  see crypto-and-secrets; this skill covers JWT only inside SSO/SAML/token-trust bypass chains. SAML assertion-
  layer attacks (XSW, comment injection, signature stripping, XXE-in-assertion) are owned by saml; this
  skill owns the broader cross-protocol auth-bypass taxonomy. Use when hunting auth bypass — see the Legacy-
  Protocol Matrix for branded-UI vs legacy-endpoint patterns. Combined with the HackerOne field guide (real
  disclosed-report data: where it pays, quick wins, payload banks). Hunt login, session, and identity
  verification flaws. Use when testing login flows, password reset, SSO, JWT, magic links, or account
  verification. Backed by 989 disclosed HackerOne reports.
---

# Auth Bypass — Combined Field Guide

**Merged skill.** This fuses two complementary sources into one reference:

- **Part 1 — HackerOne field guide:** statistics from disclosed reports, "where it pays," quick wins, and curated payload banks.
- **Part 2 — Bug hunter methodology:** autonomous testing priority, canary discipline, crown-jewel targeting, OOB/validation gates, and reporting guidance.

**How to use:** Open with Part 2 for execution discipline (set your canary, know your success/failure gate). Use Part 1 to prioritize targets and pull payloads. Before reporting, run the validation gates in both parts.

---

<!-- ============ PART 1: HACKERONE FIELD GUIDE (data + payloads) ============ -->

# Authentication Bypass — HackerOne field guide

Built from **989** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Signal

- Reports: **989** · paid: **197**
- Median bounty **$500** · p90 **$3,000** · max **$15,300** · total **$289,790**
- Median upvotes **10**

## Where it pays

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

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`email` `username` `password` `otp` `code` `token` `reset` `next` `redirect_uri` `state` `saml` `jwt`

## Tools

`jwt_tool` · `hashcat` · `Burp` · `ffuf` · `nuclei`

## Escalation chains

- Reset poisoning -> ATO.
- JWT forgery -> admin access.
- OAuth redirect -> token theft.

## Related

- `mfa-and-passwords` (285 reports)
- `oauth-oidc` (177 reports)
- `session` (150 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

## Crown Jewel Targets

Auth bypass is consistently one of the highest-paying vulnerability classes in bug bounty because it directly violates the most fundamental security control. High-value targets include:

- **SSO/SAML implementations** at enterprise SaaS companies (Slack, Okta, OneLogin integrations) — payouts regularly in the $5K–$25K+ range
- **Admin panels and partner/internal portals** — subdomain-separated admin surfaces like `partners.shopify.com`, `admin.company.com`
- **Third-party auth plugin integrations** — WordPress plugins (OneLogin, WP-SAML-Auth), Drupal SSO modules, any CMS with pluggable auth
- **XMLRPC endpoints** on WordPress — often forgotten, bypasses standard WP auth flows entirely
- **OAuth callback flows** — state parameter mishandling, redirect_uri mismatches
- **API authentication layers** — especially where auth was bolted on after the fact

**Asset priority:** Targets with federated identity (SAML, OAuth, OIDC) connected to large user populations. Partner/reseller portals are particularly juicy because they often have elevated permissions and less security scrutiny than the main product.

---

### SSH certificate-authority trust forgery (Git-hosting / enterprise platforms)
When an org or instance registers an SSH certificate authority, cert `principals` may not be bound server-side to the requesting identity — a member can mint a cert asserting another user's principal and authenticate as them (e.g. modify another user's resource given only its URL). Add SSH-CA trust to the auth-surface list on Git-hosting targets; niche/platform-specific. Disclosed: reports/1901040.

## Attack Surface Signals

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

## Step-by-Step Hunting Methodology

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

## Legacy-Protocol Matrix (Probe These First on Any Custom-Branded Login)

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

## Common Root Causes

1. **SSO bypasses local auth entirely at the UI layer, but not at the API layer** — developers disable the login form but forget that API endpoints (`/xmlrpc.php`, REST API, mobile API) have their own auth handlers that still accept native credentials.

2. **SAML signature validation is skipped or optional** — library defaults often don't enforce signature checking; developers use `wantAssertionsSigned: false` or fail to configure the IdP certificate correctly.

3. **Shared session infrastructure across different trust levels** — partner portals and admin portals reuse the same session cookie or JWT secret because they're built on the same internal framework, assuming access control at the application layer is sufficient.

4. **Trust inheritance in multi-tenant architectures** — a token issued in a lower-privilege context (partner, reseller) is accepted in a higher-privilege context because the verification only checks signature validity, not the issuance context.

5. **Plugin/module auth is independent of application auth** — every WordPress plugin that handles auth (contact forms, REST API extensions, WooCommerce) may implement its own auth handler inconsistently with the main site's SSO.

6. **XML parsing inconsistencies** — different XML parsers (used by SP vs. IdP) handle comments, namespaces, and whitespace differently, enabling confusion attacks where the signed content differs from the evaluated content.

---

## Gate 0 Validation

Before writing any report, answer these three questions:

1. **What can the attacker DO right now?**
   Must be: authenticate as another user OR authenticate without valid credentials OR elevate to admin/privileged role. "Partial information disclosure" is not auth bypass.

2. **What does the victim LOSE?**
   Must identify a concrete asset: account takeover of specific user, access to all admin functions, ability to read/modify other tenants' data, or access to privileged APIs. Abstract "security control bypass" without impact is not sufficient.

3. **Can it be reproduced in 10 minutes from scratch?**
   You must be able to: (a) start from a fresh browser/session, (b) follow your exact steps, and (c) arrive at authenticated access to a protected resource. If reproduction requires special preconditions you can't re-create (a specific victim's active session, timing windows), the report needs more work.

---

## Real Impact Examples

**Scenario 1 — SSO Enforcement Bypassed via Forgotten Protocol Endpoint**
A large ride-sharing company enforced SSO (via OneLogin) on all WordPress-based internal/public properties. The XMLRPC endpoint (`/xmlrpc.php`) remained active and accepted WordPress-native credentials entirely independent of the SSO flow. An attacker with any valid WP-native credentials (obtained via credential stuffing or from a previous breach) could authenticate directly through XMLRPC, bypassing MFA, SSO policies, and IP restrictions enforced on the main login form. Impact: Full authenticated access to all WordPress functions available to that user role, including content management and potentially admin functions.

**Scenario 2 — SAML Assertion Forgery via Signature Validation Failure**
A major enterprise communication platform's SAML SP implementation failed to properly validate assertion signatures in specific edge cases. By manipulating the XML structure of a captured SAMLResponse (specifically through comment injection or namespace prefix attacks), an attacker could modify the `NameID` value to impersonate any user in an organization — including workspace administrators — without possessing that user's credentials or private key material. Impact: Complete account takeover of any user within a SAML-enabled organization; attacker gains access to all messages, files, and integrations in the workspace.

**Scenario 3 — Cross-Portal Privilege Escalation via Shared Auth Backend**
An e-commerce platform's partner/reseller portal issued authentication tokens that were validated by the same backend service as the merchant admin portal. A partner-level account (lower trust, external-facing) could use its issued credentials or tokens to authenticate directly against admin-tier API endpoints, bypassing the merchant onboarding and permission assignment flow. Impact: A malicious partner could access any merchant's admin panel, modify store configurations, exfiltrate customer PII and payment data, or install malicious scripts — affecting thousands of merchant storefronts.

---

## Disclosed Report Citations (Backfill +8 — 2016-2025)

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

## Duende BFF — Token-Confusion & Session-Fixation (2024-2026 surface)

Duende BFF deployments expose two distinct auth-bypass families beyond the CSRF angle covered in `csrf`. Both are documented architectural realities, not unicorn CVEs.

### Attack class 1 — YARP `UserOrClient` / `UserOrNone` privilege escalation

`Duende.BFF.Yarp` attaches access tokens to proxied routes via `WithAccessToken(TokenType.X)` metadata. The **misconfig pattern**: developer marks a route `UserOrClient` (use user token if logged in, else fall back to *client-credentials* token) intending it for a "public catalog" endpoint. The client-credentials (M2M) token frequently has broader scope (`api.admin`, `internal.read`) than any user token. An **unauthenticated** attacker hitting that route gets the request proxied with the **service-account token attached** to the downstream API — privilege escalation by design when the downstream trusts the bearer.

**Payload shape:** identify a BFF route marked `TokenType.UserOrClient` (visible via 401-vs-200 differential when no session, or via leaked OpenAPI/NSwag spec). Hit it with no cookies → BFF forwards with M2M token granting admin-scope downstream. ([docs.duendesoftware.com/bff/fundamentals/apis/yarp](https://docs.duendesoftware.com/bff/fundamentals/apis/yarp/))

**Adjacent confirmed CVE:** **CVE-2024-51987** in `Duende.AccessTokenManagement.OpenIdConnect` — *"HTTP client uses incorrect token after refresh"* — materially the same family of token-confusion at the proxy layer. Moderate severity, fixed 2024. ([GHSA-...51987](https://github.com/advisories?query=duende))

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

## Function-Level Access Control (Broken Authorization)

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

## Related Skills & Chains

- **`idor`** — Auth bypass without object-level access is half a finding; pair them. Chain primitive: legacy `/v1/users/{id}` route missing both auth middleware AND ownership check = unauthenticated cross-tenant data read via direct ID substitution → full PII dump from "I am nobody" starting position.
- **`account-takeover`** — Auth-bypass primitives feed the ATO funnel. Chain primitive: XMLRPC native-cred acceptance + no rate limit on `wp.getUsersBlogs` → credential-stuff with breach corpus from `misc` recon → `system.multicall` batches 1000 cred pairs per request → one valid pair = ATO bypassing the SSO + MFA the UI enforces.
- **`sharepoint`** — The SP equivalent of the WordPress XMLRPC pattern lives here. Chain primitive: `/_vti_bin/Authentication.asmx` anonymous reachable + native Forms-auth credential accepted + zero rate limit = unlimited credential brute-force endpoint bypassing custom-branded `customlogin.aspx` protections → FedAuth cookie → full SharePoint farm access.
- **`security-arsenal`** — Pull the JWT-attack payloads section (alg=none, kid path-traversal, JWK injection, RS256→HS256 key confusion) when JWT validation is the auth wall; pull the SAML signature-stripping section when the SP accepts unsigned assertions.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an "auth bypass" that only enumerates usernames or only reveals a 401-vs-403 differential. Username enumeration alone without lockout-amplification is consistently N/A or Informational on H1.

## Web-Research Methodology Additions (2026)

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

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/web-security/authentication/other-mechanisms
2. https://portswigger.net/web-security/authentication/multi-factor
3. https://portswigger.net/research/hidden-oauth-attack-vectors
4. https://hacktricks.wiki/en/pentesting-web/oauth-to-account-takeover.html
5. https://portswigger.net/web-security/race-conditions
