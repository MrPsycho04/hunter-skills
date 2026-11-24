# Upstream source: misc (hunting)

Original path: `/tmp/h1res_MrPsycho04_Hunting-Agent/misc/SKILL.md`

---

---
name: misc
description: Hunting skill for misc vulnerabilities. Built from 225 public bug bounty reports. Use when hunting misc on any target.
---

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Crown Jewel Targets

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

## Attack Surface Signals

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

---

## Step-by-Step Hunting Methodology

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

## Common Root Causes

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

## Gate 0 Validation

Before writing the report, answer these three questions:

1. **What can the attacker DO right now?**
   Must be a concrete action: read customer PII, escalate to admin role, take over an account, transfer a domain asset, exfiltrate an API token, inject a response header. "Could potentially..." is not sufficient.

2. **What does the victim LOSE?**
   Must map to a real asset: customer data, account control, financial assets (domains), credentials, code repository contents, or platform trust. "Security best practices not followed" is not a valid answer.

3. **Can it be reproduced in 10 minutes from scratch?**
   Write out the exact steps (no special tooling, no race conditions that require luck). If you need pre-existing conditions (e.g., must already be a maintainer), state them explicitly and verify they're realistic for an attacker to achieve.

---

## Real Impact Examples

**Scenario A — Privilege Escalation via Unverified Partner Invitation (Shopify-class)**
An attacker receives a partner invitation link for a low-privilege role. Before completing email verification, they use the invitation token in a session authenticated as a different account (or no account). The platform grants the elevated partner role without confirming identity, allowing the attacker to access merchant data, install apps, or modify store configurations for all stores in the partner account. Business impact: full partner-level access to hundreds of merchant stores with no legitimate relationship established.

**Scenario B — Cross-Tenant Data Persistence After Removal (Shopify/GitLab-class)**
A staff member with restricted permissions is removed from a company account after a dispute. Their session token remains valid because revocation only updates the membership table, not the session store. The ex-employee continues to access customer PII, order data, and financial reports via direct API calls for days or weeks post-termination. Business impact: GDPR/CCPA breach exposure, potential extortion leverage, competitive intelligence theft.

**Scenario C — SAML Signature Bypass for Account Takeover (GitHub Enterprise-class)**
An attacker targeting a GitHub Enterprise instance with SAML SSO enabled crafts a SAML response where the `Signature` element is stripped or moved to cover only a non-critical assertion attribute. The XML parser accepts the document as valid; the signature verifier passes because the signed sub-element validates correctly; the NameID (username/email) in the unsigned portion is set to a victim admin account. Attacker authenticates as the victim with no knowledge of their password or MFA. Business impact: full admin access to all private repositories, CI/CD secrets, and GitHub Actions workflows in the enterprise.

---

## Chains & Compositions (Senior Hunting)

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

### Operator-level pattern

When you confirm a misc primitive at A, **immediately** ask: what state-machine, cache layer, sibling endpoint, or auth-state-skew can amplify it? The first primitive is the entry pass. The chain is the deliverable. Every Workstream-A skill citation in this bundle pairs with at least one chain shape above:
- `auth-bypass` — Chains 2, 4, 5
- `web-cache` — Chain 3
- `saml` — Chain 4
- `subdomain-takeover` — Chain 6
- `account-takeover` — Chains 1, 2, 5, 6 (all terminal-impact paths)

---

## Related Skills & Chains

- **`saml`** — SAML signature wrapping (XSW1–XSW8) is the canonical "misc auth" critical. Chain primitive: SAML XSW + `saml` AttributeStatement injection → NameID swap → ATO of victim admin via SSO with no password.
- **`logic-and-design`** — Misc role/permission desync bugs overlap with business-logic state-machine flaws. Chain primitive: business logic (invitation-before-verify) + role assignment without identity confirmation → tenant takeover.
- **`auth-bypass`** — Session-revocation gaps and stale-token issues are pure auth-bypass primitives. Chain primitive: removed user retains session token → `auth-bypass` → post-termination data exfil and persistent access.
- **`account-takeover`** — Most misc auth bugs end at account takeover. Chain primitive: signature-stripping / NameID injection + `account-takeover` Path 6 (JWT/SAML manipulation) → admin ATO across enterprise.
- **`security-arsenal`** — Load the SAML Raider payload pack, the session-revocation probe checklist, and the Always-Rejected list (rate-limiting on auth, theoretical issues, user enumeration without sensitive PII).
- **`triage-validation`** — Apply the 7-Question Gate plus the Body-Diff Rule: misc bugs are the highest-N/A category — a state desync claim needs a concrete cross-tenant read or admin-action PoC, not just "the API let me call it".

## Web-Research Methodology Additions (2026)

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