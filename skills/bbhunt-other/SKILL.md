---
name: bbhunt-other
description: "Use only when no other class fits: novel primitives, protocol oddities, email/SMS abuse, or multi-class issues without a clear root cause. Unified from 4 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Miscellaneous Vulnerabilities — unified methodology

> **Unified skill.** Built from 4 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

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

5. **Test cross-tenant resource access** — as Tenant A, attempt to read/write Tenant B's resources by mani

### A. Discovery checklist — concrete places, params, headers, flows to look

- `misc` is the routing skill for **cross-cutting and novel primitives** that don't fit a single class. First check whether the finding belongs in a dedicated skill (XSS, SSRF, CSRF, cache, race); if it spans two or more parsers/layers or uses a brand-new technique, it belongs here.
- Track the annual research frontier: PortSwigger's **Top 10 Web Hacking Techniques of 2025** (published Feb 2026) is the best single signal for what "misc" findings are currently paid and novel. 2025's winners: parser differentials, HTTP/2 CONNECT abuse, XS-Leaks (redirect-host and ETag-length), internal Next.js cache poisoning, SOAPwn (.NET WSDL/proxy RCE), Unicode normalization, blind SSRF via redirect loops, ORM leaks, and error-based SSTI. The meta-trend: **side channels as a core exploitation primitive**.
- **Parser differentials (#10)**: anywhere two components parse the same input (proxy vs origin, WAF vs app, browser vs server, request vs response) is a misc goldmine. Compare how each handles URL encoding, case, duplicate headers, null bytes, Unicode normalization, path normalization, and content-type.
- **Unicode normalization (#4 / cookie chaos)**: fuzz identifiers, filenames, cookie names, email local-parts, and usernames with NFKC-sensitive characters (fullwidth forms, U+2000 whitespace, U+0085 NEL, U+00A0 NBSP, Kelvin sign, Turkish dotted I). Look for a value that passes one layer's filter and normalizes into a protected value at another.
- **Cookie-prefix bypass surface** (PortSwigger "Cookie Chaos", Sep

### Web-Research Methodology Additions (2026)

> Fresh-source pass: PortSwigger's Black Hat/DEF CON 2025 "HTTP/1.1 must die" research, Cloudflare Pingora CVE-2025-4366, Akamai CVE-2025-32094, Bugcrowd TE.0, and 2025-2026 emerging-vector writeups. This skill is a discovery index — these are the 2025-2026 classes most likely to arrive as "doesn't fit anywhere," each with the closest class skill to route to.

### A. Discovery checklist — concrete surfaces, inputs, configs to look for

1. **The HTTP desync family is the biggest source of "new" classes.** Evolution timeline from PortSwigger (Aug 2025): CL.TE/TE.CL (2019) → H2.CL/H2.TE (2021) → CL.0 / H2.0 / client-side desync (2022) → **TE.0** (2024, dechunking) → **TE.TE chunk extensions** (2025) → **0.CL** (2025) → **Expect-based** (2025). There are now four length interpretations in play: `CL` (Content-Length), `TE` (Transfer-Encoding), `0` (implicit zero), `H2` (HTTP/2's built-in length). HTTP/2 *downgrading* at the front-end introduces the fourth interpretation and is worse than end-to-end HTTP/1.1.
2. **Real 2025 CDN incidents to model:**
   - **Cloudflare Pingora CVE-2025-4366** — HTTP/1.1 parsing bug when caching enabled: on a cache hit the body-consumption logic was skipped, leaving unread body bytes that could be formed into a smuggled request. Exposed ~24,000,000 sites; $7,000 bounty.
   - **Akamai CVE-2025-32094** — Expect-based CL.0; 74 separate bounties totaling **$221,000**, plus $9,000 to the researcher; 65 days to fully resolve.
   - **Netlify** — CL.0 response-queue poisoning streaming other tenants' responses; **T-Mobile** 0.CL via vanilla Expect ($12,000); **GitLab** obfuscated `Expect: y 100-continue` 0.CL — 27,000 requests to capture another user's bug-bounty report video ($7,000); **LastPass** `auth.lastpass.com` CL.0 via leading-space Expect ($5,000). One research run exceeded **$350,000** in bounties.
   - **TE.0 via GCP Load Balancer** (Bugcrowd 2024) — affected thousands of Google Cloud sites including I

### Signals and surfaces

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

---

### Techniques, payloads and bypasses

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
- **Bypass Email Verificatio

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

8. **Proxy/mirror configs forwarding all requests upstream** — package registries configured to fall back to public registries without restricting w

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
- **CRLF → request splitting probe**: `GET /%0d%0aHost:%20x%0d%0a%0d%0a HTTP/1.1` and variants; a `400` on an injected invalid `Content-Length` indicates the header reached upstream. Then follow the CRLF-powered desync 

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
4. **0.CL deadlock → early-response gadget.** 0.CL normally deadlocks (front-end buffers the payload, back-end waits for the body). Escape requires a gadget that makes the back-end respond before the body arrives: nginx static files, server-level redirects, or the Windows

_...and 3 more sections in `references/unified-method.md`._

### Validation and proof

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
- **CSP findings**: a CSP allow-list gadget is only viable if the effective directive permits it (multiple enforced policies must all allow the host; `strict-dynamic`/nonces ch

### C. Validation / proof bar — how to confirm and avoid false positives (confabulation is NOT a finding for AI classes)

1. **Desync is not proven by a weird status code or a timeout.** Confirm with a deterministic oracle: a time-delay on a subsequent victim request, or a unique/victim-specific response that cannot be produced without the desync. Classic timeout-based detection is heavily fingerprinted and blocked by WAFs; prefer parser-discrepancy detection.
2. **RQP needs a specific verifiable artifact** — the GitLab case proved impact by capturing *another user's vulnerability-report video*. Random cross-user responses with no identifiable content are noise, not proof.
3. **Cache poisoning must show a poisoned response actually served to a different visitor.** The Cloudflare case was notable because the desync was internal and hijacked arbitrary third-party sites — show the cross-tenant/cross-site delivery, not just that you can inject a header.
4. **Header disclosure via Expect needs a masked internal value**, not just a version banner (banners are more compliance noise than critical; Netlify explicitly declined the banner case).
5. **Don't report theoretical protocol observations.** PortSwigger notes that findings like "this server accepts a single LF as a line terminator" are harmless for direct access and rarely pay; they become valuable only when you demonstrate exploitation behind a specific front-end.
6. **Keep the standard proof bar for out-of-class findings.** A finding with no clean class still needs a reproducible state change, an OOB callback, or a verifiabl

### Escalation and related chains

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

_...and 9 more sections in `references/unified-method.md`._

### Tools and wordlists

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
```

## Source skills merged into this topic

- `h1skills` — `hackerone-other`
- `hunting` — `misc`
- `hunting` — `other`
- `cbh` — `hunt-misc`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
