---
name: bbhunt-okta-attack
description: "Hunt tenant discovery, user enumeration, factor abuse, push fatigue and redirect_uri tampering. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Okta-as-IdP attack chain — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### A. Discovery checklist — concrete fingerprints, endpoints, headers, CVEs, misconfigs to look for

- **AiTM session-cookie theft is the dominant real-world Okta ATO path (2025-2026).** Okta Threat Intelligence tracked **EvilProxy** campaign `O-UNC-035` (active since at least March 2025, SAP Concur / DocuSign / Adobe lures). Datadog's Dec 2025 analysis of a live kit targeting M365 **and Okta** shows the exact cookies an AitM stealer hunts: `idx`, `JSESSIONID`, `proximity_`, `DT`, `sid` — exfiltrated to `/log_cookie?company=<target>.okta.com`. Defensive countermeasure to look for (absence = replay exposure): **ASN + IP session binding** on all admin apps (Settings > Features) and DPoP/device-bound sessions.
- **2025-2026 Okta/Auth0 CVEs to add to recon checks (verify version/config preconditions):**
  - **CVE-2025-47275** (CVSS 9.1) — Auth0-PHP SDK with CookieStore: brute-forceable session authentication tags (CWE-334); fixed in 8.14.0 + rotate cookie encryption keys. Also affects symfony, laravel-auth0, wordpress SDKs.
  - **CVE-2025-48947** — CDN caching of session cookies in NextJS-Auth0 SDK.
  - **CVE-2025-7371** — On-Premises Provisioning (OPP) password-reset information disclosure.
  - **CVE-2025-46572 / CVE-2025-46573** — Passport-WS-Fed SAML signature wrapping and attribute smuggling → user impersonation.
  - **Okta Access Gateway (OAG) cluster, Sep-Oct 2026:** **CVE-2026-78626** Protected Rule authz bypass (CVSS 8.1; needs a configured Protected Rule + any assigned user); **CVE-2026-78560** pass-through auth source accepts unvalidated client-supplied identity head

### Techniques, payloads and bypasses

### 5. CVE-2024-0981 — Okta AD/LDAP DelAuth bcrypt cache-key auth bypass (Oct 2024)

- Refs: <https://trust.okta.com/security-advisories/okta-ad-ldap-delegated-authentication-username/>, <https://www.theregister.com/2024/11/04/why_the_long_name_okta/>, <https://www.nodejs-security.com/blog/okta-bcrypt-security-incident-bun-nodejs>
- Flow: Okta cached AD/LDAP DelAuth results keyed by `bcrypt(userId + username + password)`. Bcrypt silently truncates input at 72 bytes. When username length ≥ 52 chars, the password bytes fall past the 72-byte boundary → cache key collapses to be password-independent. If the user had a prior successful login (cache populated) AND the AD/LDAP agent was unreachable AND MFA was disabled → any password authenticated.
- Root cause: Using bcrypt as a general-purpose hash without accounting for the algorithm's 72-byte input limit + cache fallback path inverted the security model (cache trusted over live auth).
- Year: 2024. Severity: High. Bug introduced Jul 23 2024, internally found and fixed Oct 30 2024 (~3 months exposure window).

### 6. Okta Verify iOS push-response bypass (CVE-2024-10327, disclosed Oct 2024)

- Refs: <https://trust.okta.com/security-advisories/okta-verify-for-ios-cve-2024-10327/>
- Flow: Okta Verify iOS 9.25.1-beta / 9.27.0 had a bug in the iOS ContextExtension push-action handler. From the lock screen long-press / drag-down banner / Apple Watch reply path, both the "Yes, it's me" and "No, it's not me" buttons returned the same accept-auth response. A push-fatigued user who explicitly tapped "No" still approved the auth.
- Root cause: Two notification-response action handlers wired to the same backend confirmation path — UX-level Deny did not propagate as a backend rejection.
- Year: 2024. Severity: High (silently defeats the user's last line of defence against push fatigue / Scattered-Spider-style push bombing).

### B. Techniques & bypasses — specific actionable techniques/payload shapes

```bash
# OAG pass-through auth source spoofing (CVE-2026-78560) — only if module enabled + no header-stripping proxy
curl -sk -H "X-Forwarded-User: admin@target.com" -H "X-Remote-User: admin@target.com" \
  "https://<oag-host>/protected/app" -o /dev/null -w "%{http_code}\n"
# Compare against a baseline request with no identity header; a session/authz change = candidate.

# OAG auth-source tampering (CVE-2026-115546) — with any valid session
# Flip the auth source parameter in the sign-on POST to the source bound to the Admin Console.

# System Log hunts (System Log API / admin console)
GET /api/v1/logs?filter=eventType eq "system.idp.lifecycle.create"
GET /api/v1/logs?filter=eventType eq "user.mfa.factor.reset"     # help-desk reset anomaly
GET /api/v1/logs?filter=(eventType eq "system.idp.lifecycle.activate" or eventType eq "system.idp.lifecycle.update")

# Front-channel secret check (CVE-2026-130153)
# Inspect the Location header of the /authorize redirect for client_secret / client_assertion
curl -skI "https://<tenant>.okta.com/oauth2/v1/authorize?client_id=<id>&response_type=code&..."
```

AiTM-cookie replay path: import stolen `sid`/`idx`/`JSESSIONID` cookies into a browser from a residential proxy and confirm an already-MFA-completed session is reconstructed — but only with explicit authorization; the Datadog/EvilProxy reports are the evidence basis when scope excludes phishing. ANTI-pattern update: do not assume DPoP is present; verify ASN/IP session binding is actually enabled before conc

### Validation and proof

### C. Validation / proof bar — how to confirm and avoid false positives

- **Every 2026 OAG advisory has explicit preconditions** — a Protected Rule policy must be configured, the pass-through source must be enabled *without* a header-stripping upstream, or a valid session must exist. Absent the precondition, a 200 response is normal behavior, not a finding. Confirm by toggling to a non-eligible config/baseline.
- **Auth0 SDK CVEs are version+configuration gates:** CookieStore must be in use (47275), PAR must be disabled/failed (130153), the Authorization Extension's access-control rule must be absent (130236), a multi-tenant shared client must exist (130179/130233). Match the affected version ranges exactly; do not report on version alone.
- **Cross-tenant impersonation:** the attacker needs admin first. Prove the full chain (admin foothold → new IdP → account matching → assertion for arbitrary user) before grading Critical; a lone "IdP creation" event with a benign change ticket is not an ATO.
- **AiTM/session theft:** a cookie name list from a phishing kit is not proof your tenant is vulnerable. Validate the defensive side (session binding enabled?, token binding?), then either demonstrate replay in an authorized lab or report as a documented exposure with the kit's IoCs.
- **Fact-check stale enumeration guidance:** keep the existing "verify freshness with one known-existing and one known-not-existing user" rule; Okta has hardened `/api/v1/authn` differentials. A uniform "Authentication failed" means hardened, not enumerable.
- **Severity:** OAG authz bypass / auth-sour

### Escalation and related chains

### 1. Okta + Sitel/Sykes — LAPSUS$ supply-chain breach (Jan 2022, disclosed Mar 2022)

- Refs: <https://sec.okta.com/articles/2022/03/official-okta-statement-lapsus-claims/>, <https://www.okta.com/blog/company-and-culture/oktas-investigation-of-the-january-2022-compromise/>, <https://thehackernews.com/2022/03/new-report-on-okta-hack-reveals-entire.html>, <https://www.itpro.com/security/cyber-security/367236/leaked-mandiant-report-okta-breach-lapsus-operation>
- Flow: LAPSUS$ compromised a support engineer's workstation at Sitel (third-party support sub-processor, acquired Sykes Enterprises). Via Mimikatz + GitHub-hosted tooling on a thin-client jump host, they reached Okta's internal "SuperUser" support tooling for ~25 minutes on Jan 21 2022. Final scope: 2 customer tenants accessed of 366 originally feared.
- Root cause: Third-party support provider with persistent privileged access to customer tenants, weak segmentation, domain creds stored in spreadsheets, no MFA on the inbound VPN account, delayed reporting (Mandiant report Mar 17, public disclosure Mar 22 only after LAPSUS$ tweeted screenshots).
- Year: 2022. Severity: Critical (industry-shaking — reset the trust model for IdP supply chains).

### Related Skills & Chains

- **`subdomain-takeover`** — Okta tenant naming patterns (`<org>.okta.com`, `<org>.oktapreview.com`, `<org>-admin.okta.com`) frequently include orphan/dev tenants. Chain primitive: Okta tenant discovery via `/.well-known/okta-organization` → enumerate `<org>-dev`, `<org>-uat`, `<org>-test` subdomains → `subdomain-takeover` orphan-tenant identification → claim abandoned tenant → SSO takeover (legitimate `<org>` users redirected through compromised IdP for any app federated to the dev tenant).
- **`m365-entra-attack`** — Okta-as-IdP for M365 is common in hybrid orgs. Chain primitive: `okta-attack` user enumeration + spray succeeds on Okta tenant → Okta is federated to Entra → SAML assertion issued by compromised Okta user → full M365 access without ever touching `login.microsoftonline.com` directly (bypasses Entra Conditional Access in many configurations).
- **`saml`** — Okta issues SAML assertions to every federated downstream app. Chain primitive: Okta admin or developer credential captured → mint arbitrary SAML assertions in Okta admin → `saml` XSW or signature manipulation not even needed — legitimately signed assertions for arbitrary impersonation across every federated app (Salesforce, Workday, AWS, GitHub, M365).
- **`mfa-and-passwords`** — Okta supports multiple factors with varying enforcement. Chain primitive: Okta password sprayed → MFA challenge → `mfa-and-passwords` factor-downgrade (push-fatigue, SMS fallback, voice fallback, security-question fallback) → bypass to authenticated session.
- **`triage-validation`** — Okta findings can

### Related Skills & Chains

- **`hunt-subdomain`** — Okta tenant naming patterns (`<org>.okta.com`, `<org>.oktapreview.com`, `<org>-admin.okta.com`) frequently include orphan/dev tenants. Chain primitive: Okta tenant discovery via `/.well-known/okta-organization` → enumerate `<org>-dev`, `<org>-uat`, `<org>-test` subdomains → `hunt-subdomain` orphan-tenant identification → claim abandoned tenant → SSO takeover (legitimate `<org>` users redirected through compromised IdP for any app federated to the dev tenant).
- **`m365-entra-attack`** — Okta-as-IdP for M365 is common in hybrid orgs. Chain primitive: `okta-attack` user enumeration + spray succeeds on Okta tenant → Okta is federated to Entra → SAML assertion issued by compromised Okta user → full M365 access without ever touching `login.microsoftonline.com` directly (bypasses Entra Conditional Access in many configurations).
- **`hunt-saml`** — Okta issues SAML assertions to every federated downstream app. Chain primitive: Okta admin or developer credential captured → mint arbitrary SAML assertions in Okta admin → `hunt-saml` XSW or signature manipulation not even needed — legitimately signed assertions for arbitrary impersonation across every federated app (Salesforce, Workday, AWS, GitHub, M365).
- **`hunt-mfa-bypass`** — Okta supports multiple factors with varying enforcement. Chain primitive: Okta password sprayed → MFA challenge → `hunt-mfa-bypass` factor-downgrade (push-fatigue, SMS fallback, voice fallback, security-question fallback) → bypass to authenticated session.
- **`triage-validation`** — Okta findings can b

### Tools and wordlists

### Tooling

- **`OktaTerrify`** (github.com/silverhack/OktaTerrify) — post-compromise Okta device-trust / FastPass enumeration. The only verifiable public Okta-specific offensive tool; no other named, maintained "okta-attacker"/"okta-toolkit" utility is verifiable — build engagement-specific scripts against `/api/v1/*` instead of citing unverified tool names.

---

## Source skills merged into this topic

- `hunting` — `okta-attack`
- `cbh` — `okta-attack`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
