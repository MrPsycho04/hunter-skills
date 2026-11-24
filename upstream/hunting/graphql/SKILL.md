---
name: graphql
description: >-
  Hunting skill for graphql vulnerabilities. Built from 12 public bug bounty reports across IDOR via node()
  / GID, mutation IDOR including AI/LLM features, cross-tenant IDOR, SSRF via argument, batching-DoS, query-
  cost-bypass, SQLi via argument, broken-object-level-authz, auth-bypass via unscoped mutations, and PII
  exposure from missing field-level authz. Use when hunting graphql on any target. Combined with the
  HackerOne field guide (real disclosed-report data: where it pays, quick wins, payload banks). Hunt GraphQL
  authorization, introspection, and injection flaws. Use when testing /graphql endpoints, mutations, and
  federated schemas. Backed by 79 disclosed HackerOne reports.
---

# Graphql — Combined Field Guide

**Merged skill.** This fuses two complementary sources into one reference:

- **Part 1 — HackerOne field guide:** statistics from disclosed reports, "where it pays," quick wins, and curated payload banks.
- **Part 2 — Bug hunter methodology:** autonomous testing priority, canary discipline, crown-jewel targeting, OOB/validation gates, and reporting guidance.

**How to use:** Open with Part 2 for execution discipline (set your canary, know your success/failure gate). Use Part 1 to prioritize targets and pull payloads. Before reporting, run the validation gates in both parts.

---

<!-- ============ PART 1: HACKERONE FIELD GUIDE (data + payloads) ============ -->

# GraphQL Security — HackerOne field guide

Built from **79** publicly disclosed HackerOne reports (2017–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Signal

- Reports: **79** · paid: **28**
- Median bounty **$2,250** · p90 **$7,000** · max **$25,000** · total **$89,172**
- Median upvotes **54**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| HackerOne | 32 | $48,000 | 4532 |
| Shopify | 14 | $13,802 | 845 |
| Mozilla | 1 | $12,000 | 361 |
| GitLab | 7 | $7,370 | 275 |
| EXNESS | 1 | $3,000 | 261 |
| Mail.ru | 1 | $2,500 | 42 |
| New Relic | 4 | $750 | 16 |
| Tools for Humanity | 1 | $500 | 91 |

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`/graphql` `/api/graphql` `/v1/graphql` `node` `edges` `mutation`

## Tools

`graphql-voyager` · `InQL` · `GraphQLmap` · `clairvoyance`

## Escalation chains

- GraphQL IDOR -> PII.
- GraphQL injection -> RCE.
- Mutation mass assignment -> admin.

## Related

- `idor` (450 reports)
- `authz-bypass` (1,386 reports)
- `sqli` (331 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

## Crown Jewel Targets

GraphQL vulnerabilities are high-value because the attack surface is both broad and deep — a single endpoint can expose entire data models, privilege escalation paths, and cross-API state confusion. Highest payouts occur in:

- **Platform APIs** (GitHub, Shopify, Stripe-tier targets) where GraphQL mutations interact with REST APIs managing the same resources
- **Race conditions between GraphQL mutations and REST endpoints** where state synchronization is non-atomic — these hit medium-to-high severity reliably
- **Authorization persistence bugs** where team/org/repo membership state is controlled by one API but readable/writable by another
- **B2B SaaS platforms** where one tenant affecting another via schema traversal = critical
- **Internal admin GraphQL endpoints** accidentally exposed to lower-privilege users

The GitHub reports demonstrate the crown jewel pattern: **privilege that should be revoked persists because two APIs disagree on ground truth**.

---

## Attack Surface Signals

**URL Patterns:**
```
/graphql
/api/graphql
/v1/graphql
/query
/gql
/graph
/api/v2/graphql
/internal/graphql
```

**Response Headers:**
```
Content-Type: application/json  (with query body)
X-Request-Id + no REST-style path params = likely GraphQL
```

**JavaScript Source Patterns:**
```js
// grep for these in JS bundles
"query {"
"mutation {"
"__typename"
"apollo"
"ApolloClient"
"graphql-tag"
"gql`"
"operationName"
"GRAPHQL_URI"
```

**Tech Stack Signals:**
- Apollo Server/Client in JS bundles
- Relay in React apps
- `graphene` or `strawberry` (Python), `graphql-ruby`, `gqlgen` (Go), `Lighthouse` (Laravel)
- POST requests with `{"query": "..."}` body shape in Burp history
- `__schema` or `__type` in any response = confirmed GraphQL

**Recon Sources:**
- `github.com` search: `"graphql" site:target.com`
- Wayback Machine for `/graphql` paths
- JS bundle scanning with `LinkFinder` or `getallurls`

---

## Step-by-Step Hunting Methodology

1. **Discover the endpoint** — spider JS bundles, check `/graphql`, `/api/graphql`, review Burp passive scan hits for `application/json` POST with query fields

2. **Test introspection** — send the full introspection query. Even if blocked, try field-level enumeration:
   ```graphql
   { __typename }
   ```
   If that returns, introspection may be partially blocked but the schema is discoverable

3. **Map the full schema** — use `InQL` (Burp extension) or `graphql-voyager` to visualize relationships. Specifically look for:
   - Mutations that modify ownership, permissions, or membership
   - Mutations that mirror REST API functionality

4. **Identify REST/GraphQL overlap** — document every resource that can be modified via BOTH REST and GraphQL. These dual-write surfaces are your RC targets.

5. **Test authorization boundaries per mutation** — replay mutations as lower-privilege users. Does the server enforce the same authz as the equivalent REST call?

6. **Hunt cross-API state desync** — find sequences where:
   - REST action should revoke access
   - GraphQL mutation re-grants or preserves it
   - Test the ordering: REST first → GraphQL → check state; then GraphQL first → REST → check state

7. **Test for persistent privilege after role/membership changes** — remove a user via REST, then call the corresponding GraphQL mutation for that resource. Query current state via both APIs and compare.

8. **Probe for IDOR in node IDs** — GraphQL global IDs often encode object type + ID. Swap IDs across object boundaries and across account contexts.

9. **Check batch query abuse** — send arrays of operations to bypass rate limiting or amplify enumeration.

10. **Document the exact reproduction chain** — for RC bugs, time-based steps must be reproducible deterministically.

---

## Common Root Causes

1. **Dual-write without atomic locking** — developers implement the same resource modification in both REST and GraphQL independently. Neither system is aware the other exists for that resource. State updates aren't serialized or compared.

2. **Inconsistent authorization middleware** — REST endpoints go through one auth layer (e.g., middleware chain), GraphQL resolvers go through a different resolver-level check. The same action, different enforcement.

3. **GraphQL as "new REST" migration** — teams add GraphQL mutations that mirror REST functionality without auditing the permission model. The GraphQL version is less mature and skips checks the REST version accumulated over time.

4. **Introspection left on in production** — default framework settings (Apollo, Graphene) enable introspection in all environments. Developers forget to disable it, treating it as "just documentation."

5. **Node ID trust without re-authorization** — GraphQL global IDs (`base64("ObjectType:123")`) are decoded and trusted without verifying the requesting user has access to that specific object.

6. **Mutation side effects not mirrored** — when a REST action triggers cascading effects (e.g., team removal cascades to permission revocation), the GraphQL equivalent mutation doesn't trigger the same cascades.

---

## Gate 0 Validation

1. **What can the attacker DO right now?**
   Must be a concrete action: access data they shouldn't see, retain privileges after revocation, modify another user's resources. "The schema is visible" alone is not enough — what does the schema unlock?

2. **What does the victim LOSE?**
   Must be a real asset: data confidentiality, access control integrity, org security guarantees. For the RC pattern: an org admin loses the guarantee that removing a team revokes all access. That's a security contract violation.

3. **Can it be reproduced in 10 minutes from scratch?**
   For RC/desync bugs: write the exact curl sequence. Run it twice. If the privilege persists deterministically (not timing-dependent flakiness), it's reportable. If it requires millisecond timing luck, document the window and test on low-load times.

---

## Real Impact Examples

**Scenario A — Covert Persistent Admin After Team Removal (GitHub-pattern)**
An attacker who legitimately had admin access to a repository via team membership gets removed by the org admin through the REST API. The attacker, before removal completes, calls the `updateTeamsRepository` GraphQL mutation to re-associate their team with admin permissions. The REST removal and GraphQL re-grant create a desync where the UI shows the team as removed, but the GraphQL state preserves admin-level access. The attacker retains covert write access to the repository indefinitely — pushing code, reading secrets in CI/CD — without appearing in the team's member list. This persists through org audits.

**Scenario B — Covert Access via Repo Transfer Race (GitHub-pattern)**
An attacker with admin access initiates a repository transfer to another organization via the REST API. During or after the transfer, they invoke `updateTeamsRepository` on the now-transferred repo's ID. Because the GraphQL mutation doesn't validate current org ownership state consistently with the REST transfer event, the original attacker's team retains admin access on a repo now owned by a different organization. The receiving org has no visibility into this team association. The attacker can exfiltrate intellectual property from an org they have no legitimate relationship with.

**Scenario C — Introspection as Reconnaissance Prerequisite (Shopify-pattern)**
On a platform where introspection is intentionally enabled (per-program rules), a hunter maps the full schema and discovers undocumented mutations for `fulfillmentOrderMove` and `inventoryAdjust` that are not surfaced in public docs. These mutations accept merchant IDs as arguments with no scoping validation visible in the schema. This recon directly enables targeted IDOR testing against merchant-to-merchant data isolation — the introspection itself is zero-severity, but it is the entry point to critical findings.

---

## Disclosed Report Citations (Backfill +9 — 2019-2024)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill beyond the original 3 internal references. Each is a distinct GraphQL subclass with a working PoC documented in the cited writeup.

4. **HackerOne — Confidential user-data exposure via GraphQL `User` type** ([H1 #489146](https://hackerone.com/reports/489146))
    - Subclass: broken field-level authorization (PII exposure)
    - Payload: direct `user(id:...)` query returning `email`, `backup_codes_hash`, `facebook_user_id`, `account_recovery_phone_number_verified_at`, `totp_enabled`
    - Root cause: backend migration introduced a GraphQL `User` type with no field-level authz; any authenticated user could enumerate PII of all users
    - Year: 2019 — **$20,000**, 1,028 upvotes

5. **HackerOne — `DestroyLlmConversation` mutation IDOR (Copilot pre-release)** ([H1 #2218334](https://hackerone.com/reports/2218334))
    - Subclass: mutation IDOR on AI/LLM feature
    - Payload: `mutation { destroyLlmConversation(input:{id:"<victim_conv_id>"}) { … } }`
    - Root cause: new LLM-conversation mutation shipped without authorization decorator; any user could destroy any conversation
    - Year: 2023 — caught pre-launch, no bounty (202 upvotes)

6. **Shopify — `BillingDocumentDownload` cross-tenant IDOR** ([H1 #2207248](https://hackerone.com/reports/2207248))
    - Subclass: IDOR on relay GID across tenants
    - Payload: `query { billingDocumentDownload(id:"gid://shopify/BillingInvoice/<other_shop_id>") { url } }`
    - Root cause: `BillingInvoice` resolver authorized the requester's shop but did not verify the invoice belonged to that shop
    - Year: 2024 — **$5,000**, 175 upvotes

7. **Shopify — Rate-limit bypass via negative cost** ([H1 #481518](https://hackerone.com/reports/481518))
    - Subclass: query-cost-calc abuse (sibling pattern to alias batching)
    - Payload: `query { products(first:-100) { … } }` — negative `first` produced a negative query-cost contribution, refilling the leaky-bucket each call
    - Root cause: query-cost calculator did not floor at zero; negative values subtracted from the consumed budget
    - Year: 2019 — **$1,000**

8. **Stripe — Cross-tenant IDOR via `UpdateAtlasApplicationPerson`** ([H1 #1066203](https://hackerone.com/reports/1066203))
    - Subclass: cross-tenant IDOR on mutation
    - Payload: `mutation { updateAtlasApplicationPerson(input:{personId:"<victim_person_id>", …}) }` — adding/modifying a co-founder on another merchant's Stripe Atlas application
    - Root cause: mutation scoped only to "is admin of some merchant," not "is admin of the merchant owning this person"
    - Year: 2020 — bounty undisclosed (resolved)

9. **EXNESS — SSRF in GraphQL `allTicks` query** ([H1 #1864188](https://hackerone.com/reports/1864188))
    - Subclass: SSRF via GraphQL argument
    - Payload: `query { allTicks(source:"http://169.254.169.254/latest/meta-data/") { … } }` — `source` arg fed into a server-side HTTP client
    - Root cause: GraphQL field accepted a URL arg and dereferenced it without scheme/host allowlist
    - Year: 2023 — **$3,000**, 249 upvotes

10. **EXNESS — GraphQL attribute-batching DoS** ([H1 #2293642](https://hackerone.com/reports/2293642))
    - Subclass: DoS via batching / deep-attribute amplification on unauth endpoint
    - Payload: single HTTP request containing N batched operations, each requesting deeply nested attribute trees, sustained until origin OOM
    - Root cause: no query-depth, query-complexity, or batch-size limits on unauthenticated `/graphql`
    - Year: 2024 — bounty undisclosed (resolved)

11. **GitLab — Malicious-runner attach via `runnerUpdate` (CVE-2023-2478)** ([Advisory](https://about.gitlab.com/releases/2023/05/05/critical-security-release-gitlab-15-11-2-released/))
    - Subclass: auth bypass on mutation / project-scope missing
    - Payload: `mutation { runnerUpdate(input:{id:"<attacker_runner_gid>", associatedProjects:["<victim_project_gid>"]}) }`
    - Root cause: `runnerUpdate` did not check that the caller had Maintainer on the target project — any user could bind their malicious runner and intercept CI jobs (build secrets, code execution)
    - Year: 2023 — Critical, CVSS 9.6 (H1 bounty undisclosed; GitLab Critical-tier typically $20k–$35k)

12. **AS Watson — Auth bypass via unrestricted `createAdminUser` mutation** ([HackerOne blog](https://www.hackerone.com/blog/how-graphql-bug-resulted-authentication-bypass))
    - Subclass: sensitive mutation reachable without authentication (introspection-aided discovery)
    - Payload: `mutation { createAdminUser(input:{email:"x@x", role:"ADMIN", password:"…"}) { token } }` invoked unauthenticated after schema enumeration via introspection
    - Root cause: schema lacked per-field authorization directives; `createAdminUser` exposed to public role
    - Year: 2023 — "Best Bug" prize at HackerOne Ambassador World Cup

---

## Related Skills & Chains

- **`idor`** — GraphQL `node(id:)` and global-relay-ID resolvers are IDOR factories: same shape, no scoping. Chain primitive: GraphQL introspection + IDOR (`node()` resolver) → cross-tenant data via base64-decoded type:id replay.
- **`api-misconfig`** — GraphQL mutations are mass-assignment magnets: clients send full input objects, server merges. Chain primitive: GraphQL mutation + extra fields (`isAdmin:true`, `verified:true`) → mass assignment → role escalation.
- **`logic-and-design`** — GraphQL aliases let you call the same mutation N times in one request, defeating per-request rate limits. Chain primitive: aliased mutation + business-logic flaw → coupon redeemed N times in single network round-trip.
- **`race-condition`** — GraphQL batching collapses N mutations into one HTTP packet — perfect single-packet race vehicle. Chain primitive: GraphQL batch + race → atomic-update missing → double-spend balance.
- **`security-arsenal`** — Load the GraphQL Payload Pack: introspection query, schema-suggestion error probe, alias amplification template, depth-bomb DoS payload, batch-attack template.
- **`triage-validation`** — Apply the Body-Diff Rule: introspection alone is informational; require a concrete cross-tenant read or mutation-with-impact PoC before submitting.

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete places, params, headers, flows to look

- **Endpoint discovery by universal query**: `{query:{__typename}}` (or `{"query":"{__typename}"}`) returns `{"data":{"__typename":"query"}}` on any GraphQL service. Probe `/graphql`, `/api`, `/api/graphql`, `/graphql/api`, `/graphql/graphql`, `/v1/graphql`, plus `/graphiql`, `/playground`, `/altair`. A non-GraphQL endpoint typically replies "query not present" — still a useful discriminator.
- **HTTP-method differential**: production best practice is JSON POST only. Test GET with `?query=...`, POST `application/x-www-form-urlencoded`, and POST `multipart/form-data`. These alternate shapes enable CSRF (below) and often bypass introspection filters that only inspect POST JSON bodies.
- **Introspection probe**: `{"query":"{__schema{queryType{name}}}"}`. Then full introspection (`query IntrospectionQuery { __schema { queryType{name} mutationType{name} subscriptionType{name} types{...FullType} directives{...} } } ...`). If the canonical query fails, delete `onOperation`/`onFragment`/`onField` from the `directives` block — many servers reject those.
- **Schema leakage without introspection**: Apollo/graphql-js "Did you mean ...?" suggestions. Run Clairvoyance to reconstruct the schema from suggestions, and look for hidden `__typename`-bearing fields. Disable is not sufficient — WSTG explicitly says disable *both* introspection and suggestions.
- **Introspection-defense bypass**: insert characters GraphQL ignores but regex filters don't — newline, space, comma, tab after `__schema`: `{"query":"query{__schema\n{queryType{name}}}"}`. Also retry over GET, form-POST, and with literal `\u005f\u005f schema` encodings.
- Map every **argument that is an object ID / email / username / tenant**: `id`, `userId`, `internalId`, `node(id:)`, `nodes(ids:)`, `email`, `slug`, `orgId`. OWASP notes that `node`/`nodes` root fields frequently allow direct object access even when not used by the UI (`cat schema.json | jq '.data.__schema.types[] | select(.name=="Query") | .fields[].name' | grep node`).
- Enumerate **mutations** separately from queries: `createUser`, `updateProfile`, `changeRole`, `setEmail`, `resetPassword`, `approveBooking`, `issueCoupon`, `deleteAccount`. Authorization often exists on queries but not mutations (or vice versa).
- Check **edges AND nodes** for authorization. OWASP cites a real report where edge fields were protected but node fields were not — request both the connection wrapper and each returned object's scalar fields.
- Look for **aliases and arrays** in existing client traffic: `aliasedName:field(...)`, or a top-level JSON array of queries. Both are batching primitives and rate-limit bypass candidates.
- Look for **GET-based GraphQL** query params on any endpoint — the CSRF surface PortSwigger calls out. If the app forces `application/json` POST, CSRF is largely blocked by preflight; GET/form-POST reopens it.
- Enumerate **subscriptions** as a separate authz surface (WSS endpoint, `subscription { ... }`). Resolver authorization on queries/mutations is often not applied to subscription setup, yielding a live stream of another tenant's events.
- Check **multipart file-upload GraphQL** endpoints (`operations`, `map`, file parts). The `map` object controls which variable receives the file — a classic place for cross-field injection and IDOR on attachment IDs.
- Note whether **persisted queries / trusted documents** are used (a hash or ID instead of a query string). These block arbitrary introspection but can be abused if hashes are guessable or if one trusted document contains an IDOR-shaped query with attacker-controlled variables.
- Track the **operation-limit** features the deployment should have (max aliases, max root fields, max bytes, max depth, max batch size). Testing each one individually tells you which DoS/brute-force primitive remains available — and gives concrete remediation language for the report.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **IDOR via unsanitized argument** (PortSwigger product-shop example): list only shows `listed:true` products with IDs 1,2,4 → query the gap: `query { product(id: 3) { id name listed } }`; a returned row with `listed: false` proves unlisted-object access. Chain to other users' records by changing `internalId`.
- **Alias-rate-limit bypass** (PortSwigger lab): a single mutation with 100 uniquely aliased `login` calls —
  ```graphql
  mutation {
    brute0:login(input:{username:"carlos",password:"p0"}){success token}
    brute1:login(input:{username:"carlos",password:"p1"}){success token}
    # ... brute99
  }
  ```
  removes `variables`/`operationName`, then search the response for `"success":true`. Works because the limiter counts HTTP requests, not operations.
- **Array batching** bypasses the same limiter: `[{"query":"{droid(id:\"2000\"){name}}"},{"query":"{droid(id:\"2001\"){name}}"}]` → enumerate objects, brute OTPs, or DoS in one round-trip. WAF/RASP/IDS see one request; Nginx-style per-request limits don't fire. Apollo Server v4 disables array batching by default, but Apollo Gateway and Hasura may still support it — verify, don't assume.
- **2FA/lockout bypass**: aliases re-sending `verifyOtp(code: N)` many times inside one request can process multiple codes before the failure counter is persisted. Report as auth bypass only with a successful verification for a code not legitimately submitted.
- **GraphQL CSRF**: if GET or form-POST is accepted, host an auto-submitting form/`<img>` that sends `?query=mutation{...}`. Defensive bar: require JSON POST, validate content-type, and use CSRF tokens. Cross-reference `csrf` for the exploit scaffold.
- **DoS / depth-bomb**: cyclic nesting `album{ songs{ album{ ... } } }` and breadth bombs with 100 aliases of the same field (`friends1: friends(limit:1)...friends100: friends(limit:100)`) — depth limits alone do not stop alias breadth. CVE-2024-50311 (OpenShift) was an alias-batching DoS; Apollo recommends limits on max aliases/root fields, bytes, query cost analysis, and DataLoader batching.
- **Resource-aware timing**: watch response times and DB load; "shorter than expected" can indicate work handed to a background thread (a race-condition clue). OWASP recommends `graphql-depth-limit`, `graphql-cost-analysis`, `MaxQueryComplexityInstrumentation` as the *defensive* side — their existence tells you what the target probably lacks.
- **Injection through arguments**: string/JSON arguments reach SQL/NoSQL, shells, and template engines like any other input. OWASP lists SQLi, NoSQLi, OS command, SSRF, and CRLF/request smuggling via GraphQL args. Payload shapes are identical to the respective class skills.
- **GraphiQL/GraphQL Playground URL parameter**: older Swagger-style UIs accept `?url=` or `?endpoint=` pointing at an attacker schema — test for SSRF/DOM-XSS style abuse of the explorer itself.

### C. Validation / proof bar — how to confirm and avoid false positives

- Introspection enabled, GraphiQL exposed, and suggestions enabled are **informational** on their own unless the schema contains data the program considers sensitive (private fields, internal mutations) — and even then, prefer a concrete read/mutation PoC. Many programs explicitly exclude "introspection enabled."
- For IDOR: prove the returned object belongs to a **different user/tenant** and contains non-public data. IDs 1/2/4 with a gap 3 returning a delisted product is a valid demo; a delisted-but-public product may just be intended behavior — check the business context.
- For alias/batch bypass: show the *before* state (per-request limiter triggers at N requests) and the *after* state (N×k operations accepted in one request) with a meaningful outcome (successful login, OTP verified, coupon granted). A response containing all attempts but all failing is not a rate-limit bypass.
- For DoS findings, stay within authorization: use short, bounded bursts, document request counts and timings, and stop at the first clear resource-exhaustion signal. Many programs reject purely theoretical "no depth limit" reports — show a concrete latency/thread exhaustion effect or a vendor-advisory/CVE match (e.g., CVE-2024-50311).
- For CSRF, you must demonstrate a real cross-site state change with the victim's session — not merely that GET is accepted. Confirm SameSite and content-type enforcement; a JSON-POST-only endpoint with correct preflight rejection is not vulnerable.
- Mutation authz: use two accounts (attacker A, victim B) and show A's token executing a mutation on B's object. A mutation that only returns an error message difference is an enumeration clue, not a finding (unless sensitive PII is exposed).
- Do not report a "hidden field" discovered only via introspection if the resolver rejects unauthorized access — resolver-level authorization is what matters; schema visibility is not an authorization boundary.
- Record exact query text, variables, endpoint path, and method in the report — GraphQL requests are not self-describing in a screenshot, and triagers must be able to replay the alias/batch exactly.

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/web-security/graphql
2. https://portswigger.net/web-security/graphql/lab-graphql-brute-force-protection-bypass
3. https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
4. https://www.graphql.org/learn/security/
5. https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/99-GraphQL/
6. https://afine.com/graphql-security-from-a-pentesters-perspective
7. https://www.yeswehack.com/learn-bug-bounty/hacking-graphql-endpoints
8. https://github.com/PortSwigger/inql
