---
name: bbhunt-graphql
description: "Use for GraphQL endpoints: introspection, field-level authorization, batching/aliasing abuse, IDOR in queries/mutations, and injection in resolvers. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# GraphQL Authorization and Injection Flaws — unified methodology

> **Unified skill.** Built from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus-backed method (this class)

1. Enumerate the schema (introspection, persisted queries, error-based reconstruction) and record queries, mutations and input types.
2. Map which inputs take caller-supplied IDs/roles and which fields are sensitive.
3. Test field-level authorization with two accounts and different roles — a protected root field often has unprotected nested fields.
4. Test batching and aliasing to bypass rate limits and to amplify repeated resolver calls.
5. Probe fragment/alias/directive tricks that change resolver arguments after validation.
6. Test injection inside resolver-built SQL/templates and file paths; use the corresponding class skill for the sink.
7. Prove unauthorized data or state change with exact operation documents in evidence.

### Signals

- /graphql or Apollo/GraphiQL markers
- Introspection enabled or reconstructable via validation errors
- Mutations that change money, roles, or objects

### Kill criteria

- Introspection disabled *and* schema not reconstructable — still test known operations from JS bundles.
- All field-level checks enforced against the authenticated identity.
- No sensitive field or state-changing mutation reachable.

### Escalation chains

- Introspection -> hidden mutation -> authz bypass -> PII.
- Batching -> rate-limit bypass -> OTP brute force.

### Veteran tip

The operator's thredup notes show schema reconstruction via validation errors even with introspection disabled.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Run introspection; if disabled, use field suggestions and error messages.
- Test object-level authz on every query and mutation.
- Look for nested traversal and alias/batch abuse.
- Test mass assignment on mutations and hidden/admin fields.
- Check injection in arguments passed to resolvers.

### Deeper checklist

- Run introspection; if disabled, use field suggestions and error messages to recover the schema.
- Test object-level authorization on every query and mutation, not just the UI-used ones.
- Look for nested traversal and batch/alias abuse to bypass rate limits.
- Test mass assignment on mutations and hidden/admin fields.
- Check injection in arguments passed to resolvers (SQL/NoSQL, SSRF, template).
- Probe depth/complexity limits and query batching for DoS.
- Verify cross-tenant data access with two accounts.

### Step-by-Step Hunting Methodology

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

8. **Probe for IDOR in node IDs** — GraphQL global IDs often encode object type + ID. Swap IDs across object boundaries and across account cont

### A. Discovery checklist — concrete places, params, headers, flows to look

- **Endpoint discovery by universal query**: `{query:{__typename}}` (or `{"query":"{__typename}"}`) returns `{"data":{"__typename":"query"}}` on any GraphQL service. Probe `/graphql`, `/api`, `/api/graphql`, `/graphql/api`, `/graphql/graphql`, `/v1/graphql`, plus `/graphiql`, `/playground`, `/altair`. A non-GraphQL endpoint typically replies "query not present" — still a useful discriminator.
- **HTTP-method differential**: production best practice is JSON POST only. Test GET with `?query=...`, POST `application/x-www-form-urlencoded`, and POST `multipart/form-data`. These alternate shapes enable CSRF (below) and often bypass introspection filters that only inspect POST JSON bodies.
- **Introspection probe**: `{"query":"{__schema{queryType{name}}}"}`. Then full introspection (`query IntrospectionQuery { __schema { queryType{name} mutationType{name} subscriptionType{name} types{...FullType} directives{...} } } ...`). If the canonical query fails, delete `onOperation`/`onFragment`/`onField` from the `directives` block — many servers reject those.
- **Schema leakage without introspection**: Apollo/graphql-js "Did you mean ...?" suggestions. Run Clairvoyance to reconstruct the schema from suggestions, and look for hidden `__typename`-bearing fields. Disable is not sufficient — WSTG explicitly says disable *both* introspection and suggestions.
- **Introspection-defense bypass**: insert characters GraphQL ignores but regex filters don't — newline, space, comma, tab after `__schema`: `{"query":"query{__s

### Signals and surfaces

### Signal

- Reports: **79** · paid: **28**
- Median bounty **$2,250** · p90 **$7,000** · max **$25,000** · total **$89,172**
- Median upvotes **54**

### Where it pays

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

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`/graphql` `/api/graphql` `/v1/graphql` `node` `edges` `mutation`

### Crown Jewel Targets

GraphQL vulnerabilities are high-value because the attack surface is both broad and deep — a single endpoint can expose entire data models, privilege escalation paths, and cross-API state confusion. Highest payouts occur in:

- **Platform APIs** (GitHub, Shopify, Stripe-tier targets) where GraphQL mutations interact with REST APIs managing the same resources
- **Race conditions between GraphQL mutations and REST endpoints** where state synchronization is non-atomic — these hit medium-to-high severity reliably
- **Authorization persistence bugs** where team/org/repo membership state is controlled by one API but readable/writable by another
- **B2B SaaS platforms** where one tenant affecting another via schema traversal = critical
- **Internal admin GraphQL endpoints** accidentally exposed to lower-privilege users

The GitHub reports demonstrate the crown jewel pattern: **privilege that should be revoked persists because two APIs disagree on ground truth**.

---

### Attack Surface Signals

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

### Techniques, payloads and bypasses

### Payloads & probes

- Introspection -> `{__schema{types{name fields{name}}}}`
- Alias abuse -> `{a:login(u:"a") b:login(u:"b")}`
- Mass assignment -> `mutation{updateUser(role:"admin"){id}}`
- Injection -> `filter: "{\"$where\":\"...\"}"`

### Bypass tricks

- Bypass depth/complexity limits with aliases or fragments.
- Use GET/query params when POST is blocked.
- Bypass authz with nested connections and node(id:) lookups.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Confidential data of users and limited metadata of programs and reports accessible via GraphQL** — `#489146` · HackerOne · $0 · ▲1033
  > The GraphQL endpoint doesn't have access controls implemented properly.
- **Email address of any user can be queried on Report Invitation GraphQL type when username is known** — `#792927` · HackerOne · $0 · ▲671
  > gid://hackerone/Report/626371 (here 626371 my test program's report id) convert it into base 64, replace that id with the "report id" in the above graphql query
- **Unauthenticated RCE in Taskcluster web-server via GraphQL filter argument (sift $where)** — `#3782701` · Mozilla · $12,000 · ▲361
  > The anonymous role has the required scopes. On `firefox-ci-tc` the `anonymous` role grants `auth:expand-scopes`, `auth:list-roles`, `auth:current-scopes`, and `hooks:list-hooks: `.
- **Private list members disclosure via GraphQL** — `#885539` · X / xAI · $0 · ▲346
  > Send requests to `https://api.█████████.com/graphql/iUmNRKLdkKVH4WyBNw9x2A/ListMembers?variables=%7B%22listId%22%3A%22[Valid Snowflake…
- **Disclosing  PolicyPageAssetGroup in Private Programs via /graphql `gid://hackerone/PolicyPageAssetGroupsIndex::PolicyPageAssetGroup/{id}`** — `#1618347` · HackerOne · $25,000 · ▲295
  > `{"query":"{node(id:\"gid://hackerone/PolicyPageAssetGroupsIndex::PolicyPageAssetGroup/3981-41287\"){...
- **SSRF in graphQL query (pwapi.ex2b.com)** — `#1864188` · EXNESS · $3,000 · ▲261
  > The que

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 7× | `$where` |
| 2× | `\\| Decoded` |
| 2× | `{F_number_file}` |
| 2× | `curl 'https://gitlab.com/api/graphql' -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'Authorization: Bearer <<TOKEN>>` |
| 1× | `sift(filter)` |
| 1× | `In CSP mode, sift does not support strings in "$where" condition` |
| 1× | `new Function("obj", "return " + myString)` |
| 1× | `next()` |
| 1× | `curl -sk 'https://hackerone.com/graphql' -H @/tmp/h1.headers -b "$COOKIE" \ / --data-raw '{"query":"{me{_id username}}"}' \\| jq` |
| 1× | `(empty) \\| HTTP 500 /` |
| 1× | `edges { cursor node { id } }` |
| 1× | `source: "doc[\"_seq_no\"].value` |
| 1× | `sort_query: '[{"id":"asc"}]` |
| 1× | `doc[\"_seq_no\"].value` |
| 1× | `doc['<field>'].value` |
| 1× | `curl -X POST http://localhost:8080/graphql\?embedded_submission_form_uuid\=1%27%3BSELECT%201%3BSELECT%20pg_sleep\(30\)%3B--%27` |
| 1× | `curl -X POST https://hackerone.com/graphql\?embedded_submission_form_uuid\=1%27%3BSELECT%201%3BSELECT%20pg_sleep\(30\)%3B--%27` |
| 1× | `{"data":{"team":{"_id":"██████████","report_sources":[]}}}` |
| 1× | `{"data":{"team":{"_id":"█████","report_sources":["HackerOne Platform"]}}}` |
| 1× | `{"data":{"team":{"_id":"█████████","report_sources":["HackerOne Platform"]}}}` |

### Common Root Causes

1. **Dual-write without atomic locking** — developers implement the same resource modification in both REST and GraphQL independently. Neither system is aware the other exists for that resource. State updates aren't serialized or compared.

2. **Inconsistent authorization middleware** — REST endpoints go through one auth layer (e.g., middleware chain), GraphQL resolvers go through a different resolver-level check. The same action, different enforcement.

3. **GraphQL as "new REST" migration** — teams add GraphQL mutations that mirror REST functionality without auditing the permission model. The GraphQL version is less mature and skips checks the REST version accumulated over time.

4. **Introspection left on in production** — default framework settings (Apollo, Graphene) enable introspection in all environments. Developers forget to disable it, treating it as "just documentation."

5. **Node ID trust without re-authorization** — GraphQL global IDs (`base64("ObjectType:123")`) are decoded and trusted without verifying the requesting user has access to that specific object.

6. **Mutation side effects not mirrored** — when a REST action triggers cascading effects (e.g., team removal cascades to permission revocation), the GraphQL equivalent mutation doesn't trigger the same cascades.

---

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
- **GraphQL CSRF**: if GET or form-POST is accepted, host an auto-submitting form/`<img>` that send

_...and 2 more sections in `references/unified-method.md`._

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

1. **What can the attacker DO right now?**
   Must be a concrete action: access data they shouldn't see, retain privileges after revocation, modify another user's resources. "The schema is visible" alone is not enough — what does the schema unlock?

2. **What does the victim LOSE?**
   Must be a real asset: data confidentiality, access control integrity, org security guarantees. For the RC pattern: an org admin loses the guarantee that removing a team revokes all access. That's a security contract violation.

3. **Can it be reproduced in 10 minutes from scratch?**
   For RC/desync bugs: write the exact curl sequence. Run it twice. If the privilege persists deterministically (not timing-dependent flakiness), it's reportable. If it requires millisecond timing luck, document the window and test on low-load times.

---

### C. Validation / proof bar — how to confirm and avoid false positives

- Introspection enabled, GraphiQL exposed, and suggestions enabled are **informational** on their own unless the schema contains data the program considers sensitive (private fields, internal mutations) — and even then, prefer a concrete read/mutation PoC. Many programs explicitly exclude "introspection enabled."
- For IDOR: prove the returned object belongs to a **different user/tenant** and contains non-public data. IDs 1/2/4 with a gap 3 returning a delisted product is a valid demo; a delisted-but-public product may just be intended behavior — check the business context.
- For alias/batch bypass: show the *before* state (per-request limiter triggers at N requests) and the *after* state (N×k operations accepted in one request) with a meaningful outcome (successful login, OTP verified, coupon granted). A response containing all attempts but all failing is not a rate-limit bypass.
- For DoS findings, stay within authorization: use short, bounded bursts, document request counts and timings, and stop at the first clear resource-exhaustion signal. Many programs reject purely theoretical "no depth limit" reports — show a concrete latency/thread exhaustion effect or a vendor-advisory/CVE match (e.g., CVE-2024-50311).
- For CSRF, you must demonstrate a real cross-site state change with the victim's session — not merely that GET is accepted. Confirm SameSite and content-type enforcement; a JSON-POST-only endpoint with correct preflight rejection is not vulnerable.
- Mutation authz: use two accounts (attacker

### Escalation and related chains

### Escalation chains

- GraphQL IDOR -> PII.
- GraphQL injection -> RCE.
- Mutation mass assignment -> admin.

### Related Skills & Chains

- **`idor`** — GraphQL `node(id:)` and global-relay-ID resolvers are IDOR factories: same shape, no scoping. Chain primitive: GraphQL introspection + IDOR (`node()` resolver) → cross-tenant data via base64-decoded type:id replay.
- **`api-misconfig`** — GraphQL mutations are mass-assignment magnets: clients send full input objects, server merges. Chain primitive: GraphQL mutation + extra fields (`isAdmin:true`, `verified:true`) → mass assignment → role escalation.
- **`logic-and-design`** — GraphQL aliases let you call the same mutation N times in one request, defeating per-request rate limits. Chain primitive: aliased mutation + business-logic flaw → coupon redeemed N times in single network round-trip.
- **`race-condition`** — GraphQL batching collapses N mutations into one HTTP packet — perfect single-packet race vehicle. Chain primitive: GraphQL batch + race → atomic-update missing → double-spend balance.
- **`security-arsenal`** — Load the GraphQL Payload Pack: introspection query, schema-suggestion error probe, alias amplification template, depth-bomb DoS payload, batch-attack template.
- **`triage-validation`** — Apply the Body-Diff Rule: introspection alone is informational; require a concrete cross-tenant read or mutation-with-impact PoC before submitting.

### Related Skills & Chains

- **`hunt-idor`** — GraphQL `node(id:)` and global-relay-ID resolvers are IDOR factories: same shape, no scoping. Chain primitive: GraphQL introspection + IDOR (`node()` resolver) → cross-tenant data via base64-decoded type:id replay.
- **`hunt-api-misconfig`** — GraphQL mutations are mass-assignment magnets: clients send full input objects, server merges. Chain primitive: GraphQL mutation + extra fields (`isAdmin:true`, `verified:true`) → mass assignment → role escalation.
- **`hunt-business-logic`** — GraphQL aliases let you call the same mutation N times in one request, defeating per-request rate limits. Chain primitive: aliased mutation + business-logic flaw → coupon redeemed N times in single network round-trip.
- **`hunt-race-condition`** — GraphQL batching collapses N mutations into one HTTP packet — perfect single-packet race vehicle. Chain primitive: GraphQL batch + race → atomic-update missing → double-spend balance.
- **`security-arsenal`** — Load the GraphQL Payload Pack: introspection query, schema-suggestion error probe, alias amplification template, depth-bomb DoS payload, batch-attack template.
- **`triage-validation`** — Apply the Body-Diff Rule: introspection alone is informational; require a concrete cross-tenant read or mutation-with-impact PoC before submitting.

### Tools and wordlists

### Tools

`graphql-voyager` · `InQL` · `GraphQLmap` · `clairvoyance`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_graphql.txt` | 64 |
| `~/.local/share/hackerone-reports/wordlists/params_graphql.txt` | 14 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_graphql.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_graphql.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

### Nuclei

Run introspection and authz tests by hand; templates mostly fingerprint servers and known CVEs.

```sh
nuclei -u https://target -tags graphql \
       -severity low,medium,high,critical -rl 40 -o nuclei_graphql.txt
nuclei -u https://target -t ~/nuclei-templates/http/technologies/graphql \
       -rl 40 -o nuclei_graphql_graphql.txt
nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/other \
       -rl 40 -o nuclei_graphql_other.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Source skills merged into this topic

- `h1skills` — `hackerone-graphql`
- `hunting` — `graphql`
- `cbh` — `hunt-graphql`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 2 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `../../upstream/` — complete unmodified archives of all five source repositories
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
