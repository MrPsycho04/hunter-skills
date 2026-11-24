# Evidence appendix — GraphQL Authorization and Injection Flaws

Mined from all **13 valid disclosed reports** for this class (2 paid, 15% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
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

## Tools mentioned

| Item | Count |
|---|---:|
| source-code-review | 1 |
| python | 1 |
| burp | 1 |
| burp-repeater | 1 |
| browser | 1 |

## Bypass primitives

| Item | Count |
|---|---:|
| race condition | 2 |
| bypass | 1 |
| bypassing | 1 |
| content-type | 1 |
| time based | 1 |

## Impact language

| Item | Count |
|---|---:|
| password | 19 |
| token | 9 |
| admin | 6 |
| sensitive data | 3 |
| unauthorised | 3 |
| unauthorized | 2 |
| sensitive information | 2 |
| localhost | 1 |

## Parameters observed

| Item | Count |
|---|---:|
| z2lkoi8vagfja2vyb25ll1rlyw0vmtm | 1 |

## Recurring approach patterns

- **1×** when clicking on change password after supplying values for current password password and confirm password user is directed to sign in page to log in again with changed password
  - e.g. When clicking on "change password" after supplying values for current password, password and confirm password, user is directed to sign_in page to log in again with changed password.
- **1×** i ve found a misconfiguration in your graphql api on the endpoint in which an attacker is able to run a graphql interospection query to fetch schemas types fields available query operations after running interospection query on the graphql api endpoint an attacker is able to list all type of available api calls so he ll be able to perform unauthorised api calls due to this misconfiguration
  - e.g. i've found a misconfiguration in your graphql Api on the endpoint in which an attacker is able to run a graphql interospection query to fetch schemas , types , fields , available query operations , after running interospection query on the graphql api endpoint , an attacker is able to list all type 
- **1×** impact an attacker can exploit this vulnerability to cause a denial of service dos by sending a single graphql request with multiple aliases of the expensive mutation
  - e.g. ## Impact An attacker can exploit this vulnerability to cause a Denial of Service (DoS) by sending a single GraphQL request with multiple aliases of the expensive mutation.

## Case studies (full excerpts)

### 1618347 — Disclosing  PolicyPageAssetGroup in Private Programs via /graphql `gid://hackerone/PolicyPageAssetGroupsIndex::PolicyPageAssetGroup/{id}`
HackerOne · $25000 · critical · https://hackerone.com/reports/1618347

**Summary:** Hi team, I understand what's going on **Description:** Just a recent update gives the results of private programs ### Steps To Reproduce Without authorization GraphQL: `{"query":"{node(id:\"gid://hackerone/PolicyPageAssetGroupsIndex::PolicyPageAssetGroup/3981-41287\"){... on PolicyPageAssetGroupDocument{id,name}}}"}` Answer: `{"data":{"node":{"id":"Z2lkOi8vaGFja2Vyb25lL1BvbGljeVBhZ2VBc3NldEdyb3Vwc0luZGV4OjpQb2xpY3lQYWdlQXNzZXRHcm91cC8zOTgxLTQxMjg3","name":"██████"}}}` This is Asset program - █████████ Thanks! ## Impact Disclosing Sсope(Assets) in Private Programs

### 707406 — Team object in GraphQL disclosed of private programs via the industry
HackerOne · $500 · low · https://hackerone.com/reports/707406

**Summary:** Disclosure of private programs across the industry If the program is private, it will show industriy ### Steps To Reproduce {"query": "query {team(handle:\\"█████████\\"){_id,industry}}"} `{"data":{"team":{"_id":"█████████","industry":"Computer Hardware \u0026 Peripherals"}}}` {"query": "query {team(handle:\\"█████████\\"){_id,industry}}"} `{"data":{"team":{"_id":"████████","industry":"Computer Software"}}}` {"query": "query {team(handle:\\"███\\"){_id,industry}}"} `{"data":{"team":{"_id":"████","industry":null}}}` ## Impact Disclosure of private programs

### 3287208 — DOS via Mutation Aliasing in GraphQL Account Recovery Phone Number Verification API
HackerOne · no bounty (valid finding) · severity n/a · https://hackerone.com/reports/3287208

**Summary:** The GraphQL API’s `verifyAccountRecoveryPhoneNumber` mutation can be aliased multiple times in a single request, causing the server to process each mutation sequentially. Each additional alias adds approximately 8 seconds to the server’s response time, enabling (DoS) attack by exhausting server resources and increasing latency. **Description:** The `verifyAccountRecoveryPhoneNumber` mutation is designed to verify user phone numbers during account recovery phone change. However, the API does not limit the number of mutation aliases in a single GraphQL request. When the same mutation is repeated with different aliases, the server executes each one separately, performing expensive backend operations multiple times. This leads to a linear increase in response time based on the number of aliases included. The result is a resource exhaustion vulnerability that can degrade or deny service availability to legitimate users. ### Steps To Reproduce 1. Prepare a GraphQL mutation request with multiple aliases for `verifyAccountRecoveryPhoneNumber`, In this case, the response time will exceed 20 seconds because each alias (verify1, verify2, verify3) adds approximately 8 seconds of processing time. 2. Send the request to the GraphQL endpoint with valid or dummy `verification_code` and `otp_code` variables. 3. Observe the response time increases by 8 seconds for each additional mu

### 898528 — GraphQL AdminGenerateSessionPayload is leaked to staff with no permission
Shopify · no bounty (valid finding) · medium · https://hackerone.com/reports/898528

@hiffley reported the ability to generate app tokens via the adminGenerateSession mutation in Shopify Admin, as a staff member with no permissions. This allowed for accessing a small subset of installed apps that are using this new flow (including Shopify Email). Access was limited to the current shop. We fixed this by adding a check for Apps permission to this mutation. This is a limited disclosure at the request of @hiffley. POC request:

### 2357012 — Inadequate redaction exposes sensitive information via the “ShareReportViaEmail" GraphQL endpoint
HackerOne · no bounty (valid finding) · medium · https://hackerone.com/reports/2357012

## Summary The vulnerability involves the insufficient redaction of sensitive information within the HackerOne platform. Specifically, the redaction feature, designed to conceal certain data such as JIRA references, fails to completely obscure this information from being accessed through GraphQL requests. ## Steps to Reproduce 1. Execute the following GraphQL request: 2. Observe the response, which includes the redacted `impact` field. ## Impact The impact of this vulnerability is significant as it undermines the confidentiality measures put in place by the redaction feature. An attacker or unauthorized user could potentially exploit this vulnerability to gain access to sensitive information which might include critical data. ███████

### 3287208 — DOS via Mutation Aliasing in GraphQL Account Recovery Phone Number Verification API
HackerOne · no bounty (valid finding) · severity n/a · https://hackerone.com/reports/3287208

**Summary:** The GraphQL API’s `verifyAccountRecoveryPhoneNumber` mutation can be aliased multiple times in a single request, causing the server to process each mutation sequentially. Each additional alias adds approximately 8 seconds to the server’s response time, enabling (DoS) attack by exhausting server resources and increasing latency. **Description:** The `verifyAccountRecoveryPhoneNumber` mutation is designed to verify user phone numbers during account recovery phone change. However, the API does not limit the number of mutation aliases in a single GraphQL request. When the same mutation is repeated with different aliases, the server executes each one separately, performing expensive backend operations multiple times. This leads to a linear increase in response time based on the number of aliases included. The result is a resource exhaustion vulnerability that can degrade or deny service availability to legitimate users. ### Steps To Reproduce 1. Prepare a GraphQL mutation request with multiple aliases for `verifyAccountRecoveryPhoneNumber`, In this case, the response time will exceed 20 seconds because each alias (verify1, verify2, verify3) adds approximately 8 seconds of processing time. 2. Send the request to the GraphQL endpoint with valid or dummy `verification_code` and `otp_code` variables. 3. Observe the response time increases by 8 seconds for each additional mu

### 898528 — GraphQL AdminGenerateSessionPayload is leaked to staff with no permission
Shopify · no bounty (valid finding) · medium · https://hackerone.com/reports/898528

@hiffley reported the ability to generate app tokens via the adminGenerateSession mutation in Shopify Admin, as a staff member with no permissions. This allowed for accessing a small subset of installed apps that are using this new flow (including Shopify Email). Access was limited to the current shop. We fixed this by adding a check for Apps permission to this mutation. This is a limited disclosure at the request of @hiffley. POC request:

## Field playbook (unedited)

### quick

- Run introspection; if disabled, use field suggestions and error messages.
- Test object-level authz on every query and mutation.
- Look for nested traversal and alias/batch abuse.
- Test mass assignment on mutations and hidden/admin fields.
- Check injection in arguments passed to resolvers.

### payloads

- Introspection -> `{__schema{types{name fields{name}}}}`
- Alias abuse -> `{a:login(u:"a") b:login(u:"b")}`
- Mass assignment -> `mutation{updateUser(role:"admin"){id}}`
- Injection -> `filter: "{\"$where\":\"...\"}"`

### bypass

- Bypass depth/complexity limits with aliases or fragments.
- Use GET/query params when POST is blocked.
- Bypass authz with nested connections and node(id:) lookups.

### surface

- /graphql
- /api/graphql
- /v1/graphql
- node
- edges
- mutation

### tools

- graphql-voyager
- InQL
- GraphQLmap
- clairvoyance

### chain

- GraphQL IDOR -> PII.
- GraphQL injection -> RCE.
- Mutation mass assignment -> admin.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class graphql
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class graphql --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
