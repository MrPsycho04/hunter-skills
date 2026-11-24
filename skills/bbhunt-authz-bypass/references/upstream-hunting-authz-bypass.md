# Upstream source: authz-bypass (hunting)

Original path: `/tmp/h1res_MrPsycho04_Hunting-Agent/authz-bypass/SKILL.md`

---

---
name: authz-bypass
description: >-
  Hunt IDOR, privilege escalation, tenant isolation breaks, and missing function-level authorization. Use when testing roles, admin actions, org boundaries, or object IDs. Backed by 1,386 disclosed HackerOne reports.
---

# Broken Access Control / Authorization Bypass — HackerOne field guide

Built from **1,386** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Signal

- Reports: **1,386** · paid: **337**
- Median bounty **$500** · p90 **$2,500** · max **$35,000** · total **$484,104**
- Median upvotes **20**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| GitLab | 52 | $100,590 | 4494 |
| Mail.ru | 43 | $40,350 | 1580 |
| PlayStation | 6 | $30,700 | 830 |
| Shopify | 92 | $29,400 | 5300 |
| Valve | 10 | $22,500 | 1064 |
| Teleport | 1 | $21,000 | 255 |
| HackerOne | 63 | $20,100 | 5079 |
| Internet Bug Bounty | 22 | $17,005 | 705 |

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`role` `admin` `permission` `org` `team` `account` `tenant` `owner` `visibility` `public` `internal`

## Tools

`Autorize` · `Burp` · `ffuf` · `nuclei` · `jwt_tool`

## Escalation chains

- Authz bypass -> admin panel -> data export.
- Privilege escalation -> cross-tenant access.
- Unauth endpoint -> internal API -> RCE.

## Related

- `idor` (450 reports)
- `auth-bypass` (989 reports)
- `logic-and-design` (931 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete places, params, headers, flows to look

- Build an identifier inventory before testing. Classify every object reference: sequential integers (`user_id=1234`, `order_id=5678`), UUIDs/GUIDs, Base64/MD5 hashed IDs, Mongo ObjectIDs, and composite keys. Sequential IDs are trivially enumerable; UUIDs are safe only if never leaked elsewhere (list endpoints, public object responses, logs).
- Search all identifier locations: URL path (`/api/v1/orders/{id}`), query string (`?id=`, `?user_id=`, `?customer_number=`), JSON body (`{"userId":...}`), headers (`X-User-Id`, `X-Tenant-Id`), cookies, WebSocket topics, GraphQL variables/global `node()` IDs, and static files (`/static/12144.txt` chat transcripts — PortSwigger IDOR example).
- Include write/delete surfaces in the map, not just reads: `PUT`/`PATCH`/`DELETE` variants, import/export and download endpoints, attachment and invoice IDs, and role/permission parameters (`role_id`, `permission_id`) for privilege escalation.
- Multi-tenant SaaS: create accounts in two orgs and look for `organizationId`, `workspace_id`, `account_id`, `team_id`. Tenant-isolation breaks are the highest-impact BOLA variant.
- Burp workflow (PortSwigger): capture requests as a low-privileged user, add a session-handling rule with that user's cookie, then re-request the entire site map; use Authorize / AuthMatrix / AuthZ extensions to replay each request with a second session and flag where the second session still gets a 200.
- Benchmark "not found" vs "forbidden" vs genuine success responses by response length, status, and body before drawing conclusions. Check method-based access control: try GET where POST is expected and `X-HTTP-Method-Override`.

- Include non-HTTP object references in the map: file names in downloads, message/group IDs in chat, job/task IDs in async APIs, and database record indexes used directly as query parameters (PortSwigger's `customer_number` example).
- Check responses for leaked references to other objects (`creator_id`, `ownerId`, `parent_id`, signed URLs, thumbnails) — these often supply the "unguessable" UUID you need for a BOLA test.
- In GraphQL, run introspection if enabled to find object types and ID arguments; test the same five scenarios through query variables rather than URL paths.
- For WebSocket apps, enumerate room/channel/subscription identifiers and test whether a client can subscribe to another user's stream by ID.
- Look for API version drift: `/v1/.../users/{id}` may lack the ownership check that `/v2/...` enforces. Cross-check old and current versions with the same session.
- Use the Burp "Authorize" extension or a BCheck that rewrites the session cookie/token on every proxied request; red results (second session still gets 200) are the primary triage signal.
- Check whether an object reference appears in a signed structure (JWT claim, HMAC-signed URL) — if so, see the `crypto-and-secrets` skill for forgery before concluding the ID cannot be changed.
- Map role hierarchy: vertical BOLA often lives in a different endpoint family (admin audit logs, billing settings) than horizontal read APIs; crawl as an admin once (if a test admin is available) and replay those endpoints as a low-priv user.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- The five scenarios covering most of the BOLA surface (OWASP API1:2023 / CWE-639): (1) read another user's object with your session, (2) write/modify it — email change = ATO, (3) delete it (DoS capability), (4) cross-tenant substitution, (5) role/permission ID swap for horizontal privilege escalation.
- Horizontal IDOR: `/customer_account?customer_number=132355` → change the number (PortSwigger). Vertical/function-level (BFLA): invoke an admin action by path or verb change. Unauthenticated IDOR: any anonymous user's objects.
- Sniper Intruder over adjacent numeric IDs; Cluster Bomb for multi-ID objects. Sort by response Length — a distinctly longer body usually means another user's data was returned. If you can view it, also test edit and delete (real 2025 writeup: viewing → editing → deleting another company's punch tickets by changing one URL number).
- Platform-layer bypass via header spoofing: use `TRACE /admin` to discover `X-Custom-IP-Authorization`, then set `X-Custom-IP-Authorization: 127.0.0.1` via Match-and-Replace to reach the admin panel (PortSwigger information-disclosure lab).
- Mass-assignment overlap: add `{"role":"admin","is_admin":true,"verified":true,"owner_id":<victim>}` to profile/reset requests; combine with `role_id` substitution for privilege escalation.
- Format/parser bypasses: switch Content-Type between JSON/form/XML, use array injection (`id[]=`, Ruby/Rails `param[key]` → nil during partial-construction windows), non-normalized paths (`/oauth/../anything`), and duplicate `id` parameters.
- GraphQL/WebSocket surfaces: test object IDs in query variables and field arguments, and topic/room subscription IDs, not only REST paths.
- Defeat "unguessable" IDs by harvesting leaked UUIDs from list responses, Referer headers, and logs; opaque/hashed IDs are not a security control.

- Referer-based / location-based controls: spoof `Referer` to the expected page or set a geo header (`X-Forwarded-For` with an internal IP) to bypass checks that rely on these instead of server-side authorization.
- Multi-step workflow BOLA: complete step 1 for your own object, then substitute the object ID in step 2/3 (e.g. pay for your cart, change the order ID before confirmation) — the same missing ownership check, just later in the state machine.
- Forceful browsing to admin paths with a low-privileged cookie, plus verb tampering (`GET /admin/deleteUser?id=...`) when the platform layer only protects POST.
- Parameter-based role escalation: `/admin?role=admin`, `?debug=true`, `?isAdmin=1`, or a `role_id` swap in an update profile request — test each role-bearing parameter independently.
- CORS/BOLA combination: if a BOLA endpoint also reflects `Origin` with credentials, demonstrate the cross-origin read from an attacker-controlled origin in a browser to raise impact from "with session" to "drive-by".
- Blind/second-order BOLA: submit another user's ID into an action that later emails or exports data (e.g. "send invoice to"), and confirm via the email/out-of-band channel that the foreign object was processed.
- Timing/length side channels: when a 403 and 404 are returned, a consistently longer response for "exists but forbidden" is still an authorization leak — report it as Info/Low, not as a full BOLA.
- Error-based enumeration: compare `{"error":"not found"}` vs `{"error":"forbidden"}` vs a stack trace; a verbose error that confirms another user's object exists can be the first half of a chain.

### C. Validation / proof bar — how to confirm and avoid false positives

- `200 OK` is not proof. Inspect the response body delta and show *distinct foreign data* — e.g. another company's bundle name and payout company, not just a different ID echoed back.
- Use two controlled accounts; for write/delete BOLA, prove the mutation persisted by reading the object back with the owner's session.
- Confirm the backend check is actually absent: hidden buttons/UI restrictions are not authorization. Try the endpoint directly with a modified ID and no browser UI.
- Severity: cross-tenant access, bulk enumeration of all users' records, and ATO-enabling writes = **Critical**; private non-regulated reads and delete/DoS = **High**; non-sensitive metadata = **Medium**; non-enumerable UUID with no leak, or disabled deprecated API version = **Low/Informational**.
- Track coverage in an endpoint authorization matrix (method + path, ID type, authz check, test status, impact). Group findings by root cause (shared data-access module, ORM pattern) and add a regression test asserting 403/404 for cross-user access.

- Two controlled accounts are mandatory. A single-account test where youOnly change an ID and see "another record" can be a caching artifact or a shared-tenant object, not a real ownership break.
- Verify the object really belongs to the second account: compare owner fields, timestamps, and content with the owner's own view; a "different" record that is actually public/shared data is not BOLA.
- For cross-tenant findings, create two tenants and prove the isolation boundary explicitly — show data from tenant A fetched with tenant B's token, plus the same request failing when the tenant ID is removed.
- Check idempotency: a write BOLA that succeeds once but is blocked on repeat may be a race artifact; reproduce at least twice with fresh requests.
- Do not report "the API returns an ID I didn't expect" — BOLA requires using a client-supplied identifier to access/modify an object you are not authorized to touch.
- Beware false positives from predictable-but-public objects (public profiles, shared documents): confirm the data is actually private to the other user per the app's model.
- For delete/write BOLA, restore any test data afterwards and keep the PoC limited to your own test accounts; destructive proofs against real users are out of scope.
- Document the authorization matrix as evidence: one row per endpoint with the two sessions' status codes and body lengths makes the review trivial to reproduce.
- Severity escalation requires data sensitivity or breadth: a single non-sensitive metadata field is Medium at most; credentials, payment data, health data, or bulk enumeration push to Critical.

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/web-security/access-control/idor
2. https://www.decryptiondigest.com/blog/bola-idor-api-authorization-test-remediation
3. https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/session-management
