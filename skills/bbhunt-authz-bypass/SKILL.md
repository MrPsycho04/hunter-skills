---
name: bbhunt-authz-bypass
description: "Use for missing function-level authorization, vertical privilege escalation, tenant isolation breaks and admin functionality reachable by a lower role. Unified from 2 upstream skills (h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Authorization and Access-Control Bypass — unified methodology

> **Unified skill.** Built from 2 upstream skills across h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus-backed method (this class)

1. Build a role/permission matrix: anonymous, user, admin, service; map which functions each should reach.
2. Enumerate function-level endpoints from JS, docs, error messages, and versioned API paths; privileged functions often lack a UI.
3. Test every privileged function with the lowest-privilege account; use method and content-type variations where routing differs.
4. Look for client-supplied authorization context: role in body, headers, JWT claims, or query params that the server trusts.
5. Try mass assignment of privileged fields (isAdmin, role, permissions) on profile/update endpoints.
6. Test path normalization and middleware ordering: `/admin/..;/`, double slashes, trailing dots, encoded separators, static-asset prefixes.
7. Prove the consequence of the bypass — a privileged state change or data read — not just that the route responded.

### Signals

- Admin or internal routes visible in JS bundles or docs
- Role, scope or tenant values supplied by the client
- Non-production endpoints that behave differently from production
- A function that checks identity but not permission

### Kill criteria

- The route is unreachable without credentials an attacker cannot obtain.
- Admin UI visibility alone with the function correctly enforced server-side.
- Response differs but no privileged action or data is obtained.

### Escalation chains

- Mass-assigned role -> admin function -> broader compromise.
- Non-production endpoint in scope -> weaker auth -> production data access.
- Authz bypass -> invite/member management -> persistent access.

### Veteran tip

Admin-context testing is the top corpus technique for this class; the bug is usually a missing check on a function, not a clever payload.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Build a role matrix (anon, user, member, admin, support) and replay every request across roles.
- Try admin endpoints and hidden routes found in JS bundles, mobile apps, and API docs.
- Test org/tenant boundaries with two accounts on different plans.
- Check function-level authz: the UI hides it, but does the API enforce it?
- Replay requests after removing cookies, tokens, and role headers.

### Deeper checklist

- Build a role matrix (anon, user, org member, admin, support) and replay every request across roles.
- Swap object identifiers (numeric, UUID, slug, base64) and test cross-tenant access.
- Try HTTP method swaps (GET/POST/PUT/PATCH/DELETE) and hidden admin routes from JS bundles.
- Test parameter pollution and mass assignment on role/org/owner fields.
- Check GraphQL/REST resolvers individually; list endpoints often leak more than detail endpoints.
- Look for client-side-only checks: disabled buttons, hidden menus, local role flags.
- Test invitation, transfer, export, and billing flows for cross-org actions.
- Verify impact with a second account you control; capture both identities and responses.

### A. Discovery checklist — concrete places, params, headers, flows to look

- Build an identifier inventory before testing. Classify every object reference: sequential integers (`user_id=1234`, `order_id=5678`), UUIDs/GUIDs, Base64/MD5 hashed IDs, Mongo ObjectIDs, and composite keys. Sequential IDs are trivially enumerable; UUIDs are safe only if never leaked elsewhere (list endpoints, public object responses, logs).
- Search all identifier locations: URL path (`/api/v1/orders/{id}`), query string (`?id=`, `?user_id=`, `?customer_number=`), JSON body (`{"userId":...}`), headers (`X-User-Id`, `X-Tenant-Id`), cookies, WebSocket topics, GraphQL variables/global `node()` IDs, and static files (`/static/12144.txt` chat transcripts — PortSwigger IDOR example).
- Include write/delete surfaces in the map, not just reads: `PUT`/`PATCH`/`DELETE` variants, import/export and download endpoints, attachment and invoice IDs, and role/permission parameters (`role_id`, `permission_id`) for privilege escalation.
- Multi-tenant SaaS: create accounts in two orgs and look for `organizationId`, `workspace_id`, `account_id`, `team_id`. Tenant-isolation breaks are the highest-impact BOLA variant.
- Burp workflow (PortSwigger): capture requests as a low-privileged user, add a session-handling rule with that user's cookie, then re-request the entire site map; use Authorize / AuthMatrix / AuthZ extensions to replay each request with a second session and flag where the second session still gets a 200.
- Benchmark "not found" vs "forbidden" vs genuine success responses by response length, status, and

### Signals and surfaces

### Signal

- Reports: **1,386** · paid: **337**
- Median bounty **$500** · p90 **$2,500** · max **$35,000** · total **$484,104**
- Median upvotes **20**

### Where it pays

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

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`role` `admin` `permission` `org` `team` `account` `tenant` `owner` `visibility` `public` `internal`

### Techniques, payloads and bypasses

### Payloads & probes

- Role fields -> `role=admin`, `is_admin=true`, `plan=enterprise`, `permissions=["*"]`
- Headers -> `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For: 127.0.0.1`, `X-User-Id`
- Path tricks -> `/admin/../user`, `/admin%2f..%2f`, `/.;/admin`, trailing slash
- Method swap -> GET->POST->PUT->DELETE, `X-HTTP-Method-Override`

### Bypass tricks

- Middleware path-normalization mismatch: `/admin/..;/`, `%2e%2e`, double slashes.
- Header spoofing for IP allowlists and internal-only endpoints.
- GraphQL/REST resolver differences: one enforces authz, the other does not.
- Stale permissions after role change or org removal.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Account Takeover via Password Reset without user interactions** — `#2293343` · GitLab · $35,000 · ▲989
  > Forward the requests and you should get an email containing the reset link that was send to both emails (``victim@gmail.com`` and ``attacker@gmail.com``) .
- **[Part II] Email Confirmation Bypass in myshop.myshopify.com that Leads to Full Privilege Escalation** — `#796808` · Shopify · $0 · ▲894
  > - Cannot integrate across stores/partner even they share the same email address after confirming them
- **Exfiltrate and mutate repository and project data through injected templated service** — `#446585` · GitLab · $11,000 · ▲762
  > Replace `CiService` in the `services` array with `MockCiService`
- **Email address of any user can be queried on Report Invitation GraphQL type when username is known** — `#792927` · HackerOne · $0 · ▲671
  > gid://hackerone/Report/626371 (here 626371 my test program's report id) convert it into base 64, replace that id with the "report id" in the above graphql query
- **Getting all the CD keys of any game** — `#391217` · Valve · $20,000 · ▲638
  > Using the `/partnercdkeys/assignkeys/` endpoint on partner.steamgames.com with specific parameters, an authenticated user could download previously-generated CD keys for a game which they would not normally have access.
- **Ability to reset password for account** — `#322985` · Upserve · $0 · ▲637
  > POST https://hq.breadcrumb.com/api/v1/password res

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 5× | `victim@ato.com` |
| 4× | `%TEMP%` |
| 3× | `@hackerone.com` |
| 3× | `../../app0/bdjstack/lib/ext/00000.jar` |
| 3× | `../../` |
| 3× | `The HEY Team <support@hey.com>` |
| 3× | `support@hey.com` |
| 3× | `POST /index.php/apps/groupfolders/folders/{id}/groups` |
| 3× | `postmaster@email.mg.gitlab.com` |
| 3× | `%temp%\Acronis\DriverSetup\inst.log` |
| 3× | `get_editable_roles()` |
| 3× | `wp_ensure_editable_role()` |
| 3× | `setuid()` |
| 2× | `victim@gmail.com` |
| 2× | `attacker@gmail.com` |
| 2× | `demo-member@hackerone.com` |
| 2× | `%0d%0a` |
| 2× | `j@hackerone.com` |
| 2× | `0xacb@hackerone.com` |
| 2× | `https://cdn.kastatic.org/khanacademy/khanacademy.<hash>.js.map` |

### [Part II] Email Confirmation Bypass in myshop.myshopify.com that Leads to Full Privilege Escalation

`#796808` · Shopify · $0 · critical · 2020-04-01 · ▲894
> In 791775, I submitted a bug at Sunday 5pm Canada time, it was triaged two hours later, and I got the temp fix message at around 3am the next day in Canada time. Truly awesome, the next day I retested after the first fix, and found that I - Cannot receive the email confirmation in the email used to sign up - Cannot integrate across stores/partner even they share the same email address after confirming them And the report was later resolved after I…

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- The five scenarios covering most of the BOLA surface (OWASP API1:2023 / CWE-639): (1) read another user's object with your session, (2) write/modify it — email change = ATO, (3) delete it (DoS capability), (4) cross-tenant substitution, (5) role/permission ID swap for horizontal privilege escalation.
- Horizontal IDOR: `/customer_account?customer_number=132355` → change the number (PortSwigger). Vertical/function-level (BFLA): invoke an admin action by path or verb change. Unauthenticated IDOR: any anonymous user's objects.
- Sniper Intruder over adjacent numeric IDs; Cluster Bomb for multi-ID objects. Sort by response Length — a distinctly longer body usually means another user's data was returned. If you can view it, also test edit and delete (real 2025 writeup: viewing → editing → deleting another company's punch tickets by changing one URL number).
- Platform-layer bypass via header spoofing: use `TRACE /admin` to discover `X-Custom-IP-Authorization`, then set `X-Custom-IP-Authorization: 127.0.0.1` via Match-and-Replace to reach the admin panel (PortSwigger information-disclosure lab).
- Mass-assignment overlap: add `{"role":"admin","is_admin":true,"verified":true,"owner_id":<victim>}` to profile/reset requests; combine with `role_id` substitution for privilege escalation.
- Format/parser bypasses: switch Content-Type between JSON/form/XML, use array injection (`id[]=`, Ruby/Rails `param[key]` → nil during partial-construction windows), non-normalized paths (`/oauth/../anything`), and duplic

### Validation and proof

### Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

### C. Validation / proof bar — how to confirm and avoid false positives

- `200 OK` is not proof. Inspect the response body delta and show *distinct foreign data* — e.g. another company's bundle name and payout company, not just a different ID echoed back.
- Use two controlled accounts; for write/delete BOLA, prove the mutation persisted by reading the object back with the owner's session.
- Confirm the backend check is actually absent: hidden buttons/UI restrictions are not authorization. Try the endpoint directly with a modified ID and no browser UI.
- Severity: cross-tenant access, bulk enumeration of all users' records, and ATO-enabling writes = **Critical**; private non-regulated reads and delete/DoS = **High**; non-sensitive metadata = **Medium**; non-enumerable UUID with no leak, or disabled deprecated API version = **Low/Informational**.
- Track coverage in an endpoint authorization matrix (method + path, ID type, authz check, test status, impact). Group findings by root cause (shared data-access module, ORM pattern) and add a regression test asserting 403/404 for cross-user access.

- Two controlled accounts are mandatory. A single-account test where youOnly change an ID and see "another record" can be a caching artifact or a shared-tenant object, not a real ownership break.
- Verify the object really belongs to the second account: compare owner fields, timestamps, and content with the owner's own view; a "different" record that is actually public/shared data is not BOLA.
- For cross-tenant findings, create two tenants and prove the isolation boundary explicitly —

### Escalation and related chains

### Escalation chains

- Authz bypass -> admin panel -> data export.
- Privilege escalation -> cross-tenant access.
- Unauth endpoint -> internal API -> RCE.

### Tools and wordlists

### Tools

`Autorize` · `Burp` · `ffuf` · `nuclei` · `jwt_tool`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_authz-bypass.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_authz-bypass.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_authz-bypass.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_authz-bypass.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

### Nuclei

Nuclei cannot infer your object model. Use tags for exposed admin panels, then build a manual role/object matrix.

```sh
nuclei -u https://target -tags idor,authorization,exposure \
       -severity low,medium,high,critical -rl 40 -o nuclei_authz-bypass.txt
nuclei -u https://target -t ~/nuclei-templates/http/exposures \
       -rl 40 -o nuclei_authz-bypass_exposures.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Source skills merged into this topic

- `h1skills` — `hackerone-authz-bypass`
- `hunting` — `authz-bypass`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 2 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `../../upstream/` — complete unmodified archives of all five source repositories
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
