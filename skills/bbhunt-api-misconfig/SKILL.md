---
name: bbhunt-api-misconfig
description: "Hunt mass assignment, verb tampering, prototype pollution and schema-exposure flaws. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# API misconfiguration hunting — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### A. Discovery checklist — concrete places, params, headers, flows to look

- Reframe the hunt around **OWASP API3:2023 Broken Object Property Level Authorization (BOPLA)**, which formally merged *Excessive Data Exposure* (API3:2019) and *Mass Assignment* (API6:2019). BOLA = wrong object; BOPLA = right object, wrong *property* of it. Test both the read side (fields the API returns) and the write side (fields the API silently accepts).
- For every `GET /api/<resource>/<id>` (or list response), diff the returned JSON keys against the fields the UI actually renders. Each extra key is a candidate hidden/mass-assignable parameter: `id`, `isAdmin`, `role`, `email_verified`, `created_by`, `price`, `total_stay_price`, `blocked`, `org_id`, `tenant_id`, `owner_id`.
- Enumerate supported **methods** with `OPTIONS` and an Intruder verb list (`GET POST PUT PATCH DELETE HEAD TRACE`). API8:2023 explicitly calls out unnecessary verbs as misconfiguration. Note verb-level authz asymmetry: a `POST /admin/roles` may be blocked while `GET` (or a bogus verb like `POSTX`) with the same params is not.
- Try **method-override headers** when the proxy only allowlists verbs: `X-HTTP-Method-Override: PATCH`, `X-Method-Override: DELETE`, `X-Original-URL: /admin/...`, `X-Rewrite-URL: /admin/...`, `_method=PATCH` in form bodies. Some stacks apply authz to the outer verb but route on the override.
- Provoke **content-type differentials** (API8): resend the same JSON request as `application/xml`, `application/x-www-form-urlencoded`, `text/plain`, `multipart/form-data`, and with `+json` suffixes (`applica

### Techniques, payloads and bypasses

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Invalid-value oracle** (PortSwigger mass-assignment lab methodology): first send the suspected hidden field with a valid value, then with an invalid type (`"percentage": "x"`, `"isAdmin": []`). If the invalid value changes behavior (error/500) while the valid one is silently ignored, the field is being processed server-side. Escalate only then.
- Canonical PortSwigger checkout payload (hidden `chosen_discount` found only in the `GET` response, then injected into `POST /api/checkout`):
  ```json
  {"chosen_discount":{"percentage":100},"chosen_products":[{"product_id":"1","quantity":1}]}
  ```
  A `201 Created` + order-confirmation redirect proves the bound field changed business state.
- OWASP BOPLA scenario shapes worth mirroring: `{"approved":true,"comment":"...","total_stay_price":"$1,000,000"}` on `POST /api/host/approve_booking` (unauthorized price field) and `{"description":"...","blocked":false}` on `PUT /api/video/update_video` (unlock own censored content).
- **Framework-homeword field names** from the OWASP Mass Assignment Cheat Sheet: Spring `isAdmin`, Laravel `is_admin`, Mongoose `isAdmin`/`protect:true`, Rails `:admin`, plus `role`, `verified`, `permissions`, `email_verified`, `owner_id`, `account_balance`, `credit`. Always include the framework's native naming convention (`isAdmin` vs `is_admin` vs `admin`).
- **Type confusion in binding**: booleans accept `true`, `"true"`, `1`, `"1"`, `yes`; roles accept `["admin"]` or `{"role":"admin"}`; try arrays/objects where scalars are expe

### OData $filter / $select / $expand WAF-Blacklist Bypass (2024-2026 surface)

OData (Open Data Protocol) is the query layer behind **SharePoint, Microsoft Dynamics 365 / Power Platform, SAP NetWeaver Gateway / Fiori,** and any ASP.NET WebAPI project using `Microsoft.AspNetCore.OData`. It exposes SQL-shaped query operators (`eq`, `ne`, `and`, `or`, `substringof`, `startswith`, `tolower`, `concat`, `replace`) that look SQL-ish but are NOT SQL — meaning keyword-blacklist WAFs routinely fail open on OData traffic.

### Attack class 2 — `$orderby` / `$select` column-disclosure bypass

```
GET /api/data/v9.0/contacts?$orderby=emailaddress1 desc&$select=fullname
```

`$orderby` accepts column names the user has no `$select` permission for, but the engine still sorts on them — the returned order leaks the protected column. Column-level ACLs are enforced on the projection (`$select`) but NOT on `$orderby` / `$filter` — same protected column, different code path. Second Stratus finding in the same Dynamics 365 disclosure; "more dangerous than the first because it directly returned the data" per Stratus.

### Attack class 3 — `$batch` multipart/mixed → per-request WAF signatures miss sub-operations

```
POST /odata/$batch  Content-Type: multipart/mixed; boundary=batch_1
--batch_1
Content-Type: application/http
GET Users?$filter=1 eq 1 HTTP/1.1
--batch_1--
```

WAFs that scan only the outer request body (or that don't natively parse `multipart/mixed`) skip every inner operation. ModSecurity refused `multipart/mixed` historically ([Issue #3296](https://github.com/owasp-modsecurity/ModSecurity/issues/3296)); F5 added native batch parsing only in Advanced WAF v16.1 ([F5 SAP-Fiori advisory](https://www.f5.com/company/blog/securing-sap-fiori-http-batched-requests-odata-with-f5-advance)). The 2025 WAFFLED paper ([arXiv 2503.10846](https://arxiv.org/html/2503.10846v1)) generalises the parsing-discrepancy bypass class across 5 major WAFs.

### Attack class 4 — Encoded / non-canonical operator → keyword-blacklist bypass

```
GET /api?%24filter=Name%20eq%20'x'%20or%201%20eq%201   # URL-encoded $
GET /api?%2524filter=...                                # double-encoded
GET /Users(1)/$value                                    # path-segment style
```

Mixed-case operators (`Eq`, `EQ`) and obscure ones (`substringof`, `tolower`, `concat`, `replace`) look unlike `SELECT`/`UNION` so SQLi-keyword signatures never fire. WAFs that key on the literal string `$filter` see neither form — but the OData server normalises both before evaluating the predicate. Documented since Kalra Black Hat AD 2012; canonical OData-vs-WAF impedance mismatch. ([OWASP Double Encoding](https://owasp.org/www-community/Double_Encoding))

### Validation and proof

### C. Validation / proof bar — how to confirm and avoid false positives

- A declared field is **not** a finding. Prove state change: after adding `role=admin`, re-fetch `GET /api/users/me` (privileged field now true) **and** access one admin-only function. Two independent observations beat a single reflected value.
- Run the three-request triad on each candidate: (1) valid value → accepted, (2) invalid type → error/different behavior, (3) benign-but-distinct valid value → observable state or response change. Missing (2) usually means the field is ignored, not protected.
- Verify on a **second controlled account** as attacker → victim direction where relevant (e.g., set `owner_id` on your object to another user's ID, then confirm you can read/modify that object). Report exact IDs and raw request/response pairs.
- Guard against self-inflicted bugs: if the field only affects data you own and yields no privilege/tenant/business impact, it is often accepted-risk or informational. Apply the triage rule: show unauthorized access to another object/role, or a real monetary effect.
- Do not report a permissive `Access-Control-Allow-Origin` or an extra response field alone. Demonstrate credentialed cross-origin read (CORS skill) or a sensitive property that should not be readable (BOPLA read side).
- Watch for **false-positive field reflection**: a field echoed in the response does not prove it was *bound*. Test persistence across a new `GET`; verify the value survives a round trip and is not merely a client-supplied echo.
- Watch for **false-negative silent filtering**: if a valida

### Escalation and related chains

### Attack chains

**A. Spec disclosure → mass IDOR / BOLA.** Spec lists every `GET /api/v1/users/{userId}/...`. `jq '.paths | keys' swagger.json` → swap `{userId}` for victim's ID via Autorize/`ffuf -mc 200`. Common case: spec leaks `/api/admin/users/{id}/reset-password` documented but missing `[Authorize(Roles="Admin")]` on the controller — low-priv ATO.

**B. Spec disclosure → mass-assignment payload construction.** `components.schemas.UserUpdateDto` enumerates every model field including `isAdmin`, `emailVerified`, `tenantId`, `role`. Attacker copies the schema verbatim into `PATCH /users/me` and adds the privileged fields. Server's `[FromBody]` binder accepts them when DTOs aren't split into read-vs-write models.

**C. Hidden endpoints.** Specs document `/internal/*`, `/debug/*`, `/v0/*`, `/legacy/*` routes that no front-end UI references. Reachable but uncovered by WAF rules and often skipped during auth reviews.

**D. Swagger UI configUrl takeover.** Swagger UI loads its config from `?configUrl=`. If unsanitised, attacker hosts an evil OpenAPI spec, sends victim a link to the *legitimate* Swagger UI with `?configUrl=https://evil/spec.json`. Spec routes point back at the legitimate origin so the victim's "Try It Out" clicks fire same-origin authenticated requests. ([HackerOne #3124103 — U.S. DoD Swagger UI Injection, May 2025](https://hackerone.com/reports/3124103))

### Related Skills & Chains

- **`account-takeover`** — Mass assignment on signup/profile is the fastest path to admin. Chain primitive: API mass assignment + `account-takeover` → `role=admin` set on signup → ATO via privileged role on first login.
- **`auth-bypass`** — JWT flaws collapse the entire auth layer. Chain primitive: JWT `alg=none` + `auth-bypass` → impersonate any user by setting `sub` to victim ID, no signature required.
- **`rce`** — Prototype pollution gadgets in Node.js dependencies (lodash, mongoose, jQuery) reach `child_process.spawn`. Chain primitive: Prototype pollution (`__proto__.shell=true`) + `rce` (Node.js gadget chain) → RCE on the API node.
- **`subdomain-takeover`** — CORS regex with wildcard subdomain trusts a takeoverable host. Chain primitive: CORS allowlist `*.target.com` + subdomain takeover → attacker-controlled origin reads credentialed API responses.
- **`security-arsenal`** — Load the JWT Attack Payloads section (alg=none, kid path traversal, JWK injection, embedded JWK) and the Mass-Assignment Field Wordlist (`is_admin`, `role`, `verified`, `permissions`, `org_id`, `tenant_id`).
- **`triage-validation`** — Apply the Server-Policy-vs-State gate: a permissive CORS header alone is informational; demonstrate actual cross-origin credentialed read of sensitive data before reporting.

### Related Skills & Chains

- **`hunt-ato`** — Mass assignment on signup/profile is the fastest path to admin. Chain primitive: API mass assignment + `hunt-ato` → `role=admin` set on signup → ATO via privileged role on first login.
- **`hunt-auth-bypass`** — JWT flaws collapse the entire auth layer. Chain primitive: JWT `alg=none` + `hunt-auth-bypass` → impersonate any user by setting `sub` to victim ID, no signature required.
- **`hunt-rce`** — Prototype pollution gadgets in Node.js dependencies (lodash, mongoose, jQuery) reach `child_process.spawn`. Chain primitive: Prototype pollution (`__proto__.shell=true`) + `hunt-rce` (Node.js gadget chain) → RCE on the API node.
- **`hunt-subdomain`** — CORS regex with wildcard subdomain trusts a takeoverable host. Chain primitive: CORS allowlist `*.target.com` + subdomain takeover → attacker-controlled origin reads credentialed API responses.
- **`security-arsenal`** — Load the JWT Attack Payloads section (alg=none, kid path traversal, JWK injection, embedded JWK) and the Mass-Assignment Field Wordlist (`is_admin`, `role`, `verified`, `permissions`, `org_id`, `tenant_id`).
- **`triage-validation`** — Apply the Server-Policy-vs-State gate: a permissive CORS header alone is informational; demonstrate actual cross-origin credentialed read of sensitive data before reporting.

## Source skills merged into this topic

- `hunting` — `api-misconfig`
- `cbh` — `hunt-api-misconfig`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 1 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `references/unified-method.md` — includes 1 merged companion methodology documents
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
