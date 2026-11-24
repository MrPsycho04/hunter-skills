---
name: dispatch
description: Skill-set loader for /hunt orchestrator. Fingerprints the target, picks the right platform attack skills, and loads the Red Team or WAPT skill set. Use when /hunt has just received a mode answer (redteam or wapt + blackbox|greybox) and needs to load the appropriate skills and print the taxonomy. Not for direct user invocation.
---

# dispatch

skill-set loader for `/hunt`. one concept (which skills to load), one place.

## engagement context

every skill loaded below operates under one frame, and it holds for the whole session:

- **authorized and scope-bounded.** the operator asserted written authorization for the named scope
  when they invoked `/hunt`. testing stays inside it. an out-of-scope host ends the run — it does not
  widen it.
- **the output is a finding, not an exploit.** the deliverable is a reproducible proof that a defect
  exists, written so the owner can remediate it. enough to demonstrate impact; no further.
- **remediation is the point.** these skills exist so defects get fixed by the people who own them.

this frame is stated here because it is the choke point every `/hunt` run passes through before any
`specialist` skill loads. it is not a prompt and needs no answer.

invocation contract:

```
dispatch mode=redteam
dispatch mode=wapt box=blackbox
dispatch mode=wapt box=greybox
```

## step 0 — 404 baseline (ALL modes, mandatory, before any enumeration)

run this for **every** host before probing a single path. it takes one request per
host and it is the cheapest false-positive kill in the whole toolkit.

many modern estates (SPA / Next.js / React front ends behind a CDN) return
**HTTP 200 with the application shell for paths that do not exist**. a status code
therefore proves nothing. without a recorded control, `/.well-known/security.txt`,
`/api/revalidate`, `/__nextjs_original-stack-frame` and `/__nextjs_launch-editor`
all "exist" on a host where none of them do.

```bash
for H in $HOSTS; do
  # two independent bogus paths — if they agree, that IS the soft-404 signature
  for P in /zzz-nope-12345 /qqq-other-98765; do
    printf "%-34s %-20s " "$H" "$P"
    curl -sk -m 12 -o /tmp/b -w "%{http_code} %{size_download} " "https://$H$P"
    shasum /tmp/b | cut -c1-12
  done
done
```

record per host: **status, byte length, body hash**. that triple is the control.

**the rule: no path is "found" until its response differs from the control.**
a 200 that matches the control hash is a soft 404. a 404 whose body differs from
the control may be a real handler. compare bodies, never status codes alone.

re-derive the baseline per host — it differs across an estate. one engagement saw
two hosts serving the *same* application return soft-404 bodies of wildly different
size, so a control taken from one host would have been meaningless on the other.
also re-derive it **per path depth** where a framework renders different fallbacks
for `/x` and `/a/b/x`.

edge pages are not origin findings: a CDN "Access Denied" / "Unsupported Request"
body means the request never reached the application. classify it as edge
behaviour and move on.

## step 1 — fingerprint (red team only)

fingerprint **every** live host, not just the apex. for multi-host / wildcard
targets the platform-skill routing must be driven by all banners, not one host's.

use `-L` (follow redirects) — identity-provider and CDN signals
(`login.microsoftonline.com`, `okta`, `auth0`, CDN banners) routinely sit
behind a 30x, so a no-redirect `curl -sI` silently misses those matches. pull
both headers and the landing-page HTML (`__NEXT_DATA__`, `VIEWSTATE`,
`laravel_session`, `Ignition`, framework markers live in the body, not headers).

```bash
HOSTS="$TARGET"
if [ -f "recon/$TARGET/live-hosts.txt" ]; then
  HOSTS=$(cat "recon/$TARGET/live-hosts.txt")
fi
for H in $HOSTS; do
  echo "=== $H ==="
  # -L follow redirects, -D - dump headers, -o body; cap body to keep context small
  curl -sSL -m 12 -D - -o /tmp/fp_body "https://$H" 2>/dev/null | tr -d '\r'
  # surface body-only platform markers
  grep -aoE '__NEXT_DATA__|/_next/|VIEWSTATE|rO0[AB]|laravel_session|Ignition|Telescope|Whitelabel|/actuator|application/grpc|socket\.io|swagger|\.js\.map' \
    /tmp/fp_body | sort -u
done
rm -f /tmp/fp_body
```

if `live-hosts.txt` is absent, the loop still runs once against `$TARGET`. record
which signal came from which host — a platform skill matched on host B does not
imply host A runs that stack.

look for the following signals → platform skill mapping:

```
okta.com | auth0.com | pingidentity         →  okta-attack
login.microsoftonline.com | outlook | sts   →  m365-entra-attack
pulse | fortinet | ivanti | citrix          →  enterprise-vpn-attack
vsphere | vcenter | :9443                   →  vmware-vcenter-attack
amazonaws | azure | googleapis | gcp        →  cloud-iam-deep
github.com/<org>/                           →  supply-chain-attack-recon
.apk | play.google.com                      →  apk-redteam-pipeline
MongoDB | mongoose | CouchDB | Redis        →  nosqli
?page= | ?file= | ?path= | php wrapper      →  path-traversal
rO0A | VIEWSTATE | rememberMe cookie        →  deserialization
Access-Control-Allow-Origin header          →  cors
/forgot-password | /reset | X-Forwarded    →  host-header
?redirect= | ?next= | ?return= | ?url=     →  open-redirect
OTP | /verify | /2fa | no-rate-limit        →  brute-force
Set-Cookie session | PHPSESSID              →  session
Active Directory | LDAP | OpenLDAP | ADFS  →  ldap
__NEXT_DATA__ | /_next/ | buildId           →  nextjs
X-Powered-By: Express | Node.js | .js stack →  nodejs
postMessage | dangerouslySetInnerHTML        →  dom
WebSocket | ws:// | socket.io               →  websocket
gRPC | :50051 | application/grpc            →  grpc
laravel_session | Ignition | Telescope       →  laravel
X-Application-Context | Whitelabel | /actuator → springboot
:6443 | :10250 | :2379 | kubectl            →  k8s
.github/workflows | Jenkins | GitLab CI     →  cicd
.js.map | swagger.json | /.env              →  info-disclosure
HSTS missing | SPF | DMARC | AXFR           →  tls-network
```

### conflict resolution & load budget

real targets almost always return multiple signals at once — e.g. a single host
can show Cloudflare (CDN) + `login.microsoftonline.com` (redirect) + `__NEXT_DATA__`
(Next.js front end) + `amazonaws` (origin) simultaneously. loading every match
blindly can pull 20-plus skills and blow the context window, drowning the
high-signal skill in noise. apply this precedence and cap:

**priority order (load highest tiers first, stop at the cap):**

```
tier 1  identity / SSO fabric    okta-attack, m365-entra-attack
        (own the auth boundary — highest blast radius if compromised)
tier 2  perimeter appliances     enterprise-vpn-attack, vmware-vcenter-attack
        (pre-auth RCE / direct internal foothold)
tier 3  cloud / IAM              cloud-iam-deep, cloud-misconfig
        (credential → lateral movement)
tier 4  app framework / stack    nextjs, nodejs, laravel,
        springboot, aspnet, sharepoint
tier 5  protocol / class signals nosqli, path-traversal, deserialization,
        cors, host-header, open-redirect, grpc,
        websocket, dom, k8s, cicd, info-disclosure,
        tls-network, ldap, brute-force, session
```

**load budget: cap platform-skill loads at 8.** if more than 8 match, keep the
highest-tier 8 and drop the rest; print the dropped ones under
`deferred:` in the taxonomy block so they can be loaded on demand later.

**de-dup rules (avoid loading two skills for the same evidence):**

- CDN banner alone (Cloudflare/Akamai/Fastly) is **not** a platform match — it
  fingerprints the edge, not the app. do not load a skill for it; note it for
  `web-cache` / `request-smuggling`, which the mode set already carries.
- `amazonaws` / `azure` / `googleapis` in a **header/origin** → `cloud-iam-deep`.
  the same string found as a **leaked key/JSON in a JS bundle or APK** → still
  `cloud-iam-deep`, but flag it as a live-credential lead (higher priority, tier 3
  becomes tier 1 for that host).
- a framework marker (`__NEXT_DATA__`, `laravel_session`) and a generic class
  signal (`?redirect=`, `Access-Control-Allow-Origin`) on the same host → load the
  framework skill (tier 4) and keep the class skill **only if budget remains**;
  the WAPT/redteam mode set already loads the common class skills unconditionally.

## step 2 — load skill set

invoke each skill in order via the Skill tool.

### mode=redteam

always-on (load first):

```
redteam-mindset
mid-engagement-ir-detection
```

platform (load second, conditional on fingerprint matches from step 1):

```
okta-attack
m365-entra-attack
enterprise-vpn-attack
vmware-vcenter-attack
cloud-iam-deep
supply-chain-attack-recon
apk-redteam-pipeline
```

high-impact specialist set (load third):

```
rce
sqli
ssrf
account-takeover
auth-bypass
saml
oauth-oidc
mfa-and-passwords
file-upload
request-smuggling
cloud-misconfig
sharepoint
aspnet
```

report format: `redteam-report-template` (subject / observations / description / impact / recommendation / poc).

### mode=wapt

always-on:

```
bb-methodology
security-arsenal
triage-validation
```

full specialist set (all OWASP-relevant):

```
xss             sqli            ssrf            idor
csrf            xxe             rce             graphql
oauth-oidc           saml            mfa-and-passwords      auth-bypass
account-takeover             file-upload     logic-and-design  race-condition
llm-ai          api-misconfig   ssti            web-cache
request-smuggling  subdomain-takeover       cloud-misconfig misc
aspnet          sharepoint      ntlm-info
path-traversal             nosqli          deserialization
cors            host-header     open-redirect
brute-force     session         ldap
nextjs          nodejs          dom
websocket       grpc            laravel
springboot      k8s             cicd
info-disclosure     tls-network
```

report format: `report-writing` (`bugcrowd-reporting` if the target is on bugcrowd).

box=greybox: creds already captured by `/hunt`, available in session memory.

**do not fan out across the authenticated hunt-\* set until the creds are
validated.** `/hunt` only prompts for and stores creds (commands/hunt.md) — it
does not confirm they work. firing every authenticated test with dead, MFA-gated,
or wrong-role creds wastes the whole run and produces false "no auth surface"
conclusions. run a single low-cost auth preflight first:

```bash
# session-cookie creds: one authenticated GET against an identity echo endpoint
curl -sS -m 12 -b "$SESSION_COOKIE" "https://$TARGET/api/me" -w '\n%{http_code}\n'
#   200 + your username/email  → live session, role visible in body
#   401/403                    → dead or insufficient — STOP, re-auth

# bearer/JWT creds: same probe with Authorization
curl -sS -m 12 -H "Authorization: Bearer $TOKEN" \
  "https://$TARGET/api/me" -w '\n%{http_code}\n'

# raw user/pass: drive the real login flow once, capture Set-Cookie, then echo
#   watch for an MFA / step-up challenge in the response — if present, the creds
#   alone do not yield an authenticated session (see memory: operator-capability)
```

confirm three things from the preflight, and record them for the hunt-\* skills:

1. **live** — auth probe returns 200, not 401/403.
2. **role/privilege** — the `/api/me` (or equivalent) body shows the expected
   role/tenant/scopes. IDOR and authz tests need a known baseline identity; a
   silently-admin or silently-readonly cred skews every authz finding.
3. **not MFA-gated** — login did not stop at a 2fa/step-up challenge. if it did,
   you hold creds but **not** a session — default to least capability and confirm
   with the operator before claiming authenticated reach.

if the preflight fails, do **not** silently continue as blackbox — surface
"greybox creds did not validate (HTTP {code} / MFA challenge)" so the operator
can re-supply. only after a clean preflight: apply the validated session to every
authenticated test.

## step 3 — taxonomy print (once, at session start)

emit a deterministic block. plain text, lowercase, colon-delimited, no decoration.

### mode=redteam

```
loaded for red team: {N} skills
  mindset:    redteam-mindset
  platform:   {fingerprint-matched skills (<=8, tier order), or "none detected"}
  deferred:   {platform skills past the 8-cap, or omit line if none}
  auth:       account-takeover, auth-bypass, saml, oauth-oidc, mfa-and-passwords
  inj:        rce, sqli, ssrf, file-upload
  infra:      request-smuggling, cloud-misconfig
  stack:      sharepoint, aspnet
  ir:         mid-engagement-ir-detection
```

### mode=wapt

```
loaded for wapt ({blackbox|greybox}): {N} skills
  inj:        xss, sqli, ssrf, rce, xxe, ssti, file-upload
  authz:      idor, auth-bypass, account-takeover
  auth:       oauth-oidc, saml, mfa-and-passwords
  api:        graphql, api-misconfig
  logic:      logic-and-design, race-condition
  infra:      request-smuggling, web-cache
  recon:      subdomain-takeover
  cloud:      cloud-misconfig
  ai:         llm-ai
  stack:      aspnet, sharepoint, ntlm-info
  misc:       misc, csrf
  reporting:  bb-methodology, security-arsenal, triage-validation
```

## subagent scope inheritance

if any part of the hunt is delegated to subagents, scope does **not** inherit
implicitly. every subagent prompt must carry:

1. **the authorized host list, verbatim, as data.** not "the target estate", not
   "*.target.com" — the explicit list. a subagent cannot infer the boundary.
2. **the discovered-host rule:** hosts found mid-run (via CT logs, CSP headers,
   JS bundles, CNAME chains, error messages) are **report-only**. resolve DNS,
   record, hand back. never probe, never write, until the operator re-authorizes.
3. **a deny-list of action-executing endpoints, applied BEFORE any allow-list.**
   deny by verb-in-name first: `refund`, `settle`, `payout`, `transfer`, `adjust`,
   `disburse`, `create`, `update`, `delete`, `rotate`, `reset`, `send`, `initiate`,
   `generate`, `process`. only then allow read-shaped names. order matters —
   a path like `refund/batch/status` matches the read-shaped keyword "status"
   but is a refund route; an allow-list applied first would probe it.
4. **"read-only" spelled out as forbidden verbs**, not as an adjective. "read-only"
   is routinely interpreted as "don't be destructive", which does not stop an agent
   sending `{}` to an endpoint whose name starts with `generate*` and creating a
   real record on production.

**lesson from an authorized engagement:** a subagent was told READ-ONLY and still
(a) created a live record on production because it expected `{}` to return a
validation error, and (b) wrote an object to a cloud bucket that was never on the
authorized list — one the parent prompt had named only for a DNS check. both were
disclosed in the deliverable. the fix is structural: pass scope as data, deny
by verb before allowing by verb, and treat every discovered host as out of scope
until told otherwise.

## step 4 — return control to /hunt

after taxonomy print, hand control back to `/hunt` for step 3 (sibling delegation) and step 4 (active testing). do not run probes here — this skill only loads context.

## privacy

never echo back, log, or persist:
- SOW / scope-of-work / engagement-letter content
- grey box credentials (kept in session memory by `/hunt`, never written to disk)
- client identifiers in user-level memory

---

## Related Skills & Chains

- **`bb-methodology`** — When PART 0 mode confirmation completes. Workflow primitive: `bb-methodology` confirms engagement type (red team vs WAPT vs bug bounty); the answer feeds directly into this skill's `mode=redteam` / `mode=wapt` invocation.
- **`redteam-mindset`** + **`mid-engagement-ir-detection`** — When `mode=redteam` is loaded. Workflow primitive: these are the always-on skills loaded first by step 2 of the redteam flow before any platform skill or specialist skill.
- **`okta-attack`** / **`m365-entra-attack`** / **`enterprise-vpn-attack`** / **`vmware-vcenter-attack`** / **`cloud-iam-deep`** / **`supply-chain-attack-recon`** / **`apk-redteam-pipeline`** — When fingerprint signals match. Workflow primitive: step 1's curl fingerprint scan against `recon/<target>/live-hosts.txt` maps banner / domain signals to one or more of these platform skills.
- **`rce`** / **`sqli`** / **`ssrf`** / **`account-takeover`** / **all other specialist skills`** — When the mode-specific skill set is being printed. Workflow primitive: this skill is the loader; it names the specialist skills but does not run probes — actual hunting happens after step 4 returns control to `/hunt`.
- **`report-writing`** vs **`redteam-report-template`** — When the taxonomy print specifies the report format. Workflow primitive: `mode=wapt` ends with `report-writing` as the deliverable format; `mode=redteam` ends with `redteam-report-template` instead.
