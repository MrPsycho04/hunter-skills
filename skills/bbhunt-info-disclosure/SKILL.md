---
name: bbhunt-info-disclosure
description: "Use for sensitive data exposure: debug files, stack traces, source maps, secrets, public buckets, directory listings, logs, cache, and PII in unexpected responses. Unified from 2 upstream skills (h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Information Disclosure — unified methodology

> **Unified skill.** Built from 2 upstream skills across h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus-backed method (this class)

1. Check the public UI in incognito first — data already visible there is not a disclosure.
2. Enumerate debug/config/backup surfaces: actuator, telescope, status, env, logs, .git, .env, .DS_Store, swagger, source maps.
3. Classify what was exposed: credentials, tokens, PII, internal architecture, or source. The sensitivity determines severity.
4. Compare anonymous vs authenticated vs another-role responses for the same endpoint; the delta is often the bug.
5. Probe headers and caches: error pages, CDN-cached authenticated responses, and unkeyed headers that leak data to another user.
6. When a secret is found, demonstrate what it unlocks before reporting; a string alone is weak.
7. Redact all third-party data in evidence and access only the minimum needed to prove sensitivity.

### Signals

- Verbose errors, debug endpoints, status pages, backup files
- Secrets/tokens in JS bundles, config, or repo metadata
- Public storage buckets, directory listings, or unauthenticated APIs
- Data in responses that the UI does not show to that role

### Kill criteria

- Information is already public or intentionally disclosed by the program.
- Only a version banner, framework name, or generic stack trace with no actionable detail.
- Secret is invalid/revoked and unlocks nothing.

### Escalation chains

- Source-map secret -> API access -> cross-tenant data.
- Debug endpoint -> cloud credential -> infrastructure access.
- Public bucket -> JS bundles -> client secret -> OAuth chain.

### Veteran tip

Public source-code/repo review and admin-context comparison lead the valid writeups; use them before broad file brute force.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Fuzz for debug endpoints: /debug, /actuator, /health, /metrics, /graphql, .env, .git, source maps.
- Check error handling for stack traces, SQL errors, internal hosts, and versions.
- Look for extra fields, deleted records, internal notes, PII, tokens in API responses.
- Enumerate cloud storage, backups, DB dumps, log archives, CI artifacts.

### Deeper checklist

- Fuzz for debug endpoints: /debug, /actuator, /health, /metrics, /graphql introspection, .env, .git, source maps.
- Check error handling: stack traces, SQL errors, internal hostnames, framework versions, request IDs.
- Look for object leaks in API responses: extra fields, deleted records, internal notes, PII, tokens.
- Enumerate cloud storage and backups: S3/GCS/Azure buckets, DB dumps, log archives, CI artifacts.
- Test cache and CDN behavior for private content leakage across users or regions.
- Check JS bundles for hardcoded keys, internal URLs, feature flags, staging hosts.
- Compare responses across roles and unauthenticated requests for over-exposure.
- Verify the data is genuinely sensitive and not intended public data before reporting.

### A. Discovery checklist — concrete artifacts, endpoints, patterns, tools to look for

- **Build a channel map first:** web, API, GraphQL, WebSocket, gRPC, mobile, background jobs, exports, and CDN. Information leaks surface while testing something else — avoid tunnel vision (PortSwigger).
- **DVCS/build artifacts:** `/.git/HEAD`, `/.git/config`, `/.git/index`, `/.git/COMMIT_EDITMSG`, `/.git/refs/heads/main`, `/.svn/entries`, `/.hg/hgrc`, `/.env`, `.bak`, `.swp`, archives, `package.json`, `/.next/`, build manifests. `httpx -path /.git/HEAD -mc 200` across the live-host list is the fast sweep.
- **Source maps:** append `.map` to every external JS path (`/static/js/main.chunk.js.map`); OWASP WSTG-INFO-05 cites this explicitly. Look for `sources` with absolute paths (`/home/sysadmin/.../src/actions/cashoutAction.js`) and `sourcesContent`.
- **API schema/introspection endpoints:** `/swagger`, `/api-docs`, `/openapi.json`, `/api/swagger/v1`, `/swagger/v1/swagger.json`, `/redoc`, `/docs`, `.well-known/openapi.json`; GraphQL introspection; gRPC server reflection on gRPC ports. Check for prefilled bearer tokens in served Swagger UI HTML.
- **Next.js-specific artifacts:** `/_next/static/<buildId>/_buildManifest.js`, `__NEXT_DATA__`, `.next/routes-manifest.json`, `.next/server/pages/api/auth/[...nextauth].js` (compiled NextAuth config with fallback passwords), `next.config.js`. With `productionBrowserSourceMaps` enabled, `createServerReference(...)` entries map `Next-Action` hashes to function names.
- **Client env leakage:** `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_` inlined literals; 

### Signals and surfaces

### Signal

- Reports: **1,827** · paid: **339**
- Median bounty **$500** · p90 **$2,500** · max **$40,000** · total **$418,640**
- Median upvotes **11**

### Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| HackerOne | 156 | $98,650 | 11273 |
| Uber | 47 | $47,600 | 2067 |
| Snapchat | 6 | $41,000 | 1282 |
| Mail.ru | 136 | $34,350 | 1894 |
| Internet Bug Bounty | 35 | $28,998 | 751 |
| Shopify | 45 | $27,902 | 1327 |
| GitLab | 32 | $26,300 | 1725 |
| X / xAI | 30 | $15,710 | 1172 |

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`debug` `actuator` `health` `metrics` `env` `backup` `export` `logs` `graphql`

### Crown Jewel Targets

Source map exposing TypeScript source = see all API routes, auth logic, secrets. Swagger/OpenAPI JSON = complete API surface map.

**Highest-value findings:**
- **`.js.map` source maps** — reconstruct full TypeScript/ES6 source code → find hardcoded API keys, internal endpoints, auth logic bypasses
- **`swagger.json` / `openapi.json`** — complete REST API specification with all endpoints, parameters, auth schemes, and internal route names
- **`.env` / `.env.production`** — APP_KEY, DB_PASSWORD, API_KEY, SECRET_KEY in plaintext
- **`.git/` exposure** — `git clone` the entire source history → all past hardcoded secrets
- **`asset-manifest.json` / `_next/static/`** — all JS bundle paths → systematic source map discovery
- **`build-info` / `info.json`** — git commit hash, build timestamp, dependency versions → CVE targeting

---

### Techniques, payloads and bypasses

### Payloads & probes

- `/.git/config` `/.env` `/.DS_Store` `/server-status` `/actuator/env`
- `/api/v1/users?limit=1000` `/api/v1/users/0`
- `?fields=all` `?expand=*` `?include=deleted`
- S3 -> `https://bucket.s3.amazonaws.com/?list-type=2`

### Bypass tricks

- Bypass auth on static/debug paths with path normalization.
- Use GraphQL introspection and field suggestions.
- Check cache headers for private data.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Confidential data of users and limited metadata of programs and reports accessible via GraphQL** — `#489146` · HackerOne · $0 · ▲1033
  > The GraphQL endpoint doesn't have access controls implemented properly.
- **Sensitive user information disclosure at bonjour.uber.com/marketplace/_rpc via the 'userUuid' parameter** — `#542340` · Uber · $0 · ▲643
  > Public API endpoint leaked mobile API token of a user by passing driver uuid/rider uuid in the request.
- **The /reports/:id.json endpoint discloses potentially sensitive user attributes when reporter summary is present** — `#3000510` · HackerOne · $0 · ▲625
  > The.json endpoint of any disclosed report is leaking reporter's email, OTP backup codes, reporter's phone number, "graphql secret token", tshirt size all the reporter account's internal details etc.
- **Customer private program can disclose email any users through invited via username** — `#807448` · HackerOne · $7,500 · ▲589
  > `{"data":{"team":{" id":"47388","handle":"hackerone h1p bbp3","soft launch invitations":{"total count":5,"nodes":[{"token":"████████"},{"token":"███"},{"token":"████"},{"token":"██████"},{"token":"████████"}]}}}}`
- **Access to multiple production Grafana dashboards** — `#663628` · Snapchat · $10,000 · ▲464
  > Furthermore one of the custom modules was vulnerable to SQL Injection.
- **Open prod Jenkins instance** — `#231460` · Snapchat · $15,000 · ▲436
  > Once logged in, they gained access t

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 6× | `acf_get_posts()` |
| 6× | `is_trusted_daemon()` |
| 5× | `try_to_connect_and_handshake_with_new_peer()` |
| 4× | `rescan_spent()` |
| 3× | `connections_maker()` |
| 3× | `curl_easy_reset()` |
| 3× | `\x00` |
| 3× | `data->state.referer` |
| 3× | `wallet2::rescan_spent()` |
| 2× | `jdh34k' and 1=0 union all select 1,2,3;--` |
| 2× | `doSearch()` |
| 2× | `{id}` |
| 2× | `<feature.flag>` |
| 2× | `<REDACTED>` |
| 2× | `{F_number_file}` |
| 2× | `fetch()` |
| 2× | `https://fetlife.com/events/{event-id}` |
| 2× | `curl -XPOST -H 'Content-Type: application/json' -d ‘{"solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution", "parameter` |
| 2× | `/wp-json/wp/v2/sensei-messages/<numericID>` |
| 2× | `get_outgoing_connections_count()` |

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **.git exposure → full source reconstruction:** confirm with `/.git/config` and `/.git/HEAD` returning the expected content shape, then `git-dumper victim/.git/ ./dump`, `git checkout -- .`, `git log --graph --oneline --decorate --all`, `git config -l`, `ls .git/hooks`. Deleted-but-not-purged secrets live in history (rotated Stripe keys, bcrypt hashes reused in prod). Note: 403 on `/.git/` still means the directory exists; 404 means it does not.
- **Source-map rebuild:** fetch the `.map`, iterate `sources`/`sourcesContent` into a tree (`unwebpack_sourcemap.py`, `source-map-extract`), then grep routing/service/config files for endpoints and role names. Vite fix posture is `build.sourcemap: false` (or `'hidden'` for Sentry-only upload); Next.js should not enable `productionBrowserSourceMaps`.
- **Schema-to-auth bypass chain:** a leaked spec reveals hidden fields/endpoints → send requests with those fields (mass assignment) → confirm missing authorization. Spec-vs-runtime diff: jq out `'.paths | keys[]'` from two specs and `comm -23` to find routes only in the old one.
- **Wayback-persisted specs:** a deprecated version's Swagger often stays indexed after the live link is removed — query the CDX API for `*swagger*` and `*openapi*`.
- **Engineer informative responses:** fuzz with wrong types, broken JSON, oversized fields, null bytes, alternate content types; normalize and diff by status/body length/ETag/headers across owner vs non-owner vs anonymous.
- **Trace-to-LFI chain:** stack-trace paths reve

### Validation and proof

### Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

### Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

# HUNT-SOURCE-LEAK — Source Code & Build Artifact Leakage

### Validation

✅ Source map: reconstructed TypeScript source contains API endpoints or hardcoded secrets
✅ Swagger: JSON contains internal endpoints not visible in UI
✅ .git exposed: git-dumper successfully clones repo, secrets in history
✅ .env exposed: DATABASE_URL, API_KEY, SECRET_KEY visible in plaintext

**Severity:**
- .env with credentials: Critical
- .git with secrets in history: Critical
- Source map with secrets: High
- Swagger with internal routes: Medium-High
- robots.txt only: Informational

### C. Validation / proof bar — how to confirm and avoid false positives

- Artifacts before payloads: DVCS directories, backups, maps, and client-data JSON yield the fastest wins; chain quickly to one concrete, minimal, reversible risk and stop.
- **Content-shape confirmation:** a 200 from `/.git/config` must return Git config text, not a SPA HTML fallback; a `.map` must be JSON with `sources`, not an error page.
- **A leaked URL/hostname is not impact:** confirm reachability and demonstrate what the data grants (version→CVE, path→LFI/RCE, key→cloud access, schema→auth bypass).
- **Key triage:** publishable Stripe `pk_`, Firebase web config, and Supabase `anon` keys are intended to be public — report only a demonstrated permission/capability or a genuinely secret key (`sk_`, `service_role`, cloud credentials).
- **Credentials must still authenticate today** — an exposed but revoked/rotated secret is not a live finding; verify minimally and within scope, and do not use it beyond proof.
- **Role-differential harness:** normalize responses and diff by digest to reduce noise; an error page returning HTTP 200 is not a successful unauthorized read.
- Per OWASP ASVS 5.0 V13.4: verify absence of `.git`/`.svn`, debug modes off, no directory listings, no TRACE in production, no detailed backend version info, and restricted file extensions — these raise the bar even though each alone is often Info/Low.

- **Threat-actor context:** GreyNoise observed ~4,800 unique IPs in a single day (April 2025) scanning for exposed `.git/config`; EmeraldWhale (Oct 2024) used the same primitive to st

### Escalation and related chains

### Escalation chains

- Info leak -> creds -> ATO.
- Debug endpoint -> RCE.
- PII leak -> compliance impact.

### Chain Table

| Source leak finding | Chain to | Impact |
|--------------------|----------|--------|
| Source map with API key | Use key directly → API access | High/Critical |
| Source map with auth logic | Find auth bypass route | Critical |
| Swagger → internal endpoints | Test undocumented admin routes | High |
| .git exposed | Full source history → all past secrets | Critical |
| build-info with git hash | CVE targeting exact version | High |
| .env with DB_PASSWORD | Direct database access | Critical |

---

### Tools and wordlists

### Tools

`ffuf` · `gobuster` · `nuclei` · `trufflehog` · `waybackurls`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_info-disclosure.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_info-disclosure.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_info-disclosure.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_info-disclosure.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

### Nuclei

Run exposures/misconfiguration templates against every host; triage for real secrets and PII.

```sh
nuclei -u https://target -tags exposure,disclosure,debug,config,files,keys,tokens \
       -severity info,low,medium,high,critical -rl 40 -o nuclei_info-disclosure.txt
nuclei -u https://target -t ~/nuclei-templates/http/exposures \
       -rl 40 -o nuclei_info-disclosure_exposures.txt
nuclei -u https://target -t ~/nuclei-templates/http/misconfiguration \
       -rl 40 -o nuclei_info-disclosure_misconfiguration.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Tools

```bash
# git-dumper (reconstruct exposed .git)
pip3 install git-dumper
git-dumper "https://target.com/.git/" /tmp/repo/

# sourcemap-explorer (visualize what's in bundles)
npm install -g source-map-explorer
source-map-explorer main.js

# unwebpack-sourcemap (extract all source files)
npm install -g unwebpack-sourcemap

# trufflehog (secret scanning)
trufflehog filesystem /tmp/repo/
```

---

## Source skills merged into this topic

- `h1skills` — `hackerone-info-disclosure`
- `hunting` — `info-disclosure`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
