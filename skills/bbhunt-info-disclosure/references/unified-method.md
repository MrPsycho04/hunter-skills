# Unified upstream methodology

Collected from every contributing repository skill. Deduplicated by content hash; full originals are preserved in `references/upstream-*.md`.

## Discovery and hunting method

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
- **Client env leakage:** `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_` inlined literals; embedded JSON `<script type="application/json">` blocks such as `runtimeConfig`, `BASE_BACKOFFICE_API: "10.10.10.2/api"`, `ADMIN_PAGE: "/hidden_administrator"`.
- **Error/debug surface:** verbose stack traces, ORM internals, file paths, framework versions; `debug` modes, profilers, feature-flag dashboards; `customErrors mode=Off`, TRACE/`trace.axd`, `elmah.axd`.
- **Headers/metadata:** `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Request-Id`, `traceparent`, `Server-Timing`; ETag/If-None-Match and Last-Modified caching oracles; `Access-Control-Expose-Headers` widening cross-origin reads.
- **File metadata:** EXIF and Office/PDF properties (authors, paths, software versions, timestamps); cloud storage object metadata leaking owner/project IDs.
- **Tooling:** `git-dumper` (parallel `holly-hacker/git-dumper` >10x faster, `Ebryx/GitDump` brute-forces object names when directory listing is off), GitTools Finder/Dumper/Extractor, `gitleaks git -v --log-opts="--all"`, `trufflehog filesystem`, `detect-secrets`, `ggshield`, `Titus` (replaces Nosey Parker).

## Signals and surfaces

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

## Techniques, payloads and bypasses

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
  > Once logged in, they gained access to sensitive API tokens.
- **An attacker can can view any hacker email via  /SaveCollaboratorsMutation operation name** — `#2032716` · HackerOne · $12,500 · ▲429
  > 4- Go the pen on the right for adding more collaborator and click on the pen and capture traffic , you will see the user email in first request,
- **gitlab-workhorse bypass in Gitlab::Middleware::Multipart allowing files in `allowed_paths` to be read** — `#850447` · GitLab · $10,000 · ▲410
  > Determine a valid PID by looping over `/proc/PID` until a `cwd` is found and readable by `git` (eg the `unicorn` worker will have `/proc/19606/cwd - /var/opt/gitlab/gitlab-rails/working`) and traverse to a valid upload path:
- **Employee's GitHub Token Found In Travis CI Build Logs** — `#496937` · Superhuman (formerly Grammarly) · $5,000 · ▲408
  > This report was a part of our research on Travis CI's attack surface: https://edoverflow.com/2019/ci-knew-there-would-be-bugs-here/
- **JSON serialization of any Project model results in all Runner tokens being exposed through Quick Actions** — `#509924` · GitLab · $12,000 · ▲366
  > Write `/move <full path of any other project ` and click "Comment", a request to `/:namespace/:project/notes` is submitted
- **Partial disclosure of report activity through new "Export as .zip" feature** — `#182358` · HackerOne · $10,000 · ▲355
  > Go to this partially disclosed report https://hackerone.com/reports/██████████
- **Information Disclosure in /skills call** — `#188719` · HackerOne · $10,000 · ▲287
  > IN respone of above request all reports submitted for review are getting disclosed.
- **Brave Browser Tor Window leaks user's real IP to the external DNS server** — `#1077022` · Brave Software · $0 · ▲280
  > When a user navigates to a URL in Tor Window, the DNS requests are sent directly without using the Tor proxy, which leaks the user's real IP address and the requested domain name to the user's ISP and the DNS server.
- **Exfiltrating a victim's exact location (to within 5m)** — `#1234406` · Bumble · $0 · ▲278
  > This is not a new vulnerability; Tinder was found to be vulnerable to a version of it in 2014 (https://blog.includesecurity.com/2014/02/how-i-was-able-to-track-the-location-of-any-tinder-user/).
- **Internal attachments can be exported via "Export as .zip" feature** — `#186230` · HackerOne · $12,500 · ▲269
  > Now extract the .zip file (`HackerOne Report-security 182358.zip`)
- **OAuth `redirect_uri` bypass using IDN homograph attack resulting in user's access token leakage** — `#861940` · Semrush · $0 · ▲265
  > IDN homography attack exploits the fact that many different characters look alike such as `semrush.com` is different from `sеmrush.com` because in the latter we used the Cyrillic letter `е` which looks exactly like the latin `e`.
- **AWS keys and user cookie leakage via uninitialized memory leak in outdated librsvg version in Basecamp** — `#2107680` · Basecamp · $8,868 · ▲248
  > Replace the `.avif` extension with `.png`, and the filename (the part right before the extension) with the string `$RANDOM$RANDOM$RANDOM$RANDOM`.
- **[www.zomato.com] CORS Misconfiguration, could lead to disclosure of sensitive information** — `#426165` · Eternal · $550 · ▲246
  > run the following code in console and you would find it pops up user information var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://www.zomato.com/abudhabi',true); req.withCredentials = true; req.send('{}'); function…
- **Google API key leaked to Public** — `#1065041` · FetLife · $0 · ▲228
  > https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key=AI████████DM
- **Public GitHub repositories for multiple HackerOne managed triage team profiles contain private HackerOne reports information** — `#2937622` · HackerOne · $0 · ▲226
  > Here's a random report's commit: █████/setup-chain-node/commit/█████████ (and another fresh commit called "Retest," meaning the issue is potentially fixed) , which is a GitHub actions injection into █████'s repository.
- **Google Docs link in JS files allows editing & reading survey information** — `#2180521` · HackerOne · $0 · ▲217
  > `https://hackerone.com/assets/static/js/5930.078b8e86.chunk.js`
- **Manipulate hacker profile and private program hacktivity to expose your name as researchers who is actively submitting reports with resolve status** — `#654198` · HackerOne · $500 · ▲213
  > For PoC purposes, I have tested it in [███████](https://hackerone.com/███████) private program because they have `security@` email forwarding: `hackerone@█████████.com`.
- **Stealing Facebook OAuth Code Through Screenshot viewer** — `#488269` · Rockstar Games · $0 · ▲200
  > We have resolved the image injection vulnerability, thereby preventing the potential exfiltration of sensitive authentication tokens.
- **An invite-only's program submission state is accessible to users no longer part of the program** — `#800109` · HackerOne · $500 · ▲194
  > Cookie: cfduid=████████; cfuid=█████; ga=█████████; mkto trk=███████; biz uid=███████; biz nA=14; biz pendingA=%5B%5D; biz flagsA=████████; Host-session=█████████████; gid=GA1.2.1121101145.1582021374
- **Unauthorized access to metadata of undisclosed reports that were retested** — `#871749` · HackerOne · $0 · ▲189
  > `report retests` object in `User` node discloses some information about undisclosed report
- **How The Hackers Saved Christmas** — `#1069335` · h1-ctf · $0 · ▲179
  > Note: `/api/experiments` is a false positive because `/api/anythingandeverything` will respond with `401` as well.
- **Information Disclosure through Sentry Instance ███████** — `#697512` · Eternal · $750 · ▲178
  > Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng, / ;q=0.8,application/signed-exchange;v=b3
- **Disclosure of `payment_transactions` for programs via GraphQL query** — `#707433` · HackerOne · $0 · ▲178
  > {"query":"query Team mini profile($handle 0:String!,$size 1:ProfilePictureSizes!) {team(handle:$handle 0) {id,...F0}} fragment F0 on Team {id,name,about, profile picturePkPpF:profile picture(size:$size 1),offers swag,offers bounties,base bounty,payment…
- **404-response contains debug-information with all headers** — `#792998` · HackerOne · $0 · ▲173
  > When requesting a page that does not exist under `www.hackerone.com` the page returns a hidden HTML-element ` debugData` that reflects all headers in the GET-request, including http-only cookies.
- **Total Paid Bounty Paid can be disclose** — `#674757` · HackerOne · $500 · ▲168
  > 2- The program is not 90 days or younger, but an automated script is continually tracking "Bounties sent in the last 90 days" value (note that this would give an exact number since the tracking has started or a very approximate number) (inspired from report…

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
- **Trace-to-LFI chain:** stack-trace paths reveal filesystem layout → LFI/traversal to fetch config/keys → for Next.js target `.env`, `.next/routes-manifest.json`, and compiled NextAuth config.
- **Server-side Git integrations** (HackTricks): if the app clones attacker-controlled repos and later runs `git status/diff/checkout/pull`, `.git/config` write or hook abuse can turn a file write into command execution during later Git actions.
- **Swagger UI posture:** usually an exposure, not a standalone flaw — but OWASP API9 says docs should be available only to authorized users; a spec listing a deprecated version tells an attacker which old host is still running.

## Validation and proof

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

- **Threat-actor context:** GreyNoise observed ~4,800 unique IPs in a single day (April 2025) scanning for exposed `.git/config`; EmeraldWhale (Oct 2024) used the same primitive to steal 15,000+ cloud credentials — prioritize remediation of live exposures accordingly.
- **Swagger/Redoc/Stoplight variants** have different production-readiness defaults; audit each UI variant rather than assuming one config covers all.
- **GraphQL/gRPC equivalents of OpenAPI leaks:** introspection queries and gRPC server reflection expose services/messages just as a Swagger spec does, and are frequently left enabled in production.
- **Exposed Swagger UIs with a "Try it out" bearer token prefilled** leak the token itself — rotate any credential that appears in served HTML.
- **Repository-level secret scanning** complements web-root artifacts: `trufflehog github --org <ORG> --results=verified`, `gitleaks git -v --log-opts="--all" <repo>`, and `detect-secrets` on the dumped repo.
- **File-metadata sweep:** EXIF from downloaded images/PDFs and Office document properties often contain internal usernames, UNC paths, and software versions — feed version strings into CVE lookup.
- **Cache-oracle validation:** confirm `Vary` includes `Authorization`/tenant identity on responses containing sensitive data; an identity-unaware cache key turns a leak into cross-user disclosure.
- **Debug-endpoint sweep should be last:** observability/profiling endpoints are noisy but high-yield — run them after the artifact pass and normalize by digest to avoid drowning in telemetry.
- **Report framing:** ASVS V13.4 issues alone are usually Info/Low but are "bar-raisers" — state the chain (version → CVE, path → LFI, key → cloud access, schema → auth bypass) that converts them into a finding.

- **Error-page fuzzing matrix:** wrong type, broken JSON, oversized field, null byte, and alternate content-type (XML vs JSON) on a single endpoint often yields four different disclosure shapes — diff them side by side.
- **Backup/config filename sweep:** `.env`, `.env.local`, `.env.bak`, `config.yaml`, `credentials.json`, `docker-compose.yml`, `wp-config.php.bak`, and `web.config` are the usual high-value targets after the DVCS pass.

## Escalation and related chains

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

## Tools and wordlists

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

## Sources and related reading

### Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class info-disclosure --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class info-disclosure
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class info-disclosure
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class info-disclosure --min-bounty 1000
```

### Related

- `hackerone-authz-bypass` (1,386 reports)
- `hackerone-crypto-and-secrets` (562 reports)
- `hackerone-idor` (450 reports)

### Related

- `authz-bypass` (1,386 reports)
- `crypto-and-secrets` (562 reports)
- `idor` (450 reports)

### Phase 2 — Source Map Discovery

> **Always resolve the CURRENT build hash before testing, and again before
> re-verifying.** Bundle filenames are content-hashed, so they rotate on every
> deploy. A `.map` URL recorded yesterday can 404 today while the map is still
> fully exposed under a new name. **A 404 at the old URL is not remediation** —
> it is a new build.
>
> ```bash
> # ALWAYS derive the hash live, never reuse a recorded URL
> HASH=$(curl -s "https://$TARGET/" | grep -oE 'main\.[a-f0-9]+\.js' | head -1)
> curl -s -o /dev/null -w '%{http_code} %{size_download} %{content_type}\n' \
>   "https://$TARGET/static/js/${HASH}.map"
> ```
>
> **Lesson from an authorized engagement.** A large production map was found at
> `main.<hashA>.js.map`. On re-verification that URL returned a small HTML
> soft-404 and the finding was nearly closed as fixed. The bundle had rotated to
> `main.<hashB>.js` — and the map was still published at `main.<hashB>.js.map`,
> same size. Nothing had been remediated.
>
> Tell the client this explicitly in the report: **redeploying does not fix source
> map exposure.** Only `GENERATE_SOURCEMAP=false` (or stripping `.map` at deploy)
> plus a CDN purge closes it. A team that redeploys and re-checks the old link
> will wrongly declare victory.
>
> Same rule applies to any content-hashed artifact: chunk files, CSS maps,
> `asset-manifest.json`, and staging equivalents.

```bash
# Step 1: Get asset manifest to find all JS bundle paths
curl -s "https://$TARGET/asset-manifest.json" | python3 -m json.tool 2>/dev/null
curl -s "https://$TARGET/static/js/main.*.js" 2>/dev/null | head -3

# Next.js
BUILD_ID=$(curl -s https://$TARGET/ | grep -oP '"buildId":"\K[^"]+')
curl -s "https://$TARGET/_next/static/$BUILD_ID/_buildManifest.js" | head -5

# Step 2: For each JS bundle, check for source map reference at end of file
for JS_URL in $(curl -s https://$TARGET/ | grep -oP 'src="[^"]*\.js"' | sed 's/src="//;s/"//'); do
  LAST_LINE=$(curl -s "https://$TARGET$JS_URL" | tail -1)
  echo "$LAST_LINE" | grep -q "sourceMappingURL" && echo "[+] Source map: $JS_URL"
done

# Step 3: Download and reconstruct source from .map files
JS_URL="https://$TARGET/static/js/main.abc123.js"
MAP_URL="${JS_URL}.map"
curl -s "$MAP_URL" | python3 -c "
import sys, json, os
data = json.load(sys.stdin)
sources = data.get('sources', [])
contents = data.get('sourcesContent', [])
for i, (src, content) in enumerate(zip(sources, contents)):
    if content:
        path = '/tmp/sourcemap_extract/' + src.replace('../','').replace('./',''). replace('webpack://','')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            f.write(content)
        print(f'[+] Extracted: {src}')
"

# Step 4: Grep extracted source for secrets
grep -r "API_KEY\|SECRET\|PASSWORD\|TOKEN\|PRIVATE" /tmp/sourcemap_extract/ 2>/dev/null
grep -r "process\.env\." /tmp/sourcemap_extract/ 2>/dev/null | grep -v "NEXT_PUBLIC_" | head -20
grep -r "http://internal\|localhost\|127\.0\.0\.1\|10\.\|172\.\|192\.168" /tmp/sourcemap_extract/ 2>/dev/null | head -20
```

---

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/web-security/information-disclosure/exploiting (fuzzing, version-control history, avoiding tunnel vision)
2. https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage (source-map and embedded-config examples)
3. https://scotthelme.co.uk/content/files/2025/06/OWASP_Application_Security_Verification_Standard_5.0.0_en.pdf (ASVS 5.0 V13.4 unintended information leakage)
4. https://hacktricks.wiki/en/network-services-pentesting/pentesting-web/git.html (fast .git dumping 2024–2026, dirlisting bypass, post-dump triage, Git CLI attack surface)
5. https://hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/github-leaked-secrets.html (TruffleHog v3, gitleaks, Titus)
6. https://bugbounty.info/Recon/Exposed-Git (httpx `/.git/HEAD` sweep, git-dumper/GitTools workflow)
7. https://github.com/usestrix/strix/blob/main/strix/skills/vulnerabilities/information_disclosure.md (channel map, diff harness, schema→auth-bypass chain)
8. https://vibe-eval.com/patterns/graphql-swagger-grpc-exposure (Swagger/introspection/gRPC runtime detection and prefilled-token check)
9. https://www.inspectiv.com/articles/source-code-reconstruction-from-.git-directory-exposure (403 vs 404 interpretation, commit-history mining)

## Additional notes

### Parameters observed

`text_query` · `page` · `url` · `token` · `subject` · `sort_type` · `client_id` · `sentry_key` · `action` · `query` · `defid` · `id` · `username` · `email` · `sort` · `file.path` · `SRBHeaderID` · `isBoard` · `OT` · `redirect_uri`

### Confidential data of users and limited metadata of programs and reports accessible via GraphQL

`#489146` · HackerOne · $0 · critical · 2019-02-03 · ▲1033
> Summary: The GraphQL endpoint doesn't have access controls implemented properly. Description: Any attacker can get personally identifiable information of users of Hackerone such as email address, backup hash codes, facebook user id, account recovery phone number verified at, totp enabled, etc. These are just some examples of fields which are getting leaked directly from GraphQL.

### Sensitive user information disclosure at bonjour.uber.com/marketplace/_rpc via the 'userUuid' parameter

`#542340` · Uber · $0 · high · 2019-09-09 · ▲643
> It was possible for an attacker to insert another user’s UUID into the userUuid POST parameter when making a request to https://bonjour.uber.com/marketplace/ rpc?rpc=getConsentScreenDetails, allowing them to retrieve personal data from the victim user’s account, as well as the user's mobile auth token, which could allow them to make requests to mobile APIs as the victim.

### The /reports/:id.json endpoint discloses potentially sensitive user attributes when reporter summary is present

`#3000510` · HackerOne · $0 · critical · 2025-04-01 · ▲625
> Hi The.json endpoint of any disclosed report is leaking reporter's email, OTP backup codes, reporter's phone number, "graphql secret token", tshirt size all the reporter account's internal details etc. I was checking Hackerone's disclosed report ██████████ and suddenly during check found .json point is leaking too much data of reporter . I immediately reported it to you.

### Customer private program can disclose email any users through invited via username

`#807448` · HackerOne · $7,500 · high · 2020-05-15 · ▲589
> Summary: Hey team,This bug could have been used by my calculations a long time ago Steps To Reproduce: 1)Go to https://hackerone.com/hackerone h1p bbp3/launch 2)Take invite via username 3)Input username , send invite 3.1)When an invite is created, we get a token 4)Now Go use GraphQL query https://hackerone.com/graphql? {"query": "query {team(handle:\\"hackerone h1p bbp3\\"){ id,handle,soft launch invitations{total count,nodes{...

### Access to multiple production Grafana dashboards

`#663628` · Snapchat · $10,000 · high · 2020-11-04 · ▲464
> @damian89 found a production Grafana instance which displayed confidential metrics inside various dashboards. While fuzzing patterns of certain snapchat related projects, I was able to find an instance of Grafana which was accessible by a guest user. That instance contained hundreds of production dashboards, valuable data about company. Furthermore one of the custom modules was vulnerable to SQL Injection.

### Phase 3 — Swagger / OpenAPI Discovery

```bash
# Common paths
SWAGGER_PATHS=(
  "/swagger.json" "/swagger.yaml" "/swagger/"
  "/api/swagger.json" "/api/swagger.yaml"
  "/v1/swagger.json" "/v2/swagger.json" "/v3/swagger.json"
  "/openapi.json" "/openapi.yaml"
  "/api/openapi.json" "/api-docs" "/api-docs.json"
  "/api/v1/swagger.json" "/api/v2/swagger.json"
  "/rest/swagger.json" "/rest/api-docs"
  "/.well-known/openapi.json"
  "/graphql/schema.json"
)

for PATH in "${SWAGGER_PATHS[@]}"; do
  STATUS=$(curl -s -o /tmp/swagger_test -w "%{http_code}" "https://$TARGET$PATH")
  if [ "$STATUS" = "200" ]; then
    echo "[+] Found: https://$TARGET$PATH"
    # Extract all API paths from swagger
    python3 -c "
import sys, json
try:
    d = json.load(open('/tmp/swagger_test'))
    paths = list(d.get('paths', {}).keys())
    print(f'Endpoints: {len(paths)}')
    print('\n'.join(sorted(paths)))
except: pass
" | head -50
  fi
done
```

---

### Phase 4 — .git Exposure

```bash
# Check if .git directory is accessible
curl -s "https://$TARGET/.git/HEAD" | grep -q "ref:" && echo "[+] .git exposed!"

# If exposed, reconstruct repo
# Tool: git-dumper
pip3 install git-dumper
git-dumper "https://$TARGET/.git/" /tmp/dumped-repo/

# Grep for secrets in all git history
cd /tmp/dumped-repo && \
  git log --all --oneline 2>/dev/null | head -20
  git grep -i "password\|secret\|api_key\|token" $(git rev-list --all) 2>/dev/null | head -30

# trufflehog on git history
trufflehog git file:///tmp/dumped-repo/ 2>/dev/null | head -50
```

---

### Phase 5 — Forgotten Files & Debug Endpoints

```bash
# Build artifacts and debug files
DEBUG_PATHS=(
  "/build-info.json" "/build/build-info.json"
  "/info" "/actuator/info" "/api/info"
  "/version" "/api/version" "/_version"
  "/health" "/status" "/ping"
  "/robots.txt" "/security.txt" "/.well-known/security.txt"
  "/sitemap.xml" "/manifest.json" "/browserconfig.xml"
  "/crossdomain.xml" "/clientaccesspolicy.xml"
  "/phpinfo.php" "/info.php" "/test.php"
  "/server-status" "/server-info" "/.htaccess"
  "/web.config" "/applicationHost.config"
  "/WEB-INF/web.xml" "/META-INF/MANIFEST.MF"
  "/package.json" "/composer.json" "/Gemfile"
  "/Dockerfile" "/docker-compose.yml" "/.dockerenv"
)

for PATH in "${DEBUG_PATHS[@]}"; do
  STATUS=$(curl -s -o /tmp/debug_test -w "%{http_code}" "https://$TARGET$PATH")
  if [ "$STATUS" = "200" ]; then
    echo "[+] Found: https://$TARGET$PATH ($STATUS, $(wc -c < /tmp/debug_test) bytes)"
    head -3 /tmp/debug_test
    echo "---"
  fi
done
```

---

### Phase 6 — .DS_Store File Listing

```bash
# .DS_Store files on macOS-deployed web servers reveal directory structure
curl -s "https://$TARGET/.DS_Store" | xxd | head -10

# Parse .DS_Store to extract filenames
pip3 install ds_store
python3 -c "
from ds_store import DSStore
with DSStore.open('/tmp/ds_store_test', 'r') as d:
    for entry in d:
        print(entry.filename)
"

# Recursive .DS_Store enumeration
# Tool: https://github.com/lijiejie/ds_store_exp
python3 ds_store_exp.py "https://$TARGET/"
```

---

### Phase 7 — webpack Chunk Analysis

```bash
# Download and analyze webpack chunks for hardcoded values
# Find chunk files
curl -s https://$TARGET/ | grep -oP '"[^"]*\.chunk\.js"' | tr -d '"' | while read chunk; do
  echo "Analyzing: $chunk"
  curl -s "https://$TARGET$chunk" | \
    grep -oE '"(api_key|apiKey|secret|password|token|key)"\s*:\s*"[^"]+"' | head -5
done

# Also grep for internal hostnames
curl -s "https://$TARGET/static/js/main.*.js" | \
  grep -oE '"(https?://[^"]*internal[^"]*|http://[^"]*localhost[^"]*)"' | sort -u

# Check for Base64-encoded secrets
curl -s "https://$TARGET/static/js/main.*.js" | \
  grep -oP '"[A-Za-z0-9+/]{30,}={0,2}"' | while read b64; do
  DECODED=$(echo "$b64" | tr -d '"' | base64 -d 2>/dev/null)
  echo "$DECODED" | grep -iE "key|secret|password|token" && echo "  B64: $b64"
done
```

---

## Companion methodology (merged, deduplicated)

Full text of every non-SKILL.md methodology file from the contributing skills — payload banks, technique references, reconnaissance and attack-class guides.

### Companion: hunting / references/payloads.md

# Info Disclosure — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- `/.git/config` `/.env` `/.DS_Store` `/server-status` `/actuator/env`

- `/api/v1/users?limit=1000` `/api/v1/users/0`

- `?fields=all` `?expand=*` `?include=deleted`

- S3 -> `https://bucket.s3.amazonaws.com/?list-type=2`



## Payload fragments observed



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



## Parameters observed



`text_query` · `page` · `url` · `token` · `subject` · `sort_type` · `client_id` · `sentry_key` · `action` · `query` · `defid` · `id` · `username` · `email` · `sort` · `file.path` · `SRBHeaderID` · `isBoard` · `OT` · `redirect_uri`



## Wordlists



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



## Nuclei



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

### Companion: hunting / references/techniques.md

# Info Disclosure — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Fuzz for debug endpoints: /debug, /actuator, /health, /metrics, /graphql, .env, .git, source maps.

- Check error handling for stack traces, SQL errors, internal hosts, and versions.

- Look for extra fields, deleted records, internal notes, PII, tokens in API responses.

- Enumerate cloud storage, backups, DB dumps, log archives, CI artifacts.



## Bypass tricks



- Bypass auth on static/debug paths with path normalization.

- Use GraphQL introspection and field suggestions.

- Check cache headers for private data.



## Deeper checklist



- Fuzz for debug endpoints: /debug, /actuator, /health, /metrics, /graphql introspection, .env, .git, source maps.

- Check error handling: stack traces, SQL errors, internal hostnames, framework versions, request IDs.

- Look for object leaks in API responses: extra fields, deleted records, internal notes, PII, tokens.

- Enumerate cloud storage and backups: S3/GCS/Azure buckets, DB dumps, log archives, CI artifacts.

- Test cache and CDN behavior for private content leakage across users or regions.

- Check JS bundles for hardcoded keys, internal URLs, feature flags, staging hosts.

- Compare responses across roles and unauthenticated requests for over-exposure.

- Verify the data is genuinely sensitive and not intended public data before reporting.



## Techniques from real reports



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

  > Once logged in, they gained access to sensitive API tokens.

- **An attacker can can view any hacker email via  /SaveCollaboratorsMutation operation name** — `#2032716` · HackerOne · $12,500 · ▲429

  > 4- Go the pen on the right for adding more collaborator and click on the pen and capture traffic , you will see the user email in first request,

- **gitlab-workhorse bypass in Gitlab::Middleware::Multipart allowing files in `allowed_paths` to be read** — `#850447` · GitLab · $10,000 · ▲410

  > Determine a valid PID by looping over `/proc/PID` until a `cwd` is found and readable by `git` (eg the `unicorn` worker will have `/proc/19606/cwd - /var/opt/gitlab/gitlab-rails/working`) and traverse to a valid upload path:

- **Employee's GitHub Token Found In Travis CI Build Logs** — `#496937` · Superhuman (formerly Grammarly) · $5,000 · ▲408

  > This report was a part of our research on Travis CI's attack surface: https://edoverflow.com/2019/ci-knew-there-would-be-bugs-here/

- **JSON serialization of any Project model results in all Runner tokens being exposed through Quick Actions** — `#509924` · GitLab · $12,000 · ▲366

  > Write `/move <full path of any other project ` and click "Comment", a request to `/:namespace/:project/notes` is submitted

- **Partial disclosure of report activity through new "Export as .zip" feature** — `#182358` · HackerOne · $10,000 · ▲355

  > Go to this partially disclosed report https://hackerone.com/reports/██████████

- **Information Disclosure in /skills call** — `#188719` · HackerOne · $10,000 · ▲287

  > IN respone of above request all reports submitted for review are getting disclosed.

- **Brave Browser Tor Window leaks user's real IP to the external DNS server** — `#1077022` · Brave Software · $0 · ▲280

  > When a user navigates to a URL in Tor Window, the DNS requests are sent directly without using the Tor proxy, which leaks the user's real IP address and the requested domain name to the user's ISP and the DNS server.

- **Exfiltrating a victim's exact location (to within 5m)** — `#1234406` · Bumble · $0 · ▲278

  > This is not a new vulnerability; Tinder was found to be vulnerable to a version of it in 2014 (https://blog.includesecurity.com/2014/02/how-i-was-able-to-track-the-location-of-any-tinder-user/).

- **Internal attachments can be exported via "Export as .zip" feature** — `#186230` · HackerOne · $12,500 · ▲269

  > Now extract the .zip file (`HackerOne Report-security 182358.zip`)

- **OAuth `redirect_uri` bypass using IDN homograph attack resulting in user's access token leakage** — `#861940` · Semrush · $0 · ▲265

  > IDN homography attack exploits the fact that many different characters look alike such as `semrush.com` is different from `sеmrush.com` because in the latter we used the Cyrillic letter `е` which looks exactly like the latin `e`.

- **AWS keys and user cookie leakage via uninitialized memory leak in outdated librsvg version in Basecamp** — `#2107680` · Basecamp · $8,868 · ▲248

  > Replace the `.avif` extension with `.png`, and the filename (the part right before the extension) with the string `$RANDOM$RANDOM$RANDOM$RANDOM`.

- **[www.zomato.com] CORS Misconfiguration, could lead to disclosure of sensitive information** — `#426165` · Eternal · $550 · ▲246

  > run the following code in console and you would find it pops up user information var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://www.zomato.com/abudhabi',true); req.withCredentials = true; req.send('{}'); function…

- **Google API key leaked to Public** — `#1065041` · FetLife · $0 · ▲228

  > https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key=AI████████DM

- **Public GitHub repositories for multiple HackerOne managed triage team profiles contain private HackerOne reports information** — `#2937622` · HackerOne · $0 · ▲226

  > Here's a random report's commit: █████/setup-chain-node/commit/█████████ (and another fresh commit called "Retest," meaning the issue is potentially fixed) , which is a GitHub actions injection into █████'s repository.

- **Google Docs link in JS files allows editing & reading survey information** — `#2180521` · HackerOne · $0 · ▲217

  > `https://hackerone.com/assets/static/js/5930.078b8e86.chunk.js`

- **Manipulate hacker profile and private program hacktivity to expose your name as researchers who is actively submitting reports with resolve status** — `#654198` · HackerOne · $500 · ▲213

  > For PoC purposes, I have tested it in [███████](https://hackerone.com/███████) private program because they have `security@` email forwarding: `hackerone@█████████.com`.

- **Stealing Facebook OAuth Code Through Screenshot viewer** — `#488269` · Rockstar Games · $0 · ▲200

  > We have resolved the image injection vulnerability, thereby preventing the potential exfiltration of sensitive authentication tokens.

- **An invite-only's program submission state is accessible to users no longer part of the program** — `#800109` · HackerOne · $500 · ▲194

  > Cookie: cfduid=████████; cfuid=█████; ga=█████████; mkto trk=███████; biz uid=███████; biz nA=14; biz pendingA=%5B%5D; biz flagsA=████████; Host-session=█████████████; gid=GA1.2.1121101145.1582021374

- **Unauthorized access to metadata of undisclosed reports that were retested** — `#871749` · HackerOne · $0 · ▲189

  > `report retests` object in `User` node discloses some information about undisclosed report

- **How The Hackers Saved Christmas** — `#1069335` · h1-ctf · $0 · ▲179

  > Note: `/api/experiments` is a false positive because `/api/anythingandeverything` will respond with `401` as well.

- **Information Disclosure through Sentry Instance ███████** — `#697512` · Eternal · $750 · ▲178

  > Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng, / ;q=0.8,application/signed-exchange;v=b3

- **Disclosure of `payment_transactions` for programs via GraphQL query** — `#707433` · HackerOne · $0 · ▲178

  > {"query":"query Team mini profile($handle 0:String!,$size 1:ProfilePictureSizes!) {team(handle:$handle 0) {id,...F0}} fragment F0 on Team {id,name,about, profile picturePkPpF:profile picture(size:$size 1),offers swag,offers bounties,base bounty,payment…

- **404-response contains debug-information with all headers** — `#792998` · HackerOne · $0 · ▲173

  > When requesting a page that does not exist under `www.hackerone.com` the page returns a hidden HTML-element ` debugData` that reflects all headers in the GET-request, including http-only cookies.

- **Total Paid Bounty Paid can be disclose** — `#674757` · HackerOne · $500 · ▲168

  > 2- The program is not 90 days or younger, but an automated script is continually tracking "Bounties sent in the last 90 days" value (note that this would give an exact number since the tracking has started or a very approximate number) (inspired from report…



## Case studies



### Confidential data of users and limited metadata of programs and reports accessible via GraphQL

`#489146` · HackerOne · $0 · critical · 2019-02-03 · ▲1033

> Summary: The GraphQL endpoint doesn't have access controls implemented properly. Description: Any attacker can get personally identifiable information of users of Hackerone such as email address, backup hash codes, facebook user id, account recovery phone number verified at, totp enabled, etc. These are just some examples of fields which are getting leaked directly from GraphQL.



### Sensitive user information disclosure at bonjour.uber.com/marketplace/_rpc via the 'userUuid' parameter

`#542340` · Uber · $0 · high · 2019-09-09 · ▲643

> It was possible for an attacker to insert another user’s UUID into the userUuid POST parameter when making a request to https://bonjour.uber.com/marketplace/ rpc?rpc=getConsentScreenDetails, allowing them to retrieve personal data from the victim user’s account, as well as the user's mobile auth token, which could allow them to make requests to mobile APIs as the victim.



### The /reports/:id.json endpoint discloses potentially sensitive user attributes when reporter summary is present

`#3000510` · HackerOne · $0 · critical · 2025-04-01 · ▲625

> Hi The.json endpoint of any disclosed report is leaking reporter's email, OTP backup codes, reporter's phone number, "graphql secret token", tshirt size all the reporter account's internal details etc. I was checking Hackerone's disclosed report ██████████ and suddenly during check found .json point is leaking too much data of reporter . I immediately reported it to you.



### Customer private program can disclose email any users through invited via username

`#807448` · HackerOne · $7,500 · high · 2020-05-15 · ▲589

> Summary: Hey team,This bug could have been used by my calculations a long time ago Steps To Reproduce: 1)Go to https://hackerone.com/hackerone h1p bbp3/launch 2)Take invite via username 3)Input username , send invite 3.1)When an invite is created, we get a token 4)Now Go use GraphQL query https://hackerone.com/graphql? {"query": "query {team(handle:\\"hackerone h1p bbp3\\"){ id,handle,soft launch invitations{total count,nodes{...



### Access to multiple production Grafana dashboards

`#663628` · Snapchat · $10,000 · high · 2020-11-04 · ▲464

> @damian89 found a production Grafana instance which displayed confidential metrics inside various dashboards. While fuzzing patterns of certain snapchat related projects, I was able to find an instance of Grafana which was accessible by a guest user. That instance contained hundreds of production dashboards, valuable data about company. Furthermore one of the custom modules was vulnerable to SQL Injection.



## Query the corpus



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class info-disclosure --limit 20

python3 ~/.local/share/hackerone-reports/h1.py stats --class info-disclosure

python3 ~/.local/share/hackerone-reports/h1.py show <id> --full

```



Search by technology, endpoint, parameter, or program. Examples:



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class info-disclosure

python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class info-disclosure --min-bounty 1000

```



## Phase 1 — Quick Wins (Run First)



```bash

# These 10 requests take <30 seconds and often yield Critical findings

for PATH in \

  "/.env" \

  "/.env.production" \

  "/.env.local" \

  "/.git/HEAD" \

  "/swagger.json" \

  "/api/swagger.json" \

  "/v1/swagger.json" \

  "/openapi.json" \

  "/api/openapi.json" \

  "/api-docs"; do

  STATUS=$(curl -s -o /tmp/sl_test -w "%{http_code}" "https://$TARGET$PATH")

  if [ "$STATUS" = "200" ]; then

    echo "[+] HIT: https://$TARGET$PATH"

    head -5 /tmp/sl_test

    echo "---"

  fi

done

```



---
