---
name: request-smuggling
description: >-
  Hunt HTTP request smuggling (CL.TE, TE.CL, H2.CL, H2.TE). Cause: front-end proxy and back-end server
  disagree on where one request ends and the next begins (Content-Length vs Transfer-Encoding header parsing
  inconsistency). CL.TE: front-end uses CL, back uses TE → smuggle by sending TE: chunked but with body that
  fits CL count. TE.CL: opposite. H2.CL: HTTP/2 downgrade, smuggle CL into HTTP/1.1 back-end. Detection
  tools: Burp HTTP Request Smuggler extension, smuggler.py, h2csmuggler. Confirm: time-delay technique
  (smuggled GET with 30s timeout) — if front-end returns slow on next victim request, smuggling works.
  Validate: cache poisoning chain (smuggle request that gets cached for victim), credential theft (smuggle
  X-Forwarded-For override that captures next user's cookies), bypass auth (smuggled internal-path request).
  Real paid examples from major CDN deployments. Use when hunting H1 paid programs running CDN+origin
  stacks, when targeting load balancer / WAF bypass. Combined with the HackerOne field guide (real
  disclosed-report data: where it pays, quick wins, payload banks). Hunt request smuggling and cache desync.
  Use when testing front-end/back-end chains, CDNs, and HTTP/2 downgrades. Backed by 101 disclosed HackerOne
  reports.
---

# Request Smuggling — Combined Field Guide

**Merged skill.** This fuses two complementary sources into one reference:

- **Part 1 — HackerOne field guide:** statistics from disclosed reports, "where it pays," quick wins, and curated payload banks.
- **Part 2 — Bug hunter methodology:** autonomous testing priority, canary discipline, crown-jewel targeting, OOB/validation gates, and reporting guidance.

**How to use:** Open with Part 2 for execution discipline (set your canary, know your success/failure gate). Use Part 1 to prioritize targets and pull payloads. Before reporting, run the validation gates in both parts.

---

<!-- ============ PART 1: HACKERONE FIELD GUIDE (data + payloads) ============ -->

# HTTP Request Smuggling / Desync — HackerOne field guide

Built from **101** publicly disclosed HackerOne reports (2015–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Signal

- Reports: **101** · paid: **31**
- Median bounty **$1,800** · p90 **$6,000** · max **$20,000** · total **$104,040**
- Median upvotes **18**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| PayPal | 2 | $38,900 | 3372 |
| Internet Bug Bounty | 15 | $31,980 | 485 |
| Cloudflare Public Bug Bounty | 3 | $10,600 | 216 |
| Basecamp | 3 | $7,500 | 355 |
| Mail.ru | 5 | $5,000 | 274 |
| New Relic | 1 | $3,000 | 490 |
| Airbnb | 1 | $2,500 | 37 |
| Shopify | 1 | $800 | 136 |

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`any endpoint behind CDN/proxy` `login` `API gateway` `static assets`

## Tools

`Burp HTTP Request Smuggler` · `smuggler.py` · `h2cSmuggler`

## Escalation chains

- Smuggling -> cache poisoning -> XSS.
- Smuggling -> auth bypass.
- Smuggling -> request capture.

## Related

- `web-cache` (68 reports)
- `ssrf` (337 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

## 17. HTTP REQUEST SMUGGLING
> Lowest dup rate. $5K–$30K. PortSwigger research by James Kettle.

### CL.TE (Content-Length front, Transfer-Encoding back)
```http
POST / HTTP/1.1
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### Detection
```
1. Burp extension: HTTP Request Smuggler
2. Right-click request → Extensions → HTTP Request Smuggler → Smuggle probe
3. Manual timing: CL.TE probe + ~10s delay = backend waiting for rest of body
```

### Impact Chain
```
Poison next request → access admin as victim
Steal credentials → capture victim's session
Cache poisoning → stored XSS at scale
```

---

## Target-Suitability Matrix (2026 reality check)

The classic CL.TE / TE.CL payloads are NOT universally exploitable in 2026. Modern proxies are RFC 9112 strict by default. Fingerprint the front-end BEFORE investing time.

| Front-end | CL.TE | TE.CL | H2.CL | H2.TE | Notes |
|---|---|---|---|---|---|
| **Nginx ≥ 1.21** | NO | NO | partial (H2 ingress) | partial | RFC-strict; rejects CL+TE with HTTP 400. Verified locally on Nginx 1.27 — all 9 documented variants killed by front-end ([docs/verification/phase2h-smuggling-cachepoison.md](../../docs/verification/phase2h-smuggling-cachepoison.md)). |
| **Caddy 2.x** | NO | NO | — | — | Hardened by default |
| **Envoy ≥ 1.20** | NO | NO | partial | partial | Hardened in most paths |
| **HAProxy ≤ 2.4** | ✓ | ✓ | — | — | **Vulnerable**, see CVE-2021-40346 |
| **AWS ALB + specific upstream** | partial | partial | ✓ | ✓ | Several disclosed-paid reports 2022-2024 |
| **Cloudflare → S3 / Lambda chains** | — | — | ✓ | ✓ | H2-downgrade attacks remain viable |
| **Older F5 BIG-IP (TMM < 16)** | ✓ | — | — | — | Vendor advisories |
| **Citrix ADC / NetScaler (older firmware)** | ✓ | ✓ | — | — | Disclosed in 2020-2022 |
| **Squid 3.x** | ✓ | — | — | — | Older deployments |
| **Apache Traffic Server (older)** | ✓ | ✓ | ✓ | ✓ | PortSwigger research |
| **Apache mod_proxy_ajp → Tomcat** | — | — | — | — | Cross-protocol HTTP→AJP desync (CVE-2022-26377); smuggled request is opaque to the WAF and reaches internal AJP admin/status paths that lack the external auth controls |
| **Custom Python / Go proxies** | ✓ | ✓ | — | — | Frequently miss RFC enforcement |

### Operator fingerprint quick-check

```bash
curl -sI https://target/ | grep -i "Server:"
```

- `nginx/1.21+`, `Caddy`, `envoy` → CL/TE classic is dead — pivot to H2.CL/H2.TE if the front-end speaks HTTP/2, or look for legacy proxies upstream
- `HAProxy`, header points to AWS/CDN → run the full payload matrix
- No Server header → assume hardened, but run a single quick `space-before-colon` probe; if it doesn't 400, dig deeper

### H2.CL / H2.TE (the modern dominant vector)

H2-downgrade smuggling attacks rely on the front-end speaking HTTP/2 to the client and HTTP/1.1 to origin. The downgrade introduces CL/TE confusion because HTTP/2's frame-length headers don't survive the conversion cleanly. Most CDN+origin chains in 2024-2026 use this exact topology.

Tools that send HTTP/2 raw frames (Burp Pro's HTTP Request Smuggler extension, `h2csmuggler`, `smuggler.py`) are the right starting point against CDN-fronted targets. Avoid HTTP/1.1-only test clients (curl, raw sockets) against H2-front-ended targets — you'll send the wrong protocol entirely.

### Mass credential harvesting — the "collector gadget"
The highest-impact smuggling outcome needs no per-victim interaction. Instead of blindly poisoning the queue, smuggle a request aimed at a **back-end handler that echoes the full request** — a search endpoint that reflects headers, or a redirect that mirrors the request line. The next victim's headers (`Cookie`, `Authorization`, `X-Access-Token`) get attributed to your smuggled request, and the reflecting handler returns them **in a response you read**. Repeated on a busy keep-alive socket, this harvests live credentials from arbitrary users at scale — and it works even through a CDN (Akamai/Cloudflare) when the CDN↔origin hop desyncs. Chains to `account-takeover`.

---

## Related Skills & Chains

- **`web-cache`** — Smuggling + cache is the canonical critical chain; one smuggled request becomes the cached response for every subsequent victim. Chain primitive: CL.TE smuggle a request whose response body contains attacker HTML/JS → front-end cache stores it under a popular URL (`/`, `/login`) → de-sync poisoning where the smuggled request becomes the cached response for the next N victims, persisting for the cache TTL.
- **`auth-bypass`** — Smuggling reaches internal-only routes that the front-end WAF/auth-proxy filters out. Chain primitive: smuggle `GET /admin/users HTTP/1.1` past the front-end ACL that blocks external `/admin/*` → backend processes the smuggled request as if from a trusted internal source → bypass front-end auth by smuggling internal-routed request → admin data in the response queue.
- **`idor`** — Smuggling attaches the NEXT user's session cookies to an attacker-controlled request path. Chain primitive: smuggle `GET /api/me HTTP/1.1` with no cookies → backend pairs it with the next legitimate user's incoming connection cookies → victim's session cookie attached to attacker's smuggled request → attacker reads the response containing victim's PII/tokens.
- **`xss`** — Smuggling injects XSS payloads into the response stream of the next victim without ever appearing in a URL parameter. Chain primitive: smuggled request body contains reflected payload that the backend renders into the next response in the queue → next visitor to `/` receives attacker HTML inline → reflected XSS at every visitor without any URL parameter visible to them or to logs.
- **`security-arsenal`** — Reach for the smuggling payload bank (CL.TE / TE.CL / TE.TE obfuscations, H2.CL downgrade probes, h2csmuggler one-liners, Burp HTTP Request Smuggler extension config) and the time-delay confirmation template before manual hex-editing.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical: the smuggled-request effect MUST land on a request issued by a different client/session, not your own follow-up. A timing delta in your own browser alone is parser disagreement, not exploitable smuggling.

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete places, params, headers, infra signals to look
- Map the full request chain before fuzzing: client -> CDN/WAF -> reverse proxy -> origin. Desync is a property of the chain, not one host. Record `Server`, `Via`, `X-Cache`, `CF-Cache-Status`, `X-Amzn-Trace-Id`, `X-Nf-Request-Id`, `X-Served-By` on every response to identify each hop.
- Fingerprint the upstream HTTP version. If the edge speaks h2 to the client but downgrades to HTTP/1.1 upstream, you have a fourth length source (H2) and CL/TE parser-diff tricks apply again. Send the same path over HTTP/1.1 and HTTP/2 in Burp Repeater (Inspector -> Request Attributes -> protocol) and diff the responses.
- Target endpoints likely to be on a shared connection pool: static assets (`/assets/*`, `/resources/*`, `/js/*`, `robots.txt`, `favicon.ico`), `/logout`, login redirects, any 30x-redirecting path. Early-response gadgets are what make 0.CL exploitable.
- Note WAF fingerprints that mean classic probes will be filtered: regex blocking of obfuscated `Transfer-Encoding`, requests with embedded `GET /... HTTP/1.1` in a body, or timing-based probes. If classic CL.TE fails on a hardened edge, pivot to parser-discrepancy detection instead of concluding "not vulnerable."
- Look for cloud-proxy infra with known parser quirks: AWS ALB in front of IIS (H-V discrepancy on malformed `Host`), web VPNs, and WAFs that rewrite requests. Kettle notes AWS declined to patch the ALB/IIS issue centrally; hardening knobs are `routing.http.drop_invalid_header_fields.enabled` and `routing.http.desync_mitigation_mode = strictest`.
- Check whether the origin ignores `Content-Length` on GET/HEAD/OPTIONS (implicit-zero, "0" length interpretation). A valid request with a body that the front-end counts but the back-end ignores is CL.0 — browser-deliverable.
- Inventory early-response gadgets per server family: nginx static files respond before reading the full body; IIS throws on reserved device names (`/con`, `/nul`, `/aux`, `COM1`); server-level redirects; `Expect: 100-continue` behavior. Apache closes on errors and is a poor 0.CL target.
- Probe `Expect: 100-continue` explicitly — both vanilla and obfuscated forms (`Expect: y 100-continue`, `Expect:` with a leading space/newline before the value) produced 0.CL and CL.0 desyncs throughout 2025 research.

### B. Techniques & bypasses — specific actionable techniques/payload shapes
- Use HTTP Request Smuggler v3.0 (Burp BApp) parser-discrepancy scanning. It sends masked headers (partially hidden `Host`, duplicate `Host`, `Host:` with leading space, invalid duplicate values) and reports when a unique response appears that cannot be produced by a normal, omitted, or arbitrary masked header. Interpret:
  - V-H (visible to front-end, hidden from back-end) -> prefer CL.0; hide the `Content-Length` with a leading space so the front-end ignores it.
  - H-V (hidden from front-end, visible to back-end) -> classic CL.TE, or 0.CL when TE is blocked.
  - Status codes are irrelevant; only response *differences* matter.
- CL.0 via hidden Content-Length (V-H):
  ```
  GET /style.css HTTP/1.1
  Host: target
  Foo: bar
   Content-Length: 23

  GET /404 HTTP/1.1
  X: y
  ```
  Front-end counts the body; back-end ignores CL and parses `GET /404` as the next request. If GET-with-body is rejected, switch the method to `OPTIONS`.
- 0.CL deadlock break: find an early-response gadget. On IIS use `/con`:
  ```
  GET /con HTTP/1.1
  Host: target
   Content-Length: 7

  GET / HTTP/1.1
  X: Y
  ```
  The back-end responds before consuming the body; a following "victim" request gets sliced. Prove it with a controllable nested request line:
  ```
  GET /con HTTP/1.1
  Host: target
   Content-Length: 20

  GET / HTTP/1.1
  X: yGET /wrtz HTTP/1.1
  Host: target
  ```
  A `302 Location: /Logon?ReturnUrl=%2fwrtz` proves the hidden request line was processed.
- Double-desync 0.CL -> CL.0: request 1 poisons the connection with 0.CL, request 2 is weaponized into CL.0 and installs a prefix. Find the injected front-end header offset with `0cl-find-offset.py` (Turbo Intruder examples), but prefer a smuggle that starts before the injected headers because servers append at the end of the block. A HEAD technique then serves attacker JS to other users on the pooled connection.
- Expect-based desyncs (the dominant 2025 discovery):
  ```
  GET /logout HTTP/1.1
  Host: target
  Expect: 100-continue
  Content-Length: 291
  ```
  or obfuscated `Expect:\n 100-continue` on Akamai and `Expect: y 100-continue` on GitLab. Effects include 0.CL, CL.0, and a second response header block that defeats front-end response-header stripping (leaking `X-Nf-Cache-Key`, account IDs, version banners) plus memory/key disclosure fragments.
- H2.CL / H2.TE: send over HTTP/2 with `Content-Length: 0` and a smuggled prefix in the body; for H2.TE add `transfer-encoding: chunked`. The downgrading front-end ignores/strips H2 framing while the back-end trusts CL/TE:
  ```
  POST / HTTP/2
  Host: target
  Content-Length: 0

  GET /resources HTTP/1.1
  Host: foo
  Content-Length: 5
  x=1
  ```
- Response queue poisoning (high impact, low traffic): poison, then repeatedly fetch "your own" 404 until you capture another user's 302 or session cookie. Expect a race — tens of thousands of requests may be needed.
- Bypass WAF regexes: prefer CL.0/0.CL (valid HTTP, no obfuscated TE), switch methods GET/OPTIONS/POST, use leading whitespace in header names, duplicate headers, and LF-only line endings (RFC-9112 MAY accept a single LF) to expose parsers that deviate.

### C. Validation / proof bar — how to confirm and avoid false positives
- A timeout alone is not proof. Require a *different response* for the same sequence: your request returns a 404 while a subsequent benign request returns a redirect or another user's data. Distinguish V-H from H-V by which server the response appears to come from (banner/header shape), not by status codes.
- Demonstrate one of: (a) a smuggled prefix changing the next request's method/path (`GPOST`, 404 on a hidden path), (b) response-queue poisoning capturing another principal's response, (c) cache poisoning of a JS/static path leading to XSS, or (d) header injection / IP spoof leading to auth bypass. A "Mystery 400" is a lead, not a finding — convert it into a controllable response.
- Replay with a unique cachebuster on cacheable paths so your probes are not served from cache — but know when to strip it: Kettle's 24M-site Cloudflare case was missed until the cache-buster was removed. Test both with and without.
- Reproduce with the connection kept alive and control the exact CL offsets. If the exploit depends on front-end-injected headers containing the client IP, triage may fail from a different IP — disclose this or move the smuggle ahead of the injected headers.
- For client-side desync, prove the attack in a real browser with a cross-origin no-cors request that poisons the browser's own connection pool; a Burp-only PoC does not establish browser-deliverability.
- Do not report theoretical parser deviations (e.g. LF-only line endings on a directly accessed server) as bounties. They matter only when that server sits behind a reverse proxy; frame them as ecosystem/defense observations.
- Record the full raw request/response pair, the HTTP version per hop, and exact byte offsets. Redact cookies/session tokens of other users captured via response-queue poisoning.

### D. Sources — numbered list of URLs you actually fetched
1. https://portswigger.net/research/http1-must-die
2. https://portswigger.net/web-security/request-smuggling
3. https://portswigger.net/web-security/request-smuggling/advanced
4. https://portswigger.net/research/http2
5. https://blogs.jsmon.sh/http-2-request-smuggling-why-h2-cl-h2-te-and-browser-desync-still-pay
6. https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-cl-request-smuggling
7. https://www.usenix.org/system/files/usenixsecurity25-mu.pdf
