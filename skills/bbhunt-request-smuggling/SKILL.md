---
name: bbhunt-request-smuggling
description: "Use for CL.TE / TE.CL / H2.CL / H2.TE desync, header framing inconsistencies and cache-poisoning via request framing. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# HTTP Request Smuggling and Desync — unified methodology

> **Unified skill.** Built from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus evidence (97 valid reports, 30 paid / 31%)

Payment is not validity — zero-bounty disclosures are mined as evidence too.

### Techniques ranked across ALL valid writeups

| Technique | Reports |
|---|---:|
| parser confusion / normalization | 61 |
| encoding / double-encode / null byte | 46 |
| cache / CDN / unkeyed header | 39 |
| JS bundle / source-map inspection | 39 |
| internal service / port / container | 36 |
| header injection (Host / X-Forwarded / etc.) | 28 |
| Content-Type / body-format switch | 21 |
| public source-code / repo review | 17 |
| parameter pollution / duplicate keys | 17 |
| intercept & replay request in Burp | 15 |

### Parameters observed

`result`, `target`, `daemon`, `path`, `session`, `capture_output`, `body`, `args`, `domain`, `max-age`, `injected`, `qop`, `port`, `payload`, `nextnonce`

### Case studies (real reports, paid and unpaid)

- [510152](https://hackerone.com/reports/510152) PayPal — Bypass for #488147 enables stored XSS on https://paypal.com/signin again ($20000, high)
- [488147](https://hackerone.com/reports/488147) PayPal — Stored XSS on https://paypal.com/signin via cache poisoning ($18900, high)
- [1478633](https://hackerone.com/reports/1478633) Cloudflare Public Bug Bounty — HTTP Request Smuggling in Transform Rules using hexadecimal escape sequences in the concat() function ($6000, critical)

Full payload bank, bypass frequencies, approach patterns and case-study excerpts: `references/evidence.md`.

## Corpus-backed method (this class)

1. Fingerprint the chain (CDN, reverse proxy, origin) — desync needs two parsers that disagree.
2. Run bounded smuggling probes with unique markers; avoid sustained or destructive requests.
3. Classify the desync variant from the response/timing pattern, and confirm with a harmless second request that observes the smuggled prefix.
4. Correlate with cache behaviour: an unkeyed header plus desync can poison a shared response.
5. Prove a concrete consequence (another user's response, cache poisoning, ACL bypass), not just a timeout.

### Signals

- Proxy/CDN in front of an origin with different HTTP parsing
- Duplicate Content-Length or both CL and Transfer-Encoding
- Timeout/desync behaviour on malformed framed requests

### Kill criteria

- Only a timeout with no observable cross-request effect.
- Single parser / no intermediary — smuggling cannot occur.
- Program excludes DoS-style or destabilizing request tests.

### Escalation chains

- Smuggling -> cache poisoning -> cross-user page takeover.
- Desync -> ACL bypass -> internal endpoint access.

### Veteran tip

Parser confusion and cache headers dominate the valid writeups; treat the intermediary, not the app, as the target.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Identify proxy/CDN + origin stack and HTTP version handling.
- Test CL.TE, TE.CL, TE.TE obfuscation, and HTTP/2 downgrade desync.
- Use timing-based and differential probes before exploitation.
- Check connection reuse, pipelining, and hop-by-hop headers.

### Deeper checklist

- Identify proxy/CDN + origin stacks and HTTP version handling.
- Test CL.TE, TE.CL, TE.TE obfuscation, and HTTP/2 downgrade desync.
- Use timing-based and differential probes before attempting exploitation.
- Check connection reuse, pipelining, and hop-by-hop header handling.
- Demonstrate a controlled impact: poisoning another user's request or bypassing controls.
- Keep payloads minimal and avoid disrupting production traffic.

### A. Discovery checklist — concrete places, params, headers, infra signals to look

- Map the full request chain before fuzzing: client -> CDN/WAF -> reverse proxy -> origin. Desync is a property of the chain, not one host. Record `Server`, `Via`, `X-Cache`, `CF-Cache-Status`, `X-Amzn-Trace-Id`, `X-Nf-Request-Id`, `X-Served-By` on every response to identify each hop.
- Fingerprint the upstream HTTP version. If the edge speaks h2 to the client but downgrades to HTTP/1.1 upstream, you have a fourth length source (H2) and CL/TE parser-diff tricks apply again. Send the same path over HTTP/1.1 and HTTP/2 in Burp Repeater (Inspector -> Request Attributes -> protocol) and diff the responses.
- Target endpoints likely to be on a shared connection pool: static assets (`/assets/*`, `/resources/*`, `/js/*`, `robots.txt`, `favicon.ico`), `/logout`, login redirects, any 30x-redirecting path. Early-response gadgets are what make 0.CL exploitable.
- Note WAF fingerprints that mean classic probes will be filtered: regex blocking of obfuscated `Transfer-Encoding`, requests with embedded `GET /... HTTP/1.1` in a body, or timing-based probes. If classic CL.TE fails on a hardened edge, pivot to parser-discrepancy detection instead of concluding "not vulnerable."
- Look for cloud-proxy infra with known parser quirks: AWS ALB in front of IIS (H-V discrepancy on malformed `Host`), web VPNs, and WAFs that rewrite requests. Kettle notes AWS declined to patch the ALB/IIS issue centrally; hardening knobs are `routing.http.drop_invalid_header_fields.enabled` and `routing.http.desync_mitigation_mode 

### Signals and surfaces

### Signal

- Reports: **101** · paid: **31**
- Median bounty **$1,800** · p90 **$6,000** · max **$20,000** · total **$104,040**
- Median upvotes **18**

### Where it pays

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

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`any endpoint behind CDN/proxy` `login` `API gateway` `static assets`

### Techniques, payloads and bypasses

### Payloads & probes

- CL.TE -> `Content-Length: 13` + `Transfer-Encoding: chunked`
- TE.CL -> chunked body with a smaller Content-Length
- TE.TE -> `Transfer-Encoding: xchunked`, `Transfer-Encoding : chunked`
- HTTP/2 -> `Transfer-Encoding: chunked` injected as a header

### Bypass tricks

- Obfuscate TE with case, spaces, tabs, and duplicate headers.
- Exploit front-end/back-end parser differences in header folding.
- Use cache deception/poisoning to prove impact.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Bypass for #488147 enables stored XSS on https://paypal.com/signin again** — `#510152` · PayPal · $20,000 · ▲2687
  > I've posted a full writeup over at https://portswigger.net/blog/http-desync-attacks-request-smuggling-reborn
- **Mass account takeovers using HTTP Request Smuggling on https://slackb.com/ to steal session cookies** — `#737140` · Slack · $0 · ▲870
  > The CLTE issue found on slackb.com is when the frontend server interprets the request sized using `Content-Length` and the backend server interprets the request using the `Transfer-Encoding: chunked` method.
- **Request smuggling on admin-official.line.me could lead to account takeover** — `#740037` · LY Corporation · $0 · ▲565
  > The reporter identified a request smuggling issue on admin-official.line.me [(TE.CL-type).](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn) The reporter clearly illustrated the impact without putting our users at risk or…
- **Stealing Zomato X-Access-Token: in Bulk using HTTP Request Smuggling on api.zomato.com** — `#771666` · Eternal · $0 · ▲559
  > It appears when you smuggle and hijack an HTTP request and you change the request endpoint to be: `https://some.host.name/desync/` on the request line the backend server should never see a request like this because the frontend server immediately returns `404…
- **HTTP request Smuggling** — `#867952` · Helium · $0 · ▲300
  > console.helium.com s vulnerable t

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 6× | `\r\r` |
| 4× | `\r\n` |
| 3× | `{size}` |
| 3× | `auth_digest_string_quoted()` |
| 3× | `parse_conversion()` |
| 2× | `GET https://<URL> HTTP/1.1` |
| 2× | `r\n` |
| 2× | `Connection: close\t` |
| 2× | `http.createServer()` |
| 2× | `Content-Length: 6\r\n\r\nHello A` |
| 2× | `http_req_set_reader()` |
| 2× | `http://newscdn.starbucks.com/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(document.domain)>%0d%0a0` |
| 2× | `is_custom_fetch_listing_match()` |
| 2× | `imap_state_listsearch_resp()` |
| 2× | `Curl_pp_readresp()` |
| 2× | `printf "POST / HTTP/1.1\r\n"\ / "Host: localhost:5000\r\n"\ / "X-Abc:\rxTransfer-Encoding: chunked\r\n"\ / "\r\n"\ / "1\r\n"\ / "A\r\n"\ / ` |
| 2× | `Response / { host: 'localhost:5000', 'x-abc': '', 'transfer-encoding': 'chunked' } / A / ---` |
| 2× | `[\r]xTransfer-Encoding: chunked[\r\n]` |
| 2× | `legit@example.com` |
| 2× | `{50}` |

### Bypass for #488147 enables stored XSS on https://paypal.com/signin again

`#510152` · PayPal · $20,000 · high · 2019-08-07 · ▲2687
> Due to a configuration in frontend, caching servers, it was possible for a researcher to use request smuggling to convert a page request into a cached redirect. If the cached redirect were accessed by a legitimate user, an attacker's content would be rendered instead of the requested page. While this would not impact any back-end data, this could interfere with the integrity of certain pages, including potential interference with the sign-in page.

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
- Double-desync 0.CL -> CL.0: request 1 poisons th

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

### C. Validation / proof bar — how to confirm and avoid false positives

- A timeout alone is not proof. Require a *different response* for the same sequence: your request returns a 404 while a subsequent benign request returns a redirect or another user's data. Distinguish V-H from H-V by which server the response appears to come from (banner/header shape), not by status codes.
- Demonstrate one of: (a) a smuggled prefix changing the next request's method/path (`GPOST`, 404 on a hidden path), (b) response-queue poisoning capturing another principal's response, (c) cache poisoning of a JS/static path leading to XSS, or (d) header injection / IP spoof leading to auth bypass. A "Mystery 400" is a lead, not a finding — convert it into a controllable response.
- Replay with a unique cachebuster on cacheable paths so your probes are not served from cache — but know when to strip it: Kettle's 24M-site Cloudflare case was missed until the cache-buster was removed. Test both with and without.
- Reproduce with the connection kept alive and control the exact CL offsets. If the exploit depends on front-end-injected headers containing the client IP, triage may fail from a different IP — disclose this or move the smuggle ahead of the injected headers.
- For client-side desync, prove the attack in a real browser with a cross-origin no-cors request that poisons the browser's own connection pool; a Burp-only PoC does not establish browser-deliverability.
- Do not report theoretical parser deviations (e.g. LF-only line endings on a directly accessed server) as bounties. They matter only wh

### Escalation and related chains

### Escalation chains

- Smuggling -> cache poisoning -> XSS.
- Smuggling -> auth bypass.
- Smuggling -> request capture.

### Impact Chain

```
Poison next request → access admin as victim
Steal credentials → capture victim's session
Cache poisoning → stored XSS at scale
```

---

### Related Skills & Chains

- **`web-cache`** — Smuggling + cache is the canonical critical chain; one smuggled request becomes the cached response for every subsequent victim. Chain primitive: CL.TE smuggle a request whose response body contains attacker HTML/JS → front-end cache stores it under a popular URL (`/`, `/login`) → de-sync poisoning where the smuggled request becomes the cached response for the next N victims, persisting for the cache TTL.
- **`auth-bypass`** — Smuggling reaches internal-only routes that the front-end WAF/auth-proxy filters out. Chain primitive: smuggle `GET /admin/users HTTP/1.1` past the front-end ACL that blocks external `/admin/*` → backend processes the smuggled request as if from a trusted internal source → bypass front-end auth by smuggling internal-routed request → admin data in the response queue.
- **`idor`** — Smuggling attaches the NEXT user's session cookies to an attacker-controlled request path. Chain primitive: smuggle `GET /api/me HTTP/1.1` with no cookies → backend pairs it with the next legitimate user's incoming connection cookies → victim's session cookie attached to attacker's smuggled request → attacker reads the response containing victim's PII/tokens.
- **`xss`** — Smuggling injects XSS payloads into the response stream of the next victim without ever appearing in a URL parameter. Chain primitive: smuggled request body contains reflected payload that the backend renders into the next response in the queue → next visitor to `/` receives attacker HTML inline → reflected XSS at every visitor without any URL parameter visi

### Related Skills & Chains

- **`hunt-cache-poison`** — Smuggling + cache is the canonical critical chain; one smuggled request becomes the cached response for every subsequent victim. Chain primitive: CL.TE smuggle a request whose response body contains attacker HTML/JS → front-end cache stores it under a popular URL (`/`, `/login`) → de-sync poisoning where the smuggled request becomes the cached response for the next N victims, persisting for the cache TTL.
- **`hunt-auth-bypass`** — Smuggling reaches internal-only routes that the front-end WAF/auth-proxy filters out. Chain primitive: smuggle `GET /admin/users HTTP/1.1` past the front-end ACL that blocks external `/admin/*` → backend processes the smuggled request as if from a trusted internal source → bypass front-end auth by smuggling internal-routed request → admin data in the response queue.
- **`hunt-idor`** — Smuggling attaches the NEXT user's session cookies to an attacker-controlled request path. Chain primitive: smuggle `GET /api/me HTTP/1.1` with no cookies → backend pairs it with the next legitimate user's incoming connection cookies → victim's session cookie attached to attacker's smuggled request → attacker reads the response containing victim's PII/tokens.
- **`hunt-xss`** — Smuggling injects XSS payloads into the response stream of the next victim without ever appearing in a URL parameter. Chain primitive: smuggled request body contains reflected payload that the backend renders into the next response in the queue → next visitor to `/` receives attacker HTML inline → reflected XSS at every visitor without

### Tools and wordlists

### Tools

`Burp HTTP Request Smuggler` · `smuggler.py` · `h2cSmuggler`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_request-smuggling.txt` | 94 |
| `~/.local/share/hackerone-reports/wordlists/params_request-smuggling.txt` | 17 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_request-smuggling.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_request-smuggling.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

### Nuclei

Use Burp HTTP Request Smuggler / smuggler.py against CDN+origin pairs; Nuclei coverage is limited.

```sh
nuclei -u https://target -tags smuggling,http-smuggling \
       -severity low,medium,high,critical -rl 40 -o nuclei_request-smuggling.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Source skills merged into this topic

- `h1skills` — `hackerone-request-smuggling`
- `hunting` — `request-smuggling`
- `cbh` — `hunt-http-smuggling`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 2 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `references/unified-method.md` — includes 2 merged companion methodology documents
- `references/corpus-wordlists/` — 2 mined paths/params/payload lists from the HackerOne corpus
- `../../upstream/` — complete unmodified archives of all five source repositories
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
