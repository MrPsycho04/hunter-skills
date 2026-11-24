---
name: crlf-injection
description: >-
  Hunt CRLF injection and response splitting. Use when testing redirects, headers, logs, and email fields. Backed by 168 disclosed HackerOne reports.
---

# CRLF / Header Injection — HackerOne field guide

Built from **168** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Signal

- Reports: **168** · paid: **25**
- Median bounty **$400** · p90 **$1,800** · max **$5,000** · total **$18,960**
- Median upvotes **11**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| Aiven Ltd | 1 | $5,000 | 72 |
| GitHub Security Lab | 2 | $3,300 | 17 |
| Airbnb | 1 | $2,500 | 37 |
| Internet Bug Bounty | 6 | $2,100 | 395 |
| X / xAI | 5 | $1,680 | 656 |
| Shopify | 2 | $1,300 | 141 |
| New Relic | 5 | $500 | 138 |
| Urban Company | 1 | $500 | 33 |

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`redirect` `next` `url` `filename` `email` `subject` `log`

## Tools

`Burp` · `crlfuzz` · `interactsh`

## Escalation chains

- CRLF -> XSS.
- CRLF -> cache poisoning.
- CRLF -> smuggling.

## Related

- `xss` (2,569 reports)
- `request-smuggling` (101 reports)
- `open-redirect` (385 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete places, params, headers, file types to look
- Response-header sinks: `Location`/redirect params (`redirect`, `next`, `url`, `return`), `Set-Cookie` / preference values, `Content-Type` (`?type=`), `Content-Disposition` / `filename`, custom reflected headers, and `X-Forwarded-*` echoes at a proxy.
- Request-header sinks: URL path segments reflected by an upstream proxy, session cookies echoed into a rewritten path (payment provider case in the 2026 PortSwigger research), and any header built from user input in curl/libcurl-style clients.
- Log-file sinks: newline injection into user-agent, referer, username, or filename → log forging (CWE-117); useful for confusion/delaying analysis rather than direct impact.
- SMTP/header contexts: email `subject`, `from`, `to`, and `filename` fields that are copied into mail headers.
- Classic Nginx misconfiguration to fingerprint: `proxy_pass http://backend$uri;` or `return 302 https://example.com$uri;` — Nginx URL-normalises `$uri`, decoding `%0d%0a` before forwarding upstream. OpenResty/Tengine inherit the same flaw.
- HTTP/2 downgrade surfaces: any front-end that folds header values into an HTTP/1.1 request; CRLF in an HTTP/2 header value can create a second header on the back end.
- 2025-2026 case studies worth modelling: Pi-hole web GHSA-5v79-p56f-x7c4 (session fixation + response splitting), curl `Curl_add_custom_headers` H1 #3484431 (request smuggling/SSRF), TikTok cookie tossing, telecom access-token theft ($20k), clothing-store account takeover via injected `Transfer-Encoding` ($2.2k).

### B. Techniques & bypasses — specific actionable techniques/payload shapes
- Canonical response-header injection: `GET /redirect?url=/home%0d%0aSet-Cookie:%20sessionid=attacker` → a forged `Set-Cookie` line in the raw 302 response.
- Response splitting: `%0d%0a%0d%0a` closes the header block and starts a fully attacker-controlled body/response; add a matching `Content-Length: 0` on the first response so the browser treats the next as a new response.
- Encoding variants to try in order: `%0d%0a`, `%250d%250a` (double-encoded), bare `%0a` (many parsers accept bare LF per RFC 9112), `\r\n` inside JSON/API values, and Unicode-normalisation variants (WAFs often check only the literal `%0d%0a`).
- Request-header injection detection oracles (PortSwigger 2026): `GET /<urlencoded> HTTP/13.37` → `HTTP/1.1 505 Version Not Supported`; injected `Transfer-Encoding: x` → `501 Not Implemented`; injected `Expect: asdf` → `417 Expectation Failed`. A predictable anomaly status proves the injected bytes are parsed as protocol syntax.
- Request splitting / Response Queue Poisoning: inject two consecutive CRLFs plus a complete second request (`TRACE / HTTP/1.1`), then harvest other users' responses (session cookies, auth tokens) from the same connection. `Connection: keep-alive` sometimes required.
- If double-CRLF is blocked, inject a *single* header: `Transfer-Encoding: chunked` alongside the existing `Content-Length` produces a CL.TE desync; confirm with the timeout technique (`Transfer-Encoding: chunked` + truncated body → 30s hang).
- Nested response splitting CSP bypass (siunam, 2025): inject `Content-Length` and a second response whose body is a `Content-Type` + `<script>` pair, so a strict `script-src 'self'` CSP is bypassed because the script appears to come from a same-origin static path. Fixed-length Content-Length can be handled by padding with junk.
- CDN-Cache-Control trick: inject `CDN-Cache-Control: private="Location"` to make Cloudflare strip the `Location` header, allowing XSS to fire on a redirect response; combine with `Content-Type: text/html;charset=ISO-2022-JP` and escaped script tokens to evade WAF signatures.
- Reverse desync (classic 2004 response splitting): inject `Content-Length: 0` plus a second response in the *server's* reply; usually blocked today by stacked-response handling, but worth testing.
- Browser-powered desync: most CRLF-powered attacks work via `fetch()` or navigation — use `window.open()` + `location` or rapid iframe creation for connection-/IP-locked cases, enabling desync worms and HttpOnly cookie theft via HEAD/Range over-read.

### C. Validation / proof bar — how to confirm and avoid false positives
- Always inspect the **raw** response in Burp (not the rendered browser view) — the browser hides exactly the byte-level structure you are proving.
- Confirm the injected header appears as its own line (`Set-Cookie: ...` etc.), not as text inside the original header value or body — that distinction separates real injection from reflection.
- A WAF 403 on `%0d%0a` is a filter hit, not a finding; try double encoding, bare LF, and Unicode-normalisation variants before concluding.
- For response splitting, prove the second response is actually parsed: the browser must render attacker content, or a cache must serve it to a second visitor. A well-formed but ignored second response is not impact.
- For request-header injection → desync, prove cross-user impact with a unique marker (own email changed, collaborator callback, stolen token from another user) rather than only an anomaly status code. Anomaly statuses prove parsing; they do not prove exploitation.
- Avoid destructive PoCs: logging every active user into your account or overwriting carts is real impact but creates noise and can end an engagement early — prefer a benign marker.
- Wait and re-poll Collaborator for delayed interactions; poll for 30-120s and use unique subdomains per sink.
- When reporting, chain the primitive to a concrete outcome: session fixation, cache poisoning, cross-user XSS/ATO, or internal token theft. Bare "header injection" is routinely downgraded.

**Encoding matrix (try every row):**
- `%0D%0A` — canonical CRLF, URL-encoded.
- `%250d%250a` — double-encoded; survives one decode, becomes CRLF after a second.
- `%0A` / `%0D` — bare LF / bare CR; many parsers accept either as a line terminator.
- `%0d%0a%0d%0a` — header block terminator (response splitting / request splitting).
- `\r\n` literal — JSON body values, log fields, SMTP headers.
- Unicode normalisation variants — defeat WAFs that only match ASCII `%0d%0a` (BlackHat USA 2025 research).
- `%c0%0d%c0%0a` — overlong UTF-8 encodings on legacy servers.

**Impact ladder for triage:**
- Low: a forged custom header echoed back with no security consequence.
- Medium: open redirect, arbitrary header injection, log forging.
- High: session fixation via forged `Set-Cookie`, CSP/frame-header override enabling clickjacking or XSS, cache poisoning of a single URL.
- Critical: response-queue poisoning / CL.TE desync stealing other users' cookies and tokens, mass cache poisoning, desync worm, HttpOnly cookie theft.

**Tooling and detection aids:**
- `crlfuzz` for parameter fuzzing; Burp's HTTP Request Header Injection scan check; the open-source `crlf-powered-desync-scanner` Burp extension and `crlf-desyncs` nuclei templates from the 2026 research.
- Hackvertor `<@urlencode_all> ... </@urlencode_all>` notation makes multi-line request-splitting payloads readable in Burp Repeater.
- Test non-path insertion points explicitly (cookies, headers, JSON fields) — the research calls these the best bet for an easy bounty because tooling covers paths well but not other locations.
- For header injection found by a scanner, PortSwigger's 2026 "one prompt" workflow is: identify the upstream injection location, validate via request splitting with unique status codes, mini-crawl for a redirect gadget (Host / X-Forwarded-Host / absolute URL), then combine prefix + gadget into the exploit.
- Always capture the raw hex of the injected bytes when reporting a request-smuggling chain — hex dumps are decisive evidence that CRLF was transmitted unsanitized (as in curl H1 #3484431).
- For log-injection variants, demonstrate the forged entry in the actual log view (or a log-shipping sink) rather than only in the request — the impact is analyst confusion and delayed detection.
- A single extra header is often enough: a forged `X-Forwarded-For`, `X-Original-URL`, or `X-Rewrite-URL` can alter upstream authorization or routing even when response splitting is blocked.

### D. Sources — numbered list of URLs you actually fetched
1. https://portswigger.net/research/crlf-powered-desync-attacks
2. https://owasp.org/www-community/attacks/HTTP_Response_Splitting
