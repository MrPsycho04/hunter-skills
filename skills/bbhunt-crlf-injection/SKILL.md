---
name: bbhunt-crlf-injection
description: "Use for user input reflected into headers, redirects, filenames, cookies, or logs where CR/LF can be injected. Unified from 2 upstream skills (h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# CRLF Injection and Response Splitting — unified methodology

> **Unified skill.** Built from 2 upstream skills across h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus-backed method (this class)

1. Locate reflection into header values rather than bodies; query, path and JSON fields can all reach headers.
2. Test raw, URL-encoded and double-encoded CR/LF, plus Unicode line separators where the stack normalizes them.
3. Determine whether the framework blocks newlines or the proxy/CDN normalizes them away.
4. For response splitting, prove a second header or body section is actually parsed by the client.
5. For log/filename injection, prove a meaningful consequence (header injection in an email, log forging that changes an access decision).

### Signals

- Input copied into a header or Set-Cookie
- Filename/content-disposition controlled by user
- Redirect Location built from input

### Kill criteria

- Newlines are rejected or safely encoded at every layer.
- Injected header has no observable effect on client behaviour.

### Escalation chains

- CRLF in redirect -> header injection -> cache poisoning or session fix.

### Veteran tip

Corpus bypasses cluster around encoding layers — test the decoder before writing a payload.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Inject %0d%0a into params reflected in headers, redirects, or filenames.
- Test header injection for XSS, cache poisoning, and smuggling.
- Check email header injection in contact/notification forms.

### Deeper checklist

- Inject `%0d%0a` into params reflected in headers, redirects, or filenames.
- Test header injection for XSS, cache poisoning, and request smuggling.
- Try encoded variants and unicode line separators.
- Check email header injection in contact/notification forms.
- Demonstrate header control or response splitting.

### A. Discovery checklist — concrete places, params, headers, file types to look

- Response-header sinks: `Location`/redirect params (`redirect`, `next`, `url`, `return`), `Set-Cookie` / preference values, `Content-Type` (`?type=`), `Content-Disposition` / `filename`, custom reflected headers, and `X-Forwarded-*` echoes at a proxy.
- Request-header sinks: URL path segments reflected by an upstream proxy, session cookies echoed into a rewritten path (payment provider case in the 2026 PortSwigger research), and any header built from user input in curl/libcurl-style clients.
- Log-file sinks: newline injection into user-agent, referer, username, or filename → log forging (CWE-117); useful for confusion/delaying analysis rather than direct impact.
- SMTP/header contexts: email `subject`, `from`, `to`, and `filename` fields that are copied into mail headers.
- Classic Nginx misconfiguration to fingerprint: `proxy_pass http://backend$uri;` or `return 302 https://example.com$uri;` — Nginx URL-normalises `$uri`, decoding `%0d%0a` before forwarding upstream. OpenResty/Tengine inherit the same flaw.
- HTTP/2 downgrade surfaces: any front-end that folds header values into an HTTP/1.1 request; CRLF in an HTTP/2 header value can create a second header on the back end.
- 2025-2026 case studies worth modelling: Pi-hole web GHSA-5v79-p56f-x7c4 (session fixation + response splitting), curl `Curl_add_custom_headers` H1 #3484431 (request smuggling/SSRF), TikTok cookie tossing, telecom access-token theft ($20k), clothing-store account takeover via injected `Transfer-Encoding` ($2.2k).

### Signals and surfaces

### Signal

- Reports: **168** · paid: **25**
- Median bounty **$400** · p90 **$1,800** · max **$5,000** · total **$18,960**
- Median upvotes **11**

### Where it pays

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

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`redirect` `next` `url` `filename` `email` `subject` `log`

### Techniques, payloads and bypasses

### Payloads & probes

- `%0d%0aSet-Cookie:%20x=1` `%0aLocation:%20//evil.com`
- `%E5%98%8A%E5%98%8D` unicode CRLF
- `\r\n` in filenames and log lines

### Payload bank

**20 curated payloads** in 2 context groups. Try them in order, stop at the first hit, then minimize. These are seeds, not a substitute for understanding the sink.

### Bypass tricks

- Double encoding and unicode line separators.
- Use header folding and whitespace variations.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **CRLF injection** — `#446271` · X / xAI · $0 · ▲439
  > https://ads.twitter.com/subscriptions/mobile/landing?ref=gl-tw-tw-promote-mode?t=%0d%0atest:tested
- **HTTP Response Header Injection in shopify/pitchfork + Rack 3** — `#2279572` · Shopify · $800 · ▲136
  > Header injection succeeds in case of `r\n` and `\n`.
- **CRLF injection leads to internal XSS on PangleGlobal** — `#2189960` · TikTok · $0 · ▲97
  > A cross-site scripting vulnerability was found on a Pangle endpoint due to CRLF injection on the 'file name' parameter.
- **CRLF to XSS & Open Redirection** — `#2012519` · TikTok · $0 · ▲97
  > This could have led to Reflective XSS (Cross-Site Scripting) to gain access to a user's cookies, or the ability to send users to unauthorized webpages ending in "tiktok.com" via an open redirect.
- **Creating malformed URLs via new line character in-between two URLs leads to misrepresented hyperlinks in Tweets/DMs** — `#712979` · X / xAI · $0 · ▲96
  > This allows an attacker to create realistic looking phishing URLs via combining `attacker.com` + `%0d` + `website.com`.
- **Grafana RCE via SMTP server parameter injection** — `#1200647` · Aiven Ltd · $5,000 · ▲72
  > Using this CRLF-injection, the `rendering args` of grafana image renderer can be modified which leads to code execution on the Grafana server.
- **jitsi-meet: Prosody/Jigasi missing header whitelist in mod_filter_iq_rayo allows arbitrary SIP header injection and Caller

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 14× | `\r\n` |
| 5× | `rtsp_do()` |
| 5× | `data->set.crlf` |
| 5× | `conn_config->CRLfile` |
| 5× | `Curl_setstropt()` |
| 4× | `Curl_creader_total_length()` |
| 3× | `Mail_mimePart::encodeHeader()` |
| 3× | `cr_init_backend()` |
| 3× | `auth_digest_string_quoted()` |
| 2× | `r\n` |
| 2× | `%0d` |
| 2× | `curl_easy_setopt()` |
| 2× | `stripcslashes()` |
| 2× | `preg_match('#([^\s\x21-\x7E]){1}#')` |
| 2× | `Net_SMTP::quotedata()` |
| 2× | `http://newscdn.starbucks.com/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(document.domain)>%0d%0a0` |
| 2× | `rtsp_setup_request()` |
| 2× | `rtsp_header_alloc()` |
| 2× | `legit@example.com` |
| 2× | `invalid ${key} header` |

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- Canonical response-header injection: `GET /redirect?url=/home%0d%0aSet-Cookie:%20sessionid=attacker` → a forged `Set-Cookie` line in the raw 302 response.
- Response splitting: `%0d%0a%0d%0a` closes the header block and starts a fully attacker-controlled body/response; add a matching `Content-Length: 0` on the first response so the browser treats the next as a new response.
- Encoding variants to try in order: `%0d%0a`, `%250d%250a` (double-encoded), bare `%0a` (many parsers accept bare LF per RFC 9112), `\r\n` inside JSON/API values, and Unicode-normalisation variants (WAFs often check only the literal `%0d%0a`).
- Request-header injection detection oracles (PortSwigger 2026): `GET /<urlencoded> HTTP/13.37` → `HTTP/1.1 505 Version Not Supported`; injected `Transfer-Encoding: x` → `501 Not Implemented`; injected `Expect: asdf` → `417 Expectation Failed`. A predictable anomaly status proves the injected bytes are parsed as protocol syntax.
- Request splitting / Response Queue Poisoning: inject two consecutive CRLFs plus a complete second request (`TRACE / HTTP/1.1`), then harvest other users' responses (session cookies, auth tokens) from the same connection. `Connection: keep-alive` sometimes required.
- If double-CRLF is blocked, inject a *single* header: `Transfer-Encoding: chunked` alongside the existing `Content-Length` produces a CL.TE desync; confirm with the timeout technique (`Transfer-Encoding: chunked` + truncated body → 30s hang).
- Nested response splitting CSP bypass (siunam, 2025): 

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
- `%0D%0A` — canonical CRLF, URL-encoded

### Escalation and related chains

### Escalation chains

- CRLF -> XSS.
- CRLF -> cache poisoning.
- CRLF -> smuggling.

### Tools and wordlists

### Tools

`Burp` · `crlfuzz` · `interactsh`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_crlf-injection.txt` | 94 |
| `~/.local/share/hackerone-reports/wordlists/params_crlf-injection.txt` | 51 |
| `~/.local/share/hackerone-reports/wordlists/payloads_crlf-injection.txt` | 20 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_crlf-injection.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_crlf-injection.txt \
     -mr 'canary|error|invalid|not found' -rate 40
ffuf -u 'https://target/api?<param>=FUZZ' -w $W/payloads_crlf-injection.txt \
     -mr '<hit-marker>' -rate 20
```

### Nuclei

Test params reflected in headers, redirects, filenames, and emails.

```sh
nuclei -u https://target -tags crlf \
       -severity low,medium,high,critical -rl 40 -o nuclei_crlf-injection.txt
nuclei -u https://target -t ~/nuclei-templates/dast/vulnerabilities/crlf -dast \
       -rl 40 -o nuclei_crlf-injection_crlf.txt
nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/generic \
       -rl 40 -o nuclei_crlf-injection_generic.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Source skills merged into this topic

- `h1skills` — `hackerone-crlf-injection`
- `hunting` — `crlf-injection`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 2 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `../../upstream/` — complete unmodified archives of all five source repositories
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
