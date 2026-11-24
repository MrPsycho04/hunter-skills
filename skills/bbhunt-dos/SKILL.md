---
name: bbhunt-dos
description: "Use only when the program explicitly allows availability testing; cover algorithmic complexity, unbounded work, and cost amplifiers. Unified from 2 upstream skills (h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Denial of Service and Resource Exhaustion — unified skill

> **Complete merged skill.** Everything from 2 upstream skills across h1skills, hunting and the local HackerOne corpus is contained in this file. Unmodified originals remain in `references/` for provenance only.

## Corpus evidence — 66 valid HackerOne reports (18 paid / 27%)

Every disclosed report is valid; payment is an impact signal, not a validity test.

### Techniques ranked across ALL valid reports

| Technique | Reports |
|---|---:|
| internal service / port / container | 14 |
| public source-code / repo review | 14 |
| HTTP method / verb tampering | 10 |
| file upload / filename / extension | 10 |
| parameter pollution / duplicate keys | 10 |
| admin / privileged-role context | 10 |
| encoding / double-encode / null byte | 9 |
| Content-Type / body-format switch | 8 |
| header injection (Host / X-Forwarded / etc.) | 6 |
| WAF / sanitizer / filter bypass | 6 |
| second-order / stored / blind delivery | 6 |
| OAST / DNS / HTTP callback proof | 5 |
| race / concurrency / timing | 5 |
| error message / stack trace probing | 4 |
| unauthenticated / removed-cookie test | 4 |
| fuzzing / wordlist brute force | 3 |
| intercept & replay request in Burp | 3 |
| replay / modify a captured request | 3 |
| XML / SOAP / SAML / XXE | 3 |
| deserialization / gadget chain | 3 |
| parser confusion / normalization | 3 |
| JWT / token / base64 decode | 3 |
| JS bundle / source-map inspection | 3 |
| third-party data / paste / breach reuse | 2 |
| employee / developer public info | 1 |
|  HosT/absolute-URL reset poisoning | 1 |
| git history / exposed .git | 1 |
| verbose debug / framework fingerprint | 1 |
| two-account / cross-account replay | 1 |
| mass assignment / extra request fields | 1 |
| subdomain / DNS / cert-transparency recon | 1 |
| redirect chain / Location header | 1 |

### Parameters observed in writeups

`conn` (10), `format` (5), `mem` (3), `len` (3), `csrfmiddlewaretoken` (2), `email` (2), `content` (2), `json` (2), `uid` (2), `mail` (2), `username` (2), `samaccountname` (2), `cloudron_ldap_bind_dn` (2), `cloudron_ldap_bind_password` (2), `cloudron_ldap_users_base_dn` (2), `cloudron_ldap_url` (2), `data` (2), `ap_save` (2), `repeatable` (2), `subject` (1), `name` (1), `message` (1), `charset` (1), `m-b` (1), `m-s` (1), `m-css_v` (1), `m-login` (1), `m-early_v` (1), `m-tz` (1), `m-wf-loaded` (1)

### Bypass primitives observed

`content-type` (9), `blind` (5), `backslash` (4), `unicode` (2), `chunked` (2), `crlf` (2), `blacklist` (1), `url encoded` (1), `bypass` (1), `transfer-encoding` (1), `lowercase` (1), `bypasses` (1)

### Impact language observed

`password` (58), `admin` (30), `token` (23), `localhost` (15), `credential` (7), `secret` (6), `rce` (2), `arbitrary file` (1)

### Case studies — full excerpts (paid and unpaid)

#### [2520679](https://hackerone.com/reports/2520679) — Possible DoS Vulnerability with Range Header in Rack

Internet Bug Bounty · $5420 · high

I made a report and patch at > There is a possible DoS vulnerability relating to the Range request header in Rack. This vulnerability has been assigned the CVE identifier CVE-2024-26141. > Versions Affected: >= 1.3.0. Not affected: < 1.3.0 Fixed Versions: 3.0.9.1, 2.2.8.1 ## Impact > Carefully crafted Range headers can cause a server to respond with an unexpectedly large response. Responding with such large responses could lead to a denial of service issue. > Vulnerable applications will use the Rack::File middleware or the Rack::Utils.byte_ranges methods (this includes Rails applications).

#### [880187](https://hackerone.com/reports/880187) — Near to Infinite loop when changing Group's name that has API token as Team Member

HackerOne · $2500 · medium

**Summary:** The ` contains an iteration or loop with an exit condition that is near to infinite loop. If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory and even a DoS attack. **Description:** Hello Security team, I have a test Enterprise Program ` enabled in my second H1 account. Last days I have been hunting on the program features and I have founded a weird behavior that can consume excessive resources on the platform. Under the `group management` feature the program administrator can add a new `group` to segregate the permissions. The website runs the following function to create the group on the platform. Once the group is created its can be read in `JSON` format throuhg the page ` as example below: {F838205} From the `group management` page the program administrator can add only users to that group, can't add API token to that group from there. {F838206} But the API token can be added to that group through ` {F838209} Clicking on **Manage groups** is possible to add this API token to the previously created group. {F838210} Once you save that, you can read this API token permission/groups in `JSON` format too, just goint to ` team member ID of your API toke].json` Just like before, the same data will be displayed. Also, the `group` will be displayed under API Token page. {F838211} The issu

#### [1627159](https://hackerone.com/reports/1627159) — Rack CVE-2022-30122: Denial of Service Vulnerability in Rack Multipart Parsing

Internet Bug Bounty · $2400 · medium

ReDoS in `Rack::Multipart::BROKEN_QUOTED` and `Rack::Multipart::BROKEN_UNQUOTED`. > Carefully crafted multipart POST requests can cause Rack's multipart parser to take much longer than expected, leading to a possible denial of service vulnerability. ## Impact When the client sends a specially crafted header, it occur ReDoS on the server side. Servers that interpret Post data by default, like Rails, are affected.

#### [20861](https://hackerone.com/reports/20861) — moderate: mod_deflate denial of service

Internet Bug Bounty · $500 · severity n/a

A resource consumption flaw was found in mod_deflate. If request body decompression was configured (using the "DEFLATE" input filter), a remote attacker could cause the server to consume significant memory and/or CPU resources. The use of request body decompression is not a common configuration. Acknowledgements: This issue was reported by Giancarlo Pellegrino and Davide Balzarotti Resolved in Apache httpd 2.4.10-dev:

#### [1895316](https://hackerone.com/reports/1895316) — CVE-2023-25692: Apache Airflow Google Provider: Google Cloud Sql Provider Denial Of Service and Remote Command Execution

Internet Bug Bounty · $480 · low

## 0x01 Environment - airflow 2.5.1 - apache-airflow-providers-google 8.8.0 - Build with docker compose ## 0x02 Reproduction Steps ### 2.1 Create a malicious Google Cloud SQL Database connection Create the following Google Cloud SQL Database connection named **aaa** under the Admin->Connections menu.Among them, Host, Schema, Login, and Port are required, just fill in the content that conforms to the format. {F2213508} The actual content filled in **Extra** field is as follows. Note that **sql_proxy_version** must be similar to `?a=`, and the value of **sql_proxy_binary_path** is set to the command to be executed. Fill in 'whoami' here. ### 2.2 Use the CloudSQLExecuteQueryOperator operator in the DAG for verification Create a google_test.py script that uses the CloudSQLExecuteQueryOperator operator, and put it in the `/opt/airflow/dags` directory in the background so that it can be automatically loaded by airflow. The content is as follows, where **gcp_cloudsql_conn_id** is set to the connection name we established above **aaa** Enable the** example_gcp_sql_query** DAG corresponding to our **google_test.py** script in the UI management interface, and run. Click to view the running graph and logs through the Graph menu. {F2213514} It can be seen from the log that the victim machine executed the malicious parameter 'whoami' we constructed. {F2213518} ### 2.3 Other methods for remo

#### [3556769](https://hackerone.com/reports/3556769) — Incomplete fix for CVE-2026-21637: loadSNI() in _tls_wrap.js lacks try/catch leading to Remote DoS

Node.js · no bounty — still valid · high

A flaw in Node.js TLS error handling leaves `SNICallback` invocations unprotected against synchronous exceptions, while the equivalent ALPN and PSK callbacks were already addressed in CVE-2026-21637. This represents an incomplete fix of that prior vulnerability. When an `SNICallback` throws synchronously on unexpected input the exception bypasses TLS error handlers and propagates as an uncaught exception, crashing the Node.js process. * This vulnerability affects all Node.js versions that received the CVE-2026-21637 fix, including **20.x, 22.x, 24.x, and 25.x**, on any TLS server where `SNICallback` may throw on unexpected `servername` input.

#### [3168039](https://hackerone.com/reports/3168039) — CVE-2025-5399: WebSocket endless loop

curl · no bounty — still valid · low

The function `curl_ws_send()` in libcurl on commit [12d13b84fa40aa657b83d5458944dbd9b978fb7e]( contains an infinite loop that can be triggered by a malicious server under specific circumstances. If an application uses `curl_ws_recv()` and `curl_ws_send()` to communicate with a websocket server, a malicious server can send a carefully timed PING message while the client is constructing a frame via `CURLWS_OFFSET` that leads to the next `curl_ws_send()` invocation not terminating a loop that flushes data. The affected code is in file `lib/ws.c` in function `curl_ws_send()` on [lines 1376 - 1419]( `buflen` is coming from the application and is the length of data to be sent. If the loop starts with `ws->sendbuf_payload == 0`, then `buflen > ws->sendbuf_payload` is always true. After a successful `ws_flush()`, `sent`, `buffer` and `buflen` remain unmodified and the loop runs forever. ## PoC Consider the following client that repeatedly sends and receives messages: And consider the following server that serves malicious packets: When the server is launched in the background with And the client is run with it can be seen that `./client` takes up 100% CPU usage and never terminates. ## Explanation I still don't 100% understand the websocket code and why it comes to this bug but here is a rough overview what happens: - The client tries building a 70-byte frame over the course of 3 `curl

### Recurring approach patterns from real reports

- 1× steps to reproduce i ve created a script that can be run here against any rack based application by default it generates a request body with parts which in my testing was enough to cause github api to take between seconds to service the request once the request transfer had completed
- 1× f838206 but the api token can be added to that group through f838209 clicking on manage groups is possible to add this api token to the previously created group
- 1× so in my test i changed from testing to aaabc2
- 1× istead of the above setting i tested the app locally
- 1× as mentioned in another project to simulate a ldap server for users authentication i used a test server provided by the same author you can find attached
- 1× summary hello team while testing it was observed that on 3d cs money a dos is possible via specially crafted request using only single request from single machine on search bar
- 1× filed publicly my first gut reaction was that this had to be a problem with curl fnmatch as that has caused us grief in the past and on most platforms we use the native fnmatch now but not on windows iirc and this is a reported to happen on windows but i then built a test program and i made it crash in what seems like potential stack overflow due to recursive calls to wc statemach from within itself
- 1× i discovered this issue in the ftp functionality of the curl project as described in curl uses epsv mode as the default ftp file transfer method
- 1× component pkg plugin plugin go affected version aws encryption provider 4341c70 all versions found by fuzz testing fuzzv1decrypt seed empty byte summary v1plugin decrypt accesses request cipher without checking that the slice is non empty
- 1× a sufficiently deep tree of nested curl mime subparts objects causes stack exhaustion when libcurl starts reading the mime body
- 1× summary gis geometry collection init from wkb and get data size recurse once per nested child geometry when parsing a wkb well known binary geometrycollection with no recursion depth limit and no check stack overrun call

## Corpus-backed method (this class)

1. Confirm the program's DoS policy before any test; many exclude it entirely.
2. Prefer bounded, single-request demonstrations of pathological complexity over sustained load.
3. Measure the cost delta (time, memory, requests, money) and identify the algorithmic cause.
4. Check for ways one cheap request triggers disproportionate work in a shared or multi-tenant context.
5. Stop at the threshold that proves the issue; never degrade service for other users.

### Signals

- Expensive search/export/report operations
- Recursive or combinatorial input handling
- No quota on expensive API calls or outbound messages

### Kill criteria

- Program excludes DoS/availability findings.
- Only a personal slowdown with no shared-resource impact.
- Requires sustained traffic or third-party harm.

### Escalation chains

- Amplified cost -> quota exhaustion -> service degradation (only if permitted).

### Probes

- Deeply nested structures, catastrophic regex inputs, unbounded page-size/export parameters.

### Veteran tip

Most valid DoS-class reports in the corpus are about unbounded work or cost, not raw traffic floods.

## Unified upstream methodology (complete, deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Look for expensive operations on user input: regex, XML/JSON parsing, image/video, PDF.
- Test unbounded pagination, large limits, deep nesting, and zip bombs (safely).
- Check rate limits on search/export/invite/SMS.
- Try amplification: one request causing many downstream calls.

### Deeper checklist

- Look for expensive operations on user input: regex, XML/JSON parsing, image/video processing, PDF generation.
- Test unbounded pagination, large `limit`/`size` values, deep nesting, and zip bombs (safely, low volume).
- Check rate limits on expensive endpoints (search, export, invite, SMS/email).
- Try amplification: one request causing many downstream calls or notifications.
- Test file decompression, archive extraction, and thumbnail generation for resource blowups.
- Use small, controlled payloads; never run sustained floods against production.
- Demonstrate recovery impact and quantify resource amplification.

### A. Discovery checklist — concrete fingerprints, endpoints, headers, CVEs to look for

- **ReDoS ("evil regex") patterns — OWASP's canonical list.** A regex is vulnerable when it contains **grouping with repetition**, and inside the repeated group **another repetition or an overlapping alternation**:
```
(a+)+$          ([a-zA-Z]+)*$       (a|aa)+$       (a|a?)+$
```
  Trigger with `aaaaaaaaaaaaaaaaaaaaaaaa!` (nine-to-thirty `a`s then `!`). OWASP's worked example `^(a+)+$` has 16 possible paths for `aaaaX` and **65,536** for 16 `a`s — doubling per character, i.e. exponential runtime. Also check real-world patterns: `^(([a-z])+.)+[A-Z]([a-z])+$`, and the email-validation regex at RegexLib id 1757 (`(([-.]|[_]+)?([a-zA-Z0-9]+))*`). Known CVEs: **CVE-2022-3517** (`minimatch`), **CVE-2015-2526** (.NET Framework), CVE-2009-3275/3276/3277 (EntLib / Telerik / DataVault).
- **Regex injection is a separate, higher-severity variant:** if user input becomes the *pattern* (OWASP's Java `new Regex(userName)` example), inject `^(([a-z])+.)+[A-Z]([a-z])+$` as the username and 30 `a`s + `!` as the password — no vulnerable regex needs to exist in the source.
- **CVE-2023-44487 — HTTP/2 Rapid Reset (CISA KEV; Cloudflare/Google/AWS coordinated disclosure).** Peaked at **201 million requests/second** using only ~20,000 bots. Mechanism: client opens HTTP/2 streams with `HEADERS` then immediately sends `RST_STREAM`; cancelled streams leave the open/half-closed state, so `SETTINGS_MAX_CONCURRENT_STREAMS` provides **no protection**. In Cloudflare's pcap, the first HEADERS frame is 26 bytes and subsequent ones just **9 bytes** thanks to HPACK — one 1,500-byte packet carried 525 requests. Affects essentially every HTTP/2 implementation.
- **Observables that indicate Rapid Reset rather than ordinary load:** a huge HEADERS/RST_STREAM frame ratio in Wireshark (`Statistics > HTTP2`), **502 Bad Gateway** spikes from saturated proxy→business-logic links, and **499** client-close errors (clients assume 100 concurrent streams; servers advertising fewer cause resets). Cloudflare briefly set max concurrency to 64, which broke legitimate image-gallery pages that open 100 streams — so 499s alone are not proof of an attack.
- **Classic app-layer DoS surfaces (baseline, with 2026 validation bar):** unbounded `search` / `export` / `report` / `graphql` (query depth, batching), image processing (pixel flood / decompression bombs), file parsing (zip bombs, XXE entity expansion), pagination with huge `offset`/`limit`, and any endpoint where input length controls an O(n²) or O(2ⁿ) path.
- **Framework-specific 2026 signals to cross-reference:** Node2Shell (CVE-2026-111497, Brotli decoder — crash is the *reliable* outcome, RCE is narrow); Telerik CVE-2025-3600 (unsafe reflection → app-pool recycle); Kubernetes IngressNightmare NGINX config injection.
- **Where ReDoS actually hides in 2026 stacks:** email/URL validators in Node (validator.js, older `minimatch`), Java (Spring routing regex, Apache Commons), Python (`re` on user-supplied patterns, Django URL converters), and WAF rule sets. A vulnerable regex in a WAF can hang the WAF itself — test by sending the torture string through the proxy and comparing with a direct-to-origin baseline where scope allows.
- **Amplification math for the report:** for `^(a+)+$`, each added `a` roughly doubles the number of NFA paths; a payload of ~30 characters can consume seconds of CPU on one worker. Because workers are finite, a modest number of concurrent ReDoS requests can exhaust the pool — this is the "ReDoS → worker exhaustion" escalation chain in the baseline.
- **HTTP/2 protocol detail worth citing:** the default `SETTINGS_MAX_CONCURRENT_STREAMS` is effectively unlimited (31-bit stream ID space, odd IDs → 1,073,741,824); the spec recommends at least 100. Clients generally do not wait for SETTINGS and assume 100, which is why a server value below 100 causes 499s — useful when separating legitimate client behavior from Rapid Reset.

### Signals and surfaces

### Signal

- Reports: **66** · paid: **18**
- Median bounty **$447** · p90 **$2,500** · max **$5,420** · total **$18,061**
- Median upvotes **11**

### Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| Internet Bug Bounty | 6 | $8,800 | 85 |
| Pornhub | 2 | $2,500 | 160 |
| HackerOne | 1 | $2,500 | 77 |
| Open-Xchange | 8 | $1,894 | 70 |
| Tron Foundation | 1 | $1,500 | 23 |
| LocalTapiola | 1 | $400 | 15 |
| Razer | 1 | $375 | 21 |
| Boozt Fashion AB | 1 | $80 | 12 |

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`search` `export` `report` `image` `upload` `graphql` `pagination`

### Techniques, payloads and bypasses

### Payloads & probes

- `limit=999999` `page_size=100000` `depth=50`
- ReDoS -> `(a+)+$` in a search/regex field
- Zip bomb -> nested archives; XML billion laughs
- GraphQL alias storm

### Bypass tricks

- Distribute requests across connections/accounts.
- Use slowloris-style partial bodies where allowed.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Near to Infinite loop when changing Group's name that has API token as Team Member** — `#880187` · HackerOne · $2,500 · ▲77
  > Once you save that, you can read this API token permission/groups in `JSON` format too, just goint to `https://hackerone.com/[Your Program]/team members/[The team member ID of your API toke].json`
- **Incomplete fix for CVE-2026-21637: loadSNI() in _tls_wrap.js lacks try/catch leading to Remote DoS** — `#3556769` · Node.js · $0 · ▲59
  > This vulnerability affects all Node.js versions that received the CVE-2026-21637 fix, including 20.x, 22.x, 24.x, and 25.x , on any TLS server where `SNICallback` may throw on unexpected `servername` input.
- **CVE-2025-5399: WebSocket endless loop** — `#3168039` · curl · $0 · ▲58
  > If an application uses `curl ws recv()` and `curl ws send()` to communicate with a websocket server, a malicious server can send a carefully timed PING message while the client is constructing a frame via `CURLWS OFFSET` that leads to the next `curl ws…
- **Possible DoS Vulnerability with Range Header in Rack** — `#2520679` · Internet Bug Bounty · $5,420 · ▲56
  > https://discuss.rubyonrails.org/t/possible-dos-vulnerability-with-range-header-in-rack/84944
- **Memory Exhaustion in CometBFT v1.0.1 via malicious ProposalMessage leads to network-wide denial of service** — `#3510161` · Cosmos · $0 · ▲47
  > An attacker can send a malicious `ProposalMessage` with `PartSetHeader.Total` set to `2^32-1`, causing the receiving node to immediately allocate 512 MB of memory without prior validation, resulting in an OOM kill.
- **V1Plugin.Decrypt panics on empty ciphertext (Remote DoS)** — `#3620748` · AWS VDP · $0 · ▲41
  > Sending a `DecryptRequest` with empty or nil `Cipher` field causes an unrecoverable `index out of range` panic that crashes the entire gRPC server process.
- **Application DOS via specially crafted payload on 3d.cs.money** — `#993582` · CS Money · $0 · ▲36
  > While testing it was observed that on 3d.cs.money a DOS is possible via specially crafted request using only single request from single machine on search bar.
- **DoS via Unbounded Memory Allocation in sendWebStream on Fastify v5.7.0+ leads to OOM crash when backpressure is ignored** — `#3524779` · Fastify · $0 · ▲35
  > When a `ReadableStream` is sent as a response, Fastify continuously pulls data from the stream producer (`controller.enqueue`) and writes it to the response object (`res.write`).
- **V2Plugin.Decrypt panics on empty ciphertext (Remote DoS)** — `#3620753` · AWS VDP · $0 · ▲25
  > `V2Plugin.Decrypt()` accesses `request.Ciphertext[0]` without checking that the slice is non-empty.
- **Unbounded decompression chain in HTTP responses on Node.js Fetch API via Content-Encoding leads to resource exhaustion** — `#3456148` · Node.js · $0 · ▲25
  > However, the number of links in the decompression chain is unbounded and the default `maxHeaderSize` allows a malicious server to insert thousands compression steps leading to high CPU usage and excessive memory allocation.
- **ASGIRequest header concatenation quadratic CPU DoS on Django via repeated headers leads to worker exhaustion** — `#3426417` · Django · $0 · ▲24
  > `django.core.handlers.asgi.ASGIRequest` builds the `META` dictionary by iterating over the ASGI `scope["headers"]` array.
- **DoS with crafted "Range" header** — `#2307813` · Ruby on Rails · $0 · ▲24
  > The `Range` object returned by [Rack::Utils.get byte ranges](https://github.com/rack/rack/blob/v3.0.8/lib/rack/utils.rb L435) will never exceed the file size, but there is no restriction on overlapping ranges.
- **ZMQ get_output_distribution duplicate amount DoS** — `#3681690` · Monero · $0 · ▲22
  > The issue is also reachable with `--restricted-zmq-rpc`, because ZMQ lacks the stricter validation applied by restricted HTTP RPC.
- **Disk Space Exhaustion leading to a Denial of Service (DoS)** — `#3250490` · curl · $0 · ▲21
  > If an attacker can cause cURL to download or upload a very large amount of data (e.g., via a very large HTTP response or an unlimited upload), the log file generated by this debug function can grow indefinitely.
- **Potential DoS due to PasswordPoliciesNotMet in errors.go** — `#2441029` · passhash · $0 · ▲19
  > To fix this, we need to make sure the `PasswordPoliciesNotMet` struct doesn't collect an unlimited number of errors.
- **Server crash (stack-overflow DoS) via unbounded recursion in MariaDB WKB GEOMETRYCOLLECTION parser** — `#3896507` · MariaDB · $0 · ▲18
  > `item.cc`, `item func.cc`, `item cmpfunc.cc`, `item subselect.cc`, `item jsonfunc.cc`,
- **Infinite loop issue in the state machine of the curl project** — `#3442060` · curl · $0 · ▲17
  > In the state machine of curl, the `state performing` function in `/lib/multi.c` calls the `Curl sendrecv` function at [1] to receive data from the peer:
- **Specially constructed multi-part requests cause multi-second response times; vulnerable to DoS** — `#431561` · Ruby on Rails · $0 · ▲17
  > Resource starvation of web request servicing, by causing multiple long-running requests.
- **No Rate Limiting on https://██████/██████████/accounts/password/reset/ endpoint leads to Denial of Service** — `#862681` · U.S. Dept Of Defense · $0 · ▲15
  > Go to https://█████/█████/accounts/password/reset/
- **DoS of https://blog.yelp.com/ and other WP instances via CVE-2018-6389** — `#753491` · Yelp · $0 · ▲15
  > There is possibility in /wp-admin/load-scripts.php script to generate large (~3Mb) amount of data via simple non-authenticated request to server.
- **CVE-2022-35252: control code in cookie denial of service** — `#1613943` · curl · $0 · ▲13
  > My guess for that vulnerability is that since cookies are persistent, someone who can trick curl into storing cookies can store large amounts of cookies into curl cookie store, which will prevent curl from ever interacting with the server (due to large…
- **Application level DOS at Login Page ( Accepts Long Password )** — `#1168804` · Reddit · $0 · ▲11
  > Go to the link https://www.ajaxshop.nl/nl/account
- **Rack CVE-2022-30122: Denial of Service Vulnerability in Rack Multipart Parsing** — `#1627159` · Internet Bug Bounty · $2,400 · ▲9
  > ReDoS in `Rack::Multipart::BROKEN QUOTED` and `Rack::Multipart::BROKEN UNQUOTED`.
- **CVE-2023-25692: Apache Airflow Google Provider: Google Cloud Sql Provider Denial Of Service and Remote Command Execution** — `#1895316` · Internet Bug Bounty · $480 · ▲8
  > You can also see the existence of the `load my evil dag.py` file in `/opt/airflow/dags` of the woker terminal.
- **[cloudron-surfer] Denial of Service via LDAP Injection** — `#906959` · Node.js third-party modules · $0 · ▲8
  > The filter uses an `OR` operation between different attributes that are `uid`, `mail`, `username`, `sAMAccountName`.
- **Memory leak in Node.js HTTP/2 server via WINDOW_UPDATE on stream 0 leads to resource exhaustion** — `#3531737` · Node.js · $0 · ▲7
  > A memory leak occurs in Node.js HTTP/2 servers when a client sends WINDOW UPDATE frames on stream 0 (connection-level) that cause the flow control window to exceed the maximum value of 2³¹-1.
- **Remote P2P DoS** — `#592200` · Monero · $0 · ▲6
  > https://www.activism.net/cypherpunk/manifesto.html
- **Stack exhaustion in MIME multipart reading with deeply nested subparts** — `#3684603` · curl · $0 · ▲4
  > The affected code is in `lib/mime.c`, primarily the `readback part()`, `read part content()`, and `mime subparts read()` call chain.
- **Abuse of Api that causes spamming users and possible DOS due to missing rate limit on contact form** — `#223542` · Weblate · $0 · ▲4
  > csrfmiddlewaretoken=XXX&subject=&name=&email=asd%40yahoo.com&message=&content=
- **moderate: mod_deflate denial of service** — `#20861` · Internet Bug Bounty · $500 · ▲3
  > If request body decompression was configured (using the "DEFLATE" input filter), a remote attacker could cause the server to consume significant memory and/or CPU resources.

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 5× | `curl_ws_send()` |
| 3× | `check_stack_overrun()` |
| 2× | `Cipher: []byte{}` |
| 2× | `res.write()` |
| 2× | `SELECT ST_GeomFromWKB(0x…)` |
| 2× | `*)(cn=*)(cn=*` |
| 2× | `mime_subparts_read()` |
| 1× | `curl_ws_recv()` |
| 1× | `ws->sendbuf_payload == 0` |
| 1× | `buflen > ws->sendbuf_payload` |
| 1× | `ws_flush()` |
| 1× | `InitProposalBlockParts()` |
| 1× | `V1Plugin.Decrypt()` |
| 1× | `[]byte{}` |
| 1× | `len(request.Cipher) > 0` |
| 1× | `(((((()0)))))` |
| 1× | `((((((()0))))))` |
| 1× | `[Server] Memory usage: ${usage.toFixed(2)} MB` |
| 1× | `Server listening on port ${port}` |
| 1× | `V2Plugin.Decrypt()` |

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **ReDoS detection recipe:** find a regex applied to user input (email/URL/username validators, WAF rules, route patterns), classify it against the four evil shapes, then ramp the payload length and time it:
```
a{n}!  for n = 8, 12, 16, 20, 24, 28
```
  Plot response time vs n. A **linear** slope is normal validation; a **doubling** slope confirms catastrophic backtracking. Use Burp Turbo Intruder or a tiny Python timing harness; keep a control request (`b{n}!`) to separate regex cost from generic body-parsing cost.
- **Regex-injection bypass:** where the application builds the pattern from a field (search "advanced mode", custom validators, report filters), feed the evil pattern as input and the torture string as the value. This bypasses the need to find a vulnerable regex in the source.
- **Rapid Reset reproduction:** a client opens N streams with HEADERS (END_STREAM=1) and immediately sends RST_STREAM for each, without waiting for any server response. HPACK-compressed 9-byte HEADERS keep the request tiny. Compare request rate and server CPU/worker-queue depth against a baseline of ordinary HTTP/2 traffic. Cloudflare publishes a `rapidreset.pcapng` with the technique dissected — use it to validate your harness, then point it only at in-scope infrastructure.
- **Proxy-chain amplifier:** the attack is most damaging where an HTTP/2 proxy dispatches work asynchronously to an upstream (business-logic) tier that cannot be told to stop cleanly. Test both the edge and the origin: an edge that absorbs resets may still leave the origin with queued work.
- **Mitigation-boundary probes (to prove a fix works, not to break production):** count server-originated `RST_STREAM` frames and close the connection with `GOAWAY` after a threshold; cap concurrent streams at **100** (not 64 — clients assume 100 by default); rate-limit per connection and per IP at the TLS proxy. Re-run the harness after each change and show the request-rate collapse.
- **Resource-exhaustion payload shapes for other classes:** deeply nested JSON (body-parser `depth`), GraphQL query batching + deep nesting, zip bombs, SVG with huge dimensions, `?page=999999999&limit=100000`, and export endpoints with unbounded date ranges. Measure **server-side** impact (worker time, memory, queue depth), not just your own client's timing.

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

- **Timing is necessary but not sufficient.** A slow response can be network jitter, cold cache, or a slow DB query. Require (a) a reproducible monotonic/exponential curve over ≥5 input lengths, (b) a control input of equal size that stays fast, and (c) ideally server-side corroboration (CPU spike, worker hang, thread dump showing the regex engine). Report the raw timings table.
- **Availability impact must be demonstrated, not inferred.** Show a second request timing out while the first is still processing, a worker-pool exhaustion curve, or an actual 5xx/timeout under a modest request rate. "This regex is theoretically evil" is a code-review note, not a finding.
- **Distinguish client-side from server-side ReDoS.** If the regex only runs in the browser, the impact is a hung tab (client DoS) — usually out of scope. Confirm execution server-side via a proxy-captured request whose timing changes with payload length.
- **Rapid Reset false positives:** a single connection with a few resets is normal browser behavior (scrolling cancels images). Look for thousands of HEADERS/RST_STREAM pairs per connection and a measurable request-rate multiplier. 499/502 alone are not evidence; correlate with frame counts.
- **RCE-vs-DoS honesty (Node2Shell / Telerik):** where public research shows crashes are reliably reproducible but code execution is narrow or unproven, report the **availability** impact. Inflating a crash to "RCE" is the fastest way to get a finding closed as N/A.
- **Scope and safety:** stay inside program scope, use a minimal request count, avoid sustained volumetric traffic against shared infrastructure, and prefer a single controlled connection for Rapid Reset. Per the baseline reporting bar, prove impact on a second controlled account or a safe callback and keep the PoC minimal and reproducible with raw requests and exact IDs.
- **Redact** any session cookies, tokens, or other-user PII captured while demonstrating the DoS; keep only timings, status codes, and the request shapes.

### Escalation and related chains

### Escalation chains

- DoS -> service outage.
- ReDoS -> worker exhaustion.

### Tools and wordlists

### Tools

`Burp Turbo Intruder` · `custom scripts` · `time`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_dos.txt` | 41 |
| `~/.local/share/hackerone-reports/wordlists/params_dos.txt` | 12 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_dos.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_dos.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

### Nuclei

Do not run DoS templates against production without explicit permission; measure resource use on a test account.

```sh
nuclei -u https://target -tags dos \
       -severity low,medium,high,critical -rl 40 -o nuclei_dos.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Sources and related reading

### Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class dos --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class dos
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class dos
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class dos --min-bounty 1000
```

### Related

- `hackerone-logic-and-design` (931 reports)
- `hackerone-memory-corruption` (892 reports)

### Related

- `logic-and-design` (931 reports)
- `memory-corruption` (892 reports)

### D. Sources — numbered list of URLs you actually fetched

1. https://community.owasp.org/attacks/Regular_expression_Denial_of_Service_-_ReDoS
2. https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack
3. https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-vulnerability-cve-2023-44487
4. https://community.owasp.org/attacks/HTTP2_Reset_Attack
5. https://cloud.google.com/blog/products/identity-security/how-it-works-the-novel-http2-rapid-reset-ddos-attack
6. https://www.netspi.com/blog/executive-blog/attack-surface-management/netspi-analysis-of-http-2-rapid-reset/
7. https://www.cve.org/CVERecord?id=CVE-2023-44487
8. https://en.wikipedia.org/wiki/ReDoS
9. https://nvd.nist.gov/vuln/detail/CVE-2022-3517
10. https://blog.cloudflare.com/on-the-recent-http-2-dos-attacks/
11. https://www.rfc-editor.org/rfc/rfc9113
12. https://community.owasp.org/attacks/Denial_of_Service
13. https://blog.cloudflare.com/cloudflare-mitigates-record-breaking-71-million-request-per-second-ddos-attack/
14. https://www.cloudflare.com/learning/ddos/how-to-prevent-ddos-attacks/

### Additional notes

### Parameters observed

`name` · `load` · `email` · `content` · `subject` · `message` · `revision` · `formkey` · `postkey` · `window_id` · `referring_controller` · `referring_action`

### Near to Infinite loop when changing Group's name that has API token as Team Member

`#880187` · HackerOne · $2,500 · medium · 2020-07-23 · ▲77
> Summary: The https://hackerone.com contains an iteration or loop with an exit condition that is near to infinite loop. If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory and even a DoS attack. Description: Hello Security team, I have a test Enterprise Program https://hackerone.com/tonight ptdkf enabled in my second H1 account.

### Incomplete fix for CVE-2026-21637: loadSNI() in _tls_wrap.js lacks try/catch leading to Remote DoS

`#3556769` · Node.js · $0 · high · 2026-04-23 · ▲59
> A flaw in Node.js TLS error handling leaves SNICallback invocations unprotected against synchronous exceptions, while the equivalent ALPN and PSK callbacks were already addressed in CVE-2026-21637. This represents an incomplete fix of that prior vulnerability. When an SNICallback throws synchronously on unexpected input the exception bypasses TLS error handlers and propagates as an uncaught exception, crashing the Node.js process.

### CVE-2025-5399: WebSocket endless loop

`#3168039` · curl · $0 · low · 2025-06-04 · ▲58
> The function curl ws send() in libcurl on commit 12d13b84fa40aa657b83d5458944dbd9b978fb7e contains an infinite loop that can be triggered by a malicious server under specific circumstances. If an application uses curl ws recv() and curl ws send() to communicate with a websocket server, a malicious server can send a carefully timed PING message while the client is constructing a frame via CURLWS OFFSET that leads to the next curl ws send() invocation not…

### Possible DoS Vulnerability with Range Header in Rack

`#2520679` · Internet Bug Bounty · $5,420 · high · 2024-09-25 · ▲56
> I made a report and patch at https://hackerone.com/reports/2307813. https://discuss.rubyonrails.org/t/possible-dos-vulnerability-with-range-header-in-rack/84944 There is a possible DoS vulnerability relating to the Range request header in Rack. This vulnerability has been assigned the CVE identifier CVE-2024-26141. Versions Affected: = 1.3.0. Not affected: Carefully crafted Range headers can cause a server to respond with an unexpectedly large response.

### Memory Exhaustion in CometBFT v1.0.1 via malicious ProposalMessage leads to network-wide denial of service

`#3510161` · Cosmos · $0 · n/a · 2026-01-20 · ▲47
> CometBFT v1.0.1 contains a critical memory exhaustion vulnerability that allows any peer to crash nodes with a single ~50-byte P2P message. An attacker can send a malicious ProposalMessage with PartSetHeader.Total set to 2^32-1, causing the receiving node to immediately allocate 512 MB of memory without prior validation, resulting in an OOM kill. The impact is complete network denial of service.

## Companion methodology (complete, deduplicated)

Full text of every non-SKILL.md methodology document from the contributing skills.

### Companion: hunting / references/payloads.md

# Denial of Service / Resource Exhaustion — HackerOne field guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- `limit=999999` `page_size=100000` `depth=50`

- ReDoS -> `(a+)+$` in a search/regex field

- Zip bomb -> nested archives; XML billion laughs

- GraphQL alias storm



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 5× | `curl_ws_send()` |

| 3× | `check_stack_overrun()` |

| 2× | `Cipher: []byte{}` |

| 2× | `res.write()` |

| 2× | `SELECT ST_GeomFromWKB(0x…)` |

| 2× | `*)(cn=*)(cn=*` |

| 2× | `mime_subparts_read()` |

| 1× | `curl_ws_recv()` |

| 1× | `ws->sendbuf_payload == 0` |

| 1× | `buflen > ws->sendbuf_payload` |

| 1× | `ws_flush()` |

| 1× | `InitProposalBlockParts()` |

| 1× | `V1Plugin.Decrypt()` |

| 1× | `[]byte{}` |

| 1× | `len(request.Cipher) > 0` |

| 1× | `(((((()0)))))` |

| 1× | `((((((()0))))))` |

| 1× | `[Server] Memory usage: ${usage.toFixed(2)} MB` |

| 1× | `Server listening on port ${port}` |

| 1× | `V2Plugin.Decrypt()` |



## Parameters observed



`name` · `load` · `email` · `content` · `subject` · `message` · `revision` · `formkey` · `postkey` · `window_id` · `referring_controller` · `referring_action`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_dos.txt` | 41 |

| `~/.local/share/hackerone-reports/wordlists/params_dos.txt` | 12 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_dos.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_dos.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Do not run DoS templates against production without explicit permission; measure resource use on a test account.



```sh

nuclei -u https://target -tags dos \

       -severity low,medium,high,critical -rl 40 -o nuclei_dos.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Companion: hunting / references/techniques.md

# Denial of Service / Resource Exhaustion — HackerOne field guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Look for expensive operations on user input: regex, XML/JSON parsing, image/video, PDF.

- Test unbounded pagination, large limits, deep nesting, and zip bombs (safely).

- Check rate limits on search/export/invite/SMS.

- Try amplification: one request causing many downstream calls.



## Bypass tricks



- Distribute requests across connections/accounts.

- Use slowloris-style partial bodies where allowed.



## Deeper checklist



- Look for expensive operations on user input: regex, XML/JSON parsing, image/video processing, PDF generation.

- Test unbounded pagination, large `limit`/`size` values, deep nesting, and zip bombs (safely, low volume).

- Check rate limits on expensive endpoints (search, export, invite, SMS/email).

- Try amplification: one request causing many downstream calls or notifications.

- Test file decompression, archive extraction, and thumbnail generation for resource blowups.

- Use small, controlled payloads; never run sustained floods against production.

- Demonstrate recovery impact and quantify resource amplification.



## Techniques from real reports



One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.



- **Near to Infinite loop when changing Group's name that has API token as Team Member** — `#880187` · HackerOne · $2,500 · ▲77

  > Once you save that, you can read this API token permission/groups in `JSON` format too, just goint to `https://hackerone.com/[Your Program]/team members/[The team member ID of your API toke].json`

- **Incomplete fix for CVE-2026-21637: loadSNI() in _tls_wrap.js lacks try/catch leading to Remote DoS** — `#3556769` · Node.js · $0 · ▲59

  > This vulnerability affects all Node.js versions that received the CVE-2026-21637 fix, including 20.x, 22.x, 24.x, and 25.x , on any TLS server where `SNICallback` may throw on unexpected `servername` input.

- **CVE-2025-5399: WebSocket endless loop** — `#3168039` · curl · $0 · ▲58

  > If an application uses `curl ws recv()` and `curl ws send()` to communicate with a websocket server, a malicious server can send a carefully timed PING message while the client is constructing a frame via `CURLWS OFFSET` that leads to the next `curl ws…

- **Possible DoS Vulnerability with Range Header in Rack** — `#2520679` · Internet Bug Bounty · $5,420 · ▲56

  > https://discuss.rubyonrails.org/t/possible-dos-vulnerability-with-range-header-in-rack/84944

- **Memory Exhaustion in CometBFT v1.0.1 via malicious ProposalMessage leads to network-wide denial of service** — `#3510161` · Cosmos · $0 · ▲47

  > An attacker can send a malicious `ProposalMessage` with `PartSetHeader.Total` set to `2^32-1`, causing the receiving node to immediately allocate 512 MB of memory without prior validation, resulting in an OOM kill.

- **V1Plugin.Decrypt panics on empty ciphertext (Remote DoS)** — `#3620748` · AWS VDP · $0 · ▲41

  > Sending a `DecryptRequest` with empty or nil `Cipher` field causes an unrecoverable `index out of range` panic that crashes the entire gRPC server process.

- **Application DOS via specially crafted payload on 3d.cs.money** — `#993582` · CS Money · $0 · ▲36

  > While testing it was observed that on 3d.cs.money a DOS is possible via specially crafted request using only single request from single machine on search bar.

- **DoS via Unbounded Memory Allocation in sendWebStream on Fastify v5.7.0+ leads to OOM crash when backpressure is ignored** — `#3524779` · Fastify · $0 · ▲35

  > When a `ReadableStream` is sent as a response, Fastify continuously pulls data from the stream producer (`controller.enqueue`) and writes it to the response object (`res.write`).

- **V2Plugin.Decrypt panics on empty ciphertext (Remote DoS)** — `#3620753` · AWS VDP · $0 · ▲25

  > `V2Plugin.Decrypt()` accesses `request.Ciphertext[0]` without checking that the slice is non-empty.

- **Unbounded decompression chain in HTTP responses on Node.js Fetch API via Content-Encoding leads to resource exhaustion** — `#3456148` · Node.js · $0 · ▲25

  > However, the number of links in the decompression chain is unbounded and the default `maxHeaderSize` allows a malicious server to insert thousands compression steps leading to high CPU usage and excessive memory allocation.

- **ASGIRequest header concatenation quadratic CPU DoS on Django via repeated headers leads to worker exhaustion** — `#3426417` · Django · $0 · ▲24

  > `django.core.handlers.asgi.ASGIRequest` builds the `META` dictionary by iterating over the ASGI `scope["headers"]` array.

- **DoS with crafted "Range" header** — `#2307813` · Ruby on Rails · $0 · ▲24

  > The `Range` object returned by [Rack::Utils.get byte ranges](https://github.com/rack/rack/blob/v3.0.8/lib/rack/utils.rb L435) will never exceed the file size, but there is no restriction on overlapping ranges.

- **ZMQ get_output_distribution duplicate amount DoS** — `#3681690` · Monero · $0 · ▲22

  > The issue is also reachable with `--restricted-zmq-rpc`, because ZMQ lacks the stricter validation applied by restricted HTTP RPC.

- **Disk Space Exhaustion leading to a Denial of Service (DoS)** — `#3250490` · curl · $0 · ▲21

  > If an attacker can cause cURL to download or upload a very large amount of data (e.g., via a very large HTTP response or an unlimited upload), the log file generated by this debug function can grow indefinitely.

- **Potential DoS due to PasswordPoliciesNotMet in errors.go** — `#2441029` · passhash · $0 · ▲19

  > To fix this, we need to make sure the `PasswordPoliciesNotMet` struct doesn't collect an unlimited number of errors.

- **Server crash (stack-overflow DoS) via unbounded recursion in MariaDB WKB GEOMETRYCOLLECTION parser** — `#3896507` · MariaDB · $0 · ▲18

  > `item.cc`, `item func.cc`, `item cmpfunc.cc`, `item subselect.cc`, `item jsonfunc.cc`,

- **Infinite loop issue in the state machine of the curl project** — `#3442060` · curl · $0 · ▲17

  > In the state machine of curl, the `state performing` function in `/lib/multi.c` calls the `Curl sendrecv` function at [1] to receive data from the peer:

- **Specially constructed multi-part requests cause multi-second response times; vulnerable to DoS** — `#431561` · Ruby on Rails · $0 · ▲17

  > Resource starvation of web request servicing, by causing multiple long-running requests.

- **No Rate Limiting on https://██████/██████████/accounts/password/reset/ endpoint leads to Denial of Service** — `#862681` · U.S. Dept Of Defense · $0 · ▲15

  > Go to https://█████/█████/accounts/password/reset/

- **DoS of https://blog.yelp.com/ and other WP instances via CVE-2018-6389** — `#753491` · Yelp · $0 · ▲15

  > There is possibility in /wp-admin/load-scripts.php script to generate large (~3Mb) amount of data via simple non-authenticated request to server.

- **CVE-2022-35252: control code in cookie denial of service** — `#1613943` · curl · $0 · ▲13

  > My guess for that vulnerability is that since cookies are persistent, someone who can trick curl into storing cookies can store large amounts of cookies into curl cookie store, which will prevent curl from ever interacting with the server (due to large…

- **Application level DOS at Login Page ( Accepts Long Password )** — `#1168804` · Reddit · $0 · ▲11

  > Go to the link https://www.ajaxshop.nl/nl/account

- **Rack CVE-2022-30122: Denial of Service Vulnerability in Rack Multipart Parsing** — `#1627159` · Internet Bug Bounty · $2,400 · ▲9

  > ReDoS in `Rack::Multipart::BROKEN QUOTED` and `Rack::Multipart::BROKEN UNQUOTED`.

- **CVE-2023-25692: Apache Airflow Google Provider: Google Cloud Sql Provider Denial Of Service and Remote Command Execution** — `#1895316` · Internet Bug Bounty · $480 · ▲8

  > You can also see the existence of the `load my evil dag.py` file in `/opt/airflow/dags` of the woker terminal.

- **[cloudron-surfer] Denial of Service via LDAP Injection** — `#906959` · Node.js third-party modules · $0 · ▲8

  > The filter uses an `OR` operation between different attributes that are `uid`, `mail`, `username`, `sAMAccountName`.

- **Memory leak in Node.js HTTP/2 server via WINDOW_UPDATE on stream 0 leads to resource exhaustion** — `#3531737` · Node.js · $0 · ▲7

  > A memory leak occurs in Node.js HTTP/2 servers when a client sends WINDOW UPDATE frames on stream 0 (connection-level) that cause the flow control window to exceed the maximum value of 2³¹-1.

- **Remote P2P DoS** — `#592200` · Monero · $0 · ▲6

  > https://www.activism.net/cypherpunk/manifesto.html

- **Stack exhaustion in MIME multipart reading with deeply nested subparts** — `#3684603` · curl · $0 · ▲4

  > The affected code is in `lib/mime.c`, primarily the `readback part()`, `read part content()`, and `mime subparts read()` call chain.

- **Abuse of Api that causes spamming users and possible DOS due to missing rate limit on contact form** — `#223542` · Weblate · $0 · ▲4

  > csrfmiddlewaretoken=XXX&subject=&name=&email=asd%40yahoo.com&message=&content=

- **moderate: mod_deflate denial of service** — `#20861` · Internet Bug Bounty · $500 · ▲3

  > If request body decompression was configured (using the "DEFLATE" input filter), a remote attacker could cause the server to consume significant memory and/or CPU resources.



## Case studies



### Near to Infinite loop when changing Group's name that has API token as Team Member

`#880187` · HackerOne · $2,500 · medium · 2020-07-23 · ▲77

> Summary: The https://hackerone.com contains an iteration or loop with an exit condition that is near to infinite loop. If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory and even a DoS attack. Description: Hello Security team, I have a test Enterprise Program https://hackerone.com/tonight ptdkf enabled in my second H1 account.



### Incomplete fix for CVE-2026-21637: loadSNI() in _tls_wrap.js lacks try/catch leading to Remote DoS

`#3556769` · Node.js · $0 · high · 2026-04-23 · ▲59

> A flaw in Node.js TLS error handling leaves SNICallback invocations unprotected against synchronous exceptions, while the equivalent ALPN and PSK callbacks were already addressed in CVE-2026-21637. This represents an incomplete fix of that prior vulnerability. When an SNICallback throws synchronously on unexpected input the exception bypasses TLS error handlers and propagates as an uncaught exception, crashing the Node.js process.



### CVE-2025-5399: WebSocket endless loop

`#3168039` · curl · $0 · low · 2025-06-04 · ▲58

> The function curl ws send() in libcurl on commit 12d13b84fa40aa657b83d5458944dbd9b978fb7e contains an infinite loop that can be triggered by a malicious server under specific circumstances. If an application uses curl ws recv() and curl ws send() to communicate with a websocket server, a malicious server can send a carefully timed PING message while the client is constructing a frame via CURLWS OFFSET that leads to the next curl ws send() invocation not…



### Possible DoS Vulnerability with Range Header in Rack

`#2520679` · Internet Bug Bounty · $5,420 · high · 2024-09-25 · ▲56

> I made a report and patch at https://hackerone.com/reports/2307813. https://discuss.rubyonrails.org/t/possible-dos-vulnerability-with-range-header-in-rack/84944 There is a possible DoS vulnerability relating to the Range request header in Rack. This vulnerability has been assigned the CVE identifier CVE-2024-26141. Versions Affected: = 1.3.0. Not affected: Carefully crafted Range headers can cause a server to respond with an unexpectedly large response.



### Memory Exhaustion in CometBFT v1.0.1 via malicious ProposalMessage leads to network-wide denial of service

`#3510161` · Cosmos · $0 · n/a · 2026-01-20 · ▲47

> CometBFT v1.0.1 contains a critical memory exhaustion vulnerability that allows any peer to crash nodes with a single ~50-byte P2P message. An attacker can send a malicious ProposalMessage with PartSetHeader.Total set to 2^32-1, causing the receiving node to immediately allocate 512 MB of memory without prior validation, resulting in an OOM kill. The impact is complete network denial of service.



## Query the corpus



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class dos --limit 20

python3 ~/.local/share/hackerone-reports/h1.py stats --class dos

python3 ~/.local/share/hackerone-reports/h1.py show <id> --full

```



Search by technology, endpoint, parameter, or program. Examples:



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class dos

python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class dos --min-bounty 1000

```

## Corpus wordlists (mined)

### `params_dos.txt`

```text
name
load
email
content
subject
message
revision
formkey
postkey
window_id
referring_controller
referring_action
```

### `paths_dos.txt`

```text
/wp-admin/load-scripts.php
/cgi-bin/cvename.cgi
/2018/02/how-to-dos-29-of-world-wide-websites.html
/stream
/storage.googleapis.com/swordlight/load_my_evil_dag.py
/cloud_sql_proxy.linux.amd64
/api/login
/get.html
/ldap-filters/
/filters.html
/search/rfc4515
/contact/
/wp-admin/
/groups.json
/team_members/
/api
/api/skin/search
/item/default
/docs/CVE-2022-32206.html
/rfc/rfc9112.html
/django-poc
/django-poc/django
/users/
/accounts/password/reset/
/█████/accounts/password/reset/
/blog/wp-admin/load-scripts.php
/doc/html/rfc6265
/nl/account
/load_my_evil_dag.py
/package/cloudron-surfer
/store/io.cloudron.surfer.html
/_admin/
/cypherpunk/manifesto.html
/security/vulnerabilities_24.html
/store/de.nebulon.guacamoly.html
/package/meemo-app
/manual/tutorial/install-mongodb-on-ubuntu/
/ajax/batched_log_POST
/accounts/email/
/index.php/settings/users/TweLbFT93aqRnEfF/settings
/2015/06/11/cve-2015-1788-openssl-binpoly-hang/
```

## Source skills merged into this topic

- `h1skills` — `hackerone-dos`
- `hunting` — `dos`

## Provenance

- `references/unified-method.md` — same deduplicated union as this file, for tooling
- `references/upstream-*.md` — unmodified original SKILL.md from each repo
- `references/upstream-assets/` — 2 companion files
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
