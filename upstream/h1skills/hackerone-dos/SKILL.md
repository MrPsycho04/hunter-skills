---
name: hackerone-dos
description: >-
  Hunt algorithmic complexity, unbounded resource use, and app-layer DoS. Use when testing exports, search, image processing, regex, pagination, or file parsing. Backed by 66 disclosed HackerOne reports.
---

# Denial of Service / Resource Exhaustion — HackerOne field guide

Built from **66** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

## Signal

- Reports: **66** · paid: **18**
- Median bounty **$447** · p90 **$2,500** · max **$5,420** · total **$18,061**
- Median upvotes **11**

## Where it pays

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

## Quick wins

Start here. These are the highest-yield tests for this class.

- Look for expensive operations on user input: regex, XML/JSON parsing, image/video, PDF.
- Test unbounded pagination, large limits, deep nesting, and zip bombs (safely).
- Check rate limits on search/export/invite/SMS.
- Try amplification: one request causing many downstream calls.

## Payloads & probes

- `limit=999999` `page_size=100000` `depth=50`
- ReDoS -> `(a+)+$` in a search/regex field
- Zip bomb -> nested archives; XML billion laughs
- GraphQL alias storm

## Bypass tricks

- Distribute requests across connections/accounts.
- Use slowloris-style partial bodies where allowed.

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`search` `export` `report` `image` `upload` `graphql` `pagination`

## Tools

`Burp Turbo Intruder` · `custom scripts` · `time`

## Escalation chains

- DoS -> service outage.
- ReDoS -> worker exhaustion.

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

## Related

- `hackerone-logic-and-design` (931 reports)
- `hackerone-memory-corruption` (892 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.
