---
name: bbhunt-dos
description: "Use only when the program explicitly allows availability testing; cover algorithmic complexity, unbounded work, and cost amplifiers. Unified from 2 upstream skills (h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Denial of Service and Resource Exhaustion — unified methodology

> **Unified skill.** Built from 2 upstream skills across h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

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

### Veteran tip

Most valid DoS-class reports in the corpus are about unbounded work or cost, not raw traffic floods.

## Unified upstream methodology (deduplicated)

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
- **CVE-2023-44487 — HTTP/2 Rapid Reset (CISA KEV; Cloudflare/Google/AWS coordinated disclosure).** Peaked at **201 million requests/second** using only ~20,000 bots. Mechanism: client opens HTTP/2 streams with `HEADERS` then immediately sends `RST_STREAM`; cancelled streams leave the open/half-closed state, so `SETTINGS_MAX_CONCURRENT_STREAMS` provides **no protection**. In Cloudflare's pcap, the first HEADERS frame is 26 bytes and 

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
  > An attacker can send a malicious `ProposalMessage` with `PartSetHeader.Total` set t

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
- **Proxy-chain amplifier:** the attack is most damaging where an HTTP/2 proxy dispatches work asynchronously to an upstream (business-logic) tier that cannot be told to stop cleanly. Test both the edge and the origin: an edge that absorbs 

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
- **Scope and safety:** stay inside p

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

## Source skills merged into this topic

- `h1skills` — `hackerone-dos`
- `hunting` — `dos`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 2 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `../../upstream/` — complete unmodified archives of all five source repositories
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
