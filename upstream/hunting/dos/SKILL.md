---
name: dos
description: >-
  Hunt algorithmic complexity, unbounded resource use, and app-layer DoS. Use when testing exports, search, image processing, regex, pagination, or file parsing. Backed by 66 disclosed HackerOne reports.
---

# Denial of Service / Resource Exhaustion — HackerOne field guide

Built from **66** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

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

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`search` `export` `report` `image` `upload` `graphql` `pagination`

## Tools

`Burp Turbo Intruder` · `custom scripts` · `time`

## Escalation chains

- DoS -> service outage.
- ReDoS -> worker exhaustion.

## Related

- `logic-and-design` (931 reports)
- `memory-corruption` (892 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

## Web-Research Methodology Additions (2026)

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

### C. Validation / proof bar — how to confirm and avoid false positives

- **Timing is necessary but not sufficient.** A slow response can be network jitter, cold cache, or a slow DB query. Require (a) a reproducible monotonic/exponential curve over ≥5 input lengths, (b) a control input of equal size that stays fast, and (c) ideally server-side corroboration (CPU spike, worker hang, thread dump showing the regex engine). Report the raw timings table.
- **Availability impact must be demonstrated, not inferred.** Show a second request timing out while the first is still processing, a worker-pool exhaustion curve, or an actual 5xx/timeout under a modest request rate. "This regex is theoretically evil" is a code-review note, not a finding.
- **Distinguish client-side from server-side ReDoS.** If the regex only runs in the browser, the impact is a hung tab (client DoS) — usually out of scope. Confirm execution server-side via a proxy-captured request whose timing changes with payload length.
- **Rapid Reset false positives:** a single connection with a few resets is normal browser behavior (scrolling cancels images). Look for thousands of HEADERS/RST_STREAM pairs per connection and a measurable request-rate multiplier. 499/502 alone are not evidence; correlate with frame counts.
- **RCE-vs-DoS honesty (Node2Shell / Telerik):** where public research shows crashes are reliably reproducible but code execution is narrow or unproven, report the **availability** impact. Inflating a crash to "RCE" is the fastest way to get a finding closed as N/A.
- **Scope and safety:** stay inside program scope, use a minimal request count, avoid sustained volumetric traffic against shared infrastructure, and prefer a single controlled connection for Rapid Reset. Per the baseline reporting bar, prove impact on a second controlled account or a safe callback and keep the PoC minimal and reproducible with raw requests and exact IDs.
- **Redact** any session cookies, tokens, or other-user PII captured while demonstrating the DoS; keep only timings, status codes, and the request shapes.

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
