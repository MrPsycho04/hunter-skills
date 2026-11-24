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
