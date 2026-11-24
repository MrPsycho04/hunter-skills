# Evidence appendix — File Upload and File-Handling Flaws

Mined from all **55 valid disclosed reports** for this class (12 paid, 22% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
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

## Tools mentioned

| Item | Count |
|---|---:|
| browser | 5 |
| source-code-review | 4 |
| devtools | 3 |
| curl | 3 |
| decompiler | 1 |
| python | 1 |
| burp | 1 |

## Bypass primitives

| Item | Count |
|---|---:|
| content-type | 11 |
| bypass | 6 |
| bypassed | 4 |
| open redirect | 2 |
| whitelist | 2 |
| bypassing | 1 |

## Impact language

| Item | Count |
|---|---:|
| rce | 13 |
| admin | 8 |
| token | 5 |
| remote code execution | 4 |
| arbitrary file | 3 |
| localhost | 3 |
| secret | 2 |
| credential | 2 |
| exfiltrate | 1 |
| sensitive data | 1 |
| unauthorised | 1 |
| password | 1 |
| unauthorized | 1 |

## Parameters observed

| Item | Count |
|---|---:|
| src | 5 |
| width | 4 |
| height | 4 |
| onerror | 3 |
| href | 3 |
| page | 2 |
| type | 2 |
| fwa | 2 |
| style | 2 |
| stroke-width | 2 |
| has_used_cb | 2 |
| details | 1 |
| case | 1 |
| mimetype | 1 |
| max-age | 1 |
| boundary | 1 |
| name | 1 |
| filename | 1 |
| xss | 1 |
| xssi | 1 |
| version | 1 |
| encoding | 1 |
| standalone | 1 |
| svg | 1 |
| xmlns | 1 |
| xlink | 1 |
| like | 1 |
| payload | 1 |

## Recurring approach patterns

- **2×** description i was able to identify unsafe upload endpoint on the poc go to the upload some test file
  - e.g. ##Description I was able to identify unsafe upload endpoint on the ##POC 1) Go to the 2) Upload some test file.
- **1×** hi when a new driver is registering on uber they have to upload a variety of files proof of insurance id etc
  - e.g. Hi, When a new driver is registering on Uber, they have to upload a variety of files (proof of insurance, ID, etc).
- **1×** i was able to access your account data f297519 f297520 those keys give me ability to not only access the files but also replace and delete them change different their settings
  - e.g. I was able to access your account data {F297519} {F297520} Those keys give me ability to not only access the files, but also replace and delete them, change different their settings.
- **1×** this is the first report we identified ourselves where we re expanding retesting to the community
  - e.g. This is the first report we identified ourselves where we're expanding retesting to the community.
- **1×** when we identified this vulnerability we filed a ticket to our own bug bounty program instead of filing an internal ticket
  - e.g. When we identified this vulnerability, we filed a ticket to our own bug bounty program instead of filing an internal ticket.
- **1×** this was possible by sending a specially crafted request to the attachments endpoint
  - e.g. This was possible by sending a specially crafted request to the `/attachments` endpoint.
- **1×** i found an unrestricted file upload on which let me upload anything
  - e.g. i found an Unrestricted File Upload on which let me upload anything.
- **1×** i tested by uploading an executable visual studio community installer and a php file
  - e.g. I tested by uploading an executable (visual studio community installer) and a php file.
- **1×** i have not tried this but found the below resource about it steps to reproduce
  - e.g. I have not tried this but found the below resource about it: ## Steps to reproduce 1.
- **1×** i observed that when uploading a user avatar picture the first request was sent to with a post parameter contenttype telling the type of file being uploaded
  - e.g. I observed that when uploading a user avatar picture, the first request was sent to with a POST parameter "contentType" telling the type of file being uploaded.
- **1×** i changed the value to image svg xml
  - e.g. I changed the value to "image/svg+xml".
- **1×** now i sent a put request to the presignedurl that we got from the first request with http header content type image svg xml
  - e.g. Now, I sent a PUT request to the "preSignedURL" that we got from the first request with HTTP header "Content-Type: image/svg+xml".
- **1×** for fetching local files from the server itself lfi i created another user named testing68 and uploaded an avatar picture for it
  - e.g. For fetching local files from the server itself (LFI), I created another user named testing68 and uploaded an avatar picture for it.
- **1×** summary hello i found a critical vunerability in one of your site where user can upload any file type as a profile picture including php file steps to reproduce
  - e.g. ## Summary: Hello I found a critical vunerability in one of your site, where user can upload any file type as a profile picture (including php file) ## Steps To Reproduce: 1.
- **1×** summary hello again lichess team i found an input validation issue in the image upload endpoint that lets me inject special characters into the rel parameter
  - e.g. # Summary Hello Again Lichess Team, I found an input validation issue in the image upload endpoint that lets me inject special characters into the `rel` parameter.
- **1×** while testing upload functionality i noticed that colon characters aren t properly sanitized which could cause parsing issues in other parts of the application description the upload image user rel endpoint doesn t validate the rel parameter properly
  - e.g. While testing upload functionality, I noticed that colon characters aren't properly sanitized, which could cause parsing issues in other parts of the application # Description The `/upload/image/user/{rel}` endpoint doesn't validate the `rel` parameter properly.
- **1×** i noticed there s regex parsing logic in findinmarkdown that might not handle malformed imageids correctly this could cause issues in logging image lookup or markdown parsing where the format of imageid is implicitly assumed
  - e.g. I noticed there's regex parsing logic in `findInMarkdown` that might not handle malformed ImageIds correctly .This could cause issues in logging, image lookup, or markdown parsing where the format of imageId is implicitly assumed.
- **1×** the bug is in cr in resume from lib sendf c when it falls back to reading and discarding through ctx read cb no seek callback available it does not set ctx has used cb
  - e.g. The bug is in `cr_in_resume_from()` (`lib/sendf.c`): when it falls back to reading-and-discarding through `ctx->read_cb` (no seek callback available), it does not set `ctx->has_used_cb`.

## Case studies (full excerpts)

### 1547877 — [Kafka Connect] [JdbcSinkConnector][HttpSinkConnector] RCE by leveraging file upload via SQLite JDBC driver and SSRF to internal Jolokia
Aiven Ltd · $5000 · critical · https://hackerone.com/reports/1547877

## Summary: The Aiven JDBC sink includes the SQLite JDBC Driver. This JDBC driver can be used to upload SQLite database files onto the server. The HTTP sink connector allows sending HTTP requests to localhost. There is unprotected Jolokia listening on `localhost:6725`. JMX exports the `com.sun.management:type=DiagnosticCommand` MBean, which contains the `jvmtiAgentLoad` operation. This operation can be used to execute the SQLite database as JVM Agent by embedding the JVM Agent JAR file inside the SQLite database as an BLOB field in a table. ## Steps To Reproduce: {F1703051} 1. Login into my VPS: `ssh ████`, password: `█████████@` 1. Execute `nc -nlvp 4446` 1. cd to `jdbc-sqlite-jolokia-rce` and run `python3 poc.py` (if running locally, install kafka-python using pip first). 1. Reverse shell connection should now be established to my test instance ## Impact RCE on the Kafka Connect server

### 401483 — [chaturbate.com] - CSRF Vulnerability on image upload
Chaturbate · $300 · medium · https://hackerone.com/reports/401483

##Summary## Hi guys, One of the features available to a Chaturbate user is the ability to upload images into photo sets. The upload functionality does not use any CSRF tokens, allowing attackers to perform CSRF attacks and upload images to a user's profile without the user's consent. ## Steps To Reproduce: 1. Login to Chaturbate. 2. Browse to your profile page and upload an image. 3. Note the `set` ID of the newly created set (this is available by visiting set in the profile page. It'll be in the URL : ` 4. Download the poc.html file attached to this report. 5. Edit `poc.html` by replacing the number `4771110` by the `set` ID found at step #3. 6. Open poc.html and click on `Submit request`. 7. Visit your Chaturbate image set. You'll notice that the photo set now inludes an additional image (a blank/white image). ## Impact In order for this attack to work, an attacker would need to know the correct photo set ID. Since set IDs are public information, this isn't an issue. I've set the impact here to medium since this affects the integrity of user accounts.

### 3008878 — Stored XSS via SVG Upload in chat.line.biz
LY Corporation · $100 · low · https://hackerone.com/reports/3008878

The web application allowed users to upload SVG files via chat.line.biz without properly filtering or disabling scripts embedded inside the SVG content. As a result, an attacker could upload a malicious SVG containing JavaScript, and when another user later opened this file in the management interface, the embedded script would be executed in the browser, leading to a stored cross-site scripting (Stored XSS) vulnerability.

### 1606957 — Unrestricted File Upload on reddit.secure.force.com
Reddit · $100 · low · https://hackerone.com/reports/1606957

## Summary: Reddit.secure.force.com is Reddit SalesForce instance. Attacker is able to send attachments of disallowed filetypes to this server. The attacker is able to send malicious documents such as CVE-2022-30190 Follina to the victim. ## Impact: Attacker can send malicious files to whoever handles the form behind ## Steps To Reproduce: 1. Go to 2. Notice that the specified allowed filetype is: jpg jpeg gif png pdf as you can see with the image below: {F1780944} 3. If you try dragging and dropping a docx file to that box, there is a Javascript which forbids such action. But if you used the "Click to browse" option you can start uploading the file. {F1780957} 4. The file upload request: Here the data parameter contains the base64 encoded version of my clickme.docx file, which is based on the critical Follina vulnerability {F1780963}. This vulnerability can become a [zero click exploit]( 5. Response returns 200, indicated that there is no existing server side check for filetype and the file was uploaded successfully: ## Impact Attacker can send malicious files to whoever handles the form behind

### 351555 — Disclosure of all uploads to Cloudinary via hardcoded api secret in Android app
Reverb.com · no bounty (valid finding) · medium · https://hackerone.com/reports/351555

Hi, in file you have hardcoded the following config: where is basic auth details. It shouldn't be disclosed to third parties as official docs say ( > Note: You should only include the in the value, the api secret and key should be left out of the application. I was able to access your account data {F297519} {F297520} Those keys give me ability to not only access the files, but also replace and delete them, change different their settings. Also this url discloses statistics regarding stored files ## Impact Disclosure of all uploads to Cloudinary via hardcoded api secret in Android app

### 351555 — Disclosure of all uploads to Cloudinary via hardcoded api secret in Android app
Reverb.com · no bounty (valid finding) · medium · https://hackerone.com/reports/351555

Hi, in file you have hardcoded the following config: where is basic auth details. It shouldn't be disclosed to third parties as official docs say ( > Note: You should only include the in the value, the api secret and key should be left out of the application. I was able to access your account data {F297519} {F297520} Those keys give me ability to not only access the files, but also replace and delete them, change different their settings. Also this url discloses statistics regarding stored files ## Impact Disclosure of all uploads to Cloudinary via hardcoded api secret in Android app

### 419896 — Unauthenticated user can upload an attachment to the last updated report draft
HackerOne · no bounty (valid finding) · high · https://hackerone.com/reports/419896

"What, HackerOne resolved a report that was submitted by @jobert?" At HackerOne we often find security vulnerabilities ourselves. In most cases, we find them before new features even make it into production. Sometimes we find them when they're already in the wild. Recently we've launched a new feature called [retesting]( Up until now, HackerOne would always retest our own findings. We're changing that. This is the first report we identified ourselves where we're expanding retesting to the community. When we identified this vulnerability, we filed a ticket to our own bug bounty program instead of filing an internal ticket. We then leveraged the community to retest the vulnerability and allow them to find a bypass. This particular security vulnerability allowed an unauthenticated user to upload attachments and attach them to the last created report draft of other users. This was possible by sending a specially crafted request to the `/attachments` endpoint. Our investigation concluded that this was not abused. Thanks to the hackers that retested this vulnerability!

## Field playbook (unedited)

### quick

- Test extension/MIME/content-type bypasses and double extensions.
- Try SVG, HTML, polyglot images, and office macros for stored XSS/RCE.
- Check path traversal in filenames and zip-slip in archives.
- Test access control on uploaded files (private vs public, IDOR).
- Look for image processing and thumbnail generation sinks.

### payloads

- `shell.php.jpg` `shell.pHp` `shell.php%00.jpg` `shell.svg`
- `.htaccess` -> `AddType application/x-httpd-php .jpg`
- SVG -> `<svg onload=alert(1)>`
- Zip -> `../../../../var/www/shell.php`

### bypass

- Content-type spoofing, magic-byte prefixing, and polyglots.
- Double extension, trailing dot/space, and case tricks.
- Race the upload validation or overwrite an existing file.

### surface

- avatar
- upload
- file
- attachment
- document
- image
- import
- archive

### tools

- Burp
- ffuf
- exiftool
- nuclei

### chain

- Upload -> XSS.
- Upload + parser -> RCE.
- Zip slip -> file write.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class file-upload
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class file-upload --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
