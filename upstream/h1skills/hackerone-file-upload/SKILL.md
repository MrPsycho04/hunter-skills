---
name: hackerone-file-upload
description: >-
  Hunt file upload flaws. Use when testing avatars, documents, imports, and archive extraction. Backed by 100 disclosed HackerOne reports.
---

# File Upload — HackerOne field guide

Built from **100** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

## Signal

- Reports: **100** · paid: **20**
- Median bounty **$400** · p90 **$4,000** · max **$5,000** · total **$21,500**
- Median upvotes **14**

## Where it pays

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

## Quick wins

Start here. These are the highest-yield tests for this class.

- Test extension/MIME/content-type bypasses and double extensions.
- Try SVG, HTML, polyglot images, and office macros for stored XSS/RCE.
- Check path traversal in filenames and zip-slip in archives.
- Test access control on uploaded files (private vs public, IDOR).
- Look for image processing and thumbnail generation sinks.

## Payloads & probes

- `shell.php.jpg` `shell.pHp` `shell.php%00.jpg` `shell.svg`
- `.htaccess` -> `AddType application/x-httpd-php .jpg`
- SVG -> `<svg onload=alert(1)>`
- Zip -> `../../../../var/www/shell.php`

## Bypass tricks

- Content-type spoofing, magic-byte prefixing, and polyglots.
- Double extension, trailing dot/space, and case tricks.
- Race the upload validation or overwrite an existing file.

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`avatar` `upload` `file` `attachment` `document` `image` `import` `archive`

## Tools

`Burp` · `ffuf` · `exiftool` · `nuclei`

## Escalation chains

- Upload -> XSS.
- Upload + parser -> RCE.
- Zip slip -> file write.

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

## Related

- `hackerone-rce` (1,399 reports)
- `hackerone-path-traversal` (300 reports)
- `hackerone-xss` (2,569 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.
