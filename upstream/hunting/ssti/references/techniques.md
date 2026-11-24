# SSTI — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Fuzz template syntax: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`.

- Identify the engine from output and error messages.

- Escalate to file read/RCE with engine-specific payloads.

- Check email templates, PDF/report generators, and theme editors.



## Bypass tricks



- Bypass filters with string concatenation, `attr`, `|join`, and hex escapes.

- Use sandbox escapes for the specific engine/version.

- Blind SSTI via time delays or OOB.



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
