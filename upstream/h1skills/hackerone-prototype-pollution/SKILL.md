---
name: hackerone-prototype-pollution
description: >-
  Hunt prototype pollution and object injection. Use when testing JS merges, query parsers, jQuery.extend, lodash, config loaders, and client-side state. Backed by 59 disclosed HackerOne reports.
---

# Prototype Pollution & Client-Side Object Injection — HackerOne field guide

Built from **59** publicly disclosed HackerOne reports (2017–2026). Corpus: `~/.local/share/hackerone-reports/`.

## Signal

- Reports: **59** · paid: **2**
- Median bounty **$3,000** · p90 **$3,000** · max **$3,000** · total **$6,000**
- Median upvotes **5**

## Where it pays

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

## Quick wins

Start here. These are the highest-yield tests for this class.

- Find recursive merge/clone helpers and query parsers (jQuery.extend, lodash.merge, qs).
- Try __proto__, constructor.prototype, and prototype in query strings, JSON, cookies.
- Confirm pollution with `({}).polluted` and a downstream gadget.
- Test server-side Node.js merge paths too.

## Payloads & probes

- `?__proto__[polluted]=yes` `?constructor[prototype][polluted]=yes`
- `{"__proto__":{"isAdmin":true}}`
- `a[__proto__][x]=1` in qs/body-parser

## Bypass tricks

- Bypass filters with `constructor.prototype` and nested keys.
- Chain to DOM XSS via polluted options.

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`query string` `JSON body` `cookies` `config` `merge`

## Tools

`Burp` · `DOM Invader` · `ppmap` · `browser console`

## Escalation chains

- Prototype pollution -> DOM XSS.
- Prototype pollution -> auth bypass.

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

## Payload fragments observed

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

## Wordlists

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

## Nuclei

Scanner coverage is minimal; test merge/query parsers and confirm a downstream gadget.

```sh
nuclei -u https://target -tags prototype-pollution \
       -severity low,medium,high,critical -rl 40 -o nuclei_prototype-pollution.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

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
```

## Related

- `hackerone-xss` (2,569 reports)
- `hackerone-rce` (1,399 reports)
- `hackerone-logic-and-design` (931 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.
