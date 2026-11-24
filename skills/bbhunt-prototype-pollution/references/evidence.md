# Evidence appendix — Prototype Pollution

Mined from all **14 valid disclosed reports** for this class (0 paid, 0% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
|---|---:|
| public source-code / repo review | 9 |
| HTTP method / verb tampering | 2 |
| deserialization / gadget chain | 1 |
| third-party data / paste / breach reuse | 1 |
| file upload / filename / extension | 1 |
| mass assignment / extra request fields | 1 |

## Tools mentioned

| Item | Count |
|---|---:|
| javascript-debugging | 12 |
| source-code-review | 3 |

## Bypass primitives

| Item | Count |
|---|---:|
| bypass | 1 |
| bypassed | 1 |

## Impact language

| Item | Count |
|---|---:|
| remote code execution | 13 |
| rce | 4 |
| admin | 3 |
| sensitive information | 2 |

## Parameters observed

| Item | Count |
|---|---:|
| malicious_payload | 5 |
| merge | 4 |
| payload | 2 |
| test | 2 |
| deap | 1 |
| mergify | 1 |
| upmerge | 1 |
| tsdot | 1 |
| obj | 1 |

## Recurring approach patterns

- **1×** module stats weekly downloads vulnerability vulnerability description i tested the deepcopy and deepextend functions
  - e.g. ## Module Stats [1,516,157] weekly downloads # Vulnerability ## Vulnerability Description I tested the [`deepCopy`]( and [`deepExtend`]( functions.

## Case studies (full excerpts)

### 778414 — [klona] Prototype pollution
Node.js third-party modules · no bounty (valid finding) · critical · https://hackerone.com/reports/778414

I would like to report Prototype pollution in klona It allows adding arbitrary property to Prototype while deep cloning an object # Module **module name:** klona **version:** <1.1.1 **npm page:** ` ## Module Description A tiny (366B) and fast utility to "deep clone" Objects, Arrays, Dates, RegExps, and more! ## Module Stats 356 weekly downloads # Vulnerability ## Vulnerability Description See: ## Steps To Reproduce: Described here: Note: This vulnerability was reported directly to owner here on 10/01/2020. Fix published in v1.1.1 on 15/01/2020 # Wrap up - I contacted the maintainer to let them know: Y - I opened an issue in the related repository: Y > Hunter's comments and funny memes goes here {F690469} ## Impact Denial of Service and possible Remote code execution by overriding object's property methods like `toString`

### 245228 — Object Injection in Woocommerce / Handle PDT Responses from PayPal
Automattic · no bounty (valid finding) · medium · https://hackerone.com/reports/245228

At this moment prevention from object injection is in the following line of code: but the PHP native [unserialize]( function supports little `o` as option in it and it is a StdClass object. Due this protection, we have a bypass (PoC below) e.g. due the fact how woocommerce gets the order we can set any order object we want. As an extra, if combined with capital `S` then for some attacks even known firewall rules will fail/will be bypassed.

### 390860 — Prototype Pollution Vulnerability in mpath Package
Node.js third-party modules · no bounty (valid finding) · high · https://hackerone.com/reports/390860

I would like to report prototype pollution vulnerability in mpath. It allows an attacker to inject arbitrary properties on Object.prototype. # Module **module name:** mpath **version:** 0.4.1 **npm page:** ` ## Module Description {G,S}et javascript object values using MongoDB-like path notatio ## Module Stats 305,874 downloads in the last week # Vulnerability ## Vulnerability Description An attacker can specify a path that include the prototype object, and thus overwrite important properties on Object.prototype or add new ones. ## Steps To Reproduce: ## Patch N/A validate property names before overwriting them and prevent write to certain paths. # Wrap up - I contacted the maintainer to let them know: [N - I opened an issue in the related repository: N ## Impact This may be an intended behaviour of this module, but it needs to be better documented. Moreover, to properly analyse the impact of this vulnerability one must look at the clients of this module, such as mongoose and see if attackers can realistically control the path value.

### 311333 — Prototype pollution attack (deep-extend)
Node.js third-party modules · no bounty (valid finding) · low · https://hackerone.com/reports/311333

As discussed in #309391, here's the separate report for each of the library. This one is the information for the deep-extend library. **Module:** [deep-extend]( **Summary:** Utilities function in all the listed modules can be tricked into modifying the prototype of "Object" when the attacker control part of the structure passed to these function. This can let an attacker add or modify existing property that will exist on all object. **Description:** ## Steps To Reproduce: The simplest test case to reproduce the issue is the following code snippet. In the code snippet, "malicious_payload" would come from an endpoint which accepts JSON data. > var merge = require('deep-extend'); > var malicious_payload = '{"\_\_proto\_\_":{"oops":"It works !"}}'; > > var a = {}; > console.log("Before : " + a.oops); > merge({}, JSON.parse(malicious_payload)); > console.log("After : " + a.oops); This shows that an attacker can add attributes to all existing object on the server. Additional attribute can be used to change the execution code flow or cause error on every subsequent request by replacing "toString" or "valueOf". ## Impact: This vulnerability is guaranteed to at least obtain denial of service as all the library allow the property "toString" and "valueOf" to be replaced by a "String". This breaks the express module and forces the server to either crash or return a 500 to every subsequent 

### 390857 — Prototype Pollution Vulnerability in noble Package
Node.js third-party modules · no bounty (valid finding) · high · https://hackerone.com/reports/390857

I would like to report prototype pollution vulnerability in noble. It allows attackers to pollute the Object.prototype object of an application running noble, possibly through Bluetooth. # Module **module name:** noble **version:** 1.9.1 **npm page:** ` ## Module Description A Node.js BLE (Bluetooth Low Energy) central module. Want to implement a peripheral? Checkout bleno Note: macOS / Mac OS X, Linux, FreeBSD and Windows are currently the only supported OSes. Other platforms may be developed later on. ## Module Stats 2,270 downloads in the last week # Vulnerability ## Vulnerability Description An attacker can inject arbitrary properties on Object.prototype using one of the methods exposed by this module. Moreover, there is strong evidence (parameter names) to believe that these values can be controlled remotely by the attacker, through Bluetooth. ## Steps To Reproduce: For now, I only have a local payload, but it seems to me that both the peripheralUuid and serviceUuids, expected by the onServicesDiscover are specified in the Bluetooth standard, thus it may come from another device advertising itself over Bluetooth. However, this scenario needs to be investigated further. ## Patch N/A validate the property name or initialize the target object using Object.create(null). # Wrap up - I contacted the maintainer to let them know: N - I opened an issue in the related repository: N 

### 778414 — [klona] Prototype pollution
Node.js third-party modules · no bounty (valid finding) · critical · https://hackerone.com/reports/778414

I would like to report Prototype pollution in klona It allows adding arbitrary property to Prototype while deep cloning an object # Module **module name:** klona **version:** <1.1.1 **npm page:** ` ## Module Description A tiny (366B) and fast utility to "deep clone" Objects, Arrays, Dates, RegExps, and more! ## Module Stats 356 weekly downloads # Vulnerability ## Vulnerability Description See: ## Steps To Reproduce: Described here: Note: This vulnerability was reported directly to owner here on 10/01/2020. Fix published in v1.1.1 on 15/01/2020 # Wrap up - I contacted the maintainer to let them know: Y - I opened an issue in the related repository: Y > Hunter's comments and funny memes goes here {F690469} ## Impact Denial of Service and possible Remote code execution by overriding object's property methods like `toString`

### 245228 — Object Injection in Woocommerce / Handle PDT Responses from PayPal
Automattic · no bounty (valid finding) · medium · https://hackerone.com/reports/245228

At this moment prevention from object injection is in the following line of code: but the PHP native [unserialize]( function supports little `o` as option in it and it is a StdClass object. Due this protection, we have a bypass (PoC below) e.g. due the fact how woocommerce gets the order we can set any order object we want. As an extra, if combined with capital `S` then for some attacks even known firewall rules will fail/will be bypassed.

## Field playbook (unedited)

### quick

- Find recursive merge/clone helpers and query parsers (jQuery.extend, lodash.merge, qs).
- Try __proto__, constructor.prototype, and prototype in query strings, JSON, cookies.
- Confirm pollution with `({}).polluted` and a downstream gadget.
- Test server-side Node.js merge paths too.

### payloads

- `?__proto__[polluted]=yes` `?constructor[prototype][polluted]=yes`
- `{"__proto__":{"isAdmin":true}}`
- `a[__proto__][x]=1` in qs/body-parser

### bypass

- Bypass filters with `constructor.prototype` and nested keys.
- Chain to DOM XSS via polluted options.

### surface

- query string
- JSON body
- cookies
- config
- merge

### tools

- Burp
- DOM Invader
- ppmap
- browser console

### chain

- Prototype pollution -> DOM XSS.
- Prototype pollution -> auth bypass.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class prototype-pollution
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class prototype-pollution --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
