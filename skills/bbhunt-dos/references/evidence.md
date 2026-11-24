# Evidence appendix — Denial of Service and Resource Exhaustion

Mined from all **66 valid disclosed reports** for this class (18 paid, 27% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
|---|---:|
| internal service / port / container | 14 |
| public source-code / repo review | 14 |
| HTTP method / verb tampering | 10 |
| file upload / filename / extension | 10 |
| parameter pollution / duplicate keys | 10 |
| admin / privileged-role context | 10 |
| encoding / double-encode / null byte | 9 |
| Content-Type / body-format switch | 8 |
| header injection (Host / X-Forwarded / etc.) | 6 |
| WAF / sanitizer / filter bypass | 6 |
| second-order / stored / blind delivery | 6 |
| OAST / DNS / HTTP callback proof | 5 |
| race / concurrency / timing | 5 |
| error message / stack trace probing | 4 |
| unauthenticated / removed-cookie test | 4 |
| fuzzing / wordlist brute force | 3 |
| intercept & replay request in Burp | 3 |
| replay / modify a captured request | 3 |
| XML / SOAP / SAML / XXE | 3 |
| deserialization / gadget chain | 3 |
| parser confusion / normalization | 3 |
| JWT / token / base64 decode | 3 |
| JS bundle / source-map inspection | 3 |
| third-party data / paste / breach reuse | 2 |
| employee / developer public info | 1 |
|  HosT/absolute-URL reset poisoning | 1 |
| git history / exposed .git | 1 |
| verbose debug / framework fingerprint | 1 |
| two-account / cross-account replay | 1 |
| mass assignment / extra request fields | 1 |
| subdomain / DNS / cert-transparency recon | 1 |
| redirect chain / Location header | 1 |

## Tools mentioned

| Item | Count |
|---|---:|
| source-code-review | 13 |
| curl | 7 |
| browser | 6 |
| python | 4 |
| devtools | 3 |
| burp | 2 |
| burp-intruder | 2 |
| git | 2 |
| javascript-debugging | 2 |
| zap | 2 |
| burp-repeater | 1 |

## Bypass primitives

| Item | Count |
|---|---:|
| content-type | 9 |
| blind | 5 |
| backslash | 4 |
| unicode | 2 |
| chunked | 2 |
| crlf | 2 |
| blacklist | 1 |
| url encoded | 1 |
| bypass | 1 |
| transfer-encoding | 1 |
| lowercase | 1 |
| bypasses | 1 |

## Impact language

| Item | Count |
|---|---:|
| password | 58 |
| admin | 30 |
| token | 23 |
| localhost | 15 |
| credential | 7 |
| secret | 6 |
| rce | 2 |
| arbitrary file | 1 |

## Parameters observed

| Item | Count |
|---|---:|
| conn | 10 |
| format | 5 |
| mem | 3 |
| len | 3 |
| csrfmiddlewaretoken | 2 |
| email | 2 |
| content | 2 |
| json | 2 |
| uid | 2 |
| mail | 2 |
| username | 2 |
| samaccountname | 2 |
| cloudron_ldap_bind_dn | 2 |
| cloudron_ldap_bind_password | 2 |
| cloudron_ldap_users_base_dn | 2 |
| cloudron_ldap_url | 2 |
| data | 2 |
| ap_save | 2 |
| repeatable | 2 |
| subject | 1 |
| name | 1 |
| message | 1 |
| charset | 1 |
| m-b | 1 |
| m-s | 1 |
| m-css_v | 1 |
| m-login | 1 |
| m-early_v | 1 |
| m-tz | 1 |
| m-wf-loaded | 1 |

## Recurring approach patterns

- **1×** steps to reproduce i ve created a script that can be run here against any rack based application by default it generates a request body with parts which in my testing was enough to cause github api to take between seconds to service the request once the request transfer had completed
  - e.g. ## Steps To Reproduce: I've created a script that can be run here against any Rack-based application: By default it generates a request body with 10,000 parts which, in my testing, was enough to cause GitHub API to take between 15-25 seconds to service the request once the request transfer had compl
- **1×** f838206 but the api token can be added to that group through f838209 clicking on manage groups is possible to add this api token to the previously created group
  - e.g. {F838206} But the API token can be added to that group through ` {F838209} Clicking on **Manage groups** is possible to add this API token to the previously created group.
- **1×** so in my test i changed from testing to aaabc2
  - e.g. So, in my test I changed from `Testing` to `AAABC2`.
- **1×** istead of the above setting i tested the app locally
  - e.g. Istead of the above setting, I tested the app locally.
- **1×** as mentioned in another project to simulate a ldap server for users authentication i used a test server provided by the same author you can find attached
  - e.g. As mentioned in another project ( ), to simulate a LDAP server for users authentication, I used a test server provided by the same author ( (you can find attached).
- **1×** summary hello team while testing it was observed that on 3d cs money a dos is possible via specially crafted request using only single request from single machine on search bar
  - e.g. ## Summary: Hello Team, While testing it was observed that on **3d.cs.money** a DOS is possible via specially crafted request using only single request from single machine on search bar.
- **1×** filed publicly my first gut reaction was that this had to be a problem with curl fnmatch as that has caused us grief in the past and on most platforms we use the native fnmatch now but not on windows iirc and this is a reported to happen on windows but i then built a test program and i made it crash in what seems like potential stack overflow due to recursive calls to wc statemach from within itself
  - e.g. **Filed publicly** My first gut reaction was that this had to be a problem with `curl_fnmatch` as that has caused us grief in the past (and on most platforms we use the native `fnmatch()` now, but not on Windows IIRC and this is a reported to happen on Windows), but I then built a test program and I
- **1×** i discovered this issue in the ftp functionality of the curl project as described in curl uses epsv mode as the default ftp file transfer method
  - e.g. I discovered this issue in the FTP functionality of the curl project .As described in curl uses EPSV mode as the default FTP file transfer method.
- **1×** component pkg plugin plugin go affected version aws encryption provider 4341c70 all versions found by fuzz testing fuzzv1decrypt seed empty byte summary v1plugin decrypt accesses request cipher without checking that the slice is non empty
  - e.g. **Component:** pkg/plugin/plugin.go:179 **Affected Version:** aws-encryption-provider @ 4341c70 (all versions) **Found by:** Fuzz testing (FuzzV1Decrypt, seed#0: empty []byte{}) --- ## Summary `V1Plugin.Decrypt()` accesses `request.Cipher[0]` without checking that the slice is non-empty.
- **1×** a sufficiently deep tree of nested curl mime subparts objects causes stack exhaustion when libcurl starts reading the mime body
  - e.g. A sufficiently deep tree of nested `curl_mime_subparts()` objects causes stack exhaustion when libcurl starts reading the MIME body.
- **1×** summary gis geometry collection init from wkb and get data size recurse once per nested child geometry when parsing a wkb well known binary geometrycollection with no recursion depth limit and no check stack overrun call
  - e.g. --- ## Summary `Gis_geometry_collection::init_from_wkb()` and `::get_data_size()` recurse once per nested child geometry when parsing a WKB (Well-Known Binary) `GEOMETRYCOLLECTION`, with **no recursion-depth limit and no `check_stack_overrun()` call**.

## Case studies (full excerpts)

### 2520679 — Possible DoS Vulnerability with Range Header in Rack
Internet Bug Bounty · $5420 · high · https://hackerone.com/reports/2520679

I made a report and patch at > There is a possible DoS vulnerability relating to the Range request header in Rack. This vulnerability has been assigned the CVE identifier CVE-2024-26141. > Versions Affected: >= 1.3.0. Not affected: < 1.3.0 Fixed Versions: 3.0.9.1, 2.2.8.1 ## Impact > Carefully crafted Range headers can cause a server to respond with an unexpectedly large response. Responding with such large responses could lead to a denial of service issue. > Vulnerable applications will use the Rack::File middleware or the Rack::Utils.byte_ranges methods (this includes Rails applications).

### 880187 — Near to Infinite loop when changing Group's name that has API token as Team Member
HackerOne · $2500 · medium · https://hackerone.com/reports/880187

**Summary:** The ` contains an iteration or loop with an exit condition that is near to infinite loop. If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory and even a DoS attack. **Description:** Hello Security team, I have a test Enterprise Program ` enabled in my second H1 account. Last days I have been hunting on the program features and I have founded a weird behavior that can consume excessive resources on the platform. Under the `group management` feature the program administrator can add a new `group` to segregate the permissions. The website runs the following function to create the group on the platform. Once the group is created its can be read in `JSON` format throuhg the page ` as example below: {F838205} From the `group management` page the program administrator can add only users to that group, can't add API token to that group from there. {F838206} But the API token can be added to that group through ` {F838209} Clicking on **Manage groups** is possible to add this API token to the previously created group. {F838210} Once you save that, you can read this API token permission/groups in `JSON` format too, just goint to ` team member ID of your API toke].json` Just like before, the same data will be displayed. Also, the `group` will be displayed under API Token page. {F838211} The issu

### 1627159 — Rack CVE-2022-30122: Denial of Service Vulnerability in Rack Multipart Parsing
Internet Bug Bounty · $2400 · medium · https://hackerone.com/reports/1627159

ReDoS in `Rack::Multipart::BROKEN_QUOTED` and `Rack::Multipart::BROKEN_UNQUOTED`. > Carefully crafted multipart POST requests can cause Rack's multipart parser to take much longer than expected, leading to a possible denial of service vulnerability. ## Impact When the client sends a specially crafted header, it occur ReDoS on the server side. Servers that interpret Post data by default, like Rails, are affected.

### 20861 — moderate: mod_deflate denial of service
Internet Bug Bounty · $500 · severity n/a · https://hackerone.com/reports/20861

A resource consumption flaw was found in mod_deflate. If request body decompression was configured (using the "DEFLATE" input filter), a remote attacker could cause the server to consume significant memory and/or CPU resources. The use of request body decompression is not a common configuration. Acknowledgements: This issue was reported by Giancarlo Pellegrino and Davide Balzarotti Resolved in Apache httpd 2.4.10-dev:

### 1895316 — CVE-2023-25692: Apache Airflow Google Provider: Google Cloud Sql Provider Denial Of Service and Remote Command Execution
Internet Bug Bounty · $480 · low · https://hackerone.com/reports/1895316

## 0x01 Environment - airflow 2.5.1 - apache-airflow-providers-google 8.8.0 - Build with docker compose ## 0x02 Reproduction Steps ### 2.1 Create a malicious Google Cloud SQL Database connection Create the following Google Cloud SQL Database connection named **aaa** under the Admin->Connections menu.Among them, Host, Schema, Login, and Port are required, just fill in the content that conforms to the format. {F2213508} The actual content filled in **Extra** field is as follows. Note that **sql_proxy_version** must be similar to `?a=`, and the value of **sql_proxy_binary_path** is set to the command to be executed. Fill in 'whoami' here. ### 2.2 Use the CloudSQLExecuteQueryOperator operator in the DAG for verification Create a google_test.py script that uses the CloudSQLExecuteQueryOperator operator, and put it in the `/opt/airflow/dags` directory in the background so that it can be automatically loaded by airflow. The content is as follows, where **gcp_cloudsql_conn_id** is set to the connection name we established above **aaa** Enable the** example_gcp_sql_query** DAG corresponding to our **google_test.py** script in the UI management interface, and run. Click to view the running graph and logs through the Graph menu. {F2213514} It can be seen from the log that the victim machine executed the malicious parameter 'whoami' we constructed. {F2213518} ### 2.3 Other methods for remo

### 3556769 — Incomplete fix for CVE-2026-21637: loadSNI() in _tls_wrap.js lacks try/catch leading to Remote DoS
Node.js · no bounty (valid finding) · high · https://hackerone.com/reports/3556769

A flaw in Node.js TLS error handling leaves `SNICallback` invocations unprotected against synchronous exceptions, while the equivalent ALPN and PSK callbacks were already addressed in CVE-2026-21637. This represents an incomplete fix of that prior vulnerability. When an `SNICallback` throws synchronously on unexpected input the exception bypasses TLS error handlers and propagates as an uncaught exception, crashing the Node.js process. * This vulnerability affects all Node.js versions that received the CVE-2026-21637 fix, including **20.x, 22.x, 24.x, and 25.x**, on any TLS server where `SNICallback` may throw on unexpected `servername` input.

### 3168039 — CVE-2025-5399: WebSocket endless loop
curl · no bounty (valid finding) · low · https://hackerone.com/reports/3168039

The function `curl_ws_send()` in libcurl on commit [12d13b84fa40aa657b83d5458944dbd9b978fb7e]( contains an infinite loop that can be triggered by a malicious server under specific circumstances. If an application uses `curl_ws_recv()` and `curl_ws_send()` to communicate with a websocket server, a malicious server can send a carefully timed PING message while the client is constructing a frame via `CURLWS_OFFSET` that leads to the next `curl_ws_send()` invocation not terminating a loop that flushes data. The affected code is in file `lib/ws.c` in function `curl_ws_send()` on [lines 1376 - 1419]( `buflen` is coming from the application and is the length of data to be sent. If the loop starts with `ws->sendbuf_payload == 0`, then `buflen > ws->sendbuf_payload` is always true. After a successful `ws_flush()`, `sent`, `buffer` and `buflen` remain unmodified and the loop runs forever. ## PoC Consider the following client that repeatedly sends and receives messages: And consider the following server that serves malicious packets: When the server is launched in the background with And the client is run with it can be seen that `./client` takes up 100% CPU usage and never terminates. ## Explanation I still don't 100% understand the websocket code and why it comes to this bug but here is a rough overview what happens: - The client tries building a 70-byte frame over the course of 3 `curl

## Field playbook (unedited)

### quick

- Look for expensive operations on user input: regex, XML/JSON parsing, image/video, PDF.
- Test unbounded pagination, large limits, deep nesting, and zip bombs (safely).
- Check rate limits on search/export/invite/SMS.
- Try amplification: one request causing many downstream calls.

### payloads

- `limit=999999` `page_size=100000` `depth=50`
- ReDoS -> `(a+)+$` in a search/regex field
- Zip bomb -> nested archives; XML billion laughs
- GraphQL alias storm

### bypass

- Distribute requests across connections/accounts.
- Use slowloris-style partial bodies where allowed.

### surface

- search
- export
- report
- image
- upload
- graphql
- pagination

### tools

- Burp Turbo Intruder
- custom scripts
- time

### chain

- DoS -> service outage.
- ReDoS -> worker exhaustion.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class dos
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class dos --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
