# Payloads — Subdomain Takeover

Payload lists and probe banks. Methodology and usage are in the parent SKILL.md.

## Payload references from upstream skills (deduplicated)

### hunting / references/payloads.md

# Subdomain Takeover — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- CNAME -> `foo.s3.amazonaws.com` (NoSuchBucket)

- CNAME -> `foo.github.io` (404 repo)

- CNAME -> `foo.herokuapp.com` (No such app)

- CNAME -> `foo.statuspage.io` / `foo.zendesk.com`



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 4× | `{REDACTED}.data.gov` |

| 3× | `smb_send_open()` |

| 3× | `req->path` |

| 3× | `smbc->share` |

| 2× | `smb_parse_url_path()` |

| 2× | `Curl_conn_free()` |

| 2× | `smb_conn_dtor()` |

| 1× | `*@devrel.roblox.com` |

| 1× | `% dig +short fr1.vpn.zomans.com / 52.47.57.107 / % curl fr1.vpn.zomans.com / <!-- hackerone.com/ian -->` |

| 1× | `% dig +short v.zego.com / 52.214.138.192 / % curl v.zego.com / <!-- hackerone.com/ian -->` |

| 1× | `Force HTTPS (requires valid certificates)` |

| 1× | `ASAN_OPTIONS=detect_leaks=0 LD_LIBRARY_PATH=./lib/.libs \ / ./src/.libs/curl -u guest:guest \ / "smb://127.0.0.1:5445/share1/file1" -o /dev/` |

| 1× | `strlen(req->path)` |

| 1× | `smbc->share = strdup(path)` |

| 1× | `req->path = slash` |

| 1× | `url_find_or_create_conn()` |

| 1× | `free(smbc->share)` |

| 1× | `smb_request_state()` |

| 1× | `% curl https://s3.amazonaws.com/affirm-prod-www-cms████████/index.html / <!-- taken over by hackerone.com/ian bugcrowd.com/iangcarroll ian@l` |

| 1× | `alert(document.domain)` |



## Parameters observed



`_method` · `authenticity_token` · `domainToCheck` · `conversationId` · `pageSize` · `domain` · `state` · `dl` · `button` · `id`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_subdomain-takeover.txt` | 81 |

| `~/.local/share/hackerone-reports/wordlists/params_subdomain-takeover.txt` | 10 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_subdomain-takeover.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_subdomain-takeover.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Enumerate subdomains first (subfinder/amass), then run the takeover templates against the resolved host list.



```sh

nuclei -u https://target -tags takeover \

       -severity low,medium,high,critical -rl 40 -o nuclei_subdomain-takeover.txt

nuclei -u https://target -t ~/nuclei-templates/http/takeovers \

       -rl 40 -o nuclei_subdomain-takeover_takeovers.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.



## Payload & Detection Patterns



**Bulk CNAME extraction and NXDOMAIN detection:**

```bash

# Extract CNAMEs and check if target resolves

while read sub; do

  cname=$(dig +short CNAME "$sub" | head -1)

  if [ -n "$cname" ]; then

    result=$(dig +short A "$cname")

    if [ -z "$result" ]; then

      echo "[POTENTIAL] $sub -> $cname (NXDOMAIN)"

    fi

  fi

done < subdomains.txt

```



**Nuclei takeover scan:**

```bash

nuclei -l subdomains.txt -t ~/nuclei-templates/http/takeovers/ -severity medium,high,critical

```



**subjack with SSL:**

```bash

subjack -w subdomains.txt -t 100 -timeout 30 -ssl -c $GOPATH/src/github.com/haccer/subjack/fingerprints.json -v

```



**Provider fingerprint grep patterns:**

```bash

curl -sk "https://$subdomain" | grep -iE \

  "there isn't a github pages|no such bucket|no such app|this uservoice|fastly error: unknown domain|do you want to register|sorry, this shop|project not found|404 not found|unclaimed"

```



**Check if subdomain is in scope for cookies (shared parent domain):**

```bash

curl -Isk "https://target.com" | grep -i "set-cookie" | grep "domain=.target.com"

```



**Fastly-specific detection:**

```bash

curl -sI "https://subdomain.target.com" -H "Host: subdomain.target.com" | grep -i "fastly\|x-served-by\|x-cache"

curl -sk "https://subdomain.target.com" | grep -i "fastly error"

```



**S3 unclaimed bucket check:**

```bash

aws s3api head-bucket --bucket <extracted-bucket-name> 2>&1 | grep -i "NoSuchBucket\|403\|404"

```



**GitLab Pages specific:**

```bash

dig CNAME sub.target.com

# If pointing to *.gitlab.io — visit the gitlab.io URL directly

# 404 from gitlab.io project = claimable

```



---
