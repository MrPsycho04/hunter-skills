# Payloads — Denial of Service and Resource Exhaustion

Payload lists and probe banks. Methodology and usage are in the parent SKILL.md.

## Payload references from upstream skills (deduplicated)

### hunting / references/payloads.md

# Denial of Service / Resource Exhaustion — HackerOne field guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- `limit=999999` `page_size=100000` `depth=50`

- ReDoS -> `(a+)+$` in a search/regex field

- Zip bomb -> nested archives; XML billion laughs

- GraphQL alias storm



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 5× | `curl_ws_send()` |

| 3× | `check_stack_overrun()` |

| 2× | `Cipher: []byte{}` |

| 2× | `res.write()` |

| 2× | `SELECT ST_GeomFromWKB(0x…)` |

| 2× | `*)(cn=*)(cn=*` |

| 2× | `mime_subparts_read()` |

| 1× | `curl_ws_recv()` |

| 1× | `ws->sendbuf_payload == 0` |

| 1× | `buflen > ws->sendbuf_payload` |

| 1× | `ws_flush()` |

| 1× | `InitProposalBlockParts()` |

| 1× | `V1Plugin.Decrypt()` |

| 1× | `[]byte{}` |

| 1× | `len(request.Cipher) > 0` |

| 1× | `(((((()0)))))` |

| 1× | `((((((()0))))))` |

| 1× | `[Server] Memory usage: ${usage.toFixed(2)} MB` |

| 1× | `Server listening on port ${port}` |

| 1× | `V2Plugin.Decrypt()` |



## Parameters observed



`name` · `load` · `email` · `content` · `subject` · `message` · `revision` · `formkey` · `postkey` · `window_id` · `referring_controller` · `referring_action`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_dos.txt` | 41 |

| `~/.local/share/hackerone-reports/wordlists/params_dos.txt` | 12 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_dos.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_dos.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Do not run DoS templates against production without explicit permission; measure resource use on a test account.



```sh

nuclei -u https://target -tags dos \

       -severity low,medium,high,critical -rl 40 -o nuclei_dos.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.
