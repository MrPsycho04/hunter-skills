# Other & emerging classes — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payload fragments observed



| Seen | Fragment |

|---:|---|

| 8× | `curl_multi_socket_action()` |

| 7× | `%RFLAGS.AC` |

| 7× | `jobert@mydocz.cosmic` |

| 6× | `<a>` |

| 6× | `free()` |

| 6× | `javascript:` |

| 6× | `curl_multi_perform()` |

| 5× | `multi->process` |

| 5× | `--url @file` |

| 4× | `ExternalMemoryAccounter::Increase()` |

| 4× | `__%48ost-` |

| 4× | `wcurl -- "$url` |

| 4× | `parse_netscape()` |

| 4× | `multi_run_dirty()` |

| 4× | `smbc->share` |

| 4× | `swrite()` |

| 4× | `digest->origin` |

| 3× | `copyin()` |

| 3× | `<iframe>` |

| 3× | `^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$` |



## Parameters observed



`username` · `password` · `template` · `url` · `hash` · `id` · `callback` · `ingredients[]` · `email` · `variant` · `shop` · `month` · `year` · `report_id` · `checkout_token` · `template[]` · `next` · `data` · `token` · `subject`



## Nuclei



Start broad, then classify the root cause and open the matching skill.



```sh

nuclei -u https://target -tags vuln,cve,exposure \

       -severity low,medium,high,critical -rl 40 -o nuclei_other.txt

nuclei -u https://target -t ~/nuclei-templates/http/exposures \

       -rl 40 -o nuclei_other_exposures.txt

nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/generic \

       -rl 40 -o nuclei_other_generic.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_other.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/params_other.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_other.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_other.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```
