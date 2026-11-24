# Payloads — Memory Safety and Native Software

Payload lists and probe banks. Methodology and usage are in the parent SKILL.md.

## Payload references from upstream skills (deduplicated)

### hunting / references/payloads.md

# Memory Corruption (Binary / Native) — HackerOne field guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- Craft malformed length fields, counts, and chunk sizes.

- Use AFL++/libFuzzer with a seed corpus.

- ASan -> `heap-buffer-overflow`, `use-after-free`



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 19× | `quote_name()` |

| 14× | `curl_easy_pause()` |

| 11× | `curl_easy_escape()` |

| 10× | `strlen()` |

| 9× | `curl_multi_remove_handle()` |

| 9× | `mq->sendleftovers` |

| 9× | `next->text` |

| 8× | `strcpy()` |

| 8× | `redirect_url()` |

| 8× | `curl_easy_duphandle()` |

| 8× | `free()` |

| 8× | `Curl_close()` |

| 6× | `smb_send_open()` |

| 6× | `req->path` |

| 6× | `smbc->share` |

| 6× | `unpack_fields()` |

| 6× | `curl_easy_cleanup()` |

| 6× | `mev_assess()` |

| 6× | `suboption()` |

| 6× | `curl_msprintf()` |



## Parameters observed



`id` · `name` · `usp` · `response` · `_task` · `_action` · `center` · `size` · `maptype` · `markers` · `sensor` · `scale` · `zoom` · `language` · `raw` · `password` · `plain` · `lang` · `summary` · `statement`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_memory-corruption.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/params_memory-corruption.txt` | 36 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_memory-corruption.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_memory-corruption.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Identify the exact product/version, then run matching CVE templates; fuzz parsers locally with ASan.



```sh

nuclei -u https://target -tags cve,rce \

       -severity low,medium,high,critical -rl 40 -o nuclei_memory-corruption.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.
