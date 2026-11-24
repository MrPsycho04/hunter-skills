# MFA And Passwords — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- OTP -> `000000`, reuse old code, race multiple codes

- MFA -> call the post-MFA endpoint directly

- Password -> `password[]=x`, type juggling

- Enumeration -> response length/timing variants



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 2× | `> POST /users/sign_in HTTP/1.1 / > Host: 159.xxx.xxx.xxx / > ... / > ----------1881604860 / > Content-Disposition: form-data; name="user[otp` |

| 2× | `{{temaplte:38dhs_admins_only_header.html}}` |

| 1× | `{email: \"█████ \", password: \"███\" }` |

| 1× | `POST /login/confirm HTTP/1.1 / Host: cs.money / Content-Length: 28 / Connection: close / Cookie: steamid=<victim_steam_id>; / {"token":"foo` |

| 1× | `HTTP/1.1 400 Bad Request / Content-Encoding: gzip / Content-Type: application/json; charset=utf-8 / Date: Tue, 31 Jan 2017 17:45:43 GMT / X-` |

| 1× | `Throttler\sleepDelay` |

| 1× | `{"username":"admin"}` |

| 1× | `/api/system/verification-codes/[0-9]{6}` |

| 1× | `{"password":"<NEW PASSWORD>","code":"<BRUTEFORCED SMS TOKEN>","securityCode":"<RETRIEVED SECURITY CODE>"}` |

| 1× | `<methodName> system.listMethods </methodName>` |

| 1× | `curl -u "RANDOM1:RANDOM2" -X PROPFIND https://server/public.php/webdav` |

| 1× | `[...]OCA\\\\DAV\\\\Connector\\\\Sabre\\\\Auth->validateUserPass('matthes', '***THE_PASSWORD***')[...]` |

| 1× | `/php/restaurantSmsHandler.php?type=app-download-sms&mobile_no=<NUMBER>&csrf_token=<TOKEN>` |

| 1× | `/php/restaurantSmsHandler.php?type=order-app-download-sms&mobile_no=<NUMBER>&csrf_token=<TOKEN>` |

| 1× | `/php/restaurantSmsHandler.php?type=app-download-sms&mobile_no=[8127410000,8317030000,...]&csrf_token=<TOKEN>` |

| 1× | `$ curl --globoff 'http://localhost:3000/api/v1/gems?api_key[]=key1&api_key[]=key2' / > Access Denied. Please sign up for an account at https` |

| 1× | `SecureRandom.hex (32)` |

| 1× | `$response->throttle()` |

| 1× | `using the way ''{{temaplte:38dhs_admins_only_header.html}}'' in 'create new' via 'preview feature', nothing. The other variable name, which` |

| 1× | `{id:"2"}` |



## Parameters observed



`password` · `username` · `template` · `authenticity_token` · `invite_code` · `commit` · `hash` · `phone` · `token` · `api_key[]` · `id` · `next` · `_method` · `type` · `mobile_no` · `csrf_token` · `data` · `uuid` · `redirect` · `product`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_mfa-and-passwords.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/params_mfa-and-passwords.txt` | 75 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_mfa-and-passwords.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_mfa-and-passwords.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Test OTP brute-force limits, reuse, and direct post-MFA endpoint access manually.



```sh

nuclei -u https://target -tags auth-bypass,default-login,token-spray,login \

       -severity low,medium,high,critical -rl 40 -o nuclei_mfa-and-passwords.txt

nuclei -u https://target -t ~/nuclei-templates/http/default-logins \

       -rl 40 -o nuclei_mfa-and-passwords_default-logins.txt

nuclei -u https://target -t ~/nuclei-templates/http/token-spray \

       -rl 40 -o nuclei_mfa-and-passwords_token-spray.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.
