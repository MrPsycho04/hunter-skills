# Broken Access Control / Authorization Bypass — HackerOne field guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- Role fields -> `role=admin`, `is_admin=true`, `plan=enterprise`, `permissions=["*"]`

- Headers -> `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For: 127.0.0.1`, `X-User-Id`

- Path tricks -> `/admin/../user`, `/admin%2f..%2f`, `/.;/admin`, trailing slash

- Method swap -> GET->POST->PUT->DELETE, `X-HTTP-Method-Override`



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 5× | `victim@ato.com` |

| 4× | `%TEMP%` |

| 3× | `@hackerone.com` |

| 3× | `../../app0/bdjstack/lib/ext/00000.jar` |

| 3× | `../../` |

| 3× | `The HEY Team <support@hey.com>` |

| 3× | `support@hey.com` |

| 3× | `POST /index.php/apps/groupfolders/folders/{id}/groups` |

| 3× | `postmaster@email.mg.gitlab.com` |

| 3× | `%temp%\Acronis\DriverSetup\inst.log` |

| 3× | `get_editable_roles()` |

| 3× | `wp_ensure_editable_role()` |

| 3× | `setuid()` |

| 2× | `victim@gmail.com` |

| 2× | `attacker@gmail.com` |

| 2× | `demo-member@hackerone.com` |

| 2× | `%0d%0a` |

| 2× | `j@hackerone.com` |

| 2× | `0xacb@hackerone.com` |

| 2× | `https://cdn.kastatic.org/khanacademy/khanacademy.<hash>.js.map` |



## Parameters observed



`subject` · `report_id` · `scope` · `state` · `client_id` · `response_type` · `redirect_uri` · `group_id` · `search` · `repository_ref` · `aura.context` · `aura.pageURI` · `aura.token` · `authenticity_token` · `page` · `code` · `id` · `type` · `snippets` · `phone`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_authz-bypass.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/params_authz-bypass.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_authz-bypass.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_authz-bypass.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Nuclei cannot infer your object model. Use tags for exposed admin panels, then build a manual role/object matrix.



```sh

nuclei -u https://target -tags idor,authorization,exposure \

       -severity low,medium,high,critical -rl 40 -o nuclei_authz-bypass.txt

nuclei -u https://target -t ~/nuclei-templates/http/exposures \

       -rl 40 -o nuclei_authz-bypass_exposures.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.
