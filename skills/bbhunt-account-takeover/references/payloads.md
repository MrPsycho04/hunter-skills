# Payloads — Account Takeover Chains

Payload lists and probe banks. Methodology and usage are in the parent SKILL.md.

## Payload references from upstream skills (deduplicated)

### hunting / references/payloads.md

# Account Takeover — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- Host header -> `Host: evil.com` in reset request

- Email -> `victim@example.com` with unicode/plus/dot variants

- OAuth -> link attacker provider to victim email

- OTP -> brute force, reuse, response leakage



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 5× | `victim@ato.com` |

| 3× | `attacker@example.com` |

| 3× | `@import` |

| 2× | `GET https://<URL> HTTP/1.1` |

| 2× | `demo-member@hackerone.com` |

| 2× | `https://cdn.kastatic.org/khanacademy/khanacademy.<hash>.js.map` |

| 2× | `badca7@wearehackerone.com` |

| 2× | `application%5Bid%5D` |

| 2× | `check_alter_user()` |

| 2× | `$regex` |

| 2× | `loadDataWithBaseURL()` |

| 2× | `^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$` |

| 2× | `<input>` |

| 1× | `user[email]":"victim@gmail.com` |

| 1× | `victim@gmail.com` |

| 1× | `attacker@gmail.com` |

| 1× | `GET / HTTP/1.1 / Transfer-Encoding : chunked / Host: slackb.com / User-Agent: Smuggler/v1.0 / Content-Length: 83 / 0 / GET <URL> HTTP/1.1 /` |

| 1× | `https://<URL>` |

| 1× | `Burp->Burp Collaborator Client` |

| 1× | `host: slackb.com , Port: 443 (SSL)` |



## Parameters observed



`username` · `month` · `year` · `template` · `template[]` · `url` · `email` · `redirectUrl` · `token` · `userId` · `p_datasource_data` · `switch` · `ticket_id` · `canary` · `password` · `continue` · `PositionTitleIds` · `Title` · `FirstName` · `MiddleName`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_account-takeover.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/params_account-takeover.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_account-takeover.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_account-takeover.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Use Nuclei for exposed tokens and takeover fingerprints, then chain reset/OAuth/email-change primitives manually.



```sh

nuclei -u https://target -tags takeover,auth-bypass,jwt \

       -severity low,medium,high,critical -rl 40 -o nuclei_account-takeover.txt

nuclei -u https://target -t ~/nuclei-templates/http/takeovers \

       -rl 40 -o nuclei_account-takeover_takeovers.txt

nuclei -u https://target -t ~/nuclei-templates/http/exposures/tokens/generic/jwt-token.yaml \

       -rl 40 -o nuclei_account-takeover_jwt-token.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.
