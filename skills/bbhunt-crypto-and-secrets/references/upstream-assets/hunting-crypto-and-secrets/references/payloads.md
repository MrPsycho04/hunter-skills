# Crypto And Secrets — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- Regex -> `AKIA[0-9A-Z]{16}`, `AIza[0-9A-Za-z_-]{35}`, `ghp_[0-9A-Za-z]{36}`

- JWT secret -> `hashcat -m 16500`

- Weak reset token -> timestamp/random seed



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 7× | `SecTrustSetOCSPResponse()` |

| 7× | `hsts_check()` |

| 6× | `$position` |

| 6× | `ssl_peer_key_build()` |

| 5× | `ossl_apple_verify()` |

| 5× | `hsts_add_host_expire()` |

| 5× | `Curl_hsts_parse()` |

| 4× | `master @ 3ad4a5ee8` |

| 4× | `Curl_ossl_check_peer_cert()` |

| 4× | `verifystatus()` |

| 4× | `SSL_get_tlsext_status_ocsp_resp()` |

| 4× | `gnutls_certificate_verify_peers2()` |

| 4× | `Math.random()` |

| 4× | `EntropySource()` |

| 4× | `Curl_fopen()` |

| 4× | `Curl_vtls_apple_verify()` |

| 4× | `$passPhrase` |

| 4× | `$version` |

| 4× | `OC\Security\SecureRandom::generate` |

| 4× | `hsts_create()` |



## Parameters observed



`id` · `token` · `type` · `_gl` · `redirectUrl` · `EQ` · `name` · `uuid` · `dnssec` · `key` · `PackageID` · `jwt` · `action` · `active_action` · `item_id` · `item_no` · `page_id` · `block_id` · `client_id` · `redirect_uri`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_crypto-and-secrets.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/params_crypto-and-secrets.txt` | 77 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_crypto-and-secrets.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_crypto-and-secrets.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Verify leaked keys before reporting; check scope and whether the key is live.



```sh

nuclei -u https://target -tags exposure,keys,tokens,ssl \

       -severity info,low,medium,high,critical -rl 40 -o nuclei_crypto-and-secrets.txt

nuclei -u https://target -t ~/nuclei-templates/http/exposures/tokens \

       -rl 40 -o nuclei_crypto-and-secrets_tokens.txt

nuclei -u https://target -t ~/nuclei-templates/http/exposures/configs \

       -rl 40 -o nuclei_crypto-and-secrets_configs.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.
